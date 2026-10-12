using Mvv42.Auth.Data;
using Mvv42.Auth.Telegram;

namespace Mvv42.Auth.Tests.Data;

/// <summary>
/// Behaviour every <see cref="IAuthStore"/> must have. Runs against the in-memory store always and against
/// MySQL when <c>MVV42_AUTH_TEST_MYSQL</c> is set (CI). Tests use unique ids so a shared database is fine.
/// </summary>
public abstract class AuthStoreContractTests
{
    protected abstract IAuthStore Store { get; }

    // Whole seconds: MySQL DATETIME(6) keeps microseconds, .NET ticks are 100ns.
    protected static readonly DateTime T0 = new(2026, 10, 11, 12, 0, 0, DateTimeKind.Utc);

    private static long UniqueTelegramId() => Random.Shared.NextInt64(1_000_000_000, 9_000_000_000);
    private static string UniqueAppId() => "t_" + Guid.NewGuid().ToString("N")[..12];
    private static string Hash() => Convert.ToHexString(Guid.NewGuid().ToByteArray()).ToLowerInvariant().PadRight(64, '0');

    private async Task<User> NewUser() =>
        await Store.UpsertUserAsync(new TelegramProfile(UniqueTelegramId(), "Max", "V", "max", null), T0);

    private async Task<App> NewApp(string access = AppAccess.Invite)
    {
        var app = new App { Id = UniqueAppId(), Name = "Test", Anonymous = false, Access = access };
        await Store.UpsertAppAsync(app);
        return app;
    }

    [Fact]
    public async Task UpsertUser_CreatesThenUpdatesProfile()
    {
        var tg = UniqueTelegramId();
        var created = await Store.UpsertUserAsync(new TelegramProfile(tg, "Max", null, "max", null), T0);
        var updated = await Store.UpsertUserAsync(new TelegramProfile(tg, "Maxim", "V", null, "https://t.me/p.jpg"), T0.AddDays(1));

        Assert.Equal(created.Id, updated.Id);
        Assert.Equal(tg, updated.TelegramId);
        Assert.Equal("Maxim", updated.FirstName);
        Assert.Equal("V", updated.LastName);
        Assert.Null(updated.Username);
        Assert.Equal("https://t.me/p.jpg", updated.PhotoUrl);
        Assert.Equal(T0.AddDays(1), updated.LastLoginAt);
        Assert.Equal(T0, updated.CreatedAt);
        Assert.False(updated.IsAdmin);

        var loaded = await Store.GetUserAsync(created.Id);
        Assert.Equal("Maxim", loaded!.FirstName);
    }

    [Fact]
    public async Task SetUserAdmin_FlagsUser()
    {
        var user = await NewUser();
        Assert.True(await Store.SetUserAdminAsync(user.Id, true));
        // unchanged value: still "found" whatever the connection's affected-rows mode is
        Assert.True(await Store.SetUserAdminAsync(user.Id, true));
        Assert.True((await Store.GetUserAsync(user.Id))!.IsAdmin);
        Assert.Contains(await Store.ListUsersAsync(), u => u.Id == user.Id && u.IsAdmin);
        Assert.False(await Store.SetUserAdminAsync(-1, true));
    }

    [Fact]
    public async Task SeededApps_ArePresent()
    {
        var apps = (await Store.GetAppsAsync()).ToDictionary(a => a.Id);
        Assert.Equal((false, AppAccess.Public), (apps["cashpulse"].Anonymous, apps["cashpulse"].Access));
        Assert.Equal((true, AppAccess.Public), (apps["credit_calc"].Anonymous, apps["credit_calc"].Access));
        Assert.Equal((false, AppAccess.Admin), (apps["bonds"].Anonymous, apps["bonds"].Access));
    }

    [Fact]
    public async Task UpsertApp_InsertsAndUpdates_DeleteRemovesGrants()
    {
        var app = await NewApp();
        await Store.UpsertAppAsync(app with { Name = "Renamed", Anonymous = true, Access = AppAccess.Public });
        Assert.Contains(await Store.GetAppsAsync(), a => a == app with { Name = "Renamed", Anonymous = true, Access = AppAccess.Public });

        var user = await NewUser();
        await Store.AddGrantAsync(user.Id, app.Id, T0);
        Assert.True(await Store.DeleteAppAsync(app.Id));
        Assert.DoesNotContain(await Store.GetAppsAsync(), a => a.Id == app.Id);
        Assert.Empty(await Store.GetGrantsAsync(user.Id));
        Assert.False(await Store.DeleteAppAsync(app.Id));
    }

    [Fact]
    public async Task Grants_AddIsIdempotent_RemoveWorks()
    {
        var user = await NewUser();
        var app = await NewApp();

        await Store.AddGrantAsync(user.Id, app.Id, T0);
        await Store.AddGrantAsync(user.Id, app.Id, T0);
        Assert.Equal([app.Id], await Store.GetGrantsAsync(user.Id));
        Assert.Single(await Store.ListGrantsAsync(user.Id));

        Assert.True(await Store.RemoveGrantAsync(user.Id, app.Id));
        Assert.False(await Store.RemoveGrantAsync(user.Id, app.Id));
        Assert.Empty(await Store.GetGrantsAsync(user.Id));
    }

    private async Task<Session> NewSession(DateTime? expiresAt = null)
    {
        var user = await NewUser();
        var session = new Session
        {
            UserId = user.Id,
            FamilyId = Guid.NewGuid().ToString(),
            RefreshHash = Hash(),
            CreatedAt = T0,
            ExpiresAt = expiresAt ?? T0.AddDays(30),
            LastUsedAt = T0,
            UserAgent = "test",
        };
        var id = await Store.CreateSessionAsync(session);
        return session with { Id = id };
    }

    [Fact]
    public async Task Session_RotationIsConditional_AndFindableByBothHashes()
    {
        var s = await NewSession();
        var next = Hash();

        Assert.True(await Store.UpdateSessionRotationAsync(s.Id, s.RefreshHash, next, T0.AddMinutes(10), T0.AddDays(31)));
        Assert.False(await Store.UpdateSessionRotationAsync(s.Id, s.RefreshHash, Hash(), T0.AddMinutes(10), T0.AddDays(31)));

        var byCurrent = await Store.GetSessionByRefreshHashAsync(next);
        var byPrevious = await Store.GetSessionByRefreshHashAsync(s.RefreshHash);
        Assert.Equal(s.Id, byCurrent!.Id);
        Assert.Equal(s.Id, byPrevious!.Id);
        Assert.Equal(next, byCurrent.RefreshHash);
        Assert.Equal(s.RefreshHash, byCurrent.PrevRefreshHash);
        Assert.Equal(T0.AddMinutes(10), byCurrent.RotatedAt);
        Assert.Equal(T0.AddMinutes(10), byCurrent.LastUsedAt);
        Assert.Equal(T0.AddDays(31), byCurrent.ExpiresAt);
        Assert.Null(await Store.GetSessionByRefreshHashAsync(Hash()));
    }

    [Fact]
    public async Task Rotation_RecordsReplacedHashInHistory_UntilTheSessionIsDeleted()
    {
        var s = await NewSession();
        var (h1, h2, unknown) = (Hash(), Hash(), Hash());
        Assert.Null(await Store.GetRefreshHistoryAsync(s.RefreshHash));

        Assert.True(await Store.UpdateSessionRotationAsync(s.Id, s.RefreshHash, h1, T0.AddMinutes(1), T0.AddDays(30)));
        Assert.True(await Store.UpdateSessionRotationAsync(s.Id, h1, h2, T0.AddMinutes(2), T0.AddDays(30)));
        // a failed (conditional) rotation records nothing
        Assert.False(await Store.UpdateSessionRotationAsync(s.Id, unknown, Hash(), T0.AddMinutes(3), T0.AddDays(30)));

        var h0Entry = await Store.GetRefreshHistoryAsync(s.RefreshHash);
        Assert.NotNull(h0Entry);
        Assert.Equal(s.FamilyId, h0Entry.FamilyId);
        Assert.Equal(s.Id, h0Entry.SessionId);
        Assert.Equal(T0.AddMinutes(1), h0Entry.RotatedAt);
        Assert.Equal(T0.AddMinutes(2), (await Store.GetRefreshHistoryAsync(h1))!.RotatedAt);
        Assert.Null(await Store.GetRefreshHistoryAsync(h2)); // current token
        Assert.Null(await Store.GetRefreshHistoryAsync(unknown));

        // revoked family → removed by the cleanup together with its history
        await Store.RevokeFamilyAsync(s.FamilyId, T0.AddMinutes(5));
        await Store.DeleteStaleSessionsAsync(now: T0.AddMinutes(10), revokedBefore: T0.AddMinutes(6));
        Assert.Null(await Store.GetRefreshHistoryAsync(s.RefreshHash));
        Assert.Null(await Store.GetRefreshHistoryAsync(h1));
    }

    [Fact]
    public async Task RevokeFamily_And_RevokeSession_SetRevokedAt()
    {
        var a = await NewSession();
        var b = await NewSession();

        await Store.RevokeFamilyAsync(a.FamilyId, T0.AddMinutes(1));
        await Store.RevokeSessionAsync(b.Id, T0.AddMinutes(2));

        Assert.Equal(T0.AddMinutes(1), (await Store.GetSessionByRefreshHashAsync(a.RefreshHash))!.RevokedAt);
        Assert.Equal(T0.AddMinutes(2), (await Store.GetSessionByRefreshHashAsync(b.RefreshHash))!.RevokedAt);
    }

    [Fact]
    public async Task DeleteStaleSessions_RemovesExpiredAndOldRevoked()
    {
        var expired = await NewSession(expiresAt: T0.AddHours(1));
        var revokedLongAgo = await NewSession();
        await Store.RevokeSessionAsync(revokedLongAgo.Id, T0);
        var revokedRecently = await NewSession();
        await Store.RevokeSessionAsync(revokedRecently.Id, T0.AddDays(2));
        var alive = await NewSession();

        var deleted = await Store.DeleteStaleSessionsAsync(now: T0.AddDays(2), revokedBefore: T0.AddDays(1));

        Assert.True(deleted >= 2);
        Assert.Null(await Store.GetSessionByRefreshHashAsync(expired.RefreshHash));
        Assert.Null(await Store.GetSessionByRefreshHashAsync(revokedLongAgo.RefreshHash));
        Assert.NotNull(await Store.GetSessionByRefreshHashAsync(revokedRecently.RefreshHash));
        Assert.NotNull(await Store.GetSessionByRefreshHashAsync(alive.RefreshHash));
    }

    private async Task<(Invite Invite, App App)> NewInvite(int maxUses = 1, DateTime? expiresAt = null)
    {
        var app = await NewApp();
        var invite = new Invite { CodeHash = Hash(), AppId = app.Id, MaxUses = maxUses, ExpiresAt = expiresAt, CreatedAt = T0 };
        var id = await Store.CreateInviteAsync(invite);
        return (invite with { Id = id }, app);
    }

    [Fact]
    public async Task RedeemInvite_GrantsApp_UntilUsesExhausted()
    {
        var (invite, app) = await NewInvite(maxUses: 1);
        var first = await NewUser();
        var second = await NewUser();

        Assert.Equal(new InviteRedeemResult(InviteRedeemStatus.Granted, app.Id), await Store.RedeemInviteAsync(invite.CodeHash, first.Id, T0));
        Assert.Equal([app.Id], await Store.GetGrantsAsync(first.Id));

        Assert.Equal(new InviteRedeemResult(InviteRedeemStatus.Exhausted, app.Id), await Store.RedeemInviteAsync(invite.CodeHash, second.Id, T0));
        Assert.Empty(await Store.GetGrantsAsync(second.Id));
        Assert.Equal(1, (await Store.ListInvitesAsync()).Single(i => i.Id == invite.Id).Uses);
    }

    [Fact]
    public async Task RedeemInvite_AlreadyGranted_DoesNotConsumeUse()
    {
        var (invite, app) = await NewInvite(maxUses: 1);
        var user = await NewUser();
        await Store.AddGrantAsync(user.Id, app.Id, T0);

        Assert.Equal(new InviteRedeemResult(InviteRedeemStatus.AlreadyGranted, app.Id), await Store.RedeemInviteAsync(invite.CodeHash, user.Id, T0));
        Assert.Equal(0, (await Store.ListInvitesAsync()).Single(i => i.Id == invite.Id).Uses);
    }

    [Fact]
    public async Task RedeemInvite_ExpiredOrUnknown()
    {
        var (invite, app) = await NewInvite(expiresAt: T0.AddHours(1));
        var user = await NewUser();

        Assert.Equal(new InviteRedeemResult(InviteRedeemStatus.Expired, app.Id), await Store.RedeemInviteAsync(invite.CodeHash, user.Id, T0.AddHours(1)));
        Assert.Equal(new InviteRedeemResult(InviteRedeemStatus.NotFound, null), await Store.RedeemInviteAsync(Hash(), user.Id, T0));
        Assert.Empty(await Store.GetGrantsAsync(user.Id));
    }

    // ---- admin extensions (migrations 003–006)

    [Fact]
    public async Task GetUserByTelegramId_FindsUser()
    {
        var user = await NewUser();
        Assert.Equal(user.Id, (await Store.GetUserByTelegramIdAsync(user.TelegramId))!.Id);
        Assert.Null(await Store.GetUserByTelegramIdAsync(UniqueTelegramId()));
    }

    [Fact]
    public async Task SetUserBlocked_SetsFlagAndTime_UnblockClearsThem()
    {
        var user = await NewUser();
        Assert.False(user.IsBlocked);
        Assert.Null(user.BlockedAt);

        Assert.True(await Store.SetUserBlockedAsync(user.Id, true, T0.AddMinutes(5)));
        Assert.True(await Store.SetUserBlockedAsync(user.Id, true, T0.AddMinutes(9))); // unchanged → still found
        var blocked = (await Store.GetUserAsync(user.Id))!;
        Assert.True(blocked.IsBlocked);
        Assert.Equal(T0.AddMinutes(5), blocked.BlockedAt); // first block time is kept
        Assert.Contains(await Store.ListUsersAsync(), u => u.Id == user.Id && u.IsBlocked);

        // a later login refreshes the profile but never unblocks
        var relogin = await Store.UpsertUserAsync(new TelegramProfile(user.TelegramId, "Max", null, null, null), T0.AddHours(1));
        Assert.True(relogin.IsBlocked);

        Assert.True(await Store.SetUserBlockedAsync(user.Id, false, T0.AddMinutes(10)));
        var unblocked = (await Store.GetUserAsync(user.Id))!;
        Assert.False(unblocked.IsBlocked);
        Assert.Null(unblocked.BlockedAt);

        Assert.False(await Store.SetUserBlockedAsync(-1, true, T0));
    }

    [Fact]
    public async Task ReadTimes_AreUtc()
    {
        var user = await NewUser();
        var loaded = (await Store.GetUserAsync(user.Id))!;
        Assert.Equal(DateTimeKind.Utc, loaded.CreatedAt.Kind);
        Assert.Equal(DateTimeKind.Utc, loaded.LastLoginAt!.Value.Kind);
    }

    private async Task<Session> NewSessionFor(long userId, DateTime? expiresAt = null, string? ip = "203.0.113.7")
    {
        var session = new Session
        {
            UserId = userId,
            FamilyId = Guid.NewGuid().ToString(),
            RefreshHash = Hash(),
            CreatedAt = T0,
            ExpiresAt = expiresAt ?? T0.AddDays(30),
            LastUsedAt = T0,
            UserAgent = "test",
            Ip = ip,
        };
        return session with { Id = await Store.CreateSessionAsync(session) };
    }

    [Fact]
    public async Task Sessions_PerUser_ListCountRevokeAll()
    {
        var user = await NewUser();
        var other = await NewUser();
        var a = await NewSessionFor(user.Id);
        var b = await NewSessionFor(user.Id, ip: null);
        var expired = await NewSessionFor(user.Id, expiresAt: T0.AddMinutes(1));
        var revoked = await NewSessionFor(user.Id);
        await Store.RevokeSessionAsync(revoked.Id, T0);
        var foreign = await NewSessionFor(other.Id);

        var now = T0.AddHours(1);
        var active = await Store.ListActiveSessionsAsync(user.Id, now);
        Assert.Equal([b.Id, a.Id], active.Select(s => s.Id)); // newest first
        Assert.Equal("203.0.113.7", active.Single(s => s.Id == a.Id).Ip);
        Assert.Null(active.Single(s => s.Id == b.Id).Ip);

        var counts = await Store.CountActiveSessionsAsync(now);
        Assert.Equal(2, counts[user.Id]);
        Assert.Equal(1, counts[other.Id]);

        Assert.Equal(a.Id, (await Store.GetSessionAsync(a.Id))!.Id);
        Assert.Equal(expired.UserId, (await Store.GetSessionAsync(expired.Id))!.UserId);
        Assert.Null(await Store.GetSessionAsync(-1));

        Assert.Equal(3, await Store.RevokeUserSessionsAsync(user.Id, now)); // a, b and the expired one
        Assert.Empty(await Store.ListActiveSessionsAsync(user.Id, now));
        Assert.False((await Store.CountActiveSessionsAsync(now)).ContainsKey(user.Id));
        Assert.Equal(now, (await Store.GetSessionAsync(a.Id))!.RevokedAt);
        Assert.Equal(T0, (await Store.GetSessionAsync(revoked.Id))!.RevokedAt); // already revoked: untouched
        Assert.Null((await Store.GetSessionAsync(foreign.Id))!.RevokedAt);
    }

    private static LoginEvent Event(long? userId, long? tg, DateTime at, string result = LoginResult.Ok) =>
        new() { UserId = userId, TelegramId = tg, At = at, Ip = "198.51.100.1", UserAgent = "ua", Result = result };

    [Fact]
    public async Task LoginEvents_AddList_PagesNewestFirst_FilterByUser()
    {
        var user = await NewUser();
        var ids = new List<long>();
        foreach (var result in new[] { LoginResult.Ok, LoginResult.DeniedBlocked, LoginResult.Ok })
            ids.Add(await Store.AddLoginEventAsync(Event(user.Id, user.TelegramId, T0, result)));
        var anonymous = await Store.AddLoginEventAsync(Event(null, null, T0, LoginResult.Invalid));

        var mine = await Store.ListLoginEventsAsync(user.Id, beforeId: null, limit: 10);
        Assert.Equal(ids.AsEnumerable().Reverse(), mine.Select(e => e.Id));
        var first = mine.Last();
        Assert.Equal((user.Id, user.TelegramId, T0, "198.51.100.1", "ua", LoginResult.Ok),
            (first.UserId!.Value, first.TelegramId!.Value, first.At, first.Ip, first.UserAgent, first.Result));
        Assert.Equal(LoginResult.DeniedBlocked, mine[1].Result);

        var page = await Store.ListLoginEventsAsync(user.Id, beforeId: ids[2], limit: 1);
        Assert.Equal([ids[1]], page.Select(e => e.Id));

        var all = await Store.ListLoginEventsAsync(null, beforeId: anonymous + 1, limit: 2);
        Assert.Equal([anonymous, ids[2]], all.Select(e => e.Id));
        Assert.Null(all[0].UserId);
        Assert.Null(all[0].TelegramId);
        Assert.Equal(LoginResult.Invalid, all[0].Result);
    }

    [Fact]
    public async Task LoginEvents_CountSince_OnlyGivenResult()
    {
        // A random far-future window: the MySQL contract shares one database between tests.
        var since = new DateTime(3000, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddDays(Random.Shared.Next(0, 1_500_000));
        await Store.AddLoginEventAsync(Event(null, null, since.AddMinutes(1)));
        await Store.AddLoginEventAsync(Event(null, null, since.AddMinutes(2)));
        await Store.AddLoginEventAsync(Event(null, null, since.AddMinutes(3), LoginResult.Invalid));
        await Store.AddLoginEventAsync(Event(null, null, since.AddMinutes(-1)));

        Assert.Equal(2, await Store.CountLoginEventsAsync(since, LoginResult.Ok));
        Assert.Equal(1, await Store.CountLoginEventsAsync(since, LoginResult.Invalid));
    }

    [Fact]
    public async Task LoginEvents_DeleteOlderThan()
    {
        var old = await Store.AddLoginEventAsync(Event(null, null, new DateTime(1990, 6, 1, 0, 0, 0, DateTimeKind.Utc)));
        var kept = await Store.AddLoginEventAsync(Event(null, null, new DateTime(1991, 6, 1, 0, 0, 0, DateTimeKind.Utc)));

        Assert.True(await Store.DeleteLoginEventsBeforeAsync(new DateTime(1991, 1, 1, 0, 0, 0, DateTimeKind.Utc)) >= 1);

        var remaining = (await Store.ListLoginEventsAsync(null, beforeId: kept + 1, limit: 500)).Select(e => e.Id).ToList();
        Assert.Contains(kept, remaining);
        Assert.DoesNotContain(old, remaining);
    }

    [Fact]
    public async Task LoginEvents_DeleteOlderThan_OnlyGivenResults()
    {
        var at = new DateTime(1985, 6, 1, 0, 0, 0, DateTimeKind.Utc);
        var invalid = await Store.AddLoginEventAsync(Event(null, null, at, LoginResult.Invalid));
        var replayed = await Store.AddLoginEventAsync(Event(null, null, at, LoginResult.Replayed));
        var ok = await Store.AddLoginEventAsync(Event(null, null, at));
        var denied = await Store.AddLoginEventAsync(Event(null, null, at, LoginResult.DeniedBlocked));

        Assert.True(await Store.DeleteLoginEventsBeforeAsync(at.AddDays(1), LoginResult.Invalid, LoginResult.Replayed) >= 2);

        var remaining = (await Store.ListLoginEventsAsync(null, beforeId: denied + 1, limit: 500)).Select(e => e.Id).ToList();
        Assert.Contains(ok, remaining);
        Assert.Contains(denied, remaining);
        Assert.DoesNotContain(invalid, remaining);
        Assert.DoesNotContain(replayed, remaining);
    }

    [Fact]
    public async Task LoginEvents_PerUser_NewestByTimeFirst_WithUserName()
    {
        var user = await NewUser(); // "Max" "V"
        var middle = await Store.AddLoginEventAsync(Event(user.Id, user.TelegramId, T0.AddMinutes(1)));
        var latest = await Store.AddLoginEventAsync(Event(user.Id, user.TelegramId, T0.AddMinutes(2)));
        var earliest = await Store.AddLoginEventAsync(Event(user.Id, user.TelegramId, T0));

        var mine = await Store.ListLoginEventsAsync(user.Id, beforeId: null, limit: 10);
        Assert.Equal([latest, middle, earliest], mine.Select(e => e.Id));
        Assert.All(mine, e => Assert.Equal("Max V", e.UserName));

        var anonymous = await Store.AddLoginEventAsync(Event(null, null, T0, LoginResult.Invalid));
        Assert.Null((await Store.ListLoginEventsAsync(null, beforeId: anonymous + 1, limit: 1)).Single().UserName);
    }

    [Fact]
    public async Task GetInviteByCodeHash_FindsInvite()
    {
        var (invite, app) = await NewInvite(maxUses: 3);
        var found = await Store.GetInviteByCodeHashAsync(invite.CodeHash);
        Assert.Equal((invite.Id, app.Id, 3, 0), (found!.Id, found.AppId, found.MaxUses, found.Uses));
        Assert.Null(await Store.GetInviteByCodeHashAsync(Hash()));
    }

    [Fact]
    public async Task DeleteInvite_RemovesIt()
    {
        var (invite, _) = await NewInvite();
        Assert.True(await Store.DeleteInviteAsync(invite.Id));
        Assert.DoesNotContain(await Store.ListInvitesAsync(), i => i.Id == invite.Id);
        Assert.False(await Store.DeleteInviteAsync(invite.Id));
    }
}

public class InMemoryAuthStoreTests : AuthStoreContractTests
{
    private readonly InMemoryAuthStore _store = new();

    protected override IAuthStore Store => _store;

    /// <summary>Same as the MySQL foreign keys (ON DELETE SET NULL on both columns).</summary>
    [Fact]
    public async Task DeleteUser_NullsUserAndTelegramIdInLoginEvents()
    {
        var user = await _store.UpsertUserAsync(new TelegramProfile(4242, "Max", null, null, null), T0);
        var id = await _store.AddLoginEventAsync(new LoginEvent { UserId = user.Id, TelegramId = 4242, At = T0 });

        _store.DeleteUser(user.Id);

        var e = (await _store.ListLoginEventsAsync(null, null, 10)).Single(x => x.Id == id);
        Assert.Null(e.UserId);
        Assert.Null(e.TelegramId);
    }
}
