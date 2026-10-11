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
            UserId = user.Id, FamilyId = Guid.NewGuid().ToString(), RefreshHash = Hash(),
            CreatedAt = T0, ExpiresAt = expiresAt ?? T0.AddDays(30), LastUsedAt = T0, UserAgent = "test",
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

        Assert.Equal(app.Id, await Store.RedeemInviteAsync(invite.CodeHash, first.Id, T0));
        Assert.Equal([app.Id], await Store.GetGrantsAsync(first.Id));

        Assert.Null(await Store.RedeemInviteAsync(invite.CodeHash, second.Id, T0));
        Assert.Empty(await Store.GetGrantsAsync(second.Id));
        Assert.Equal(1, (await Store.ListInvitesAsync()).Single(i => i.Id == invite.Id).Uses);
    }

    [Fact]
    public async Task RedeemInvite_AlreadyGranted_DoesNotConsumeUse()
    {
        var (invite, app) = await NewInvite(maxUses: 1);
        var user = await NewUser();
        await Store.AddGrantAsync(user.Id, app.Id, T0);

        Assert.Equal(app.Id, await Store.RedeemInviteAsync(invite.CodeHash, user.Id, T0));
        Assert.Equal(0, (await Store.ListInvitesAsync()).Single(i => i.Id == invite.Id).Uses);
    }

    [Fact]
    public async Task RedeemInvite_ExpiredOrUnknown_ReturnsNull()
    {
        var (invite, _) = await NewInvite(expiresAt: T0.AddHours(1));
        var user = await NewUser();

        Assert.Null(await Store.RedeemInviteAsync(invite.CodeHash, user.Id, T0.AddHours(1)));
        Assert.Null(await Store.RedeemInviteAsync(Hash(), user.Id, T0));
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
    protected override IAuthStore Store { get; } = new InMemoryAuthStore();
}
