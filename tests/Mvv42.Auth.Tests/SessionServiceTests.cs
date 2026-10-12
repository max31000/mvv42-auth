using Microsoft.Extensions.Logging.Abstractions;
using Mvv42.Auth.Data;
using Mvv42.Auth.Options;
using Mvv42.Auth.Sessions;
using Mvv42.Auth.Telegram;

namespace Mvv42.Auth.Tests;

public class SessionServiceTests
{
    private readonly FakeTime _time = new(new DateTimeOffset(2026, 10, 11, 12, 0, 0, TimeSpan.Zero));
    private readonly InMemoryAuthStore _store = new();
    private readonly SessionService _sessions;
    private readonly long _userId;

    public SessionServiceTests()
    {
        _sessions = new SessionService(_store, Microsoft.Extensions.Options.Options.Create(new AuthOptions()), _time);
        _userId = _store.UpsertUserAsync(new TelegramProfile(42, "Max", null, null, null), _time.GetUtcNow().UtcDateTime).Result.Id;
    }

    private DateTime Now => _time.GetUtcNow().UtcDateTime;

    [Fact]
    public async Task Create_StoresOnlyHash_With30DayExpiry()
    {
        var (session, token) = await _sessions.CreateAsync(_userId, "ua");

        Assert.Equal(43, token.Length); // 32 random bytes, base64url
        var stored = await _store.GetSessionByRefreshHashAsync(SessionService.Hash(token));
        Assert.NotNull(stored);
        Assert.NotEqual(token, stored.RefreshHash);
        Assert.Equal(session.Id, stored.Id);
        Assert.Equal(Now.AddDays(30), stored.ExpiresAt);
        Assert.Equal("ua", stored.UserAgent);
    }

    [Fact]
    public async Task Refresh_Rotates_AndOldTokenBecomesPrevious()
    {
        var (_, token) = await _sessions.CreateAsync(_userId, null);
        _time.Advance(TimeSpan.FromDays(1));

        var result = await _sessions.RefreshAsync(token);

        Assert.Equal(RefreshStatus.Rotated, result.Status);
        Assert.NotNull(result.NewRefreshToken);
        Assert.NotEqual(token, result.NewRefreshToken);
        Assert.Equal(_userId, result.Session!.UserId);
        Assert.Equal(Now.AddDays(30), result.Session.ExpiresAt);
        var stored = await _store.GetSessionByRefreshHashAsync(SessionService.Hash(result.NewRefreshToken));
        Assert.Equal(SessionService.Hash(token), stored!.PrevRefreshHash);
    }

    [Fact]
    public async Task Refresh_WithPreviousToken_Within30s_IsBenignRace()
    {
        var (_, token) = await _sessions.CreateAsync(_userId, null);
        var rotated = await _sessions.RefreshAsync(token);
        _time.Advance(TimeSpan.FromSeconds(29));

        var race = await _sessions.RefreshAsync(token);

        Assert.Equal(RefreshStatus.Grace, race.Status);
        Assert.Null(race.NewRefreshToken);
        Assert.Equal(_userId, race.Session!.UserId);
        // the winner's token keeps working
        Assert.Equal(RefreshStatus.Rotated, (await _sessions.RefreshAsync(rotated.NewRefreshToken!)).Status);
    }

    [Fact]
    public async Task Refresh_WithPreviousToken_After30s_RevokesFamily()
    {
        var (_, token) = await _sessions.CreateAsync(_userId, null);
        var rotated = await _sessions.RefreshAsync(token);
        _time.Advance(TimeSpan.FromSeconds(31));

        Assert.Equal(RefreshStatus.Reused, (await _sessions.RefreshAsync(token)).Status);
        Assert.Equal(RefreshStatus.Invalid, (await _sessions.RefreshAsync(rotated.NewRefreshToken!)).Status);
    }

    [Fact]
    public async Task Refresh_WithTokenOlderThanPrevious_IsReuse_AndRevokesFamily()
    {
        var (_, t0) = await _sessions.CreateAsync(_userId, null);
        _time.Advance(TimeSpan.FromMinutes(10));
        var t1 = (await _sessions.RefreshAsync(t0)).NewRefreshToken!;
        _time.Advance(TimeSpan.FromMinutes(10));
        var t2 = (await _sessions.RefreshAsync(t1)).NewRefreshToken!;

        // t0 is neither current nor previous any more: only the history knows it
        Assert.Equal(RefreshStatus.Reused, (await _sessions.RefreshAsync(t0)).Status);
        Assert.Equal(RefreshStatus.Invalid, (await _sessions.RefreshAsync(t2)).Status);
    }

    [Fact]
    public async Task Refresh_WithAncientToken_IsReuse_EvenRightAfterRotation()
    {
        var (_, t0) = await _sessions.CreateAsync(_userId, null);
        var t1 = (await _sessions.RefreshAsync(t0)).NewRefreshToken!;
        var t2 = (await _sessions.RefreshAsync(t1)).NewRefreshToken!;

        // grace covers only the immediately previous token
        Assert.Equal(RefreshStatus.Reused, (await _sessions.RefreshAsync(t0)).Status);
        Assert.Equal(RefreshStatus.Invalid, (await _sessions.RefreshAsync(t2)).Status);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-known-token")]
    public async Task Refresh_UnknownToken_IsInvalid(string? token)
    {
        Assert.Equal(RefreshStatus.Invalid, (await _sessions.RefreshAsync(token)).Status);
    }

    [Fact]
    public async Task Refresh_AfterSlidingExpiry_IsInvalid()
    {
        var (_, token) = await _sessions.CreateAsync(_userId, null);
        _time.Advance(TimeSpan.FromDays(30) + TimeSpan.FromSeconds(1));
        Assert.Equal(RefreshStatus.Invalid, (await _sessions.RefreshAsync(token)).Status);
    }

    [Fact]
    public async Task Family_HasAbsolute90DayLifetime()
    {
        var created = Now;
        var (_, token) = await _sessions.CreateAsync(_userId, null);

        for (var day = 20; day <= 80; day += 20)
        {
            _time.Advance(TimeSpan.FromDays(20));
            var result = await _sessions.RefreshAsync(token);
            Assert.Equal(RefreshStatus.Rotated, result.Status);
            token = result.NewRefreshToken!;
            Assert.True(result.Session!.ExpiresAt <= created.AddDays(90));
        }

        Assert.Equal(created.AddDays(90), (await _store.GetSessionByRefreshHashAsync(SessionService.Hash(token)))!.ExpiresAt);
        _time.Advance(TimeSpan.FromDays(10)); // day 90
        Assert.Equal(RefreshStatus.Invalid, (await _sessions.RefreshAsync(token)).Status);
    }

    [Fact]
    public async Task Revoke_InvalidatesSession_AndGraceDoesNotApply()
    {
        var (_, token) = await _sessions.CreateAsync(_userId, null);
        var rotated = await _sessions.RefreshAsync(token);

        await _sessions.RevokeAsync(rotated.NewRefreshToken);

        Assert.Equal(RefreshStatus.Invalid, (await _sessions.RefreshAsync(rotated.NewRefreshToken!)).Status);
        Assert.Equal(RefreshStatus.Invalid, (await _sessions.RefreshAsync(token)).Status);
    }

    [Fact]
    public async Task Cleanup_DeletesExpiredSessions()
    {
        var (_, expired) = await _sessions.CreateAsync(_userId, null);
        _time.Advance(TimeSpan.FromDays(31));
        var (_, alive) = await _sessions.CreateAsync(_userId, null);

        var cleanup = new SessionCleanupService(_store, _time, NullLogger<SessionCleanupService>.Instance);
        await cleanup.CleanupOnceAsync();

        Assert.Null(await _store.GetSessionByRefreshHashAsync(SessionService.Hash(expired)));
        Assert.NotNull(await _store.GetSessionByRefreshHashAsync(SessionService.Hash(alive)));
    }

    [Fact]
    public async Task Cleanup_DeletesLoginEventsOlderThan180Days()
    {
        var old = await _store.AddLoginEventAsync(new LoginEvent { At = Now.AddDays(-181), Result = LoginResult.Ok });
        var recent = await _store.AddLoginEventAsync(new LoginEvent { At = Now.AddDays(-179), Result = LoginResult.Ok });

        await new SessionCleanupService(_store, _time, NullLogger<SessionCleanupService>.Instance).CleanupOnceAsync();

        var left = (await _store.ListLoginEventsAsync(null, null, 10)).Select(e => e.Id).ToList();
        Assert.Contains(recent, left);
        Assert.DoesNotContain(old, left);
    }

    [Fact]
    public async Task Cleanup_DeletesInvalidReplayedUnregisteredAfter7Days_KeepsOkAndBlocked()
    {
        var ids = new Dictionary<string, long>();
        foreach (var result in new[] { LoginResult.Ok, LoginResult.DeniedBlocked, LoginResult.Invalid, LoginResult.Replayed, LoginResult.DeniedUnregistered })
            ids[result] = await _store.AddLoginEventAsync(new LoginEvent { At = Now.AddDays(-8), Result = result });
        var freshInvalid = await _store.AddLoginEventAsync(new LoginEvent { At = Now.AddDays(-6), Result = LoginResult.Invalid });
        var freshUnregistered = await _store.AddLoginEventAsync(new LoginEvent { At = Now.AddDays(-6), Result = LoginResult.DeniedUnregistered });

        await new SessionCleanupService(_store, _time, NullLogger<SessionCleanupService>.Instance).CleanupOnceAsync();

        var left = (await _store.ListLoginEventsAsync(null, null, 10)).Select(e => e.Id).ToHashSet();
        Assert.Equal(new HashSet<long> { ids[LoginResult.Ok], ids[LoginResult.DeniedBlocked], freshInvalid, freshUnregistered }, left);
    }
}
