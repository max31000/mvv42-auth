using Mvv42.Auth.Telegram;

namespace Mvv42.Auth.Data;

/// <summary>
/// Thread-safe in-memory store for tests and for running locally without MySQL (Development only).
/// Seeds the same apps as 001_init.sql.
/// </summary>
public sealed class InMemoryAuthStore : IAuthStore
{
    private readonly object _lock = new();
    private readonly List<User> _users = [];
    private readonly List<App> _apps =
    [
        new() { Id = "cashpulse", Name = "CashPulse", Anonymous = false, Access = AppAccess.Public },
        new() { Id = "credit_calc", Name = "Кредитный калькулятор", Anonymous = true, Access = AppAccess.Public },
        new() { Id = "bonds", Name = "Облигации", Anonymous = false, Access = AppAccess.Admin },
    ];
    private readonly List<Grant> _grants = [];
    private readonly List<Session> _sessions = [];
    private readonly List<Invite> _invites = [];
    private long _nextId = 1;

    private T Locked<T>(Func<T> action)
    {
        lock (_lock) return action();
    }

    private Task<T> Run<T>(Func<T> action) => Task.FromResult(Locked(action));

    public Task<User> UpsertUserAsync(TelegramProfile p, DateTime now) => Run(() =>
    {
        var index = _users.FindIndex(u => u.TelegramId == p.TelegramId);
        var existing = index >= 0 ? _users[index] : new User { Id = _nextId++, TelegramId = p.TelegramId, CreatedAt = now };
        var user = existing with
        {
            FirstName = p.FirstName,
            LastName = p.LastName,
            Username = p.Username,
            PhotoUrl = p.PhotoUrl,
            LastLoginAt = now,
        };
        if (index >= 0) _users[index] = user; else _users.Add(user);
        return user;
    });

    public Task<User?> GetUserAsync(long id) => Run(() => _users.FirstOrDefault(u => u.Id == id));

    public Task<IReadOnlyList<User>> ListUsersAsync() => Run(() => (IReadOnlyList<User>)_users.OrderBy(u => u.Id).ToList());

    public Task<bool> SetUserAdminAsync(long id, bool isAdmin) => Run(() =>
    {
        var index = _users.FindIndex(u => u.Id == id);
        if (index < 0) return false;
        _users[index] = _users[index] with { IsAdmin = isAdmin };
        return true;
    });

    public Task<IReadOnlyList<App>> GetAppsAsync() => Run(() => (IReadOnlyList<App>)_apps.OrderBy(a => a.Id, StringComparer.Ordinal).ToList());

    public Task UpsertAppAsync(App app) => Run(() =>
    {
        _apps.RemoveAll(a => a.Id == app.Id);
        _apps.Add(app);
        return true;
    });

    public Task<bool> DeleteAppAsync(string id) => Run(() =>
    {
        _grants.RemoveAll(g => g.AppId == id);
        _invites.RemoveAll(i => i.AppId == id);
        return _apps.RemoveAll(a => a.Id == id) > 0;
    });

    public Task<IReadOnlyList<string>> GetGrantsAsync(long userId) =>
        Run(() => (IReadOnlyList<string>)_grants.Where(g => g.UserId == userId).Select(g => g.AppId).Order(StringComparer.Ordinal).ToList());

    public Task<IReadOnlyList<Grant>> ListGrantsAsync(long? userId) =>
        Run(() => (IReadOnlyList<Grant>)_grants.Where(g => userId is null || g.UserId == userId).ToList());

    public Task AddGrantAsync(long userId, string appId, DateTime now) => Run(() => AddGrant(userId, appId, now));

    private bool AddGrant(long userId, string appId, DateTime now)
    {
        if (_grants.Any(g => g.UserId == userId && g.AppId == appId)) return false;
        _grants.Add(new Grant { UserId = userId, AppId = appId, CreatedAt = now });
        return true;
    }

    public Task<bool> RemoveGrantAsync(long userId, string appId) =>
        Run(() => _grants.RemoveAll(g => g.UserId == userId && g.AppId == appId) > 0);

    public Task<long> CreateSessionAsync(Session session) => Run(() =>
    {
        var id = _nextId++;
        _sessions.Add(session with { Id = id });
        return id;
    });

    public Task<Session?> GetSessionByRefreshHashAsync(string hash) =>
        Run(() => _sessions.FirstOrDefault(s => s.RefreshHash == hash || s.PrevRefreshHash == hash));

    public Task<bool> UpdateSessionRotationAsync(long id, string expectedHash, string newHash, DateTime rotatedAt, DateTime expiresAt) => Run(() =>
    {
        var index = _sessions.FindIndex(s => s.Id == id && s.RefreshHash == expectedHash);
        if (index < 0) return false;
        _sessions[index] = _sessions[index] with
        {
            PrevRefreshHash = expectedHash,
            RefreshHash = newHash,
            RotatedAt = rotatedAt,
            LastUsedAt = rotatedAt,
            ExpiresAt = expiresAt,
        };
        return true;
    });

    public Task RevokeFamilyAsync(string familyId, DateTime now) => Run(() => Revoke(s => s.FamilyId == familyId, now));

    public Task RevokeSessionAsync(long id, DateTime now) => Run(() => Revoke(s => s.Id == id, now));

    private bool Revoke(Predicate<Session> match, DateTime now)
    {
        for (var i = 0; i < _sessions.Count; i++)
            if (match(_sessions[i]) && _sessions[i].RevokedAt is null)
                _sessions[i] = _sessions[i] with { RevokedAt = now };
        return true;
    }

    public Task<int> DeleteStaleSessionsAsync(DateTime now, DateTime revokedBefore) =>
        Run(() => _sessions.RemoveAll(s => s.ExpiresAt < now || s.RevokedAt < revokedBefore));

    public Task<long> CreateInviteAsync(Invite invite) => Run(() =>
    {
        var id = _nextId++;
        _invites.Add(invite with { Id = id, Uses = 0 });
        return id;
    });

    public Task<IReadOnlyList<Invite>> ListInvitesAsync() => Run(() => (IReadOnlyList<Invite>)_invites.ToList());

    public Task<bool> DeleteInviteAsync(long id) => Run(() => _invites.RemoveAll(i => i.Id == id) > 0);

    public Task<string?> RedeemInviteAsync(string codeHash, long userId, DateTime now) => Run(() =>
    {
        var index = _invites.FindIndex(i => i.CodeHash == codeHash);
        if (index < 0) return null;
        var invite = _invites[index];
        if (_grants.Any(g => g.UserId == userId && g.AppId == invite.AppId)) return invite.AppId;
        if (invite.Uses >= invite.MaxUses || invite.ExpiresAt <= now) return null;

        _invites[index] = invite with { Uses = invite.Uses + 1 };
        AddGrant(userId, invite.AppId, now);
        return (string?)invite.AppId;
    });
}
