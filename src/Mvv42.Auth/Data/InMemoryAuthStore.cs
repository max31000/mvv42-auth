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
    private readonly List<RefreshHistoryEntry> _history = [];
    private readonly List<Invite> _invites = [];
    private readonly List<LoginEvent> _loginEvents = [];
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

    /// <summary>Tests only: deletes a user with their grants, sessions and history (FK cascades in MySQL).</summary>
    internal void DeleteUser(long id) => Locked(() =>
    {
        var sessions = _sessions.Where(s => s.UserId == id).Select(s => s.Id).ToHashSet();
        _history.RemoveAll(h => sessions.Contains(h.SessionId));
        _sessions.RemoveAll(s => s.UserId == id);
        _grants.RemoveAll(g => g.UserId == id);
        for (var i = 0; i < _loginEvents.Count; i++) // ON DELETE SET NULL in MySQL
            if (_loginEvents[i].UserId == id)
                _loginEvents[i] = _loginEvents[i] with { UserId = null, TelegramId = null };
        return _users.RemoveAll(u => u.Id == id);
    });

    public Task<User?> GetUserAsync(long id) => Run(() => _users.FirstOrDefault(u => u.Id == id));

    public Task<User?> GetUserByTelegramIdAsync(long telegramId) => Run(() => _users.FirstOrDefault(u => u.TelegramId == telegramId));

    public Task<bool> SetUserBlockedAsync(long id, bool blocked, DateTime now) => Run(() =>
    {
        var index = _users.FindIndex(u => u.Id == id);
        if (index < 0) return false;
        var user = _users[index];
        _users[index] = user with { IsBlocked = blocked, BlockedAt = blocked ? user.BlockedAt ?? now : null };
        return true;
    });

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
        _history.Add(new RefreshHistoryEntry
        {
            Hash = expectedHash,
            FamilyId = _sessions[index].FamilyId,
            SessionId = id,
            RotatedAt = rotatedAt,
        });
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

    public Task<RefreshHistoryEntry?> GetRefreshHistoryAsync(string refreshHash) =>
        Run(() => _history.FirstOrDefault(h => h.Hash == refreshHash));

    public Task RevokeFamilyAsync(string familyId, DateTime now) => Run(() => Revoke(s => s.FamilyId == familyId, now));

    public Task RevokeSessionAsync(long id, DateTime now) => Run(() => Revoke(s => s.Id == id, now));

    private int Revoke(Predicate<Session> match, DateTime now)
    {
        var count = 0;
        for (var i = 0; i < _sessions.Count; i++)
        {
            if (match(_sessions[i]) && _sessions[i].RevokedAt is null)
            {
                _sessions[i] = _sessions[i] with { RevokedAt = now };
                count++;
            }
        }
        return count;
    }

    public Task<Session?> GetSessionAsync(long id) => Run(() => _sessions.FirstOrDefault(s => s.Id == id));

    public Task<int> RevokeUserSessionsAsync(long userId, DateTime now) => Run(() => Revoke(s => s.UserId == userId, now));

    private static bool IsActive(Session s, DateTime now) => s.RevokedAt is null && s.ExpiresAt > now;

    public Task<IReadOnlyList<Session>> ListActiveSessionsAsync(long userId, DateTime now) => Run(() =>
        (IReadOnlyList<Session>)_sessions.Where(s => s.UserId == userId && IsActive(s, now)).OrderByDescending(s => s.Id).ToList());

    public Task<IReadOnlyDictionary<long, int>> CountActiveSessionsAsync(DateTime now) => Run(() =>
        (IReadOnlyDictionary<long, int>)_sessions.Where(s => IsActive(s, now)).GroupBy(s => s.UserId).ToDictionary(g => g.Key, g => g.Count()));

    public Task<int> DeleteStaleSessionsAsync(DateTime now, DateTime revokedBefore) => Run(() =>
    {
        var stale = _sessions.Where(s => s.ExpiresAt < now || s.RevokedAt < revokedBefore).Select(s => s.Id).ToHashSet();
        _history.RemoveAll(h => stale.Contains(h.SessionId)); // ON DELETE CASCADE in MySQL
        return _sessions.RemoveAll(s => stale.Contains(s.Id));
    });

    public Task<long> CreateInviteAsync(Invite invite) => Run(() =>
    {
        var id = _nextId++;
        _invites.Add(invite with { Id = id, Uses = 0 });
        return id;
    });

    public Task<IReadOnlyList<Invite>> ListInvitesAsync() => Run(() => (IReadOnlyList<Invite>)_invites.ToList());

    public Task<Invite?> GetInviteByCodeHashAsync(string codeHash) => Run(() => _invites.FirstOrDefault(i => i.CodeHash == codeHash));

    public Task<bool> DeleteInviteAsync(long id) => Run(() => _invites.RemoveAll(i => i.Id == id) > 0);

    public Task<InviteRedeemResult> RedeemInviteAsync(string codeHash, long userId, DateTime now) => Run(() =>
    {
        var index = _invites.FindIndex(i => i.CodeHash == codeHash);
        if (index < 0) return new InviteRedeemResult(InviteRedeemStatus.NotFound, null);
        var invite = _invites[index];
        if (invite.AppId is null || _grants.Any(g => g.UserId == userId && g.AppId == invite.AppId))
            return new InviteRedeemResult(InviteRedeemStatus.AlreadyGranted, invite.AppId);
        if (invite.ExpiresAt <= now) return new InviteRedeemResult(InviteRedeemStatus.Expired, invite.AppId);
        if (invite.Uses >= invite.MaxUses) return new InviteRedeemResult(InviteRedeemStatus.Exhausted, invite.AppId);

        _invites[index] = invite with { Uses = invite.Uses + 1 };
        AddGrant(userId, invite.AppId, now);
        return new InviteRedeemResult(InviteRedeemStatus.Granted, invite.AppId);
    });

    public Task<InviteRegistrationResult> RegisterWithInviteAsync(TelegramProfile p, IReadOnlyList<string> codeHashes, DateTime now) => Run(() =>
    {
        var index = codeHashes.Select(h => _invites.FindIndex(i => i.CodeHash == h)).FirstOrDefault(i => i >= 0, -1);
        if (index < 0) return new InviteRegistrationResult(InviteRegistrationStatus.NotFound, null, null);
        var invite = _invites[index];
        if (invite.ExpiresAt <= now) return new InviteRegistrationResult(InviteRegistrationStatus.Expired, null, null);
        if (invite.Uses >= invite.MaxUses) return new InviteRegistrationResult(InviteRegistrationStatus.Exhausted, null, null);
        if (_users.Any(u => u.TelegramId == p.TelegramId))
            return new InviteRegistrationResult(InviteRegistrationStatus.AlreadyRegistered, null, null);

        var user = new User
        {
            Id = _nextId++,
            TelegramId = p.TelegramId,
            FirstName = p.FirstName,
            LastName = p.LastName,
            Username = p.Username,
            PhotoUrl = p.PhotoUrl,
            CreatedAt = now,
            LastLoginAt = now,
        };
        _users.Add(user);
        _invites[index] = invite with { Uses = invite.Uses + 1 };
        if (invite.AppId is not null)
            AddGrant(user.Id, invite.AppId, now);
        return new InviteRegistrationResult(InviteRegistrationStatus.Registered, user, invite.AppId);
    });

    public Task<long> AddLoginEventAsync(LoginEvent loginEvent) => Run(() =>
    {
        var id = _nextId++;
        _loginEvents.Add(loginEvent with { Id = id });
        return id;
    });

    public Task<IReadOnlyList<LoginEvent>> ListLoginEventsAsync(long? userId, long? beforeId, int limit) => Run(() =>
    {
        var rows = _loginEvents.Where(e => (userId is null || e.UserId == userId) && (beforeId is null || e.Id < beforeId));
        var ordered = userId is null
            ? rows.OrderByDescending(e => e.Id)
            : rows.OrderByDescending(e => e.At).ThenByDescending(e => e.Id);
        return (IReadOnlyList<LoginEvent>)ordered
            .Take(limit)
            .Select(e => e with { UserName = _users.FirstOrDefault(u => u.Id == e.UserId)?.DisplayName })
            .ToList();
    });

    public Task<int> CountLoginEventsAsync(DateTime since, string result) =>
        Run(() => _loginEvents.Count(e => e.At >= since && e.Result == result));

    public Task<int> DeleteLoginEventsBeforeAsync(DateTime cutoff, params string[] results) =>
        Run(() => _loginEvents.RemoveAll(e => e.At < cutoff && (results.Length == 0 || results.Contains(e.Result))));
}
