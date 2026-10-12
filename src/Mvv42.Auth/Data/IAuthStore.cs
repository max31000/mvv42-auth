using Mvv42.Auth.Telegram;

namespace Mvv42.Auth.Data;

public interface IAuthStore
{
    // Users
    /// <summary>Creates the user on first login or refreshes the profile; sets last_login_at.</summary>
    Task<User> UpsertUserAsync(TelegramProfile profile, DateTime now);
    Task<User?> GetUserAsync(long id);
    Task<User?> GetUserByTelegramIdAsync(long telegramId);
    Task<IReadOnlyList<User>> ListUsersAsync();
    Task<bool> SetUserAdminAsync(long id, bool isAdmin);
    /// <summary>
    /// Block: <c>is_blocked</c> = 1 and <c>blocked_at</c> = <paramref name="now"/> (kept if already blocked);
    /// unblock clears both. Sessions are not touched (see <see cref="RevokeUserSessionsAsync"/>). false = no such user.
    /// </summary>
    Task<bool> SetUserBlockedAsync(long id, bool blocked, DateTime now);

    // Apps
    Task<IReadOnlyList<App>> GetAppsAsync();
    Task UpsertAppAsync(App app);
    /// <summary>Deletes the app with its grants and invites.</summary>
    Task<bool> DeleteAppAsync(string id);

    // Grants
    Task<IReadOnlyList<string>> GetGrantsAsync(long userId);
    Task<IReadOnlyList<Grant>> ListGrantsAsync(long? userId);
    /// <summary>Idempotent.</summary>
    Task AddGrantAsync(long userId, string appId, DateTime now);
    Task<bool> RemoveGrantAsync(long userId, string appId);

    // Sessions
    Task<long> CreateSessionAsync(Session session);
    /// <summary>Finds a session whose current OR previous refresh hash matches.</summary>
    Task<Session?> GetSessionByRefreshHashAsync(string refreshHash);
    /// <summary>
    /// Rotates only if the current hash is still <paramref name="expectedHash"/> (optimistic concurrency):
    /// prev = expected, current = new, rotated_at = last_used_at = <paramref name="rotatedAt"/>; in the same
    /// transaction <paramref name="expectedHash"/> is recorded in the refresh-token history.
    /// </summary>
    Task<bool> UpdateSessionRotationAsync(long id, string expectedHash, string newHash, DateTime rotatedAt, DateTime expiresAt);
    /// <summary>A hash that was rotated away (any generation), or null.</summary>
    Task<RefreshHistoryEntry?> GetRefreshHistoryAsync(string refreshHash);
    Task RevokeFamilyAsync(string familyId, DateTime now);
    Task RevokeSessionAsync(long id, DateTime now);
    Task<Session?> GetSessionAsync(long id);
    /// <summary>Revokes every not yet revoked session of the user; returns how many were revoked.</summary>
    Task<int> RevokeUserSessionsAsync(long userId, DateTime now);
    /// <summary>Not revoked and not expired at <paramref name="now"/>, newest first.</summary>
    Task<IReadOnlyList<Session>> ListActiveSessionsAsync(long userId, DateTime now);
    /// <summary>Active session count per user (users without active sessions are absent).</summary>
    Task<IReadOnlyDictionary<long, int>> CountActiveSessionsAsync(DateTime now);
    /// <summary>
    /// Deletes sessions expired before <paramref name="now"/> or revoked before <paramref name="revokedBefore"/>,
    /// together with their refresh-token history.
    /// </summary>
    Task<int> DeleteStaleSessionsAsync(DateTime now, DateTime revokedBefore);

    // Invites
    Task<long> CreateInviteAsync(Invite invite);
    Task<IReadOnlyList<Invite>> ListInvitesAsync();
    Task<Invite?> GetInviteByCodeHashAsync(string codeHash);
    /// <summary>One lookup (<c>code_hash IN (…)</c>); of several matches the earliest in <paramref name="codeHashes"/> wins.</summary>
    Task<Invite?> FindInviteAsync(IReadOnlyList<string> codeHashes);
    Task<bool> DeleteInviteAsync(long id);
    /// <summary>
    /// Atomically: valid (not expired, uses &lt; max_uses) → uses+1 and grant (<see cref="InviteRedeemStatus.Granted"/>).
    /// A user who already has the grant, or a login-only invite (no app), gets <see cref="InviteRedeemStatus.AlreadyGranted"/>
    /// without consuming a use.
    /// </summary>
    Task<InviteRedeemResult> RedeemInviteAsync(string codeHash, long userId, DateTime now);

    /// <summary>
    /// Closed registration, one transaction: invites matching <paramref name="codeHashes"/> row-locked in one
    /// <c>SELECT … WHERE code_hash IN (…) FOR UPDATE</c>, the earliest candidate wins →
    /// expiry/uses check → plain INSERT of the user (created_at = last_login_at = <paramref name="now"/>) → uses+1 → grant of
    /// the invite's app (if any). A duplicate telegram id rolls everything back (<see cref="InviteRegistrationStatus.AlreadyRegistered"/>,
    /// the use is not consumed); refusals store nothing.
    /// </summary>
    Task<InviteRegistrationResult> RegisterWithInviteAsync(TelegramProfile profile, IReadOnlyList<string> codeHashes, DateTime now);

    // Login events
    Task<long> AddLoginEventAsync(LoginEvent loginEvent);
    /// <summary>
    /// Newest first with <see cref="LoginEvent.UserName"/> filled: the whole journal by id (keyset paging,
    /// <paramref name="beforeId"/> = exclusive upper bound); one user's events by time, then id.
    /// </summary>
    Task<IReadOnlyList<LoginEvent>> ListLoginEventsAsync(long? userId, long? beforeId, int limit);
    Task<int> CountLoginEventsAsync(DateTime since, string result);
    /// <summary>Deletes events older than <paramref name="cutoff"/>; only with the given results when any are given.</summary>
    Task<int> DeleteLoginEventsBeforeAsync(DateTime cutoff, params string[] results);
}
