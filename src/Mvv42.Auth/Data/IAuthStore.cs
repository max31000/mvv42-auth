using Mvv42.Auth.Telegram;

namespace Mvv42.Auth.Data;

public interface IAuthStore
{
    // Users
    /// <summary>Creates the user on first login or refreshes the profile; sets last_login_at.</summary>
    Task<User> UpsertUserAsync(TelegramProfile profile, DateTime now);
    Task<User?> GetUserAsync(long id);
    Task<IReadOnlyList<User>> ListUsersAsync();
    Task<bool> SetUserAdminAsync(long id, bool isAdmin);

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
    /// prev = expected, current = new, rotated_at = last_used_at = <paramref name="rotatedAt"/>.
    /// </summary>
    Task<bool> UpdateSessionRotationAsync(long id, string expectedHash, string newHash, DateTime rotatedAt, DateTime expiresAt);
    Task RevokeFamilyAsync(string familyId, DateTime now);
    Task RevokeSessionAsync(long id, DateTime now);
    /// <summary>Deletes sessions expired before <paramref name="now"/> or revoked before <paramref name="revokedBefore"/>.</summary>
    Task<int> DeleteStaleSessionsAsync(DateTime now, DateTime revokedBefore);

    // Invites
    Task<long> CreateInviteAsync(Invite invite);
    Task<IReadOnlyList<Invite>> ListInvitesAsync();
    Task<bool> DeleteInviteAsync(long id);
    /// <summary>
    /// Atomically: valid (not expired, uses &lt; max_uses) → uses+1 and grant; returns the app id.
    /// A user who already has the grant gets the app id back without consuming a use. Invalid → null.
    /// </summary>
    Task<string?> RedeemInviteAsync(string codeHash, long userId, DateTime now);
}
