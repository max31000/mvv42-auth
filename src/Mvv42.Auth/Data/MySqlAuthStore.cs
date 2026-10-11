using Dapper;
using Mvv42.Auth.Telegram;
using MySqlConnector;

namespace Mvv42.Auth.Data;

/// <summary>Dapper + MySqlConnector implementation. One short-lived connection per call (pooled).</summary>
public sealed class MySqlAuthStore(string connectionString) : IAuthStore
{
    private const string UserColumns =
        "id, telegram_id, username, first_name, last_name, photo_url, is_admin, created_at, last_login_at";
    private const string SessionColumns =
        "id, user_id, family_id, refresh_hash, prev_refresh_hash, rotated_at, created_at, expires_at, last_used_at, revoked_at, user_agent";
    private const string InviteColumns =
        "id, code_hash, app_id, max_uses, uses, expires_at, created_by, created_at";

    static MySqlAuthStore() => DefaultTypeMap.MatchNamesWithUnderscores = true;

    private async Task<MySqlConnection> OpenAsync()
    {
        var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync();
        return conn;
    }

    // ---- users

    public async Task<User> UpsertUserAsync(TelegramProfile p, DateTime now)
    {
        await using var conn = await OpenAsync();
        await conn.ExecuteAsync("""
            INSERT INTO users (telegram_id, username, first_name, last_name, photo_url, created_at, last_login_at)
            VALUES (@TelegramId, @Username, @FirstName, @LastName, @PhotoUrl, @now, @now)
            ON DUPLICATE KEY UPDATE
                username = VALUES(username), first_name = VALUES(first_name), last_name = VALUES(last_name),
                photo_url = VALUES(photo_url), last_login_at = VALUES(last_login_at)
            """, new { p.TelegramId, p.Username, p.FirstName, p.LastName, p.PhotoUrl, now });
        return await conn.QuerySingleAsync<User>(
            $"SELECT {UserColumns} FROM users WHERE telegram_id = @TelegramId", new { p.TelegramId });
    }

    public async Task<User?> GetUserAsync(long id)
    {
        await using var conn = await OpenAsync();
        return await conn.QuerySingleOrDefaultAsync<User>($"SELECT {UserColumns} FROM users WHERE id = @id", new { id });
    }

    public async Task<IReadOnlyList<User>> ListUsersAsync()
    {
        await using var conn = await OpenAsync();
        return (await conn.QueryAsync<User>($"SELECT {UserColumns} FROM users ORDER BY id")).AsList();
    }

    public async Task<bool> SetUserAdminAsync(long id, bool isAdmin)
    {
        await using var conn = await OpenAsync();
        // FOUND_ROWS semantics: MySqlConnector defaults UseAffectedRows=false, so an unchanged row still counts.
        return await conn.ExecuteAsync("UPDATE users SET is_admin = @isAdmin WHERE id = @id", new { id, isAdmin }) > 0;
    }

    // ---- apps

    public async Task<IReadOnlyList<App>> GetAppsAsync()
    {
        await using var conn = await OpenAsync();
        return (await conn.QueryAsync<App>("SELECT id, name, anonymous, access FROM apps ORDER BY id")).AsList();
    }

    public async Task UpsertAppAsync(App app)
    {
        await using var conn = await OpenAsync();
        await conn.ExecuteAsync("""
            INSERT INTO apps (id, name, anonymous, access) VALUES (@Id, @Name, @Anonymous, @Access)
            ON DUPLICATE KEY UPDATE name = VALUES(name), anonymous = VALUES(anonymous), access = VALUES(access)
            """, app);
    }

    public async Task<bool> DeleteAppAsync(string id)
    {
        await using var conn = await OpenAsync();
        // app_grants and invites go away via ON DELETE CASCADE.
        return await conn.ExecuteAsync("DELETE FROM apps WHERE id = @id", new { id }) > 0;
    }

    // ---- grants

    public async Task<IReadOnlyList<string>> GetGrantsAsync(long userId)
    {
        await using var conn = await OpenAsync();
        return (await conn.QueryAsync<string>(
            "SELECT app_id FROM app_grants WHERE user_id = @userId ORDER BY app_id", new { userId })).AsList();
    }

    public async Task<IReadOnlyList<Grant>> ListGrantsAsync(long? userId)
    {
        await using var conn = await OpenAsync();
        return (await conn.QueryAsync<Grant>(
            "SELECT user_id, app_id, created_at FROM app_grants WHERE @userId IS NULL OR user_id = @userId ORDER BY user_id, app_id",
            new { userId })).AsList();
    }

    public async Task AddGrantAsync(long userId, string appId, DateTime now)
    {
        await using var conn = await OpenAsync();
        await conn.ExecuteAsync(
            "INSERT IGNORE INTO app_grants (user_id, app_id, created_at) VALUES (@userId, @appId, @now)",
            new { userId, appId, now });
    }

    public async Task<bool> RemoveGrantAsync(long userId, string appId)
    {
        await using var conn = await OpenAsync();
        return await conn.ExecuteAsync(
            "DELETE FROM app_grants WHERE user_id = @userId AND app_id = @appId", new { userId, appId }) > 0;
    }

    // ---- sessions

    public async Task<long> CreateSessionAsync(Session s)
    {
        await using var conn = await OpenAsync();
        return await conn.ExecuteScalarAsync<long>("""
            INSERT INTO sessions (user_id, family_id, refresh_hash, prev_refresh_hash, rotated_at,
                                  created_at, expires_at, last_used_at, revoked_at, user_agent)
            VALUES (@UserId, @FamilyId, @RefreshHash, @PrevRefreshHash, @RotatedAt,
                    @CreatedAt, @ExpiresAt, @LastUsedAt, @RevokedAt, @UserAgent);
            SELECT LAST_INSERT_ID();
            """, s);
    }

    public async Task<Session?> GetSessionByRefreshHashAsync(string refreshHash)
    {
        await using var conn = await OpenAsync();
        // UNION keeps both lookups on their own index (an OR across two columns may not).
        return await conn.QueryFirstOrDefaultAsync<Session>($"""
            SELECT {SessionColumns} FROM sessions WHERE refresh_hash = @refreshHash
            UNION
            SELECT {SessionColumns} FROM sessions WHERE prev_refresh_hash = @refreshHash
            LIMIT 1
            """, new { refreshHash });
    }

    public async Task<bool> UpdateSessionRotationAsync(long id, string expectedHash, string newHash, DateTime rotatedAt, DateTime expiresAt)
    {
        await using var conn = await OpenAsync();
        return await conn.ExecuteAsync("""
            UPDATE sessions
            SET prev_refresh_hash = refresh_hash, refresh_hash = @newHash,
                rotated_at = @rotatedAt, last_used_at = @rotatedAt, expires_at = @expiresAt
            WHERE id = @id AND refresh_hash = @expectedHash
            """, new { id, expectedHash, newHash, rotatedAt, expiresAt }) == 1;
    }

    public async Task RevokeFamilyAsync(string familyId, DateTime now)
    {
        await using var conn = await OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE sessions SET revoked_at = @now WHERE family_id = @familyId AND revoked_at IS NULL", new { familyId, now });
    }

    public async Task RevokeSessionAsync(long id, DateTime now)
    {
        await using var conn = await OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE sessions SET revoked_at = @now WHERE id = @id AND revoked_at IS NULL", new { id, now });
    }

    public async Task<int> DeleteStaleSessionsAsync(DateTime now, DateTime revokedBefore)
    {
        await using var conn = await OpenAsync();
        return await conn.ExecuteAsync(
            "DELETE FROM sessions WHERE expires_at < @now OR revoked_at < @revokedBefore", new { now, revokedBefore });
    }

    // ---- invites

    public async Task<long> CreateInviteAsync(Invite i)
    {
        await using var conn = await OpenAsync();
        return await conn.ExecuteScalarAsync<long>("""
            INSERT INTO invites (code_hash, app_id, max_uses, uses, expires_at, created_by, created_at)
            VALUES (@CodeHash, @AppId, @MaxUses, 0, @ExpiresAt, @CreatedBy, @CreatedAt);
            SELECT LAST_INSERT_ID();
            """, i);
    }

    public async Task<IReadOnlyList<Invite>> ListInvitesAsync()
    {
        await using var conn = await OpenAsync();
        return (await conn.QueryAsync<Invite>($"SELECT {InviteColumns} FROM invites ORDER BY id")).AsList();
    }

    public async Task<bool> DeleteInviteAsync(long id)
    {
        await using var conn = await OpenAsync();
        return await conn.ExecuteAsync("DELETE FROM invites WHERE id = @id", new { id }) > 0;
    }

    public async Task<string?> RedeemInviteAsync(string codeHash, long userId, DateTime now)
    {
        await using var conn = await OpenAsync();
        await using var tx = await conn.BeginTransactionAsync();

        // Row lock serialises concurrent redemptions of the same code.
        var invite = await conn.QuerySingleOrDefaultAsync<Invite>(
            $"SELECT {InviteColumns} FROM invites WHERE code_hash = @codeHash FOR UPDATE", new { codeHash }, tx);
        if (invite is null)
            return null;

        var alreadyGranted = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM app_grants WHERE user_id = @userId AND app_id = @AppId",
            new { userId, invite.AppId }, tx) > 0;
        if (alreadyGranted)
            return invite.AppId;

        if (invite.Uses >= invite.MaxUses || invite.ExpiresAt <= now)
            return null;

        await conn.ExecuteAsync("UPDATE invites SET uses = uses + 1 WHERE id = @Id", new { invite.Id }, tx);
        await conn.ExecuteAsync(
            "INSERT IGNORE INTO app_grants (user_id, app_id, created_at) VALUES (@userId, @AppId, @now)",
            new { userId, invite.AppId, now }, tx);
        await tx.CommitAsync();
        return invite.AppId;
    }
}
