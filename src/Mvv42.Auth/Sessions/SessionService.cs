using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Mvv42.Auth.Data;
using Mvv42.Auth.Options;

namespace Mvv42.Auth.Sessions;

public enum RefreshStatus
{
    /// <summary>New refresh token issued (set both cookies).</summary>
    Rotated,

    /// <summary>Previous token presented within the grace window: issue an access token only, keep the refresh cookie.</summary>
    Grace,

    /// <summary>Unknown, expired or revoked.</summary>
    Invalid,

    /// <summary>Previous token presented after the grace window: the whole family has been revoked.</summary>
    Reused,
}

public sealed record RefreshResult(RefreshStatus Status, Session? Session = null, string? NewRefreshToken = null)
{
    public bool Succeeded => Status is RefreshStatus.Rotated or RefreshStatus.Grace;
}

/// <summary>
/// Refresh tokens: 32 random bytes, only SHA-256 stored. Rotation on every refresh with a 30 s grace for
/// concurrent refreshes (spec §9.1); sliding 30-day expiry capped by the 90-day family lifetime (§9.2).
/// </summary>
public sealed class SessionService(IAuthStore store, IOptions<AuthOptions> options, TimeProvider time)
{
    private AuthOptions O => options.Value;

    public async Task<(Session Session, string RefreshToken)> CreateAsync(long userId, string? userAgent)
    {
        var now = time.GetUtcNow().UtcDateTime;
        var token = NewToken();
        var session = new Session
        {
            UserId = userId,
            FamilyId = Guid.NewGuid().ToString(),
            RefreshHash = Hash(token),
            CreatedAt = now,
            ExpiresAt = Min(now + O.RefreshTokenLifetime, now + O.SessionFamilyLifetime),
            LastUsedAt = now,
            UserAgent = userAgent is { Length: > 512 } ? userAgent[..512] : userAgent,
        };
        var id = await store.CreateSessionAsync(session);
        return (session with { Id = id }, token);
    }

    public async Task<RefreshResult> RefreshAsync(string? refreshToken)
    {
        if (string.IsNullOrEmpty(refreshToken))
            return new(RefreshStatus.Invalid);

        var now = time.GetUtcNow().UtcDateTime;
        var hash = Hash(refreshToken);
        var session = await store.GetSessionByRefreshHashAsync(hash);
        if (session is null || session.RevokedAt is not null || now >= session.ExpiresAt
            || now >= session.CreatedAt + O.SessionFamilyLifetime)
            return new(RefreshStatus.Invalid);

        if (session.RefreshHash == hash)
        {
            var newToken = NewToken();
            var expiresAt = Min(now + O.RefreshTokenLifetime, session.CreatedAt + O.SessionFamilyLifetime);
            if (await store.UpdateSessionRotationAsync(session.Id, hash, Hash(newToken), now, expiresAt))
            {
                return new(RefreshStatus.Rotated, session with
                {
                    PrevRefreshHash = hash, RefreshHash = Hash(newToken), RotatedAt = now, LastUsedAt = now, ExpiresAt = expiresAt,
                }, newToken);
            }

            // Lost a race against a concurrent rotation of the same token a moment ago: that is the benign case.
            return new(RefreshStatus.Grace, session);
        }

        // Matched prev_refresh_hash.
        if (session.RotatedAt is { } rotatedAt && now - rotatedAt < O.RefreshReuseGrace)
            return new(RefreshStatus.Grace, session);

        await store.RevokeFamilyAsync(session.FamilyId, now);
        return new(RefreshStatus.Reused);
    }

    /// <summary>Logout: revokes the session the token belongs to (current or previous token).</summary>
    public async Task RevokeAsync(string? refreshToken)
    {
        if (string.IsNullOrEmpty(refreshToken))
            return;
        var session = await store.GetSessionByRefreshHashAsync(Hash(refreshToken));
        if (session is not null)
            await store.RevokeSessionAsync(session.Id, time.GetUtcNow().UtcDateTime);
    }

    public static string Hash(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token))).ToLowerInvariant();

    private static string NewToken() => Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));

    private static DateTime Min(DateTime a, DateTime b) => a < b ? a : b;
}
