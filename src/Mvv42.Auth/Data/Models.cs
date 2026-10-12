namespace Mvv42.Auth.Data;

// Plain row types (Dapper maps snake_case columns via MatchNamesWithUnderscores). All times are UTC.

public sealed record User
{
    public long Id { get; init; }
    public long TelegramId { get; init; }
    public string? Username { get; init; }
    public string FirstName { get; init; } = "";
    public string? LastName { get; init; }
    public string? PhotoUrl { get; init; }
    public bool IsAdmin { get; init; }

    /// <summary>Blocked users get no tokens: <c>/telegram</c> → 403, refresh → 401, sessions revoked (spec §10.8).</summary>
    public bool IsBlocked { get; init; }
    public DateTime? BlockedAt { get; init; }
    public DateTime CreatedAt { get; init; }
    public DateTime? LastLoginAt { get; init; }

    public string DisplayName => string.IsNullOrWhiteSpace(LastName) ? FirstName : $"{FirstName} {LastName}";
}

public static class AppAccess
{
    public const string Public = "public";
    public const string Invite = "invite";
    public const string Admin = "admin";

    public static bool IsValid(string? value) => value is Public or Invite or Admin;
}

public sealed record App
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";

    /// <summary>App opens without login; login only unlocks extra features (UI/app-level, not part of the claim).</summary>
    public bool Anonymous { get; init; }

    /// <summary><see cref="AppAccess"/>: who may use the app's authenticated features.</summary>
    public string Access { get; init; } = AppAccess.Invite;
}

public sealed record Grant
{
    public long UserId { get; init; }
    public string AppId { get; init; } = "";
    public DateTime CreatedAt { get; init; }
}

/// <summary>
/// One login = one row, rotated in place. <see cref="PrevRefreshHash"/> + <see cref="RotatedAt"/> implement the
/// 30 s grace for concurrent refreshes; presenting the previous token later is reuse → the family is revoked.
/// </summary>
public sealed record Session
{
    public long Id { get; init; }
    public long UserId { get; init; }
    public string FamilyId { get; init; } = "";
    public string RefreshHash { get; init; } = "";
    public string? PrevRefreshHash { get; init; }
    public DateTime? RotatedAt { get; init; }
    public DateTime CreatedAt { get; init; }

    /// <summary>Sliding expiry, never beyond CreatedAt + family lifetime.</summary>
    public DateTime ExpiresAt { get; init; }

    public DateTime LastUsedAt { get; init; }
    public DateTime? RevokedAt { get; init; }
    public string? UserAgent { get; init; }

    /// <summary>Client IP at login, normalised (IPv4-mapped IPv6 → IPv4).</summary>
    public string? Ip { get; init; }
}

public sealed record Invite
{
    public long Id { get; init; }
    /// <summary>HMAC-SHA256 of the normalised code (new codes) or SHA-256 of the raw code (legacy), hex.</summary>
    public string CodeHash { get; init; } = "";

    /// <summary>App granted on use; null = login-only invite (registration without a grant).</summary>
    public string? AppId { get; init; }
    public int MaxUses { get; init; } = 1;
    public int Uses { get; init; }
    public DateTime? ExpiresAt { get; init; }
    public long? CreatedBy { get; init; }
    public DateTime CreatedAt { get; init; }
}

/// <summary>
/// A refresh hash that has been rotated away (written in the same transaction as the rotation). Presenting it
/// later — older than the 30 s grace of <see cref="Session.PrevRefreshHash"/> — is reuse → the family is revoked.
/// Rows go away with their session (cleanup of expired/revoked sessions).
/// </summary>
public sealed record RefreshHistoryEntry
{
    public string Hash { get; init; } = "";
    public string FamilyId { get; init; } = "";
    public long SessionId { get; init; }
    public DateTime RotatedAt { get; init; }
}

public static class LoginResult
{
    public const string Ok = "ok";
    public const string DeniedBlocked = "denied_blocked";
    public const string Invalid = "invalid";
    public const string Replayed = "replayed";

    /// <summary>
    /// Unknown telegram user refused by the closed registration (no code, bad code). Stores <b>nothing</b> but the time:
    /// user id, telegram id, IP and User-Agent are NULL. Kept 7 days.
    /// </summary>
    public const string DeniedUnregistered = "denied_unregistered";
}

/// <summary>
/// One <c>/telegram</c> attempt. <see cref="UserId"/>/<see cref="TelegramId"/> are null for
/// <see cref="LoginResult.Invalid"/>/<see cref="LoginResult.Replayed"/>: an unverified telegram id is never stored.
/// </summary>
public sealed record LoginEvent
{
    public long Id { get; init; }
    public long? UserId { get; init; }
    public long? TelegramId { get; init; }
    public DateTime At { get; init; }
    public string? Ip { get; init; }
    public string? UserAgent { get; init; }
    public string Result { get; init; } = LoginResult.Ok;

    /// <summary>Display name of <see cref="UserId"/>, filled by <see cref="IAuthStore.ListLoginEventsAsync"/> (not stored).</summary>
    public string? UserName { get; init; }
}

public enum InviteRedeemStatus
{
    Granted,

    /// <summary>The user already had the grant: no use consumed (even if the invite is expired/exhausted).</summary>
    AlreadyGranted,
    NotFound,
    Expired,
    Exhausted,
}

/// <param name="AppId">The invite's app; null for <see cref="InviteRedeemStatus.NotFound"/> and for a login-only invite.</param>
public sealed record InviteRedeemResult(InviteRedeemStatus Status, string? AppId);

public enum InviteRegistrationStatus
{
    /// <summary>User created, one use consumed, the invite's app granted (if any).</summary>
    Registered,

    /// <summary>The telegram id already has a user (e.g. a parallel request won): nothing changed, no use consumed.</summary>
    AlreadyRegistered,
    NotFound,
    Expired,
    Exhausted,
}

/// <param name="User">The new user, only for <see cref="InviteRegistrationStatus.Registered"/>.</param>
/// <param name="AppId">The granted app, only for <see cref="InviteRegistrationStatus.Registered"/> (null = login-only invite).</param>
public sealed record InviteRegistrationResult(InviteRegistrationStatus Status, User? User, string? AppId);
