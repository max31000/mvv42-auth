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
}

public sealed record Invite
{
    public long Id { get; init; }
    public string CodeHash { get; init; } = "";
    public string AppId { get; init; } = "";
    public int MaxUses { get; init; } = 1;
    public int Uses { get; init; }
    public DateTime? ExpiresAt { get; init; }
    public long? CreatedBy { get; init; }
    public DateTime CreatedAt { get; init; }
}
