namespace Mvv42.Auth.Options;

/// <summary>Section <c>Auth</c>. Env vars use <c>Auth__*</c>.</summary>
public sealed class AuthOptions
{
    public const string Section = "Auth";

    /// <summary>Directory with ES256 PEM keys (<c>es256-yyyyMMddHHmmss.pem</c>).</summary>
    public string KeysPath { get; set; } = "/var/lib/mvv42-auth/keys";

    /// <summary>Comma-separated origins allowed for unsafe methods (CSRF guard).</summary>
    public string AllowedOrigins { get; set; } = "https://mvv42.ru";

    /// <summary>Comma-separated telegram ids that are always admins (in addition to <c>users.is_admin</c>).</summary>
    public string AdminTelegramIds { get; set; } = "";

    public string Issuer { get; set; } = "https://mvv42.ru/auth";
    public string Audience { get; set; } = "mvv42";

    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>Sliding lifetime of a refresh token (renewed on each rotation).</summary>
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(30);

    /// <summary>Absolute lifetime of a session family, regardless of rotations.</summary>
    public TimeSpan SessionFamilyLifetime { get; set; } = TimeSpan.FromDays(90);

    /// <summary>Re-presenting the previous refresh token within this window is a benign race, not reuse.</summary>
    public TimeSpan RefreshReuseGrace { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>A new key is published in JWKS immediately but signs only after this delay (unless it is the only key).</summary>
    public TimeSpan KeyActivationDelay { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// true (prod): cookies are <c>Secure</c> and use <c>__Host-</c>/<c>__Secure-</c> prefixes.
    /// false (Development over plain http): no Secure flag, names without prefixes.
    /// </summary>
    public bool SecureCookies { get; set; } = true;

    public IReadOnlySet<string> AllowedOriginSet() =>
        SplitList(AllowedOrigins).Select(o => o.TrimEnd('/')).ToHashSet(StringComparer.OrdinalIgnoreCase);

    public IReadOnlySet<long> AdminTelegramIdSet() =>
        SplitList(AdminTelegramIds).Select(long.Parse).ToHashSet();

    private static IEnumerable<string> SplitList(string? value) =>
        (value ?? "").Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
