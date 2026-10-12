using System.Globalization;
using System.Net;
using AspNetIPNetwork = Microsoft.AspNetCore.HttpOverrides.IPNetwork;

namespace Mvv42.Auth.Options;

/// <summary><c>Auth:Registration</c>: who may create an account on first login.</summary>
public enum RegistrationMode
{
    /// <summary>Only with a valid invite code (header <c>X-Invite-Code</c>); owners always may.</summary>
    Invite,

    /// <summary>Anyone with a valid Telegram login (behaviour before the closed registration).</summary>
    Open,
}

/// <summary>Section <c>Auth</c>. Env vars use <c>Auth__*</c>.</summary>
public sealed class AuthOptions
{
    public const string Section = "Auth";

    /// <summary>Directory with ES256 PEM keys (<c>es256-yyyyMMddHHmmss.pem</c>).</summary>
    public string KeysPath { get; set; } = "/var/lib/mvv42-auth/keys";

    /// <summary>Comma-separated origins allowed for unsafe methods (CSRF guard).</summary>
    public string AllowedOrigins { get; set; } = "https://mvv42.ru";

    /// <summary>
    /// Comma-separated telegram ids that are always admins (in addition to <c>users.is_admin</c>).
    /// Parsed once; a malformed value stops the service at startup.
    /// </summary>
    public string AdminTelegramIds
    {
        get => _adminTelegramIds;
        set
        {
            _adminTelegramIds = value;
            _adminTelegramIdSet = null;
        }
    }

    /// <summary>
    /// Comma-separated IPs/CIDRs whose <c>X-Forwarded-For/Proto</c> are trusted (loopback always is). nginx on the host
    /// reaches the container through docker-proxy, so the peer the app sees is the gateway of the docker network the
    /// published port maps through: <c>docker network inspect cashpulse-network -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}'</c>.
    /// The deploy workflow sets it to exactly that gateway (/32). Default: docker's default address pool 172.16.0.0/12
    /// (any container on a docker network could then spoof X-Forwarded-For).
    /// </summary>
    public string TrustedProxyCidrs { get; set; } = "172.16.0.0/12";

    /// <summary>
    /// <c>invite</c> (default) or <c>open</c>, see <see cref="Options.RegistrationMode"/>. Validated at startup: an unknown
    /// value stops the service.
    /// </summary>
    public string Registration { get; set; } = "invite";

    /// <summary>App-level limit (defence in depth behind nginx limit_req) for /telegram, /refresh, /invites/redeem per client IP.</summary>
    public int RateLimitPerMinute { get; set; } = 30;

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

    private string _adminTelegramIds = "";
    private IReadOnlySet<long>? _adminTelegramIdSet;

    /// <exception cref="FormatException">A value is not a positive telegram id.</exception>
    public IReadOnlySet<long> AdminTelegramIdSet() => _adminTelegramIdSet ??= SplitList(AdminTelegramIds)
        .Select(item => long.TryParse(item, NumberStyles.None, CultureInfo.InvariantCulture, out var id) && id > 0
            ? id
            : throw new FormatException($"Auth:AdminTelegramIds: '{item}' is not a telegram id"))
        .ToHashSet();

    /// <exception cref="FormatException">Not <c>invite</c> or <c>open</c>.</exception>
    public RegistrationMode GetRegistrationMode() => (Registration ?? "").Trim().ToLowerInvariant() switch
    {
        "invite" => Options.RegistrationMode.Invite,
        "open" => Options.RegistrationMode.Open,
        _ => throw new FormatException($"Auth:Registration: '{Registration}' is not 'invite' or 'open'"),
    };

    /// <summary>Configurations that start but are probably a mistake (logged as warnings at startup).</summary>
    public IReadOnlyList<string> StartupWarnings() =>
        GetRegistrationMode() == Options.RegistrationMode.Invite && AdminTelegramIdSet().Count == 0
            ? ["Auth:Registration is 'invite' but Auth:AdminTelegramIds is empty: nobody can create invites, new users cannot register"]
            : [];

    /// <exception cref="FormatException">A value is not an IP address or CIDR.</exception>
    public IReadOnlyList<AspNetIPNetwork> TrustedProxyNetworks() => SplitList(TrustedProxyCidrs).Select(item =>
    {
        var slash = item.IndexOf('/');
        var address = slash < 0 ? item : item[..slash];
        if (!IPAddress.TryParse(address, out var ip))
            throw new FormatException($"Auth:TrustedProxyCidrs: '{item}' is not an IP address or CIDR");
        var maxPrefix = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
        var prefix = maxPrefix;
        if (slash >= 0 && (!int.TryParse(item[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out prefix) || prefix > maxPrefix))
            throw new FormatException($"Auth:TrustedProxyCidrs: '{item}' has an invalid prefix length");
        return new AspNetIPNetwork(ip, prefix);
    }).ToList();

    private static IEnumerable<string> SplitList(string? value) =>
        (value ?? "").Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
