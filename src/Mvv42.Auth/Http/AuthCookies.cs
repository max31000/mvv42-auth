using Microsoft.Extensions.Options;
using Mvv42.Auth.Options;
using Mvv42.Auth.Tokens;

namespace Mvv42.Auth.Http;

/// <summary>
/// Access cookie <c>__Host-mvv42_at</c> (Path=/, 10 min) and refresh cookie <c>__Secure-mvv42_rt</c> (Path=/auth/api).
/// Both HttpOnly + SameSite=Strict (spec §9.3). With <c>Auth:SecureCookies=false</c> (Development over http)
/// the names lose their prefixes and the Secure flag (§9.18).
/// </summary>
public sealed class AuthCookies(IOptions<AuthOptions> options, TimeProvider time)
{
    public const string RefreshPath = "/auth/api";

    private bool Secure => options.Value.SecureCookies;

    public string AccessName => Secure ? "__Host-mvv42_at" : "mvv42_at";
    public string RefreshName => Secure ? "__Secure-mvv42_rt" : "mvv42_rt";

    public string? ReadAccess(HttpRequest request) => request.Cookies[AccessName];
    public string? ReadRefresh(HttpRequest request) => request.Cookies[RefreshName];

    public void SetAccess(HttpResponse response, IssuedAccessToken token) =>
        response.Cookies.Append(AccessName, token.Token, Options("/", token.ExpiresAt - time.GetUtcNow()));

    public void SetRefresh(HttpResponse response, string token, DateTime expiresAtUtc) =>
        response.Cookies.Append(RefreshName, token, Options(RefreshPath, expiresAtUtc - time.GetUtcNow().UtcDateTime));

    /// <summary>Deletes both cookies with the same Path/attributes they were set with.</summary>
    public void Clear(HttpResponse response)
    {
        response.Cookies.Delete(AccessName, Options("/", null));
        response.Cookies.Delete(RefreshName, Options(RefreshPath, null));
    }

    private CookieOptions Options(string path, TimeSpan? maxAge) => new()
    {
        HttpOnly = true,
        Secure = Secure,
        SameSite = SameSiteMode.Strict,
        Path = path,
        MaxAge = maxAge is { } m ? TimeSpan.FromSeconds(Math.Max(0, Math.Round(m.TotalSeconds))) : null,
        IsEssential = true,
    };
}
