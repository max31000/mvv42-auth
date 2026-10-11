using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Mvv42.Auth.Client;

namespace Mvv42.Auth.Tests.Sdk;

/// <summary>
/// The dual-mode (migration phase Ф1) policy exactly as documented in sdk/dotnet/README.md: legacy HS256 Bearer
/// (the app's default scheme) OR mvv42 cookie with the app in <c>apps</c> (or adm). Never scheme-only.
/// </summary>
public class DualModePolicyTests(AuthAppFactory auth) : IClassFixture<AuthAppFactory>, IAsyncLifetime
{
    private const string LegacySecret = "legacy-test-secret-key-at-least-32-chars!";
    private WebApplication? _app;

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        if (_app is not null) await _app.DisposeAsync();
    }

    private static bool LegacyAuthenticated(ClaimsPrincipal u) =>
        u.Identities.Any(i => i.IsAuthenticated && i.AuthenticationType != Mvv42Auth.Scheme);

    private static bool Mvv42Allowed(ClaimsPrincipal u, string appId) =>
        u.Identities.Any(i => i.IsAuthenticated && i.AuthenticationType == Mvv42Auth.Scheme
                              && (i.HasClaim("adm", "true") || i.HasClaim("apps", appId)));

    private async Task<HttpClient> BondsLikeAppAsync()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        builder.WebHost.UseTestServer();

        // legacy: as in bonds/credit_calc (default scheme, HS256, MapInboundClaims default)
        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(o =>
            o.TokenValidationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(LegacySecret)),
                ValidIssuer = "bonds",
                ValidAudience = "bonds",
            });
        builder.Services.AddMvv42Auth("bonds", o =>
        {
            o.JwksUrl = "http://localhost/auth/.well-known/jwks.json";
            o.BackchannelHandler = auth.Server.CreateHandler();
            o.CookieName = "mvv42_at";
            o.AllowedOrigins = [AuthAppFactory.Origin];
        });

        var dualPolicy = new AuthorizationPolicyBuilder(JwtBearerDefaults.AuthenticationScheme, Mvv42Auth.Scheme)
            .RequireAuthenticatedUser()
            .RequireAssertion(ctx => LegacyAuthenticated(ctx.User) || Mvv42Allowed(ctx.User, "bonds"))
            .Build();
        builder.Services.AddAuthorization(o =>
        {
            o.FallbackPolicy = dualPolicy;
            o.DefaultPolicy = dualPolicy;
        });

        _app = builder.Build();
        _app.UseAuthentication();
        _app.UseAuthorization();
        _app.MapGet("/api/fallback", () => "ok");
        _app.MapGet("/api/default", () => "ok").RequireAuthorization();
        _app.MapGet("/health", () => "ok").AllowAnonymous();
        await _app.StartAsync();
        return _app.GetTestClient();
    }

    private static string LegacyToken(DateTime? expires = null) => new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
    {
        Issuer = "bonds",
        Audience = "bonds",
        Subject = new ClaimsIdentity([new Claim("sub", "1")]),
        NotBefore = (expires ?? DateTime.UtcNow.AddHours(1)).AddHours(-2),
        Expires = expires ?? DateTime.UtcNow.AddHours(1),
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(LegacySecret)), SecurityAlgorithms.HmacSha256),
    });

    private async Task<string> Mvv42CookieAsync(long telegramId)
    {
        var client = auth.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });
        client.DefaultRequestHeaders.Add("Origin", AuthAppFactory.Origin);
        var login = await AuthAppFactory.LoginAsync(client, telegramId);
        return login.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith("mvv42_at=")).Split(';')[0];
    }

    private static HttpRequestMessage Get(string path, string? bearer = null, string? cookie = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (bearer is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        if (cookie is not null) request.Headers.Add("Cookie", cookie);
        return request;
    }

    [Theory]
    [InlineData("/api/fallback")]
    [InlineData("/api/default")]
    public async Task LegacyBearer_OrMvv42WithApp_Pass_ScopeIsEnforced(string path)
    {
        var client = await BondsLikeAppAsync();
        var plainUser = await Mvv42CookieAsync(AuthAppFactory.NewTelegramId()); // bonds is access=admin → not in apps
        var admin = await Mvv42CookieAsync(AuthAppFactory.AdminTelegramId);

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Get(path))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Get(path, bearer: LegacyToken()))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Get(path, cookie: admin))).StatusCode);
        // authenticated by mvv42 but without the app: not a scheme-only policy
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(Get(path, cookie: plainUser))).StatusCode);
        // an expired legacy Bearer does not block a valid mvv42 cookie
        Assert.Equal(HttpStatusCode.OK,
            (await client.SendAsync(Get(path, bearer: LegacyToken(DateTime.UtcNow.AddHours(-1)), cookie: admin))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Get("/health"))).StatusCode);
    }
}
