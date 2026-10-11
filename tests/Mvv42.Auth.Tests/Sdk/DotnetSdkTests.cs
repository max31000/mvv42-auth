using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Mvv42.Auth.Client;

namespace Mvv42.Auth.Tests.Sdk;

/// <summary>
/// The copy-in SDK (sdk/dotnet/Mvv42Auth.cs) in a minimal "app" host, validating access tokens issued by the
/// real auth service; JWKS is fetched from that service through its in-memory test handler.
/// </summary>
public class DotnetSdkTests(AuthAppFactory auth) : IClassFixture<AuthAppFactory>, IAsyncLifetime
{
    private readonly List<WebApplication> _apps = [];

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        foreach (var app in _apps) await app.DisposeAsync();
    }

    private async Task<HttpClient> AppAsync(string appId)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        builder.WebHost.UseTestServer();
        builder.Services.AddMvv42Auth(appId, o =>
        {
            o.JwksUrl = "http://localhost/auth/.well-known/jwks.json";
            o.BackchannelHandler = auth.Server.CreateHandler();
            o.CookieName = "mvv42_at"; // auth service runs with SecureCookies=false in tests
            o.AllowedOrigins = [AuthAppFactory.Origin];
        });

        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGet("/api/whoami", (ClaimsPrincipal user) => user.GetMvv42User()).RequireAuthorization(Mvv42Auth.Policy);
        app.MapPost("/api/action", () => "done").RequireAuthorization(Mvv42Auth.Policy);
        app.MapPost("/api/public", () => "done");
        await app.StartAsync();
        _apps.Add(app);
        return app.GetTestClient();
    }

    private async Task<string> AccessTokenAsync(long telegramId)
    {
        var client = auth.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });
        client.DefaultRequestHeaders.Add("Origin", AuthAppFactory.Origin);
        var login = await AuthAppFactory.LoginAsync(client, telegramId);
        var cookie = login.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith("mvv42_at="));
        return cookie["mvv42_at=".Length..cookie.IndexOf(';')];
    }

    private static HttpRequestMessage Request(HttpMethod method, string url, string? token, string? origin = null)
    {
        var request = new HttpRequestMessage(method, url);
        if (token is not null) request.Headers.Add("Cookie", $"mvv42_at={token}");
        if (origin is not null) request.Headers.Add("Origin", origin);
        return request;
    }

    [Fact]
    public async Task ValidCookie_ForAllowedApp_ExposesMvv42User()
    {
        var tg = AuthAppFactory.NewTelegramId();
        var client = await AppAsync("cashpulse");

        var response = await client.SendAsync(Request(HttpMethod.Get, "/api/whoami", await AccessTokenAsync(tg)));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var user = await response.Content.ReadFromJsonAsync<Mvv42User>();
        Assert.Equal(tg, user!.TelegramId);
        Assert.Equal("Max", user.Name);
        Assert.False(user.IsAdmin);
        Assert.True(long.TryParse(user.AuthUserId, out _));
    }

    [Fact]
    public async Task NoCookie_Is401_AndBearerHeaderIsIgnored()
    {
        var client = await AppAsync("cashpulse");
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/whoami")).StatusCode);

        var bearer = Request(HttpMethod.Get, "/api/whoami", token: null);
        bearer.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await AccessTokenAsync(AuthAppFactory.NewTelegramId()));
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(bearer)).StatusCode);
    }

    [Fact]
    public async Task AppNotInAppsClaim_Is403_ButAdminPasses()
    {
        var client = await AppAsync("bonds"); // access=admin

        var user = await client.SendAsync(Request(HttpMethod.Get, "/api/whoami", await AccessTokenAsync(AuthAppFactory.NewTelegramId())));
        Assert.Equal(HttpStatusCode.Forbidden, user.StatusCode);

        var admin = await client.SendAsync(Request(HttpMethod.Get, "/api/whoami", await AccessTokenAsync(AuthAppFactory.AdminTelegramId)));
        Assert.Equal(HttpStatusCode.OK, admin.StatusCode);
        Assert.True((await admin.Content.ReadFromJsonAsync<Mvv42User>())!.IsAdmin);
    }

    [Fact]
    public async Task GarbageToken_Is401()
    {
        var client = await AppAsync("cashpulse");
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Request(HttpMethod.Get, "/api/whoami", "a.b.c"))).StatusCode);
    }

    [Fact]
    public async Task UnsafeRequest_WithCookie_RequiresAllowedOrigin()
    {
        var client = await AppAsync("cashpulse");
        var token = await AccessTokenAsync(AuthAppFactory.NewTelegramId());

        var noOrigin = await client.SendAsync(Request(HttpMethod.Post, "/api/action", token));
        Assert.Equal(HttpStatusCode.Forbidden, noOrigin.StatusCode);
        // JSON like the auth service, so apps keep JSON error bodies
        Assert.Equal("application/json", noOrigin.Content.Headers.ContentType?.MediaType);
        Assert.Equal("""{"error":"origin_not_allowed"}""", await noOrigin.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.Forbidden,
            (await client.SendAsync(Request(HttpMethod.Post, "/api/action", token, "https://evil.example"))).StatusCode);
        Assert.Equal(HttpStatusCode.OK,
            (await client.SendAsync(Request(HttpMethod.Post, "/api/action", token, AuthAppFactory.Origin))).StatusCode);
    }

    [Fact]
    public async Task UnsafeRequest_WithoutCookie_IsNotTouchedByOriginFilter()
    {
        // Non-browser clients (old Bearer scheme during dual-mode, scripts) carry no ambient cookie → no CSRF risk.
        var client = await AppAsync("cashpulse");
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Request(HttpMethod.Post, "/api/public", token: null))).StatusCode);
    }

    [Fact]
    public void GetMvv42User_WithoutMvv42Identity_IsNull()
    {
        var other = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "1"), new Claim("tg", "2")], "Bearer"));
        Assert.Null(other.GetMvv42User());
    }
}
