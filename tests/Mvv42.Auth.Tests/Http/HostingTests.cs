using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Mvv42.Auth.Tests.Http;

public class HostingTests(AuthAppFactory factory) : IClassFixture<AuthAppFactory>
{
    [Fact]
    public async Task ProductionCookies_UseHostAndSecurePrefixes()
    {
        var client = factory
            .WithWebHostBuilder(b => b.UseSetting("Auth:SecureCookies", "true"))
            .CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });
        client.DefaultRequestHeaders.Add("Origin", AuthAppFactory.Origin);

        var response = await AuthAppFactory.LoginAsync(client, AuthAppFactory.NewTelegramId());
        var cookies = response.Headers.GetValues("Set-Cookie").ToList();

        Assert.Contains(cookies, c => c.StartsWith("__Host-mvv42_at=") && c.Contains("max-age=600") && c.Contains("path=/;")
            && c.Contains("secure") && c.Contains("samesite=strict") && c.Contains("httponly"));
        Assert.Contains(cookies, c => c.StartsWith("__Secure-mvv42_rt=") && c.Contains("max-age=2592000") && c.Contains("path=/auth/api")
            && c.Contains("secure") && c.Contains("samesite=strict") && c.Contains("httponly"));
    }

    [Fact]
    public void NonDevelopment_WithoutBotToken_RefusesToStart()
    {
        var production = factory.WithWebHostBuilder(b =>
        {
            b.UseEnvironment("Production");
            b.UseSetting("Telegram:BotToken", "");
        });

        var ex = Assert.Throws<InvalidOperationException>(() => production.CreateClient());
        Assert.Contains("Telegram:BotToken", ex.Message);
    }

    [Fact]
    public void NonDevelopment_WithoutConnectionString_RefusesToStart()
    {
        var production = factory.WithWebHostBuilder(b => b.UseEnvironment("Production"));

        var ex = Assert.Throws<InvalidOperationException>(() => production.CreateClient());
        Assert.Contains("ConnectionStrings:Auth", ex.Message);
    }

    [Fact]
    public void MalformedAdminTelegramIds_RefuseToStart()
    {
        var broken = factory.WithWebHostBuilder(b => b.UseSetting("Auth:AdminTelegramIds", "1000,abc"));

        var ex = Assert.Throws<InvalidOperationException>(() => broken.CreateClient());
        Assert.Contains("Auth:AdminTelegramIds", ex.Message);
    }

    [Fact]
    public void ForwardedHeaders_TrustOnlyLoopbackAndConfiguredProxyNetworks()
    {
        var configured = factory.WithWebHostBuilder(b => b.UseSetting("Auth:TrustedProxyCidrs", "172.18.0.1/32, 10.10.0.0/16"));

        var options = configured.Services.GetRequiredService<IOptions<ForwardedHeadersOptions>>().Value;

        Assert.Empty(options.KnownProxies);
        Assert.Equal(
            ["10.10.0.0/16", "127.0.0.0/8", "172.18.0.1/32", "::1/128"],
            options.KnownNetworks.Select(n => $"{n.Prefix}/{n.PrefixLength}").Order(StringComparer.Ordinal));
    }

    [Fact]
    public void ForwardedHeaders_DefaultTrustsDockerBridgeRange()
    {
        var options = factory.Services.GetRequiredService<IOptions<ForwardedHeadersOptions>>().Value;
        Assert.Contains(options.KnownNetworks, n => n.Prefix.ToString() == "172.16.0.0" && n.PrefixLength == 12);
        Assert.DoesNotContain(options.KnownNetworks, n => n.PrefixLength == 0);
    }

    [Fact]
    public void UnknownRegistrationMode_RefusesToStart()
    {
        var broken = factory.WithWebHostBuilder(b => b.UseSetting("Auth:Registration", "closed"));

        var ex = Assert.Throws<InvalidOperationException>(() => broken.CreateClient());
        Assert.Contains("Auth:Registration", ex.Message);
    }

    [Fact]
    public void FirstStart_CreatesInvitePepperInKeysPath()
    {
        using var keys = new TempDir();
        using var app = factory.WithWebHostBuilder(b => b.UseSetting("Auth:KeysPath", keys.Path));
        _ = app.CreateClient();

        Assert.Equal(32, new FileInfo(Path.Combine(keys.Path, "invite-pepper")).Length);
    }

    [Fact]
    public void MalformedTrustedProxyCidrs_RefuseToStart()
    {
        var broken = factory.WithWebHostBuilder(b => b.UseSetting("Auth:TrustedProxyCidrs", "172.18.0.1/99"));

        var ex = Assert.Throws<InvalidOperationException>(() => broken.CreateClient());
        Assert.Contains("Auth:TrustedProxyCidrs", ex.Message);
    }

    [Fact]
    public async Task SensitiveEndpoints_AreRateLimitedPerIp()
    {
        var limited = factory.WithWebHostBuilder(b => b.UseSetting("Auth:RateLimitPerMinute", "2"));
        var client = limited.CreateClient();
        client.DefaultRequestHeaders.Add("Origin", AuthAppFactory.Origin);

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsync("/auth/api/refresh", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsync("/auth/api/refresh", null)).StatusCode);
        var third = await client.PostAsync("/auth/api/telegram", AuthAppFactory.WidgetJson(AuthAppFactory.WidgetData(AuthAppFactory.NewTelegramId())));

        Assert.Equal(HttpStatusCode.TooManyRequests, third.StatusCode);
        Assert.Equal("rate_limited", (await third.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString());
        // /me and /health are not limited
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/auth/api/me")).StatusCode);
    }

    [Fact]
    public async Task ForwardedProto_IsHonoured()
    {
        // Sanity check that the service sits behind nginx: X-Forwarded-* must not break routing.
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Forwarded-Proto", "https");
        client.DefaultRequestHeaders.Add("X-Forwarded-For", "203.0.113.7");
        var health = await client.GetFromJsonAsync<Dictionary<string, string>>("/auth/health");
        Assert.Equal("ok", health!["status"]);
    }
}
