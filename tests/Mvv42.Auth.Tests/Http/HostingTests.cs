using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

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
