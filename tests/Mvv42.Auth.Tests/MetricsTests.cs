using System.Net;
using Prometheus;

namespace Mvv42.Auth.Tests;

/// <summary>Prometheus metrics (mvv42-infra docs/specs/2026-10-16-app-metrics.md): own port only, no raw paths.</summary>
public class MetricsTests(AuthAppFactory factory) : IClassFixture<AuthAppFactory>
{
    private static async Task<string> ScrapeAsync()
    {
        using var stream = new MemoryStream();
        await Metrics.DefaultRegistry.CollectAndExportAsTextAsync(stream);
        return System.Text.Encoding.UTF8.GetString(stream.ToArray());
    }

    [Theory]
    [InlineData("/auth/metrics")]
    [InlineData("/metrics")]
    public async Task PublicPort_DoesNotServeMetrics(string path)
    {
        var response = await factory.CreateClient().GetAsync(path);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task HttpMetrics_UseRouteTemplates_LoginsCountedByResult()
    {
        var owner = factory.CreateBrowser();
        await AuthAppFactory.LoginAsync(owner, AuthAppFactory.AdminTelegramId);
        await owner.GetAsync("/auth/api/admin/users/987654");

        var text = await ScrapeAsync();
        Assert.Contains("endpoint=\"/api/admin/users/{id:long}\"", text);
        Assert.DoesNotContain("987654", text);
        Assert.Contains("mvv42_auth_logins_total{result=\"ok\"}", text);
    }
}
