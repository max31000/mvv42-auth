using System.Net;

namespace Mvv42.Auth.Tests;

public class HealthTests(AuthAppFactory factory) : IClassFixture<AuthAppFactory>
{
    [Fact]
    public async Task Health_UnderPathBase_ReturnsOk()
    {
        var client = factory.CreateClient();
        var response = await client.GetAsync("/auth/health");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
