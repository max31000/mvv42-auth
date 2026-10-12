using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Mvv42.Auth.Tests;

/// <summary>
/// The auth service in "Testing" environment: in-memory store (no connection string), temp key directory,
/// plain-http cookie names (mvv42_at / mvv42_rt) so the test client's cookie container round-trips them.
/// </summary>
public class AuthAppFactory : WebApplicationFactory<Program>
{
    public const string BotToken = "123456:TEST-token";
    public const string Origin = "http://localhost";
    public const long AdminTelegramId = 1000;

    private readonly TempDir _keys = new();

    /// <summary>
    /// <c>Auth:Registration</c>. <c>open</c> here so tests can log arbitrary new users in; null leaves the service
    /// default (<c>invite</c>, see <c>InviteAuthAppFactory</c>).
    /// </summary>
    protected virtual string? Registration => "open";

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("Auth:KeysPath", _keys.Path);
        builder.UseSetting("Auth:AllowedOrigins", Origin);
        builder.UseSetting("Auth:AdminTelegramIds", AdminTelegramId.ToString());
        builder.UseSetting("Auth:SecureCookies", "false");
        builder.UseSetting("Telegram:BotToken", BotToken);
        builder.UseSetting("Auth:RateLimitPerMinute", "100000"); // tests share one (null) remote IP
        if (Registration is not null)
            builder.UseSetting("Auth:Registration", Registration);
    }

    /// <summary>Client with a cookie container and a same-origin Origin header (as a browser fetch would send).</summary>
    public HttpClient CreateBrowser()
    {
        var client = CreateClient();
        client.DefaultRequestHeaders.Add("Origin", Origin);
        return client;
    }

    private static readonly long AuthDateBase = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    private static long _widgetCounter;

    /// <summary>
    /// Signed widget data. Every call gets a distinct auth_date (strictly decreasing, still within the window),
    /// so two logins of the same user are never byte-identical and do not trip the replay cache.
    /// </summary>
    public static Dictionary<string, string> WidgetData(long telegramId, string firstName = "Max") =>
        TelegramVerifierTests.Signed(new Dictionary<string, string>
        {
            ["id"] = telegramId.ToString(),
            ["first_name"] = firstName,
            ["auth_date"] = (AuthDateBase - Interlocked.Increment(ref _widgetCounter)).ToString(),
        }, BotToken);

    /// <summary>Widget JSON as the browser sends it: id and auth_date are numbers.</summary>
    public static JsonContent WidgetJson(Dictionary<string, string> fields) =>
        JsonContent.Create(fields.ToDictionary(f => f.Key, f => f.Key is "id" or "auth_date" ? (object)long.Parse(f.Value) : f.Value));

    public static async Task<HttpResponseMessage> LoginAsync(HttpClient client, long telegramId)
    {
        var response = await client.PostAsync("/auth/api/telegram", WidgetJson(WidgetData(telegramId)));
        response.EnsureSuccessStatusCode();
        return response;
    }

    public static long NewTelegramId() => Random.Shared.NextInt64(2_000, 1_000_000_000);

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing) _keys.Dispose();
    }
}
