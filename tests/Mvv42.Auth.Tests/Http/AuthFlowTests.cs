using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Mvv42.Auth.Data;

namespace Mvv42.Auth.Tests.Http;

public class AuthFlowTests(AuthAppFactory factory) : IClassFixture<AuthAppFactory>
{
    private static IEnumerable<string> SetCookies(HttpResponseMessage r) =>
        r.Headers.TryGetValues("Set-Cookie", out var values) ? values : [];

    private static string? CookieValue(HttpResponseMessage r, string name) =>
        SetCookies(r).Where(c => c.StartsWith(name + "=")).Select(c => c[(name.Length + 1)..c.IndexOf(';')]).FirstOrDefault();

    private static async Task<JsonElement> Json(HttpResponseMessage r) => await r.Content.ReadFromJsonAsync<JsonElement>();

    private static JsonElement App(JsonElement me, string id) =>
        me.GetProperty("apps").EnumerateArray().Single(a => a.GetProperty("id").GetString() == id);

    /// <summary>Client without a cookie container: cookies are sent explicitly.</summary>
    private HttpClient RawClient(string? cookie = null)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });
        client.DefaultRequestHeaders.Add("Origin", AuthAppFactory.Origin);
        if (cookie is not null) client.DefaultRequestHeaders.Add("Cookie", cookie);
        return client;
    }

    [Fact]
    public async Task Login_SetsBothCookies_AndReturnsUserWithApps()
    {
        var tg = AuthAppFactory.NewTelegramId();
        var response = await AuthAppFactory.LoginAsync(RawClient(), tg);

        var cookies = SetCookies(response).ToList();
        Assert.Contains(cookies, c => c.StartsWith("mvv42_at=") && c.Contains("path=/;") && c.Contains("max-age=600")
            && c.Contains("samesite=strict") && c.Contains("httponly"));
        Assert.Contains(cookies, c => c.StartsWith("mvv42_rt=") && c.Contains("path=/auth/api")
            && c.Contains("samesite=strict") && c.Contains("httponly"));

        var me = await Json(response);
        Assert.Equal(tg, me.GetProperty("user").GetProperty("telegramId").GetInt64());
        Assert.Equal("Max", me.GetProperty("user").GetProperty("name").GetString());
        Assert.False(me.GetProperty("user").GetProperty("isAdmin").GetBoolean());
        Assert.True(App(me, "cashpulse").GetProperty("granted").GetBoolean());
        Assert.True(App(me, "credit_calc").GetProperty("anonymous").GetBoolean());
        Assert.False(App(me, "bonds").GetProperty("granted").GetBoolean());
        Assert.Equal("admin", App(me, "bonds").GetProperty("access").GetString());
    }

    [Fact]
    public async Task Me_Anonymous_ReturnsNullUser_AndNothingGranted()
    {
        var response = await factory.CreateClient().GetAsync("/auth/api/me");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var me = await Json(response);
        Assert.Equal(JsonValueKind.Null, me.GetProperty("user").ValueKind);
        Assert.All(me.GetProperty("apps").EnumerateArray(), a => Assert.False(a.GetProperty("granted").GetBoolean()));
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
    }

    [Fact]
    public async Task FullFlow_Login_Me_Refresh_Logout()
    {
        var browser = factory.CreateBrowser();
        var tg = AuthAppFactory.NewTelegramId();
        await AuthAppFactory.LoginAsync(browser, tg);

        var me = await Json(await browser.GetAsync("/auth/api/me"));
        Assert.Equal(tg, me.GetProperty("user").GetProperty("telegramId").GetInt64());

        var refresh = await browser.PostAsync("/auth/api/refresh", null);
        Assert.Equal(HttpStatusCode.NoContent, refresh.StatusCode);
        Assert.NotNull(CookieValue(refresh, "mvv42_at"));
        Assert.NotNull(CookieValue(refresh, "mvv42_rt"));

        var logout = await browser.PostAsync("/auth/api/logout", null);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
        Assert.Contains(SetCookies(logout), c => c.StartsWith("mvv42_rt=;") && c.Contains("path=/auth/api"));
        Assert.Contains(SetCookies(logout), c => c.StartsWith("mvv42_at=;") && c.Contains("path=/;"));

        var after = await Json(await browser.GetAsync("/auth/api/me"));
        Assert.Equal(JsonValueKind.Null, after.GetProperty("user").ValueKind);
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.PostAsync("/auth/api/refresh", null)).StatusCode);
    }

    [Fact]
    public async Task Refresh_WithJustRotatedToken_IsBenignRace_AccessOnly()
    {
        var login = await AuthAppFactory.LoginAsync(RawClient(), AuthAppFactory.NewTelegramId());
        var rt = CookieValue(login, "mvv42_rt");

        var first = await RawClient($"mvv42_rt={rt}").PostAsync("/auth/api/refresh", null);
        var second = await RawClient($"mvv42_rt={rt}").PostAsync("/auth/api/refresh", null);

        Assert.Equal(HttpStatusCode.NoContent, first.StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, second.StatusCode);
        Assert.NotNull(CookieValue(second, "mvv42_at"));
        Assert.Null(CookieValue(second, "mvv42_rt"));

        // the rotated token still works
        var third = await RawClient($"mvv42_rt={CookieValue(first, "mvv42_rt")}").PostAsync("/auth/api/refresh", null);
        Assert.Equal(HttpStatusCode.NoContent, third.StatusCode);
    }

    [Fact]
    public async Task Me_WithoutAccessCookie_RefreshesImplicitly()
    {
        var tg = AuthAppFactory.NewTelegramId();
        var login = await AuthAppFactory.LoginAsync(RawClient(), tg);

        var response = await RawClient($"mvv42_rt={CookieValue(login, "mvv42_rt")}").GetAsync("/auth/api/me");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(tg, (await Json(response)).GetProperty("user").GetProperty("telegramId").GetInt64());
        Assert.NotNull(CookieValue(response, "mvv42_at"));
        Assert.NotNull(CookieValue(response, "mvv42_rt"));
    }

    [Fact]
    public async Task Me_WithInvalidRefreshCookie_IsAnonymous_AndClearsCookies()
    {
        var response = await RawClient("mvv42_rt=garbage").GetAsync("/auth/api/me");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(JsonValueKind.Null, (await Json(response)).GetProperty("user").ValueKind);
        Assert.Contains(SetCookies(response), c => c.StartsWith("mvv42_rt=;"));
    }

    [Fact]
    public async Task Telegram_ReplayedWidgetData_Is401()
    {
        var fields = AuthAppFactory.WidgetData(AuthAppFactory.NewTelegramId());

        var first = await RawClient().PostAsync("/auth/api/telegram", AuthAppFactory.WidgetJson(fields));
        var replay = await RawClient().PostAsync("/auth/api/telegram", AuthAppFactory.WidgetJson(fields));

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
        Assert.Equal("Replayed", (await Json(replay)).GetProperty("error").GetString());
        Assert.Empty(SetCookies(replay));
    }

    [Fact]
    public async Task Me_WithValidAccessToken_ButDeletedUser_IsAnonymous_AndClearsCookies()
    {
        var tg = AuthAppFactory.NewTelegramId();
        var login = await AuthAppFactory.LoginAsync(RawClient(), tg);
        var cookie = $"mvv42_at={CookieValue(login, "mvv42_at")}; mvv42_rt={CookieValue(login, "mvv42_rt")}";
        var userId = (await Json(login)).GetProperty("user").GetProperty("id").GetInt64();

        ((InMemoryAuthStore)factory.Services.GetRequiredService<IAuthStore>()).DeleteUser(userId);
        var response = await RawClient(cookie).GetAsync("/auth/api/me");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(JsonValueKind.Null, (await Json(response)).GetProperty("user").ValueKind);
        Assert.Contains(SetCookies(response), c => c.StartsWith("mvv42_at=;"));
        Assert.Contains(SetCookies(response), c => c.StartsWith("mvv42_rt=;"));
    }

    [Fact]
    public async Task Refresh_WithoutCookie_Is401()
    {
        Assert.Equal(HttpStatusCode.Unauthorized, (await RawClient().PostAsync("/auth/api/refresh", null)).StatusCode);
    }

    [Fact]
    public async Task Telegram_BadSignature_Is401_MissingHash_Is400()
    {
        var fields = AuthAppFactory.WidgetData(AuthAppFactory.NewTelegramId());
        fields["first_name"] = "Mallory";
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await RawClient().PostAsync("/auth/api/telegram", AuthAppFactory.WidgetJson(fields))).StatusCode);

        fields.Remove("hash");
        Assert.Equal(HttpStatusCode.BadRequest,
            (await RawClient().PostAsync("/auth/api/telegram", AuthAppFactory.WidgetJson(fields))).StatusCode);

        Assert.Equal(HttpStatusCode.BadRequest,
            (await RawClient().PostAsync("/auth/api/telegram", JsonContent.Create(new[] { 1 }))).StatusCode);
    }

    [Fact]
    public async Task Telegram_NullOptionalFields_AreNotPartOfCheckString()
    {
        var fields = AuthAppFactory.WidgetData(AuthAppFactory.NewTelegramId());
        var body = fields.ToDictionary(f => f.Key, f => (object?)f.Value);
        body["last_name"] = null; // the widget omits it; a client may serialise it as null

        var response = await RawClient().PostAsync("/auth/api/telegram", JsonContent.Create(body));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("https://evil.example", null)]
    [InlineData("null", null)]
    [InlineData(null, "https://evil.example/page")]
    public async Task UnsafeMethod_WithoutAllowedOrigin_Is403(string? origin, string? referer)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });
        var request = new HttpRequestMessage(HttpMethod.Post, "/auth/api/telegram")
        {
            Content = AuthAppFactory.WidgetJson(AuthAppFactory.WidgetData(AuthAppFactory.NewTelegramId())),
        };
        if (origin is not null) request.Headers.Add("Origin", origin);
        if (referer is not null) request.Headers.Referrer = new Uri(referer);

        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(request)).StatusCode);
    }

    [Fact]
    public async Task UnsafeMethod_WithAllowedReferer_AndNoOrigin_IsAllowed()
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });
        var request = new HttpRequestMessage(HttpMethod.Post, "/auth/api/telegram")
        {
            Content = AuthAppFactory.WidgetJson(AuthAppFactory.WidgetData(AuthAppFactory.NewTelegramId())),
        };
        request.Headers.Referrer = new Uri(AuthAppFactory.Origin + "/cashpulse/");

        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(request)).StatusCode);
    }
}
