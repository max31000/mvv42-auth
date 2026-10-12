using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Mvv42.Auth.Data;
using Mvv42.Auth.Invites;
using Mvv42.Auth.Sessions;
using Mvv42.Auth.Telegram;

namespace Mvv42.Auth.Tests.Http;

/// <summary>
/// Code-first login (mvv42-infra docs/specs/2026-10-12-code-first-login.md): <c>POST /auth/api/invites/check</c> tells
/// the shell whether a code is usable before the Telegram widget is loaded. Anonymous, consumes nothing, stores nothing
/// on success; a failed check is journalled as <c>invite_check_failed</c> with only the time.
/// </summary>
public class InviteCheckTests(InviteAuthAppFactory factory) : IClassFixture<InviteAuthAppFactory>
{
    private const string App = "check_app";
    private const string Path = "/auth/api/invites/check";

    private InMemoryAuthStore Store => (InMemoryAuthStore)factory.Services.GetRequiredService<IAuthStore>();
    private InviteCodeHasher Hasher => factory.Services.GetRequiredService<InviteCodeHasher>();

    private HttpClient Raw()
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });
        client.DefaultRequestHeaders.Add("Origin", AuthAppFactory.Origin);
        return client;
    }

    private Task<HttpResponseMessage> Check(object body, HttpClient? client = null) => (client ?? Raw()).PostAsJsonAsync(Path, body);

    private static async Task<JsonElement> Json(HttpResponseMessage r) => await r.Content.ReadFromJsonAsync<JsonElement>();

    private async Task<(string Code, long Id)> InviteAsync(string? appId, int maxUses = 1, DateTime? expiresAt = null, int uses = 0)
    {
        if (appId is not null)
            await Store.UpsertAppAsync(new App { Id = appId, Name = "Check", Anonymous = false, Access = AppAccess.Invite });
        var code = InviteCodes.Generate();
        var id = await Store.CreateInviteAsync(new Invite
        {
            CodeHash = Hasher.Hash(code.Replace("-", "")),
            AppId = appId,
            MaxUses = maxUses,
            ExpiresAt = expiresAt ?? DateTime.UtcNow.AddDays(1),
            CreatedAt = DateTime.UtcNow,
        });
        // Consume uses through the store, as a real redeem would (needs an app invite).
        for (var i = 0; i < uses; i++)
        {
            var user = await Store.UpsertUserAsync(new TelegramProfile(AuthAppFactory.NewTelegramId(), "U", null, null, null), DateTime.UtcNow);
            await Store.RedeemInviteAsync(Hasher.Hash(code.Replace("-", "")), user.Id, DateTime.UtcNow);
        }
        return (code, id);
    }

    private async Task<int> Uses(long id) => (await Store.ListInvitesAsync()).Single(i => i.Id == id).Uses;

    private async Task<IReadOnlyList<LoginEvent>> Journal() => await Store.ListLoginEventsAsync(null, null, 500);

    private async Task AssertCheckError(HttpResponseMessage r, string code)
    {
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.Equal(code, (await Json(r)).GetProperty("error").GetString());
        Assert.False(r.Headers.Contains("Set-Cookie"));
    }

    [Fact]
    public async Task ValidCode_200_AppId_NothingConsumedOrStored()
    {
        var (code, id) = await InviteAsync(App);
        var journal = (await Journal()).Count;
        var users = (await Store.ListUsersAsync()).Count;

        var r = await Check(new { code });

        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.False(r.Headers.Contains("Set-Cookie"));
        var body = await Json(r);
        Assert.True(body.GetProperty("valid").GetBoolean());
        Assert.Equal(App, body.GetProperty("appId").GetString());
        Assert.Equal(0, await Uses(id));
        Assert.Equal(journal, (await Journal()).Count);
        Assert.Equal(users, (await Store.ListUsersAsync()).Count);
    }

    [Fact]
    public async Task LoginOnlyInvite_200_AppIdNull()
    {
        var (code, _) = await InviteAsync(null);

        var r = await Check(new { code });

        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Equal(JsonValueKind.Null, (await Json(r)).GetProperty("appId").ValueKind);
    }

    [Fact]
    public async Task Code_IsNormalisedLikeRegistration()
    {
        var (code, _) = await InviteAsync(null);
        // lower case, spaces instead of dashes, Cyrillic look-alikes where the code has A/B/E/K/M/H/P/C/T/X
        var typed = "  " + string.Concat(code.ToLowerInvariant().Replace('-', ' ')
            .Select(c => c switch { 'a' => 'а', 'e' => 'е', 'k' => 'к', 'c' => 'с', 'x' => 'х', _ => c })) + " ";

        var r = await Check(new { code = typed });

        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
    }

    [Fact]
    public async Task LegacyCode_Sha256OfRaw_IsValid()
    {
        var raw = SecretTokens.New(16);
        await Store.CreateInviteAsync(new Invite { CodeHash = SecretTokens.Sha256Hex(raw), AppId = null, MaxUses = 1, ExpiresAt = DateTime.UtcNow.AddDays(1), CreatedAt = DateTime.UtcNow });

        Assert.Equal(HttpStatusCode.OK, (await Check(new { code = raw })).StatusCode);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("ABC")]
    [InlineData("ABCD-EFGH-ÏJKL")]
    public async Task MalformedCode_400InvalidInviteFormat(string code) =>
        await AssertCheckError(await Check(new { code }), "invalid_invite_format");

    [Fact]
    public async Task MissingCode_400InvalidInviteFormat() =>
        await AssertCheckError(await Check(new { }), "invalid_invite_format");

    [Theory]
    [InlineData("application/json", "")]
    [InlineData("application/json", "{")]
    [InlineData("application/json", "not json")]
    [InlineData("application/json", "[\"ABCD-EFGH-JKMN\"]")]
    [InlineData("application/json", "\"ABCD-EFGH-JKMN\"")]
    [InlineData("application/json", "{\"code\":123}")]
    [InlineData("application/json", "{\"code\":null}")]
    [InlineData("text/plain", "ABCD-EFGH-JKMN")]
    public async Task MalformedBody_400InvalidInviteFormat_Journalled(string contentType, string body)
    {
        var before = (await Journal()).Count(e => e.Result == LoginResult.InviteCheckFailed);

        var r = await Raw().PostAsync(Path, new StringContent(body, System.Text.Encoding.UTF8, contentType));

        await AssertCheckError(r, "invalid_invite_format");
        Assert.Equal(before + 1, (await Journal()).Count(e => e.Result == LoginResult.InviteCheckFailed));
    }

    [Fact]
    public async Task UnknownCode_400InviteNotFound() =>
        await AssertCheckError(await Check(new { code = InviteCodes.Generate() }), "invite_not_found");

    [Fact]
    public async Task ExpiredCode_400InviteExpired()
    {
        var (code, _) = await InviteAsync(App, expiresAt: DateTime.UtcNow.AddMinutes(-1));

        await AssertCheckError(await Check(new { code }), "invite_expired");
    }

    [Fact]
    public async Task ExhaustedCode_400InviteExhausted()
    {
        var (code, id) = await InviteAsync(App, maxUses: 1, uses: 1);
        Assert.Equal(1, await Uses(id));

        await AssertCheckError(await Check(new { code }), "invite_exhausted");
        Assert.Equal(1, await Uses(id));
    }

    [Fact]
    public async Task ExpiredAndExhausted_400InviteExpired()
    {
        var (code, _) = await InviteAsync(App, maxUses: 1, uses: 1, expiresAt: DateTime.UtcNow.AddSeconds(2));
        await Task.Delay(TimeSpan.FromSeconds(2.2));

        await AssertCheckError(await Check(new { code }), "invite_expired");
    }

    [Fact]
    public async Task FailedChecks_AreJournalled_AsInviteCheckFailed_WithoutPii()
    {
        var (expired, _) = await InviteAsync(App, expiresAt: DateTime.UtcNow.AddMinutes(-1));
        var client = Raw();
        client.DefaultRequestHeaders.Add("User-Agent", "check-test/1.0");
        var before = (await Journal()).Count(e => e.Result == LoginResult.InviteCheckFailed);

        await Check(new { code = "nope" }, client);
        await Check(new { code = InviteCodes.Generate() }, client);
        await Check(new { code = expired }, client);

        var failed = (await Journal()).Where(e => e.Result == LoginResult.InviteCheckFailed).ToList();
        Assert.Equal(before + 3, failed.Count);
        Assert.All(failed, e => Assert.Equal((null, null, null, null), (e.UserId, e.TelegramId, e.Ip, e.UserAgent)));
    }

    [Fact]
    public async Task WithoutAllowedOrigin_403()
    {
        var (code, _) = await InviteAsync(null);
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });

        var r = await client.PostAsJsonAsync(Path, new { code });

        Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
        Assert.Equal("origin_not_allowed", (await Json(r)).GetProperty("error").GetString());
    }

    [Fact]
    public async Task Overview_CountsFailedInviteChecks7d()
    {
        var owner = factory.CreateBrowser();
        await AuthAppFactory.LoginAsync(owner, AuthAppFactory.AdminTelegramId);
        await Store.AddLoginEventAsync(new LoginEvent { At = DateTime.UtcNow.AddDays(-8), Result = LoginResult.InviteCheckFailed });
        var before = (await Json(await owner.GetAsync("/auth/api/admin/overview"))).GetProperty("failedInviteChecks7d").GetInt32();

        await AssertCheckError(await Check(new { code = InviteCodes.Generate() }), "invite_not_found");

        var after = (await Json(await owner.GetAsync("/auth/api/admin/overview"))).GetProperty("failedInviteChecks7d").GetInt32();
        Assert.Equal(before + 1, after);
        Assert.Equal(await Store.CountLoginEventsAsync(DateTime.UtcNow.AddDays(-7), LoginResult.InviteCheckFailed), after);
    }
}
