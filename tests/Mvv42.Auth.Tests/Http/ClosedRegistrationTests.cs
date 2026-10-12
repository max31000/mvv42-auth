using System.Net;
using System.Net.Http.Json;
using System.Reflection;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Mvv42.Auth.Data;
using Mvv42.Auth.Invites;
using Mvv42.Auth.Sessions;
using Mvv42.Auth.Telegram;

namespace Mvv42.Auth.Tests.Http;

/// <summary>The service with <c>Auth:Registration</c> left at its default (<c>invite</c>).</summary>
public class InviteAuthAppFactory : AuthAppFactory
{
    protected override string? Registration => null;
}

/// <summary>
/// Closed registration (mvv42-infra docs/specs/2026-10-12-closed-registration.md): known users and owners log in as
/// before; an unknown telegram user needs a valid invite code in <c>X-Invite-Code</c>; nothing about a refused stranger
/// is stored.
/// </summary>
public class ClosedRegistrationTests(InviteAuthAppFactory factory) : IClassFixture<InviteAuthAppFactory>
{
    private const string App = "reg_app";

    private InMemoryAuthStore Store => (InMemoryAuthStore)factory.Services.GetRequiredService<IAuthStore>();
    private InviteCodeHasher Hasher => factory.Services.GetRequiredService<InviteCodeHasher>();

    private static async Task<JsonElement> Json(HttpResponseMessage r) => await r.Content.ReadFromJsonAsync<JsonElement>();

    private static async Task AssertError(HttpResponseMessage r, HttpStatusCode status, string code)
    {
        Assert.Equal(status, r.StatusCode);
        Assert.Equal(code, (await Json(r)).GetProperty("error").GetString());
        Assert.False(r.Headers.Contains("Set-Cookie"));
    }

    private HttpClient Raw(WebApplicationFactory<Program>? app = null)
    {
        var client = (app ?? factory).CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });
        client.DefaultRequestHeaders.Add("Origin", AuthAppFactory.Origin);
        return client;
    }

    private static HttpRequestMessage TelegramRequest(Dictionary<string, string> fields, string? code)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/auth/api/telegram") { Content = AuthAppFactory.WidgetJson(fields) };
        if (code is not null)
            request.Headers.TryAddWithoutValidation("X-Invite-Code", code);
        return request;
    }

    private Task<HttpResponseMessage> PostTelegram(Dictionary<string, string> fields, string? code = null, HttpClient? client = null) =>
        (client ?? Raw()).SendAsync(TelegramRequest(fields, code));

    private async Task EnsureAppAsync() =>
        await Store.UpsertAppAsync(new App { Id = App, Name = "Reg", Anonymous = false, Access = AppAccess.Invite });

    /// <summary>A new-format invite stored like the admin API does (HMAC of the normalised code).</summary>
    private async Task<(string Code, long Id)> InviteAsync(string? appId, int maxUses = 1, DateTime? expiresAt = null, InviteCodeHasher? hasher = null, IAuthStore? store = null)
    {
        var code = InviteCodes.Generate();
        var id = await (store ?? Store).CreateInviteAsync(new Invite
        {
            CodeHash = (hasher ?? Hasher).Hash(code.Replace("-", "")),
            AppId = appId,
            MaxUses = maxUses,
            ExpiresAt = expiresAt ?? DateTime.UtcNow.AddDays(1),
            CreatedAt = DateTime.UtcNow,
        });
        return (code, id);
    }

    private async Task<int> Uses(long inviteId, IAuthStore? store = null) =>
        (await (store ?? Store).ListInvitesAsync()).Single(i => i.Id == inviteId).Uses;

    private async Task<IReadOnlyList<LoginEvent>> Journal() => await Store.ListLoginEventsAsync(null, null, 500);

    /// <summary>Nothing about this telegram id anywhere: no user, no journal row; refusals left only bare time stamps.</summary>
    private async Task AssertNothingStoredAbout(long tg)
    {
        Assert.DoesNotContain(await Store.ListUsersAsync(), u => u.TelegramId == tg);
        var journal = await Journal();
        Assert.DoesNotContain(journal, e => e.TelegramId == tg);
        Assert.All(journal.Where(e => e.Result == LoginResult.DeniedUnregistered),
            e => Assert.Equal((null, null, null, null), (e.UserId, e.TelegramId, e.Ip, e.UserAgent)));
    }

    private async Task<int> DeniedUnregisteredCount() => (await Journal()).Count(e => e.Result == LoginResult.DeniedUnregistered);

    private static JsonElement AppOf(JsonElement me, string id) =>
        me.GetProperty("apps").EnumerateArray().Single(a => a.GetProperty("id").GetString() == id);

    // ---- known users

    [Fact]
    public async Task KnownUser_LogsIn_CodeHeaderIgnored_NoInviteField()
    {
        var tg = AuthAppFactory.NewTelegramId();
        await Store.UpsertUserAsync(new TelegramProfile(tg, "Known", null, null, null), DateTime.UtcNow);
        var (code, id) = await InviteAsync(null);

        var response = await PostTelegram(AuthAppFactory.WidgetData(tg), code);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await Json(response);
        Assert.Equal(tg, body.GetProperty("user").GetProperty("telegramId").GetInt64());
        Assert.False(body.TryGetProperty("invite", out _));
        Assert.Equal(0, await Uses(id));
        Assert.Contains(response.Headers.GetValues("Set-Cookie"), c => c.StartsWith("mvv42_rt="));
    }

    [Fact]
    public async Task Owner_WithoutRow_LogsIn_WithoutInvite()
    {
        var ownerTg = AuthAppFactory.NewTelegramId();
        using var app = factory.WithWebHostBuilder(b => b.UseSetting("Auth:AdminTelegramIds", ownerTg.ToString()));

        var response = await Raw(app).SendAsync(TelegramRequest(AuthAppFactory.WidgetData(ownerTg), null));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await Json(response);
        Assert.True(body.GetProperty("user").GetProperty("isOwner").GetBoolean());
        Assert.False(body.TryGetProperty("invite", out _));
    }

    [Fact]
    public async Task BlockedUser_WithCode_IsStillBlocked()
    {
        var tg = AuthAppFactory.NewTelegramId();
        var user = await Store.UpsertUserAsync(new TelegramProfile(tg, "Blocked", null, null, null), DateTime.UtcNow);
        await Store.SetUserBlockedAsync(user.Id, true, DateTime.UtcNow);
        var (code, id) = await InviteAsync(null);

        await AssertError(await PostTelegram(AuthAppFactory.WidgetData(tg), code), HttpStatusCode.Forbidden, "user_blocked");
        Assert.Equal(0, await Uses(id));
    }

    // ---- strangers

    [Fact]
    public async Task Stranger_WithoutCode_403InviteRequired_StoresNothing_ButTheTime()
    {
        var tg = AuthAppFactory.NewTelegramId();
        var before = await DeniedUnregisteredCount();

        var request = TelegramRequest(AuthAppFactory.WidgetData(tg), null);
        request.Headers.UserAgent.ParseAdd("StrangerBrowser/1.0");
        await AssertError(await Raw().SendAsync(request), HttpStatusCode.Forbidden, "invite_required");
        await AssertError(await PostTelegram(AuthAppFactory.WidgetData(tg), code: "   "), HttpStatusCode.Forbidden, "invite_required");

        Assert.Equal(before + 2, await DeniedUnregisteredCount());
        await AssertNothingStoredAbout(tg);
        Assert.DoesNotContain(await Journal(), e => e.UserAgent == "StrangerBrowser/1.0");
    }

    /// <summary>Refusals hand the widget payload back: the shell resends the very same data with a code.</summary>
    [Fact]
    public async Task Stranger_RefusedThenResendsSamePayloadWithCode_Registers()
    {
        await EnsureAppAsync();
        var tg = AuthAppFactory.NewTelegramId();
        var fields = AuthAppFactory.WidgetData(tg, "Newbie");
        var (code, id) = await InviteAsync(App, maxUses: 3);

        await AssertError(await PostTelegram(fields), HttpStatusCode.Forbidden, "invite_required");
        var response = await PostTelegram(fields, code);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await Json(response);
        Assert.Equal(App, body.GetProperty("invite").GetProperty("appId").GetString());
        Assert.Equal("Newbie", body.GetProperty("user").GetProperty("name").GetString());
        Assert.True(AppOf(body, App).GetProperty("granted").GetBoolean());
        Assert.Contains(response.Headers.GetValues("Set-Cookie"), c => c.StartsWith("mvv42_at="));
        Assert.Equal(1, await Uses(id));

        var user = (await Store.GetUserByTelegramIdAsync(tg))!;
        Assert.Equal([App], await Store.GetGrantsAsync(user.Id));
        Assert.Contains(await Journal(), e => e.Result == LoginResult.Ok && e.UserId == user.Id && e.TelegramId == tg);

        // The payload is used now: a replay is refused as before.
        await AssertError(await PostTelegram(fields, code), HttpStatusCode.Unauthorized, "Replayed");
        Assert.Equal(1, await Uses(id));

        // A registered user is known: the next login needs no code.
        Assert.Equal(HttpStatusCode.OK, (await PostTelegram(AuthAppFactory.WidgetData(tg))).StatusCode);
    }

    [Fact]
    public async Task Stranger_BadCodes_400_PayloadReusable_NothingStored()
    {
        var tg = AuthAppFactory.NewTelegramId();
        var fields = AuthAppFactory.WidgetData(tg);
        var (expired, expiredId) = await InviteAsync(null, maxUses: 5, expiresAt: DateTime.UtcNow.AddMinutes(-1));
        var (exhausted, exhaustedId) = await InviteAsync(null, maxUses: 1);
        Assert.Equal(HttpStatusCode.OK, (await PostTelegram(AuthAppFactory.WidgetData(AuthAppFactory.NewTelegramId()), exhausted)).StatusCode);
        var before = await DeniedUnregisteredCount();

        await AssertError(await PostTelegram(fields, InviteCodes.Generate()), HttpStatusCode.BadRequest, "invite_not_found");
        await AssertError(await PostTelegram(fields, expired), HttpStatusCode.BadRequest, "invite_expired");
        await AssertError(await PostTelegram(fields, exhausted), HttpStatusCode.BadRequest, "invite_exhausted");
        await AssertError(await PostTelegram(fields, "nope"), HttpStatusCode.BadRequest, "invalid_invite_format");
        await AssertError(await PostTelegram(fields, "ABCD-EFGH-JKMU"), HttpStatusCode.BadRequest, "invalid_invite_format");

        Assert.Equal(before + 5, await DeniedUnregisteredCount());
        Assert.Equal(0, await Uses(expiredId));
        Assert.Equal(1, await Uses(exhaustedId));
        await AssertNothingStoredAbout(tg);

        // still the same payload, never marked as used
        var (good, _) = await InviteAsync(null);
        Assert.Equal(HttpStatusCode.OK, (await PostTelegram(fields, good)).StatusCode);
    }

    [Fact]
    public async Task Stranger_LoginOnlyInvite_RegistersWithoutGrant_InviteAppIdNull()
    {
        var tg = AuthAppFactory.NewTelegramId();
        var (code, id) = await InviteAsync(null);

        var response = await PostTelegram(AuthAppFactory.WidgetData(tg), code);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var invite = (await Json(response)).GetProperty("invite");
        Assert.Equal(JsonValueKind.Null, invite.GetProperty("appId").ValueKind);
        Assert.Empty(await Store.GetGrantsAsync((await Store.GetUserByTelegramIdAsync(tg))!.Id));
        Assert.Equal(1, await Uses(id));
    }

    [Theory]
    [InlineData("0123ABCD1XYZ", "0123-abcd-1xyz")]     // lower case
    [InlineData("4567EFGH1JKM", " 4567 EFGH 1JKM ")]   // spaces instead of hyphens
    [InlineData("89AB0CDE1FGH", "89ab-OCDE-iFGH")]     // Crockford: O → 0, I → 1
    [InlineData("2345VWXY1Z00", "2345-vwxy-LZoo")]     // Crockford: L → 1, o → 0
    public async Task Stranger_CodeIsNormalised(string normalized, string typed)
    {
        var id = await Store.CreateInviteAsync(new Invite
        {
            CodeHash = Hasher.Hash(normalized),
            MaxUses = 1,
            ExpiresAt = DateTime.UtcNow.AddDays(1),
            CreatedAt = DateTime.UtcNow,
        });

        var response = await PostTelegram(AuthAppFactory.WidgetData(AuthAppFactory.NewTelegramId()), typed);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, await Uses(id));
    }

    [Fact]
    public async Task Stranger_LegacyCode_Sha256OfRaw_StillWorks()
    {
        const string legacy = "kq3Zp9_x-AbCdEfGhIjKlMn";
        var id = await Store.CreateInviteAsync(new Invite
        {
            CodeHash = SecretTokens.Sha256Hex(legacy),
            MaxUses = 1,
            ExpiresAt = DateTime.UtcNow.AddDays(1),
            CreatedAt = DateTime.UtcNow,
        });

        Assert.Equal(HttpStatusCode.OK, (await PostTelegram(AuthAppFactory.WidgetData(AuthAppFactory.NewTelegramId()), legacy)).StatusCode);
        Assert.Equal(1, await Uses(id));
    }

    [Fact]
    public async Task ParallelSamePayload_ExactlyOneSuccess()
    {
        var tg = AuthAppFactory.NewTelegramId();
        var fields = AuthAppFactory.WidgetData(tg);
        var (code, id) = await InviteAsync(null, maxUses: 10);

        var responses = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => PostTelegram(fields, code)));

        Assert.Single(responses, r => r.StatusCode == HttpStatusCode.OK);
        Assert.All(responses.Where(r => r.StatusCode != HttpStatusCode.OK), r => Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode));
        Assert.Equal(1, await Uses(id));
        Assert.Single(await Store.ListUsersAsync(), u => u.TelegramId == tg);
    }

    [Fact]
    public async Task ParallelSamePayload_KnownUser_ExactlyOneSuccess()
    {
        var tg = AuthAppFactory.NewTelegramId();
        await Store.UpsertUserAsync(new TelegramProfile(tg, "Known", null, null, null), DateTime.UtcNow);
        var fields = AuthAppFactory.WidgetData(tg);

        var responses = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => PostTelegram(fields)));

        Assert.Single(responses, r => r.StatusCode == HttpStatusCode.OK);
    }

    /// <summary>The telegram id got a row between the lookup and the INSERT (a parallel login won): a known user, no use spent.</summary>
    [Fact]
    public async Task RegistrationRace_DuplicateTelegramId_LogsInAsKnownUser_WithoutConsumingTheInvite()
    {
        var inner = new InMemoryAuthStore();
        using var app = factory.WithWebHostBuilder(b => b.ConfigureTestServices(s => s.AddSingleton(RaceLosingStore.Wrap(inner))));
        var (code, id) = await InviteAsync(null, hasher: app.Services.GetRequiredService<InviteCodeHasher>(), store: inner);
        var tg = AuthAppFactory.NewTelegramId();

        var response = await Raw(app).SendAsync(TelegramRequest(AuthAppFactory.WidgetData(tg, "Racer"), code));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await Json(response);
        Assert.False(body.TryGetProperty("invite", out _));
        Assert.Equal("Racer", body.GetProperty("user").GetProperty("name").GetString());
        Assert.Equal(0, await Uses(id, inner));
        Assert.Single(await inner.ListUsersAsync(), u => u.TelegramId == tg);
    }

    [Fact]
    public async Task DeletedUser_IsAStrangerAgain()
    {
        var tg = AuthAppFactory.NewTelegramId();
        var (code, _) = await InviteAsync(null);
        var login = await Json(await PostTelegram(AuthAppFactory.WidgetData(tg), code));

        Store.DeleteUser(login.GetProperty("user").GetProperty("id").GetInt64());

        await AssertError(await PostTelegram(AuthAppFactory.WidgetData(tg)), HttpStatusCode.Forbidden, "invite_required");
    }

    // ---- redeem (logged-in users) shares the lookup

    private async Task<HttpClient> KnownUserAsync()
    {
        var tg = AuthAppFactory.NewTelegramId();
        await Store.UpsertUserAsync(new TelegramProfile(tg, "Known", null, null, null), DateTime.UtcNow);
        var browser = factory.CreateBrowser();
        await AuthAppFactory.LoginAsync(browser, tg);
        return browser;
    }

    [Fact]
    public async Task Redeem_LoginOnlyInvite_200AlreadyGranted_AppIdNull_NothingConsumed()
    {
        var browser = await KnownUserAsync();
        var (code, id) = await InviteAsync(null);

        var response = await browser.PostAsJsonAsync("/auth/api/invites/redeem", new { code });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await Json(response);
        Assert.Equal(JsonValueKind.Null, body.GetProperty("appId").ValueKind);
        Assert.True(body.GetProperty("alreadyGranted").GetBoolean());
        Assert.NotEqual(JsonValueKind.Null, body.GetProperty("me").GetProperty("user").ValueKind);
        Assert.False(body.GetProperty("me").TryGetProperty("invite", out _));
        Assert.Equal(0, await Uses(id));
    }

    [Fact]
    public async Task Redeem_NewCode_NormalisedLikeRegistration_IncludingCyrillicLookalikes()
    {
        await EnsureAppAsync();
        var browser = await KnownUserAsync();
        const string normalized = "ABCEHKMPTX01";
        var id = await Store.CreateInviteAsync(new Invite
        {
            CodeHash = Hasher.Hash(normalized),
            AppId = App,
            MaxUses = 1,
            ExpiresAt = DateTime.UtcNow.AddDays(1),
            CreatedAt = DateTime.UtcNow,
        });

        // Cyrillic А В С Е Н К М Р Т Х typed on a Russian layout, lower case, O and l for 0 and 1
        var response = await browser.PostAsJsonAsync("/auth/api/invites/redeem", new { code = " авсе-нкмр-тхol " });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(App, (await Json(response)).GetProperty("appId").GetString());
        Assert.Equal(1, await Uses(id));
    }

    // ---- admin

    private async Task<HttpClient> OwnerAsync()
    {
        var owner = factory.CreateBrowser();
        await AuthAppFactory.LoginAsync(owner, AuthAppFactory.AdminTelegramId);
        return owner;
    }

    [Fact]
    public async Task Admin_CreateLoginOnlyInvite_FormattedCode_ThatRegisters()
    {
        var owner = await OwnerAsync();

        var created = await owner.PostAsJsonAsync("/auth/api/admin/invites", new { appId = (string?)null, maxUses = 2, expiresInHours = 24 });

        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        var body = await Json(created);
        Assert.Equal(JsonValueKind.Null, body.GetProperty("appId").ValueKind);
        var code = body.GetProperty("code").GetString()!;
        Assert.Matches("^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$", code);
        var id = body.GetProperty("id").GetInt64();

        // stored as the peppered HMAC of the normalised code, never as the code or its plain SHA-256
        var stored = (await Store.ListInvitesAsync()).Single(i => i.Id == id);
        Assert.Equal(Hasher.Hash(code.Replace("-", "")), stored.CodeHash);

        var listed = (await Json(await owner.GetAsync("/auth/api/admin/invites"))).EnumerateArray().Single(i => i.GetProperty("id").GetInt64() == id);
        Assert.Equal(JsonValueKind.Null, listed.GetProperty("appId").ValueKind);
        Assert.Equal("active", listed.GetProperty("status").GetString());

        Assert.Equal(HttpStatusCode.OK, (await PostTelegram(AuthAppFactory.WidgetData(AuthAppFactory.NewTelegramId()), code.ToLowerInvariant())).StatusCode);
        Assert.Equal(1, await Uses(id));
    }

    [Fact]
    public async Task Admin_CreateInvite_AppIdMustBeExplicit()
    {
        var owner = await OwnerAsync();

        await AssertBad(await owner.PostAsJsonAsync("/auth/api/admin/invites", new { maxUses = 1 }), "invalid_app_id");
        await AssertBad(await owner.PostAsJsonAsync("/auth/api/admin/invites", new { appId = 5 }), "invalid_app_id");
        await AssertBad(await owner.PostAsJsonAsync("/auth/api/admin/invites", new { appId = "" }), "unknown_app");
        await AssertBad(await owner.PostAsJsonAsync("/auth/api/admin/invites", new { appId = "no_such_app" }), "unknown_app");
        Assert.Equal(HttpStatusCode.OK, (await owner.PostAsJsonAsync("/auth/api/admin/invites", new { appId = "cashpulse" })).StatusCode);

        static async Task AssertBad(HttpResponseMessage r, string code)
        {
            Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
            Assert.Equal(code, (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString());
        }
    }

    [Fact]
    public async Task Overview_CountsDeniedUnregistered7d()
    {
        var owner = await OwnerAsync();
        await Store.AddLoginEventAsync(new LoginEvent { At = DateTime.UtcNow.AddDays(-8), Result = LoginResult.DeniedUnregistered });
        var before = (await Json(await owner.GetAsync("/auth/api/admin/overview"))).GetProperty("deniedUnregistered7d").GetInt32();

        await AssertError(await PostTelegram(AuthAppFactory.WidgetData(AuthAppFactory.NewTelegramId())), HttpStatusCode.Forbidden, "invite_required");

        var after = (await Json(await owner.GetAsync("/auth/api/admin/overview"))).GetProperty("deniedUnregistered7d").GetInt32();
        Assert.Equal(before + 1, after);
        Assert.Equal(await Store.CountLoginEventsAsync(DateTime.UtcNow.AddDays(-7), LoginResult.DeniedUnregistered), after);
    }
}

/// <summary>Open registration (<c>Auth:Registration=open</c>, the base test factory).</summary>
public class OpenRegistrationTests(AuthAppFactory factory) : IClassFixture<AuthAppFactory>
{
    private static HttpRequestMessage TelegramRequest(long tg, string? code)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/auth/api/telegram") { Content = AuthAppFactory.WidgetJson(AuthAppFactory.WidgetData(tg)) };
        if (code is not null)
            request.Headers.TryAddWithoutValidation("X-Invite-Code", code);
        return request;
    }

    private HttpClient Raw()
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });
        client.DefaultRequestHeaders.Add("Origin", AuthAppFactory.Origin);
        return client;
    }

    [Fact]
    public async Task Stranger_WithoutCode_Registers()
    {
        var response = await Raw().SendAsync(TelegramRequest(AuthAppFactory.NewTelegramId(), null));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False((await response.Content.ReadFromJsonAsync<JsonElement>()).TryGetProperty("invite", out _));
    }

    [Fact]
    public async Task Stranger_WithValidCode_IsRedeemedAsAtRegistration()
    {
        var store = factory.Services.GetRequiredService<IAuthStore>();
        var code = InviteCodes.Generate();
        var id = await store.CreateInviteAsync(new Invite
        {
            CodeHash = factory.Services.GetRequiredService<InviteCodeHasher>().Hash(code.Replace("-", "")),
            AppId = "cashpulse",
            MaxUses = 1,
            ExpiresAt = DateTime.UtcNow.AddDays(1),
            CreatedAt = DateTime.UtcNow,
        });

        var response = await Raw().SendAsync(TelegramRequest(AuthAppFactory.NewTelegramId(), code));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("cashpulse", (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("invite").GetProperty("appId").GetString());
        Assert.Equal(1, (await store.ListInvitesAsync()).Single(i => i.Id == id).Uses);
    }

    [Theory]
    [InlineData("nope")]
    [InlineData("ZZZZ-ZZZZ-ZZZZ")]
    public async Task Stranger_WithBadCode_CodeIgnored_Registers(string code)
    {
        var response = await Raw().SendAsync(TelegramRequest(AuthAppFactory.NewTelegramId(), code));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False((await response.Content.ReadFromJsonAsync<JsonElement>()).TryGetProperty("invite", out _));
    }
}

/// <summary>
/// Simulates losing the registration race: right before <see cref="IAuthStore.RegisterWithInviteAsync"/> another request
/// creates the user, so the plain INSERT hits the unique telegram id.
/// </summary>
public class RaceLosingStore : DispatchProxy
{
    private IAuthStore _inner = null!;

    public static IAuthStore Wrap(IAuthStore inner)
    {
        var proxy = Create<IAuthStore, RaceLosingStore>();
        ((RaceLosingStore)(object)proxy)._inner = inner;
        return proxy;
    }

    protected override object? Invoke(MethodInfo? method, object?[]? args)
    {
        if (method!.Name == nameof(IAuthStore.RegisterWithInviteAsync))
        {
            var profile = (TelegramProfile)args![0]!;
            _inner.UpsertUserAsync(profile with { FirstName = "Winner" }, (DateTime)args[2]!).GetAwaiter().GetResult();
        }
        try
        {
            return method.Invoke(_inner, args);
        }
        catch (TargetInvocationException e) when (e.InnerException is not null)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw(e.InnerException);
            throw;
        }
    }
}
