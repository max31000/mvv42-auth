using System.Net;
using System.Net.Http.Json;
using System.Reflection;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Mvv42.Auth.Data;
using Mvv42.Auth.Sessions;

namespace Mvv42.Auth.Tests.Http;

/// <summary>Admin API (round 2, contract addendum A): owner policy, users, blocking, sessions, login journal, overview.</summary>
public class AdminApiTests(AuthAppFactory factory) : IClassFixture<AuthAppFactory>
{
    private static async Task<JsonElement> Json(HttpResponseMessage r) => await r.Content.ReadFromJsonAsync<JsonElement>();

    private static async Task AssertError(HttpResponseMessage r, HttpStatusCode status, string code)
    {
        Assert.Equal(status, r.StatusCode);
        Assert.Equal(code, (await Json(r)).GetProperty("error").GetString());
    }

    private async Task<HttpClient> OwnerAsync()
    {
        var owner = factory.CreateBrowser();
        await AuthAppFactory.LoginAsync(owner, AuthAppFactory.AdminTelegramId);
        return owner;
    }

    private async Task<(HttpClient Client, long Id, long TelegramId)> UserAsync()
    {
        var client = factory.CreateBrowser();
        var tg = AuthAppFactory.NewTelegramId();
        var me = await Json(await AuthAppFactory.LoginAsync(client, tg));
        return (client, me.GetProperty("user").GetProperty("id").GetInt64(), tg);
    }

    private IAuthStore Store => factory.Services.GetRequiredService<IAuthStore>();

    /// <summary>Every route under /api/admin, with placeholder values for its parameters.</summary>
    private IReadOnlyList<(string Method, string Path)> AdminRoutes()
    {
        _ = factory.Server; // build the host
        return factory.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>()
            .Where(e => e.RoutePattern.RawText?.StartsWith("/api/admin", StringComparison.Ordinal) == true)
            .SelectMany(e => e.Metadata.GetMetadata<HttpMethodMetadata>()!.HttpMethods.Select(m => (m, Path(e.RoutePattern))))
            .ToList();

        static string Path(RoutePattern p) => "/auth" + string.Concat(p.PathSegments.Select(s => "/" + string.Concat(s.Parts.Select(part => part switch
        {
            RoutePatternLiteralPart l => l.Content,
            RoutePatternParameterPart { Name: "appId" or "id" } x when p.RawText!.Contains("apps/{id}") || x.Name == "appId" => "cashpulse",
            _ => "1",
        }))));
    }

    private static HttpRequestMessage Request(string method, string path) => new(new HttpMethod(method), path)
    {
        Content = method is "GET" or "DELETE" ? null : JsonContent.Create(new { }),
    };

    [Fact]
    public async Task EveryAdminEndpoint_RequiresOwner_NotJustAdminFlag()
    {
        var routes = AdminRoutes();
        Assert.True(routes.Count >= 17, $"only {routes.Count} admin routes found");

        // users.is_admin (access to access=admin apps) does not make an owner
        var (flagged, flaggedId, _) = await UserAsync();
        await Store.SetUserAdminAsync(flaggedId, true);
        await flagged.PostAsync("/auth/api/refresh", null);
        var me = await Json(await flagged.GetAsync("/auth/api/me"));
        Assert.True(me.GetProperty("user").GetProperty("isAdmin").GetBoolean());
        Assert.False(me.GetProperty("user").GetProperty("isOwner").GetBoolean());

        var anonymous = factory.CreateBrowser();
        foreach (var (method, path) in routes)
        {
            Assert.True(HttpStatusCode.Unauthorized == (await anonymous.SendAsync(Request(method, path))).StatusCode, $"{method} {path} anonymous");
            Assert.True(HttpStatusCode.Forbidden == (await flagged.SendAsync(Request(method, path))).StatusCode, $"{method} {path} is_admin");
        }
    }

    [Fact]
    public async Task Me_IsOwner_OnlyForAdminTelegramIds()
    {
        var owner = await OwnerAsync();
        var me = await Json(await owner.GetAsync("/auth/api/me"));
        Assert.True(me.GetProperty("user").GetProperty("isOwner").GetBoolean());
        Assert.True(me.GetProperty("user").GetProperty("isAdmin").GetBoolean());

        var (user, _, _) = await UserAsync();
        Assert.False((await Json(await user.GetAsync("/auth/api/me"))).GetProperty("user").GetProperty("isOwner").GetBoolean());
    }

    [Fact]
    public async Task Users_ListAndDetail_HaveContractShape()
    {
        var owner = await OwnerAsync();
        var (_, userId, tg) = await UserAsync();
        await owner.PutAsJsonAsync("/auth/api/admin/apps/shape_app", new { name = "S", anonymous = false, access = "invite" });
        await owner.PostAsJsonAsync("/auth/api/admin/grants", new { userId, appId = "shape_app" });

        var users = await Json(await owner.GetAsync("/auth/api/admin/users"));
        var u = users.EnumerateArray().Single(x => x.GetProperty("id").GetInt64() == userId);
        Assert.Equal(tg, u.GetProperty("telegramId").GetInt64());
        Assert.Equal("Max", u.GetProperty("name").GetString());
        Assert.Equal(JsonValueKind.Null, u.GetProperty("username").ValueKind);
        Assert.Equal(JsonValueKind.Null, u.GetProperty("photoUrl").ValueKind);
        Assert.False(u.GetProperty("isAdmin").GetBoolean());
        Assert.False(u.GetProperty("isOwner").GetBoolean());
        Assert.False(u.GetProperty("isBlocked").GetBoolean());
        Assert.Equal(JsonValueKind.Null, u.GetProperty("blockedAt").ValueKind);
        Assert.EndsWith("Z", u.GetProperty("createdAt").GetString());
        Assert.EndsWith("Z", u.GetProperty("lastLoginAt").GetString());
        Assert.Equal(1, u.GetProperty("activeSessions").GetInt32());
        Assert.Equal(["shape_app"], u.GetProperty("grants").EnumerateArray().Select(g => g.GetString()));
        Assert.Contains(users.EnumerateArray(), x => x.GetProperty("telegramId").GetInt64() == AuthAppFactory.AdminTelegramId
            && x.GetProperty("isOwner").GetBoolean() && x.GetProperty("isAdmin").GetBoolean());

        var detail = await Json(await owner.GetAsync($"/auth/api/admin/users/{userId}"));
        Assert.Equal(userId, detail.GetProperty("user").GetProperty("id").GetInt64());
        var session = Assert.Single(detail.GetProperty("sessions").EnumerateArray());
        Assert.True(session.GetProperty("id").GetInt64() > 0);
        foreach (var field in new[] { "createdAt", "lastUsedAt", "expiresAt", "userAgent", "ip" })
            Assert.True(session.TryGetProperty(field, out _), field);
        var login = Assert.Single(detail.GetProperty("logins").EnumerateArray());
        Assert.Equal("ok", login.GetProperty("result").GetString());
        Assert.Equal(userId, login.GetProperty("userId").GetInt64());
        Assert.Equal(tg, login.GetProperty("telegramId").GetInt64());
        Assert.Equal("Max", login.GetProperty("userName").GetString());

        await AssertError(await owner.GetAsync("/auth/api/admin/users/999999999"), HttpStatusCode.NotFound, "user_not_found");
    }

    [Fact]
    public async Task UnknownUser_404_UserNotFound_OnEveryUserMutation()
    {
        var owner = await OwnerAsync();
        await AssertError(await owner.PutAsJsonAsync("/auth/api/admin/users/999999999/admin", new { isAdmin = true }), HttpStatusCode.NotFound, "user_not_found");
        await AssertError(await owner.PutAsJsonAsync("/auth/api/admin/users/999999999/blocked", new { blocked = true }), HttpStatusCode.NotFound, "user_not_found");
        await AssertError(await owner.PostAsync("/auth/api/admin/users/999999999/revoke-sessions", null), HttpStatusCode.NotFound, "user_not_found");
        await AssertError(await owner.DeleteAsync("/auth/api/admin/sessions/999999999"), HttpStatusCode.NotFound, "session_not_found");
    }

    [Fact]
    public async Task Block_RevokesSessions_MeAnonymous_RefreshFails_LoginDenied_UnblockRestores()
    {
        var owner = await OwnerAsync();
        var (user, userId, tg) = await UserAsync();

        Assert.Equal(HttpStatusCode.NoContent, (await owner.PutAsJsonAsync($"/auth/api/admin/users/{userId}/blocked", new { blocked = true })).StatusCode);

        var listed = (await Json(await owner.GetAsync("/auth/api/admin/users"))).EnumerateArray().Single(x => x.GetProperty("id").GetInt64() == userId);
        Assert.True(listed.GetProperty("isBlocked").GetBoolean());
        Assert.EndsWith("Z", listed.GetProperty("blockedAt").GetString());
        Assert.Equal(0, listed.GetProperty("activeSessions").GetInt32());

        // the still-valid access cookie no longer yields a user, and cookies are cleared
        var me = await user.GetAsync("/auth/api/me");
        Assert.Equal(JsonValueKind.Null, (await Json(me)).GetProperty("user").ValueKind);
        Assert.Contains(me.Headers.GetValues("Set-Cookie"), c => c.StartsWith("mvv42_at=;"));
        Assert.Equal(HttpStatusCode.Unauthorized, (await user.PostAsync("/auth/api/refresh", null)).StatusCode);

        // a fresh Telegram login is refused before the profile is touched
        var denied = await user.PostAsync("/auth/api/telegram", AuthAppFactory.WidgetJson(AuthAppFactory.WidgetData(tg, "Changed")));
        await AssertError(denied, HttpStatusCode.Forbidden, "user_blocked");
        Assert.Equal("Max", (await Store.GetUserAsync(userId))!.FirstName);
        var logins = (await Json(await owner.GetAsync($"/auth/api/admin/users/{userId}"))).GetProperty("logins");
        Assert.Equal("denied_blocked", logins[0].GetProperty("result").GetString());
        Assert.Equal(tg, logins[0].GetProperty("telegramId").GetInt64());

        Assert.Equal(HttpStatusCode.NoContent, (await owner.PutAsJsonAsync($"/auth/api/admin/users/{userId}/blocked", new { blocked = false })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await user.PostAsync("/auth/api/telegram", AuthAppFactory.WidgetJson(AuthAppFactory.WidgetData(tg)))).StatusCode);
        Assert.Equal(userId, (await Json(await user.GetAsync("/auth/api/me"))).GetProperty("user").GetProperty("id").GetInt64());
    }

    [Fact]
    public async Task Block_Owner_IsRefused()
    {
        var owner = await OwnerAsync();
        var ownerId = (await Json(await owner.GetAsync("/auth/api/me"))).GetProperty("user").GetProperty("id").GetInt64();
        await AssertError(await owner.PutAsJsonAsync($"/auth/api/admin/users/{ownerId}/blocked", new { blocked = true }),
            HttpStatusCode.BadRequest, "cannot_block_owner");
        Assert.False((await Store.GetUserAsync(ownerId))!.IsBlocked);
    }

    [Fact]
    public async Task BlockedUser_Redeem_401()
    {
        var owner = await OwnerAsync();
        await owner.PutAsJsonAsync("/auth/api/admin/apps/blocked_redeem", new { name = "B", anonymous = false, access = "invite" });
        var code = (await Json(await owner.PostAsJsonAsync("/auth/api/admin/invites", new { appId = "blocked_redeem" }))).GetProperty("code").GetString();
        var (user, userId, _) = await UserAsync();

        await owner.PutAsJsonAsync($"/auth/api/admin/users/{userId}/blocked", new { blocked = true });

        Assert.Equal(HttpStatusCode.Unauthorized, (await user.PostAsJsonAsync("/auth/api/invites/redeem", new { code })).StatusCode);
        Assert.Empty(await Store.GetGrantsAsync(userId));
    }

    [Fact]
    public async Task Owner_FlaggedBlockedInDb_IsNeverTreatedAsBlocked()
    {
        // Not reachable through the API (cannot_block_owner), e.g. a row blocked before its id went into the env.
        using var isolated = new AuthAppFactory();
        var owner = isolated.CreateBrowser();
        var ownerId = (await Json(await AuthAppFactory.LoginAsync(owner, AuthAppFactory.AdminTelegramId))).GetProperty("user").GetProperty("id").GetInt64();
        await isolated.Services.GetRequiredService<IAuthStore>().SetUserBlockedAsync(ownerId, true, DateTime.UtcNow);

        Assert.Equal(ownerId, (await Json(await owner.GetAsync("/auth/api/me"))).GetProperty("user").GetProperty("id").GetInt64());
        Assert.Equal(HttpStatusCode.OK, (await owner.GetAsync("/auth/api/admin/users")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await owner.PostAsync("/auth/api/refresh", null)).StatusCode);
        await AuthAppFactory.LoginAsync(owner, AuthAppFactory.AdminTelegramId);
    }

    [Fact]
    public async Task Owner_AdminFlag_CannotBeChanged()
    {
        var owner = await OwnerAsync();
        var ownerId = (await Json(await owner.GetAsync("/auth/api/me"))).GetProperty("user").GetProperty("id").GetInt64();
        foreach (var value in new[] { false, true })
            await AssertError(await owner.PutAsJsonAsync($"/auth/api/admin/users/{ownerId}/admin", new { isAdmin = value }),
                HttpStatusCode.BadRequest, "cannot_change_owner");
        Assert.False((await Store.GetUserAsync(ownerId))!.IsAdmin); // DB flag untouched
    }

    [Fact]
    public async Task Logins_InvalidBefore_400()
    {
        var owner = await OwnerAsync();
        foreach (var bad in new[] { "x", "-1", "1.5" })
            await AssertError(await owner.GetAsync($"/auth/api/admin/logins?before={bad}"), HttpStatusCode.BadRequest, "invalid_before");
        Assert.Equal(HttpStatusCode.OK, (await owner.GetAsync("/auth/api/admin/logins?before=5")).StatusCode);
    }

    [Fact]
    public async Task Redeem_AppAlreadyAllowedByPolicy_AlreadyGranted_WithoutConsumingUse()
    {
        var owner = await OwnerAsync();
        await owner.PutAsJsonAsync("/auth/api/admin/apps/policy_app", new { name = "P", anonymous = false, access = "invite" });
        var invite = await Json(await owner.PostAsJsonAsync("/auth/api/admin/invites", new { appId = "policy_app", maxUses = 1 }));
        var publicInvite = await Json(await owner.PostAsJsonAsync("/auth/api/admin/invites", new { appId = "cashpulse", maxUses = 1 }));

        // owner (admin) already may use every app; a regular user already may use a public app
        var ownerRedeem = await Json(await owner.PostAsJsonAsync("/auth/api/invites/redeem", new { code = invite.GetProperty("code").GetString() }));
        Assert.True(ownerRedeem.GetProperty("alreadyGranted").GetBoolean());
        var (user, _, _) = await UserAsync();
        var userRedeem = await Json(await user.PostAsJsonAsync("/auth/api/invites/redeem", new { code = publicInvite.GetProperty("code").GetString() }));
        Assert.True(userRedeem.GetProperty("alreadyGranted").GetBoolean());
        Assert.Equal("cashpulse", userRedeem.GetProperty("appId").GetString());

        var invites = (await Json(await owner.GetAsync("/auth/api/admin/invites"))).EnumerateArray().ToList();
        foreach (var id in new[] { invite.GetProperty("id").GetInt64(), publicInvite.GetProperty("id").GetInt64() })
            Assert.Equal(0, invites.Single(i => i.GetProperty("id").GetInt64() == id).GetProperty("uses").GetInt32());
    }

    [Fact]
    public async Task LoginJournalFailure_NeverFailsALogin()
    {
        using var broken = factory.WithWebHostBuilder(b => b.ConfigureTestServices(s =>
            s.AddSingleton(FailingJournalStore.Wrap(new InMemoryAuthStore()))));
        var client = broken.CreateClient();
        client.DefaultRequestHeaders.Add("Origin", AuthAppFactory.Origin);
        var tg = AuthAppFactory.NewTelegramId();

        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync("/auth/api/telegram", AuthAppFactory.WidgetJson(AuthAppFactory.WidgetData(tg)))).StatusCode);
        var forged = AuthAppFactory.WidgetData(tg);
        forged["first_name"] = "Mallory";
        await AssertError(await client.PostAsync("/auth/api/telegram", AuthAppFactory.WidgetJson(forged)), HttpStatusCode.Unauthorized, "InvalidHash");
    }

    [Fact]
    public async Task RevokeSessions_And_DeleteSession_EndRefresh()
    {
        var owner = await OwnerAsync();
        var (user, userId, tg) = await UserAsync();

        Assert.Equal(HttpStatusCode.NoContent, (await owner.PostAsync($"/auth/api/admin/users/{userId}/revoke-sessions", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await user.PostAsync("/auth/api/refresh", null)).StatusCode);

        await AuthAppFactory.LoginAsync(user, tg);
        var sessionId = (await Json(await owner.GetAsync($"/auth/api/admin/users/{userId}"))).GetProperty("sessions")[0].GetProperty("id").GetInt64();
        Assert.Equal(HttpStatusCode.NoContent, (await owner.DeleteAsync($"/auth/api/admin/sessions/{sessionId}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await user.PostAsync("/auth/api/refresh", null)).StatusCode);
        Assert.Empty((await Json(await owner.GetAsync($"/auth/api/admin/users/{userId}"))).GetProperty("sessions").EnumerateArray());
        Assert.Equal(HttpStatusCode.NoContent, (await owner.DeleteAsync($"/auth/api/admin/sessions/{sessionId}")).StatusCode); // idempotent
    }

    [Fact]
    public async Task LoginJournal_RecordsResults_WithoutUnverifiedTelegramId_AndPages()
    {
        var owner = await OwnerAsync();
        var client = factory.CreateBrowser();
        client.DefaultRequestHeaders.UserAgent.ParseAdd("JournalTest/1.0");
        var tg = AuthAppFactory.NewTelegramId();

        var forged = AuthAppFactory.WidgetData(tg);
        forged["first_name"] = "Mallory"; // breaks the signature
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsync("/auth/api/telegram", AuthAppFactory.WidgetJson(forged))).StatusCode);
        var valid = AuthAppFactory.WidgetData(tg);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync("/auth/api/telegram", AuthAppFactory.WidgetJson(valid))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsync("/auth/api/telegram", AuthAppFactory.WidgetJson(valid))).StatusCode);

        var page = await Json(await owner.GetAsync("/auth/api/admin/logins?limit=3"));
        var items = page.GetProperty("items").EnumerateArray().ToList();
        Assert.Equal(["replayed", "ok", "invalid"], items.Select(i => i.GetProperty("result").GetString()));
        foreach (var unverified in new[] { items[0], items[2] })
        {
            Assert.Equal(JsonValueKind.Null, unverified.GetProperty("telegramId").ValueKind);
            Assert.Equal(JsonValueKind.Null, unverified.GetProperty("userId").ValueKind);
            Assert.Equal(JsonValueKind.Null, unverified.GetProperty("userName").ValueKind);
            // no verified identity behind it: no client data either
            Assert.Equal(JsonValueKind.Null, unverified.GetProperty("ip").ValueKind);
            Assert.Equal(JsonValueKind.Null, unverified.GetProperty("userAgent").ValueKind);
        }
        Assert.Equal("JournalTest/1.0", items[1].GetProperty("userAgent").GetString());
        Assert.Equal(tg, items[1].GetProperty("telegramId").GetInt64());
        Assert.EndsWith("Z", items[1].GetProperty("at").GetString());
        Assert.True(items[1].TryGetProperty("ip", out _));
        Assert.True(items[1].TryGetProperty("userAgent", out _));

        var nextBefore = page.GetProperty("nextBefore").GetInt64();
        Assert.Equal(items[2].GetProperty("id").GetInt64(), nextBefore);
        var next = await Json(await owner.GetAsync($"/auth/api/admin/logins?limit=1&before={nextBefore}"));
        Assert.True(next.GetProperty("items")[0].GetProperty("id").GetInt64() < nextBefore);

        var oldest = next.GetProperty("items").EnumerateArray().Last().GetProperty("id").GetInt64();
        var end = await Json(await owner.GetAsync($"/auth/api/admin/logins?before={oldest}&limit=500"));
        Assert.Equal(JsonValueKind.Null, end.GetProperty("nextBefore").ValueKind);

        foreach (var bad in new[] { "0", "501", "x" })
            Assert.Equal(HttpStatusCode.BadRequest, (await owner.GetAsync($"/auth/api/admin/logins?limit={bad}")).StatusCode);
    }

    [Fact]
    public async Task ClientIp_IsNormalised_InSessionsAndJournal()
    {
        using var mapped = factory.WithWebHostBuilder(b => b.ConfigureServices(s =>
            s.AddSingleton<IStartupFilter>(new RemoteIpFilter("::ffff:203.0.113.9"))));
        var owner = mapped.CreateClient();
        owner.DefaultRequestHeaders.Add("Origin", AuthAppFactory.Origin);
        await AuthAppFactory.LoginAsync(owner, AuthAppFactory.AdminTelegramId);
        var user = mapped.CreateClient();
        user.DefaultRequestHeaders.Add("Origin", AuthAppFactory.Origin);
        var userId = (await Json(await AuthAppFactory.LoginAsync(user, AuthAppFactory.NewTelegramId()))).GetProperty("user").GetProperty("id").GetInt64();

        var detail = await Json(await owner.GetAsync($"/auth/api/admin/users/{userId}"));
        Assert.Equal("203.0.113.9", detail.GetProperty("sessions")[0].GetProperty("ip").GetString());
        Assert.Equal("203.0.113.9", detail.GetProperty("logins")[0].GetProperty("ip").GetString());
    }

    private sealed class RemoteIpFilter(string ip) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use((ctx, nextMiddleware) =>
            {
                ctx.Connection.RemoteIpAddress = IPAddress.Parse(ip);
                return nextMiddleware(ctx);
            });
            next(app);
        };
    }

    [Fact]
    public async Task Overview_CountsAndApps()
    {
        var owner = await OwnerAsync();
        var (_, blockedId, _) = await UserAsync();
        await owner.PutAsJsonAsync($"/auth/api/admin/users/{blockedId}/blocked", new { blocked = true });

        var o = await Json(await owner.GetAsync("/auth/api/admin/overview"));
        var users = (await Json(await owner.GetAsync("/auth/api/admin/users"))).EnumerateArray().ToList();
        Assert.Equal(users.Count, o.GetProperty("users").GetInt32());
        Assert.Equal(users.Count(u => u.GetProperty("isBlocked").GetBoolean()), o.GetProperty("blocked").GetInt32());
        Assert.Equal(users.Sum(u => u.GetProperty("activeSessions").GetInt32()), o.GetProperty("activeSessions").GetInt32());
        Assert.True(o.GetProperty("logins24h").GetInt32() >= 2);
        Assert.True(o.GetProperty("logins7d").GetInt32() >= o.GetProperty("logins24h").GetInt32());

        var apps = o.GetProperty("apps").EnumerateArray().ToDictionary(a => a.GetProperty("id").GetString()!);
        Assert.Equal("admin", apps["bonds"].GetProperty("access").GetString());
        Assert.Equal("Облигации", apps["bonds"].GetProperty("name").GetString());
        Assert.False(apps["bonds"].GetProperty("anonymous").GetBoolean());
        // public: every non-blocked user; admin-only: owners/admins
        var active = users.Count(u => !u.GetProperty("isBlocked").GetBoolean());
        Assert.Equal(active, apps["cashpulse"].GetProperty("grantedUsers").GetInt32());
        Assert.Equal(users.Count(u => !u.GetProperty("isBlocked").GetBoolean() && u.GetProperty("isAdmin").GetBoolean()),
            apps["bonds"].GetProperty("grantedUsers").GetInt32());
    }

    [Fact]
    public async Task AppId_Admin_IsReserved()
    {
        var owner = await OwnerAsync();
        await AssertError(await owner.PutAsJsonAsync("/auth/api/admin/apps/admin", new { name = "x", anonymous = false, access = "public" }),
            HttpStatusCode.BadRequest, "invalid_app_id");
    }

    [Fact]
    public async Task Invites_Status_Delete404_And_RedeemOutcomes()
    {
        var owner = await OwnerAsync();
        await owner.PutAsJsonAsync("/auth/api/admin/apps/status_app", new { name = "S", anonymous = false, access = "invite" });
        var created = await Json(await owner.PostAsJsonAsync("/auth/api/admin/invites", new { appId = "status_app", maxUses = 1 }));
        var code = created.GetProperty("code").GetString()!;
        Assert.Equal("status_app", created.GetProperty("appId").GetString());
        Assert.Equal(1, created.GetProperty("maxUses").GetInt32());
        Assert.EndsWith("Z", created.GetProperty("expiresAt").GetString());

        // expired invite straight in the store (no clock control over the app)
        const string expiredCode = "expired-code-for-status-test";
        await Store.CreateInviteAsync(new Invite
        {
            CodeHash = SecretTokens.Sha256Hex(expiredCode),
            AppId = "status_app",
            MaxUses = 5,
            ExpiresAt = DateTime.UtcNow.AddHours(-1),
            CreatedAt = DateTime.UtcNow.AddDays(-1),
        });

        var (user, _, _) = await UserAsync();
        var redeemed = await user.PostAsJsonAsync("/auth/api/invites/redeem", new { code });
        Assert.Equal(HttpStatusCode.OK, redeemed.StatusCode);
        var body = await Json(redeemed);
        Assert.Equal("status_app", body.GetProperty("appId").GetString());
        Assert.False(body.GetProperty("alreadyGranted").GetBoolean());
        Assert.True(body.GetProperty("me").GetProperty("apps").EnumerateArray()
            .Single(a => a.GetProperty("id").GetString() == "status_app").GetProperty("granted").GetBoolean());
        Assert.Contains(redeemed.Headers.GetValues("Set-Cookie"), c => c.StartsWith("mvv42_at="));

        var again = await Json(await user.PostAsJsonAsync("/auth/api/invites/redeem", new { code }));
        Assert.True(again.GetProperty("alreadyGranted").GetBoolean());

        var (other, _, _) = await UserAsync();
        await AssertError(await other.PostAsJsonAsync("/auth/api/invites/redeem", new { code }), HttpStatusCode.BadRequest, "invite_exhausted");
        await AssertError(await other.PostAsJsonAsync("/auth/api/invites/redeem", new { code = expiredCode }), HttpStatusCode.BadRequest, "invite_expired");
        await AssertError(await other.PostAsJsonAsync("/auth/api/invites/redeem", new { code = "nope" }), HttpStatusCode.BadRequest, "invite_not_found");
        await AssertError(await other.PostAsJsonAsync("/auth/api/invites/redeem", new { code = " " }), HttpStatusCode.BadRequest, "invite_not_found");

        var invites = (await Json(await owner.GetAsync("/auth/api/admin/invites"))).EnumerateArray().Where(i => i.GetProperty("appId").GetString() == "status_app").ToList();
        Assert.Equal(["exhausted", "expired"], invites.Select(i => i.GetProperty("status").GetString()).Order());
        var exhausted = invites.Single(i => i.GetProperty("status").GetString() == "exhausted");
        Assert.Equal(1, exhausted.GetProperty("uses").GetInt32());
        Assert.False(exhausted.TryGetProperty("code", out _));
        Assert.False(exhausted.TryGetProperty("codeHash", out _));
        Assert.True(exhausted.GetProperty("createdBy").GetInt64() > 0);
        Assert.EndsWith("Z", exhausted.GetProperty("createdAt").GetString());

        var active = await Json(await owner.PostAsJsonAsync("/auth/api/admin/invites", new { appId = "status_app", maxUses = 2, expiresInHours = 1 }));
        var activeId = active.GetProperty("id").GetInt64();
        Assert.Contains((await Json(await owner.GetAsync("/auth/api/admin/invites"))).EnumerateArray(),
            i => i.GetProperty("id").GetInt64() == activeId && i.GetProperty("status").GetString() == "active");

        Assert.Equal(HttpStatusCode.NoContent, (await owner.DeleteAsync($"/auth/api/admin/invites/{activeId}")).StatusCode);
        await AssertError(await owner.DeleteAsync($"/auth/api/admin/invites/{activeId}"), HttpStatusCode.NotFound, "invite_not_found");
    }
}

/// <summary>An <see cref="IAuthStore"/> whose login journal is down (every other call goes to the inner store).</summary>
public class FailingJournalStore : DispatchProxy
{
    private IAuthStore _inner = null!;

    public static IAuthStore Wrap(IAuthStore inner)
    {
        var proxy = Create<IAuthStore, FailingJournalStore>();
        ((FailingJournalStore)(object)proxy)._inner = inner;
        return proxy;
    }

    protected override object? Invoke(MethodInfo? method, object?[]? args)
    {
        if (method!.Name == nameof(IAuthStore.AddLoginEventAsync))
            return Task.FromException<long>(new InvalidOperationException("login journal is down"));
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
