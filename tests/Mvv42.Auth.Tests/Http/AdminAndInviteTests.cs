using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Mvv42.Auth.Tests.Http;

public class AdminAndInviteTests(AuthAppFactory factory) : IClassFixture<AuthAppFactory>
{
    private async Task<HttpClient> AdminAsync()
    {
        var admin = factory.CreateBrowser();
        await AuthAppFactory.LoginAsync(admin, AuthAppFactory.AdminTelegramId);
        return admin;
    }

    private async Task<HttpClient> UserAsync()
    {
        var user = factory.CreateBrowser();
        await AuthAppFactory.LoginAsync(user, AuthAppFactory.NewTelegramId());
        return user;
    }

    private static async Task<JsonElement> Json(HttpResponseMessage r) => await r.Content.ReadFromJsonAsync<JsonElement>();

    private static bool Granted(JsonElement me, string appId) =>
        me.GetProperty("apps").EnumerateArray().Single(a => a.GetProperty("id").GetString() == appId).GetProperty("granted").GetBoolean();

    [Fact]
    public async Task AdminEndpoints_Unauthenticated_401_NonAdmin_403()
    {
        Assert.Equal(HttpStatusCode.Unauthorized, (await factory.CreateBrowser().GetAsync("/auth/api/admin/users")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await (await UserAsync()).GetAsync("/auth/api/admin/users")).StatusCode);
    }

    [Fact]
    public async Task AdminBootstrap_ViaAdminTelegramIds()
    {
        var admin = await AdminAsync();

        var me = await Json(await admin.GetAsync("/auth/api/me"));
        Assert.True(me.GetProperty("user").GetProperty("isAdmin").GetBoolean());
        Assert.True(Granted(me, "bonds"));
        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync("/auth/api/admin/users")).StatusCode);
    }

    [Fact]
    public async Task Admin_UpsertApp_ValidatesId()
    {
        var admin = await AdminAsync();

        foreach (var bad in new[] { "auth", "api", "assets", "health", "portal", "Bad", "a.b" })
        {
            var r = await admin.PutAsJsonAsync($"/auth/api/admin/apps/{bad}", new { name = "x", anonymous = false, access = "public" });
            Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        }

        var badAccess = await admin.PutAsJsonAsync("/auth/api/admin/apps/okapp", new { name = "x", anonymous = false, access = "everyone" });
        Assert.Equal(HttpStatusCode.BadRequest, badAccess.StatusCode);

        var ok = await admin.PutAsJsonAsync("/auth/api/admin/apps/okapp", new { name = "Ok", anonymous = true, access = "invite" });
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        var apps = await Json(await admin.GetAsync("/auth/api/admin/apps"));
        Assert.Contains(apps.EnumerateArray(), a => a.GetProperty("id").GetString() == "okapp" && a.GetProperty("access").GetString() == "invite");
    }

    [Fact]
    public async Task Admin_Grant_TakesEffectOnNextToken()
    {
        var admin = await AdminAsync();
        await admin.PutAsJsonAsync("/auth/api/admin/apps/granted_app", new { name = "G", anonymous = false, access = "invite" });

        var user = factory.CreateBrowser();
        var login = await Json(await AuthAppFactory.LoginAsync(user, AuthAppFactory.NewTelegramId()));
        var userId = login.GetProperty("user").GetProperty("id").GetInt64();
        Assert.False(Granted(login, "granted_app"));

        var grant = await admin.PostAsJsonAsync("/auth/api/admin/grants", new { userId, appId = "granted_app" });
        Assert.Equal(HttpStatusCode.NoContent, grant.StatusCode);
        Assert.True(Granted(await Json(await user.GetAsync("/auth/api/me")), "granted_app"));

        var grants = await Json(await admin.GetAsync($"/auth/api/admin/grants?userId={userId}"));
        Assert.Single(grants.EnumerateArray());

        Assert.Equal(HttpStatusCode.NoContent, (await admin.DeleteAsync($"/auth/api/admin/grants/{userId}/granted_app")).StatusCode);
        Assert.False(Granted(await Json(await user.GetAsync("/auth/api/me")), "granted_app"));

        var unknownApp = await admin.PostAsJsonAsync("/auth/api/admin/grants", new { userId, appId = "nope" });
        Assert.Equal(HttpStatusCode.BadRequest, unknownApp.StatusCode);
    }

    [Fact]
    public async Task Invite_Redeem_GrantsApp_AndReissuesAccessCookie()
    {
        var admin = await AdminAsync();
        await admin.PutAsJsonAsync("/auth/api/admin/apps/invite_app", new { name = "I", anonymous = false, access = "invite" });
        var created = await Json(await admin.PostAsJsonAsync("/auth/api/admin/invites", new { appId = "invite_app", maxUses = 1 }));
        var code = created.GetProperty("code").GetString();

        var user = await UserAsync();
        var redeem = await user.PostAsJsonAsync("/auth/api/invites/redeem", new { code });

        Assert.Equal(HttpStatusCode.OK, redeem.StatusCode);
        Assert.True(Granted(await Json(redeem), "invite_app"));
        Assert.Contains(redeem.Headers.GetValues("Set-Cookie"), c => c.StartsWith("mvv42_at="));

        var other = await UserAsync();
        Assert.Equal(HttpStatusCode.BadRequest, (await other.PostAsJsonAsync("/auth/api/invites/redeem", new { code })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await other.PostAsJsonAsync("/auth/api/invites/redeem", new { code = "nope" })).StatusCode);

        var invites = await Json(await admin.GetAsync("/auth/api/admin/invites"));
        Assert.Contains(invites.EnumerateArray(), i => i.GetProperty("appId").GetString() == "invite_app" && i.GetProperty("uses").GetInt32() == 1);
    }

    [Fact]
    public async Task Invite_Redeem_RequiresLogin()
    {
        var r = await factory.CreateBrowser().PostAsJsonAsync("/auth/api/invites/redeem", new { code = "x" });
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
    }

    [Fact]
    public async Task Admin_SetUserAdmin_AppliesToTargetsNextToken()
    {
        var admin = await AdminAsync();
        var user = factory.CreateBrowser();
        var login = await Json(await AuthAppFactory.LoginAsync(user, AuthAppFactory.NewTelegramId()));
        var userId = login.GetProperty("user").GetProperty("id").GetInt64();

        var r = await admin.PutAsJsonAsync($"/auth/api/admin/users/{userId}/admin", new { isAdmin = true });
        Assert.Equal(HttpStatusCode.NoContent, r.StatusCode);

        await user.PostAsync("/auth/api/refresh", null);
        Assert.Equal(HttpStatusCode.OK, (await user.GetAsync("/auth/api/admin/apps")).StatusCode);
    }
}
