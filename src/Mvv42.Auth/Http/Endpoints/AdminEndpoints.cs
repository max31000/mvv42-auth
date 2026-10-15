using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using Mvv42.Auth.Access;
using Mvv42.Auth.Data;
using Mvv42.Auth.Invites;
using Mvv42.Auth.Options;

namespace Mvv42.Auth.Http.Endpoints;

/// <summary>
/// Admin API under <c>/api/admin</c>, policy <c>owner</c> (contract: mvv42-infra round-2 plan, addendum A).
/// Changes to other users apply on their next access token (≤ 10 min); the caller's own access cookie is reissued
/// after every mutation.
/// </summary>
public static partial class AdminEndpoints
{
    /// <summary>Paths taken by the platform itself; an app id becomes the URL prefix <c>/&lt;id&gt;/</c>.</summary>
    public static readonly IReadOnlySet<string> ReservedAppIds =
        new HashSet<string>(StringComparer.Ordinal) { "auth", "api", "assets", "health", ".well-known", "portal", "admin" };

    public const int DefaultLoginsLimit = 100;
    public const int MaxLoginsLimit = 500;
    public const int UserDetailLogins = 50;

    [GeneratedRegex("^[a-z][a-z0-9_-]{0,63}$")]
    private static partial Regex AppIdPattern();

    public sealed record AppRequest(string? Name, bool Anonymous, string? Access);
    public sealed record SetAdminRequest(bool IsAdmin);
    public sealed record SetBlockedRequest(bool Blocked);
    public sealed record GrantRequest(long UserId, string? AppId);
    /// <summary><c>appId</c> must be present: an app id, or an explicit <c>null</c> for a login-only invite.</summary>
    public sealed record CreateInviteRequest(JsonElement AppId, int MaxUses = 1, int ExpiresInHours = 168);

    public sealed record AdminUser(
        long Id, long TelegramId, string Name, string? Username, string? PhotoUrl,
        bool IsAdmin, bool IsOwner, bool IsBlocked, DateTime? BlockedAt,
        DateTime CreatedAt, DateTime? LastLoginAt, int ActiveSessions, IReadOnlyList<string> Grants);

    public sealed record AdminSession(long Id, DateTime CreatedAt, DateTime? LastUsedAt, DateTime ExpiresAt, string? UserAgent, string? Ip);

    public sealed record AdminLoginEvent(
        long Id, DateTime At, long? UserId, long? TelegramId, string? UserName, string? Ip, string? UserAgent, string Result);

    public sealed record UserDetail(AdminUser User, IReadOnlyList<AdminSession> Sessions, IReadOnlyList<AdminLoginEvent> Logins);

    public sealed record LoginsPage(IReadOnlyList<AdminLoginEvent> Items, long? NextBefore);

    public sealed record OverviewApp(string Id, string Name, bool Anonymous, string Access, int GrantedUsers);

    /// <param name="DeniedUnregistered7d">Refused logins of unknown users (no/bad invite code) in the last 7 days.</param>
    /// <param name="FailedInviteChecks7d">Codes refused by <c>POST /invites/check</c> in the last 7 days.</param>
    public sealed record Overview(
        int Users, int ActiveSessions, int Logins24h, int Logins7d, int Blocked, int DeniedUnregistered7d,
        int FailedInviteChecks7d, IReadOnlyList<OverviewApp> Apps);

    public sealed record AdminInvite(
        long Id, string? AppId, int MaxUses, int Uses, DateTime? ExpiresAt, long? CreatedBy, DateTime CreatedAt, string Status);

    private static IResult Error(string error, int status) => Results.Json(new { error }, statusCode: status);

    private static IResult Bad(string error) => Error(error, StatusCodes.Status400BadRequest);

    private static IResult NotFound(string error) => Error(error, StatusCodes.Status404NotFound);

    private static DateTime Now(TimeProvider time) => time.GetUtcNow().UtcDateTime;

    public static void MapAdminEndpoints(this RouteGroupBuilder api)
    {
        var admin = api.MapGroup("/admin")
            .RequireAuthorization(AuthEndpoints.OwnerPolicy)
            .AddEndpointFilter(CallerFilter);

        // ---- owner check for nginx auth_request (monitoring proxy, mvv42-infra spec 2026-10-16):
        // 204 for the owner, 401/403 otherwise (policy + CallerFilter). Reads nothing else, writes nothing.
        admin.MapGet("/check", () => Results.NoContent());

        // ---- overview
        admin.MapGet("/overview", Overview_);

        // ---- users
        admin.MapGet("/users", async (IAuthStore store, IOptions<AuthOptions> options, TimeProvider time) =>
        {
            var users = await store.ListUsersAsync();
            var sessions = await store.CountActiveSessionsAsync(Now(time));
            var grants = (await store.ListGrantsAsync(null)).ToLookup(g => g.UserId, g => g.AppId);
            var owners = options.Value.AdminTelegramIdSet();
            return users.Select(u => ToAdminUser(u, owners, sessions.GetValueOrDefault(u.Id), grants[u.Id])).ToList();
        });

        admin.MapGet("/users/{id:long}", async (long id, IAuthStore store, IOptions<AuthOptions> options, TimeProvider time) =>
        {
            if (await store.GetUserAsync(id) is not { } user)
                return NotFound("user_not_found");

            var sessions = await store.ListActiveSessionsAsync(id, Now(time));
            var logins = await store.ListLoginEventsAsync(id, beforeId: null, UserDetailLogins);
            return Results.Ok(new UserDetail(
                ToAdminUser(user, options.Value.AdminTelegramIdSet(), sessions.Count, await store.GetGrantsAsync(id)),
                sessions.Select(s => new AdminSession(s.Id, s.CreatedAt, s.LastUsedAt, s.ExpiresAt, s.UserAgent, s.Ip)).ToList(),
                logins.Select(ToAdminLoginEvent).ToList()));
        });

        admin.MapPut("/users/{id:long}/admin", async (long id, SetAdminRequest body, IAuthStore store, UserAccessService access) =>
        {
            if (await store.GetUserAsync(id) is not { } user)
                return NotFound("user_not_found");
            // An owner is admin through the env whatever the flag says: changing it would be a silent no-op.
            if (access.IsOwner(user.TelegramId))
                return Bad("cannot_change_owner");
            return await store.SetUserAdminAsync(id, body.IsAdmin) ? Results.NoContent() : NotFound("user_not_found");
        });

        admin.MapPut("/users/{id:long}/blocked", async (long id, SetBlockedRequest body, IAuthStore store,
            UserAccessService access, TimeProvider time) =>
        {
            if (await store.GetUserAsync(id) is not { } user)
                return NotFound("user_not_found");
            if (body.Blocked && access.IsOwner(user.TelegramId))
                return Bad("cannot_block_owner");

            var now = Now(time);
            if (!await store.SetUserBlockedAsync(id, body.Blocked, now))
                return NotFound("user_not_found");
            if (body.Blocked)
                await store.RevokeUserSessionsAsync(id, now);
            return Results.NoContent();
        });

        admin.MapPost("/users/{id:long}/revoke-sessions", async (long id, IAuthStore store, TimeProvider time) =>
        {
            if (await store.GetUserAsync(id) is null)
                return NotFound("user_not_found");
            await store.RevokeUserSessionsAsync(id, Now(time));
            return Results.NoContent();
        });

        // ---- sessions
        admin.MapDelete("/sessions/{id:long}", async (long id, IAuthStore store, TimeProvider time) =>
        {
            if (await store.GetSessionAsync(id) is null)
                return NotFound("session_not_found");
            await store.RevokeSessionAsync(id, Now(time)); // already revoked: no-op
            return Results.NoContent();
        });

        // ---- login journal
        admin.MapGet("/logins", async (string? limit, string? before, IAuthStore store) =>
        {
            var take = DefaultLoginsLimit;
            if (limit is not null && (!int.TryParse(limit, NumberStyles.None, CultureInfo.InvariantCulture, out take)
                                      || take is < 1 or > MaxLoginsLimit))
                return Bad("invalid_limit");
            long? beforeId = null;
            if (before is not null)
            {
                if (!long.TryParse(before, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed))
                    return Bad("invalid_before");
                beforeId = parsed;
            }

            // One extra row tells whether another page exists.
            var rows = await store.ListLoginEventsAsync(null, beforeId, take + 1);
            var page = rows.Take(take).ToList();
            return Results.Ok(new LoginsPage(
                page.Select(ToAdminLoginEvent).ToList(),
                rows.Count > take ? page[^1].Id : null));
        });

        // ---- apps
        admin.MapGet("/apps", (IAuthStore store) => store.GetAppsAsync());

        admin.MapPut("/apps/{id}", async (string id, AppRequest body, IAuthStore store) =>
        {
            if (!AppIdPattern().IsMatch(id) || ReservedAppIds.Contains(id))
                return Bad("invalid_app_id");
            if (string.IsNullOrWhiteSpace(body.Name))
                return Bad("invalid_name");
            if (!AppAccess.IsValid(body.Access))
                return Bad("invalid_access");

            var app = new App { Id = id, Name = body.Name.Trim(), Anonymous = body.Anonymous, Access = body.Access! };
            await store.UpsertAppAsync(app);
            return Results.Ok(app);
        });

        admin.MapDelete("/apps/{id}", async (string id, IAuthStore store) =>
            await store.DeleteAppAsync(id) ? Results.NoContent() : Results.NotFound());

        // ---- grants
        admin.MapGet("/grants", (long? userId, IAuthStore store) => store.ListGrantsAsync(userId));

        admin.MapPost("/grants", async (GrantRequest body, IAuthStore store, TimeProvider time) =>
        {
            if (await store.GetUserAsync(body.UserId) is null)
                return Bad("unknown_user");
            if (!(await store.GetAppsAsync()).Any(a => a.Id == body.AppId))
                return Bad("unknown_app");
            await store.AddGrantAsync(body.UserId, body.AppId!, Now(time));
            return Results.NoContent();
        });

        admin.MapDelete("/grants/{userId:long}/{appId}", async (long userId, string appId, IAuthStore store) =>
            await store.RemoveGrantAsync(userId, appId) ? Results.NoContent() : Results.NotFound());

        // ---- invites (the code is returned once; only its peppered hash is stored)
        admin.MapGet("/invites", async (IAuthStore store, TimeProvider time) =>
        {
            var now = Now(time);
            return (await store.ListInvitesAsync())
                .Select(i => new AdminInvite(i.Id, i.AppId, i.MaxUses, i.Uses, i.ExpiresAt, i.CreatedBy, i.CreatedAt, InviteStatus(i, now)))
                .ToList();
        });

        admin.MapPost("/invites", async (CreateInviteRequest body, HttpContext ctx, IAuthStore store, TimeProvider time,
            InviteCodeHasher hasher) =>
        {
            // Missing (Undefined) or not a string/null → invalid_app_id; "" or an id that is not an app → unknown_app.
            string? appId;
            switch (body.AppId.ValueKind)
            {
                case JsonValueKind.Null:
                    appId = null;
                    break;
                case JsonValueKind.String:
                    appId = body.AppId.GetString();
                    if (!(await store.GetAppsAsync()).Any(a => a.Id == appId))
                        return Bad("unknown_app");
                    break;
                default:
                    return Bad("invalid_app_id");
            }
            if (body.MaxUses is < 1 or > 1000)
                return Bad("invalid_max_uses");
            if (body.ExpiresInHours is < 1 or > 24 * 365)
                return Bad("invalid_expiry");

            var now = Now(time);
            var code = InviteCodes.Generate();
            var invite = new Invite
            {
                CodeHash = hasher.Hash(InviteCodes.Parse(code)!.Value),
                AppId = appId,
                MaxUses = body.MaxUses,
                ExpiresAt = now.AddHours(body.ExpiresInHours),
                CreatedBy = ctx.User.CurrentUserId(),
                CreatedAt = now,
            };
            var id = await store.CreateInviteAsync(invite);
            return Results.Ok(new { id, code, invite.AppId, invite.MaxUses, invite.ExpiresAt });
        });

        admin.MapDelete("/invites/{id:long}", async (long id, IAuthStore store) =>
            await store.DeleteInviteAsync(id) ? Results.NoContent() : NotFound("invite_not_found"));
    }

    private static async Task<Overview> Overview_(IAuthStore store, IOptions<AuthOptions> options, TimeProvider time)
    {
        var now = Now(time);
        var users = await store.ListUsersAsync();
        var apps = await store.GetAppsAsync();
        var grants = (await store.ListGrantsAsync(null)).ToLookup(g => g.UserId, g => g.AppId);
        var sessions = await store.CountActiveSessionsAsync(now);
        var owners = options.Value.AdminTelegramIdSet();

        // "Granted" as in /me: who may use the app's authenticated features (blocked users may not).
        var granted = users.Where(u => !u.IsBlocked)
            .SelectMany(u => AccessPolicy.AllowedApps(AccessPolicy.IsAdmin(u, owners), apps, grants[u.Id]))
            .GroupBy(appId => appId, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.Ordinal);

        return new Overview(
            Users: users.Count,
            ActiveSessions: sessions.Values.Sum(),
            Logins24h: await store.CountLoginEventsAsync(now.AddHours(-24), LoginResult.Ok),
            Logins7d: await store.CountLoginEventsAsync(now.AddDays(-7), LoginResult.Ok),
            Blocked: users.Count(u => u.IsBlocked),
            DeniedUnregistered7d: await store.CountLoginEventsAsync(now.AddDays(-7), LoginResult.DeniedUnregistered),
            FailedInviteChecks7d: await store.CountLoginEventsAsync(now.AddDays(-7), LoginResult.InviteCheckFailed),
            Apps: apps.Select(a => new OverviewApp(a.Id, a.Name, a.Anonymous, a.Access, granted.GetValueOrDefault(a.Id))).ToList());
    }

    /// <summary><c>isAdmin</c> is effective (DB flag or owner), <c>grants</c> are the explicit grants.</summary>
    private static AdminUser ToAdminUser(User u, IReadOnlySet<long> owners, int activeSessions, IEnumerable<string> grants) => new(
        u.Id, u.TelegramId, u.DisplayName, u.Username, u.PhotoUrl,
        AccessPolicy.IsAdmin(u, owners), owners.Contains(u.TelegramId), u.IsBlocked, u.BlockedAt,
        u.CreatedAt, u.LastLoginAt, activeSessions, grants.Order(StringComparer.Ordinal).ToList());

    private static AdminLoginEvent ToAdminLoginEvent(LoginEvent e) =>
        new(e.Id, e.At, e.UserId, e.TelegramId, e.UserName, e.Ip, e.UserAgent, e.Result);

    /// <summary>
    /// <c>exhausted</c> wins over <c>expired</c>: no use left is the more final state. A NULL expiry (never written by
    /// the API, only possible for hand-made rows) never expires; it is serialised as <c>expiresAt: null</c>.
    /// </summary>
    private static string InviteStatus(Invite i, DateTime now) =>
        i.Uses >= i.MaxUses ? "exhausted" : i.ExpiresAt <= now ? "expired" : "active";

    /// <summary>
    /// Before: the caller must still pass <see cref="UserAccessService.GetAsync"/> (not deleted, not blocked) → else 401.
    /// After a mutation: the caller's rights may have changed (own grants, admin flag, app access) → fresh access cookie.
    /// </summary>
    private static async ValueTask<object?> CallerFilter(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var http = context.HttpContext;
        var access = http.RequestServices.GetRequiredService<UserAccessService>();
        if (http.User.CurrentUserId() is not { } userId || await access.GetAsync(userId) is null)
            return Results.Unauthorized();

        var result = await next(context);
        if (!HttpMethods.IsGet(http.Request.Method) && await access.GetAsync(userId) is { } userAccess)
            http.RequestServices.GetRequiredService<AuthCookies>().SetAccess(http.Response, access.Issue(userAccess));
        return result;
    }
}
