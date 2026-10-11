using System.Text.RegularExpressions;
using Mvv42.Auth.Access;
using Mvv42.Auth.Data;
using Mvv42.Auth.Sessions;

namespace Mvv42.Auth.Http.Endpoints;

/// <summary>
/// Minimal admin CRUD under <c>/api/admin</c> (requires <c>adm=true</c>). Changes to other users apply on
/// their next token (≤ 10 min); the caller's own access cookie is reissued after every mutation.
/// </summary>
public static partial class AdminEndpoints
{
    /// <summary>Paths taken by the platform itself; an app id becomes the URL prefix <c>/&lt;id&gt;/</c>.</summary>
    public static readonly IReadOnlySet<string> ReservedAppIds =
        new HashSet<string>(StringComparer.Ordinal) { "auth", "api", "assets", "health", ".well-known", "portal" };

    [GeneratedRegex("^[a-z][a-z0-9_-]{0,63}$")]
    private static partial Regex AppIdPattern();

    public sealed record AppRequest(string? Name, bool Anonymous, string? Access);
    public sealed record SetAdminRequest(bool IsAdmin);
    public sealed record GrantRequest(long UserId, string? AppId);
    public sealed record CreateInviteRequest(string? AppId, int MaxUses = 1, int ExpiresInHours = 168);

    private static IResult Bad(string error) => Results.Json(new { error }, statusCode: StatusCodes.Status400BadRequest);

    public static void MapAdminEndpoints(this RouteGroupBuilder api)
    {
        var admin = api.MapGroup("/admin")
            .RequireAuthorization(AuthEndpoints.AdminPolicy)
            .AddEndpointFilter(ReissueCallerToken);

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

        // ---- users
        admin.MapGet("/users", (IAuthStore store) => store.ListUsersAsync());

        admin.MapPut("/users/{id:long}/admin", async (long id, SetAdminRequest body, IAuthStore store) =>
            await store.SetUserAdminAsync(id, body.IsAdmin) ? Results.NoContent() : Results.NotFound());

        // ---- grants
        admin.MapGet("/grants", (long? userId, IAuthStore store) => store.ListGrantsAsync(userId));

        admin.MapPost("/grants", async (GrantRequest body, IAuthStore store, TimeProvider time) =>
        {
            if (await store.GetUserAsync(body.UserId) is null)
                return Bad("unknown_user");
            if (!(await store.GetAppsAsync()).Any(a => a.Id == body.AppId))
                return Bad("unknown_app");
            await store.AddGrantAsync(body.UserId, body.AppId!, time.GetUtcNow().UtcDateTime);
            return Results.NoContent();
        });

        admin.MapDelete("/grants/{userId:long}/{appId}", async (long userId, string appId, IAuthStore store) =>
            await store.RemoveGrantAsync(userId, appId) ? Results.NoContent() : Results.NotFound());

        // ---- invites (the code is returned once; only its hash is stored)
        admin.MapGet("/invites", async (IAuthStore store) => (await store.ListInvitesAsync())
            .Select(i => new { i.Id, i.AppId, i.MaxUses, i.Uses, i.ExpiresAt, i.CreatedBy, i.CreatedAt }));

        admin.MapPost("/invites", async (CreateInviteRequest body, HttpContext ctx, IAuthStore store, TimeProvider time) =>
        {
            if (!(await store.GetAppsAsync()).Any(a => a.Id == body.AppId))
                return Bad("unknown_app");
            if (body.MaxUses is < 1 or > 1000)
                return Bad("invalid_max_uses");
            if (body.ExpiresInHours is < 1 or > 24 * 365)
                return Bad("invalid_expiry");

            var now = time.GetUtcNow().UtcDateTime;
            var code = SecretTokens.New(16);
            var invite = new Invite
            {
                CodeHash = SecretTokens.Sha256Hex(code),
                AppId = body.AppId!,
                MaxUses = body.MaxUses,
                ExpiresAt = now.AddHours(body.ExpiresInHours),
                CreatedBy = ctx.User.CurrentUserId(),
                CreatedAt = now,
            };
            var id = await store.CreateInviteAsync(invite);
            return Results.Ok(new { id, code, invite.AppId, invite.MaxUses, invite.ExpiresAt });
        });

        admin.MapDelete("/invites/{id:long}", async (long id, IAuthStore store) =>
            await store.DeleteInviteAsync(id) ? Results.NoContent() : Results.NotFound());
    }

    /// <summary>After a mutation the caller's rights may have changed (own grants, admin flag, app access) → fresh access cookie.</summary>
    private static async ValueTask<object?> ReissueCallerToken(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var result = await next(context);
        var http = context.HttpContext;
        if (!HttpMethods.IsGet(http.Request.Method) && http.User.CurrentUserId() is { } userId)
        {
            var access = http.RequestServices.GetRequiredService<UserAccessService>();
            if (await access.GetAsync(userId) is { } userAccess)
                http.RequestServices.GetRequiredService<AuthCookies>().SetAccess(http.Response, access.Issue(userAccess));
        }
        return result;
    }
}
