using Mvv42.Auth.Access;
using Mvv42.Auth.Data;
using Mvv42.Auth.Sessions;

namespace Mvv42.Auth.Http.Endpoints;

public static class InviteEndpoints
{
    public sealed record RedeemRequest(string? Code);

    /// <summary>POST /api/invites/redeem {code} — grants the app and reissues the access cookie at once.</summary>
    public static void MapInviteEndpoints(this RouteGroupBuilder api) =>
        api.MapPost("/invites/redeem", async (RedeemRequest body, HttpContext ctx, IAuthStore store,
            UserAccessService access, AuthCookies cookies, TimeProvider time) =>
        {
            if (string.IsNullOrWhiteSpace(body.Code))
                return Results.Json(new { error = "invalid_invite" }, statusCode: StatusCodes.Status400BadRequest);

            var userId = ctx.User.CurrentUserId()!.Value;
            var appId = await store.RedeemInviteAsync(SecretTokens.Sha256Hex(body.Code.Trim()), userId, time.GetUtcNow().UtcDateTime);
            if (appId is null)
                return Results.Json(new { error = "invalid_invite" }, statusCode: StatusCodes.Status400BadRequest);

            var userAccess = await access.GetAsync(userId);
            if (userAccess is null)
                return Results.Unauthorized();

            cookies.SetAccess(ctx.Response, access.Issue(userAccess));
            return Results.Ok(UserAccessService.ToMe(userAccess));
        }).RequireAuthorization().RequireRateLimiting(AuthEndpoints.RateLimitPolicy);
}
