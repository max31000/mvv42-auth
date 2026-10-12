using Mvv42.Auth.Access;
using Mvv42.Auth.Data;
using Mvv42.Auth.Sessions;

namespace Mvv42.Auth.Http.Endpoints;

public static class InviteEndpoints
{
    public sealed record RedeemRequest(string? Code);

    /// <summary><c>me</c> is the caller's <c>/me</c> payload after the grant.</summary>
    public sealed record RedeemResponse(string AppId, bool AlreadyGranted, MeResponse Me);

    private static IResult Bad(string error) => Results.Json(new { error }, statusCode: StatusCodes.Status400BadRequest);

    /// <summary>
    /// POST /api/invites/redeem {code} — grants the app and reissues the access cookie at once.
    /// 200 <c>{ appId, alreadyGranted, me }</c>; 400 <c>invite_not_found</c> / <c>invite_expired</c> /
    /// <c>invite_exhausted</c>; 401 without a token or for a blocked/deleted user.
    /// </summary>
    public static void MapInviteEndpoints(this RouteGroupBuilder api) =>
        api.MapPost("/invites/redeem", async (RedeemRequest body, HttpContext ctx, IAuthStore store,
            UserAccessService access, AuthCookies cookies, TimeProvider time) =>
        {
            // Blocked or deleted callers do not get to consume an invite.
            var userId = ctx.User.CurrentUserId()!.Value;
            if (await access.GetAsync(userId) is not { } callerAccess)
                return Results.Unauthorized();

            if (string.IsNullOrWhiteSpace(body.Code))
                return Bad("invite_not_found");

            var codeHash = SecretTokens.Sha256Hex(body.Code.Trim());

            // The policy already lets the caller use the app (admin/owner, public app, existing grant): nothing to
            // grant, so no use is consumed, whatever state the invite is in.
            if (await store.GetInviteByCodeHashAsync(codeHash) is { } invite && callerAccess.AllowedApps.Contains(invite.AppId))
            {
                cookies.SetAccess(ctx.Response, access.Issue(callerAccess));
                return Results.Ok(new RedeemResponse(invite.AppId, AlreadyGranted: true, UserAccessService.ToMe(callerAccess)));
            }

            var result = await store.RedeemInviteAsync(codeHash, userId, time.GetUtcNow().UtcDateTime);
            switch (result.Status)
            {
                case InviteRedeemStatus.NotFound: return Bad("invite_not_found");
                case InviteRedeemStatus.Expired: return Bad("invite_expired");
                case InviteRedeemStatus.Exhausted: return Bad("invite_exhausted");
            }

            var userAccess = await access.GetAsync(userId);
            if (userAccess is null)
                return Results.Unauthorized();

            cookies.SetAccess(ctx.Response, access.Issue(userAccess));
            return Results.Ok(new RedeemResponse(result.AppId!, result.Status == InviteRedeemStatus.AlreadyGranted,
                UserAccessService.ToMe(userAccess)));
        }).RequireAuthorization().RequireRateLimiting(AuthEndpoints.RateLimitPolicy);
}
