using Mvv42.Auth.Access;
using Mvv42.Auth.Data;
using Mvv42.Auth.Invites;

namespace Mvv42.Auth.Http.Endpoints;

public static class InviteEndpoints
{
    public sealed record RedeemRequest(string? Code);

    /// <summary><c>me</c> is the caller's <c>/me</c> payload after the grant; <c>appId</c> null = login-only invite.</summary>
    public sealed record RedeemResponse(string? AppId, bool AlreadyGranted, MeResponse Me);

    private static IResult Bad(string error) => Results.Json(new { error }, statusCode: StatusCodes.Status400BadRequest);

    /// <summary>
    /// POST /api/invites/redeem {code} — grants the app and reissues the access cookie at once.
    /// 200 <c>{ appId, alreadyGranted, me }</c>; 400 <c>invite_not_found</c> (also an empty or malformed code) /
    /// <c>invite_expired</c> / <c>invite_exhausted</c>; 401 without a token or for a blocked/deleted user.
    /// The code is normalised and looked up exactly as at registration (<see cref="InviteCodes"/>, <see cref="InviteCodeHasher"/>).
    /// </summary>
    public static void MapInviteEndpoints(this RouteGroupBuilder api) =>
        api.MapPost("/invites/redeem", async (RedeemRequest body, HttpContext ctx, IAuthStore store,
            UserAccessService access, AuthCookies cookies, TimeProvider time, InviteCodeHasher hasher) =>
        {
            // Blocked or deleted callers do not get to consume an invite.
            var userId = ctx.User.CurrentUserId()!.Value;
            if (await access.GetAsync(userId) is not { } callerAccess)
                return Results.Unauthorized();

            if (InviteCodes.Parse(body.Code) is not { } code
                || await store.FindInviteAsync(hasher.Candidates(code)) is not { } invite)
                return Bad("invite_not_found");

            // Nothing to grant — a login-only invite, or the policy already lets the caller use the app (admin/owner,
            // public app, existing grant): no use is consumed, whatever state the invite is in.
            if (invite.AppId is null || callerAccess.AllowedApps.Contains(invite.AppId))
            {
                cookies.SetAccess(ctx.Response, access.Issue(callerAccess));
                return Results.Ok(new RedeemResponse(invite.AppId, AlreadyGranted: true, UserAccessService.ToMe(callerAccess)));
            }

            var result = await store.RedeemInviteAsync(invite.CodeHash, userId, time.GetUtcNow().UtcDateTime);
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
            return Results.Ok(new RedeemResponse(result.AppId, result.Status == InviteRedeemStatus.AlreadyGranted,
                UserAccessService.ToMe(userAccess)));
        }).RequireAuthorization().RequireRateLimiting(AuthEndpoints.RateLimitPolicy);
}
