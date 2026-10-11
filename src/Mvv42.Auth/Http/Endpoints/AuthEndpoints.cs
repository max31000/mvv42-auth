using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Mvv42.Auth.Access;
using Mvv42.Auth.Data;
using Mvv42.Auth.Sessions;
using Mvv42.Auth.Telegram;

namespace Mvv42.Auth.Http.Endpoints;

public static class AuthEndpoints
{
    /// <summary>JwtBearer scheme reading the access cookie (the service's own tokens).</summary>
    public const string Scheme = "mvv42";
    public const string AdminPolicy = "admin";

    /// <summary>Maps <c>/api/telegram|refresh|logout|me</c>; returns the <c>/api</c> group (OriginGuard applied).</summary>
    public static RouteGroupBuilder MapAuthApi(this IEndpointRouteBuilder app)
    {
        var api = app.MapGroup("/api").AddEndpointFilter<OriginGuard>();
        api.MapPost("/telegram", TelegramLogin);
        api.MapPost("/refresh", Refresh);
        api.MapPost("/logout", Logout);
        api.MapGet("/me", Me);
        return api;
    }

    public static long? CurrentUserId(this ClaimsPrincipal user) =>
        long.TryParse(user.FindFirst("sub")?.Value, out var id) ? id : null;

    private static IResult Error(string code, int status) => Results.Json(new { error = code }, statusCode: status);

    /// <summary>POST /api/telegram — raw Login Widget object → session, both cookies, /me payload.</summary>
    private static async Task<IResult> TelegramLogin(
        JsonElement body, HttpContext ctx, TelegramVerifier verifier, IAuthStore store, SessionService sessions,
        UserAccessService access, AuthCookies cookies, TimeProvider time)
    {
        var fields = TelegramAuthData.ToFields(body);
        if (fields is null)
            return Error("invalid_body", StatusCodes.Status400BadRequest);

        var check = verifier.Verify(fields, time.GetUtcNow());
        if (check.Error == TelegramVerifyError.NotConfigured)
            return Error("telegram_not_configured", StatusCodes.Status503ServiceUnavailable);
        if (!check.Ok)
            return Error(check.Error.ToString(), check.IsMalformed ? StatusCodes.Status400BadRequest : StatusCodes.Status401Unauthorized);

        var user = await store.UpsertUserAsync(TelegramAuthData.ToProfile(fields), time.GetUtcNow().UtcDateTime);

        // A new login replaces whatever session this browser had.
        await sessions.RevokeAsync(cookies.ReadRefresh(ctx.Request));
        var (session, refreshToken) = await sessions.CreateAsync(user.Id, ctx.Request.Headers.UserAgent.ToString());

        var userAccess = (await access.GetAsync(user.Id))!;
        cookies.SetAccess(ctx.Response, access.Issue(userAccess));
        cookies.SetRefresh(ctx.Response, refreshToken, session.ExpiresAt);
        return Results.Ok(UserAccessService.ToMe(userAccess));
    }

    /// <summary>POST /api/refresh — rotation (or access-only within the 30 s grace); 401 + cleared cookies otherwise.</summary>
    private static async Task<IResult> Refresh(HttpContext ctx, SessionService sessions, UserAccessService access, AuthCookies cookies) =>
        await RefreshCookiesAsync(ctx, sessions, access, cookies) is null
            ? Error("invalid_refresh_token", StatusCodes.Status401Unauthorized)
            : Results.NoContent();

    /// <summary>POST /api/logout — revokes the session and deletes both cookies.</summary>
    private static async Task<IResult> Logout(HttpContext ctx, SessionService sessions, AuthCookies cookies)
    {
        await sessions.RevokeAsync(cookies.ReadRefresh(ctx.Request));
        cookies.Clear(ctx.Response);
        return Results.NoContent();
    }

    /// <summary>
    /// GET /api/me — works anonymously. Without a valid access cookie but with a valid refresh cookie it
    /// refreshes implicitly (same logic as /refresh, spec §9.4), so clients just call /me on start.
    /// </summary>
    private static async Task<IResult> Me(HttpContext ctx, SessionService sessions, UserAccessService access, AuthCookies cookies)
    {
        ctx.Response.Headers.CacheControl = "no-store";

        UserAccess? userAccess = null;
        var auth = await ctx.AuthenticateAsync(Scheme);
        if (auth.Succeeded && auth.Principal.CurrentUserId() is { } userId)
            userAccess = await access.GetAsync(userId);
        else if (cookies.ReadRefresh(ctx.Request) is not null)
            userAccess = await RefreshCookiesAsync(ctx, sessions, access, cookies);

        return Results.Ok(userAccess is null ? await access.AnonymousAsync() : UserAccessService.ToMe(userAccess));
    }

    private static async Task<UserAccess?> RefreshCookiesAsync(
        HttpContext ctx, SessionService sessions, UserAccessService access, AuthCookies cookies)
    {
        var result = await sessions.RefreshAsync(cookies.ReadRefresh(ctx.Request));
        var userAccess = result.Succeeded ? await access.GetAsync(result.Session!.UserId) : null;
        if (userAccess is null)
        {
            cookies.Clear(ctx.Response);
            return null;
        }

        cookies.SetAccess(ctx.Response, access.Issue(userAccess));
        if (result.Status == RefreshStatus.Rotated)
            cookies.SetRefresh(ctx.Response, result.NewRefreshToken!, result.Session!.ExpiresAt);
        return userAccess;
    }
}
