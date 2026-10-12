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
    /// <summary>Authenticated and the <c>tg</c> claim is in <c>Auth:AdminTelegramIds</c> (claim-based; all of /api/admin).</summary>
    public const string OwnerPolicy = "owner";
    public const string RateLimitPolicy = "per-ip";

    /// <summary>Maps <c>/api/telegram|refresh|logout|me</c>; returns the <c>/api</c> group (OriginGuard applied).</summary>
    public static RouteGroupBuilder MapAuthApi(this IEndpointRouteBuilder app)
    {
        var api = app.MapGroup("/api").AddEndpointFilter<OriginGuard>();
        api.MapPost("/telegram", TelegramLogin).RequireRateLimiting(RateLimitPolicy);
        api.MapPost("/refresh", Refresh).RequireRateLimiting(RateLimitPolicy);
        api.MapPost("/logout", Logout);
        api.MapGet("/me", Me);
        return api;
    }

    public static long? CurrentUserId(this ClaimsPrincipal user) =>
        long.TryParse(user.FindFirst("sub")?.Value, out var id) ? id : null;

    private static IResult Error(string code, int status) => Results.Json(new { error = code }, statusCode: status);

    /// <summary>
    /// POST /api/telegram — raw Login Widget object → session, both cookies, /me payload. Every attempt that gets past
    /// body parsing is written to <c>login_events</c>; a blocked user is refused before the profile is touched.
    /// </summary>
    private static async Task<IResult> TelegramLogin(
        JsonElement body, HttpContext ctx, TelegramVerifier verifier, IAuthStore store, SessionService sessions,
        UserAccessService access, AuthCookies cookies, TimeProvider time, TelegramReplayCache replay)
    {
        var fields = TelegramAuthData.ToFields(body);
        if (fields is null)
            return Error("invalid_body", StatusCodes.Status400BadRequest);

        var check = verifier.Verify(fields, time.GetUtcNow());
        if (check.Error == TelegramVerifyError.NotConfigured)
            return Error("telegram_not_configured", StatusCodes.Status503ServiceUnavailable);

        // The telegram id of a payload that failed verification (or was replayed) is unverified: never stored.
        if (!check.Ok)
        {
            await LogLoginAsync(ctx, store, time, LoginResult.Invalid, null, null);
            return Error(check.Error.ToString(), check.IsMalformed ? StatusCodes.Status400BadRequest : StatusCodes.Status401Unauthorized);
        }
        if (!replay.TryUse(fields["hash"]))
        {
            await LogLoginAsync(ctx, store, time, LoginResult.Replayed, null, null);
            return Error("Replayed", StatusCodes.Status401Unauthorized);
        }

        var profile = TelegramAuthData.ToProfile(fields);
        if (await store.GetUserByTelegramIdAsync(profile.TelegramId) is { IsBlocked: true } blocked)
            return await DenyBlockedAsync(ctx, store, time, blocked.Id, blocked.TelegramId);

        var user = await store.UpsertUserAsync(profile, time.GetUtcNow().UtcDateTime);

        // A new login replaces whatever session this browser had.
        await sessions.RevokeAsync(cookies.ReadRefresh(ctx.Request));
        var (session, refreshToken) = await sessions.CreateAsync(user.Id, ctx.Request.Headers.UserAgent.ToString(), ClientIp.Of(ctx));

        var userAccess = await access.GetAsync(user.Id);
        if (userAccess is null) // blocked in the meantime
        {
            await store.RevokeSessionAsync(session.Id, time.GetUtcNow().UtcDateTime);
            return await DenyBlockedAsync(ctx, store, time, user.Id, user.TelegramId);
        }

        await LogLoginAsync(ctx, store, time, LoginResult.Ok, user.Id, user.TelegramId);
        cookies.SetAccess(ctx.Response, access.Issue(userAccess));
        cookies.SetRefresh(ctx.Response, refreshToken, session.ExpiresAt);
        return Results.Ok(UserAccessService.ToMe(userAccess));
    }

    private static async Task<IResult> DenyBlockedAsync(HttpContext ctx, IAuthStore store, TimeProvider time, long userId, long telegramId)
    {
        await LogLoginAsync(ctx, store, time, LoginResult.DeniedBlocked, userId, telegramId);
        return Error("user_blocked", StatusCodes.Status403Forbidden);
    }

    private static Task LogLoginAsync(HttpContext ctx, IAuthStore store, TimeProvider time, string result, long? userId, long? telegramId) =>
        store.AddLoginEventAsync(new LoginEvent
        {
            UserId = userId,
            TelegramId = telegramId,
            At = time.GetUtcNow().UtcDateTime,
            Ip = SessionService.Truncate(ClientIp.Of(ctx), 45),
            UserAgent = SessionService.Truncate(ctx.Request.Headers.UserAgent.ToString() is { Length: > 0 } ua ? ua : null, 512),
            Result = result,
        });

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
        {
            userAccess = await access.GetAsync(userId);
            if (userAccess is null)
                cookies.Clear(ctx.Response); // valid token of a deleted user: its session is gone too
        }
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
