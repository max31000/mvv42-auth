using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Mvv42.Auth.Access;
using Mvv42.Auth.Data;
using Mvv42.Auth.Invites;
using Mvv42.Auth.Options;
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

    /// <summary>Invite code for a first login (closed registration). Ignored for known users.</summary>
    public const string InviteCodeHeader = "X-Invite-Code";

    /// <param name="AppId">The app granted by the invite; null = login-only invite.</param>
    public sealed record TelegramInvite(string? AppId);

    /// <summary>
    /// <c>/telegram</c> response: the <c>/me</c> payload plus <c>invite</c> — present only when this login registered the
    /// user with an invite code (the shared <see cref="MeResponse"/> of <c>/me</c> and redeem is unchanged).
    /// </summary>
    public sealed record TelegramLoginResponse(
        MeUser? User,
        IReadOnlyList<MeApp> Apps,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] TelegramInvite? Invite);

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
    /// Closed registration: a user is known when a row with the telegram id exists or the id is an owner; anyone else
    /// needs a valid <see cref="InviteCodeHeader"/> (<c>Auth:Registration=invite</c>), and a refusal stores nothing
    /// about them and hands the widget payload back (not marked as used).
    /// </summary>
    private static async Task<IResult> TelegramLogin(
        JsonElement body, HttpContext ctx, TelegramVerifier verifier, IAuthStore store, SessionService sessions,
        UserAccessService access, AuthCookies cookies, TimeProvider time, TelegramReplayCache replay,
        InviteCodeHasher inviteHasher, IOptions<AuthOptions> options)
    {
        var fields = TelegramAuthData.ToFields(body);
        if (fields is null)
            return Error("invalid_body", StatusCodes.Status400BadRequest);

        var check = verifier.Verify(fields, time.GetUtcNow());
        if (check.Error == TelegramVerifyError.NotConfigured)
            return Error("telegram_not_configured", StatusCodes.Status503ServiceUnavailable);

        // A payload that failed verification (or was replayed) has no verified identity behind it: neither the
        // telegram id nor the client's IP / User-Agent is stored.
        if (!check.Ok)
        {
            await LogLoginAsync(ctx, store, time, LoginResult.Invalid, null, null, withClient: false);
            return Error(check.Error.ToString(), check.IsMalformed ? StatusCodes.Status400BadRequest : StatusCodes.Status401Unauthorized);
        }
        if (!replay.TryUse(fields["hash"]))
        {
            await LogLoginAsync(ctx, store, time, LoginResult.Replayed, null, null, withClient: false);
            return Error("Replayed", StatusCodes.Status401Unauthorized);
        }

        var profile = TelegramAuthData.ToProfile(fields);
        var existing = await store.GetUserByTelegramIdAsync(profile.TelegramId);
        if (existing is not null && access.IsEffectivelyBlocked(existing))
            return await DenyBlockedAsync(ctx, store, time, existing.Id, existing.TelegramId);

        User? user = null;
        TelegramInvite? invite = null;
        if (existing is null && !access.IsOwner(profile.TelegramId))
        {
            var mode = options.Value.GetRegistrationMode();
            var registration = await RegisterAsync(ctx, store, time, inviteHasher, mode, profile);
            var refusal = registration.Refusal;
            if (registration.Result is { Status: InviteRegistrationStatus.Registered } registered)
            {
                user = registered.User!;
                invite = new TelegramInvite(registered.AppId);
            }
            else if (registration.Result?.Status == InviteRegistrationStatus.AlreadyRegistered)
            {
                // A parallel request created the row first: a known user now — but only if the row can be read back.
                // Never re-create it through the upsert below in closed mode.
                if (await store.GetUserByTelegramIdAsync(profile.TelegramId) is { } raced)
                {
                    if (access.IsEffectivelyBlocked(raced))
                        return await DenyBlockedAsync(ctx, store, time, raced.Id, raced.TelegramId);
                }
                else if (mode == RegistrationMode.Invite)
                    refusal = Error("invite_required", StatusCodes.Status403Forbidden);
            }

            if (refusal is not null)
            {
                // Nothing was issued: the shell may resend the same widget data with a (better) code.
                replay.Release(fields["hash"]);
                await LogLoginAsync(ctx, store, time, LoginResult.DeniedUnregistered, null, null, withClient: false);
                return refusal;
            }
        }

        // Known user (or open registration without a usable code, or a parallel request created the row first).
        user ??= await store.UpsertUserAsync(profile, time.GetUtcNow().UtcDateTime);

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
        var me = UserAccessService.ToMe(userAccess);
        return Results.Ok(new TelegramLoginResponse(me.User, me.Apps, invite));
    }

    /// <summary>Outcome for an unknown user: a refusal to return, or the registration attempt (null = no usable code, open mode).</summary>
    private readonly record struct Registration(IResult? Refusal, InviteRegistrationResult? Result);

    private static async Task<Registration> RegisterAsync(
        HttpContext ctx, IAuthStore store, TimeProvider time, InviteCodeHasher hasher, RegistrationMode mode, TelegramProfile profile)
    {
        var closed = mode == RegistrationMode.Invite;
        var header = ctx.Request.Headers[InviteCodeHeader].ToString();
        if (string.IsNullOrWhiteSpace(header))
            return new(closed ? Error("invite_required", StatusCodes.Status403Forbidden) : null, null);
        if (InviteCodes.Parse(header) is not { } code)
            return new(closed ? Error("invalid_invite_format", StatusCodes.Status400BadRequest) : null, null);

        var result = await store.RegisterWithInviteAsync(profile, hasher.Candidates(code), time.GetUtcNow().UtcDateTime);
        var error = result.Status switch
        {
            InviteRegistrationStatus.NotFound => "invite_not_found",
            InviteRegistrationStatus.Expired => "invite_expired",
            InviteRegistrationStatus.Exhausted => "invite_exhausted",
            _ => null,
        };
        if (error is null)
            return new(null, result);
        // Open registration: a bad code is ignored, the user registers without it.
        return closed ? new(Error(error, StatusCodes.Status400BadRequest), null) : new(null, null);
    }

    private static async Task<IResult> DenyBlockedAsync(HttpContext ctx, IAuthStore store, TimeProvider time, long userId, long telegramId)
    {
        await LogLoginAsync(ctx, store, time, LoginResult.DeniedBlocked, userId, telegramId);
        return Error("user_blocked", StatusCodes.Status403Forbidden);
    }

    /// <summary>
    /// Best effort: a journal failure is logged and never fails the login itself. <paramref name="withClient"/> = false
    /// leaves IP and User-Agent out (refused strangers: only the time is stored).
    /// </summary>
    private static async Task LogLoginAsync(
        HttpContext ctx, IAuthStore store, TimeProvider time, string result, long? userId, long? telegramId, bool withClient = true)
    {
        try
        {
            await store.AddLoginEventAsync(new LoginEvent
            {
                UserId = userId,
                TelegramId = telegramId,
                At = time.GetUtcNow().UtcDateTime,
                Ip = withClient ? SessionService.Truncate(ClientIp.Of(ctx), 45) : null,
                UserAgent = withClient
                    ? SessionService.Truncate(ctx.Request.Headers.UserAgent.ToString() is { Length: > 0 } ua ? ua : null, 512)
                    : null,
                Result = result,
            });
        }
        catch (Exception ex)
        {
            ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger(typeof(AuthEndpoints))
                .LogWarning(ex, "Could not write the login event ({Result}, user {UserId})", result, userId);
        }
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
