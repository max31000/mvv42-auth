using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Mvv42.Auth.Access;
using Mvv42.Auth.Data;
using Mvv42.Auth.Http;
using Mvv42.Auth.Http.Endpoints;
using Mvv42.Auth.Keys;
using Mvv42.Auth.Options;
using Mvv42.Auth.Sessions;
using Mvv42.Auth.Telegram;
using Mvv42.Auth.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<AuthOptions>(builder.Configuration.GetSection(AuthOptions.Section));
builder.Services.Configure<TelegramOptions>(builder.Configuration.GetSection(TelegramOptions.Section));

// nginx terminates TLS and proxies /auth/ to 127.0.0.1:5010. Inside the container the peer is the gateway of
// the docker network (docker-proxy), not loopback. Only loopback and Auth:TrustedProxyCidrs (deploy sets the
// exact gateway of cashpulse-network) may set X-Forwarded-*: other containers on the network must not be able
// to spoof the client IP the rate limiter partitions on.
builder.Services.AddOptions<ForwardedHeadersOptions>()
    .Configure<IOptions<AuthOptions>>((o, auth) =>
    {
        o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
        o.ForwardLimit = 1; // exactly one proxy hop (nginx)
        o.KnownProxies.Clear();
        o.KnownNetworks.Clear();
        o.KnownNetworks.Add(new Microsoft.AspNetCore.HttpOverrides.IPNetwork(IPAddress.Parse("127.0.0.0"), 8));
        o.KnownNetworks.Add(new Microsoft.AspNetCore.HttpOverrides.IPNetwork(IPAddress.IPv6Loopback, 128));
        foreach (var network in auth.Value.TrustedProxyNetworks())
            o.KnownNetworks.Add(network);
    });

// Defence in depth behind nginx limit_req: one fixed window per client IP shared by /telegram, /refresh and
// /invites/redeem (the endpoints that verify secrets).
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    o.OnRejected = (ctx, cancel) =>
    {
        ctx.HttpContext.Response.ContentType = "application/json";
        return new ValueTask(ctx.HttpContext.Response.WriteAsync("""{"error":"rate_limited"}""", cancel));
    };
    o.AddPolicy(AuthEndpoints.RateLimitPolicy, ctx =>
    {
        var limit = ctx.RequestServices.GetRequiredService<IOptions<AuthOptions>>().Value.RateLimitPerMinute;
        return RateLimitPartition.GetFixedWindowLimiter(ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions { PermitLimit = limit, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 });
    });
});

// ---- storage: MySQL when a connection string is set, otherwise in-memory (Development/tests only;
// the startup guard below forbids that outside Development/Testing).
var connectionString = builder.Configuration.GetConnectionString("Auth");
if (!string.IsNullOrWhiteSpace(connectionString))
{
    builder.Services.AddSingleton<IAuthStore>(new MySqlAuthStore(connectionString));
    builder.Services.AddSingleton(sp => new MigrationRunner(connectionString, sp.GetRequiredService<ILogger<MigrationRunner>>()));
}
else
{
    builder.Services.AddSingleton<IAuthStore, InMemoryAuthStore>();
}

// ---- domain services
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton(sp =>
{
    var o = sp.GetRequiredService<IOptions<AuthOptions>>().Value;
    return new SigningKeyStore(Path.GetFullPath(o.KeysPath), o.KeyActivationDelay, sp.GetRequiredService<TimeProvider>(),
        sp.GetRequiredService<ILogger<SigningKeyStore>>());
});
builder.Services.AddSingleton(sp =>
{
    var t = sp.GetRequiredService<IOptions<TelegramOptions>>().Value;
    return new TelegramVerifier(t.BotToken, t.AuthDateWindow, t.AuthDateFutureSkew);
});
builder.Services.AddMemoryCache();
builder.Services.AddSingleton(sp =>
{
    // A payload is accepted while auth_date is within the window (+ future skew), so remember it that long.
    var t = sp.GetRequiredService<IOptions<TelegramOptions>>().Value;
    return new TelegramReplayCache(sp.GetRequiredService<IMemoryCache>(), t.AuthDateWindow + t.AuthDateFutureSkew + TimeSpan.FromMinutes(1));
});
builder.Services.AddSingleton<AccessTokenIssuer>();
builder.Services.AddSingleton<SessionService>();
builder.Services.AddSingleton<UserAccessService>();
builder.Services.AddSingleton<AuthCookies>();
builder.Services.AddHostedService<SessionCleanupService>();

// ---- authN/Z: the service validates its own access cookie (used by /invites/redeem and /admin/*).
builder.Services.AddAuthentication(AuthEndpoints.Scheme).AddJwtBearer(AuthEndpoints.Scheme);
builder.Services.AddOptions<JwtBearerOptions>(AuthEndpoints.Scheme)
    .Configure<IOptions<AuthOptions>, SigningKeyStore, AuthCookies>((o, auth, keys, cookies) =>
    {
        o.MapInboundClaims = false;
        o.TokenValidationParameters = AccessTokenIssuer.ValidationParameters(auth.Value, keys);
        o.Events = new JwtBearerEvents
        {
            // Cookie only; an Authorization header is ignored.
            OnMessageReceived = ctx =>
            {
                ctx.Token = cookies.ReadAccess(ctx.Request);
                if (string.IsNullOrEmpty(ctx.Token))
                    ctx.NoResult(); // otherwise JwtBearer falls back to the Authorization header
                return Task.CompletedTask;
            },
        };
    });
builder.Services.AddAuthorizationBuilder()
    .AddPolicy(AuthEndpoints.AdminPolicy, p => p.RequireAuthenticatedUser().RequireClaim("adm", "true"));

var app = builder.Build();

// Malformed security settings stop the service in every environment (instead of failing per request).
var authOptions = app.Services.GetRequiredService<IOptions<AuthOptions>>().Value;
try
{
    authOptions.AdminTelegramIdSet();
    authOptions.TrustedProxyNetworks();
}
catch (FormatException ex)
{
    throw new InvalidOperationException(ex.Message, ex);
}
if (authOptions.RateLimitPerMinute < 1)
    throw new InvalidOperationException("Auth:RateLimitPerMinute must be positive.");

// Outside Development/Testing the service must not start half-configured.
if (!app.Environment.IsDevelopment() && !app.Environment.IsEnvironment("Testing"))
{
    if (string.IsNullOrWhiteSpace(app.Configuration["Telegram:BotToken"]))
        throw new InvalidOperationException("Telegram:BotToken must be configured (env Telegram__BotToken).");
    if (string.IsNullOrWhiteSpace(connectionString))
        throw new InvalidOperationException("ConnectionStrings:Auth must be configured (env ConnectionStrings__Auth).");
}

if (string.IsNullOrWhiteSpace(connectionString))
    app.Logger.LogWarning("ConnectionStrings:Auth is empty: using the in-memory store, data is lost on restart");
else
    await app.Services.GetRequiredService<MigrationRunner>().RunAsync();

// Generate the first signing key at startup rather than on the first request.
app.Services.GetRequiredService<SigningKeyStore>().GetSigningKey();

app.UseForwardedHeaders();

// nginx does not strip the prefix: /auth/api/... arrives as is (spec §9.8).
app.UsePathBase("/auth");
app.UseRouting(); // explicitly after UsePathBase so routes match the path without the prefix
app.UseRateLimiter();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));
app.MapJwks();

var api = app.MapAuthApi();
api.MapInviteEndpoints();
api.MapAdminEndpoints();

app.Run();

// For WebApplicationFactory<Program> in tests.
public partial class Program;
