using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
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

// nginx terminates TLS and proxies /auth/ to 127.0.0.1:5010. Inside the container the peer is the
// docker bridge gateway, not loopback, so the default KnownProxies would ignore X-Forwarded-*.
// The port is published on 127.0.0.1 only, therefore trusting any peer is safe here.
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    o.KnownNetworks.Clear();
    o.KnownProxies.Clear();
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
    return new SigningKeyStore(Path.GetFullPath(o.KeysPath), o.KeyActivationDelay, sp.GetRequiredService<TimeProvider>());
});
builder.Services.AddSingleton(sp =>
{
    var t = sp.GetRequiredService<IOptions<TelegramOptions>>().Value;
    return new TelegramVerifier(t.BotToken, t.AuthDateWindow, t.AuthDateFutureSkew);
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
