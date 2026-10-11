using Microsoft.AspNetCore.HttpOverrides;
using Mvv42.Auth.Options;

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

var app = builder.Build();

// Outside Development/Testing the service must not start half-configured.
if (!app.Environment.IsDevelopment() && !app.Environment.IsEnvironment("Testing"))
{
    if (string.IsNullOrWhiteSpace(app.Configuration["Telegram:BotToken"]))
        throw new InvalidOperationException("Telegram:BotToken must be configured (env Telegram__BotToken).");
    if (string.IsNullOrWhiteSpace(app.Configuration.GetConnectionString("Auth")))
        throw new InvalidOperationException("ConnectionStrings:Auth must be configured (env ConnectionStrings__Auth).");
}

app.UseForwardedHeaders();

// nginx does not strip the prefix: /auth/api/... arrives as is.
app.UsePathBase("/auth");

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.Run();

// For WebApplicationFactory<Program> in tests.
public partial class Program;
