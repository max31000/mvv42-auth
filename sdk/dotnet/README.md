# mvv42-auth .NET SDK (copy-in)

`Mvv42Auth.cs` is a single file you copy into an app's API project. No NuGet package on purpose (round 1).
The copy in this repo is tested against the real service (`tests/Mvv42.Auth.Tests/Sdk`).

## Requirements

- .NET 8, package `Microsoft.AspNetCore.Authentication.JwtBearer` 8.0.x.
- The app container is attached to the docker network `cashpulse-network` (JWKS is fetched from
  `http://mvv42-auth:8080/auth/.well-known/jwks.json`).

## Usage

```csharp
using Mvv42.Auth.Client;

builder.Services.AddMvv42Auth("bonds", o => builder.Configuration.GetSection("Mvv42Auth").Bind(o));
// ...
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/api/positions", (ClaimsPrincipal user) =>
{
    var me = user.GetMvv42User()!;          // AuthUserId, TelegramId, Name, IsAdmin
    // find/create the local user by me.TelegramId (UNIQUE telegram_id)
}).RequireAuthorization(Mvv42Auth.Policy);
```

What `AddMvv42Auth(appId, configure)` registers:

| Piece | Behaviour |
|---|---|
| Scheme `mvv42` | JwtBearer; token **only** from the `__Host-mvv42_at` cookie (an `Authorization` header is ignored, it belongs to the app's legacy scheme). ES256, `iss=https://mvv42.ru/auth`, `aud=mvv42`, `ClockSkew=30s`, `MapInboundClaims=false` (claims keep their JWT names: `sub`, `tg`, `name`, `adm`, `apps`). The default scheme of the app is not changed. |
| JWKS | Own `IConfigurationRetriever<JsonWebKeySet>` + `ConfigurationManager<JsonWebKeySet>` (no OIDC discovery). Re-fetched every 10 min and on an unknown `kid` (at most every 30 s). |
| Policy `mvv42:app` | authenticated via `mvv42` **and** (`adm == "true"` or `appId ∈ apps`). |
| Origin filter | `IStartupFilter` middleware: POST/PUT/PATCH/DELETE **carrying the mvv42 cookie** need `Origin` (or `Referer`) from `AllowedOrigins`, else 403. Requests without the cookie (scripts, legacy Bearer clients) are untouched. |
| `ClaimsPrincipal.GetMvv42User()` | `Mvv42User(AuthUserId, TelegramId, Name, IsAdmin)` or `null` if the request was not authenticated by `mvv42`. |

## Options (`Mvv42AuthOptions`)

| Option | Default |
|---|---|
| `JwksUrl` | `http://mvv42-auth:8080/auth/.well-known/jwks.json` |
| `Issuer` / `Audience` | `https://mvv42.ru/auth` / `mvv42` |
| `CookieName` | `__Host-mvv42_at` (local dev against a Development auth service: `mvv42_at`) |
| `RequireHttpsMetadata` | `false` (internal http) |
| `JwksRefreshInterval` | 10 min |
| `EnforceOrigin` / `AllowedOrigins` | `true` / `["https://mvv42.ru"]` |

## Dual mode (migration phase Ф1)

Keep the legacy scheme as the default and accept either:

```csharp
builder.Services.AddAuthorization(o =>
{
    o.FallbackPolicy = new AuthorizationPolicyBuilder(JwtBearerDefaults.AuthenticationScheme, Mvv42Auth.Scheme)
        .RequireAuthenticatedUser()
        .Build();
});
```

Details per service: `docs/migration.md`.
