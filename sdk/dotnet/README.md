# mvv42-auth .NET SDK (copy-in)

`Mvv42Auth.cs` is a single file you copy into an app's API project. No NuGet package on purpose (round 1).
The copy in this repo is tested against the real service (`tests/Mvv42.Auth.Tests/Sdk`).

## Requirements

- .NET 8, package `Microsoft.AspNetCore.Authentication.JwtBearer` 8.0.x (8.0.11 recommended, as in the auth service).
- **One IdentityModel version.** JwtBearer 8.0.11 brings `Microsoft.IdentityModel.*` 7.1.2; an app that also references
  `System.IdentityModel.Tokens.Jwt` 7.6.3 (bonds, cashpulse, credit_calc) would end up with mixed 7.1.2/7.6.3 assemblies.
  Pin `Microsoft.IdentityModel.Protocols.OpenIdConnect` to the same version as the app's (and its test projects')
  `System.IdentityModel.Tokens.Jwt`; check with `dotnet list package --include-transitive | grep -i identitymodel` —
  every line must show one version. The SDK is compiled and tested against 7.1.2, 7.6.3 and 8.4.0.
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
| Origin filter | `IStartupFilter` middleware: POST/PUT/PATCH/DELETE **carrying the mvv42 cookie** need `Origin` (or `Referer`) from `AllowedOrigins`, else `403 {"error":"origin_not_allowed"}`. Requests without the cookie (scripts, legacy Bearer clients) are untouched. |
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

The legacy scheme stays the default; a request may authenticate with either scheme. **Never use a scheme-only policy**
(`new AuthorizationPolicyBuilder(Bearer, Mvv42Auth.Scheme).RequireAuthenticatedUser()`): it would let in *any* mvv42
user, including ones without access to this app. The mvv42 branch must carry the same assertion as
`Mvv42Auth.Policy` (`adm == "true"` or `appId ∈ apps`):

```csharp
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Mvv42.Auth.Client;

builder.Services.AddMvv42Auth("bonds", o => builder.Configuration.GetSection("Mvv42Auth").Bind(o));

static bool LegacyAuthenticated(ClaimsPrincipal u) =>
    u.Identities.Any(i => i.IsAuthenticated && i.AuthenticationType != Mvv42Auth.Scheme);

static bool Mvv42Allowed(ClaimsPrincipal u, string appId) =>
    u.Identities.Any(i => i.IsAuthenticated && i.AuthenticationType == Mvv42Auth.Scheme
                          && (i.HasClaim("adm", "true") || i.HasClaim("apps", appId)));

var dualPolicy = new AuthorizationPolicyBuilder(JwtBearerDefaults.AuthenticationScheme, Mvv42Auth.Scheme)
    .RequireAuthenticatedUser()
    .RequireAssertion(ctx => LegacyAuthenticated(ctx.User) || Mvv42Allowed(ctx.User, "bonds"))
    .Build();

builder.Services.AddAuthorization(o =>
{
    o.FallbackPolicy = dualPolicy; // endpoints without metadata
    o.DefaultPolicy = dualPolicy;  // .RequireAuthorization() without a policy name
});
```

The mvv42 identity has `AuthenticationType == "mvv42"` (set by the SDK); the legacy JwtBearer identity has a different
one. App-specific extra conditions go into `Mvv42Allowed` (bonds additionally requires `tg == Telegram:OwnerId`).
After the migration (Ф3) the policy becomes simply `Mvv42Auth.Policy` (plus app-specific conditions).

`sub` is the **auth** user id, not the app's: resolve the local user by `tg`. Per-service code (user provisioning,
replacing `ClaimTypes.NameIdentifier` reads, rollback, gates): `docs/migration.md`.
