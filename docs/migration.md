# Перевод приложений на mvv42-auth

Порядок: **credit_calc** (anonymous, проще) → **bonds** → **cashpulse**. Каждая фаза — отдельный деплой с собственным
откатом. Данные приложений не мигрируют: локальный пользователь находится/создаётся по claim `tg`
(`telegram_id`/`TelegramId` UNIQUE во всех трёх БД).

| Фаза | Что | Откат |
|---|---|---|
| Ф0 | auth-сервис, nginx `/auth/` | `docker rm -f mvv42-auth`, revert `nginx/apps/auth.conf` в infra; приложения не затронуты |
| Ф-1 (только cashpulse) | привязать пользователей без `TelegramId` | `UPDATE … SET TelegramId = NULL` по сохранённому списку |
| Ф1 | бэкенд: вторая схема (dual-mode), provisioning по `tg`, лог `auth=legacy` | предыдущий образ/коммит бэкенда; созданные по `tg` пользователи — обычные строки, чистить не нужно |
| Ф2 | фронт: cookies + `mvv42Fetch`, логин через shell | предыдущая сборка фронта; бэкенд всё ещё принимает Bearer, старый логин включён |
| Ф2.5 | `LegacyAuth__LoginEnabled=false` (старый `/api/auth/telegram` → 410) | вернуть `true`, перезапустить деплой |
| гейт | ≥ 30 дней с Ф2.5 **и** 0 строк `auth=legacy` за 7 дней | — |
| Ф3 | удалить старый логин, `Jwt__Secret`, localStorage-ключи | `git revert` + вернуть секреты (не удалять `JWT_SECRET` из GitHub ещё 30 дней) |

30 дней = `Jwt:ExpirationDays` всех трёх сервисов: после Ф2.5 новых legacy-токенов нет, старые истекают за 30 дней.

## Общие правила

### Пакеты (одна версия IdentityModel)

SDK требует `Microsoft.AspNetCore.Authentication.JwtBearer` 8.0.x (как в auth — 8.0.11). JwtBearer 8.0.11 тянет
`Microsoft.IdentityModel.*` 7.1.2, а приложения ещё ссылаются на `System.IdentityModel.Tokens.Jwt`; смешение версий
IdentityModel в одном процессе ломает валидацию в рантайме. Поэтому `Microsoft.IdentityModel.Protocols.OpenIdConnect`
пинится к той же версии, что и `System.IdentityModel.Tokens.Jwt`, а она — к максимальной в решении (включая тесты).
SDK собран и прогнан против 7.1.2, 7.6.3 и 8.4.0 (`tests/Mvv42.Auth.Tests`), снипеты ниже — против реальных проектов.

| Сервис | Сейчас | Ф1 (API-проект) |
|---|---|---|
| credit_calc `server/src/CreditCalc.Api` | JwtBearer 8.0.11, Jwt 7.6.3 (тесты IdentityModel не тянут) | JwtBearer 8.0.11, `System.IdentityModel.Tokens.Jwt` 7.6.3, **+** `Microsoft.IdentityModel.Protocols.OpenIdConnect` 7.6.3 |
| bonds `src/Bonds.Api` | JwtBearer 8.0.0, Jwt 7.6.3; `tests/Bonds.IntegrationTests`: Tokens/Jwt 8.4.0 | JwtBearer **8.0.11**, Jwt **8.4.0**, **+** OpenIdConnect 8.4.0 |
| cashpulse `src/CashPulse.Api` | JwtBearer 8.0.0 (не используется), Jwt 7.6.3; `tests/CashPulse.IntegrationTests`: Tokens/Jwt 8.4.0 | JwtBearer **8.0.11**, Jwt **8.4.0**, **+** OpenIdConnect 8.4.0 |

Проверка: `dotnet list <sln> package --include-transitive | grep -i identitymodel` — у каждого пакета одна версия во всех проектах.

### Сеть и конфиг

- JWKS берётся по docker-сети: `http://mvv42-auth:8080/auth/.well-known/jwks.json` → API-контейнер в `cashpulse-network`
  (cashpulse и bonds уже там; credit_calc — см. его раздел).
- `AddMvv42Auth("<app-id>", o => builder.Configuration.GetSection("Mvv42Auth").Bind(o))`; в проде дефолты подходят.
  `appsettings.Development.json` для локального auth (`dotnet run` в mvv42-auth, http):
  ```json
  "Mvv42Auth": {
    "JwksUrl": "http://localhost:5010/auth/.well-known/jwks.json",
    "CookieName": "mvv42_at",
    "AllowedOrigins": [ "http://localhost:5173" ]
  }
  ```
- Cookies ходят только same-origin: фронт должен звать API **относительным** путём того же origin (таблица ниже).
  CORS `AllowCredentials` не нужен.

| Сервис | Переменная фронта | Прод | Что сделать |
|---|---|---|---|
| credit_calc | `VITE_API_BASE` (`src/api/client.ts:8`) | `/credit_calc/api` (relative) | ничего; nginx контейнера `credit_calc` пробрасывает `Cookie`/`Origin` |
| bonds | `VITE_API_BASE` (`vars.VITE_API_BASE`, default `/bonds/api`) | relative | ничего |
| cashpulse | `VITE_API_URL` (secret; `src/api/client.ts:5`, `src/api/auth.ts:3`, default `http://localhost:5000`) | абсолютный | сделать относительным: default `?? ''`, secret `VITE_API_URL` пустой (запросы пойдут на `/api/…` того же origin). Абсолютный URL допустим только если **точно** равен origin страницы (`https://mvv42.ru`, не IP и не `www`) |

### Политика: никогда не только схема

Политика Ф1 = «legacy Bearer **ИЛИ** (mvv42 **И** `apps ∋ <app>` или `adm`)». Политика вида
`new AuthorizationPolicyBuilder(Bearer, Mvv42Auth.Scheme).RequireAuthenticatedUser()` пропустила бы любого
пользователя платформы — запрещена. Ставится и `FallbackPolicy` (эндпоинты без метаданных), и `DefaultPolicy`
(`.RequireAuthorization()` без имени — в bonds это `/api/auth/me`). Поведение проверено тестом
`tests/Mvv42.Auth.Tests/Sdk/DualModePolicyTests.cs` (legacy → 200, mvv42 без app → 403, просроченный Bearer + валидная
cookie → 200).

### Локальный пользователь по `tg`

`sub` в mvv42-токене — id пользователя **auth**, не локальный. Локальный id получается так:

1. `UserProvisioning.GetOrCreateAsync` — `GetByTelegramIdAsync(tg)`, иначе `CreateAsync`. Гонка первых параллельных
   запросов нового пользователя: `SemaphoreSlim` (один инстанс API) + на всякий случай перехват MySQL **1062**
   (`MySqlErrorCode.DuplicateKeyEntry` на `uq_users_telegram_id`) с повторным чтением.
2. bonds/credit_calc: `IClaimsTransformation` добавляет в mvv42-identity claim `local_uid` (кэш `IMemoryCache` 10 мин,
   пользователь создаётся только если политика его пропустит). Существующие места чтения id переходят на хелпер
   «`local_uid`, иначе `ClaimTypes.NameIdentifier`» (legacy-схема с `MapInboundClaims=true` по-прежнему кладёт
   `sub` → `NameIdentifier`; mvv42-схема с `MapInboundClaims=false` никогда не даёт `NameIdentifier`, т.е. auth-`sub`
   не перепутается с локальным id).
3. cashpulse (своя middleware, без ASP.NET-авторизации): то же внутри `JwtMiddleware` → `Items["UserId"]`.

`Mvv42User.Name` — «Имя Фамилия» из Telegram; кладётся в `first_name`/`DisplayName` при создании, дальше не обновляется.

### Флаг старого логина и лог для гейта

- `LegacyAuth:LoginEnabled` (env `LegacyAuth__LoginEnabled`, по умолчанию `true`). В начале старого
  `TelegramLogin`:
  ```csharp
  if (!config.GetValue("LegacyAuth:LoginEnabled", true))
      return Results.Json(new { error = "Вход выполняется через mvv42.ru" }, statusCode: StatusCodes.Status410Gone);
  ```
  (в credit_calc добавить параметр `IConfiguration config` в `TelegramLogin`). Деплой передаёт значение из
  GitHub-переменной: `-e "LegacyAuth__LoginEnabled=${{ vars.LEGACY_LOGIN_ENABLED || 'true' }}"` (bonds/cashpulse),
  в compose credit_calc — `LegacyAuth__LoginEnabled: "${LEGACY_LOGIN_ENABLED:-true}"` + строка в `.env` из deploy.
- Каждый запрос по старой схеме пишет `auth=legacy` (Information). Гейт перед Ф3:
  ```bash
  docker logs --since 168h <container> 2>&1 | grep -c 'auth=legacy'   # должно быть 0
  ```
  контейнеры: `credit_calc_api`, `bonds-api`, `cashpulse-api`.

## Ф0. Запуск auth (один раз)

1. БД в `cashpulse-mysql` — идемпотентный SQL из README (раздел «Деплой»; тот же шаблон, что `mvv42-infra/docs/server-layout.md`).
2. Секреты репо `mvv42-auth`: `AUTH_DB_CONNECTION_STRING`
   (`Server=cashpulse-mysql;Port=3306;Database=mvv42_auth;User=mvv42_auth;Password=<generated>;`),
   `AUTH_TELEGRAM_BOT_TOKEN` (токен `mv_cashpulse_bot`), `AUTH_ADMIN_TELEGRAM_IDS`, `VDS_*`, `TELEGRAM_BOT_TOKEN`/`TELEGRAM_CHAT_ID`.
3. BotFather: `/setdomain` → `mv_cashpulse_bot` → `mvv42.ru` (по спеке уже привязан — проверить).
4. Push в `main` → deploy (env-файл `/etc/mvv42/env/mvv42-auth.env`). Проверка на сервере:
   `curl -s http://127.0.0.1:5010/auth/health`.
5. nginx `nginx/apps/auth.conf` из `mvv42-infra` + `apply-nginx`. Снаружи:
   `curl -s https://mvv42.ru/auth/.well-known/jwks.json`, `curl -s https://mvv42.ru/auth/api/me` → `{"user":null,…}`.
   `www.mvv42.ru` → 301 на apex (host-only cookies).
6. `apps` засеяны миграцией: `cashpulse(anonymous=0, public)`, `credit_calc(1, public)`, `bonds(0, admin)`.
   Владелец bonds — в `AUTH_ADMIN_TELEGRAM_IDS`.
7. Shell показывает логин, как только `/auth/api/me` отвечает 200.

Откат: `docker rm -f mvv42-auth` + revert `auth.conf`; приложения ещё не зависят от auth.

## credit_calc

Бэкенд `server/src/CreditCalc.Api`: `AddJwtBearer()` (схема `Bearer`, настройки через `IConfigureOptions`, `Program.cs:52-72`),
`FallbackPolicy = RequireAuthenticatedUser` (`Program.cs:76-81`), анонимны только `/api/auth/telegram` и health.
Id пользователя: `JwtIssuer.GetUserId(ClaimsPrincipal) → ulong?` (`Auth/JwtIssuer.cs:45-50`), `UserRepository`
конкретный класс (`Data/UserRepository.cs`, `AddScoped<UserRepository>()`): `GetByTelegramIdAsync(long) → Task<User?>`,
`CreateAsync(User) → Task<ulong>` (id не проставляет в `user.Id`).

### Ф1 — бэкенд

1. Пакеты (таблица выше), `sdk/dotnet/Mvv42Auth.cs` → `server/src/CreditCalc.Api/Auth/Mvv42Auth.cs`.
2. Новый файл `server/src/CreditCalc.Api/Auth/Mvv42LocalUser.cs`:
   ```csharp
   using System.Globalization;
   using System.Security.Claims;
   using CreditCalc.Api.Data;
   using Microsoft.AspNetCore.Authentication;
   using Microsoft.Extensions.Caching.Memory;
   using Mvv42.Auth.Client;
   using MySqlConnector;

   namespace CreditCalc.Api.Auth;

   /// <summary>Who may use the app during dual-mode: a legacy Bearer user or an mvv42 user with the app in `apps`.</summary>
   public static class Mvv42Access
   {
       public const string AppId = "credit_calc";

       public static bool LegacyAuthenticated(ClaimsPrincipal user) =>
           user.Identities.Any(i => i.IsAuthenticated && i.AuthenticationType != Mvv42Auth.Scheme);

       public static bool Mvv42Allowed(ClaimsPrincipal user) =>
           user.Identities.Any(i => i.IsAuthenticated && i.AuthenticationType == Mvv42Auth.Scheme
                                    && (i.HasClaim("adm", "true") || i.HasClaim("apps", AppId)));
   }

   /// <summary>Finds or creates the local `users` row for an mvv42 user (key: telegram id, UNIQUE).</summary>
   public sealed class UserProvisioning(UserRepository users)
   {
       // One instance of the API: serialises the "first request of a new user" burst (parallel API calls).
       private static readonly SemaphoreSlim Gate = new(1, 1);

       public async Task<ulong> GetOrCreateAsync(Mvv42User me)
       {
           if (await users.GetByTelegramIdAsync(me.TelegramId) is { } existing)
               return existing.Id;

           await Gate.WaitAsync();
           try
           {
               if (await users.GetByTelegramIdAsync(me.TelegramId) is { } created)
                   return created.Id;
               return await users.CreateAsync(new User { TelegramId = me.TelegramId, FirstName = me.Name });
           }
           catch (MySqlException ex) when (ex.ErrorCode == MySqlErrorCode.DuplicateKeyEntry)
           {
               // another instance/request inserted the same telegram_id first (uq_users_telegram_id)
               return (await users.GetByTelegramIdAsync(me.TelegramId))?.Id
                      ?? throw new InvalidOperationException($"users.telegram_id={me.TelegramId}: duplicate key but no row", ex);
           }
           finally
           {
               Gate.Release();
           }
       }
   }

   /// <summary>
   /// Adds the local user id (claim <c>local_uid</c>) to an allowed mvv42 identity, so the existing
   /// <c>JwtIssuer.GetUserId</c> call sites keep working for both schemes.
   /// </summary>
   public sealed class LocalUserClaimsTransformation(UserProvisioning provisioning, IMemoryCache cache) : IClaimsTransformation
   {
       public const string ClaimType = "local_uid";

       public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
       {
           if (principal.HasClaim(c => c.Type == ClaimType) || !Mvv42Access.Mvv42Allowed(principal)
               || principal.GetMvv42User() is not { } me)
               return principal;

           var localId = await cache.GetOrCreateAsync($"mvv42-local-uid:{me.TelegramId}", entry =>
           {
               entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(10);
               return provisioning.GetOrCreateAsync(me);
           });

           var clone = principal.Clone();
           clone.Identities.First(i => i.IsAuthenticated && i.AuthenticationType == Mvv42Auth.Scheme)
               .AddClaim(new Claim(ClaimType, localId.ToString(CultureInfo.InvariantCulture)));
           return clone;
       }
   }
   ```
3. `Program.cs` — после `AddAuthentication(...).AddJwtBearer()`, **вместо** нынешнего `AddAuthorization(...)`:
   ```csharp
   builder.Services.AddMvv42Auth(Mvv42Access.AppId, o => builder.Configuration.GetSection("Mvv42Auth").Bind(o));
   builder.Services.AddMemoryCache();
   builder.Services.AddScoped<UserProvisioning>();
   builder.Services.AddScoped<IClaimsTransformation, LocalUserClaimsTransformation>();

   var dualPolicy = new AuthorizationPolicyBuilder(JwtBearerDefaults.AuthenticationScheme, Mvv42Auth.Scheme)
       .RequireAuthenticatedUser()
       .RequireAssertion(ctx => Mvv42Access.LegacyAuthenticated(ctx.User) || Mvv42Access.Mvv42Allowed(ctx.User))
       .Build();
   builder.Services.AddAuthorization(options =>
   {
       options.FallbackPolicy = dualPolicy;
       options.DefaultPolicy = dualPolicy;
   });
   ```
   `using CreditCalc.Api.Auth; using Microsoft.AspNetCore.Authentication; using Mvv42.Auth.Client;`.
   В лямбде `ConfigureNamedOptions<JwtBearerOptions>` (legacy) добавить лог для гейта:
   ```csharp
   options.Events = new JwtBearerEvents
   {
       OnTokenValidated = ctx =>
       {
           ctx.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("LegacyAuth")
               .LogInformation("auth=legacy path={Path}", ctx.Request.Path);
           return Task.CompletedTask;
       },
   };
   ```
4. `JwtIssuer.GetUserId` — единственное место чтения id, call sites не меняются
   (`Endpoints/AuthEndpoints.cs:66` `/me`, `Endpoints/MortgageEndpoints.cs:147`, `Endpoints/ProfileEndpoints.cs:69`):
   ```csharp
   public static ulong? GetUserId(ClaimsPrincipal principal)
   {
       var raw = principal.FindFirstValue(LocalUserClaimsTransformation.ClaimType) // mvv42: local id resolved by tg
                 ?? principal.FindFirstValue(ClaimTypes.NameIdentifier);          // legacy token
       return ulong.TryParse(raw, out var id) ? id : null;
   }
   ```
   Тесты `JwtIssuerTests` (L51/61/70) продолжают работать; добавить кейс с identity `AuthenticationType="mvv42"` + `local_uid`.
5. Флаг `LegacyAuth:LoginEnabled` в `TelegramLogin` (см. «Общие правила»).
6. `deploy/docker-compose.prod.yml` — API в общую сеть (имя сети = существующая `cashpulse-network`):
   ```yaml
   services:
     credit_calc_api:
       # ...
       environment:
         # ...
         LegacyAuth__LoginEnabled: "${LEGACY_LOGIN_ENABLED:-true}"
       networks:
         - credit_calc_net
         - cashpulse-network

   networks:
     credit_calc_net:
       driver: bridge
     cashpulse-network:
       external: true
   ```
   `credit_calc_net` здесь — ключ сети внутри compose-файла; реальное имя docker-сети на сервере —
   `credit_calc_credit_calc_net` (префикс compose-проекта `credit_calc_`), его видно в `docker network ls`.
   `cashpulse-network` — внешняя сеть, её имя не префиксуется.
   Проверка после деплоя: `docker exec credit_calc_api getent hosts mvv42-auth` (если `getent` нет в образе —
   `docker network inspect cashpulse-network | grep credit_calc_api`).

Откат Ф1: revert коммита → workflow пересоберёт и `compose up -d`; лишняя сеть безвредна.

### Ф2 — фронт

- `sdk/web/mvv42.ts` → `src/lib/mvv42.ts`.
- `src/api/client.ts`: `fetch` → `mvv42Fetch`, убрать `authHeaders()`; финальный 401 → `requestLogin('credit_calc')`
  вместо `logout()` + `location.href = …login`. `TRACKER_ENABLED` остаётся производным от `API_BASE`.
- `src/store/useAuthStore.ts`: вместо `{token,user}` в localStorage — `me` из `getMe()` (в памяти);
  `isAuthenticated = me?.user != null`. `getMe()` вернул `null` (auth недоступен) → аноним, калькулятор работает.
- `App.tsx:205-213` (стартовый `fetchMe(token)`) → `getMe()`; `onShellMessage` `AUTH_CHANGED` → повторный `getMe()`.
- `LoginPage.tsx`, `ProtectedRoute.tsx`, кнопка «Войти» в `Header.tsx` → `requestLogin('credit_calc')`; выход —
  `POST /auth/api/logout` (`credentials: 'same-origin'`) и `getMe()`.

Откат Ф2: предыдущая сборка фронта (revert + push); бэкенд принимает Bearer, старый логин включён.

### Ф3 (после гейта)

Удалить `POST /api/auth/telegram`, `TelegramAuthService`, `JwtIssuer.Issue`, legacy `AddJwtBearer` и `JwtSecretGuard`;
`AddAuthentication(Mvv42Auth.Scheme)`; политика — только `Mvv42Allowed`; `GetUserId` читает только `local_uid`.
Env/секреты: `Jwt__Secret`/`JWT_SECRET` (и проверку длины в deploy), `Telegram__BotToken`/`TELEGRAM_BOT_TOKEN`
(нужен только логину), `LEGACY_LOGIN_ENABLED`. Фронт: `localStorage.removeItem('credit-calc-auth')` один раз при старте,
удалить `LoginPage`.

## bonds

Бэкенд `src/Bonds.Api`: `AddJwtBearer()` (`Program.cs:42-62`), `FallbackPolicy = RequireAuthenticatedUser` (`:67-72`),
`/api/auth/me` с `.RequireAuthorization()` (`Endpoints/AuthEndpoints.cs:17` → **DefaultPolicy**). Логин пускает только
`Telegram:OwnerId` (`AuthEndpoints.cs:39-43`) и делает onboarding счёта (`:73-76`,
`IAccountRepository.GetPrimaryAccountIdAsync()` — глобальный, не per user). `IUserRepository`
(`Bonds.Core.Interfaces.Repositories`): `GetByTelegramIdAsync(long) → Task<User?>`, `GetByIdAsync(ulong)`,
`CreateAsync(User) → Task<ulong>`.

**Риск эскалации.** App `bonds` = `access=admin`, значит `apps ∋ bonds` у **любого** админа auth: `users.is_admin=1`
(его может выставить любой админ через `PUT /auth/api/admin/users/{id}/admin`) или `Auth__AdminTelegramIds`. Данные
bonds фактически принадлежат владельцу (глобальные `GetPrimaryAccountIdAsync`/`GetPrimaryUserIdAsync`, токен T-Invest),
так что второй админ получил бы чужой брокерский портфель. Поэтому mvv42-ветка дополнительно требует
`tg == Telegram:OwnerId` — то же правило, что у нынешнего логина; без него доступ расширился бы с «владелец» до
«все админы платформы». Не-владельцу локальный пользователь не создаётся.

### Ф1 — бэкенд

1. Пакеты (таблица выше), `Mvv42Auth.cs` → `src/Bonds.Api/Auth/Mvv42Auth.cs`.
2. Новый файл `src/Bonds.Api/Auth/Mvv42LocalUser.cs`:
   ```csharp
   using System.Globalization;
   using System.Security.Claims;
   using Bonds.Core.Interfaces.Repositories;
   using Bonds.Core.Models;
   using Microsoft.AspNetCore.Authentication;
   using Microsoft.Extensions.Caching.Memory;
   using Mvv42.Auth.Client;
   using MySqlConnector;

   namespace Bonds.Api.Auth;

   /// <summary>
   /// Dual-mode access. bonds is single-owner: besides `apps ∋ bonds` (which every mvv42 admin has, app access=admin)
   /// the telegram id must equal Telegram:OwnerId — the same rule the legacy login enforces.
   /// </summary>
   public static class Mvv42Access
   {
       public const string AppId = "bonds";

       public static bool LegacyAuthenticated(ClaimsPrincipal user) =>
           user.Identities.Any(i => i.IsAuthenticated && i.AuthenticationType != Mvv42Auth.Scheme);

       public static bool Mvv42Allowed(ClaimsPrincipal user, long? ownerTelegramId) =>
           ownerTelegramId is { } owner
           && user.GetMvv42User() is { } me && me.TelegramId == owner
           && user.Identities.Any(i => i.IsAuthenticated && i.AuthenticationType == Mvv42Auth.Scheme
                                       && (i.HasClaim("adm", "true") || i.HasClaim("apps", AppId)));

       public static long? OwnerTelegramId(IConfiguration config) =>
           long.TryParse(config["Telegram:OwnerId"], NumberStyles.None, CultureInfo.InvariantCulture, out var id) ? id : null;
   }

   /// <summary>Finds or creates the local user by telegram id and runs the same Account onboarding as TelegramLogin.</summary>
   public sealed class UserProvisioning(IUserRepository users, IAccountRepository accounts)
   {
       // One API instance: serialises the first-request burst so onboarding cannot create two primary accounts.
       private static readonly SemaphoreSlim Gate = new(1, 1);

       public async Task<ulong> GetOrCreateAsync(Mvv42User me)
       {
           await Gate.WaitAsync();
           try
           {
               ulong userId;
               if (await users.GetByTelegramIdAsync(me.TelegramId) is { } existing)
               {
                   userId = existing.Id;
               }
               else
               {
                   try
                   {
                       userId = await users.CreateAsync(new User { TelegramId = me.TelegramId, FirstName = me.Name });
                   }
                   catch (MySqlException ex) when (ex.ErrorCode == MySqlErrorCode.DuplicateKeyEntry)
                   {
                       userId = (await users.GetByTelegramIdAsync(me.TelegramId))?.Id
                                ?? throw new InvalidOperationException($"users.telegram_id={me.TelegramId}: duplicate key but no row", ex);
                   }
               }

               // Same onboarding as AuthEndpoints.TelegramLogin (GetPrimaryAccountIdAsync is global, not per user).
               if (await accounts.GetPrimaryAccountIdAsync() is null)
                   await accounts.CreateAsync(new Account { UserId = userId });
               return userId;
           }
           finally
           {
               Gate.Release();
           }
       }
   }

   /// <summary>Adds claim <c>local_uid</c> (local users.id) to the owner's mvv42 identity.</summary>
   public sealed class LocalUserClaimsTransformation(UserProvisioning provisioning, IMemoryCache cache, IConfiguration config)
       : IClaimsTransformation
   {
       public const string ClaimType = "local_uid";

       public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
       {
           if (principal.HasClaim(c => c.Type == ClaimType)
               || !Mvv42Access.Mvv42Allowed(principal, Mvv42Access.OwnerTelegramId(config))
               || principal.GetMvv42User() is not { } me)
               return principal; // not the owner: no local user is created, the policy denies

           var localId = await cache.GetOrCreateAsync($"mvv42-local-uid:{me.TelegramId}", entry =>
           {
               entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(10);
               return provisioning.GetOrCreateAsync(me);
           });

           var clone = principal.Clone();
           clone.Identities.First(i => i.IsAuthenticated && i.AuthenticationType == Mvv42Auth.Scheme)
               .AddClaim(new Claim(ClaimType, localId.ToString(CultureInfo.InvariantCulture)));
           return clone;
       }
   }

   /// <summary>Replaces every <c>principal.FindFirstValue(ClaimTypes.NameIdentifier)</c> + <c>ulong.TryParse</c>.</summary>
   public static class LocalUser
   {
       /// <summary>Local users.id for either scheme: mvv42 → <c>local_uid</c>, legacy → NameIdentifier (= sub).</summary>
       public static ulong? Id(ClaimsPrincipal principal) =>
           ulong.TryParse(principal.FindFirstValue(LocalUserClaimsTransformation.ClaimType)
                          ?? principal.FindFirstValue(ClaimTypes.NameIdentifier),
               NumberStyles.None, CultureInfo.InvariantCulture, out var id)
               ? id
               : null;
   }
   ```
3. `Program.cs` — после `AddAuthentication(...).AddJwtBearer()`, **вместо** нынешнего `AddAuthorization(...)`:
   ```csharp
   builder.Services.AddMvv42Auth(Mvv42Access.AppId, o => builder.Configuration.GetSection("Mvv42Auth").Bind(o));
   builder.Services.AddMemoryCache();
   builder.Services.AddScoped<UserProvisioning>();
   builder.Services.AddScoped<IClaimsTransformation, LocalUserClaimsTransformation>();

   var ownerTelegramId = Mvv42Access.OwnerTelegramId(builder.Configuration);
   var dualPolicy = new AuthorizationPolicyBuilder(JwtBearerDefaults.AuthenticationScheme, Mvv42Auth.Scheme)
       .RequireAuthenticatedUser()
       .RequireAssertion(ctx => Mvv42Access.LegacyAuthenticated(ctx.User) || Mvv42Access.Mvv42Allowed(ctx.User, ownerTelegramId))
       .Build();
   builder.Services.AddAuthorization(options =>
   {
       options.FallbackPolicy = dualPolicy;
       options.DefaultPolicy = dualPolicy; // /api/auth/me uses .RequireAuthorization() = DefaultPolicy
   });
   ```
   Лог `auth=legacy` — `Events.OnTokenValidated` в legacy `ConfigureNamedOptions` (как у credit_calc).
4. Заменить все 9 чтений `principal.FindFirstValue(ClaimTypes.NameIdentifier)` + `ulong.TryParse` на `LocalUser.Id(principal)`:

   | Файл:строка | Сейчас | После |
   |---|---|---|
   | `Endpoints/AuthEndpoints.cs:90` (`/me`) | `sub` → `GetByIdAsync` | `LocalUser.Id(principal) is not { } userId` → 401 JSON как сейчас |
   | `Endpoints/AnalyticsEndpoints.cs:202`, `:516` | `userIdClaim` → watchlist | `if (LocalUser.Id(principal) is { } userId)` |
   | `Endpoints/AnalyticsEndpoints.cs:845` | `userId` → watchlist / `[]` | то же |
   | `Endpoints/AnalyticsEndpoints.cs:1252` | `userIdClaim` → user settings / `null` | то же |
   | `Endpoints/PositionsEndpoints.cs:279` (`ResolveAccountIdAsync`, общий хелпер) | `sub` | `if (LocalUser.Id(principal) is not { } userId) return null;` |
   | `Endpoints/SettingsEndpoints.cs:251` (`ResolveUserId`) | `sub` → throw `ValidationException` | `LocalUser.Id(principal) ?? throw new ValidationException(…)` |
   | `Endpoints/WatchlistEndpoints.cs:193` (`ResolveUserId`) | `sub` → `null` | `=> LocalUser.Id(principal);` |
   | `Endpoints/UniverseEndpoints.cs:189` | `sub` → watchlist / `[]` | `if (LocalUser.Id(principal) is { } userId)` |

   Пример (`PositionsEndpoints.ResolveAccountIdAsync`):
   ```csharp
   internal static async Task<ulong?> ResolveAccountIdAsync(ClaimsPrincipal principal, IAccountRepository accountRepo)
   {
       if (LocalUser.Id(principal) is not { } userId)
           return null;
       var accounts = await accountRepo.GetByUserIdAsync(userId);
       return accounts.Select(a => (ulong?)a.Id).OrderBy(id => id).FirstOrDefault();
   }
   ```
   Контроль: `grep -rn "ClaimTypes.NameIdentifier" src/Bonds.Api --include=*.cs` → только `Auth/Mvv42LocalUser.cs` и `GenerateJwt`.
5. Флаг `LegacyAuth:LoginEnabled` в `TelegramLogin`; `backend.yml`: `-e "LegacyAuth__LoginEnabled=${{ vars.LEGACY_LOGIN_ENABLED || 'true' }}"`.
6. Сеть: уже `--network cashpulse-network`.

Откат Ф1: образ только `:latest` → revert коммита + push (пересборка). Локальная строка владельца уже есть (тот же
`telegram_id`), новых данных не появляется.

### Ф2 — фронт (bonds-web)

- `src/api/client.ts`: `fetch` → `mvv42Fetch`, без `Authorization`; финальный 401 → `requestLogin('bonds')`.
- `src/api/auth.ts` `fetchMe(token)` → `getMe()`; `src/App.tsx:33-38` — `getMe()` на старте; `user == null` →
  `requestLogin('bonds')`; `granted == false` для `bonds` (не владелец/не админ) → экран «нет доступа», не цикл логина.
- `src/store/useAuthStore.ts` (`bonds-auth`) → `me` в памяти; `src/pages/Login.tsx`, `ProtectedRoute.tsx` → `requestLogin('bonds')`.
- `VITE_API_BASE` относительный — менять не нужно.

Откат Ф2: предыдущая сборка (`frontend.yml` на прошлом коммите).

### Ф3 (после гейта)

Удалить `TelegramLogin`/`GenerateJwt`/`ITelegramAuthService`, legacy `AddJwtBearer`, `JwtSecretGuard`, `Jwt__Secret`
(`JWT_SECRET` + проверку длины в `backend.yml`), `VITE_TELEGRAM_BOT_USERNAME`, localStorage `bonds-auth`.
**Оставить** `Telegram__BotToken` и `Telegram__OwnerId`: их читает `TelegramAlertSender` (`Telegram:BotToken`,
`Telegram:OwnerId` = `chat_id` алертов), а `OwnerId` нужен проверке выше.

## cashpulse

Бэкенд `src/CashPulse.Api`: **нет** ASP.NET-аутентификации — своя `Middleware/JwtMiddleware.cs` проверяет Bearer
и кладёт `ulong` в `HttpContext.Items["UserId"]` (читается в 10 местах: хелперы `GetUserId(HttpContext)` в
`Accounts/BalanceSnapshots/Categories/Operations/Scenarios/IncomeSource`-эндпоинтах и inline в `Forecast:20`,
`Import:21,69`, `Tags:17` — они не меняются). Ошибки — JSON `{"error":"…"}`. `AuthEndpoints.TelegramLogin` создаёт
пользователя и вызывает private `SeedCategoriesForUser`. Таблица `Users`: `DisplayName NOT NULL` без дефолта,
`TelegramId BIGINT NULL UNIQUE`, `GoogleSubjectId` UNIQUE. Сеть `cashpulse-network` уже есть; фронт ходит на абсолютный
`VITE_API_URL`, nginx отдаёт legacy `/api/` контейнеру `cashpulse-api`.

### Ф-1 — пользователи без Telegram (до Ф1!)

Provisioning ищет только по `TelegramId`: пользователь без него, войдя через mvv42, получит **новый пустой** аккаунт,
а последующая привязка упрётся в UNIQUE. Поэтому сначала:

```sql
-- docker exec -it cashpulse-mysql mysql -uroot -p cashpulse
SELECT Id, Email, DisplayName, GoogleSubjectId, CreatedAt FROM Users WHERE TelegramId IS NULL;
```

`Id=1 'dev@local'` — сид из `002_seed_data.sql`, его не трогать. Для каждого реального пользователя узнать его
Telegram id (например, @userinfobot) и проверить конфликт:

```sql
SELECT Id, DisplayName, CreatedAt FROM Users WHERE TelegramId = <tg>;
```

- строки нет → привязать (сохранить список `(Id, tg)` для отката):
  ```sql
  UPDATE Users SET TelegramId = <tg> WHERE Id = <id> AND TelegramId IS NULL;
  ```
- строка есть (человек уже входил через Telegram и получил второй аккаунт) → сначала `mysqldump cashpulse`, затем
  посмотреть, где данные:
  ```sql
  SELECT TABLE_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'cashpulse' AND COLUMN_NAME = 'UserId';
  -- для каждой таблицы T из списка:
  SELECT UserId, COUNT(*) FROM T WHERE UserId IN (<id>, <tgUserId>) GROUP BY UserId;
  ```
  Telegram-аккаунт пуст (только системные категории) → `DELETE FROM Users WHERE Id = <tgUserId>;` (FK `ON DELETE
  CASCADE` уберёт его категории и т.п.) и `UPDATE` выше. Данные в обоих → ручное слияние по таблицам в транзакции
  (вне этого гайда; не автоматизировать). Пока конфликт не решён — Ф1 не начинать.

Откат: `UPDATE Users SET TelegramId = NULL WHERE Id IN (…)` по сохранённому списку.

### Ф1 — бэкенд

1. Пакеты (таблица выше; `MySqlConnector` 2.3.5 в API уже есть), `Mvv42Auth.cs` → `src/CashPulse.Api/Auth/Mvv42Auth.cs`.
2. Новый сервис `src/CashPulse.Api/Auth/UserProvisioning.cs` (сюда переезжает `SeedCategoriesForUser`, его используют
   и старый логин, и новый путь):
   ```csharp
   using CashPulse.Core.Interfaces.Repositories;
   using CashPulse.Core.Models;
   using MySqlConnector;

   namespace CashPulse.Api.Auth;

   /// <summary>
   /// The single place that creates users: the legacy /api/auth/telegram AND the mvv42 path. A new user always gets the
   /// system categories (formerly AuthEndpoints.SeedCategoriesForUser).
   /// </summary>
   public sealed class UserProvisioning(IUserRepository users, ICategoryRepository categoryRepo)
   {
       // One API instance: serialises the first-request burst of a new user (parallel API calls from the SPA).
       private static readonly SemaphoreSlim Gate = new(1, 1);

       /// <summary>Existing user by telegram id, or a new one with seeded categories.</summary>
       public async Task<User> GetOrCreateAsync(long telegramId, string displayName)
       {
           if (await users.GetByTelegramIdAsync(telegramId) is { } existing)
               return existing;

           await Gate.WaitAsync();
           try
           {
               if (await users.GetByTelegramIdAsync(telegramId) is { } created)
                   return created;

               var user = new User
               {
                   TelegramId = telegramId,
                   DisplayName = string.IsNullOrWhiteSpace(displayName) ? $"user_{telegramId}" : displayName,
                   Email = null,
                   BaseCurrency = "RUB",
               };
               try
               {
                   user.Id = await users.CreateAsync(user);
               }
               catch (MySqlException ex) when (ex.ErrorCode == MySqlErrorCode.DuplicateKeyEntry)
               {
                   // uq_users_telegram_id: someone else created it a moment ago (and seeded its categories)
                   return await users.GetByTelegramIdAsync(telegramId)
                          ?? throw new InvalidOperationException($"Users.TelegramId={telegramId}: duplicate key but no row", ex);
               }

               await SeedCategoriesAsync(user.Id);
               return user;
           }
           finally
           {
               Gate.Release();
           }
       }

       /// <summary>Moved verbatim from AuthEndpoints.SeedCategoriesForUser.</summary>
       private async Task SeedCategoriesAsync(ulong userId)
       {
           // Корневые категории
           var incomeId  = await categoryRepo.CreateAsync(new Category { UserId = userId, Name = "Доходы",  IsSystem = true, SortOrder = 0 });
           var expenseId = await categoryRepo.CreateAsync(new Category { UserId = userId, Name = "Расходы", IsSystem = true, SortOrder = 1 });

           // Доходы
           await categoryRepo.CreateAsync(new Category { UserId = userId, Name = "ЗП",                   ParentId = incomeId,  IsSystem = true, SortOrder = 0 });
           await categoryRepo.CreateAsync(new Category { UserId = userId, Name = "Инвестиции (доход)",    ParentId = incomeId,  IsSystem = true, SortOrder = 1 });
           await categoryRepo.CreateAsync(new Category { UserId = userId, Name = "Прочие доходы",         ParentId = incomeId,  IsSystem = true, SortOrder = 2 });

           // Расходы
           await categoryRepo.CreateAsync(new Category { UserId = userId, Name = "Ипотека",              ParentId = expenseId, IsSystem = true, SortOrder = 0 });
           await categoryRepo.CreateAsync(new Category { UserId = userId, Name = "Кредитка (погашение)",  ParentId = expenseId, IsSystem = true, SortOrder = 1 });
           var bytId = await categoryRepo.CreateAsync(new Category { UserId = userId, Name = "Быт",       ParentId = expenseId, IsSystem = true, SortOrder = 2 });
           await categoryRepo.CreateAsync(new Category { UserId = userId, Name = "Продукты",              ParentId = bytId,     IsSystem = true, SortOrder = 0 });
           await categoryRepo.CreateAsync(new Category { UserId = userId, Name = "Рестораны/Кафе",        ParentId = bytId,     IsSystem = true, SortOrder = 1 });
           await categoryRepo.CreateAsync(new Category { UserId = userId, Name = "Подписки",              ParentId = bytId,     IsSystem = true, SortOrder = 2 });
           await categoryRepo.CreateAsync(new Category { UserId = userId, Name = "Транспорт",             ParentId = expenseId, IsSystem = true, SortOrder = 3 });
           await categoryRepo.CreateAsync(new Category { UserId = userId, Name = "Поездки",               ParentId = expenseId, IsSystem = true, SortOrder = 4 });
           await categoryRepo.CreateAsync(new Category { UserId = userId, Name = "Ремонт",                ParentId = expenseId, IsSystem = true, SortOrder = 5 });
           await categoryRepo.CreateAsync(new Category { UserId = userId, Name = "Здоровье/Медицина",     ParentId = expenseId, IsSystem = true, SortOrder = 6 });
           await categoryRepo.CreateAsync(new Category { UserId = userId, Name = "Образование",           ParentId = expenseId, IsSystem = true, SortOrder = 7 });
           await categoryRepo.CreateAsync(new Category { UserId = userId, Name = "Прочее",                ParentId = expenseId, IsSystem = true, SortOrder = 8 });
       }
   }
   ```
3. Старый `AuthEndpoints.TelegramLogin`: параметры `IUserRepository userRepo, UserProvisioning provisioning` вместо
   `ICategoryRepository`; блок «2. Находим или создаём пользователя» →
   ```csharp
   if (!config.GetValue("LegacyAuth:LoginEnabled", true))
       return Results.Json(new { error = "Вход выполняется через mvv42.ru" }, statusCode: StatusCodes.Status410Gone);
   // ... ValidateAuthData как сейчас ...
   var displayName = BuildDisplayName(data);
   var user = await provisioning.GetOrCreateAsync(data.Id, displayName);
   if (user.DisplayName != displayName)
   {
       user.DisplayName = displayName;
       await userRepo.UpdateAsync(user);
   }
   ```
   `SeedCategoriesForUser` из `AuthEndpoints` удалить.
4. `Middleware/JwtMiddleware.cs` целиком (legacy-валидация без изменений; mvv42 — и когда Bearer нет, и когда он
   невалиден/истёк; ошибки остаются JSON):
   ```csharp
   using System.IdentityModel.Tokens.Jwt;
   using System.Security.Claims;
   using System.Text;
   using CashPulse.Api.Auth;
   using Microsoft.AspNetCore.Authentication;
   using Microsoft.AspNetCore.Authorization;
   using Microsoft.Extensions.Caching.Memory;
   using Microsoft.IdentityModel.Tokens;
   using Mvv42.Auth.Client;

   namespace CashPulse.Api.Middleware;

   /// <summary>
   /// Puts the local user id into HttpContext.Items["UserId"] (boxed ulong), as before. Accepts
   /// 1) the legacy Bearer token (unchanged validation), or
   /// 2) the mvv42 access cookie — also when the Bearer header is present but invalid/expired (stale localStorage) —
   ///    if Mvv42Auth.Policy allows the app (`apps ∋ cashpulse` or adm). The local user is found/created by `tg`.
   /// Errors stay JSON {"error": "..."}.
   /// </summary>
   public class JwtMiddleware
   {
       private readonly RequestDelegate _next;
       private readonly string _secret;
       private readonly string _issuer;
       private readonly string _audience;

       private static readonly HashSet<string> _publicPaths =
       [
           "/health",
           "/api/auth/telegram",
           "/swagger",
       ];

       public JwtMiddleware(RequestDelegate next, IConfiguration configuration)
       {
           _next = next;
           _secret   = configuration["Jwt:Secret"]   ?? throw new InvalidOperationException("Jwt:Secret не настроен");
           _issuer   = configuration["Jwt:Issuer"]   ?? "cashpulse";
           _audience = configuration["Jwt:Audience"] ?? "cashpulse";
       }

       public async Task InvokeAsync(HttpContext context, UserProvisioning provisioning, IAuthorizationService authorization,
           IMemoryCache cache, ILogger<JwtMiddleware> logger)
       {
           var path = context.Request.Path.Value ?? string.Empty;
           if (IsPublicPath(path))
           {
               await _next(context);
               return;
           }

           // 1. legacy Bearer
           var token = ExtractToken(context);
           if (token is not null && ValidateToken(token) is { } legacyUserId)
           {
               logger.LogInformation("auth=legacy user={UserId} path={Path}", legacyUserId, path); // Ф3 gate
               context.Items["UserId"] = legacyUserId;
               await _next(context);
               return;
           }

           // 2. mvv42 cookie (no Bearer, or Bearer invalid/expired)
           var mvv42 = await context.AuthenticateAsync(Mvv42Auth.Scheme);
           if (mvv42.Succeeded && mvv42.Principal.GetMvv42User() is { } me)
           {
               if (!(await authorization.AuthorizeAsync(mvv42.Principal, Mvv42Auth.Policy)).Succeeded)
               {
                   await WriteError(context, StatusCodes.Status403Forbidden, "Нет доступа к приложению");
                   return;
               }

               var userId = await cache.GetOrCreateAsync($"mvv42-local-uid:{me.TelegramId}", async entry =>
               {
                   entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(10);
                   return (await provisioning.GetOrCreateAsync(me.TelegramId, me.Name)).Id;
               });
               context.User = mvv42.Principal;
               context.Items["UserId"] = userId;
               await _next(context);
               return;
           }

           await WriteError(context, StatusCodes.Status401Unauthorized,
               token is null ? "Требуется авторизация" : "Токен недействителен или истёк");
       }

       private static Task WriteError(HttpContext context, int status, string error)
       {
           context.Response.StatusCode = status;
           return context.Response.WriteAsJsonAsync(new { error });
       }

       private static string? ExtractToken(HttpContext context)
       {
           var header = context.Request.Headers.Authorization.FirstOrDefault();
           if (header?.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) == true)
               return header["Bearer ".Length..].Trim();
           return null;
       }

       private ulong? ValidateToken(string token)
       {
           try
           {
               var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secret));
               var handler = new JwtSecurityTokenHandler();

               var parameters = new TokenValidationParameters
               {
                   ValidateIssuerSigningKey = true,
                   IssuerSigningKey         = key,
                   ValidateIssuer           = true,
                   ValidIssuer              = _issuer,
                   ValidateAudience         = true,
                   ValidAudience            = _audience,
                   ValidateLifetime         = true,
                   ClockSkew                = TimeSpan.FromSeconds(30),
               };

               var principal = handler.ValidateToken(token, parameters, out _);
               var sub = principal.FindFirstValue(ClaimTypes.NameIdentifier);

               if (ulong.TryParse(sub, out var userId))
                   return userId;

               return null;
           }
           catch
           {
               return null;
           }
       }

       internal static bool IsPublicPath(string path) =>
           _publicPaths.Contains(path.TrimEnd('/'), StringComparer.OrdinalIgnoreCase)
           || path.StartsWith("/swagger/", StringComparison.OrdinalIgnoreCase);
   }
   ```
5. `Program.cs` (до `builder.Build()`):
   ```csharp
   builder.Services.AddMvv42Auth("cashpulse", o => builder.Configuration.GetSection("Mvv42Auth").Bind(o));
   builder.Services.AddMemoryCache();
   builder.Services.AddScoped<UserProvisioning>();
   ```
   `UseAuthentication/UseAuthorization` не нужны: middleware сама вызывает `AuthenticateAsync(Mvv42Auth.Scheme)` и
   `AuthorizeAsync(…, Mvv42Auth.Policy)` (политика с `apps`/`adm`, не только схема). Origin-фильтр SDK (`IStartupFilter`)
   отвечает `403 {"error":"origin_not_allowed"}` на небезопасные запросы с mvv42-cookie без нашего `Origin`.
6. `backend.yml`: `-e "LegacyAuth__LoginEnabled=${{ vars.LEGACY_LOGIN_ENABLED || 'true' }}"`.
7. Тесты: `JwtTestHelper` (legacy) работает как есть; для mvv42-пути — тестовый ES256-ключ и JWKS через
   `Mvv42AuthOptions.BackchannelHandler` (как `tests/Mvv42.Auth.Tests/Sdk/DotnetSdkTests.cs`).

Откат Ф1: `docker run … ghcr.io/max31000/cashpulse-api:sha-<предыдущий>` (или revert + push). Пользователи,
созданные по `tg`, — те же строки, что создал бы старый логин (с категориями).

### Ф2 — фронт (cashpulse-web)

- `VITE_API_URL`: default `?? ''` в `src/api/client.ts:5` и `src/api/auth.ts:3`, secret пустой (см. таблицу API base);
  локально — vite proxy `/api` и `/auth` вместо абсолютного URL.
- `src/api/client.ts`: `request`/`requestMultipart` → `mvv42Fetch`, без `getAuthHeaders()`; финальный 401 →
  `requestLogin('cashpulse')` вместо `logout()` + `/cashpulse/login`.
- `src/store/useAuthStore.ts` (`cashpulse-auth`) → `me` из `getMe()`. `AuthUser` (`id`, `displayName`, `baseCurrency`,
  `telegramId`) берётся уже из API приложения (локальный id ≠ `me.user.id` auth!), если UI это нужно.
- `src/pages/Login.tsx`, `ProtectedRoute.tsx` → `requestLogin('cashpulse')`; `AppLayout.tsx:36-39` logout →
  `POST /auth/api/logout`.
- Обновить `src/store/useAuthStore.test.ts`, `src/test/msw-handlers.ts`.

Откат Ф2: предыдущая сборка фронта; Bearer и старый логин ещё работают.

### Ф3 (после гейта)

`JwtMiddleware` — только mvv42-ветка; удалить `/api/auth/telegram`, `GenerateJwt`, `ITelegramAuthService`/`TelegramAuthService`,
`JwtSecretGuard`, `Jwt:*` в appsettings, `Jwt__Secret`/`JWT_SECRET`, `Telegram__BotToken`/`TELEGRAM_BOT_TOKEN`
(нужен только логину), `VITE_TELEGRAM_BOT_USERNAME`, localStorage `cashpulse-auth`, `Login.tsx`; `UserProvisioning`
остаётся. Тесты: `JwtTestHelper` → mvv42-токены.

## Ф2 — общее для фронтов (web SDK)

`sdk/web/mvv42.ts` копируется в `src/lib/mvv42.ts`. `mvv42Fetch` = fetch с `credentials: 'same-origin'`, на 401 —
один общий `/auth/api/refresh` (Web Lock `mvv42-refresh` на все вкладки/iframe) и один повтор. `getMe()` →
`{user, apps}` или `null` (auth недоступен — вести себя как до auth). `requestLogin(serviceId)` — в iframe просит
shell, standalone уходит на `/?login=1&return=<текущий путь>` (путь нормализуется: ведущие `/` схлопываются, `\` → `/`).
`onShellMessage` — `AUTH_CHANGED` после логина/логаута в shell.
