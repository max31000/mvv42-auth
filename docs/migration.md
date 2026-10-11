# Перевод приложений на mvv42-auth

Порядок: **credit_calc** (anonymous, проще) → **bonds** → **cashpulse**. Каждая фаза — отдельный деплой, откатываемый
независимо. Данные приложений не мигрируют: локальный пользователь находится/создаётся по claim `tg`
(во всех трёх сервисах `TelegramId` уже UNIQUE).

## Ф0. Запуск auth (один раз)

1. БД в `cashpulse-mysql`:
   ```sql
   CREATE DATABASE mvv42_auth CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   CREATE USER 'mvv42_auth'@'%' IDENTIFIED BY '<пароль>';
   GRANT ALL PRIVILEGES ON mvv42_auth.* TO 'mvv42_auth'@'%';
   ```
2. Секреты репо `mvv42-auth`: `AUTH_DB_CONNECTION_STRING`
   (`Server=cashpulse-mysql;Port=3306;Database=mvv42_auth;User ID=mvv42_auth;Password=<пароль>`),
   `AUTH_TELEGRAM_BOT_TOKEN` (токен `mv_cashpulse_bot`), `AUTH_ADMIN_TELEGRAM_IDS`, `VDS_*`, `TELEGRAM_BOT_TOKEN`/`TELEGRAM_CHAT_ID`.
3. BotFather: `/setdomain` → `mv_cashpulse_bot` → `mvv42.ru` (по спеке уже привязан — проверить).
4. Push в `main` → deploy. Проверка: `curl -s http://127.0.0.1:5010/auth/health` на сервере.
5. nginx: `nginx/apps/auth.conf` из `mvv42-infra` (`location /auth/ { proxy_pass http://127.0.0.1:5010; }` + `limit_req`
   на `/auth/api/telegram|refresh|invites/redeem`), `apply-nginx`. Проверка снаружи:
   `curl -s https://mvv42.ru/auth/.well-known/jwks.json`, `curl -s https://mvv42.ru/auth/api/me` → `{"user":null,…}`.
   Также `www.mvv42.ru` → 301 на apex (host-only cookies).
6. Строки в `apps` засеяны миграцией: `cashpulse(anonymous=0, public)`, `credit_calc(1, public)`, `bonds(0, admin)` —
   bonds соответствует нынешнему `Telegram:OwnerId` (только владелец). Владелец должен быть в `AUTH_ADMIN_TELEGRAM_IDS`.
7. Shell (portal-shell) начинает показывать логин и слот пользователя, как только `/auth/api/me` отвечает 200.

## Ф1. Бэкенд приложения: вторая схема (dual-mode)

Общее для всех:

1. Скопировать `sdk/dotnet/Mvv42Auth.cs` в API-проект (например `Auth/Mvv42Auth.cs`), пакет
   `Microsoft.AspNetCore.Authentication.JwtBearer` 8.0.x (в bonds/credit_calc уже есть; в cashpulse добавить).
2. Контейнер должен быть в docker-сети `cashpulse-network` (`--network cashpulse-network` в deploy) — JWKS берётся с
   `http://mvv42-auth:8080/auth/.well-known/jwks.json`. bonds уже в ней; credit_calc и cashpulse — проверить.
3. `builder.Services.AddMvv42Auth("<app-id>");` — до `builder.Build()`. Origin-фильтр SDK срабатывает только на запросы
   с mvv42-cookie, поэтому старые Bearer-клиенты не ломаются.
4. **Не путать id:** `sub` в mvv42-токене — id пользователя *auth*, а не локальный. Локальный id получать только через
   `GetMvv42User().TelegramId` → локальный пользователь.

Хелпер, общий для bonds и credit_calc (адаптировать под их репозиторий пользователей):

```csharp
// Возвращает локальный user id для запроса, аутентифицированного любой из двух схем.
public static async Task<ulong?> ResolveLocalUserIdAsync(ClaimsPrincipal principal, IUserRepository users)
{
    if (principal.GetMvv42User() is { } me)
    {
        var user = await users.GetByTelegramIdAsync(me.TelegramId)
                   ?? await users.CreateAsync(new User { TelegramId = me.TelegramId, DisplayName = me.Name });
        return user.Id;
    }
    // Старая схема: sub = локальный id
    return ulong.TryParse(principal.FindFirst("sub")?.Value ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value, out var id)
        ? id : null;
}
```

### bonds / credit_calc (стандартный `AddJwtBearer`)

```csharp
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(); // как сейчас
builder.Services.AddMvv42Auth("bonds");                                                  // "credit_calc"

builder.Services.AddAuthorization(options =>
{
    // старая ИЛИ новая схема
    options.FallbackPolicy = new AuthorizationPolicyBuilder(JwtBearerDefaults.AuthenticationScheme, Mvv42Auth.Scheme)
        .RequireAuthenticatedUser()
        .RequireAssertion(ctx =>
            ctx.User.GetMvv42User() is null                       // старый токен — прежние правила
            || ctx.User.HasClaim("adm", "true")
            || ctx.User.HasClaim("apps", "bonds"))                // app id
        .Build();
});
```

- bonds: `Telegram:OwnerId`-проверку оставить для старой схемы; для новой доступ уже ограничен `apps`/`adm`
  (app `bonds` = `admin`).
- credit_calc (`anonymous=true`): публичные эндпоинты остаются `AllowAnonymous`; «функции после логина» — под
  FallbackPolicy выше.
- Эндпоинты, которые читают `sub` напрямую, перевести на `ResolveLocalUserIdAsync`.

### cashpulse (свой `JwtMiddleware`, `HttpContext.Items["UserId"]`)

`UseAuthentication()` поставить **до** `JwtMiddleware`, а в middleware — fallback на mvv42, если Bearer-заголовка нет:

```csharp
// Program.cs
builder.Services.AddAuthentication();          // без схемы по умолчанию
builder.Services.AddMvv42Auth("cashpulse");
// ...
app.UseMiddleware<ErrorHandlingMiddleware>();
app.UseAuthentication();
app.UseMiddleware<JwtMiddleware>();
```

```csharp
// JwtMiddleware.InvokeAsync, вместо немедленного 401 при отсутствии Bearer:
var token = ExtractToken(context);
if (token is null)
{
    var result = await context.AuthenticateAsync(Mvv42Auth.Scheme);
    var me = result.Succeeded ? result.Principal!.GetMvv42User() : null;
    if (me is null || !(result.Principal!.HasClaim("adm", "true") || result.Principal.HasClaim("apps", "cashpulse")))
    {
        context.Response.StatusCode = me is null ? 401 : 403;
        return;
    }
    var users = context.RequestServices.GetRequiredService<IUserRepository>();
    var user = await users.GetByTelegramIdAsync(me.TelegramId)
               ?? /* тот же путь создания, что и в POST /api/auth/telegram (пользователь + дефолтные данные) */;
    context.Items["UserId"] = user.Id;
    await _next(context);
    return;
}
```

Перед Ф2 cashpulse (§9.12): проверить пользователей без `TelegramId` (наследие Google-входа):

```sql
SELECT Id, Email, GoogleSubjectId FROM Users WHERE TelegramId IS NULL;
-- если есть — разово связать вручную:
UPDATE Users SET TelegramId = <telegram id> WHERE Id = <id>;
```

## Ф2. Фронтенд приложения

1. Скопировать `sdk/web/mvv42.ts` (например `src/lib/mvv42.ts`).
2. Все запросы к своему API — через `mvv42Fetch` (cookies same-origin; 401 → один общий refresh под `navigator.locks`
   `mvv42-refresh` → повтор). Убрать заголовок `Authorization`.
3. Удалить свой экран логина и хранение токена; где нужен логин — `requestLogin('<app-id>')`
   (в iframe — `AUTH_REQUIRED` в shell, standalone — `/?login=1&return=…`).
4. Кто я / есть ли доступ: `getMe()` (null = auth недоступен → вести себя как раньше).
5. Shell-протокол: `onShellMessage` (`AUTH_CHANGED` → перечитать `getMe()`/данные), `onShellTheme('<app-id>', cb)`
   (шлёт `READY`, получает `THEME`), навигация — `startShellNavigationSync('<app-id>')` либо прежний `useShellSync`
   (targetOrigin `window.location.origin`).

```ts
import { getMe, mvv42Fetch, onShellMessage, onShellTheme, requestLogin } from './lib/mvv42';

onShellTheme('bonds', (scheme) => setColorScheme(scheme));
onShellMessage((m) => { if (m.type === 'AUTH_CHANGED') queryClient.invalidateQueries(); });
const res = await mvv42Fetch('/bonds/api/positions');
if (res.status === 401) requestLogin('bonds');
```

## Ф3. Уборка

- Удалить `POST /api/auth/telegram` и старую Bearer-схему/`JwtMiddleware`; FallbackPolicy — только `Mvv42Auth.Scheme`
  (или `RequireAuthorization(Mvv42Auth.Policy)`).
- Удалить `Jwt__Secret` из secrets/deploy, `Telegram__BotToken` из приложения (если больше не нужен боту), ключи
  localStorage со старым токеном (разово `localStorage.removeItem('<key>')` при старте).

## Чек-лист на приложение

- [ ] Ф1: `Mvv42Auth.cs` скопирован, пакет JwtBearer, контейнер в `cashpulse-network`
- [ ] Ф1: `AddMvv42Auth("<id>")`, dual-mode политика/middleware, локальный id только через `TelegramId`
- [ ] Ф1: тест: запрос с cookie `__Host-mvv42_at` проходит, без cookie и Bearer — 401, POST с cookie без `Origin` — 403
- [ ] Ф2: `mvv42Fetch`, `requestLogin`, `getMe`, свой логин удалён
- [ ] Ф2: проверено в shell и standalone (`/<id>/`)
- [ ] Ф3: старые эндпоинты, секрет и localStorage-ключи удалены
