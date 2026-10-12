# mvv42-auth API

Все пути публичные, через nginx на `https://mvv42.ru`. Ответы — JSON (camelCase). Ошибки: `{"error": "<code>"}`.
Даты — ISO-8601 UTC с `Z` (`"2026-10-12T08:00:00.123456Z"`).

**CSRF:** любой POST/PUT/PATCH/DELETE под `/auth/api/` без `Origin` (или, если его нет, `Referer`) из
`Auth__AllowedOrigins` → `403 {"error":"origin_not_allowed"}`. Браузерный same-origin `fetch` шлёт `Origin` сам.
Проверка — фильтр эндпоинта, т.е. выполняется **после** rate limit и авторизации: для эндпоинтов с
`RequireAuthorization` запрос без access-cookie получит `401` раньше, чем `403 origin_not_allowed`.

**Rate limit:** `/telegram`, `/refresh`, `/invites/redeem` — общее фиксированное окно 1 мин на IP клиента
(`Auth__RateLimitPerMinute`, по умолчанию 30; IP берётся из `X-Forwarded-For` только от доверенного прокси,
`Auth__TrustedProxyCidrs`) → `429 {"error":"rate_limited"}`. Перед сервисом ещё nginx `limit_req` (10 r/m, burst 10,
`429` без тела).

## Коды ошибок

Все JSON-ошибки — `{"error":"<code>"}`. Пустое тело — у ответов фреймворка (401/403 авторизации, 404, 400 на нечитаемый JSON).

| Код | Статус | Где |
|---|---|---|
| `invalid_body` | 400 | `/telegram`: тело не плоский JSON-объект (вложенные объекты/массивы) |
| `MissingHash` / `MissingAuthDate` / `MissingId` | 400 | `/telegram`: нет поля или оно не число |
| `InvalidHash` / `Expired` / `FromFuture` | 401 | `/telegram`: подпись / окно `auth_date` |
| `Replayed` | 401 | `/telegram`: этот же payload виджета (тот же `hash`) уже использован |
| `user_blocked` | 403 | `/telegram`: пользователь заблокирован владельцем |
| `telegram_not_configured` | 503 | `/telegram`: нет `Telegram__BotToken` (возможно только в Development) |
| `invalid_refresh_token` | 401 | `/refresh`: нет cookie, неизвестный/истёкший/отозванный токен, reuse (семья отозвана), пользователь удалён или заблокирован; cookies удаляются |
| `invite_not_found` | 400 | `/invites/redeem`: пустой или неизвестный код |
| `invite_expired` / `invite_exhausted` | 400 | `/invites/redeem`: срок истёк / использования кончились (если грант уже есть — это не ошибка, см. ниже) |
| `origin_not_allowed` | 403 | любой небезопасный метод под `/auth/api/` с чужим `Origin` или без него |
| `rate_limited` | 429 | `/telegram`, `/refresh`, `/invites/redeem` |
| `invalid_app_id` / `invalid_name` / `invalid_access` | 400 | `PUT /admin/apps/{id}` |
| `unknown_user` / `unknown_app` | 400 | `POST /admin/grants`; `unknown_app` также `POST /admin/invites` |
| `invalid_max_uses` / `invalid_expiry` | 400 | `POST /admin/invites` (`maxUses` 1…1000, `expiresInHours` 1…8760) |
| `user_not_found` | 404 | `GET /admin/users/{id}`, `PUT /admin/users/{id}/admin`, `PUT /admin/users/{id}/blocked`, `POST /admin/users/{id}/revoke-sessions` |
| `cannot_block_owner` | 400 | `PUT /admin/users/{id}/blocked` с `blocked: true` для владельца |
| `session_not_found` | 404 | `DELETE /admin/sessions/{id}` |
| `invite_not_found` | 404 | `DELETE /admin/invites/{id}` |
| `cannot_change_owner` | 400 | `PUT /admin/users/{id}/admin` для владельца (его `isAdmin` эффективный и неизменяемый) |
| `invalid_limit` / `invalid_before` | 400 | `GET /admin/logins`: `limit` не целое 1…500 / `before` не неотрицательное целое |

## Cookies

| Cookie (prod / Development) | Атрибуты | Содержимое |
|---|---|---|
| `__Host-mvv42_at` / `mvv42_at` | HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=600 | access JWT |
| `__Secure-mvv42_rt` / `mvv42_rt` | HttpOnly; Secure; SameSite=Strict; Path=/auth/api; Max-Age ≤ 30 дней | refresh-токен |

Logout и неуспешный refresh удаляют обе cookie с теми же Path/атрибутами.

## Access JWT

Header: `alg=ES256`, `kid` (RFC 7638 thumbprint ключа), `typ=JWT`.
Payload: `iss=https://mvv42.ru/auth`, `aud=mvv42`, `iat`, `nbf`, `exp` (+600 с), `sub` (id пользователя auth, строка),
`tg` (telegram id, строка), `name`, `adm` (`"true"`/`"false"`), `apps` (JSON-массив id приложений, к функциям которых
есть доступ: админ → все; `public` → все; `invite` → по гранту; `admin` → только админ).

Приложения проверяют JWT локально (JWKS), без запроса в auth. Поэтому изменения прав (гранты, флаг admin, режим
приложения) и **блокировка** доходят до приложений с истечением уже выданного access-токена: **≤ 10 мин**. Уже выданный
access-JWT заблокированного пользователя принимается приложениями до своего `exp`; обновить его он не сможет.

## Эндпоинты

### `POST /auth/api/telegram`
Тело — объект Telegram Login Widget как есть: `{id, first_name, last_name?, username?, photo_url?, auth_date, hash}`.
В data-check-string идут только присланные поля (null отбрасывается), окно `auth_date` — 1 ч (+60 с в будущее).

| Ответ | Когда |
|---|---|
| 200 + обе cookie + тело как у `/me` | ок (предыдущая сессия этого браузера отзывается) |
| 400 `MissingHash` / `MissingAuthDate` / `MissingId` / `invalid_body` | кривой запрос |
| 401 `InvalidHash` / `Expired` / `FromFuture` | проверка не прошла |
| 401 `Replayed` | payload с этим `hash` уже обменян на сессию (кэш в памяти на время окна `auth_date`) |
| 403 `user_blocked` | пользователь заблокирован; проверка **до** обновления профиля, сессия не создаётся |
| 429 `rate_limited` | см. Rate limit |
| 503 `telegram_not_configured` | нет `Telegram__BotToken` (только dev) |

Булевы поля виджета (если придут JSON `true`/`false`) входят в data-check-string как `true`/`false`.

**Журнал входов** (`login_events`, админка → `GET /admin/logins`): каждая попытка после разбора тела —
`ok`, `denied_blocked` (с `userId`/`telegramId`), `invalid` (любая ошибка проверки: `Missing*`, `InvalidHash`, `Expired`,
`FromFuture`), `replayed`. Для `invalid`/`replayed` `telegramId` и `userId` **не сохраняются** (id не проверен).
Плюс IP (после `X-Forwarded-For` от доверенного прокси; IPv4-mapped IPv6 `::ffff:a.b.c.d` пишется как `a.b.c.d`) и
User-Agent. Тот же IP пишется в `sessions.ip`. `invalid_body` и `telegram_not_configured` не журналируются.
Часовая фоновая очистка удаляет `invalid`/`replayed` старше 7 дней, остальные — старше 180 дней. Запись в журнал —
best effort: её сбой логируется и **не** ломает вход.

### `POST /auth/api/refresh`
По refresh-cookie. `204` + новый access + новый refresh (ротация). Если предъявлен **предыдущий** refresh-токен,
ротированный < 30 с назад, и сессия не отозвана — `204` только с новым access (гонка вкладок). Предыдущий токен позже 30 с
или **любой более ранний** токен этой сессии (таблица `refresh_token_history`) — отзыв всей семьи.
Все неуспехи — `401 {"error":"invalid_refresh_token"}` и удаление обеих cookie (нет cookie, неизвестный, истёкший,
отозванный, reuse, удалённый или заблокированный пользователь). `429 rate_limited` — см. выше.
Сессия: скользящие 30 дней, но не дольше 90 дней от логина.

### `POST /auth/api/logout`
Отзывает сессию (по текущему или предыдущему refresh-токену), удаляет обе cookie. Всегда `204`
(кроме `403 origin_not_allowed`).

**Потерянный ответ (edge case).** Ответ на `/refresh` (или на неявный refresh в `/me`) с новым refresh-cookie может не
дойти до браузера (обрыв сети после коммита ротации). Тогда у браузера остаётся старый токен, а сервер считает его
*предыдущим*: 30 с повтор даёт `204` только с новым access, refresh-cookie не меняется; позже — reuse, семья отозвана,
пользователь разлогинен (не позже чем через 10 мин, на следующем refresh). С logout наоборот: если потерян ответ на
`/logout`, сессия на сервере уже отозвана, а cookies в браузере остались — access-cookie ещё до 10 мин принимается
приложениями (JWT проверяется локально), следующий `/me` вернёт анонима и удалит cookies, `/refresh` — `401
invalid_refresh_token`. Повтор `/logout` безопасен (идемпотентен) — клиенту стоит повторить его при сетевой ошибке.

### `GET /auth/api/me`
Работает анонимно, всегда `200`, `Cache-Control: no-store`. Если access-cookie нет или он истёк, а refresh валиден —
делает то же, что `/refresh` (ставит cookies) и отвечает с пользователем; если refresh невалиден — аноним, cookies
удаляются. Access валиден, но пользователя уже нет в БД **или он заблокирован** — аноним, cookies удаляются (то же при
неявном refresh). Клиенту на старте достаточно вызвать `/me`.

```json
{
  "user": { "id": 7, "telegramId": 123456789, "name": "Max V", "username": "max", "photoUrl": null, "isAdmin": false, "isOwner": false },
  "apps": [
    { "id": "bonds", "anonymous": false, "access": "admin", "granted": false },
    { "id": "cashpulse", "anonymous": false, "access": "public", "granted": true },
    { "id": "credit_calc", "anonymous": true, "access": "public", "granted": true }
  ]
}
```
Аноним: `"user": null`, `granted: false` везде. Замок в launcher — `!anonymous && !granted`.
`isAdmin` — доступ к `access=admin`-приложениям (`users.is_admin` или владелец). `isOwner` — telegram id в
`Auth__AdminTelegramIds`: только владелец видит админку и вызывает `/auth/api/admin/*`.

### `POST /auth/api/invites/redeem`
Нужен access-cookie любого залогиненного (не заблокированного) пользователя. `{ "code": "…" }` →
`200 { "appId": "…", "alreadyGranted": false, "me": <тело как у /me> }` и **сразу переизданный** access-cookie.
Если пользователь **уже** может пользоваться приложением (явный грант, `public`-приложение, админ/владелец) — `200` с
`alreadyGranted: true`, использование не списывается (даже если инвайт уже истёк или исчерпан). Shell строит ссылку `https://mvv42.ru/?invite=<code>`.

| Ответ | Когда |
|---|---|
| `400 invite_not_found` | пустой или неизвестный код (в т.ч. удалённый инвайт) |
| `400 invite_expired` | `expiresAt` прошёл |
| `400 invite_exhausted` | `uses = maxUses` |
| `401` (пустое тело) | нет access-cookie или он истёк — клиент делает `/refresh` и повторяет (это делает `mvv42Fetch`); пользователь удалён или заблокирован |
| `403 origin_not_allowed` | access-cookie есть, но `Origin`/`Referer` не из `Auth__AllowedOrigins` |
| `429 rate_limited` | см. Rate limit |

### `GET /auth/.well-known/jwks.json`
`{"keys":[{"kty":"EC","crv":"P-256","x":"…","y":"…","kid":"…","alg":"ES256","use":"sig"}]}`, `Cache-Control: public, max-age=300`.
Приложения ходят сюда по docker-сети: `http://mvv42-auth:8080/auth/.well-known/jwks.json`.

### `GET /auth/health`
`{"status":"ok"}` (без БД).

## Admin API (`/auth/api/admin`, политика `owner`)

**Доступ:** access-cookie, в котором claim `tg` входит в `Auth__AdminTelegramIds` (владелец). Иначе `401` (нет/истёк
cookie, пользователь удалён) / `403` **с пустым телом** (не владелец — `users.is_admin` **не** даёт доступа к админке,
он только открывает `access=admin`-приложения). Проверка по claim'у; заблокированный токена не получает. Владельца
заблокировать нельзя, а флаг `is_blocked` в его строке (если он стоит) игнорируется — владелец никогда не считается
заблокированным.

После любого изменяющего запроса вызывающему переиздаётся access-cookie (его собственные права применяются сразу).
Права **других** пользователей (гранты, `isAdmin`, режим приложения, блокировка) доходят до их приложений с их следующим
access-токеном — **≤ 10 мин** (`/me` и `/refresh` видят изменения сразу).

### Типы

```ts
type AdminUser = { id: number; telegramId: number; name: string; username: string | null; photoUrl: string | null;
  isAdmin: boolean;            // эффективный: users.is_admin или владелец
  isOwner: boolean; isBlocked: boolean; blockedAt: string | null;
  createdAt: string; lastLoginAt: string | null;
  activeSessions: number;      // не отозванные и не истёкшие
  grants: string[] };          // явные гранты (app id), отсортированы
type AdminSession = { id: number; createdAt: string; lastUsedAt: string | null; expiresAt: string;
  userAgent: string | null; ip: string | null };
type LoginEvent = { id: number; at: string; userId: number | null; telegramId: number | null; userName: string | null;
  ip: string | null; userAgent: string | null; result: 'ok' | 'denied_blocked' | 'invalid' | 'replayed' };
type AdminApp = { id: string; name: string; anonymous: boolean; access: 'public' | 'invite' | 'admin' };
type AdminInvite = { id: number; appId: string; maxUses: number; uses: number;
  expiresAt: string | null;    // API всегда ставит срок; null — только у строк, созданных вручную (такой не истекает)
  createdBy: number | null; createdAt: string;
  status: 'active' | 'expired' | 'exhausted' };   // exhausted важнее expired
```

### Эндпоинты

| Метод + путь | Тело → ответ |
|---|---|
| `GET /overview` | `{ users, activeSessions, logins24h, logins7d, blocked, apps: (AdminApp & { grantedUsers })[] }`. `logins*` — входы с `result=ok` за 24 ч / 7 дней; `grantedUsers` — сколько незаблокированных пользователей имеют доступ к приложению (как `granted` в `/me`: `public` — все, `invite` — по гранту + админы, `admin` — админы) |
| `GET /users` | `AdminUser[]` (по `id`) |
| `GET /users/{id}` | `{ user: AdminUser, sessions: AdminSession[], logins: LoginEvent[] }` — активные сессии (новые первыми), последние 50 входов (по времени, новые первыми) · 404 `user_not_found` |
| `PUT /users/{id}/admin` | `{ isAdmin }` → 204 · 404 `user_not_found` · 400 `cannot_change_owner` |
| `PUT /users/{id}/blocked` | `{ blocked }` → 204 · 404 `user_not_found` · 400 `cannot_block_owner`. Блокировка ставит `blockedAt` и **отзывает все сессии**; разблокировка сессии не возвращает (нужен новый вход) |
| `POST /users/{id}/revoke-sessions` | → 204 · 404 `user_not_found` |
| `DELETE /sessions/{id}` | → 204 (повтор для уже отозванной — тоже 204) · 404 `session_not_found` |
| `GET /logins?limit=1..500&before=<id>` | `{ items: LoginEvent[], nextBefore: number \| null }` — новые первыми (по `id`), `limit` по умолчанию 100; следующая страница — `before=nextBefore`; `nextBefore: null` — дальше нет · 400 `invalid_limit` / `invalid_before` |
| `GET /apps` | `AdminApp[]` |
| `PUT /apps/{id}` | `{ name, anonymous, access }` → 200 `AdminApp`. `id`: `^[a-z][a-z0-9_-]{0,63}$`, не из зарезервированных `auth, api, assets, health, .well-known, portal, admin` · 400 `invalid_app_id` / `invalid_name` / `invalid_access` |
| `DELETE /apps/{id}` | → 204 / 404 (пустое тело; гранты и инвайты удаляются каскадно) |
| `GET /grants?userId=` | `{ userId, appId, createdAt }[]` |
| `POST /grants` | `{ userId, appId }` → 204 · 400 `unknown_user` / `unknown_app` |
| `DELETE /grants/{userId}/{appId}` | → 204 / 404 (пустое тело) |
| `GET /invites` | `AdminInvite[]` (без кодов) |
| `POST /invites` | `{ appId, maxUses = 1, expiresInHours = 168 }` → `{ id, code, appId, maxUses, expiresAt }` — код показывается **один раз** (хранится только SHA-256) · 400 `unknown_app` / `invalid_max_uses` / `invalid_expiry` |
| `DELETE /invites/{id}` | → 204 · 404 `invite_not_found` |

## Модель сессий (для понимания поведения)

Одна строка `sessions` на логин, ротация на месте: `refresh_hash` ← новый, `prev_refresh_hash` ← старый, `rotated_at` ← now;
в той же транзакции старый хеш пишется в `refresh_token_history(hash, family_id, session_id, rotated_at)`.
Повторное предъявление *предыдущего* токена различается по `rotated_at` (grace 30 с / reuse). Хеш, который есть только в
истории (старше предыдущего), — всегда reuse, отзыв семьи.
Фоновая служба раз в час удаляет истёкшие сессии и отозванные более суток назад вместе с их историей (FK `ON DELETE CASCADE`),
а также записи `login_events` старше 180 дней (`invalid`/`replayed` — старше 7 дней). При удалении пользователя из БД
`login_events.user_id` и `telegram_id` его записей обнуляются (два FK `ON DELETE SET NULL`). В `sessions.ip` — IP клиента при входе (нормализованный, см. журнал входов).
Блокировка: `users.is_blocked`/`blocked_at`; единая точка проверки — выдача токена (`/telegram`, `/refresh`, неявный refresh
в `/me`, переиздание cookie после redeem/admin), заблокированному токен не выдаётся.
