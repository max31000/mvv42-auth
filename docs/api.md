# mvv42-auth API

Все пути публичные, через nginx на `https://mvv42.ru`. Ответы — JSON (camelCase). Ошибки: `{"error": "<code>"}`.

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
| `telegram_not_configured` | 503 | `/telegram`: нет `Telegram__BotToken` (возможно только в Development) |
| `invalid_refresh_token` | 401 | `/refresh`: нет cookie, неизвестный/истёкший/отозванный токен, reuse (семья отозвана), пользователь удалён; cookies удаляются |
| `invalid_invite` | 400 | `/invites/redeem`: пустой/неизвестный/истёкший/исчерпанный код |
| `origin_not_allowed` | 403 | любой небезопасный метод под `/auth/api/` с чужим `Origin` или без него |
| `rate_limited` | 429 | `/telegram`, `/refresh`, `/invites/redeem` |
| `invalid_app_id` / `invalid_name` / `invalid_access` | 400 | `PUT /admin/apps/{id}` |
| `unknown_user` / `unknown_app` | 400 | `POST /admin/grants`; `unknown_app` также `POST /admin/invites` |
| `invalid_max_uses` / `invalid_expiry` | 400 | `POST /admin/invites` (`maxUses` 1…1000, `expiresInHours` 1…8760) |

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
| 429 `rate_limited` | см. Rate limit |
| 503 `telegram_not_configured` | нет `Telegram__BotToken` (только dev) |

Булевы поля виджета (если придут JSON `true`/`false`) входят в data-check-string как `true`/`false`.

### `POST /auth/api/refresh`
По refresh-cookie. `204` + новый access + новый refresh (ротация). Если предъявлен **предыдущий** refresh-токен,
ротированный < 30 с назад, и сессия не отозвана — `204` только с новым access (гонка вкладок). Предыдущий токен позже 30 с
или **любой более ранний** токен этой сессии (таблица `refresh_token_history`) — отзыв всей семьи.
Все неуспехи — `401 {"error":"invalid_refresh_token"}` и удаление обеих cookie (нет cookie, неизвестный, истёкший,
отозванный, reuse, удалённый пользователь). `429 rate_limited` — см. выше.
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
удаляются. Access валиден, но пользователя уже нет в БД — аноним, cookies удаляются. Клиенту на старте достаточно
вызвать `/me`.

```json
{
  "user": { "id": 7, "telegramId": 123456789, "name": "Max V", "username": "max", "photoUrl": null, "isAdmin": false },
  "apps": [
    { "id": "bonds", "anonymous": false, "access": "admin", "granted": false },
    { "id": "cashpulse", "anonymous": false, "access": "public", "granted": true },
    { "id": "credit_calc", "anonymous": true, "access": "public", "granted": true }
  ]
}
```
Аноним: `"user": null`, `granted: false` везде. Замок в launcher — `!anonymous && !granted`.

### `POST /auth/api/invites/redeem`
Нужен access-cookie. `{ "code": "…" }` → `200` с телом как у `/me` и **сразу переизданным** access-cookie.
Если грант уже есть — `200`, использование не списывается.

| Ответ | Когда |
|---|---|
| `400 invalid_invite` | пустой/неизвестный/истёкший/исчерпанный код |
| `401` (пустое тело, `WWW-Authenticate: Bearer`) | нет access-cookie или он истёк — клиент делает `/refresh` и повторяет (это делает `mvv42Fetch`); пользователь удалён |
| `403 origin_not_allowed` | access-cookie есть, но `Origin`/`Referer` не из `Auth__AllowedOrigins` |
| `429 rate_limited` | см. Rate limit |

### `GET /auth/.well-known/jwks.json`
`{"keys":[{"kty":"EC","crv":"P-256","x":"…","y":"…","kid":"…","alg":"ES256","use":"sig"}]}`, `Cache-Control: public, max-age=300`.
Приложения ходят сюда по docker-сети: `http://mvv42-auth:8080/auth/.well-known/jwks.json`.

### `GET /auth/health`
`{"status":"ok"}` (без БД).

## Admin (`adm=true` в access-cookie, иначе 401/403)

После любого изменяющего запроса вызывающему переиздаётся access-cookie (его собственные права применяются сразу);
права других пользователей меняются с их следующим access-токеном (≤ 10 мин).

| Метод | Путь | Тело / ответ |
|---|---|---|
| GET | `/auth/api/admin/apps` | список приложений |
| PUT | `/auth/api/admin/apps/{id}` | `{name, anonymous, access}` → 200 app. `id`: `^[a-z0-9][a-z0-9_-]{0,63}$`, не из зарезервированных `auth, api, assets, health, .well-known, portal` |
| DELETE | `/auth/api/admin/apps/{id}` | 204 / 404 (гранты и инвайты удаляются каскадно) |
| GET | `/auth/api/admin/users` | список пользователей (`isAdmin` — флаг в БД, без учёта env) |
| PUT | `/auth/api/admin/users/{id}/admin` | `{isAdmin}` → 204 / 404 |
| GET | `/auth/api/admin/grants?userId=` | гранты |
| POST | `/auth/api/admin/grants` | `{userId, appId}` → 204; 400 `unknown_user` / `unknown_app` |
| DELETE | `/auth/api/admin/grants/{userId}/{appId}` | 204 / 404 |
| GET | `/auth/api/admin/invites` | инвайты без кодов |
| POST | `/auth/api/admin/invites` | `{appId, maxUses=1, expiresInHours=168}` → `{id, code, appId, maxUses, expiresAt}` (код показывается один раз) |
| DELETE | `/auth/api/admin/invites/{id}` | 204 / 404 |

## Модель сессий (для понимания поведения)

Одна строка `sessions` на логин, ротация на месте: `refresh_hash` ← новый, `prev_refresh_hash` ← старый, `rotated_at` ← now;
в той же транзакции старый хеш пишется в `refresh_token_history(hash, family_id, session_id, rotated_at)`.
Повторное предъявление *предыдущего* токена различается по `rotated_at` (grace 30 с / reuse). Хеш, который есть только в
истории (старше предыдущего), — всегда reuse, отзыв семьи.
Фоновая служба раз в час удаляет истёкшие сессии и отозванные более суток назад вместе с их историей (FK `ON DELETE CASCADE`).
