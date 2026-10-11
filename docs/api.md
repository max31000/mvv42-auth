# mvv42-auth API

Все пути публичные, через nginx на `https://mvv42.ru`. Ответы — JSON (camelCase). Ошибки: `{"error": "<code>"}`.

**CSRF:** любой POST/PUT/PATCH/DELETE под `/auth/api/` без `Origin` (или, если его нет, `Referer`) из
`Auth__AllowedOrigins` → `403 {"error":"origin_not_allowed"}`. Браузерный same-origin `fetch` шлёт `Origin` сам.

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
| 503 `telegram_not_configured` | нет `Telegram__BotToken` (только dev) |

### `POST /auth/api/refresh`
По refresh-cookie. `204` + новый access + новый refresh (ротация). Если предъявлен **предыдущий** refresh-токен,
ротированный < 30 с назад, и сессия не отозвана — `204` только с новым access (гонка вкладок). Предыдущий токен позже 30 с —
отзыв всей семьи, `401`. Неизвестный/истёкший/отозванный — `401`, cookies удаляются.
Сессия: скользящие 30 дней, но не дольше 90 дней от логина.

### `POST /auth/api/logout`
Отзывает сессию, удаляет обе cookie. Всегда `204`.

### `GET /auth/api/me`
Работает анонимно, `Cache-Control: no-store`. Если access-cookie нет или он истёк, а refresh валиден — делает то же,
что `/refresh` (ставит cookies) и отвечает с пользователем. Клиенту на старте достаточно вызвать `/me`.

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
Нужен access-cookie. `{ "code": "…" }` → `200` с телом как у `/me` и **сразу переизданным** access-cookie;
`400 invalid_invite` — неизвестный/истёкший/исчерпанный код. Если грант уже есть — `200`, использование не списывается.

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

Одна строка `sessions` на логин, ротация на месте: `refresh_hash` ← новый, `prev_refresh_hash` ← старый, `rotated_at` ← now.
Повторное предъявление *предыдущего* токена различается по `rotated_at` (grace 30 с / reuse). Токены старше предыдущего
просто неизвестны → 401 (семья в этом случае уже либо ротирована дважды легитимно, либо отозвана).
Фоновая служба раз в час удаляет истёкшие сессии и отозванные более суток назад.
