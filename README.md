# mvv42-auth

Общий сервис аутентификации платформы `https://mvv42.ru`: Telegram Login Widget → сессия в HttpOnly-cookies →
короткий ES256 access JWT, который приложения (`cashpulse`, `bonds`, `credit_calc`, …) проверяют сами по JWKS.

- Спека: `mvv42-infra/docs/specs/2026-10-11-platform-design.md` (§4 и §9).
- API: [`docs/api.md`](docs/api.md). Перевод приложений: [`docs/migration.md`](docs/migration.md).
- SDK (copy-in файлы): [`sdk/dotnet/Mvv42Auth.cs`](sdk/dotnet/README.md), [`sdk/web/mvv42.ts`](sdk/web/mvv42.ts).

## Как устроено

| Что | Как |
|---|---|
| Публичный путь | nginx `location /auth/ { proxy_pass http://127.0.0.1:5010; }` — префикс не режется, сервис делает `UsePathBase("/auth")` |
| Access | JWT ES256, 10 мин, `iss=https://mvv42.ru/auth`, `aud=mvv42`, claims `sub tg name adm apps`, `kid` = RFC 7638 thumbprint. Cookie `__Host-mvv42_at` (HttpOnly, Secure, SameSite=Strict, Path=/) |
| Refresh | 32 случайных байта, в БД только SHA-256. Cookie `__Secure-mvv42_rt` (Path=/auth/api, Strict). Ротация на каждый refresh; повтор предыдущего токена < 30 с — гонка (только новый access), позже — отзыв семьи. Скользящие 30 дней, абсолютно 90 дней |
| Ключи | PEM `es256-yyyyMMddHHmmss.pem` в `Auth__KeysPath` (volume). Первый генерируется при старте. Новый ключ сразу в JWKS, подписывает через 15 мин |
| CSRF | SameSite=Strict + для POST/PUT/PATCH/DELETE обязателен `Origin`/`Referer` из `Auth__AllowedOrigins` |
| Доступ | таблица `apps(id, name, anonymous, access)`, `access ∈ public/invite/admin`; гранты по инвайтам; админ = `users.is_admin` ИЛИ `Auth__AdminTelegramIds` |
| Хранилище | MySQL (`mvv42_auth` в контейнере `cashpulse-mysql`), Dapper, SQL-миграции из `Data/Migrations` при старте |

Структура: один веб-проект `src/Mvv42.Auth` (`Telegram/`, `Keys/`, `Tokens/`, `Sessions/`, `Access/`, `Data/`, `Http/`),
тесты `tests/Mvv42.Auth.Tests` (xUnit, `WebApplicationFactory` + in-memory store; SDK компилируется в тесты и
проверяется против настоящего сервиса).

## Переменные окружения

| Переменная | Обязательна | По умолчанию / пример |
|---|---|---|
| `ConnectionStrings__Auth` | да (вне Development) | `Server=cashpulse-mysql;Database=mvv42_auth;User ID=mvv42_auth;Password=…` |
| `Telegram__BotToken` | да (вне Development) | токен `mv_cashpulse_bot` |
| `Telegram__BotUsername` | нет | `mv_cashpulse_bot` (справочно; виджет живёт в shell) |
| `Auth__AdminTelegramIds` | нет | `123456789,987654321` |
| `Auth__KeysPath` | нет | `/var/lib/mvv42-auth/keys` |
| `Auth__AllowedOrigins` | нет | `https://mvv42.ru` |
| `Auth__SecureCookies` | нет | `true`; в `appsettings.Development.json` — `false` (cookie `mvv42_at`/`mvv42_rt` без префиксов и без Secure для http://localhost) |

Вне Development/Testing сервис не стартует без `Telegram__BotToken` и `ConnectionStrings__Auth`.

## Локально

```bash
dotnet test                                   # 100+ тестов, MySQL не нужен
cd sdk/web && npm ci && npm test              # web SDK (vitest)
dotnet run --project src/Mvv42.Auth           # http://localhost:5010/auth/health
```

Без `ConnectionStrings__Auth` в Development используется in-memory store (данные теряются при рестарте),
ключи пишутся в `src/Mvv42.Auth/.keys/` (в .gitignore). Тесты стора против MySQL:
`MVV42_AUTH_TEST_MYSQL="Server=…;Database=mvv42_auth_test;…" dotnet test --filter Category=MySql` (в CI — job `mysql-store`).

## Деплой

`.github/workflows/deploy.yml` на push в `main`: тесты → образ `ghcr.io/max31000/mvv42-auth:{latest,sha-…}` →
ssh на VDS: секреты пишутся в `/etc/mvv42-auth/auth.env` (600), контейнер `mvv42-auth` в сети `cashpulse-network`,
`127.0.0.1:5010:8080`, volume `/var/lib/mvv42-auth/keys` (владелец uid 1654), health-check до 30 с, уведомление в Telegram при ошибке.

Секреты репозитория: `VDS_HOST`, `VDS_USER`, `VDS_SSH_KEY`, `AUTH_DB_CONNECTION_STRING`, `AUTH_TELEGRAM_BOT_TOKEN`,
`AUTH_ADMIN_TELEGRAM_IDS`, `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` (уведомления).

Однократно руками (не автоматизировано):

```sql
-- в контейнере cashpulse-mysql: docker exec -it cashpulse-mysql mysql -uroot -p
CREATE DATABASE mvv42_auth CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'mvv42_auth'@'%' IDENTIFIED BY '<пароль>';
GRANT ALL PRIVILEGES ON mvv42_auth.* TO 'mvv42_auth'@'%';
```

Плюс nginx `location /auth/` (репо `mvv42-infra`, `nginx/apps/auth.conf`) и, если ещё не сделано, `/setdomain mvv42.ru` у бота в BotFather.

### Ротация ключа подписи

```bash
cd /var/lib/mvv42-auth/keys
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out es256-$(date -u +%Y%m%d%H%M%S).pem
chown 1654:1654 es256-*.pem && chmod 600 es256-*.pem
```

Сервис подхватит файл в течение минуты, сразу опубликует его в JWKS и начнёт им подписывать через 15 мин.
Старый файл удалять не раньше чем через 10 мин + 30 с после начала подписи новым (иначе ещё живые access-токены станут невалидны).
