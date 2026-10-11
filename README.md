# mvv42-auth

Общий сервис аутентификации платформы `https://mvv42.ru`: Telegram Login Widget → сессия в HttpOnly-cookies →
короткий ES256 access JWT, который приложения (`cashpulse`, `bonds`, `credit_calc`, …) проверяют сами по JWKS.

- Спека: `mvv42-infra/docs/specs/2026-10-11-platform-design.md` (§4 и §9).
- API: [`docs/api.md`](docs/api.md). Перевод приложений: [`docs/migration.md`](docs/migration.md).
- SDK (copy-in файлы): [`sdk/dotnet/Mvv42Auth.cs`](sdk/dotnet/README.md), [`sdk/web/mvv42.ts`](sdk/web/mvv42.ts).

## Как устроено

| Что | Как |
|---|---|
| Публичный путь | nginx (`mvv42-infra/nginx/apps/auth.conf`): `location ^~ /auth/ { proxy_pass http://127.0.0.1:5010; }` плюс три exact-location с `limit_req` (`location = /auth/api/telegram`, `= /auth/api/refresh`, `= /auth/api/invites/redeem`) — префикс не режется, сервис делает `UsePathBase("/auth")` |
| Access | JWT ES256, 10 мин, `iss=https://mvv42.ru/auth`, `aud=mvv42`, claims `sub tg name adm apps`, `kid` = RFC 7638 thumbprint. Cookie `__Host-mvv42_at` (HttpOnly, Secure, SameSite=Strict, Path=/) |
| Refresh | 32 случайных байта, в БД только SHA-256. Cookie `__Secure-mvv42_rt` (Path=/auth/api, Strict). Ротация на каждый refresh; повтор предыдущего токена < 30 с — гонка (только новый access), позже (или любой более старый токен из `refresh_token_history`) — отзыв семьи. Скользящие 30 дней, абсолютно 90 дней |
| Ключи | PEM `es256-yyyyMMddHHmmss.pem` в `Auth__KeysPath` (volume). Первый генерируется при старте. Новый ключ сразу в JWKS, подписывает через 15 мин. Запись атомарная (`.tmp` → rename); нечитаемые, не P-256 и public-only файлы пропускаются с ошибкой в логе |
| CSRF | SameSite=Strict + для POST/PUT/PATCH/DELETE обязателен `Origin`/`Referer` из `Auth__AllowedOrigins` |
| Защита | rate limit на IP (`/telegram`, `/refresh`, `/invites/redeem`) поверх nginx `limit_req`; payload виджета принимается один раз (replay-кэш); `X-Forwarded-*` только от доверенного прокси |
| Доступ | таблица `apps(id, name, anonymous, access)`, `access ∈ public/invite/admin`; гранты по инвайтам; админ = `users.is_admin` ИЛИ `Auth__AdminTelegramIds` |
| Хранилище | MySQL (`mvv42_auth` в контейнере `cashpulse-mysql`), Dapper, SQL-миграции из `Data/Migrations` при старте |

Структура: один веб-проект `src/Mvv42.Auth` (`Telegram/`, `Keys/`, `Tokens/`, `Sessions/`, `Access/`, `Data/`, `Http/`),
тесты `tests/Mvv42.Auth.Tests` (xUnit, `WebApplicationFactory` + in-memory store; SDK компилируется в тесты и
проверяется против настоящего сервиса).

## Переменные окружения

| Переменная | Обязательна | По умолчанию / пример |
|---|---|---|
| `ConnectionStrings__Auth` | да (вне Development) | `Server=cashpulse-mysql;Port=3306;Database=mvv42_auth;User=mvv42_auth;Password=…;` (см. ниже) |
| `Telegram__BotToken` | да (вне Development) | токен `mv_cashpulse_bot` |
| `Telegram__BotUsername` | нет | `mv_cashpulse_bot` (справочно; виджет живёт в shell) |
| `Auth__AdminTelegramIds` | нет | `123456789,987654321` |
| `Auth__KeysPath` | нет | `/var/lib/mvv42-auth/keys` |
| `Auth__AllowedOrigins` | нет | `https://mvv42.ru` |
| `Auth__SecureCookies` | нет | `true`; в `appsettings.Development.json` — `false` (cookie `mvv42_at`/`mvv42_rt` без префиксов и без Secure для http://localhost) |
| `Auth__TrustedProxyCidrs` | нет | `172.16.0.0/12`; deploy пишет точный gateway сети: `172.18.0.1/32` (см. ниже) |
| `Auth__RateLimitPerMinute` | нет | `30` — лимит на IP для `/telegram`, `/refresh`, `/invites/redeem` (за nginx `limit_req`) |

Вне Development/Testing сервис не стартует без `Telegram__BotToken` и `ConnectionStrings__Auth`. В любом окружении
не стартует с кривыми `Auth__AdminTelegramIds` (не положительные целые) или `Auth__TrustedProxyCidrs`.

**Строка подключения.** Обычная строка MySqlConnector (ключи как в примере). Стор сам фиксирует нужную семантику
поверх того, что задано: `GuidFormat=None` (иначе MySqlConnector читает любой `CHAR(36)`, в т.ч. `family_id`, как `Guid`
и Dapper падает при маппинге в `string`). От `UseAffectedRows` результат не зависит (`SetUserAdminAsync` проверяет
существование отдельно, ротация всегда меняет хеш), так что `UseAffectedRows=true` тоже допустим. Все `DATETIME` — UTC,
сервер БД ничего не конвертирует (`DATETIME`, не `TIMESTAMP`), поэтому `time_zone` сессии роли не играет.
Пользователю БД нужны права на DDL (миграции при старте): `GRANT ALL PRIVILEGES ON mvv42_auth.*`.

**Доверенный прокси.** nginx на хосте ходит в контейнер через опубликованный порт (`127.0.0.1:5010` → docker-proxy),
поэтому сервис видит в качестве peer gateway docker-сети, через которую проброшен порт. Только loopback и
`Auth__TrustedProxyCidrs` могут задавать `X-Forwarded-For/Proto` (иначе любой контейнер в `cashpulse-network` подделал бы
IP клиента и обошёл rate limit). Проверить gateway:
`docker network inspect cashpulse-network -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}'`. Deploy делает это сам и пишет
`Auth__TrustedProxyCidrs=<gateway>/32`; дефолт `172.16.0.0/12` — пул адресов docker по умолчанию (подходит, но шире).
Если в логах IP клиентов — gateway, а не реальные адреса, значит peer не совпал с этим списком.

## Локально

```bash
dotnet test                                   # 130+ тестов, MySQL не нужен
cd sdk/web && npm ci && npm test              # web SDK (vitest)
dotnet run --project src/Mvv42.Auth           # http://localhost:5010/auth/health
```

Без `ConnectionStrings__Auth` в Development используется in-memory store (данные теряются при рестарте),
ключи пишутся в `src/Mvv42.Auth/.keys/` (в .gitignore). Тесты стора против MySQL:
`MVV42_AUTH_TEST_MYSQL="Server=…;Database=mvv42_auth_test;…" dotnet test --filter Category=MySql` (в CI — job `mysql-store`).

## Деплой

`.github/workflows/deploy.yml` на push в `main` (job `deploy` выключен, пока repo variable `AUTH_DEPLOY_ENABLED` ≠ `true` — включить после bootstrap БД и секретов: `gh variable set AUTH_DEPLOY_ENABLED -b true -R max31000/mvv42-auth`): тесты → образ `ghcr.io/max31000/mvv42-auth:{latest,sha-…}` →
ssh на VDS: секреты пишутся в `/etc/mvv42/env/mvv42-auth.env` (каталог 700, файл 600 — конвенция `mvv42-infra`
`docs/conventions.md`), `Auth__TrustedProxyCidrs` = gateway `cashpulse-network`/32, контейнер `mvv42-auth` в сети
`cashpulse-network`, `127.0.0.1:5010:8080`, volume `/var/lib/mvv42-auth/keys` (владелец uid 1654), health-check до 30 с,
уведомление в Telegram при ошибке.

**GHCR.** Job `image` пушит с `permissions: packages: write`; job `deploy` (`packages: read`) передаёт на сервер
`GITHUB_TOKEN` и делает `docker login ghcr.io` во временный `DOCKER_CONFIG` перед `docker pull`, затем `docker logout`
(тот же приём, что в `mvv42-infra` `deploy-dotnet-api.yml`). Поэтому пакет `ghcr.io/max31000/mvv42-auth` может
оставаться приватным (пакет, созданный workflow этого репо, даёт ему доступ по умолчанию); можно и сделать его
публичным, как `bonds-api`. Токен действует только пока идёт job.

**Откат.** Перед заменой запоминается образ текущего контейнера (`docker inspect -f '{{.Config.Image}}' mvv42-auth`).
Если новый контейнер не стал healthy за 30 с, он удаляется, а старый образ запускается с теми же аргументами
(тот же env-файл, volume, порт); job всё равно падает. Первый деплой (старого контейнера нет) просто падает.
Ручной откат на любую версию: перезапустить workflow на нужном коммите или
`docker rm -f mvv42-auth && docker run … ghcr.io/max31000/mvv42-auth:sha-<commit>` с аргументами из `deploy.yml`.
Миграции только добавляют таблицы (`IF NOT EXISTS`), поэтому старый образ работает с новой схемой.

Секреты репозитория: `VDS_HOST`, `VDS_USER`, `VDS_SSH_KEY`, `AUTH_DB_CONNECTION_STRING`, `AUTH_TELEGRAM_BOT_TOKEN`,
`AUTH_ADMIN_TELEGRAM_IDS`, `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` (уведомления).

Однократно руками (не автоматизировано):

```bash
docker exec -it cashpulse-mysql mysql -uroot -p
```
```sql
CREATE DATABASE IF NOT EXISTS mvv42_auth CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'mvv42_auth'@'%' IDENTIFIED BY '<generated>';
GRANT ALL PRIVILEGES ON mvv42_auth.* TO 'mvv42_auth'@'%';
FLUSH PRIVILEGES;
```
Идемпотентно (повторный запуск ничего не ломает; пароль существующего пользователя `CREATE USER IF NOT EXISTS` не меняет).
Тот же шаблон, что в `mvv42-infra/docs/server-layout.md` («New database in the shared MySQL») с `myapp` = `mvv42_auth`.
Секрет `AUTH_DB_CONNECTION_STRING`: `Server=cashpulse-mysql;Port=3306;Database=mvv42_auth;User=mvv42_auth;Password=<generated>;`.

Плюс nginx `location ^~ /auth/` и три rate-limited exact-location (репо `mvv42-infra`, `nginx/apps/auth.conf`) и, если ещё не сделано, `/setdomain mvv42.ru` у бота в BotFather.

### Ротация ключа подписи

```bash
cd /var/lib/mvv42-auth/keys
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out es256-$(date -u +%Y%m%d%H%M%S).pem
chown 1654:1654 es256-*.pem && chmod 600 es256-*.pem
```

Сервис подхватит файл в течение минуты, сразу опубликует его в JWKS и начнёт им подписывать через 15 мин.
Старый файл удалять не раньше чем через 10 мин + 30 с после начала подписи новым (иначе ещё живые access-токены станут невалидны).
