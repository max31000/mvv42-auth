-- mvv42-auth initial schema. All DATETIME values are UTC.
-- MigrationRunner splits on semicolons and strips line comments, so keep both out of string literals.

CREATE TABLE users (
    id             BIGINT        NOT NULL AUTO_INCREMENT,
    telegram_id    BIGINT        NOT NULL,
    username       VARCHAR(64)   NULL,
    first_name     VARCHAR(255)  NOT NULL,
    last_name      VARCHAR(255)  NULL,
    photo_url      VARCHAR(1024) NULL,
    is_admin       TINYINT(1)    NOT NULL DEFAULT 0,
    created_at     DATETIME(6)   NOT NULL,
    last_login_at  DATETIME(6)   NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_telegram_id (telegram_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE apps (
    id         VARCHAR(64)                      NOT NULL,
    name       VARCHAR(255)                     NOT NULL,
    anonymous  TINYINT(1)                       NOT NULL DEFAULT 0,
    access     ENUM('public','invite','admin')  NOT NULL DEFAULT 'invite',
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE app_grants (
    user_id     BIGINT       NOT NULL,
    app_id      VARCHAR(64)  NOT NULL,
    created_at  DATETIME(6)  NOT NULL,
    PRIMARY KEY (user_id, app_id),
    KEY ix_app_grants_app (app_id),
    CONSTRAINT fk_app_grants_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_app_grants_app FOREIGN KEY (app_id) REFERENCES apps (id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE invites (
    id          BIGINT       NOT NULL AUTO_INCREMENT,
    code_hash   CHAR(64)     NOT NULL,
    app_id      VARCHAR(64)  NOT NULL,
    max_uses    INT          NOT NULL DEFAULT 1,
    uses        INT          NOT NULL DEFAULT 0,
    expires_at  DATETIME(6)  NULL,
    created_by  BIGINT       NULL,
    created_at  DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_invites_code_hash (code_hash),
    KEY ix_invites_app (app_id),
    CONSTRAINT fk_invites_app FOREIGN KEY (app_id) REFERENCES apps (id) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_invites_created_by FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE sessions (
    id                 BIGINT        NOT NULL AUTO_INCREMENT,
    user_id            BIGINT        NOT NULL,
    family_id          CHAR(36)      NOT NULL,
    refresh_hash       CHAR(64)      NOT NULL,
    prev_refresh_hash  CHAR(64)      NULL,
    rotated_at         DATETIME(6)   NULL,
    created_at         DATETIME(6)   NOT NULL,
    expires_at         DATETIME(6)   NOT NULL,
    last_used_at       DATETIME(6)   NOT NULL,
    revoked_at         DATETIME(6)   NULL,
    user_agent         VARCHAR(512)  NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_sessions_refresh_hash (refresh_hash),
    KEY ix_sessions_prev_refresh_hash (prev_refresh_hash),
    KEY ix_sessions_family (family_id),
    KEY ix_sessions_expires (expires_at),
    KEY ix_sessions_user (user_id),
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO apps (id, name, anonymous, access) VALUES
    ('cashpulse', 'CashPulse', 0, 'public'),
    ('credit_calc', 'Кредитный калькулятор', 1, 'public'),
    ('bonds', 'Облигации', 0, 'admin');
