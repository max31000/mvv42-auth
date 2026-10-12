-- Login journal for the admin UI. One row per /telegram attempt that got past body parsing.
-- user_id / telegram_id are NULL for invalid / replayed attempts (an unverified telegram id is never stored).
-- Rows older than 180 days are removed by the hourly cleanup. Idempotent (indexes are part of CREATE TABLE).

CREATE TABLE IF NOT EXISTS login_events (
    id           BIGINT                                              NOT NULL AUTO_INCREMENT,
    user_id      BIGINT                                              NULL,
    telegram_id  BIGINT                                              NULL,
    at           DATETIME(6)                                         NOT NULL,
    ip           VARCHAR(45)                                         NULL,
    user_agent   VARCHAR(512)                                        NULL,
    result       ENUM('ok','denied_blocked','invalid','replayed')    NOT NULL,
    PRIMARY KEY (id),
    KEY ix_login_events_at (at),
    KEY ix_login_events_user_at (user_id, at),
    CONSTRAINT fk_login_events_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
