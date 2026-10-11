-- Every refresh hash that has been rotated away (spec §9.1 extended): presenting any of them later is reuse
-- and revokes the family, not only the immediately previous one. Written in the rotation transaction;
-- rows disappear with their session (ON DELETE CASCADE) when the hourly cleanup deletes expired/revoked sessions.
-- Idempotent, see 001_init.sql.

CREATE TABLE IF NOT EXISTS refresh_token_history (
    hash        CHAR(64)     NOT NULL,
    family_id   CHAR(36)     NOT NULL,
    session_id  BIGINT       NOT NULL,
    rotated_at  DATETIME(6)  NOT NULL,
    PRIMARY KEY (hash),
    KEY ix_refresh_token_history_family (family_id),
    KEY ix_refresh_token_history_session (session_id),
    CONSTRAINT fk_refresh_token_history_session FOREIGN KEY (session_id) REFERENCES sessions (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
