-- Client IP at login (normalised: IPv4-mapped IPv6 is stored as IPv4; 45 = longest IPv6 text form).
-- Guarded ALTER, see 003_users_blocked.sql.

SET @ddl = IF((SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'sessions' AND column_name = 'ip') > 0, 'DO 0', 'ALTER TABLE sessions ADD COLUMN ip VARCHAR(45) NULL AFTER user_agent');
PREPARE mvv42_ddl FROM @ddl;
EXECUTE mvv42_ddl;
DEALLOCATE PREPARE mvv42_ddl;
