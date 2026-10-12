-- When the user was blocked (NULL when not blocked). Guarded ALTER, see 003_users_blocked.sql.

SET @ddl = IF((SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'blocked_at') > 0, 'DO 0', 'ALTER TABLE users ADD COLUMN blocked_at DATETIME(6) NULL AFTER is_blocked');
PREPARE mvv42_ddl FROM @ddl;
EXECUTE mvv42_ddl;
DEALLOCATE PREPARE mvv42_ddl;
