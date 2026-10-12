-- Closed registration: invites.app_id NULL = login-only invite (registration without a grant).
-- Same type and collation as apps.id (fk_invites_app stays valid). Guarded through information_schema so a
-- re-run after a crash between the DDL and the _migrations bookkeeping is a no-op.

SET @ddl = IF((SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'invites' AND column_name = 'app_id' AND is_nullable = 'NO') > 0, 'ALTER TABLE invites MODIFY app_id VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL', 'DO 0');
PREPARE mvv42_ddl FROM @ddl;
EXECUTE mvv42_ddl;
DEALLOCATE PREPARE mvv42_ddl;
