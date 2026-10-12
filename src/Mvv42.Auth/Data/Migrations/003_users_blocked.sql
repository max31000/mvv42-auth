-- Admin round 2 (spec §10.8/§10.9): blocked users. One schema change per file; MySQL 8.0 has no
-- ADD COLUMN IF NOT EXISTS, so the ALTER is guarded through information_schema (re-runnable after a crash
-- between the DDL and the _migrations bookkeeping). MigrationRunner enables AllowUserVariables for @ddl.

SET @ddl = IF((SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'is_blocked') > 0, 'DO 0', 'ALTER TABLE users ADD COLUMN is_blocked TINYINT(1) NOT NULL DEFAULT 0 AFTER is_admin');
PREPARE mvv42_ddl FROM @ddl;
EXECUTE mvv42_ddl;
DEALLOCATE PREPARE mvv42_ddl;
