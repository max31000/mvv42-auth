-- Code-first login: login_events.result gets 'invite_check_failed' (POST /invites/check refused a code; such rows keep
-- only the time, every other column is NULL). The full ENUM is restated in order. Guarded through information_schema.

SET @ddl = IF((SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'login_events' AND column_name = 'result' AND column_type NOT LIKE '%invite_check_failed%') > 0, 'ALTER TABLE login_events MODIFY result ENUM(''ok'',''denied_blocked'',''invalid'',''replayed'',''denied_unregistered'',''invite_check_failed'') NOT NULL', 'DO 0');
PREPARE mvv42_ddl FROM @ddl;
EXECUTE mvv42_ddl;
DEALLOCATE PREPARE mvv42_ddl;
