-- Closed registration: login_events.result gets 'denied_unregistered' (unknown user refused without/with a bad
-- invite code; such rows keep only the time, every other column is NULL). Guarded through information_schema.

SET @ddl = IF((SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'login_events' AND column_name = 'result' AND column_type NOT LIKE '%denied_unregistered%') > 0, 'ALTER TABLE login_events MODIFY result ENUM(''ok'',''denied_blocked'',''invalid'',''replayed'',''denied_unregistered'') NOT NULL', 'DO 0');
PREPARE mvv42_ddl FROM @ddl;
EXECUTE mvv42_ddl;
DEALLOCATE PREPARE mvv42_ddl;
