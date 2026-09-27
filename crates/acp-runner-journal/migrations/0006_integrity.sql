-- acp-runner journal schema v6: integrity hardening.
--
-- 1. Targeted lookups of runnerd-owned progress events (environment phase, connection
--    reference, snapshots) instead of scanning an attempt's whole journal.
CREATE INDEX session_events_progress_idx
    ON session_events (attempt_id, (data->>'category'), id DESC)
    WHERE kind = 'Progress' AND source = 'runnerd';
CREATE INDEX session_events_terminal_idx
    ON session_events (attempt_id, id DESC)
    WHERE kind IN ('AttemptCompleted', 'AttemptFailed', 'AttemptTimedOut');

-- 2. An attempt (and an environment) may only point at an artifact it produced itself.
CREATE FUNCTION acp_check_attempt_artifact() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.artifact_id IS NOT NULL AND NEW.artifact_id IS DISTINCT FROM OLD.artifact_id THEN
        IF NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id = NEW.artifact_id AND a.attempt_id = NEW.id) THEN
            RAISE EXCEPTION 'artifact % does not belong to attempt %', NEW.artifact_id, NEW.id
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER attempts_artifact_owner BEFORE UPDATE OF artifact_id ON attempts
    FOR EACH ROW EXECUTE FUNCTION acp_check_attempt_artifact();

CREATE FUNCTION acp_check_environment_artifact() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.final_artifact_id IS NOT NULL AND NEW.final_artifact_id IS DISTINCT FROM OLD.final_artifact_id THEN
        IF NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id = NEW.final_artifact_id AND a.attempt_id = NEW.attempt_id) THEN
            RAISE EXCEPTION 'artifact % does not belong to environment %', NEW.final_artifact_id, NEW.id
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER environments_artifact_owner BEFORE UPDATE OF final_artifact_id ON environments
    FOR EACH ROW EXECUTE FUNCTION acp_check_environment_artifact();
