-- acp-runner journal schema v8: durable controller → runnerd directives.
--
-- Environment operations (snapshot, finish, cancel) used to live in one controller process'
-- memory: a restart or a second replica lost them. They are now rows, delivered in order on
-- runnerd's heartbeat replies, redelivered until runnerd acknowledges them with a
-- `directive_ack` progress event (runnerd de-duplicates by id).
CREATE TABLE environment_directives (
    id              uuid PRIMARY KEY,
    attempt_id      uuid NOT NULL REFERENCES attempts(id) ON DELETE CASCADE,
    seq             bigserial NOT NULL,
    directive       jsonb NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    delivered_at    timestamptz,
    delivery_count  integer NOT NULL DEFAULT 0,
    acked_at        timestamptz
);
CREATE INDEX environment_directives_pending_idx
    ON environment_directives (attempt_id, seq) WHERE acked_at IS NULL;

-- When a heartbeat was last written to the event journal (rate limit shared by replicas).
ALTER TABLE attempts ADD COLUMN last_heartbeat_journaled_at timestamptz;
