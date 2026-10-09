-- Team chat, operator-facing session UI state and webhook configuration.

CREATE TABLE IF NOT EXISTS chat_messages (
    id BIGSERIAL PRIMARY KEY,
    operator TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS chat_messages_created_idx ON chat_messages (created_at DESC);

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS color TEXT;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS operator_status TEXT;
