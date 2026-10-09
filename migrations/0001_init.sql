-- Shikra C2 initial schema.

CREATE TABLE IF NOT EXISTS operators (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL DEFAULT 'operator',
    password_hash TEXT NOT NULL,
    totp_secret TEXT,
    disabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS engagements (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    scope JSONB NOT NULL DEFAULT '[]'::jsonb,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS listener_profiles (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    protocol TEXT NOT NULL,
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS listeners (
    id UUID PRIMARY KEY,
    profile_id UUID REFERENCES listener_profiles (id) ON DELETE SET NULL,
    name TEXT NOT NULL UNIQUE,
    protocol TEXT NOT NULL,
    bind_addr TEXT NOT NULL,
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    running BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS implants (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    platform TEXT NOT NULL,
    architecture TEXT NOT NULL,
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    sha256 TEXT,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY,
    engagement_id UUID NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    implant_id UUID REFERENCES implants (id) ON DELETE SET NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    platform TEXT NOT NULL,
    architecture TEXT NOT NULL,
    hostname TEXT NOT NULL,
    username TEXT NOT NULL DEFAULT '',
    process_name TEXT NOT NULL DEFAULT '',
    remote_addr TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sessions_engagement_idx ON sessions (engagement_id);
CREATE INDEX IF NOT EXISTS sessions_status_idx ON sessions (status);

CREATE TABLE IF NOT EXISTS tasks (
    id UUID PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    operator_id UUID REFERENCES operators (id) ON DELETE SET NULL,
    command TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    state TEXT NOT NULL DEFAULT 'pending',
    exit_code INTEGER,
    output TEXT,
    ai_initiated BOOLEAN NOT NULL DEFAULT FALSE,
    approved_by UUID REFERENCES operators (id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    dispatched_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS tasks_session_idx ON tasks (session_id);
CREATE INDEX IF NOT EXISTS tasks_state_idx ON tasks (state);

CREATE TABLE IF NOT EXISTS events (
    id UUID PRIMARY KEY,
    kind TEXT NOT NULL,
    subject UUID,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS events_occurred_idx ON events (occurred_at DESC);

CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    prev_hash BYTEA,
    hash BYTEA NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_log_recorded_idx ON audit_log (recorded_at DESC);

CREATE TABLE IF NOT EXISTS ai_conversations (
    id UUID PRIMARY KEY,
    operator_id UUID REFERENCES operators (id) ON DELETE SET NULL,
    title TEXT,
    target_session_id UUID REFERENCES sessions (id) ON DELETE SET NULL,
    active_turn_id UUID,
    turn_state TEXT NOT NULL DEFAULT 'idle',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_messages (
    id UUID PRIMARY KEY,
    conversation_id UUID NOT NULL REFERENCES ai_conversations (id) ON DELETE CASCADE,
    turn_id UUID,
    item_id UUID,
    kind TEXT NOT NULL,
    visibility TEXT NOT NULL DEFAULT 'context',
    include_in_context BOOLEAN NOT NULL DEFAULT TRUE,
    state TEXT NOT NULL DEFAULT 'completed',
    role TEXT NOT NULL,
    content TEXT NOT NULL DEFAULT '',
    tool_name TEXT,
    tool_arguments JSONB,
    tool_result JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ai_messages_conversation_idx ON ai_messages (conversation_id, created_at);
