-- M7: team features — credentials, loot, canaries, reactions, RBAC tokens.

ALTER TABLE operators ADD COLUMN IF NOT EXISTS token_hash TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS operators_token_hash_idx ON operators (token_hash)
    WHERE token_hash IS NOT NULL;

CREATE TABLE IF NOT EXISTS credentials (
    id UUID PRIMARY KEY,
    engagement_id UUID REFERENCES engagements (id) ON DELETE CASCADE,
    session_id UUID REFERENCES sessions (id) ON DELETE SET NULL,
    host TEXT NOT NULL DEFAULT '',
    domain TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL,
    secret TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'password',
    source TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS credentials_engagement_idx ON credentials (engagement_id);

CREATE TABLE IF NOT EXISTS loot (
    id UUID PRIMARY KEY,
    engagement_id UUID REFERENCES engagements (id) ON DELETE CASCADE,
    session_id UUID REFERENCES sessions (id) ON DELETE SET NULL,
    kind TEXT NOT NULL DEFAULT 'file',
    name TEXT NOT NULL,
    size BIGINT NOT NULL DEFAULT 0,
    sha256 TEXT,
    data BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS loot_engagement_idx ON loot (engagement_id);

CREATE TABLE IF NOT EXISTS canaries (
    id UUID PRIMARY KEY,
    token TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL DEFAULT 'http',
    note TEXT NOT NULL DEFAULT '',
    triggered BOOLEAN NOT NULL DEFAULT FALSE,
    triggered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS reaction_rules (
    id UUID PRIMARY KEY,
    event_kind TEXT NOT NULL,
    action TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS reaction_rules_event_idx ON reaction_rules (event_kind);
