-- M12: signed extension registry.

CREATE TABLE IF NOT EXISTS extensions (
    id UUID PRIMARY KEY,
    engagement_id UUID REFERENCES engagements (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    kind TEXT NOT NULL,
    platform TEXT NOT NULL,
    architecture TEXT NOT NULL DEFAULT 'any',
    description TEXT NOT NULL DEFAULT '',
    sha256 TEXT NOT NULL,
    size BIGINT NOT NULL,
    signer TEXT NOT NULL,
    manifest JSONB NOT NULL,
    payload BYTEA NOT NULL,
    installed_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (engagement_id, name, version)
);

CREATE INDEX IF NOT EXISTS extensions_engagement_idx ON extensions (engagement_id);
CREATE INDEX IF NOT EXISTS extensions_name_idx ON extensions (engagement_id, name);
