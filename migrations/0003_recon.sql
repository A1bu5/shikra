-- M8: reconnaissance host inventory.

CREATE TABLE IF NOT EXISTS hosts (
    id UUID PRIMARY KEY,
    engagement_id UUID REFERENCES engagements (id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    hostname TEXT NOT NULL DEFAULT '',
    os TEXT NOT NULL DEFAULT '',
    ports JSONB NOT NULL DEFAULT '[]'::jsonb,
    source TEXT NOT NULL DEFAULT 'nmap',
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (engagement_id, ip)
);

CREATE INDEX IF NOT EXISTS hosts_engagement_idx ON hosts (engagement_id);
