-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Secrets table: stores encrypted secret metadata and content
CREATE TABLE secrets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    content_type    TEXT NOT NULL CHECK (content_type IN ('text', 'file')),
    encrypted_dek   BYTEA NOT NULL,
    dek_nonce       BYTEA NOT NULL,
    ciphertext      BYTEA,
    blob_path       TEXT,
    content_nonce   BYTEA NOT NULL,
    password_hash   TEXT,
    burn_on_read    BOOLEAN NOT NULL DEFAULT true,
    expires_at      TIMESTAMPTZ,
    viewed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    ip_hint         TEXT
);

-- Access log: records every attempt to view a secret
CREATE TABLE access_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id       UUID NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    accessed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    viewer_ip       TEXT,
    outcome         TEXT NOT NULL CHECK (outcome IN ('success', 'wrong_password', 'already_burned', 'expired'))
);

-- Index for the background worker: quickly find expired secrets
CREATE INDEX idx_secrets_expires_at ON secrets(expires_at)
    WHERE expires_at IS NOT NULL;