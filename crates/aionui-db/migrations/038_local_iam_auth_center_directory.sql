-- Migration 038: Local IAM users, organizations, and Auth Center directory sync.
--
-- Renumbered from private 013 during the v0.1.63 upstream replay (upstream
-- occupied 013-037). Runs after upstream 030_user_scope, which already
-- rebuilds `users` with a `status` column ('active'/'disabled'), so the
-- original `ADD COLUMN status` is intentionally omitted here and the IAM
-- layer reuses the upstream column.

ALTER TABLE users ADD COLUMN auth_sub TEXT;
ALTER TABLE users ADD COLUMN auth_provider TEXT;
ALTER TABLE users ADD COLUMN display_name TEXT;
ALTER TABLE users ADD COLUMN mobile TEXT;
ALTER TABLE users ADD COLUMN department_ids TEXT;
ALTER TABLE users ADD COLUMN auth_source TEXT;
ALTER TABLE users ADD COLUMN auth_app_code TEXT;
ALTER TABLE users ADD COLUMN source TEXT NOT NULL DEFAULT 'local' CHECK(source IN ('local', 'auth_center'));
ALTER TABLE users ADD COLUMN external_status TEXT;
ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN external_updated_at INTEGER;

UPDATE users
SET source = 'local',
    status = 'active',
    is_admin = CASE WHEN id = 'system_default_user' THEN 1 ELSE is_admin END
WHERE source IS NULL OR id = 'system_default_user';

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_auth_provider_sub
ON users(auth_provider, auth_sub)
WHERE auth_sub IS NOT NULL AND auth_provider IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_users_source_status ON users(source, status);
CREATE INDEX IF NOT EXISTS idx_users_is_admin ON users(is_admin);

CREATE TABLE IF NOT EXISTS organizations (
    id          TEXT PRIMARY KEY NOT NULL,
    parent_id   TEXT,
    name        TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT 'local' CHECK(source IN ('local', 'auth_center')),
    external_id TEXT,
    status      TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'disabled')),
    sort        INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    FOREIGN KEY (parent_id) REFERENCES organizations(id) ON DELETE SET NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_organizations_source_external
ON organizations(source, external_id)
WHERE external_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_organizations_parent ON organizations(parent_id);
CREATE INDEX IF NOT EXISTS idx_organizations_source_status ON organizations(source, status);

CREATE TABLE IF NOT EXISTS user_organizations (
    user_id         TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    source          TEXT NOT NULL DEFAULT 'local' CHECK(source IN ('local', 'auth_center')),
    is_primary      INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    PRIMARY KEY (user_id, organization_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_user_organizations_user ON user_organizations(user_id);
CREATE INDEX IF NOT EXISTS idx_user_organizations_org ON user_organizations(organization_id);
CREATE INDEX IF NOT EXISTS idx_user_organizations_source ON user_organizations(source);

CREATE TABLE IF NOT EXISTS auth_center_directory_sync_states (
    app_code             TEXT PRIMARY KEY NOT NULL,
    last_synced_at       INTEGER,
    last_full_synced_at  INTEGER,
    last_status          TEXT NOT NULL DEFAULT 'never',
    last_message         TEXT,
    user_count           INTEGER NOT NULL DEFAULT 0,
    department_count     INTEGER NOT NULL DEFAULT 0,
    user_created         INTEGER NOT NULL DEFAULT 0,
    user_updated         INTEGER NOT NULL DEFAULT 0,
    user_disabled        INTEGER NOT NULL DEFAULT 0,
    updated_at           INTEGER NOT NULL
);
