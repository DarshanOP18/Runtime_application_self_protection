-- migrations/010_create_tenant_management.sql
-- ──────────────────────────────────────────────
-- Provisions tables for Tenant Provisioning, SDK Licensing, and ABAC Policies.

-- 1. Tenant Management
CREATE TABLE IF NOT EXISTS tenants (
    id                    TEXT PRIMARY KEY,
    name                  TEXT NOT NULL,
    slug                  TEXT NOT NULL UNIQUE,
    subscription_tier     TEXT NOT NULL CHECK(subscription_tier IN ('TRIAL','PROFESSIONAL','ENTERPRISE')),
    is_active             INTEGER DEFAULT 1,
    max_apps              INTEGER DEFAULT 3,
    max_devices           INTEGER DEFAULT 1000,
    created_at            TEXT DEFAULT (datetime('now')),
    contact_email         TEXT NOT NULL,
    data_retention_days   INTEGER DEFAULT 90
);

-- 2. Subscriptions
CREATE TABLE IF NOT EXISTS subscriptions (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id                 TEXT NOT NULL,
    plan_name                 TEXT NOT NULL,
    starts_at                 TEXT NOT NULL,
    expires_at                TEXT NOT NULL,
    is_active                 INTEGER DEFAULT 1,
    features_json             TEXT, -- Array of strings: ["realtime_ai", "export_siem"]
    max_threat_events_per_day INTEGER DEFAULT 10000,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- 3. Registered Apps
CREATE TABLE IF NOT EXISTS registered_apps (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id     TEXT NOT NULL,
    app_name      TEXT NOT NULL,
    bundle_id     TEXT NOT NULL UNIQUE,
    platform      TEXT NOT NULL CHECK(platform IN ('ANDROID','IOS','FLUTTER')),
    created_at    TEXT DEFAULT (datetime('now')),
    api_key_hash  TEXT NOT NULL UNIQUE,
    is_active     INTEGER DEFAULT 1,
    config_json   TEXT,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- 4. Licenses
CREATE TABLE IF NOT EXISTS licenses (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id         TEXT NOT NULL,
    app_id            INTEGER NOT NULL,
    license_key_hash  TEXT NOT NULL UNIQUE,
    bundle_id         TEXT NOT NULL,
    cert_hash         TEXT NOT NULL,
    issued_at         TEXT DEFAULT (datetime('now')),
    expires_at        TEXT NOT NULL,
    is_active         INTEGER DEFAULT 1,
    grace_until       TEXT,
    activation_count  INTEGER DEFAULT 0,
    max_activations   INTEGER DEFAULT 5000,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (app_id) REFERENCES registered_apps(id) ON DELETE CASCADE
);

-- 5. SDK Activations
CREATE TABLE IF NOT EXISTS sdk_activations (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id        INTEGER NOT NULL,
    device_id         TEXT NOT NULL,
    activated_at      TEXT DEFAULT (datetime('now')),
    activation_token  TEXT NOT NULL,
    ip_address        TEXT,
    sdk_version       TEXT,
    is_active         INTEGER DEFAULT 1,
    FOREIGN KEY (license_id) REFERENCES licenses(id) ON DELETE CASCADE
);

-- 6. ABAC Policies
CREATE TABLE IF NOT EXISTS abac_policies (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_name       TEXT NOT NULL UNIQUE,
    subject_attrs     TEXT, -- JSON
    resource_attrs    TEXT, -- JSON
    environment_attrs TEXT, -- JSON
    action_attrs      TEXT, -- JSON
    effect            TEXT NOT NULL CHECK(effect IN ('ALLOW','DENY')),
    priority          INTEGER DEFAULT 10,
    is_active         INTEGER DEFAULT 1
);

-- 7. SDK Versions
CREATE TABLE IF NOT EXISTS sdk_versions (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    version_string          TEXT NOT NULL UNIQUE,
    release_date            TEXT NOT NULL,
    min_compatible_version  TEXT NOT NULL,
    is_deprecated           INTEGER DEFAULT 0,
    changelog               TEXT,
    download_url            TEXT NOT NULL
);

-- 8. Webhook Configs
CREATE TABLE IF NOT EXISTS webhook_configs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   TEXT,
    url         TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    events_json TEXT,
    is_active   INTEGER DEFAULT 1,
    retry_count INTEGER DEFAULT 3,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- 9. Daily Stats (for master analytics caching)
CREATE TABLE IF NOT EXISTS daily_stats (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id      TEXT NOT NULL,
    date           TEXT NOT NULL,
    total_events   INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    devices_seen   INTEGER DEFAULT 0,
    ai_analyses    INTEGER DEFAULT 0,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    UNIQUE(tenant_id, date)
);

CREATE INDEX IF NOT EXISTS idx_registered_apps_tenant ON registered_apps(tenant_id);
CREATE INDEX IF NOT EXISTS idx_licenses_key_hash ON licenses(license_key_hash);
CREATE INDEX IF NOT EXISTS idx_sdk_activations_license ON sdk_activations(license_id);
CREATE INDEX IF NOT EXISTS idx_daily_stats_tenant_date ON daily_stats(tenant_id, date);
