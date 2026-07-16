-- Proxy route table: subdomain → upstream mapping for nginx/caddy/cloudflared.
CREATE TABLE IF NOT EXISTS proxy_route (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subdomain TEXT NOT NULL UNIQUE,
    target_host TEXT NOT NULL,
    target_port INTEGER NOT NULL,
    target_scheme TEXT NOT NULL DEFAULT 'http',
    container TEXT,
    ssl_managed INTEGER NOT NULL DEFAULT 0,
    cloudflare_proxied INTEGER NOT NULL DEFAULT 0,
    http_auth_user TEXT,
    http_auth_pass_hash TEXT,
    rate_limit_rps INTEGER,
    access_rules_json TEXT,
    extra_config TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
