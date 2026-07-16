CREATE TABLE IF NOT EXISTS file_scan (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    clamav_clean INTEGER,
    clamav_virus TEXT,
    vt_status TEXT,
    vt_positives INTEGER,
    vt_total INTEGER,
    vt_url TEXT,
    scanned_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
