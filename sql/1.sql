-- Reason: Live server metrics — host snapshots + per-container Docker stats.
-- Arrives with the metrics feature slice (ADMIN_SEPARATION_PLAN Phase 4, Step C4);
-- schema is identical to the monolith's sql/3.sql so the storage layer ports 1:1.

-- One row per scrape (default cadence: 30 seconds).
-- All ts values are Unix epoch seconds (INTEGER for fast range queries).
CREATE TABLE IF NOT EXISTS metric_sample
(
    ts            INTEGER NOT NULL PRIMARY KEY,

    -- CPU (percentages 0-100 averaged across all cores)
    cpu_user      REAL    NOT NULL DEFAULT 0,
    cpu_system    REAL    NOT NULL DEFAULT 0,
    cpu_iowait    REAL    NOT NULL DEFAULT 0,
    cpu_idle      REAL    NOT NULL DEFAULT 0,

    -- Load averages
    load_1        REAL    NOT NULL DEFAULT 0,
    load_5        REAL    NOT NULL DEFAULT 0,
    load_15       REAL    NOT NULL DEFAULT 0,

    -- Memory (bytes)
    mem_total     INTEGER NOT NULL DEFAULT 0,
    mem_used      INTEGER NOT NULL DEFAULT 0,
    mem_cached    INTEGER NOT NULL DEFAULT 0,
    swap_total    INTEGER NOT NULL DEFAULT 0,
    swap_used     INTEGER NOT NULL DEFAULT 0,

    -- Network (cumulative bytes since boot; deltas computed on read)
    net_rx_bytes  INTEGER NOT NULL DEFAULT 0,
    net_tx_bytes  INTEGER NOT NULL DEFAULT 0,

    -- Disk I/O & Storage Metrics (cumulative bytes since boot; deltas computed on read)
    disk_read_bytes  INTEGER NOT NULL DEFAULT 0,
    disk_write_bytes INTEGER NOT NULL DEFAULT 0,
    disk_read_ops    INTEGER NOT NULL DEFAULT 0,
    disk_write_ops   INTEGER NOT NULL DEFAULT 0,

    -- Root filesystem disk usage (bytes)
    disk_total    INTEGER NOT NULL DEFAULT 0,
    disk_used     INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;

-- One row per (timestamp, container).
CREATE TABLE IF NOT EXISTS docker_stat
(
    ts             INTEGER NOT NULL,
    container_name TEXT    NOT NULL,
    cpu_pct        REAL    NOT NULL DEFAULT 0,
    mem_used       INTEGER NOT NULL DEFAULT 0,
    mem_limit      INTEGER NOT NULL DEFAULT 0,
    net_rx_bytes   INTEGER NOT NULL DEFAULT 0,
    net_tx_bytes   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ts, container_name)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS docker_stat_name_ts ON docker_stat (container_name, ts);
