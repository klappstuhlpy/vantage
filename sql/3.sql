-- Container snapshots (schema byte-identical to the monolith's sql/7.sql, so
-- the snapshots slice ports over unchanged).
--
-- One row per `docker commit`ed image: the source container it was captured
-- from, the operator's description, and the unique `klappstuhl-snapshot:<tag>`
-- reference the image was tagged with (the tag is what restore/delete address).
CREATE TABLE IF NOT EXISTS docker_snapshot (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    container_id   TEXT    NOT NULL,
    container_name TEXT    NOT NULL,
    original_image TEXT    NOT NULL,
    snapshot_tag   TEXT    NOT NULL UNIQUE,
    description    TEXT,
    created_at     TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);
