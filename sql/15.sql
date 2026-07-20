-- Profile: an optional avatar stored beside the account it belongs to.
--
-- The bytes live in the database rather than on the data volume so they are
-- covered by the backup and the cascade that already exist for the row. There is
-- exactly one avatar per account and it is capped well under a megabyte, so the
-- usual "don't put blobs in SQLite" caution does not apply at this size.
--
-- `avatar_type` is written from server-side byte sniffing, never from the
-- upload's Content-Type: it is echoed back as the response's own Content-Type,
-- and a client that could choose it could choose `image/svg+xml` and serve
-- script from this origin.

ALTER TABLE account ADD COLUMN avatar BLOB;
ALTER TABLE account ADD COLUMN avatar_type TEXT;
