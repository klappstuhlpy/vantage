//! Shared introspection shapes for the schema explorer (DB Studio P1).
//!
//! Both backends answer the same two questions with the same shapes:
//! - "what's in this database" — [`SchemaOverview`], one call per source
//! - "what is this table, exactly" — [`TableDetail`], one call per table
//!
//! The shapes are deliberately backend-neutral: the frontend tree renders them
//! without knowing which engine produced them, and the Phase 2 filter validator
//! will validate request identifiers against *this* output — introspection is
//! the allowlist identifiers are checked against, which is why nothing in here
//! ever echoes a request string that didn't resolve.

use serde::Serialize;

use super::TableInfo;

/// Everything in one source worth showing in the schema tree, in one call.
#[derive(Debug, Serialize)]
pub struct SchemaOverview {
    /// Real tables, with the same per-table facts the old `/tables` list had.
    pub tables: Vec<TableInfo>,
    /// Views carry no row estimate or size — a view has no rows of its own, and
    /// counting one means executing it. Name and schema are the honest facts.
    pub views: Vec<ViewInfo>,
}

#[derive(Debug, Serialize)]
pub struct ViewInfo {
    pub schema: String,
    pub name: String,
}

/// One table (or view), fully described: the answer to "what was that column
/// called and what points at it" without writing a query.
#[derive(Debug, Serialize)]
pub struct TableDetail {
    pub schema: String,
    pub name: String,
    /// `"table"` or `"view"` — the UI shows views read-only.
    pub kind: &'static str,
    pub columns: Vec<Column>,
    pub foreign_keys: Vec<Fk>,
    pub indexes: Vec<Index>,
}

#[derive(Debug, Serialize)]
pub struct Column {
    pub name: String,
    /// The declared type, as the engine reports it. SQLite allows a column with
    /// no declared type at all; that is an empty string, not an invention.
    pub data_type: String,
    /// Declared nullability. (SQLite's implicit rowid-PK behaviour is not
    /// second-guessed here — declared is what we report.)
    pub nullable: bool,
    /// The default expression, verbatim, when one is declared.
    pub default: Option<String>,
    /// 1-based position in the primary key; `None` when not part of it. The
    /// ordinal (not just a flag) is what makes composite PKs renderable — and
    /// is what Phase 5's PK-addressed statement generation will key off.
    pub pk_ordinal: Option<u32>,
}

/// One foreign key, possibly composite: `columns` on this table reference
/// `ref_columns` on `ref_schema.ref_table`, pairwise in order.
#[derive(Debug, Serialize)]
pub struct Fk {
    pub columns: Vec<String>,
    pub ref_schema: String,
    pub ref_table: String,
    /// Empty when the reference is to the target's primary key implicitly
    /// (SQLite allows `REFERENCES other` with no column list).
    pub ref_columns: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Index {
    pub name: String,
    /// Column names, or the engine's rendering of an expression for
    /// expression-index members.
    pub columns: Vec<String>,
    pub unique: bool,
}
