//! Staged edits: validation and statement generation (DB Studio P5, D15).
//!
//! This is the only part of `dbadmin` that composes a statement which *writes*,
//! so it is the strictest. The rules, in the order they matter:
//!
//! 1. **Every identifier comes from introspection.** A change names columns; the
//!    planner looks each one up in the [`TableDetail`] and uses *that* spelling,
//!    quoted by [`quote_ident`]. A column the table does not have is a refusal
//!    naming it, never a dropped assignment — the same rule filters follow (D5),
//!    and it matters more here, because a silently dropped `SET` would report
//!    success for an edit that never happened.
//! 2. **Every value is a bound parameter.** Values are `Option<String>` and
//!    travel in the parameter list. There is no path where a cell value reaches
//!    the SQL string. The rendered `preview` inlines them for *reading only* and
//!    is never executed.
//! 3. **Every statement addresses exactly one row by full primary key.** No
//!    statement this module emits can touch two rows; the caller then verifies
//!    that each one actually affected exactly 1, and rolls the batch back if not
//!    (a stale PK must not pass as "0 rows updated, silently").
//!
//! What it deliberately refuses, so the refusals are documented rather than
//! discovered: tables without a primary key, views, changing a primary key
//! value, an empty `SET`, and batches over [`MAX_CHANGES`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::quote_ident;
use super::schema::TableDetail;

/// Upper bound on one batch. The grid stages a handful of edits; a five-figure
/// batch is a script, and a script should be a script — visible in the audit
/// log as SQL someone wrote, not as an opaque bulk apply.
pub const MAX_CHANGES: usize = 500;

/// Which placeholder and casting dialect to emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// `?N` placeholders; type affinity converts a text parameter, so no casts.
    Sqlite,
    /// `$N` placeholders; strict typing, so parameters cast to the column's
    /// introspected type — the same `CAST($n AS <type>)` the filters use.
    Postgres,
}

/// One staged change, as the grid sends it.
#[derive(Debug, Clone, Deserialize)]
pub struct ChangeSpec {
    /// `"update"`, `"delete"` or `"insert"`.
    pub kind: String,
    /// Primary-key columns addressing the row (update/delete).
    #[serde(default)]
    pub pk: BTreeMap<String, Option<String>>,
    /// Columns being assigned (update).
    #[serde(default)]
    pub set: BTreeMap<String, Option<String>>,
    /// Columns being supplied (insert).
    #[serde(default)]
    pub values: BTreeMap<String, Option<String>>,
}

/// One generated statement, ready to execute.
#[derive(Debug, Serialize)]
pub struct PlannedStatement {
    pub kind: &'static str,
    /// Parameterised SQL. This is what runs.
    pub sql: String,
    /// Bound values, positionally matching the placeholders.
    #[serde(skip)]
    pub params: Vec<Option<String>>,
    /// The same statement with values inlined, for the review drawer. **Display
    /// only** — it is never sent to a database, which is why inlining a value
    /// here is not an injection surface. It exists so the operator reads what
    /// they are about to run instead of a row of question marks.
    pub preview: String,
}

/// A validated batch.
#[derive(Debug, Serialize)]
pub struct EditPlan {
    pub statements: Vec<PlannedStatement>,
}

impl EditPlan {
    /// Counts per kind, for the audit detail.
    pub fn counts(&self) -> (usize, usize, usize) {
        let mut u = 0;
        let mut d = 0;
        let mut i = 0;
        for s in &self.statements {
            match s.kind {
                "update" => u += 1,
                "delete" => d += 1,
                _ => i += 1,
            }
        }
        (u, d, i)
    }
}

/// What one statement did. `affected` is recorded rather than assumed: it is
/// the number the batch is verified against, so it belongs in the report and in
/// the audit entry.
#[derive(Debug, Serialize)]
pub struct AppliedStatement {
    pub kind: &'static str,
    pub preview: String,
    pub affected: u64,
}

/// The outcome of an applied batch.
#[derive(Debug, Serialize)]
pub struct ApplyReport {
    pub applied: usize,
    pub statements: Vec<AppliedStatement>,
    pub elapsed_ms: u64,
}

/// The refusal every backend raises when a statement did not affect exactly one
/// row. Shared so both engines phrase it identically — the operator should not
/// have to learn two vocabularies for the same failure, and the phrasing has to
/// say that *nothing* was kept, not just that one statement misbehaved.
pub fn row_count_mismatch(at: usize, affected: u64) -> anyhow::Error {
    anyhow::anyhow!(
        "statement {at} affected {affected} rows, expected exactly 1 — the whole batch was rolled back and nothing was changed. \
         The row may have been deleted or its key changed since the grid loaded it; reload the table and stage the edit again."
    )
}

/// Emits placeholders and collects bound values in step.
struct Params {
    dialect: Dialect,
    values: Vec<Option<String>>,
}

impl Params {
    fn new(dialect: Dialect) -> Self {
        Self {
            dialect,
            values: Vec::new(),
        }
    }

    /// Binds `value` and returns its placeholder, cast to `data_type` on
    /// Postgres. The cast target is introspection output (`format_type`), never
    /// a request string.
    fn bind(&mut self, value: Option<String>, data_type: &str) -> String {
        self.values.push(value);
        let n = self.values.len();
        match self.dialect {
            Dialect::Sqlite => format!("?{n}"),
            Dialect::Postgres => format!("CAST(${n} AS {data_type})"),
        }
    }
}

/// Renders a value as a SQL literal **for the preview string only**.
fn literal(value: &Option<String>) -> String {
    match value {
        None => "NULL".into(),
        Some(v) => format!("'{}'", v.replace('\'', "''")),
    }
}

/// Substitutes the bound values into the placeholders for display. Positional
/// and naive on purpose: it walks the placeholders in order, which is exactly
/// how they were emitted.
fn render_preview(sql: &str, params: &[Option<String>], dialect: Dialect) -> String {
    let mut out = sql.to_string();
    // Descending index order so `?1` cannot match inside `?10`.
    for (i, v) in params.iter().enumerate().rev() {
        let n = i + 1;
        match dialect {
            Dialect::Sqlite => out = out.replace(&format!("?{n}"), &literal(v)),
            Dialect::Postgres => out = out.replace(&format!("${n}"), &literal(v)),
        }
    }
    out
}

/// The qualified table name, quoted per part (D6) so a dot in a name cannot
/// become a separator.
fn qualified(dialect: Dialect, schema: &str, table: &str) -> String {
    match dialect {
        // SQLite sources are single-schema; `main.` in front of every statement
        // would be noise in the preview without adding any addressing.
        Dialect::Sqlite => quote_ident(table),
        Dialect::Postgres => format!("{}.{}", quote_ident(schema), quote_ident(table)),
    }
}

/// Validates a batch against the introspected table and generates its
/// statements. Every error names what was refused — these become 400s.
pub fn plan(detail: &TableDetail, dialect: Dialect, changes: Vec<ChangeSpec>) -> anyhow::Result<EditPlan> {
    if changes.is_empty() {
        anyhow::bail!("no changes to apply");
    }
    if changes.len() > MAX_CHANGES {
        anyhow::bail!(
            "too many staged changes: {} (limit {MAX_CHANGES}) — apply in smaller batches or write it as SQL",
            changes.len()
        );
    }
    if detail.kind != "table" {
        anyhow::bail!(
            "{} is a {}, not a table — it cannot be edited here",
            detail.name,
            detail.kind
        );
    }

    // The primary key is the whole addressing scheme: without one there is no
    // way to write a statement that provably touches one row.
    let mut pk_cols: Vec<(u32, &str)> = detail
        .columns
        .iter()
        .filter_map(|c| c.pk_ordinal.map(|o| (o, c.name.as_str())))
        .collect();
    pk_cols.sort_by_key(|(o, _)| *o);
    let pk_names: Vec<&str> = pk_cols.into_iter().map(|(_, n)| n).collect();
    if pk_names.is_empty() {
        anyhow::bail!(
            "{} has no primary key, so a row cannot be addressed unambiguously — edit it with SQL in danger mode",
            detail.name
        );
    }

    let column = |name: &str| detail.columns.iter().find(|c| c.name == name);
    let table_name = qualified(dialect, &detail.schema, &detail.name);

    let mut statements = Vec::with_capacity(changes.len());
    for (i, change) in changes.into_iter().enumerate() {
        let at = i + 1;
        let stmt = match change.kind.as_str() {
            "update" => {
                if change.set.is_empty() {
                    anyhow::bail!("change {at}: an update with nothing to set");
                }
                let mut p = Params::new(dialect);

                let mut assignments = Vec::with_capacity(change.set.len());
                for (name, value) in &change.set {
                    let col = column(name).ok_or_else(|| anyhow::anyhow!("change {at}: unknown column: {name}"))?;
                    // Moving the address while using it is the stale-PK hazard
                    // this whole design exists to avoid.
                    if pk_names.contains(&col.name.as_str()) {
                        anyhow::bail!(
                            "change {at}: {} is part of the primary key and cannot be edited here — delete and re-insert the row",
                            col.name
                        );
                    }
                    assignments.push(format!(
                        "{} = {}",
                        quote_ident(&col.name),
                        p.bind(value.clone(), &col.data_type)
                    ));
                }

                let where_clause = pk_predicate(detail, &pk_names, &change.pk, &mut p, at)?;
                let sql = format!(
                    "UPDATE {table_name} SET {} WHERE {where_clause}",
                    assignments.join(", ")
                );
                finish("update", sql, p, dialect)
            }

            "delete" => {
                if !change.set.is_empty() || !change.values.is_empty() {
                    anyhow::bail!("change {at}: a delete carries no column values");
                }
                let mut p = Params::new(dialect);
                let where_clause = pk_predicate(detail, &pk_names, &change.pk, &mut p, at)?;
                let sql = format!("DELETE FROM {table_name} WHERE {where_clause}");
                finish("delete", sql, p, dialect)
            }

            "insert" => {
                if change.values.is_empty() {
                    anyhow::bail!("change {at}: an insert with no values");
                }
                if !change.pk.is_empty() {
                    anyhow::bail!("change {at}: an insert addresses no existing row — put every value in `values`");
                }
                let mut p = Params::new(dialect);
                let mut names = Vec::with_capacity(change.values.len());
                let mut placeholders = Vec::with_capacity(change.values.len());
                for (name, value) in &change.values {
                    let col = column(name).ok_or_else(|| anyhow::anyhow!("change {at}: unknown column: {name}"))?;
                    names.push(quote_ident(&col.name));
                    placeholders.push(p.bind(value.clone(), &col.data_type));
                }
                let sql = format!(
                    "INSERT INTO {table_name} ({}) VALUES ({})",
                    names.join(", "),
                    placeholders.join(", ")
                );
                finish("insert", sql, p, dialect)
            }

            other => anyhow::bail!("change {at}: unknown change kind: {other}"),
        };
        statements.push(stmt);
    }

    Ok(EditPlan { statements })
}

/// The `WHERE` that addresses exactly one row: every primary-key column, bound.
///
/// Requiring the *complete* key is the point. A partial key would still produce
/// a valid statement — one that could match many rows, which the affected-count
/// check would then reject after the fact. Refusing here means the batch never
/// reaches a database in that shape.
fn pk_predicate(
    detail: &TableDetail,
    pk_names: &[&str],
    supplied: &BTreeMap<String, Option<String>>,
    p: &mut Params,
    at: usize,
) -> anyhow::Result<String> {
    for name in supplied.keys() {
        if !pk_names.contains(&name.as_str()) {
            anyhow::bail!("change {at}: {name} is not part of the primary key");
        }
    }

    let mut parts = Vec::with_capacity(pk_names.len());
    for name in pk_names {
        let value = supplied
            .get(*name)
            .ok_or_else(|| anyhow::anyhow!("change {at}: missing primary key column: {name}"))?;
        // A NULL key addresses nothing (`= NULL` is never true), so it can only
        // be a bug in the caller — say so rather than emitting a no-op.
        let value = value
            .clone()
            .ok_or_else(|| anyhow::anyhow!("change {at}: primary key {name} cannot be null"))?;
        let col = detail
            .columns
            .iter()
            .find(|c| &c.name.as_str() == name)
            .expect("pk names come from detail");
        parts.push(format!(
            "{} = {}",
            quote_ident(&col.name),
            p.bind(Some(value), &col.data_type)
        ));
    }
    Ok(parts.join(" AND "))
}

fn finish(kind: &'static str, sql: String, p: Params, dialect: Dialect) -> PlannedStatement {
    let preview = render_preview(&sql, &p.values, dialect);
    PlannedStatement {
        kind,
        sql,
        params: p.values,
        preview,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dbadmin::schema::Column;

    fn col(name: &str, ty: &str, pk: Option<u32>) -> Column {
        Column {
            name: name.into(),
            data_type: ty.into(),
            nullable: true,
            default: None,
            pk_ordinal: pk,
        }
    }

    fn table() -> TableDetail {
        TableDetail {
            schema: "public".into(),
            name: "account".into(),
            kind: "table",
            columns: vec![
                col("id", "integer", Some(1)),
                col("name", "text", None),
                col("flags", "integer", None),
            ],
            foreign_keys: Vec::new(),
            indexes: Vec::new(),
        }
    }

    /// A table keyed on two columns — the case a single-column assumption breaks.
    fn composite() -> TableDetail {
        TableDetail {
            schema: "main".into(),
            name: "member".into(),
            kind: "table",
            columns: vec![
                col("guild_id", "integer", Some(1)),
                col("user_id", "integer", Some(2)),
                col("nick", "text", None),
            ],
            foreign_keys: Vec::new(),
            indexes: Vec::new(),
        }
    }

    fn spec(kind: &str, pk: &[(&str, &str)], set: &[(&str, Option<&str>)]) -> ChangeSpec {
        ChangeSpec {
            kind: kind.into(),
            pk: pk.iter().map(|(k, v)| (k.to_string(), Some(v.to_string()))).collect(),
            set: set
                .iter()
                .map(|(k, v)| (k.to_string(), v.map(|s| s.to_string())))
                .collect(),
            values: BTreeMap::new(),
        }
    }

    #[test]
    fn update_binds_values_and_addresses_by_pk() {
        let plan = plan(
            &table(),
            Dialect::Sqlite,
            vec![spec("update", &[("id", "7")], &[("name", Some("root"))])],
        )
        .unwrap();
        let s = &plan.statements[0];
        assert_eq!(s.kind, "update");
        assert_eq!(s.sql, r#"UPDATE "account" SET "name" = ?1 WHERE "id" = ?2"#);
        assert_eq!(s.params, vec![Some("root".into()), Some("7".into())]);
        // The value never appears in the SQL — only in the display rendering.
        assert!(!s.sql.contains("root"));
        assert_eq!(s.preview, r#"UPDATE "account" SET "name" = 'root' WHERE "id" = '7'"#);
    }

    #[test]
    fn postgres_casts_every_parameter_to_the_introspected_type() {
        let plan = plan(
            &table(),
            Dialect::Postgres,
            vec![spec("update", &[("id", "7")], &[("flags", Some("3"))])],
        )
        .unwrap();
        assert_eq!(
            plan.statements[0].sql,
            r#"UPDATE "public"."account" SET "flags" = CAST($1 AS integer) WHERE "id" = CAST($2 AS integer)"#
        );
    }

    #[test]
    fn a_null_assignment_binds_null_rather_than_the_text_null() {
        let plan = plan(
            &table(),
            Dialect::Sqlite,
            vec![spec("update", &[("id", "1")], &[("name", None)])],
        )
        .unwrap();
        assert_eq!(plan.statements[0].params[0], None);
        assert_eq!(
            plan.statements[0].preview,
            r#"UPDATE "account" SET "name" = NULL WHERE "id" = '1'"#
        );
    }

    #[test]
    fn a_composite_key_requires_every_column() {
        let ok = plan(
            &composite(),
            Dialect::Sqlite,
            vec![spec(
                "update",
                &[("guild_id", "1"), ("user_id", "2")],
                &[("nick", Some("x"))],
            )],
        )
        .unwrap();
        assert_eq!(
            ok.statements[0].sql,
            r#"UPDATE "member" SET "nick" = ?1 WHERE "guild_id" = ?2 AND "user_id" = ?3"#
        );

        // Half a key would address a whole guild.
        let err = plan(
            &composite(),
            Dialect::Sqlite,
            vec![spec("update", &[("guild_id", "1")], &[("nick", Some("x"))])],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("missing primary key column: user_id"), "got: {err}");
    }

    #[test]
    fn quotes_are_doubled_so_an_identifier_cannot_escape_its_quoting() {
        let mut t = table();
        t.columns.push(col(r#"we"ird"#, "text", None));
        let plan = plan(
            &t,
            Dialect::Sqlite,
            vec![spec("update", &[("id", "1")], &[(r#"we"ird"#, Some("v"))])],
        )
        .unwrap();
        assert_eq!(
            plan.statements[0].sql,
            r#"UPDATE "account" SET "we""ird" = ?1 WHERE "id" = ?2"#
        );
    }

    #[test]
    fn a_value_that_looks_like_sql_stays_a_parameter() {
        let evil = "'); DROP TABLE account; --";
        let plan = plan(
            &table(),
            Dialect::Sqlite,
            vec![spec("update", &[("id", "1")], &[("name", Some(evil))])],
        )
        .unwrap();
        assert_eq!(
            plan.statements[0].sql,
            r#"UPDATE "account" SET "name" = ?1 WHERE "id" = ?2"#
        );
        assert_eq!(plan.statements[0].params[0], Some(evil.into()));
        assert!(!plan.statements[0].sql.contains("DROP"));
        // The preview escapes it for reading; it is never executed.
        assert!(plan.statements[0].preview.contains("''); DROP TABLE account; --"));
    }

    #[test]
    fn delete_and_insert_generate_single_row_statements() {
        let del = plan(&table(), Dialect::Sqlite, vec![spec("delete", &[("id", "9")], &[])]).unwrap();
        assert_eq!(del.statements[0].sql, r#"DELETE FROM "account" WHERE "id" = ?1"#);

        let ins = plan(
            &table(),
            Dialect::Sqlite,
            vec![ChangeSpec {
                kind: "insert".into(),
                pk: BTreeMap::new(),
                set: BTreeMap::new(),
                values: [("name".to_string(), Some("new".to_string()))].into_iter().collect(),
            }],
        )
        .unwrap();
        assert_eq!(ins.statements[0].sql, r#"INSERT INTO "account" ("name") VALUES (?1)"#);
    }

    #[test]
    fn refusals_name_what_was_refused() {
        let cases: Vec<(ChangeSpec, &str)> = vec![
            (
                spec("update", &[("id", "1")], &[("nope", Some("x"))]),
                "unknown column: nope",
            ),
            (spec("update", &[("id", "1")], &[]), "nothing to set"),
            (
                spec("update", &[("id", "1")], &[("id", Some("2"))]),
                "part of the primary key",
            ),
            (
                spec("update", &[("name", "x")], &[("flags", Some("1"))]),
                "not part of the primary key",
            ),
            (spec("frobnicate", &[("id", "1")], &[]), "unknown change kind"),
        ];
        for (change, expected) in cases {
            let err = plan(&table(), Dialect::Sqlite, vec![change]).unwrap_err().to_string();
            assert!(err.contains(expected), "expected {expected:?}, got: {err}");
        }
    }

    #[test]
    fn a_table_without_a_primary_key_cannot_be_edited() {
        let mut t = table();
        for c in &mut t.columns {
            c.pk_ordinal = None;
        }
        let err = plan(&t, Dialect::Sqlite, vec![spec("update", &[], &[("name", Some("x"))])])
            .unwrap_err()
            .to_string();
        assert!(err.contains("no primary key"), "got: {err}");
    }

    #[test]
    fn a_view_cannot_be_edited() {
        let mut t = table();
        t.kind = "view";
        let err = plan(
            &t,
            Dialect::Sqlite,
            vec![spec("update", &[("id", "1")], &[("name", Some("x"))])],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not a table"), "got: {err}");
    }

    #[test]
    fn a_batch_is_bounded_and_never_empty() {
        assert!(plan(&table(), Dialect::Sqlite, vec![])
            .unwrap_err()
            .to_string()
            .contains("no changes"));

        let many: Vec<ChangeSpec> = (0..MAX_CHANGES + 1)
            .map(|i| spec("update", &[("id", "1")], &[("name", Some(&format!("n{i}")))]))
            .collect();
        let err = plan(&table(), Dialect::Sqlite, many).unwrap_err().to_string();
        assert!(err.contains("too many staged changes"), "got: {err}");
    }

    #[test]
    fn preview_substitution_is_not_confused_by_double_digit_placeholders() {
        // 11 assignments: `?1` must not be substituted inside `?11`.
        let set: Vec<(String, Option<String>)> = (0..11).map(|i| (format!("c{i}"), Some(format!("v{i}")))).collect();
        let mut t = table();
        for (name, _) in &set {
            t.columns.push(col(name, "text", None));
        }
        let plan = plan(
            &t,
            Dialect::Sqlite,
            vec![ChangeSpec {
                kind: "update".into(),
                pk: [("id".to_string(), Some("1".to_string()))].into_iter().collect(),
                set: set.into_iter().collect(),
                values: BTreeMap::new(),
            }],
        )
        .unwrap();
        let preview = &plan.statements[0].preview;
        assert!(
            !preview.contains('?'),
            "every placeholder should be rendered: {preview}"
        );
        assert!(preview.contains("'v10'"), "got: {preview}");
    }
}
