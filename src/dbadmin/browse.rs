//! Filter/sort plan validation and SQL assembly for the table browser (DB
//! Studio P2).
//!
//! The browser's contract (D5): filters arrive as structured data —
//! `{column, op, value}[]` — never as SQL fragments. This module turns that
//! request into a [`BrowsePlan`]:
//!
//! - `column` is validated against the *introspected* schema; an unknown
//!   column is a 400 naming it, never a silently dropped clause (a dropped
//!   clause would turn "filtered view" into a lie).
//! - `op` is matched against a closed whitelist.
//! - `value` travels as a bound parameter; LIKE values are escaped for `%_\`
//!   and wrapped server-side.
//!
//! The plan is backend-neutral. Each backend turns it into its own SQL
//! ([`sqlite_query`] / [`pg_query`]), and only identifiers that came out of
//! introspection are ever interpolated — quoted by [`quote_ident`] as defence
//! in depth (D6). There is no code path where a request string meets a format
//! string.

use super::quote_ident;
use super::schema::TableDetail;

/// Page size for the grid (D8). The client may ask for less, never more.
pub const PAGE_LIMIT: usize = 500;

/// One page of browsed rows.
#[derive(Debug, serde::Serialize)]
pub struct RowsPage {
    pub columns: Vec<String>,
    /// Cells as text; `None` is SQL NULL (D2).
    pub rows: Vec<Vec<Option<String>>>,
    pub offset: usize,
    /// A hint, not a promise: `true` when this page came back full, so the
    /// next page may exist. At an exact boundary the next fetch is empty —
    /// one wasted request, never a missing row.
    pub has_more: bool,
    pub elapsed_ms: u64,
}

/// The exact count under the current filters (`/database/count`).
#[derive(Debug, serde::Serialize)]
pub struct CountResult {
    pub count: i64,
    pub elapsed_ms: u64,
}

/// Export encodings. CSV cannot say NULL (it renders as an empty field, same
/// as the empty string); NDJSON preserves it as a real `null`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Csv,
    Ndjson,
}

impl ExportFormat {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "csv" => Ok(ExportFormat::Csv),
            "ndjson" => Ok(ExportFormat::Ndjson),
            other => anyhow::bail!("unknown export format: {other}"),
        }
    }

    pub fn content_type(self) -> &'static str {
        match self {
            ExportFormat::Csv => "text/csv; charset=utf-8",
            ExportFormat::Ndjson => "application/x-ndjson",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            ExportFormat::Csv => "csv",
            ExportFormat::Ndjson => "ndjson",
        }
    }

    /// The header chunk that precedes the rows (CSV column line; nothing for
    /// NDJSON, where every line carries its own keys).
    pub fn header(self, columns: &[String]) -> String {
        match self {
            ExportFormat::Csv => {
                let mut line = columns.iter().map(|c| csv_field(c)).collect::<Vec<_>>().join(",");
                line.push('\n');
                line
            }
            ExportFormat::Ndjson => String::new(),
        }
    }

    /// One encoded row, newline included.
    pub fn line(self, columns: &[String], row: &[Option<String>]) -> String {
        match self {
            ExportFormat::Csv => {
                let mut line = row
                    .iter()
                    .map(|c| c.as_deref().map(csv_field).unwrap_or_default())
                    .collect::<Vec<_>>()
                    .join(",");
                line.push('\n');
                line
            }
            ExportFormat::Ndjson => {
                let obj: serde_json::Map<String, serde_json::Value> = columns
                    .iter()
                    .zip(row)
                    .map(|(k, v)| {
                        (
                            k.clone(),
                            v.as_deref().map(Into::into).unwrap_or(serde_json::Value::Null),
                        )
                    })
                    .collect();
                let mut line = serde_json::Value::Object(obj).to_string();
                line.push('\n');
                line
            }
        }
    }
}

/// Quotes one CSV field per RFC 4180: only when it needs it, doubling quotes.
fn csv_field(s: &str) -> String {
    if s.contains(['"', ',', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// One filter as the client sent it, before validation.
#[derive(Debug, serde::Deserialize)]
pub struct FilterSpec {
    pub column: String,
    pub op: String,
    #[serde(default)]
    pub value: Option<String>,
}

/// The operator whitelist. Anything else is refused by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Contains,
    StartsWith,
    EndsWith,
    IsNull,
    NotNull,
}

impl Op {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "=" => Op::Eq,
            "!=" => Op::Ne,
            "<" => Op::Lt,
            "<=" => Op::Le,
            ">" => Op::Gt,
            ">=" => Op::Ge,
            "contains" => Op::Contains,
            "starts-with" => Op::StartsWith,
            "ends-with" => Op::EndsWith,
            "is-null" => Op::IsNull,
            "not-null" => Op::NotNull,
            _ => return None,
        })
    }

    fn comparison(self) -> Option<&'static str> {
        Some(match self {
            Op::Eq => "=",
            Op::Ne => "<>",
            Op::Lt => "<",
            Op::Le => "<=",
            Op::Gt => ">",
            Op::Ge => ">=",
            _ => return None,
        })
    }

    fn takes_value(self) -> bool {
        !matches!(self, Op::IsNull | Op::NotNull)
    }
}

/// A validated filter: the column exists, the op is known, and the value (for
/// LIKE ops) is already escaped and wrapped.
#[derive(Debug)]
pub struct PlannedFilter {
    /// Column name as introspection spelled it — not as the request did.
    pub column: String,
    /// The column's declared type, for backends that cast the bound value.
    pub data_type: String,
    pub op: Op,
    /// The bound parameter value; `None` exactly for the null-ops.
    pub value: Option<String>,
}

/// A validated browse request, ready for SQL assembly.
#[derive(Debug)]
pub struct BrowsePlan {
    /// Every column of the table, in introspection order — the SELECT list.
    pub columns: Vec<ColumnPlan>,
    pub filters: Vec<PlannedFilter>,
    /// `(column, descending)` — the user's sort, if any.
    pub sort: Option<(String, bool)>,
    /// PK columns in ordinal order: the stable tiebreak that keeps
    /// LIMIT/OFFSET pages from repeating or skipping rows on equal sort keys.
    pub pk: Vec<String>,
    pub limit: usize,
    pub offset: usize,
}

#[derive(Debug)]
pub struct ColumnPlan {
    pub name: String,
    pub data_type: String,
}

/// Validates a browse request against the introspected table. Every error
/// names what was refused — these become 400s the operator can act on.
pub fn plan(
    detail: &TableDetail,
    filters: Vec<FilterSpec>,
    sort: Option<(String, bool)>,
    limit: Option<usize>,
    offset: usize,
) -> anyhow::Result<BrowsePlan> {
    let find = |name: &str| detail.columns.iter().find(|c| c.name == name);

    let mut planned = Vec::with_capacity(filters.len());
    for f in filters {
        let col = find(&f.column).ok_or_else(|| anyhow::anyhow!("unknown column in filter: {}", f.column))?;
        let op = Op::parse(&f.op).ok_or_else(|| anyhow::anyhow!("unknown filter operator: {}", f.op))?;
        let value = match (op.takes_value(), f.value) {
            (true, Some(v)) => Some(match op {
                Op::Contains => format!("%{}%", escape_like(&v)),
                Op::StartsWith => format!("{}%", escape_like(&v)),
                Op::EndsWith => format!("%{}", escape_like(&v)),
                _ => v,
            }),
            (true, None) => anyhow::bail!("filter on {} needs a value for '{}'", f.column, f.op),
            (false, Some(_)) => anyhow::bail!("filter '{}' on {} takes no value", f.op, f.column),
            (false, None) => None,
        };
        planned.push(PlannedFilter {
            column: col.name.clone(),
            data_type: col.data_type.clone(),
            op,
            value,
        });
    }

    let sort = match sort {
        Some((name, desc)) => {
            let col = find(&name).ok_or_else(|| anyhow::anyhow!("unknown sort column: {name}"))?;
            Some((col.name.clone(), desc))
        }
        None => None,
    };

    let mut pk: Vec<(u32, String)> = detail
        .columns
        .iter()
        .filter_map(|c| c.pk_ordinal.map(|o| (o, c.name.clone())))
        .collect();
    pk.sort_by_key(|(o, _)| *o);

    Ok(BrowsePlan {
        columns: detail
            .columns
            .iter()
            .map(|c| ColumnPlan {
                name: c.name.clone(),
                data_type: c.data_type.clone(),
            })
            .collect(),
        filters: planned,
        sort,
        pk: pk.into_iter().map(|(_, n)| n).collect(),
        limit: limit.unwrap_or(PAGE_LIMIT).clamp(1, PAGE_LIMIT),
        offset,
    })
}

/// Escapes `%`, `_` and the escape character itself for a `LIKE … ESCAPE '\'`
/// pattern, so a filter value is matched literally.
fn escape_like(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

// ─── SQL assembly ────────────────────────────────────────────────────

/// The ORDER BY clause: the user's sort first, then the PK as a stable
/// tiebreak. Empty when there is nothing to order by — a table with no PK and
/// no sort pages in natural order, which is the honest option left.
fn order_by(plan: &BrowsePlan) -> String {
    let mut keys: Vec<String> = Vec::new();
    if let Some((col, desc)) = &plan.sort {
        keys.push(format!("{} {}", quote_ident(col), if *desc { "DESC" } else { "ASC" }));
    }
    for pk in &plan.pk {
        if plan.sort.as_ref().map(|(c, _)| c) != Some(pk) {
            keys.push(quote_ident(pk));
        }
    }
    if keys.is_empty() {
        String::new()
    } else {
        format!(" ORDER BY {}", keys.join(", "))
    }
}

/// SQLite: values bind as `?N` and comparisons lean on type affinity (a text
/// parameter compared to an INTEGER column converts numerically), so no casts
/// are needed — and none are wanted in the SELECT list either, because the
/// cell renderer handles every storage class including blobs (D2/D4).
pub fn sqlite_query(plan: &BrowsePlan, table: &str) -> (String, Vec<String>) {
    let (sql, params) = sqlite_select(plan, table);
    (format!("{sql} LIMIT {} OFFSET {}", plan.limit, plan.offset), params)
}

/// The same SELECT without the page bounds — what the export streams (D13).
pub fn sqlite_export_query(plan: &BrowsePlan, table: &str) -> (String, Vec<String>) {
    sqlite_select(plan, table)
}

fn sqlite_select(plan: &BrowsePlan, table: &str) -> (String, Vec<String>) {
    let select: Vec<String> = plan.columns.iter().map(|c| quote_ident(&c.name)).collect();
    let (where_clause, params) = sqlite_where(plan);
    let sql = format!(
        "SELECT {} FROM {}{}{}",
        select.join(", "),
        quote_ident(table),
        where_clause,
        order_by(plan),
    );
    (sql, params)
}

/// SQLite `COUNT(*)` under the same filters.
pub fn sqlite_count(plan: &BrowsePlan, table: &str) -> (String, Vec<String>) {
    let (where_clause, params) = sqlite_where(plan);
    (
        format!("SELECT COUNT(*) FROM {}{}", quote_ident(table), where_clause),
        params,
    )
}

/// The WHERE clause (with leading space) and its bound values, `?N` style.
fn sqlite_where(plan: &BrowsePlan) -> (String, Vec<String>) {
    let mut params: Vec<String> = Vec::new();
    let mut wheres: Vec<String> = Vec::new();
    for f in &plan.filters {
        let col = quote_ident(&f.column);
        match f.op {
            Op::IsNull => wheres.push(format!("{col} IS NULL")),
            Op::NotNull => wheres.push(format!("{col} IS NOT NULL")),
            Op::Contains | Op::StartsWith | Op::EndsWith => {
                params.push(f.value.clone().expect("validated"));
                wheres.push(format!("{col} LIKE ?{} ESCAPE '\\'", params.len()));
            }
            _ => {
                params.push(f.value.clone().expect("validated"));
                wheres.push(format!(
                    "{col} {} ?{}",
                    f.op.comparison().expect("comparison op"),
                    params.len()
                ));
            }
        }
    }
    if wheres.is_empty() {
        (String::new(), params)
    } else {
        (format!(" WHERE {}", wheres.join(" AND ")), params)
    }
}

/// Postgres: the grid controls the SELECT list, so every column casts to
/// `::text` in SQL and the extended protocol returns nothing but text —
/// bound parameters work and no per-OID decode table exists (D4). `bytea`
/// summarises as a length instead of megabytes of hex.
///
/// Comparison values are cast to the *column's introspected type* so `<` on a
/// number is numeric, not lexicographic; LIKE compares the text rendering.
pub fn pg_query(plan: &BrowsePlan, schema: &str, table: &str) -> (String, Vec<String>) {
    let (sql, params) = pg_select(plan, schema, table);
    (format!("{sql} LIMIT {} OFFSET {}", plan.limit, plan.offset), params)
}

/// The same SELECT without the page bounds — what the export streams (D13).
pub fn pg_export_query(plan: &BrowsePlan, schema: &str, table: &str) -> (String, Vec<String>) {
    pg_select(plan, schema, table)
}

fn pg_select(plan: &BrowsePlan, schema: &str, table: &str) -> (String, Vec<String>) {
    let select: Vec<String> = plan.columns.iter().map(pg_select_expr).collect();
    let (where_clause, params) = pg_where(plan);
    let sql = format!(
        "SELECT {} FROM {}.{}{}{}",
        select.join(", "),
        quote_ident(schema),
        quote_ident(table),
        where_clause,
        order_by(plan),
    );
    (sql, params)
}

/// Postgres `COUNT(*)` under the same filters. `::text` so the count arrives
/// as text like everything else on this path — no int8 decode.
pub fn pg_count(plan: &BrowsePlan, schema: &str, table: &str) -> (String, Vec<String>) {
    let (where_clause, params) = pg_where(plan);
    (
        format!(
            "SELECT COUNT(*)::text FROM {}.{}{}",
            quote_ident(schema),
            quote_ident(table),
            where_clause
        ),
        params,
    )
}

/// The WHERE clause (with leading space) and its bound values, `$N` style.
fn pg_where(plan: &BrowsePlan) -> (String, Vec<String>) {
    let mut params: Vec<String> = Vec::new();
    let mut wheres: Vec<String> = Vec::new();
    for f in &plan.filters {
        wheres.push(pg_condition(f, &mut params));
    }
    if wheres.is_empty() {
        (String::new(), params)
    } else {
        (format!(" WHERE {}", wheres.join(" AND ")), params)
    }
}

fn pg_condition(f: &PlannedFilter, params: &mut Vec<String>) -> String {
    let col = quote_ident(&f.column);
    match f.op {
        Op::IsNull => format!("{col} IS NULL"),
        Op::NotNull => format!("{col} IS NOT NULL"),
        Op::Contains | Op::StartsWith | Op::EndsWith => {
            params.push(f.value.clone().expect("validated"));
            format!("{col}::text LIKE ${} ESCAPE '\\'", params.len())
        }
        _ => {
            params.push(f.value.clone().expect("validated"));
            // The CAST target is introspection output (format_type), never a
            // request string. A value that doesn't parse as the column's type
            // is the engine's 400 to give.
            format!(
                "{col} {} CAST(${} AS {})",
                f.op.comparison().expect("comparison op"),
                params.len(),
                f.data_type
            )
        }
    }
}

fn pg_select_expr(c: &ColumnPlan) -> String {
    let q = quote_ident(&c.name);
    if c.data_type == "bytea" {
        format!("CASE WHEN {q} IS NULL THEN NULL ELSE '<bytea: ' || octet_length({q}) || ' bytes>' END AS {q}")
    } else {
        format!("{q}::text AS {q}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dbadmin::schema::{Column, TableDetail};

    fn detail() -> TableDetail {
        let col = |name: &str, ty: &str, pk: Option<u32>| Column {
            name: name.into(),
            data_type: ty.into(),
            nullable: pk.is_none(),
            default: None,
            pk_ordinal: pk,
        };
        TableDetail {
            schema: "public".into(),
            name: "widget".into(),
            kind: "table",
            columns: vec![
                col("id", "bigint", Some(1)),
                col("name", "text", None),
                col("data", "bytea", None),
            ],
            foreign_keys: vec![],
            indexes: vec![],
        }
    }

    fn spec(column: &str, op: &str, value: Option<&str>) -> FilterSpec {
        FilterSpec {
            column: column.into(),
            op: op.into(),
            value: value.map(String::from),
        }
    }

    #[test]
    fn unknown_columns_and_ops_are_refused_by_name() {
        let d = detail();
        let err = plan(&d, vec![spec("nope", "=", Some("1"))], None, None, 0)
            .unwrap_err()
            .to_string();
        assert!(err.contains("nope"), "got: {err}");

        let err = plan(&d, vec![spec("name", "LIKE", Some("x"))], None, None, 0)
            .unwrap_err()
            .to_string();
        assert!(err.contains("LIKE"), "the op is named, got: {err}");

        let err = plan(&d, vec![], Some(("nope".into(), false)), None, 0)
            .unwrap_err()
            .to_string();
        assert!(err.contains("sort"), "got: {err}");
    }

    #[test]
    fn null_ops_take_no_value_and_comparisons_require_one() {
        let d = detail();
        assert!(plan(&d, vec![spec("name", "is-null", Some("x"))], None, None, 0).is_err());
        assert!(plan(&d, vec![spec("name", "=", None)], None, None, 0).is_err());
        assert!(plan(&d, vec![spec("name", "not-null", None)], None, None, 0).is_ok());
    }

    #[test]
    fn like_values_are_escaped_and_wrapped() {
        let d = detail();
        let p = plan(&d, vec![spec("name", "contains", Some("50%_off\\"))], None, None, 0).unwrap();
        assert_eq!(p.filters[0].value.as_deref(), Some("%50\\%\\_off\\\\%"));

        let p = plan(&d, vec![spec("name", "starts-with", Some("a_b"))], None, None, 0).unwrap();
        assert_eq!(p.filters[0].value.as_deref(), Some("a\\_b%"));
    }

    #[test]
    fn limit_is_clamped_to_the_page_cap() {
        let d = detail();
        assert_eq!(plan(&d, vec![], None, Some(10_000), 0).unwrap().limit, PAGE_LIMIT);
        assert_eq!(plan(&d, vec![], None, Some(0), 0).unwrap().limit, 1);
        assert_eq!(plan(&d, vec![], None, None, 0).unwrap().limit, PAGE_LIMIT);
    }

    /// Golden test: the assembled SQLite SQL. Bound placeholders for values,
    /// quoted identifiers, PK tiebreak after the user's sort.
    #[test]
    fn sqlite_sql_binds_values_and_orders_stably() {
        let d = detail();
        let p = plan(
            &d,
            vec![spec("name", "contains", Some("ro")), spec("id", ">=", Some("5"))],
            Some(("name".into(), true)),
            Some(100),
            200,
        )
        .unwrap();
        let (sql, params) = sqlite_query(&p, "widget");
        assert_eq!(
            sql,
            "SELECT \"id\", \"name\", \"data\" FROM \"widget\" \
             WHERE \"name\" LIKE ?1 ESCAPE '\\' AND \"id\" >= ?2 \
             ORDER BY \"name\" DESC, \"id\" LIMIT 100 OFFSET 200"
        );
        assert_eq!(params, vec!["%ro%", "5"]);

        let (count_sql, count_params) = sqlite_count(&p, "widget");
        assert_eq!(
            count_sql,
            "SELECT COUNT(*) FROM \"widget\" WHERE \"name\" LIKE ?1 ESCAPE '\\' AND \"id\" >= ?2"
        );
        assert_eq!(count_params, params);
    }

    /// Golden test: the assembled Postgres SQL. Every selected column casts to
    /// text, bytea summarises, comparison values cast to the column's type.
    #[test]
    fn pg_sql_casts_columns_to_text_and_values_to_column_types() {
        let d = detail();
        let p = plan(
            &d,
            vec![spec("id", "<", Some("9")), spec("name", "is-null", None)],
            None,
            None,
            0,
        )
        .unwrap();
        let (sql, params) = pg_query(&p, "public", "widget");
        assert_eq!(
            sql,
            "SELECT \"id\"::text AS \"id\", \"name\"::text AS \"name\", \
             CASE WHEN \"data\" IS NULL THEN NULL ELSE '<bytea: ' || octet_length(\"data\") || ' bytes>' END AS \"data\" \
             FROM \"public\".\"widget\" \
             WHERE \"id\" < CAST($1 AS bigint) AND \"name\" IS NULL \
             ORDER BY \"id\" LIMIT 500 OFFSET 0"
        );
        assert_eq!(params, vec!["9"]);

        let (count_sql, _) = pg_count(&p, "public", "widget");
        assert_eq!(
            count_sql,
            "SELECT COUNT(*)::text FROM \"public\".\"widget\" WHERE \"id\" < CAST($1 AS bigint) AND \"name\" IS NULL"
        );
    }

    /// The export runs the same validated SELECT, unbounded — the stream is
    /// the cap (D13).
    #[test]
    fn export_sql_has_no_page_bounds() {
        let d = detail();
        let p = plan(&d, vec![spec("id", "=", Some("1"))], None, Some(100), 50).unwrap();
        let (sqlite_sql, _) = sqlite_export_query(&p, "widget");
        let (pg_sql, _) = pg_export_query(&p, "public", "widget");
        assert!(!sqlite_sql.contains("LIMIT"), "got: {sqlite_sql}");
        assert!(!pg_sql.contains("LIMIT"), "got: {pg_sql}");
        assert!(sqlite_sql.contains("WHERE"), "filters still apply");
    }

    #[test]
    fn csv_and_ndjson_encode_nulls_and_special_characters() {
        let cols = vec!["a".to_string(), "b".to_string()];
        let row = vec![Some("he said \"hi\", twice".to_string()), None];

        assert_eq!(ExportFormat::Csv.header(&cols), "a,b\n");
        // The quoted field doubles its quotes; the NULL is an empty field —
        // CSV simply cannot say NULL, which is why NDJSON exists here.
        assert_eq!(ExportFormat::Csv.line(&cols, &row), "\"he said \"\"hi\"\", twice\",\n");
        assert_eq!(ExportFormat::Ndjson.header(&cols), "");
        assert_eq!(
            ExportFormat::Ndjson.line(&cols, &row),
            "{\"a\":\"he said \\\"hi\\\", twice\",\"b\":null}\n"
        );
    }

    /// A table with no PK and no sort assembles without an ORDER BY at all —
    /// natural order is the honest option left.
    #[test]
    fn no_pk_and_no_sort_means_no_order_by() {
        let mut d = detail();
        d.columns[0].pk_ordinal = None;
        let p = plan(&d, vec![], None, None, 0).unwrap();
        let (sql, _) = sqlite_query(&p, "widget");
        assert!(!sql.contains("ORDER BY"), "got: {sql}");
    }
}
