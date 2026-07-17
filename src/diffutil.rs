//! A small line-level diff, server-side (FRONTEND_MIGRATION_PLAN §11.2).
//!
//! The "Preview changes" step shows an operator what an apply will do to the
//! config it generates for an external engine (nginx/caddy/cloudflared) *before*
//! it writes it. The diff is computed here and shipped as a flat list of tagged
//! lines; the client only paints them (see the `diff-view` component). Doing the
//! diff on the server keeps the two sides from disagreeing about what changed,
//! and means the browser never has to carry a diff library.
//!
//! The algorithm is a classic LCS over lines — O(n·m) memory, which is nothing
//! for the tens-of-lines config fragments this runs on, and dead simple to read.
//! A packet filter's config is the last place to want a clever diff nobody can
//! follow.

use serde::Serialize;

/// One line of a rendered diff. `tag` is `"ctx"` (unchanged), `"add"` (only in
/// the new text) or `"del"` (only in the old).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffLine {
    pub tag: &'static str,
    pub text: String,
}

impl DiffLine {
    fn new(tag: &'static str, text: &str) -> Self {
        Self {
            tag,
            text: text.to_string(),
        }
    }
}

/// A quick summary of a diff — what the caller needs to say "3 added, 1 removed"
/// without re-walking the lines.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct DiffStat {
    pub added: usize,
    pub removed: usize,
}

impl DiffStat {
    /// Whether the two texts are identical (nothing added or removed).
    pub fn is_unchanged(&self) -> bool {
        self.added == 0 && self.removed == 0
    }
}

/// Tallies the adds and removes in a rendered diff.
pub fn stat(lines: &[DiffLine]) -> DiffStat {
    let mut s = DiffStat::default();
    for line in lines {
        match line.tag {
            "add" => s.added += 1,
            "del" => s.removed += 1,
            _ => {}
        }
    }
    s
}

/// Diffs two texts line by line. A trailing newline does not produce a spurious
/// empty final line: both sides are split the same way, so it cancels.
pub fn diff(old: &str, new: &str) -> Vec<DiffLine> {
    let old_lines: Vec<&str> = split(old);
    let new_lines: Vec<&str> = split(new);
    diff_lines(&old_lines, &new_lines)
}

/// Splits into lines without the trailing-newline artefact. `""` is zero lines,
/// not one empty line, so an empty old file diffs cleanly to "all added".
fn split(s: &str) -> Vec<&str> {
    if s.is_empty() {
        Vec::new()
    } else {
        s.strip_suffix('\n').unwrap_or(s).split('\n').collect()
    }
}

fn diff_lines(old: &[&str], new: &[&str]) -> Vec<DiffLine> {
    // LCS length table: lcs[i][j] = longest common subsequence of old[i..], new[j..].
    let (n, m) = (old.len(), new.len());
    let mut lcs = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if old[i] == new[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }

    // Walk the table forward, emitting a del before an add at each divergence so
    // a changed line reads old-then-new, the way a person expects.
    let mut out = Vec::with_capacity(n.max(m));
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if old[i] == new[j] {
            out.push(DiffLine::new("ctx", old[i]));
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            out.push(DiffLine::new("del", old[i]));
            i += 1;
        } else {
            out.push(DiffLine::new("add", new[j]));
            j += 1;
        }
    }
    while i < n {
        out.push(DiffLine::new("del", old[i]));
        i += 1;
    }
    while j < m {
        out.push(DiffLine::new("add", new[j]));
        j += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(lines: &[DiffLine]) -> Vec<&'static str> {
        lines.iter().map(|l| l.tag).collect()
    }

    #[test]
    fn identical_texts_are_all_context() {
        let lines = diff("a\nb\nc\n", "a\nb\nc\n");
        assert_eq!(tags(&lines), ["ctx", "ctx", "ctx"]);
        assert!(stat(&lines).is_unchanged());
    }

    #[test]
    fn an_empty_old_is_all_additions() {
        let lines = diff("", "x\ny\n");
        assert_eq!(tags(&lines), ["add", "add"]);
        assert_eq!(stat(&lines), DiffStat { added: 2, removed: 0 });
    }

    #[test]
    fn a_removed_file_is_all_deletions() {
        let lines = diff("x\ny\n", "");
        assert_eq!(tags(&lines), ["del", "del"]);
        assert_eq!(stat(&lines), DiffStat { added: 0, removed: 2 });
    }

    #[test]
    fn a_changed_line_reads_old_then_new() {
        // Context around a single changed middle line.
        let lines = diff("keep\nold\ntail\n", "keep\nnew\ntail\n");
        assert_eq!(tags(&lines), ["ctx", "del", "add", "ctx"]);
        assert_eq!(lines[1].text, "old");
        assert_eq!(lines[2].text, "new");
    }

    #[test]
    fn an_inserted_line_keeps_the_surrounding_context() {
        let lines = diff("a\nb\n", "a\nmid\nb\n");
        assert_eq!(tags(&lines), ["ctx", "add", "ctx"]);
        assert_eq!(lines[1].text, "mid");
    }

    #[test]
    fn a_trailing_newline_does_not_add_a_phantom_line() {
        // With and without the final newline diff to the same thing.
        assert_eq!(diff("a\nb", "a\nb\n"), diff("a\nb", "a\nb"));
    }
}
