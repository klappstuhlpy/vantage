use secretshape::{Scanner, Severity};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
    sync::OnceLock,
};
use tracing::warn;

const MAX_FILE_BYTES: u64 = 1024 * 1024;
const MAX_LINE_BYTES: usize = 8 * 1024;
const SNIFF_BYTES: usize = 8 * 1024;

const SKIP_DIRS: &[&str] = &[
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "bower_components",
    "target",
    "build",
    "dist",
    "out",
    ".next",
    ".nuxt",
    "venv",
    ".venv",
    "__pycache__",
    ".cache",
    ".idea",
    ".vscode",
];

const SKIP_EXTS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "bmp", "ico", "tiff", "mp3", "mp4", "mkv", "webm", "avi", "mov", "wav", "ogg",
    "flac", "zip", "tar", "gz", "bz2", "xz", "7z", "rar", "deb", "rpm", "pdf", "doc", "docx", "xls", "xlsx", "ppt",
    "pptx", "exe", "dll", "so", "dylib", "bin", "class", "jar", "wasm", "ttf", "otf", "woff", "woff2", "eot", "db",
    "sqlite", "sqlite3",
];

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule: String,
    pub severity: Severity,
    pub file_path: PathBuf,
    pub line: u32,
    pub snippet: String,
    pub finding_hash: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ScanCounters {
    pub files_scanned: u64,
    pub bytes_scanned: u64,
}

pub fn scan(roots: &[PathBuf]) -> (Vec<Finding>, ScanCounters) {
    let mut out = Vec::new();
    let mut counters = ScanCounters::default();
    for root in roots {
        match std::fs::metadata(root) {
            Ok(m) if m.is_dir() || m.is_file() => walk(root, &mut out, &mut counters),
            Ok(m) => warn!(
                root = %root.display(),
                file_type = ?m.file_type(),
                "secret scan: configured root is neither a file nor a directory, skipping",
            ),
            Err(e) => warn!(
                root = %root.display(),
                error = %e,
                "secret scan: cannot access configured root",
            ),
        }
    }
    out.sort_by(|a, b| a.file_path.cmp(&b.file_path).then(a.line.cmp(&b.line)));
    (out, counters)
}

fn walk(root: &Path, out: &mut Vec<Finding>, counters: &mut ScanCounters) {
    let metadata = match std::fs::metadata(root) {
        Ok(m) => m,
        Err(_) => return,
    };

    if metadata.is_file() {
        scan_file(root, out, counters);
        return;
    }
    if !metadata.is_dir() {
        return;
    }

    let entries = match std::fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            let name = entry.file_name();
            let name_s = name.to_string_lossy();
            if SKIP_DIRS.contains(&name_s.as_ref()) || name_s.starts_with('.') && name_s.as_ref() != "." {
                continue;
            }
            walk(&path, out, counters);
        } else if file_type.is_file() {
            scan_file(&path, out, counters);
        }
    }
}

fn scan_file(path: &Path, out: &mut Vec<Finding>, counters: &mut ScanCounters) {
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext_lower = ext.to_ascii_lowercase();
        if SKIP_EXTS.contains(&ext_lower.as_str()) {
            return;
        }
    }

    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return,
    };
    if meta.len() > MAX_FILE_BYTES {
        return;
    }

    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return,
    };

    let mut sniff = vec![0u8; SNIFF_BYTES.min(meta.len() as usize)];
    let read = match file.read(&mut sniff) {
        Ok(n) => n,
        Err(_) => return,
    };
    if sniff[..read].contains(&0) {
        return;
    }

    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let reader = BufReader::new(file);

    counters.files_scanned += 1;
    counters.bytes_scanned += meta.len();

    for (i, line) in reader.lines().enumerate() {
        let Ok(line) = line else { continue };
        let mut seen: Vec<std::borrow::Cow<'static, str>> = Vec::new();
        for finding in scanner().scan(&line) {
            if seen.contains(&finding.rule) {
                continue;
            }
            let snippet = redact_snippet(&line, finding.span.start, finding.span.end);
            let hash = hash_finding(&finding.rule, path, &snippet);
            out.push(Finding {
                rule: finding.rule.to_string(),
                severity: finding.severity,
                file_path: path.to_path_buf(),
                line: (i + 1) as u32,
                snippet,
                finding_hash: hash,
            });
            seen.push(finding.rule);
        }
    }
}

fn scanner() -> &'static Scanner {
    static SLOT: OnceLock<Scanner> = OnceLock::new();
    SLOT.get_or_init(|| Scanner::new().max_input_bytes(MAX_LINE_BYTES))
}

fn redact_snippet(line: &str, m_start: usize, m_end: usize) -> String {
    let mut s = String::new();
    let prefix_start = m_start.saturating_sub(20);
    let suffix_end = (m_end + 20).min(line.len());

    s.push_str(&line[prefix_start..m_start]);
    let matched = &line[m_start..m_end];
    if matched.len() <= 8 {
        s.push_str(&"*".repeat(matched.len()));
    } else {
        s.push_str(&matched[..4]);
        s.push_str(&"*".repeat(matched.len().saturating_sub(8)));
        s.push_str(&matched[matched.len() - 4..]);
    }
    s.push_str(&line[m_end..suffix_end]);

    s.trim().to_string()
}

fn hash_finding(rule: &str, path: &Path, snippet: &str) -> String {
    let mut h = Sha256::new();
    h.update(rule.as_bytes());
    h.update(b"|");
    h.update(path.to_string_lossy().as_bytes());
    h.update(b"|");
    h.update(snippet.as_bytes());
    let digest = h.finalize();
    let mut out = String::with_capacity(64);
    for b in digest.iter() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_hides_middle_of_long_match() {
        let line = "aws_secret_access_key = AKIAIOSFODNN7EXAMPLE";
        let start = 24;
        let end = line.len();
        let snippet = redact_snippet(line, start, end);
        assert!(snippet.contains("AKIA"));
        assert!(snippet.contains("MPLE"));
        assert!(snippet.contains("*"));
        assert!(!snippet.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn redact_short_match_is_all_stars() {
        let snippet = redact_snippet("key=abcd1234", 4, 8);
        assert_eq!(snippet, "key=****1234");
    }

    #[test]
    fn hash_is_deterministic() {
        let a = hash_finding("AWS", Path::new("/etc/foo"), "snip");
        let b = hash_finding("AWS", Path::new("/etc/foo"), "snip");
        assert_eq!(a, b);
        let c = hash_finding("AWS", Path::new("/etc/bar"), "snip");
        assert_ne!(a, c);
    }
}
