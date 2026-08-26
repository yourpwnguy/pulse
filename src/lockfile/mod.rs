//! Finding lockfiles on disk and turning them into projects.
//!
//! This is one of exactly two modules that touch the outside world (the other is
//! [`crate::osv`]). Keeping I/O at the edges is what lets the rest of the crate
//! be tested with plain values.

pub mod cargo;

use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::domain::Project;
use crate::error::{Error, Result};

/// Directories that never contain a lockfile worth scanning: build output,
/// vendored copies of other people's trees, and VCS metadata. Descending into
/// `node_modules` in particular produces findings for code you do not ship.
const PRUNED: &[&str] = &["target", "node_modules", ".git", "vendor", ".cargo"];

const CARGO_LOCK: &str = "Cargo.lock";

/// Recursively finds every supported lockfile under `root`.
///
/// If `root` is itself a lockfile it is returned directly, so
/// `pulse path/to/Cargo.lock` works.
pub fn discover(root: &Path) -> Result<Vec<PathBuf>> {
    if root.is_file() {
        return Ok(match root.file_name().and_then(|n| n.to_str()) {
            Some(CARGO_LOCK) => vec![root.to_path_buf()],
            _ => Vec::new(),
        });
    }

    let mut found = Vec::new();

    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !is_pruned(e.file_name().to_str()))
    {
        let entry = entry.map_err(|e| {
            let path = e.path().unwrap_or(root).to_path_buf();
            Error::Discovery {
                path,
                source: e
                    .into_io_error()
                    .unwrap_or_else(|| std::io::Error::other("directory walk failed")),
            }
        })?;

        if entry.file_type().is_file() && entry.file_name() == CARGO_LOCK {
            found.push(entry.into_path());
        }
    }

    // Deterministic order: the report should not depend on filesystem iteration.
    found.sort();
    Ok(found)
}

/// Parses a discovered lockfile according to its filename.
pub fn parse(path: &Path) -> Result<Project> {
    match path.file_name().and_then(|n| n.to_str()) {
        Some(CARGO_LOCK) => cargo::parse(path),
        other => Err(Error::Lockfile {
            path: path.to_path_buf(),
            reason: format!("unsupported lockfile {}", other.unwrap_or("<invalid>")),
        }),
    }
}

/// The pruning check never prunes the root itself, because `WalkDir`'s
/// `filter_entry` also sees the starting directory: scanning `~/code/target`
/// explicitly should still work.
fn is_pruned(name: Option<&str>) -> bool {
    name.is_some_and(|n| PRUNED.contains(&n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_pruned_directories() {
        assert!(is_pruned(Some("target")));
        assert!(is_pruned(Some("node_modules")));
        assert!(is_pruned(Some(".git")));
        assert!(!is_pruned(Some("src")));
        assert!(!is_pruned(None));
    }

    #[test]
    fn rejects_unsupported_lockfile_names() {
        let err = parse(Path::new("/tmp/package-lock.json"));
        assert!(matches!(err, Err(Error::Lockfile { .. })));
    }
}
