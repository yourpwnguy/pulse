//! A scanned project and its resolved dependency set.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::package::{Ecosystem, Origin, Package};

/// A package as it appears in one project's lockfile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedPackage {
    pub package: Package,
    pub origin: Origin,
}

/// One project: a lockfile, and everything it resolves to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Project {
    /// Display name, taken from the workspace root package where possible and
    /// falling back to the containing directory.
    pub name: String,
    /// Directory containing the lockfile.
    pub root: PathBuf,
    pub lockfile: PathBuf,
    pub ecosystem: Ecosystem,
    pub packages: Vec<ResolvedPackage>,
    /// Packages skipped because a vulnerability database cannot identify them:
    /// git and path dependencies have no registry coordinates. Counted and
    /// reported rather than silently dropped, because "0 findings" means
    /// something different when part of the tree was never examined.
    pub unscannable: Vec<String>,
}

impl Project {
    /// Number of packages actually submitted for advisory lookup.
    pub fn scanned_count(&self) -> usize {
        self.packages.len()
    }

    pub fn direct_count(&self) -> usize {
        self.packages
            .iter()
            .filter(|p| p.origin.is_direct())
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use semver::Version;

    fn resolved(name: &str, origin: Origin) -> ResolvedPackage {
        ResolvedPackage {
            package: Package::new(Ecosystem::CratesIo, name, Version::new(1, 0, 0)),
            origin,
        }
    }

    #[test]
    fn counts_split_direct_from_transitive() {
        let project = Project {
            name: "demo".into(),
            root: PathBuf::from("/tmp/demo"),
            lockfile: PathBuf::from("/tmp/demo/Cargo.lock"),
            ecosystem: Ecosystem::CratesIo,
            packages: vec![
                resolved("serde", Origin::Direct),
                resolved("clap", Origin::Direct),
                resolved(
                    "time",
                    Origin::Transitive {
                        depth: 2,
                        path: vec!["chrono".into(), "time".into()],
                    },
                ),
            ],
            unscannable: vec!["local-helper".into()],
        };

        assert_eq!(project.scanned_count(), 3);
        assert_eq!(project.direct_count(), 2);
        assert_eq!(project.unscannable.len(), 1);
    }
}
