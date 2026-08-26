//! Package identity and how a package got into the tree.

use std::fmt;

use semver::Version;
use serde::{Deserialize, Serialize};

/// A packaging ecosystem, in OSV's naming.
///
/// An enum rather than the reference implementation's `String`: an ecosystem is
/// a closed set that the parser and the advisory client must agree on, and a
/// typo in a string is a silent no-results bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ecosystem {
    CratesIo,
}

impl Ecosystem {
    /// The identifier OSV expects in a query.
    pub fn as_osv(self) -> &'static str {
        match self {
            Ecosystem::CratesIo => "crates.io",
        }
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_osv())
    }
}

/// A resolved package: an exact name and version from a lockfile.
///
/// The version is a parsed [`Version`], not a string. Every interesting
/// question about a vulnerability ("am I past the fix?") is a version
/// comparison, and string comparison gets those wrong (`"0.10.0" < "0.9.0"`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Package {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: Version,
}

impl Package {
    pub fn new(ecosystem: Ecosystem, name: impl Into<String>, version: Version) -> Package {
        Package {
            ecosystem,
            name: name.into(),
            version,
        }
    }
}

impl fmt::Display for Package {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.name, self.version)
    }
}

/// How a package entered the dependency tree.
///
/// This is the axis that decides *who can fix it*, and it is the main thing
/// existing scanners bury. A vulnerable direct dependency is a one-line change
/// you own. A vulnerable dependency five levels down may require an upstream
/// maintainer to act first, which is a completely different piece of work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Origin {
    /// Named in a workspace member's own manifest. You control the version.
    Direct,
    /// Pulled in by something else. `path` is the shortest chain of package
    /// names from the direct dependency down to this package, so the report can
    /// say *"via chrono → time"* instead of leaving the user to run
    /// `cargo tree` themselves.
    Transitive { depth: usize, path: Vec<String> },
}

impl Origin {
    /// Distance from a workspace member. Direct dependencies are depth 1.
    pub fn depth(&self) -> usize {
        match self {
            Origin::Direct => 1,
            Origin::Transitive { depth, .. } => *depth,
        }
    }

    pub fn is_direct(&self) -> bool {
        matches!(self, Origin::Direct)
    }

    /// Renders the dependency chain for display, e.g. `chrono → time`.
    pub fn chain(&self) -> Option<String> {
        match self {
            Origin::Direct => None,
            Origin::Transitive { path, .. } if path.is_empty() => None,
            Origin::Transitive { path, .. } => Some(path.join(" → ")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_numerically_not_lexically() {
        let older = Version::parse("0.9.0").unwrap();
        let newer = Version::parse("0.10.0").unwrap();
        // The string comparison that a naive implementation would do is wrong.
        assert!("0.10.0" < "0.9.0");
        // The typed comparison is right.
        assert!(older < newer);
    }

    #[test]
    fn origin_reports_depth_and_chain() {
        assert_eq!(Origin::Direct.depth(), 1);
        assert!(Origin::Direct.is_direct());
        assert_eq!(Origin::Direct.chain(), None);

        let transitive = Origin::Transitive {
            depth: 2,
            path: vec!["chrono".into(), "time".into()],
        };
        assert_eq!(transitive.depth(), 2);
        assert!(!transitive.is_direct());
        assert_eq!(transitive.chain().unwrap(), "chrono → time");
    }

    #[test]
    fn ecosystem_uses_osv_identifier() {
        assert_eq!(Ecosystem::CratesIo.as_osv(), "crates.io");
    }
}
