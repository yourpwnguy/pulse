//! `Cargo.lock` → [`Project`], including the dependency graph.
//!
//! The graph is the part that matters. A lockfile is a flat list of packages
//! plus edges; the reference implementation kept only the list, which meant it
//! could tell you *that* `time 0.1.44` was vulnerable but not that it was there
//! because of `chrono`, nor whether you could fix it yourself. Walking the edges
//! costs one breadth-first search and turns a finding into an action.

use std::collections::{HashMap, VecDeque};
use std::path::Path;

use semver::Version;
use serde::Deserialize;

use crate::domain::{Ecosystem, Origin, Package, Project, ResolvedPackage};
use crate::error::{Error, Result};

/// Wire shape of `Cargo.lock`. Fields we don't use are ignored by serde.
#[derive(Debug, Deserialize)]
struct Lockfile {
    #[serde(default)]
    package: Vec<LockPackage>,
}

#[derive(Debug, Deserialize)]
struct LockPackage {
    name: String,
    version: String,
    /// Absent for workspace members and path dependencies; `registry+…` for
    /// crates.io; `git+…` for git dependencies.
    source: Option<String>,
    #[serde(default)]
    dependencies: Vec<String>,
}

impl LockPackage {
    /// Local code: a workspace member or a path dependency.
    ///
    /// `Cargo.lock` cannot tell these apart (neither has a `source`), but the
    /// distinction does not matter here, because both are the user's own code
    /// rather than a third-party dependency, and neither has registry
    /// coordinates to look up.
    fn is_local(&self) -> bool {
        self.source.is_none()
    }

    /// Only registry packages have coordinates a vulnerability database can
    /// resolve. Git dependencies are third-party code we genuinely cannot check,
    /// so they are reported as unscannable rather than quietly dropped.
    fn is_registry(&self) -> bool {
        self.source
            .as_deref()
            .is_some_and(|s| s.starts_with("registry+"))
    }
}

/// Parses a `Cargo.lock` into a project with origin information for every
/// registry package.
pub fn parse(path: &Path) -> Result<Project> {
    let text = std::fs::read_to_string(path).map_err(|source| Error::Read {
        path: path.to_path_buf(),
        source,
    })?;
    parse_str(&text, path)
}

/// The parsing logic proper, separated from the filesystem so tests can feed it
/// a string.
pub fn parse_str(text: &str, path: &Path) -> Result<Project> {
    let lockfile: Lockfile = toml::from_str(text).map_err(|e| Error::Lockfile {
        path: path.to_path_buf(),
        reason: e.message().to_string(),
    })?;

    let root = path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let name = project_name(&lockfile, &root);
    let origins = resolve_origins(&lockfile.package);

    let mut packages = Vec::new();
    let mut unscannable = Vec::new();

    for (index, entry) in lockfile.package.iter().enumerate() {
        if entry.is_local() {
            continue;
        }

        if !entry.is_registry() {
            unscannable.push(format!("{} {}", entry.name, entry.version));
            continue;
        }

        // A lockfile version that isn't semver can't be range-matched, so it
        // would produce meaningless results. Report it instead of guessing.
        let Ok(version) = Version::parse(&entry.version) else {
            unscannable.push(format!("{} {}", entry.name, entry.version));
            continue;
        };

        // A package unreachable from any workspace member is dead weight in the
        // lockfile (stale entry, or a target-specific dependency for another
        // platform). Treat it as deep transitive rather than dropping it.
        let origin = origins.get(&index).cloned().unwrap_or(Origin::Transitive {
            depth: usize::MAX,
            path: Vec::new(),
        });

        packages.push(ResolvedPackage {
            package: Package::new(Ecosystem::CratesIo, entry.name.clone(), version),
            origin,
        });
    }

    packages.sort_by(|a, b| a.package.cmp(&b.package));
    packages.dedup_by(|a, b| a.package == b.package);
    unscannable.sort();
    unscannable.dedup();

    Ok(Project {
        name,
        root,
        lockfile: path.to_path_buf(),
        ecosystem: Ecosystem::CratesIo,
        packages,
        unscannable,
    })
}

/// Names the project after its sole workspace member, falling back to the
/// directory. A multi-member workspace has no single sensible name, so the
/// directory wins.
fn project_name(lockfile: &Lockfile, root: &Path) -> String {
    let mut members = lockfile.package.iter().filter(|p| p.is_local());
    if let (Some(only), None) = (members.next(), members.next()) {
        return only.name.clone();
    }

    root.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string()
}

/// Breadth-first search from the workspace members, recording each package's
/// shortest distance and the chain that reached it.
///
/// BFS (not DFS) because we want the *shortest* explanation: if a package is
/// reachable both directly and through four intermediaries, the user cares that
/// they own it directly.
fn resolve_origins(packages: &[LockPackage]) -> HashMap<usize, Origin> {
    let by_name = index_by_name(packages);
    let mut origins: HashMap<usize, Origin> = HashMap::new();
    let mut queue: VecDeque<(usize, usize, Vec<String>)> = VecDeque::new();

    // Seed with the direct dependencies of every workspace member.
    for member in packages.iter().filter(|p| p.is_local()) {
        for dep in &member.dependencies {
            if let Some(index) = resolve_dependency(dep, &by_name, packages) {
                if origins.contains_key(&index) {
                    continue;
                }
                origins.insert(index, Origin::Direct);
                queue.push_back((index, 1, vec![packages[index].name.clone()]));
            }
        }
    }

    while let Some((index, depth, path)) = queue.pop_front() {
        for dep in &packages[index].dependencies {
            let Some(child) = resolve_dependency(dep, &by_name, packages) else {
                continue;
            };
            // First visit wins, and BFS guarantees the first visit is the
            // shortest path. This also terminates on cyclic dev-dependency
            // graphs, which Cargo permits.
            if origins.contains_key(&child) {
                continue;
            }

            let mut child_path = path.clone();
            child_path.push(packages[child].name.clone());
            origins.insert(
                child,
                Origin::Transitive {
                    depth: depth + 1,
                    path: child_path.clone(),
                },
            );
            queue.push_back((child, depth + 1, child_path));
        }
    }

    origins
}

fn index_by_name(packages: &[LockPackage]) -> HashMap<&str, Vec<usize>> {
    let mut map: HashMap<&str, Vec<usize>> = HashMap::new();
    for (index, package) in packages.iter().enumerate() {
        map.entry(package.name.as_str()).or_default().push(index);
    }
    map
}

/// Resolves a `dependencies` entry to a package index.
///
/// Cargo writes `"name"`, `"name version"`, or `"name version (source)"`
/// depending on whether the name alone is ambiguous in that lockfile.
fn resolve_dependency(
    spec: &str,
    by_name: &HashMap<&str, Vec<usize>>,
    packages: &[LockPackage],
) -> Option<usize> {
    let mut parts = spec.split_whitespace();
    let name = parts.next()?;
    let version = parts.next();

    let candidates = by_name.get(name)?;
    match version {
        // Disambiguated form: match the exact version.
        Some(version) => candidates
      .iter()
      .copied()
      .find(|&i| packages[i].version == version)
      // A version that doesn't match anything means a malformed lockfile;
      // fall back to the name so the package still appears in the graph.
      .or_else(|| candidates.first().copied()),
        None => candidates.first().copied(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const LOCKFILE: &str = r#"
version = 3

[[package]]
name = "demo"
version = "0.1.0"
dependencies = ["chrono", "serde"]

[[package]]
name = "chrono"
version = "0.4.19"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["time"]

[[package]]
name = "time"
version = "0.1.44"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["libc"]

[[package]]
name = "libc"
version = "0.2.150"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "local-helper"
version = "0.1.0"

[[package]]
name = "forked-thing"
version = "0.3.0"
source = "git+https://github.com/example/forked-thing#abc123"
"#;

    fn parse_fixture() -> Project {
        parse_str(LOCKFILE, &PathBuf::from("/tmp/demo/Cargo.lock")).unwrap()
    }

    fn origin_of<'a>(project: &'a Project, name: &str) -> &'a Origin {
        &project
            .packages
            .iter()
            .find(|p| p.package.name == name)
            .unwrap_or_else(|| panic!("{name} should be present"))
            .origin
    }

    #[test]
    fn names_project_after_its_sole_workspace_member() {
        assert_eq!(parse_fixture().name, "demo");
    }

    #[test]
    fn falls_back_to_directory_name_for_workspaces() {
        let workspace = r#"
[[package]]
name = "member-a"
version = "0.1.0"

[[package]]
name = "member-b"
version = "0.1.0"
"#;
        let project = parse_str(workspace, &PathBuf::from("/tmp/my-workspace/Cargo.lock")).unwrap();
        assert_eq!(project.name, "my-workspace");
    }

    #[test]
    fn classifies_direct_dependencies() {
        let project = parse_fixture();
        assert_eq!(origin_of(&project, "chrono"), &Origin::Direct);
        assert_eq!(origin_of(&project, "serde"), &Origin::Direct);
        assert_eq!(project.direct_count(), 2);
    }

    #[test]
    fn records_shortest_chain_for_transitive_dependencies() {
        let project = parse_fixture();

        assert_eq!(
            origin_of(&project, "time"),
            &Origin::Transitive {
                depth: 2,
                path: vec!["chrono".into(), "time".into()],
            }
        );
        assert_eq!(
            origin_of(&project, "time").chain().unwrap(),
            "chrono → time"
        );

        assert_eq!(
            origin_of(&project, "libc"),
            &Origin::Transitive {
                depth: 3,
                path: vec!["chrono".into(), "time".into(), "libc".into()],
            }
        );
    }

    #[test]
    fn excludes_local_code_and_reports_unscannable_dependencies() {
        let project = parse_fixture();

        // Cargo.lock cannot distinguish a workspace member from a path
        // dependency: both simply lack a `source`. Either way the code is the
        // user's own, not a third-party dependency, so it is excluded silently
        // rather than counted as a blind spot.
        assert!(!project.packages.iter().any(|p| p.package.name == "demo"));
        assert!(!project
            .packages
            .iter()
            .any(|p| p.package.name == "local-helper"));
        assert!(!project
            .unscannable
            .contains(&"local-helper 0.1.0".to_string()));

        // A git dependency *is* third-party code that no database can identify
        // by version. That is a genuine gap and must be surfaced.
        assert_eq!(project.unscannable, vec!["forked-thing 0.3.0".to_string()]);
    }

    #[test]
    fn prefers_direct_when_a_package_is_reachable_both_ways() {
        let lock = r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["wrapper", "leaf"]

[[package]]
name = "wrapper"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["leaf"]

[[package]]
name = "leaf"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
        let project = parse_str(lock, &PathBuf::from("/tmp/app/Cargo.lock")).unwrap();
        assert_eq!(origin_of(&project, "leaf"), &Origin::Direct);
    }

    #[test]
    fn terminates_on_cyclic_graphs() {
        // Cargo allows cycles through dev-dependencies. A naive walk hangs.
        let lock = r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["a"]

[[package]]
name = "a"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["b"]

[[package]]
name = "b"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["a"]
"#;
        let project = parse_str(lock, &PathBuf::from("/tmp/app/Cargo.lock")).unwrap();
        assert_eq!(project.packages.len(), 2);
        assert_eq!(origin_of(&project, "a"), &Origin::Direct);
        assert_eq!(origin_of(&project, "b").depth(), 2);
    }

    #[test]
    fn resolves_versioned_dependency_specs() {
        // Two versions of the same crate: the edge is disambiguated by version.
        let lock = r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["dup 2.0.0"]

[[package]]
name = "dup"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "dup"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
        let project = parse_str(lock, &PathBuf::from("/tmp/app/Cargo.lock")).unwrap();

        let v2 = project
            .packages
            .iter()
            .find(|p| p.package.version == Version::parse("2.0.0").unwrap())
            .unwrap();
        assert_eq!(v2.origin, Origin::Direct);

        // The unreferenced 1.0.0 is still scanned, just not marked reachable.
        let v1 = project
            .packages
            .iter()
            .find(|p| p.package.version == Version::parse("1.0.0").unwrap())
            .unwrap();
        assert!(!v1.origin.is_direct());
    }

    #[test]
    fn rejects_malformed_lockfiles() {
        let err = parse_str("this is not toml {{{", &PathBuf::from("/tmp/x/Cargo.lock"));
        assert!(matches!(err, Err(Error::Lockfile { .. })));
    }

    #[test]
    fn empty_lockfile_yields_no_packages() {
        let project = parse_str("version = 3\n", &PathBuf::from("/tmp/x/Cargo.lock")).unwrap();
        assert_eq!(project.scanned_count(), 0);
    }
}
