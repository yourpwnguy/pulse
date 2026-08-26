//! The domain: types with no knowledge of files, sockets, or terminals.
//!
//! Everything in here is pure data plus the logic that belongs to it. Nothing in
//! this module reads a file or opens a connection, which is what makes the
//! interesting logic — version-range matching, CVSS scoring, prioritisation —
//! testable without fixtures, mocks, or a network.

pub mod advisory;
pub mod age;
pub mod effort;
pub mod package;
pub mod project;
pub mod severity;

pub use advisory::{Advisory, AffectedInterval, AffectedRange, Bound};
pub use age::{days_since, Date};
pub use effort::{remediation, Effort};
pub use package::{Ecosystem, Origin, Package};
pub use project::{Project, ResolvedPackage};
pub use severity::{Provenance, Rating, Severity};
