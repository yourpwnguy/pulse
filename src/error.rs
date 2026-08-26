//! The crate's error surface.
//!
//! Hand-rolled rather than pulled from `anyhow`/`thiserror`: there are six
//! failure modes, they are all known at compile time, and callers benefit
//! from being able to `match` on them (`main` maps them to exit codes).
//! A dependency would buy nothing here.

use std::fmt;
use std::io;
use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    /// A path given on the command line does not exist or cannot be walked.
    Discovery { path: PathBuf, source: io::Error },
    /// A lockfile was found but could not be read.
    Read { path: PathBuf, source: io::Error },
    /// A lockfile was read but is not valid for its format.
    Lockfile { path: PathBuf, reason: String },
    /// The advisory database could not be reached or returned garbage.
    Advisory(String),
    /// Rendering the report to the output stream failed (e.g. broken pipe).
    Output(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Discovery { path, source } => {
                write!(f, "cannot scan {}: {source}", path.display())
            }
            Error::Read { path, source } => {
                write!(f, "cannot read {}: {source}", path.display())
            }
            Error::Lockfile { path, reason } => {
                write!(f, "malformed lockfile {}: {reason}", path.display())
            }
            Error::Advisory(reason) => write!(f, "advisory lookup failed: {reason}"),
            Error::Output(source) => write!(f, "cannot write report: {source}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Discovery { source, .. } | Error::Read { source, .. } => Some(source),
            Error::Output(source) => Some(source),
            Error::Lockfile { .. } | Error::Advisory(_) => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(source: io::Error) -> Self {
        Error::Output(source)
    }
}
