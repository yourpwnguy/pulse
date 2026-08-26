//! How much work a fix actually is.
//!
//! "A patch exists" is not the same as "you can ship it this afternoon". Under
//! Cargo's semver rules a `0.103.9 → 0.103.13` bump is a one-line no-op, while
//! `0.1.44 → 0.2.23` is a breaking change, because for `0.x` releases the *minor*
//! component is the compatibility axis. No scanner tells you which one you are
//! looking at, and it is the difference between a five-minute task and an
//! afternoon.
//!
//! This is also what makes the "quick win" mechanic honest: the tool can promise
//! an easy victory only because it can prove the upgrade is compatible.

use semver::Version;
use serde::{Deserialize, Serialize};

/// Effort required to apply a fix, derived purely from the two versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effort {
    /// Semver-compatible patch bump. `cargo update` and you are done.
    Trivial,
    /// Semver-compatible minor bump. Should be a drop-in.
    Compatible,
    /// Breaking under Cargo's rules: a new major, or a new minor on `0.x`.
    Breaking,
}

impl Effort {
    /// Classifies the jump from `current` to `fix`.
    pub fn classify(current: &Version, fix: &Version) -> Effort {
        if fix.major != current.major {
            return Effort::Breaking;
        }

        // Cargo treats 0.x.y as "minor is breaking": 0.1 and 0.2 are
        // incompatible, but 0.1.1 and 0.1.9 are not.
        if current.major == 0 {
            return if fix.minor == current.minor {
                Effort::Trivial
            } else {
                Effort::Breaking
            };
        }

        if fix.minor == current.minor {
            Effort::Trivial
        } else {
            Effort::Compatible
        }
    }

    /// True when `cargo update` alone can perform the upgrade.
    pub fn is_compatible(self) -> bool {
        matches!(self, Effort::Trivial | Effort::Compatible)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Effort::Trivial => "trivial",
            Effort::Compatible => "compatible",
            Effort::Breaking => "breaking",
        }
    }

    /// Short label for the report.
    pub fn label(self) -> &'static str {
        match self {
            Effort::Trivial => "quick win",
            Effort::Compatible => "drop-in",
            Effort::Breaking => "breaking",
        }
    }
}

/// The command (or instruction) that applies a fix.
///
/// Concrete and copy-pasteable. A finding that tells you what to *run* is
/// finished work; a finding that tells you what is *wrong* is homework.
pub fn remediation(package: &str, current: &Version, fix: &Version, direct: bool) -> String {
    match Effort::classify(current, fix) {
        Effort::Trivial | Effort::Compatible => format!("cargo update -p {package}"),
        Effort::Breaking if direct => {
            format!(
                "edit Cargo.toml: {package} = \"{}\"",
                compat_requirement(fix)
            )
        }
        // A breaking bump of something you don't declare cannot be fixed locally:
        // the parent has to move first.
        Effort::Breaking => format!("needs upstream: {package} {fix} is a breaking bump"),
    }
}

/// The version requirement a person would actually write in `Cargo.toml`.
fn compat_requirement(fix: &Version) -> String {
    if fix.major == 0 {
        format!("0.{}", fix.minor)
    } else {
        fix.major.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn patch_bumps_are_trivial() {
        // The real rustls-webpki case.
        assert_eq!(
            Effort::classify(&v("0.103.9"), &v("0.103.13")),
            Effort::Trivial
        );
        assert_eq!(Effort::classify(&v("1.2.3"), &v("1.2.9")), Effort::Trivial);
    }

    #[test]
    fn minor_bumps_are_compatible_above_one_zero() {
        assert_eq!(
            Effort::classify(&v("1.2.3"), &v("1.5.0")),
            Effort::Compatible
        );
    }

    #[test]
    fn minor_bumps_below_one_zero_are_breaking() {
        // The real `time` case: 0.1 → 0.2 is a breaking change in Cargo.
        assert_eq!(
            Effort::classify(&v("0.1.44"), &v("0.2.23")),
            Effort::Breaking
        );
        assert_eq!(
            Effort::classify(&v("0.4.19"), &v("0.5.0")),
            Effort::Breaking
        );
    }

    #[test]
    fn major_bumps_are_breaking() {
        assert_eq!(Effort::classify(&v("1.2.3"), &v("2.0.0")), Effort::Breaking);
        assert_eq!(Effort::classify(&v("0.9.0"), &v("1.0.0")), Effort::Breaking);
    }

    #[test]
    fn compatible_upgrades_get_a_runnable_command() {
        assert_eq!(
            remediation("rustls-webpki", &v("0.103.9"), &v("0.103.13"), false),
            "cargo update -p rustls-webpki"
        );
    }

    #[test]
    fn breaking_direct_upgrades_get_a_manifest_edit() {
        assert_eq!(
            remediation("time", &v("0.1.44"), &v("0.2.23"), true),
            "edit Cargo.toml: time = \"0.2\""
        );
        assert_eq!(
            remediation("foo", &v("1.0.0"), &v("2.1.0"), true),
            "edit Cargo.toml: foo = \"2\""
        );
    }

    #[test]
    fn breaking_transitive_upgrades_name_the_real_blocker() {
        let advice = remediation("time", &v("0.1.44"), &v("0.2.23"), false);
        assert!(advice.contains("upstream"));
    }

    #[test]
    fn compatibility_predicate_matches_classification() {
        assert!(Effort::Trivial.is_compatible());
        assert!(Effort::Compatible.is_compatible());
        assert!(!Effort::Breaking.is_compatible());
    }

    #[test]
    fn effort_orders_easiest_first() {
        let mut efforts = [Effort::Breaking, Effort::Trivial, Effort::Compatible];
        efforts.sort();
        assert_eq!(
            efforts,
            [Effort::Trivial, Effort::Compatible, Effort::Breaking]
        );
    }
}
