//! Severity, modelled as a *fact with provenance*.
//!
//! The reference implementation read severity from `database_specific.severity`
//! and gave up if it was absent. That field is absent from essentially every
//! RustSec advisory, so severity silently became "unknown", which the scorer
//! then weighted as zero risk. A project full of real advisories scored a
//! perfect 100.
//!
//! The fix is to compute the severity from the CVSS vector that OSV actually
//! ships in `severity[]`, and to record *where the number came from* so a
//! reader can audit it. A severity without provenance is not evidence.

use serde::{Deserialize, Serialize};

/// Qualitative severity band.
///
/// `Ord` runs `Unknown < None < Low < Medium < High < Critical` so that
/// "worst finding" comparisons work. `Unknown` sorting lowest is a *display*
/// convenience, not a risk judgement: [`crate::triage`] never treats an
/// unknown-severity advisory as safe, and the summary always reports the
/// unknown count separately so it cannot be silently dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Rating {
    Unknown,
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Rating {
    /// CVSS v3.1 qualitative bands (specification table 14).
    pub fn from_score(score: f64) -> Rating {
        if score <= 0.0 {
            Rating::None
        } else if score < 4.0 {
            Rating::Low
        } else if score < 7.0 {
            Rating::Medium
        } else if score < 9.0 {
            Rating::High
        } else {
            Rating::Critical
        }
    }

    /// Parses a database-supplied severity word.
    ///
    /// GitHub advisories say `MODERATE` where CVSS says `MEDIUM`; treating
    /// those as different buckets (as the reference implementation did) drops
    /// every GHSA medium on the floor.
    pub fn from_word(word: &str) -> Rating {
        match word.trim().to_ascii_uppercase().as_str() {
            "CRITICAL" => Rating::Critical,
            "HIGH" | "IMPORTANT" => Rating::High,
            "MEDIUM" | "MODERATE" => Rating::Medium,
            "LOW" | "MINOR" => Rating::Low,
            "NONE" | "INFORMATIONAL" => Rating::None,
            _ => Rating::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Rating::Critical => "critical",
            Rating::High => "high",
            Rating::Medium => "medium",
            Rating::Low => "low",
            Rating::None => "none",
            Rating::Unknown => "unknown",
        }
    }
}

/// Where a [`Severity`] came from. Displayed alongside the score so the user
/// can tell a computed CVSS base score from a vendor's opinion from a guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    /// Base score computed locally from a CVSS v3.x vector.
    Cvss3,
    /// Taken verbatim from the advisory database's own severity word.
    Database,
    /// A vector we do not score (e.g. CVSS v4.0) or nothing usable at all.
    Unrated,
}

impl Provenance {
    pub fn as_str(self) -> &'static str {
        match self {
            Provenance::Cvss3 => "cvss:3.x",
            Provenance::Database => "database",
            Provenance::Unrated => "unrated",
        }
    }
}

/// A severity judgement together with the evidence behind it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Severity {
    pub rating: Rating,
    /// Numeric CVSS base score, when we computed one.
    pub score: Option<f64>,
    /// The raw vector string, kept so the user can verify our arithmetic or
    /// score a version we do not support themselves.
    pub vector: Option<String>,
    pub provenance: Provenance,
}

impl Severity {
    pub fn unrated() -> Severity {
        Severity {
            rating: Rating::Unknown,
            score: None,
            vector: None,
            provenance: Provenance::Unrated,
        }
    }

    /// Derives a severity from the two signals OSV actually provides.
    ///
    /// A locally computed CVSS base score wins over the database's word: it is
    /// reproducible, auditable, and finer-grained. The word is the fallback for
    /// advisories that ship no vector, or a vector version we decline to score.
    pub fn resolve(vectors: &[String], database_word: Option<&str>) -> Severity {
        for vector in vectors {
            if let Some(score) = cvss3_base_score(vector) {
                return Severity {
                    rating: Rating::from_score(score),
                    score: Some(score),
                    vector: Some(vector.clone()),
                    provenance: Provenance::Cvss3,
                };
            }
        }

        if let Some(word) = database_word {
            let rating = Rating::from_word(word);
            if rating != Rating::Unknown {
                return Severity {
                    rating,
                    score: None,
                    // Surface an unscored vector (CVSS v4.0) if one exists, so
                    // the information is not lost just because we can't score it.
                    vector: vectors.first().cloned(),
                    provenance: Provenance::Database,
                };
            }
        }

        Severity {
            rating: Rating::Unknown,
            score: None,
            vector: vectors.first().cloned(),
            provenance: Provenance::Unrated,
        }
    }
}

/// Computes the CVSS v3.0/v3.1 **base** score from a vector string.
///
/// Implements the specification's base-score equations directly, including the
/// v3.1 `Roundup`. Returns `None` for anything that is not a well-formed v3.x
/// vector with all eight base metrics present — notably CVSS v4.0, whose
/// scoring is a large interpolation table we deliberately do not implement.
/// Refusing to score is better than inventing a number.
pub fn cvss3_base_score(vector: &str) -> Option<f64> {
    let mut parts = vector.split('/');
    match parts.next()? {
        "CVSS:3.0" | "CVSS:3.1" => {}
        _ => return None,
    }

    let mut av: Option<f64> = None;
    let mut ac: Option<f64> = None;
    // Privileges Required is stored raw: its weight depends on Scope, which may
    // appear later in the vector.
    let mut pr: Option<&str> = None;
    let mut ui: Option<f64> = None;
    let mut scope_changed: Option<bool> = None;
    let mut c: Option<f64> = None;
    let mut i: Option<f64> = None;
    let mut a: Option<f64> = None;

    for part in parts {
        let (metric, value) = part.split_once(':')?;
        match metric {
            "AV" => {
                av = Some(match value {
                    "N" => 0.85,
                    "A" => 0.62,
                    "L" => 0.55,
                    "P" => 0.20,
                    _ => return None,
                })
            }
            "AC" => {
                ac = Some(match value {
                    "L" => 0.77,
                    "H" => 0.44,
                    _ => return None,
                })
            }
            // Privileges Required is the one metric whose weights depend on
            // Scope, so it is stored raw and resolved after the loop.
            "PR" => {
                pr = Some(match value {
                    "N" | "L" | "H" => value,
                    _ => return None,
                })
            }
            "UI" => {
                ui = Some(match value {
                    "N" => 0.85,
                    "R" => 0.62,
                    _ => return None,
                })
            }
            "S" => {
                scope_changed = Some(match value {
                    "U" => false,
                    "C" => true,
                    _ => return None,
                })
            }
            "C" | "I" | "A" => {
                let weight = match value {
                    "H" => 0.56,
                    "L" => 0.22,
                    "N" => 0.0,
                    _ => return None,
                };
                match metric {
                    "C" => c = Some(weight),
                    "I" => i = Some(weight),
                    _ => a = Some(weight),
                }
            }
            // Temporal and environmental metrics do not affect the base score.
            _ => {}
        }
    }

    let (av, ac, ui) = (av?, ac?, ui?);
    let (changed, c, i, a) = (scope_changed?, c?, i?, a?);
    let pr = match (pr?, changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.50,
        _ => return None,
    };

    let iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));
    let impact = if changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };

    if impact <= 0.0 {
        return Some(0.0);
    }

    let exploitability = 8.22 * av * ac * pr * ui;
    let raw = if changed {
        1.08 * (impact + exploitability)
    } else {
        impact + exploitability
    };

    Some(roundup(raw.min(10.0)))
}

/// The CVSS v3.1 `Roundup` function: the smallest one-decimal value greater
/// than or equal to the input. Integer arithmetic, because the specification
/// says so — naive `(x * 10).ceil() / 10.0` gives the wrong answer for inputs
/// that floating point represents just below an exact tenth.
fn roundup(input: f64) -> f64 {
    let scaled = (input * 100_000.0).round() as i64;
    if scaled % 10_000 == 0 {
        scaled as f64 / 100_000.0
    } else {
        ((scaled / 10_000) + 1) as f64 / 10.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectors and expected scores taken from the CVSS v3.1 specification
    /// examples and from NVD entries, so these tests fail if the arithmetic
    /// drifts.
    #[test]
    fn scores_known_vectors() {
        let cases = [
            // CVE-2020-26235 (RUSTSEC-2020-0071), the advisory that exposed
            // the reference implementation's severity bug.
            ("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 6.2),
            // Worst case: remote, unauthenticated, total compromise.
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            // Scope change raises the score above the unchanged equivalent.
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
            ("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 2.0),
            ("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H", 7.5),
        ];

        for (vector, expected) in cases {
            let got = cvss3_base_score(vector).expect("vector should score");
            assert!(
                (got - expected).abs() < f64::EPSILON,
                "{vector}: expected {expected}, got {got}"
            );
        }
    }

    #[test]
    fn zero_impact_scores_zero() {
        let v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N";
        assert_eq!(cvss3_base_score(v), Some(0.0));
        assert_eq!(Rating::from_score(0.0), Rating::None);
    }

    #[test]
    fn refuses_unsupported_and_malformed_vectors() {
        // CVSS v4.0 is parseable but we do not implement its scoring.
        assert_eq!(
            cvss3_base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"),
            None
        );
        // Missing the Availability metric entirely.
        assert_eq!(
            cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"),
            None
        );
        assert_eq!(cvss3_base_score("not a vector"), None);
        assert_eq!(cvss3_base_score(""), None);
        // Unknown metric value must fail rather than silently default.
        assert_eq!(
            cvss3_base_score("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            None
        );
    }

    #[test]
    fn rating_bands_match_specification() {
        assert_eq!(Rating::from_score(0.0), Rating::None);
        assert_eq!(Rating::from_score(0.1), Rating::Low);
        assert_eq!(Rating::from_score(3.9), Rating::Low);
        assert_eq!(Rating::from_score(4.0), Rating::Medium);
        assert_eq!(Rating::from_score(6.9), Rating::Medium);
        assert_eq!(Rating::from_score(7.0), Rating::High);
        assert_eq!(Rating::from_score(8.9), Rating::High);
        assert_eq!(Rating::from_score(9.0), Rating::Critical);
        assert_eq!(Rating::from_score(10.0), Rating::Critical);
    }

    #[test]
    fn github_moderate_is_medium() {
        assert_eq!(Rating::from_word("MODERATE"), Rating::Medium);
        assert_eq!(Rating::from_word("moderate"), Rating::Medium);
        assert_eq!(Rating::from_word("MEDIUM"), Rating::Medium);
        assert_eq!(Rating::from_word("nonsense"), Rating::Unknown);
    }

    #[test]
    fn computed_cvss_beats_database_word() {
        // Vector says 9.8 critical; database claims "LOW". We trust the vector
        // and record that we computed it.
        let vectors = vec!["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()];
        let severity = Severity::resolve(&vectors, Some("LOW"));
        assert_eq!(severity.rating, Rating::Critical);
        assert_eq!(severity.score, Some(9.8));
        assert_eq!(severity.provenance, Provenance::Cvss3);
    }

    #[test]
    fn falls_back_to_database_word_then_unrated() {
        let severity = Severity::resolve(&[], Some("HIGH"));
        assert_eq!(severity.rating, Rating::High);
        assert_eq!(severity.provenance, Provenance::Database);

        let severity = Severity::resolve(&[], None);
        assert_eq!(severity.rating, Rating::Unknown);
        assert_eq!(severity.provenance, Provenance::Unrated);
    }

    #[test]
    fn unscorable_vector_is_still_reported_to_the_user() {
        // We can't score CVSS v4.0, but we must not throw the vector away.
        let vectors = vec!["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H".to_string()];
        let severity = Severity::resolve(&vectors, Some("CRITICAL"));
        assert_eq!(severity.rating, Rating::Critical);
        assert_eq!(severity.provenance, Provenance::Database);
        assert!(severity.vector.is_some());
    }

    #[test]
    fn rating_orders_critical_highest_and_unknown_lowest() {
        let mut ratings = [
            Rating::High,
            Rating::Unknown,
            Rating::Critical,
            Rating::Low,
            Rating::None,
            Rating::Medium,
        ];
        ratings.sort();
        assert_eq!(
            ratings,
            [
                Rating::Unknown,
                Rating::None,
                Rating::Low,
                Rating::Medium,
                Rating::High,
                Rating::Critical
            ]
        );
    }
}
