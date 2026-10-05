//! Machine-readable report.
//!
//! The [`Report`] type *is* the schema. There is no separate set of DTOs to keep
//! in sync, because triage already produces flat, presentation-ready values
//! (which is the reason `Finding` holds a `String` package name rather than a
//! nested domain object).

use std::io::Write;

use serde::Serialize;

use crate::error::Result;
use crate::progress::Delta;
use crate::triage::Report;

/// Machine-readable output.
///
/// Wrapped in an envelope with a `schema` version so a consumer can detect a
/// breaking change instead of silently misreading a renamed field.
#[derive(Serialize)]
struct Envelope<'a> {
    schema: u32,
    #[serde(flatten)]
    report: &'a Report,
    progress: &'a Delta,
}

/// Bumped when the JSON shape changes incompatibly.
const SCHEMA: u32 = 1;

pub fn render(out: &mut dyn Write, report: &Report, delta: &Delta) -> Result<()> {
    let envelope = Envelope {
        schema: SCHEMA,
        report,
        progress: delta,
    };
    serde_json::to_writer_pretty(&mut *out, &envelope)
        .map_err(|e| crate::error::Error::Output(e.into()))?;
    writeln!(out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use semver::Version;
    use serde_json::Value;

    use crate::domain::{Ecosystem, Effort, Origin, Provenance, Rating, Severity};

    fn pulse_effort() -> Effort {
        // 0.1.44 → 0.2.23 is breaking under Cargo's 0.x rules.
        Effort::Breaking
    }
    use crate::progress::Delta;
    use crate::triage::{Finding, Fix, Priority, Report, Summary};

    fn sample() -> Report {
        Report {
            projects: vec!["demo".into()],
            findings: vec![Finding {
                project: "demo".into(),
                ecosystem: Ecosystem::CratesIo,
                package: "time".into(),
                version: Version::parse("0.1.44").unwrap(),
                advisory: "RUSTSEC-2020-0071".into(),
                aliases: vec!["CVE-2020-26235".into()],
                summary: Some("Potential segfault in the time crate".into()),
                details: Some(
                    "### Impact\n\nThe affected functions set environment variables.".into(),
                ),
                age_days: Some(1900),
                severity: Severity {
                    rating: Rating::Medium,
                    score: Some(6.2),
                    vector: Some("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H".into()),
                    provenance: Provenance::Cvss3,
                },
                origin: Origin::Transitive {
                    depth: 2,
                    path: vec!["chrono".into(), "time".into()],
                },
                informational: None,
                fix: Fix::Available {
                    version: Version::parse("0.2.23").unwrap(),
                },
                effort: Some(pulse_effort()),
                remediation: Some("edit Cargo.toml: time = \"0.2\"".into()),
                affected_functions: vec!["time::at".into()],
                priority: Priority::Plan,
                rationale: "medium severity (CVSS 6.2), upgrade to 0.2.23 or later".into(),
                url: "https://osv.dev/vulnerability/RUSTSEC-2020-0071".into(),
            }],
            summary: Summary {
                projects: 1,
                packages_scanned: 42,
                findings: 1,
                plan: 1,
                medium: 1,
                ..Summary::default()
            },
            skipped_projects: Vec::new(),
        }
    }

    fn delta() -> Delta {
        Delta {
            fixed: vec!["app|a|ADV-a".into()],
            introduced: vec![],
            carried: 1,
            last_run: Some("2026-08-20".into()),
            days_since: Some(4),
            lifetime_fixed: 7,
            first_run: false,
        }
    }

    fn render_to_value(report: &Report) -> Value {
        let mut buffer = Vec::new();
        super::render(&mut buffer, report, &delta()).unwrap();
        serde_json::from_slice(&buffer).expect("output must be valid JSON")
    }

    #[test]
    fn emits_the_documented_schema() {
        let value = render_to_value(&sample());
        let finding = &value["findings"][0];

        assert_eq!(finding["package"], "time");
        assert_eq!(finding["version"], "0.1.44");
        assert_eq!(finding["advisory"], "RUSTSEC-2020-0071");
        assert_eq!(finding["priority"], "plan");
        assert_eq!(finding["ecosystem"], "crates_io");

        // Severity ships with its provenance so a consumer can tell a computed
        // score from a vendor's assertion.
        assert_eq!(finding["severity"]["rating"], "medium");
        assert_eq!(finding["severity"]["score"], 6.2);
        assert_eq!(finding["severity"]["provenance"], "cvss3");

        // Fix and origin are tagged unions, not bare strings.
        assert_eq!(finding["fix"]["status"], "available");
        assert_eq!(finding["fix"]["version"], "0.2.23");
        assert_eq!(finding["origin"]["kind"], "transitive");
        assert_eq!(finding["origin"]["depth"], 2);

        assert_eq!(value["summary"]["packages_scanned"], 42);
        assert_eq!(value["summary"]["plan"], 1);
        // Progress is real deltas, not points.
        assert_eq!(value["progress"]["lifetime_fixed"], 7);
        assert_eq!(value["progress"]["days_since"], 4);
        // Every counter is always present, so consumers need no null handling.
        assert_eq!(value["summary"]["act"], 0);
        assert_eq!(value["summary"]["unpatchable_severe"], 0);
    }

    #[test]
    fn round_trips_through_serde() {
        let report = sample();
        let mut buffer = Vec::new();
        super::render(&mut buffer, &report, &delta()).unwrap();
        let parsed: Report = serde_json::from_slice(&buffer).unwrap();
        assert_eq!(parsed, report);
    }

    #[test]
    fn clean_report_still_emits_all_keys() {
        let value = render_to_value(&Report::default());
        assert!(value["findings"].is_array());
        assert_eq!(value["findings"].as_array().unwrap().len(), 0);
        assert_eq!(value["summary"]["findings"], 0);
    }
}
