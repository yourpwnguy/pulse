//! Human-readable report rendering.
//!
//! ## Shape
//!
//! ```text
//! ♡ pulse   7 issues · 6 fixable now · 1 blocked · worst 7.5 high · oldest 158d
//!           2 fixed since Tuesday · 1 new
//!
//! ▸ cargo update -p rustls-webpki                          fixes 4 of 7
//!
//! ◆ fix now
//!   rustls-webpki 0.103.9 → 0.103.13   quick    4 issues   via ureq → rustls
//!     high 7.5  DoS via panic on malformed CRL      GHSA-82j2-j2ch-gfr8   123d
//! ```
//!
//! ## Why it looks like this
//!
//! * **Real numbers only.** Every value in the status line changes a decision:
//!   how many, how many you can fix *right now*, how bad the worst one is, how
//!   long you have been exposed. An earlier version showed XP and a level here;
//!   those were a scoreboard about the work rather than a view of it.
//! * **Momentum, not points.** `2 fixed since Tuesday` is the motivating line,
//!   because it is true and it is caused by the reader.
//! * **Full width.** Widths come from [`Layout`], so a wide terminal gets wider
//!   columns instead of a wasted right margin and a longer scroll.
//! * **No boxes.** Borders cost four columns on every row and force content
//!   narrower than the terminal. Indentation cannot misalign and costs nothing.
//! * **Bounded height.** `--full` shows a capped excerpt, not the entire advisory:
//!   one finding used to print 75 lines, which is not a report.

mod action;
mod group;
mod header;
mod hints;
pub(crate) mod sections;
pub(crate) mod wrap;

use std::io::Write;

use crate::domain::Rating;
use crate::error::Result;
use crate::progress::{Delta, Headline};
use crate::triage::{Priority, Report};

use super::layout::Layout;
use super::line::{truncate, Line};
use super::mascot::Mood;
use super::style::Style;

/// What to show. Each field maps to exactly one flag.
#[derive(Debug, Clone, Copy, Default)]
pub struct View {
    /// `--full`: a capped excerpt of each advisory plus its link.
    pub full: bool,
    /// Set when `--fix` has already run in this invocation.
    ///
    /// Changes the closing suggestion: telling someone to run `--fix` immediately
    /// after `--fix` failed is worse than saying nothing, because it implies the
    /// tool did not notice.
    pub after_fix: bool,
}

pub fn render(
    out: &mut dyn Write,
    report: &Report,
    delta: &Delta,
    layout: Layout,
    style: Style,
    view: View,
) -> Result<()> {
    let headline = Headline::of(report);
    let critical = report
        .findings
        .iter()
        .filter(|f| f.severity.rating == Rating::Critical)
        .count();
    let all_fixable = headline.issues > 0 && headline.fixable == headline.issues;
    let mood = Mood::from_report(
        headline.issues,
        headline.blocked,
        critical,
        all_fixable,
        delta.fixed.len(),
    );

    writeln!(out)?;
    header::header(out, report, &headline, delta, mood, layout, style)?;

    if report.is_clean() {
        clean(out, &headline, delta, layout, style)?;
    } else {
        action::action(out, report, &headline, layout, style, view)?;
        for bucket in [
            Priority::Act,
            Priority::Plan,
            Priority::Monitor,
            Priority::Note,
        ] {
            sections::section(out, report, bucket, layout, style, view)?;
        }
    }

    hints::caveats(out, report, layout, style)?;
    hints::hint(out, report, &headline, layout, style, view)?;
    Ok(())
}

/// The clean state. Says what was verified, because unexamined silence and
/// verified safety otherwise look identical.
fn clean(
    out: &mut dyn Write,
    headline: &Headline,
    delta: &Delta,
    layout: Layout,
    style: Style,
) -> Result<()> {
    let mut text = format!(
        "{} {} checked against OSV · nothing to fix",
        headline.packages,
        plural(headline.packages, "package", "packages")
    );
    if delta.lifetime_fixed > 0 {
        text.push_str(&format!(" · {} resolved all time", delta.lifetime_fixed));
    }

    writeln!(
        out,
        "{}",
        Line::indent(2).dim(style, &truncate(&text, layout.body()))
    )?;
    writeln!(out)?;
    Ok(())
}

fn plural(count: usize, one: &str, many: &str) -> String {
    if count == 1 { one } else { many }.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Ecosystem, Effort, Origin, Provenance, Severity};
    use crate::triage::{Finding, Fix, Summary};
    use semver::Version;
    use unicode_width::UnicodeWidthStr;

    fn finding(package: &str, effort: Option<Effort>, command: Option<&str>) -> Finding {
        Finding {
            project: "app".into(),
            ecosystem: Ecosystem::CratesIo,
            package: package.into(),
            version: Version::new(1, 0, 0),
            advisory: format!("ADV-{package}"),
            aliases: vec![],
            summary: Some("a summary of the problem".into()),
            details: None,
            age_days: Some(42),
            severity: Severity {
                rating: Rating::High,
                score: Some(7.5),
                vector: None,
                provenance: Provenance::Cvss3,
            },
            informational: None,
            origin: Origin::Direct,
            fix: match effort {
                Some(_) => Fix::Available {
                    version: Version::new(1, 0, 5),
                },
                None => Fix::Unavailable,
            },
            effort,
            remediation: command.map(str::to_string),
            affected_functions: vec![],
            priority: Priority::Act,
            rationale: String::new(),
            url: "https://osv.dev/x".into(),
        }
    }

    fn report(findings: Vec<Finding>) -> Report {
        Report {
            projects: vec!["app".into()],
            summary: Summary {
                projects: 1,
                packages_scanned: 42,
                ..Summary::default()
            },
            findings,
            skipped_projects: vec![],
        }
    }

    fn show(report: &Report, layout: Layout, view: View) -> String {
        let mut buffer = Vec::new();
        render(
            &mut buffer,
            report,
            &Delta::default(),
            layout,
            Style::Plain,
            view,
        )
        .unwrap();
        String::from_utf8(buffer).unwrap()
    }

    fn widest(text: &str) -> usize {
        text.lines().map(UnicodeWidthStr::width).max().unwrap_or(0)
    }

    #[test]
    fn nothing_exceeds_the_terminal_width() {
        let mut long = finding(
            "a-package-with-a-very-long-name",
            Some(Effort::Trivial),
            Some("cargo update -p a-package-with-a-very-long-name"),
        );
        long.summary = Some("an extremely long advisory summary that goes on well past any reasonable column limit and keeps going".into());
        long.advisory = "GHSA-aaaa-bbbb-cccc-dddd".into();

        for columns in [56, 60, 80, 100, 120, 200] {
            let layout = Layout::of(columns);
            let text = show(&report(vec![long.clone()]), layout, View::default());
            let offender = text
                .lines()
                .max_by_key(|l| UnicodeWidthStr::width(*l))
                .unwrap_or_default();
            assert!(
                widest(&text) <= layout.total,
                "at {columns} columns a line reached {} (limit {}): {offender:?}",
                widest(&text),
                layout.total
            );
        }
    }

    #[test]
    fn the_clean_path_also_respects_the_width() {
        let mut empty = report(vec![]);
        empty.skipped_projects = vec![crate::triage::SkippedProject {
            name: "a-project-with-a-long-name".into(),
            reason: "ignored: some long pattern".into(),
        }];
        empty.summary.unrated = 3;
        empty.summary.packages_unscannable = 4;

        for columns in [56, 60, 80, 120] {
            let layout = Layout::of(columns);
            let mut buffer = Vec::new();
            render(
                &mut buffer,
                &empty,
                &Delta {
                    lifetime_fixed: 12345,
                    ..Delta::default()
                },
                layout,
                Style::Plain,
                View::default(),
            )
            .unwrap();
            let text = String::from_utf8(buffer).unwrap();
            let offender = text
                .lines()
                .max_by_key(|l| UnicodeWidthStr::width(*l))
                .unwrap_or_default();
            assert!(
                widest(&text) <= layout.total,
                "clean path at {columns} reached {} (limit {}): {offender:?}",
                widest(&text),
                layout.total
            );
        }
    }

    #[test]
    fn wide_terminals_get_wider_content_not_a_bigger_margin() {
        let f = finding("pkg", Some(Effort::Trivial), Some("cargo update -p pkg"));
        let narrow = widest(&show(
            &report(vec![f.clone()]),
            Layout::of(80),
            View::default(),
        ));
        let wide = widest(&show(&report(vec![f]), Layout::of(140), View::default()));
        assert!(wide > narrow, "wide={wide} narrow={narrow}");
    }

    #[test]
    fn full_output_stays_bounded() {
        let mut item = finding("pkg", Some(Effort::Trivial), Some("cargo update -p pkg"));
        item.details = Some(
            (0..200)
                .map(|i| format!("paragraph line number {i} with some words in it"))
                .collect::<Vec<_>>()
                .join("\n\n"),
        );

        let text = show(
            &report(vec![item]),
            Layout::of(100),
            View {
                full: true,
                after_fix: false,
            },
        );
        let lines = text.lines().count();
        assert!(lines <= 42, "--full produced {lines} lines");
        assert!(text.contains("more lines"), "must say what it withheld");
        assert!(text.contains("https://osv.dev/x"), "must link to the rest");
    }

    #[test]
    fn status_line_shows_only_decision_relevant_numbers() {
        let text = show(
            &report(vec![
                finding("a", Some(Effort::Trivial), Some("cargo update -p a")),
                finding("b", None, None),
            ]),
            Layout::of(120),
            View::default(),
        );
        assert!(text.contains("2 issues"));
        assert!(text.contains("1 fixable now"));
        assert!(text.contains("1 blocked"));
        assert!(text.contains("worst 7.5 high"));
        assert!(text.contains("1 of 2 fixable right now"));

        for banned in ["xp", "lv ", "level", "streak", "guardian", "badge"] {
            assert!(
                !text.contains(banned),
                "status line still mentions {banned:?}"
            );
        }
    }

    #[test]
    fn shows_exactly_one_command() {
        let text = show(
            &report(vec![
                finding("a", Some(Effort::Trivial), Some("cargo update -p shared")),
                finding("b", Some(Effort::Trivial), Some("cargo update -p shared")),
                finding("c", Some(Effort::Trivial), Some("cargo update -p other")),
            ]),
            Layout::of(100),
            View::default(),
        );
        assert_eq!(text.matches("▸ ").count(), 1);
        assert!(text.contains("fixes 2 of 3"));
    }

    #[test]
    fn one_package_many_advisories_is_one_block() {
        let mut second = finding("dup", Some(Effort::Trivial), Some("cargo update -p dup"));
        second.advisory = "ADV-second".into();
        let text = show(
            &report(vec![
                finding("dup", Some(Effort::Trivial), Some("cargo update -p dup")),
                second,
            ]),
            Layout::of(100),
            View::default(),
        );
        assert!(text.contains("2 issues"));
        assert_eq!(text.matches("cargo update -p dup").count(), 2);
    }

    #[test]
    fn breaking_changes_are_not_offered_as_a_command() {
        let text = show(
            &report(vec![finding(
                "t",
                Some(Effort::Breaking),
                Some("edit Cargo.toml"),
            )]),
            Layout::of(100),
            View::default(),
        );
        assert!(text.contains("breaking"));
        assert!(
            !text.contains("▸ "),
            "a decision must not be the hero action"
        );
    }

    #[test]
    fn the_suggestion_changes_after_a_failed_fix() {
        let r = report(vec![finding(
            "webpki",
            Some(Effort::Trivial),
            Some("cargo update -p webpki"),
        )]);

        let before = show(&r, Layout::of(100), View::default());
        assert!(before.contains("pulse --fix"));

        let after = show(
            &r,
            Layout::of(100),
            View {
                full: false,
                after_fix: true,
            },
        );
        assert!(!after.contains("pulse --fix"));
        assert!(after.contains("Cargo.toml is capping"));
        assert!(after.contains("cargo add webpki@1.0.5"));
    }

    #[test]
    fn blocked_findings_get_an_honest_suggestion() {
        let mut stuck = finding("stuck", None, None);
        stuck.priority = Priority::Monitor;
        let text = show(&report(vec![stuck]), Layout::of(100), View::default());
        assert!(text.contains("nothing to upgrade to yet"));
    }

    #[test]
    fn clean_report_says_what_was_verified() {
        let text = show(&report(vec![]), Layout::of(100), View::default());
        assert!(text.contains("all clear"));
        assert!(text.contains("42 packages checked"));
    }

    #[test]
    fn plain_style_emits_no_escapes() {
        let text = show(
            &report(vec![finding(
                "a",
                Some(Effort::Trivial),
                Some("cargo update -p a"),
            )]),
            Layout::of(100),
            View::default(),
        );
        assert!(!text.contains('\x1b'));
    }
}
