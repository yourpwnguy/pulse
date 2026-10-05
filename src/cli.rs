//! Command-line surface.
//!
//! Every flag here changes behaviour in a way you can observe, and each one is
//! there because it answers a question a person actually has. Three earlier flags
//! were removed rather than kept for symmetry:
//!
//! * `--no-rewards` (there are no rewards any more: the XP/level/streak display
//!   it hid was a scoreboard about the work rather than a view of it.
//! * `--no-history` (history is now just the baseline for *"2 fixed since
//!   Tuesday"*: turning it off removed information and gained nothing, so it is
//!   folded into `--no-save`, which is about not *writing*.
//! * `--fail-on` kept its outcome-word values (`urgent`/`fixable`/`anything`/
//!   `never`) because an earlier threshold-style version read backwards:
//!   `--fail-on monitor` sounded narrower than `--fail-on act` but was broader.
//!
//! Short flags follow one convention so they can be guessed: **lowercase asks for
//! more** (`-f` full, `-x` exclude, `-o` output) and **uppercase selects a mode or
//! switches something off** (`-P` projects, `-F` fail-on, `-C` no-colour).

use std::path::PathBuf;

use clap::{Parser, ValueEnum};

use crate::render::Format;
use crate::triage::Priority;

#[derive(Debug, Parser)]
#[command(
    name = "pulse",
    version,
    about = "A triage-first security tool that turns a wall of CVEs into a prioritized plan with severity ratings, fix effort estimates, and ready-to-run commands.",
    long_about = "pulse scans your locked dependencies for known vulnerabilities, \
ranks them by severity and fixability, and hands you the exact commands to resolve them.\n\n\
Run with no arguments to scan the current directory. Add --fix to apply every \
safe upgrade automatically."
)]
pub struct Cli {
    /// Directories or lockfiles to scan
    #[arg(value_name = "PATH", default_value = ".")]
    pub paths: Vec<PathBuf>,

    // ── Doing something about it ─────────────────────────────────────────────
    /// Apply every safe upgrade, then re-scan to show the result
    ///
    /// Runs `cargo update` for each semver-compatible fix. Breaking changes are
    /// never applied automatically (those stay your decision).
    #[arg(long, verbatim_doc_comment, help_heading = "Fixing")]
    pub fix: bool,

    /// Re-query OSV instead of using the cache
    ///
    /// Advisory text is cached for a week and match results for an hour, so
    /// repeat runs are instant. Use this right after a disclosure you know is new.
    #[arg(long, verbatim_doc_comment, help_heading = "Fixing")]
    pub fresh: bool,

    // ── Scope ───────────────────────────────────────────────────────────────
    /// List the projects that were found, then stop (makes no network calls)
    #[arg(short = 'P', long, help_heading = "Scope")]
    pub projects: bool,

    /// Skip projects matching NAME, for this run only (repeatable)
    #[arg(short = 'x', long, value_name = "NAME", help_heading = "Scope")]
    pub exclude: Vec<String>,

    /// Always skip projects matching NAME, and remember it
    #[arg(long, value_name = "NAME", help_heading = "Scope")]
    pub ignore: Vec<String>,

    /// Stop always skipping NAME
    #[arg(long, value_name = "NAME", help_heading = "Scope")]
    pub unignore: Vec<String>,

    // ── Output ──────────────────────────────────────────────────────────────
    /// How to print the report
    #[arg(short, long, value_enum, default_value_t = Output::Text, help_heading = "Output")]
    pub output: Output,

    /// Include an excerpt of each advisory and a link to the rest
    #[arg(short = 'f', long, help_heading = "Output")]
    pub full: bool,

    /// Also list unmaintained and yanked crates, which are not vulnerabilities
    #[arg(short = 'a', long = "all", help_heading = "Output")]
    pub all: bool,

    /// Turn off colour (the NO_COLOR environment variable does the same)
    #[arg(short = 'C', long, help_heading = "Output")]
    pub no_color: bool,

    /// Do not record this run, so the next one has no baseline to compare against
    #[arg(long, help_heading = "Output")]
    pub no_save: bool,

    // ── Exit code ───────────────────────────────────────────────────────────
    /// When to exit non-zero
    ///
    /// urgent   dangerous AND a patch exists (the default)
    /// fixable  anything with a patch available
    /// anything any finding at all
    /// never    always exit 0
    #[arg(
        short = 'F',
        long,
        value_enum,
        default_value_t = FailOn::Urgent,
        verbatim_doc_comment,
        help_heading = "Exit code"
    )]
    pub fail_on: FailOn,
}

/// Output format. `text`/`json` rather than `human`/`json`, because "human" is
/// jargon for a file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Output {
    /// Readable report for a terminal
    Text,
    /// Machine-readable JSON
    Json,
}

impl From<Output> for Format {
    fn from(value: Output) -> Format {
        match value {
            Output::Text => Format::Human,
            Output::Json => Format::Json,
        }
    }
}

/// When the process should exit non-zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailOn {
    /// Dangerous and fixable
    Urgent,
    /// Anything with a patch available
    Fixable,
    /// Any finding at all
    Anything,
    /// Never fail
    Never,
}

impl FailOn {
    /// The urgency threshold, or `None` to never fail.
    ///
    /// Maps outcome-words onto internal buckets, so the vocabulary a user sees
    /// never has to match the vocabulary the code uses.
    pub fn threshold(self) -> Option<Priority> {
        match self {
            FailOn::Urgent => Some(Priority::Act),
            FailOn::Fixable => Some(Priority::Plan),
            FailOn::Anything => Some(Priority::Note),
            FailOn::Never => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("arguments should parse")
    }

    #[test]
    fn defaults_are_sensible() {
        let cli = parse(&["pulse"]);
        assert_eq!(cli.paths, vec![PathBuf::from(".")]);
        assert_eq!(cli.output, Output::Text);
        assert_eq!(cli.fail_on, FailOn::Urgent);
        assert!(!cli.fix && !cli.fresh && !cli.full && !cli.all && !cli.no_save);
    }

    #[test]
    fn every_flag_has_a_short_form_or_a_reason_not_to() {
        // Flags a person types often get a short form. The rest are deliberate:
        // destructive or rare options should be spelled out.
        let long_only = ["fix", "fresh", "ignore", "unignore", "no-save"];
        for name in long_only {
            assert!(
                Cli::try_parse_from(["pulse", &format!("--{name}"), "x"]).is_ok()
                    || Cli::try_parse_from(["pulse", &format!("--{name}")]).is_ok(),
                "{name} should be accepted in long form"
            );
        }
    }

    #[test]
    fn short_forms_match_their_long_forms() {
        assert_eq!(parse(&["pulse", "-o", "json"]).output, Output::Json);
        assert!(parse(&["pulse", "-f"]).full);
        assert!(parse(&["pulse", "-a"]).all);
        assert!(parse(&["pulse", "-P"]).projects);
        assert!(parse(&["pulse", "-C"]).no_color);
        assert_eq!(parse(&["pulse", "-F", "never"]).fail_on, FailOn::Never);
        assert_eq!(parse(&["pulse", "-x", "demo"]).exclude, vec!["demo"]);
    }

    #[test]
    fn shorts_can_be_stacked() {
        let cli = parse(&["pulse", "-faC"]);
        assert!(cli.full && cli.all && cli.no_color);
    }

    #[test]
    fn fail_on_words_widen_monotonically() {
        // The point of the rename: each word catches strictly more than the last,
        // and reads that way in English.
        assert_eq!(FailOn::Urgent.threshold(), Some(Priority::Act));
        assert_eq!(FailOn::Fixable.threshold(), Some(Priority::Plan));
        assert_eq!(FailOn::Anything.threshold(), Some(Priority::Note));
        assert_eq!(FailOn::Never.threshold(), None);
        assert!(Priority::Act < Priority::Plan && Priority::Plan < Priority::Note);
    }

    #[test]
    fn repeatable_scope_flags_accumulate() {
        let cli = parse(&["pulse", "-x", "a", "-x", "b", "--ignore", "c"]);
        assert_eq!(cli.exclude, vec!["a", "b"]);
        assert_eq!(cli.ignore, vec!["c"]);
    }

    #[test]
    fn the_removed_flags_are_gone() {
        // Guard against re-adding a scoreboard toggle by reflex.
        for dead in ["--no-rewards", "--no-history", "--format", "--show-notes"] {
            assert!(
                Cli::try_parse_from(["pulse", dead]).is_err(),
                "{dead} should no longer exist"
            );
        }
    }

    #[test]
    fn rejects_unknown_values() {
        assert!(Cli::try_parse_from(["pulse", "-o", "yaml"]).is_err());
        assert!(Cli::try_parse_from(["pulse", "-F", "whenever"]).is_err());
    }

    #[test]
    fn help_renders_with_all_sections() {
        let help = Cli::try_parse_from(["pulse", "--help"])
            .unwrap_err()
            .to_string();
        for section in ["Fixing", "Scope", "Output", "Exit code"] {
            assert!(help.contains(section), "help is missing {section}");
        }
    }
}
