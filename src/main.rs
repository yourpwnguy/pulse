//! Binary entry point: argument parsing, exit codes, error printing.
//!
//! Deliberately tiny. It contains no logic a test would want to reach, which is
//! the point of keeping [`pulse::run`] in the library.

use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;

use clap::Parser;

use pulse::cli::Cli;
use pulse::render::{Layout, Style, View};
use pulse::{error::Error, Options, Outcome};

/// Exit codes, chosen so scripts can distinguish "found problems" from "broke".
/// Conflating those is how a CI job goes green because the network was down.
const EXIT_OK: u8 = 0;
const EXIT_FINDINGS: u8 = 1;
const EXIT_ERROR: u8 = 2;

fn main() -> ExitCode {
    let cli = Cli::parse();

    let stdout = io::stdout();
    let style = Style::detect(stdout.is_terminal(), cli.no_color);
    let mut out = io::BufWriter::new(stdout.lock());

    let options = Options {
        format: cli.output.into(),
        layout: Layout::detect(),
        style,
        view: View {
            full: cli.full,
            after_fix: false,
        },
        gate: cli.fail_on.threshold(),
        show_notes: cli.all,
        // History is only ever read for the "since last run" baseline; --no-save
        // stops us writing it, which is the part a user might not want.
        history: !cli.no_save,
        exclude: cli.exclude,
        ignore: cli.ignore,
        unignore: cli.unignore,
        list_projects: cli.projects,
        fix: cli.fix,
        cache: !cli.fresh,
    };

    let result = pulse::run(&cli.paths, &mut out, &options);

    // Flush explicitly: a `BufWriter` that fails on drop would otherwise lose the
    // tail of the report and still report success.
    let flushed = out.flush();

    match (result, flushed) {
        (Ok(outcome), Ok(())) => match outcome {
            Outcome::Pass => ExitCode::from(EXIT_OK),
            Outcome::Gated => ExitCode::from(EXIT_FINDINGS),
        },
        (Err(error), _) => fail(&error),
        (Ok(_), Err(error)) => fail(&Error::Output(error)),
    }
}

/// Reports an error to stderr with its cause chain, and exits distinctly from
/// "found vulnerabilities".
fn fail(error: &Error) -> ExitCode {
    // A closed pipe (`pulse | head`) is normal shell behaviour, not a failure.
    if let Error::Output(io) = error {
        if io.kind() == io::ErrorKind::BrokenPipe {
            return ExitCode::from(EXIT_OK);
        }
    }

    eprintln!("pulse: {error}");

    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        eprintln!("  caused by: {cause}");
        source = cause.source();
    }

    ExitCode::from(EXIT_ERROR)
}
