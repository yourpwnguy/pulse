//! The `--projects` view: what pulse found, and what it will skip.
//!
//! Exists because "3 projects" is not an answer to "*which* three?". When a tool
//! scans by walking the filesystem, the set it chose is a fact the user needs to
//! be able to audit (otherwise a typo'd path or an over-broad `--exclude`
//! silently shrinks the scan and nothing looks wrong.
//!
//! Makes no network calls, so it is instant.

use std::io::Write;

use unicode_width::UnicodeWidthStr;

use crate::domain::Project;
use crate::error::Result;
use crate::triage::SkippedProject;

use super::layout::Layout;
use super::line::{truncate, Line};

use super::style::{Style, KIN, MINT, ROSE, SKY, SLATE};

pub fn render(
    out: &mut dyn Write,
    projects: &[Project],
    skipped: &[SkippedProject],
    layout: Layout,
    style: Style,
) -> Result<()> {
    writeln!(out)?;
    writeln!(
        out,
        "{}",
        Line::indent(2)
            .bold(style, ROSE, "♡ pulse")
            .plain("   ")
            .dim(style, "projects found")
    )?;
    writeln!(out)?;

    if projects.is_empty() && skipped.is_empty() {
        writeln!(
            out,
            "{}",
            Line::indent(2).dim(
                style,
                &truncate(
                    "no Cargo.lock found \u{2014} is this the right directory?",
                    layout.room(2)
                )
            )
        )?;
        writeln!(out)?;
        return Ok(());
    }

    // Column widths are measured on plain text and capped as a share of the
    // terminal, so a long name cannot push the counts or the path off the edge.
    let name_col = projects
        .iter()
        .map(|p| UnicodeWidthStr::width(p.name.as_str()))
        .chain(
            skipped
                .iter()
                .map(|s| UnicodeWidthStr::width(s.name.as_str())),
        )
        .max()
        .unwrap_or(0)
        .clamp(4, (layout.total * 34 / 100).max(8));

    for project in projects {
        let packages = project.scanned_count();
        let counts = format!(
            "{packages} {}, {} direct",
            plural(packages, "package", "packages"),
            project.direct_count()
        );

        let row = Line::indent(2)
            .paint(style, MINT, "●")
            .plain(" ")
            .bold(style, SKY, &truncate(&project.name, name_col))
            .pad_to(4 + name_col + 2)
            .dim(style, &counts);

        // The path takes whatever is left, and only when something is left.
        let row = match layout.total.checked_sub(row.width() + 2) {
            Some(space) if space >= 12 => row
                .plain("  ")
                .dim(style, &truncate(&display_path(project), space)),
            _ => row,
        };
        writeln!(out, "{row}")?;
    }

    for entry in skipped {
        let row = Line::indent(2)
            .paint(style, SLATE, "○")
            .plain(" ")
            .paint(style, SLATE, &truncate(&entry.name, name_col))
            .pad_to(4 + name_col + 2);
        let space = layout.total.saturating_sub(row.width());
        writeln!(
            out,
            "{}",
            row.dim(
                style,
                &truncate(&format!("skipped \u{2014} {}", entry.reason), space)
            )
        )?;
    }

    writeln!(out)?;

    // Repeated as a warning, not merely listed above: a suppressed project is the
    // one thing a security tool must not let you forget about.
    if !skipped.is_empty() {
        writeln!(
            out,
            "{}",
            Line::indent(2).paint(style, KIN, "!").plain(" ").dim(
                style,
                &truncate(
                    &format!(
                        "{} {} not being scanned",
                        skipped.len(),
                        plural(skipped.len(), "project is", "projects are")
                    ),
                    layout.room(4)
                )
            )
        )?;
    }

    writeln!(
        out,
        "{}",
        Line::indent(2).dim(
            style,
            &truncate(
                "--exclude NAME skips once · --ignore NAME skips from now on",
                layout.room(2)
            )
        )
    )?;
    writeln!(out)?;
    Ok(())
}

/// Shortens the displayed path by collapsing `$HOME` to `~`.
fn display_path(project: &Project) -> String {
    let path = project.root.to_string_lossy().to_string();
    match std::env::var("HOME") {
        Ok(home) if !home.is_empty() && path.starts_with(&home) => {
            format!("~{}", &path[home.len()..])
        }
        _ => path,
    }
}

fn plural(count: usize, one: &str, many: &str) -> String {
    if count == 1 { one } else { many }.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Ecosystem, Origin, Package, ResolvedPackage};
    use semver::Version;
    use std::path::PathBuf;

    fn project(name: &str, packages: usize, direct: usize) -> Project {
        Project {
            name: name.into(),
            root: PathBuf::from(format!("/tmp/{name}")),
            lockfile: PathBuf::from(format!("/tmp/{name}/Cargo.lock")),
            ecosystem: Ecosystem::CratesIo,
            packages: (0..packages)
                .map(|i| ResolvedPackage {
                    package: Package::new(
                        Ecosystem::CratesIo,
                        format!("dep{i}"),
                        Version::new(1, 0, 0),
                    ),
                    origin: if i < direct {
                        Origin::Direct
                    } else {
                        Origin::Transitive {
                            depth: 2,
                            path: vec!["x".into()],
                        }
                    },
                })
                .collect(),
            unscannable: vec![],
        }
    }

    fn render_to_string(projects: &[Project], skipped: &[SkippedProject]) -> String {
        let mut buffer = Vec::new();
        render(
            &mut buffer,
            projects,
            skipped,
            Layout::of(100),
            Style::Plain,
        )
        .unwrap();
        String::from_utf8(buffer).unwrap()
    }

    #[test]
    fn lists_projects_with_counts() {
        let text = render_to_string(&[project("alpha", 10, 3), project("beta", 1, 1)], &[]);

        assert!(text.contains("alpha"));
        assert!(text.contains("10 packages, 3 direct"));
        assert!(text.contains("beta"));
        // Singular agreement.
        assert!(text.contains("1 package, 1 direct"));
    }

    #[test]
    fn shows_skipped_projects_and_why() {
        let text = render_to_string(
            &[project("alpha", 2, 1)],
            &[SkippedProject {
                name: "scratch".into(),
                reason: "--exclude scratch".into(),
            }],
        );

        assert!(text.contains("scratch"));
        assert!(text.contains("--exclude scratch"));
        // And warns, so suppression stays visible.
        assert!(text.contains("1 project is not being scanned"));
    }

    #[test]
    fn explains_how_to_change_the_scope() {
        let text = render_to_string(&[project("alpha", 1, 1)], &[]);
        assert!(text.contains("--exclude"));
        assert!(text.contains("--ignore"));
    }

    #[test]
    fn handles_an_empty_scan() {
        let text = render_to_string(&[], &[]);
        assert!(text.contains("no Cargo.lock found"));
    }

    #[test]
    fn alignment_is_measured_in_terminal_cells() {
        // A CJK name is 3 chars, 9 bytes, and 6 terminal cells. Only the last of
        // those three numbers aligns a table.
        let text = render_to_string(&[project("日本語", 1, 1), project("ab", 1, 1)], &[]);
        let lines: Vec<&str> = text.lines().filter(|l| l.contains("package,")).collect();
        assert_eq!(lines.len(), 2);

        // Measure the rendered column, not the byte offset: `str::find` returns
        // bytes, which differ for multi-byte input even when the terminal output
        // lines up correctly.
        let column = |line: &str| {
            let index = line.find("1 package,").unwrap();
            UnicodeWidthStr::width(&line[..index])
        };
        assert_eq!(
            column(lines[0]),
            column(lines[1]),
            "columns must line up in terminal cells regardless of glyph width"
        );
    }

    #[test]
    fn nothing_exceeds_the_terminal_width() {
        let deep = Project {
            root: PathBuf::from(
                "/a/very/deeply/nested/path/that/keeps/going/for/quite/a/while/project",
            ),
            ..project("a-project-with-a-rather-long-name", 120, 12)
        };
        let skipped = vec![SkippedProject {
            name: "another-long-project-name".into(),
            reason: "ignored: some quite long pattern here".into(),
        }];

        for columns in [56, 60, 80, 120, 200] {
            let layout = Layout::of(columns);
            let mut buffer = Vec::new();
            render(
                &mut buffer,
                std::slice::from_ref(&deep),
                &skipped,
                layout,
                Style::Plain,
            )
            .unwrap();
            let text = String::from_utf8(buffer).unwrap();
            let widest = text
                .lines()
                .map(unicode_width::UnicodeWidthStr::width)
                .max()
                .unwrap_or(0);
            assert!(
                widest <= layout.total,
                "at {columns} columns reached {widest} (limit {})",
                layout.total
            );
        }
    }

    #[test]
    fn plain_output_has_no_escapes() {
        let text = render_to_string(&[project("alpha", 1, 1)], &[]);
        assert!(!text.contains('\x1b'));
    }
}
