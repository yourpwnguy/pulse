# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-26

### Added

- Initial release
- Cargo.lock and Cargo.toml lockfile parsing
- OSV advisory database integration
- Dependency graph traversal with cycle detection
- Severity scoring from CVSS vectors
- Triage policy: fix now, when you can, blocked upstream, worth knowing
- Automatic fix suggestions with `cargo update` commands
- `--fix` mode to apply upgrades automatically
- Live terminal animation with Doki the cat mascot
- JSON output for CI integration
- Multi-project workspace support
- Caching with 1-hour TTL for match results, 7-day TTL for advisory bodies
- Progress reporting with animated status bar
- Color-coded output with plain mode for piping

### Security

- Verified fixes by checking lockfile after `cargo update`
- MSRV-aware upgrades (respects rust-version)
- Semver-compatible upgrades only (breaking changes require manual decision)
