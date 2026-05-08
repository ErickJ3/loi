# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial workspace scaffold: `loi-core`, `loi-syscalls`, `loi-memory`, `loi-output`, `loi-filter` crates plus `loi` binary and `xtask` automation.
- CLI skeleton with `clap` derive: `--output`, `--syscall`, `--fail`, `--follow-forks`.
- Toolchain pin (1.95), `rustfmt.toml`, `clippy.toml`.
- E2E tests for `--help`, `--version`, missing-command failure.
