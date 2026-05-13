//! Syscall filter DSL: `--syscall` glob set, `--fail` boolean, `--path`
//! glob set.
//!
//! `loi` 0.2 ships three filters: a comma-separated list of syscall-name
//! globs (`open*,read,write`), a flag that drops successful calls, and a
//! comma-separated list of path globs (`/etc/*,/tmp/*`) matched against
//! decoded path arguments. All filters compose: an event must satisfy
//! every active filter to pass.
//!
//! The syscall-name and `--fail` filters run before decoding via
//! [`Filter::matches_event`]; the path filter runs after decoding via
//! [`Filter::matches_decoded`]. When a path filter is set, syscalls whose
//! decoded arguments carry no path (e.g. `close`, `mmap`) are dropped.
//!
//! Build a [`Filter`] with [`Filter::parse`], then call
//! [`Filter::matches_event`] on each [`SyscallEvent`]; if it passes,
//! decode the event and call [`Filter::matches_decoded`] before
//! formatting. [`Filter::needs_decode`] lets callers skip the
//! decode-stage gate when no path filter is active.
#![deny(missing_docs)]

use globset::{Glob, GlobSet, GlobSetBuilder};
use loi_core::SyscallEvent;
use loi_syscalls::DecodedCall;

/// Errors produced by [`Filter::parse`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FilterError {
    /// One of the comma-separated patterns is not a valid glob.
    #[error("invalid glob `{pattern}`: {source}")]
    InvalidGlob {
        /// The offending pattern as supplied by the user.
        pattern: String,
        /// Underlying [`globset`] parser error.
        #[source]
        source: globset::Error,
    },
}

/// Compiled set of MVP filters applied to each [`SyscallEvent`] and
/// [`DecodedCall`].
///
/// An empty filter (no syscall pattern, no path pattern, `only_fail =
/// false`) matches every event. Use [`Filter::parse`] to build one from
/// CLI flags.
#[derive(Clone, Debug, Default)]
pub struct Filter {
    syscalls: Option<GlobSet>,
    only_fail: bool,
    paths: Option<GlobSet>,
}

impl Filter {
    /// Build a filter from a syscall glob pattern, the `--fail` flag,
    /// and a path glob pattern.
    ///
    /// Both glob args accept patterns like `"open*,read,write"` and
    /// `"/etc/*,/tmp/*"`; whitespace around each segment is trimmed and
    /// empty segments are skipped. `None` (or a string that yields no
    /// segments) disables that gate, so every value passes it.
    ///
    /// `only_fail = true` rejects events whose `ret >= 0`.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError::InvalidGlob`] when a segment of either
    /// glob arg fails to parse as a [`Glob`].
    pub fn parse(
        syscalls: Option<&str>,
        only_fail: bool,
        paths: Option<&str>,
    ) -> Result<Self, FilterError> {
        Ok(Self {
            syscalls: compile_globs(syscalls)?,
            only_fail,
            paths: compile_globs(paths)?,
        })
    }

    /// Return `true` when `ev` passes the pre-decode gates (`--syscall`,
    /// `--fail`). The path gate is ignored here; call
    /// [`Filter::matches_decoded`] after decoding.
    #[must_use]
    pub fn matches_event(&self, ev: &SyscallEvent) -> bool {
        if self.only_fail && ev.ret >= 0 {
            return false;
        }
        match &self.syscalls {
            Some(set) => set.is_match(ev.syscall_name.as_ref()),
            None => true,
        }
    }

    /// Return `true` when `decoded` passes the post-decode gates
    /// (`--path`).
    ///
    /// With no path filter set, returns `true` unconditionally. With a
    /// path filter set, returns `true` only when at least one
    /// [`DecodedArg::Path`](loi_syscalls::DecodedArg::Path) in
    /// `decoded.args` matches the glob set; calls with no path arg are
    /// rejected.
    #[must_use]
    pub fn matches_decoded(&self, decoded: &DecodedCall) -> bool {
        let Some(set) = &self.paths else {
            return true;
        };
        decoded
            .args
            .iter()
            .filter_map(|(_, arg)| arg.as_path())
            .any(|p| set.is_match(p))
    }

    /// Whether a decoded call is needed to fully evaluate the filter.
    ///
    /// Returns `true` when a path filter is active. Callers can use this
    /// to short-circuit the decode-stage gate when no path filter is
    /// set, leaving the 0.1 pipeline cost unchanged.
    #[must_use]
    pub fn needs_decode(&self) -> bool {
        self.paths.is_some()
    }
}

fn compile_globs(raw: Option<&str>) -> Result<Option<GlobSet>, FilterError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let mut builder = GlobSetBuilder::new();
    let mut any = false;
    for seg in raw.split(',') {
        let pattern = seg.trim();
        if pattern.is_empty() {
            continue;
        }
        let glob = Glob::new(pattern).map_err(|source| FilterError::InvalidGlob {
            pattern: pattern.to_owned(),
            source,
        })?;
        builder.add(glob);
        any = true;
    }
    if !any {
        return Ok(None);
    }
    builder
        .build()
        .map(Some)
        .map_err(|source| FilterError::InvalidGlob {
            pattern: source.glob().map_or_else(|| raw.to_owned(), str::to_owned),
            source,
        })
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::time::Duration;

    use loi_syscalls::{DecodedArg, DecodedCall, FdRepr};

    use super::*;

    fn ev(name: &'static str, ret: i64) -> SyscallEvent {
        SyscallEvent::new(1, 0, Cow::Borrowed(name), [0; 6], ret, Duration::ZERO)
    }

    fn decoded_with_path(path: &str) -> DecodedCall {
        DecodedCall {
            args: vec![
                ("dirfd", DecodedArg::Fd(FdRepr::AtFdCwd)),
                ("pathname", DecodedArg::Path(path.to_owned())),
            ],
            ret: 0,
        }
    }

    fn decoded_close() -> DecodedCall {
        DecodedCall {
            args: vec![("fd", DecodedArg::Fd(FdRepr::Num(3)))],
            ret: 0,
        }
    }

    #[test]
    fn parse_glob_matches_open_star_and_read_not_write() {
        let f = Filter::parse(Some("open*,read"), false, None).expect("valid patterns");
        assert!(f.matches_event(&ev("openat", 0)));
        assert!(f.matches_event(&ev("open", 0)));
        assert!(f.matches_event(&ev("read", 0)));
        assert!(!f.matches_event(&ev("write", 0)));
    }

    #[test]
    fn only_fail_rejects_non_negative_ret() {
        let f = Filter::parse(None, true, None).expect("valid");
        assert!(f.matches_event(&ev("openat", -1)));
        assert!(!f.matches_event(&ev("openat", 0)));
        assert!(!f.matches_event(&ev("openat", 42)));
    }

    #[test]
    fn invalid_syscall_glob_returns_error() {
        match Filter::parse(Some("[invalid"), false, None) {
            Err(FilterError::InvalidGlob { pattern, .. }) => {
                assert_eq!(pattern, "[invalid");
            }
            other => panic!("expected InvalidGlob, got {other:?}"),
        }
    }

    #[test]
    fn empty_filter_matches_everything() {
        let f = Filter::parse(None, false, None).expect("valid");
        assert!(f.matches_event(&ev("openat", 0)));
        assert!(f.matches_event(&ev("write", -1)));
        assert!(f.matches_event(&ev("syscall_999", 7)));
    }

    #[test]
    fn empty_pattern_string_is_treated_as_no_filter() {
        let f = Filter::parse(Some(""), false, None).expect("empty parses");
        assert!(f.matches_event(&ev("anything", 0)));
    }

    #[test]
    fn whitespace_and_empty_segments_skipped() {
        let f = Filter::parse(Some(" read , , write "), false, None).expect("valid");
        assert!(f.matches_event(&ev("read", 0)));
        assert!(f.matches_event(&ev("write", 0)));
        assert!(!f.matches_event(&ev("open", 0)));
    }

    #[test]
    fn syscall_filter_and_only_fail_compose() {
        let f = Filter::parse(Some("openat"), true, None).expect("valid");
        assert!(f.matches_event(&ev("openat", -1)));
        assert!(!f.matches_event(&ev("openat", 0)));
        assert!(!f.matches_event(&ev("read", -1)));
    }

    #[test]
    fn path_filter_accepts_decoded_with_matching_path() {
        let f = Filter::parse(None, false, Some("/etc/*")).expect("valid");
        assert!(f.matches_decoded(&decoded_with_path("/etc/passwd")));
    }

    #[test]
    fn path_filter_rejects_decoded_with_non_matching_path() {
        let f = Filter::parse(None, false, Some("/etc/*")).expect("valid");
        assert!(!f.matches_decoded(&decoded_with_path("/tmp/x")));
    }

    #[test]
    fn invalid_path_glob_returns_error() {
        match Filter::parse(None, false, Some("[invalid")) {
            Err(FilterError::InvalidGlob { pattern, .. }) => {
                assert_eq!(pattern, "[invalid");
            }
            other => panic!("expected InvalidGlob, got {other:?}"),
        }
    }

    #[test]
    fn empty_path_filter_passes_everything() {
        let f = Filter::parse(None, false, None).expect("valid");
        assert!(f.matches_decoded(&decoded_with_path("/etc/passwd")));
        assert!(f.matches_decoded(&decoded_close()));
    }

    #[test]
    fn path_filter_skips_syscalls_with_no_path_arg() {
        let f = Filter::parse(None, false, Some("/etc/*")).expect("valid");
        assert!(!f.matches_decoded(&decoded_close()));
    }

    #[test]
    fn path_filter_accepts_any_of_multiple_globs() {
        let f = Filter::parse(None, false, Some("/etc/*,/tmp/*")).expect("valid");
        assert!(f.matches_decoded(&decoded_with_path("/etc/passwd")));
        assert!(f.matches_decoded(&decoded_with_path("/tmp/x")));
        assert!(!f.matches_decoded(&decoded_with_path("/var/log/x")));
    }

    #[test]
    fn needs_decode_true_only_when_path_filter_set() {
        assert!(
            !Filter::parse(None, false, None)
                .expect("valid")
                .needs_decode()
        );
        assert!(
            !Filter::parse(Some("openat"), true, None)
                .expect("valid")
                .needs_decode()
        );
        assert!(
            Filter::parse(None, false, Some("/etc/*"))
                .expect("valid")
                .needs_decode()
        );
    }
}
