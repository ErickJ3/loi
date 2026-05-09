//! Syscall filter DSL: `--syscall` glob set and `--fail` boolean.
//!
//! `loi` 0.1 ships two filters: a comma-separated list of syscall-name
//! globs (`open*,read,write`) and a flag that drops successful calls.
//! Both compose: an event must satisfy every active filter to pass.
//!
//! Build a [`Filter`] with [`Filter::parse`], then call
//! [`Filter::matches`] on each [`SyscallEvent`] before formatting.
#![deny(missing_docs)]

use globset::{Glob, GlobSet, GlobSetBuilder};
use loi_core::SyscallEvent;

/// Errors produced by [`Filter::parse`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FilterError {
    /// One of the comma-separated patterns is not a valid glob.
    #[error("invalid syscall glob `{pattern}`: {source}")]
    InvalidGlob {
        /// The offending pattern as supplied by the user.
        pattern: String,
        /// Underlying [`globset`] parser error.
        #[source]
        source: globset::Error,
    },
}

/// Compiled set of MVP filters applied to each [`SyscallEvent`].
///
/// An empty filter (no syscall pattern, `only_fail = false`) matches
/// every event. Use [`Filter::parse`] to build one from CLI flags.
#[derive(Clone, Debug, Default)]
pub struct Filter {
    syscalls: Option<GlobSet>,
    only_fail: bool,
}

impl Filter {
    /// Build a filter from a comma-separated glob pattern and the
    /// `--fail` flag.
    ///
    /// `syscalls` accepts patterns like `"open*,read,write"`; whitespace
    /// around each segment is trimmed, and empty segments are skipped.
    /// `None` (or a string that yields no segments) leaves the syscall
    /// matcher disabled, so every name passes that gate.
    ///
    /// `only_fail = true` rejects events whose `ret >= 0`.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError::InvalidGlob`] when a segment fails to parse
    /// as a [`Glob`].
    pub fn parse(syscalls: Option<&str>, only_fail: bool) -> Result<Self, FilterError> {
        let syscalls = match syscalls {
            None => None,
            Some(raw) => {
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
                if any {
                    Some(builder.build().map_err(|source| {
                        let pattern = source.glob().map_or_else(|| raw.to_owned(), str::to_owned);
                        FilterError::InvalidGlob { pattern, source }
                    })?)
                } else {
                    None
                }
            }
        };
        Ok(Self {
            syscalls,
            only_fail,
        })
    }

    /// Return `true` when `ev` passes every active filter.
    #[must_use]
    pub fn matches(&self, ev: &SyscallEvent) -> bool {
        if self.only_fail && ev.ret >= 0 {
            return false;
        }
        match &self.syscalls {
            Some(set) => set.is_match(ev.syscall_name.as_ref()),
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::time::Duration;

    use super::*;

    fn ev(name: &'static str, ret: i64) -> SyscallEvent {
        SyscallEvent::new(1, 0, Cow::Borrowed(name), [0; 6], ret, Duration::ZERO)
    }

    #[test]
    fn parse_glob_matches_open_star_and_read_not_write() {
        let f = Filter::parse(Some("open*,read"), false).expect("valid patterns");
        assert!(f.matches(&ev("openat", 0)));
        assert!(f.matches(&ev("open", 0)));
        assert!(f.matches(&ev("read", 0)));
        assert!(!f.matches(&ev("write", 0)));
    }

    #[test]
    fn only_fail_rejects_non_negative_ret() {
        let f = Filter::parse(None, true).expect("valid");
        assert!(f.matches(&ev("openat", -1)));
        assert!(!f.matches(&ev("openat", 0)));
        assert!(!f.matches(&ev("openat", 42)));
    }

    #[test]
    fn invalid_glob_returns_error() {
        match Filter::parse(Some("[invalid"), false) {
            Err(FilterError::InvalidGlob { pattern, .. }) => {
                assert_eq!(pattern, "[invalid");
            }
            other => panic!("expected InvalidGlob, got {other:?}"),
        }
    }

    #[test]
    fn empty_filter_matches_everything() {
        let f = Filter::parse(None, false).expect("valid");
        assert!(f.matches(&ev("openat", 0)));
        assert!(f.matches(&ev("write", -1)));
        assert!(f.matches(&ev("syscall_999", 7)));
    }

    #[test]
    fn empty_pattern_string_is_treated_as_no_filter() {
        let f = Filter::parse(Some(""), false).expect("empty parses");
        assert!(f.matches(&ev("anything", 0)));
    }

    #[test]
    fn whitespace_and_empty_segments_skipped() {
        let f = Filter::parse(Some(" read , , write "), false).expect("valid");
        assert!(f.matches(&ev("read", 0)));
        assert!(f.matches(&ev("write", 0)));
        assert!(!f.matches(&ev("open", 0)));
    }

    #[test]
    fn syscall_filter_and_only_fail_compose() {
        let f = Filter::parse(Some("openat"), true).expect("valid");
        assert!(f.matches(&ev("openat", -1)));
        assert!(!f.matches(&ev("openat", 0)));
        assert!(!f.matches(&ev("read", -1)));
    }
}
