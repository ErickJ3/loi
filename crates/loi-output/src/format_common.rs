//! Shared helpers used by both the [`crate::pretty`] and [`crate::json`]
//! formatters.
//!
//! The helpers convert raw fields from a [`loi_core::SyscallEvent`] +
//! [`loi_syscalls::DecodedCall`] pair into stable text / JSON shapes.

use loi_syscalls::{DecodedArg, DecodedCall, FdRepr};
use nix::errno::Errno;
use serde_json::{Value, json};
use std::time::Duration;

/// `-ENOENT` as a raw `ret` value: the kernel returns `-errno` on failure.
pub(crate) const RET_ENOENT: i64 = -2;

/// Render a single decoded argument as the text the pretty formatter places
/// inside the parenthesised argument list.
pub(crate) fn render_arg_text(arg: &DecodedArg) -> String {
    match arg {
        DecodedArg::Path(s) => format!("\"{}\"", s.escape_default()),
        DecodedArg::Fd(FdRepr::AtFdCwd) => "AT_FDCWD".to_owned(),
        DecodedArg::Fd(FdRepr::Invalid) => "-1".to_owned(),
        DecodedArg::Fd(FdRepr::Num(n)) => n.to_string(),
        DecodedArg::Flags(names) => {
            if names.is_empty() {
                "0".to_owned()
            } else {
                names.join("|")
            }
        }
        DecodedArg::Mode(m) => format!("0o{m:o}"),
        DecodedArg::Int(i) => i.to_string(),
        DecodedArg::Uint(u) => u.to_string(),
        DecodedArg::Bytes { inline, total } => {
            let body = String::from_utf8_lossy(inline);
            let suffix = if inline.len() < *total { "..." } else { "" };
            format!("\"{}\"{}", body.escape_default(), suffix)
        }
        DecodedArg::Ptr(0) => "NULL".to_owned(),
        DecodedArg::Hex(n) | DecodedArg::Ptr(n) => format!("0x{n:x}"),
        DecodedArg::Argv(entries) => {
            let mut s = String::with_capacity(2 + entries.len() * 8);
            s.push('[');
            for (i, entry) in entries.iter().enumerate() {
                if i > 0 {
                    s.push_str(", ");
                }
                s.push('"');
                s.push_str(&entry.escape_default().to_string());
                s.push('"');
            }
            s.push(']');
            s
        }
        // `DecodedArg` is `#[non_exhaustive]`: render any future variant
        // safely until a real rendering is added.
        _ => "?".to_owned(),
    }
}

/// Convert a single decoded argument to a JSON value. Strings stay strings,
/// flag bitsets become JSON arrays, fds become numbers (or `"AT_FDCWD"`),
/// and byte buffers become a `{ inline, total, truncated }` object.
pub(crate) fn arg_to_json(arg: &DecodedArg) -> Value {
    match arg {
        DecodedArg::Path(s) => Value::String(s.clone()),
        DecodedArg::Fd(FdRepr::AtFdCwd) => Value::String("AT_FDCWD".to_owned()),
        DecodedArg::Fd(FdRepr::Invalid) => json!(-1),
        DecodedArg::Fd(FdRepr::Num(n)) => json!(n),
        DecodedArg::Flags(names) => json!(names),
        DecodedArg::Mode(m) => json!(m),
        DecodedArg::Int(i) => json!(i),
        DecodedArg::Uint(u) => json!(u),
        DecodedArg::Bytes { inline, total } => {
            let truncated = inline.len() < *total;
            json!({
                "inline": String::from_utf8_lossy(inline),
                "total": total,
                "truncated": truncated,
            })
        }
        DecodedArg::Ptr(0) => Value::Null,
        DecodedArg::Hex(n) | DecodedArg::Ptr(n) => Value::String(format!("0x{n:x}")),
        DecodedArg::Argv(entries) => json!(entries),
        // `DecodedArg` is `#[non_exhaustive]`: future variants serialize as
        // `null` until they get a dedicated mapping.
        _ => Value::Null,
    }
}

/// Resolve a negative kernel return value to `(symbol, description)`.
///
/// Returns `None` when `ret >= 0` or the value does not map to a known
/// errno (e.g. an arch-specific code outside the [`Errno`] enum).
pub(crate) fn errno_of_ret(ret: i64) -> Option<(String, &'static str)> {
    if ret >= 0 {
        return None;
    }
    let raw = i32::try_from(-ret).ok()?;
    let errno = Errno::from_raw(raw);
    if errno == Errno::UnknownErrno {
        return None;
    }
    Some((format!("{errno:?}"), errno.desc()))
}

/// Whether `name` is a path-lookup-style syscall.
///
/// The set covers the calls the dynamic linker rains down when probing
/// for a library: `openat` (most opens), the older `open`, plus the
/// metadata family (`stat` / `newfstatat` / `statx` / `access` /
/// `faccessat`). Used by the pretty formatter to dim ENOENT bursts and
/// to detect same-basename runs for tree-prefix grouping.
pub(crate) fn is_path_lookup(name: &str) -> bool {
    matches!(
        name,
        "openat" | "open" | "newfstatat" | "access" | "faccessat" | "stat" | "statx"
    )
}

/// Final path component of the `pathname` argument when `name` is a
/// path-lookup syscall.
///
/// Returns `None` when `name` is not a lookup, when the decoded call
/// has no `pathname` arg, or when that arg is not a [`DecodedArg::Path`].
/// Centralised here so the dim-detection and burst-grouping logic in
/// `pretty.rs` share a single, testable heuristic.
pub(crate) fn lookup_basename<'a>(name: &str, decoded: &'a DecodedCall) -> Option<&'a str> {
    if !is_path_lookup(name) {
        return None;
    }
    for (label, arg) in &decoded.args {
        if *label == "pathname"
            && let DecodedArg::Path(p) = arg
        {
            return Some(p.rsplit('/').next().unwrap_or(p.as_str()));
        }
    }
    None
}

/// Render a [`Duration`] picking the largest unit that keeps the magnitude
/// readable: `ns`, `us`, `ms`, or `s`.
pub(crate) fn fmt_duration(d: Duration) -> String {
    let nanos = d.as_nanos();
    if nanos < 1_000 {
        format!("{nanos}ns")
    } else if nanos < 1_000_000 {
        format!("{}us", nanos / 1_000)
    } else if nanos < 1_000_000_000 {
        #[expect(
            clippy::cast_precision_loss,
            reason = "duration magnitude bounded by Duration::MAX, lossy display is acceptable"
        )]
        let ms = nanos as f64 / 1_000_000.0;
        format!("{ms:.1}ms")
    } else {
        #[expect(
            clippy::cast_precision_loss,
            reason = "duration magnitude bounded by Duration::MAX, lossy display is acceptable"
        )]
        let s = nanos as f64 / 1_000_000_000.0;
        format!("{s:.1}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_path_quotes_and_escapes() {
        let arg = DecodedArg::Path("/tmp/x\n".to_owned());
        assert_eq!(render_arg_text(&arg), "\"/tmp/x\\n\"");
    }

    #[test]
    fn render_fd_at_fdcwd() {
        assert_eq!(
            render_arg_text(&DecodedArg::Fd(FdRepr::AtFdCwd)),
            "AT_FDCWD"
        );
    }

    #[test]
    fn render_fd_num() {
        assert_eq!(render_arg_text(&DecodedArg::Fd(FdRepr::Num(3))), "3");
    }

    #[test]
    fn render_flags_joined_with_pipe() {
        let arg = DecodedArg::Flags(vec!["O_RDONLY", "O_CLOEXEC"]);
        assert_eq!(render_arg_text(&arg), "O_RDONLY|O_CLOEXEC");
    }

    #[test]
    fn render_flags_empty_is_zero() {
        assert_eq!(render_arg_text(&DecodedArg::Flags(Vec::new())), "0");
    }

    #[test]
    fn render_mode_octal() {
        assert_eq!(render_arg_text(&DecodedArg::Mode(0o644)), "0o644");
    }

    #[test]
    fn render_bytes_truncation_marker() {
        let arg = DecodedArg::Bytes {
            inline: b"hi".to_vec(),
            total: 5,
        };
        assert_eq!(render_arg_text(&arg), "\"hi\"...");
    }

    #[test]
    fn render_bytes_no_marker_when_complete() {
        let arg = DecodedArg::Bytes {
            inline: b"hi".to_vec(),
            total: 2,
        };
        assert_eq!(render_arg_text(&arg), "\"hi\"");
    }

    #[test]
    fn errno_of_ret_resolves_enoent() {
        let (sym, desc) = errno_of_ret(-2).expect("ENOENT resolves");
        assert_eq!(sym, "ENOENT");
        assert!(!desc.is_empty());
    }

    #[test]
    fn errno_of_ret_none_for_success() {
        assert!(errno_of_ret(0).is_none());
        assert!(errno_of_ret(42).is_none());
    }

    #[test]
    fn fmt_duration_picks_unit() {
        assert_eq!(fmt_duration(Duration::from_nanos(500)), "500ns");
        assert_eq!(fmt_duration(Duration::from_micros(12)), "12us");
        assert_eq!(
            fmt_duration(Duration::from_millis(1) + Duration::from_micros(200)),
            "1.2ms"
        );
        assert_eq!(fmt_duration(Duration::from_millis(3_400)), "3.4s");
    }

    #[test]
    fn arg_to_json_path_is_string() {
        let v = arg_to_json(&DecodedArg::Path("/tmp".to_owned()));
        assert_eq!(v, json!("/tmp"));
    }

    #[test]
    fn arg_to_json_flags_is_array() {
        let v = arg_to_json(&DecodedArg::Flags(vec!["O_RDONLY"]));
        assert_eq!(v, json!(["O_RDONLY"]));
    }

    #[test]
    fn render_hex_with_0x_prefix() {
        assert_eq!(render_arg_text(&DecodedArg::Hex(0xdead_beef)), "0xdeadbeef");
    }

    #[test]
    fn render_ptr_zero_renders_null() {
        assert_eq!(render_arg_text(&DecodedArg::Ptr(0)), "NULL");
    }

    #[test]
    fn render_ptr_nonzero_renders_hex() {
        assert_eq!(render_arg_text(&DecodedArg::Ptr(0x1000)), "0x1000");
    }

    #[test]
    fn render_argv_quotes_each_entry() {
        let arg = DecodedArg::Argv(vec!["ls".to_owned(), "-l".to_owned()]);
        assert_eq!(render_arg_text(&arg), "[\"ls\", \"-l\"]");
    }

    #[test]
    fn render_argv_escapes_special_chars() {
        let arg = DecodedArg::Argv(vec!["a\nb".to_owned()]);
        assert_eq!(render_arg_text(&arg), "[\"a\\nb\"]");
    }

    #[test]
    fn render_argv_empty_is_empty_brackets() {
        assert_eq!(render_arg_text(&DecodedArg::Argv(Vec::new())), "[]");
    }

    #[test]
    fn arg_to_json_hex_is_string_with_prefix() {
        let v = arg_to_json(&DecodedArg::Hex(0x42));
        assert_eq!(v, json!("0x42"));
    }

    #[test]
    fn arg_to_json_ptr_zero_is_null() {
        assert_eq!(arg_to_json(&DecodedArg::Ptr(0)), Value::Null);
    }

    #[test]
    fn arg_to_json_ptr_nonzero_is_string() {
        let v = arg_to_json(&DecodedArg::Ptr(0x1000));
        assert_eq!(v, json!("0x1000"));
    }

    #[test]
    fn arg_to_json_argv_is_string_array() {
        let v = arg_to_json(&DecodedArg::Argv(vec!["a".to_owned(), "b".to_owned()]));
        assert_eq!(v, json!(["a", "b"]));
    }

    #[test]
    fn arg_to_json_bytes_object() {
        let v = arg_to_json(&DecodedArg::Bytes {
            inline: b"hi".to_vec(),
            total: 5,
        });
        assert_eq!(v, json!({ "inline": "hi", "total": 5, "truncated": true }));
    }
}
