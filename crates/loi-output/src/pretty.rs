//! Colored, human-friendly single-line formatter.
//!
//! Renders one [`SyscallEvent`] as a single strace-style line:
//!
//! ```text
//! [pid] syscall(arg, arg, ...) = ret <duration>
//! ```
//!
//! Color is opt-in via [`PrettyConfig`]: callers writing to a terminal pass
//! `color: true`; everything else (pipes, files, snapshot tests) leaves it
//! `false` so the output stays ANSI-free.

use crate::format_common::{errno_of_ret, fmt_duration, render_arg_text};
use loi_core::SyscallEvent;
use loi_syscalls::DecodedCall;
use owo_colors::OwoColorize;
use std::io::{self, Write};

/// Tunable knobs for the [`write_event`] formatter.
///
/// `color` is the only knob today: when `true`, the formatter emits ANSI
/// escapes via [`owo_colors`]; when `false`, the output is plain bytes
/// safe to capture in a snapshot or pipe to a file. Default is `false`.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct PrettyConfig {
    /// Whether to emit ANSI color escapes. Callers that target a terminal
    /// typically gate this on [`std::io::IsTerminal`] for the real sink.
    pub color: bool,
}

/// Write one syscall event as a single pretty line ending with `\n`.
///
/// `ev` provides the pid, syscall name, return value, and duration; `decoded`
/// provides the labelled, semantically-typed argument list rendered inside
/// the parentheses.
///
/// # Errors
///
/// Returns any [`io::Error`] surfaced by `w` while writing.
pub fn write_event<W: Write>(
    w: &mut W,
    ev: &SyscallEvent,
    decoded: &DecodedCall,
    cfg: &PrettyConfig,
) -> io::Result<()> {
    let pid = format!("[{}]", ev.pid);
    let name = ev.syscall_name.as_ref();
    let args: Vec<String> = decoded
        .args
        .iter()
        .map(|(_, arg)| render_arg_text(arg))
        .collect();
    let args_joined = args.join(", ");
    let duration = format!("<{}>", fmt_duration(ev.duration));

    if cfg.color {
        write!(w, "{} ", pid.dimmed())?;
        write!(w, "{}", name.bold().cyan())?;
        write!(w, "({args_joined}) = ")?;
        write_ret(w, ev.ret, true)?;
        writeln!(w, " {}", duration.dimmed())?;
    } else {
        write!(w, "{pid} {name}({args_joined}) = ")?;
        write_ret(w, ev.ret, false)?;
        writeln!(w, " {duration}")?;
    }
    Ok(())
}

fn write_ret<W: Write>(w: &mut W, ret: i64, color: bool) -> io::Result<()> {
    match errno_of_ret(ret) {
        Some((sym, desc)) => {
            if color {
                write!(w, "{} {} ({})", ret.bold().red(), sym.bold().red(), desc)
            } else {
                write!(w, "{ret} {sym} ({desc})")
            }
        }
        None => {
            if color {
                write!(w, "{}", ret.bold())
            } else {
                write!(w, "{ret}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::time::Duration;

    use loi_syscalls::{DecodedArg, DecodedCall, FdRepr};

    use super::*;

    fn openat_ok() -> (SyscallEvent, DecodedCall) {
        let event = SyscallEvent::new(
            1234,
            257,
            Cow::Borrowed("openat"),
            [0, 0, 0, 0, 0, 0],
            3,
            Duration::from_micros(12),
        );
        let decoded = DecodedCall {
            args: vec![
                ("dirfd", DecodedArg::Fd(FdRepr::AtFdCwd)),
                ("pathname", DecodedArg::Path("/etc/hosts".to_owned())),
                ("flags", DecodedArg::Flags(vec!["O_RDONLY", "O_CLOEXEC"])),
                ("mode", DecodedArg::Mode(0)),
            ],
            ret: 3,
        };
        (event, decoded)
    }

    fn render(ev: &SyscallEvent, decoded: &DecodedCall, color: bool) -> String {
        let mut buf = Vec::new();
        write_event(&mut buf, ev, decoded, &PrettyConfig { color }).expect("write to Vec succeeds");
        String::from_utf8(buf).expect("output is valid UTF-8")
    }

    #[test]
    fn openat_basic_snapshot() {
        let (ev, decoded) = openat_ok();
        let line = render(&ev, &decoded, false);
        insta::assert_snapshot!("pretty_openat_basic", line);
    }

    #[test]
    fn errno_name_appears_for_negative_ret() {
        let (mut ev, mut decoded) = openat_ok();
        ev.ret = -2;
        decoded.ret = -2;
        let line = render(&ev, &decoded, false);
        assert!(
            line.contains("-2 ENOENT"),
            "expected '-2 ENOENT' in line: {line}"
        );
        assert!(
            line.contains("(No such file or directory)"),
            "expected errno description in line: {line}"
        );
    }

    #[test]
    fn color_absent_when_disabled() {
        let (ev, decoded) = openat_ok();
        let line = render(&ev, &decoded, false);
        assert!(
            !line.contains('\x1b'),
            "expected no ANSI escape in monochrome output: {line:?}"
        );
    }

    #[test]
    fn color_present_when_enabled() {
        let (ev, decoded) = openat_ok();
        let line = render(&ev, &decoded, true);
        assert!(
            line.contains('\x1b'),
            "expected ANSI escape in colored output: {line:?}"
        );
    }

    #[test]
    fn line_terminates_with_newline() {
        let (ev, decoded) = openat_ok();
        let line = render(&ev, &decoded, false);
        assert!(line.ends_with('\n'));
    }
}
