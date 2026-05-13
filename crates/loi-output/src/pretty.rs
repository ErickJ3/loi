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
//!
//! # Column alignment
//!
//! When [`PrettyConfig::aligned`] is `true` (the default), [`write_event`]
//! right-pads the bracketed pid and the syscall name to the widest values
//! observed so far via the caller-owned [`PrettyState`]. Alignment is
//! running-max only: the first event renders at its own widths, and later
//! events grow each column when a wider value appears. There is no buffering
//! pass, so lines already written stay at the widths they had when emitted.
//! Callers that need byte-for-byte unpadded output (snapshot tests, machine
//! readers) opt out with [`PrettyConfig::aligned(false)`][PrettyConfig::aligned].

use crate::format_common::{errno_of_ret, fmt_duration, render_arg_text};
use loi_core::SyscallEvent;
use loi_syscalls::DecodedCall;
use owo_colors::OwoColorize;
use std::io::{self, Write};

/// Tunable knobs for the [`write_event`] formatter.
///
/// `color` toggles ANSI escapes; `aligned` toggles the running-max column
/// padding described in the module docs. Both default to `false` via
/// [`Default`]; [`PrettyConfig::new`] sets `aligned: true` to match the
/// behaviour terminal callers want.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct PrettyConfig {
    /// Whether to emit ANSI color escapes. Callers that target a terminal
    /// typically gate this on [`std::io::IsTerminal`] for the real sink.
    pub color: bool,
    /// Whether to right-pad the pid and syscall-name columns to the running
    /// max widths tracked in [`PrettyState`]. Defaults to `true` via
    /// [`PrettyConfig::new`]; snapshot tests and machine consumers can flip
    /// it off with [`PrettyConfig::aligned`].
    pub aligned: bool,
}

impl PrettyConfig {
    /// Build a [`PrettyConfig`] with `color` set as requested and column
    /// alignment enabled.
    ///
    /// The struct is `#[non_exhaustive]`, so callers outside this crate
    /// cannot use the struct literal form; this constructor keeps the
    /// builder noise out of every call site.
    #[must_use]
    pub fn new(color: bool) -> Self {
        Self {
            color,
            aligned: true,
        }
    }

    /// Toggle the running-max column alignment. Returns `self` for chaining.
    #[must_use]
    pub fn aligned(mut self, aligned: bool) -> Self {
        self.aligned = aligned;
        self
    }
}

/// Running-max widths owned by the caller and threaded through successive
/// [`write_event`] calls.
///
/// Each call grows the tracked widths to the maximum of the value being
/// rendered, then pads the current line to those widths. See the module
/// docs for the wider rationale.
#[derive(Debug, Default, Clone)]
pub struct PrettyState {
    pid_width: usize,
    name_width: usize,
}

impl PrettyState {
    /// Build a fresh tracker with both widths at zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Write one syscall event as a single pretty line ending with `\n`.
///
/// `ev` provides the pid, syscall name, return value, and duration; `decoded`
/// provides the labelled, semantically-typed argument list rendered inside
/// the parentheses. When `cfg.aligned` is `true`, `state` is updated to the
/// running max of the pid and name widths and used to right-pad both columns.
///
/// # Errors
///
/// Returns any [`io::Error`] surfaced by `w` while writing.
pub fn write_event<W: Write>(
    w: &mut W,
    ev: &SyscallEvent,
    decoded: &DecodedCall,
    cfg: &PrettyConfig,
    state: &mut PrettyState,
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

    let (pid_pad, name_pad) = if cfg.aligned {
        state.pid_width = state.pid_width.max(pid.len());
        state.name_width = state.name_width.max(name.len());
        (
            state.pid_width.saturating_sub(pid.len()),
            state.name_width.saturating_sub(name.len()),
        )
    } else {
        (0, 0)
    };

    if cfg.color {
        write!(w, "{}", pid.dimmed())?;
        write_spaces(w, pid_pad)?;
        write!(w, " {}", name.bold().cyan())?;
        write_spaces(w, name_pad)?;
        write!(w, "({args_joined}) = ")?;
        write_ret(w, ev.ret, true)?;
        writeln!(w, " {}", duration.dimmed())?;
    } else {
        write!(
            w,
            "{pid:<pid_w$} {name:<name_w$}({args_joined}) = ",
            pid_w = pid.len() + pid_pad,
            name_w = name.len() + name_pad
        )?;
        write_ret(w, ev.ret, false)?;
        writeln!(w, " {duration}")?;
    }
    Ok(())
}

fn write_spaces<W: Write>(w: &mut W, n: usize) -> io::Result<()> {
    if n == 0 {
        return Ok(());
    }
    write!(w, "{:n$}", "", n = n)
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

    fn open_ok(pid: i32) -> (SyscallEvent, DecodedCall) {
        let event = SyscallEvent::new(
            pid,
            2,
            Cow::Borrowed("open"),
            [0, 0, 0, 0, 0, 0],
            3,
            Duration::from_micros(7),
        );
        let decoded = DecodedCall {
            args: vec![
                ("pathname", DecodedArg::Path("/etc/hosts".to_owned())),
                ("flags", DecodedArg::Flags(vec!["O_RDONLY"])),
            ],
            ret: 3,
        };
        (event, decoded)
    }

    fn read_ok(pid: i32) -> (SyscallEvent, DecodedCall) {
        let event = SyscallEvent::new(
            pid,
            0,
            Cow::Borrowed("read"),
            [0, 0, 0, 0, 0, 0],
            0,
            Duration::from_micros(3),
        );
        let decoded = DecodedCall {
            args: vec![
                ("fd", DecodedArg::Fd(FdRepr::Num(3))),
                ("buf", DecodedArg::Ptr(0x1000)),
                ("count", DecodedArg::Uint(64)),
            ],
            ret: 0,
        };
        (event, decoded)
    }

    fn render(ev: &SyscallEvent, decoded: &DecodedCall, color: bool) -> String {
        let mut buf = Vec::new();
        let mut state = PrettyState::default();
        write_event(&mut buf, ev, decoded, &PrettyConfig::new(color), &mut state)
            .expect("write to Vec succeeds");
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

    #[test]
    fn pretty_align_two_names() {
        let cfg = PrettyConfig::new(false);
        let mut state = PrettyState::default();
        let mut buf = Vec::new();
        let (ev1, dec1) = open_ok(1234);
        write_event(&mut buf, &ev1, &dec1, &cfg, &mut state).unwrap();
        let (ev2, dec2) = openat_ok();
        write_event(&mut buf, &ev2, &dec2, &cfg, &mut state).unwrap();
        let (ev3, dec3) = open_ok(1234);
        write_event(&mut buf, &ev3, &dec3, &cfg, &mut state).unwrap();
        let out = String::from_utf8(buf).unwrap();
        insta::assert_snapshot!("pretty_align_two_names", out);
        let lines: Vec<&str> = out.lines().collect();
        let col_open = lines[2].find('(').expect("line 3 has '('");
        let col_openat = lines[1].find('(').expect("line 2 has '('");
        assert_eq!(
            col_open, col_openat,
            "after openat widened the name column, the trailing open() should align with it:\n{out}"
        );
    }

    #[test]
    fn pretty_align_pid_widens() {
        let cfg = PrettyConfig::new(false);
        let mut state = PrettyState::default();
        let mut buf = Vec::new();
        let (ev1, dec1) = read_ok(1);
        write_event(&mut buf, &ev1, &dec1, &cfg, &mut state).unwrap();
        let (ev2, dec2) = read_ok(99_999);
        write_event(&mut buf, &ev2, &dec2, &cfg, &mut state).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2, "expected two lines, got: {out:?}");
        let name_col_1 = lines[0].find("read").expect("name in line 1");
        let name_col_2 = lines[1].find("read").expect("name in line 2");
        assert!(
            name_col_2 > name_col_1,
            "expected wider pid column on line 2: line1 name@{name_col_1}, line2 name@{name_col_2}\n{out}"
        );
    }

    #[test]
    fn pretty_align_off_when_opted_out() {
        let cfg = PrettyConfig::new(false).aligned(false);
        let mut state = PrettyState::default();
        let mut buf = Vec::new();
        let (ev1, dec1) = open_ok(1234);
        write_event(&mut buf, &ev1, &dec1, &cfg, &mut state).unwrap();
        let (ev2, dec2) = openat_ok();
        write_event(&mut buf, &ev2, &dec2, &cfg, &mut state).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(
            lines[0].starts_with("[1234] open("),
            "line1 unpadded: {:?}",
            lines[0]
        );
        assert!(
            lines[1].starts_with("[1234] openat("),
            "line2 unpadded: {:?}",
            lines[1]
        );
    }
}
