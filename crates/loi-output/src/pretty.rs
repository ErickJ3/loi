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

use crate::format_common::{
    RET_ENOENT, errno_of_ret, fmt_duration, is_path_lookup, lookup_basename, render_arg_text,
};
use loi_core::SyscallEvent;
use loi_syscalls::{Category, DecodedCall};
use owo_colors::{OwoColorize, Style};
use std::io::{self, Write};

/// Tunable knobs for the [`write_event`] formatter.
///
/// `color` toggles ANSI escapes; `aligned` toggles the running-max column
/// padding described in the module docs. Both default to `false` via
/// [`Default`]; [`PrettyConfig::new`] sets the visual-affordance flags
/// (`aligned`, `category_colors`, `dim_lookups`, `group_lookups`) to
/// `true` to match the behaviour terminal callers want.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
#[allow(clippy::struct_excessive_bools)]
pub struct PrettyConfig {
    /// Whether to emit ANSI color escapes. Callers that target a terminal
    /// typically gate this on [`std::io::IsTerminal`] for the real sink.
    pub color: bool,
    /// Whether to right-pad the pid and syscall-name columns to the running
    /// max widths tracked in [`PrettyState`]. Defaults to `true` via
    /// [`PrettyConfig::new`]; snapshot tests and machine consumers can flip
    /// it off with [`PrettyConfig::aligned`].
    pub aligned: bool,
    /// Whether the syscall-name token is colored by its decoder's
    /// [`Category`]. Requires `color` to take effect. Defaults to `true`
    /// via [`PrettyConfig::new`]; opt out with
    /// [`PrettyConfig::category_colors`].
    pub category_colors: bool,
    /// Whether ENOENT returns from path-lookup syscalls are rendered with
    /// the whole line dimmed, so dynamic-linker probe bursts recede from
    /// the eye. Requires `color`. Defaults to `true`.
    pub dim_lookups: bool,
    /// Whether consecutive lookup events targeting the same path basename
    /// are rendered with a `↳` tree prefix in place of the `[pid]` bracket,
    /// so a fan-out of library probes reads as one logical search.
    /// Defaults to `true`.
    pub group_lookups: bool,
}

impl PrettyConfig {
    /// Build a [`PrettyConfig`] with `color` set as requested and the
    /// visual-affordance flags (alignment, category colors, dim lookups,
    /// group lookups) all on.
    ///
    /// The struct is `#[non_exhaustive]`, so callers outside this crate
    /// cannot use the struct literal form; this constructor keeps the
    /// builder noise out of every call site.
    #[must_use]
    pub fn new(color: bool) -> Self {
        Self {
            color,
            aligned: true,
            category_colors: true,
            dim_lookups: true,
            group_lookups: true,
        }
    }

    /// Toggle the running-max column alignment. Returns `self` for chaining.
    #[must_use]
    pub fn aligned(mut self, aligned: bool) -> Self {
        self.aligned = aligned;
        self
    }

    /// Toggle category-driven coloring of the syscall-name token. When
    /// `false`, the name renders in the default bold-cyan style regardless
    /// of the decoder's [`Category`]. Returns `self` for chaining.
    #[must_use]
    pub fn category_colors(mut self, on: bool) -> Self {
        self.category_colors = on;
        self
    }

    /// Toggle dimming of ENOENT-on-lookup events. Returns `self` for
    /// chaining.
    #[must_use]
    pub fn dim_lookups(mut self, on: bool) -> Self {
        self.dim_lookups = on;
        self
    }

    /// Toggle the `↳`-prefix grouping of same-basename lookup bursts.
    /// Returns `self` for chaining.
    #[must_use]
    pub fn group_lookups(mut self, on: bool) -> Self {
        self.group_lookups = on;
        self
    }
}

/// Running-max widths and look-back state owned by the caller and
/// threaded through successive [`write_event`] calls.
///
/// Each call grows the tracked widths to the maximum of the value being
/// rendered, then pads the current line to those widths. The
/// `last_basename` / `last_pid` fields support the same-basename burst
/// grouping (see [`PrettyConfig::group_lookups`]). See the module docs
/// for the wider rationale.
#[derive(Debug, Default, Clone)]
pub struct PrettyState {
    pid_width: usize,
    name_width: usize,
    last_basename: Option<String>,
    last_pid: Option<i32>,
}

impl PrettyState {
    /// Build a fresh tracker with both widths at zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Tree-prefix glyph emitted in place of the `[pid]` bracket on
/// continuation events in a same-basename lookup burst.
const BURST_PREFIX: &str = "↳ ";

/// Write one syscall event as a single pretty line ending with `\n`.
///
/// `ev` provides the pid, syscall name, return value, and duration; `decoded`
/// provides the labelled, semantically-typed argument list rendered inside
/// the parentheses. `category` is the decoder-declared family the formatter
/// uses to colour the syscall-name token (the caller looks it up via
/// [`loi_syscalls::Registry::category`]); pass `None` for syscalls without a
/// registered decoder. When `cfg.aligned` is `true`, `state` is updated to
/// the running max of the pid and name widths and used to right-pad both
/// columns; it also tracks the previous pid and lookup-basename so this
/// call can decide whether the event is a continuation of a same-target
/// burst.
///
/// # Errors
///
/// Returns any [`io::Error`] surfaced by `w` while writing.
pub fn write_event<W: Write>(
    w: &mut W,
    ev: &SyscallEvent,
    decoded: &DecodedCall,
    category: Option<Category>,
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

    let current_basename = lookup_basename(name, decoded);
    let is_continuation = cfg.group_lookups
        && current_basename.is_some()
        && current_basename.map(str::to_owned) == state.last_basename
        && state.last_pid == Some(ev.pid);

    let dim_line = cfg.dim_lookups && cfg.color && ev.ret == RET_ENOENT && is_path_lookup(name);
    let name_style = name_style(*cfg, category, dim_line);

    if cfg.color {
        write_pid_column_color(w, &pid, pid_pad, is_continuation)?;
        write!(w, " {}", name.style(name_style))?;
        write_spaces(w, name_pad)?;
        write!(w, "({args_joined}) = ")?;
        write_ret(w, ev.ret, true, dim_line)?;
        writeln!(w, " {}", duration.style(Style::new().dimmed()))?;
    } else {
        write_pid_column_plain(w, &pid, pid_pad, is_continuation)?;
        write!(
            w,
            " {name:<name_w$}({args_joined}) = ",
            name_w = name.len() + name_pad
        )?;
        write_ret(w, ev.ret, false, false)?;
        writeln!(w, " {duration}")?;
    }

    if let Some(b) = current_basename {
        state.last_basename = Some(b.to_owned());
        state.last_pid = Some(ev.pid);
    }
    Ok(())
}

/// Render the pid column in color mode, swapping the `[pid]` bracket for
/// the `↳ ` glyph on continuation events.
///
/// The column width is preserved either way (`pid_width = state.pid_width`)
/// so the syscall-name column stays aligned across burst and non-burst
/// events.
fn write_pid_column_color<W: Write>(
    w: &mut W,
    pid: &str,
    pid_pad: usize,
    is_continuation: bool,
) -> io::Result<()> {
    if is_continuation {
        let total = pid.len() + pid_pad;
        let lead = total.saturating_sub(BURST_PREFIX.chars().count());
        write_spaces(w, lead)?;
        write!(w, "{}", BURST_PREFIX.dimmed())
    } else {
        write!(w, "{}", pid.dimmed())?;
        write_spaces(w, pid_pad)
    }
}

/// Plain-text mirror of [`write_pid_column_color`] for the `cfg.color = false`
/// branch. Keeps snapshot output free of ANSI escapes.
fn write_pid_column_plain<W: Write>(
    w: &mut W,
    pid: &str,
    pid_pad: usize,
    is_continuation: bool,
) -> io::Result<()> {
    if is_continuation {
        let total = pid.len() + pid_pad;
        let lead = total.saturating_sub(BURST_PREFIX.chars().count());
        write_spaces(w, lead)?;
        write!(w, "{BURST_PREFIX}")
    } else {
        write!(w, "{pid:<pid_w$}", pid_w = pid.len() + pid_pad)
    }
}

/// Pick the [`Style`] for the syscall-name token.
///
/// Precedence: a dimmed lookup-failure line overrides everything, then
/// category color when enabled, then the default bold-cyan (matches the
/// pre-category behaviour for opt-out callers and `Category::Other`).
fn name_style(cfg: PrettyConfig, category: Option<Category>, dim_line: bool) -> Style {
    if dim_line {
        return Style::new().dimmed();
    }
    if !cfg.color {
        return Style::new();
    }
    if !cfg.category_colors {
        return Style::new().bold().cyan();
    }
    match category {
        Some(Category::File) => Style::new().bold().cyan(),
        Some(Category::FileMeta) => Style::new().bold().blue(),
        Some(Category::Memory) => Style::new().bold().magenta(),
        Some(Category::Process) => Style::new().bold().yellow(),
        // `Category::Other`, `None`, and any future `#[non_exhaustive]`
        // variant fall through to plain bold so an unknown family stays
        // legible without picking a colour at random.
        _ => Style::new().bold(),
    }
}

fn write_spaces<W: Write>(w: &mut W, n: usize) -> io::Result<()> {
    if n == 0 {
        return Ok(());
    }
    write!(w, "{:n$}", "", n = n)
}

fn write_ret<W: Write>(w: &mut W, ret: i64, color: bool, dim: bool) -> io::Result<()> {
    match errno_of_ret(ret) {
        Some((sym, desc)) => {
            if dim {
                write!(w, "{} {} ({})", ret.dimmed(), sym.dimmed(), desc.dimmed())
            } else if color {
                write!(w, "{} {} ({})", ret.bold().red(), sym.bold().red(), desc)
            } else {
                write!(w, "{ret} {sym} ({desc})")
            }
        }
        None => {
            if dim {
                write!(w, "{}", ret.dimmed())
            } else if color {
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
        render_with(ev, decoded, None, PrettyConfig::new(color))
    }

    fn render_with(
        ev: &SyscallEvent,
        decoded: &DecodedCall,
        category: Option<Category>,
        cfg: PrettyConfig,
    ) -> String {
        let mut buf = Vec::new();
        let mut state = PrettyState::default();
        write_event(&mut buf, ev, decoded, category, &cfg, &mut state)
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
        let cfg = PrettyConfig::new(false).group_lookups(false);
        let mut state = PrettyState::default();
        let mut buf = Vec::new();
        let (ev1, dec1) = open_ok(1234);
        write_event(&mut buf, &ev1, &dec1, None, &cfg, &mut state).unwrap();
        let (ev2, dec2) = openat_ok();
        write_event(&mut buf, &ev2, &dec2, None, &cfg, &mut state).unwrap();
        let (ev3, dec3) = open_ok(1234);
        write_event(&mut buf, &ev3, &dec3, None, &cfg, &mut state).unwrap();
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
        write_event(&mut buf, &ev1, &dec1, None, &cfg, &mut state).unwrap();
        let (ev2, dec2) = read_ok(99_999);
        write_event(&mut buf, &ev2, &dec2, None, &cfg, &mut state).unwrap();
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
        let cfg = PrettyConfig::new(false).aligned(false).group_lookups(false);
        let mut state = PrettyState::default();
        let mut buf = Vec::new();
        let (ev1, dec1) = open_ok(1234);
        write_event(&mut buf, &ev1, &dec1, None, &cfg, &mut state).unwrap();
        let (ev2, dec2) = openat_ok();
        write_event(&mut buf, &ev2, &dec2, None, &cfg, &mut state).unwrap();
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

    fn enoent_openat(pid: i32, path: &str) -> (SyscallEvent, DecodedCall) {
        let event = SyscallEvent::new(
            pid,
            257,
            Cow::Borrowed("openat"),
            [0, 0, 0, 0, 0, 0],
            -2,
            Duration::from_micros(5),
        );
        let decoded = DecodedCall {
            args: vec![
                ("dirfd", DecodedArg::Fd(FdRepr::AtFdCwd)),
                ("pathname", DecodedArg::Path(path.to_owned())),
                ("flags", DecodedArg::Flags(vec!["O_RDONLY", "O_CLOEXEC"])),
                ("mode", DecodedArg::Mode(0)),
            ],
            ret: -2,
        };
        (event, decoded)
    }

    fn mmap_ok(pid: i32) -> (SyscallEvent, DecodedCall) {
        let event = SyscallEvent::new(
            pid,
            9,
            Cow::Borrowed("mmap"),
            [0, 0, 0, 0, 0, 0],
            0x7f00_0000_0000,
            Duration::from_micros(8),
        );
        let decoded = DecodedCall {
            args: vec![
                ("addr", DecodedArg::Hex(0)),
                ("length", DecodedArg::Uint(4096)),
                ("prot", DecodedArg::Flags(vec!["PROT_READ"])),
                ("flags", DecodedArg::Flags(vec!["MAP_PRIVATE"])),
                ("fd", DecodedArg::Fd(FdRepr::Num(3))),
                ("offset", DecodedArg::Uint(0)),
            ],
            ret: 0x7f00_0000_0000,
        };
        (event, decoded)
    }

    fn contains_color_escape(s: &str, code: u8) -> bool {
        let code = code.to_string();
        // owo-colors emits the SGR parameters in either order, so accept
        // both: standalone `\x1b[36m`, or combined with bold as
        // `\x1b[36;1m` / `\x1b[1;36m`.
        let solo = format!("\x1b[{code}m");
        let after_bold = format!("\x1b[1;{code}m");
        let before_bold = format!("\x1b[{code};1m");
        s.contains(&solo) || s.contains(&after_bold) || s.contains(&before_bold)
    }

    #[test]
    fn pretty_category_color_file_is_cyan() {
        let (ev, decoded) = openat_ok();
        let cfg = PrettyConfig::new(true);
        let line = render_with(&ev, &decoded, Some(Category::File), cfg);
        assert!(
            contains_color_escape(&line, 36),
            "expected cyan escape for File category: {line:?}"
        );
    }

    #[test]
    fn pretty_category_color_memory_is_magenta() {
        let (ev, decoded) = mmap_ok(1234);
        let cfg = PrettyConfig::new(true);
        let line = render_with(&ev, &decoded, Some(Category::Memory), cfg);
        assert!(
            contains_color_escape(&line, 35),
            "expected magenta escape for Memory category: {line:?}"
        );
    }

    #[test]
    fn pretty_category_colors_off_falls_back_to_cyan() {
        let (ev, decoded) = mmap_ok(1234);
        let cfg = PrettyConfig::new(true).category_colors(false);
        let line = render_with(&ev, &decoded, Some(Category::Memory), cfg);
        assert!(
            !contains_color_escape(&line, 35),
            "expected no magenta escape with category_colors off: {line:?}"
        );
        assert!(
            contains_color_escape(&line, 36),
            "expected cyan fallback with category_colors off: {line:?}"
        );
    }

    #[test]
    fn pretty_dim_lookup_enoent_dims_full_line() {
        let (ev, decoded) = enoent_openat(1234, "/usr/lib/libc.so.6");
        let cfg = PrettyConfig::new(true);
        let line = render_with(&ev, &decoded, Some(Category::File), cfg);
        assert!(
            line.contains("\x1b[2m"),
            "expected dim escape in ENOENT-on-lookup line: {line:?}"
        );
        assert!(
            !contains_color_escape(&line, 31),
            "expected no bright red errno when dim is active: {line:?}"
        );
    }

    #[test]
    fn pretty_dim_off_keeps_red_errno() {
        let (ev, decoded) = enoent_openat(1234, "/usr/lib/libc.so.6");
        let cfg = PrettyConfig::new(true).dim_lookups(false);
        let line = render_with(&ev, &decoded, Some(Category::File), cfg);
        assert!(
            contains_color_escape(&line, 31),
            "expected red errno escape with dim_lookups off: {line:?}"
        );
    }

    #[test]
    fn pretty_group_same_basename_tree_prefix() {
        let cfg = PrettyConfig::new(false);
        let mut state = PrettyState::default();
        let mut buf = Vec::new();
        for path in [
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/usr/lib/libc.so.6",
            "/usr/local/lib/libc.so.6",
        ] {
            let (ev, dec) = enoent_openat(1234, path);
            write_event(&mut buf, &ev, &dec, Some(Category::File), &cfg, &mut state).unwrap();
        }
        let out = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3, "expected three lines: {out:?}");
        assert!(
            lines[0].contains("[1234]"),
            "first line should carry pid bracket: {:?}",
            lines[0]
        );
        assert!(
            !lines[1].contains("[1234]") && lines[1].contains(BURST_PREFIX.trim_end()),
            "second line should carry burst prefix, not pid: {:?}",
            lines[1]
        );
        assert!(
            !lines[2].contains("[1234]") && lines[2].contains(BURST_PREFIX.trim_end()),
            "third line should carry burst prefix, not pid: {:?}",
            lines[2]
        );
    }

    #[test]
    fn pretty_group_resets_on_basename_change() {
        let cfg = PrettyConfig::new(false);
        let mut state = PrettyState::default();
        let mut buf = Vec::new();
        let (ev1, dec1) = enoent_openat(1234, "/usr/lib/libc.so.6");
        write_event(
            &mut buf,
            &ev1,
            &dec1,
            Some(Category::File),
            &cfg,
            &mut state,
        )
        .unwrap();
        let (ev2, dec2) = enoent_openat(1234, "/usr/lib/libm.so.6");
        write_event(
            &mut buf,
            &ev2,
            &dec2,
            Some(Category::File),
            &cfg,
            &mut state,
        )
        .unwrap();
        let out = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert!(
            lines[1].contains("[1234]"),
            "basename switch should restart the pid bracket: {:?}",
            lines[1]
        );
        assert!(
            !lines[1].contains(BURST_PREFIX.trim_end()),
            "no burst prefix when basename changes: {:?}",
            lines[1]
        );
    }

    #[test]
    fn pretty_group_resets_on_pid_change() {
        let cfg = PrettyConfig::new(false);
        let mut state = PrettyState::default();
        let mut buf = Vec::new();
        let (ev1, dec1) = enoent_openat(1234, "/usr/lib/libc.so.6");
        write_event(
            &mut buf,
            &ev1,
            &dec1,
            Some(Category::File),
            &cfg,
            &mut state,
        )
        .unwrap();
        let (ev2, dec2) = enoent_openat(5678, "/usr/lib/libc.so.6");
        write_event(
            &mut buf,
            &ev2,
            &dec2,
            Some(Category::File),
            &cfg,
            &mut state,
        )
        .unwrap();
        let out = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert!(
            lines[1].contains("[5678]"),
            "pid switch should restart the pid bracket: {:?}",
            lines[1]
        );
    }

    #[test]
    fn pretty_no_group_when_opted_out() {
        let cfg = PrettyConfig::new(false).group_lookups(false);
        let mut state = PrettyState::default();
        let mut buf = Vec::new();
        let (ev1, dec1) = enoent_openat(1234, "/a/libc.so.6");
        write_event(
            &mut buf,
            &ev1,
            &dec1,
            Some(Category::File),
            &cfg,
            &mut state,
        )
        .unwrap();
        let (ev2, dec2) = enoent_openat(1234, "/b/libc.so.6");
        write_event(
            &mut buf,
            &ev2,
            &dec2,
            Some(Category::File),
            &cfg,
            &mut state,
        )
        .unwrap();
        let out = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert!(
            lines[1].contains("[1234]"),
            "with grouping off, every line should keep its pid bracket: {:?}",
            lines[1]
        );
        assert!(
            !lines[1].contains(BURST_PREFIX.trim_end()),
            "no burst prefix with grouping off: {:?}",
            lines[1]
        );
    }
}
