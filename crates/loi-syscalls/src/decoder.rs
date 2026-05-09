//! Shared decoder traits and helpers.
//!
//! Per-syscall decoders in [`crate::decoders`] implement [`Decoder`] and
//! call the helpers in this module to turn raw register values + tracee
//! memory into a structured [`DecodedCall`] that formatters consume.

use loi_memory::MemError;

/// Cap for [`decode_path`]. Mirrors Linux `PATH_MAX` (4096 bytes).
pub const PATH_MAX: usize = 4096;

/// `AT_FDCWD` sentinel value passed for `dirfd` arguments.
const AT_FDCWD: i64 = -100;

/// Context passed to every per-syscall [`Decoder::decode`] call.
///
/// The tracer pairs entry and exit stops, then hands the decoder the pid,
/// the six syscall argument registers, and the return value.
#[derive(Debug, Clone, Copy)]
pub struct DecodeCtx {
    /// Tracee process id.
    pub pid: i32,
    /// Raw syscall argument registers (`rdi`/`rsi`/... on `x86_64`).
    pub args: [u64; 6],
    /// Return value from the syscall exit stop.
    pub ret: i64,
}

/// Errors a [`Decoder`] can surface. Decoders never panic on tracee state.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// A tracee memory read failed.
    #[error("tracee memory read failed: {0}")]
    Memory(#[from] MemError),
}

/// Rendered file-descriptor argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FdRepr {
    /// `AT_FDCWD` sentinel (`-100`), used by `*at` syscalls.
    AtFdCwd,
    /// Negative non-sentinel value; the kernel treats this as invalid.
    Invalid,
    /// Concrete fd value (`>= 0`).
    Num(i32),
}

/// One decoded syscall argument, in the order it appears in the call.
///
/// Per-syscall decoders pick the variant that matches the argument's
/// semantic shape; formatters ([`crate`] consumers) render each variant.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DecodedArg {
    /// NUL-terminated path read from tracee memory, lossy UTF-8.
    Path(String),
    /// File descriptor.
    Fd(FdRepr),
    /// Bitset rendered as the names of the bits that were set.
    Flags(Vec<&'static str>),
    /// Permission/mode bits (e.g. `open` mode argument).
    Mode(u32),
    /// Generic signed integer argument.
    Int(i64),
    /// Generic unsigned integer argument.
    Uint(u64),
    /// Buffer captured from tracee memory.
    Bytes {
        /// Prefix actually read (possibly truncated).
        inline: Vec<u8>,
        /// Original length the syscall referenced.
        total: usize,
    },
}

/// Output of [`Decoder::decode`]: labeled args plus the syscall return value.
#[derive(Debug, Clone)]
pub struct DecodedCall {
    /// Decoded arguments paired with a stable label per syscall.
    pub args: Vec<(&'static str, DecodedArg)>,
    /// Syscall return value (mirrors `DecodeCtx::ret`; copied for convenience).
    pub ret: i64,
}

/// Per-syscall decoder. Implementations live in [`crate::decoders`].
pub trait Decoder: Send + Sync {
    /// Decode one syscall invocation from its [`DecodeCtx`] into a
    /// structured [`DecodedCall`].
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] when a tracee memory read fails. Decoders
    /// must not panic on bad tracee state; surface every failure as a
    /// typed error so the tracer can keep running.
    fn decode(&self, ctx: &DecodeCtx) -> Result<DecodedCall, DecodeError>;
}

/// Read a NUL-terminated path from tracee memory, lossy-UTF-8 decoded.
///
/// Reuses the `Vec<u8>` allocation when the path is already valid UTF-8.
/// Falls back to [`String::from_utf8_lossy`] on invalid sequences.
///
/// # Errors
///
/// Returns [`DecodeError::Memory`] when the underlying
/// [`loi_memory::read_cstr`] fails or runs past [`PATH_MAX`] without a
/// NUL terminator.
pub fn decode_path(pid: i32, addr: u64) -> Result<String, DecodeError> {
    let bytes = loi_memory::read_cstr(pid, addr, PATH_MAX)?;
    match String::from_utf8(bytes) {
        Ok(s) => Ok(s),
        Err(e) => Ok(String::from_utf8_lossy(&e.into_bytes()).into_owned()),
    }
}

/// Map a raw `i64` register value to an [`FdRepr`].
///
/// `AT_FDCWD` (`-100`) is recognised explicitly; any other negative value
/// becomes [`FdRepr::Invalid`]. Non-negative values become
/// [`FdRepr::Num`]; the cast is total because Linux fds always fit in
/// `i32` (the kernel returns `int`).
///
/// # Examples
///
/// ```
/// use loi_syscalls::{FdRepr, decode_fd};
/// assert_eq!(decode_fd(-100), FdRepr::AtFdCwd);
/// assert_eq!(decode_fd(-1), FdRepr::Invalid);
/// assert_eq!(decode_fd(3), FdRepr::Num(3));
/// ```
#[must_use]
pub fn decode_fd(raw: i64) -> FdRepr {
    match raw {
        AT_FDCWD => FdRepr::AtFdCwd,
        n if n < 0 => FdRepr::Invalid,
        n => {
            debug_assert!(
                n <= i64::from(i32::MAX),
                "kernel fd should fit in i32 by ABI; got {n}"
            );
            FdRepr::Num(i32::try_from(n).unwrap_or(i32::MAX))
        }
    }
}

/// Decode a bitset against a static `(mask, name)` table.
///
/// Each entry's `mask` is checked with `raw & mask == mask`. Entries with
/// `mask == 0` are skipped: zero-valued constants like `O_RDONLY` carry
/// access-mode semantics and are decoded by their owning syscall, not by
/// this generic helper.
///
/// Empty-bitset fast path: returns [`Vec::new`] (no allocation) when
/// `raw == 0`.
///
/// # Examples
///
/// ```
/// use loi_syscalls::decode_flags;
/// const TABLE: &[(u64, &str)] = &[(0o2_000_000, "O_CLOEXEC"), (0o100, "O_CREAT")];
/// assert_eq!(decode_flags(0o2_000_000, TABLE), vec!["O_CLOEXEC"]);
/// assert!(decode_flags(0, TABLE).is_empty());
/// ```
#[must_use]
pub fn decode_flags(raw: u64, table: &'static [(u64, &'static str)]) -> Vec<&'static str> {
    if raw == 0 {
        return Vec::new();
    }
    table
        .iter()
        .filter(|&&(mask, _)| mask != 0 && raw & mask == mask)
        .map(|&(_, name)| name)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use super::{DecodeError, FdRepr, MemError, decode_fd, decode_flags, decode_path};

    fn self_pid() -> i32 {
        i32::try_from(std::process::id()).expect("pid fits in i32")
    }

    #[test]
    fn decode_path_reads_cstring_from_self() {
        let cs = CString::new("/tmp/x").expect("no interior nul");
        let got = decode_path(self_pid(), cs.as_ptr() as u64).expect("decode_path self read");
        assert_eq!(got, "/tmp/x");
    }

    #[test]
    fn decode_fd_at_fdcwd() {
        assert_eq!(decode_fd(-100), FdRepr::AtFdCwd);
    }

    #[test]
    fn decode_fd_invalid() {
        assert_eq!(decode_fd(-1), FdRepr::Invalid);
    }

    #[test]
    fn decode_fd_num() {
        assert_eq!(decode_fd(3), FdRepr::Num(3));
    }

    #[test]
    fn decode_flags_picks_set_bits() {
        const TABLE: &[(u64, &str)] = &[
            (0o4000, "O_NONBLOCK"),
            (0o2_000_000, "O_CLOEXEC"),
            (0o100, "O_CREAT"),
        ];
        let raw = 0o2_000_000 | 0o100;
        let got = decode_flags(raw, TABLE);
        assert_eq!(got, vec!["O_CLOEXEC", "O_CREAT"]);
    }

    #[test]
    fn decode_flags_empty_returns_empty_vec() {
        const TABLE: &[(u64, &str)] = &[(0o2_000_000, "O_CLOEXEC")];
        assert!(decode_flags(0, TABLE).is_empty());
    }

    #[test]
    fn decode_flags_empty_does_not_allocate() {
        const TABLE: &[(u64, &str)] = &[(0o2_000_000, "O_CLOEXEC")];
        assert_eq!(decode_flags(0, TABLE).capacity(), 0);
    }

    #[test]
    fn decode_flags_skips_zero_mask_entries() {
        const TABLE: &[(u64, &str)] = &[(0, "O_RDONLY"), (0o2_000_000, "O_CLOEXEC")];
        let got = decode_flags(0o2_000_000, TABLE);
        assert_eq!(got, vec!["O_CLOEXEC"]);
    }

    #[test]
    fn decode_error_wraps_mem_error_via_from() {
        let mem = MemError::TruncatedCstr { max: 16 };
        let de: DecodeError = mem.into();
        assert!(matches!(
            de,
            DecodeError::Memory(MemError::TruncatedCstr { max: 16 })
        ));
    }
}
