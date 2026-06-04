//! Decoder for `execve(pathname, argv, envp) -> int`.
//!
//! `pathname` reads up to `PATH_MAX` via [`crate::decode_path`]. `argv` is
//! a tracee pointer to a NULL-terminated array of `char *`; the walk is
//! capped at [`MAX_ARGV`] entries and each entry's C-string is capped at
//! [`MAX_ARGV_ENTRY_BYTES`] bytes to bound the work the tracer performs
//! per exec.
//!
//! Sentinels in the returned [`DecodedArg::Argv`]:
//!
//! - `"..."` appears as the last entry when the [`MAX_ARGV`] cap is hit
//!   before a NULL terminator is seen.
//! - `"<unreadable>"` appears as the last entry when a mid-walk read
//!   fails after at least one entry has been recorded successfully.
//!
//! Hard failure - when the very first array pointer read fails - is
//! propagated as [`DecodeError::Memory`] so callers see a real decoding
//! error rather than an empty argv.
//!
//! `envp` is surfaced as [`DecodedArg::Ptr`] only; walking the
//! environment is deferred to a follow-up feature to keep per-exec work
//! bounded.

use crate::decode_path;
use crate::decoder::{Category, DecodeCtx, DecodeError, DecodedArg, DecodedCall, Decoder};

/// Maximum number of argv entries decoded per `execve`.
pub const MAX_ARGV: usize = 64;

/// Maximum number of bytes read per argv entry.
pub const MAX_ARGV_ENTRY_BYTES: usize = 256;

const PTR_BYTES: usize = std::mem::size_of::<u64>();

const SENTINEL_OVERFLOW: &str = "...";
const SENTINEL_UNREADABLE: &str = "<unreadable>";

fn decode_argv_entry(pid: i32, addr: u64) -> Result<String, DecodeError> {
    let bytes = loi_memory::read_cstr(pid, addr, MAX_ARGV_ENTRY_BYTES)?;
    Ok(match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(&e.into_bytes()).into_owned(),
    })
}

fn read_ptr_slot(pid: i32, addr: u64) -> Result<u64, DecodeError> {
    let bytes = loi_memory::read_bytes(pid, addr, PTR_BYTES)?;
    let arr: [u8; PTR_BYTES] = bytes
        .try_into()
        .expect("read_bytes returns exactly PTR_BYTES bytes by contract");
    Ok(u64::from_ne_bytes(arr))
}

/// Decoder for the Linux `execve` syscall.
///
/// Stateless; the unit value is `Send + Sync` so a single static instance
/// can be shared across the registry.
#[derive(Debug, Clone, Copy, Default)]
pub struct Execve;

impl Decoder for Execve {
    fn category(&self) -> Category {
        Category::Process
    }

    /// Decode an `execve` call from its syscall registers.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Memory`] when [`crate::decode_path`] cannot
    /// read `pathname`, or when the very first argv-array slot is
    /// unreadable. Subsequent failures are recorded as the
    /// `"<unreadable>"` sentinel; the call still resolves to `Ok`.
    fn decode(&self, ctx: &DecodeCtx) -> Result<DecodedCall, DecodeError> {
        let pathname = decode_path(ctx.pid, ctx.args[0])?;
        let argv = walk_argv(ctx.pid, ctx.args[1])?;
        let envp = ctx.args[2];

        Ok(DecodedCall {
            args: vec![
                ("pathname", DecodedArg::Path(pathname)),
                ("argv", DecodedArg::Argv(argv)),
                ("envp", DecodedArg::Ptr(envp)),
            ],
            ret: ctx.ret,
        })
    }
}

fn walk_argv(pid: i32, argv_addr: u64) -> Result<Vec<String>, DecodeError> {
    let mut entries: Vec<String> = Vec::new();
    let mut cursor = argv_addr;
    let mut overflowed = true;

    for _ in 0..MAX_ARGV {
        let ptr = match read_ptr_slot(pid, cursor) {
            Ok(p) => p,
            Err(e) if entries.is_empty() => return Err(e),
            Err(_) => {
                entries.push(SENTINEL_UNREADABLE.to_owned());
                overflowed = false;
                break;
            }
        };
        if ptr == 0 {
            overflowed = false;
            break;
        }
        if let Ok(s) = decode_argv_entry(pid, ptr) {
            entries.push(s);
        } else {
            entries.push(SENTINEL_UNREADABLE.to_owned());
            overflowed = false;
            break;
        }
        cursor = cursor.saturating_add(PTR_BYTES as u64);
    }

    if overflowed {
        entries.push(SENTINEL_OVERFLOW.to_owned());
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::{Execve, MAX_ARGV, SENTINEL_OVERFLOW, SENTINEL_UNREADABLE};
    use crate::decoder::{DecodeCtx, DecodeError, DecodedArg, Decoder};
    use std::ffi::CString;

    fn self_pid() -> i32 {
        i32::try_from(std::process::id()).expect("pid fits in i32")
    }

    fn build_argv(strings: &[&CString]) -> Vec<*const libc::c_char> {
        let mut v: Vec<*const libc::c_char> = strings.iter().map(|c| c.as_ptr()).collect();
        v.push(std::ptr::null());
        v
    }

    fn argv_arg(call: &super::DecodedCall) -> &[String] {
        let DecodedArg::Argv(v) = &call.args[1].1 else {
            panic!("expected Argv, got {:?}", call.args[1].1);
        };
        v
    }

    #[test]
    fn execve_decoder_reads_pathname_and_two_entry_argv() {
        let path = CString::new("/bin/echo").expect("no interior nul");
        let arg_zero = CString::new("/bin/echo").expect("no interior nul");
        let arg_one = CString::new("hi").expect("no interior nul");
        let argv = build_argv(&[&arg_zero, &arg_one]);

        let ctx = DecodeCtx {
            pid: self_pid(),
            args: [path.as_ptr() as u64, argv.as_ptr() as u64, 0, 0, 0, 0],
            ret: 0,
        };
        let call = Execve.decode(&ctx).expect("decode succeeds");

        let DecodedArg::Path(ref p) = call.args[0].1 else {
            panic!("expected Path, got {:?}", call.args[0].1);
        };
        assert_eq!(p, "/bin/echo");

        let entries = argv_arg(&call);
        assert_eq!(entries, &["/bin/echo".to_owned(), "hi".to_owned()]);
    }

    #[test]
    fn execve_decoder_caps_argv_walk_at_max_argv() {
        let strings: Vec<CString> = (0..100)
            .map(|i| CString::new(format!("arg{i}")).expect("no interior nul"))
            .collect();
        let refs: Vec<&CString> = strings.iter().collect();
        let argv = build_argv(&refs);
        let path = CString::new("/bin/sh").expect("no interior nul");

        let ctx = DecodeCtx {
            pid: self_pid(),
            args: [path.as_ptr() as u64, argv.as_ptr() as u64, 0, 0, 0, 0],
            ret: 0,
        };
        let call = Execve.decode(&ctx).expect("decode succeeds");
        let entries = argv_arg(&call);

        assert_eq!(entries.len(), MAX_ARGV + 1);
        assert_eq!(entries.last().expect("non-empty"), SENTINEL_OVERFLOW);
        assert_eq!(entries[0], "arg0");
        assert_eq!(entries[MAX_ARGV - 1], format!("arg{}", MAX_ARGV - 1));
    }

    #[test]
    fn execve_decoder_surfaces_error_when_argv_pointer_unreadable() {
        let path = CString::new("/bin/sh").expect("no interior nul");
        let ctx = DecodeCtx {
            pid: self_pid(),
            args: [path.as_ptr() as u64, 0x1, 0, 0, 0, 0],
            ret: 0,
        };
        let r = Execve.decode(&ctx);
        assert!(
            matches!(r, Err(DecodeError::Memory(_))),
            "expected Memory error, got {r:?}"
        );
    }

    #[test]
    fn execve_decoder_replaces_truncated_entry_with_unreadable_sentinel() {
        let path = CString::new("/bin/sh").expect("no interior nul");
        let first = CString::new("ok").expect("no interior nul");
        let long: Vec<u8> = vec![b'A'; 4096];
        let argv: Vec<*const libc::c_char> =
            vec![first.as_ptr(), long.as_ptr().cast(), std::ptr::null()];

        let ctx = DecodeCtx {
            pid: self_pid(),
            args: [path.as_ptr() as u64, argv.as_ptr() as u64, 0, 0, 0, 0],
            ret: 0,
        };
        let call = Execve.decode(&ctx).expect("decode succeeds");
        let entries = argv_arg(&call);

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], "ok");
        assert_eq!(entries[1], SENTINEL_UNREADABLE);
    }

    #[test]
    fn execve_decoder_renders_envp_as_ptr() {
        let path = CString::new("/bin/sh").expect("no interior nul");
        let argv: Vec<*const libc::c_char> = vec![std::ptr::null()];
        let ctx = DecodeCtx {
            pid: self_pid(),
            args: [path.as_ptr() as u64, argv.as_ptr() as u64, 0x42, 0, 0, 0],
            ret: 0,
        };
        let call = Execve.decode(&ctx).expect("decode succeeds");
        assert!(
            matches!(call.args[2].1, DecodedArg::Ptr(0x42)),
            "got {:?}",
            call.args[2].1
        );
    }
}
