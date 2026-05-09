//! Tracee memory readers for the `loi` syscall tracer.
//!
//! Two leaf primitives, both addressing memory in another process by `(pid, addr)`:
//!
//! - [`read_bytes`] reads exactly `len` bytes from the tracee.
//! - [`read_cstr`] reads bytes up to the first NUL (or returns
//!   [`MemError::TruncatedCstr`] when none is found within `max`).
//!
//! The primary path is [`nix::sys::uio::process_vm_readv`], which works
//! against any pid the caller can `ptrace`-attach to (including its own
//! pid, which is what the unit tests exercise). When the kernel rejects
//! the read with `EPERM` (Yama `ptrace_scope`, restricted cgroup, etc.),
//! the implementation routes to a `ptrace(PTRACE_PEEKDATA)` fallback.
//! The fallback body is not yet implemented; the dispatch is wired and
//! currently returns [`MemError::Ptrace`] with `ENOSYS`.
#![deny(missing_docs)]

use nix::errno::Errno;
use nix::sys::uio::{RemoteIoVec, process_vm_readv};
use nix::unistd::Pid;
use std::io::IoSliceMut;

/// Errors returned by the tracee memory readers.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MemError {
    /// `process_vm_readv` returned an error or a short read.
    #[error("process_vm_readv failed: {0}")]
    Vm(Errno),
    /// `ptrace(PTRACE_PEEKDATA)` returned an error.
    #[error("ptrace PEEKDATA failed: {0}")]
    Ptrace(Errno),
    /// [`read_cstr`] reached `max` bytes without finding a NUL terminator.
    #[error("c-string not terminated within {max} bytes")]
    TruncatedCstr {
        /// The cap that was reached.
        max: usize,
    },
}

/// Convenience alias for results returned by this crate.
pub type Result<T> = std::result::Result<T, MemError>;

/// Page-size hint used for [`read_cstr`] chunking.
///
/// `process_vm_readv` already handles arbitrary spans, but capping each
/// call at the next page boundary means a partial read on a later
/// unmapped page does not lose the prefix bytes we already collected.
/// 4 KiB is the base page size on x86\_64 and aarch64 Linux; other arches
/// (large-page kernels, ppc64) only see this as a chunk-size knob, never
/// a correctness invariant.
const PAGE_SIZE: usize = 4096;

/// Read exactly `len` bytes from `pid`'s address space starting at `addr`.
///
/// Uses `process_vm_readv`; on `EPERM` routes to a `ptrace PEEKDATA`
/// fallback whose body is not yet implemented.
///
/// # Errors
///
/// - [`MemError::Vm`] when `process_vm_readv` returns an error or a
///   short read (treated as `EFAULT` because callers ask for an exact
///   length).
/// - [`MemError::Ptrace`] when the PEEKDATA fallback fails.
pub fn read_bytes(pid: i32, addr: u64, len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let base = usize::try_from(addr).map_err(|_| MemError::Vm(Errno::EFAULT))?;
    let remote = [RemoteIoVec { base, len }];
    let mut local = [IoSliceMut::new(&mut buf)];

    match process_vm_readv(Pid::from_raw(pid), &mut local, &remote) {
        Ok(n) if n == len => Ok(buf),
        Ok(_) => Err(MemError::Vm(Errno::EFAULT)),
        Err(Errno::EPERM) => read_via_ptrace(pid, addr, len),
        Err(e) => Err(MemError::Vm(e)),
    }
}

/// Read a NUL-terminated byte string from `pid`, up to `max` bytes.
///
/// Returns the bytes up to but not including the first NUL. Reads in
/// chunks bounded by the next 4 KiB page boundary so a later unmapped
/// page does not poison the prefix.
///
/// # Errors
///
/// - [`MemError::TruncatedCstr`] when `max` bytes are scanned with no NUL.
/// - Any error returned by [`read_bytes`] for the underlying chunk read.
pub fn read_cstr(pid: i32, addr: u64, max: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(max.min(256));
    let mut cursor = addr;
    let mut remaining = max;

    while remaining > 0 {
        let next_page = (cursor | (PAGE_SIZE as u64 - 1)) + 1;
        let to_page = usize::try_from(next_page - cursor).unwrap_or(PAGE_SIZE);
        let chunk = remaining.min(to_page);
        let bytes = read_bytes(pid, cursor, chunk)?;
        if let Some(i) = bytes.iter().position(|&b| b == 0) {
            out.extend_from_slice(&bytes[..i]);
            return Ok(out);
        }
        out.extend_from_slice(&bytes);
        cursor += chunk as u64;
        remaining -= chunk;
    }

    Err(MemError::TruncatedCstr { max })
}

/// PEEKDATA fallback for [`read_bytes`] when `process_vm_readv` returns `EPERM`.
///
/// Stub: returns [`MemError::Ptrace`] with `ENOSYS`. The loop body
/// (`c_long`-sized reads, last-word masking when `len` is not
/// word-aligned) lands once a tracer harness can drive a real ptrace
/// stop end-to-end.
fn read_via_ptrace(_pid: i32, _addr: u64, _len: usize) -> Result<Vec<u8>> {
    Err(MemError::Ptrace(Errno::ENOSYS))
}

#[cfg(test)]
mod tests {
    use super::{MemError, read_bytes, read_cstr};
    use nix::errno::Errno;
    use std::ffi::CString;

    fn self_pid() -> i32 {
        i32::try_from(std::process::id()).expect("pid fits in i32")
    }

    #[test]
    fn mem_error_displays_truncated_variant() {
        let e = MemError::TruncatedCstr { max: 16 };
        assert!(format!("{e}").contains("16"));
    }

    #[test]
    fn read_bytes_against_self_returns_known_bytes() {
        let buf: Vec<u8> = (0u8..32).collect();
        let got = read_bytes(self_pid(), buf.as_ptr() as u64, buf.len()).expect("self read");
        assert_eq!(got, buf);
    }

    #[test]
    fn read_bytes_bogus_pid_returns_vm_esrch() {
        let r = read_bytes(i32::MAX, 0x1000, 4);
        assert!(matches!(r, Err(MemError::Vm(Errno::ESRCH))), "got {r:?}");
    }

    #[test]
    fn read_cstr_stops_at_nul() {
        let cs = CString::new("hello").expect("no interior nul");
        let got = read_cstr(self_pid(), cs.as_ptr() as u64, 64).expect("cstr read");
        assert_eq!(got, b"hello");
    }

    #[test]
    fn read_cstr_truncated_returns_error() {
        let bytes = [b'A'; 32];
        let r = read_cstr(self_pid(), bytes.as_ptr() as u64, 16);
        assert!(
            matches!(r, Err(MemError::TruncatedCstr { max: 16 })),
            "got {r:?}"
        );
    }

    #[test]
    #[ignore = "needs a real ptrace stop; exercised by the tracer integration suite"]
    fn read_bytes_falls_back_to_ptrace_on_eperm() {}
}
