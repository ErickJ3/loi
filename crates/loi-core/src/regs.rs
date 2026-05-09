//! Per-architecture register access for ptrace syscall stops.
//!
//! At a syscall-entry stop, the kernel exposes the syscall number and the
//! six argument slots through architecture-specific user registers. At a
//! syscall-exit stop, the same struct carries the return value (negative
//! meaning `-errno`). This module hides the layout differences behind a
//! pair of pid-keyed accessors so [`crate::tracer::Tracer`] can stay
//! arch-agnostic.

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!(
    "loi-core register layout is only implemented for x86_64 and aarch64; \
     add an extract_entry/extract_ret pair for the new arch before building"
);

use nix::sys::ptrace;
use nix::unistd::Pid;

/// Read the syscall number and six argument registers for `pid`, which
/// must be currently stopped at a syscall-entry stop.
///
/// # Errors
///
/// Returns the underlying [`nix::Error`] if `ptrace(PTRACE_GETREGS)` (or
/// `PTRACE_GETREGSET` on aarch64) fails.
pub fn read_entry(pid: Pid) -> nix::Result<(u64, [u64; 6])> {
    let regs = ptrace::getregs(pid)?;
    Ok(extract_entry(&regs))
}

/// Read the syscall return value for `pid`, which must be currently
/// stopped at a syscall-exit stop.
///
/// The kernel encodes failure as a negative `-errno` value in the same
/// register that holds successful return values, so callers receive an
/// `i64` and decide on the failure boundary themselves.
///
/// # Errors
///
/// Returns the underlying [`nix::Error`] if `ptrace(PTRACE_GETREGS)` (or
/// `PTRACE_GETREGSET` on aarch64) fails.
pub fn read_exit_ret(pid: Pid) -> nix::Result<i64> {
    let regs = ptrace::getregs(pid)?;
    Ok(extract_ret(&regs))
}

#[cfg(target_arch = "x86_64")]
fn extract_entry(r: &libc::user_regs_struct) -> (u64, [u64; 6]) {
    (r.orig_rax, [r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9])
}

#[cfg(target_arch = "x86_64")]
#[expect(
    clippy::cast_possible_wrap,
    reason = "kernel returns -errno as a signed value in the same register that holds successful returns; reinterpreting the raw u64 as i64 is the documented way to read it"
)]
fn extract_ret(r: &libc::user_regs_struct) -> i64 {
    r.rax as i64
}

#[cfg(target_arch = "aarch64")]
fn extract_entry(r: &libc::user_regs_struct) -> (u64, [u64; 6]) {
    (
        r.regs[8],
        [
            r.regs[0], r.regs[1], r.regs[2], r.regs[3], r.regs[4], r.regs[5],
        ],
    )
}

#[cfg(target_arch = "aarch64")]
#[expect(
    clippy::cast_possible_wrap,
    reason = "kernel returns -errno as a signed value in x0; reinterpreting the raw u64 as i64 is the documented way to read it"
)]
fn extract_ret(r: &libc::user_regs_struct) -> i64 {
    r.regs[0] as i64
}
