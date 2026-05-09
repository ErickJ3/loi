//! Error types produced by the core tracer.

use nix::errno::Errno;
use std::ffi::NulError;
use thiserror::Error;

/// Errors returned by the core tracer engine.
///
/// Variants wrap the underlying cause from `nix`/`std::io` when relevant,
/// or describe a tracer-specific condition (the tracee disappeared, or a
/// syscall number had no entry in the registry).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// A `ptrace` system call returned an error.
    #[error("ptrace error: {0}")]
    Ptrace(#[from] nix::Error),

    /// An I/O operation against the tracee or process state failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The tracee process exited or was killed before tracing finished.
    #[error("tracee terminated unexpectedly")]
    TraceeGone,

    /// A syscall number was observed that has no decoder/name registered.
    #[error("unknown syscall number: {0}")]
    UnknownSyscall(u64),

    /// The command vector passed to [`crate::Tracer::spawn`] was empty.
    #[error("invalid command: empty argv")]
    InvalidCommand,

    /// `execvp` in the freshly-forked child failed; the errno is
    /// reported back to the parent through a `CLOEXEC` pipe.
    #[error("exec failed: {0}")]
    Exec(Errno),

    /// A command argument contained an interior NUL byte and could not
    /// be converted into a [`std::ffi::CString`].
    #[error("argument contains NUL byte: {0}")]
    Nul(#[from] NulError),
}

/// Result alias used across the core tracer crate.
pub type Result<T> = std::result::Result<T, Error>;
