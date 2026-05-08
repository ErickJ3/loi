//! Error types produced by the core tracer.

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
}

/// Result alias used across the core tracer crate.
pub type Result<T> = std::result::Result<T, Error>;
