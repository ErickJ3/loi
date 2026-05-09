//! Core ptrace-based tracer engine for `loi`.
//!
//! This crate exposes the [`Tracer`] entry point and the [`SyscallEvent`]
//! value type produced for every traced syscall. Output formatting and
//! filtering live in sibling crates.
#![deny(missing_docs)]

pub mod error;
pub mod event;
pub mod tracee;
pub mod tracer;

#[cfg(target_os = "linux")]
mod regs;

pub use error::{Error, Result};
pub use event::SyscallEvent;
pub use tracer::Tracer;
