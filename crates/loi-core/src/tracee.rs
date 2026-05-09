//! Per-tracee state: entry/exit pairing, signal handling, fork tracking.
//!
//! A [`Tracee`] is the value the [`crate::tracer::Tracer`] keeps for every
//! ptraced process: it tracks where the tracee currently sits in the
//! syscall protocol so the next [`crate::SyscallEvent`] can be assembled
//! by pairing an entry stop with its matching exit stop. Only the
//! [`Phase::Entry`] variant is used until [`crate::tracer::Tracer::run`]
//! starts emitting events.

use std::time::Instant;

/// Where in the syscall protocol a given tracee currently sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Next ptrace syscall-stop will be a syscall-entry.
    Entry,
    /// Last stop was an entry; the next is the matching exit. The entry
    /// args and the wall-clock instant of the entry stop are saved so
    /// [`crate::SyscallEvent::duration`] can be computed at exit time.
    Exit {
        /// Raw kernel syscall number captured at entry.
        nr: u64,
        /// Raw register values for the six argument slots at entry.
        args: [u64; 6],
        /// Monotonic instant of the entry stop, used to derive duration.
        started_at: Instant,
    },
}

/// State tracked for one ptraced process.
#[derive(Debug)]
pub struct Tracee {
    /// Current entry/exit phase.
    pub phase: Phase,
}

impl Tracee {
    /// Build a tracee that has just finished `execve` and whose next
    /// ptrace stop is the first syscall-entry of the new program.
    #[must_use]
    pub fn new_root() -> Self {
        Self {
            phase: Phase::Entry,
        }
    }
}
