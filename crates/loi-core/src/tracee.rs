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
    /// `true` while the tracee has not yet consumed the auto-attach
    /// `SIGSTOP` group-stop the kernel delivers to a freshly-cloned
    /// child of a tracer with `PTRACE_O_TRACEFORK`/`VFORK`/`CLONE`. The
    /// run loop swallows that single `SIGSTOP` instead of re-injecting
    /// it; subsequent `Stopped(_, SIGSTOP)` stops are real signal
    /// deliveries and are passed through.
    pub awaiting_initial_sigstop: bool,
    /// `true` while the tracee still owes the run loop one syscall-stop
    /// that should be ignored without flipping [`Self::phase`]. This
    /// covers the syscall-exit-stop the kernel emits after a
    /// `PTRACE_EVENT_EXEC` stop: the matching syscall-entry-stop was
    /// suppressed by the kernel (the pre-exec process was a different
    /// program), so pairing it as an entry would shift every subsequent
    /// event by one stop.
    pub skip_next_syscall_stop: bool,
}

impl Tracee {
    /// Build a tracee that has just finished `execve` and whose next
    /// ptrace stop is the syscall-exit-stop of that initial `execve`.
    /// The root tracee is past its initial `SIGSTOP` by the time
    /// [`crate::tracer::Tracer::spawn`] returns, so it does not need
    /// the initial-`SIGSTOP` swallow, but it still owes one bogus
    /// post-`EVENT_EXEC` syscall-stop that the run loop must drop.
    #[must_use]
    pub fn new_root() -> Self {
        Self {
            phase: Phase::Entry,
            awaiting_initial_sigstop: false,
            skip_next_syscall_stop: true,
        }
    }

    /// Build a tracee that was just auto-attached as a child of an
    /// existing tracee via `PTRACE_EVENT_FORK`/`VFORK`/`CLONE`. Its
    /// first `SIGSTOP` is the kernel's group-stop and must be
    /// consumed without re-injection.
    #[must_use]
    pub fn new_child() -> Self {
        Self {
            phase: Phase::Entry,
            awaiting_initial_sigstop: true,
            skip_next_syscall_stop: false,
        }
    }
}
