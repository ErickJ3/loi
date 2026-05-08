//! The ptrace-based tracer entry point.

use crate::Result;

/// Drives a traced child process, emitting [`crate::SyscallEvent`]s on
/// each syscall exit.
///
/// Stub: see TODOs in [`Tracer::spawn`] and [`Tracer::run`].
pub struct Tracer {}

impl Tracer {
    /// Fork a child running `command` under `ptrace::traceme`, wait for
    /// the initial stop, configure tracing options, and return the
    /// tracer ready to be driven by [`Tracer::run`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if `fork`, `execve`, or any of the
    /// initial `ptrace` setup calls fail.
    pub fn spawn(_command: &[String]) -> Result<Self> {
        // TODO:
        // 1. fork()
        // 2. child: ptrace::traceme(); execve(command)
        // 3. parent: waitpid for initial stop
        // 4. set PTRACE_O_TRACESYSGOOD | TRACEFORK | TRACEVFORK | TRACECLONE
        // 5. return self with state map populated for child pid
        todo!("not implemented")
    }

    /// Run the main wait loop until every traced process has exited.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if `waitpid` or any `ptrace` call fails,
    /// or if the tracee disappears unexpectedly.
    pub fn run(&mut self) -> Result<()> {
        // TODO: main loop
        // - waitpid(-1)
        // - match status: syscall-stop, signal-stop, exit, fork
        // - emit SyscallEvent on entry+exit completion
        todo!("not implemented")
    }
}
