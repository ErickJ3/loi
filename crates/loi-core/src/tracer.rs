//! The ptrace-based tracer entry point.

use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::sys::ptrace::{self, Options};
use nix::sys::signal::{Signal, raise};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, execvp, fork, pipe2, read, write};
use std::collections::HashMap;
use std::convert::Infallible;
use std::ffi::CString;
use std::os::fd::OwnedFd;

use crate::tracee::Tracee;
use crate::{Error, Result};

const PTRACE_OPTIONS: Options = Options::PTRACE_O_TRACESYSGOOD
    .union(Options::PTRACE_O_TRACEFORK)
    .union(Options::PTRACE_O_TRACEVFORK)
    .union(Options::PTRACE_O_TRACECLONE)
    .union(Options::PTRACE_O_TRACEEXEC)
    .union(Options::PTRACE_O_EXITKILL);

const EXEC_FAILURE_EXIT: i32 = 127;

/// Drives a traced child process, emitting [`crate::SyscallEvent`]s on
/// each syscall exit.
///
/// The instance is constructed via [`Tracer::spawn`] and then driven with
/// [`Tracer::run`]. After [`Tracer::spawn`] returns successfully, the root
/// tracee is stopped at the `PTRACE_EVENT_EXEC` event-stop produced by
/// the kernel for its successful `execve`; [`Tracer::run`] resumes from
/// that stop and walks the syscall trace from there.
#[derive(Debug)]
pub struct Tracer {
    root_pid: Pid,
    tracees: HashMap<Pid, Tracee>,
}

impl Tracer {
    /// Fork a child running `command` under `ptrace::traceme`, wait for
    /// the initial stop, configure tracing options, drive the child past
    /// `execve`, and return a [`Tracer`] ready to be driven by
    /// [`Tracer::run`].
    ///
    /// Exec failures in the child are reported back to the parent via a
    /// `CLOEXEC` pipe, so this function returns [`Error::Exec`] rather
    /// than letting the failure leak into the run loop.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidCommand`] if `command` is empty.
    /// - [`Error::Nul`] if any argument contains an interior NUL byte.
    /// - [`Error::Ptrace`] if `pipe2`, `fork`, or any subsequent ptrace /
    ///   wait call fails.
    /// - [`Error::Exec`] if the child's `execvp` failed; the inner
    ///   [`Errno`] is the value reported by the child via the pipe.
    /// - [`Error::TraceeGone`] if the child died before reaching the
    ///   first post-`execve` ptrace stop without reporting an errno.
    pub fn spawn(command: &[String]) -> Result<Self> {
        if command.is_empty() {
            return Err(Error::InvalidCommand);
        }

        let argv: Vec<CString> = command
            .iter()
            .map(|s| CString::new(s.as_str()))
            .collect::<std::result::Result<_, _>>()?;

        let (read_end, write_end) = pipe2(OFlag::O_CLOEXEC)?;

        // SAFETY: fork runs on the main thread of a binary that has not
        // yet spawned worker threads, so no other thread can observe
        // inconsistent post-fork state. The child path uses only
        // async-signal-safe operations (`OwnedFd` drop -> `close`,
        // `write`, `_exit`, `ptrace::traceme`, `raise`, `execvp`)
        // between fork and exec.
        match unsafe { fork() }? {
            ForkResult::Child => {
                drop(read_end);
                run_child(&argv, write_end);
            }
            ForkResult::Parent { child } => {
                drop(write_end);
                finish_parent(child, read_end)
            }
        }
    }

    /// PID of the originally spawned root tracee.
    #[must_use]
    pub fn root_pid(&self) -> Pid {
        self.root_pid
    }

    /// Run the main wait loop until every traced process has exited.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if `waitpid` or any `ptrace` call fails,
    /// or if the tracee disappears unexpectedly.
    pub fn run(&mut self) -> Result<()> {
        todo!("not implemented")
    }
}

impl Drop for Tracer {
    fn drop(&mut self) {
        for &pid in self.tracees.keys() {
            if let Err(e) = ptrace::detach(pid, Signal::SIGKILL) {
                tracing::trace!(?pid, error = %e, "ptrace::detach during Drop failed");
            }
            match waitpid(pid, None) {
                Ok(_) | Err(Errno::ECHILD) => {}
                Err(e) => tracing::trace!(?pid, error = %e, "waitpid during Drop failed"),
            }
        }
    }
}

/// Child arm of [`Tracer::spawn`]: install ptrace, stop, and exec.
///
/// Diverges: on failure writes the errno to `write_end` and `_exit`s; on
/// success `execvp` does not return.
fn run_child(argv: &[CString], write_end: OwnedFd) -> ! {
    let errno = match try_child(argv) {
        Ok(never) => match never {},
        Err(e) => e,
    };
    let bytes = (errno as i32).to_ne_bytes();
    let _ = write_all(&write_end, &bytes);
    drop(write_end);
    // SAFETY: `_exit` is async-signal-safe and unconditionally exits the
    // process without running atexit handlers, which is the only valid
    // way to leave the child after a post-fork pre-exec failure.
    unsafe { libc::_exit(EXEC_FAILURE_EXIT) };
}

fn try_child(argv: &[CString]) -> std::result::Result<Infallible, Errno> {
    ptrace::traceme()?;
    raise(Signal::SIGSTOP)?;
    let argv0 = argv.first().ok_or(Errno::EINVAL)?;
    match execvp(argv0, argv) {
        Ok(never) => match never {},
        Err(e) => Err(e),
    }
}

/// Parent arm of [`Tracer::spawn`]: wait for the initial SIGSTOP, set
/// options, drive past `execve`, and return the populated [`Tracer`].
fn finish_parent(child: Pid, read_end: OwnedFd) -> Result<Tracer> {
    match waitpid(child, None)? {
        WaitStatus::Stopped(_, Signal::SIGSTOP) => {}
        WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _) => {
            return Err(read_exec_errno(&read_end));
        }
        other => {
            tracing::warn!(?other, "unexpected status before initial SIGSTOP");
            return Err(Error::TraceeGone);
        }
    }

    ptrace::setoptions(child, PTRACE_OPTIONS)?;
    // Use PTRACE_CONT (not PTRACE_SYSCALL): we only want to wake on
    // either the kernel-delivered PTRACE_EVENT_EXEC (exec succeeded) or
    // the child's own exit (exec failed). Stopping at execve's
    // syscall-enter would block the child before its CLOEXEC pipe could
    // close, deadlocking the parent if it tried to confirm exec status
    // by reading the pipe.
    ptrace::cont(child, Option::<Signal>::None)?;

    match waitpid(child, None)? {
        WaitStatus::PtraceEvent(_, _, _) | WaitStatus::Stopped(_, Signal::SIGTRAP) => {}
        WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _) => {
            return Err(read_exec_errno(&read_end));
        }
        other => {
            tracing::warn!(?other, "unexpected status after exec");
            return Err(Error::TraceeGone);
        }
    }
    drop(read_end);

    let mut tracees = HashMap::new();
    tracees.insert(child, Tracee::new_root());
    Ok(Tracer {
        root_pid: child,
        tracees,
    })
}

/// Read up to four bytes from `read_end` and translate them into a
/// reportable error. Four bytes is an [`Errno`] payload from the child;
/// fewer bytes (or zero == EOF) means the child died without reporting,
/// which we surface as [`Error::TraceeGone`].
fn read_exec_errno(read_end: &OwnedFd) -> Error {
    let mut buf = [0u8; 4];
    let n = read_full(read_end, &mut buf).unwrap_or(0);
    if n == buf.len() {
        Error::Exec(Errno::from_raw(i32::from_ne_bytes(buf)))
    } else {
        Error::TraceeGone
    }
}

fn write_all(fd: &OwnedFd, mut buf: &[u8]) -> nix::Result<()> {
    while !buf.is_empty() {
        match write(fd, buf) {
            Ok(0) => return Err(Errno::EIO),
            Ok(n) => buf = &buf[n..],
            Err(Errno::EINTR) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn read_full(fd: &OwnedFd, buf: &mut [u8]) -> nix::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match read(fd, &mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(Errno::EINTR) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn spawn_true_succeeds_and_reports_root_pid() {
        let tracer = Tracer::spawn(&[String::from("/bin/true")]).expect("spawn /bin/true");
        assert!(tracer.root_pid().as_raw() > 0);
    }

    #[test]
    fn empty_command_returns_invalid_command() {
        match Tracer::spawn(&[]) {
            Err(Error::InvalidCommand) => {}
            other => panic!("expected InvalidCommand, got {other:?}"),
        }
    }

    #[test]
    fn nonexistent_binary_surfaces_exec_failure() {
        let err =
            Tracer::spawn(&[String::from("/nonexistent/loi-test-bin")]).expect_err("must fail");
        match err {
            Error::Exec(Errno::ENOENT) => {}
            other => panic!("expected Exec(ENOENT), got {other:?}"),
        }
    }
}
