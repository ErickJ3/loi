//! Integration tests for [`loi_core::Tracer::run`]: spawn small Linux
//! commands under the tracer and assert the emitted [`SyscallEvent`]
//! stream and the exit semantics of the loop.
//!
//! Every test grabs [`TRACER_LOCK`] for its full duration. Cargo runs
//! integration tests in parallel by default, and `Tracer::run` waits on
//! `waitpid(-1)`, which would happily reap a sibling test's tracee and
//! desync both wait loops. Holding a process-global mutex serialises
//! the wait loops without forcing the consumer of `Tracer` to do so.

#![cfg(target_os = "linux")]

use loi_core::{SyscallEvent, Tracer};
use std::collections::HashSet;
use std::sync::mpsc;
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

static TRACER_LOCK: Mutex<()> = Mutex::new(());

fn lock_tracer() -> MutexGuard<'static, ()> {
    TRACER_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn spawn(cmd: &[&str]) -> Tracer {
    let argv: Vec<String> = cmd.iter().map(|s| (*s).to_string()).collect();
    Tracer::spawn(&argv).unwrap_or_else(|e| panic!("spawn {cmd:?}: {e}"))
}

fn collect_events(tracer: Tracer) -> Vec<SyscallEvent> {
    let mut events = Vec::new();
    tracer.run(|ev| events.push(ev.clone())).expect("run");
    events
}

fn collect_events_follow(cmd: &[&str], follow: bool) -> (i32, Vec<SyscallEvent>) {
    let tracer = spawn(cmd).with_follow_forks(follow);
    let root = tracer.root_pid().as_raw();
    let mut events = Vec::new();
    tracer.run(|ev| events.push(ev.clone())).expect("run");
    (root, events)
}

#[test]
fn run_true_emits_events_and_returns_ok() {
    let _guard = lock_tracer();
    let events = collect_events(spawn(&["/bin/true"]));
    assert!(
        !events.is_empty(),
        "expected at least one SyscallEvent from /bin/true"
    );
}

#[test]
fn run_echo_hello_emits_write_event() {
    let _guard = lock_tracer();
    let events = collect_events(spawn(&["/bin/echo", "hello"]));
    let write = events
        .iter()
        .find(|e| e.syscall_name == "write" && e.ret >= 6);
    assert!(
        write.is_some(),
        "expected a write event with ret >= 6; got {events:#?}"
    );
}

#[test]
fn entry_exit_pairing_yields_nonzero_duration() {
    let _guard = lock_tracer();
    let events = collect_events(spawn(&["/bin/true"]));
    assert!(
        events.iter().any(|e| e.duration > Duration::ZERO),
        "expected at least one event with non-zero duration; got {events:#?}"
    );
}

#[test]
fn follow_forks_true_emits_events_from_multiple_pids() {
    let _guard = lock_tracer();
    let (_root, events) =
        collect_events_follow(&["/bin/sh", "-c", "echo a; (echo b; echo c)"], true);
    let pids: HashSet<i32> = events.iter().map(|e| e.pid).collect();
    assert!(
        pids.len() >= 2,
        "expected events from at least two distinct pids under follow_forks=true; got {pids:?}"
    );
}

#[test]
fn follow_forks_false_emits_events_only_from_root_pid() {
    let _guard = lock_tracer();
    let (root, events) =
        collect_events_follow(&["/bin/sh", "-c", "echo a; (echo b; echo c)"], false);
    let pids: HashSet<i32> = events.iter().map(|e| e.pid).collect();
    assert_eq!(
        pids,
        HashSet::from([root]),
        "expected events only from root pid {root} under follow_forks=false; got {pids:?}"
    );
}

#[test]
fn run_returns_ok_when_child_outlives_parent() {
    let _guard = lock_tracer();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let result = (|| -> loi_core::Result<()> {
            let tracer = Tracer::spawn(&[
                String::from("/bin/sh"),
                String::from("-c"),
                String::from("(true) &"),
            ])?
            .with_follow_forks(false);
            tracer.run(|_| {})
        })();
        let _ = tx.send(result);
    });
    let result = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("tracer.run did not finish within 5s; loop may not be draining children");
    result.expect("tracer.run should return Ok when the child outlives the root");
}

#[test]
fn signal_delivery_stop_is_passed_through() {
    let _guard = lock_tracer();
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("signal-delivered");
    let marker_str = marker.to_str().expect("utf-8 path").to_owned();

    let script = format!("trap 'touch {marker_str}; exit 0' USR1; kill -USR1 $$; sleep 1; exit 1");
    let tracer = spawn(&["/bin/sh", "-c", &script]);
    let _events = collect_events(tracer);

    assert!(
        marker.exists(),
        "expected the SIGUSR1 trap to have run (marker file at {marker_str:?}), \
         indicating the tracer re-injected the signal"
    );
}
