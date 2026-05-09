//! The [`SyscallEvent`] value type emitted by the tracer.

use std::borrow::Cow;
use std::time::Duration;

/// A single completed syscall observation produced by the tracer.
///
/// One event is emitted per syscall *exit*: the tracer pairs the entry
/// stop (which captures `args`) with the exit stop (which captures `ret`
/// and `duration`). Use [`syscall_name`](Self::syscall_name) for the
/// human-readable name and [`syscall_nr`](Self::syscall_nr) for the raw
/// kernel number.
///
/// Construct with [`SyscallEvent::new`] to remain forward-compatible
/// when new fields are added.
///
/// # Examples
///
/// ```
/// use std::borrow::Cow;
/// use std::time::Duration;
/// use loi_core::SyscallEvent;
///
/// let event = SyscallEvent::new(
///     1234,
///     1,
///     Cow::Borrowed("write"),
///     [1, 0, 5, 0, 0, 0],
///     5,
///     Duration::from_micros(12),
/// );
/// assert_eq!(event.syscall_name, "write");
/// ```
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SyscallEvent {
    /// PID of the tracee that executed the syscall.
    pub pid: i32,
    /// Raw kernel syscall number on the tracee architecture.
    pub syscall_nr: u64,
    /// Human-readable syscall name. Borrowed from a static table when
    /// known, owned for synthetic / arch-specific names.
    pub syscall_name: Cow<'static, str>,
    /// Raw register values for the six syscall argument slots
    /// (`rdi, rsi, rdx, r10, r8, r9` on `x86_64`).
    pub args: [u64; 6],
    /// Raw return value. Negative values are kernel `-errno`.
    pub ret: i64,
    /// Wall-clock duration between syscall entry and exit stops.
    /// Serialized as nanoseconds.
    #[cfg_attr(feature = "serde", serde(with = "duration_nanos"))]
    pub duration: Duration,
}

impl SyscallEvent {
    /// Construct a new event from raw tracer state.
    #[must_use]
    pub fn new(
        pid: i32,
        syscall_nr: u64,
        syscall_name: Cow<'static, str>,
        args: [u64; 6],
        ret: i64,
        duration: Duration,
    ) -> Self {
        Self {
            pid,
            syscall_nr,
            syscall_name,
            args,
            ret,
            duration,
        }
    }
}

#[cfg(feature = "serde")]
mod duration_nanos {
    use std::time::Duration;

    use serde::{Serializer, ser::Error as _};

    pub(super) fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        let nanos = u64::try_from(d.as_nanos()).map_err(S::Error::custom)?;
        s.serialize_u64(nanos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SyscallEvent {
        SyscallEvent::new(
            42,
            1,
            Cow::Borrowed("write"),
            [1, 0xdead_beef, 5, 0, 0, 0],
            5,
            Duration::from_nanos(1_500),
        )
    }

    #[test]
    fn syscall_name_borrows_static_str_without_alloc() {
        let event = sample();
        assert!(matches!(event.syscall_name, Cow::Borrowed(_)));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serializes_duration_as_nanoseconds() {
        let event = sample();
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["duration"], serde_json::json!(1_500u64));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serializes_pid_and_name() {
        let event = sample();
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["pid"], 42);
        assert_eq!(json["syscall_name"], "write");
    }
}
