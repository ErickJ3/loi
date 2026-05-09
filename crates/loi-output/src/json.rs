//! JSON-lines formatter, one event per line.
//!
//! Each call to [`write_event`] emits exactly one `\n`-terminated JSON
//! object. The schema is:
//!
//! ```text
//! { "pid", "syscall_nr", "syscall_name", "ret", "duration",
//!   "args": [ { "name", "value" }, ... ],
//!   "errno_name"?  // present only when ret < 0 and resolves
//! }
//! ```
//!
//! `args` carries the *decoded* argument list (from
//! [`DecodedCall`](loi_syscalls::DecodedCall)); the raw `[u64; 6]` register
//! view from [`SyscallEvent`](loi_core::SyscallEvent) is intentionally not
//! re-emitted here to keep each line focused on one shape.
//! `duration` is encoded as nanoseconds.

use crate::format_common::{arg_to_json, errno_of_ret};
use loi_core::SyscallEvent;
use loi_syscalls::DecodedCall;
use serde_json::{Map, Value, json};
use std::io::{self, Write};

/// Write one event as a single JSON object terminated by `\n`.
///
/// # Errors
///
/// Returns any [`io::Error`] surfaced by `w` while writing, or an
/// [`io::ErrorKind::Other`] wrapping a `serde_json` failure (no field of
/// the schema can fail to serialize today, but the conversion is kept for
/// forward compatibility).
pub fn write_event<W: Write>(
    w: &mut W,
    ev: &SyscallEvent,
    decoded: &DecodedCall,
) -> io::Result<()> {
    let nanos = u64::try_from(ev.duration.as_nanos())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let args: Vec<Value> = decoded
        .args
        .iter()
        .map(|(name, arg)| {
            json!({
                "name": *name,
                "value": arg_to_json(arg),
            })
        })
        .collect();

    let mut obj = Map::new();
    obj.insert("pid".to_owned(), json!(ev.pid));
    obj.insert("syscall_nr".to_owned(), json!(ev.syscall_nr));
    obj.insert(
        "syscall_name".to_owned(),
        Value::String(ev.syscall_name.as_ref().to_owned()),
    );
    obj.insert("ret".to_owned(), json!(ev.ret));
    if let Some((sym, _)) = errno_of_ret(ev.ret) {
        obj.insert("errno_name".to_owned(), Value::String(sym));
    }
    obj.insert("duration".to_owned(), json!(nanos));
    obj.insert("args".to_owned(), Value::Array(args));

    serde_json::to_writer(&mut *w, &Value::Object(obj)).map_err(io::Error::other)?;
    w.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::time::Duration;

    use loi_syscalls::{DecodedArg, DecodedCall, FdRepr};

    use super::*;

    fn openat_ok() -> (SyscallEvent, DecodedCall) {
        let event = SyscallEvent::new(
            1234,
            257,
            Cow::Borrowed("openat"),
            [0, 0, 0, 0, 0, 0],
            3,
            Duration::from_micros(12),
        );
        let decoded = DecodedCall {
            args: vec![
                ("dirfd", DecodedArg::Fd(FdRepr::AtFdCwd)),
                ("pathname", DecodedArg::Path("/etc/hosts".to_owned())),
                ("flags", DecodedArg::Flags(vec!["O_RDONLY", "O_CLOEXEC"])),
                ("mode", DecodedArg::Mode(0)),
            ],
            ret: 3,
        };
        (event, decoded)
    }

    fn render(ev: &SyscallEvent, decoded: &DecodedCall) -> Vec<u8> {
        let mut buf = Vec::new();
        write_event(&mut buf, ev, decoded).expect("write to Vec succeeds");
        buf
    }

    #[test]
    fn line_is_parseable_json_object() {
        let (ev, decoded) = openat_ok();
        let buf = render(&ev, &decoded);
        assert_eq!(buf.last(), Some(&b'\n'), "must end with newline");
        let body = &buf[..buf.len() - 1];
        let v: Value = serde_json::from_slice(body).expect("valid JSON");
        assert!(v.is_object(), "expected object");
    }

    #[test]
    fn no_interior_newline_in_record() {
        let (ev, decoded) = openat_ok();
        let buf = render(&ev, &decoded);
        let body = &buf[..buf.len() - 1];
        assert!(
            body.iter().all(|&b| b != b'\n'),
            "no interior newlines allowed"
        );
    }

    #[test]
    fn snapshot_of_openat() {
        let (ev, decoded) = openat_ok();
        let buf = render(&ev, &decoded);
        let s = String::from_utf8(buf).expect("utf8");
        insta::assert_snapshot!("json_openat", s);
    }

    #[test]
    fn errno_name_present_on_negative_ret() {
        let (mut ev, mut decoded) = openat_ok();
        ev.ret = -13;
        decoded.ret = -13;
        let buf = render(&ev, &decoded);
        let body = &buf[..buf.len() - 1];
        let v: Value = serde_json::from_slice(body).expect("valid JSON");
        assert_eq!(v["errno_name"], json!("EACCES"));
    }

    #[test]
    fn errno_name_absent_on_success() {
        let (ev, decoded) = openat_ok();
        let buf = render(&ev, &decoded);
        let body = &buf[..buf.len() - 1];
        let v: Value = serde_json::from_slice(body).expect("valid JSON");
        assert!(
            v.get("errno_name").is_none(),
            "errno_name must be omitted on success"
        );
    }

    #[test]
    fn duration_is_nanoseconds_number() {
        let (ev, decoded) = openat_ok();
        let buf = render(&ev, &decoded);
        let body = &buf[..buf.len() - 1];
        let v: Value = serde_json::from_slice(body).expect("valid JSON");
        assert_eq!(v["duration"], json!(12_000));
    }
}
