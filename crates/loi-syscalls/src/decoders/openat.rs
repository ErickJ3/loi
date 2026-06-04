//! Decoder for `openat(dirfd, pathname, flags, mode) -> fd`.
//!
//! Reads `pathname` from tracee memory via [`crate::decode_path`], maps
//! `dirfd` (with `AT_FDCWD` recognised) via [`crate::decode_fd`], and
//! splits `flags` into the access-mode bits and the rest of the bitset.
//! `mode` is exposed unconditionally as raw bits; formatters decide
//! whether to render it.

use crate::decoder::{
    Category, DecodeCtx, DecodeError, DecodedArg, DecodedCall, Decoder, c_int_to_u64,
};
use crate::{decode_fd, decode_path};

const O_ACCMODE: u64 = 0o3;

const O_TMPFILE_MASK: u64 = c_int_to_u64(libc::O_TMPFILE);
const O_DIRECTORY_MASK: u64 = c_int_to_u64(libc::O_DIRECTORY);

// O_TMPFILE on Linux is defined as `__O_TMPFILE | O_DIRECTORY`, so a naive
// bitset scan would emit O_DIRECTORY whenever O_TMPFILE is set. The decoder
// suppresses that double emission below to match strace's behavior.
const OPEN_FLAGS_TABLE: &[(u64, &str)] = &[
    (c_int_to_u64(libc::O_CREAT), "O_CREAT"),
    (c_int_to_u64(libc::O_EXCL), "O_EXCL"),
    (c_int_to_u64(libc::O_NOCTTY), "O_NOCTTY"),
    (c_int_to_u64(libc::O_TRUNC), "O_TRUNC"),
    (c_int_to_u64(libc::O_APPEND), "O_APPEND"),
    (c_int_to_u64(libc::O_NONBLOCK), "O_NONBLOCK"),
    (c_int_to_u64(libc::O_DSYNC), "O_DSYNC"),
    (c_int_to_u64(libc::O_DIRECT), "O_DIRECT"),
    (c_int_to_u64(libc::O_NOFOLLOW), "O_NOFOLLOW"),
    (c_int_to_u64(libc::O_NOATIME), "O_NOATIME"),
    (c_int_to_u64(libc::O_CLOEXEC), "O_CLOEXEC"),
    (c_int_to_u64(libc::O_PATH), "O_PATH"),
    (O_TMPFILE_MASK, "O_TMPFILE"),
    (O_DIRECTORY_MASK, "O_DIRECTORY"),
];

fn access_mode_name(flags: u64) -> Option<&'static str> {
    match flags & O_ACCMODE {
        0 => Some("O_RDONLY"),
        1 => Some("O_WRONLY"),
        2 => Some("O_RDWR"),
        _ => None,
    }
}

fn decode_open_flags(flags: u64) -> Vec<&'static str> {
    let mut out = Vec::with_capacity(OPEN_FLAGS_TABLE.len() + 1);
    if let Some(mode) = access_mode_name(flags) {
        out.push(mode);
    }
    let tmpfile_set = flags & O_TMPFILE_MASK == O_TMPFILE_MASK;
    for &(mask, name) in OPEN_FLAGS_TABLE {
        if mask == 0 {
            continue;
        }
        if mask == O_DIRECTORY_MASK && tmpfile_set {
            continue;
        }
        if flags & mask == mask {
            out.push(name);
        }
    }
    out
}

/// Decoder for the Linux `openat` syscall.
///
/// Stateless; the unit value is `Send + Sync` so a single static instance
/// can be shared across the registry.
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenAt;

impl Decoder for OpenAt {
    fn category(&self) -> Category {
        Category::File
    }

    /// Decode an `openat` call from its syscall registers.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Memory`] when [`crate::decode_path`] fails
    /// to read `pathname` from the tracee.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "dirfd is `int` and mode_t is 32 bits on Linux; only the low 32 bits carry the value"
    )]
    fn decode(&self, ctx: &DecodeCtx) -> Result<DecodedCall, DecodeError> {
        let dirfd = i64::from(ctx.args[0] as i32);
        let pathname_addr = ctx.args[1];
        let flags = ctx.args[2];
        let mode = ctx.args[3] as u32;

        let pathname = decode_path(ctx.pid, pathname_addr)?;

        Ok(DecodedCall {
            args: vec![
                ("dirfd", DecodedArg::Fd(decode_fd(dirfd))),
                ("pathname", DecodedArg::Path(pathname)),
                ("flags", DecodedArg::Flags(decode_open_flags(flags))),
                ("mode", DecodedArg::Mode(mode)),
            ],
            ret: ctx.ret,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{OpenAt, decode_open_flags};
    use crate::decoder::{DecodeCtx, DecodeError, DecodedArg, Decoder, FdRepr};
    use std::ffi::CString;

    fn self_pid() -> i32 {
        i32::try_from(std::process::id()).expect("pid fits in i32")
    }

    fn ctx_with_path(path: &CString, dirfd: u64, flags: u64, mode: u64, ret: i64) -> DecodeCtx {
        DecodeCtx {
            pid: self_pid(),
            args: [dirfd, path.as_ptr() as u64, flags, mode, 0, 0],
            ret,
        }
    }

    fn basic_call() -> super::DecodedCall {
        let path = CString::new("/tmp/x").expect("no interior nul");
        let ctx = ctx_with_path(&path, 3, 0, 0, 7);
        OpenAt.decode(&ctx).expect("decode succeeds against self")
    }

    #[test]
    fn decoder_emits_four_labeled_args_in_order() {
        let call = basic_call();
        let labels: Vec<&str> = call.args.iter().map(|(l, _)| *l).collect();
        assert_eq!(labels, vec!["dirfd", "pathname", "flags", "mode"]);
    }

    #[test]
    fn decoder_decodes_dirfd_as_num() {
        let call = basic_call();
        assert!(
            matches!(&call.args[0].1, DecodedArg::Fd(FdRepr::Num(3))),
            "got {:?}",
            call.args[0].1
        );
    }

    #[test]
    fn decoder_reads_pathname_from_tracee_memory() {
        let call = basic_call();
        let DecodedArg::Path(ref p) = call.args[1].1 else {
            panic!("expected Path, got {:?}", call.args[1].1);
        };
        assert_eq!(p, "/tmp/x");
    }

    #[test]
    fn decoder_renders_default_flags_as_rdonly() {
        let call = basic_call();
        let DecodedArg::Flags(ref f) = call.args[2].1 else {
            panic!("expected Flags, got {:?}", call.args[2].1);
        };
        assert_eq!(f, &vec!["O_RDONLY"]);
    }

    #[test]
    fn decoder_passes_through_ret_value() {
        let call = basic_call();
        assert_eq!(call.ret, 7);
    }

    #[test]
    fn at_fdcwd_renders_as_label_not_number() {
        let path = CString::new("/etc/hosts").expect("no interior nul");
        let dirfd = (-100i64).cast_unsigned();
        let ctx = ctx_with_path(&path, dirfd, 0, 0, 5);
        let call = OpenAt.decode(&ctx).expect("decode succeeds");

        match &call.args[0].1 {
            DecodedArg::Fd(FdRepr::AtFdCwd) => {}
            other => panic!("expected AtFdCwd, got {other:?}"),
        }
    }

    #[test]
    fn create_wronly_trunc_produces_all_three_flags() {
        let path = CString::new("/tmp/out").expect("no interior nul");
        let flags = (libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC) as u64;
        let ctx = ctx_with_path(&path, (-100i64).cast_unsigned(), flags, 0o644, 9);
        let call = OpenAt.decode(&ctx).expect("decode succeeds");

        let DecodedArg::Flags(names) = &call.args[2].1 else {
            panic!("expected Flags variant");
        };
        assert!(names.contains(&"O_WRONLY"), "flags: {names:?}");
        assert!(names.contains(&"O_CREAT"), "flags: {names:?}");
        assert!(names.contains(&"O_TRUNC"), "flags: {names:?}");

        match &call.args[3].1 {
            DecodedArg::Mode(0o644) => {}
            other => panic!("mode: expected Mode(0o644), got {other:?}"),
        }
    }

    #[test]
    fn bad_pathname_addr_returns_decode_error() {
        let ctx = DecodeCtx {
            pid: self_pid(),
            args: [(-100i64).cast_unsigned(), 0x1, 0, 0, 0, 0],
            ret: -1,
        };
        let r = OpenAt.decode(&ctx);
        assert!(
            matches!(r, Err(DecodeError::Memory(_))),
            "expected Memory error, got {r:?}"
        );
    }

    #[test]
    fn decode_open_flags_empty_yields_only_access_mode() {
        let got = decode_open_flags(0);
        assert_eq!(got, vec!["O_RDONLY"]);
    }

    #[test]
    fn decode_open_flags_rdwr_alone_renders_correctly() {
        let got = decode_open_flags(2);
        assert_eq!(got, vec!["O_RDWR"]);
    }

    #[test]
    fn o_tmpfile_does_not_emit_o_directory() {
        let flags = libc::O_TMPFILE as u64 | libc::O_WRONLY as u64;
        let got = decode_open_flags(flags);
        assert!(got.contains(&"O_TMPFILE"), "flags: {got:?}");
        assert!(!got.contains(&"O_DIRECTORY"), "flags: {got:?}");
    }

    #[test]
    fn explicit_o_directory_still_emits_when_o_tmpfile_unset() {
        let flags = libc::O_DIRECTORY as u64;
        let got = decode_open_flags(flags);
        assert!(got.contains(&"O_DIRECTORY"), "flags: {got:?}");
        assert!(!got.contains(&"O_TMPFILE"), "flags: {got:?}");
    }
}
