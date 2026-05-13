//! Decoders for the stat-family syscalls: `stat`, `fstat`, `statx`.
//!
//! All three surface the `statbuf` output pointer as [`DecodedArg::Ptr`].
//! Unpacking the kernel `struct statx` / `struct stat` (file type, mode,
//! size, timestamps) is intentionally out of scope for this batch -
//! formatters render the pointer only.
//!
//! - `stat(pathname, statbuf) -> int` (`x86_64`-only; modern aarch64
//!   kernels do not number this syscall and glibc emulates it via
//!   `newfstatat`).
//! - `fstat(fd, statbuf) -> int`.
//! - `statx(dirfd, pathname, flags, mask, statbuf) -> int`.

use crate::decoder::{DecodeCtx, DecodeError, DecodedArg, DecodedCall, Decoder, c_int_to_u64};
use crate::{decode_fd, decode_flags, decode_path};

const fn c_uint_to_u64(x: libc::c_uint) -> u64 {
    x as u64
}

const STATX_FLAGS_TABLE: &[(u64, &str)] = &[
    (c_int_to_u64(libc::AT_EMPTY_PATH), "AT_EMPTY_PATH"),
    (c_int_to_u64(libc::AT_NO_AUTOMOUNT), "AT_NO_AUTOMOUNT"),
    (
        c_int_to_u64(libc::AT_SYMLINK_NOFOLLOW),
        "AT_SYMLINK_NOFOLLOW",
    ),
    (
        c_int_to_u64(libc::AT_STATX_SYNC_AS_STAT),
        "AT_STATX_SYNC_AS_STAT",
    ),
    (
        c_int_to_u64(libc::AT_STATX_FORCE_SYNC),
        "AT_STATX_FORCE_SYNC",
    ),
    (c_int_to_u64(libc::AT_STATX_DONT_SYNC), "AT_STATX_DONT_SYNC"),
];

const STATX_MASK_TABLE: &[(u64, &str)] = &[
    (c_uint_to_u64(libc::STATX_TYPE), "STATX_TYPE"),
    (c_uint_to_u64(libc::STATX_MODE), "STATX_MODE"),
    (c_uint_to_u64(libc::STATX_NLINK), "STATX_NLINK"),
    (c_uint_to_u64(libc::STATX_UID), "STATX_UID"),
    (c_uint_to_u64(libc::STATX_GID), "STATX_GID"),
    (c_uint_to_u64(libc::STATX_ATIME), "STATX_ATIME"),
    (c_uint_to_u64(libc::STATX_MTIME), "STATX_MTIME"),
    (c_uint_to_u64(libc::STATX_CTIME), "STATX_CTIME"),
    (c_uint_to_u64(libc::STATX_INO), "STATX_INO"),
    (c_uint_to_u64(libc::STATX_SIZE), "STATX_SIZE"),
    (c_uint_to_u64(libc::STATX_BLOCKS), "STATX_BLOCKS"),
    (c_uint_to_u64(libc::STATX_BASIC_STATS), "STATX_BASIC_STATS"),
    (c_uint_to_u64(libc::STATX_BTIME), "STATX_BTIME"),
    (c_uint_to_u64(libc::STATX_ALL), "STATX_ALL"),
];

/// Decoder for the Linux `stat` syscall.
///
/// Stateless; the unit value is `Send + Sync` so a single static instance
/// can be shared across the registry.
#[derive(Debug, Clone, Copy, Default)]
pub struct Stat;

impl Decoder for Stat {
    /// Decode a `stat` call from its syscall registers.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Memory`] when [`crate::decode_path`] fails
    /// to read `pathname` from the tracee.
    fn decode(&self, ctx: &DecodeCtx) -> Result<DecodedCall, DecodeError> {
        let pathname = decode_path(ctx.pid, ctx.args[0])?;
        Ok(DecodedCall {
            args: vec![
                ("pathname", DecodedArg::Path(pathname)),
                ("statbuf", DecodedArg::Ptr(ctx.args[1])),
            ],
            ret: ctx.ret,
        })
    }
}

/// Decoder for the Linux `fstat` syscall.
///
/// Stateless; the unit value is `Send + Sync` so a single static instance
/// can be shared across the registry.
#[derive(Debug, Clone, Copy, Default)]
pub struct Fstat;

impl Decoder for Fstat {
    /// Decode an `fstat` call from its syscall registers.
    ///
    /// # Errors
    ///
    /// Infallible in practice: no tracee memory is read. Returns
    /// [`DecodeError`] only to match the [`Decoder`] trait signature.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "fd is `int`; only the low 32 bits of the register carry the value"
    )]
    fn decode(&self, ctx: &DecodeCtx) -> Result<DecodedCall, DecodeError> {
        let fd_raw = i64::from(ctx.args[0] as i32);
        Ok(DecodedCall {
            args: vec![
                ("fd", DecodedArg::Fd(decode_fd(fd_raw))),
                ("statbuf", DecodedArg::Ptr(ctx.args[1])),
            ],
            ret: ctx.ret,
        })
    }
}

/// Decoder for the Linux `statx` syscall.
///
/// Stateless; the unit value is `Send + Sync` so a single static instance
/// can be shared across the registry.
#[derive(Debug, Clone, Copy, Default)]
pub struct Statx;

impl Decoder for Statx {
    /// Decode a `statx` call from its syscall registers.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Memory`] when [`crate::decode_path`] fails
    /// to read `pathname` from the tracee.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "dirfd is `int`; only the low 32 bits of the register carry the value"
    )]
    fn decode(&self, ctx: &DecodeCtx) -> Result<DecodedCall, DecodeError> {
        let dirfd = i64::from(ctx.args[0] as i32);
        let pathname = decode_path(ctx.pid, ctx.args[1])?;
        let flags = ctx.args[2];
        let mask = ctx.args[3];
        let statbuf = ctx.args[4];

        Ok(DecodedCall {
            args: vec![
                ("dirfd", DecodedArg::Fd(decode_fd(dirfd))),
                ("pathname", DecodedArg::Path(pathname)),
                (
                    "flags",
                    DecodedArg::Flags(decode_flags(flags, STATX_FLAGS_TABLE)),
                ),
                (
                    "mask",
                    DecodedArg::Flags(decode_flags(mask, STATX_MASK_TABLE)),
                ),
                ("statbuf", DecodedArg::Ptr(statbuf)),
            ],
            ret: ctx.ret,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Fstat, Stat, Statx};
    use crate::decoder::{DecodeCtx, DecodeError, DecodedArg, Decoder, FdRepr};
    use std::ffi::CString;

    fn self_pid() -> i32 {
        i32::try_from(std::process::id()).expect("pid fits in i32")
    }

    #[test]
    fn stat_decoder_reads_path_from_synthetic_args() {
        let cs = CString::new("/etc/hosts").expect("no interior nul");
        let ctx = DecodeCtx {
            pid: self_pid(),
            args: [cs.as_ptr() as u64, 0x1000, 0, 0, 0, 0],
            ret: 0,
        };
        let call = Stat.decode(&ctx).expect("decode succeeds");
        assert!(
            matches!(&call.args[0].1, DecodedArg::Path(p) if p == "/etc/hosts"),
            "got {:?}",
            call.args[0].1
        );
        assert!(
            matches!(call.args[1].1, DecodedArg::Ptr(0x1000)),
            "got {:?}",
            call.args[1].1
        );
    }

    #[test]
    fn fstat_decoder_with_fd_3_produces_fd_num() {
        let ctx = DecodeCtx {
            pid: self_pid(),
            args: [3, 0x1000, 0, 0, 0, 0],
            ret: 0,
        };
        let call = Fstat.decode(&ctx).expect("decode succeeds");
        assert!(
            matches!(call.args[0].1, DecodedArg::Fd(FdRepr::Num(3))),
            "got {:?}",
            call.args[0].1
        );
    }

    #[test]
    fn statx_decoder_with_at_fdcwd_renders_label() {
        let cs = CString::new("foo").expect("no interior nul");
        let dirfd = (-100i64).cast_unsigned();
        let ctx = DecodeCtx {
            pid: self_pid(),
            args: [dirfd, cs.as_ptr() as u64, 0, 0, 0x1000, 0],
            ret: 0,
        };
        let call = Statx.decode(&ctx).expect("decode succeeds");
        match &call.args[0].1 {
            DecodedArg::Fd(FdRepr::AtFdCwd) => {}
            other => panic!("expected AtFdCwd, got {other:?}"),
        }
    }

    #[test]
    fn statx_decoder_with_symlink_nofollow_decodes_flag_name() {
        let cs = CString::new("foo").expect("no interior nul");
        let flags = libc::AT_SYMLINK_NOFOLLOW as u64;
        let ctx = DecodeCtx {
            pid: self_pid(),
            args: [
                (-100i64).cast_unsigned(),
                cs.as_ptr() as u64,
                flags,
                0,
                0x1000,
                0,
            ],
            ret: 0,
        };
        let call = Statx.decode(&ctx).expect("decode succeeds");
        let DecodedArg::Flags(names) = &call.args[2].1 else {
            panic!("expected Flags, got {:?}", call.args[2].1);
        };
        assert!(names.contains(&"AT_SYMLINK_NOFOLLOW"), "flags: {names:?}");
    }

    #[test]
    fn statx_decoder_with_statx_basic_stats_mask_decodes_name() {
        let cs = CString::new("foo").expect("no interior nul");
        let mask = u64::from(libc::STATX_BASIC_STATS);
        let ctx = DecodeCtx {
            pid: self_pid(),
            args: [
                (-100i64).cast_unsigned(),
                cs.as_ptr() as u64,
                0,
                mask,
                0x1000,
                0,
            ],
            ret: 0,
        };
        let call = Statx.decode(&ctx).expect("decode succeeds");
        let DecodedArg::Flags(names) = &call.args[3].1 else {
            panic!("expected Flags, got {:?}", call.args[3].1);
        };
        assert!(names.contains(&"STATX_BASIC_STATS"), "mask: {names:?}");
    }

    #[test]
    fn stat_decoder_returns_decode_error_on_memory_read_failure() {
        let ctx = DecodeCtx {
            pid: self_pid(),
            args: [0x1, 0x1000, 0, 0, 0, 0],
            ret: -1,
        };
        let r = Stat.decode(&ctx);
        assert!(
            matches!(r, Err(DecodeError::Memory(_))),
            "expected Memory error, got {r:?}"
        );
    }
}
