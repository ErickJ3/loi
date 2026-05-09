//! Decoder for `read(fd, buf, count) -> ssize_t`.
//!
//! Decodes `fd` via [`crate::decode_fd`] and surfaces `count` as a raw
//! [`DecodedArg::Uint`]. On a successful return (`ret > 0`) the decoder
//! reads up to `min(ret as usize, MAX_INLINE_BYTES)` bytes from the
//! tracee's `buf` for buffer preview. On error returns (`ret < 0`) and
//! on EOF (`ret == 0`) the buffer is skipped: the kernel did not write
//! to it (or wrote nothing), so the bytes there are irrelevant to the
//! call's outcome.

use crate::decode_fd;
use crate::decoder::{DecodeCtx, DecodeError, DecodedArg, DecodedCall, Decoder};

/// Cap on the buffer prefix captured for pretty/JSON output.
///
/// Formatters render at most this many bytes of the buffer payload;
/// `total` on [`DecodedArg::Bytes`] preserves the syscall-reported length
/// so consumers know the prefix is truncated.
///
/// # Examples
///
/// ```
/// use loi_syscalls::MAX_INLINE_BYTES;
/// assert_eq!(MAX_INLINE_BYTES, 64);
/// ```
pub const MAX_INLINE_BYTES: usize = 64;

/// Decoder for the Linux `read` syscall.
///
/// Stateless; the unit value is `Send + Sync` so a single static instance
/// can be shared across the registry.
///
/// # Examples
///
/// ```
/// use loi_syscalls::{DecodeCtx, DecodedArg, Decoder, FdRepr, Read};
///
/// let buf = [0u8; 0];
/// let ctx = DecodeCtx {
///     pid: i32::try_from(std::process::id()).unwrap(),
///     args: [3, buf.as_ptr().addr() as u64, 0, 0, 0, 0],
///     ret: 0,
/// };
/// let call = Read.decode(&ctx).unwrap();
/// assert!(matches!(call.args[0].1, DecodedArg::Fd(FdRepr::Num(3))));
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Read;

impl Decoder for Read {
    /// Decode a `read` call from its syscall registers.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Memory`] when [`loi_memory::read_bytes`]
    /// fails while capturing the buffer preview. The buffer is only
    /// touched when `ctx.ret > 0`, so failed and EOF reads never surface
    /// a memory error.
    #[expect(
        clippy::cast_possible_wrap,
        reason = "fd register holds a c_int promoted to u64 by the kernel ABI"
    )]
    fn decode(&self, ctx: &DecodeCtx) -> Result<DecodedCall, DecodeError> {
        let fd_raw = ctx.args[0] as i64;
        let buf_addr = ctx.args[1];
        let count = ctx.args[2];
        let total = usize::try_from(count).unwrap_or(usize::MAX);

        let inline = if ctx.ret > 0 {
            let want = usize::try_from(ctx.ret).unwrap_or(0).min(MAX_INLINE_BYTES);
            loi_memory::read_bytes(ctx.pid, buf_addr, want)?
        } else {
            Vec::new()
        };

        Ok(DecodedCall {
            args: vec![
                ("fd", DecodedArg::Fd(decode_fd(fd_raw))),
                ("buf", DecodedArg::Bytes { inline, total }),
                ("count", DecodedArg::Uint(count)),
            ],
            ret: ctx.ret,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_INLINE_BYTES, Read};
    use crate::decoder::{DecodeCtx, DecodeError, DecodedArg, Decoder, FdRepr};

    fn self_pid() -> i32 {
        i32::try_from(std::process::id()).expect("pid fits in i32")
    }

    fn ctx_for(buf: &[u8], fd: u64, count: u64, ret: i64) -> DecodeCtx {
        DecodeCtx {
            pid: self_pid(),
            args: [fd, buf.as_ptr().addr() as u64, count, 0, 0, 0],
            ret,
        }
    }

    fn bytes_arg(call: &super::DecodedCall) -> (&[u8], usize) {
        let DecodedArg::Bytes { inline, total } = &call.args[1].1 else {
            panic!("expected Bytes, got {:?}", call.args[1].1);
        };
        (inline.as_slice(), *total)
    }

    #[test]
    fn decoder_emits_three_labeled_args_in_order() {
        let buf = [0u8; 0];
        let ctx = ctx_for(&buf, 3, 0, 0);
        let call = Read.decode(&ctx).expect("decode succeeds");
        let labels: Vec<&str> = call.args.iter().map(|(l, _)| *l).collect();
        assert_eq!(labels, vec!["fd", "buf", "count"]);
    }

    #[test]
    fn decoder_decodes_fd_as_num() {
        let buf = [0u8; 0];
        let ctx = ctx_for(&buf, 3, 0, 0);
        let call = Read.decode(&ctx).expect("decode succeeds");
        assert!(
            matches!(&call.args[0].1, DecodedArg::Fd(FdRepr::Num(3))),
            "got {:?}",
            call.args[0].1
        );
    }

    #[test]
    fn decoder_with_positive_ret_reads_buffer_prefix_inline() {
        let buf: Vec<u8> = (0u8..12).collect();
        let ctx = ctx_for(&buf, 3, 4096, 12);
        let call = Read.decode(&ctx).expect("decode succeeds");
        let (inline, _) = bytes_arg(&call);
        assert_eq!(inline, buf.as_slice());
    }

    #[test]
    fn decoder_with_positive_ret_preserves_total_count() {
        let buf: Vec<u8> = (0u8..12).collect();
        let ctx = ctx_for(&buf, 3, 4096, 12);
        let call = Read.decode(&ctx).expect("decode succeeds");
        let (_, total) = bytes_arg(&call);
        assert_eq!(total, 4096);
    }

    #[test]
    fn decoder_with_negative_ret_skips_buffer_read() {
        let ctx = DecodeCtx {
            pid: self_pid(),
            args: [3, 0x1, 4096, 0, 0, 0],
            ret: -9,
        };
        let call = Read
            .decode(&ctx)
            .expect("decode succeeds without touching buf");
        let (inline, _) = bytes_arg(&call);
        assert!(inline.is_empty(), "inline should stay empty: {inline:?}");
    }

    #[test]
    fn decoder_with_negative_ret_keeps_total_count() {
        let ctx = DecodeCtx {
            pid: self_pid(),
            args: [3, 0x1, 4096, 0, 0, 0],
            ret: -9,
        };
        let call = Read
            .decode(&ctx)
            .expect("decode succeeds without touching buf");
        let (_, total) = bytes_arg(&call);
        assert_eq!(total, 4096);
    }

    #[test]
    fn decoder_truncates_inline_at_max_inline_bytes() {
        let buf: Vec<u8> = vec![0xab; 256];
        let ret = i64::try_from(buf.len()).expect("256 fits in i64");
        let count = u64::try_from(buf.len()).expect("256 fits in u64");
        let ctx = ctx_for(&buf, 3, count, ret);
        let call = Read.decode(&ctx).expect("decode succeeds");
        let (inline, _) = bytes_arg(&call);
        assert_eq!(inline.len(), MAX_INLINE_BYTES);
    }

    #[test]
    fn decoder_truncated_inline_matches_buffer_prefix() {
        let buf: Vec<u8> = vec![0xab; 256];
        let ret = i64::try_from(buf.len()).expect("256 fits in i64");
        let count = u64::try_from(buf.len()).expect("256 fits in u64");
        let ctx = ctx_for(&buf, 3, count, ret);
        let call = Read.decode(&ctx).expect("decode succeeds");
        let (inline, _) = bytes_arg(&call);
        assert_eq!(inline, &buf[..MAX_INLINE_BYTES]);
    }

    #[test]
    fn decoder_truncated_total_preserves_original_count() {
        let buf: Vec<u8> = vec![0xab; 256];
        let ret = i64::try_from(buf.len()).expect("256 fits in i64");
        let count = u64::try_from(buf.len()).expect("256 fits in u64");
        let ctx = ctx_for(&buf, 3, count, ret);
        let call = Read.decode(&ctx).expect("decode succeeds");
        let (_, total) = bytes_arg(&call);
        assert_eq!(total, 256);
    }

    #[test]
    fn decoder_with_zero_ret_yields_empty_inline() {
        let buf = [0u8; 16];
        let ctx = ctx_for(&buf, 3, 16, 0);
        let call = Read.decode(&ctx).expect("decode succeeds");
        let (inline, _) = bytes_arg(&call);
        assert!(inline.is_empty(), "EOF inline should be empty: {inline:?}");
    }

    #[test]
    fn decoder_with_zero_ret_keeps_total_count() {
        let buf = [0u8; 16];
        let ctx = ctx_for(&buf, 3, 16, 0);
        let call = Read.decode(&ctx).expect("decode succeeds");
        let (_, total) = bytes_arg(&call);
        assert_eq!(total, 16);
    }

    #[test]
    fn decoder_passes_through_ret_value() {
        let buf: Vec<u8> = (0u8..4).collect();
        let ctx = ctx_for(&buf, 3, 4, 4);
        let call = Read.decode(&ctx).expect("decode succeeds");
        assert_eq!(call.ret, 4);
    }

    #[test]
    fn decoder_renders_count_as_uint() {
        let buf = [0u8; 0];
        let ctx = ctx_for(&buf, 3, 8192, 0);
        let call = Read.decode(&ctx).expect("decode succeeds");
        assert!(
            matches!(call.args[2].1, DecodedArg::Uint(8192)),
            "got {:?}",
            call.args[2].1
        );
    }

    #[test]
    fn bad_buf_addr_with_positive_ret_returns_decode_error() {
        let ctx = DecodeCtx {
            pid: self_pid(),
            args: [3, 0x1, 4096, 0, 0, 0],
            ret: 8,
        };
        let r = Read.decode(&ctx);
        assert!(
            matches!(r, Err(DecodeError::Memory(_))),
            "expected Memory error, got {r:?}"
        );
    }
}
