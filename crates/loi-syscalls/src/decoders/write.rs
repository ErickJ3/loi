//! Decoder for `write(fd, buf, count) -> ssize_t`.
//!
//! Decodes `fd` via [`crate::decode_fd`] and surfaces `count` as a raw
//! [`DecodedArg::Uint`]. The buffer is captured regardless of return:
//! the tracee filled `buf` before the syscall, so the bytes are a valid
//! record of what was attempted even on partial writes or error
//! returns. This is the mirror image of [`crate::Read`], where the
//! buffer is only meaningful on a successful return.
//!
//! The captured prefix is bounded by [`MAX_INLINE_BYTES`]. On a
//! successful partial write (`0 < ret < count`) the prefix is further
//! capped at `ret` so formatters never display bytes the kernel never
//! inspected.

use crate::decode_fd;
use crate::decoder::{DecodeCtx, DecodeError, DecodedArg, DecodedCall, Decoder};
use crate::decoders::read::MAX_INLINE_BYTES;

/// Decoder for the Linux `write` syscall.
///
/// Stateless; the unit value is `Send + Sync` so a single static instance
/// can be shared across the registry.
///
/// # Examples
///
/// ```
/// use loi_syscalls::{DecodeCtx, DecodedArg, Decoder, FdRepr, Write};
///
/// let buf = b"hi";
/// let ctx = DecodeCtx {
///     pid: i32::try_from(std::process::id()).unwrap(),
///     args: [1, buf.as_ptr().addr() as u64, buf.len() as u64, 0, 0, 0],
///     ret: 2,
/// };
/// let call = Write.decode(&ctx).unwrap();
/// assert!(matches!(call.args[0].1, DecodedArg::Fd(FdRepr::Num(1))));
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Write;

impl Decoder for Write {
    /// Decode a `write` call from its syscall registers.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Memory`] when [`loi_memory::read_bytes`]
    /// fails while capturing the buffer preview. The buffer is only
    /// touched when the requested prefix length is non-zero, so calls
    /// with `count == 0` never surface a memory error.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "fd is `int`; only the low 32 bits of the register carry the value"
    )]
    fn decode(&self, ctx: &DecodeCtx) -> Result<DecodedCall, DecodeError> {
        let fd_raw = i64::from(ctx.args[0] as i32);
        let buf_addr = ctx.args[1];
        let count = ctx.args[2];
        let total = usize::try_from(count).unwrap_or(usize::MAX);

        let want = if ctx.ret > 0 {
            usize::try_from(ctx.ret).unwrap_or(total).min(total)
        } else {
            total
        }
        .min(MAX_INLINE_BYTES);

        let inline = if want == 0 {
            Vec::new()
        } else {
            loi_memory::read_bytes(ctx.pid, buf_addr, want)?
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
    use super::{MAX_INLINE_BYTES, Write};
    use crate::decoder::{DecodeCtx, DecodeError, DecodedArg, DecodedCall, Decoder, FdRepr};

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

    fn bytes_arg(call: &DecodedCall) -> (&[u8], usize) {
        let DecodedArg::Bytes { inline, total } = &call.args[1].1 else {
            panic!("expected Bytes, got {:?}", call.args[1].1);
        };
        (inline.as_slice(), *total)
    }

    #[test]
    fn decoder_emits_three_labeled_args_in_order() {
        let buf = [0u8; 0];
        let ctx = ctx_for(&buf, 1, 0, 0);
        let call = Write.decode(&ctx).expect("decode succeeds");
        let labels: Vec<&str> = call.args.iter().map(|(l, _)| *l).collect();
        assert_eq!(labels, vec!["fd", "buf", "count"]);
    }

    #[test]
    fn decoder_decodes_fd_as_num() {
        let buf = [0u8; 0];
        let ctx = ctx_for(&buf, 1, 0, 0);
        let call = Write.decode(&ctx).expect("decode succeeds");
        assert!(
            matches!(&call.args[0].1, DecodedArg::Fd(FdRepr::Num(1))),
            "got {:?}",
            call.args[0].1
        );
    }

    #[test]
    fn decoder_reads_synthetic_buffer_of_hello() {
        let buf = b"hello";
        let count = u64::try_from(buf.len()).expect("5 fits in u64");
        let ret = i64::try_from(buf.len()).expect("5 fits in i64");
        let ctx = ctx_for(buf, 1, count, ret);
        let call = Write.decode(&ctx).expect("decode succeeds");
        let (inline, _) = bytes_arg(&call);
        assert_eq!(inline, b"hello");
    }

    #[test]
    fn decoder_synthetic_buffer_preserves_total_count() {
        let buf = b"hello";
        let count = u64::try_from(buf.len()).expect("5 fits in u64");
        let ret = i64::try_from(buf.len()).expect("5 fits in i64");
        let ctx = ctx_for(buf, 1, count, ret);
        let call = Write.decode(&ctx).expect("decode succeeds");
        let (_, total) = bytes_arg(&call);
        assert_eq!(total, 5);
    }

    #[test]
    fn decoder_truncates_inline_at_max_inline_bytes() {
        let buf: Vec<u8> = vec![0xcd; 256];
        let count = u64::try_from(buf.len()).expect("256 fits in u64");
        let ret = i64::try_from(buf.len()).expect("256 fits in i64");
        let ctx = ctx_for(&buf, 1, count, ret);
        let call = Write.decode(&ctx).expect("decode succeeds");
        let (inline, _) = bytes_arg(&call);
        assert_eq!(inline.len(), MAX_INLINE_BYTES);
    }

    #[test]
    fn decoder_truncated_inline_matches_buffer_prefix() {
        let buf: Vec<u8> = vec![0xcd; 256];
        let count = u64::try_from(buf.len()).expect("256 fits in u64");
        let ret = i64::try_from(buf.len()).expect("256 fits in i64");
        let ctx = ctx_for(&buf, 1, count, ret);
        let call = Write.decode(&ctx).expect("decode succeeds");
        let (inline, _) = bytes_arg(&call);
        assert_eq!(inline, &buf[..MAX_INLINE_BYTES]);
    }

    #[test]
    fn decoder_truncated_total_preserves_original_count() {
        let buf: Vec<u8> = vec![0xcd; 256];
        let count = u64::try_from(buf.len()).expect("256 fits in u64");
        let ret = i64::try_from(buf.len()).expect("256 fits in i64");
        let ctx = ctx_for(&buf, 1, count, ret);
        let call = Write.decode(&ctx).expect("decode succeeds");
        let (_, total) = bytes_arg(&call);
        assert_eq!(total, 256);
    }

    #[test]
    fn decoder_with_negative_ret_still_reads_buffer() {
        let buf = b"payload";
        let count = u64::try_from(buf.len()).expect("7 fits in u64");
        let ctx = ctx_for(buf, 1, count, -32);
        let call = Write
            .decode(&ctx)
            .expect("decode succeeds even on errored write");
        let (inline, _) = bytes_arg(&call);
        assert_eq!(inline, b"payload");
    }

    #[test]
    fn decoder_with_negative_ret_keeps_total_count() {
        let buf = b"payload";
        let count = u64::try_from(buf.len()).expect("7 fits in u64");
        let ctx = ctx_for(buf, 1, count, -32);
        let call = Write
            .decode(&ctx)
            .expect("decode succeeds even on errored write");
        let (_, total) = bytes_arg(&call);
        assert_eq!(total, 7);
    }

    #[test]
    fn decoder_with_zero_count_yields_empty_inline() {
        let ctx = DecodeCtx {
            pid: self_pid(),
            args: [1, 0x1, 0, 0, 0, 0],
            ret: 0,
        };
        let call = Write
            .decode(&ctx)
            .expect("decode succeeds without touching buf");
        let (inline, _) = bytes_arg(&call);
        assert!(inline.is_empty(), "inline should stay empty: {inline:?}");
    }

    #[test]
    fn decoder_with_zero_count_keeps_total_count() {
        let ctx = DecodeCtx {
            pid: self_pid(),
            args: [1, 0x1, 0, 0, 0, 0],
            ret: 0,
        };
        let call = Write
            .decode(&ctx)
            .expect("decode succeeds without touching buf");
        let (_, total) = bytes_arg(&call);
        assert_eq!(total, 0);
    }

    #[test]
    fn decoder_with_partial_write_caps_inline_at_ret() {
        let buf: Vec<u8> = (0u8..32).collect();
        let count = u64::try_from(buf.len()).expect("32 fits in u64");
        let ctx = ctx_for(&buf, 1, count, 8);
        let call = Write.decode(&ctx).expect("decode succeeds");
        let (inline, _) = bytes_arg(&call);
        assert_eq!(inline, &buf[..8]);
    }

    #[test]
    fn decoder_with_partial_write_keeps_total_count() {
        let buf: Vec<u8> = (0u8..32).collect();
        let count = u64::try_from(buf.len()).expect("32 fits in u64");
        let ctx = ctx_for(&buf, 1, count, 8);
        let call = Write.decode(&ctx).expect("decode succeeds");
        let (_, total) = bytes_arg(&call);
        assert_eq!(total, 32);
    }

    #[test]
    fn decoder_passes_through_ret_value() {
        let buf = b"abcd";
        let ctx = ctx_for(buf, 1, 4, 4);
        let call = Write.decode(&ctx).expect("decode succeeds");
        assert_eq!(call.ret, 4);
    }

    #[test]
    fn decoder_renders_count_as_uint() {
        let buf = [0u8; 0];
        let ctx = ctx_for(&buf, 1, 8192, 0);
        let call = Write.decode(&ctx).expect("decode succeeds");
        assert!(
            matches!(call.args[2].1, DecodedArg::Uint(8192)),
            "got {:?}",
            call.args[2].1
        );
    }

    #[test]
    fn bad_buf_addr_with_nonzero_count_returns_decode_error() {
        let ctx = DecodeCtx {
            pid: self_pid(),
            args: [1, 0x1, 4096, 0, 0, 0],
            ret: -1,
        };
        let r = Write.decode(&ctx);
        assert!(
            matches!(r, Err(DecodeError::Memory(_))),
            "expected Memory error, got {r:?}"
        );
    }
}
