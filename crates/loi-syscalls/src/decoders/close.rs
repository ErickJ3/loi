//! Decoder for `close(fd) -> int`.
//!
//! Single-arg decoder. `fd` is mapped via [`crate::decode_fd`]; the
//! formatter pairs negative `ret` with an errno label, so this decoder
//! only forwards the raw return value.

use crate::decode_fd;
use crate::decoder::{DecodeCtx, DecodeError, DecodedArg, DecodedCall, Decoder};

/// Decoder for the Linux `close` syscall.
///
/// Stateless; the unit value is `Send + Sync` so a single static instance
/// can be shared across the registry.
#[derive(Debug, Clone, Copy, Default)]
pub struct Close;

impl Decoder for Close {
    /// Decode a `close` call from its syscall registers.
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
            args: vec![("fd", DecodedArg::Fd(decode_fd(fd_raw)))],
            ret: ctx.ret,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Close;
    use crate::decoder::{DecodeCtx, DecodedArg, Decoder, FdRepr};

    fn self_pid() -> i32 {
        i32::try_from(std::process::id()).expect("pid fits in i32")
    }

    fn ctx_for(fd: u64, ret: i64) -> DecodeCtx {
        DecodeCtx {
            pid: self_pid(),
            args: [fd, 0, 0, 0, 0, 0],
            ret,
        }
    }

    #[test]
    fn decoder_emits_single_fd_arg() {
        let call = Close.decode(&ctx_for(3, 0)).expect("decode succeeds");
        let labels: Vec<&str> = call.args.iter().map(|(l, _)| *l).collect();
        assert_eq!(labels, vec!["fd"]);
        assert!(
            matches!(call.args[0].1, DecodedArg::Fd(FdRepr::Num(3))),
            "got {:?}",
            call.args[0].1
        );
    }

    #[test]
    fn decoder_passes_through_zero_ret() {
        let call = Close.decode(&ctx_for(3, 0)).expect("decode succeeds");
        assert_eq!(call.ret, 0);
    }

    #[test]
    fn decoder_preserves_negative_ret_and_renders_fd_invalid() {
        let invalid_fd = (-1i64).cast_unsigned();
        let call = Close
            .decode(&ctx_for(invalid_fd, -9))
            .expect("decode succeeds");
        assert_eq!(call.ret, -9);
        assert!(
            matches!(call.args[0].1, DecodedArg::Fd(FdRepr::Invalid)),
            "got {:?}",
            call.args[0].1
        );
    }
}
