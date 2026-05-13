//! Decoder for `mprotect(addr, len, prot) -> int`.
//!
//! Reuses [`crate::decode_prot`] (and through it [`crate::decoder::PROT_TABLE`])
//! so the `PROT_NONE` rendering stays consistent with `mmap`.

use crate::decode_prot;
use crate::decoder::{DecodeCtx, DecodeError, DecodedArg, DecodedCall, Decoder};

/// Decoder for the Linux `mprotect` syscall.
///
/// Stateless; the unit value is `Send + Sync` so a single static instance
/// can be shared across the registry.
#[derive(Debug, Clone, Copy, Default)]
pub struct Mprotect;

impl Decoder for Mprotect {
    /// Decode an `mprotect` call from its syscall registers.
    ///
    /// # Errors
    ///
    /// Infallible in practice: no tracee memory is read. Returns
    /// [`DecodeError`] only to match the [`Decoder`] trait signature.
    fn decode(&self, ctx: &DecodeCtx) -> Result<DecodedCall, DecodeError> {
        Ok(DecodedCall {
            args: vec![
                ("addr", DecodedArg::Hex(ctx.args[0])),
                ("len", DecodedArg::Uint(ctx.args[1])),
                ("prot", DecodedArg::Flags(decode_prot(ctx.args[2]))),
            ],
            ret: ctx.ret,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Mprotect;
    use crate::decoder::{DecodeCtx, DecodedArg, Decoder};

    fn ctx_for(addr: u64, len: u64, prot: u64) -> DecodeCtx {
        DecodeCtx {
            pid: i32::try_from(std::process::id()).expect("pid fits in i32"),
            args: [addr, len, prot, 0, 0, 0],
            ret: 0,
        }
    }

    #[test]
    fn mprotect_decoder_with_read_exec_produces_both_flag_names() {
        let prot = (libc::PROT_READ | libc::PROT_EXEC) as u64;
        let call = Mprotect
            .decode(&ctx_for(0x1000, 4096, prot))
            .expect("decode succeeds");
        let DecodedArg::Flags(names) = &call.args[2].1 else {
            panic!("expected Flags, got {:?}", call.args[2].1);
        };
        assert!(names.contains(&"PROT_READ"), "prot: {names:?}");
        assert!(names.contains(&"PROT_EXEC"), "prot: {names:?}");
    }

    #[test]
    fn mprotect_decoder_with_prot_zero_produces_prot_none() {
        let call = Mprotect
            .decode(&ctx_for(0x1000, 4096, 0))
            .expect("decode succeeds");
        let DecodedArg::Flags(names) = &call.args[2].1 else {
            panic!("expected Flags, got {:?}", call.args[2].1);
        };
        assert_eq!(names, &vec!["PROT_NONE"]);
    }

    #[test]
    fn mprotect_decoder_renders_addr_as_hex() {
        let call = Mprotect
            .decode(&ctx_for(0xfeed_face, 4096, 0))
            .expect("decode succeeds");
        assert!(
            matches!(call.args[0].1, DecodedArg::Hex(0xfeed_face)),
            "got {:?}",
            call.args[0].1
        );
    }
}
