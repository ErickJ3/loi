//! Decoder for `wait4(pid, wstatus, options, rusage) -> pid`.
//!
//! `wstatus` is an out-pointer the kernel fills only when the call
//! reaps a child (`ret > 0`). The decoder reads the four-byte status
//! word in that case and surfaces it as [`DecodedArg::Hex`]; otherwise
//! it surfaces the pointer itself as [`DecodedArg::Ptr`]. Semantic
//! decoding of the status word (`WIFEXITED`, `WIFSIGNALED`, etc.) is
//! deferred to a follow-up feature.

use crate::decode_flags;
use crate::decoder::{DecodeCtx, DecodeError, DecodedArg, DecodedCall, Decoder, c_int_to_u64};

const STATUS_WORD_BYTES: usize = std::mem::size_of::<u32>();

const OPTIONS_TABLE: &[(u64, &str)] = &[
    (c_int_to_u64(libc::WNOHANG), "WNOHANG"),
    (c_int_to_u64(libc::WUNTRACED), "WUNTRACED"),
    (c_int_to_u64(libc::WCONTINUED), "WCONTINUED"),
];

fn read_status_word(pid: i32, addr: u64) -> Option<u32> {
    let bytes = loi_memory::read_bytes(pid, addr, STATUS_WORD_BYTES).ok()?;
    let arr: [u8; STATUS_WORD_BYTES] = bytes.try_into().ok()?;
    Some(u32::from_ne_bytes(arr))
}

/// Decoder for the Linux `wait4` syscall.
///
/// Stateless; the unit value is `Send + Sync` so a single static instance
/// can be shared across the registry.
#[derive(Debug, Clone, Copy, Default)]
pub struct Wait4;

impl Decoder for Wait4 {
    /// Decode a `wait4` call from its syscall registers.
    ///
    /// # Errors
    ///
    /// Infallible in practice. A failed `wstatus` memory read does not
    /// propagate: the decoder falls back to [`DecodedArg::Ptr`] for that
    /// argument so the rest of the call still renders.
    #[expect(
        clippy::cast_possible_wrap,
        reason = "pid is `int`; widening through i64 preserves the value"
    )]
    fn decode(&self, ctx: &DecodeCtx) -> Result<DecodedCall, DecodeError> {
        let pid_arg = ctx.args[0] as i64;
        let wstatus_addr = ctx.args[1];
        let options = ctx.args[2];
        let rusage_addr = ctx.args[3];

        let wstatus = if ctx.ret > 0 && wstatus_addr != 0 {
            match read_status_word(ctx.pid, wstatus_addr) {
                Some(word) => DecodedArg::Hex(u64::from(word)),
                None => DecodedArg::Ptr(wstatus_addr),
            }
        } else {
            DecodedArg::Ptr(wstatus_addr)
        };

        Ok(DecodedCall {
            args: vec![
                ("pid", DecodedArg::Int(pid_arg)),
                ("wstatus", wstatus),
                (
                    "options",
                    DecodedArg::Flags(decode_flags(options, OPTIONS_TABLE)),
                ),
                ("rusage", DecodedArg::Ptr(rusage_addr)),
            ],
            ret: ctx.ret,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Wait4;
    use crate::decoder::{DecodeCtx, DecodedArg, Decoder};

    fn self_pid() -> i32 {
        i32::try_from(std::process::id()).expect("pid fits in i32")
    }

    #[test]
    fn wait4_decoder_with_wnohang_option_produces_flag_name() {
        let ctx = DecodeCtx {
            pid: self_pid(),
            args: [u64::MAX, 0, libc::WNOHANG as u64, 0, 0, 0],
            ret: 0,
        };
        let call = Wait4.decode(&ctx).expect("decode succeeds");
        let DecodedArg::Flags(names) = &call.args[2].1 else {
            panic!("expected Flags, got {:?}", call.args[2].1);
        };
        assert!(names.contains(&"WNOHANG"), "options: {names:?}");
    }

    #[test]
    fn wait4_decoder_reads_wstatus_pointee_as_hex_when_ret_positive() {
        let status: u32 = 0x1234_5678;
        let ctx = DecodeCtx {
            pid: self_pid(),
            args: [u64::MAX, (&raw const status).addr() as u64, 0, 0, 0, 0],
            ret: 4242,
        };
        let call = Wait4.decode(&ctx).expect("decode succeeds");
        assert!(
            matches!(call.args[1].1, DecodedArg::Hex(v) if v == u64::from(status)),
            "got {:?}",
            call.args[1].1
        );
    }

    #[test]
    fn wait4_decoder_leaves_wstatus_as_ptr_when_ret_zero() {
        let ctx = DecodeCtx {
            pid: self_pid(),
            args: [u64::MAX, 0x1000, 0, 0, 0, 0],
            ret: 0,
        };
        let call = Wait4.decode(&ctx).expect("decode succeeds");
        assert!(
            matches!(call.args[1].1, DecodedArg::Ptr(0x1000)),
            "got {:?}",
            call.args[1].1
        );
    }

    #[test]
    fn wait4_decoder_renders_minus_one_pid_as_int_neg_one() {
        let ctx = DecodeCtx {
            pid: self_pid(),
            args: [u64::MAX, 0, 0, 0, 0, 0],
            ret: 0,
        };
        let call = Wait4.decode(&ctx).expect("decode succeeds");
        assert!(
            matches!(call.args[0].1, DecodedArg::Int(-1)),
            "got {:?}",
            call.args[0].1
        );
    }

    #[test]
    fn wait4_decoder_renders_rusage_as_ptr() {
        let ctx = DecodeCtx {
            pid: self_pid(),
            args: [u64::MAX, 0, 0, 0xdead_face, 0, 0],
            ret: 0,
        };
        let call = Wait4.decode(&ctx).expect("decode succeeds");
        assert!(
            matches!(call.args[3].1, DecodedArg::Ptr(0xdead_face)),
            "got {:?}",
            call.args[3].1
        );
    }
}
