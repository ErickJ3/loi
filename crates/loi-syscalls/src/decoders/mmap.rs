//! Decoder for `mmap(addr, length, prot, flags, fd, offset) -> void *`.
//!
//! `prot` routes through the shared [`crate::decode_prot`] helper so the
//! `PROT_NONE` rendering stays consistent with `mprotect`. `flags` is
//! decoded against a local `MAP_*` table.

use crate::decoder::{DecodeCtx, DecodeError, DecodedArg, DecodedCall, Decoder, c_int_to_u64};
use crate::{decode_fd, decode_flags, decode_prot};

const MAP_TABLE: &[(u64, &str)] = &[
    (c_int_to_u64(libc::MAP_SHARED), "MAP_SHARED"),
    (c_int_to_u64(libc::MAP_PRIVATE), "MAP_PRIVATE"),
    (c_int_to_u64(libc::MAP_FIXED), "MAP_FIXED"),
    (c_int_to_u64(libc::MAP_ANONYMOUS), "MAP_ANONYMOUS"),
    (c_int_to_u64(libc::MAP_NORESERVE), "MAP_NORESERVE"),
    (c_int_to_u64(libc::MAP_STACK), "MAP_STACK"),
    (c_int_to_u64(libc::MAP_POPULATE), "MAP_POPULATE"),
    (c_int_to_u64(libc::MAP_DENYWRITE), "MAP_DENYWRITE"),
    (c_int_to_u64(libc::MAP_HUGETLB), "MAP_HUGETLB"),
];

/// Decoder for the Linux `mmap` syscall.
///
/// Stateless; the unit value is `Send + Sync` so a single static instance
/// can be shared across the registry.
#[derive(Debug, Clone, Copy, Default)]
pub struct Mmap;

impl Decoder for Mmap {
    /// Decode an `mmap` call from its syscall registers.
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
        let addr = ctx.args[0];
        let length = ctx.args[1];
        let prot = ctx.args[2];
        let flags = ctx.args[3];
        let fd_raw = i64::from(ctx.args[4] as i32);
        let offset = ctx.args[5];

        Ok(DecodedCall {
            args: vec![
                ("addr", DecodedArg::Hex(addr)),
                ("length", DecodedArg::Uint(length)),
                ("prot", DecodedArg::Flags(decode_prot(prot))),
                ("flags", DecodedArg::Flags(decode_flags(flags, MAP_TABLE))),
                ("fd", DecodedArg::Fd(decode_fd(fd_raw))),
                ("offset", DecodedArg::Hex(offset)),
            ],
            ret: ctx.ret,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Mmap;
    use crate::decoder::{DecodeCtx, DecodedArg, Decoder};

    fn ctx_for(addr: u64, length: u64, prot: u64, flags: u64, fd: u64, offset: u64) -> DecodeCtx {
        DecodeCtx {
            pid: i32::try_from(std::process::id()).expect("pid fits in i32"),
            args: [addr, length, prot, flags, fd, offset],
            ret: 0,
        }
    }

    #[test]
    fn mmap_decoder_with_read_write_produces_both_flag_names() {
        let prot = (libc::PROT_READ | libc::PROT_WRITE) as u64;
        let call = Mmap
            .decode(&ctx_for(0, 4096, prot, 0, 0, 0))
            .expect("decode succeeds");
        let DecodedArg::Flags(names) = &call.args[2].1 else {
            panic!("expected Flags, got {:?}", call.args[2].1);
        };
        assert!(names.contains(&"PROT_READ"), "prot: {names:?}");
        assert!(names.contains(&"PROT_WRITE"), "prot: {names:?}");
    }

    #[test]
    fn mmap_decoder_with_prot_zero_produces_prot_none() {
        let call = Mmap
            .decode(&ctx_for(0, 4096, 0, 0, 0, 0))
            .expect("decode succeeds");
        let DecodedArg::Flags(names) = &call.args[2].1 else {
            panic!("expected Flags, got {:?}", call.args[2].1);
        };
        assert_eq!(names, &vec!["PROT_NONE"]);
    }

    #[test]
    fn mmap_decoder_with_private_anonymous_produces_both_flag_names() {
        let flags = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64;
        let call = Mmap
            .decode(&ctx_for(0, 4096, 0, flags, 0, 0))
            .expect("decode succeeds");
        let DecodedArg::Flags(names) = &call.args[3].1 else {
            panic!("expected Flags, got {:?}", call.args[3].1);
        };
        assert!(names.contains(&"MAP_PRIVATE"), "flags: {names:?}");
        assert!(names.contains(&"MAP_ANONYMOUS"), "flags: {names:?}");
    }

    #[test]
    fn mmap_decoder_renders_addr_as_hex() {
        let call = Mmap
            .decode(&ctx_for(0xdead_beef, 0, 0, 0, 0, 0))
            .expect("decode succeeds");
        assert!(
            matches!(call.args[0].1, DecodedArg::Hex(0xdead_beef)),
            "got {:?}",
            call.args[0].1
        );
    }

    #[test]
    fn mmap_decoder_renders_offset_as_hex() {
        let call = Mmap
            .decode(&ctx_for(0, 0, 0, 0, 0, 0x4000))
            .expect("decode succeeds");
        assert!(
            matches!(call.args[5].1, DecodedArg::Hex(0x4000)),
            "got {:?}",
            call.args[5].1
        );
    }
}
