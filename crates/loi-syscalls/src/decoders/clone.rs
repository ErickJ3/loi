//! Decoder for the Linux `clone` syscall.
//!
//! `clone` has a wide flag bitset and an architecture-specific argument
//! ordering. The decoder targets the kernel ABI's register layout:
//!
//! - `x86_64`: `clone(flags, stack, parent_tid, child_tid, tls) -> pid`.
//! - `aarch64`: `clone(flags, stack, parent_tid, tls, child_tid) -> pid`
//!   (the kernel swaps the last two args on this arch).
//!
//! `clone3` has a struct-shaped argument and is intentionally out of scope.
//! Calls go through the generic fallback decoder which renders raw register
//! values.

use crate::decode_flags;
use crate::decoder::{
    Category, DecodeCtx, DecodeError, DecodedArg, DecodedCall, Decoder, c_int_to_u64,
};

const CLONE_TABLE: &[(u64, &str)] = &[
    (c_int_to_u64(libc::CLONE_VM), "CLONE_VM"),
    (c_int_to_u64(libc::CLONE_FS), "CLONE_FS"),
    (c_int_to_u64(libc::CLONE_FILES), "CLONE_FILES"),
    (c_int_to_u64(libc::CLONE_SIGHAND), "CLONE_SIGHAND"),
    (c_int_to_u64(libc::CLONE_PIDFD), "CLONE_PIDFD"),
    (c_int_to_u64(libc::CLONE_PTRACE), "CLONE_PTRACE"),
    (c_int_to_u64(libc::CLONE_VFORK), "CLONE_VFORK"),
    (c_int_to_u64(libc::CLONE_PARENT), "CLONE_PARENT"),
    (c_int_to_u64(libc::CLONE_THREAD), "CLONE_THREAD"),
    (c_int_to_u64(libc::CLONE_NEWNS), "CLONE_NEWNS"),
    (c_int_to_u64(libc::CLONE_SYSVSEM), "CLONE_SYSVSEM"),
    (c_int_to_u64(libc::CLONE_SETTLS), "CLONE_SETTLS"),
    (
        c_int_to_u64(libc::CLONE_PARENT_SETTID),
        "CLONE_PARENT_SETTID",
    ),
    (
        c_int_to_u64(libc::CLONE_CHILD_CLEARTID),
        "CLONE_CHILD_CLEARTID",
    ),
    (c_int_to_u64(libc::CLONE_DETACHED), "CLONE_DETACHED"),
    (c_int_to_u64(libc::CLONE_UNTRACED), "CLONE_UNTRACED"),
    (c_int_to_u64(libc::CLONE_CHILD_SETTID), "CLONE_CHILD_SETTID"),
    (c_int_to_u64(libc::CLONE_NEWCGROUP), "CLONE_NEWCGROUP"),
    (c_int_to_u64(libc::CLONE_NEWUTS), "CLONE_NEWUTS"),
    (c_int_to_u64(libc::CLONE_NEWIPC), "CLONE_NEWIPC"),
    (c_int_to_u64(libc::CLONE_NEWUSER), "CLONE_NEWUSER"),
    (c_int_to_u64(libc::CLONE_NEWPID), "CLONE_NEWPID"),
    (c_int_to_u64(libc::CLONE_NEWNET), "CLONE_NEWNET"),
    (c_int_to_u64(libc::CLONE_IO), "CLONE_IO"),
];

#[cfg(target_arch = "aarch64")]
const PTR_LABELS: [&str; 3] = ["parent_tid", "tls", "child_tid"];

#[cfg(not(target_arch = "aarch64"))]
const PTR_LABELS: [&str; 3] = ["parent_tid", "child_tid", "tls"];

/// Decoder for the Linux `clone` syscall.
///
/// Stateless; the unit value is `Send + Sync` so a single static instance
/// can be shared across the registry.
#[derive(Debug, Clone, Copy, Default)]
pub struct Clone;

impl Decoder for Clone {
    fn category(&self) -> Category {
        Category::Process
    }

    /// Decode a `clone` call from its syscall registers.
    ///
    /// # Errors
    ///
    /// Infallible in practice: no tracee memory is read. Returns
    /// [`DecodeError`] only to match the [`Decoder`] trait signature.
    fn decode(&self, ctx: &DecodeCtx) -> Result<DecodedCall, DecodeError> {
        Ok(DecodedCall {
            args: vec![
                (
                    "flags",
                    DecodedArg::Flags(decode_flags(ctx.args[0], CLONE_TABLE)),
                ),
                ("stack", DecodedArg::Ptr(ctx.args[1])),
                (PTR_LABELS[0], DecodedArg::Ptr(ctx.args[2])),
                (PTR_LABELS[1], DecodedArg::Ptr(ctx.args[3])),
                (PTR_LABELS[2], DecodedArg::Ptr(ctx.args[4])),
            ],
            ret: ctx.ret,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Clone;
    use crate::decoder::{DecodeCtx, DecodedArg, Decoder};

    fn ctx_for(flags: u64) -> DecodeCtx {
        DecodeCtx {
            pid: i32::try_from(std::process::id()).expect("pid fits in i32"),
            args: [flags, 0x1000, 0x2000, 0x3000, 0x4000, 0],
            ret: 1234,
        }
    }

    fn flag_names(call: &super::DecodedCall) -> &[&'static str] {
        let DecodedArg::Flags(names) = &call.args[0].1 else {
            panic!("expected Flags, got {:?}", call.args[0].1);
        };
        names
    }

    #[test]
    fn clone_decoder_with_vm_fs_files_produces_all_three_flag_names() {
        let flags = (libc::CLONE_VM | libc::CLONE_FS | libc::CLONE_FILES) as u64;
        let call = Clone.decode(&ctx_for(flags)).expect("decode succeeds");
        let names = flag_names(&call);
        assert!(names.contains(&"CLONE_VM"), "names: {names:?}");
        assert!(names.contains(&"CLONE_FS"), "names: {names:?}");
        assert!(names.contains(&"CLONE_FILES"), "names: {names:?}");
    }

    #[test]
    fn clone_decoder_with_newns_newuts_produces_namespace_flag_names() {
        let flags = (libc::CLONE_NEWNS | libc::CLONE_NEWUTS) as u64;
        let call = Clone.decode(&ctx_for(flags)).expect("decode succeeds");
        let names = flag_names(&call);
        assert!(names.contains(&"CLONE_NEWNS"), "names: {names:?}");
        assert!(names.contains(&"CLONE_NEWUTS"), "names: {names:?}");
    }

    #[test]
    fn clone_decoder_renders_pointer_args_as_ptr() {
        let call = Clone.decode(&ctx_for(0)).expect("decode succeeds");
        assert!(
            matches!(call.args[1].1, DecodedArg::Ptr(0x1000)),
            "got {:?}",
            call.args[1].1
        );
        assert!(
            matches!(call.args[2].1, DecodedArg::Ptr(0x2000)),
            "got {:?}",
            call.args[2].1
        );
    }

    #[test]
    fn clone_decoder_passes_through_ret_value() {
        let call = Clone.decode(&ctx_for(0)).expect("decode succeeds");
        assert_eq!(call.ret, 1234);
    }
}
