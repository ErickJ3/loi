//! Syscall registry and per-syscall argument decoders.
//!
//! [`registry`] maps syscall numbers to names + decoder dispatch.
//! [`decoder`] holds shared decoding helpers used by [`decoders`].
#![deny(missing_docs)]

pub mod decoder;
pub mod decoders;
pub mod registry;
pub use decoder::{
    DecodeCtx, DecodeError, DecodedArg, DecodedCall, Decoder, FdRepr, PATH_MAX, decode_fd,
    decode_flags, decode_path,
};
pub use decoders::openat::OpenAt;
pub use decoders::read::{MAX_INLINE_BYTES, Read};
pub use decoders::write::Write;
pub use registry::{Registry, name};
