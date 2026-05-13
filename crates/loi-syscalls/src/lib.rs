//! Syscall registry and per-syscall argument decoders.
//!
//! [`registry`] maps syscall numbers to names + decoder dispatch.
//! [`decoder`] holds shared decoding helpers used by [`decoders`].
#![deny(missing_docs)]

pub mod decoder;
pub mod decoders;
pub mod registry;
pub use decoder::{
    DecodeCtx, DecodeError, DecodedArg, DecodedCall, Decoder, FdRepr, PATH_MAX, PROT_TABLE,
    decode_fd, decode_flags, decode_path, decode_prot,
};
pub use decoders::close::Close;
pub use decoders::mmap::Mmap;
pub use decoders::openat::OpenAt;
pub use decoders::read::{MAX_INLINE_BYTES, Read};
pub use decoders::stat::{Fstat, Stat, Statx};
pub use decoders::write::Write;
pub use registry::{Registry, name};
