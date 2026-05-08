//! Syscall registry and per-syscall argument decoders.
//!
//! [`registry`] maps syscall numbers to names + decoder dispatch.
//! [`decoder`] holds shared decoding helpers used by [`decoders`].
#![deny(missing_docs)]

pub mod decoder;
pub mod decoders;
pub mod registry;
