//! Shared decoder traits and helpers.
//!
//! This module currently exposes the [`Decoder`] marker trait so
//! [`crate::registry::Registry`] can hold dispatch slots. Helper
//! functions and the full trait body land alongside the per-syscall
//! decoders in [`crate::decoders`].

/// Decode a single syscall's arguments and return value into a
/// structured representation.
///
/// Implementations live in [`crate::decoders`]. The trait is currently
/// a marker; method signatures will be added when the shared decoding
/// helpers (path, fd, flag bitsets) land.
pub trait Decoder: Send + Sync {}
