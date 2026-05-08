//! Output formatters for [`loi_core::SyscallEvent`] streams.
//!
//! - [`pretty`]: human-friendly colored single-line output.
//! - [`json`]: JSON-lines output, one event per line.
#![deny(missing_docs)]

pub mod json;
pub mod pretty;
