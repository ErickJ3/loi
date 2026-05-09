//! Output formatters for [`loi_core::SyscallEvent`] streams.
//!
//! - [`pretty`]: human-friendly colored single-line output.
//! - [`json`]: JSON-lines output, one event per line.
#![deny(missing_docs)]

mod format_common;

pub mod json;
pub mod pretty;

pub use pretty::PrettyConfig;
