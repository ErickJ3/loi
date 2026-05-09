//! Syscall number to name lookup and decoder dispatch.
//!
//! Names come from the [`syscalls`] crate's per-arch `Sysno` enum,
//! re-exported by `cfg(target_arch = ...)` (see
//! `syscalls::arch` for the full list of supported architectures).
//! Lookup is a single `match` inside `Sysno::name`: O(1), no allocation.
//!
//! Decoder dispatch is populated by per-syscall decoders in
//! [`crate::decoders`]; until they land, every slot is `None`.

use crate::decoder::Decoder;
use std::collections::HashMap;
use syscalls::Sysno;

fn sysno_from_nr(nr: u64) -> Option<Sysno> {
    Sysno::new(usize::try_from(nr).ok()?)
}

/// Resolve a raw syscall number to its name on the host arch.
///
/// Returns `None` if `nr` is outside the host arch's syscall table.
/// The returned `&'static str` is borrowed from a compile-time table;
/// no allocation occurs per lookup.
#[must_use]
pub fn name(nr: u64) -> Option<&'static str> {
    sysno_from_nr(nr).map(|s| s.name())
}

/// Per-arch syscall registry: name lookup plus decoder dispatch.
///
/// Construct with [`Registry::new`]. Decoder slots are empty until
/// per-syscall decoders register themselves in later milestones.
#[derive(Default)]
pub struct Registry {
    decoders: HashMap<Sysno, &'static dyn Decoder>,
}

impl Registry {
    /// Build an empty registry. Decoder slots are populated by callers.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up the decoder for a syscall number, if registered.
    #[must_use]
    pub fn decoder(&self, nr: u64) -> Option<&'static dyn Decoder> {
        self.decoders.get(&sysno_from_nr(nr)?).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::{Registry, name};

    fn host_write_nr() -> u64 {
        u64::try_from(syscalls::Sysno::write.id()).expect("write syscall id is non-negative")
    }

    #[test]
    fn name_returns_write_for_host_write_syscall() {
        assert_eq!(name(host_write_nr()), Some("write"));
    }

    #[test]
    fn name_returns_none_for_u64_max() {
        assert_eq!(name(u64::MAX), None);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn name_x86_64_nr_1_is_write() {
        assert_eq!(name(1), Some("write"));
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn name_aarch64_nr_64_is_write() {
        assert_eq!(name(64), Some("write"));
    }

    #[test]
    fn registry_decoder_slot_is_none_until_registered() {
        let reg = Registry::new();
        assert!(reg.decoder(host_write_nr()).is_none());
    }
}
