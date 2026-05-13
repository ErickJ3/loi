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
use crate::decoders::close::Close;
use crate::decoders::openat::OpenAt;
use crate::decoders::read::Read;
use crate::decoders::stat::{Fstat, Statx};
use crate::decoders::write::Write;
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

    /// Build a registry pre-populated with the host-arch decoders shipped
    /// with the crate.
    ///
    /// Numbers come from the per-arch [`Sysno`] table, so the same call
    /// works on every architecture the `syscalls` crate covers.
    #[must_use]
    pub fn with_default_decoders() -> Self {
        static OPENAT_DECODER: OpenAt = OpenAt;
        static READ_DECODER: Read = Read;
        static WRITE_DECODER: Write = Write;
        static CLOSE_DECODER: Close = Close;
        static FSTAT_DECODER: Fstat = Fstat;
        static STATX_DECODER: Statx = Statx;

        let mut r = Self::new();
        r.register(sysno_id_u64(Sysno::openat), &OPENAT_DECODER);
        r.register(sysno_id_u64(Sysno::read), &READ_DECODER);
        r.register(sysno_id_u64(Sysno::write), &WRITE_DECODER);
        r.register(sysno_id_u64(Sysno::close), &CLOSE_DECODER);
        r.register(sysno_id_u64(Sysno::fstat), &FSTAT_DECODER);
        r.register(sysno_id_u64(Sysno::statx), &STATX_DECODER);
        #[cfg(target_arch = "x86_64")]
        {
            use crate::decoders::stat::Stat;
            static STAT_DECODER: Stat = Stat;
            r.register(sysno_id_u64(Sysno::stat), &STAT_DECODER);
        }
        r
    }

    /// Register `decoder` for syscall number `nr`. Replaces any existing
    /// entry for the same number.
    ///
    /// Numbers outside the host arch's [`Sysno`] table are silently
    /// dropped: the registry only has rows for syscalls the kernel can
    /// actually emit, so storing a decoder under an unknown number would
    /// be unreachable. The `debug_assert` flags accidental misuse during
    /// development without aborting in release builds.
    pub fn register(&mut self, nr: u64, decoder: &'static dyn Decoder) {
        match sysno_from_nr(nr) {
            Some(sysno) => {
                self.decoders.insert(sysno, decoder);
            }
            None => debug_assert!(false, "register called with unknown syscall nr {nr}"),
        }
    }

    /// Look up the decoder for a syscall number, if registered.
    #[must_use]
    pub fn decoder(&self, nr: u64) -> Option<&'static dyn Decoder> {
        self.decoders.get(&sysno_from_nr(nr)?).copied()
    }
}

fn sysno_id_u64(s: Sysno) -> u64 {
    debug_assert!(s.id() >= 0, "Sysno::id is non-negative");
    u64::try_from(s.id()).unwrap_or(u64::MAX)
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

    #[test]
    fn with_default_decoders_wires_openat_read_write() {
        let reg = Registry::with_default_decoders();
        let openat_nr = u64::try_from(syscalls::Sysno::openat.id()).expect("openat id fits in u64");
        let read_nr = u64::try_from(syscalls::Sysno::read.id()).expect("read id fits in u64");
        let write_nr = host_write_nr();
        assert!(reg.decoder(openat_nr).is_some());
        assert!(reg.decoder(read_nr).is_some());
        assert!(reg.decoder(write_nr).is_some());
    }

    #[test]
    fn with_default_decoders_wires_close() {
        let reg = Registry::with_default_decoders();
        let close_nr = u64::try_from(syscalls::Sysno::close.id()).expect("close id fits in u64");
        assert!(reg.decoder(close_nr).is_some());
    }

    #[test]
    fn with_default_decoders_wires_fstat_and_statx() {
        let reg = Registry::with_default_decoders();
        let fstat_nr = u64::try_from(syscalls::Sysno::fstat.id()).expect("fstat id fits in u64");
        let statx_nr = u64::try_from(syscalls::Sysno::statx.id()).expect("statx id fits in u64");
        assert!(reg.decoder(fstat_nr).is_some());
        assert!(reg.decoder(statx_nr).is_some());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn with_default_decoders_wires_stat_on_x86_64() {
        let reg = Registry::with_default_decoders();
        let stat_nr = u64::try_from(syscalls::Sysno::stat.id()).expect("stat id fits in u64");
        assert!(reg.decoder(stat_nr).is_some());
    }
}
