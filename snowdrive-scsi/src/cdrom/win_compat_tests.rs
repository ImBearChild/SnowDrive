//! Windows-compatibility regression tests for the UdfRw CD-ROM profile.
//!
//! Captured-traffic background (usbredir → usb-storage on Windows 10):
//! during enumeration Windows fires a burst of SECURITY PROTOCOL IN (A2h)
//! probes that the drive correctly rejects with ILLEGAL REQUEST. With the
//! former "any pending sense preempts the next command" behaviour, that
//! stale sense then poisoned the following GET EVENT STATUS NOTIFICATION /
//! GET CONFIGURATION polls, Windows' media-state machine gave up and the
//! medium was treated as read-only (no format UI, `format X:` silent-exit).
//! Per SPC-4 only a UNIT ATTENTION may preempt a later command — see the
//! pending-sense gate in [`CdromDrive::do_cmd`].

use crate::cdrom::drive::CdromDrive;
#[cfg(feature = "udf_void")]
use crate::cdrom::udfrw::UdfRwMedia;
use crate::common::block_storage::RwRef;
use crate::scsi::backend::{BlockBackend, RamBackend};
use crate::scsi::device::CommandOutcome;
use crate::scsi::spc::SpcDevice as _;

fn hex(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// READ FORMAT CAPACITIES must advertise the Formattable Capacity Descriptor
/// with Format Type 00h and Type Dependent Parameter = block length 0800h
/// (MMC-6 Tables 468/469). Hosts echo this descriptor verbatim inside the
/// FORMAT UNIT parameter list (dvd+rw-format does exactly that), so a wrong
/// TDP here turns into an INVALID-FIELD failure over there.
#[test]
fn rfc_formattable_descriptor_tdp_is_block_length() {
    let mut img = vec![0u8; 2048 * 204800];
    let mut scratch = [0u8; 256];
    let mut dev = CdromDrive::new();
    let mut bb = BlockBackend::Ram(RamBackend::new(&mut img));
    #[cfg(feature = "udf_void")]
    {
        let media = UdfRwMedia::materialize(RwRef::new(&mut bb), "TEST", &mut scratch).unwrap();
        dev.load_quiet(crate::cdrom::media::CdMedia::Rw(media));
    }
    #[cfg(not(feature = "udf_void"))]
    dev.load_quiet(crate::cdrom::media::CdMedia::ro(&mut bb));

    let mut w = [0u8; crate::MIN_DATA_LEN];
    let cdb = [0x23u8, 0, 0, 0, 0, 0, 0, 0, 0x14, 0]; // alloc=20
    let out = dev.do_cmd(&cdb, &mut w).unwrap();
    let n = match out {
        CommandOutcome::OutInline { len } => len,
        other => panic!("expected inline data, got {other:?}"),
    };
    assert_eq!(n, 20);
    assert_eq!(w[3], 16, "capacity list length = 2 descriptors");
    // Current/Maximum Capacity Descriptor: formatted media, 2048-byte blocks.
    assert_eq!(w[8], 0x02);
    assert_eq!(&w[9..12], &[0x00, 0x08, 0x00]);
    // Formattable Capacity Descriptor: Full Format (type 00h « 2), and the
    // Type Dependent Parameter MUST carry the block length.
    assert_eq!(w[16], 0x00, "format type 00h");
    assert_eq!(
        &w[17..20],
        &[0x00, 0x08, 0x00],
        "TDP must advertise block length 2048"
    );
}

/// Single-command sanity: the probes Windows sends must behave per spec.
#[test]
fn win_single_cmds_diag() {
    let mut img = vec![0u8; 2048 * 204800];
    let mut scratch = [0u8; 256];
    let mut dev = CdromDrive::new();
    let mut bb = BlockBackend::Ram(RamBackend::new(&mut img));
    #[cfg(feature = "udf_void")]
    {
        let media = UdfRwMedia::materialize(RwRef::new(&mut bb), "TEST", &mut scratch).unwrap();
        dev.load_quiet(crate::cdrom::media::CdMedia::Rw(media));
    }
    #[cfg(not(feature = "udf_void"))]
    dev.load_quiet(crate::cdrom::media::CdMedia::ro(&mut bb));

    // consume initial UA
    let mut w = [0u8; crate::MIN_DATA_LEN];
    let _ = dev.do_cmd(&[0x00; 6], &mut w);
    let _ = dev.take_sense();

    let cases: &[(&str, Vec<u8>)] = &[
        ("GESN class=00", vec![0x4A, 1, 0, 0, 0x00, 0, 0, 0, 0x08, 0]),
        ("GESN class=10", vec![0x4A, 1, 0, 0, 0x10, 0, 0, 0, 0x08, 0]),
        ("GETCFG alloc8", vec![0x46, 0, 0, 0, 0, 0, 0, 0, 0x08, 0]),
        ("MODESNSE p20", vec![0x5A, 0, 0x20, 0, 0, 0, 0, 0, 0x80, 0]),
        (
            "ATA PASSTHRU",
            vec![0x85, 8, 0x24, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xA1, 0],
        ),
        (
            "SEC PROTO IN",
            vec![0xA2, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0],
        ),
    ];
    for (name, cdb, expect) in [
        (
            "GESN class=00",
            vec![0x4A, 1, 0, 0, 0x00, 0, 0, 0, 0x08, 0],
            "inline8",
        ),
        (
            "GESN class=10",
            vec![0x4A, 1, 0, 0, 0x10, 0, 0, 0, 0x08, 0],
            "inline8",
        ),
        (
            "GETCFG alloc8",
            vec![0x46, 0, 0, 0, 0, 0, 0, 0, 0x08, 0],
            "inline8",
        ),
        (
            "MODESENSE p20",
            vec![0x5A, 0, 0x20, 0, 0, 0, 0, 0, 0x80, 0],
            "cc24",
        ),
        (
            "ATA PASSTHRU",
            vec![0x85, 8, 0x24, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xA1, 0],
            "cc20",
        ),
        (
            "SEC PROTO IN",
            vec![0xA2, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0],
            "cc20",
        ),
    ] {
        let mut w = [0u8; crate::MIN_DATA_LEN];
        let out = dev.do_cmd(&cdb, &mut w).unwrap();
        match (expect, &out) {
            ("inline8", CommandOutcome::OutInline { len }) => assert_eq!(*len, 8),
            ("cc20", CommandOutcome::CheckCondition) => {
                let s = dev.peek_sense().unwrap();
                assert_eq!(s.key, crate::scsi::scsi::SenseKey::IllegalRequest);
                assert_eq!(s.asc, crate::scsi::scsi::asc::INVALID_COMMAND);
            }
            ("cc24", CommandOutcome::CheckCondition) => {
                let s = dev.peek_sense().unwrap();
                assert_eq!(s.key, crate::scsi::scsi::SenseKey::IllegalRequest);
                assert_eq!(s.asc, crate::scsi::scsi::asc::INVALID_FIELD);
            }
            _ => panic!("{name}: unexpected outcome {out:?}"),
        }
        let _ = dev.take_sense();
    }
}

/// Regression: a rejected SECURITY PROTOCOL IN leaves NO lingering sense —
/// the next GET EVENT STATUS NOTIFICATION and GET CONFIGURATION must succeed.
#[test]
fn win_rejected_probe_does_not_poison_next_command() {
    let mut img = vec![0u8; 2048 * 204800];
    let mut scratch = [0u8; 256];
    let mut dev = CdromDrive::new();
    let mut bb = BlockBackend::Ram(RamBackend::new(&mut img));
    #[cfg(feature = "udf_void")]
    {
        let media = UdfRwMedia::materialize(RwRef::new(&mut bb), "TEST", &mut scratch).unwrap();
        dev.load_quiet(crate::cdrom::media::CdMedia::Rw(media));
    }
    #[cfg(not(feature = "udf_void"))]
    dev.load_quiet(crate::cdrom::media::CdMedia::ro(&mut bb));

    let mut w = [0u8; crate::MIN_DATA_LEN];
    let _ = dev.do_cmd(&[0x00; 6], &mut w); // initial UA via TUR
    let _ = dev.take_sense();

    let spi = [0xA2u8, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0];
    for i in 0..6 {
        let out = dev.do_cmd(&spi, &mut w).unwrap();
        assert_eq!(out, CommandOutcome::CheckCondition, "A2 #{i} must reject");
        assert_eq!(
            dev.peek_sense().unwrap().asc,
            crate::scsi::scsi::asc::INVALID_COMMAND
        );
    }

    let gesn = [0x4Au8, 1, 0, 0, 0x00, 0, 0, 0, 0x08, 0];
    let out = dev.do_cmd(&gesn, &mut w).unwrap();
    assert!(
        matches!(out, CommandOutcome::OutInline { .. }),
        "stale ILLEGAL REQUEST sense must not fail GESN"
    );

    let getcfg = [0x46u8, 0, 0, 0, 0, 0, 0, 0, 0x08, 0];
    let out = dev.do_cmd(&getcfg, &mut w).unwrap();
    assert!(
        matches!(out, CommandOutcome::OutInline { .. }),
        "stale sense must not fail GET CONFIGURATION"
    );
}

/// UNIT ATTENTION keeps its preemption semantics: reported exactly once on
/// the next non-bypass command, consumed on delivery.
#[test]
fn win_ua_still_reports_once() {
    use crate::scsi::scsi::{asc, Sense, SenseKey};

    let mut img = vec![0u8; 2048 * 204800];
    let mut scratch = [0u8; 256];
    let mut dev = CdromDrive::new();
    let mut bb = BlockBackend::Ram(RamBackend::new(&mut img));
    #[cfg(feature = "udf_void")]
    {
        let media = UdfRwMedia::materialize(RwRef::new(&mut bb), "TEST", &mut scratch).unwrap();
        dev.load_quiet(crate::cdrom::media::CdMedia::Rw(media));
    }
    #[cfg(not(feature = "udf_void"))]
    dev.load_quiet(crate::cdrom::media::CdMedia::ro(&mut bb));

    let mut w = [0u8; crate::MIN_DATA_LEN];
    dev.set_sense(Sense::new(
        SenseKey::UnitAttention,
        asc::MEDIUM_MAY_HAVE_CHANGED,
        0,
    ));
    let gesn = [0x4Au8, 1, 0, 0, 0x10, 0, 0, 0, 0x08, 0];
    assert_eq!(
        dev.do_cmd(&gesn, &mut w).unwrap(),
        CommandOutcome::CheckCondition
    );
    assert!(dev.peek_sense().is_none(), "UA delivered once");
    assert_eq!(
        dev.do_cmd(&gesn, &mut w).unwrap(),
        CommandOutcome::OutInline { len: 8 }
    );
}
