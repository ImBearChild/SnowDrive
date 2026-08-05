//! libiscsi whitebox integration tests.
//!
//! A real initiator (libiscsi) drives the in-process Rust iSCSI target over a
//! real TCP loopback connection. FFI uses opaque pointers plus a tiny C
//! accessor (`tests/c/iscsi_access.c`, compiled by `cc` in build.rs) so no
//! libiscsi struct layout is assumed on the Rust side.
//!
//! ABI notes:
//! - `iscsi_connect_sync` only establishes TCP; login needs
//!   `iscsi_full_connect_sync` (TCP + Login Request + UA-eating TUR).
//! - `iscsi_testunitready_sync` returns `struct scsi_task *`, not `int`.
//!
//! The WRITE(10) path is the regression test for the W-bit fix (`de7e8c1`):
//! libiscsi emits the Linux-kernel byte 1 layout (F|W|ATTR), and a target
//! that misreads the W bit (0x04) rejects these writes with CHECK CONDITION.

use std::ffi::{c_int, CStr, CString};
use std::net::TcpListener;
use std::thread;

use snowscsi::transport::DEFAULT_READ_TIMEOUT;
use snowscsi::{serve_conn, Device, RamBackend, Session, TargetError, TcpConn, MIN_WORK_LEN};

/// libiscsi constants (iscsi.h / scsi-lowlevel.h).
const ISCSI_SESSION_NORMAL: c_int = 2;
const ISCSI_HEADER_DIGEST_NONE_CRC32C: c_int = 1;
const SCSI_STATUS_GOOD: c_int = 0;
const SCSI_STATUS_CHECK_CONDITION: c_int = 2;
const SENSE_KEY_ILLEGAL_REQUEST: c_int = 5;

/// 16 MiB RAM disk = 32768 logical blocks of 512 B (last LBA 32767).
const RAM_SIZE: usize = 16 * 1024 * 1024;
const BLOCK_SIZE: u32 = 512;
const LAST_LBA: u32 = 32767;

/// Opaque libiscsi FFI surface. All handles are `*mut c_void`; struct access
/// goes through the C accessors, never through a hand-written layout.
mod ffi {
    use core::ffi::{c_char, c_int, c_void};

    pub type Iscsi = *mut c_void;
    pub type Task = *mut c_void;

    extern "C" {
        pub fn iscsi_create_context(initiator_name: *const c_char) -> Iscsi;
        pub fn iscsi_destroy_context(iscsi: Iscsi) -> c_int;
        pub fn iscsi_set_targetname(iscsi: Iscsi, targetname: *const c_char) -> c_int;
        pub fn iscsi_set_session_type(iscsi: Iscsi, session_type: c_int) -> c_int;
        pub fn iscsi_set_header_digest(iscsi: Iscsi, value: c_int) -> c_int;
        pub fn iscsi_full_connect_sync(iscsi: Iscsi, portal: *const c_char, lun: c_int) -> c_int;
        pub fn iscsi_disconnect(iscsi: Iscsi) -> c_int;
        pub fn iscsi_get_error(iscsi: Iscsi) -> *const c_char;
        pub fn iscsi_testunitready_sync(iscsi: Iscsi, lun: c_int) -> Task;
        pub fn iscsi_inquiry_sync(
            iscsi: Iscsi,
            lun: c_int,
            evpd: c_int,
            page_code: c_int,
            maxsize: c_int,
        ) -> Task;
        pub fn iscsi_readcapacity10_sync(iscsi: Iscsi, lun: c_int, lba: c_int, pmi: c_int) -> Task;
        pub fn iscsi_read10_sync(
            iscsi: Iscsi,
            lun: c_int,
            lba: u32,
            datalen: u32,
            blocksize: c_int,
            rdprotect: c_int,
            dpo: c_int,
            fua: c_int,
            fua_nv: c_int,
            group_number: c_int,
        ) -> Task;
        pub fn iscsi_write10_sync(
            iscsi: Iscsi,
            lun: c_int,
            lba: u32,
            data: *const u8,
            datalen: u32,
            blocksize: c_int,
            wrprotect: c_int,
            dpo: c_int,
            fua: c_int,
            fua_nv: c_int,
            group_number: c_int,
        ) -> Task;
        pub fn scsi_free_scsi_task(task: Task);
        pub fn snow_task_status(task: Task) -> c_int;
        pub fn snow_task_datain_size(task: Task) -> c_int;
        pub fn snow_task_datain_data(task: Task) -> *const u8;
        pub fn snow_task_sense_key(task: Task) -> c_int;
    }
}

/// Owned `iscsi_context`; disconnect + free on drop (panic-safe teardown).
struct IscsiCtx {
    raw: ffi::Iscsi,
}

impl IscsiCtx {
    fn new(initiator_name: &str) -> Self {
        let name = CString::new(initiator_name).unwrap();
        let raw = unsafe { ffi::iscsi_create_context(name.as_ptr()) };
        assert!(!raw.is_null(), "iscsi_create_context failed");
        Self { raw }
    }

    fn error(&self) -> String {
        let e = unsafe { ffi::iscsi_get_error(self.raw) };
        if e.is_null() {
            "unknown libiscsi error".to_string()
        } else {
            unsafe { CStr::from_ptr(e) }.to_string_lossy().into_owned()
        }
    }

    fn set_targetname(&self, target: &str) {
        let t = CString::new(target).unwrap();
        assert_eq!(
            unsafe { ffi::iscsi_set_targetname(self.raw, t.as_ptr()) },
            0,
            "set_targetname: {}",
            self.error()
        );
    }

    fn set_session_type(&self, session_type: c_int) {
        assert_eq!(
            unsafe { ffi::iscsi_set_session_type(self.raw, session_type) },
            0,
            "set_session_type: {}",
            self.error()
        );
    }

    fn set_header_digest(&self, value: c_int) {
        assert_eq!(
            unsafe { ffi::iscsi_set_header_digest(self.raw, value) },
            0,
            "set_header_digest: {}",
            self.error()
        );
    }

    /// Full connect: TCP + Login Request (+ the UA-eating TUR libiscsi issues
    /// right after login). `iscsi_connect_sync` alone is NOT enough — it only
    /// establishes TCP and leaves `is_loggedin == 0`, so every later SCSI
    /// command fails with "Trying to send command while not logged in".
    fn full_connect(&self, portal: &str) {
        let p = CString::new(portal).unwrap();
        assert_eq!(
            unsafe { ffi::iscsi_full_connect_sync(self.raw, p.as_ptr(), 0) },
            0,
            "full_connect: {}",
            self.error()
        );
    }

    fn disconnect(&self) {
        unsafe { ffi::iscsi_disconnect(self.raw) };
    }

    fn test_unit_ready(&self, lun: c_int) -> Task {
        let raw = unsafe { ffi::iscsi_testunitready_sync(self.raw, lun) };
        assert!(!raw.is_null(), "TUR transport: {}", self.error());
        Task { raw }
    }

    fn inquiry(&self, lun: c_int, evpd: c_int, page_code: c_int, maxsize: c_int) -> Task {
        let raw = unsafe { ffi::iscsi_inquiry_sync(self.raw, lun, evpd, page_code, maxsize) };
        assert!(!raw.is_null(), "INQUIRY transport: {}", self.error());
        Task { raw }
    }

    fn read_capacity10(&self, lun: c_int) -> Task {
        let raw = unsafe { ffi::iscsi_readcapacity10_sync(self.raw, lun, 0, 0) };
        assert!(!raw.is_null(), "READ CAPACITY transport: {}", self.error());
        Task { raw }
    }

    fn read10(&self, lun: c_int, lba: u32, datalen: u32, blocksize: c_int) -> Task {
        let raw = unsafe {
            ffi::iscsi_read10_sync(self.raw, lun, lba, datalen, blocksize, 0, 0, 0, 0, 0)
        };
        assert!(!raw.is_null(), "READ(10) transport: {}", self.error());
        Task { raw }
    }

    fn write10(&self, lun: c_int, lba: u32, data: &[u8], blocksize: c_int) -> Task {
        let raw = unsafe {
            ffi::iscsi_write10_sync(
                self.raw,
                lun,
                lba,
                data.as_ptr(),
                data.len() as u32,
                blocksize,
                0,
                0,
                0,
                0,
                0,
            )
        };
        assert!(!raw.is_null(), "WRITE(10) transport: {}", self.error());
        Task { raw }
    }
}

impl Drop for IscsiCtx {
    fn drop(&mut self) {
        unsafe { ffi::iscsi_destroy_context(self.raw) };
    }
}

/// Owned `scsi_task`; freed on drop.
struct Task {
    raw: ffi::Task,
}

impl Task {
    fn status(&self) -> c_int {
        unsafe { ffi::snow_task_status(self.raw) }
    }

    fn datain(&self) -> &[u8] {
        let size = unsafe { ffi::snow_task_datain_size(self.raw) };
        if size <= 0 {
            return &[];
        }
        let ptr = unsafe { ffi::snow_task_datain_data(self.raw) };
        assert!(!ptr.is_null(), "datain data pointer is null");
        unsafe { std::slice::from_raw_parts(ptr, size as usize) }
    }

    fn sense_key(&self) -> c_int {
        unsafe { ffi::snow_task_sense_key(self.raw) }
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        unsafe { ffi::scsi_free_scsi_task(self.raw) };
    }
}

/// Start the in-process target on an ephemeral loopback port. Returns the
/// port and the server thread join handle.
fn start_target() -> (u16, thread::JoinHandle<Result<(), TargetError>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (stream, _peer) = listener.accept().expect("target accept");
        let mut conn = TcpConn::new(stream, Some(DEFAULT_READ_TIMEOUT)).expect("tcp conn");
        let mut work = vec![0u8; MIN_WORK_LEN];
        let mut session = Session::new();
        let mut ram = vec![0u8; RAM_SIZE];
        let mut devs = [Device::new(RamBackend::new(&mut ram), BLOCK_SIZE).expect("device")];
        serve_conn(&mut conn, &mut work, &mut session, &mut devs)
    });
    (port, handle)
}

/// Connect a libiscsi context to the in-process target and log in.
fn connect(port: u16) -> IscsiCtx {
    let iscsi = IscsiCtx::new("iqn.1994-05.com.redhat:snowdrive-test");
    iscsi.set_targetname("iqn.1970-01.local.snowscsi:target");
    iscsi.set_session_type(ISCSI_SESSION_NORMAL);
    iscsi.set_header_digest(ISCSI_HEADER_DIGEST_NONE_CRC32C);
    iscsi.full_connect(&format!("127.0.0.1:{port}"));
    iscsi
}

/// Drop the connection and assert the target loop exited cleanly.
fn teardown(iscsi: &IscsiCtx, server: thread::JoinHandle<Result<(), TargetError>>) {
    iscsi.disconnect();
    server
        .join()
        .expect("target thread panicked")
        .expect("target server error");
}

#[test]
fn test_unit_ready_inquiry_read_capacity() {
    let (port, server) = start_target();
    let iscsi = connect(port);

    assert_eq!(
        iscsi.test_unit_ready(0).status(),
        SCSI_STATUS_GOOD,
        "TUR: {}",
        iscsi.error()
    );

    let task = iscsi.inquiry(0, 0, 0, 256);
    assert_eq!(
        task.status(),
        SCSI_STATUS_GOOD,
        "INQUIRY: {}",
        iscsi.error()
    );
    let data = task.datain();
    assert!(data.len() >= 66, "INQUIRY data too short: {}", data.len());
    assert_eq!(data[0] & 0x1F, 0, "PDT must be 0 (direct-access)");
    assert_eq!(data[2], 0x06, "byte[2] must be SPC-4 (分歧2)");
    assert_eq!(&data[8..16], b"SnowSCSI", "vendor ID");
    assert_eq!(&data[16..32], b"Virtual Disk    ", "product ID");
    assert_eq!(&data[32..36], b"0100", "product revision");
    let desc = |i: usize| u16::from_be_bytes([data[58 + 2 * i], data[58 + 2 * i + 1]]);
    assert_eq!(desc(0), 0x00A0, "version descriptor SAM-5");
    assert_eq!(desc(1), 0x0960, "version descriptor iSCSI");
    assert_eq!(desc(2), 0x0460, "version descriptor SPC-4");
    assert_eq!(desc(3), 0x04C0, "version descriptor SBC-3");

    let task = iscsi.read_capacity10(0);
    assert_eq!(
        task.status(),
        SCSI_STATUS_GOOD,
        "READ CAPACITY: {}",
        iscsi.error()
    );
    let data = task.datain();
    assert_eq!(data.len(), 8, "RC10 returns 8 bytes");
    assert_eq!(
        u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
        LAST_LBA
    );
    assert_eq!(
        u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        BLOCK_SIZE
    );

    teardown(&iscsi, server);
}

/// WRITE(10)+READ(10) roundtrip over the wire, 100 iterations. libiscsi
/// sends the Linux-kernel byte 1 layout — this is the W-bit regression
/// (a target reading W as 0x04 rejects every one of these with
/// CHECK CONDITION).
#[test]
fn write_read_roundtrip_100() {
    let (port, server) = start_target();
    let iscsi = connect(port);

    for i in 0..100u32 {
        let mut buf = vec![0u8; 512];
        buf[..4].copy_from_slice(&i.to_be_bytes());
        buf[4..].fill(0xA5);
        let t = iscsi.write10(0, i, &buf, BLOCK_SIZE as c_int);
        assert_eq!(
            t.status(),
            SCSI_STATUS_GOOD,
            "WRITE lba={i}: {}",
            iscsi.error()
        );
        let t = iscsi.read10(0, i, 512, BLOCK_SIZE as c_int);
        assert_eq!(
            t.status(),
            SCSI_STATUS_GOOD,
            "READ lba={i}: {}",
            iscsi.error()
        );
        assert_eq!(t.datain(), &buf[..], "roundtrip mismatch at lba={i}");
    }

    teardown(&iscsi, server);
}

/// A write past the end of the device must surface a CHECK CONDITION with
/// ILLEGAL REQUEST sense on the wire.
#[test]
fn write_out_of_range_sense() {
    let (port, server) = start_target();
    let iscsi = connect(port);

    let buf = vec![0x5Au8; 512];
    let t = iscsi.write10(0, LAST_LBA + 1, &buf, BLOCK_SIZE as c_int);
    assert_eq!(
        t.status(),
        SCSI_STATUS_CHECK_CONDITION,
        "out-of-range write must be CHECK CONDITION: {}",
        iscsi.error()
    );
    assert_eq!(
        t.sense_key(),
        SENSE_KEY_ILLEGAL_REQUEST,
        "sense key must be ILLEGAL_REQUEST (5): {}",
        iscsi.error()
    );

    teardown(&iscsi, server);
}
