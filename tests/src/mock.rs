//! Step-level iSCSI target integration tests (port of test_iscsi_mock.cpp
//! semantics). Deterministic, single thread: `MockConn` scripted byte stream
//! + `Session::step`.

#[cfg(test)]
mod tests {
    use snowscsi::iscsi_pdu::{flag, op, reject, stage, status, tmf, tmf_response};
    use snowscsi::{BlockDevice, LoginStage, RamBackend, Session, StepResult, MIN_WORK_LEN};
    use snowscsi_mock::MockConn;

    /// Login parameters as sent by a Linux open-iscsi initiator
    /// (concatenated literals preserve embedded NUL separators).
    const REQ_TEXT: &str = "InitiatorName=iqn.1994-05.com.redhat:702f27e1da14\0InitiatorAlias=develop\0TargetName=iqn.1970-01.local.snowscsi:target\0SessionType=Normal\0HeaderDigest=None\0DataDigest=None\0DefaultTime2Wait=2\0DefaultTime2Retain=0\0IFMarker=No\0OFMarker=No\0ErrorRecoveryLevel=0\0InitialR2T=No\0ImmediateData=Yes\0MaxBurstLength=16776192\0FirstBurstLength=262144\0MaxOutstandingR2T=1\0MaxConnections=1\0DataPDUInOrder=Yes\0DataSequenceInOrder=Yes\0MaxRecvDataSegmentLength=262144\0";

    fn be32(v: u32) -> [u8; 4] {
        v.to_be_bytes()
    }

    /// Login Request BHS: I=1, T=1, CSG=1, NSG=3 (matches Linux initiator).
    fn login_bhs(dsl: u32) -> [u8; 48] {
        let mut bhs = [0u8; 48];
        bhs[0] = op::LOGIN_REQ | 0x40;
        bhs[1] = flag::T_BIT | ((stage::OP_PARAM & 0x03) << flag::CSG_SHIFT) | stage::FULL_FEATURE;
        bhs[5] = (dsl >> 16) as u8;
        bhs[6] = (dsl >> 8) as u8;
        bhs[7] = dsl as u8;
        // CmdSN stays 0 (RFC 3720 §10.12.8): the first FullFeature command
        // reuses the leading Login Request's CmdSN.
        bhs
    }

    /// SCSI Command BHS for READ(10).
    fn read10_bhs(lba: u32, blocks: u16, itt: u32, cmd_sn: u32) -> [u8; 48] {
        let mut bhs = [0u8; 48];
        bhs[0] = op::SCSI_CMD;
        bhs[1] = 0x40; // task attribute (direction is taken from the CDB)
        bhs[16..20].copy_from_slice(&be32(itt));
        bhs[24..28].copy_from_slice(&be32(cmd_sn));
        bhs[28..32].copy_from_slice(&be32(cmd_sn)); // ExpStatSN
        bhs[32] = 0x28; // READ(10)
        bhs[34..38].copy_from_slice(&be32(lba));
        bhs[39..41].copy_from_slice(&blocks.to_be_bytes());
        bhs
    }

    /// SCSI Command BHS for WRITE(10) with a data segment (`dsl` bytes).
    fn write10_bhs(lba: u32, blocks: u16, itt: u32, cmd_sn: u32, dsl: u32) -> [u8; 48] {
        let mut bhs = [0u8; 48];
        bhs[0] = op::SCSI_CMD;
        // Kernel write layout (§2.3.3): F(0x80) | W(0x20) | ATTR_SIMPLE(0x01) = 0xA1.
        bhs[1] = 0xA1;
        bhs[5] = (dsl >> 16) as u8;
        bhs[6] = (dsl >> 8) as u8;
        bhs[7] = dsl as u8;
        bhs[16..20].copy_from_slice(&be32(itt));
        bhs[24..28].copy_from_slice(&be32(cmd_sn));
        bhs[28..32].copy_from_slice(&be32(cmd_sn)); // ExpStatSN
        bhs[32] = 0x2A; // WRITE(10)
        bhs[34..38].copy_from_slice(&be32(lba));
        bhs[39..41].copy_from_slice(&blocks.to_be_bytes());
        bhs
    }

    /// SCSI Data-Out BHS.
    fn dataout_bhs(itt: u32, ttt: u32, data_sn: u32, bo: u32, dsl: u32) -> [u8; 48] {
        let mut bhs = [0u8; 48];
        bhs[0] = op::SCSI_DATA_OUT;
        bhs[1] = 0x80; // F bit
        bhs[5] = (dsl >> 16) as u8;
        bhs[6] = (dsl >> 8) as u8;
        bhs[7] = dsl as u8;
        bhs[16..20].copy_from_slice(&be32(itt));
        bhs[20..24].copy_from_slice(&be32(ttt));
        bhs[36..40].copy_from_slice(&be32(data_sn));
        bhs[40..44].copy_from_slice(&be32(bo));
        bhs
    }

    fn resp_value<'a>(data: &'a [u8], key: &str) -> Option<&'a [u8]> {
        let k = key.as_bytes();
        let mut p = 0usize;
        while p < data.len() {
            if data[p..].starts_with(k) && p + k.len() < data.len() && data[p + k.len()] == b'=' {
                let start = p + k.len() + 1;
                let end = data[start..]
                    .iter()
                    .position(|&b| b == 0)
                    .map_or(data.len(), |i| start + i);
                return Some(&data[start..end]);
            }
            p = data[p..]
                .iter()
                .position(|&b| b == 0)
                .map_or(data.len(), |i| p + i + 1);
        }
        None
    }

    /// One-PDU login on the given harness; returns the Login Response PDU.
    fn login(
        conn: &mut MockConn,
        session: &mut Session,
        work: &mut [u8],
        devs: &mut [BlockDevice<RamBackend<'_>>],
    ) -> (Vec<u8>, Vec<u8>) {
        let text = REQ_TEXT.as_bytes();
        let bhs = login_bhs(text.len() as u32);
        conn.feed_padded(&bhs, text);
        assert_eq!(session.step(conn, work, devs), StepResult::Processed);
        conn.take_pdu().expect("login response")
    }

    // ── Login Response BHS: RFC 3720 §10.12.2 byte layout ──────────

    #[test]
    fn login_resp_bhs_rfc() {
        let mut conn = MockConn::new();
        let mut session = Session::default();
        let mut work = vec![0u8; MIN_WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let dev = BlockDevice::new(RamBackend::new(&mut ram), 512).unwrap();
        let mut devs = [dev];
        let (bhs, _data) = login(&mut conn, &mut session, &mut work, &mut devs);

        assert_eq!(bhs[0] & 0x3F, op::LOGIN_RESP);
        assert_eq!(bhs[1] & 0x80, 0x80); // T=1
        assert_eq!(bhs[1] & 0x40, 0x00); // C=0
        assert_eq!((bhs[1] >> 2) & 0x03, stage::OP_PARAM); // CSG
        assert_eq!(bhs[1] & 0x03, stage::FULL_FEATURE); // NSG
        assert_eq!(bhs[2], 0x00); // Version-max
        assert_eq!(bhs[3], 0x00); // Version-active
        assert_eq!(bhs[4], 0x00); // TotalAHSLength
        let dsl = (u32::from(bhs[5]) << 16) | (u32::from(bhs[6]) << 8) | u32::from(bhs[7]);
        assert!(dsl > 0);

        let lreq = login_bhs(REQ_TEXT.len() as u32);
        assert_eq!(&bhs[8..14], &lreq[8..14]); // ISID echoed
        let tsih = (u16::from(bhs[14]) << 8) | u16::from(bhs[15]);
        assert_ne!(tsih, 0); // new session TSIH non-zero
        assert_eq!(&bhs[16..20], &lreq[16..20]); // ITT echoed
        assert_eq!(&bhs[20..24], &[0, 0, 0, 0]); // reserved
        assert_eq!(&bhs[24..28], &be32(0)); // StatSN = 0
        assert_eq!(&bhs[28..32], &be32(0)); // ExpCmdSN = request CmdSN
        assert_eq!(&bhs[32..36], &be32(0)); // MaxCmdSN
        assert_eq!(bhs[36], 0x00); // Status-Class
        assert_eq!(bhs[37], 0x00); // Status-Detail
        assert_eq!(&bhs[38..48], &[0u8; 10]); // reserved
    }

    // ── Login Response keys ─────────────────────────────────────────

    #[test]
    fn login_resp_no_skipped_keys() {
        let mut conn = MockConn::new();
        let mut session = Session::default();
        let mut work = vec![0u8; MIN_WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let dev = BlockDevice::new(RamBackend::new(&mut ram), 512).unwrap();
        let mut devs = [dev];
        let (_bhs, data) = login(&mut conn, &mut session, &mut work, &mut devs);
        for k in [
            "TargetName",
            "InitiatorName",
            "InitiatorAlias",
            "SessionType",
            "AuthMethod",
            "TargetAddress",
        ] {
            assert!(resp_value(&data, k).is_none(), "{k} must not appear");
        }
    }

    #[test]
    fn login_resp_has_required_keys() {
        let mut conn = MockConn::new();
        let mut session = Session::default();
        let mut work = vec![0u8; MIN_WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let dev = BlockDevice::new(RamBackend::new(&mut ram), 512).unwrap();
        let mut devs = [dev];
        let (_bhs, data) = login(&mut conn, &mut session, &mut work, &mut devs);
        assert_eq!(
            resp_value(&data, "TargetAlias"),
            Some(b"SnowSCSI".as_slice())
        );
        assert_eq!(
            resp_value(&data, "TargetPortalGroupTag"),
            Some(b"1".as_slice())
        );
    }

    #[test]
    fn login_resp_echoes_all_keys() {
        let mut conn = MockConn::new();
        let mut session = Session::default();
        let mut work = vec![0u8; MIN_WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let dev = BlockDevice::new(RamBackend::new(&mut ram), 512).unwrap();
        let mut devs = [dev];
        let (_bhs, data) = login(&mut conn, &mut session, &mut work, &mut devs);
        assert_eq!(resp_value(&data, "InitialR2T"), Some(b"Yes".as_slice()));
        assert_eq!(
            resp_value(&data, "MaxBurstLength"),
            Some(b"16776192".as_slice())
        );
        assert_eq!(
            resp_value(&data, "FirstBurstLength"),
            Some(b"262144".as_slice())
        );
        assert_eq!(
            resp_value(&data, "MaxRecvDataSegmentLength"),
            Some(b"8192".as_slice())
        );
        assert_eq!(resp_value(&data, "DataPDUInOrder"), Some(b"Yes".as_slice()));
        assert_eq!(
            resp_value(&data, "DataSequenceInOrder"),
            Some(b"Yes".as_slice())
        );
        assert_eq!(resp_value(&data, "DefaultTime2Wait"), Some(b"2".as_slice()));
        assert_eq!(
            resp_value(&data, "DefaultTime2Retain"),
            Some(b"0".as_slice())
        );
        assert_eq!(resp_value(&data, "IFMarker"), Some(b"No".as_slice()));
        assert_eq!(resp_value(&data, "OFMarker"), Some(b"No".as_slice()));
        assert_eq!(resp_value(&data, "HeaderDigest"), Some(b"None".as_slice()));
        assert_eq!(resp_value(&data, "DataDigest"), Some(b"None".as_slice()));
        assert_eq!(resp_value(&data, "ImmediateData"), Some(b"Yes".as_slice()));
        assert_eq!(
            resp_value(&data, "MaxOutstandingR2T"),
            Some(b"1".as_slice())
        );
        assert_eq!(resp_value(&data, "MaxConnections"), Some(b"1".as_slice()));
        assert_eq!(
            resp_value(&data, "ErrorRecoveryLevel"),
            Some(b"0".as_slice())
        );
    }

    #[test]
    fn login_resp_data_length() {
        let mut conn = MockConn::new();
        let mut session = Session::default();
        let mut work = vec![0u8; MIN_WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let dev = BlockDevice::new(RamBackend::new(&mut ram), 512).unwrap();
        let mut devs = [dev];
        let (bhs, _data) = login(&mut conn, &mut session, &mut work, &mut devs);
        let dsl = (u32::from(bhs[5]) << 16) | (u32::from(bhs[6]) << 8) | u32::from(bhs[7]);
        assert!(dsl <= 4096);
        assert!(dsl <= 8192);
    }

    // ── Multi-stage login (CSG=0 → CSG=1 → Full Feature) ───────────

    #[test]
    fn multi_stage_login() {
        let mut conn = MockConn::new();
        let mut session = Session::default();
        let mut work = vec![0u8; MIN_WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let dev = BlockDevice::new(RamBackend::new(&mut ram), 512).unwrap();
        let mut devs = [dev];

        // Stage 1: CSG=0 (Security), T=1, NSG=3 → target forces NSG=1.
        let mut bhs = [0u8; 48];
        bhs[0] = op::LOGIN_REQ | 0x40;
        bhs[1] = flag::T_BIT | ((stage::SECURITY & 0x03) << flag::CSG_SHIFT) | stage::FULL_FEATURE;
        conn.feed(&bhs, &[]);
        assert_eq!(
            session.step(&mut conn, &mut work, &mut devs),
            StepResult::Processed
        );
        let (resp1, _) = conn.take_pdu().unwrap();
        assert_eq!(resp1[1] & 0x80, 0x80); // T=1
        assert_eq!((resp1[1] >> 2) & 0x03, stage::SECURITY);
        assert_eq!(resp1[1] & 0x03, stage::OP_PARAM);
        assert_eq!(session.stage(), LoginStage::OpParam);

        // Stage 2: CSG=1 (OpParam), T=1, NSG=3 → Full Feature.
        let mut bhs = [0u8; 48];
        bhs[0] = op::LOGIN_REQ | 0x40;
        bhs[1] = flag::T_BIT | ((stage::OP_PARAM & 0x03) << flag::CSG_SHIFT) | stage::FULL_FEATURE;
        bhs[15] = 0x01; // TSIH from stage 1 response
        conn.feed(&bhs, &[]);
        assert_eq!(
            session.step(&mut conn, &mut work, &mut devs),
            StepResult::Processed
        );
        let (resp2, _) = conn.take_pdu().unwrap();
        assert_eq!((resp2[1] >> 2) & 0x03, stage::OP_PARAM);
        assert_eq!(resp2[1] & 0x03, stage::FULL_FEATURE);
        assert_eq!(session.stage(), LoginStage::FullFeature);

        // A SCSI command now works (StatSN = 2 after two login responses).
        let cmd = read10_bhs(0, 1, 0x9999, 0);
        conn.feed(&cmd, &[]);
        assert_eq!(
            session.step(&mut conn, &mut work, &mut devs),
            StepResult::Processed
        );
        let (resp, _) = conn.take_pdu().unwrap();
        assert_eq!(resp[0] & 0x3F, op::SCSI_DATA_IN);
        assert_eq!(&resp[24..28], &be32(2)); // StatSN = 2
    }

    // ── READ(10): Data-In BufferOffset / DataSN continuity ─────────

    #[test]
    fn data_in_buffer_offset() {
        let mut conn = MockConn::new();
        let mut session = Session::default();
        let mut work = vec![0u8; MIN_WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let dev = BlockDevice::new(RamBackend::new(&mut ram), 512).unwrap();
        let mut devs = [dev];
        login(&mut conn, &mut session, &mut work, &mut devs);

        // Pre-fill the device with a known pattern (LBA 0..18).
        let pattern: Vec<u8> = (0..9216u32).map(|i| (i & 0xFF) as u8).collect();
        devs[0].write_data(0, &pattern).unwrap();

        // READ 18 blocks (9216 bytes) — crosses 2+ Data-In PDUs.
        let cmd = read10_bhs(0, 18, 0x12345678, 0);
        conn.feed(&cmd, &[]);
        assert_eq!(
            session.step(&mut conn, &mut work, &mut devs),
            StepResult::Processed
        );

        let mut count = 0;
        let mut expected_bo = 0u32;
        let mut expected_dsn = 0u32;
        while let Some((bhs, _data)) = conn.take_pdu() {
            if bhs[0] & 0x3F != op::SCSI_DATA_IN {
                continue;
            }
            let bo = u32::from_be_bytes([bhs[40], bhs[41], bhs[42], bhs[43]]);
            let dsn = u32::from_be_bytes([bhs[36], bhs[37], bhs[38], bhs[39]]);
            let dsl = (u32::from(bhs[5]) << 16) | (u32::from(bhs[6]) << 8) | u32::from(bhs[7]);
            assert_eq!(bo, expected_bo, "BufferOffset mismatch");
            assert_eq!(dsn, expected_dsn, "DataSN mismatch");
            if bhs[1] & flag::F_BIT != 0 {
                assert_ne!(bhs[1] & flag::S_BIT, 0, "final Data-In must have S bit");
                assert_eq!(&bhs[24..28], &be32(1)); // StatSN advanced
            }
            expected_bo += dsl;
            expected_dsn += 1;
            count += 1;
        }
        assert!(count >= 2, "expected >= 2 Data-In PDUs for 9216-byte read");
        assert_eq!(expected_bo, 9216);
    }

    // ── WRITE(10): immediate data → R2T → Data-Out → status ───────

    #[test]
    fn write_flow_r2t_and_response() {
        let mut conn = MockConn::new();
        let mut session = Session::default();
        let mut work = vec![0u8; MIN_WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let dev = BlockDevice::new(RamBackend::new(&mut ram), 512).unwrap();
        let mut devs = [dev];
        login(&mut conn, &mut session, &mut work, &mut devs);

        // WRITE 3 blocks at LBA 10 with only 512 bytes of immediate data.
        let itt = 0x7777_0001;
        let imm: Vec<u8> = (0..512u32).map(|i| (i & 0xFF) as u8).collect();
        let cmd = write10_bhs(10, 3, itt, 0, 512);
        conn.feed_padded(&cmd, &imm);

        // Pre-feed the solicited Data-Out (1024 bytes): one step consumes the
        // whole transaction (Command → R2T → Data-Out → Response).
        let out: Vec<u8> = (0x100..0x500u32).map(|i| (i & 0xFF) as u8).collect();
        let dout = dataout_bhs(itt, 1, 0, 512, 1024);
        conn.feed_padded(&dout, &out);
        assert_eq!(
            session.step(&mut conn, &mut work, &mut devs),
            StepResult::Processed
        );

        // R2T: remaining 1024 bytes.
        let (r2t, _) = conn.take_pdu().unwrap();
        assert_eq!(r2t[0] & 0x3F, op::R2T);
        assert_eq!(&r2t[16..20], &be32(itt));
        assert_eq!(&r2t[20..24], &be32(1)); // TTT
        assert_eq!(&r2t[40..44], &be32(512)); // BufferOffset
        assert_eq!(&r2t[44..48], &be32(1024)); // DesiredLen
        assert_eq!(&r2t[36..40], &be32(0)); // R2TSN

        // Final SCSI Response.
        let (resp, _) = conn.take_pdu().unwrap();
        assert_eq!(resp[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(resp[3], status::GOOD);
        assert_eq!(&resp[16..20], &be32(itt));
        assert_eq!(&resp[24..28], &be32(1)); // StatSN
        assert_eq!(&resp[28..32], &be32(1)); // ExpCmdSN = cmd_sn+1
        assert_eq!(&resp[32..36], &be32(1)); // MaxCmdSN

        // Verify backend content.
        let mut buf = [0u8; 1536];
        devs[0].read_data(10 * 512, &mut buf).unwrap();
        let mut expect = imm.clone();
        expect.extend_from_slice(&out);
        assert_eq!(&buf, expect.as_slice());
    }

    // ── Large write: multiple R2Ts bounded by MaxBurstLength ───────

    #[test]
    fn write_multi_r2t_bounded_by_max_burst() {
        let mut conn = MockConn::new();
        let mut session = Session::default();
        let mut work = vec![0u8; MIN_WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let dev = BlockDevice::new(RamBackend::new(&mut ram), 512).unwrap();
        let mut devs = [dev];
        login(&mut conn, &mut session, &mut work, &mut devs);

        // 600 blocks = 307200 bytes > MaxBurstLength (262144).
        let itt = 0xAAAA_0001;
        let imm = vec![0x5Au8; 8192];
        let cmd = write10_bhs(0, 600, itt, 0, 8192);
        conn.feed_padded(&cmd, &imm);

        // Feed the full Data-Out sequence up front: one step consumes the
        // whole transaction (Command → R2T1 → 32×Data-Out → R2T2 → Data-Out).
        let chunk = vec![0x6Bu8; 8192];
        let mut bo = 8192u32;
        for dsn in 0..32 {
            let dout = dataout_bhs(itt, 1, dsn, bo, 8192);
            conn.feed_padded(&dout, &chunk);
            bo += 8192;
        }
        let chunk2 = vec![0x7Cu8; 8192];
        for dsn in 0..(36864 / 8192) {
            let dout = dataout_bhs(itt, 1, dsn, bo, 8192);
            conn.feed_padded(&dout, &chunk2);
            bo += 8192;
        }
        let dout = dataout_bhs(itt, 1, 4, bo, 4096);
        conn.feed_padded(&dout, &vec![0x7Cu8; 4096]);

        assert_eq!(
            session.step(&mut conn, &mut work, &mut devs),
            StepResult::Processed
        );

        // R2T #1: BO after immediate, DesiredLen bounded by MaxBurstLength.
        let r2t1 = conn.take_pdu().unwrap().0;
        assert_eq!(r2t1[0] & 0x3F, op::R2T);
        assert_eq!(&r2t1[40..44], &be32(8192)); // BO after immediate
        assert_eq!(&r2t1[44..48], &be32(262144)); // DesiredLen ≤ MaxBurstLength

        // R2T #2 for the remainder.
        let r2t2 = conn.take_pdu().unwrap().0;
        assert_eq!(r2t2[0] & 0x3F, op::R2T);
        assert_eq!(&r2t2[40..44], &be32(8192 + 262144)); // BO
        assert_eq!(&r2t2[44..48], &be32(307200 - 8192 - 262144)); // 36864

        let (resp, _) = conn.take_pdu().unwrap();
        assert_eq!(resp[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(resp[3], status::GOOD);
    }

    // ── NOP-Out keepalive → NOP-In ─────────────────────────────────

    #[test]
    fn nop_in_echoes_ttt() {
        let mut conn = MockConn::new();
        let mut session = Session::default();
        let mut work = vec![0u8; MIN_WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let dev = BlockDevice::new(RamBackend::new(&mut ram), 512).unwrap();
        let mut devs = [dev];
        login(&mut conn, &mut session, &mut work, &mut devs);

        let mut nop = [0u8; 48];
        nop[0] = op::NOP_OUT;
        nop[16..20].copy_from_slice(&be32(0xABCD));
        nop[20..24].copy_from_slice(&be32(0xFFFF_FFFF));
        conn.feed(&nop, &[]);
        assert_eq!(
            session.step(&mut conn, &mut work, &mut devs),
            StepResult::Processed
        );

        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::NOP_IN);
        assert_eq!(&bhs[16..20], &be32(0xABCD));
        assert_eq!(&bhs[20..24], &be32(0xFFFF_FFFF));
    }

    // ── Invalid LUN → Reject 0x09 with the rejected header ─────────

    #[test]
    fn reject_invalid_lun() {
        let mut conn = MockConn::new();
        let mut session = Session::default();
        let mut work = vec![0u8; MIN_WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let dev = BlockDevice::new(RamBackend::new(&mut ram), 512).unwrap();
        let mut devs = [dev];
        login(&mut conn, &mut session, &mut work, &mut devs);

        let mut cmd = read10_bhs(0, 1, 0x1111, 0);
        cmd[9] = 5; // LUN out of range (only LUN 0 exists)
        conn.feed(&cmd, &[]);
        assert_eq!(
            session.step(&mut conn, &mut work, &mut devs),
            StepResult::Closed
        );

        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::REJECT);
        assert_eq!(bhs[2], reject::INVALID_PDU_FIELD);
        assert_eq!(&bhs[16..20], &[0xFF; 4]); // ITT = 0xffffffff (#18)
        assert_eq!(data, cmd.to_vec()); // rejected header in data segment (#18)
    }

    // ── Out-of-window non-immediate CmdSN → silently ignored ───────

    #[test]
    fn cmd_sn_out_of_window_ignored() {
        let mut conn = MockConn::new();
        let mut session = Session::default();
        let mut work = vec![0u8; MIN_WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let dev = BlockDevice::new(RamBackend::new(&mut ram), 512).unwrap();
        let mut devs = [dev];
        login(&mut conn, &mut session, &mut work, &mut devs);

        // CmdSN=5 while the next expected is 0 → silent ignore, no PDU.
        let cmd = read10_bhs(0, 1, 0x2222, 5);
        conn.feed(&cmd, &[]);
        assert_eq!(
            session.step(&mut conn, &mut work, &mut devs),
            StepResult::Idle
        );
        assert!(conn.take_pdu().is_none());

        // A correct CmdSN=0 command still executes afterwards.
        let cmd = read10_bhs(0, 1, 0x3333, 0);
        conn.feed(&cmd, &[]);
        assert_eq!(
            session.step(&mut conn, &mut work, &mut devs),
            StepResult::Processed
        );
        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);
    }

    // ── RFC §10.12.8: first FullFeature command reuses login CmdSN ──

    #[test]
    fn first_command_reuses_login_cmd_sn() {
        let mut conn = MockConn::new();
        let mut session = Session::default();
        let mut work = vec![0u8; MIN_WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let dev = BlockDevice::new(RamBackend::new(&mut ram), 512).unwrap();
        let mut devs = [dev];

        // Login carrying a non-zero CmdSN, as a real initiator would.
        let text = REQ_TEXT.as_bytes();
        let mut bhs = login_bhs(text.len() as u32);
        bhs[24..28].copy_from_slice(&be32(0x73dd_e21f));
        conn.feed_padded(&bhs, text);
        assert_eq!(
            session.step(&mut conn, &mut work, &mut devs),
            StepResult::Processed
        );
        let (resp, _) = conn.take_pdu().unwrap();
        assert_eq!(&resp[28..32], &be32(0x73dd_e21f)); // ExpCmdSN = login CmdSN
        assert_eq!(&resp[32..36], &be32(0x73dd_e21f)); // MaxCmdSN

        // The first command reuses the same CmdSN (not +1).
        let cmd = read10_bhs(0, 1, 0x9999, 0x73dd_e21f);
        conn.feed(&cmd, &[]);
        assert_eq!(
            session.step(&mut conn, &mut work, &mut devs),
            StepResult::Processed
        );
        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);

        // The second command advances to +1.
        let cmd = read10_bhs(0, 1, 0x999A, 0x73dd_e220);
        conn.feed(&cmd, &[]);
        assert_eq!(
            session.step(&mut conn, &mut work, &mut devs),
            StepResult::Processed
        );
    }

    // ── Immediate TMF (I=1) accepted out of window (#21) ───────────

    #[test]
    fn immediate_tmf_abort_task_complete() {
        let mut conn = MockConn::new();
        let mut session = Session::default();
        let mut work = vec![0u8; MIN_WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let dev = BlockDevice::new(RamBackend::new(&mut ram), 512).unwrap();
        let mut devs = [dev];
        login(&mut conn, &mut session, &mut work, &mut devs);

        let mut tmfr = [0u8; 48];
        tmfr[0] = op::SCSI_TASK_REQ | 0x40; // I bit
        tmfr[1] = 0x80;
        tmfr[2] = tmf::ABORT_TASK;
        tmfr[16..20].copy_from_slice(&be32(0x5555));
        tmfr[24..28].copy_from_slice(&be32(9)); // out of window, but I=1
        conn.feed(&tmfr, &[]);
        assert_eq!(
            session.step(&mut conn, &mut work, &mut devs),
            StepResult::Processed
        );

        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_TASK_RESP);
        assert_eq!(bhs[2], tmf_response::COMPLETE);
        assert_eq!(&bhs[24..28], &be32(1)); // StatSN
    }

    // ── Non-immediate TMF with bad CmdSN → silently ignored ────────

    #[test]
    fn tmf_bad_cmd_sn_ignored() {
        let mut conn = MockConn::new();
        let mut session = Session::default();
        let mut work = vec![0u8; MIN_WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let dev = BlockDevice::new(RamBackend::new(&mut ram), 512).unwrap();
        let mut devs = [dev];
        login(&mut conn, &mut session, &mut work, &mut devs);

        let mut tmfr = [0u8; 48];
        tmfr[0] = op::SCSI_TASK_REQ; // I=0
        tmfr[2] = tmf::LOGICAL_UNIT_RESET;
        tmfr[16..20].copy_from_slice(&be32(0x6666));
        tmfr[24..28].copy_from_slice(&be32(7)); // out of window, I=0 → ignore
        conn.feed(&tmfr, &[]);
        assert_eq!(
            session.step(&mut conn, &mut work, &mut devs),
            StepResult::Idle
        );
        assert!(conn.take_pdu().is_none());
    }

    // ── Logout → Logout Response → connection closed ───────────────

    #[test]
    fn logout_closes_connection() {
        let mut conn = MockConn::new();
        let mut session = Session::default();
        let mut work = vec![0u8; MIN_WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let dev = BlockDevice::new(RamBackend::new(&mut ram), 512).unwrap();
        let mut devs = [dev];
        login(&mut conn, &mut session, &mut work, &mut devs);

        let mut lo = [0u8; 48];
        lo[0] = op::LOGOUT_REQ;
        lo[16..20].copy_from_slice(&be32(0xCAFE));
        conn.feed(&lo, &[]);
        assert_eq!(
            session.step(&mut conn, &mut work, &mut devs),
            StepResult::Closed
        );

        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::LOGOUT_RESP);
        assert_eq!(&bhs[16..20], &be32(0xCAFE));
    }

    // ── Text Request → Reject 0x05 (command not supported) ─────────

    #[test]
    fn text_request_rejected() {
        let mut conn = MockConn::new();
        let mut session = Session::default();
        let mut work = vec![0u8; MIN_WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let dev = BlockDevice::new(RamBackend::new(&mut ram), 512).unwrap();
        let mut devs = [dev];
        login(&mut conn, &mut session, &mut work, &mut devs);

        let mut txt = [0u8; 48];
        txt[0] = op::TEXT_REQ;
        txt[16..20].copy_from_slice(&be32(0x1234));
        txt[24..28].copy_from_slice(&be32(1)); // CmdSN (Text uses the window)
        conn.feed(&txt, &[]);
        assert_eq!(
            session.step(&mut conn, &mut work, &mut devs),
            StepResult::Closed
        );

        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::REJECT);
        assert_eq!(bhs[2], reject::COMMAND_NOT_SUPPORTED);
    }

    // ── AHS defense: TotalAHSLength > 0 → Reject 0x04 ──────────────

    #[test]
    fn ahs_rejected() {
        let mut conn = MockConn::new();
        let mut session = Session::default();
        let mut work = vec![0u8; MIN_WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let dev = BlockDevice::new(RamBackend::new(&mut ram), 512).unwrap();
        let mut devs = [dev];
        login(&mut conn, &mut session, &mut work, &mut devs);

        let mut pdu = read10_bhs(0, 1, 0x7777, 0);
        pdu[4] = 1; // TotalAHSLength = 1 (4 bytes of AHS)
        conn.feed(&pdu, &[]);
        conn.feed_bytes(&[0u8; 4]); // the AHS bytes
        assert_eq!(
            session.step(&mut conn, &mut work, &mut devs),
            StepResult::Closed
        );

        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::REJECT);
        assert_eq!(bhs[2], reject::PROTOCOL_ERROR);
    }

    // ── WRITE fully covered by immediate data → GOOD, no R2T ───────

    #[test]
    fn write_all_immediate_no_r2t() {
        let mut conn = MockConn::new();
        let mut session = Session::default();
        let mut work = vec![0u8; MIN_WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let dev = BlockDevice::new(RamBackend::new(&mut ram), 512).unwrap();
        let mut devs = [dev];
        login(&mut conn, &mut session, &mut work, &mut devs);

        let itt = 0xBBBB_0001;
        let imm = vec![0x42u8; 512];
        let cmd = write10_bhs(0, 1, itt, 0, 512);
        conn.feed_padded(&cmd, &imm);
        assert_eq!(
            session.step(&mut conn, &mut work, &mut devs),
            StepResult::Processed
        );

        let (resp, _) = conn.take_pdu().unwrap();
        assert_eq!(resp[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(resp[3], status::GOOD);
        assert!(conn.take_pdu().is_none()); // no R2T
    }

    // ── Linux-kernel (open-iscsi) write flag layout (RFC 3720 §2.3.3) ──
    // The kernel sends byte 1 = F(0x80) | W(0x20) | ATTR (bits 0-2): 0xA1 for
    // a Simple write, 0xA0 for an untagged write. W is RFC 3720 bit 2 = 0x20
    // (bit 0 is the MSB per the Byte Rule) — the target must accept these
    // writes (regression: a prior fix checked 0x04 and Rejected them 0x04).

    #[test]
    fn linux_kernel_write_flag_layout_accepted() {
        let mut conn = MockConn::new();
        let mut session = Session::default();
        let mut work = vec![0u8; MIN_WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let dev = BlockDevice::new(RamBackend::new(&mut ram), 512).unwrap();
        let mut devs = [dev];
        login(&mut conn, &mut session, &mut work, &mut devs);

        // F(0x80) | W(0x20) | ATTR_SIMPLE(0x01) = 0xA1 — write10_bhs default.
        let itt = 0xA100_0001;
        let imm = vec![0x42u8; 512];
        let cmd = write10_bhs(0, 1, itt, 0, 512);
        conn.feed_padded(&cmd, &imm);
        assert_eq!(
            session.step(&mut conn, &mut work, &mut devs),
            StepResult::Processed
        );
        let (resp, _) = conn.take_pdu().unwrap();
        assert_eq!(resp[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(resp[3], status::GOOD);

        // F(0x80) | W(0x20), untagged (0x00) = 0xA0.
        let itt = 0xA100_0002;
        let mut cmd = write10_bhs(0, 1, itt, 1, 512);
        cmd[1] = 0xA0;
        conn.feed_padded(&cmd, &imm);
        assert_eq!(
            session.step(&mut conn, &mut work, &mut devs),
            StepResult::Processed
        );
        let (resp, _) = conn.take_pdu().unwrap();
        assert_eq!(resp[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(resp[3], status::GOOD);
    }

    // ── serve_conn blocking loop: login + logout → Ok ──────────────

    #[test]
    fn serve_conn_login_then_logout() {
        use snowscsi::serve_conn;

        let mut conn = MockConn::new();
        let mut session = Session::default();
        let mut work = vec![0u8; MIN_WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let dev = BlockDevice::new(RamBackend::new(&mut ram), 512).unwrap();
        let mut devs = [dev];

        let text = REQ_TEXT.as_bytes();
        conn.feed_padded(&login_bhs(text.len() as u32), text);
        let mut lo = [0u8; 48];
        lo[0] = op::LOGOUT_REQ;
        lo[16..20].copy_from_slice(&be32(1));
        conn.feed(&lo, &[]);

        assert!(serve_conn(&mut conn, &mut work, &mut session, &mut devs).is_ok());

        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::LOGIN_RESP);
        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::LOGOUT_RESP);
        assert!(conn.take_pdu().is_none());
    }

    // ── Multi-LUN REPORT LUNS (target-level) ────────────────────────
    // Regression: a single-LUN hardcoded response made the Linux client
    // discover only LUN 0 even when more `--block` specs were given.
    // The fix lives in the target layer (iscsi_target::handle_report_luns),
    // so REPORT LUNS no longer goes through any individual Device.

    fn report_luns_bhs(lun: u8, itt: u32, cmd_sn: u32) -> [u8; 48] {
        let mut bhs = [0u8; 48];
        bhs[0] = op::SCSI_CMD;
        bhs[16..20].copy_from_slice(&be32(itt));
        bhs[24..28].copy_from_slice(&be32(cmd_sn));
        bhs[28..32].copy_from_slice(&be32(cmd_sn));
        bhs[9] = lun; // BHS LUN — does not affect the LUN list
                      // CDB starts at BHS byte 32 (12 bytes for REPORT LUNS, group 5).
        bhs[32] = 0xA0; // REPORT LUNS opcode
                        // CDB bytes 6..10: allocation length (4 bytes BE). 0x0800 = 2048,
                        // comfortably above 4 + 8*256.
        bhs[38] = 0x08;
        bhs[39] = 0x00;
        bhs[40] = 0x00;
        bhs[41] = 0x00;
        bhs
    }

    #[test]
    fn report_luns_single_lun() {
        let mut conn = MockConn::new();
        let mut session = Session::default();
        let mut work = vec![0u8; MIN_WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024];
        let dev = BlockDevice::new(RamBackend::new(&mut ram), 512).unwrap();
        let mut devs = [dev];
        login(&mut conn, &mut session, &mut work, &mut devs);

        conn.feed(&report_luns_bhs(0, 0xA1, 0), &[]);
        assert_eq!(
            session.step(&mut conn, &mut work, &mut devs),
            StepResult::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);
        assert_eq!(
            bhs[1] & (flag::F_BIT | flag::S_BIT),
            flag::F_BIT | flag::S_BIT
        );
        assert_eq!(bhs[3], status::GOOD);
        assert_eq!(bhs[16..20], be32(0xA1)); // ITT echoed
                                             // Header: 4-byte LUN list length = 8.
        assert_eq!(&data[..4], &[0, 0, 0, 8]);
        // 4-byte reserved (zeros) per SPC-4 / Linux kernel layout.
        assert_eq!(&data[4..8], &[0, 0, 0, 0]);
        // One 8-byte LUN 0 entry.
        assert_eq!(&data[8..16], &[0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn report_luns_three_luns() {
        // Three independent ram-backed devices (LUN 0, 1, 2).
        let mut r0 = vec![0u8; 16 * 1024];
        let mut r1 = vec![0u8; 16 * 1024];
        let mut r2 = vec![0u8; 16 * 1024];
        let d0 = BlockDevice::new(RamBackend::new(&mut r0), 512).unwrap();
        let d1 = BlockDevice::new(RamBackend::new(&mut r1), 512).unwrap();
        let d2 = BlockDevice::new(RamBackend::new(&mut r2), 512).unwrap();
        let mut devs = [d0, d1, d2];

        let mut conn = MockConn::new();
        let mut session = Session::default();
        let mut work = vec![0u8; MIN_WORK_LEN];
        login(&mut conn, &mut session, &mut work, &mut devs);

        // REPORT LUNS to LUN 0 (BHS LUN irrelevant — the response is target-wide).
        conn.feed(&report_luns_bhs(0, 0xCAFE, 0), &[]);
        assert_eq!(
            session.step(&mut conn, &mut work, &mut devs),
            StepResult::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);
        assert_eq!(bhs[3], status::GOOD);
        assert_eq!(bhs[16..20], be32(0xCAFE));
        // Header: LUN list length = 3 * 8 = 24.
        assert_eq!(&data[..4], &[0, 0, 0, 24]);
        // 4-byte reserved.
        assert_eq!(&data[4..8], &[0, 0, 0, 0]);
        // Three 8-byte single-level peripheral-device LUN entries.
        for (i, expected) in [0u8, 1, 2].iter().enumerate() {
            let off = 8 + i * 8;
            assert_eq!(data[off], 0x00, "LUN {}: method/bus", i);
            assert_eq!(data[off + 1], *expected, "LUN {}: id", i);
            assert_eq!(&data[off + 2..off + 8], &[0u8; 6], "LUN {}: tail", i);
        }
    }

    // ── Linux kernel REPORT LUNS scanner compatibility ─────────────
    // Regression: the prior layout packed the first LUN entry at offset 4,
    // but Linux's `scsi_report_lun_scan` iterates `lun_data[1..=num_luns]`
    // (8-byte stride starting at offset 8). With the wrong layout, LUN 0
    // straddled lun_data[0] and lun_data[1], and `scsilun_to_int` decoded
    // the LUN 0 / LUN 1 boundary as 2^32, which then exceeded the HBA's
    // `max_lun` and produced:
    //   sd 0:0:0:0: lun4294967296 has a LUN larger than allowed ...
    // (only LUN 0 was visible to the Linux initiator). This test mirrors
    // the kernel's `scsilun_to_int` byte ordering and checks every entry.

    fn kernel_scsilun_to_int(s: &[u8; 8]) -> u64 {
        let mut lun: u64 = 0;
        for i in (0..8).step_by(2) {
            lun |=
                (u64::from(s[i]) << ((i as u64 + 1) * 8)) | (u64::from(s[i + 1]) << (i as u64 * 8));
        }
        lun
    }

    #[test]
    fn report_luns_kernel_scsilun_to_int_alignment() {
        let mut r0 = vec![0u8; 16 * 1024];
        let mut r1 = vec![0u8; 16 * 1024];
        let mut r2 = vec![0u8; 16 * 1024];
        let d0 = BlockDevice::new(RamBackend::new(&mut r0), 512).unwrap();
        let d1 = BlockDevice::new(RamBackend::new(&mut r1), 512).unwrap();
        let d2 = BlockDevice::new(RamBackend::new(&mut r2), 512).unwrap();
        let mut devs = [d0, d1, d2];

        let mut conn = MockConn::new();
        let mut session = Session::default();
        let mut work = vec![0u8; MIN_WORK_LEN];
        login(&mut conn, &mut session, &mut work, &mut devs);

        conn.feed(&report_luns_bhs(0, 0xBEEF, 0), &[]);
        session.step(&mut conn, &mut work, &mut devs);
        let (_, data) = conn.take_pdu().unwrap();

        // Replay the kernel's parse loop (drivers/scsi/scsi_scan.c):
        //   num_luns = be32(lun_list_length) / 8;
        //   for (lunp = &lun_data[1]; lunp <= &lun_data[num_luns]; lunp++) {
        //     lun = scsilun_to_int(lunp);
        let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let num_luns = length as usize / 8;
        assert_eq!(num_luns, 3, "LUN list length should be 3*8");
        for i in 1..=num_luns {
            let off = i * 8;
            let mut entry = [0u8; 8];
            entry.copy_from_slice(&data[off..off + 8]);
            let lun = kernel_scsilun_to_int(&entry);
            assert_eq!(
                lun,
                i as u64 - 1,
                "lun_data[{i}] must decode to LUN {}",
                i - 1
            );
        }
    }

    #[test]
    fn report_luns_three_luns_requested_at_lun_1() {
        // Same as above but the initiator sent REPORT LUNS to LUN 1 — the
        // target must still list all three LUNs, not just the LUN 1 entry.
        let mut r0 = vec![0u8; 16 * 1024];
        let mut r1 = vec![0u8; 16 * 1024];
        let mut r2 = vec![0u8; 16 * 1024];
        let d0 = BlockDevice::new(RamBackend::new(&mut r0), 512).unwrap();
        let d1 = BlockDevice::new(RamBackend::new(&mut r1), 512).unwrap();
        let d2 = BlockDevice::new(RamBackend::new(&mut r2), 512).unwrap();
        let mut devs = [d0, d1, d2];

        let mut conn = MockConn::new();
        let mut session = Session::default();
        let mut work = vec![0u8; MIN_WORK_LEN];
        login(&mut conn, &mut session, &mut work, &mut devs);

        conn.feed(&report_luns_bhs(1, 0xCAFE, 0), &[]);
        assert_eq!(
            session.step(&mut conn, &mut work, &mut devs),
            StepResult::Processed
        );
        let (_, data) = conn.take_pdu().unwrap();
        assert_eq!(&data[..4], &[0, 0, 0, 24]);
        // The single-level LUN id bytes — must include 0, 1, 2.
        let ids: Vec<u8> = (0..3).map(|i| data[8 + i * 8 + 1]).collect();
        assert_eq!(ids, vec![0, 1, 2]);
    }

    #[test]
    fn report_luns_rejects_out_of_range_lun() {
        // The LUN-validity check happens before the REPORT LUNS intercept,
        // so an out-of-range LUN in the BHS still gets Rejected.
        let mut ram = vec![0u8; 16 * 1024];
        let dev = BlockDevice::new(RamBackend::new(&mut ram), 512).unwrap();
        let mut devs = [dev];

        let mut conn = MockConn::new();
        let mut session = Session::default();
        let mut work = vec![0u8; MIN_WORK_LEN];
        login(&mut conn, &mut session, &mut work, &mut devs);

        let mut cmd = report_luns_bhs(5, 0xDEAD, 0); // LUN 5 doesn't exist
        cmd[9] = 5;
        conn.feed(&cmd, &[]);
        assert_eq!(
            session.step(&mut conn, &mut work, &mut devs),
            StepResult::Closed
        );
        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::REJECT);
        assert_eq!(bhs[2], reject::INVALID_PDU_FIELD);
    }
}
