#[allow(dead_code)]
mod tests {
    use snowscsi_mock::MockConn;

    #[test]
    fn test_mock_conn_roundtrip() {
        let mut conn = MockConn::new();
        conn.feed(&[0x00u8; 48], b"hello");
        let mut buf = [0u8; 100];
        let n = embedded_io::Read::read(&mut conn, &mut buf).unwrap();
        assert!(n >= 48);
    }
}
