#![no_std]
#![forbid(unsafe_code)]
#![doc = "Zero-alloc logging and hex formatting for SnowDrive."]
#![doc = ""]
#![doc = "- `log!(level, ...)` / `hexdump!(level, buf)` macros write to caller-provided buffer"]
#![doc = "- Compile-time level gating via `cfg!(feature = \"log_trace\")` etc."]
#![doc = "- `fmt` feature enables `core::fmt::Write` on `LogBuf` for structured output"]

pub struct LogBuf<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> LogBuf<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub const fn version() -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.pos]).unwrap_or("")
    }

    pub fn clear(&mut self) {
        self.pos = 0;
    }
}

impl<'a> core::fmt::Write for LogBuf<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let remaining = self.buf.len() - self.pos;
        let to_write = bytes.len().min(remaining);
        self.buf[self.pos..self.pos + to_write].copy_from_slice(&bytes[..to_write]);
        self.pos += to_write;
        Ok(())
    }
}
