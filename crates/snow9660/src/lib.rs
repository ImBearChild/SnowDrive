#![no_std]
#![forbid(unsafe_code)]
//! ISO9660 + Joliet filesystem library (Phase 1 stub).

pub mod live;

/// Library version (SemVer), like `snow9660_version()` in the C stub.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the library version string.
pub fn version() -> &'static str {
    VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_not_null() {
        assert!(!version().is_empty());
    }

    #[test]
    fn version_format() {
        assert!(version().contains('.'));
    }

    #[test]
    fn version_const_matches_fn() {
        assert_eq!(version(), VERSION);
    }
}
