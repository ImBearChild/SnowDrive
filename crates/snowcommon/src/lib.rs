#![no_std]
#![forbid(unsafe_code)]
//! Unified logging macros for SnowDrive.
//!
//! [`trace!`], [`debug!`], [`info!`], [`warn!`], [`error!`] are unified
//! macros that dispatch to either the [`log`] crate or [`defmt`],
//! depending on which Cargo feature is enabled.  The two features are
//! mutually exclusive.
//!
//! - `log` feature  — dispatch to `::log::info!()` etc.
//! - `defmt` feature — dispatch to `::defmt::info!()` etc.
//! - (neither)      — every call is compiled to a no-op.
//!
//! The design follows the Embassy pattern: the library never chooses a
//! backend; the final binary enables the feature it wants.  Capturing
//! or routing log output is the caller's responsibility (e.g. an upper
//! layer implements `log::Log` or provides a `defmt` logger).

#[cfg(all(feature = "log", feature = "defmt"))]
compile_error!("You may not enable both `log` and `defmt` features.");

#[macro_export]
macro_rules! trace {
    ($s:literal $(, $x:expr)* $(,)?) => {{
        #[cfg(feature = "log")]
        ::log::trace!($s $(, $x)*);
        #[cfg(feature = "defmt")]
        ::defmt::trace!($s $(, $x)*);
        #[cfg(not(any(feature = "log", feature = "defmt")))]
        let _ = ($( & $x ),*);
    }};
}

#[macro_export]
macro_rules! debug {
    ($s:literal $(, $x:expr)* $(,)?) => {{
        #[cfg(feature = "log")]
        ::log::debug!($s $(, $x)*);
        #[cfg(feature = "defmt")]
        ::defmt::debug!($s $(, $x)*);
        #[cfg(not(any(feature = "log", feature = "defmt")))]
        let _ = ($( & $x ),*);
    }};
}

#[macro_export]
macro_rules! info {
    ($s:literal $(, $x:expr)* $(,)?) => {{
        #[cfg(feature = "log")]
        ::log::info!($s $(, $x)*);
        #[cfg(feature = "defmt")]
        ::defmt::info!($s $(, $x)*);
        #[cfg(not(any(feature = "log", feature = "defmt")))]
        let _ = ($( & $x ),*);
    }};
}

#[macro_export]
macro_rules! warn {
    ($s:literal $(, $x:expr)* $(,)?) => {{
        #[cfg(feature = "log")]
        ::log::warn!($s $(, $x)*);
        #[cfg(feature = "defmt")]
        ::defmt::warn!($s $(, $x)*);
        #[cfg(not(any(feature = "log", feature = "defmt")))]
        let _ = ($( & $x ),*);
    }};
}

#[macro_export]
macro_rules! error {
    ($s:literal $(, $x:expr)* $(,)?) => {{
        #[cfg(feature = "log")]
        ::log::error!($s $(, $x)*);
        #[cfg(feature = "defmt")]
        ::defmt::error!($s $(, $x)*);
        #[cfg(not(any(feature = "log", feature = "defmt")))]
        let _ = ($( & $x ),*);
    }};
}

#[cfg(test)]
mod tests {
    /// When neither `log` nor `defmt` is enabled, macros are no-ops.
    #[cfg(not(any(feature = "log", feature = "defmt")))]
    #[test]
    fn macros_noop_without_feature() {
        info!("hello");
        warn!("hello");
        error!("hello");
        debug!("hello");
        trace!("hello");
    }

    /// When neither feature is enabled, macros with format args are
    /// still no-ops (no unused-variable warnings).
    #[cfg(not(any(feature = "log", feature = "defmt")))]
    #[test]
    fn macros_noop_with_args() {
        let x = 42;
        let y = "foo";
        info!("x={} y={}", x, y);
        debug!("x={}", x);
    }

    /// With `log` enabled, macros compile and dispatch (actual dispatch
    /// validated by downstream integration tests with a real logger).
    #[cfg(feature = "log")]
    #[test]
    fn macros_compile_with_log() {
        let x = 42;
        info!("hello");
        warn!("world");
        error!("CmdSN={}", x);
        debug!("debug={}", x);
        trace!("trace");
    }
}
