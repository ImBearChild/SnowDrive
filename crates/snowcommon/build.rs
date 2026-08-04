//! Build script: emits a compile-time warning when logging is compiled out.
//!
//! When neither the `log` nor `defmt` feature is enabled, the unified
//! logging macros become no-ops.  This script prints a one-time reminder
//! during compilation so the developer does not silently lose logs.

fn main() {
    let log = std::env::var("CARGO_FEATURE_LOG").is_ok();
    let defmt = std::env::var("CARGO_FEATURE_DEFMT").is_ok();
    if !log && !defmt {
        println!(
            "cargo:warning=snowcommon: neither the `log` nor `defmt` feature is enabled; \
             logging macros compile to no-ops. Enable one of them in the final binary, e.g. \
             snowcommon = {{ features = [\"log\"] }}"
        );
    }
}
