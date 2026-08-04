#![no_std]
#![doc = "C ABI bindings for snowscsi."]
#![doc = ""]
#![doc = "Provides opaque handle wrappers and C-style mirror API over"]
#![doc = "the borrow-based snowscsi core. Unsafe code is confined to"]
#![doc = "this crate for raw pointer ↔ reference transmutation."]

pub fn version() -> &'static str {
    snowscsi::version()
}
