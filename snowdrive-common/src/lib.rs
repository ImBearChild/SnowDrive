//! SnowDrive common: zero-alloc storage seams + unified logging macros.
//!
//! Always available — no feature gate on this crate.

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![deny(unsafe_code)]

pub mod block_storage;
pub mod fs_storage;
pub mod logging;
