//! SnowDrive disc: ISO9660/Joliet live-generation algorithms.

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![deny(unsafe_code)]

pub mod live;
