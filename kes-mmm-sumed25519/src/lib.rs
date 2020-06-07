//! realization of ouroboros-KES
#![cfg_attr(feature = "with-bench", feature(test))]

#[cfg(test)]
#[cfg(feature = "with-bench")]
extern crate test;

#[cfg(test)]
extern crate quickcheck;
#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

mod common;
pub mod sumed25519;

pub mod version {
    pub const FULL: &str = env!("FULL_VERSION");
    pub const SIMPLE: &str = env!("SIMPLE_VERSION");
    pub const SOURCE: &str = env!("SOURCE_VERSION");
    pub const PKG: &str = env!("CARGO_PKG_VERSION");
}

#[cfg(test)]
mod sumrec;
