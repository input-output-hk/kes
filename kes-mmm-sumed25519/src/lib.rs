//! A key evolving signatures implementation.
//!
//! "Composition and Efficiency Tradeoffs for Forward-Secure Digital Signatures"
//! By Tal Malkin, Daniele Micciancio and Sara Miner
//! <https://eprint.iacr.org/2001/034>
//!
#![warn(missing_docs, rust_2018_idioms)]

mod common;
#[macro_use]
pub mod single_kes;
mod errors;
pub mod kes;
pub mod traits;

/// Module to handle version environment variables.
pub mod version {
    /// Return the environment variable `FULL_VERSION`.
    pub const FULL: &str = env!("FULL_VERSION");
    /// Return the environment variable `SIMPLE_VERSION`.
    pub const SIMPLE: &str = env!("SIMPLE_VERSION");
    /// Return the environment variable `SOURCE_VERSION`.
    pub const SOURCE: &str = env!("SOURCE_VERSION");
    /// Return the environment variable `CARGO_PKG_VERSION`.
    pub const PKG: &str = env!("CARGO_PKG_VERSION");
}
