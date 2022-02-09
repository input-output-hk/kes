//! A key evolving signatures implementation.
//!
//! "Composition and Efficiency Tradeoffs for Forward-Secure Digital Signatures"
//! By Tal Malkin, Daniele Micciancio and Sara Miner
//! <https://eprint.iacr.org/2001/034>
//!
#![warn(missing_docs, rust_2018_idioms)]

mod common;
#[macro_use]
mod single_kes;
mod errors;
pub mod kes;
pub mod traits;
