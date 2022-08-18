#![warn(missing_docs, rust_2018_idioms)]
//! A key evolving signatures implementation based on
//! "Composition and Efficiency Tradeoffs for Forward-Secure Digital Signatures"
//! by Tal Malkin, Daniele Micciancio and Sara Miner
//! <https://eprint.iacr.org/2001/034>
//!
//! Specfically we do the binary sum composition directly as in the paper, and
//! then use that in a nested\/recursive fashion to construct a 7-level deep
//! binary tree version.
//!
//! This relies on "Cardano.Crypto.KES.CompactSingle" for the base case.
//!
//! Compared to the implementation in 'Cardano.Crypto.KES.Sum', this flavor
//! stores only one VerKey in the branch node.
//!
//! Consider the following Merkle tree:
//!
//! ```ascii
//!       (A)
//!      /   \
//!   (B)     (C)
//!   / \     / \
//! (D) (E) (F) (G)
//!      ^
//!  0   1   2   3
//! ```
//!
//! The caret points at leaf node E, indicating that the current period is 1.
//! The signatures for leaf nodes D through G all contain their respective
//! DSIGN keys; the signature for branch node B however only holds the signature
//! for node E, and the VerKey for node D. It can reconstruct its own VerKey
//! from these two. The signature for branch node A (the root node), then, only
//! contains the VerKey for node C, and the signature for node B. In other
//! words, the number of individual hashes to be stored equals the depth of the
//! Merkle tree. Compare that to the older, naive 'SumKES', where each branch
//! node stores two VerKeys: here, the number of keys to store is the depth of
//! the tree times two.
//!
//! Note that when we verify such a signature, we need to also compare the
//! ultimate VerKey at the root against the one passed in externally, because
//! all VerKeys until that point have been derived from the (user-supplied, so
//! untrusted) signature. But we only need to do this once, at the tree root,
//! so we split up the verification into two parts: verifying a signature
//! against its embedded VerKey, and comparing that VerKey against the
//! externally supplied target key.

mod common;
#[macro_use]
mod single_kes;
mod errors;
pub mod kes;
pub mod traits;
