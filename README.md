# Key Evolving Signatures ![CI workflow](https://github.com/input-output-hk/kes/actions/workflows/ci.yml/badge.svg) ![crates.io](https://img.shields.io/crates/v/kes-summed-ed25519.svg)


This crate is ongoing work, and has not been audited. Do not use in production.

## Rust implementation of KES
`kes-sumed-ed25519` is a pure rust implementation of Key Evolving Signatures, following the paper 
from ["Composition and Efficiency Tradeoffs for Forward-Secure Digital Signatures"](https://eprint.iacr.org/2001/034)
by Malkin, Micciancio and Miner. In particular, we implement the "sum" composition, from Section
3.1. As a depth zero signature algorithm we use Ed25519 using the `strict` verification criteria from
[`ed25519_dalek`](https://github.com/dalek-cryptography/ed25519-dalek), which is the same as currently
used in [libsodium](https://github.com/jedisct1/libsodium). 

This library defines macros to generate KES algorithms with different depths. We currently expose KES
algorithms up to depth 7. 

## Library usage
This library exposes `SumXKes` for `X` in [0,7]. A KES algorithm with depth `X` can evolve the key 
`2^X`. When a secret key is evolved, the old seed is overwritten with zeroes. 

```rust
use kes_summed_ed25519::kes::Sum6Kes;
use kes_summed_ed25519::traits::{KesSig, KesSk};

fn main() {
    let (mut skey, pkey) = Sum6Kes::keygen(&mut [0u8; 32]);
    let dummy_message = b"tilin";
    let sigma = skey.sign(0, dummy_message);

    assert!(sigma.verify(0, &pkey, dummy_message).is_ok());

    // Key can be updated 63 times                         
    for i in 0..63 {
        assert!(skey.update(i).is_ok());
    }
}                                                          
```

## Compatibility with Cardano
We provide two implementations of KES for compatibility with Cardano's blockchain. Cardano currently
uses `Sum6Kes`. However, that implementation is not optimal in what concerns signature size. Instead,
we provide implementation of `SumCompact6Kes`, which provides an asymptotic halving of the signature
size. We provide test vectors generated using Cardano's code to ensure that future changes in the
library will not lose compatibility with Cardano. These test vectors can be found in `./tests/data`, 
and the tests can be found in `./tests/interoperability.rs`.

## Previous versions of the code
This repo is a copy and modification of 
[kes-mmm-sumed25519](https://github.com/input-output-hk/kes-mmm-sumed25519). The old repo
remains unchanged for historical purposes. 
