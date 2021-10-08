//! Tests to check for interoperability with Haskell function. To generate the
//! test data, we ran the following script using the `cardano-base` implementation.
//!
//! To generate the data, available in ./data, we ran the following haskell script
//! for different depths, in particular depth 1 and depth 6.
//!
//! ```haskell
//! import Cardano.Crypto.Seed
//! import Cardano.Crypto.DSIGN
//! import Cardano.Crypto.Hash
//! import Cardano.Crypto.KES(Sum1KES, genKeyKES, rawSerialiseSignKeyKES)
//!
//! import qualified Data.ByteString.Char8 as Bytechar
//! import qualified Data.ByteString as B
//!
//!
//! main :: IO()
//! main = let
//!   seed = mkSeedFromBytes $ Bytechar.pack "test string of 32 byte of lenght"
//!   kesInstance =  genKeyKES @(Sum1KES Ed25519DSIGN Blake2b_256) seed
//!   in do
//!     B.writeFile "/Users/queremendi/iohk/CryptoLibs/kes-mmm-sumed25519/kes-mmm-sumed25519/tests/key1.bin" (rawSerialiseSignKeyKES kesInstance)
//! ```
//!
use kes_mmm_sumed25519::erasable_buffer::{Sum1Kes, Sum6Kes};
use kes_mmm_sumed25519::single_kes::Sum0Kes;
use kes_mmm_sumed25519::traits::KesSk;

#[test]
fn haskel_depth_1() {
    let a: &[u8; 128] = include_bytes!("data/key1.bin");

    let seed = b"test string of 32 byte of lenght";
    let (skey, _) = Sum1Kes::keygen_kes(&mut seed.to_owned());
    assert_eq!(skey.as_bytes(), a);
}

#[test]
fn haskell_depth_6() {
    let a: &[u8; 608] = include_bytes!("data/key6.bin");

    let seed = b"test string of 32 byte of lenght";
    let (skey, _) = Sum6Kes::keygen_kes(&mut seed.to_owned());
    assert_eq!(skey.as_bytes(), a);
}

#[test]
pub fn haskell_single() {
    let a: &[u8; 32] = include_bytes!("data/key0.bin");

    let seed = b"test string of 32 byte of lenght";
    let (skey, _) = Sum0Kes::keygen_kes(&mut seed.to_owned());
    let skey_bytes = skey.as_bytes();
    assert_eq!(skey_bytes, a);
}
