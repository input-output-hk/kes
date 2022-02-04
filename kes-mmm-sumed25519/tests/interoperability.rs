//! Tests to check for interoperability with Haskell function. To generate the
//! test data, available in ./data, we ran the following script using the `cardano-base`
//! implementation. Run the same code with `SumXCompactKES` to generate the data of
//! the compact version.
//!
//! ```haskell
//! import Cardano.Crypto.Seed
//! import Cardano.Crypto.DSIGN
//! import Cardano.Crypto.Hash
//! import Cardano.Crypto.KES
//!
//! import Data.Maybe (fromJust)
//! import qualified Data.ByteString.Char8 as Bytechar
//! import qualified Data.ByteString as B
//!
//!
//! main :: IO()
//! main = let
//!     seed = mkSeedFromBytes $ Bytechar.pack "test string of 32 byte of lenght"
//!     kesSk0 = genKeyKES @(Sum0KES Ed25519DSIGN) seed
//!     kesSk1 = genKeyKES @(Sum1KES Ed25519DSIGN Blake2b_256) seed
//!     kesSk =  genKeyKES @(Sum6KES Ed25519DSIGN Blake2b_256) seed
//!     kesSignature = signKES () 0 (Bytechar.pack "test message") kesSk
//!     kesSkOneUpdate = fromJust (updateKES () kesSk 0)
//!     kesSkTwoUpdate = fromJust (updateKES () kesSkOneUpdate 1)
//!     kesSkThreeUpdate = fromJust (updateKES () kesSkTwoUpdate 2)
//!     kesSkFourUpdate = fromJust (updateKES () kesSkThreeUpdate 3)
//!     kesSkFiveUpdate = fromJust (updateKES () kesSkFourUpdate 4)
//!     kesSignatureFive = signKES () 5 (Bytechar.pack "test message") kesSkFiveUpdate
//!     
//!     in do
//!         B.writeFile "<PATH>/key0.bin" (rawSerialiseSignKeyKES kesSk0)
//!         B.writeFile "<PATH>/key1.bin" (rawSerialiseSignKeyKES kesSk1)
//!         B.writeFile "<PATH>/key6.bin" (rawSerialiseSignKeyKES kesSk)
//!         B.writeFile "<PATH>/key6Sig.bin" (rawSerialiseSigKES kesSignature)
//!         B.writeFile "<PATH>/key6update1.bin" (rawSerialiseSignKeyKES kesSkOneUpdate)
//!         B.writeFile "<PATH>/key6update5.bin" (rawSerialiseSignKeyKES kesSkFiveUpdate)
//!         B.writeFile "<PATH>/key6Sig5.bin" (rawSerialiseSigKES kesSignatureFive)
//! ```
//!
use kes_mmm_sumed25519::erasable_buffer::*;
use kes_mmm_sumed25519::single_kes::Sum0Kes;
use kes_mmm_sumed25519::compact_kes::{Sum6CompactKes, Sum1CompactKes};
use kes_mmm_sumed25519::compact_single_kes::Sum0CompactKes;
use kes_mmm_sumed25519::traits::KesSk;

#[test]
fn haskel_depth_1() {
    // haskell generated key
    let h_key: &[u8; 128] = include_bytes!("data/key1.bin");

    let seed = b"test string of 32 byte of lenght";
    let (skey, _) = Sum1Kes::keygen(&mut seed.to_owned());

    assert_eq!(skey.as_bytes(), h_key);
}

#[test]
fn haskell_depth_6() {
    let h_key: &[u8; 608] = include_bytes!("data/key6.bin");

    let seed = b"test string of 32 byte of lenght";
    let (mut skey, _) = Sum6Kes::keygen(&mut seed.to_owned());
    assert_eq!(skey.as_bytes(), h_key);

    let h_1update_key: &[u8; 608] = include_bytes!("data/key6update1.bin");
    skey.update(0).unwrap();
    assert_eq!(skey.as_bytes(), h_1update_key);
}

#[test]
fn haskell_single() {
    let h_key: &[u8; 32] = include_bytes!("data/key0.bin");

    let seed = b"test string of 32 byte of lenght";
    let (skey, _) = Sum0Kes::keygen(&mut seed.to_owned());
    assert_eq!(skey.as_bytes(), h_key);
}

#[test]
fn haskell_signature_6() {
    // haskell generated signature
    let h_signature: &[u8; 448] = include_bytes!("data/key6Sig.bin");

    let seed = b"test string of 32 byte of lenght";
    let message = b"test message";
    let (skey, _) = Sum6Kes::keygen(&mut seed.to_owned());
    let signature = skey.sign(0, message);
    assert_eq!(&signature.to_bytes(), h_signature);
}

#[test]
fn haskell_signature_6_update_5() {
    let h_key: &[u8; 608] = include_bytes!("data/key6update5.bin");
    let h_signature: &[u8; 448] = include_bytes!("data/key6Sig5.bin");

    let seed = b"test string of 32 byte of lenght";
    let message = b"test message";
    let (mut skey, _) = Sum6Kes::keygen(&mut seed.to_owned());
    skey.update(0).unwrap();
    skey.update(1).unwrap();
    skey.update(2).unwrap();
    skey.update(3).unwrap();
    skey.update(4).unwrap();
    assert_eq!(skey.as_bytes(), h_key);

    let signature = skey.sign(5, message);
    assert_eq!(&signature.to_bytes(), h_signature);
}

#[test]
fn haskel_compact_depth_1() {
    // haskell generated key
    let h_key: &[u8; 128] = include_bytes!("data/compactkey1.bin");

    let seed = b"test string of 32 byte of lenght";
    let (skey, _) = Sum1CompactKes::keygen(&mut seed.to_owned());

    assert_eq!(skey.as_bytes(), h_key);
}

#[test]
fn haskell_compact_depth_6() {
    let h_key: &[u8; 608] = include_bytes!("data/compactkey6.bin");

    let seed = b"test string of 32 byte of lenght";
    let (mut skey, _) = Sum6CompactKes::keygen(&mut seed.to_owned());
    assert_eq!(skey.as_bytes(), h_key);

    let h_1update_key: &[u8; 608] = include_bytes!("data/compactkey6update1.bin");
    skey.update(0).unwrap();
    assert_eq!(skey.as_bytes(), h_1update_key);
}

#[test]
fn haskell_compact_single() {
    let h_key: &[u8; 32] = include_bytes!("data/compactkey0.bin");

    let seed = b"test string of 32 byte of lenght";
    let (skey, _) = Sum0CompactKes::keygen(&mut seed.to_owned());
    assert_eq!(skey.as_bytes(), h_key);
}

#[test]
fn haskell_compact_signature_6() {
    // haskell generated signature
    let h_signature: &[u8; 288] = include_bytes!("data/compactkey6Sig.bin");

    let seed = b"test string of 32 byte of lenght";
    let message = b"test message";
    let (skey, _) = Sum6CompactKes::keygen(&mut seed.to_owned());
    let signature = skey.sign(0, message);
    assert_eq!(&signature.to_bytes(), h_signature);
}

#[test]
fn haskell_compact_signature_6_update_5() {
    let h_key: &[u8; 608] = include_bytes!("data/compactkey6update5.bin");
    let h_signature: &[u8; 288] = include_bytes!("data/compactkey6Sig5.bin");

    let seed = b"test string of 32 byte of lenght";
    let message = b"test message";
    let (mut skey, _) = Sum6CompactKes::keygen(&mut seed.to_owned());
    skey.update(0).unwrap();
    skey.update(1).unwrap();
    skey.update(2).unwrap();
    skey.update(3).unwrap();
    skey.update(4).unwrap();
    assert_eq!(skey.as_bytes(), h_key);

    let signature = skey.sign(5, message);
    assert_eq!(&signature.to_bytes(), h_signature);
}
