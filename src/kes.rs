//! This module contains the macros to build the KES algorithms.
//! Tentative at making a recursive, and smaller code, which builds a key formed
//! by an array, allowing for a more granular memory management when calling the function.
//! The goal is to provide a similar construction to what is achieved in [sumed25519](./../sumed25519)
//! while maintaining code simplicity, and a smaller crate to facilitate audit and maintenance.

use crate::common::{Depth, Seed};
use crate::common::{PublicKey, INDIVIDUAL_SECRET_SIZE, PUBLIC_KEY_SIZE, SIGMA_SIZE};
use crate::errors::Error;
use crate::single_kes::{Sum0CompactKes, Sum0CompactKesSig, Sum0Kes, Sum0KesSig};
use crate::traits::{KesCompactSig, KesSig, KesSk};
use std::cmp::Ordering;
use zeroize::Zeroize;

#[cfg(feature = "serde_enabled")]
use {
    serde::{Deserialize, Serialize},
};

macro_rules! sum_kes {
    ($name:ident, $signame:ident, $sk:ident, $sigma:ident, $depth:expr, $doc:expr) => {
        #[derive(Debug, Zeroize)]
        #[zeroize(drop)]
        #[doc=$doc]
        pub struct $name(
            [u8; 4 + INDIVIDUAL_SECRET_SIZE + $depth * 32 + $depth * (PUBLIC_KEY_SIZE * 2)],
        );

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[cfg_attr(feature = "serde_enabled", derive(Serialize, Deserialize))]
        /// Structure that represents a KES signature.
        pub struct $signame {
            sigma: $sigma,
            lhs_pk: PublicKey,
            rhs_pk: PublicKey,
        }

        // First we implement the KES traits.
        impl KesSk for $name {
            type Sig = $signame;

            /// Function that takes a mutable seed, and generates the key pair. It overwrites
            /// the seed with zeroes.
            fn keygen(master_seed: &mut [u8]) -> (Self, PublicKey) {
                assert_eq!(
                    master_seed.len(),
                    Seed::SIZE,
                    "Size of the seed is incorrect."
                );
                let mut data = [0u8; Self::SIZE + 4];
                let (mut r0, mut seed) = Seed::split_slice(master_seed);
                // We copy the seed before overwriting with zeros (in the `keygen` call).
                data[$sk::SIZE..$sk::SIZE + 32].copy_from_slice(&seed);

                let (sk_0, pk_0) = $sk::keygen(&mut r0);
                let (_, pk_1) = $sk::keygen(&mut seed);

                let pk = pk_0.hash_pair(&pk_1);

                // We write the keys to the main data.
                data[..$sk::SIZE].copy_from_slice(&sk_0.0[..$sk::SIZE]);
                data[$sk::SIZE + 32..$sk::SIZE + 64].copy_from_slice(&pk_0.as_bytes());
                data[$sk::SIZE + 64..$sk::SIZE + 96].copy_from_slice(&pk_1.as_bytes());

                // We write the period the the main data.
                data[Self::SIZE..].copy_from_slice(&0u32.to_be_bytes());

                (Self(data), pk)
            }

            fn sign(&self, m: &[u8]) -> Self::Sig {
                let sk =
                    $sk::skey_from_bytes(&self.as_bytes()[..$sk::SIZE]).expect("Invalid key bytes");
                let sigma = sk.sign(m);

                let lhs_pk =
                    PublicKey::from_bytes(&self.as_bytes()[$sk::SIZE + 32..$sk::SIZE + 64])
                        .expect("Won't fail as slice has size 32");
                let rhs_pk =
                    PublicKey::from_bytes(&self.as_bytes()[$sk::SIZE + 64..$sk::SIZE + 96])
                        .expect("Won't fail as slice has size 32");
                $signame {
                    sigma,
                    lhs_pk,
                    rhs_pk,
                }
            }

            fn update(&mut self) -> Result<(), Error> {
                let mut u32_bytes = [0u8; 4];
                u32_bytes.copy_from_slice(&self.0[Self::SIZE..]);
                let period = u32::from_be_bytes(u32_bytes);

                Self::update_slice(&mut self.0[..Self::SIZE], period)?;

                self.0[Self::SIZE..].copy_from_slice(&(period + 1).to_be_bytes());
                Ok(())
            }

            fn update_slice(key_slice: &mut [u8], period: u32) -> Result<(), Error> {
                if period + 1 == Depth($depth).total() {
                    return Err(Error::KeyCannotBeUpdatedMore);
                }

                match (period + 1).cmp(&Depth($depth).half()) {
                    Ordering::Less => $sk::update_slice(&mut key_slice[..$sk::SIZE], period)?,
                    Ordering::Equal => {
                        let updated_key = $sk::keygen(&mut key_slice[$sk::SIZE..$sk::SIZE + 32]).0;
                        key_slice[..$sk::SIZE]
                            .copy_from_slice(&updated_key.as_bytes()[..$sk::SIZE]);
                    }
                    Ordering::Greater => $sk::update_slice(
                        &mut key_slice[..$sk::SIZE],
                        period - &Depth($depth).half(),
                    )?,
                }

                Ok(())
            }
        }

        impl KesSig for $signame {
            fn verify(&self, period: u32, pk: &PublicKey, m: &[u8]) -> Result<(), Error> {
                if &self.lhs_pk.hash_pair(&self.rhs_pk) != pk {
                    return Err(Error::InvalidHashComparison);
                }

                if period < Depth($depth).half() {
                    self.sigma.verify(period, &self.lhs_pk, m)?;
                } else {
                    self.sigma
                        .verify(period - &Depth($depth).half(), &self.rhs_pk, m)?
                }

                Ok(())
            }
        }

        // And now we implement serialisation
        impl $name {
            /// Byte size of the KES key
            pub const SIZE: usize =
                INDIVIDUAL_SECRET_SIZE + $depth * 32 + $depth * (PUBLIC_KEY_SIZE * 2);

            /// Convert the slice of bytes into `Self`.
            ///
            /// # Errors
            /// The function fails if
            /// * `bytes.len()` is not of the expected size
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != Self::SIZE + 4 {
                    // We need to account for the seed
                    return Err(Error::InvalidSecretKeySize(bytes.len()));
                }

                let mut key = [0u8; Self::SIZE + 4];
                key.copy_from_slice(bytes);
                Ok(Self(key))
            }

            /// Convert the slice of bytes to the skey part of Self. This function intentionally
            /// leaves out the period, as the period from low level keys are not needed (only
            /// the parent's method period is required).
            #[allow(dead_code)] // we need this because the last layer of KES will never use this function.
            fn skey_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != Self::SIZE {
                    return Err(Error::InvalidSecretKeySize(bytes.len()));
                }

                let mut key = [0u8; Self::SIZE + 4];
                key[..Self::SIZE].copy_from_slice(bytes);
                Ok(Self(key))
            }

            /// Convert `Self` into it's byte representation. In particular, the encoding returns
            /// the following array of size `Self::SIZE + 4`:
            /// ( sk_{-1} || seed || self.lhs_pk || self.rhs_pk || period )
            /// where `sk_{-1}` is the secret secret key of lower depth.
            /// Note that the period is only included in the last layer.
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }

        impl $signame {
            /// Byte size of the signature
            pub const SIZE: usize = SIGMA_SIZE + $depth * (PUBLIC_KEY_SIZE * 2);

            /// Convert the slice of bytes into `Self`.
            ///
            /// # Errors
            /// The function fails if
            /// * `bytes.len()` is not of the expected size
            /// * the bytes in the expected positions of the signature do not represent a valid
            ///   signature
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != Self::SIZE {
                    return Err(Error::InvalidSignatureSize(bytes.len()));
                }

                let sigma = $sigma::from_bytes(&bytes[..$sigma::SIZE])?;
                let lhs_pk =
                    PublicKey::from_bytes(&bytes[$sigma::SIZE..$sigma::SIZE + PUBLIC_KEY_SIZE])?;
                let rhs_pk = PublicKey::from_bytes(
                    &bytes[$sigma::SIZE + PUBLIC_KEY_SIZE..$sigma::SIZE + 2 * PUBLIC_KEY_SIZE],
                )?;
                Ok(Self {
                    sigma,
                    lhs_pk,
                    rhs_pk,
                })
            }

            /// Convert `Self` into it's byte representation. In particular, the encoding returns
            /// the following array of size `Self::SIZE`:
            /// ( self.sigma || self.lhs_pk || self.rhs_pk )
            pub fn to_bytes(&self) -> [u8; Self::SIZE] {
                let mut data = [0u8; Self::SIZE];
                data[..$sigma::SIZE].copy_from_slice(&self.sigma.to_bytes());
                data[$sigma::SIZE..$sigma::SIZE + PUBLIC_KEY_SIZE]
                    .copy_from_slice(self.lhs_pk.as_ref());
                data[$sigma::SIZE + PUBLIC_KEY_SIZE..$sigma::SIZE + 2 * PUBLIC_KEY_SIZE]
                    .copy_from_slice(self.rhs_pk.as_ref());

                data
            }
        }
    };
}
macro_rules! sum_compact_kes {
    ($name:ident, $signame:ident, $sk:ident, $sigma:ident, $depth:expr, $doc:expr) => {
        #[derive(Debug, Zeroize)]
        #[zeroize(drop)]
        #[doc=$doc]
        pub struct $name(
            [u8; 4 + INDIVIDUAL_SECRET_SIZE + $depth * 32 + $depth * (PUBLIC_KEY_SIZE * 2)],
        );

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[cfg_attr(feature = "serde_enabled", derive(Serialize, Deserialize))]
        /// Structure that represents a KES signature.
        pub struct $signame {
            sigma: $sigma,
            pk: PublicKey,
        }

        // First we implement the KES traits.
        impl KesSk for $name {
            type Sig = $signame;

            /// Function that takes a mutable
            fn keygen(master_seed: &mut [u8]) -> (Self, PublicKey) {
                assert_eq!(
                    master_seed.len(),
                    Seed::SIZE,
                    "Size of the seed is incorrect."
                );
                let mut data = [0u8; Self::SIZE + 4];
                let (mut r0, mut seed) = Seed::split_slice(master_seed);
                // We copy the seed before overwriting with zeros (in the `keygen` call).
                data[$sk::SIZE..$sk::SIZE + 32].copy_from_slice(&seed);

                let (sk_0, pk_0) = $sk::keygen(&mut r0);
                let (_, pk_1) = $sk::keygen(&mut seed);

                let pk = pk_0.hash_pair(&pk_1);

                // We write the keys to the main data.
                data[..$sk::SIZE].copy_from_slice(&sk_0.0[..$sk::SIZE]);
                data[$sk::SIZE + 32..$sk::SIZE + 64].copy_from_slice(&pk_0.as_bytes());
                data[$sk::SIZE + 64..$sk::SIZE + 96].copy_from_slice(&pk_1.as_bytes());

                // We write the period the the main data.
                data[Self::SIZE..].copy_from_slice(&0u32.to_be_bytes());

                (Self(data), pk)
            }

            fn sign(&self, m: &[u8]) -> Self::Sig {
                let mut u32_bytes = [0u8; 4];
                u32_bytes.copy_from_slice(&self.0[Self::SIZE..]);
                let period = u32::from_be_bytes(u32_bytes);

                self.sign_compact(m, period)
            }

            fn update(&mut self) -> Result<(), Error> {
                let mut u32_bytes = [0u8; 4];
                u32_bytes.copy_from_slice(&self.0[Self::SIZE..]);
                let period = u32::from_be_bytes(u32_bytes);

                Self::update_slice(&mut self.0[..Self::SIZE], period)?;

                self.0[Self::SIZE..].copy_from_slice(&(period + 1).to_be_bytes());
                Ok(())
            }

            fn update_slice(key_slice: &mut [u8], period: u32) -> Result<(), Error> {
                if period + 1 == Depth($depth).total() {
                    return Err(Error::KeyCannotBeUpdatedMore);
                }

                match (period + 1).cmp(&Depth($depth).half()) {
                    Ordering::Less => $sk::update_slice(&mut key_slice[..$sk::SIZE], period)?,
                    Ordering::Equal => {
                        let updated_key = $sk::keygen(&mut key_slice[$sk::SIZE..$sk::SIZE + 32]).0;
                        key_slice[..$sk::SIZE]
                            .copy_from_slice(&updated_key.as_bytes()[..$sk::SIZE]);
                    }
                    Ordering::Greater => $sk::update_slice(
                        &mut key_slice[..$sk::SIZE],
                        period - &Depth($depth).half(),
                    )?,
                }

                Ok(())
            }
        }

        impl KesCompactSig for $signame {
            fn recompute(&self, period: u32, m: &[u8]) -> Result<PublicKey, Error> {
                if period < Depth($depth).half() {
                    let recomputed_key = self.sigma.recompute(period, m)?;
                    Ok(recomputed_key.hash_pair(&self.pk))
                } else {
                    let recomputed_key = self.sigma.recompute(period - &Depth($depth).half(), m)?;
                    Ok(self.pk.hash_pair(&recomputed_key))
                }
            }
        }

        impl $name {
            /// Byte size of the KES key
            pub const SIZE: usize =
                INDIVIDUAL_SECRET_SIZE + $depth * 32 + $depth * (PUBLIC_KEY_SIZE * 2);

            pub(crate) fn sign_compact(&self, m: &[u8], period: u32) -> <Self as KesSk>::Sig {
                let t0 = Depth($depth).half();
                let sk =
                    $sk::skey_from_bytes(&self.as_bytes()[..$sk::SIZE]).expect("Invalid key bytes");
                let mut pk_bytes = [0u8; 32];
                let sigma = if period < t0 {
                    pk_bytes.copy_from_slice(&self.as_bytes()[$sk::SIZE + 64..$sk::SIZE + 96]);
                    sk.sign_compact(m, period)
                } else {
                    pk_bytes.copy_from_slice(&self.as_bytes()[$sk::SIZE + 32..$sk::SIZE + 64]);
                    sk.sign_compact(m, period - t0)
                };

                let pk = PublicKey::from_bytes(&pk_bytes).expect("Won't fail as slice has size 32");
                $signame { sigma, pk }
            }

            /// Convert the slice of bytes into `Self`.
            ///
            /// # Errors
            /// The function fails if
            /// * `bytes.len()` is not of the expected size
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != Self::SIZE + 4 {
                    return Err(Error::InvalidSecretKeySize(bytes.len()));
                }

                let mut key = [0u8; Self::SIZE + 4];
                key.copy_from_slice(bytes);
                Ok(Self(key))
            }

            /// Convert the slice of bytes to the skey part of Self. This function intentionally
            /// leaves out the period, as the period from low level keys are not needed (only
            /// the parent's method period is required).
            #[allow(dead_code)] // we need this because the last layer of KES will never use this function.
            fn skey_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != Self::SIZE {
                    return Err(Error::InvalidSecretKeySize(bytes.len()));
                }

                let mut key = [0u8; Self::SIZE + 4];
                key[..Self::SIZE].copy_from_slice(bytes);
                Ok(Self(key))
            }

            /// Convert `Self` into it's byte representation. In particular, the encoding returns
            /// the following array of size `Self::SIZE + 4`:
            /// ( sk_{-1} || seed || self.lhs_pk || self.rhs_pk || period )
            /// where `sk_{-1}` is the secret secret key of lower depth.
            /// Note that the period is only included in the last layer.
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }

        impl $signame {
            /// Byte size of the signature
            pub const SIZE: usize = SIGMA_SIZE + ($depth + 1) * PUBLIC_KEY_SIZE;

            /// Convert the slice of bytes into `Self`.
            ///
            /// # Errors
            /// The function fails if
            /// * `bytes.len()` is not of the expected size
            /// * the bytes in the expected positions of the signature do not represent a valid
            ///   signature
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != Self::SIZE {
                    return Err(Error::InvalidSignatureSize(bytes.len()));
                }

                let sigma = $sigma::from_bytes(&bytes[..$sigma::SIZE])?;
                let pk =
                    PublicKey::from_bytes(&bytes[$sigma::SIZE..$sigma::SIZE + PUBLIC_KEY_SIZE])?;

                Ok(Self { sigma, pk })
            }

            /// Convert `Self` into it's byte representation. In particular, the encoding returns
            /// the following array of size `Self::SIZE`:
            /// ( self.sigma || self.lhs_pk || self.rhs_pk )
            pub fn to_bytes(&self) -> [u8; Self::SIZE] {
                let mut data = [0u8; Self::SIZE];
                data[..$sigma::SIZE].copy_from_slice(&self.sigma.to_bytes());
                data[$sigma::SIZE..$sigma::SIZE + PUBLIC_KEY_SIZE]
                    .copy_from_slice(self.pk.as_ref());

                data
            }
        }
    };
}

sum_kes!(
    Sum1Kes,
    Sum1KesSig,
    Sum0Kes,
    Sum0KesSig,
    1,
    "KES implementation with depth 1"
);
sum_kes!(
    Sum2Kes,
    Sum2KesSig,
    Sum1Kes,
    Sum1KesSig,
    2,
    "KES implementation with depth 2"
);
sum_kes!(
    Sum3Kes,
    Sum3KesSig,
    Sum2Kes,
    Sum2KesSig,
    3,
    "KES implementation with depth 3"
);
sum_kes!(
    Sum4Kes,
    Sum4KesSig,
    Sum3Kes,
    Sum3KesSig,
    4,
    "KES implementation with depth 4"
);
sum_kes!(
    Sum5Kes,
    Sum5KesSig,
    Sum4Kes,
    Sum4KesSig,
    5,
    "KES implementation with depth 5"
);
sum_kes!(
    Sum6Kes,
    Sum6KesSig,
    Sum5Kes,
    Sum5KesSig,
    6,
    "KES implementation with depth 6"
);
sum_kes!(
    Sum7Kes,
    Sum7KesSig,
    Sum6Kes,
    Sum6KesSig,
    7,
    "KES implementation with depth 7"
);

sum_compact_kes!(
    Sum1CompactKes,
    Sum1CompactKesSig,
    Sum0CompactKes,
    Sum0CompactKesSig,
    1,
    "KES implementation with depth 1"
);
sum_compact_kes!(
    Sum2CompactKes,
    Sum2CompactKesSig,
    Sum1CompactKes,
    Sum1CompactKesSig,
    2,
    "KES implementation with depth 2"
);
sum_compact_kes!(
    Sum3CompactKes,
    Sum3CompactKesSig,
    Sum2CompactKes,
    Sum2CompactKesSig,
    3,
    "KES implementation with depth 3"
);
sum_compact_kes!(
    Sum4CompactKes,
    Sum4CompactKesSig,
    Sum3CompactKes,
    Sum3CompactKesSig,
    4,
    "KES implementation with depth 4"
);
sum_compact_kes!(
    Sum5CompactKes,
    Sum5CompactKesSig,
    Sum4CompactKes,
    Sum4CompactKesSig,
    5,
    "KES implementation with depth 5"
);
sum_compact_kes!(
    Sum6CompactKes,
    Sum6CompactKesSig,
    Sum5CompactKes,
    Sum5CompactKesSig,
    6,
    "KES implementation with depth 6"
);
sum_compact_kes!(
    Sum7CompactKes,
    Sum7CompactKesSig,
    Sum6CompactKes,
    Sum6CompactKesSig,
    7,
    "KES implementation with depth 7"
);

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn buff_single() {
        let (mut skey, pkey) = Sum1Kes::keygen(&mut [0u8; 32]);
        let dummy_message = b"tilin";
        let sigma = skey.sign(dummy_message);

        assert!(sigma.verify(0, &pkey, dummy_message).is_ok());

        // Key can be updated once
        assert!(skey.update().is_ok());
    }

    #[test]
    fn buff_4() {
        let (mut skey, pkey) = Sum4Kes::keygen(&mut [0u8; 32]);
        let dummy_message = b"tilin";
        let sigma = skey.sign(dummy_message);

        assert!(sigma.verify(0, &pkey, dummy_message).is_ok());

        // Key can be updated 2^4 - 1 times
        for _ in 0..15 {
            assert!(skey.update().is_ok());
        }

        let sigma_15 = skey.sign(dummy_message);
        assert!(sigma_15.verify(15, &pkey, dummy_message).is_ok())
    }

    #[test]
    fn buff_compact_single() {
        let (mut skey, pkey) = Sum1CompactKes::keygen(&mut [0u8; 32]);
        let dummy_message = b"tilin";
        let sigma = skey.sign(dummy_message);

        assert!(sigma.verify(0, &pkey, dummy_message).is_ok());

        // Key can be updated once
        assert!(skey.update().is_ok());
    }

    #[test]
    fn buff_compact_4() {
        let (mut skey, pkey) = Sum4CompactKes::keygen(&mut [0u8; 32]);
        let dummy_message = b"tilin";
        let sigma = skey.sign(dummy_message);

        assert!(sigma.verify(0, &pkey, dummy_message).is_ok());

        // Key can be updated 2^4 - 1 times
        for _ in 0..15 {
            assert!(skey.update().is_ok());
        }
    }
}

#[cfg(feature = "serde_enabled")]
#[cfg(test)]
mod test_serde {
    use super::*;

    #[test]
    fn test_serde_1() {
        let (skey, pkey) = Sum1Kes::keygen(&mut [0u8; 32]);

        let pkey_bytes = serde_json::to_string(&pkey).unwrap();
        let deser_pkey: PublicKey = serde_json::from_str(&pkey_bytes).unwrap();

        assert_eq!(pkey, deser_pkey);

        let dummy_message = b"tolon";
        let sigma = skey.sign(dummy_message);

        let sigma_bytes = serde_json::to_string(&sigma).unwrap();
        let deser_sigma: Sum1KesSig = serde_json::from_str(&sigma_bytes).unwrap();

        assert_eq!(sigma, deser_sigma);
        assert!(deser_sigma.verify(0, &pkey, dummy_message).is_ok());

        let (skey, pkey) = Sum1CompactKes::keygen(&mut [0u8; 32]);

        let pkey_bytes = serde_json::to_string(&pkey).unwrap();
        let deser_pkey: PublicKey = serde_json::from_str(&pkey_bytes).unwrap();

        assert_eq!(pkey, deser_pkey);

        let dummy_message = b"tolon";
        let sigma = skey.sign(dummy_message);

        let sigma_bytes = serde_json::to_string(&sigma).unwrap();
        let deser_sigma: Sum1CompactKesSig = serde_json::from_str(&sigma_bytes).unwrap();

        assert_eq!(sigma, deser_sigma);
        assert!(deser_sigma.verify(0, &pkey, dummy_message).is_ok());
    }

    #[test]
    fn test_serde_4() {
        let (skey, pkey) = Sum4Kes::keygen(&mut [0u8; 32]);

        let pkey_bytes = serde_json::to_string(&pkey).unwrap();
        let deser_pkey: PublicKey = serde_json::from_str(&pkey_bytes).unwrap();

        assert_eq!(pkey, deser_pkey);

        let dummy_message = b"tolon";
        let sigma = skey.sign(dummy_message);

        let sigma_bytes = serde_json::to_string(&sigma).unwrap();
        let deser_sigma: Sum4KesSig = serde_json::from_str(&sigma_bytes).unwrap();

        assert_eq!(sigma, deser_sigma);
        assert!(deser_sigma.verify(0, &pkey, dummy_message).is_ok());

        let (skey, pkey) = Sum4CompactKes::keygen(&mut [0u8; 32]);

        let pkey_bytes = serde_json::to_string(&pkey).unwrap();
        let deser_pkey: PublicKey = serde_json::from_str(&pkey_bytes).unwrap();

        assert_eq!(pkey, deser_pkey);

        let dummy_message = b"tolon";
        let sigma = skey.sign(dummy_message);

        let sigma_bytes = serde_json::to_string(&sigma).unwrap();
        let deser_sigma: Sum4CompactKesSig = serde_json::from_str(&sigma_bytes).unwrap();

        assert_eq!(sigma, deser_sigma);
        assert!(deser_sigma.verify(0, &pkey, dummy_message).is_ok());
    }

    #[test]
    fn test_serde_6() {
        let (skey, pkey) = Sum6Kes::keygen(&mut [0u8; 32]);

        let pkey_bytes = serde_json::to_string(&pkey).unwrap();
        let deser_pkey: PublicKey = serde_json::from_str(&pkey_bytes).unwrap();

        assert_eq!(pkey, deser_pkey);

        let dummy_message = b"tolon";
        let sigma = skey.sign(dummy_message);

        let sigma_bytes = serde_json::to_string(&sigma).unwrap();
        let deser_sigma: Sum6KesSig = serde_json::from_str(&sigma_bytes).unwrap();

        assert_eq!(sigma, deser_sigma);
        assert!(deser_sigma.verify(0, &pkey, dummy_message).is_ok());

        let (skey, pkey) = Sum6CompactKes::keygen(&mut [0u8; 32]);

        let pkey_bytes = serde_json::to_string(&pkey).unwrap();
        let deser_pkey: PublicKey = serde_json::from_str(&pkey_bytes).unwrap();

        assert_eq!(pkey, deser_pkey);

        let dummy_message = b"tolon";
        let sigma = skey.sign(dummy_message);

        let sigma_bytes = serde_json::to_string(&sigma).unwrap();
        let deser_sigma: Sum6CompactKesSig = serde_json::from_str(&sigma_bytes).unwrap();

        assert_eq!(sigma, deser_sigma);
        assert!(deser_sigma.verify(0, &pkey, dummy_message).is_ok());
    }
}
