//! This module contains the macros to build the Compact KES algorithms as introduced in the
//! Babbage HF. Same construction as in [erasable_buffer](./../erasable_buffer) but with
//! a smaller signature size.

use crate::common::{Depth, Seed};
use crate::errors::Error;
use crate::compact_single_kes::{Sum0CompactKes, Sum0CompactKesSig};
use crate::common::{hash, PublicKey, INDIVIDUAL_SECRET_SIZE, PUBLIC_KEY_SIZE, SIGMA_SIZE};
use crate::traits::{KesCompactSig, KesSk};
use std::cmp::Ordering;
use zeroize::Zeroize;

macro_rules! sum_compact_kes {
    ($name:ident, $signame:ident, $sk:ident, $sigma:ident, $depth:expr, $doc:expr) => {
        #[derive(Zeroize)]
        #[zeroize(drop)]
        #[doc=$doc]
        pub struct $name(
            [u8; INDIVIDUAL_SECRET_SIZE + $depth * 32 + $depth * (PUBLIC_KEY_SIZE * 2)],
        );

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
                let mut data = [0u8; Self::SIZE];
                let (mut r0, mut seed) = Seed::split_slice(master_seed);
                // We copy the seed before overwriting with zeros (in the `keygen` call).
                data[$sk::SIZE..$sk::SIZE + 32].copy_from_slice(&seed);

                let (sk_0, pk_0) = $sk::keygen(&mut r0);
                let (_, pk_1) = $sk::keygen(&mut seed);

                let pk = hash(&pk_0, &pk_1);

                // We write the keys to the main data.
                data[..$sk::SIZE].copy_from_slice(&sk_0.0);
                data[$sk::SIZE + 32..$sk::SIZE + 64].copy_from_slice(&pk_0.as_bytes());
                data[$sk::SIZE + 64..$sk::SIZE + 96].copy_from_slice(&pk_1.as_bytes());

                (Self(data), pk)
            }

            fn sign(&self, period: usize, m: &[u8]) -> Self::Sig {
                let t0 = Depth($depth).half();
                let sk = $sk::from_bytes(&self.as_bytes()[..$sk::SIZE]).expect("Invalid key bytes");
                let mut pk_bytes = [0u8; 32];
                let sigma = if period < t0 {
                    pk_bytes.copy_from_slice(&self.as_bytes()[$sk::SIZE + 64..$sk::SIZE + 96]);
                    sk.sign(period, m)
                } else {
                    pk_bytes.copy_from_slice(&self.as_bytes()[$sk::SIZE + 32..$sk::SIZE + 64]);
                    sk.sign(period - t0, m)
                };

                let pk = PublicKey::from_bytes(&pk_bytes)
                        .expect("Won't fail as slice has size 32");
                $signame {
                    sigma,
                    pk,
                }
            }

            fn update(&mut self, period: usize) -> Result<(), Error> {
                Self::update_slice(&mut self.0, period)
            }

            fn update_slice(key_slice: &mut [u8], period: usize) -> Result<(), Error> {
                if period + 1 == Depth($depth).total() {
                    return Err(Error::KeyCannotBeUpdatedMore);
                }

                match (period + 1).cmp(&Depth($depth).half()) {
                    Ordering::Less => $sk::update_slice(&mut key_slice[..$sk::SIZE], period)?,
                    Ordering::Equal => {
                        let updated_key = $sk::keygen(&mut key_slice[$sk::SIZE..$sk::SIZE + 32]).0;
                        key_slice[..$sk::SIZE].copy_from_slice(updated_key.as_bytes());
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
            fn recompute(&self, period: usize, m: &[u8]) -> Result<PublicKey, Error> {
                if period < Depth($depth).half() {
                    let recomputed_key = self.sigma.recompute(period, m)?;
                    Ok(hash(&recomputed_key, &self.pk))
                } else {
                    let recomputed_key = self.sigma.recompute(period - &Depth($depth).half(), m)?;
                    Ok(hash(&self.pk, &recomputed_key))
                }
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
                if bytes.len() != Self::SIZE {
                    return Err(Error::InvalidSecretKeySize(bytes.len()));
                }

                let mut key = [0u8; Self::SIZE];
                key.copy_from_slice(bytes);
                Ok(Self(key))
            }

            /// Convert `Self` into it's byte representation. In particular, the encoding returns
            /// the following array of size `Self::SIZE`:
            /// ( sk_{-1} || seed || self.lhs_pk || self.rhs_pk )
            /// where `sk_{-1}` is the secret secret key of lower depth.
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
                    return Err(Error::InvalidSecretKeySize(bytes.len()));
                }

                let sigma = $sigma::from_bytes(&bytes[..$sigma::SIZE])?;
                let pk =
                    PublicKey::from_bytes(&bytes[$sigma::SIZE..$sigma::SIZE + PUBLIC_KEY_SIZE])?;

                Ok(Self {
                    sigma,
                    pk
                })
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
        let (mut skey, pkey) = Sum1CompactKes::keygen(&mut [0u8; 32]);
        let dummy_message = b"tilin";
        let sigma = skey.sign(0, dummy_message);

        assert!(sigma.verify(0, &pkey, dummy_message).is_ok());

        // Key can be updated once
        assert!(skey.update(0).is_ok());
    }

    #[test]
    fn buff_4() {
        let (mut skey, pkey) = Sum4CompactKes::keygen(&mut [0u8; 32]);
        let dummy_message = b"tilin";
        let sigma = skey.sign(0, dummy_message);

        assert!(sigma.verify(0, &pkey, dummy_message).is_ok());

        // Key can be updated 2^4 - 1 times
        for period in 0..15 {
            assert!(skey.update(period).is_ok());
        }
    }
}