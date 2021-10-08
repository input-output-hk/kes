//! This module contains the macros to build the KES algorithms.
//! Tentative at making a recursive, and smaller code, which builds a key formed
//! by an array, allowing for a more granular memory management when calling the function.
//! The goal is to provide a similar construction to what is achieved in [sumed25519](./../sumed25519)
//! while maintaining code simplicity, and a smaller crate to facilitate audit and maintenance.

use crate::common::{Depth, Seed};
use crate::errors::Error;
use crate::single_kes::{Sum0Kes, Sum0KesSig};
use crate::sumed25519::{hash, PublicKey, INDIVIDUAL_SECRET_SIZE, PUBLIC_KEY_SIZE, SIGMA_SIZE};
use crate::traits::{KesSig, KesSk};
use std::cmp::Ordering;
use zeroize::Zeroize;

macro_rules! sum_kes {
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
            lhs_pk: PublicKey,
            rhs_pk: PublicKey,
        }

        // First we implement the KES traits.
        impl KesSk for $name {
            type Sig = $signame;

            /// Function that takes a mutable
            fn keygen_kes(master_seed: &mut [u8]) -> (Self, PublicKey) {
                let mut data = [0u8; Self::SIZE];
                let (mut r0, mut seed) = Seed::split_slice(master_seed);
                // We copy the seed before overwriting with zeros (in the `keygen_kes` call).
                data[$sk::SIZE..$sk::SIZE + 32].copy_from_slice(&seed);

                let (sk_0, pk_0) = $sk::keygen_kes(&mut r0);
                let (_, pk_1) = $sk::keygen_kes(&mut seed);

                let pk = hash(&pk_0, &pk_1);

                // We write the keys to the main data.
                data[..$sk::SIZE].copy_from_slice(&sk_0.0);
                data[$sk::SIZE + 32..$sk::SIZE + 64].copy_from_slice(&pk_0.as_bytes());
                data[$sk::SIZE + 64..$sk::SIZE + 96].copy_from_slice(&pk_1.as_bytes());

                (Self(data), pk)
            }

            fn sign_kes(&self, period: usize, m: &[u8]) -> Self::Sig {
                let t0 = Depth($depth).half();
                let sk = $sk::from_bytes(&self.as_bytes()[..$sk::SIZE]).expect("Invalid key bytes");
                let sigma = if period < t0 {
                    sk.sign_kes(period, m)
                } else {
                    sk.sign_kes(period - t0, m)
                };

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

            fn update_kes(&mut self, period: usize) -> Result<(), Error> {
                if period + 1 == Depth($depth).total() {
                    return Err(Error::KeyCannotBeUpdatedMore);
                }

                match (period + 1).cmp(&Depth($depth).half()) {
                    Ordering::Less => {
                        $sk::from_bytes(&self.as_bytes()[..$sk::SIZE])?.update_kes(period)?
                    }
                    Ordering::Equal => {
                        let updated_key = $sk::keygen_kes(&mut self.0[$sk::SIZE..$sk::SIZE + 32]).0;
                        self.0[..$sk::SIZE].copy_from_slice(updated_key.as_bytes());
                    }
                    Ordering::Greater => $sk::from_bytes(&self.as_bytes()[..$sk::SIZE])?
                        .update_kes(period - &Depth($depth).half())?,
                }

                Ok(())
            }
        }

        impl KesSig for $signame {
            fn verify_kes(&self, period: usize, pk: &PublicKey, m: &[u8]) -> Result<(), Error> {
                if &hash(&self.lhs_pk, &self.rhs_pk) != pk {
                    return Err(Error::InvalidHashComparison);
                }

                if period < Depth($depth).half() {
                    self.sigma.verify_kes(period, &self.lhs_pk, m)?;
                } else {
                    self.sigma
                        .verify_kes(period - &Depth($depth).half(), &self.rhs_pk, m)?
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
                    return Err(Error::InvalidSecretKeySize(bytes.len()));
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn buff_single() {
        let (mut skey, pkey) = Sum1Kes::keygen_kes(&mut [0u8; 32]);
        let dummy_message = b"tilin";
        let sigma = skey.sign_kes(0, dummy_message);

        assert!(sigma.verify_kes(0, &pkey, dummy_message).is_ok());

        // Key can be updated once
        assert!(skey.update_kes(0).is_ok());
    }

    #[test]
    fn buff_4() {
        let (mut skey, pkey) = Sum4Kes::keygen_kes(&mut [0u8; 32]);
        let dummy_message = b"tilin";
        let sigma = skey.sign_kes(0, dummy_message);

        assert!(sigma.verify_kes(0, &pkey, dummy_message).is_ok());

        // Key can be updated 2^4 - 1 times
        for period in 0..15 {
            assert!(skey.update_kes(period).is_ok());
        }
    }
}
