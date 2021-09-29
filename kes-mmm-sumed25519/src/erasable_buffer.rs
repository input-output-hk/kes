//! Tentative at making a recursive, and smaller code, which builds a key formed
//! by an array, allowing for a more granular memory management when calling the function.
//! The goal is to provide a similar construction to what is achieved in [sumed25519](./../sumed25519)
//! while maintaining code simplicity, and a smaller crate to facilitate audit and maintenance.
use crate::common::{Depth, Seed};
use crate::errors::Error;
use crate::sumed25519::{hash, PublicKey};
use crate::traits::{KesSig, KesSk};
use ed25519_dalek::{
    Keypair as EdKeypair, SecretKey as EdSecretKey, Signature as EdSignature, Signer, Verifier,
};
use std::cmp::Ordering;
use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]
struct Sum0Kes([u8; 64]);

type Sum0KesSig = EdSignature;

impl KesSk for Sum0Kes {
    const SIZE: usize = 64;
    type Sig = Sum0KesSig;

    fn keygen_kes(master_seed: &mut Seed) -> (Self, PublicKey) {
        let secret = EdSecretKey::from_bytes(master_seed.as_ref())
            .expect("Seed is defined with 32 bytes, so it won't fail.");
        let public = (&secret).into();
        (
            Sum0Kes(EdKeypair { secret, public }.to_bytes()),
            PublicKey::from_ed25519_publickey(&public),
        )
    }

    fn sign_kes(&self, _: usize, m: &[u8]) -> Sum0KesSig {
        let ed_sk = EdKeypair::from_bytes(&self.0).expect("internal error: keypair invalid");
        ed_sk.sign(m)
    }

    fn update_kes(&mut self, _: usize) -> Result<(), Error> {
        Err(Error::KeyCannotBeUpdatedMore)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != Self::SIZE {
            return Err(Error::InvalidSecretKeySize(bytes.len()));
        }

        let mut key = [0u8; Self::SIZE];
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl KesSig for Sum0KesSig {
    fn verify_kes(&self, _: usize, pk: &PublicKey, m: &[u8]) -> Result<(), Error> {
        let ed_pk = pk.to_ed25519()?;
        ed_pk.verify(m, self).map_err(Error::from)
    }
}

sum_kes_buff!(
    Sum1Kes,
    Sum1KesSig,
    Sum0Kes,
    Sum0KesSig,
    1,
    "KES implementation with depth 1"
);
sum_kes_buff!(
    Sum2Kes,
    Sum2KesSig,
    Sum1Kes,
    Sum1KesSig,
    2,
    "KES implementation with depth 2"
);
sum_kes_buff!(
    Sum3Kes,
    Sum3KesSig,
    Sum2Kes,
    Sum2KesSig,
    3,
    "KES implementation with depth 3"
);
sum_kes_buff!(
    Sum4Kes,
    Sum4KesSig,
    Sum3Kes,
    Sum3KesSig,
    4,
    "KES implementation with depth 4"
);
sum_kes_buff!(
    Sum5Kes,
    Sum5KesSig,
    Sum4Kes,
    Sum4KesSig,
    5,
    "KES implementation with depth 5"
);
sum_kes_buff!(
    Sum6Kes,
    Sum6KesSig,
    Sum5Kes,
    Sum5KesSig,
    6,
    "KES implementation with depth 6"
);
sum_kes_buff!(
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
        let mut seed = Seed::from_bytes([0u8; 32]);

        let (mut skey, pkey) = Sum1Kes::keygen_kes(&mut seed);
        let dummy_message = b"tilin";
        let sigma = skey.sign_kes(0, dummy_message);

        assert!(sigma.verify_kes(0, &pkey, dummy_message).is_ok());

        // Key can be updated once
        assert!(skey.update_kes(0).is_ok());
    }

    #[test]
    fn buff_4() {
        let mut seed = Seed::from_bytes([0u8; 32]);

        let (mut skey, pkey) = Sum4Kes::keygen_kes(&mut seed);
        let dummy_message = b"tilin";
        let sigma = skey.sign_kes(0, dummy_message);

        assert!(sigma.verify_kes(0, &pkey, dummy_message).is_ok());

        // Key can be updated 2^4 - 1 times
        for period in 0..15 {
            assert!(skey.update_kes(period).is_ok());
        }
    }
}
