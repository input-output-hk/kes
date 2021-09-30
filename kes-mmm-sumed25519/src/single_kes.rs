//! Implementation of the base signature used for KES. This is a standard signature
//! mechanism which is considered a KES signature scheme with a single period. In this
//! case, the single instance is ed25519.
pub use ed25519_dalek::{
    SECRET_KEY_LENGTH, PUBLIC_KEY_LENGTH
};
use crate::sumed25519::PublicKey;
use crate::errors::Error;
use crate::traits::{KesSig, KesSk};
use ed25519_dalek::{Keypair as EdKeypair, SecretKey as EdSecretKey, Signature as EdSignature, Verifier, Signer, SIGNATURE_LENGTH};
use zeroize::Zeroize;


#[derive(Zeroize)]
#[zeroize(drop)]
pub(crate) struct Sum0Kes(pub(crate) [u8; SECRET_KEY_LENGTH]);

pub(crate) struct Sum0KesSig(pub(crate) EdSignature);

impl KesSk for Sum0Kes {
    type Sig = Sum0KesSig;

    fn keygen_kes(master_seed: &mut [u8]) -> (Self, PublicKey) {
        let secret = EdSecretKey::from_bytes(master_seed)
            .expect("Seed is defined with 32 bytes, so it won't fail.");
        let public = (&secret).into();
        master_seed.copy_from_slice(&[0u8; 32]);
        (
            Sum0Kes(secret.to_bytes()),
            PublicKey::from_ed25519_publickey(&public),
        )
    }

    fn sign_kes(&self, _: usize, m: &[u8]) -> Sum0KesSig {
        let secret = EdSecretKey::from_bytes(&self.0)
            .expect("Seed is defined with 32 bytes, so it won't fail.");
        let public = (&secret).into();
        let ed_sk = EdKeypair { secret, public };
        Sum0KesSig(ed_sk.sign(m))
    }

    fn update_kes(&mut self, _: usize) -> Result<(), Error> {
        Err(Error::KeyCannotBeUpdatedMore)
    }
}

impl KesSig for Sum0KesSig {
    fn verify_kes(&self, _: usize, pk: &PublicKey, m: &[u8]) -> Result<(), Error> {
        let ed_pk = pk.to_ed25519()?;
        ed_pk.verify(m, &self.0).map_err(Error::from)
    }
}

// Serialisation
impl Sum0Kes {
    pub const SIZE: usize = SECRET_KEY_LENGTH;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != Self::SIZE {
            return Err(Error::InvalidSecretKeySize(bytes.len()));
        }

        let mut key = [0u8; Self::SIZE];
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Sum0KesSig {
    pub const SIZE: usize = SIGNATURE_LENGTH;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != Self::SIZE {
            return Err(Error::InvalidSecretKeySize(bytes.len()));
        }

        let mut signature = [0u8; Self::SIZE];
        signature.copy_from_slice(bytes);
        Ok(Self(EdSignature::from(signature)))
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        self.0.to_bytes()
    }
}
