//! Implementation of the base signature used for CompactKES. This is a standard signature
//! mechanism which is considered a KES signature scheme with a single period. In this
//! case, the single instance is ed25519. Contrarily to Sum0Kes, Sum0CompactKes signature
//! stores the signature and the public key. While this might be counterintuitive with respect
//! with the naming (size of Sum0Kes signatures is smaller than that of Sum0CompactKes), this
//! change allows us for a more compact signature verification in KES instances with more
//! periods.
use crate::errors::Error;
use crate::sumed25519::PublicKey;
use crate::traits::{KesSk, KesCompactSig};
use ed25519_dalek::{
    Keypair as EdKeypair,
    SecretKey as EdSecretKey,
    PublicKey as EdPublicKey,
    Signature as EdSignature,
    Signer,
    Verifier,
    SIGNATURE_LENGTH,
};
pub use ed25519_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]
/// Single KES instance, which is a wrapper over ed25519.
pub struct Sum0CompactKes(pub(crate) [u8; SECRET_KEY_LENGTH]);

/// Singke KES Signature instance, which is a wrapper over ed25519.
pub struct Sum0CompactKesSig(pub(crate) EdSignature, pub(crate) EdPublicKey);

impl KesSk for Sum0CompactKes {
    type Sig = Sum0CompactKesSig;

    fn keygen(master_seed: &mut [u8]) -> (Self, PublicKey) {
        let secret = EdSecretKey::from_bytes(master_seed)
            .expect("Seed is defined with 32 bytes, so it won't fail.");
        let public = (&secret).into();
        master_seed.copy_from_slice(&[0u8; 32]);
        (
            Sum0CompactKes(secret.to_bytes()),
            PublicKey::from_ed25519_publickey(&public),
        )
    }

    fn sign(&self, _: usize, m: &[u8]) -> Sum0CompactKesSig {
        let secret = EdSecretKey::from_bytes(&self.0)
            .expect("Seed is defined with 32 bytes, so it won't fail.");
        let public = (&secret).into();
        let ed_sk = EdKeypair { secret, public };
        Sum0CompactKesSig(ed_sk.sign(m), public)
    }

    fn update(&mut self, _: usize) -> Result<(), Error> {
        Err(Error::KeyCannotBeUpdatedMore)
    }
    fn update_slice(_: &mut [u8], _: usize) -> Result<(), Error> {
        Err(Error::KeyCannotBeUpdatedMore)
    }
}

impl KesCompactSig for Sum0CompactKesSig {
    fn recompute(&self, _: usize, m: &[u8]) -> Result<PublicKey, Error> {
        self.1.verify(m, &self.0).map_err(Error::from)?;
        Ok(PublicKey(self.1.to_bytes()))
    }
}

// Serialisation
impl Sum0CompactKes {
    /// Size of secret key of Single KES instance
    pub const SIZE: usize = SECRET_KEY_LENGTH;

    /// Convert a byte array into a key
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != Self::SIZE {
            return Err(Error::InvalidSecretKeySize(bytes.len()));
        }

        let mut key = [0u8; Self::SIZE];
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    /// Return the current key as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Sum0CompactKesSig {
    /// Size of the KES signature with depth 0
    pub const SIZE: usize = SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH;

    /// Convert a byte array into a signature
    /// todo: failures.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != Self::SIZE {
            return Err(Error::InvalidSecretKeySize(bytes.len()));
        }

        let mut signature = [0u8; SIGNATURE_LENGTH];
        let mut pk_bytes = [0u8; PUBLIC_KEY_LENGTH];
        signature.copy_from_slice(&bytes[..SIGNATURE_LENGTH]);
        pk_bytes.copy_from_slice(&bytes[SIGNATURE_LENGTH..]);
        let ed_key = EdPublicKey::from_bytes(&pk_bytes)?;
        Ok(Self(EdSignature::from(signature), ed_key))
    }

    /// Return `Self` as a byte array.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut output = [0u8; Self::SIZE];
        output[..SIGNATURE_LENGTH].copy_from_slice(&self.0.to_bytes());
        output[SIGNATURE_LENGTH..].copy_from_slice(self.1.as_bytes());
        output
    }
}
