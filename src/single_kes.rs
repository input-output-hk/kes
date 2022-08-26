//! Implementation of the base signature used for KES. This is a standard signature
//! mechanism which is considered a KES signature scheme with a single period. In this
//! case, the single instance is ed25519.
use crate::common::PublicKey;
use crate::errors::Error;
use crate::traits::{KesCompactSig, KesSig, KesSk};
use ed25519_dalek::{
    Keypair as EdKeypair, PublicKey as EdPublicKey, SecretKey as EdSecretKey,
    Signature as EdSignature, Signer, SIGNATURE_LENGTH,
};
pub use ed25519_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use zeroize::Zeroize;

#[cfg(feature = "serde_enabled")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
#[cfg_attr(feature = "serde_enabled", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde_enabled", serde_as)]
/// Single KES instance, which is a wrapper over ed25519.
pub struct Sum0Kes(
    #[cfg_attr(feature = "serde_enabled", serde_as(as = "Bytes"))]
    pub(crate)  [u8; SECRET_KEY_LENGTH],
);

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde_enabled", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde_enabled", serde_as)]
/// Single KES Signature instance, which is a wrapper over ed25519.
pub struct Sum0KesSig(
    #[cfg_attr(feature = "serde_enabled", serde_as(as = "Bytes"))] pub(crate) EdSignature,
);

impl KesSk for Sum0Kes {
    type Sig = Sum0KesSig;

    fn keygen(master_seed: &mut [u8]) -> (Self, PublicKey) {
        let secret = EdSecretKey::from_bytes(master_seed)
            .expect("Seed is defined with 32 bytes, so it won't fail.");
        let public = (&secret).into();
        master_seed.copy_from_slice(&[0u8; 32]);
        (
            Sum0Kes(secret.to_bytes()),
            PublicKey::from_ed25519_publickey(&public),
        )
    }

    fn sign(&self, _: usize, m: &[u8]) -> Sum0KesSig {
        let secret = EdSecretKey::from_bytes(&self.0)
            .expect("Seed is defined with 32 bytes, so it won't fail.");
        let public = (&secret).into();
        let ed_sk = EdKeypair { secret, public };
        Sum0KesSig(ed_sk.sign(m))
    }

    fn update(&mut self, _: usize) -> Result<(), Error> {
        Err(Error::KeyCannotBeUpdatedMore)
    }

    fn update_slice(_: &mut [u8], _: usize) -> Result<(), Error> {
        Err(Error::KeyCannotBeUpdatedMore)
    }
}

impl KesSig for Sum0KesSig {
    fn verify(&self, _: usize, pk: &PublicKey, m: &[u8]) -> Result<(), Error> {
        let ed_pk = pk.to_ed25519()?;
        ed_pk.verify_strict(m, &self.0).map_err(Error::from)
    }
}

impl Sum0Kes {
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

impl Sum0KesSig {
    /// Size of the KES signature with depth 0
    pub const SIZE: usize = SIGNATURE_LENGTH;

    /// Convert a byte array into a signature
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != Self::SIZE {
            return Err(Error::InvalidSecretKeySize(bytes.len()));
        }

        let mut signature = [0u8; Self::SIZE];
        signature.copy_from_slice(bytes);
        Ok(Self(EdSignature::from(signature)))
    }

    /// Return `Self` as a byte array.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        self.0.to_bytes()
    }
}

#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
#[cfg_attr(feature = "serde_enabled", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde_enabled", serde_as)]
/// Single KES instance, which is a wrapper over ed25519.
pub struct Sum0CompactKes(
    #[cfg_attr(feature = "serde_enabled", serde_as(as = "Bytes"))]
    pub(crate)  [u8; SECRET_KEY_LENGTH],
);

/// Singke KES Signature instance, which is a wrapper over ed25519.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde_enabled", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde_enabled", serde_as)]
pub struct Sum0CompactKesSig(
    #[cfg_attr(feature = "serde_enabled", serde_as(as = "Bytes"))] pub(crate) EdSignature,
    pub(crate) EdPublicKey,
);

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
        self.1.verify_strict(m, &self.0)?;
        Ok(PublicKey(self.1.to_bytes()))
    }
}

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
