//! Implementation of the base signature used for KES. This is a standard signature
//! mechanism which is considered a KES signature scheme with a single period. In this
//! case, the single instance is ed25519.
use crate::common::{PublicKey, Seed};
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

#[derive(Debug, Zeroize)]
#[zeroize(drop)]
/// Single KES instance, which is a wrapper over ed25519.
pub struct Sum0Kes(pub(crate) [u8; SECRET_KEY_LENGTH]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde_enabled", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde_enabled", serde_as)]
/// Single KES Signature instance, which is a wrapper over ed25519.
pub struct Sum0KesSig(
    #[cfg_attr(feature = "serde_enabled", serde_as(as = "Bytes"))] pub(crate) EdSignature,
);

impl KesSk for Sum0Kes {
    type Sig = Sum0KesSig;
    const SIZE: usize = SECRET_KEY_LENGTH;

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

    fn update(&mut self) -> Result<(), Error> {
        Err(Error::KeyCannotBeUpdatedMore)
    }

    fn sign(&self, m: &[u8]) -> Sum0KesSig {
        let secret = EdSecretKey::from_bytes(&self.0)
            .expect("Seed is defined with 32 bytes, so it won't fail.");
        let public = (&secret).into();
        let ed_sk = EdKeypair { secret, public };
        Sum0KesSig(ed_sk.sign(m))
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != Self::SIZE + 4 {
            // We need to account for the seed
            return Err(Error::InvalidSecretKeySize(bytes.len()));
        }

        let mut key = [0u8; Self::SIZE];
        key.copy_from_slice(&bytes[..Self::SIZE]);
        Ok(Self(key))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn get_period(&self) -> u32 {
        0
    }
}

impl Sum0Kes {
    pub(crate) fn update_slice(_: &mut [u8], _: u32) -> Result<(), Error> {
        Err(Error::KeyCannotBeUpdatedMore)
    }

    pub(crate) fn keygen_slice(in_slice: &mut [u8], opt_seed: Option<&mut [u8]>) -> PublicKey {
        let secret = if let Some(seed) = opt_seed {
            assert_eq!(in_slice.len(), Self::SIZE, "Input size is incorrect.");

            let sk = EdSecretKey::from_bytes(seed).expect("Size of the seed is incorrect.");

            seed.copy_from_slice(&[0u8; 32]);
            sk
        } else {
            assert_eq!(
                in_slice.len(),
                Self::SIZE + Seed::SIZE,
                "Input size is incorrect."
            );

            let sk = EdSecretKey::from_bytes(&in_slice[Self::SIZE..])
                .expect("Size of the seed is incorrect.");

            in_slice[Self::SIZE..].copy_from_slice(&[0u8; 32]);
            sk
        };

        let public = (&secret).into();

        // We need to make this copies unfortunately by how the
        // underlying library behaves. Would be great to have a
        // EdPubKey from seed function.
        // todo: think of a redesign
        in_slice[..Self::SIZE].copy_from_slice(secret.as_bytes());

        PublicKey::from_ed25519_publickey(&public)
    }

    pub(crate) fn sign_from_slice(sk: &[u8], m: &[u8]) -> <Self as KesSk>::Sig {
        let secret =
            EdSecretKey::from_bytes(sk).expect("Seed is defined with 32 bytes, so it won't fail.");
        let public = (&secret).into();
        let ed_sk = EdKeypair { secret, public };
        Sum0KesSig(ed_sk.sign(m))
    }
}
impl KesSig for Sum0KesSig {
    fn verify(&self, _: u32, pk: &PublicKey, m: &[u8]) -> Result<(), Error> {
        let ed_pk = pk.as_ed25519()?;
        ed_pk.verify_strict(m, &self.0).map_err(Error::from)
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
    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        self.0.to_bytes()
    }
}

#[derive(Debug, Zeroize)]
#[zeroize(drop)]
/// Single KES instance, which is a wrapper over ed25519.
pub struct Sum0CompactKes(pub(crate) [u8; SECRET_KEY_LENGTH]);

/// Singke KES Signature instance, which is a wrapper over ed25519.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde_enabled", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde_enabled", serde_as)]
pub struct Sum0CompactKesSig(
    #[cfg_attr(feature = "serde_enabled", serde_as(as = "Bytes"))] pub(crate) EdSignature,
    pub(crate) EdPublicKey,
);

impl KesSk for Sum0CompactKes {
    type Sig = Sum0CompactKesSig;
    const SIZE: usize = SECRET_KEY_LENGTH;

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

    fn sign(&self, m: &[u8]) -> Sum0CompactKesSig {
        let secret = EdSecretKey::from_bytes(&self.0)
            .expect("Seed is defined with 32 bytes, so it won't fail.");
        let public = (&secret).into();
        let ed_sk = EdKeypair { secret, public };
        Sum0CompactKesSig(ed_sk.sign(m), public)
    }

    fn update(&mut self) -> Result<(), Error> {
        Err(Error::KeyCannotBeUpdatedMore)
    }

    fn get_period(&self) -> u32 {
        0
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != Self::SIZE + 4 {
            // We need to account for the seed
            return Err(Error::InvalidSecretKeySize(bytes.len()));
        }

        let mut key = [0u8; Self::SIZE];
        key.copy_from_slice(&bytes[..Self::SIZE]);
        Ok(Self(key))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl KesCompactSig for Sum0CompactKesSig {
    fn recompute(&self, _: u32, m: &[u8]) -> Result<PublicKey, Error> {
        self.1.verify_strict(m, &self.0)?;
        Ok(PublicKey(self.1.to_bytes()))
    }
}

impl Sum0CompactKes {
    pub(crate) fn update_slice(_: &mut [u8], _: u32) -> Result<(), Error> {
        Err(Error::KeyCannotBeUpdatedMore)
    }

    pub(crate) fn keygen_slice(in_slice: &mut [u8], opt_seed: Option<&mut [u8]>) -> PublicKey {
        let secret = if let Some(seed) = opt_seed {
            assert_eq!(in_slice.len(), Self::SIZE, "Input size is incorrect.");

            let sk = EdSecretKey::from_bytes(seed).expect("Size of the seed is incorrect.");

            seed.copy_from_slice(&[0u8; 32]);
            sk
        } else {
            assert_eq!(
                in_slice.len(),
                Self::SIZE + Seed::SIZE,
                "Input size is incorrect."
            );

            let sk = EdSecretKey::from_bytes(&in_slice[Self::SIZE..])
                .expect("Size of the seed is incorrect.");

            in_slice[Self::SIZE..].copy_from_slice(&[0u8; 32]);
            sk
        };

        let public = (&secret).into();

        // We need to make this copies unfortunately by how the
        // underlying library behaves. Would be great to have a
        // EdPubKey from seed function.
        // todo: think of a redesign
        in_slice[..Self::SIZE].copy_from_slice(secret.as_bytes());

        PublicKey::from_ed25519_publickey(&public)
    }

    pub(crate) fn sign_from_slice(sk: &[u8], m: &[u8], _period: u32) -> <Self as KesSk>::Sig {
        let secret =
            EdSecretKey::from_bytes(sk).expect("Seed is defined with 32 bytes, so it won't fail.");
        let public = (&secret).into();
        let ed_sk = EdKeypair { secret, public };
        Sum0CompactKesSig(ed_sk.sign(m), public)
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
    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut output = [0u8; Self::SIZE];
        output[..SIGNATURE_LENGTH].copy_from_slice(&self.0.to_bytes());
        output[SIGNATURE_LENGTH..].copy_from_slice(self.1.as_bytes());
        output
    }
}
