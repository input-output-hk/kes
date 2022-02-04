//! Structures common to all constructions of key evolving signatures
use crate::errors::Error;
use blake2::digest::{Update, VariableOutput};
use blake2::VarBlake2b;
use ed25519_dalek as ed25519;

/// ED25519 secret key size
pub const INDIVIDUAL_SECRET_SIZE: usize = 32;
/// ED25519 signature size
pub const SIGMA_SIZE: usize = 64;

/// KES public key size (which equals the size of the output of the Hash).
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Seed of a KES scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seed;

/// KES public key, which is represented as an array of bytes. A `PublicKey`is the output
/// of a Blake2b hash.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PublicKey(pub(crate) [u8; PUBLIC_KEY_SIZE]);

impl PublicKey {
    /// Compute a KES `PublicKey` from an ed25519 key. This function convers the ed25519
    /// key into its byte representation and returns it as `Self`.
    pub fn from_ed25519_publickey(public: &ed25519::PublicKey) -> Self {
        let mut out = [0u8; PUBLIC_KEY_SIZE];
        out.copy_from_slice(public.as_bytes());
        PublicKey(out)
    }

    pub(crate) fn to_ed25519(&self) -> Result<ed25519::PublicKey, Error> {
        ed25519::PublicKey::from_bytes(self.as_bytes())
            .or(Err(Error::Ed25519InvalidCompressedFormat))
    }

    /// Return `Self` as its byte representation.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Tries to convert a slice of `bytes` as `Self`.
    ///
    /// # Errors
    /// This function returns an error if the length of `bytes` is not equal to
    /// `PUBLIC_KEY_SIZE`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() == PUBLIC_KEY_SIZE {
            let mut v = [0u8; PUBLIC_KEY_SIZE];
            v.copy_from_slice(bytes);
            Ok(PublicKey(v))
        } else {
            Err(Error::InvalidPublicKeySize(bytes.len()))
        }
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Seed {
    /// Byte representation size of a `Seed`.
    pub const SIZE: usize = 32;

    /// Function that takes as input a mutable slice, splits it into two, and overwrites the input
    /// slice with zeros.
    pub fn split_slice(bytes: &mut [u8]) -> ([u8; 32], [u8; 32]) {
        let mut left_seed = [0u8; Self::SIZE];
        let mut right_seed = [0u8; Self::SIZE];

        let mut hleft = VarBlake2b::new(32).expect("valid size");
        let mut hright = VarBlake2b::new(32).expect("valid size");

        hleft.update(&[1]);
        hleft.update(&bytes);

        hright.update(&[2]);
        hright.update(&bytes);

        // finalize() consumes the hasher instance.

        hleft.finalize_variable(|out| left_seed.copy_from_slice(out));
        hright.finalize_variable(|out| right_seed.copy_from_slice(out));

        bytes.copy_from_slice(&[0u8; Self::SIZE]);

        (left_seed, right_seed)
    }
}

/// Structure that represents the depth of the binary tree.
#[derive(Debug, Copy, Clone)]
pub struct Depth(pub usize);

impl Depth {
    /// Compute the total number of signatures one can generate with the given `Depth`
    pub fn total(self) -> usize {
        usize::pow(2, self.0 as u32)
    }

    /// Compute half of the total number of signatures one can generate with the given `Depth`
    pub fn half(self) -> usize {
        assert!(self.0 > 0);
        usize::pow(2, (self.0 - 1) as u32)
    }

    /// Returns a new `Depth` value with one less depth as `self`.
    pub fn decr(self) -> Self {
        assert!(self.0 > 0);
        Depth(self.0 - 1)
    }

    /// Returns a new `Depth` value with one more depth as `self`.
    pub fn incr(self) -> Self {
        Depth(self.0 + 1)
    }
}

impl PartialEq for Depth {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

/// Hash two public keys using Blake2b
pub fn hash(pk1: &PublicKey, pk2: &PublicKey) -> PublicKey {
    let mut out = [0u8; 32];
    let mut h = VarBlake2b::new(32).expect("valid size");
    h.update(&pk1.0);
    h.update(&pk2.0);

    h.finalize_variable(|res| out.copy_from_slice(res));
    PublicKey(out)
}
