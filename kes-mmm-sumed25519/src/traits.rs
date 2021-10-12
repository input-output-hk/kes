//! Traits that define a KES signature instance
use crate::errors::Error;
use crate::sumed25519::PublicKey;

/// Trait that defined a Kes secret key
/// todo: improve docs if we keep this public
pub trait KesSk: Sized {
    /// Type of the associated signature
    type Sig;
    /// Key generation
    fn keygen(seed: &mut [u8]) -> (Self, PublicKey);
    /// KES signature, using `self`.
    fn sign(&self, period: usize, m: &[u8]) -> Self::Sig;
    /// Update key by taking a mutable reference to `self`
    fn update(&mut self, period: usize) -> Result<(), Error>;
    /// Update key by taking a mutable reference to a slice
    fn update_slice(key_slice: &mut [u8], period: usize) -> Result<(), Error>;
}

/// Trait that defines a KES signature
pub trait KesSig: Sized {
    /// Verify the signature
    fn verify(&self, period: usize, pk: &PublicKey, m: &[u8]) -> Result<(), Error>;
}
