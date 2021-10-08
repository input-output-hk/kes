//! Traits that define a KES signature instance
use crate::errors::Error;
use crate::sumed25519::PublicKey;

/// Trait that defined a Kes secret key
/// todo: improve docs if we keep this public
pub trait KesSk: Sized {
    /// Type of the associated signature
    type Sig;
    /// Key generation
    fn keygen_kes(seed: &mut [u8]) -> (Self, PublicKey);
    /// KES signature, using `self`.
    fn sign_kes(&self, period: usize, m: &[u8]) -> Self::Sig;
    /// Update key
    fn update_kes(&mut self, period: usize) -> Result<(), Error>;
}

/// Trait that defines a KES signature
pub trait KesSig: Sized {
    /// Verify the signature
    fn verify_kes(&self, period: usize, pk: &PublicKey, m: &[u8]) -> Result<(), Error>;
}
