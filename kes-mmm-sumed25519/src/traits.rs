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

/// Trait that defined a CompactKES signature. Instead of recursively verifying, we simply
/// verify once (equality with the root), and else we recompute the root of the subtree.
/// When we reach the leaf, we also verify the ed25519 signature.
pub trait KesCompactSig: Sized {
    /// Verify the root equality
    fn verify(&self, period: usize, pk: &PublicKey, m: &[u8]) -> Result<(), Error> {
        let pk_subtree = self.recompute(period, m)?;
        if pk == &pk_subtree {
            return Ok(())
        }
        return Err(Error::InvalidHashComparison)
    }
    /// Recompute the root of the subtree, and verify ed25519 if on leaf
    fn recompute(&self, period: usize, m: &[u8]) -> Result<PublicKey, Error>;
}
