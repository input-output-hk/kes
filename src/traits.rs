//! Traits that define a KES signature instance
use crate::common::PublicKey;
use crate::errors::Error;

/// Trait that defined a Kes secret key
pub trait KesSk: Sized {
    /// Type of the associated signature
    type Sig;
    /// Key generation
    fn keygen(seed: &mut [u8]) -> (Self, PublicKey);
    /// KES signature, using `self`.
    fn sign(&self, m: &[u8]) -> Self::Sig;
    /// Update key by taking a mutable reference to `self`
    fn update(&mut self) -> Result<(), Error>;
    /// Update key by taking a mutable reference to a slice
    fn update_slice(key_slice: &mut [u8], period: u32) -> Result<(), Error>;
}

/// Trait that defines a KES signature
///
/// # Example
/// ```
/// use kes_summed_ed25519::kes::Sum6Kes;
/// use kes_summed_ed25519::traits::{KesSig, KesSk};
///
/// let (mut skey, pkey) = Sum6Kes::keygen(&mut [0u8; 32]);
/// let dummy_message = b"tilin";
/// let sigma = skey.sign(dummy_message);
///
/// assert!(sigma.verify(0, &pkey, dummy_message).is_ok());
///
/// // Key can be updated 63 times
/// for _ in 0..63 {
///     assert!(skey.update().is_ok());
/// }
/// ```
pub trait KesSig: Sized {
    /// Verify the signature
    fn verify(&self, period: u32, pk: &PublicKey, m: &[u8]) -> Result<(), Error>;
}

/// Trait that defined a CompactKES signature. Instead of recursively verifying, we simply
/// verify once (equality with the root), and else we recompute the root of the subtree.
/// When we reach the leaf, we also verify the ed25519 signature.
pub trait KesCompactSig: Sized {
    /// Verify the root equality
    fn verify(&self, period: u32, pk: &PublicKey, m: &[u8]) -> Result<(), Error> {
        let pk_subtree = self.recompute(period, m)?;
        if pk == &pk_subtree {
            return Ok(());
        }
        Err(Error::InvalidHashComparison)
    }
    /// Recompute the root of the subtree, and verify ed25519 if on leaf
    fn recompute(&self, period: u32, m: &[u8]) -> Result<PublicKey, Error>;
}
