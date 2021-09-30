use crate::errors::Error;
use crate::sumed25519::PublicKey;

pub trait KesSk: Sized {
    type Sig;
    fn keygen_kes(seed: &mut [u8]) -> (Self, PublicKey);
    fn sign_kes(&self, period: usize, m: &[u8]) -> Self::Sig;
    fn update_kes(&mut self, period: usize) -> Result<(), Error>;
}

pub trait KesSig: Sized {
    fn verify_kes(&self, period: usize, pk: &PublicKey, m: &[u8]) -> Result<(), Error>;
}
