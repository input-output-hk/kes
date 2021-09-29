use crate::common::Seed;
use crate::errors::Error;
use crate::sumed25519::PublicKey;

pub trait KesSk: Sized {
    const SIZE: usize;
    type Sig;
    fn keygen_kes(seed: &mut Seed) -> (Self, PublicKey);
    fn sign_kes(&self, period: usize, m: &[u8]) -> Self::Sig;
    fn update_kes(&mut self, period: usize) -> Result<(), Error>;
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error>;
    fn as_bytes(&self) -> &[u8];
}

pub trait KesSig {
    fn verify_kes(&self, period: usize, pk: &PublicKey, m: &[u8]) -> Result<(), Error>;
}
