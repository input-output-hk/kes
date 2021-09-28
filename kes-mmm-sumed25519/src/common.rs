//! Structures common to all constructions of key evolving signatures
use crate::sumed25519::PublicKey;
use ed25519_dalek as ed25519;
use ed25519_dalek::Digest;

/// Seed of a KES scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seed([u8; 32]);

impl AsRef<[u8]> for Seed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Seed {
    /// Byte representation size of a `Seed`.
    pub const SIZE: usize = 32;

    /// Create a zero seed
    pub fn zero() -> Seed {
        Seed([0u8; Self::SIZE])
    }

    /// Takes a mutable reference of `self` and overwrites it with zero
    pub fn set_zero(&mut self) {
        self.0.copy_from_slice(&[0u8; Self::SIZE])
    }

    /// Creates a `Seed` from a byte array of length `Self::SIZE`.
    pub fn from_bytes(b: [u8; Self::SIZE]) -> Seed {
        Seed(b)
    }

    /// Creates a `Seed` from a slice.
    ///
    /// # Panics
    /// Function panics when `b.len() != Self::SIZE`.
    pub fn from_slice(b: &[u8]) -> Seed {
        assert_eq!(b.len(), Self::SIZE);
        let mut out = [0u8; Self::SIZE];
        out.copy_from_slice(b);
        Seed(out)
    }

    /// Function that takes as input an existing seed, and splits it into two. To extend the seed,
    /// the function hashes (0x01 || self.0) for the first part of the output, and (0x02 || self.0)
    /// for the second part.
    pub fn split_seed(&self) -> (Seed, Seed) {
        let mut hleft = sha2::Sha256::default();
        let mut hright = sha2::Sha256::default();

        // todo: where are these domain separations coming from? Same as Haskell impl?
        hleft.update(&[1]);
        hleft.update(&self.0);

        hright.update(&[2]);
        hright.update(&self.0);

        let o1 = hleft.finalize();
        let o2 = hright.finalize();
        let s1 = Seed::from_slice(&o1);
        let s2 = Seed::from_slice(&o2);
        (s1, s2)
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

/// Generate a Keypair for `Depth` = 0, i.e. for the standard signature scheme over which
/// we rely (in this case, `ed25519`).
pub fn leaf_keygen(r: &Seed) -> (ed25519::Keypair, PublicKey) {
    let sk = ed25519::SecretKey::from_bytes(&r.0).unwrap();
    let pk: ed25519::PublicKey = (&sk).into();
    (
        ed25519::Keypair {
            secret: sk,
            public: pk,
        },
        PublicKey::from_ed25519_publickey(&pk),
    )
}
