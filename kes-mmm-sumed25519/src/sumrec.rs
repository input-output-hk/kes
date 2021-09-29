//! New design of recursive functions. This will eventually fall (or be merged with sumrec).
//! Currently only used for ease of understanding.
#![allow(dead_code)]
use crate::common::{leaf_keygen, Depth, Seed};
use crate::errors::Error;
use crate::sumed25519::{hash, PublicKey};
use ed25519_dalek::{Keypair as EdKeypair, Signature as EdSignature, Signer, Verifier};
use std::cmp::Ordering;

/// A `KesSecretKey`, that can be either a `Leaf` or a `Node` depending on its position on the
/// Merkle tree.
pub enum KesSecretKey {
    /// Key is a `ed25519` keypair in case of it being a leaf
    Leaf(EdKeypair),
    /// Key is a `Box` of a recursive `SecretKey` in case of it being the node.
    Node(Box<KesRecSecretKey>),
}

impl From<EdKeypair> for KesSecretKey {
    fn from(kp: EdKeypair) -> Self {
        Self::Leaf(kp)
    }
}

impl From<KesRecSecretKey> for KesSecretKey {
    fn from(k: KesRecSecretKey) -> Self {
        Self::Node(Box::new(k))
    }
}

/// A `KesRecSecretKey` is a recursive `KesSecretKey`. As described in Figure 3 of the paper, it
/// contains a secret key `lhs_sk`, a seed `rhs_seed`, and two public keys, `lhs_pk` and `rhs_pk`.
pub struct KesRecSecretKey {
    depth: Depth,
    sk: KesSecretKey,
    seed: Seed,
    lhs_pk: PublicKey,
    rhs_pk: PublicKey,
}

/// A `KesSignature`, that can be either a `Leaf` or a `Node` depending on its position on the
/// Merkle tree.
pub enum KesSignature {
    /// In case of it being a `Leaf`, it contains an `EdSignature`.
    Leaf(EdSignature),
    /// In case of it being a `Node`, it contains a `Box` with a recursive signature `KesRecSignature`
    Node(Box<KesRecSignature>),
}

impl From<EdSignature> for KesSignature {
    fn from(sig: EdSignature) -> Self {
        Self::Leaf(sig)
    }
}

impl From<KesRecSignature> for KesSignature {
    fn from(s: KesRecSignature) -> Self {
        Self::Node(Box::new(s))
    }
}

/// A recursive KES signature as defined in Figure 3.
pub struct KesRecSignature {
    depth: Depth,
    signature: KesSignature,
    lhs_pk: PublicKey,
    rhs_pk: PublicKey,
}

/// Generate a key pair of the recursive secret key `KesRecSecretKey`.
pub fn keygen(depth: Depth, seed: &Seed) -> (KesRecSecretKey, PublicKey) {
    let (r0, seed) = seed.split_seed();
    let (sk, lhs_pk, rhs_pk) = if depth.0 == 1 {
        let (sk_0, pk_0) = leaf_keygen(&r0);
        let (_, pk_1) = leaf_keygen(&seed);
        (sk_0.into(), pk_0, pk_1)
    } else {
        let (sk_0, pk_0) = keygen(depth.decr(), &r0);
        let (_, pk_1) = keygen(depth.decr(), &seed);
        (sk_0.into(), pk_0, pk_1)
    };
    let pk = hash(&lhs_pk, &rhs_pk);
    (
        KesRecSecretKey {
            depth,
            sk,
            seed,
            lhs_pk,
            rhs_pk,
        },
        pk,
    )
}

impl KesRecSecretKey {
    /// Given a `KesRecSecretKey`, this function returns a `KesRecSignature`.
    pub fn sign(&self, period: usize, m: &[u8]) -> KesRecSignature {
        let signature = match &self.sk {
            KesSecretKey::Leaf(lhs_sk) => lhs_sk.sign(m).into(),
            KesSecretKey::Node(lhs_sk) => {
                if period < self.depth.half() {
                    lhs_sk.sign(period, m).into()
                } else {
                    lhs_sk.sign(period - self.depth.half(), m).into()
                }
            }
        };
        KesRecSignature {
            depth: self.depth,
            signature,
            lhs_pk: self.lhs_pk.clone(),
            rhs_pk: self.rhs_pk.clone(),
        }
    }

    /// Given a mutable reference to self, and the current `period`, this function overwirtes
    /// the secret key, with the updated key.
    ///
    /// # Errors
    /// This function fails if the Key can no longer be updated.
    pub fn update(&mut self, period: usize) -> Result<(), Error> {
        match &mut self.sk {
            KesSecretKey::Leaf(_) => {
                assert_eq!(period + 1, self.depth.half());
                self.sk = leaf_keygen(&self.seed).0.into();
                // todo: drop the seed.
            }
            KesSecretKey::Node(s) => {
                if period == self.depth.total() {
                    return Err(Error::KeyCannotBeUpdatedMore);
                }

                match (period + 1).cmp(&self.depth.half()) {
                    Ordering::Less => s.update(period)?,
                    Ordering::Equal => self.sk = keygen(self.depth.decr(), &self.seed).0.into(),
                    Ordering::Greater => s.update(period - self.depth.half())?,
                }
            }
        };

        Ok(())
    }
}

impl KesRecSignature {
    /// Given a `KesRecSignature`, a `period`, `PublicKey` `pk` and a message `m`, this function
    /// checks the `KES`signature.
    pub fn verify(&self, period: usize, pk: &PublicKey, m: &[u8]) -> Result<(), Error> {
        if &hash(&self.lhs_pk, &self.rhs_pk) != pk {
            return Err(Error::InvalidHashComparison);
        };

        // We compute the public key and updated period over which to verify the next signature
        let (updated_pk, updated_period) = if period < self.depth.half() {
            (&self.lhs_pk, period)
        } else {
            (&self.rhs_pk, period - self.depth.half())
        };

        match &self.signature {
            KesSignature::Leaf(s) => updated_pk.to_ed25519()?.verify(m, s).map_err(|e| e.into()),
            KesSignature::Node(s) => s.verify(updated_period, updated_pk, m),
        }
    }
}
