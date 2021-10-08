//! Implementation of MMM's SUM algorithm
use super::common;
pub use super::common::{Depth, Seed};
use super::errors::Error;
use blake2::digest::{Update, VariableOutput};
use blake2::VarBlake2b;
use ed25519_dalek as ed25519;
use ed25519_dalek::Signer;
use ed25519_dalek::Verifier;
use rand::{CryptoRng, RngCore};

/// todo: unclear what this is
const USE_TRUNCATE: bool = false;

/// Time period
type PeriodSerialized = u32;
/// Time period size in bytes
const PERIOD_SERIALIZE_SIZE: usize = 4;

/// ED25519 secret key size
pub const INDIVIDUAL_SECRET_SIZE: usize = 32;
/// ED25519 public key size
pub const INDIVIDUAL_PUBLIC_SIZE: usize = 32;
/// ED25519 signature size
pub const SIGMA_SIZE: usize = 64;

/// KES public key size (which equals the size of the output of the Hash).
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Secret Key in the binary tree sum composition of the ed25519 scheme. As described in Figure 3,
/// a `SecretKey` is constituted by a `SecretKey` of depth = `Depth` - 1, the right part of the
/// extended seed, and two `PublicKeys`.
///
/// By representing the `SecretKey` with a vector, the caller of the function can map the content
/// of the key to erasable buffer. This allows the key to be mutated in place on filesystem with
/// reasonable guarantee, and therefore, delete the previous keys and/or seeds.
///
/// In particular, the format in which we represent the secret key within the vector is
/// as follows:
///
/// * period
/// * keypair : ED25519 keypair
/// * pks : depth size of left and right public keys
/// * rs : Stack of right seed for updates
///
/// The reason for having the seeds at the end, is because during the `update` call, a seed
/// is deleted. By having them at the end, this does not affect the positioning of the rest of
/// elements of the key.
#[derive(Clone)]
pub struct SecretKey {
    depth: Depth,
    data: Vec<u8>,
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

/// const function that computes the minimum size of `SecretKey`. It leaves aside the seeds. This
/// represents the smalles possible key size, where all seeds have been deleted. Note that when a
/// key is updated, the seed used to generate the latest version of the key is deleted.
pub const fn minimum_secretkey_size(depth: Depth) -> usize {
    PERIOD_SERIALIZE_SIZE
        + INDIVIDUAL_SECRET_SIZE + INDIVIDUAL_PUBLIC_SIZE // keypair
        + depth.0 * 2 * PUBLIC_KEY_SIZE
}

/// const function that computest the maximum size of `SecretKey`. This size consists of all seeds,
/// i.e., it represents the initial size of the `SecretKey`.
pub const fn maximum_secretkey_size(depth: Depth) -> usize {
    PERIOD_SERIALIZE_SIZE
        + INDIVIDUAL_SECRET_SIZE + INDIVIDUAL_PUBLIC_SIZE // keypair
        + depth.0 * 2 * PUBLIC_KEY_SIZE
        + depth.0 * Seed::SIZE
}

/// Structure representing the `PublicKey`s used to compute the merkle tree root.
pub struct MerklePublicKeys<'a>(&'a [u8]);

impl<'a> MerklePublicKeys<'a> {
    /// Generate a new `MerklePublicKeys` structure given an array of bytes.
    ///
    /// # Panics
    /// Fails when the length of the data is not divisible by `PUBLIC_KEY_SIZE * 2`.
    pub fn new(data: &'a [u8]) -> Self {
        assert_eq!(data.len() % (PUBLIC_KEY_SIZE * 2), 0);
        MerklePublicKeys(data)
    }
}

/// Iterator that removes and returns the next pair of keys  of `MerklePublicKeys`. It returns them
/// as `PublicKey` pairs instead of slices.
impl<'a> Iterator for MerklePublicKeys<'a> {
    type Item = (PublicKey, PublicKey);

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            None
        } else {
            let mut datl = [0u8; PUBLIC_KEY_SIZE];
            let mut datr = [0u8; PUBLIC_KEY_SIZE];
            datl.copy_from_slice(&self.0[0..PUBLIC_KEY_SIZE]);
            datr.copy_from_slice(&self.0[PUBLIC_KEY_SIZE..PUBLIC_KEY_SIZE * 2]);
            *self = MerklePublicKeys::new(&self.0[PUBLIC_KEY_SIZE * 2..]);
            Some((PublicKey(datl), PublicKey(datr)))
        }
    }
}

/// Iterator that removes and returns the last pair of keys  of `MerklePublicKeys`. It returns them
/// as `PublicKey` pairs instead of slices.
impl<'a> DoubleEndedIterator for MerklePublicKeys<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            None
        } else {
            let mut datl = [0u8; PUBLIC_KEY_SIZE];
            let mut datr = [0u8; PUBLIC_KEY_SIZE];
            let last_offset = self.0.len() - (PUBLIC_KEY_SIZE * 2);
            datl.copy_from_slice(&self.0[last_offset..last_offset + PUBLIC_KEY_SIZE]);
            datr.copy_from_slice(
                &self.0[last_offset + PUBLIC_KEY_SIZE..last_offset + PUBLIC_KEY_SIZE * 2],
            );
            *self = MerklePublicKeys::new(&self.0[0..last_offset]);
            Some((PublicKey(datl), PublicKey(datr)))
        }
    }
}

impl<'a> ExactSizeIterator for MerklePublicKeys<'a> {
    fn len(&self) -> usize {
        self.0.len() / (PUBLIC_KEY_SIZE * 2)
    }
}

/// Structure representing the `Seed`s used to compute the merkle tree root. Represented as slices.
pub struct Seeds<'a>(&'a [u8]);

/// Iterator that removes and returns the next pair of keys  of `Seed`. It returns them
/// as `Seed` instead of slices.
impl<'a> Iterator for Seeds<'a> {
    type Item = Seed;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            None
        } else {
            let seed = Seed::from_slice(&self.0[0..Seed::SIZE]);
            *self = Seeds(&self.0[Seed::SIZE..]);
            Some(seed)
        }
    }
}

/// Iterator that removes and returns the last pair of keys  of `Seed`. It returns them
/// as `Seed` instead of slices.
impl<'a> ExactSizeIterator for Seeds<'a> {
    fn len(&self) -> usize {
        self.0.len() / Seed::SIZE
    }
}

/// Returns the different between the number of ones in the binary representation of depth minus the
/// number of ones in the binary representation of t.
fn rs_from_period(depth: Depth, t: usize) -> u32 {
    let bits = (depth.total() - 1).count_ones();
    bits - t.count_ones()
}

impl SecretKey {
    /// Position of the period in `Self::data`.
    const T_OFFSET: usize = 0;
    /// Position of the keypair in `Self::data`.
    const KEYPAIR_OFFSET: usize = Self::T_OFFSET + PERIOD_SERIALIZE_SIZE;
    /// Position of the public keys in `Self::data`.
    const MERKLE_PKS_OFFSET: usize =
        Self::KEYPAIR_OFFSET + INDIVIDUAL_SECRET_SIZE + INDIVIDUAL_PUBLIC_SIZE;
    /// position of the seeds in `Self::data`.
    const fn seed_offset(depth: Depth) -> usize {
        Self::MERKLE_PKS_OFFSET + depth.0 * PUBLIC_KEY_SIZE * 2
    }

    /// Position of the `ith` seed within `Self::data`.
    const fn seed_offset_index(depth: Depth, i: usize) -> usize {
        Self::seed_offset(depth) + i * Seed::SIZE
    }

    // --------------------------------------
    // accessors
    /// Get the period of the current secret key
    pub fn t(&self) -> usize {
        let mut t = [0u8; PERIOD_SERIALIZE_SIZE];
        t.copy_from_slice(&self.data[0..PERIOD_SERIALIZE_SIZE]);
        PeriodSerialized::from_le_bytes(t) as usize
    }

    /// Get the ed25519 signing key associated with `Self`.
    ///
    /// # Panics
    /// Function fails if the bytes in the position of the `ed25519::Keypair` do not represent
    /// a valid key.
    pub fn sk(&self) -> ed25519::Keypair {
        let bytes = &self.data[Self::KEYPAIR_OFFSET..Self::MERKLE_PKS_OFFSET];
        ed25519::Keypair::from_bytes(bytes).expect("internal error: keypair invalid")
    }

    #[doc(hidden)]
    // Get the public keys
    pub fn merkle_pks(&self) -> MerklePublicKeys<'_> {
        let bytes = &self.data[Self::MERKLE_PKS_OFFSET..Self::seed_offset(self.depth)];
        MerklePublicKeys::new(bytes)
    }

    #[doc(hidden)]
    // Get the seeds
    pub fn rs(&self) -> Seeds<'_> {
        let start = Self::seed_offset(self.depth);
        let end = start + (self.rs_len() as usize * Seed::SIZE);
        let bytes = &self.data[start..end];
        if USE_TRUNCATE {
            let checked_bytes = &self.data[Self::seed_offset(self.depth)..];
            assert_eq!(checked_bytes.len(), self.rs_len() as usize * Seed::SIZE);
        }
        Seeds(bytes)
    }

    #[doc(hidden)]
    // todo: not sure I understand this function...
    pub fn rs_len(&self) -> u32 {
        rs_from_period(self.depth(), self.t())
    }

    // --setters
    fn set_t(&mut self, t: usize) {
        let t_bytes = PeriodSerialized::to_le_bytes(t as PeriodSerialized);
        let out = &mut self.data[0..PERIOD_SERIALIZE_SIZE];
        out.copy_from_slice(&t_bytes)
    }

    fn set_sk(&mut self, sk: &ed25519::Keypair) {
        let out = &mut self.data[Self::KEYPAIR_OFFSET..Self::MERKLE_PKS_OFFSET];
        out.copy_from_slice(&sk.to_bytes());
    }

    fn set_merkle_pks(&mut self, n: usize, pks: &(PublicKey, PublicKey)) {
        let bytes = &mut self.data[Self::MERKLE_PKS_OFFSET..Self::seed_offset(self.depth)];
        let startl = n * PUBLIC_KEY_SIZE * 2;
        let startr = startl + PUBLIC_KEY_SIZE;
        let end = startr + PUBLIC_KEY_SIZE;
        bytes[startl..startr].copy_from_slice(pks.0.as_ref());
        bytes[startr..end].copy_from_slice(pks.1.as_ref());
    }

    // --
    // Get then `n`th `PublicKey` pair
    fn get_merkle_pks(&self, n: usize) -> (PublicKey, PublicKey) {
        let bytes = &self.data[Self::MERKLE_PKS_OFFSET..Self::seed_offset(self.depth)];
        let startl = n * PUBLIC_KEY_SIZE * 2;
        let startr = startl + PUBLIC_KEY_SIZE;
        let end = startr + PUBLIC_KEY_SIZE;

        let mut datl = [0u8; PUBLIC_KEY_SIZE];
        let mut datr = [0u8; PUBLIC_KEY_SIZE];
        datl.copy_from_slice(&bytes[startl..startr]);
        datr.copy_from_slice(&bytes[startr..end]);
        (PublicKey(datl), PublicKey(datr))
    }

    /// Compute the master public key going through all public keys.
    // todo: wouldn't it be sufficient to simply hash the top two?
    pub fn compute_public(&self) -> PublicKey {
        let t = self.t();
        let mut got = PublicKey::from_ed25519_publickey(&self.sk().public);
        for (i, (pk_left, pk_right)) in self.merkle_pks().rev().enumerate() {
            let right = (t & (1 << i)) != 0;
            if right {
                got = hash(&pk_left, &got);
            } else {
                got = hash(&got, &pk_right);
            }
        }
        got
    }

    /// Create a secret key for time period `t`, given a ed25519 keypair, an array of public key
    /// pairs, and an array of `Seed`s.
    fn create(
        t: usize,
        keypair: ed25519::Keypair,
        pks: &[(PublicKey, PublicKey)],
        rs: &[Seed],
    ) -> Self {
        let depth = Depth(pks.len());
        let mut out = Vec::with_capacity(maximum_secretkey_size(depth));

        let t_bytes = PeriodSerialized::to_le_bytes(t as PeriodSerialized);
        out.extend_from_slice(&t_bytes);
        assert_eq!(out.len(), Self::KEYPAIR_OFFSET);
        out.extend_from_slice(&keypair.to_bytes());
        assert_eq!(out.len(), Self::MERKLE_PKS_OFFSET);
        for (pkl, pkr) in pks {
            out.extend_from_slice(&pkl.0);
            out.extend_from_slice(&pkr.0);
        }
        assert_eq!(out.len(), Self::seed_offset(depth));
        for r in rs {
            out.extend_from_slice(r.as_ref());
        }

        assert_eq!(out.len(), maximum_secretkey_size(depth));

        SecretKey { depth, data: out }
    }

    /// Pop the latest seed and overwrite with zeros its position in the buffer.
    pub fn rs_pop(&mut self) -> Option<Seed> {
        if USE_TRUNCATE {
            let seed_offset = Self::seed_offset(self.depth);
            let rs_x = self.rs_len();
            let seed_data_len = self.data.len() - seed_offset;
            assert_eq!(rs_x as usize * Seed::SIZE, seed_data_len);

            if self.data.len() - seed_offset > 0 {
                // grab the last seed
                let last = self.data.len() - Seed::SIZE;
                let seed = Seed::from_slice(&self.data[last..]);
                // clear the seed memory in the secret key, then truncate
                self.data[last..].copy_from_slice(&[0u8; Seed::SIZE]);
                self.data.truncate(last);
                Some(seed)
            } else {
                None
            }
        } else {
            let rs_len = self.rs_len();
            if rs_len == 0 {
                None
            } else {
                let start = Self::seed_offset_index(self.depth, rs_len as usize - 1);
                let slice = &mut self.data[start..start + Seed::SIZE];
                let seed = Seed::from_slice(slice);
                slice.copy_from_slice(&[0u8; Seed::SIZE]);
                Some(seed)
            }
        }
    }

    /// ?
    pub fn rs_extend(&mut self, seed_offset: usize, rs: Seeds<'_>) {
        if USE_TRUNCATE {
            let seed_start = Self::seed_offset(self.depth);
            let extend_start = seed_offset * Seed::SIZE;

            let expected = self.data.len() - seed_start;
            assert_eq!(extend_start, expected);

            for r in rs {
                self.data.extend_from_slice(r.as_ref())
            }
        } else {
            let current = seed_offset as u32;
            let expect = rs_from_period(self.depth(), self.t() + 1);
            let diff = expect - current;
            let start = Self::seed_offset_index(self.depth, seed_offset);
            let end = start + diff as usize * Seed::SIZE;
            self.data[start..end].copy_from_slice(rs.0)
        }
    }

    /// Returns the depth of the key
    pub fn depth(&self) -> Depth {
        self.depth
    }

    /// Returns whether the key is updatable. A key is updatable if its current period is smaller
    /// or equal than 2^{self.depth}
    pub fn is_updatable(&self) -> bool {
        self.t() + 1 < self.depth.total()
    }

    /// Returns `Self` from a given array of bytes.
    ///
    /// # Error
    /// If some of this conditions validate:
    /// * `bytes` input is smaller (or greater) than the minimum (or maximum respectively) accepted
    /// size of a key of a given depth
    /// * `bytes` size starting at the `SEED_OFFSET` is not divisible by the `seed` size
    /// * the `ed25519::Keypair` cannot be generated from the bytes at its corresponding position
    /// * the period of the input key is greater than that allowed by the depth
    ///
    /// the function returns an error.
    pub fn from_bytes(depth: Depth, bytes: &[u8]) -> Result<Self, Error> {
        let minimum_size = Self::seed_offset(depth);
        if bytes.len() < minimum_size {
            return Err(Error::InvalidSecretKeySize(bytes.len()));
        }

        let rem = (bytes.len() - minimum_size) % 32;
        if rem > 0 {
            return Err(Error::InvalidSecretKeySize(bytes.len()));
        }

        if USE_TRUNCATE {
            // get T and make sure it's under the total
            let mut t_bytes = [0u8; PERIOD_SERIALIZE_SIZE];
            t_bytes.copy_from_slice(&bytes[0..PERIOD_SERIALIZE_SIZE]);
            let t = PeriodSerialized::from_le_bytes(t_bytes) as usize;
            if t >= depth.total() {
                return Err(Error::InvalidSignatureCount(t, depth));
            }

            let keypair_slice = &bytes[Self::KEYPAIR_OFFSET..Self::MERKLE_PKS_OFFSET];

            // verify sigma and pk format, no need to verify pks nor rs
            let _ = ed25519::Keypair::from_bytes(keypair_slice)?;

            let mut out = Vec::with_capacity(bytes.len());
            out.extend_from_slice(bytes);
            Ok(SecretKey { depth, data: out })
        } else {
            if bytes.len() != maximum_secretkey_size(depth) {
                return Err(Error::InvalidSecretKeySize(bytes.len()));
            }

            let keypair_slice = &bytes[Self::KEYPAIR_OFFSET..Self::MERKLE_PKS_OFFSET];
            let _ = ed25519::Keypair::from_bytes(keypair_slice)?;

            let mut tbuf = [0u8; PERIOD_SERIALIZE_SIZE];
            tbuf.copy_from_slice(&bytes[0..PERIOD_SERIALIZE_SIZE]);
            let t = PeriodSerialized::from_le_bytes(tbuf) as usize;

            if t >= depth.total() {
                return Err(Error::InvalidSignatureCount(t, depth));
            }

            let expected_rs = rs_from_period(depth, t);
            let start_of_zeroes = Self::seed_offset_index(depth, expected_rs as usize);
            let all_zeroes = bytes[start_of_zeroes..].iter().all(|b| *b == 0);
            if !all_zeroes {
                return Err(Error::DataInZeroArea);
            }

            let out = bytes.to_owned();

            Ok(SecretKey { depth, data: out })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// KES public key, which is represented as an array of bytes. A `PublicKey`is the output
/// of a Blake2b hash.
pub struct PublicKey([u8; PUBLIC_KEY_SIZE]);

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

/// Signature using the repetitive MMM sum composition
///
/// Serialization:
/// * period
/// * sigma : ED25519 individual signature linked to period
/// * ED25519 public key of this period
/// * public keys : merkle tree path elements
#[derive(Clone)]
pub struct Signature {
    depth: Depth,
    period: u32,
    sigma: ed25519::Signature,
    public_key: ed25519::PublicKey,
    merkle_pks: MerkleSignaturePublicKeys,
}

/// Structure representing the `PublicKey`s used to compute the merkle tree root in
/// a signature.
pub type MerkleSignaturePublicKeys = Vec<PublicKey>;

/// Return the expected signature size of a signature with the given `depth`.
pub const fn signature_size(depth: Depth) -> usize {
    PERIOD_SERIALIZE_SIZE + SIGMA_SIZE + INDIVIDUAL_PUBLIC_SIZE + depth.0 * PUBLIC_KEY_SIZE
}

impl Signature {
    /// Compute the size in bytes of a signature
    /// currently this is : 100 (4 + 64 + 32) + 32*depth()
    pub fn size_bytes(&self) -> usize {
        signature_size(self.depth)
    }

    /// Get the bytes representation of the signature
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            PERIOD_SERIALIZE_SIZE
                + SIGMA_SIZE
                + INDIVIDUAL_PUBLIC_SIZE
                + self.depth.0 * PUBLIC_KEY_SIZE,
        );
        bytes.extend_from_slice(&self.period.to_le_bytes());
        bytes.extend_from_slice(&self.sigma.to_bytes());
        bytes.extend_from_slice(&self.public_key.to_bytes());
        for key in self.merkle_pks.iter() {
            bytes.extend_from_slice(&key.0);
        }
        bytes
    }

    /// Create a `Signature` from the given byte array.
    ///
    /// # Error
    /// The function returns an error if:
    /// * `bytes.len()` is not equal to the expected signature size with the given `depth`.
    /// * the period in `bytes` is above the threshold allowed by `depth`.
    /// * the ed25519 public key in `bytes` does not correspond to a valid point in the elliptic
    ///   curve.
    pub fn from_bytes(depth: Depth, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != signature_size(depth) {
            return Err(Error::InvalidSignatureSize(bytes.len()));
        }

        let mut t_bytes = [0u8; PERIOD_SERIALIZE_SIZE];
        t_bytes.copy_from_slice(&bytes[0..PERIOD_SERIALIZE_SIZE]);
        let period = PeriodSerialized::from_le_bytes(t_bytes);
        if period as usize >= depth.total() {
            return Err(Error::InvalidSignatureCount(period as usize, depth));
        }

        let merkle_pks_offset = PERIOD_SERIALIZE_SIZE + SIGMA_SIZE + INDIVIDUAL_PUBLIC_SIZE;
        let mut sigma_slice = [0u8; SIGMA_SIZE];
        sigma_slice
            .copy_from_slice(&bytes[PERIOD_SERIALIZE_SIZE..PERIOD_SERIALIZE_SIZE + SIGMA_SIZE]);
        let sigma = ed25519::Signature::new(sigma_slice);
        let public_key = ed25519::PublicKey::from_bytes(
            &bytes[PERIOD_SERIALIZE_SIZE + SIGMA_SIZE..merkle_pks_offset],
        )?;

        let mut merkle_pks = Vec::with_capacity(depth.0);
        let mut temp_key = [0; PUBLIC_KEY_SIZE];

        for i in 0..depth.0 {
            temp_key.copy_from_slice(
                bytes[merkle_pks_offset + i * PUBLIC_KEY_SIZE
                    ..merkle_pks_offset + (i + 1) * PUBLIC_KEY_SIZE]
                    .into(),
            );
            merkle_pks.push(PublicKey(temp_key));
        }

        Ok(Signature {
            depth,
            period,
            sigma,
            public_key,
            merkle_pks,
        })
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

/// Given a mutable reference of a `Seed` vector, this function writes all seeds generated
/// throughout the way, and returns the leftmost `ed25519::KeyPair`, i.e. the key with `t=0`
fn generate_leftmost_rs(
    rs: &mut Vec<Seed>,
    log_depth: Depth,
    master: &Seed,
) -> (ed25519::Keypair, PublicKey) {
    let mut depth = log_depth;
    let mut r = master.clone();
    loop {
        let (r0, r1) = r.split_seed();
        rs.push(r1);
        if depth.0 == 1 {
            return common::leaf_keygen(&r0);
        } else {
            r = r0;
        }
        depth = depth.decr();
    }
}

/// Generate the public key from a specific level and a given seed
///
/// the following assumption hold:
///     pkeygen(depth, master) == keygen(depth, master).1
///
/// This is faster than using keygen directly
pub fn pkeygen(log_depth: Depth, master: &Seed) -> PublicKey {
    if log_depth.0 == 0 {
        return common::leaf_keygen(master).1;
    }
    // first r1 is the topmost
    let mut rs = Vec::new();

    // generate the leftmost sk, pk, and accumulate all r1
    let (_, mut pk_left) = generate_leftmost_rs(&mut rs, log_depth, master);

    let mut depth = Depth(0);
    // append to storage from leaf to root
    for r in rs.iter().rev() {
        let pk_right = if depth.0 == 0 {
            common::leaf_keygen(r).1
        } else {
            pkeygen(depth, r)
        };
        depth = depth.incr();
        pk_left = hash(&pk_left, &pk_right);
    }
    pk_left
}

/// Generate a keypair of a specific depth with the given random number generator
pub fn generate<T: RngCore + CryptoRng>(mut rng: T, depth: Depth) -> (SecretKey, PublicKey) {
    let mut priv_bytes = [0u8; common::Seed::SIZE];
    rng.fill_bytes(&mut priv_bytes);

    let seed = common::Seed::from_bytes(priv_bytes);

    keygen(depth, &seed)
}

/// Generate a keypair using the seed as master seed for the tree of depth log_depth
///
/// After creation the secret key is updatable 2^log_depth, and contains
/// the 0th version of the secret key.
pub fn keygen(log_depth: Depth, master: &Seed) -> (SecretKey, PublicKey) {
    if log_depth.0 == 0 {
        let (sk, pk) = common::leaf_keygen(master);
        return (SecretKey::create(0, sk, &[], &[]), pk);
    }

    // first r1 is the topmost
    let mut rs = Vec::new();

    // generate the leftmost sk, pk, and accumulate all r1
    let (sk0, mut pk_left) = generate_leftmost_rs(&mut rs, log_depth, master);

    let mut depth = Depth(0);
    let mut pks = Vec::new();
    // append to storage from leaf to root
    for r in rs.iter().rev() {
        let pk_right = if depth.0 == 0 {
            // if it is the initial, simply generate a ed25519 key
            common::leaf_keygen(r).1
        } else {
            // otherwise, recursively compute the corresponding hash
            pkeygen(depth, r)
        };
        // Include both keys to my list of pks
        pks.push((pk_left.clone(), pk_right.clone()));
        // todo: what if we take a mutable reference instead?
        depth = depth.incr();
        // update pk_left as the hash of the two current ones.
        pk_left = hash(&pk_left, &pk_right);
    }
    // then store pk{left,right} from root to leaf
    pks.reverse();
    assert_eq!(log_depth.0, pks.len());

    (SecretKey::create(0, sk0, &pks, &rs), pk_left)
}

/// Returns a KES signature for message `m` which is valid with respect to the root public key of
/// `secret`.
pub fn sign(secret: &SecretKey, m: &[u8]) -> Signature {
    let sk = secret.sk();
    let sigma = sk.sign(m);
    let mut merkle_pks = Vec::new();
    let mut t = secret.t();

    // re-Create the merkle tree path with the given public keys.
    for (i, (pk0, pk1)) in secret.merkle_pks().enumerate() {
        let d = Depth(secret.depth().0 - i);
        if t >= d.half() {
            t -= d.half();
            merkle_pks.push(pk0.clone());
        } else {
            merkle_pks.push(pk1.clone());
        }
    }

    Signature {
        depth: secret.depth,
        period: secret.t() as u32,
        sigma,
        public_key: sk.public,
        merkle_pks,
    }
}

/// Verify a KES signatures `sig`, under a given KES public key `pk`. This function checks that the
/// base signature is valid, and that the KES public key `pk` corresponds to the merkle tree root
/// given by the hash values available in the signature.
pub fn verify(pk: &PublicKey, m: &[u8], sig: &Signature) -> bool {
    // verify the signature of the leaf
    if sig.public_key.verify(m, &sig.sigma).is_err() {
        return false;
    }

    let t = sig.period;

    // verify that we have the expected root public key afterall
    let mut got = PublicKey::from_ed25519_publickey(&sig.public_key);
    for (i, pk_combi) in sig.clone().merkle_pks.into_iter().rev().enumerate() {
        let right = (t & (1 << i)) != 0;
        if right {
            got = hash(&pk_combi, &got);
        } else {
            got = hash(&got, &pk_combi);
        }
    }
    if &got != pk {
        return false;
    }
    true
}

/// This function takes a mutable reference of a KES `SecretKey`. The function overwrites the
/// bytes in the position of the keypair with the next key, and pops the next used seed. When
/// the pop happens, the memory is overwritten with zeros.
///
/// In order to have some guarantees that the memory is safely deleted, the caller of the function
/// must map the content of the `SecreKey` to erasable buffer, allowing for an in place mutation
/// on filesystem with.
///
/// # Errors
/// The function returns an error if it can no longer be updated, i.e. if the period went over the
/// maximum allowed by the associated depth.
pub fn update(secret: &mut SecretKey) -> Result<(), Error> {
    //assert!(secret.t() < secret.depth().total());
    // this value tells us whether we are on the lhs of a leaf (diff = 1), or if we are on the
    // rhs of a leaf (diff >= 2). This tells us how many carries there's been.
    let diff = usize::count_ones(secret.t() ^ (secret.t() + 1));
    assert!(diff >= 1); // What is the point of this assertion?

    // We get the next seed (and overwrite it with zeroes).
    match secret.rs_pop() {
        None => Err(Error::KeyCannotBeUpdatedMore),
        Some(seed) => {
            // If we are on the lhs of a leaf, we simply generate the key pair with the seed.
            if diff == 1 {
                let (sk, _) = common::leaf_keygen(&seed);
                secret.set_sk(&sk);
            } else {
                // If we are on the rhs of a leaf, it means that the "next" seed, is that of the
                // higher level. The difference tells us the height of the seed we have. We use that
                // to generate a new key with the corresponding Depth.
                let (sec_child, pub_child) = keygen(Depth((diff - 1) as usize), &seed);
                // Here we are checking the KES Public key, and not the ed25519 key
                assert_eq!(
                    secret.get_merkle_pks(secret.depth().0 - diff as usize).1,
                    pub_child
                );
                let rs_x = secret.rs_len() as usize - 1;

                secret.rs_extend(rs_x, sec_child.rs());
                let offset = secret.merkle_pks().len() - sec_child.merkle_pks().len();
                for (i, c) in sec_child.merkle_pks().enumerate() {
                    secret.set_merkle_pks(offset + i, &c)
                }
                secret.set_sk(&sec_child.sk());
            }
            secret.set_t(secret.t() + 1);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::sumrec;
    use quickcheck::{Arbitrary, Gen};

    impl Arbitrary for Seed {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let mut b = [0u8; 32];
            for v in b.iter_mut() {
                *v = Arbitrary::arbitrary(g)
            }
            Seed::from_bytes(b)
        }
    }
    impl Arbitrary for Depth {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            // We don't want depth = 0. It only makes sense with > 0. And we %4 to have a few less
            // options. Otherwise, testing takes too long.
            Depth(usize::arbitrary(g) % 4 + 1)
        }
    }

    pub fn exhaustive_signing(depth: Depth) {
        let s = Seed::zero();
        let (mut sk, pk) = keygen(depth, &s);
        let m = [1, 2, 3];

        let pk_public = pkeygen(depth, &s);
        assert_eq!(pk, pk_public);

        for i in 0..depth.total() {
            let sig = sign(&sk, &m);
            let v = verify(&pk, &m, &sig);
            assert_eq!(v, true, "key {} failed verification", i);
            if sk.is_updatable() {
                update(&mut sk).unwrap();
            }

            let sigdata = sig.as_bytes();
            assert_eq!(signature_size(depth), sigdata.len())
        }
    }

    fn secretkey_identical(sk: &[u8], expected: &[u8]) {
        assert_eq!(sk, expected)
    }

    #[test]
    pub fn d1_testvect() {
        let s = Seed::zero();
        let (mut sk, pk) = keygen(Depth(1), &s);

        secretkey_identical(
            &sk.sk().to_bytes(),
            &[
                66, 139, 76, 239, 77, 29, 24, 24, 5, 115, 119, 195, 241, 70, 216, 222, 255, 237,
                237, 15, 237, 41, 120, 41, 73, 189, 238, 116, 154, 117, 181, 236, 0, 51, 159, 203,
                83, 114, 117, 147, 134, 123, 163, 19, 124, 46, 131, 246, 201, 54, 27, 207, 235,
                149, 97, 207, 56, 82, 208, 76, 189, 187, 133, 203,
            ],
        );
        assert_eq!(update(&mut sk).is_ok(), true);
        secretkey_identical(
            &sk.sk().to_bytes(),
            &[
                15, 215, 229, 255, 142, 152, 79, 220, 219, 176, 87, 167, 140, 199, 154, 105, 227,
                110, 134, 224, 70, 136, 28, 196, 49, 99, 97, 24, 48, 167, 156, 4, 58, 206, 140,
                206, 135, 144, 159, 148, 221, 159, 149, 178, 239, 119, 50, 40, 110, 211, 120, 107,
                10, 145, 147, 233, 27, 220, 40, 171, 234, 19, 175, 124,
            ],
        );

        assert_eq!(
            pk.as_ref(),
            &[
                115, 239, 224, 116, 157, 4, 167, 209, 27, 50, 147, 108, 54, 130, 97, 155, 82, 92,
                141, 199, 182, 174, 92, 244, 71, 246, 121, 131, 117, 8, 188, 103
            ]
        );
    }

    #[test]
    pub fn check_public_is_recomputable() {
        let (mut sk, pk) = keygen(Depth(4), &Seed::zero());

        assert_eq!(sk.compute_public(), pk);
        assert_eq!(update(&mut sk).is_ok(), true);
        assert_eq!(sk.compute_public(), pk);
        assert_eq!(update(&mut sk).is_ok(), true);
        assert_eq!(sk.compute_public(), pk);
    }

    #[test]
    pub fn working_depth1() {
        exhaustive_signing(Depth(1));
    }

    #[test]
    pub fn working_depth2_8() {
        for i in 2..8 {
            exhaustive_signing(Depth(i));
        }
    }

    #[quickcheck]
    fn check_public(depth: Depth, seed: Seed) -> bool {
        let (_, pk) = keygen(depth, &seed);
        let pk_pub = pkeygen(depth, &seed);
        pk == pk_pub
    }

    #[quickcheck]
    fn check_sig(depth: Depth, seed: Seed) -> bool {
        let (sk, pk) = keygen(depth, &seed);

        let m = b"Arbitrary message";

        let sig = sign(&sk, m);
        verify(&pk, m, &sig)
    }

    #[quickcheck]
    fn check_recver_equivalent(depth: Depth, seed: Seed) -> bool {
        let (_, pk) = keygen(depth, &seed);

        let (_, pkrec) = sumrec::keygen(depth, &seed);
        pk.as_bytes() == pkrec.as_bytes()
    }

    #[quickcheck]
    fn check_verification_ref(depth: Depth, seed: Seed) -> bool {
        let (mut sk_ref, pk_ref) = sumrec::keygen(depth, &seed);

        let random_message = b"tralala";
        for period in 0..(depth.total() - 1) {
            let signature = sk_ref.sign(period, random_message);
            assert!(signature.verify(period, &pk_ref, random_message).is_ok());
            assert!(sk_ref.update(period).is_ok());
        }
        true
    }
}
