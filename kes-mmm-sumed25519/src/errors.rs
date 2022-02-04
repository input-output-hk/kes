//! Errors specific to KES signatures
use crate::common::Depth;
use ed25519_dalek as ed25519;

#[derive(Debug, Clone)]
/// Enum of error associated with KES signatures
pub enum Error {
    /// This error occurs when a base signature (ed25519) is invalid.
    Ed25519Signature(String),
    /// This error occurs when a slice of bytes is converted into a compressed
    /// point format, and it fails.
    Ed25519InvalidCompressedFormat,
    /// Error occurs when the size of the secret key is not the expected.
    InvalidSecretKeySize(usize),
    /// Error occurs when the size of the public key is not the expected.
    InvalidPublicKeySize(usize),
    /// Error occurs when the size of the signature is not the expected.
    InvalidSignatureSize(usize),
    /// Error occurs when the period associated with a signature is higher than the threshold
    /// allowed by the given `Depth`.
    InvalidSignatureCount(usize, Depth),
    /// Error that occurs when some expected data is found in an only zero slice.
    DataInZeroArea,
    /// This error occurs when a key that cannot be updated (the period has reached the allowed
    /// threshold) tries to be updated.
    KeyCannotBeUpdatedMore,
    /// This error occurs when the comparison of two hashes that are expected to be equal fail.
    InvalidHashComparison,
}

impl From<ed25519::SignatureError> for Error {
    fn from(sig: ed25519::SignatureError) -> Error {
        Error::Ed25519Signature(format!("{:?}", sig))
    }
}
