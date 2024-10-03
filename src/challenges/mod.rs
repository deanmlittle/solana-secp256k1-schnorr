use solana_secp256k1::Secp256k1Point;

/// ### Secp256k1SchnorrChallenge
///
/// Defines a standard API for generating Schnorr challenges.
///
/// https://en.wikipedia.org/wiki/Schnorr_signature#Verifying
///
/// The Schnorr signature algorithm allows users to define an arbitrary secure hash function 𝐻 to generate the challenge message:
///
/// `𝑒 = 𝐻(𝑟∥𝑀)`
///
/// Different Schnorr-based signing protocols may wish to generate challenges in a different way depending upon their specific use case, as such, we implement a trait to enable flexibilty to support as many use cases as possible.
pub trait Secp256k1SchnorrVerify: Sized {
    fn challenge<T: Secp256k1Point>(r: &[u8; 32], pubkey: &T, message: &[u8]) -> [u8; 32];
}

/// Scep256k1SchnorrNonce
///
/// This trait defines a standard API for generating secure Schnorr nonces.
///
/// WARNING: Nonce generation is dangerous. You must have a functioning understanding of nonce reuse attacks to securely implement your own scheme:
///
/// https://en.wikipedia.org/wiki/Schnorr_signature#Key_leakage_from_nonce_reuse
///
///  It is recommended that nonce generation schemes:
///
/// - Consider reutilizing the secure randomness of the private key with a pRNG such as a cryptographic hash function
/// - Include some form of domain separation accross both messages and protocols to avoid nonce reuse attacks
/// - Are not relationally bound in any predictable way
/// - Ensure the secure generation of any auxiliary randomness and do not rely solely upon it
///
/// Failure to take these precautions into consideration will likely result in your private key being leaked through a common nonce reuse attack.
pub trait Secp256k1SchnorrSign: Sized + Secp256k1SchnorrVerify {
    fn aux_randomness(privkey: &[u8; 32], aux: &[u8; 32]) -> [u8; 32];
    fn nonce<T: Secp256k1Point>(pubkey: &T, message: &[u8], aux: &[u8; 32]) -> [u8; 32];
}

#[cfg(feature = "bip340")]
pub mod bip340;

#[cfg(feature = "sha256")]
pub mod sha256;

#[cfg(feature = "keccak256")]
pub mod keccak256;
