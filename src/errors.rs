#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Secp256k1SchnorrError {
    InvalidSecretKey = 1,
    InvalidPublicKey = 2,
    InvalidRecoveryId = 3,
    InvalidSignature = 4,
    ArithmeticOverflow = 5,
}
