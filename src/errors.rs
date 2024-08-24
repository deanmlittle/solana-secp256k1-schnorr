use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Secp256k1SchnorrVerifyError {
    #[error("The public key provided is invalid")]
    InvalidPublicKey,
    #[error("The recovery_id provided is invalid")]
    InvalidRecoveryId,
    #[error("The signature provided is invalid")]
    InvalidSignature,
    #[error("Arithmetic overflow")]
    ArithmeticOverflow,
}

impl From<u64> for Secp256k1SchnorrVerifyError {
    fn from(v: u64) -> Secp256k1SchnorrVerifyError {
        match v {
            1 => Secp256k1SchnorrVerifyError::InvalidPublicKey,
            2 => Secp256k1SchnorrVerifyError::InvalidRecoveryId,
            3 => Secp256k1SchnorrVerifyError::InvalidSignature,
            4 => Secp256k1SchnorrVerifyError::ArithmeticOverflow,
            _ => panic!("Unsupported Secp256k1SchnorrVerifyError"),
        }
    }
}

impl From<Secp256k1SchnorrVerifyError> for u64 {
    fn from(v: Secp256k1SchnorrVerifyError) -> u64 {
        match v {
            Secp256k1SchnorrVerifyError::InvalidPublicKey => 1,
            Secp256k1SchnorrVerifyError::InvalidRecoveryId => 2,
            Secp256k1SchnorrVerifyError::InvalidSignature => 3,
            Secp256k1SchnorrVerifyError::ArithmeticOverflow => 4,
        }
    }
}