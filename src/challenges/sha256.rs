use crate::*;

use solana_nostd_sha256::hashv;
pub struct Sha256Challenge;

impl Secp256k1SchnorrVerify for Sha256Challenge {
    fn challenge<T: Secp256k1Point>(r: &[u8; 32], pubkey: &T, message: &[u8]) -> [u8; 32] {
        let mut m = r.to_vec();
        m.extend_from_slice(&pubkey.x());
        m.extend_from_slice(message);
        hashv(&[r.as_ref(), &pubkey.x(), message])
    }
}

impl Secp256k1SchnorrSign for Sha256Challenge {
    fn aux_randomness(secret_key: &[u8; 32], aux: &[u8; 32]) -> [u8; 32] {
        let mut t = hashv(&[aux]);
        for (a, b) in t.iter_mut().zip(secret_key.iter()) {
            *a ^= b
        }
        t
    }

    fn nonce<T: Secp256k1Point>(
        pubkey: &T,
        message: &[u8],
        aux: &[u8; 32],
    ) -> Result<([u8; 32], UncompressedPoint), Secp256k1SchnorrError> {
        let k = hashv(&[aux, pubkey.x().as_ref(), message]);
        let r = Curve::mul_g(&k).map_err(|_| Secp256k1SchnorrError::InvalidNonce)?;
        Ok((k, r))
    }
}
