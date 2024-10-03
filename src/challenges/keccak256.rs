use crate::*;

use solana_nostd_keccak::hashv;

pub struct Keccak256Challenge;

impl Secp256k1SchnorrVerify for Keccak256Challenge {
    fn challenge<T: Secp256k1Point>(r: &[u8; 32], pubkey: &T, message: &[u8]) -> [u8; 32] {
        hashv(&[r, &pubkey.x(), message])
    }
}

impl Secp256k1SchnorrSign for Keccak256Challenge {
    fn aux_randomness(secret_key: &[u8; 32], aux: &[u8; 32]) -> [u8; 32] {
        let mut t = hashv(&[aux]);
        for (a, b) in t.iter_mut().zip(secret_key.iter()) {
            *a ^= b
        }
        t
    }

    fn nonce<T: Secp256k1Point>(pubkey: &T, message: &[u8], aux: &[u8; 32]) -> [u8; 32] {
        hashv(&[aux, pubkey.x().as_ref(), message])
    }
}
