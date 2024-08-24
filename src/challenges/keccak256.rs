use crate::*;

use solana_program::keccak::hash;
pub struct Keccak256Challenge;

impl Secp256k1SchnorrChallenge for Keccak256Challenge {
    fn challenge(r: &[u8; 32], pubkey: &[u8], message: &[u8]) -> [u8; 32] {
        let mut m = r.to_vec();
        m.extend_from_slice(&pubkey[1..]);
        m.extend_from_slice(message);
        hash(&m).to_bytes()
    }
}