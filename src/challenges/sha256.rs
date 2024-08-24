use crate::*;

use solana_program::hash::hash;
pub struct Sha256Challenge;

impl Secp256k1SchnorrChallenge for Sha256Challenge {
    fn challenge(r: &[u8; 32], pubkey: &[u8], message: &[u8]) -> [u8; 32] {
        let mut m = r.to_vec();
        m.extend_from_slice(&pubkey[1..]);
        m.extend_from_slice(message);
        hash(&m).to_bytes()
    }
}