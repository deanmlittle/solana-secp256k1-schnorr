use crate::*;
use solana_program::hash::hash;

const BIP0340_CHALLENGE: [u8; 32] = [
    0x7b, 0xb5, 0x2d, 0x7a, 0x9f, 0xef, 0x58, 0x32, 0x3e, 0xb1, 0xbf, 0x7a, 0x40, 0x7d, 0xb3,
    0x82, 0xd2, 0xf3, 0xf2, 0xd8, 0x1b, 0xb1, 0x22, 0x4f, 0x49, 0xfe, 0x51, 0x8f, 0x6d, 0x48,
    0xd3, 0x7c,
];

pub struct BIP340Challenge;

impl Secp256k1SchnorrChallenge for BIP340Challenge {
    fn challenge(r: &[u8; 32], pubkey: &[u8], message: &[u8]) -> [u8; 32] {
        // sha256(BIP0340/challenge) || sha256(BIP0340/challenge)
        let mut m = BIP0340_CHALLENGE.to_vec();
        m.extend_from_slice(&BIP0340_CHALLENGE);
        m.extend_from_slice(r);
        m.extend_from_slice(&pubkey[1..]);
        m.extend_from_slice(message);
        hash(&m).to_bytes()        
    }
}