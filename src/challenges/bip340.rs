use crate::*;

use challenges::{Secp256k1SchnorrSign, Secp256k1SchnorrVerify};

use solana_nostd_sha256::hashv;

// sha256(BIP0340/challenge) tagged hash
const BIP0340_CHALLENGE: [u8; 32] = [
    0x7b, 0xb5, 0x2d, 0x7a, 0x9f, 0xef, 0x58, 0x32, 0x3e, 0xb1, 0xbf, 0x7a, 0x40, 0x7d, 0xb3, 0x82,
    0xd2, 0xf3, 0xf2, 0xd8, 0x1b, 0xb1, 0x22, 0x4f, 0x49, 0xfe, 0x51, 0x8f, 0x6d, 0x48, 0xd3, 0x7c,
];

// sha256(BIP0340/aux) tagged hash
const BIP0340_AUX: [u8; 32] = [
    0xf1, 0xef, 0x4e, 0x5e, 0xc0, 0x63, 0xca, 0xda, 0x6d, 0x94, 0xca, 0xfa, 0x9d, 0x98, 0x7e, 0xa0, 
    0x69, 0x26, 0x58, 0x39, 0xec, 0xc1, 0x1f, 0x97, 0x2d, 0x77, 0xa5, 0x2e, 0xd8, 0xc1, 0xcc, 0x90, 
];

// sha256(BIP0340/nonce) tagged hash
const BIP0340_NONCE: [u8; 32] = [
    0x07, 0x49, 0x77, 0x34, 0xa7, 0x9b, 0xcb, 0x35, 0x5b, 0x9b, 0x8c, 0x7d, 0x03, 0x4f, 0x12, 0x1c,
    0xf4, 0x34, 0xd7, 0x3e, 0xf7, 0x2d, 0xda, 0x19, 0x87, 0x00, 0x61, 0xfb, 0x52, 0xbf, 0xeb, 0x2f,
];

pub struct BIP340Challenge;

impl Secp256k1SchnorrVerify for BIP340Challenge {
    fn challenge<T: Secp256k1Point>(r: &[u8; 32], pubkey: &T, message: &[u8]) -> [u8; 32] {
        hashv(&[
            BIP0340_CHALLENGE.as_ref(),
            BIP0340_CHALLENGE.as_ref(),
            r.as_ref(),
            pubkey.x().as_ref(),
            message,
        ])
    }
}

impl Secp256k1SchnorrSign for BIP340Challenge {
    fn aux_randomness(privkey: &[u8; 32], aux: &[u8; 32]) -> [u8; 32] {
        let mut t = hashv(&[BIP0340_AUX.as_ref(), BIP0340_AUX.as_ref(), aux]);
        for (a, b) in t.iter_mut().zip(privkey.iter()) {
            *a ^= b
        }
        t
    }

    fn nonce<T: Secp256k1Point>(pubkey: &T, message: &[u8], aux: &[u8; 32]) -> Result<([u8; 32], UncompressedPoint), Secp256k1SchnorrError> {
        let mut k = hashv(&[
            BIP0340_NONCE.as_ref(),
            BIP0340_NONCE.as_ref(),
            aux,
            pubkey.x().as_ref(),
            message,
        ]);
        let mut r = UncompressedPoint::try_from(k).map_err(|_| Secp256k1SchnorrError::InvalidNonce)?;

        if r.is_odd() {
            Curve::negate_n(&mut k);
            r.invert();
        }

        Ok((k,r))
    }
}
