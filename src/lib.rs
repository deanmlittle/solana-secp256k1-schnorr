use crypto_bigint::{CheckedSub, Encoding, NonZero, U256, U512};
use errors::Secp256k1SchnorrVerifyError;
use solana_program::secp256k1_recover::secp256k1_recover;

pub mod challenges;
pub mod errors;

#[cfg(test)]
mod tests;

pub const SECP256K1_SCHNORR_SIGNATURE_LENGTH: usize = 64;
pub const SECP256K1_SCHNORR_COMPRESSED_PUBLIC_KEY_LENGTH: usize = 33;
pub struct Secp256k1SchnorrSignature([u8; SECP256K1_SCHNORR_SIGNATURE_LENGTH]);

impl Secp256k1SchnorrSignature {
    pub const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];

    pub const Q: U256 = U256::from_be_slice(&Self::N);

    pub fn r(&self) -> [u8; 32] {
        [
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7],
            self.0[8], self.0[9], self.0[10], self.0[11], self.0[12], self.0[13], self.0[14],
            self.0[15], self.0[16], self.0[17], self.0[18], self.0[19], self.0[20], self.0[21],
            self.0[22], self.0[23], self.0[24], self.0[25], self.0[26], self.0[27], self.0[28],
            self.0[29], self.0[30], self.0[31],
        ]
    }

    pub fn s(&self) -> [u8; 32] {
        [
            self.0[32], self.0[33], self.0[34], self.0[35], self.0[36], self.0[37], self.0[38],
            self.0[39], self.0[40], self.0[41], self.0[42], self.0[43], self.0[44], self.0[45],
            self.0[46], self.0[47], self.0[48], self.0[49], self.0[50], self.0[51], self.0[52],
            self.0[53], self.0[54], self.0[55], self.0[56], self.0[57], self.0[58], self.0[59],
            self.0[60], self.0[61], self.0[62], self.0[63],
        ]
    }

    pub fn verify<C: Secp256k1SchnorrChallenge>(
        &self,
        message: &[u8],
        pubkey: &[u8; SECP256K1_SCHNORR_COMPRESSED_PUBLIC_KEY_LENGTH]
    ) -> Result<(), Secp256k1SchnorrVerifyError> {
        // Calculate challenge from pubkey and message:
        let e = C::challenge(&self.r(), pubkey, message);

        // ecrecover = (m, v, r, s);
        let x_u256 = U256::from_be_slice(&pubkey[1..]);
        let e_u256 = U256::from_be_slice(&e);
        let s_u256 = U256::from_be_slice(&self.s());

        // m = -s*Px
        let m = Option::<U256>::from(Self::Q.checked_sub(&Self::mulmod(&s_u256, &x_u256)))
            .ok_or(Secp256k1SchnorrVerifyError::ArithmeticOverflow)?;
        // s = -e*Px
        let s = Option::<U256>::from(Self::Q.checked_sub(&Self::mulmod(&e_u256, &x_u256)))
            .ok_or(Secp256k1SchnorrVerifyError::ArithmeticOverflow)?
            .to_be_bytes();

        // R and S are made up of Px and and -e*Px
        let mut r_s = [0u8; 64];
        r_s[..32].clone_from_slice(&pubkey[1..]);
        r_s[32..].clone_from_slice(&s);

        if m.eq(&U256::from_u8(0)) {
            return Err(Secp256k1SchnorrVerifyError::InvalidSignature);
        }

        let parity = match pubkey[0] {
            2 => 0,
            3 => 1,
            _ => return Err(Secp256k1SchnorrVerifyError::InvalidRecoveryId)
        };

        let r = secp256k1_recover(&m.to_be_bytes(), parity, &r_s)
            .map_err(|_| Secp256k1SchnorrVerifyError::InvalidSignature)?;

        if self.r().ne(&r.0[..32]) {
            return Err(Secp256k1SchnorrVerifyError::InvalidSignature);
        }

        Ok(())
    }

    pub fn mulmod(a: &U256, b: &U256) -> U256 {
        let modulus = NonZero::<U512>::new(U512::from(
            &U256::from_be_slice(&Self::N).mul(&U256::from_u8(1)),
        ))
        .unwrap();
        let mut x = [0u8; 32];
        x.clone_from_slice(
            &U512::from_be_slice(&a.mul(&b).to_be_bytes())
                .rem(&modulus)
                .to_be_bytes()[32..],
        );
        U256::from_be_slice(&x)
    }
}

pub trait Secp256k1SchnorrChallenge: Sized {
    fn challenge(r: &[u8; 32], pubkey: &[u8], message: &[u8]) -> [u8; 32];
}