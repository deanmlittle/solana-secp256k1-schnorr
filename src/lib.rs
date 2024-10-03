pub mod challenges;
pub mod errors;
#[cfg(test)]
mod tests;

use challenges::{Secp256k1SchnorrSign, Secp256k1SchnorrVerify};
use errors::Secp256k1SchnorrError;
use solana_nostd_secp256k1_recover::secp256k1_recover;
use solana_secp256k1::{Curve, Secp256k1Point, UncompressedPoint};

pub const SECP256K1_SCHNORR_SIGNATURE_LENGTH: usize = 64;

/// # Secp256k1SchnorrSignature
/// A Schnorr signature used for signature verification purposes.
///
/// There are 2 main functions that it performs:
///
/// 1. Sign - Signs a messages with a private key and optional auxiliary randomness.
/// 2. Verify - Verifies a Schnorr signature against an arbitrary message and either a CompressedPoint or an UncompressedPoint.
pub struct Secp256k1SchnorrSignature(pub [u8; SECP256K1_SCHNORR_SIGNATURE_LENGTH]);

impl Secp256k1SchnorrSignature {
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
}

impl Secp256k1SchnorrSignature {
    /// ### Verify
    /// Verify requires a valid implementation of the trait Secp256k1SchnorrVerify.
    ///
    /// Under the hood, it abuses the `sol_secp256k1_ecrecover` syscall to perform efficient elliptic curve multiplication
    /// over the Secp256k1 curve, enabling on-chain Schnorr signature verification.
    ///
    /// Example:
    /// ```rs
    /// use solana_secp256k1_schnorr::{Secp256k1SchnorrSignature, CompressedPoint, BIP340Challenge},
    ///
    /// let signature = Secp256k1SchnorrSignature([
    ///     0xbb, 0x83, 0xe8, 0xb3, 0x48, 0xf6, 0xbe, 0xa3, 0x9e, 0x97, 0x33, 0xc5, 0x29, 0xcd, 0x9c,
    ///     0x1c, 0x8c, 0x64, 0x85, 0xb7, 0xc7, 0x6b, 0x80, 0xb9, 0x73, 0x88, 0xb3, 0xe1, 0xc2, 0xe2,
    ///     0x36, 0x39, 0x2a, 0x94, 0xb3, 0x14, 0x5b, 0x98, 0xa7, 0x92, 0x15, 0x60, 0x8f, 0xa3, 0x61,
    ///     0x08, 0x4a, 0xea, 0xd1, 0xec, 0x08, 0x09, 0xe9, 0x86, 0xb9, 0xe5, 0xb4, 0x01, 0xff, 0xff,
    ///     0x10, 0xe7, 0x12, 0x65,
    /// ]);
    ///
    /// let message = *b"test";
    ///
    /// let pubkey = CompressedPoint([
    ///     0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
    ///     0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
    ///     0xf8, 0x17, 0x98,
    /// ]);
    ///
    /// let schnorr_signature = Secp256k1SchnorrSignature(signature);
    ///
    /// schnorr_signature.verify::<BIP340Challenge, CompressedPoint>(&message, &pubkey)
    ///     .expect("Invalid signature");
    /// ```
    #[inline]
    pub fn verify<C: Secp256k1SchnorrVerify, T: Secp256k1Point>(
        &self,
        message: &[u8],
        pubkey: &T,
    ) -> Result<(), Secp256k1SchnorrError> {
        // Calculate challenge from pubkey and message:
        let e = C::challenge(&self.r(), pubkey, message);
        // m = -s*Px
        let m = Curve::negate_n(&Curve::mul_mod_n(&self.s(), &pubkey.x()));
        // s = -e*Px
        let s = Curve::negate_n(&Curve::mul_mod_n(&e, &pubkey.x()));

        // R and S are made up of Px and and -e*Px
        let mut r_s = [0u8; 64];
        r_s[..32].clone_from_slice(&pubkey.x());
        r_s[32..].clone_from_slice(&s);

        if m.eq(&[0u8; 32]) {
            return Err(Secp256k1SchnorrError::InvalidSignature);
        }

        let r = secp256k1_recover(&m, pubkey.is_odd(), &r_s)
            .map_err(|_| Secp256k1SchnorrError::InvalidSignature)?;

        if self.r().ne(&r[..32]) {
            return Err(Secp256k1SchnorrError::InvalidSignature);
        }
        Ok(())
    }
}

#[cfg(feature = "sign")]
impl Secp256k1SchnorrSignature {
    /// ### Sign
    /// Sign requires activating the "sign" feature flag. It offers BIP340 signing, but allows you to define your own challenge scheme with maximum flexibility.
    ///
    /// Challenges must provide a valid implementation of the Secp256k1SchnorrSign trait.
    ///
    /// Example:
    /// ```rs
    /// use solana_secp256k1_schnorr::{Secp256k1SchnorrSignature, BIP340Challenge},
    ///
    /// let message = *b"test";
    ///
    /// let privkey = [
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x00, 0x01,
    /// ];
    /// let schnorr_signature = Secp256k1SchnorrSignature::sign::<BIP340Challenge>(message.as_slice(), &privkey)
    ///     .expect("Invalid signature");
    /// ```
    #[inline]
    pub fn sign<C: Secp256k1SchnorrSign>(
        message: &[u8],
        privkey: &[u8; 32],
    ) -> Result<Secp256k1SchnorrSignature, Secp256k1SchnorrError> {
        // aux represents the tagged-sha256 hash of our auxiliary randomness. In our default signing, this will be zero.
        let aux = C::aux_randomness(privkey, &[0u8; 32]);

        // p is the X-only public key of our Privkey
        let pubkey = Curve::mul_g(privkey).map_err(|_| Secp256k1SchnorrError::InvalidPublicKey)?;

        // k is our ephemeral key
        let (k, r) = C::nonce::<UncompressedPoint>(&pubkey, message, &aux)?;

        // e is the challenge message
        let e = C::challenge(&r.x(), &pubkey, message);

        let mut sig_bytes = [0; 64];
        sig_bytes[..32].clone_from_slice(&r.x());
        sig_bytes[32..].clone_from_slice(&Curve::add_mod_n(&k, &Curve::mul_mod_n(&e, privkey)));
        Ok(Secp256k1SchnorrSignature(sig_bytes))
    }
}
