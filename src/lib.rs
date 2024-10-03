pub mod challenges;
pub mod errors;
#[cfg(test)]
mod tests;

use challenges::{Secp256k1SchnorrSign, Secp256k1SchnorrVerify};
use errors::Secp256k1SchnorrError;
use solana_nostd_secp256k1_recover::secp256k1_recover;
use solana_secp256k1::{Curve, Secp256k1Point};

pub const SECP256K1_SCHNORR_SIGNATURE_LENGTH: usize = 64;

/// # Secp256k1SchnorrSignature
/// A Schnorr signature used for signature verification purposes. It has two specific builds targets.
///
/// There are 3 main functions that it performs:
///
/// 1. Sign - Signs a messages with a private key and optional auxiliary randomness.
/// 2. Verify - Verifies a Schnorr signature against an arbitrary message and a 33-byte compressed secp256k1 public key.
/// 3. Point from Scalar - Creates a public key from a private key scalar
///
/// ### Sign
/// This function requires a valid implementation of the Secp256k1SchnorrChallenge + Secp256k1SchnorrNonce traits.
///
/// As it is impractical and serves no real purpose, this method is omitted from Solana build targets.
///
/// As such, signing utilizes `k256 v0.10.4` under the hood for its compatible with the current dependency tree of solana-program, as well as with a handful of WebAssembly and other useful build targets.
///
/// ### Verify
/// Verify requires a valid implementation of the trait Secp256k1SchnorrChallenge and has two separate implementations based upon build target:
///
/// **Non-Solana:** As with the sign function, verify uses k256 under the hood for the same reasons mentioned above.
///
/// **Solana:** When building for Solana, the verify function uses an SVM-specific variant that abuses the ability of the `secp256k1_ecrecover` syscall to perform efficient elliptic curve multiplication over the secp256k1 curve to perform Schnorr signature verification.
///
/// In this variant, instead of recovering R from an ecdsa signature, it recovers the X coordinate of a public key. As such, instead of the `recovery_id` referring to the Y coordinary of the `nonce` of an ecdsa signature being odd or even, it refers to the Y coordinate of the public key of the Schnorr signature.
///
/// Upon successfully recovering the X coordinate of the public key, it then performs a comparison to the inputted public key to ensure successful verification.

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
