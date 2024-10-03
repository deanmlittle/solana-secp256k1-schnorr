# solana-secp256k1-schnorr

An SVM implementation of secp256k1 Schnorr signature verification.

### Features

This library has 3 main functions that it performs:

1. Sign - Signs a messages with a private key and optional auxiliary randomness.
2. Verify - Verifies a Schnorr signature against an arbitrary message and a 33-byte compressed secp256k1 public key.

### Sign
This function requires a valid implementation of the Secp256k1SchnorrChallenge + Secp256k1SchnorrNonce traits.

Although it is technically feasible to create Schnorr signatures onchain, it is impractical and serves no real purpose, and is thus omitted from Solana build targets.

As such, signing utilizes `k256 v0.10.4` under the hood for its compatible with the current dependency tree of solana-program, as well as with a handful of WebAssembly and other useful build targets.

### Verify
Verify requires a valid implementation of the trait Secp256k1SchnorrChallenge and has two separate implementations based upon build target:
///
**Non-Solana:** As with the sign function, verify uses k256 under the hood for the same reasons mentioned above. 

**Solana:** When building for Solana, the verify function uses an SVM-specific variant that abuses the ability of the `secp256k1_ecrecover` syscall to perform efficient elliptic curve multiplication over the secp256k1 curve to perform Schnorr signature verification.

In this variant, instead of recovering R from an ecdsa signature, it recovers the X coordinate of a public key. As such, instead of the `recovery_id` referring to the Y coordinary of the `nonce` of an ecdsa signature being odd or even, it refers to the Y coordinate of the public key of the Schnorr signature.

Upon successfully recovering the X coordinate of the public key, it then performs a comparison to the inputted public key to ensure successful verification.
