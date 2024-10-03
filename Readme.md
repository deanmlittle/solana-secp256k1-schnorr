# solana-secp256k1-schnorr

An efficient SVM implementation of secp256k1 Schnorr signature verification.

### Secp256k1SchnorrSignature
A Schnorr signature used for signature verification purposes.

There are 2 main functions that it performs:

1. Sign - Signs a messages with a private key and optional auxiliary randomness.
2. Verify - Verifies a Schnorr signature against an arbitrary message and either a CompressedPoint or an UncompressedPoint.

### Sign

Sign requires activating the "sign" feature flag. It offers BIP340 signing, but allows you to define your own challenge scheme with maximum flexibility.

Do note that signing messages onchain will result in revealing your private key. As such, this crate makes no attempt to perform constant time signing operations.

Challenges must provide a valid implementation of the Secp256k1SchnorrSign trait.

Example:

```rs
use solana_secp256k1_schnorr::{Secp256k1SchnorrSignature, BIP340Challenge}, 

let message = *b"test";

let privkey = [ 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01,
];
let schnorr_signature = Secp256k1SchnorrSignature::sign::<BIP340Challenge>(message.as_slice(), &privkey)
    .expect("Invalid signature");
```

### Verify

Verify requires a valid implementation of the trait Secp256k1SchnorrVerify.

Under the hood, it abuses the `sol_secp256k1_ecrecover` syscall to perform efficient elliptic curve multiplication 
over the Secp256k1 curve, enabling on-chain Schnorr signature verification.

Example:

```rs
use solana_secp256k1_schnorr::{Secp256k1SchnorrSignature, CompressedPoint, BIP340Challenge}, 

let signature = Secp256k1SchnorrSignature([
    0xbb, 0x83, 0xe8, 0xb3, 0x48, 0xf6, 0xbe, 0xa3, 0x9e, 0x97, 0x33, 0xc5, 0x29, 0xcd, 0x9c,
    0x1c, 0x8c, 0x64, 0x85, 0xb7, 0xc7, 0x6b, 0x80, 0xb9, 0x73, 0x88, 0xb3, 0xe1, 0xc2, 0xe2,
    0x36, 0x39, 0x2a, 0x94, 0xb3, 0x14, 0x5b, 0x98, 0xa7, 0x92, 0x15, 0x60, 0x8f, 0xa3, 0x61,
    0x08, 0x4a, 0xea, 0xd1, 0xec, 0x08, 0x09, 0xe9, 0x86, 0xb9, 0xe5, 0xb4, 0x01, 0xff, 0xff,
    0x10, 0xe7, 0x12, 0x65,
]);

let message = *b"test";

let pubkey = CompressedPoint([
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
    0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
    0xf8, 0x17, 0x98,
]);

let schnorr_signature = Secp256k1SchnorrSignature(signature);

schnorr_signature.verify::<BIP340Challenge, CompressedPoint>(&message, &pubkey)
    .expect("Invalid signature");
```
