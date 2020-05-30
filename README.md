# HPKE

_Hybrid Public Key Encryption_ implemented in Haskell.

See [draft-irtf-cfrg-hpke](https://tools.ietf.org/html/draft-irtf-cfrg-hpke).

Currently supported:

- D-H groups: elliptic curves P-256, X25519, X448

- KDF: HKDF-SHA256, HKDF-SHA384, HKDF-SHA512

- AEAD: AES-GCM-128, AES-GCM-256, ChaCha20Poly1305

Elliptic curves P-384 and P-521 support operations with ephemeral keys only
because underlying cryptographic primitives with `cryptonite` take variable
time.
