# HPKE

_Hybrid Public Key Encryption_ implemented in Haskell.

See [RFC 9180](https://datatracker.ietf.org/doc/html/rfc9180).

Currently supported:

- D-H groups: elliptic curves P-256, X25519, X448

- KDF: HKDF-SHA256, HKDF-SHA384, HKDF-SHA512

- AEAD: AES-128-GCM, AES-256-GCM, ChaCha20Poly1305

Elliptic curves P-384 and P-521 support operations with ephemeral keys only
because underlying cryptographic primitives with `cryptonite` take variable
time.
