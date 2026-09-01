# zhkdf

RFC 5869 HKDF key derivation over HMAC-SHA256, in freestanding C23.

HKDF extracts a strong pseudorandom key from arbitrary input keying
material, then expands it into any amount of context-separated output
keying material. Use it whenever one shared secret must yield several
independent keys (encryption, MAC, IV) or when a low-entropy secret
must be stretched with a salt.

- `zhkdf_sha256_extract` — salt + IKM → 32-byte PRK
- `zhkdf_sha256_expand` — PRK + info → up to 8160 bytes of OKM
- `zhkdf_sha256` — one-shot extract + expand

Tested against the full RFC 5869 appendix A SHA-256 test vectors.
Depends on the Commons package `zsha256` for HMAC-SHA256.

Apache-2.0 licensed.
