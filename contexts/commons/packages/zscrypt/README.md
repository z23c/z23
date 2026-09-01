# zscrypt

RFC 7914 scrypt password-based key derivation, in freestanding C23.

scrypt is memory-hard: with cost parameters N, r, p it needs
N*r*128 bytes of RAM and 2*N*p*r Salsa20/8 rounds per derivation,
so offline guessing attacks pay a per-attempt hardware cost that
fast hashes like bare SHA-256 do not impose. Use it to turn
passphrases into keys before storage or encryption.

- `zscrypt` — full memory-hard KDF (suggested: N=16384, r=8, p=1)
- `zpbkdf2_sha256` — RFC 8018 PBKDF2-HMAC-SHA256, exposed because
  scrypt uses it internally and legacy protocols use it directly

Tested against the full RFC 7914 section 11/12 test vectors.
Depends on the Commons package `zsha256` for HMAC-SHA256.

Apache-2.0 licensed.
