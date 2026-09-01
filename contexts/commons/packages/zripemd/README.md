# zripemd

RIPEMD-160 (ISO/IEC 10118-3) hash, in freestanding C23.

RIPEMD-160 is a 160-bit hash built from two parallel 80-step
compression lines. It is the second half of Bitcoin-style HASH160
address derivation (`zripemd160(sha256_digest, 32, out)`) and shows
up wherever a compact 40-hex-digit identifier with more structure
resistance than MD5/SHA-1 is needed.

- `zripemd160_init` / `update` / `final` — incremental hashing
- `zripemd160` — one-shot into 20 raw bytes
- `zripemd160_hex` — one-shot into 40 lowercase hex chars

Tested against the standard RIPEMD-160 test suite (empty string
through the million-'a' vector) and incremental split points.
Self-contained; no dependencies beyond libc.

Apache-2.0 licensed.
