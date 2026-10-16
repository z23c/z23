<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# zclassic23/slhdsa

Allocation-free SLH-DSA (NIST FIPS 205, August 2024), the stateless hash-based
signature scheme, for C23. One generic implementation is driven by a parameter
table and serves SLH-DSA-SHAKE-128s and SLH-DSA-SHAKE-192s. Security rests only
on SHAKE256 (`zclassic23/sha3`); secrets are wiped with `memory_cleanse` from
`zclassic23/base`. Because the scheme is stateless it is safe across hosts,
backups and restores, which is why it was chosen over the stateful XMSS and LMS.

| Object | SHAKE-128s | SHAKE-192s |
| --- | --- | --- |
| Public key | 32 | 48 |
| Secret key | 64 | 96 |
| Signature | 7856 | 16224 |

## Interface

`include/slhdsa/slhdsa.h` is the FIPS 205 external "pure" interface: the signed
bytes are `M' = 0x00 || len(ctx) || ctx || M` with a context of 0..255 bytes
(longer contexts are refused with `ZCL_SLHDSA_ERR_CONTEXT`). There is no
HashSLH-DSA pre-hash variant. `zcl_slhdsa_sign` is hedged and takes a random
callback; `zcl_slhdsa_sign_deterministic` uses `opt_rand = PK.seed`. The module
never reads an operating-system generator. All functions return
`enum zcl_slhdsa_status` and are `[[nodiscard]]`. Wrong-length keys, seeds and
signatures give `ZCL_SLHDSA_ERR_LENGTH` before any hashing; a well-formed
signature that does not verify gives `ZCL_SLHDSA_ERR_VERIFY`. Signing and key
generation failures zero their output buffers. Nothing allocates on the heap;
the message is streamed through an incremental SHAKE256 sponge, so verification
stack use does not depend on message or signature length.

`include/slhdsa/slhdsa_kat.h` declares the internal algorithms (FIPS 205
Algorithms 18-20) for known-answer testing only.

## Tests

`tests/test_slhdsa.c` runs the NIST ACVP vectors in `tests/slhdsa_vectors.h` and `tests/slhdsa_verify_vectors.h`
(key generation, deterministic and hedged signature generation through both the
external and internal interfaces, and signature verification including the
expected-failure cases), round trips, single-bit-flip rejection over the
signature, message, context and public key, and input validation. It prints
sign and verify milliseconds and asserts nothing about time. The vector header
records the ACVP commit and the SHA-256 of each source JSON file;
`tests/gen_vectors.sh` regenerates it (as `slhdsa_vectors.h` and `slhdsa_verify_vectors.h`, split to stay under the lint file-size limit) with `jq` and `awk`.

Run with `make zcode-package-slhdsa-test`; the sanitizer build is part of
`make zcode-package-asan`.
