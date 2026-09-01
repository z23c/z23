# zsha1

SHA-1 message digest (FIPS 180-1 / RFC 3174) for C23.

SHA-1 is cryptographically broken for collision resistance
(SHAttered, 2017). Use this only where SHA-1 is required for legacy
interoperability — git object identities, older manifests and
checksums, HMAC-SHA1 in legacy protocols — or for non-adversarial
content identity. For new designs use SHA-256 (see `zsha256`).

- One-shot and streaming interfaces; caller-owned context, no global
  state, no allocation.
- Streaming finalization zeroizes the context.
- Tested against the RFC 3174 suite (including the million-'a' case)
  plus block/padding-boundary streaming equivalence checks.

## API

```c
#include <zsha1/zsha1.h>

zsha1 ctx;
zsha1_init(&ctx);
zsha1_update(&ctx, data, len);        /* repeatable */
uint8_t digest[ZSHA1_DIGEST_LEN];
zsha1_final(&ctx, digest);            /* 20 bytes, context zeroized */

char hex[ZSHA1_HEX_LEN];              /* 40 lowercase hex chars */
zsha1_hex(digest, hex);

/* one-shot */
zsha1_digest(data, len, digest);
zsha1_digest_hex(data, len, hex);
```

## CLI

```
printf abc | zsha1       # -> a9993e364706816aba3e25717850c26c9cd0d89d
zsha1 file1 file2        # -> sha1sum-style "hex  FILE" lines
```

## Build

C23, single translation unit: compile `src/zsha1.c` with `-Iinclude`.
Tests: `tests/test_zsha1.c` (no framework needed).

## License

Apache-2.0.
