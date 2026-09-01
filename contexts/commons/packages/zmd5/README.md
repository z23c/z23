# zmd5

MD5 message digest (RFC 1321) for C23.

MD5 is cryptographically broken for collision resistance. Use this
only where MD5 is required for legacy interoperability — ETags,
Content-MD5 headers, digest authentication, rsync-era checksums — or
for non-adversarial content identity. For new designs use SHA-256
(see `zsha256`).

- One-shot and streaming interfaces; caller-owned context, no global
  state, no allocation.
- Streaming finalization zeroizes the context.
- Tested against the full RFC 1321 section A.5 suite plus block- and
  padding-boundary streaming equivalence checks.

## API

```c
#include <zmd5/zmd5.h>

zmd5 ctx;
zmd5_init(&ctx);
zmd5_update(&ctx, data, len);        /* repeatable */
uint8_t digest[ZMD5_DIGEST_LEN];
zmd5_final(&ctx, digest);            /* 16 bytes, context zeroized */

char hex[ZMD5_HEX_LEN];              /* 32 lowercase hex chars */
zmd5_hex(digest, hex);

/* one-shot */
zmd5_digest(data, len, digest);
zmd5_digest_hex(data, len, hex);
```

## CLI

```
printf abc | zmd5        # -> 900150983cd24fb0d6963f7d28e17f72
zmd5 file1 file2         # -> md5sum-style "hex  FILE" lines
```

## Build

C23, single translation unit: compile `src/zmd5.c` with `-Iinclude`.
Tests: `tests/test_zmd5.c` (no framework needed).

## License

Apache-2.0.
