# zsha256

SHA-256 and HMAC-SHA256 for C23. Self-contained, no dependencies.

- FIPS 180-4 SHA-256, incremental context API and one-shot helpers.
- RFC 2104 HMAC-SHA256 (tested against the RFC 4231 vectors).
- Lowercase hex output helper; constant-time digest comparison.
- State is zeroed on final.

## API

```c
#include <zsha256/zsha256.h>

zsha256_ctx ctx;
zsha256_init(&ctx);
zsha256_update(&ctx, data, len);
uint8_t digest[ZSHA256_DIGEST_LEN];
zsha256_final(&ctx, digest);

void zsha256(const void *data, size_t len, uint8_t out[32]);
void zsha256_hex(const void *data, size_t len, char out[65]);

zsha256_hmac_ctx hctx;
zsha256_hmac_init(&hctx, key, key_len);
zsha256_hmac_update(&hctx, data, len);
zsha256_hmac_final(&hctx, digest);

void zsha256_hmac(const void *key, size_t klen,
                  const void *data, size_t dlen, uint8_t out[32]);
int  zsha256_compare(const uint8_t a[32], const uint8_t b[32]);
```

## CLI

```sh
zsha256 file.c              # sha256sum-style output
echo -n abc | zsha256
zsha256 --hmac secret file  # HMAC-SHA256 with key "secret"
```

## License

Apache-2.0. See LICENSE.
