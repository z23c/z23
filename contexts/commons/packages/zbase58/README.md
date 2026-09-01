# zbase58

Base58 encoding and decoding for C23 (Bitcoin alphabet).

- Alphabet `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`
  — no `0`, `O`, `I`, or `l`.
- Leading zero bytes map to leading `1`s and back.
- Strict decode: first invalid character position reported.
- Exact sizing helpers; no allocation, no dependencies beyond libc.

## API

```c
#include <zbase58/zbase58.h>

size_t zbase58_encoded_max(size_t bin_len);
size_t zbase58_decoded_max(size_t b58_len);
zbase58_err zbase58_encode(const uint8_t *bin, size_t n,
                           char *out, size_t cap, size_t *out_len);
zbase58_err zbase58_decode(const char *b58, size_t n,
                           uint8_t *out, size_t cap,
                           size_t *out_len, size_t *bad_pos);
int zbase58_char_value(char c);
```

## CLI

```sh
echo -n 'Hello World!' | zbase58 encode   # 2NEpo7TZRRrLZSi2U
echo 2NEpo7TZRRrLZSi2U | zbase58 decode   # Hello World!
```

## License

Apache-2.0. See LICENSE.
