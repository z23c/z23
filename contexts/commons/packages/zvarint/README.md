# zvarint

LEB128 variable-length integer encoding for C23.

- Unsigned LEB128 and zigzag-mapped signed LEB128.
- Buffer-based API with explicit lengths; decode reports bytes consumed
  so streams of varints can be walked without framing.
- Strict canonical mode rejects non-minimal encodings (zero padding).
- Overflow-safe: 10th byte may carry only one payload bit.
- No allocation, no dependencies beyond libc.

## API

```c
#include <zvarint/zvarint.h>

zvarint_err zvarint_encode_u64(uint64_t v, uint8_t *out, size_t cap, size_t *len);
zvarint_err zvarint_encode_i64(int64_t s, uint8_t *out, size_t cap, size_t *len);
zvarint_err zvarint_decode_u64(const uint8_t *buf, size_t len,
                               uint64_t *value, size_t *consumed,
                               int strict_canonical);
zvarint_err zvarint_decode_i64(const uint8_t *buf, size_t len,
                               int64_t *value, size_t *consumed,
                               int strict_canonical);

size_t    zvarint_len_u64(uint64_t v);
size_t    zvarint_len_i64(int64_t s);
uint64_t  zvarint_zigzag_encode(int64_t s);
int64_t   zvarint_zigzag_decode(uint64_t v);
```

## CLI

```sh
zvarint enc 0 127 128 624485     # 00 / 7f / 8001 / e58e26
zvarint encs -1 1                # 01 / 02
zvarint dec e58e26               # 624485
```

## License

Apache-2.0. See LICENSE.
