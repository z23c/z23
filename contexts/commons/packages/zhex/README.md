# zhex

Strict hexadecimal encoding and decoding for C23.

- Lowercase output by default, uppercase on request.
- Strict decoder: even length required, both cases accepted, first bad
  character position reported.
- No allocation; caller-provided buffers with exact size helpers.
- No dependencies beyond libc.

## API

```c
#include <zhex/zhex.h>

size_t zhex_encoded_len(size_t bin_len);          /* 2 * bin_len */
size_t zhex_decoded_len(size_t hex_len);          /* hex_len / 2 */

zhex_err zhex_encode(const uint8_t *bin, size_t n, char *out);
zhex_err zhex_encode_upper(const uint8_t *bin, size_t n, char *out);
zhex_err zhex_decode(const char *hex, size_t n, uint8_t *out, size_t *bad_pos);
zhex_err zhex_decode_cstr(const char *hex, uint8_t *out, size_t *bad_pos);
int      zhex_digit_value(char c);                /* 0..15 or -1 */
const char *zhex_err_str(zhex_err e);
```

Output is never NUL-terminated by the encode functions; sizes are exact.

## CLI

```sh
echo -n hello | zhex encode          # 68656c6c6f
echo 68656c6c6f | zhex decode        # hello
```

## License

Apache-2.0. See LICENSE.
