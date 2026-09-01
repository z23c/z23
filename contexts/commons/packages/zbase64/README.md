# zbase64

Strict RFC 4648 Base64 encode/decode for C23, with caller-provided buffers
and exact size arithmetic. No allocation, no global state.

## Design

- **Two alphabets, never mixed:** the standard alphabet (canonical `=`
  padding required on decode) and the URL-safe alphabet (padding optional
  on decode). A mixed-alphabet input is rejected.
- **Strict decode:** whitespace is never skipped, padding must be
  canonical, and the final partial group's leftover bits must be zero —
  malformed data is rejected, never silently truncated. A rejected decode
  reports a zero output length.
- **Exact sizes:** `zbase64_encode_len()` and `zbase64_decode_cap()` give
  the exact encoded length and the worst-case decoded size, so callers
  size their own buffers.

## API summary

```c
size_t zbase64_encode_len(size_t len);
size_t zbase64_decode_cap(size_t len);
bool   zbase64_encode(const uint8_t *in, size_t len, char *out, size_t cap);
bool   zbase64url_encode(const uint8_t *in, size_t len, char *out, size_t cap);
bool   zbase64_decode(const char *in, size_t len, uint8_t *out, size_t cap,
                      size_t *out_len);
bool   zbase64url_decode(const char *in, size_t len, uint8_t *out, size_t cap,
                         size_t *out_len);
```

## Example

```c
char enc[zbase64_encode_len(3) + 1];
zbase64_encode((const uint8_t *)"foo", 3, enc, sizeof enc); /* "Zm9v" */
```

## App

`app/main.c` builds `b64`: encodes stdin to stdout (standard alphabet,
72-column fold, trailing newline) or decodes with `-d` (its own fold's
newlines are then the only tolerated whitespace), URL-safe with `-u`.
Input is bounded at 64 MiB; non-canonical input aborts with exit 2.

## Tests

`tests/test_zbase64.c` covers the RFC 4648 vectors, standard/URL-safe
alphabet separation, strict rejections (short/long padding, interior
whitespace, nonzero leftover bits, one-sextet groups, mixed alphabets,
undersized output), a 256-byte round trip through both alphabets, and the
exact-size arithmetic including the empty input.
