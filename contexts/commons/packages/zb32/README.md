# zb32 — RFC 4648 base32 encoding/decoding

`zb32` is a strict, allocation-free base32 codec: canonical A-Z2-7
alphabet, `=` padding, and a decoder that rejects invalid characters,
misplaced padding, wrong lengths, and non-canonical leftover bits
(e.g. `MZ======`).

## API sketch

```c
size_t en = zb32_encode(dst, cap, src, n);     /* multiple of 8 */
size_t dn = zb32_decode(dst, cap, src, en);    /* SIZE_MAX if malformed */
size_t want = zb32_encoded_len(n);
size_t back = zb32_decoded_len(src, en);       /* validates too */
```

Measuring convention: return >= cap means truncated output (encoded
text still NUL-terminated when cap > 0). Sources capped at `ZB32_MAX`
(default 65535) bytes.

## Tests

`tests/test_zb32.c` asserts the seven RFC 4648 vectors, a 13-case
malformed table (padding shapes, lowercase, non-canonical bits), exact
round trips of all byte values at lengths 0–40, truncation and
measuring semantics, NULL handling, and a 3000-trial fuzz with random
corruption. Built and run under `-fsanitize=address,undefined
-Werror -pedantic`.

## License

Apache-2.0. See `LICENSE`.
