# zutf16 — strict UTF-8 <-> UTF-16LE transcoding

`zutf16` transcodes between UTF-8 and little-endian UTF-16 with strict
validation in both directions: overlong encodings, surrogates, and
codepoints above U+10FFFF are rejected on the UTF-8 side; unpaired
surrogates, truncated pairs, and odd byte counts on the UTF-16 side.

## API sketch

```c
size_t nb = zutf16_from_utf8(dst, cap, src, n);  /* UTF-8 -> LE bytes */
size_t nu = zutf16_to_utf8(dst, cap, le, nb);    /* LE bytes -> UTF-8 */
size_t used = zutf16_decode_cp(p, n, &cp);       /* one codepoint */
size_t units = zutf16_encode_cp(u, cp);          /* cp -> 1-2 units */
```

Measuring convention: pass NULL/0 to query the needed size; any
invalid input returns `SIZE_MAX`. Sources are capped at `ZUTF16_MAX`
(default 65535) bytes.

## Tests

`tests/test_zutf16.c` covers known answers (ASCII, é, €, 😀, mixed
documents), a malformed table for both directions, an exhaustive
round trip of **every valid Unicode codepoint** (all 1,112,064 of
them) through encode_cp → LE bytes → UTF-8 → decode_cp, length-query
consistency, truncation semantics, NULL safety, and a 3000-trial
fuzz with random-codepoint documents and byte mutation. Built and run
under `-fsanitize=address,undefined -Werror -pedantic`.

## License

Apache-2.0. See `LICENSE`.
