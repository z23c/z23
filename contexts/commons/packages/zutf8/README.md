# zutf8 — UTF-8 validation, decoding, and encoding for C23

zutf8 answers the three questions every text boundary asks: is this
input well-formed UTF-8, what code point does this sequence encode, and
how do I encode this scalar value. It enforces the Unicode
well-formedness table exactly — overlong forms, UTF-16 surrogates, and
values above U+10FFFF are all rejected — in one allocation-free pass.

- Total and bounded: every byte sequence either decodes or fails with a
  distinct status (`ZUTF8_TRUNCATED` vs `ZUTF8_INVALID`); no undefined
  behaviour on any input, no allocation anywhere.
- Length-delimited API first (`zutf8_validate_n`, `zutf8_decode_n`,
  `zutf8_count_n`); embedded NUL is a valid code point.
- `zutf8_encode` rejects surrogates and values above U+10FFFF and can
  measure without writing (`out == NULL`).

## API

```c
#include "zutf8/zutf8.h"

if (!zutf8_validate_n(buf, len)) { /* reject */ }

uint32_t cp;
size_t used;
zutf8_status st = zutf8_decode_n(buf, len, &cp, &used);

char out[4];
size_t n = zutf8_encode(U'€', out); /* 3 */

size_t points = zutf8_count_n(buf, len); /* SIZE_MAX when invalid */
```

## CLI

```
$ printf 'héllo\n' | zutf8 --count
6
$ printf '\xff' | zutf8
zutf8: invalid byte sequence at byte 0
```

Exit 0 on well-formed input, 1 on malformed (byte offset and reason on
stderr), 2 on misuse or input over the 64 MiB bound.

## Build and test

```sh
cc -std=c23 -O2 -Iinclude src/zutf8.c app/main.c -o zutf8

cc -std=c23 -O1 -g -fsanitize=address,undefined -Iinclude \
   src/zutf8.c tests/test_zutf8.c -o test_zutf8
./test_zutf8
```

The test suite includes the RFC 3629 boundary known-answer tables and a
full encode→decode round-trip sweep over every Unicode scalar value.

## License

Apache-2.0 (see LICENSE).
