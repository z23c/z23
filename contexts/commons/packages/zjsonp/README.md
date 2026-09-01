# zjsonp — bounded JSON pull parser for C23

zjsonp parses JSON (RFC 8259) from caller memory, one event per call.
Companion to the [zjson](../zjson) writer. No DOM, no malloc, no
global state: the parser holds a position and a 32-level state stack,
and events are slices of your input.

- Strict grammar: whitespace is only SP/HT/LF/CR; numbers match the
  RFC 8259 production exactly (no leading zeros, no bare point, no
  `+`); strings reject raw control bytes, malformed escapes, and
  invalid UTF-8 (validated via [zutf8](../zutf8)).
- Structurally total: one top-level value, nesting bounded by
  `ZJRP_MAX_DEPTH` (32), trailing commas and mismatched closes are
  `ZJRP_SYNTAX` at the offending byte (`zjsonp_pos()`).
- Payloads stay zero-copy: `ZJRP_KEY`/`ZJRP_STR`/`ZJRP_NUM` events
  point into the input; decode escapes (including `\uXXXX` surrogate
  pairs) with `zjsonp_str_decode()` and numbers with
  `zjsonp_num_i64()` / `zjsonp_num_f64()`.

## API

```c
#include "zjsonp/zjsonp.h"

zjsonp p;
zjsonp_init(&p, text, len);
for (;;) {
  zjsonp_event ev;
  zjsonp_status st = zjsonp_next(&p, &ev);
  if (st == ZJRP_DONE) break;
  if (st != ZJRP_OK) { /* syntax at zjsonp_pos(&p) */ }
  /* ev.kind, ev.off, ev.len — payload is text + ev.off */
}
```

## CLI

`zjsonp` validates stdin (bounded to 16 MiB) and dumps the indented
event stream:

```
$ echo '{"a":[1,null]}' | zjsonp
obj-open
  key a
  arr-open
    num 1
    null null
  arr-close
obj-close
```

Exit 0 valid, 1 syntax/depth error (byte offset on stderr), 2 I/O.

## Build and test

```sh
cc -std=c23 -O2 -Iinclude -I<zutf8>/include \
   src/zjsonp.c <zutf8>/src/zutf8.c app/main.c -o zjsonp

cc -std=c23 -O1 -g -fsanitize=address,undefined \
   -Iinclude -I<zutf8>/include \
   src/zjsonp.c <zutf8>/src/zutf8.c tests/test_zjsonp.c -o test_zjsonp
./test_zjsonp
```

Tests cover KAT event streams, a 27-case malformed-input table,
UTF-8 acceptance/rejection, escape decoding (surrogate pairs, lone
surrogates, measuring with cap 0), integer overflow and double
semantics (negative zero included), the depth bound, error offsets,
NULL safety, and a 4000-trial fuzz: random generated documents must
parse, and single-byte mutations must terminate cleanly.

## License

Apache-2.0 (see LICENSE).
