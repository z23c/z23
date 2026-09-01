# zjson — bounded JSON writer for C23

zjson serializes JSON (RFC 8259) into caller storage. No malloc, no
global state, no surprises: the document is exactly as large as the
buffer you give it, and overflow is a measured status, never a
corruption.

- Bounded and total: every call returns a status. On overflow the
  writer keeps measuring, so `zjson_len()` reports the exact capacity
  a retry would need.
- Structurally exact: the state machine rejects a value in key
  position, a key in an array, a mismatched close, a dangling key, a
  second top-level value, and nesting beyond `ZJSON_MAX_DEPTH` (32).
  If the calls returned `ZJSON_OK`, the output is well-formed JSON.
- Exact strings: keys and string values must be well-formed UTF-8
  (validated via [zutf8](../zutf8)); control characters, `"` and `\`
  are escaped exactly per RFC 8259; everything else passes through.
- Exact numbers: `int64_t`/`uint64_t` print in full; doubles print
  with `%.17g` (round-trips every IEEE 754 binary64 value); NaN and
  infinities are rejected because JSON cannot represent them.
- The first error is sticky — after any failure, later calls are
  no-ops returning the recorded status.

## API

```c
#include "zjson/zjson.h"

char buf[256];
zjson w;
zjson_init(&w, buf, sizeof buf);

zjson_obj_open(&w);
zjson_key(&w, "name");
zjson_str(&w, "zjson");
zjson_key(&w, "tags");
zjson_arr_open(&w);
zjson_str(&w, "json");
zjson_i64(&w, 23);
zjson_arr_close(&w);
zjson_obj_close(&w);

size_t len = 0;
if (zjson_finish(&w, &len) != ZJSON_OK) { /* inspect zjson_status_of() */ }
/* buf now holds {"name":"zjson","tags":["json",23]} */
```

## CLI

`zjson` turns `key<TAB>value` lines on stdin into a JSON object:

```
$ printf 'name\tzjson\nversion\t0.1.0\n' | zjson
{"name":"zjson","version":"0.1.0"}
```

Bounds: lines up to 4095 bytes, output up to 1 MiB. All values are
strings; compose programmatically for typed output.

## Build and test

```sh
cc -std=c23 -O2 -Iinclude -I<zutf8>/include \
   src/zjson.c <zutf8>/src/zutf8.c app/main.c -o zjson

cc -std=c23 -O1 -g -fsanitize=address,undefined \
   -Iinclude -I<zutf8>/include \
   src/zjson.c <zutf8>/src/zutf8.c tests/test_zjson.c -o test_zjson
./test_zjson
```

Tests cover KAT documents, every mandatory escape plus UTF-8
passthrough, invalid-UTF-8 rejection, integer and double formatting
(including `strtod` round-trips), NaN/Inf refusal, every state-machine
violation, the depth bound, exact-fit/one-short/NULL-buffer overflow
accounting, NULL safety, and 2000 random documents checked by a
structural validator.

## License

Apache-2.0 (see LICENSE).
