# zfmt

Allocation-free buffer formatting for C23.

- Cursor over a caller buffer: strings, spans, chars, u64/i64 decimal,
  fixed-width hex, zero-padded decimals, fixed-precision doubles.
- Sticky error model: an append that doesn't fit truncates cleanly,
  keeps the buffer NUL-terminated, and refuses further appends — check
  once at the end with `zfmt_ok`.
- Integer output cross-checked against `snprintf` over randomized
  values including INT64_MIN.
- No allocation, no dependencies beyond libc.

## API

```c
#include <zfmt/zfmt.h>

char buf[128];
zfmt f;
zfmt_init(&f, buf, sizeof buf);
zfmt_str(&f, "height=");
zfmt_u64(&f, 3203194);
zfmt_str(&f, " t=");
zfmt_double(&f, 6.25, 2);
zfmt_str(&f, "s");
if (!zfmt_ok(&f)) { /* truncated */ }
puts(zfmt_cstr(&f));   /* "height=3203194 t=6.25s" */
```

## CLI

```sh
zfmt u64 3203194
zfmt pad 42 5          # 00042
zfmt double 6.25 2     # 6.25
zfmt template world 3  # hello world, count=3
```

## License

Apache-2.0. See LICENSE.
