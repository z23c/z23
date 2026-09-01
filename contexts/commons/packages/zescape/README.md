# zescape

C-style string escaping and unescaping for C23.

- Escape renders `\n \r \t \\ \"` in classic notation and all other
  non-printable bytes as `\xNN`; printable ASCII passes through.
- Unescape is strict: unknown escape letters, truncated sequences and
  bad `\x` hex are errors with an exact byte position.
- Exact size queries (`zescape_escaped_max`, required-capacity return
  on `ZESCAPE_ERR_SMALL`); no allocation.
- No dependencies beyond libc.

## API

```c
#include <zescape/zescape.h>

size_t     zescape_escaped_max(size_t n);
zescape_err zescape_escape(const void *in, size_t len,
                           char *out, size_t cap, size_t *out_len);
zescape_err zescape_unescape(const char *in, size_t len,
                             void *out, size_t cap,
                             size_t *out_len, size_t *err_pos);
```

Supported escapes: `\\ \" \' \n \r \t \0 \a \b \f \v \xHH`.

## CLI

```sh
printf 'a\tb\n' | zescape escape     # a\tb\n (literal backslashes)
printf 'a\\x41' | zescape unescape   # aA
```

## License

Apache-2.0. See LICENSE.
