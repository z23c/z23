# zhuman

Human-readable sizes and durations for C23.

- Format bytes as IEC ("1.5 KiB") or SI ("1.5 MB"); parse both back.
- Format millisecond durations as "1d 2h 3m 4.567s"; parse back with
  optional spacing and per-unit fraction on seconds.
- Strict parsing: unknown units, repeated units, and overflows are
  errors. Integer arithmetic, no floating point in parsing.
- No allocation, no dependencies beyond libc.

## API

```c
#include <zhuman/zhuman.h>

zhuman_err zhuman_format_bytes_iec(uint64_t bytes, char *out, size_t cap);
zhuman_err zhuman_format_bytes_si(uint64_t bytes, char *out, size_t cap);
zhuman_err zhuman_parse_bytes(const char *str, uint64_t *out);

zhuman_err zhuman_format_duration(uint64_t ms, char *out, size_t cap);
zhuman_err zhuman_parse_duration(const char *str, uint64_t *out_ms);
```

## CLI

```sh
zhuman bytes 1536             # 1.5 KiB
zhuman bytes --si 1500        # 1.5 kB
zhuman parse-bytes "1.5 KiB"  # 1536
zhuman duration 90061         # 1m 30.061s
zhuman parse-duration 1h30m   # 5400000
```

## License

Apache-2.0. See LICENSE.
