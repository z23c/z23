# ztime — RFC 3339 timestamps for C23

ztime parses and formats RFC 3339 timestamps (`YYYY-MM-DDTHH:MM:SS[.f]Z`
or with a numeric offset) as Unix seconds plus nanoseconds, with strict
calendar validation. It is the timestamp layer a Commons package needs
for receipts, logs, and evidence objects — without pulling in the C
time library, timezones, or allocation.

- Strict by construction: month/day ranges follow the proleptic
  Gregorian calendar (leap centuries handled), leap seconds (`:60`)
  are rejected rather than smeared, fractions beyond nanosecond
  precision fail closed.
- Total and allocation-free: every input either parses or fails with
  the output struct zeroed; formatting writes into the caller's buffer
  (32 bytes always suffice) and reports the exact length.
- Civil-date primitives (`ztime_days_from_civil`,
  `ztime_civil_from_days`, `ztime_days_in_month`, `ztime_is_leap_year`)
  are exposed for date-only arithmetic.

## API

```c
#include "ztime/ztime.h"

ztime_instant it;
if (!ztime_parse("2001-09-09T01:46:40Z", &it)) { /* invalid */ }
/* it.unix_secs == 1000000000, it.nanos == 0 */

ztime_parse("1969-12-31T18:30:00-05:30", &it); /* offsets applied: 0 */

char buf[32];
size_t n = ztime_format(&it, buf, sizeof buf); /* "1970-01-01T00:00:00Z" */
```

Formatting always emits the canonical UTC `...Z` form with a
trailing-zero-trimmed fraction when `nanos != 0`. The representable
range is years 0000..9999.

## CLI

```
$ ztime parse 2001-09-09T01:46:40Z 1969-12-31T18:30:00-05:30
1000000000
0
$ ztime format 1000000000
2001-09-09T01:46:40Z
```

Exit 0 when every argument converts, 1 on any failure, 2 on misuse.

## Build and test

```sh
cc -std=c23 -O2 -Iinclude src/ztime.c app/main.c -o ztime

cc -std=c23 -O1 -g -fsanitize=address,undefined -Iinclude \
   src/ztime.c tests/test_ztime.c -o test_ztime
./test_ztime
```

The test suite checks the published epoch anchors, leap-century tables,
rejection of every grammar/range violation, and a parse∘format
round-trip sweep across the whole 4-digit-year range.

## License

Apache-2.0 (see LICENSE).
