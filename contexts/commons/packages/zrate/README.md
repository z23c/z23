# zrate

Rate limiting primitives for C23: token bucket and sliding window.

- Classic token bucket with fractional tokens, caller-injected
  monotonic time (fully deterministic and testable), try-consume and
  wait-until computation.
- Exact sliding-window "N per interval" counter over a caller-provided
  circular log of timestamps.
- No allocation, no wall clock, no dependencies beyond libc.

## API

```c
#include <zrate/zrate.h>

zrate_bucket b;
zrate_bucket_init(&b, 100.0, 10.0, now_ms);  /* 100 burst, 10/s */
if (zrate_bucket_take(&b, 1.0, now_ms)) { /* allowed */ }
uint64_t wait = zrate_bucket_wait_ms(&b, 1.0, now_ms);

uint64_t events[30];
zrate_window w;
zrate_window_init(&w, events, 30, 60*1000);  /* 30 per minute */
if (!zrate_window_hit(&w, now_ms)) { /* over limit */ }
```

## CLI

```sh
zrate bucket 10 2 0:5 0:5 3000:3
zrate window 3 1000 0 100 500 999 1000
```

## License

Apache-2.0. See LICENSE.
