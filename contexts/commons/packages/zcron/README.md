# zcron

Standard 5-field cron schedule parsing and next-fire computation in
freestanding C23 — no `mktime`, no `localtime`, no timezone state.
Everything is computed in UTC from a Unix epoch with civil-calendar
arithmetic.

## Syntax

```
*            any value
n            single value
a-b          inclusive ascending range
a-b/s, */s   step within a range
x,y,z        comma list of the above
```

Month names (`jan`..`dec`) and weekday names (`sun`..`sat`) are
accepted case-insensitively; weekday accepts 0 and 7 for Sunday.
Day-of-month / day-of-week follow Vixie cron semantics: when both are
restricted, a time matches if EITHER matches; otherwise both must.

## API

```c
zcron c;
if (!zcron_parse("0 9 * * 1-5", 11, &c, err, sizeof err)) /* bad */;
long long fire = zcron_next(&c, after_epoch);  /* strictly after, -1 if none in 8y */
size_t n = zcron_format(&c, buf, cap);         /* canonical normal form */
```

## CLI

```
zcron "0 9 * * 1-5"            # next 5 fires from now, epoch + UTC
zcron "0 0 29 2 *" 1786752000  # fires after a given epoch
```

## Tests

Parse KATs and a rejection table; next-fire KATs anchored to epochs
verified against `date -u`; Vixie dom/dow OR-semantics; canonical
format round-trips (parse → format → parse must be a fixed point);
randomised invariant oracle (fire times are strictly increasing
minute multiples that satisfy the schedule); leap-year handling
including Feb 29 and the impossible Feb 31. Built with
`-std=c23 -Wall -Wextra -Werror -pedantic` under ASan/UBSan.

Apache-2.0 licensed.
