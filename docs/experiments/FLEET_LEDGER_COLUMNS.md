<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Fleet ledger column integrity

Measured at 2026-09-06T07:05:23-04:00 / 2026-09-06T11:05:23Z on
AMD Ryzen 7 PRO 8840U with GCC 16.1.1 20260430, from baseline
`07aa9b93b958a664f130d28ad14036b869a9713b`.

The fleet observation generator must refuse malformed ledger columns before
writing routing observations. The previous tokenizer collapsed tab delimiters:
adding a leading, repeated, or trailing tab to fixture row 2 still admitted
that row. Each of these three regression cases failed against the baseline.

The parser now preserves every column boundary, requires exactly 22 fields,
and rejects empty fields. The existing gate exercises five malformed variants:
leading tab, repeated tab, trailing tab, empty interior field, and extra
nonempty field. Each must exit 2, identify line 2, and preserve an existing
output file byte-for-byte.

Reproduce the focused acceptance from the repository root:

```bash
cc -std=c23 -O2 -Wall -Wextra -Werror -pedantic -Itools/dev \
  tools/dev/fleet_observe.c tools/dev/fleet_observe_main.c \
  -o /tmp/z23-fleet-observe
ZCL_FLEET_OBS_BIN=/tmp/z23-fleet-observe \
  tools/lint/check_fleet_observations.sh --selftest
ZCL_FLEET_OBS_BIN=/tmp/z23-fleet-observe \
  tools/lint/check_fleet_observations.sh
```

All eight selftest checks passed after the change. The committed fixture still
reproduced its 11 observations and documentation table without regeneration.
The selftest also passed with `-O1 -g -fsanitize=address,undefined
-fno-omit-frame-pointer` replacing `-O2`. These are local parser and generator
checks; they do not establish distributed fleet acceptance or a performance
improvement.
