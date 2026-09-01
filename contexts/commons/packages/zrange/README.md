# zrange — semantic-version range matching for C23

zrange parses and evaluates semver **range expressions** (`^1.2.3`,
`~1.2.3`, `>=1.2.3 <2.0.0 || >=3.0.0`) on top of
[zsemver](../zsemver/) version primitives. It is what a package
consumer needs to answer "does this installed version satisfy my
dependency constraint?" — the question every resolver asks.

- Allocation-free and bounded: the parsed range lives entirely in the
  caller's `zrange` struct (max 4 union sets, 16 comparators total;
  larger input is a parse error, never a truncation).
- Strict SemVer 2.0.0 versions via zsemver (no wildcards, no partial
  versions, no leading zeros).
- npm-compatible caret/tilde expansion tables and prerelease gating,
  transcribed as known-answer tests.

## Grammar

```
range      := set ( "||" set )*          -- union
set        := comparator ( ws comparator )*  -- intersection
comparator := [ "<" | "<=" | ">" | ">=" | "=" ] version
            | "^" version    -- compatible-with
            | "~" version    -- approximately-equivalent
```

| Range     | Expansion          |
|-----------|--------------------|
| `^1.2.3`  | `>=1.2.3 <2.0.0`   |
| `^0.2.3`  | `>=0.2.3 <0.3.0`   |
| `^0.0.3`  | `>=0.0.3 <0.0.4`   |
| `~1.2.3`  | `>=1.2.3 <1.3.0`   |

Prerelease rule (npm-compatible): a version carrying a prerelease
satisfies a comparator set only when some comparator in that set has
the same `[major, minor, patch]` and itself carries a prerelease.

Deliberately excluded (fail-closed at parse): wildcards (`1.2.x`),
hyphen ranges, partial versions, the empty range.

## API

```c
#include "zrange/zrange.h"

zrange r;
if (!zrange_parse("^1.2.3 || >=3.0.0-rc.1 <4.0.0", &r)) { /* invalid */ }

zsemver v;
zsemver_parse("1.5.0", &v);
bool ok = zrange_satisfies(&r, &v);

/* one-shot convenience: */
ok = zrange_test("^1.2.3", "1.5.0");
```

All functions are pure over their arguments; the parsed comparators
borrow the range input, so keep the range string alive while using a
parsed `zrange`.

## CLI

```
$ printf '1.2.0\n1.5.0\n2.0.0\n' | zrange '^1.2.3'
1.5.0
```

Exit 0 when at least one input line satisfies the range, 1 when none
did, 2 on misuse or an invalid range. Non-semver lines are skipped with
a stderr note.

## Build and test

```sh
cc -std=c23 -O2 -Iinclude -I../zsemver/include \
   src/zrange.c ../zsemver/src/zsemver.c app/main.c -o zrange

cc -std=c23 -O1 -g -fsanitize=address,undefined \
   -Iinclude -I../zsemver/include \
   src/zrange.c ../zsemver/src/zsemver.c tests/test_zrange.c -o test_zrange
./test_zrange
```

## License

Apache-2.0 (see LICENSE).
