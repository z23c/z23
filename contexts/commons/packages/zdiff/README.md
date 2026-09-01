# zdiff — bounded line diff for C23

zdiff computes an exact LCS edit script between two texts and renders
it as `' '` / `'-'` / `'+'` prefixed lines. Allocation-free: line
arrays, the dynamic-programming table, and the op script all live in
caller storage.

- Exact and deterministic: full LCS dynamic program, ties break
  toward deletion first, so the same inputs always produce the same
  script.
- Bounded and total: at most `ZDIFF_MAX_LINES` (65535) lines per side
  and `ZDIFF_MAX_CELLS` (4 Mi) DP cells per comparison; anything
  larger fails with `ZDIFF_BOUND`, never with an allocation surprise.
  `zdiff_cells()` pre-computes the exact table size.
- Lines are byte slices between `\n` separators compared bytewise; a
  trailing partial line is a line, and its content compares equal to
  its newline-terminated twin.
- The script applies cleanly by construction: KEEP/DEL ops in order
  reconstruct the old text, KEEP/INS ops the new text (the property
  test verifies this on thousands of random pairs).

## API

```c
#include "zdiff/zdiff.h"

static zdiff_line ol[1024], nl[1024];
static uint32_t dp[1025 * 1025];
static zdiff_op ops[2048];

size_t n = 0;
zdiff_status st = zdiff_texts(old, old_len, ol, 1024,
                              new, new_len, nl, 1024,
                              dp, 1025 * 1025, ops, 2048, &n);
/* st == ZDIFF_OK: ops[0..n) is the script */
```

For pre-split lines use `zdiff_split()` + `zdiff_run()` directly.

## CLI

`zdiff OLD NEW` prints the script and exits 0 (identical),
1 (different), or 2 (error). Files are capped at 4 MiB.

```
$ printf 'a\nb\nc\n' > old; printf 'a\nd\nc\n' > new
$ zdiff old new
  a
- b
+ d
  c
```

## Build and test

```sh
cc -std=c23 -O2 -Iinclude src/zdiff.c app/main.c -o zdiff

cc -std=c23 -O1 -g -fsanitize=address,undefined -Iinclude \
   src/zdiff.c tests/test_zdiff.c -o test_zdiff
./test_zdiff
```

Tests cover line splitting edge cases, KAT scripts (substitution,
insertion, deletion, repeated lines, partial final line), bound and
space failures with exact needs reporting, NULL safety, and 4000
random pairs verified by script application and keep-monotonicity.

## License

Apache-2.0 (see LICENSE).
