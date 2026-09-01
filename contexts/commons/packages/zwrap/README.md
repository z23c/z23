# zwrap

Greedy UTF-8-aware word wrapping in C23, built on the
[`zutf8`](../zutf8) package for decoding.

- Width is measured in codepoints, not bytes: `中文` is two columns.
- Hard-breaks never split a multi-byte sequence.
- Spaces/tabs collapse at wrap points; existing newlines are preserved
  and reset the column.
- Long words: hard-broken at the width boundary by default, or left to
  overflow with `break_long = 0`.
- Malformed UTF-8 passes through byte-for-byte, one column per byte;
  output is valid UTF-8 whenever the input is.
- `snprintf`-style contract: returns the would-be length, always
  NUL-terminates when capacity permits, NULL/0 measures.
- No allocation, no globals.

## API

```c
zwrap_opts o = zwrap_default_opts(); /* width 72, break_long 1 */
size_t n = zwrap(in, len, out, cap, &o);
```

## CLI

```
zwrap 20 < paragraph.txt
```

## Tests

Golden wraps at boundary widths, long-word policies, codepoint-accurate
width with 2/3/4-byte sequences, invalid-UTF-8 pass-through,
measurement and truncation contracts, and a 3000-trial fuzz oracle
asserting every emitted line stays within the width (via
`zutf8_count_n`) with no trailing blanks. Built with
`-std=c23 -Wall -Wextra -Werror -pedantic` under ASan/UBSan.

Depends on `zutf8/zutf8` 0.1.0 (exact root pinned in the manifest).
Apache-2.0 licensed.
