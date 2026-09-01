# zglob

Shell-style wildcard (glob) matching for C23 — allocation-free,
NUL-free (explicit lengths), iterative with single-star backtracking.

## Design

- **Syntax:** `*` matches any run (including empty), `?` exactly one
  character, `[...]` a character class with ranges (`a-z`) and negation
  (`!` first), `\` escapes the next character literally (inside classes
  too). A `]` first in a class is a literal `]`.
- **Fail-closed on malformed patterns:** an unterminated class or a
  trailing escape never matches — pattern bugs surface as zero matches,
  never as a surprising acceptance.
- **No recursion, no allocation:** one star fallback point keeps runtime
  at O(pattern × text) worst case with constant memory; embedded NULs
  match like any other byte via the explicit-length form.

## API summary

```c
bool zglob_match_n(const char *pat, size_t plen, const char *str, size_t slen);
bool zglob_match(const char *pat, const char *str);  /* NUL-terminated */
```

## Example

```c
zglob_match("src/*.c", "engine/entry/main.c");   /* true  */
zglob_match("report-[0-9]*", "report-"); /* false */
```

## App

`app/main.c` builds a grep-lite filter: `zglob PATTERN` reads stdin lines
(bounded at 16 MiB, lines at 4096 bytes) and prints the ones matching the
pattern; exit 0 when at least one matched, 1 when none did, 2 on misuse.

## Tests

`tests/test_zglob.c` covers literals, star runs and ordering, `?`, classes
(ranges, negation, literal `]` first, escaped `-`), escapes, malformed
patterns (unterminated class, trailing escape), a star-backtracking
pathological case that must terminate promptly, and the explicit-length
entry points.
