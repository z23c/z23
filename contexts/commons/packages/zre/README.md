# zre

Regular expressions for C23 with **guaranteed linear-time matching**.
Patterns compile to a Thompson NFA and run on a pike VM (parallel lockstep
simulation) — there is no backtracking anywhere, so no pattern/input pair
can cause catastrophic blowup. Runtime is O(program size × text length)
with memory fixed at compile time.

## Syntax

The whole language; anything else is a fail-closed compile error naming
the offending offset:

- **literals** — any byte except metacharacters matches itself
- **`.`** — any byte except `'\n'`
- **`*` `+` `?`** — greedy postfix repeats; lazy forms (`*?` etc.) do not
  exist and are compile errors
- **`{m}` `{m,}` `{m,n}`** — counted repeat, 0 ≤ m ≤ n ≤ 255; a `{` not
  followed by a digit is a literal brace
- **`[...]`** — byte class with ranges (`a-z`), negation (`^` first),
  escapes and shorthand classes inside; `]` first and `-` last are literals
- **escapes** — `\d \D \w \W \s \S` (ASCII shorthands), `\n \t \r \f \v`,
  `\xNN` (exactly two hex digits), `\` + any ASCII punctuation for a
  literal; `\1`-style backreferences are `ZRE_ERR_UNSUPPORTED`
- **`^` `$`** — absolute anchors (start/end of the whole text, no multiline)
- **`(...)`** — capturing group (≤ 8, numbered from 1); **`(?:...)`** —
  non-capturing; other `(?` forms (lookahead, named groups) are
  `ZRE_ERR_UNSUPPORTED`
- **`|`** — alternation, lowest precedence; empty alternatives allowed

## Semantics

**Leftmost-first** (Perl-like): the match starts at the lowest text offset
that admits one; among paths from there, thread priority makes quantifiers
greedy and prefers the left alternative. `zre_match` searches unanchored
(grep-style); wrap in `^`/`$` to pin. Empty matches are valid: `a*` on
`"bbb"` matches the empty span `[0,0)`.

Byte-oriented: UTF-8 text matches per byte — a multibyte code point is
several bytes and `.` matches one of them. Embedded NULs are fine via the
explicit-length API and `\x00`.

## Bounds (compile errors, never truncation)

`ZRE_MAX_PATTERN` 4096 pattern bytes · `ZRE_MAX_PROG` 1024 instructions ·
`ZRE_MAX_GROUPS` 8 capture groups · `ZRE_MAX_NEST` 32 nesting depth ·
`ZRE_MAX_REPEAT` 255 counted-repeat bound.

## API summary

```c
zre_status zre_compile(const char *pattern, size_t len, zre_prog **prog_out,
                       char *errbuf, size_t errbuf_cap);
bool       zre_match(const zre_prog *prog, const char *text, size_t len,
                     zre_span caps[], size_t max_caps); /* caps[0]=whole */
size_t     zre_groups(const zre_prog *prog);
void       zre_free(zre_prog *prog);
const char *zre_strerror(zre_status st);
```

Non-participating groups report `{ZRE_NOMATCH, ZRE_NOMATCH}`. Compile
failures are named (`zre_status`) and explained in `errbuf`.

## App

`app/main.c` builds a grep: `zre PATTERN [FILE]` (or stdin) prints
matching lines — exit 0 on a match, 1 on none, 2 on misuse or input over
the 16 MiB bound. Lines are bounded at 4096 bytes for matching.

## Tests

`tests/test_zre.c` covers every construct, anchors, alternation precedence,
capture spans (nested, empty, non-participating, truncated arrays),
leftmost-first/greedy semantics, every named compile error, and the
adversarial suite: `(a*)*b`, `(a|aa)+$`, `(.*)*x` and friends over 1024
bytes of non-matching input, iterated 200× — exponential for a backtracker,
bounded here by construction.
