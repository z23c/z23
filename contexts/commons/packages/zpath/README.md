# zpath — bounded lexical path manipulation (POSIX-style)

`zpath` provides purely lexical operations on slash-separated paths:
join, normalize, dirname, basename, extension lookup, absoluteness.
No allocation, no syscalls — nothing follows symlinks or touches the
filesystem.

## Features

- `zpath_join` — one separator, absolute RHS wins
- `zpath_normalize` — collapses `//`, resolves `.` and `..` lexically;
  `..` at the root stays at the root, leading `..` of a relative path
  is preserved; empty input becomes `.`
- `zpath_dirname` / `zpath_basename` — POSIX semantics, with optional
  suffix stripping for basename
- `zpath_ext` — zero-copy pointer to the final component's extension;
  `.hidden`, `.` and `..` have none
- `zpath_isabs`, `zpath_validate`

## Convention

All producers return the needed byte count (excluding NUL). Return
>= cap means the output was truncated; when cap > 0 it is always
NUL-terminated. `SIZE_MAX` signals NULL or over-long input
(> `ZPATH_MAX`, default 4096).

## Tests

`tests/test_zpath.c` covers KAT tables for normalize/join/dirname/
basename (including root, `..` overflow, trailing slashes), extension
edge cases, truncation and measuring mode, over-long rejection, NULL
safety, and a 6000-trial fuzz over the `/ . a` alphabet checking
idempotence and output invariants. Built and run under
`-fsanitize=address,undefined -Werror -pedantic`.

## License

Apache-2.0. See `LICENSE`.
