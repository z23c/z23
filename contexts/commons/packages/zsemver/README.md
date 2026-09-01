# zsemver

Strict Semantic Versioning 2.0.0 (semver.org) parsing and precedence
comparison for C23, with zero allocation.

## Design

- **Strict grammar:** `zsemver_parse_n()` validates the complete spec —
  numeric core fields without leading zeros, dot-separated prerelease
  identifiers (numeric ones again without leading zeros), and build
  metadata. Anything else is refused; there is no "lenient" mode, so a
  caller never has to wonder which dialect was accepted.
- **Zero allocation:** the parsed struct borrows the input string for the
  prerelease/build fields. No global state, no allocator interface.
- **Precedence:** `zsemver_compare()` implements spec item 11 exactly —
  build metadata is ignored, a release outranks its prereleases, numeric
  identifiers rank below alphanumeric ones, and a shorter identifier list
  ranks below a longer one when it is a prefix of it. The result is always
  exactly -1, 0, or 1.

## API summary

```c
bool zsemver_parse_n(const char *str, size_t len, zsemver *out);
bool zsemver_parse(const char *str, zsemver *out);   /* NUL-terminated */
int  zsemver_compare(const zsemver *a, const zsemver *b);
```

## Example

```c
zsemver a, b;
if (zsemver_parse("1.0.0-rc.1", &a) && zsemver_parse("1.0.0", &b))
  assert(zsemver_compare(&a, &b) == -1); /* prerelease < release */
```

## App

`app/main.c` builds `semversort`: reads one version per line from stdin
(bounded at 1 MiB / 65536 lines), refuses any line that is not strict
SemVer with its line number, and prints the versions in precedence order
(stable for equal precedence, e.g. differing build metadata).

## Tests

`tests/test_zsemver.c` covers the semver.org item-11 ordering chain
end to end, grammar rejections (leading zeros, empty identifiers,
overflow past UINT64_MAX, non-ASCII, trailing garbage), build-metadata
equality, numeric-versus-lexical identifier ordering, the borrowed-field
layout, and NULL-tolerance of the entry points.
