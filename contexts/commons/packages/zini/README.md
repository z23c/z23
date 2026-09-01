# zini

INI configuration parser for C23 over caller-supplied bytes — no filesystem
I/O in the library. Parsed entries are stored in **zmap** hash maps (one map
of section name → `zmap*` of key → value copy), so this package genuinely
depends on `zmap/zmap`.

## Grammar (documented, deliberately small)

- Lines end on LF; a trailing CR is stripped (CRLF files work).
- Blank lines and lines whose first non-space character is `#` or `;` are
  comments.
- `[name]` opens a section; the name is trimmed and may be empty. Keys
  before any section header land in the global section, addressed by `""`
  (or NULL in `zini_get`). An empty section name aliases the global section.
- `key = value`: key is everything before the first `=`, trimmed, non-empty;
  value is trimmed and may be empty.
- **Inline comments:** a `#` or `;` inside a value starts a comment only
  when preceded by a space or tab — `a#b` is data, `a # b` is `a`.
- **Duplicate keys:** last wins, both within a section and across repeated
  sections of the same name.
- No value quoting, no line continuation, no nesting.

## Iteration order

`zini_foreach` visits entries in a **deterministic sorted order**: sections
lexicographically (the global section `""` sorts first), then keys
lexicographically within each section. File order is not preserved.

## API summary

```c
zini       *zini_parse(const char *text, size_t len, zini_error *err);
void        zini_destroy(zini *);
const char *zini_get(const zini *, const char *section /* NULL = global */,
                     const char *key);
size_t      zini_count(const zini *);
void        zini_foreach(const zini *, zini_entry_fn, void *ctx);
```

The returned `zini` owns copies of all sections/keys/values; the input bytes
may be freed right after `zini_parse`. `zini_get` returns a borrowed pointer
valid until `zini_destroy`. On parse failure `zini_parse` returns NULL and
fills `zini_error` with a 1-based line number and a static message.

## Example

```c
zini_error err;
zini *ini = zini_parse(text, len, &err);
if (!ini) { fprintf(stderr, "line %zu: %s\n", err.line, err.message); return 1; }
printf("%s\n", zini_get(ini, "server", "host"));
zini_destroy(ini);
```

## Dependency: FACTORY-PINNED

`zcode-package.json` lists `zmap/zmap` with a **placeholder
content root** (`0000…0000`). The real content root only exists once zmap
has been published to the Commons; the factory slice replaces the
placeholder with the published root before publishing zini. // FACTORY-PINNED

For local development (this repo checkout), zini compiles standalone against
the sibling package's headers:

```sh
cc -std=c23 -I contexts/commons/packages/zini/include -I contexts/commons/packages/zmap/include \
   contexts/commons/packages/zini/src/zini.c contexts/commons/packages/zmap/src/zmap.c ...
```

The real Commons build does not use that include path; the recipe system
resolves the pinned dependency by content root.

## App

`app/main.c` builds `inidump`: reads INI from stdin (bounded at 16 MiB) and
prints a flattened, sorted `section.key = value` dump.

## Tests

`tests/test_zini.c` covers sections/keys, the global section, full-line and
inline comments (including the whitespace rule and `a#b` staying data),
duplicate-key last-wins across repeated sections, empty values, whitespace
trimming, CRLF, malformed lines (no `=`, empty key, unterminated `[`,
junk after `]`) with line numbers, empty input, and deterministic sorted
iteration verified against two different file orderings.
