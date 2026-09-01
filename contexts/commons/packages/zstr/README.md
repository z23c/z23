# zstr

Bounded, honest C string utilities for C23.

- `zstr_copy` / `zstr_concat`: strlcpy/strlcat semantics — always
  NUL-terminate, always report the would-be length so truncation is
  detectable, never write past capacity even on unterminated buffers.
- In-place trim and ASCII case folding; case-insensitive compare.
- Prefix/suffix tests and non-overlapping occurrence counting.
- Zero-allocation split iterator that keeps empty fields.

No allocation, no dependencies beyond libc, NULL never dereferenced.

## API

```c
#include <zstr/zstr.h>

size_t zstr_copy(char *dst, size_t cap, const char *src);
size_t zstr_concat(char *dst, size_t cap, const char *src);
char  *zstr_trim(char *s);
char  *zstr_to_lower(char *s);
char  *zstr_to_upper(char *s);
int    zstr_casecmp(const char *a, const char *b);
bool   zstr_case_equal(const char *a, const char *b);
bool   zstr_starts_with(const char *s, const char *prefix);
bool   zstr_ends_with(const char *s, const char *suffix);
size_t zstr_count(const char *s, const char *needle);

zstr_split_it it;
zstr_split_init(&it, "a,,b", ',');
zstr_span sp;
while (zstr_split_next(&it, &sp)) { /* sp.ptr, sp.len */ }
```

## CLI

```sh
zstr trim "  hi  "        # hi
zstr count "aaa" aa       # 1
zstr split , a,,b         # a / (empty) / b
```

## License

Apache-2.0. See LICENSE.
