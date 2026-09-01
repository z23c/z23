# zslug

Deterministic URL/filename slug generation in freestanding C23.

`zslug` turns arbitrary UTF-8 text into a lowercase ASCII slug:

- ASCII letters are lowercased, digits kept.
- Latin-1 supplement letters (U+00C0..U+00FF) fold to their
  conventional ASCII base spelling (`é`→`e`, `ß`→`ss`, `æ`→`ae`,
  `þ`→`th`, …). The fold table is explicit and fully tested; this is
  not full Unicode transliteration.
- Everything else — including malformed UTF-8 — acts as a word
  separator. Separator runs collapse; leading/trailing separators are
  dropped.
- `snprintf`-style contract: the return value is the untruncated slug
  length, so truncation is detectable. Output is always NUL-terminated
  when capacity permits. `max_len` truncation happens at a word
  boundary when possible.
- `zslug_is_canonical` validates that a string already is a slug under
  given options.
- No allocation, no locale, no globals: thread-safe and embeddable.

## API

```c
zslug_opts o = zslug_default_opts();      /* '-', unlimited, fold case */
size_t n = zslug(in, len, out, cap, &o);  /* returns untruncated length */
int ok = zslug_is_canonical(s, len, &o);
```

## CLI

```
zslug "Héllo, Wörld!"        # hello-world
echo "Crème Brûlée" | zslug  # creme-brulee
zslug -s_ "a b c"            # a_b_c
```

## Tests

Golden KATs, exhaustive Latin-1 fold table, truncation boundaries,
canonical-form checker, and randomised idempotence/boundedness oracles
(slug is a projection: `slug(slug(x)) == slug(x)`). Built with
`-std=c23 -Wall -Wextra -Werror -pedantic` under ASan/UBSan.

Apache-2.0 licensed.
