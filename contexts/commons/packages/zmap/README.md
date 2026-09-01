# zmap

Open-addressing string→`void*` hash map for C23 with caller-injected
allocation.

## Design

- **Hash:** FNV-1a 64-bit by default (`zmap_hash_fnv1a`). Simple, portable,
  well-distributed for string keys. `zmap_create_ex()` accepts any hash
  function — tests use this hook to force collisions.
- **Probing:** linear probing over a power-of-two table. Erased slots
  become tombstones; the table rehashes (dropping all tombstones) when
  (size + tombstones) reaches 3/4 of capacity, so erase churn cannot grow
  the table without bound.
- **Allocation:** every map carries a `zmap_alloc` (calloc-style); the
  default is malloc-backed (`zmap_alloc_malloc()`), and tests inject
  failing allocators to exercise the OOM paths. No global mutable state.
- **Ownership:** keys are duplicated on insert and owned by the map; values
  are opaque `void*` and never owned. `zmap_clear()`/`zmap_destroy()` take
  an optional destructor invoked once per live entry.

## API summary

```c
zmap   *zmap_create(void);                          /* defaults */
zmap   *zmap_create_ex(const zmap_alloc *, zmap_hash_fn);
bool    zmap_put(zmap *, const char *key, void *value, void **old_value);
void   *zmap_get(const zmap *, const char *key);
bool    zmap_contains(const zmap *, const char *key);
void   *zmap_erase(zmap *, const char *key);
size_t  zmap_size(const zmap *);
size_t  zmap_capacity(const zmap *);
void    zmap_clear(zmap *, zmap_destroy_fn, void *ctx);
void    zmap_destroy(zmap *, zmap_destroy_fn, void *ctx);
bool    zmap_next(const zmap *, zmap_iter *, const char **key, void **value);
```

`zmap_put` returns false only on allocator failure; iteration order is
unspecified and stable only while the map is not mutated. A stored `NULL`
value is indistinguishable from absence via `zmap_get` — use
`zmap_contains` when that matters.

## Example

```c
zmap *m = zmap_create();
zmap_put(m, "answer", (void *)42, NULL);
printf("%d\n", (int)(intptr_t)zmap_get(m, "answer"));
zmap_destroy(m, NULL, NULL);
```

## App

`app/main.c` builds `wordfreq`: tokenizes stdin into words (lowercased,
bounded at 64 MiB input), counts them in a `zmap`, and prints the top N
(default 20) by frequency, ties broken lexicographically.

## Tests

`tests/test_zmap.c` covers insert/lookup/replace/erase cycles, key-copy
ownership, tombstone churn with a capacity blowup bound, a constant-hash
collision hook, iteration completeness, destructor invocation, a failing
allocator, clear-and-reuse, and a 100k-entry smoke with a capacity bound.
