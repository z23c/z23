# zlru — bounded LRU cache for C23, built on zmap

zlru is the cache every long-lived process eventually needs: string
keys, opaque values, caller-injected allocation, and a hard entry
bound. Inserting past capacity evicts the least-recently-used entry;
get and put both count as use. It layers a recency list over
[zmap](../zmap/)'s hash table, O(1) in both directions.

- Bounded by construction: capacity is fixed at creation (nonzero),
  eviction is immediate, and allocation failure is a clean `false`
  with the cache unchanged.
- Honest lifetimes: values are never owned; an optional destructor
  runs exactly once per entry exit (replace, eviction, erase,
  destroy). The stress test proves exact destructor accounting over
  10,000 mixed operations.
- No global mutable state; each cache carries its own allocator
  (forwarded to zmap).
- `zlru_visit_mru_first` walks entries in recency order without
  promoting them — for diagnostics and serialization.

## API

```c
#include "zlru/zlru.h"

zlru *c = zlru_create(1024, my_dtor, my_ctx, (zmap_alloc){0});

if (!zlru_put(c, "answer", value)) { /* allocation failed */ }
void *v = zlru_get(c, "answer");  /* promotes to MRU */
zlru_erase(c, "answer");          /* dtor runs */

zlru_destroy(c);                  /* dtor on every live entry */
```

## CLI

`zlru` is a cache-trace analyzer: replay an access log against a
hypothetical cache before you deploy one.

```
$ printf 'a\nb\na\nc\n' | zlru 2
MISS a
MISS b
HIT a
MISS c
# 4 keys: 1 hits, 3 misses, hit rate 0.250
```

## Build and test

```sh
cc -std=c23 -O2 -Iinclude -I../zmap/include \
   src/zlru.c ../zmap/src/zmap.c app/main.c -o zlru

cc -std=c23 -O1 -g -fsanitize=address,undefined \
   -Iinclude -I../zmap/include \
   src/zlru.c ../zmap/src/zmap.c tests/test_zlru.c -o test_zlru
./test_zlru
```

Tests cover eviction order, replace promotion, erase paths, capacity 1,
visit order and early stop, injected allocation failure (cache
unchanged), NULL safety, and a 10k-operation churn with exact
destructor accounting.

## License

Apache-2.0 (see LICENSE).
