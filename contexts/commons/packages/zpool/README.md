# zpool — fixed-block pool allocator for C23

zpool carves a caller-supplied arena into equal, fully aligned blocks
and hands them out in O(1). No malloc, no growth, no global state: the
pool is exactly as big as the arena you give it, and exhaustion is a
NULL, never a surprise.

- Bounded and total: block size is rounded up to `max_align_t`
  alignment (and to hold the free-list link); the arena must be
  `max_align_t`-aligned. Anything that cannot work fails at init.
- Validated frees: out-of-arena, misaligned, and double-free are
  rejected with `false` instead of corrupting the free list. Detection
  is exact — free state lives only in free blocks, and `zpool_free`
  walks the list (O(free blocks)); no metadata is stored inside live
  blocks, so callers may scribble over the whole block they own.
- The `zpool` struct is caller-owned plain data; copy it, embed it,
  put it in static storage.

## API

```c
#include "zpool/zpool.h"

static _Alignas(16) unsigned char arena[16 * 64];
zpool p;
if (!zpool_init(&p, arena, sizeof arena, 64)) { /* misconfigured */ }

void *b = zpool_alloc(&p);          /* NULL when exhausted */
if (!zpool_free(&p, b)) { /* not a live, aligned block of this pool */ }
size_t left = zpool_available(&p);
bool live = zpool_owns(&p, b);
```

## CLI

`zpool` is a deterministic ops driver for exploring or diffing pool
behaviour:

```
$ printf 'a\na\nf 0\no 0\nf 0\ns\n' | zpool 32 4
a -> 0
a -> 1
f 0 -> ok
o 0 -> no
f 0 -> rejected
s -> free 3/4
```

Ops: `a` (alloc), `f IDX` (free), `o IDX` (owns query), `s` (state).
Bounds: block size 1..64, block count 1..4096.

## Build and test

```sh
cc -std=c23 -O2 -Iinclude src/zpool.c app/main.c -o zpool

cc -std=c23 -O1 -g -fsanitize=address,undefined -Iinclude \
   src/zpool.c tests/test_zpool.c -o test_zpool
./test_zpool
```

Tests cover init validation (overflow, alignment, tiny arenas),
exhaustion, LIFO reuse through fully scribbled blocks, every rejected
free shape (double, misaligned, out-of-arena, never-allocated),
`zpool_owns`, and a 2000-round interleaved churn with per-round
aliasing and accounting checks.

## License

Apache-2.0 (see LICENSE).
