# zpq

Binary-heap priority queue for C23.

- Min-heap over `void *` with a ctx-carrying three-way comparator.
- push/pop O(log n), peek O(1), build-heap from an array in O(n),
  O(1) `replace` (pop+push in one sift).
- Caller-injected allocation; push returns false on allocation failure
  with the heap unchanged.
- Values are never owned.
- No dependencies beyond libc.

## API

```c
#include <zpq/zpq.h>

static int cmp(const void *a, const void *b, void *ctx) { ... }

zpq *pq = zpq_create(cmp, NULL, (zpq_alloc){0});
zpq_push(pq, &item);
void *min = zpq_peek(pq);
void *x = zpq_pop(pq);
zpq *h = zpq_from(items, n, cmp, NULL, (zpq_alloc){0}); /* heapify */
zpq_destroy(pq);
```

## CLI

```sh
zpq push 5 push 1 push 9 peek pop pop   # 1 / 1 / 5
```

## License

Apache-2.0. See LICENSE.
