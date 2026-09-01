# zdeque

Fixed-capacity double-ended queue of `void *` for C23.

A bounded deque over caller-provided storage: O(1) push/pop at both
ends, indexed access, no allocation, no growth. Distinct from `zring`
(a single-producer/single-consumer byte FIFO) and `zvec` (a growable
element vector) — zdeque is the fixed-capacity pointer container with
two-ended access, for work queues, undo stacks, sliding windows, and
round-robin rotation.

- Caller owns the backing `void *` array; the deque never allocates.
- All full/empty/range conditions are reported as typed errors.
- Wrap-around safe under arbitrary interleaved push/pop patterns
  (tested with 200 rounds of churn plus in-order indexed checks).

## API

```c
#include <zdeque/zdeque.h>

void *slots[128];
zdeque dq;
zdeque_init(&dq, slots, 128);

zdeque_push_back(&dq, item);      /* O(1) both ends */
zdeque_push_front(&dq, item);
zdeque_pop_front(&dq, &item);
zdeque_pop_back(&dq, &item);
zdeque_peek_front(&dq, &item);
zdeque_at(&dq, 0, &item);         /* 0 = front */

zdeque_size(&dq); zdeque_empty(&dq); zdeque_full(&dq);
zdeque_clear(&dq);                /* O(1) */
```

## CLI

```
seq 3 | zdeque reverse      # -> 3 2 1
seq 5 | zdeque rotate 2     # -> 3 4 5 1 2
```

## Build

C23, single translation unit: compile `src/zdeque.c` with `-Iinclude`.
Tests: `tests/test_zdeque.c` (no framework needed).

## License

Apache-2.0.
