# zsort

Comparison sorting with a context pointer, stable sorting, and argsort
(index permutation) in freestanding C23.

ISO C `qsort` has no context pointer and POSIX `qsort_r` exists in two
incompatible argument orders; nothing in libc gives you a stable sort
or an argsort without allocation. `zsort` does, portably:

```c
typedef int (*zsort_cmp)(const void *a, const void *b, void *ctx);

void  zsort(base, n, size, cmp, ctx);                 /* introsort, unstable */
int   zsort_stable(base, n, size, cmp, ctx, scratch); /* merge sort, stable  */
int   zargsort(perm, base, n, size, cmp, ctx);        /* stable index perm   */
```

- Introspective quicksort with median-of-three pivots, heapsort
  fallback at 2·⌊log2 n⌋ depth, insertion sort for small runs.
- Stable merge sort needs `n*size` bytes of caller scratch.
- Argsort is bottom-up stable merge over the permutation with a fixed
  stack buffer; equal keys keep original index order; `base` is never
  written.
- No allocation, no globals, recursion bounded by log2(n).

## CLI

```
seq 100 -1 1 | zsort            # sorted
seq 100 -1 1 | zsort --stable
seq 100 -1 1 | zsort --index    # via permutation
```

## Tests

Sortedness oracle against `qsort` multisets, wide-element structs
(33-byte records), stability proofs with distinguishable equal keys,
argsort permutation validity plus tie-order checks, adversarial
patterns (sorted, reverse, equal, sawtooth, organ pipe), large-n
random harness exercising the rotation fallback, and bad-argument
rejection. Built with `-std=c23 -Wall -Wextra -Werror -pedantic`
under ASan/UBSan.

Apache-2.0 licensed.
