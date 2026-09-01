# zvec

Growable pointer vector for C23.

- `void *` elements, caller-injected allocation (zeroed `zvec_alloc`
  selects hosted malloc/free).
- Geometric growth; every mutating call returns `false` on allocation
  failure with the vector unchanged.
- push/pop, ordered insert/remove, O(1) swap-remove, shrink-to-fit,
  pointer-identity index search.
- Values are never owned; destroy frees only the array.
- No dependencies beyond libc.

## API

```c
#include <zvec/zvec.h>

zvec *v = zvec_create((zvec_alloc){0});
zvec_push(v, &item);
void *x = zvec_get(v, 0);
zvec_insert(v, 1, &other);
zvec_remove(v, 0);        /* order preserved */
zvec_swap_remove(v, 0);   /* O(1), order not preserved */
zvec_destroy(v);
```

## CLI

```sh
zvec push:a push:b push:c pop        # a b
zvec push:a push:c insert:1:b        # a b c
```

## License

Apache-2.0. See LICENSE.
