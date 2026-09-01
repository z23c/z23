# zrand

xoshiro256** pseudo-random generator for C23.

- Deterministic splitmix64 seeding; any 64-bit seed is valid.
- Raw u64, unbiased bounded draws (Lemire), ranges, doubles in [0,1),
  bools, byte fills, Fisher–Yates shuffle.
- Standard jump / long-jump for stream splitting across workers.
- NOT cryptographically secure — never use for keys or tokens.

## API

```c
#include <zrand/zrand.h>

zrand r;
zrand_seed(&r, 42);

uint64_t v  = zrand_u64(&r);
uint64_t b  = zrand_bounded(&r, 100);   /* [0,100) */
uint64_t g  = zrand_range(&r, 10, 20);  /* [10,20) */
double   d  = zrand_double(&r);         /* [0,1) */
bool     c  = zrand_bool(&r);
zrand_bytes(&r, buf, n);
zrand_shuffle(&r, arr, n, sizeof arr[0]);
zrand_jump(&r);       /* skip 2^128 draws */
zrand_long_jump(&r);  /* skip 2^192 draws */
```

## CLI

```sh
zrand u64 42 3
zrand bounded 7 100 5
zrand shuffle 1 alpha beta gamma delta
```

## License

Apache-2.0. See LICENSE.
