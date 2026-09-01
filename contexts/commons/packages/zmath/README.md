# zmath

Checked integer arithmetic and small number theory for C23.

- Overflow-checked `add`/`sub`/`mul` for `uint64_t`, `int64_t` and
  `size_t` — return `false` with the output untouched on overflow.
- Saturating variants that clamp to the type range.
- `gcd`, `lcm`, `pow`, `div_ceil`, decimal digit count, min/max/clamp,
  and an `INT64_MIN`-safe absolute value.
- Cross-checked against 128-bit arithmetic over randomized operands.
- No allocation, no dependencies beyond libc.

## API

```c
#include <zmath/zmath.h>

uint64_t v;
if (!zmath_mul_u64(a, b, &v)) { /* overflow, v unchanged */ }

uint64_t s = zmath_sat_add_u64(x, y);        /* clamps */
uint64_t g = zmath_gcd(12, 18);              /* 6 */
bool ok  = zmath_lcm(4, 6, &v);              /* 12 */
bool ok2 = zmath_pow_u64(2, 63, &v);         /* 2^63 */
```

## CLI

```sh
zmath mul 6 7          # 42
zmath add 18446744073709551615 1   # overflow
zmath gcd 12 18        # 6
zmath pow 2 63         # 9223372036854775808
```

## License

Apache-2.0. See LICENSE.
