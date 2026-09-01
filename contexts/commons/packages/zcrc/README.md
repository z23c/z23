# zcrc

CRC-32 (ISO-HDLC, poly `0xEDB88320`) and CRC-32C (Castagnoli, poly
`0x82F63B78`) in freestanding C23 — reflected, init/xorout
`0xFFFFFFFF`, table-driven.

```c
uint32_t a = zcrc32(buf, len);            /* one-shot */
uint32_t c = zcrc32c(buf, len);
uint32_t s = zcrc32_init();               /* streaming */
s = zcrc32_update(s, part1, n1);
s = zcrc32_update(s, part2, n2);
uint32_t crc = zcrc32_final(s);
```

Check values for `"123456789"`: CRC-32 `0xCBF43926`, CRC-32C
`0xE3069283`. The 256-entry tables are built lazily under a C23
atomic spinlock — thread-safe, no constructors, no generated table
data in source.

## CLI

```
zcrc file.bin          # CRC-32
zcrc -c file.bin       # CRC-32C
cat file | zcrc        # stdin
```

## Tests

Published check vectors, a 5000-trial oracle against a bit-by-bit
reference implementation for both polynomials, 3000-trial split-update
streaming invariance, empty/NULL edges. Built with
`-std=c23 -Wall -Wextra -Werror -pedantic` under ASan/UBSan.

Apache-2.0 licensed.
