# zhash — classic non-cryptographic hashes, exact and bounded

`zhash` implements the standard published non-cryptographic hashes
with fixed known-answer values: FNV-1a (32/64, one-shot and
streaming), CRC32 (IEEE 802.3, reflected polynomial 0xEDB88320,
table-free, one-shot and streaming), DJB2, SDBM, the splitmix64
finalizer, and an order-sensitive 64-bit combiner.

**Not cryptographic.** Never use these for integrity against
adversaries, signatures, or key derivation.

## API sketch

```c
uint64_t h = zhash_fnv1a64(data, n);                 /* one-shot */
h = zhash_fnv1a64_update(h, more, m);                /* streaming */
uint32_t c = zhash_crc32(buf, n);                    /* CRC32 */
c = zhash_crc32_update(c, next, k);                  /* streaming */
uint64_t mixed = zhash_splitmix64(x);                /* finalizer */
uint64_t both = zhash_combine64(h1, h2);             /* combine */
```

NULL data with n > 0 never dereferences: one-shot functions return
the basis (or 0 for CRC32), update functions return the previous hash.

## Tests

`tests/test_zhash.c` checks the published known answers (FNV-1a
vectors, CRC32 of "123456789" = 0xCBF43926, DJB2 basis, splitmix64
zero-state output), streaming-vs-one-shot equivalence at every split
point, splitmix64 bijectivity on 64 inputs, NULL safety, embedded-NUL
handling, and a 3000-trial random-chunk streaming fuzz. Built and run
under `-fsanitize=address,undefined -Werror -pedantic`.

## License

Apache-2.0. See `LICENSE`.
