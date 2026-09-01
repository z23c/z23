# zring — fixed-capacity byte ring buffer

`zring` is an allocation-free FIFO byte ring over caller storage.
Single-producer/single-consumer safe; full capacity usable (no wasted
slot); O(1) single-byte ops and wrap-aware bulk read/write/peek/drop.

## API sketch

```c
unsigned char storage[256];
zring r;
zring_init(&r, storage, sizeof(storage));
zring_put(&r, 'x');                    /* ZRING_ERR_FULL when full   */
size_t n = zring_write(&r, data, len); /* short write when nearly full */
size_t m = zring_read(&r, out, len);   /* short read when nearly empty */
zring_peek_at(&r, skip, out, n);       /* inspect without consuming   */
zring_drop(&r, n);                     /* discard from the head       */
```

## Tests

`tests/test_zring.c` covers fill/drain edges, 3000 wraparounds with
FIFO verification, bulk transfers across the wrap point, `peek_at` and
`drop` semantics, zero-capacity and NULL handling, and a 2000-trial
fuzz that plays random operation bursts against a reference array
queue model. Built and run under `-fsanitize=address,undefined
-Werror -pedantic`. The CLI pumps stdin through the ring in
random-sized bursts; a 100 KB stream round-trips byte-identical
through a 7-byte ring.

## License

Apache-2.0. See `LICENSE`.
