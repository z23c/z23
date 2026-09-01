# zslot — generational handle table

Fixed-capacity slot map in strict C23. No malloc, no global state, no
clock. The caller owns the backing bytes. A 64-bit handle is a 32-bit
index plus a 32-bit generation; a freed handle misses instead of
returning a dangling pointer.

This is the table engines use when raw pointers would dangle: entities,
GPU resources, jobs, anything that outlives a reuse of the same slot.

```c
unsigned char storage[4096];
zslot t;
zslot_init(&t, storage, sizeof(storage), sizeof(uint32_t));

uint32_t v = 7;
zslot_id id = zslot_insert(&t, &v);
uint32_t *p = zslot_get(&t, id);   /* 7 */
zslot_remove(&t, id);
zslot_get(&t, id);                 /* NULL — stale */
```

Handle 0 is never live. Occupied generations are odd. A slot that would
wrap its generation is retired rather than reused, so an ancient handle
cannot alias a new occupant.

## Tests

`tests/test_zslot.c` covers init failure, insert/get/remove, stale
handles after reuse, exhaustion, NULL arguments, `zslot_each`,
zero-size occupancy tokens, and independent payloads. Build with
`-fsanitize=address,undefined -Werror -pedantic`.

`zslot selftest` inserts three values, drops the middle, reuses the
slot, and prints `ok` only when the old handle misses.

## License

Apache-2.0. See `LICENSE`.
