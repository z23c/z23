# zbuf — bounded growable byte buffer

`zbuf` is a heap byte buffer with geometric growth, a hard caller-set
maximum, and sticky errors: once a write would exceed the maximum (or
allocation fails), the buffer keeps its contents, reports the error on
every later write, and stays safe to read, clear, and free. It
replaces per-callsite measuring-emitter boilerplate for incremental
string building.

## API sketch

```c
zbuf b;
zbuf_init(&b, 1 << 20);              /* hard 1 MiB bound */
zbuf_str(&b, "result: ");
zbuf_printf(&b, "%d/%d", done, total);
zbuf_write(&b, raw, n);              /* binary-safe */
const char *s = zbuf_cstr(&b);       /* NUL-terminated view */
if (zbuf_status(&b) != ZBUF_OK) ...  /* sticky FULL/OOM */
zbuf_free(&b);
```

## Tests

`tests/test_zbuf.c` covers growth and embedded NULs, printf formats,
the exact bound (a full buffer rejects one more byte without losing
data), sticky-error behavior and clear-reset, NULL tolerance, and a
1500-trial fuzz against a reference array model with random writes and
clears. Built and run under `-fsanitize=address,undefined -Werror
-pedantic`.

## License

Apache-2.0. See `LICENSE`.
