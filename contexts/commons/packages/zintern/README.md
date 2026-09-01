# zintern

String interning pool in portable C23, no dependencies beyond libc.

Interning maps each distinct byte string to a dense, stable `uint32`
id. Ids are never reused and string bytes are stored exactly once, so
equality becomes integer comparison and ids double as indices into
side tables — the classic symbol-table pattern for compilers,
routers, and log pipelines.

## API

```c
zintern *p = zintern_create((zintern_alloc){0});
uint32_t id  = zintern_put(p, "alpha", 5);   /* 0 */
uint32_t id2 = zintern_put(p, "alpha", 5);   /* 0 again */
uint32_t miss = zintern_get(p, "gamma", 5);  /* UINT32_MAX */
const char *s = zintern_str(p, id, &len);    /* "alpha" */
zintern_destroy(p);
```

- binary-safe (embedded NULs) and empty-string safe
- caller-injected allocator; clean `UINT32_MAX` refusal on
  allocation failure with the pool unchanged
- arena + open-addressing hash; put/get are O(len) expected

## CLI

```sh
cc -std=c23 -Iinclude -o zintern app/main.c src/zintern.c
printf 'b\na\nb\n' | ./zintern   # 0 b / 1 a / 0 b
```

## License

Apache-2.0
