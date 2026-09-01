# ztrie

Byte-wise trie (prefix tree) for arbitrary byte-string keys, written in
portable C23 with no dependencies beyond libc.

## Features

- insert / exact lookup / contains / erase with node pruning
- longest-prefix match — ideal for routing tables and tokenizers
- ordered enumeration of every key under a prefix
- caller-injected allocator; a zeroed `ztrie_alloc` uses malloc/free
- key bytes are copied in; values are never owned

## API sketch

```c
ztrie *t = ztrie_create((ztrie_alloc){0});
ztrie_put(t, "app", 3, handler, NULL);
void *h = ztrie_longest_prefix(t, "apple", 5); /* handler */
ztrie_erase(t, "app", 3);
ztrie_destroy(t);
```

See `include/ztrie/ztrie.h` for the full contract.

## Build

```sh
cc -std=c23 -Iinclude -o demo app/main.c src/ztrie.c
printf 'app=demo\n' | ./demo apple
```

## License

Apache-2.0
