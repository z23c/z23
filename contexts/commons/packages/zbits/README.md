# zbits — fixed-size bitset over caller storage

`zbits` implements the standard bitset vocabulary over a
caller-provided `uint64_t` array, using C23 `<stdbit.h>` primitives:
set/clear/flip/test, set-all/clear-all/flip-all (with tail trimming),
popcount, rank, first-set/first-clear, and or/and/and-not with
aliasing allowed. Every index error is explicit (`ZBITS_ERR_RANGE`);
nothing fails silently.

## API sketch

```c
uint64_t w[zbits_words(130)];
zbits_init(w, 130);
zbits_set(w, 130, 42);
int on = zbits_test(w, 130, 42);
size_t c = zbits_count(w, 130);
size_t r = zbits_rank(w, 130, 100);
size_t f = zbits_first_set(w, 130);
zbits_or(dst, a, b, 130);
```

## Tests

`tests/test_zbits.c` covers word-boundary indexes (0/63/64/last),
tail trimming past a partial final word, rank against per-index test
sums, first-set/first-clear including empty and full sets, aliased
boolean ops, argument errors, and an 800-trial fuzz against a
byte-array model with random point ops and bulk ANDs. Built and run
under `-fsanitize=address,undefined -Werror -pedantic`.

## License

Apache-2.0. See `LICENSE`.
