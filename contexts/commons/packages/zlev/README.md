# zlev — bounded Levenshtein distance and similarity

`zlev` computes classic unit-cost Levenshtein distance over raw bytes
with O(min(n,m)) memory, plus a banded early-exit variant that answers
"is the distance greater than LIMIT?" in O((n+m)·LIMIT) time, and a
milli-similarity helper (1000 = identical).

## API sketch

```c
size_t d = zlev_distance(a, na, b, nb);                 /* full */
size_t e = zlev_distance_bounded(a, na, b, nb, limit);  /* limit+1 if over */
int milli = zlev_similarity_milli(a, na, b, nb);        /* 0..1000, -1 bad */
```

Inputs longer than `ZLEV_MAX` (default 4096) return `SIZE_MAX`.
Binary-safe: embedded NULs are data.

## Tests

`tests/test_zlev.c` covers literature known answers (kitten/sitting,
saturday/sunday, ...), bounded-variant exactness at and above the
limit, the length-lower-bound shortcut, similarity edges, NULL and
over-long rejection, exhaustive agreement between the banded and full
DP for every binary-string pair up to length 4 at every limit 0..5,
and a 4000-trial randomized fuzz checking symmetry and bounds. Built
and run under `-fsanitize=address,undefined -Werror -pedantic`.

## License

Apache-2.0. See `LICENSE`.
