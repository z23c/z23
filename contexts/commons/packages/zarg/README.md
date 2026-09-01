# zarg — bounded argv parser

`zarg` parses a process argv vector against a caller-supplied option
spec table. Zero allocation, zero copy (values point into the original
argv strings), strict typed conversion, and a measuring/truncating
usage renderer.

## Features

- short booleans, bundled: `-v`, `-vq`
- short options with values: `-o file`, `-ofile`, `-vqo out.c`
- long options: `--verbose`, `--output=file`, `--output file`
- `--` end-of-options terminator; a lone `-` is positional
- typed values: string, `i64`, `u64`, `f64` with exact overflow and
  trailing-garbage rejection
- spec-table validation (duplicate long names, bad name syntax)
- sticky error with the offending argv index
- `zarg_usage()` renders a help block with truncation-safe measuring

## Bounds

| bound          | default | meaning                     |
|----------------|---------|-----------------------------|
| `ZARG_MAX_ARGS`  | 4096  | argv entries scanned        |
| `ZARG_MAX_SPEC`  | 128   | spec table entries          |
| `ZARG_MAX_NAME`  | 64    | long-name length            |

All are compile-time overridable.

## API sketch

```c
static const zarg_opt spec[] = {
  {'v', "verbose", ZARG_BOOL, "increase verbosity"},
  {'n', "count",   ZARG_I64,  "repeat count"},
};
zarg_parser p;
zarg_item it;
zarg_init(&p, spec, 2, argc, argv);
while (zarg_next(&p, &it) == ZARG_OK && it.kind != ZARG_ITEM_END) {
  /* it.kind == ZARG_ITEM_OPT: it.spec_index, it.i64/...    */
  /* it.kind == ZARG_ITEM_POS: it.text, it.pos_index        */
}
```

## Tests

`tests/test_zarg.c` covers KAT streams (bundles, glued values, `--`,
lone dash, extremes), conversions (overflow, underflow, NaN, negative
zero), error paths (unknown, missing, bad value, sticky error, bad
spec tables), usage rendering and truncation, NULL safety, and a
4000-trial randomized fuzz over adversarial token pieces. Built and
run under `-fsanitize=address,undefined -Werror -pedantic`.

## License

Apache-2.0. See `LICENSE`.
