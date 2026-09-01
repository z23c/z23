# ztoml — bounded TOML-subset pull parser

`ztoml` parses a practical subset of TOML into a zero-copy event
stream: sections (`[a.b]`), bare/dotted keys, basic strings with full
escape decoding (including `\uXXXX` / `\UXXXXXXXX` with surrogate
rejection), literal strings, integers (dec/hex/octal/binary with
underscores, exact overflow detection), floats (`inf`/`nan`,
underscores, leading-zero rules enforced), booleans, and nested arrays
with comments and newlines inside.

Cleanly rejected with `ZTOML_ERR_SYNTAX` and a byte offset: multiline
strings, inline tables, datetimes, quoted keys, `[[array-of-tables]]`,
leading-zero numbers, `.5`/`5.` floats, misplaced underscores.

## Bounds

| bound             | default | meaning                |
|-------------------|---------|------------------------|
| `ZTOML_MAX`       | 65535   | document bytes         |
| `ZTOML_MAX_DEPTH` | 8       | array nesting          |
| `ZTOML_MAX_KEY`   | 256     | key/section path chars |

## API sketch

```c
ztoml t;
ztoml_ev ev;
ztoml_init(&t, doc, len);
while (ztoml_next(&t, &ev) == ZTOML_OK && ev.kind != ZTOML_EV_DONE) {
  /* SECTION / KEY / VALUE / ARR_OPEN / ARR_CLOSE */
}
/* t.err, t.err_off, t.line locate any failure */
```

## Tests

`tests/test_ztoml.c` covers a golden multi-section document, a typed
KAT table (int bases, extremes, floats, inf/nan, booleans, strings),
nested arrays with comments and trailing commas, a 26-case malformed
table (leading zeros, misplaced underscores, unterminated strings,
datetimes, depth bound), escape decoding with surrogate and range
rejection, sticky errors with offsets, NULL safety, and a 2500-trial
generate-and-mutate fuzz. Built and run under
`-fsanitize=address,undefined -Werror -pedantic`.

## License

Apache-2.0. See `LICENSE`.
