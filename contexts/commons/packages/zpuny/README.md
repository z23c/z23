# zpuny

Punycode encoder/decoder (RFC 3492) for internationalized domain name
labels, in portable C23 with no dependencies beyond libc.

This library converts between Unicode code-point sequences and the
ASCII bootstring encoding behind `xn--` labels. It deliberately does
not implement full IDNA (Nameprep, ToASCII framing, ACE prefix) —
compose it with your own label handling.

## API

```c
char out[64]; size_t n;
zpuny_encode_utf8("bücher", 6, out, sizeof out, &n); /* "bcher-kva" */

uint32_t cp[32]; size_t cn;
zpuny_decode("egbpdaj6bu4bxfgehfvwxn", 22, cp, 32, &cn);
```

All functions take caller-provided buffers and report the exact
required length via an out parameter, so a two-pass size-then-fill
pattern needs no guessing. Overflow, malformed input, surrogate and
out-of-range code points are reported via `zpuny_status`.

Verified against the RFC 3492 section 7.1 sample strings (Arabic,
Czech, Japanese, Russian, mixed-script) plus randomized round trips.

## CLI

```sh
cc -std=c23 -Iinclude -o zpuny app/main.c src/zpuny.c
./zpuny enc bücher     # bcher-kva
./zpuny dec bcher-kva  # bücher
```

## License

Apache-2.0
