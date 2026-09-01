# znetstring

Netstring framing codec (DJB netstrings) for C23.

A netstring frames a byte payload as `<len>:<payload>,` — e.g. the
payload `hello` travels as the 8 bytes `5:hello,`. Netstrings are
self-delimiting, binary-safe, and trivially parseable without
escaping, which makes them a solid framing layer for length-prefixed
protocols (QUAL, bencode-style payloads, simple RPC streams).

- Strict parser: leading-zero lengths rejected, terminator checked,
  oversized lengths rejected (`ZNETSTRING_MAX`, default 16 MiB).
- Stream-friendly: parse reports exact bytes consumed;
  `znetstring_prefix()` tells a reader "keep reading" vs "malformed".
- No allocation; caller-provided buffers with an exact size helper.
- No dependencies beyond libc.

## API

```c
#include <znetstring/znetstring.h>

size_t         znetstring_encoded_len(size_t payload_len);
znetstring_err znetstring_encode(const uint8_t *payload, size_t n,
                                 char *out, size_t cap, size_t *out_len);
znetstring_err znetstring_parse(const char *buf, size_t n, znetstring *out);
int            znetstring_prefix(const char *buf, size_t n);
const char    *znetstring_err_str(znetstring_err e);
```

`znetstring_parse` fills a `znetstring` struct with a pointer into the
input buffer (no copy), the payload length, and the total wire bytes
consumed — advance by `consumed` to parse consecutive frames.

## CLI

```
printf hello | znetstring encode        # -> 5:hello,
printf '5:hello,' | znetstring decode   # -> hello
```

## Build

C23, single translation unit: compile `src/znetstring.c` with
`-Iinclude`. Tests: `tests/test_znetstring.c` (no framework needed).

## License

Apache-2.0.
