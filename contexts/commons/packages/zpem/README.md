# zpem

PEM armor (RFC 7468) over DER bytes for C23.

PEM frames binary data as `-----BEGIN LABEL-----`, a 64-column base64
body, and `-----END LABEL-----` — the format of certificates, keys,
and CRLs in the TLS ecosystem.

- Strict parser: exact markers, matching labels, only CR/LF tolerated
  in the body; the base64 body is validated by `zbase64`'s strict
  decoder (canonical padding, no foreign characters, no leftover
  bits).
- Labels are 1..32 chars from `[A-Z0-9 -]`, never starting/ending
  with a space or hyphen; a five-dash run is rejected (it would
  collide with the markers).
- Multi-block friendly: `zpem_parse` reports exact bytes consumed, so
  callers advance over consecutive blocks in a bundle.
- No allocation: decoding uses a caller-provided scratch buffer for
  the stripped base64 text.
- Depends on `zbase64` (pinned exact root in the manifest).

## API

```c
#include <zpem/zpem.h>

size_t   zpem_encoded_len(der_len, label_len);
zpem_err zpem_encode(label, label_len, der, der_len, out, cap, &out_len);

zpem_block blk;
zpem_err zpem_parse(pem, pem_len, &blk);          /* blk.consumed = wire bytes */
zpem_err zpem_decode(&blk, scratch, scratch_cap, der, der_cap, &der_len);

/* one-shot: parse + decode */
zpem_err zpem_read(pem, pem_len, scratch, scratch_cap, der, der_cap,
                   &der_len, &blk);
```

## CLI

```
zpem encode CERTIFICATE < cert.der > cert.pem
zpem decode < cert.pem > cert.der     # label reported on stderr
```

## Build

C23. Compile `src/zpem.c` together with the `zbase64` package's
`src/zbase64.c`, with `-Iinclude -I<zbase64>/include`. Tests:
`tests/test_zpem.c` (no framework needed).

## License

Apache-2.0.
