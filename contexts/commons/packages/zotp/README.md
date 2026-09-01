# zotp

HOTP one-time passwords (RFC 4226) for C23, with the underlying
HMAC-SHA1 (RFC 2104) exposed separately.

HOTP is the counter-based one-time password algorithm behind TOTP
authenticator apps, hardware tokens, and two-factor login flows.
`zotp_hotp` renders the code; `zotp_hotp_value` gives the raw 31-bit
truncated value; `zotp_hmac_sha1` is available for legacy protocols
that still require HMAC-SHA1.

- No allocation, no global state; HMAC keys longer than the 64-byte
  block are hashed first per RFC 2104, and key material is wiped.
- Tested against RFC 2202 HMAC-SHA1 cases (including the long-key
  case) and the complete RFC 4226 appendix D HOTP table.
- Depends on `zsha1` (pinned exact root in the manifest).

## API

```c
#include <zotp/zotp.h>

char code[7];
zotp_hotp(secret, secret_len, counter, 6, code);   /* e.g. "755224" */

uint32_t v = zotp_hotp_value(secret, secret_len, counter); /* 31-bit */

uint8_t mac[20];
zotp_hmac_sha1(key, key_len, data, data_len, mac); /* RFC 2104 */
```

`digits` may be 6..9 (9 digits still fits the 31-bit range mod 10^9).

## CLI

```
zotp 12345678901234567890 0        # -> 755224
zotp 12345678901234567890 0 3      # -> 755224 287082 359152
zotp 12345678901234567890 0 1 8    # -> 00755224
```

## Build

C23. Compile `src/zotp.c` together with the `zsha1` package's
`src/zsha1.c`, with `-Iinclude -I<zsha1>/include`. Tests:
`tests/test_zotp.c` (no framework needed).

## License

Apache-2.0.
