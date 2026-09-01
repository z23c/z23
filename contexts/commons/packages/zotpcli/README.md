# zotpcli

A real TOTP/HOTP authenticator CLI for the C23 Commons — a minimal
`oathtool` with a local, tamper-evident entry store. C23, libc only,
bounded, fail-closed, no VLAs, every allocation checked.

## Features

- `add` / `list` / `show` / `remove` entries (label, issuer, base32
  secret, TOTP or HOTP, digits, period, counter).
- `code LABEL` prints the current code: HOTP via RFC 4226 (built on the
  Commons `zotp` package, consuming and persisting the counter); TOTP
  via RFC 6238 with `counter = floor(unix_time / period)`. The CLI uses
  `time(2)` for the current Unix time; `--now T` overrides it, and the
  library API takes `now` as a parameter so tests are deterministic.
- `import` / `export` of `otpauth://` URIs (Google Authenticator
  KeyUriFormat shape): URI parsing via `zurl`, percent codec via `zpct`,
  base32 secrets via `zb32`. Only SHA-1 is implemented; an explicit
  `algorithm=SHA256/SHA512` is rejected fail-closed.
- `export --pem` armors the exact store file bytes as a PEM block
  (`zpem` over `zbase64`).
- `verify` checks store integrity and prints the entry count.

## Store format and the honesty note

The store file is:

```
"ZOTPCLI1"                              magic (8 bytes)
record 0    header  {"v":1,"kdf":"scrypt","n":16384,"r":8,"p":1,"salt":b64}
record 1..N one JSON object per entry   (secret base64-encoded)
record N+1  trailer {"mac":b64}
```

Each record is framed as LEB128 length (`zvarint`) + JSON payload
(`zjson` writer, `zjsonp` pull parser). The trailer MAC is
HMAC-SHA256 (`zsha256`) over every preceding byte, keyed by
`HKDF-SHA256(scrypt(passphrase, salt), "zotpcli-store-mac-v1")`
(`zscrypt` + `zhkdf`).

**This is integrity + passphrase stretching, NOT encryption at rest.**
Records are plain JSON: secrets are stored obscured-but-readable
(base64). Anyone who can read the file can read every secret. With no
passphrase, anyone who can write the file can recompute the MAC, so it
then detects only accidental corruption. With a passphrase, undetected
modification requires the passphrase (scrypt-stretched per guess). No
confidentiality is claimed. Protect the file with filesystem
permissions; the passphrase only buys tamper evidence and guess cost.

## Usage

```
zotpcli [--store PATH] [--passphrase PW] [--now T] [-v] <cmd> ...

add --label L --secret B32 [--issuer I] [--hotp] [--digits 6..8]
    [--period N] [--counter N]
import URI        add an entry from an otpauth:// URI
code LABEL        print the current code (TOTP shows validity end time)
list              one line per entry
show LABEL        details incl. base32 and hex (zhex) secret rendering
remove LABEL
export [--pem]    otpauth URIs, or PEM armor of the store file
verify            check the integrity MAC
```

The passphrase may also come from `ZOTPCLI_PASSPHRASE`. Diagnostics are
leveled via `zlog` on stderr (`-v` enables info level). Entry labels
and issuers must be well-formed UTF-8, checked with `zutf8`.

## Library API

`include/zotpcli/zotpcli.h` — store container, code generation
(`zotpcli_hotp_code` / `zotpcli_totp_code`, `now` is a parameter),
base32 helpers, otpauth parse/format, and byte-level store
encode/decode (file IO lives in the app, so the library is testable
without a filesystem).

## Dependencies

Every pin below has a real call site; `zsha1` is used only transitively
by `zotp` (its own pinned dependency) and is therefore not pinned here.

| package | call site(s) |
|---|---|
| zarg | `app/main.c` option/positional parsing (`zarg_init`, `zarg_next`, `zarg_usage`, `zarg_err_str`) |
| zbase64 | `src/zotpcli.c` store JSON secret/salt/MAC fields (`zbase64_encode`, `zbase64_decode`) |
| zb32 | `src/zotpcli.c` base32 secrets (`zb32_decode`, `zb32_decoded_len`, `zb32_encode`) |
| zbuf | `include/zotpcli/zotpcli.h` public encode buffer; `src/zotpcli.c` + `app/main.c` bounded output (`zbuf_init/write/status/len/free`) |
| zfmt | `src/zotpcli.c` otpauth formatting; `app/main.c` output lines (`zfmt_*`) |
| zhex | `app/main.c` `show` secret hex rendering (`zhex_encode`) |
| zhkdf | `src/zotpcli.c` MAC key derivation (`zhkdf_sha256`) |
| zjson | `src/zotpcli.c` store record writing (`zjson_*`) |
| zjsonp | `src/zotpcli.c` store record parsing (`zjsonp_init`, `zjsonp_next`, `zjsonp_num_i64`). String payloads are decoded locally: upstream `zjsonp_str_decode` (0.1.0) double-encodes raw non-ASCII UTF-8 bytes, so it is deliberately not used |
| zlog | `app/main.c` leveled diagnostics (`zlog_sink`, `zlog_error/info`) |
| zotp | `src/zotpcli.c` HOTP core (`zotp_hotp`) |
| zpct | `src/zotpcli.c` otpauth percent encode/decode (`zpct_encode`, `zpct_decode`) |
| zpem | `app/main.c` `export --pem` (`zpem_encoded_len`, `zpem_encode`, `zpem_err_str`) |
| zscrypt | `src/zotpcli.c` passphrase stretching (`zscrypt`) |
| zsha256 | `src/zotpcli.c` store MAC (`zsha256_hmac`, `zsha256_compare`) |
| zstr | `src/zotpcli.c` query splitting + case-insensitive keys (`zstr_split_*`, `zstr_casecmp`, `zstr_to_upper`); `app/main.c` safe copies + command dispatch (`zstr_copy`, `zstr_casecmp`) |
| ztime | `app/main.c` civil rendering of code validity end (`ztime_format`) |
| zurl | `src/zotpcli.c` otpauth URI parsing (`zurl_parse_n`, `zurl_scheme_is`, `zurl_copy`) |
| zutf8 | `src/zotpcli.c` label/issuer validation (`zutf8_validate_n`, `zutf8_validate`) |
| zvarint | `src/zotpcli.c` record framing (`zvarint_encode_u64`, `zvarint_decode_u64`) |

## Tests

`tests/test_zotpcli.c`: RFC 4226 Appendix D HOTP known-answer vectors,
RFC 6238 Appendix B TOTP known-answer vectors (SHA-1, 8 digits), time
step boundaries, base32 acceptance/rejection, otpauth round-trip and
rejections, store round-trip (including a non-ASCII UTF-8 label),
tamper detection (flip a byte → MAC verify fails), wrong-passphrase
rejection, truncation rejection, duplicate/invalid-label rejection, and
the HOTP counter flow.
