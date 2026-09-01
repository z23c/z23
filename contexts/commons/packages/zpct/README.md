# zpct — RFC 3986 percent-encoding, bounded and zero-allocation

`zpct` percent-encodes bytes against a caller-selected unreserved set
and strictly decodes `%XX` triplets. Companion to `zurl`: zurl parses
absolute URIs into components; zpct escapes and unescapes their
byte content.

## Sets

| set              | passes through unescaped                        |
|------------------|--------------------------------------------------|
| `ZPCT_UNRESERVED`  | `A-Z a-z 0-9 - _ . ~`                          |
| `ZPCT_SUBDELIM`    | unreserved + `! $ & ' ( ) * + , ; =`           |
| `ZPCT_PCHAR`       | sub-delims + `: @`                             |

Everything else encodes as uppercase `%XX`. Decoding is strict: bad
hex or a truncated triplet is an error (`SIZE_MAX`), never a silent
pass-through. A literal `%` must be written `%25`.

## Convention

Producers return the needed byte count (excluding NUL); return >= cap
means truncated output (still NUL-terminated when cap > 0). `SIZE_MAX`
signals invalid input. `zpct_decode` may produce embedded NULs; use
`out_len` for the true length. Inputs are capped at `ZPCT_MAX`
(default 65535) bytes.

## Tests

`tests/test_zpct.c` covers known answers (every set, lowercase hex,
decoded NUL, embedded binary), all-256-byte round trips in every set,
malformed sequences, truncation and measuring mode, over-long and NULL
inputs, and a 4000-trial fuzz with random corruption. Built and run
under `-fsanitize=address,undefined -Werror -pedantic`.

## License

Apache-2.0. See `LICENSE`.
