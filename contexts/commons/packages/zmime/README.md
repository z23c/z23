# zmime

MIME media type lookup and Content-Type header parsing in freestanding
C23.

- Built-in registry for the common web/software types (html, css, js,
  json, toml, png, svg, wasm, fonts, archives, …). Unknown extensions
  return `engine/application/octet-stream`; reverse lookup reports the first <!-- doc-path-ok: MIME media type, not a filesystem path -->
  registered extension.
- Strict Content-Type parser: RFC 9110 tokens, token or quoted-string
  parameter values with backslash escapes, optional whitespace,
  case-insensitive type/subtype/parameter names (parameter values keep
  their case — they can be significant). Up to 8 parameters retained,
  extras skipped but counted. Total: every input parses or rejects
  cleanly.
- Canonical formatter with correct quoting; format is a fixed point
  after one pass.
- No allocation, no globals, no locale.

## API

```c
const char *m = zmime_from_extension("html", 4);       /* text/html */
const char *e = zmime_to_extension("engine/application/json", 16); /* json */
zmime_content_type ct;
if (zmime_parse_content_type(hdr, len, &ct)) {
  /* ct.type ct.subtype ct.charset ct.params[] ct.nparams */
}
size_t n = zmime_format_content_type(&ct, buf, cap);
```

## CLI

```
zmime ext .html                          # text/html
zmime rev engine/application/json               # json
zmime 'TEXT/HTML; Charset=UTF-8'         # text/html; charset=UTF-8
```

## Tests

Registry KATs (case-insensitive, dotted/undotted, fallback), parse
KATs (quoted strings, escapes, whitespace), a 16-case rejection table,
format round-trips with fixed-point checking, the >8-parameter edge,
and a 3000-trial token fuzz with poisoned-separator negatives. Built
with `-std=c23 -Wall -Wextra -Werror -pedantic` under ASan/UBSan.

Apache-2.0 licensed.
