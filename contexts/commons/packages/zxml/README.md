# zxml

Bounded XML writer for C23 (RSS/Atom/sitemap generation). Well-formedness
is guaranteed **by construction**: the writer is a state machine over a
bounded element stack, every call is checked against the current state,
and misuse is a named sticky error — never malformed output.

## Design

- **Caller sink, zero allocation:** output goes to a
  `bool (*)(void *ctx, const char *data, size_t len)` callback; the caller
  owns the `zxml` struct (~2 KiB) and the sink. A false sink return is
  `ZXML_ERR_SINK`.
- **State machine, fail closed:** attributes only inside an open start
  tag; text/comments only inside the root element (comments may also
  precede it); exactly one root; `zxml_close` fails unless the document is
  balanced. After the first error every later call returns the stored
  status — emitted bytes are always a well-formed prefix.
- **Escaping by context:** `&` `<` `>` in text, plus `"` and `'` in
  attribute values, become the five predefined entities.
- **Input validation:** text, attribute values, and comments must be
  well-formed UTF-8 (checked with [zutf8](../zutf8)) and free of control
  bytes other than tab/newline/return; `--` is rejected in comments.
  Invalid input is rejected (`ZXML_ERR_UTF8` / `ZXML_ERR_TEXT`), never
  emitted.
- **Names:** `[A-Za-z_][A-Za-z0-9._:-]*`, ≤ 63 bytes (`ZXML_ERR_NAME`).
- **Pretty vs compact:** `ZXML_PRETTY` indents two spaces per level, one
  element per line, text-only elements on one line; `ZXML_COMPACT` emits
  no extra whitespace.
- **Bounds:** nesting ≤ `ZXML_MAX_DEPTH` (32), names ≤ `ZXML_MAX_NAME`
  (63); both are named errors, never truncation.

## API summary

```c
void        zxml_open(zxml *x, zxml_write_fn fn, void *ctx, unsigned flags);
zxml_status zxml_decl(zxml *x);                    /* <?xml ...?> first */
zxml_status zxml_elem_open(zxml *x, const char *name);
zxml_status zxml_attr(zxml *x, const char *name, const char *value);
zxml_status zxml_text(zxml *x, const char *text);
zxml_status zxml_text_n(zxml *x, const char *text, size_t len);
zxml_status zxml_comment(zxml *x, const char *text);
zxml_status zxml_elem_close(zxml *x);              /* <n/> when empty */
zxml_status zxml_elem(zxml *x, const char *name, const char *text);
zxml_status zxml_close(zxml *x);                   /* verifies balance */
const char *zxml_strerror(zxml_status st);
```

## Example

```c
zxml x;
zxml_open(&x, my_write, my_ctx, ZXML_PRETTY);
zxml_decl(&x);
zxml_elem_open(&x, "rss");
zxml_attr(&x, "version", "2.0");
zxml_elem_open(&x, "channel");
zxml_elem(&x, "title", "Example & Sons");   /* & -> &amp; */
zxml_elem_close(&x);
zxml_elem_close(&x);
if (zxml_close(&x) != ZXML_OK) /* ... */;
```

## App

`app/main.c` emits a demo RSS 2.0 feed for fixed sample data:
`zxml [--compact]`.

## Tests

`tests/test_zxml.c` covers nesting, empty/self-closing elements, attribute
and text escaping (golden bytes), UTF-8 and control-byte rejection,
unbalanced/misordered calls by named error, sticky errors, name and depth
bounds, pretty vs compact goldens, sink failure, and realistic
`sitemap.xml` and RSS-item goldens.
