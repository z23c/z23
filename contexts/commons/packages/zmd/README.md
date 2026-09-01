# zmd

Markdown-subset to HTML renderer for C23 — streaming output through a
caller-supplied write callback (no allocation policy in the library),
bounded input, fail-closed errors.

## Supported subset

Anything not listed here is literal text.

**Blocks** (column 0 only; no nesting):

- ATX headings `#` … `######`, optional closing `#` run (`## T ##`);
- paragraphs; soft breaks stay newlines, two trailing spaces force a
  hard break (`<br>`);
- fenced code blocks ```` ``` ```` — the info string is ignored, and an
  unclosed fence runs to end of input (fail-visible, never dropped);
- unordered lists (`- `, `* `) and ordered lists (`N. `);
- single-level blockquotes (`>`), rendered as one paragraph;
- horizontal rules: 3+ identical `-`, `*`, or `_`, spaces allowed.

Setext headings, tables, and indented code blocks are **not** supported.
A paragraph ends at any line that starts another block construct.

**Inline:** `**strong**`, `*em*`, `` `code` ``, `[link](url)`,
`![image](url)`. Different markers nest (`**a *b* c**`); same markers do
not (`*a *b**` is first-match). Any construct that fails to parse —
including every unclosed one — comes out as escaped literal text.

## Safety properties

- **No raw HTML passthrough.** All emitted text is escaped through
  zhtml, so source markup can never inject HTML. This is a feature.
- **URL policy.** Link/image URLs allow the `http`, `https`, and
  `mailto` schemes (case-insensitive) and schemeless relative URLs.
  Whitespace, control bytes, and any other scheme (`javascript:`,
  `data:`, …) degrade the whole construct to escaped literal text.
- **Bounded and validated.** Input must be well-formed UTF-8 (checked
  with zutf8 before any output) and at most `ZMD_MAX_INPUT` (16 MiB);
  the bound is checked before the pointer is dereferenced.

## API summary

```c
typedef bool (*zmd_write_fn)(void *ctx, const char *data, size_t len);
bool zmd_render_html(const char *md, size_t md_len, zmd_write_fn write, void *ctx);
```

`zmd_render_html` streams the HTML through `write` and returns false
(fail-closed; output may be partial) on bad arguments, oversize or
invalid input, or a failing sink.

## Example

```c
static bool to_file(void *ctx, const char *d, size_t n) {
  return fwrite(d, 1, n, (FILE *)ctx) == n;
}
zmd_render_html(doc, doc_len, to_file, stdout);
```

## App

`app/main.c` builds an md2html filter: `zmd < doc.md > doc.html` reads
stdin (bounded at 16 MiB) and writes HTML to stdout; exit 0 on success,
2 on read error/over-bound input, 1 on render failure.

## Tests

`tests/test_zmd.c` covers golden output per block and inline construct,
nesting across marker types, unclosed constructs (emphasis, code, links,
fences), the no-raw-HTML escaping guarantee, the URL scheme policy
(including `javascript:`/`data:` and control bytes), invalid UTF-8
rejection, the input-size bound checked before dereference, sink-failure
propagation, CRLF handling, and a mixed end-to-end document.
