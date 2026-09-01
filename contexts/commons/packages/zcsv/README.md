# zcsv

Bounded, allocation-free RFC 4180 CSV parser and writer for C23.

The parser is a streaming state machine. It never allocates: the caller
supplies one scratch buffer for the bytes of the row currently being parsed
and one scratch array of field views. Both bounds are hard limits — input
that exceeds them fails with an explicit status instead of growing.

## API summary

```c
typedef struct { const char *ptr; size_t len; } zcsv_field;
typedef void (*zcsv_row_fn)(void *ctx, const zcsv_field *fields, size_t n);

void          zcsv_init(zcsv_parser *p, char *row_data_scratch, size_t row_data_cap,
                        zcsv_field *field_scratch, size_t field_cap,
                        zcsv_row_fn on_row, void *ctx);
zcsv_status   zcsv_feed(zcsv_parser *p, const char *data, size_t len);
zcsv_status   zcsv_finish(zcsv_parser *p);   /* detects unterminated quotes */
const char   *zcsv_status_str(zcsv_status st);

size_t        zcsv_header_index(const zcsv_field *header, size_t n, const char *name);
bool          zcsv_field_equals(const zcsv_field *f, const char *cstr);

bool          zcsv_field_needs_quotes(const char *f, size_t len);
size_t        zcsv_write_field(char *out, size_t cap, const char *f, size_t len);
size_t        zcsv_write_row(char *out, size_t cap, const char *const *fields,
                             const size_t *lens, size_t n);
```

- Strict grammar: records end on CRLF or LF; quotes are legal only at the
  start of a field or as `""` inside a quoted field; anything else is
  `ZCSV_ERR_STRAY_QUOTE`. Input ending inside a quoted field is
  `ZCSV_ERR_UNTERMINATED`.
- Every record line yields a row (an empty line is one empty field); a
  trailing terminator does not yield a phantom row.
- Writer returns the required byte count; if it exceeds the caller capacity
  the output was truncated and must be discarded. Rows end with CRLF.
- Field views handed to the row callback are valid only during the callback.

## Example

```c
static char row_data[4096];
static zcsv_field fields[64];

static void on_row(void *ctx, const zcsv_field *f, size_t n) {
  (void)ctx;
  for (size_t i = 0; i < n; i++)
    printf("[%.*s]", (int)f[i].len, f[i].ptr);
  putchar('\n');
}

zcsv_parser p;
zcsv_init(&p, row_data, sizeof row_data, fields, 64, on_row, NULL);
if (zcsv_feed(&p, text, len) == ZCSV_OK)
  zcsv_finish(&p);
```

## App

`app/main.c` builds `csvtab`: reads CSV from stdin (bounded at 16 MiB) and
prints either an aligned table (default) or `rows`/`fields`/`bytes`
statistics with `--stats`.

## Tests

`tests/test_zcsv.c` covers plain/quoted/escaped fields, CRLF/LF/mixed
endings, empty fields and empty lines, one-byte chunked feeds, malformed
input (stray quote, unterminated quote), both scratch bounds, the header
helper, and writer quoting plus a writer→parser round-trip.
