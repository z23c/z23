/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zcsv test suite.  Exits nonzero on the first failure. */
#include "zcsv/zcsv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond)                                                          \
  do {                                                                       \
    if (!(cond)) {                                                           \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
      failures++;                                                            \
    }                                                                        \
  } while (0)

/* Row collector: copies every field of every row into one flat buffer. */
typedef struct {
  char text[8192];
  size_t text_len;
  zcsv_field fields[256];
  size_t row_of_field[256];
  size_t nfields_total;
  size_t nrows;
} collector;

static void collect(void *vctx, const zcsv_field *fields, size_t n) {
  collector *c = vctx;
  for (size_t i = 0; i < n; i++) {
    size_t slot = c->nfields_total;
    memcpy(c->text + c->text_len, fields[i].ptr, fields[i].len);
    c->fields[slot].ptr = c->text + c->text_len;
    c->fields[slot].len = fields[i].len;
    c->row_of_field[slot] = c->nrows;
    c->text_len += fields[i].len;
    c->nfields_total++;
  }
  c->nrows++;
}

/* Parse `input` in `chunk` sized pieces and collect all rows. */
static zcsv_status parse_chunked(const char *input, size_t chunk,
                                 collector *c) {
  static char row_data[4096];
  static zcsv_field row_fields[64];
  zcsv_parser p;
  memset(c, 0, sizeof(*c));
  zcsv_init(&p, row_data, sizeof(row_data), row_fields,
            sizeof(row_fields) / sizeof(row_fields[0]), collect, c);
  size_t len = strlen(input);
  for (size_t at = 0; at < len; at += chunk) {
    size_t n = len - at < chunk ? len - at : chunk;
    zcsv_status st = zcsv_feed(&p, input + at, n);
    if (st != ZCSV_OK)
      return st;
  }
  return zcsv_finish(&p);
}

/* Field (row, col) from a collector as a C string view compare. */
static bool field_is(const collector *c, size_t row, size_t col,
                     const char *want) {
  size_t idx = 0;
  for (size_t i = 0; i < c->nfields_total; i++) {
    if (c->row_of_field[i] == row) {
      if (idx == col)
        return zcsv_field_equals(&c->fields[i], want);
      idx++;
    }
  }
  return false;
}

static void test_basic_rows(void) {
  collector c;
  CHECK(parse_chunked("a,b,c\n1,2,3\n", 4096, &c) == ZCSV_OK);
  CHECK(c.nrows == 2);
  CHECK(field_is(&c, 0, 0, "a") && field_is(&c, 0, 2, "c"));
  CHECK(field_is(&c, 1, 0, "1") && field_is(&c, 1, 2, "3"));

  /* Same input fed one byte at a time must give identical rows. */
  collector c1;
  CHECK(parse_chunked("a,b,c\n1,2,3\n", 1, &c1) == ZCSV_OK);
  CHECK(c1.nrows == c.nrows && c1.nfields_total == c.nfields_total);
  CHECK(c1.text_len == c.text_len &&
        memcmp(c1.text, c.text, c.text_len) == 0);
}

static void test_no_trailing_newline(void) {
  collector c;
  CHECK(parse_chunked("x,y", 4096, &c) == ZCSV_OK);
  CHECK(c.nrows == 1);
  CHECK(field_is(&c, 0, 0, "x") && field_is(&c, 0, 1, "y"));
}

static void test_empty_input_no_rows(void) {
  collector c;
  CHECK(parse_chunked("", 4096, &c) == ZCSV_OK);
  CHECK(c.nrows == 0);
}

static void test_crlf_and_mixed_endings(void) {
  collector c;
  CHECK(parse_chunked("a,b\r\nc,d\ne,f\r\ng,h", 1, &c) == ZCSV_OK);
  CHECK(c.nrows == 4);
  CHECK(field_is(&c, 3, 1, "h"));
}

static void test_empty_fields_and_empty_line(void) {
  collector c;
  CHECK(parse_chunked(",,\n\na,,b\n", 4096, &c) == ZCSV_OK);
  CHECK(c.nrows == 3);
  CHECK(field_is(&c, 0, 0, "") && field_is(&c, 0, 2, ""));
  /* An empty line is a record of one empty field. */
  CHECK(field_is(&c, 1, 0, ""));
  CHECK(field_is(&c, 2, 1, ""));
}

static void test_quoted_fields(void) {
  collector c;
  CHECK(parse_chunked("\"hello, world\",\"say \"\"hi\"\"\",\"multi\nline\"\n", 1,
                      &c) == ZCSV_OK);
  CHECK(c.nrows == 1);
  CHECK(field_is(&c, 0, 0, "hello, world"));
  CHECK(field_is(&c, 0, 1, "say \"hi\""));
  CHECK(field_is(&c, 0, 2, "multi\nline"));
}

static void test_quoted_crlf_inside_field(void) {
  collector c;
  CHECK(parse_chunked("\"a\r\nb\",c\r\n", 4096, &c) == ZCSV_OK);
  CHECK(c.nrows == 1);
  CHECK(field_is(&c, 0, 0, "a\r\nb"));
}

static void test_quote_only_at_field_start(void) {
  collector c;
  CHECK(parse_chunked("\"x\" ,y\n", 4096, &c) == ZCSV_ERR_STRAY_QUOTE);
  /* A quote in the middle of a plain field is also malformed. */
  CHECK(parse_chunked("ab\"cd,e\n", 4096, &c) == ZCSV_ERR_STRAY_QUOTE);
}

static void test_unterminated_quote(void) {
  collector c;
  CHECK(parse_chunked("\"abc,def\n", 4096, &c) == ZCSV_ERR_UNTERMINATED);
}

static void test_row_data_bound(void) {
  static char row_data[8];
  static zcsv_field row_fields[16];
  zcsv_parser p;
  zcsv_init(&p, row_data, sizeof(row_data), row_fields, 16, collect,
            &(collector){0});
  CHECK(zcsv_feed(&p, "012345678", 9) == ZCSV_ERR_FIELD_TOO_LONG);
  /* Exactly at the bound is fine. */
  collector c;
  memset(&c, 0, sizeof(c));
  zcsv_init(&p, row_data, sizeof(row_data), row_fields, 16, collect, &c);
  CHECK(zcsv_feed(&p, "01234567\n", 9) == ZCSV_OK);
  CHECK(zcsv_finish(&p) == ZCSV_OK);
}

static void test_field_count_bound(void) {
  static char row_data[64];
  static zcsv_field row_fields[2];
  collector c;
  memset(&c, 0, sizeof(c));
  zcsv_parser p;
  zcsv_init(&p, row_data, sizeof(row_data), row_fields, 2, collect, &c);
  CHECK(zcsv_feed(&p, "a,b,c\n", 6) == ZCSV_ERR_TOO_MANY_FIELDS);
}

static void test_header_index(void) {
  collector c;
  CHECK(parse_chunked("name,age,city\nann,31,oslo\n", 4096, &c) == ZCSV_OK);
  zcsv_field hdr[3];
  size_t n = 0;
  for (size_t i = 0; i < c.nfields_total; i++)
    if (c.row_of_field[i] == 0)
      hdr[n++] = c.fields[i];
  CHECK(n == 3);
  CHECK(zcsv_header_index(hdr, n, "age") == 1);
  CHECK(zcsv_header_index(hdr, n, "city") == 2);
  CHECK(zcsv_header_index(hdr, n, "missing") == SIZE_MAX);
}

static void test_writer_quoting(void) {
  char buf[64];
  /* Plain field: no quotes. */
  CHECK(zcsv_write_field(buf, sizeof(buf), "abc", 3) == 3);
  CHECK(memcmp(buf, "abc", 3) == 0);
  /* Comma forces quotes. */
  CHECK(zcsv_write_field(buf, sizeof(buf), "a,b", 3) == 5);
  CHECK(memcmp(buf, "\"a,b\"", 5) == 0);
  /* Embedded quote doubles. */
  CHECK(zcsv_write_field(buf, sizeof(buf), "a\"b", 3) == 6);
  CHECK(memcmp(buf, "\"a\"\"b\"", 6) == 0);
  /* Newline forces quotes. */
  CHECK(zcsv_write_field(buf, sizeof(buf), "a\nb", 3) == 5);
  /* Short buffer: required length is still reported. */
  CHECK(zcsv_write_field(buf, 2, "a,b", 3) == 5);
}

static void test_writer_row_and_roundtrip(void) {
  const char *fields[] = {"plain", "has,comma", "has\"quote", "has\ncrlf"};
  const size_t lens[] = {5, 9, 9, 8};
  char buf[128];
  size_t need = zcsv_write_row(buf, sizeof(buf), fields, lens, 4);
  CHECK(need < sizeof(buf));
  const char *want = "plain,\"has,comma\",\"has\"\"quote\",\"has\ncrlf\"\r\n";
  CHECK(need == strlen(want) && memcmp(buf, want, need) == 0);

  /* Round-trip: parsing the written row yields the original fields. */
  collector c;
  char row_data[256];
  zcsv_field row_fields[8];
  memset(&c, 0, sizeof(c));
  zcsv_parser p;
  zcsv_init(&p, row_data, sizeof(row_data), row_fields, 8, collect, &c);
  CHECK(zcsv_feed(&p, buf, need) == ZCSV_OK);
  CHECK(zcsv_finish(&p) == ZCSV_OK);
  CHECK(c.nrows == 1);
  for (size_t i = 0; i < 4; i++) {
    size_t idx = 0;
    for (size_t k = 0; k < c.nfields_total; k++) {
      if (c.row_of_field[k] == 0) {
        if (idx == i)
          CHECK(c.fields[k].len == lens[i] &&
                memcmp(c.fields[k].ptr, fields[i], lens[i]) == 0);
        idx++;
      }
    }
  }
}

int main(void) {
  test_basic_rows();
  test_no_trailing_newline();
  test_empty_input_no_rows();
  test_crlf_and_mixed_endings();
  test_empty_fields_and_empty_line();
  test_quoted_fields();
  test_quoted_crlf_inside_field();
  test_quote_only_at_field_start();
  test_unterminated_quote();
  test_row_data_bound();
  test_field_count_bound();
  test_header_index();
  test_writer_quoting();
  test_writer_row_and_roundtrip();
  if (failures) {
    fprintf(stderr, "zcsv: %d failure(s)\n", failures);
    return 1;
  }
  puts("zcsv: all tests passed");
  return 0;
}
