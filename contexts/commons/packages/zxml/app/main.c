/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zxml demo - emit a small RSS 2.0 feed for fixed sample data.
 *
 * Usage: zxml            pretty-printed feed on stdout
 *        zxml --compact  same feed without whitespace
 *
 * Exit 0 on success, 2 on misuse, 1 if writing fails. */
#include "zxml/zxml.h"

#include <stdio.h>
#include <string.h>

static bool out_write(void *ctx, const char *data, size_t len) {
  (void)ctx;
  return fwrite(data, 1, len, stdout) == len;
}

static const struct {
  const char *title, *link, *date;
} k_items[] = {
    {"ZClassic23 node syncs past the Sapling frontier",
     "https://example.com/posts/1", "Sun, 16 Aug 2026 00:00:00 +0000"},
    {"C23 Commons: publish, verify, reproduce",
     "https://example.com/posts/2", "Sat, 15 Aug 2026 00:00:00 +0000"},
    {"Escaping & <friends> — a \"writer\" story",
     "https://example.com/posts/3", "Fri, 14 Aug 2026 00:00:00 +0000"},
};

int main(int argc, char **argv) {
  unsigned flags = ZXML_PRETTY;
  if (argc == 2 && strcmp(argv[1], "--compact") == 0)
    flags = ZXML_COMPACT;
  else if (argc != 1) {
    fprintf(stderr, "usage: zxml [--compact]\n");
    return 2;
  }

  zxml x;
  zxml_open(&x, out_write, NULL, flags);
  zxml_status st = zxml_decl(&x);
  if (st == ZXML_OK)
    st = zxml_elem_open(&x, "rss");
  if (st == ZXML_OK)
    st = zxml_attr(&x, "version", "2.0");
  if (st == ZXML_OK)
    st = zxml_elem_open(&x, "channel");
  if (st == ZXML_OK)
    st = zxml_elem(&x, "title", "ZClassic23 News");
  if (st == ZXML_OK)
    st = zxml_elem(&x, "link", "https://example.com/");
  if (st == ZXML_OK)
    st = zxml_elem(&x, "description",
                   "Full-node and C23 Commons announcements");
  for (size_t i = 0; i < sizeof(k_items) / sizeof(k_items[0]) && st == ZXML_OK;
       i++) {
    st = zxml_elem_open(&x, "item");
    if (st == ZXML_OK)
      st = zxml_elem(&x, "title", k_items[i].title);
    if (st == ZXML_OK)
      st = zxml_elem(&x, "link", k_items[i].link);
    if (st == ZXML_OK)
      st = zxml_elem(&x, "guid", k_items[i].link);
    if (st == ZXML_OK)
      st = zxml_elem(&x, "pubDate", k_items[i].date);
    if (st == ZXML_OK)
      st = zxml_elem_close(&x);
  }
  if (st == ZXML_OK)
    st = zxml_elem_close(&x); /* channel */
  if (st == ZXML_OK)
    st = zxml_elem_close(&x); /* rss */
  if (st == ZXML_OK)
    st = zxml_close(&x);
  if (st == ZXML_OK && (flags & ZXML_PRETTY))
    st = fputc('\n', stdout) == EOF ? ZXML_ERR_SINK : ZXML_OK;
  if (st != ZXML_OK) {
    fprintf(stderr, "zxml: %s\n", zxml_strerror(st));
    return 1;
  }
  return 0;
}
