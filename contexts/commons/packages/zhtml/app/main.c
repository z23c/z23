/* zhtml CLI: escape or unescape argv strings / stdin.
 *
 * Usage: zhtml <escape|unescape> [STRING...]
 * With no STRING, processes stdin. Exit 1 on malformed input, 2 on
 * usage error. This is the package's real consumer. */
#include "zhtml/zhtml.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int malformed_stream(void) {
  fprintf(stderr, "zhtml: unescape: malformed entity\n");
  return 1;
}

/* Only a trailing entity without its semicolon must await another read.
 * The library validates every complete prefix, including nested '&' bytes. */
static size_t complete_prefix(const char *text, size_t len) {
  size_t pending = len;
  for (size_t i = 0; i < len; i++) {
    if (text[i] == '&' && pending == len) pending = i;
    else if (text[i] == ';') pending = len;
  }
  return pending;
}

static int write_unescaped(const char *text, size_t len) {
  char out[ZHTML_MAX + 1];
  size_t need = zhtml_unescape(out, sizeof out, text, len);
  if (need == SIZE_MAX || need >= sizeof out) return malformed_stream();
  if (fwrite(out, 1, need, stdout) != need) {
    fprintf(stderr, "zhtml: write error\n");
    return 1;
  }
  return 0;
}

static int unescape_stream(void) {
  char pending[ZHTML_MAX];
  size_t used = 0;
  for (;;) {
    size_t room = sizeof pending - used;
    size_t take = room < 8192 ? room : 8192;
    size_t n = fread(pending + used, 1, take, stdin);
    used += n;
    size_t prefix = complete_prefix(pending, used);
    if (prefix && write_unescaped(pending, prefix)) return 1;
    used -= prefix;
    memmove(pending, pending + prefix, used);
    if (ferror(stdin)) {
      fprintf(stderr, "zhtml: error reading stdin\n");
      return 1;
    }
    if (n < take) return used ? malformed_stream() : 0;
    if (used == sizeof pending) return malformed_stream();
  }
}

static int do_stream(int un) {
  if (un) return unescape_stream();
  char in[8192];
  char out[sizeof(in) * 6 + 1];
  size_t n;
  while ((n = fread(in, 1, sizeof(in), stdin)) > 0) {
    size_t need = zhtml_escape(out, sizeof(out), in, n);
    if (need == SIZE_MAX || need >= sizeof(out)) {
      fprintf(stderr, "zhtml: escape: output overflow\n");
      return 1;
    }
    if (fwrite(out, 1, need, stdout) != need) {
      fprintf(stderr, "zhtml: write error\n");
      return 1;
    }
  }
  if (ferror(stdin)) {
    fprintf(stderr, "zhtml: error reading stdin\n");
    return 1;
  }
  return 0;
}

int main(int argc, char **argv) {
  int un;
  if (argc < 2) {
    fprintf(stderr, "usage: zhtml <escape|unescape> [STRING...]\n");
    return 2;
  }
  un = strcmp(argv[1], "unescape") == 0;
  if (!un && strcmp(argv[1], "escape") != 0) {
    fprintf(stderr, "zhtml: unknown op '%s'\n", argv[1]);
    return 2;
  }
  if (argc > 2) {
    int i, rc = 0;
    for (i = 2; i < argc; i++) {
      static char buf[ZHTML_MAX + 8];
      size_t n = strlen(argv[i]);
      size_t need = un ? zhtml_unescape(buf, sizeof(buf), argv[i], n)
                       : zhtml_escape(buf, sizeof(buf), argv[i], n);
      if (need == SIZE_MAX || need >= sizeof(buf)) {
        fprintf(stderr, "zhtml: %s: bad input '%s'\n",
                un ? "unescape" : "escape", argv[i]);
        rc = 1;
        continue;
      }
      if (fwrite(buf, 1, need, stdout) != need) return 1;
      putchar('\n');
    }
    return rc;
  }
  return do_stream(un);
}
