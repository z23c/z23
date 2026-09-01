/* zpct CLI: percent-encode or decode argv strings / stdin.
 *
 * Usage: zpct encode [--subdelim|--pchar] [STRING...]
 *        zpct decode [STRING...]
 * With no STRING, reads stdin (binary-safe). Exit 1 on malformed
 * input, 2 on usage error. This is the package's real consumer. */
#include "zpct/zpct.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int do_stream(int decode, zpct_set set) {
  unsigned char in[4096];
  char out[sizeof(in) * 3 + 1];
  size_t n;
  int rc = 0;
  while ((n = fread(in, 1, sizeof(in), stdin)) > 0) {
    size_t need = decode ? zpct_decode(out, sizeof(out), in, n, NULL)
                         : zpct_encode(out, sizeof(out), in, n, set);
    if (need == SIZE_MAX || need >= sizeof(out)) {
      fprintf(stderr, "zpct: %s: %s\n", decode ? "decode" : "encode",
              decode ? "malformed percent sequence" : "output overflow");
      rc = 1;
      break;
    }
    /* Decoded output may contain NULs: write raw bytes. */
    if (fwrite(out, 1, need, stdout) != need) {
      fprintf(stderr, "zpct: write error\n");
      return 1;
    }
  }
  if (ferror(stdin)) {
    fprintf(stderr, "zpct: error reading stdin\n");
    return 1;
  }
  return rc;
}

int main(int argc, char **argv) {
  int decode;
  zpct_set set = ZPCT_UNRESERVED;
  int arg0 = 2;
  if (argc < 2) {
    fprintf(stderr, "usage: zpct <encode|decode> [--subdelim|--pchar] "
                    "[STRING...]\n");
    return 2;
  }
  decode = strcmp(argv[1], "decode") == 0;
  if (!decode && strcmp(argv[1], "encode") != 0) {
    fprintf(stderr, "zpct: unknown op '%s'\n", argv[1]);
    return 2;
  }
  if (argc > 2 && argv[2][0] == '-') {
    if (strcmp(argv[2], "--subdelim") == 0) set = ZPCT_SUBDELIM;
    else if (strcmp(argv[2], "--pchar") == 0) set = ZPCT_PCHAR;
    else {
      fprintf(stderr, "zpct: unknown flag '%s'\n", argv[2]);
      return 2;
    }
    arg0 = 3;
  }
  if (argc > arg0) {
    int i, rc = 0;
    for (i = arg0; i < argc; i++) {
      char buf[ZPCT_MAX + 8];
      size_t n = strlen(argv[i]);
      size_t need = decode ? zpct_decode(buf, sizeof(buf), argv[i], n, NULL)
                           : zpct_encode(buf, sizeof(buf), argv[i], n, set);
      if (need == SIZE_MAX || need >= sizeof(buf)) {
        fprintf(stderr, "zpct: %s: bad input '%s'\n",
                decode ? "decode" : "encode", argv[i]);
        rc = 1;
        continue;
      }
      if (fwrite(buf, 1, need, stdout) != need) return 1;
      putchar('\n');
    }
    return rc;
  }
  return do_stream(decode, set);
}
