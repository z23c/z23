/* zutf16 CLI: transcode between UTF-8 and UTF-16LE.
 *
 * Usage: zutf16 <to-utf16|to-utf8>
 * Streams stdin (chunks are split at sequence boundaries, so this
 * also exercises incremental correctness). Writes raw bytes to
 * stdout. Exit 1 on invalid input. This is the package's real
 * consumer. */
#include "zutf16/zutf16.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  int to16;
  static unsigned char in[8192], out[sizeof(in) * 3 + 8];
  if (argc != 2 ||
      (strcmp(argv[1], "to-utf16") != 0 && strcmp(argv[1], "to-utf8") != 0)) {
    fprintf(stderr, "usage: zutf16 <to-utf16|to-utf8>\n");
    return 2;
  }
  to16 = strcmp(argv[1], "to-utf16") == 0;
  for (;;) {
    size_t n = fread(in, 1, sizeof(in), stdin);
    size_t need;
    if (n == 0) break;
    need = to16 ? zutf16_from_utf8(out, sizeof(out), in, n)
                : zutf16_to_utf8(out, sizeof(out), in, n);
    if (need == SIZE_MAX || need >= sizeof(out)) {
      fprintf(stderr, "zutf16: invalid %s input\n",
              to16 ? "UTF-8" : "UTF-16");
      return 1;
    }
    if (fwrite(out, 1, need, stdout) != need) {
      fprintf(stderr, "zutf16: write error\n");
      return 1;
    }
  }
  if (ferror(stdin)) {
    fprintf(stderr, "zutf16: error reading stdin\n");
    return 1;
  }
  return 0;
}
