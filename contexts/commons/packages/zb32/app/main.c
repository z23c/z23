/* zb32 CLI: base32 encode/decode.
 *
 * Usage: zb32 <encode|decode>
 * Streams stdin, writes stdout. Decode is strict (canonical padding
 * required). Exit 1 on malformed input, 2 on usage error. This is the
 * package's real consumer. */
#include "zb32/zb32.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  static unsigned char in[40960];
  static char out[sizeof(in) * 2 + 8];
  int dec;
  size_t n;
  if (argc != 2 ||
      (strcmp(argv[1], "encode") != 0 && strcmp(argv[1], "decode") != 0)) {
    fprintf(stderr, "usage: zb32 <encode|decode>\n");
    return 2;
  }
  dec = strcmp(argv[1], "decode") == 0;
  n = fread(in, 1, sizeof(in), stdin);
  if (ferror(stdin)) {
    fprintf(stderr, "zb32: error reading stdin\n");
    return 1;
  }
  if (n == sizeof(in) && !feof(stdin)) {
    fprintf(stderr, "zb32: input too large (max %zu)\n", sizeof(in));
    return 1;
  }
  {
    size_t need = dec ? zb32_decode(out, sizeof(out), (char *)in, n)
                      : zb32_encode(out, sizeof(out), in, n);
    if (need == SIZE_MAX || need >= sizeof(out)) {
      fprintf(stderr, "zb32: %s failed (malformed input)\n",
              dec ? "decode" : "encode");
      return 1;
    }
    if (fwrite(out, 1, need, stdout) != need) {
      fprintf(stderr, "zb32: write error\n");
      return 1;
    }
  }
  return 0;
}
