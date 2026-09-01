/* zcrc CLI: CRC files or stdin. */

#include "zcrc/zcrc.h"

#include <stdio.h>
#include <string.h>

static int crc_stream(FILE *f, const char *name, int use_c) {
  unsigned char buf[65536];
  size_t n;
  uint32_t s = use_c ? zcrc32c_init() : zcrc32_init();
  while ((n = fread(buf, 1, sizeof buf, f)) > 0)
    s = use_c ? zcrc32c_update(s, buf, n) : zcrc32_update(s, buf, n);
  if (ferror(f)) {
    fprintf(stderr, "zcrc: read error on %s\n", name);
    return 1;
  }
  printf("%08x  %s\n", use_c ? zcrc32c_final(s) : zcrc32_final(s), name);
  return 0;
}

int main(int argc, char **argv) {
  int use_c = 0;
  int i;
  int rc = 0;
  int files = 0;
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-c") == 0) {
      use_c = 1;
      continue;
    }
    {
      FILE *f = fopen(argv[i], "rb");
      if (!f) {
        fprintf(stderr, "zcrc: cannot open %s\n", argv[i]);
        rc = 1;
        continue;
      }
      rc |= crc_stream(f, argv[i], use_c);
      fclose(f);
      files = 1;
    }
  }
  if (!files) rc |= crc_stream(stdin, "-", use_c);
  return rc;
}
