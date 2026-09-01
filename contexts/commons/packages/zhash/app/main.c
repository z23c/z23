/* zhash CLI: hash stdin or argv strings.
 *
 * Usage: zhash [fnv1a64|fnv1a32|crc32|djb2|sdbm] [STRING...]
 * With no STRING, hashes stdin as one stream. Prints one hex hash per
 * line. This is the package's real consumer. */
#include "zhash/zhash.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  const char *which = argc > 1 ? argv[1] : "fnv1a64";
  int i;
  if (argc > 2) {
    for (i = 2; i < argc; i++) {
      const char *s = argv[i];
      size_t n = strlen(s);
      if (strcmp(which, "fnv1a64") == 0)
        printf("%016llx\n", (unsigned long long)zhash_fnv1a64(s, n));
      else if (strcmp(which, "fnv1a32") == 0)
        printf("%08x\n", zhash_fnv1a32(s, n));
      else if (strcmp(which, "crc32") == 0)
        printf("%08x\n", zhash_crc32(s, n));
      else if (strcmp(which, "djb2") == 0)
        printf("%08x\n", zhash_djb2(s, n));
      else if (strcmp(which, "sdbm") == 0)
        printf("%08x\n", zhash_sdbm(s, n));
      else {
        fprintf(stderr, "zhash: unknown algorithm '%s'\n", which);
        return 2;
      }
    }
    return 0;
  }
  /* stdin, streamed in chunks (djb2/sdbm have no streaming form). */
  {
    unsigned char buf[4096];
    size_t n;
    uint64_t h64 = UINT64_C(14695981039346656037);
    uint32_t h32 = UINT32_C(2166136261), c32 = 0;
    while ((n = fread(buf, 1, sizeof(buf), stdin)) > 0) {
      h64 = zhash_fnv1a64_update(h64, buf, n);
      h32 = zhash_fnv1a32_update(h32, buf, n);
      c32 = zhash_crc32_update(c32, buf, n);
    }
    if (ferror(stdin)) {
      fprintf(stderr, "zhash: error reading stdin\n");
      return 1;
    }
    if (strcmp(which, "fnv1a64") == 0)
      printf("%016llx\n", (unsigned long long)h64);
    else if (strcmp(which, "fnv1a32") == 0)
      printf("%08x\n", h32);
    else if (strcmp(which, "crc32") == 0)
      printf("%08x\n", c32);
    else {
      fprintf(stderr,
              "zhash: algorithm '%s' unsupported for streaming stdin\n",
              which);
      return 2;
    }
  }
  return 0;
}
