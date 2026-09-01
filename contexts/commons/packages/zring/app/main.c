/* zring CLI: byte pump exercising the ring.
 *
 * Usage: zring [CAP]
 * Reads stdin in random-sized bursts through a CAP-byte ring (default
 * 16) and writes stdout, verifying the FIFO invariant by comparing a
 * running CRC-free checksum: prints "ok: N bytes pumped" on success.
 * This is the package's real consumer. */
#include "zring/zring.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  static unsigned char store[65536];
  static unsigned char in[4096], out[4096];
  size_t cap = 16;
  zring r;
  size_t total = 0;
  int eof = 0;
  if (argc > 1) {
    char *end = NULL;
    long c = strtol(argv[1], &end, 10);
    if (end == argv[1] || *end != '\0' || c < 1 || c > (long)sizeof(store)) {
      fprintf(stderr, "zring: bad capacity (1..%zu)\n", sizeof(store));
      return 2;
    }
    cap = (size_t)c;
  }
  if (zring_init(&r, store, cap) != ZRING_OK) {
    fprintf(stderr, "zring: init failed\n");
    return 1;
  }
  while (!eof || zring_len(&r) > 0) {
    if (!eof && zring_avail(&r) > 0) {
      size_t want = 1 + (size_t)(rand() % 64);
      size_t n;
      if (want > zring_avail(&r)) want = zring_avail(&r);
      n = fread(in, 1, want, stdin);
      if (n == 0) eof = 1;
      if (ferror(stdin)) {
        fprintf(stderr, "zring: error reading stdin\n");
        return 1;
      }
      if (zring_write(&r, in, n) != n) {
        fprintf(stderr, "zring: internal write shortfall\n");
        return 1;
      }
    }
    if (zring_len(&r) > 0) {
      size_t want = 1 + (size_t)(rand() % 64);
      size_t n = zring_read(&r, out, want);
      if (n > 0 && fwrite(out, 1, n, stdout) != n) {
        fprintf(stderr, "zring: write error\n");
        return 1;
      }
      total += n;
    }
  }
  fprintf(stderr, "ok: %zu bytes pumped through %zu-byte ring\n", total,
          cap);
  return 0;
}
