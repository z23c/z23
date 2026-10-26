/* zutf16 CLI: transcode between UTF-8 and UTF-16LE.
 *
 * Usage: zutf16 <to-utf16|to-utf8>
 * Streams stdin (chunks are split at sequence boundaries, so this
 * also exercises incremental correctness). Writes raw bytes to
 * stdout. Exit 1 on invalid input. This is the package's real
 * consumer. */
#include "zutf16/zutf16.h"

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#endif

enum { STREAM_CHUNK = 8192 };

static bool cli_binary_mode(FILE *stream) {
#if defined(_WIN32)
  if (_setmode(_fileno(stream), _O_BINARY) == -1) {
    fputs("zutf16: cannot select binary stream mode\n", stderr);
    return false;
  }
#else
  (void)stream;
#endif
  return true;
}

static size_t utf8_complete_prefix(const unsigned char *in, size_t n) {
  size_t pos = 0;
  while (pos < n) {
    uint32_t cp;
    size_t used = zutf16_decode_cp(in + pos, n - pos, &cp);
    if (used == 0) return SIZE_MAX;
    if (used == SIZE_MAX) return pos;
    pos += used;
  }
  return pos;
}

static size_t utf16_complete_prefix(const unsigned char *in, size_t n) {
  size_t used = n & ~(size_t)1;
  if (used >= 2) {
    unsigned last = in[used - 2] | ((unsigned)in[used - 1] << 8);
    if (last >= 0xd800 && last <= 0xdbff) used -= 2;
  }
  return used;
}

static int invalid_input(int to16) {
  fprintf(stderr, "zutf16: invalid %s input\n", to16 ? "UTF-8" : "UTF-16");
  return 1;
}

static int convert_chunk(int to16, const unsigned char *in, size_t n, FILE *output) {
  static unsigned char out[(STREAM_CHUNK + 3) * 3 + 8];
  size_t need = to16 ? zutf16_from_utf8(out, sizeof out, in, n)
                     : zutf16_to_utf8(out, sizeof out, in, n);
  if (need == SIZE_MAX || need >= sizeof out) return invalid_input(to16);
  if (fwrite(out, 1, need, output) != need) {
    fputs("zutf16: write error\n", stderr);
    return 1;
  }
  return 0;
}

static int cli_run(int argc, char **argv, FILE *source, FILE *output) {
  int to16;
  static unsigned char in[STREAM_CHUNK + 3];
  if (argc != 2 ||
      (strcmp(argv[1], "to-utf16") != 0 && strcmp(argv[1], "to-utf8") != 0)) {
    fprintf(stderr, "usage: zutf16 <to-utf16|to-utf8>\n");
    return 2;
  }
  to16 = strcmp(argv[1], "to-utf16") == 0;
  if (!cli_binary_mode(source) || !cli_binary_mode(output)) return 1;
  size_t n, pending = 0;
  while ((n = fread(in + pending, 1, STREAM_CHUNK, source)) > 0) {
    size_t total = pending + n;
    size_t used = to16 ? utf8_complete_prefix(in, total)
                       : utf16_complete_prefix(in, total);
    if (used == SIZE_MAX) return invalid_input(to16);
    if (convert_chunk(to16, in, used, output) != 0) return 1;
    pending = total - used;
    memmove(in, in + used, pending);
  }
  if (ferror(source)) {
    fprintf(stderr, "zutf16: error reading stdin\n");
    return 1;
  }
  if (pending) return invalid_input(to16);
  if (fflush(output) != 0 || ferror(output)) {
    fputs("zutf16: write error\n", stderr);
    return 1;
  }
  return 0;
}

int main(int argc, char **argv) {
  return cli_run(argc, argv, stdin, stdout);
}
