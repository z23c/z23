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

/* A suffix can need one more read; malformed complete prefixes still go
 * through the strict decoder immediately. Never retain more than two bytes. */
static size_t stream_decode_prefix(const unsigned char *in, size_t n) {
  if (n && in[n - 1] == '%') return n - 1;
  if (n >= 2 && in[n - 2] == '%') return n - 2;
  return n;
}

static int finish_output(FILE *output, int rc) {
  if (fflush(output) != 0 || ferror(output)) {
    fputs("zpct: write error\n", stderr);
    return 1;
  }
  return rc;
}

static int do_stream(int decode, zpct_set set, FILE *source, FILE *output) {
  enum { CHUNK = 4096 };
  unsigned char in[CHUNK + 2];
  char out[sizeof(in) * 3 + 1];
  size_t n, pending = 0;
  while ((n = fread(in + pending, 1, CHUNK, source)) > 0) {
    size_t total = pending + n;
    size_t used = decode ? stream_decode_prefix(in, total) : total;
    size_t need = decode ? zpct_decode(out, sizeof(out), in, used, NULL)
                         : zpct_encode(out, sizeof(out), in, used, set);
    if (need == SIZE_MAX || need >= sizeof(out)) {
      fprintf(stderr, "zpct: %s: %s\n", decode ? "decode" : "encode",
              decode ? "malformed percent sequence" : "output overflow");
      return 1;
    }
    /* Decoded output may contain NULs: write raw bytes. */
    if (fwrite(out, 1, need, output) != need) {
      fprintf(stderr, "zpct: write error\n");
      return 1;
    }
    pending = total - used;
    memmove(in, in + used, pending);
  }
  if (ferror(source)) {
    fprintf(stderr, "zpct: error reading stdin\n");
    return 1;
  }
  if (pending) {
    fputs("zpct: decode: malformed percent sequence at EOF\n", stderr);
    return 1;
  }
  return 0;
}

static int write_argument(FILE *output, const char *bytes, size_t size) {
  if (fwrite(bytes, 1, size, output) != size || fputc('\n', output) == EOF) {
    fputs("zpct: write error\n", stderr);
    return 1;
  }
  return 0;
}

static int cli_run(int argc, char **argv, FILE *source, FILE *output) {
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
      if (write_argument(output, buf, need) != 0) return 1;
    }
    return finish_output(output, rc);
  }
  return finish_output(output, do_stream(decode, set, source, output));
}

int main(int argc, char **argv) {
  return cli_run(argc, argv, stdin, stdout);
}
