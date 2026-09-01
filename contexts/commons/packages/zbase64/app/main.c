/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: b64 - strict RFC 4648 Base64 transcoder over stdin/stdout.
 *
 * Usage: b64 [-d|--decode] [-u|--url]
 *
 * Default encodes stdin to the standard alphabet (padded) with a 72-column
 * line fold and a trailing newline. -d decodes (standard alphabet by
 * default, URL-safe with -u; newlines in the input are then the only
 * whitespace tolerated, matching the encoder's fold). -u alone encodes
 * with the URL-safe alphabet. Input is bounded at 64 MiB.
 */
#include "zbase64/zbase64.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT (64u * 1024u * 1024u)

static unsigned char input[MAX_INPUT];

int main(int argc, char **argv) {
  int decode = 0, url = 0;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--decode") == 0)
      decode = 1;
    else if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--url") == 0)
      url = 1;
    else {
      fprintf(stderr, "usage: b64 [-d|--decode] [-u|--url] < in > out\n");
      return 2;
    }
  }

  size_t len = fread(input, 1, sizeof(input), stdin);
  if (ferror(stdin) || !feof(stdin)) {
    fprintf(stderr, "b64: read error or input over 64 MiB bound\n");
    return 2;
  }

  if (!decode) {
    size_t cap = zbase64_encode_len(len) + 1u;
    char *out = malloc(cap);
    if (!out) {
      fprintf(stderr, "b64: out of memory\n");
      return 2;
    }
    bool ok = url ? zbase64url_encode(input, len, out, cap)
                  : zbase64_encode(input, len, out, cap);
    if (!ok) {
      fprintf(stderr, "b64: encode failed\n");
      free(out);
      return 2;
    }
    if (url) {
      fputs(out, stdout);
      fputc('\n', stdout);
    } else {
      size_t n = strlen(out);
      for (size_t i = 0; i < n; i += 72)
        printf("%.72s\n", out + i);
    }
    free(out);
    return 0;
  }

  /* Decode: strip the encoder's own line fold (bare newlines only); any
   * other whitespace remains an error. */
  size_t flat_len = 0;
  for (size_t i = 0; i < len; i++)
    if (input[i] != '\n')
      input[flat_len++] = input[i];

  size_t cap = zbase64_decode_cap(flat_len) + 1u;
  unsigned char *out = malloc(cap);
  if (!out) {
    fprintf(stderr, "b64: out of memory\n");
    return 2;
  }
  size_t out_len = 0;
  bool ok = url ? zbase64url_decode((const char *)input, flat_len, out,
                                    cap, &out_len)
                : zbase64_decode((const char *)input, flat_len, out, cap,
                                 &out_len);
  if (!ok) {
    fprintf(stderr, "b64: input is not canonical %sbase64\n",
            url ? "URL-safe " : "");
    free(out);
    return 2;
  }
  fwrite(out, 1, out_len, stdout);
  free(out);
  return 0;
}
