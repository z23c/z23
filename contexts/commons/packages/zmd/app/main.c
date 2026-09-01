/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: md2html - render Markdown-subset stdin to HTML on stdout.
 *
 * Usage: zmd < doc.md > doc.html
 *
 * Exit 0 on success, 2 on input over the 16 MiB bound or a read error,
 * 1 when the render fails (invalid UTF-8 or a write error).
 */
#include "zmd/zmd.h"

#include <stdio.h>

static char input[ZMD_MAX_INPUT];

static bool stdout_write(void *ctx, const char *data, size_t len) {
  (void)ctx;
  return fwrite(data, 1, len, stdout) == len;
}

int main(void) {
  size_t len = fread(input, 1, sizeof(input), stdin);
  if (ferror(stdin) || !feof(stdin)) {
    fprintf(stderr, "zmd: read error or input over 16 MiB bound\n");
    return 2;
  }
  if (!zmd_render_html(input, len, stdout_write, NULL)) {
    fprintf(stderr, "zmd: render failed (invalid UTF-8 or write error)\n");
    return 1;
  }
  if (fflush(stdout) != 0) {
    fprintf(stderr, "zmd: flush failed\n");
    return 1;
  }
  return 0;
}
