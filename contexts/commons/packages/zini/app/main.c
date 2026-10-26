/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: inidump - parse INI from stdin and print a flattened,
 *          deterministic "section.key = value" dump.
 *
 * Usage: inidump < config.ini
 *
 * Input is bounded at 16 MiB.  Entries print in sorted (section, key)
 * order; global-section keys print with an empty section prefix.
 */
#include "zini/zini.h"

#include <stdio.h>
#include <stdlib.h>

#define MAX_INPUT (16u * 1024u * 1024u)

typedef struct {
  FILE *stream;
  size_t emitted;
  bool failed;
} cli_output;

static void print_entry(void *ctx, const char *section, const char *key,
                        const char *value) {
  cli_output *output = ctx;
  if (output->failed) return;
  if (section[0] != '\0' && fprintf(output->stream, "[%s] ", section) < 0) {
    output->failed = true;
    return;
  }
  if (fprintf(output->stream, "%s = %s\n", key, value) < 0) {
    output->failed = true;
    return;
  }
  output->emitted++;
}

static int cli_run(FILE *source, FILE *output) {
  static char input[MAX_INPUT];
  size_t len = fread(input, 1, sizeof(input), source);
  if (ferror(source) || !feof(source)) {
    fprintf(stderr, "inidump: read error or input over 16 MiB bound\n");
    return 2;
  }

  zini_error err = {0, nullptr};
  zini *ini = zini_parse(input, len, &err);
  if (!ini) {
    fprintf(stderr, "inidump: line %zu: %s\n", err.line, err.message);
    return 1;
  }

  size_t expected = zini_count(ini);
  cli_output state = {output, 0, false};
  zini_foreach(ini, print_entry, &state);
  zini_destroy(ini);
  if (state.failed || fflush(output) != 0 || ferror(output)) {
    fputs("inidump: output write failed\n", stderr);
    return 2;
  }
  if (state.emitted != expected) {
    fprintf(stderr, "inidump: incomplete iteration: emitted %zu of %zu entries\n",
            state.emitted, expected);
    return 2;
  }
  fprintf(stderr, "%zu entries\n", expected);
  return 0;
}

int main(void) {
  return cli_run(stdin, stdout);
}
