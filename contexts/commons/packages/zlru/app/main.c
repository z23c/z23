/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zlru - LRU cache trace analyzer.
 *
 * Usage: zlru CAPACITY < keys
 *
 * Reads newline-terminated keys on stdin and replays them against an
 * LRU cache of CAPACITY entries (1..16,000,000), printing one line per
 * key: "HIT <key>" or "MISS <key>", plus a final summary with the hit
 * rate. This is the classic cache-trace tool: feed it an access log to
 * size a cache before deploying one.
 *
 * Keys are bounded at 4096 bytes, input at 16 MiB. Exit 0 on success,
 * 2 on misuse or a bound violation.
 */
#include "zlru/zlru.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE 4096u
#define MAX_INPUT (16u * 1024u * 1024u)
#define MAX_CAPACITY 16000000u

static char input[MAX_INPUT];

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: zlru CAPACITY < keys\n");
    return 2;
  }
  char *end = NULL;
  unsigned long cap = strtoul(argv[1], &end, 10);
  if (!end || *end || cap < 1 || cap > MAX_CAPACITY) {
    fprintf(stderr, "zlru: capacity must be 1..%u\n", MAX_CAPACITY);
    return 2;
  }

  size_t len = fread(input, 1, sizeof(input), stdin);
  if (ferror(stdin) || !feof(stdin)) {
    fprintf(stderr, "zlru: read error or input over 16 MiB bound\n");
    return 2;
  }

  zlru *cache = zlru_create((size_t)cap, NULL, NULL, (zmap_alloc){0});
  if (!cache) {
    fprintf(stderr, "zlru: allocation failure\n");
    return 2;
  }

  size_t hits = 0, misses = 0;
  size_t pos = 0;
  while (pos < len) {
    size_t start = pos;
    while (pos < len && input[pos] != '\n')
      pos++;
    size_t klen = pos - start;
    pos++;
    if (!klen)
      continue;
    if (klen > MAX_LINE) {
      fprintf(stderr, "zlru: key over %u bytes\n", MAX_LINE);
      zlru_destroy(cache);
      return 2;
    }
    input[start + klen] = '\0'; /* input is ours; newline consumed */
    const char *key = input + start;
    if (zlru_get(cache, key)) {
      printf("HIT %s\n", key);
      hits++;
    } else {
      printf("MISS %s\n", key);
      misses++;
      if (!zlru_put(cache, key, cache)) { /* value: non-NULL marker */
        fprintf(stderr, "zlru: allocation failure\n");
        zlru_destroy(cache);
        return 2;
      }
    }
  }
  zlru_destroy(cache);
  printf("# %zu keys: %zu hits, %zu misses, hit rate %.3f\n",
         hits + misses, hits, misses,
         hits + misses ? (double)hits / (double)(hits + misses) : 0.0);
  return 0;
}
