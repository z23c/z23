/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: wordfreq - count word frequencies over stdin and print the top
 *          entries, most frequent first (ties broken lexicographically).
 *
 * Usage: wordfreq [n]   (default n = 20; n = 0 prints all)
 *
 * Words are maximal [a-z0-9'] runs, lowercased.  Input is bounded at
 * 64 MiB.  Counts are stored directly in the map's void* slots (count+1,
 * so a stored NULL value never collides with absence).
 */
#include "zmap/zmap.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT (64u * 1024u * 1024u)

static void bump(zmap *m, const char *word, size_t len) {
  char key[128];
  if (len >= sizeof(key))
    len = sizeof(key) - 1; /* words past the bound merge into one key */
  memcpy(key, word, len);
  key[len] = '\0';
  uintptr_t count = (uintptr_t)zmap_get(m, key);
  if (!zmap_put(m, key, (void *)(count + 1), nullptr)) {
    fprintf(stderr, "wordfreq: out of memory\n");
    exit(2);
  }
}

typedef struct {
  const char *word;
  uintptr_t count;
} entry;

static int entry_cmp(const void *va, const void *vb) {
  const entry *a = va;
  const entry *b = vb;
  if (a->count != b->count)
    return a->count < b->count ? 1 : -1; /* descending */
  return strcmp(a->word, b->word);
}

int main(int argc, char **argv) {
  long top = 20;
  if (argc > 1) {
    char *end = nullptr;
    top = strtol(argv[1], &end, 10);
    if (*end != '\0' || top < 0) {
      fprintf(stderr, "usage: wordfreq [n] < text\n");
      return 2;
    }
  }

  static char input[MAX_INPUT];
  size_t len = fread(input, 1, sizeof(input), stdin);
  if (ferror(stdin) || !feof(stdin)) {
    fprintf(stderr, "wordfreq: read error or input over 64 MiB bound\n");
    return 2;
  }
  for (size_t i = 0; i < len; i++)
    input[i] = (char)tolower((unsigned char)input[i]);

  zmap *m = zmap_create();
  if (!m) {
    fprintf(stderr, "wordfreq: out of memory\n");
    return 2;
  }

  size_t at = 0;
  while (at < len) {
    while (at < len && !isalnum((unsigned char)input[at]) && input[at] != '\'')
      at++;
    size_t start = at;
    while (at < len && (isalnum((unsigned char)input[at]) || input[at] == '\''))
      at++;
    if (at > start)
      bump(m, input + start, at - start);
  }

  size_t n = zmap_size(m);
  entry *entries = malloc(n * sizeof(*entries));
  if (!entries && n > 0) {
    fprintf(stderr, "wordfreq: out of memory\n");
    zmap_destroy(m, nullptr, nullptr);
    return 2;
  }
  size_t k = 0;
  const char *word;
  void *value;
  for (zmap_iter it = ZMAP_ITER_INIT; zmap_next(m, &it, &word, &value);) {
    entries[k].word = strdup(word); /* outlives the map */
    if (!entries[k].word) {
      fprintf(stderr, "wordfreq: out of memory\n");
      zmap_destroy(m, nullptr, nullptr);
      free(entries);
      return 2;
    }
    entries[k].count = (uintptr_t)value;
    k++;
  }
  qsort(entries, n, sizeof(*entries), entry_cmp);

  size_t shown = top == 0 || (size_t)top > n ? n : (size_t)top;
  for (size_t i = 0; i < shown; i++)
    printf("%7llu %s\n", (unsigned long long)entries[i].count,
           entries[i].word);
  fprintf(stderr, "%zu distinct words\n", n);

  for (size_t i = 0; i < n; i++)
    free((void *)entries[i].word);
  free(entries);
  zmap_destroy(m, nullptr, nullptr);
  return 0;
}
