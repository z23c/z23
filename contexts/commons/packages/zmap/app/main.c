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

/* Empty input leaves n == 0; avoid a no-op library sort. */
static void entries_sort(entry *entries, size_t n) {
  if (n > 1)
    qsort(entries, n, sizeof(*entries), entry_cmp);
}

static void count_words(zmap *m, const char *input, size_t len) {
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
}

static entry *collect_entries(zmap *m, size_t n, const zmap_alloc *alloc) {
  if (n > SIZE_MAX / sizeof(entry))
    return nullptr;
  entry *entries = alloc->alloc(alloc->ctx, n ? n * sizeof(*entries) : 1u);
  if (!entries)
    return nullptr;
  size_t k = 0;
  const char *word;
  void *value;
  for (zmap_iter it = ZMAP_ITER_INIT; zmap_next(m, &it, &word, &value);) {
    entries[k].word = word; /* borrowed until the map is destroyed */
    entries[k].count = (uintptr_t)value;
    k++;
  }
  return entries;
}

static bool print_entries(const entry *entries, size_t shown) {
  if (!shown) return true;
  for (size_t i = 0; i < shown; i++)
    if (printf("%7llu %s\n", (unsigned long long)entries[i].count,
               entries[i].word) < 0) return false;
  return fflush(stdout) == 0 && !ferror(stdout);
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
  int extra = len == sizeof input ? fgetc(stdin) : EOF;
  if (ferror(stdin) || extra != EOF) {
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

  count_words(m, input, len);

  size_t n = zmap_size(m);
  zmap_alloc alloc = zmap_alloc_malloc();
  entry *entries = collect_entries(m, n, &alloc);
  if (!entries) {
    fprintf(stderr, "wordfreq: out of memory\n");
    zmap_destroy(m, nullptr, nullptr);
    return 2;
  }
  entries_sort(entries, n);

  size_t shown = top == 0 || (size_t)top > n ? n : (size_t)top;
  bool wrote = print_entries(entries, shown);
  fprintf(stderr, "%zu distinct words\n", n);

  alloc.dealloc(alloc.ctx, entries);
  zmap_destroy(m, nullptr, nullptr);
  if (!wrote) {
    fprintf(stderr, "wordfreq: output write failed\n");
    return 2;
  }
  return 0;
}
