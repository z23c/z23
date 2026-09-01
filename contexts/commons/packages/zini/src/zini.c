/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: INI configuration parser; see zini.h for the grammar and
 *          ownership rules.  Built on zmap: one map of section name ->
 *          zmap* of key -> malloc'd value copy.
 *
 * Local (pre-publication) builds compile against ../zmap/include; the
 * Commons recipe build resolves the pinned zmap dependency by content root.
 */
#include "zini/zini.h"

#include "zmap/zmap.h"

#include <stdlib.h>
#include <string.h>

struct zini {
  zmap *sections; /* section name -> zmap* (key -> char* value) */
  size_t count;
};

static void value_free(void *ctx, const char *key, void *value) {
  (void)ctx;
  (void)key;
  free(value);
}

static void section_free(void *ctx, const char *key, void *value) {
  (void)ctx;
  (void)key;
  zmap_destroy(value, value_free, nullptr);
}

static zini *fail(zini *ini, char *section_buf, zini_error *err, size_t line,
                  const char *message) {
  if (err) {
    err->line = line;
    err->message = message;
  }
  free(section_buf);
  zini_destroy(ini);
  return nullptr;
}

zini *zini_parse(const char *text, size_t len, zini_error *err) {
  zini *ini = calloc(1, sizeof(*ini));
  if (!ini)
    return fail(nullptr, nullptr, err, 0, "out of memory");
  ini->sections = zmap_create();
  if (!ini->sections)
    return fail(ini, nullptr, err, 0, "out of memory");

  /* Current section name, NUL-terminated; "" is the global section. */
  size_t section_cap = 16;
  char *section = malloc(section_cap);
  if (!section)
    return fail(ini, nullptr, err, 0, "out of memory");
  section[0] = '\0';

  size_t line_no = 0;
  size_t at = 0;
  for (;;) {
    line_no++;
    size_t end = at;
    while (end < len && text[end] != '\n')
      end++;
    size_t line_len = end - at;
    if (line_len > 0 && text[at + line_len - 1] == '\r')
      line_len--; /* tolerate CRLF */

    const char *line = text + at;
    size_t i = 0;
    while (i < line_len && (line[i] == ' ' || line[i] == '\t'))
      i++;
    size_t body = line_len;
    while (body > i && (line[body - 1] == ' ' || line[body - 1] == '\t'))
      body--;

    if (i == body || line[i] == '#' || line[i] == ';') {
      /* blank line or full-line comment */
    } else if (line[i] == '[') {
      /* Section header: the closing ']' must be the last body byte. */
      if (line[body - 1] != ']')
        return fail(ini, section, err, line_no, "malformed section header");
      size_t name_len = body - i - 2;
      const char *name = line + i + 1;
      while (name_len > 0 && (*name == ' ' || *name == '\t')) {
        name++;
        name_len--;
      }
      while (name_len > 0 &&
             (name[name_len - 1] == ' ' || name[name_len - 1] == '\t'))
        name_len--;
      if (name_len + 1 > section_cap) {
        char *grown = realloc(section, name_len + 1);
        if (!grown)
          return fail(ini, section, err, line_no, "out of memory");
        section = grown;
        section_cap = name_len + 1;
      }
      memcpy(section, name, name_len);
      section[name_len] = '\0';
      if (!zmap_contains(ini->sections, section)) {
        zmap *kv = zmap_create();
        if (!kv || !zmap_put(ini->sections, section, kv, nullptr)) {
          zmap_destroy(kv, nullptr, nullptr);
          return fail(ini, section, err, line_no, "out of memory");
        }
      }
    } else {
      /* key = value */
      const char *eq = memchr(line + i, '=', body - i);
      if (!eq)
        return fail(ini, section, err, line_no,
                    "expected key=value or [section]");
      size_t key_len = (size_t)(eq - (line + i));
      while (key_len > 0 &&
             (line[i + key_len - 1] == ' ' || line[i + key_len - 1] == '\t'))
        key_len--;
      if (key_len == 0)
        return fail(ini, section, err, line_no, "empty key");

      /* Value: trim, then strip an inline comment (only when the comment
       * char is preceded by whitespace). */
      size_t vstart = (size_t)(eq - line) + 1;
      while (vstart < body && (line[vstart] == ' ' || line[vstart] == '\t'))
        vstart++;
      size_t vlen = body - vstart;
      for (size_t k = 0; k < vlen; k++) {
        char c = line[vstart + k];
        if ((c == '#' || c == ';') && k > 0 &&
            (line[vstart + k - 1] == ' ' || line[vstart + k - 1] == '\t')) {
          vlen = k;
          while (vlen > 0 &&
                 (line[vstart + vlen - 1] == ' ' ||
                  line[vstart + vlen - 1] == '\t'))
            vlen--;
          break;
        }
      }

      zmap *kv = zmap_get(ini->sections, section);
      if (!kv) {
        /* First key of a section whose header never appeared (the global
         * section, or an empty-name section created above): create the
         * map lazily. */
        kv = zmap_create();
        if (!kv || !zmap_put(ini->sections, section, kv, nullptr)) {
          zmap_destroy(kv, nullptr, nullptr);
          return fail(ini, section, err, line_no, "out of memory");
        }
      }

      char *key_copy = malloc(key_len + 1);
      char *val_copy = malloc(vlen + 1);
      if (!key_copy || !val_copy) {
        free(key_copy);
        free(val_copy);
        return fail(ini, section, err, line_no, "out of memory");
      }
      memcpy(key_copy, line + i, key_len);
      key_copy[key_len] = '\0';
      memcpy(val_copy, line + vstart, vlen);
      val_copy[vlen] = '\0';

      void *old = nullptr;
      if (!zmap_put(kv, key_copy, val_copy, &old)) {
        free(key_copy);
        free(val_copy);
        return fail(ini, section, err, line_no, "out of memory");
      }
      free(key_copy); /* zmap duplicates the key itself */
      if (old)
        free(old); /* duplicate key: last wins */
      else
        ini->count++;
    }

    if (end >= len)
      break;
    at = end + 1;
  }
  free(section);
  return ini;
}

void zini_destroy(zini *ini) {
  if (!ini)
    return;
  zmap_destroy(ini->sections, section_free, nullptr);
  free(ini);
}

const char *zini_get(const zini *ini, const char *section, const char *key) {
  zmap *kv = zmap_get(ini->sections, section ? section : "");
  if (!kv)
    return nullptr;
  return zmap_get(kv, key);
}

size_t zini_count(const zini *ini) { return ini->count; }

/* --- deterministic sorted iteration --- */

typedef struct {
  const char *section;
  const char *key;
  const char *value;
} zini_flat;

static int flat_cmp(const void *va, const void *vb) {
  const zini_flat *a = va;
  const zini_flat *b = vb;
  int c = strcmp(a->section, b->section);
  return c != 0 ? c : strcmp(a->key, b->key);
}

void zini_foreach(const zini *ini, zini_entry_fn fn, void *ctx) {
  size_t n = ini->count;
  if (n == 0)
    return;
  zini_flat *flat = malloc(n * sizeof(*flat));
  if (!flat) {
    /* Fail closed: a sorted snapshot we cannot allocate is not delivered
     * partially or out of order. */
    return;
  }
  size_t k = 0;
  const char *section;
  void *vkv;
  for (zmap_iter it = ZMAP_ITER_INIT;
       zmap_next(ini->sections, &it, &section, &vkv);) {
    const char *key;
    void *value;
    for (zmap_iter kit = ZMAP_ITER_INIT; zmap_next(vkv, &kit, &key, &value);) {
      flat[k].section = section;
      flat[k].key = key;
      flat[k].value = value;
      k++;
    }
  }
  qsort(flat, k, sizeof(*flat), flat_cmp);
  for (size_t i = 0; i < k; i++)
    fn(ctx, flat[i].section, flat[i].key, flat[i].value);
  free(flat);
}
