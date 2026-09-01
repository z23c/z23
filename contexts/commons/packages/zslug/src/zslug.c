/* zslug — deterministic URL/filename slug generation.  See zslug.h. */

#include "zslug/zslug.h"

#include <stdint.h>

zslug_opts zslug_default_opts(void) {
  zslug_opts o;
  o.sep = '-';
  o.max_len = 0;
  o.fold_case = 1;
  return o;
}

/* Latin-1 fold: codepoints 0xC0..0xFF -> ASCII base spelling.
 * Entries are NUL-terminated strings of one or two ASCII letters;
 * NULL means "no fold, treat as separator". */
static const char *const latin1_fold[0x40] = {
    /* C0..C7 */ "a", "a", "a", "a", "a", "a", "ae", "c",
    /* C8..CF */ "e", "e", "e", "e", "i", "i", "i", "i",
    /* D0..D7 */ "d", "n", "o", "o", "o", "o", "o", NULL,
    /* D8..DF */ "o", "u", "u", "u", "u", "y", "th", "ss",
    /* E0..E7 */ "a", "a", "a", "a", "a", "a", "ae", "c",
    /* E8..EF */ "e", "e", "e", "e", "i", "i", "i", "i",
    /* F0..F7 */ "d", "n", "o", "o", "o", "o", "o", NULL,
    /* F8..FF */ "o", "u", "u", "u", "u", "y", "th", "y",
};

/* Decode one codepoint.  Returns the codepoint (>= 0) or -1 for
 * malformed input; *advance always receives the number of input bytes
 * consumed (1 on malformed input, so callers can skip and continue). */
static long utf8_decode(const unsigned char *p, size_t n, size_t *advance) {
  *advance = 1;
  if (n == 0) return -1;
  if (p[0] < 0x80) return p[0];
  if (p[0] < 0xC2 || p[0] > 0xF4) return -1; /* stray cont or overlong lead */
  if (p[0] < 0xE0) {
    if (n < 2 || (p[1] & 0xC0) != 0x80) return -1;
    *advance = 2;
    return ((long)(p[0] & 0x1F) << 6) | (p[1] & 0x3F);
  }
  if (p[0] < 0xF0) {
    if (n < 3 || (p[1] & 0xC0) != 0x80 || (p[2] & 0xC0) != 0x80) return -1;
    if (p[0] == 0xE0 && p[1] < 0xA0) return -1; /* overlong */
    if (p[0] == 0xED && p[1] >= 0xA0) return -1; /* surrogate */
    *advance = 3;
    return ((long)(p[0] & 0x0F) << 12) | ((long)(p[1] & 0x3F) << 6) |
           (p[2] & 0x3F);
  }
  if (n < 4 || (p[1] & 0xC0) != 0x80 || (p[2] & 0xC0) != 0x80 ||
      (p[3] & 0xC0) != 0x80)
    return -1;
  if (p[0] == 0xF0 && p[1] < 0x90) return -1; /* overlong */
  if (p[0] == 0xF4 && p[1] > 0x8F) return -1; /* > U+10FFFF */
  *advance = 4;
  return ((long)(p[0] & 0x07) << 18) | ((long)(p[1] & 0x3F) << 12) |
         ((long)(p[2] & 0x3F) << 6) | (p[3] & 0x3F);
}

static char sanitize_sep(char sep) {
  if ((sep >= 'a' && sep <= 'z') || (sep >= 'A' && sep <= 'Z') ||
      (sep >= '0' && sep <= '9') || sep < 0x21 || sep > 0x7E)
    return '-';
  return sep;
}

typedef struct {
  char *out;
  size_t cap;
  size_t len;      /* logical length, grows past cap for measurement */
  int pending_sep; /* a separator has been seen since the last letter */
  zslug_opts opts;
} slug_state;

static void emit_char(slug_state *s, char c) {
  if (s->out && s->len < s->cap) s->out[s->len] = c;
  s->len++;
}

static void emit_word_char(slug_state *s, char c) {
  if (s->pending_sep && s->len > 0) emit_char(s, s->opts.sep);
  s->pending_sep = 0;
  emit_char(s, c);
}

static void emit_sep(slug_state *s) {
  if (s->len > 0) s->pending_sep = 1;
}

size_t zslug(const char *in, size_t in_len, char *out, size_t out_cap,
             const zslug_opts *opts) {
  slug_state s;
  size_t i = 0;

  if (out_cap > 0 && out) out[0] = '\0';
  if (!in && in_len > 0) return 0;

  s.out = out;
  s.cap = out_cap;
  s.len = 0;
  s.pending_sep = 0;
  s.opts = opts ? *opts : zslug_default_opts();
  s.opts.sep = sanitize_sep(s.opts.sep);

  while (i < in_len) {
    size_t adv;
    long cp = utf8_decode((const unsigned char *)in + i, in_len - i, &adv);
    i += adv;
    if (cp < 0) {
      emit_sep(&s);
      continue;
    }
    if (cp < 0x80) {
      unsigned char c = (unsigned char)cp;
      if (c >= 'A' && c <= 'Z') {
        emit_word_char(&s, s.opts.fold_case ? (char)(c + 32) : (char)c);
      } else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
        emit_word_char(&s, (char)c);
      } else {
        emit_sep(&s);
      }
    } else if (cp >= 0xC0 && cp <= 0xFF) {
      const char *f = latin1_fold[cp - 0xC0];
      if (f) {
        for (; *f; f++) emit_word_char(&s, *f);
      } else {
        emit_sep(&s);
      }
    } else {
      emit_sep(&s);
    }
  }
  /* A trailing pending separator is never emitted, so the logical slug
   * already ends on a word character. */

  if (out && out_cap > 0) {
    size_t avail = s.len < out_cap ? s.len : out_cap - 1;
    size_t term = avail;
    if (s.opts.max_len > 0 && s.len > s.opts.max_len &&
        avail >= s.opts.max_len) {
      /* max_len truncation: cut at the cap, strip a dangling separator,
       * then if the cut landed mid-word walk back to the last
       * separator so the slug ends on a word boundary. */
      size_t cut = s.opts.max_len;
      size_t j;
      while (cut > 0 && out[cut - 1] == s.opts.sep) cut--;
      j = cut;
      while (j > 0 && out[j - 1] != s.opts.sep) j--;
      if (j > 0 && j - 1 < cut && s.len > cut && cut < avail &&
          out[cut] != s.opts.sep) {
        /* cut landed mid-word (the byte at cut in the materialised
         * slug is not a separator): end at the previous separator. */
        cut = j - 1;
      }
      term = cut;
    }
    out[term] = '\0';
  }
  return s.len;
}

int zslug_is_canonical(const char *s, size_t len, const zslug_opts *opts) {
  zslug_opts o = opts ? *opts : zslug_default_opts();
  size_t i;
  if (!s) return 0;
  o.sep = sanitize_sep(o.sep);
  if (len == 0) return 0;
  if (o.max_len > 0 && len > o.max_len) return 0;
  if (s[0] == (char)o.sep || s[len - 1] == (char)o.sep) return 0;
  for (i = 0; i < len; i++) {
    unsigned char c = (unsigned char)s[i];
    int ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
             (!o.fold_case && c >= 'A' && c <= 'Z');
    if (!ok) {
      if (c != (unsigned char)o.sep) return 0;
      if (i > 0 && s[i - 1] == (char)o.sep) return 0; /* doubled */
    }
  }
  return 1;
}
