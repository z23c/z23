/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
/* zwrap — greedy UTF-8-aware word wrapping.  See zwrap.h. */

#include "zwrap/zwrap.h"

#include "zutf8/zutf8.h"

zwrap_opts zwrap_default_opts(void) {
  zwrap_opts o;
  o.width = 72;
  o.break_long = 1;
  return o;
}

typedef struct {
  char *out;
  size_t cap;
  size_t len; /* logical length */
  size_t stored; /* complete prefix bytes in out */
  int clipped; /* no later sequence may fill a truncation gap */
} emit_state;

/* One "character": either a decoded codepoint (n = sequence length) or
 * one undecodable byte (n = 1).  Returns the byte count consumed. */
static size_t next_char(const char *p, size_t avail, uint32_t *cp) {
  size_t consumed = 0;
  if (zutf8_decode_n(p, avail, cp, &consumed) == ZUTF8_OK) return consumed;
  *cp = 0xFFFFFFFFu; /* sentinel: raw byte */
  return 1;
}

static void emit(emit_state *s, const char *bytes, size_t n) {
  size_t i = 0;
  while (i < n) {
    uint32_t cp;
    size_t step = next_char(bytes + i, n - i, &cp);
    if (s->out && !s->clipped) {
      if (s->cap > s->stored && step < s->cap - s->stored) {
        for (size_t j = 0; j < step; j++)
          s->out[s->stored + j] = bytes[i + j];
        s->stored += step;
      } else {
        s->clipped = 1;
      }
    }
    s->len += step;
    i += step;
  }
}

static int is_blank(uint32_t cp, char raw) {
  if (cp == 0xFFFFFFFFu) return raw == ' ' || raw == '\t';
  return cp == ' ' || cp == '\t';
}

/* Width-one expansion is at most two output bytes per input byte. */
static int input_extent_valid(const char *in, size_t len) {
  return (in != NULL || len == 0) && len <= SIZE_MAX / 2;
}

static size_t input_refusal(const char *in) {
  return in ? SIZE_MAX : 0;
}

/* Measures the word starting at i: returns its codepoint count and sets
 * *wbytes to its byte count, stopping before a newline or blank. */
static size_t zwrap_measure_word(const char *in, size_t in_len, size_t i,
                                 size_t *wbytes) {
  size_t wlen = 0; /* codepoints */
  size_t j = i;
  *wbytes = 0;
  while (j < in_len) {
    uint32_t cp2;
    size_t n2 = next_char(in + j, in_len - j, &cp2);
    if (cp2 == '\n' || is_blank(cp2, in[j])) break;
    wlen++;
    *wbytes += n2;
    j += n2;
  }
  return wlen;
}

/* Handles the newline or blank at *i, updating the line state; returns 1
 * when the character was consumed, 0 when a word starts there instead. */
static int zwrap_consume_separator(emit_state *s, const char *in, size_t *i,
                                   uint32_t cp, size_t n, size_t *col,
                                   int *line_has_word, int *pending_blank) {
  if (cp == '\n') {
    emit(s, "\n", 1);
    *i += n;
    *col = 0;
    *line_has_word = 0;
    *pending_blank = 0;
    return 1;
  }
  if (is_blank(cp, in[*i])) {
    if (*line_has_word) *pending_blank = 1;
    *i += n;
    return 1;
  }
  return 0;
}

/* Emits the word starting at *i, adding a line break or pending blank first
 * when needed, and advances *i past the word. */
static void zwrap_place_word(emit_state *s, const char *in, size_t in_len,
                             size_t *i, size_t *col, int *line_has_word,
                             int *pending_blank, zwrap_opts o) {
  size_t wstart = *i;
  size_t wbytes = 0;
  size_t wlen = zwrap_measure_word(in, in_len, wstart, &wbytes);

  /* place the word */
  if (*line_has_word && *col + 1 + wlen > o.width) {
    emit(s, "\n", 1);
    *col = 0;
    *line_has_word = 0;
    *pending_blank = 0;
  } else if (*pending_blank) {
    emit(s, " ", 1);
    (*col)++;
  }
  if (wlen <= o.width - *col || !o.break_long) {
    emit(s, in + wstart, wbytes);
    *col += wlen;
    *i = wstart + wbytes;
  } else {
    /* hard-break at width boundary, codepoint granularity */
    size_t room = o.width - *col;
    size_t done = 0;
    while (done < wbytes) {
      uint32_t cp3;
      size_t n3 = next_char(in + wstart + done, wbytes - done, &cp3);
      if (room == 0) {
        emit(s, "\n", 1);
        *col = 0;
        room = o.width;
      }
      emit(s, in + wstart + done, n3);
      done += n3;
      (*col)++;
      room--;
    }
    *i = wstart + wbytes;
  }
  *line_has_word = 1;
  *pending_blank = 0;
}

size_t zwrap(const char *in, size_t in_len, char *out, size_t out_cap,
             const zwrap_opts *opts) {
  emit_state s;
  zwrap_opts o = opts ? *opts : zwrap_default_opts();
  size_t col = 0;
  size_t i = 0;
  int line_has_word = 0;
  int pending_blank = 0;

  if (out_cap > 0 && out) out[0] = '\0';
  if (o.width == 0) o.width = 72;
  if (!input_extent_valid(in, in_len)) return input_refusal(in);
  s.out = out;
  s.cap = out_cap;
  s.len = 0;
  s.stored = 0;
  s.clipped = 0;

  while (i < in_len) {
    uint32_t cp;
    size_t n = next_char(in + i, in_len - i, &cp);

    if (zwrap_consume_separator(&s, in, &i, cp, n, &col, &line_has_word,
                                &pending_blank))
      continue;

    /* a word starts here: measure it in codepoints */
    zwrap_place_word(&s, in, in_len, &i, &col, &line_has_word, &pending_blank,
                     o);
  }

  if (out && out_cap > 0) out[s.stored < out_cap ? s.stored : out_cap - 1] = '\0';
  return s.len;
}
