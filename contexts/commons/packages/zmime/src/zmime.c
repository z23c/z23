/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: media type registry and Content-Type parsing. See zmime.h. */

#include "zmime/zmime.h"

#include <string.h>

/* ---------- registry ------------------------------------------------ */

typedef struct {
  const char *ext;  /* no dot, lowercase */
  const char *mime; /* lowercase */
} zmime_entry;

static const zmime_entry registry[] = {
    {"aac", "audio/aac"},
    {"avif", "image/avif"},
    {"bin", "application/octet-stream"},
    {"bmp", "image/bmp"},
    {"c", "text/x-c"},
    {"css", "text/css"},
    {"csv", "text/csv"},
    {"epub", "application/epub+zip"},
    {"gif", "image/gif"},
    {"gz", "application/gzip"},
    {"h", "text/x-c"},
    {"htm", "text/html"},
    {"html", "text/html"},
    {"ico", "image/vnd.microsoft.icon"},
    {"jpeg", "image/jpeg"},
    {"jpg", "image/jpeg"},
    {"js", "text/javascript"},
    {"json", "application/json"},
    {"mjs", "text/javascript"},
    {"mp3", "audio/mpeg"},
    {"mp4", "video/mp4"},
    {"ogg", "audio/ogg"},
    {"otf", "font/otf"},
    {"pdf", "application/pdf"},
    {"png", "image/png"},
    {"svg", "image/svg+xml"},
    {"tar", "application/x-tar"},
    {"tif", "image/tiff"},
    {"tiff", "image/tiff"},
    {"toml", "application/toml"},
    {"ttf", "font/ttf"},
    {"txt", "text/plain"},
    {"wasm", "application/wasm"},
    {"webp", "image/webp"},
    {"woff", "font/woff"},
    {"woff2", "font/woff2"},
    {"xml", "application/xml"},
    {"yaml", "application/yaml"},
    {"yml", "application/yaml"},
    {"zip", "application/zip"},
    {"zst", "application/zstd"},
};

static int ascii_lower(int c) {
  return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

static int eq_ci(const char *a, size_t alen, const char *b) {
  size_t i;
  for (i = 0; i < alen; i++) {
    if (b[i] == '\0') return 0;
    if (ascii_lower((unsigned char)a[i]) != ascii_lower((unsigned char)b[i]))
      return 0;
  }
  return b[alen] == '\0';
}

const char *zmime_from_extension(const char *ext, size_t len) {
  size_t i;
  if (ext && len > 0 && ext[0] == '.') {
    ext++;
    len--;
  }
  if (ext && len > 0 && len <= 8) {
    for (i = 0; i < sizeof registry / sizeof registry[0]; i++)
      if (eq_ci(ext, len, registry[i].ext)) return registry[i].mime;
  }
  return "application/octet-stream";
}

const char *zmime_to_extension(const char *mime, size_t len) {
  size_t i;
  if (!mime) return NULL;
  for (i = 0; i < sizeof registry / sizeof registry[0]; i++)
    if (eq_ci(mime, len, registry[i].mime)) return registry[i].ext;
  return NULL;
}

/* ---------- Content-Type parsing ------------------------------------ */

static int is_alnum_ascii(int c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
         (c >= '0' && c <= '9');
}

/* RFC 9110 tchar punctuation. The NUL guard matters: strchr() would
 * otherwise match the terminator for c == 0. */
static int is_tchar_punct(int c) {
  return c != 0 && strchr("!#$%&'*+-.^_`|~", c) != NULL;
}

static int is_token_char(int c) {
  return is_alnum_ascii(c) || is_tchar_punct(c);
}

typedef struct {
  const char *p;
  size_t n;
} cur;

static void skip_ows(cur *c) {
  while (c->n > 0 && (*c->p == ' ' || *c->p == '\t')) {
    c->p++;
    c->n--;
  }
}

/* Parse a token, lowercased, into buf (cap includes NUL). */
static int take_token(cur *c, char *buf, size_t cap) {
  size_t n = 0;
  while (c->n > 0 && is_token_char((unsigned char)*c->p)) {
    if (n + 1 >= cap) return 0; /* oversized component */
    buf[n++] = (char)ascii_lower((unsigned char)*c->p);
    c->p++;
    c->n--;
  }
  if (n == 0) return 0;
  buf[n] = '\0';
  return 1;
}

/* Visible ASCII and obs-text are legal quoted bytes; HTAB is handled
 * by the caller. DEL and all other controls are forbidden. */
static int quoted_byte_valid(char ch) {
  unsigned char c = (unsigned char)ch;
  return c >= 0x20 && c != 0x7F;
}

/* HTAB is allowed inside quoted-string as well. */
static int quoted_char_ok(char ch) {
  return quoted_byte_valid(ch) || ch == '\t';
}

/* Parse a quoted-string; c->p points at the opening quote. */
static int take_quoted(cur *c, char *buf, size_t cap) {
  size_t n = 0;
  c->p++;
  c->n--;
  for (;;) {
    char ch;
    if (c->n == 0) return 0; /* unterminated */
    ch = *c->p;
    if (ch == '"') {
      c->p++;
      c->n--;
      break;
    }
    if (ch == '\\') {
      c->p++;
      c->n--;
      if (c->n == 0) return 0;
      ch = *c->p;
    }
    if (!quoted_char_ok(ch)) return 0;
    if (n + 1 >= cap) return 0;
    buf[n++] = ch;
    c->p++;
    c->n--;
  }
  buf[n] = '\0';
  return 1;
}

/* Parse a bare token parameter value. */
static int take_bare_value(cur *c, char *buf, size_t cap) {
  size_t n = 0;
  while (c->n > 0 && is_token_char((unsigned char)*c->p)) {
    if (n + 1 >= cap) return 0;
    buf[n++] = *c->p;
    c->p++;
    c->n--;
  }
  if (n == 0) return 0;
  buf[n] = '\0';
  return 1;
}

/* Parse a parameter value: token or quoted-string. */
static int take_value(cur *c, char *buf, size_t cap) {
  if (c->n > 0 && *c->p == '"') return take_quoted(c, buf, cap);
  return take_bare_value(c, buf, cap);
}

/* type "/" subtype, with optional leading whitespace. */
static int take_type_subtype(cur *c, zmime_content_type *r) {
  skip_ows(c);
  if (!take_token(c, r->type, sizeof r->type)) return 0;
  if (c->n == 0 || *c->p != '/') return 0;
  c->p++;
  c->n--;
  return take_token(c, r->subtype, sizeof r->subtype);
}

/* One ";" name "=" value parameter, c->p at the ';'. */
static int take_param(cur *c, char *name, size_t name_cap, char *value,
                      size_t value_cap) {
  if (c->n == 0 || *c->p != ';') return 0;
  c->p++;
  c->n--;
  skip_ows(c);
  if (!take_token(c, name, name_cap)) return 0;
  skip_ows(c);
  if (c->n == 0 || *c->p != '=') return 0;
  c->p++;
  c->n--;
  skip_ows(c);
  return take_value(c, value, value_cap);
}

static void store_charset(zmime_content_type *r, const char *value) {
  size_t i;
  for (i = 0; value[i] && i + 1 < sizeof r->charset; i++)
    r->charset[i] = (char)ascii_lower((unsigned char)value[i]);
  r->charset[i] = '\0';
}

int zmime_parse_content_type(const char *s, size_t len,
                             zmime_content_type *out) {
  cur c;
  zmime_content_type r;
  size_t total_params = 0;
  if (!s || !out) return 0;
  memset(&r, 0, sizeof r);
  c.p = s;
  c.n = len;
  if (!take_type_subtype(&c, &r)) return 0;
  for (;;) {
    char name[32];
    char value[64];
    skip_ows(&c);
    if (c.n == 0) break;
    if (!take_param(&c, name, sizeof name, value, sizeof value)) return 0;
    if (total_params < sizeof r.params / sizeof r.params[0]) {
      memcpy(r.params[total_params].name, name, strlen(name) + 1);
      memcpy(r.params[total_params].value, value, strlen(value) + 1);
    }
    if (strcmp(name, "charset") == 0) store_charset(&r, value);
    total_params++;
  }
  r.nparams = total_params;
  *out = r;
  return 1;
}

/* ---------- format --------------------------------------------------- */

typedef struct {
  char *out;
  size_t cap;
  size_t len;
} fmtr;

static void emit(fmtr *f, const char *s) {
  while (*s) {
    if (f->out && f->len + 1 < f->cap) f->out[f->len] = *s;
    f->len++;
    s++;
  }
}

static int needs_quote(const char *v) {
  size_t i;
  if (!v[0]) return 1;
  for (i = 0; v[i]; i++)
    if (!is_token_char((unsigned char)v[i])) return 1;
  return 0;
}

size_t zmime_format_content_type(const zmime_content_type *ct, char *out,
                                 size_t cap) {
  fmtr f;
  size_t i;
  if (!ct) {
    if (out && cap) out[0] = '\0';
    return 0;
  }
  f.out = out;
  f.cap = cap;
  f.len = 0;
  emit(&f, ct->type);
  emit(&f, "/");
  emit(&f, ct->subtype);
  for (i = 0; i < ct->nparams && i < 8; i++) {
    emit(&f, "; ");
    emit(&f, ct->params[i].name);
    emit(&f, "=");
    if (needs_quote(ct->params[i].value)) {
      const char *v = ct->params[i].value;
      emit(&f, "\"");
      for (; *v; v++) {
        if (*v == '"' || *v == '\\') emit(&f, "\\");
        {
          char ch[2] = {*v, 0};
          emit(&f, ch);
        }
      }
      emit(&f, "\"");
    } else {
      emit(&f, ct->params[i].value);
    }
  }
  if (f.out && f.cap) f.out[f.len < f.cap ? f.len : f.cap - 1] = '\0';
  return f.len;
}
