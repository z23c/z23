/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded XML writer (see the header for the well-formedness
 *          contract). No allocation; the zxml struct is caller-owned. */
#include "zxml/zxml.h"

#include "zutf8/zutf8.h"

#include <string.h>

static zxml_status emit(zxml *x, const char *data, size_t len) {
  if (x->err != ZXML_OK)
    return x->err;
  if (len == 0)
    return ZXML_OK;
  if (!x->fn || !x->fn(x->ctx, data, len)) {
    x->err = ZXML_ERR_SINK;
    return x->err;
  }
  x->wrote_any = true;
  return ZXML_OK;
}

static const char k_spaces[2 * ZXML_MAX_DEPTH + 1] =
    "                                                                ";

/* Pretty layout: newline plus two spaces per level before an element (or
 * comment) at the given depth. */
static zxml_status newline_indent(zxml *x, size_t depth) {
  zxml_status st = emit(x, "\n", 1);
  if (st != ZXML_OK)
    return st;
  return emit(x, k_spaces, 2 * depth);
}

static bool name_valid(const char *name) {
  if (!name)
    return false;
  size_t len = strlen(name);
  if (len == 0 || len > ZXML_MAX_NAME)
    return false;
  unsigned char c = (unsigned char)name[0];
  if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_'))
    return false;
  for (size_t i = 1; i < len; i++) {
    c = (unsigned char)name[i];
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
          (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' ||
          c == ':'))
      return false;
  }
  return true;
}

/* Reject control bytes (other than tab/newline/return) and ill-formed
 * UTF-8 before anything is emitted. */
static zxml_status check_text(const char *s, size_t len) {
  for (size_t i = 0; i < len; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c < 0x20 && c != '\t' && c != '\n' && c != '\r')
      return ZXML_ERR_TEXT;
  }
  if (!zutf8_validate_n(s, len))
    return ZXML_ERR_UTF8;
  return ZXML_OK;
}

/* Emit s with the five predefined entities escaped: & < > always, " and '
 * only in attribute values. */
static zxml_status emit_escaped(zxml *x, const char *s, size_t len,
                                bool attr) {
  size_t run = 0;
  for (size_t i = 0; i < len; i++) {
    const char *ent = NULL;
    switch (s[i]) {
    case '&': ent = "&amp;"; break;
    case '<': ent = "&lt;"; break;
    case '>': ent = "&gt;"; break;
    case '"':
      if (attr)
        ent = "&quot;";
      break;
    case '\'':
      if (attr)
        ent = "&apos;";
      break;
    default: break;
    }
    if (ent) {
      zxml_status st = emit(x, s + run, i - run);
      if (st != ZXML_OK)
        return st;
      st = emit(x, ent, strlen(ent));
      if (st != ZXML_OK)
        return st;
      run = i + 1;
    }
  }
  return emit(x, s + run, len - run);
}

/* Flush the pending '>' of an open start tag. */
static zxml_status close_tag(zxml *x) {
  if (!x->in_tag)
    return ZXML_OK;
  zxml_status st = emit(x, ">", 1);
  if (st == ZXML_OK)
    x->in_tag = false;
  return st;
}

void zxml_open(zxml *x, zxml_write_fn fn, void *ctx, unsigned flags) {
  if (!x)
    return;
  memset(x, 0, sizeof(*x));
  x->fn = fn;
  x->ctx = ctx;
  x->flags = flags;
  if (!fn)
    x->err = ZXML_ERR_SINK;
}

zxml_status zxml_decl(zxml *x) {
  if (!x)
    return ZXML_ERR_STATE;
  if (x->err != ZXML_OK)
    return x->err;
  if (x->closed || x->wrote_any || x->depth > 0)
    return (x->err = ZXML_ERR_STATE);
  return emit(x, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>", 38);
}

zxml_status zxml_elem_open(zxml *x, const char *name) {
  if (!x)
    return ZXML_ERR_STATE;
  if (x->err != ZXML_OK)
    return x->err;
  if (x->closed)
    return (x->err = ZXML_ERR_STATE);
  if (!name_valid(name))
    return (x->err = ZXML_ERR_NAME);
  if (x->depth == 0 && x->wrote_root)
    return (x->err = ZXML_ERR_STATE); /* exactly one root */
  if (x->depth >= ZXML_MAX_DEPTH)
    return (x->err = ZXML_ERR_DEPTH);
  zxml_status st = close_tag(x);
  if (st != ZXML_OK)
    return st;
  if ((x->flags & ZXML_PRETTY) && x->wrote_any) {
    st = newline_indent(x, x->depth);
    if (st != ZXML_OK)
      return st;
  }
  st = emit(x, "<", 1);
  if (st == ZXML_OK)
    st = emit(x, name, strlen(name));
  if (st != ZXML_OK)
    return st;
  if (x->depth > 0)
    x->kids[x->depth - 1] = true;
  x->kids[x->depth] = false;
  x->last_elem[x->depth] = false;
  strcpy(x->names[x->depth], name); /* bounded by name_valid() */
  x->depth++;
  x->in_tag = true;
  if (x->depth == 1)
    x->wrote_root = true;
  return ZXML_OK;
}

zxml_status zxml_attr(zxml *x, const char *name, const char *value) {
  if (!x)
    return ZXML_ERR_STATE;
  if (x->err != ZXML_OK)
    return x->err;
  if (x->closed || !x->in_tag)
    return (x->err = ZXML_ERR_STATE); /* only inside a start tag */
  if (!name_valid(name))
    return (x->err = ZXML_ERR_NAME);
  if (!value)
    value = "";
  zxml_status st = check_text(value, strlen(value));
  if (st != ZXML_OK)
    return (x->err = st);
  st = emit(x, " ", 1);
  if (st == ZXML_OK)
    st = emit(x, name, strlen(name));
  if (st == ZXML_OK)
    st = emit(x, "=\"", 2);
  if (st == ZXML_OK)
    st = emit_escaped(x, value, strlen(value), true);
  if (st == ZXML_OK)
    st = emit(x, "\"", 1);
  return st;
}

zxml_status zxml_text_n(zxml *x, const char *text, size_t len) {
  if (!x)
    return ZXML_ERR_STATE;
  if (x->err != ZXML_OK)
    return x->err;
  if (x->closed || x->depth == 0)
    return (x->err = ZXML_ERR_STATE); /* text must be inside the root */
  if (!text && len > 0)
    return (x->err = ZXML_ERR_TEXT);
  if (!text)
    return ZXML_OK;
  zxml_status st = check_text(text, len);
  if (st != ZXML_OK)
    return (x->err = st);
  st = close_tag(x);
  if (st != ZXML_OK)
    return st;
  x->last_elem[x->depth - 1] = false;
  return emit_escaped(x, text, len, false);
}

zxml_status zxml_text(zxml *x, const char *text) {
  return zxml_text_n(x, text, text ? strlen(text) : 0);
}

zxml_status zxml_comment(zxml *x, const char *text) {
  if (!x)
    return ZXML_ERR_STATE;
  if (x->err != ZXML_OK)
    return x->err;
  if (x->closed || (x->depth == 0 && x->wrote_root))
    return (x->err = ZXML_ERR_STATE); /* no comments after the root */
  if (!text)
    return (x->err = ZXML_ERR_TEXT);
  zxml_status st = check_text(text, strlen(text));
  if (st != ZXML_OK)
    return (x->err = st);
  if (strstr(text, "--"))
    return (x->err = ZXML_ERR_TEXT); /* "--" is illegal in comments */
  st = close_tag(x);
  if (st != ZXML_OK)
    return st;
  if ((x->flags & ZXML_PRETTY) && x->wrote_any) {
    st = newline_indent(x, x->depth);
    if (st != ZXML_OK)
      return st;
  }
  st = emit(x, "<!--", 4);
  if (st == ZXML_OK)
    st = emit(x, text, strlen(text));
  if (st == ZXML_OK)
    st = emit(x, "-->", 3);
  if (st != ZXML_OK)
    return st;
  if (x->depth > 0)
    x->last_elem[x->depth - 1] = false;
  return ZXML_OK;
}

zxml_status zxml_elem_close(zxml *x) {
  if (!x)
    return ZXML_ERR_STATE;
  if (x->err != ZXML_OK)
    return x->err;
  if (x->closed || x->depth == 0)
    return (x->err = ZXML_ERR_STATE); /* nothing to close */
  size_t d = x->depth - 1;
  zxml_status st;
  if (x->in_tag) {
    st = emit(x, "/>", 2); /* no content: self-close */
    if (st != ZXML_OK)
      return st;
    x->in_tag = false;
  } else {
    if ((x->flags & ZXML_PRETTY) && x->kids[d] && x->last_elem[d]) {
      st = newline_indent(x, d);
      if (st != ZXML_OK)
        return st;
    }
    st = emit(x, "</", 2);
    if (st == ZXML_OK)
      st = emit(x, x->names[d], strlen(x->names[d]));
    if (st == ZXML_OK)
      st = emit(x, ">", 1);
    if (st != ZXML_OK)
      return st;
  }
  x->depth = d;
  if (d > 0)
    x->last_elem[d - 1] = true; /* parent's last content: this element */
  return ZXML_OK;
}

zxml_status zxml_elem(zxml *x, const char *name, const char *text) {
  zxml_status st = zxml_elem_open(x, name);
  if (st == ZXML_OK && text)
    st = zxml_text(x, text);
  if (st == ZXML_OK)
    st = zxml_elem_close(x);
  return st;
}

zxml_status zxml_close(zxml *x) {
  if (!x)
    return ZXML_ERR_STATE;
  if (x->err != ZXML_OK)
    return x->err;
  if (x->closed)
    return (x->err = ZXML_ERR_STATE);
  if (x->in_tag || x->depth != 0)
    return (x->err = ZXML_ERR_STATE); /* unclosed elements */
  if (!x->wrote_root)
    return (x->err = ZXML_ERR_STATE); /* no root element at all */
  x->closed = true;
  return ZXML_OK;
}

const char *zxml_strerror(zxml_status st) {
  switch (st) {
  case ZXML_OK: return "ok";
  case ZXML_ERR_SINK: return "sink write failed";
  case ZXML_ERR_STATE: return "call not valid in writer state";
  case ZXML_ERR_NAME: return "invalid element/attribute name";
  case ZXML_ERR_UTF8: return "text is not well-formed UTF-8";
  case ZXML_ERR_TEXT: return "illegal byte sequence in text";
  case ZXML_ERR_DEPTH: return "nesting too deep";
  }
  return "unknown error";
}
