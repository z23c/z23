/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded XML writer for C23 (RSS/Atom/sitemap generation).
 *          Well-formedness is guaranteed by construction: the writer is a
 *          state machine over a bounded element stack, every call is
 *          checked against the current state, and misuse is a named error
 *          — never malformed output.
 *
 * Rules enforced:
 *  - exactly one root element; zxml_close() fails unless it is balanced
 *  - attributes only inside an open start tag (right after zxml_elem_open)
 *  - text and comments only inside the root element (comments are also
 *    allowed before it)
 *  - element/attribute names: [A-Za-z_][A-Za-z0-9._:-]*, at most
 *    ZXML_MAX_NAME bytes
 *  - text, attribute values, and comments must be well-formed UTF-8
 *    (checked with zutf8) and free of control bytes other than
 *    '\t' '\n' '\r'; "--" is rejected in comments
 *  - escaping by context: '&' '<' '>' in text, plus '"' and '\'' in
 *    attribute values
 *
 * Errors are sticky: after the first failure every later call returns the
 * stored status and nothing more is written. Bytes already emitted may be
 * truncated, but they are always a well-formed prefix.
 *
 * The writer never allocates; the caller owns the zxml struct and the
 * sink. The sink is byte-oriented (files, sockets, growing buffers all
 * work); a false return from it is ZXML_ERR_SINK.
 *
 * Pretty printing (ZXML_PRETTY at open): two-space indent, one element per
 * line, text-only elements stay on one line. Compact mode (ZXML_COMPACT)
 * emits no extra whitespace.
 */
#ifndef ZXML_H
#define ZXML_H

#include <stdbool.h>
#include <stddef.h>

#define ZXML_MAX_DEPTH 32u
#define ZXML_MAX_NAME 63u

typedef enum {
  ZXML_OK = 0,
  ZXML_ERR_SINK,  /* write callback reported failure */
  ZXML_ERR_STATE, /* call not valid here: unbalanced close, attribute
                     outside a start tag, text outside the root element,
                     a second root element, use after zxml_close() */
  ZXML_ERR_NAME,  /* invalid element/attribute name */
  ZXML_ERR_UTF8,  /* text/value/comment is not well-formed UTF-8 */
  ZXML_ERR_TEXT,  /* control byte in text/value, or "--" in a comment */
  ZXML_ERR_DEPTH  /* nesting over ZXML_MAX_DEPTH */
} zxml_status;

/* Return false to abort writing (becomes ZXML_ERR_SINK). */
typedef bool (*zxml_write_fn)(void *ctx, const char *data, size_t len);

enum { ZXML_COMPACT = 0, ZXML_PRETTY = 1u };

typedef struct {
  zxml_write_fn fn;
  void *ctx;
  zxml_status err;             /* sticky first error */
  unsigned flags;
  size_t depth;                /* open elements */
  bool in_tag;                 /* inside an open start tag ('>' pending) */
  bool wrote_any;              /* any bytes emitted (pretty layout) */
  bool wrote_root;             /* the one root element was opened */
  bool closed;                 /* zxml_close() succeeded */
  char names[ZXML_MAX_DEPTH][ZXML_MAX_NAME + 1];
  bool kids[ZXML_MAX_DEPTH];      /* element has element children */
  bool last_elem[ZXML_MAX_DEPTH]; /* last content was a closed element */
} zxml;

/* Initialize a writer over sink fn/ctx. flags: ZXML_COMPACT or
 * ZXML_PRETTY. Cannot fail; a NULL fn makes every call ZXML_ERR_SINK. */
void zxml_open(zxml *x, zxml_write_fn fn, void *ctx, unsigned flags);

/* `<?xml version="1.0" encoding="UTF-8"?>` — only as the very first call. */
zxml_status zxml_decl(zxml *x);

zxml_status zxml_elem_open(zxml *x, const char *name);
/* value may be NULL (empty). */
zxml_status zxml_attr(zxml *x, const char *name, const char *value);
zxml_status zxml_text(zxml *x, const char *text);
zxml_status zxml_text_n(zxml *x, const char *text, size_t len);
zxml_status zxml_comment(zxml *x, const char *text);
/* Close the current element; an element with no content becomes <n/>. */
zxml_status zxml_elem_close(zxml *x);
/* Convenience: <name>text</name> (or <name/> when text is NULL). */
zxml_status zxml_elem(zxml *x, const char *name, const char *text);
/* Verify the document is complete: exactly one balanced root. */
zxml_status zxml_close(zxml *x);

const char *zxml_strerror(zxml_status st);

#endif /* ZXML_H */
