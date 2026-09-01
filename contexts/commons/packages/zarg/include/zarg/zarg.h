/* zarg — bounded argv parser
 *
 * Apache-2.0 licensed. C23, freestanding-friendly, no allocation.
 *
 * Parses an argv vector against a caller-supplied option spec table.
 * Zero-copy: values point into the original argv strings.
 *
 * Grammar:
 *   -a            short boolean option
 *   -abc          bundled short booleans
 *   -o file       short option with value (next argv)
 *   -ofile        short option with value (rest of token; must end bundle)
 *   --alpha       long boolean option
 *   --out=file    long option with value
 *   --out file    long option with value (next argv)
 *   --            end of options; everything after is positional
 *   -             a lone dash is a positional (convention: stdin)
 *
 * Bounds:
 *   ZARG_MAX_ARGS   maximum argv entries scanned (default 4096)
 *   ZARG_MAX_SPEC   maximum spec entries (default 128)
 *   ZARG_MAX_NAME   maximum long-name length (default 64)
 *
 * Typed values: ZARG_BOOL (no value), ZARG_STR, ZARG_I64, ZARG_U64,
 * ZARG_F64. Typed conversion happens inline; failures report
 * ZARG_ERR_BADVALUE with the offending token offset.
 */
#ifndef ZARG_H
#define ZARG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ZARG_MAX_ARGS
#define ZARG_MAX_ARGS 4096u
#endif
#ifndef ZARG_MAX_SPEC
#define ZARG_MAX_SPEC 128u
#endif
#ifndef ZARG_MAX_NAME
#define ZARG_MAX_NAME 64u
#endif

typedef enum {
  ZARG_OK = 0,
  ZARG_ERR_ARG = 1,      /* NULL argument, or argc negative */
  ZARG_ERR_RANGE = 2,    /* a bound was exceeded */
  ZARG_ERR_UNKNOWN = 3,  /* option not in spec */
  ZARG_ERR_MISSING = 4,  /* value-taking option ran out of argv */
  ZARG_ERR_BADVALUE = 5, /* typed conversion failed */
  ZARG_ERR_USAGE = 6     /* duplicate long name / bad spec entry */
} zarg_err;

typedef enum {
  ZARG_BOOL = 0,
  ZARG_STR = 1,
  ZARG_I64 = 2,
  ZARG_U64 = 3,
  ZARG_F64 = 4
} zarg_type;

typedef struct {
  char short_name;       /* 0 if none; must be printable, not '-' */
  const char *long_name; /* NULL if none; [a-zA-Z0-9][a-zA-Z0-9_-]* */
  zarg_type type;
  const char *help;      /* may be NULL; shown by zarg_usage() */
} zarg_opt;

typedef struct {
  const zarg_opt *spec;
  size_t spec_count;
  int argc;
  char **argv;
  size_t next;         /* next argv index to examine */
  const char *tail;    /* pending bundle tail within current token */
  size_t pos_count;    /* positionals emitted so far */
  int opts_done;       /* seen "--" */
  zarg_err err;        /* sticky */
  size_t err_index;    /* argv index of the offending token */
} zarg_parser;

/* One parsed item. kind selects the union meaning. */
typedef enum {
  ZARG_ITEM_END = 0,       /* iteration finished */
  ZARG_ITEM_OPT = 1,       /* an option; spec_index valid */
  ZARG_ITEM_POS = 2        /* a positional; pos_index valid */
} zarg_item_kind;

typedef struct {
  zarg_item_kind kind;
  size_t spec_index;  /* ZARG_ITEM_OPT: index into spec table */
  const char *value;  /* raw string for STR/I64/U64/F64; NULL for BOOL */
  int64_t i64;        /* converted value for ZARG_I64 */
  uint64_t u64;       /* converted value for ZARG_U64 */
  double f64;         /* converted value for ZARG_F64 */
  size_t pos_index;   /* ZARG_ITEM_POS: 0-based positional ordinal */
  const char *text;   /* ZARG_ITEM_POS: the positional string */
} zarg_item;

/* Initialize. Validates the spec table (types, name syntax, duplicate
 * long names) and returns ZARG_ERR_USAGE on a bad table. */
zarg_err zarg_init(zarg_parser *p, const zarg_opt *spec, size_t spec_count,
                   int argc, char **argv);

/* Advance. Returns ZARG_OK and fills *it; it->kind == ZARG_ITEM_END at
 * the end of input. On error, returns the error (also sticky in p->err)
 * and p->err_index names the offending argv entry. */
zarg_err zarg_next(zarg_parser *p, zarg_item *it);

/* Convert a string with the same rules used for typed options.
 * Exposed so callers can re-convert or validate positionals.
 * Returns ZARG_OK or ZARG_ERR_BADVALUE. */
zarg_err zarg_conv_i64(const char *s, int64_t *out);
zarg_err zarg_conv_u64(const char *s, uint64_t *out);
zarg_err zarg_conv_f64(const char *s, double *out);

/* Render a usage block into buf: one line per spec entry plus the
 * program name if non-NULL. Returns bytes needed (excluding NUL);
 * if return >= cap the output was truncated but still NUL-terminated
 * when cap > 0. */
size_t zarg_usage(const zarg_opt *spec, size_t spec_count,
                  const char *prog, char *buf, size_t cap);

const char *zarg_err_str(zarg_err e);

#ifdef __cplusplus
}
#endif

#endif /* ZARG_H */
