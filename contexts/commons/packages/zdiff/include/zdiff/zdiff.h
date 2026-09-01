/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded line-oriented diff for C23. Computes an exact
 *          longest-common-subsequence edit script between two texts
 *          and renders it as an op dump (' ', '-', '+' prefixed
 *          lines). Allocation-free and total: all working memory is
 *          caller-supplied, and oversized inputs fail with a status
 *          instead of exhausting memory.
 *
 * Algorithm: full O((n+1)*(m+1)) LCS dynamic program with backtrack.
 * Exact, deterministic (ties break toward deletion first), and simple
 * to audit; the price is quadratic working memory, so inputs are
 * fail-closed bounded: at most ZDIFF_MAX_LINES lines per side and
 * ZDIFF_MAX_CELLS DP cells per comparison. That comfortably covers
 * source files, manifests, and configuration; it is not a
 * multi-gigabyte log differ.
 *
 * Lines are byte slices between '\n' separators; a trailing partial
 * line (no final newline) is a line. Comparison is bytewise exact.
 */
#ifndef ZDIFF_H
#define ZDIFF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZDIFF_MAX_LINES 65535u
/* (old_lines + 1) * (new_lines + 1) must not exceed this. */
#define ZDIFF_MAX_CELLS (1u << 22)

typedef enum {
  ZDIFF_OK = 0, /* script computed */
  ZDIFF_ARG,    /* NULL pointer paired with a nonzero count */
  ZDIFF_BOUND,  /* input over the line/cell bound */
  ZDIFF_SPACE   /* dp cells or ops array too small; need reported */
} zdiff_status;

typedef enum {
  ZDIFF_KEEP = 0, /* line present in both, in order */
  ZDIFF_DEL,      /* line only in old */
  ZDIFF_INS       /* line only in new */
} zdiff_kind;

typedef struct {
  zdiff_kind kind;
  uint32_t old_line; /* old line index for KEEP/DEL */
  uint32_t new_line; /* new line index for KEEP/INS */
} zdiff_op;

/* A line as a byte slice of the original text. */
typedef struct {
  size_t off;
  size_t len; /* excludes the '\n' terminator */
} zdiff_line;

/* Split text[0..len) into lines. Returns the number of lines (even
 * when it exceeds cap); fills at most cap entries. */
size_t zdiff_split(const char *text, size_t len, zdiff_line *lines,
                   size_t cap);

/* DP cells zdiff_run needs for the given line counts, or 0 when the
 * counts exceed the bounds. */
size_t zdiff_cells(size_t old_lines, size_t new_lines);

/* Compute the edit script between two pre-split line arrays.
 * dp must hold at least zdiff_cells(old_count, new_count) cells.
 * On ZDIFF_OK, *ops_out receives the script length (<= old+new lines).
 * On ZDIFF_SPACE with sufficient dp, *ops_out receives the script
 * length that would have been produced. */
zdiff_status zdiff_run(const char *old_text, const zdiff_line *old_lines,
                       size_t old_count, const char *new_text,
                       const zdiff_line *new_lines, size_t new_count,
                       uint32_t *dp, size_t dp_cells, zdiff_op *ops,
                       size_t ops_cap, size_t *ops_out);

/* One-call convenience: split both texts into caller arrays, then
 * diff. A line-count cap below the actual count yields ZDIFF_SPACE. */
zdiff_status zdiff_texts(const char *old_text, size_t old_len,
                         zdiff_line *old_lines, size_t old_cap,
                         const char *new_text, size_t new_len,
                         zdiff_line *new_lines, size_t new_cap,
                         uint32_t *dp, size_t dp_cells, zdiff_op *ops,
                         size_t ops_cap, size_t *ops_out);

/* Static name for a status ("ok", "arg", "bound", "space"). */
const char *zdiff_status_name(zdiff_status st);

#endif /* ZDIFF_H */
