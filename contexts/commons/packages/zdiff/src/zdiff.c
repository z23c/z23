/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded line diff (see the header for algorithm and
 *          bounds). */
#include "zdiff/zdiff.h"

#include <string.h>

size_t zdiff_split(const char *text, size_t len, zdiff_line *lines,
                   size_t cap) {
  if (!text || len == 0)
    return 0;
  size_t count = 0;
  size_t off = 0;
  for (size_t i = 0; i < len; i++) {
    if (text[i] != '\n')
      continue;
    if (count < cap && lines) {
      lines[count].off = off;
      lines[count].len = i - off;
    }
    count++;
    off = i + 1;
  }
  if (off < len) { /* trailing partial line */
    if (count < cap && lines) {
      lines[count].off = off;
      lines[count].len = len - off;
    }
    count++;
  }
  return count;
}

size_t zdiff_cells(size_t old_lines, size_t new_lines) {
  if (old_lines > ZDIFF_MAX_LINES || new_lines > ZDIFF_MAX_LINES)
    return 0;
  size_t cells = (old_lines + 1) * (new_lines + 1);
  if (cells > ZDIFF_MAX_CELLS)
    return 0;
  return cells;
}

static bool line_eq(const char *a_text, const zdiff_line *a,
                    const char *b_text, const zdiff_line *b) {
  return a->len == b->len && memcmp(a_text + a->off, b_text + b->off,
                                    a->len) == 0;
}

zdiff_status zdiff_run(const char *old_text, const zdiff_line *old_lines,
                       size_t old_count, const char *new_text,
                       const zdiff_line *new_lines, size_t new_count,
                       uint32_t *dp, size_t dp_cells, zdiff_op *ops,
                       size_t ops_cap, size_t *ops_out) {
  if (ops_out)
    *ops_out = 0;
  if ((old_count && (!old_text || !old_lines)) ||
      (new_count && (!new_text || !new_lines)))
    return ZDIFF_ARG;
  size_t need = zdiff_cells(old_count, new_count);
  if (need == 0)
    return ZDIFF_BOUND;
  if (!dp && dp_cells)
    return ZDIFF_ARG;
  if (dp_cells < need)
    return ZDIFF_SPACE;
  if (old_count + 1 > SIZE_MAX / (new_count + 1))
    return ZDIFF_BOUND; /* unreachable given zdiff_cells, but total */
  const size_t stride = new_count + 1;

  /* dp[i * stride + j] = LCS length of old[i..] and new[j..]. */
  for (size_t i = old_count + 1; i-- > 0;) {
    for (size_t j = new_count + 1; j-- > 0;) {
      uint32_t best = 0;
      if (i < old_count && j < new_count &&
          line_eq(old_text, &old_lines[i], new_text, &new_lines[j]))
        best = dp[(i + 1) * stride + (j + 1)] + 1;
      else if (i < old_count && j < new_count) {
        uint32_t del = dp[(i + 1) * stride + j];
        uint32_t ins = dp[i * stride + (j + 1)];
        best = del > ins ? del : ins;
      }
      dp[i * stride + j] = best;
    }
  }

  size_t script_len = old_count + new_count - (size_t)dp[0];
  if (ops_out)
    *ops_out = script_len;
  if (!ops && ops_cap)
    return ZDIFF_ARG;
  if (ops_cap < script_len)
    return ZDIFF_SPACE;

  size_t i = 0, j = 0, k = 0;
  while (i < old_count || j < new_count) {
    if (i < old_count && j < new_count &&
        line_eq(old_text, &old_lines[i], new_text, &new_lines[j])) {
      ops[k++] = (zdiff_op){ZDIFF_KEEP, (uint32_t)i, (uint32_t)j};
      i++;
      j++;
    } else if (j == new_count ||
               (i < old_count &&
                dp[(i + 1) * stride + j] >= dp[i * stride + (j + 1)])) {
      ops[k++] = (zdiff_op){ZDIFF_DEL, (uint32_t)i, (uint32_t)j};
      i++;
    } else {
      ops[k++] = (zdiff_op){ZDIFF_INS, (uint32_t)i, (uint32_t)j};
      j++;
    }
  }
  return ZDIFF_OK;
}

zdiff_status zdiff_texts(const char *old_text, size_t old_len,
                         zdiff_line *old_lines, size_t old_cap,
                         const char *new_text, size_t new_len,
                         zdiff_line *new_lines, size_t new_cap,
                         uint32_t *dp, size_t dp_cells, zdiff_op *ops,
                         size_t ops_cap, size_t *ops_out) {
  if ((old_len && !old_text) || (new_len && !new_text))
    return ZDIFF_ARG;
  size_t old_count = zdiff_split(old_text, old_len, old_lines, old_cap);
  size_t new_count = zdiff_split(new_text, new_len, new_lines, new_cap);
  if (old_count > old_cap || new_count > new_cap)
    return ZDIFF_SPACE;
  return zdiff_run(old_text, old_lines, old_count, new_text, new_lines,
                   new_count, dp, dp_cells, ops, ops_cap, ops_out);
}

const char *zdiff_status_name(zdiff_status st) {
  switch (st) {
  case ZDIFF_OK: return "ok";
  case ZDIFF_ARG: return "arg";
  case ZDIFF_BOUND: return "bound";
  case ZDIFF_SPACE: return "space";
  }
  return "unknown";
}
