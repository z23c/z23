/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: KAT, bounds, NULL-safety, and property tests for zdiff. */
#include "zdiff/zdiff.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond)                                                          \
  do {                                                                       \
    if (!(cond)) {                                                           \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
      return 1;                                                              \
    }                                                                        \
  } while (0)

static int test_split(void) {
  zdiff_line lines[8];
  CHECK(zdiff_split("", 0, lines, 8) == 0);
  CHECK(zdiff_split(NULL, 0, lines, 8) == 0);
  CHECK(zdiff_split("a", 1, lines, 8) == 1);
  CHECK(lines[0].off == 0 && lines[0].len == 1);
  CHECK(zdiff_split("a\n", 2, lines, 8) == 1);
  CHECK(zdiff_split("a\nb", 3, lines, 8) == 2);
  CHECK(lines[1].off == 2 && lines[1].len == 1);
  CHECK(zdiff_split("\n", 1, lines, 8) == 1);
  CHECK(lines[0].len == 0);
  CHECK(zdiff_split("a\n\n", 3, lines, 8) == 2);
  CHECK(lines[1].off == 2 && lines[1].len == 0);
  /* cap smaller than the count: full count still returned */
  CHECK(zdiff_split("a\nb\nc\n", 6, lines, 2) == 3);
  CHECK(lines[1].off == 2); /* filled up to cap */
  CHECK(zdiff_split("a\nb\nc\n", 6, NULL, 0) == 3); /* measure only */
  return 0;
}

/* Diff two NUL-terminated texts with generous static storage and
 * require ZDIFF_OK; returns the script length. */
static size_t diff_ok(const char *old_t, const char *new_t, zdiff_op *ops,
                      size_t ops_cap) {
  static zdiff_line ol[256], nl[256];
  static uint32_t dp[256 * 256];
  size_t out = 0;
  zdiff_status st =
      zdiff_texts(old_t, strlen(old_t), ol, 256, new_t, strlen(new_t), nl,
                  256, dp, 256 * 256, ops, ops_cap, &out);
  CHECK(st == ZDIFF_OK);
  return out;
}

static int kat_identical(zdiff_op *ops) {
  {
    size_t n = diff_ok("", "", ops, 16);
    CHECK(n == 0);
  }
  {
    size_t n = diff_ok("a\nb\nc\n", "a\nb\nc\n", ops, 16);
    CHECK(n == 3);
    for (size_t i = 0; i < n; i++)
      CHECK(ops[i].kind == ZDIFF_KEEP && ops[i].old_line == i &&
            ops[i].new_line == i);
  }
  return 0;
}

static int kat_substitution(zdiff_op *ops) {
  size_t n = diff_ok("a\nb\nc\n", "a\nd\nc\n", ops, 16);
  CHECK(n == 4);
  CHECK(ops[0].kind == ZDIFF_KEEP && ops[0].old_line == 0);
  CHECK(ops[1].kind == ZDIFF_DEL && ops[1].old_line == 1);
  CHECK(ops[2].kind == ZDIFF_INS && ops[2].new_line == 1);
  CHECK(ops[3].kind == ZDIFF_KEEP && ops[3].old_line == 2 &&
        ops[3].new_line == 2);
  return 0;
}

static int kat_insertion(zdiff_op *ops) {
  size_t n = diff_ok("a\nc\n", "a\nb\nc\n", ops, 16);
  CHECK(n == 3);
  CHECK(ops[0].kind == ZDIFF_KEEP);
  CHECK(ops[1].kind == ZDIFF_INS && ops[1].new_line == 1);
  CHECK(ops[2].kind == ZDIFF_KEEP && ops[2].new_line == 2);
  return 0;
}

static int kat_replacement(zdiff_op *ops) {
  size_t n = diff_ok("a\n", "b\n", ops, 16);
  CHECK(n == 2);
  CHECK(ops[0].kind == ZDIFF_DEL);
  CHECK(ops[1].kind == ZDIFF_INS);
  return 0;
}

static int kat_all_deleted_inserted(zdiff_op *ops) {
  size_t n = diff_ok("a\nb\n", "", ops, 16);
  CHECK(n == 2 && ops[0].kind == ZDIFF_DEL && ops[1].kind == ZDIFF_DEL);
  n = diff_ok("", "x\ny\n", ops, 16);
  CHECK(n == 2 && ops[0].kind == ZDIFF_INS && ops[1].kind == ZDIFF_INS);
  return 0;
}

static int kat_partial_line_twin(zdiff_op *ops) {
  size_t n = diff_ok("a\nb", "a\nb\n", ops, 16);
  CHECK(n == 2 && ops[0].kind == ZDIFF_KEEP && ops[1].kind == ZDIFF_KEEP);
  return 0;
}

static int kat_partial_line_diff(zdiff_op *ops) {
  size_t n = diff_ok("a\nb", "a\nc\n", ops, 16);
  CHECK(n == 3);
  CHECK(ops[0].kind == ZDIFF_KEEP);
  CHECK(ops[1].kind == ZDIFF_DEL && ops[1].old_line == 1);
  CHECK(ops[2].kind == ZDIFF_INS && ops[2].new_line == 1);
  return 0;
}

static int kat_repeated_lines(zdiff_op *ops) {
  size_t n = diff_ok("a\na\nb\n", "a\nb\na\n", ops, 16);
  CHECK(n == 4);
  CHECK(ops[0].kind == ZDIFF_KEEP);
  CHECK(ops[1].kind == ZDIFF_DEL);
  CHECK(ops[2].kind == ZDIFF_KEEP && ops[2].old_line == 2 &&
        ops[2].new_line == 1);
  CHECK(ops[3].kind == ZDIFF_INS && ops[3].new_line == 2);
  return 0;
}

static int test_kat(void) {
  zdiff_op ops[16];
  if (kat_identical(ops))
    return 1;
  /* classic substitution: b -> d between kept a and c */
  if (kat_substitution(ops))
    return 1;
  /* insertion into the middle */
  if (kat_insertion(ops))
    return 1;
  /* total replacement: deletions first, deterministic tie-break */
  if (kat_replacement(ops))
    return 1;
  /* everything deleted / everything inserted */
  if (kat_all_deleted_inserted(ops))
    return 1;
  /* line comparison is content-only: a trailing partial line equals
   * its newline-terminated twin */
  if (kat_partial_line_twin(ops))
    return 1;
  /* but different partial content diffs normally */
  if (kat_partial_line_diff(ops))
    return 1;
  /* repeated lines: LCS keeps the longest run */
  /* KEEP a, DEL a, KEEP b, INS a */
  if (kat_repeated_lines(ops))
    return 1;
  return 0;
}

static int test_bounds(void) {
  char t[] = "a\nb\nc\n";
  zdiff_line lines[3];
  CHECK(zdiff_split(t, sizeof t - 1, lines, 3) == 3);
  uint32_t dp[16];
  zdiff_op ops[8];
  size_t out = 0;

  CHECK(zdiff_cells(ZDIFF_MAX_LINES + 1, 0) == 0);
  CHECK(zdiff_cells(0, ZDIFF_MAX_LINES + 1) == 0);
  CHECK(zdiff_cells(2049, 2049) == 0); /* 2050^2 > ZDIFF_MAX_CELLS */
  CHECK(zdiff_cells(2047, 2047) == (size_t)2048 * 2048);

  /* line count over the bound (rejected before any line is read) */
  CHECK(zdiff_run(t, lines, ZDIFF_MAX_LINES + 1, t, lines, 0, dp, 16,
                  ops, 8, &out) == ZDIFF_BOUND);
  /* cell product over the bound */
  CHECK(zdiff_run(t, lines, 2049, t, lines, 2049, dp, 16, ops, 8,
                  &out) == ZDIFF_BOUND);
  /* dp too small */
  CHECK(zdiff_run(t, lines, 3, t, lines, 3, dp, 15, ops, 8, &out) ==
        ZDIFF_SPACE);
  /* ops too small: exact need reported */
  CHECK(zdiff_run(t, lines, 3, t, lines, 2, dp, 16, ops, 1, &out) ==
        ZDIFF_SPACE);
  CHECK(out == 3 + 2 - 2); /* identical prefixes: lcs == 2 */
  return 0;
}

static int test_null_safety(void) {
  zdiff_line one[1] = {{0, 0}};
  uint32_t dp[4];
  zdiff_op ops[4];
  size_t out = 0;
  char t[] = "x";

  CHECK(zdiff_run(NULL, one, 1, t, one, 1, dp, 4, ops, 4, &out) ==
        ZDIFF_ARG);
  CHECK(zdiff_run(t, NULL, 1, t, one, 1, dp, 4, ops, 4, &out) ==
        ZDIFF_ARG);
  CHECK(zdiff_run(t, one, 1, NULL, one, 1, dp, 4, ops, 4, &out) ==
        ZDIFF_ARG);
  CHECK(zdiff_run(t, one, 1, t, NULL, 1, dp, 4, ops, 4, &out) ==
        ZDIFF_ARG);
  CHECK(zdiff_run(t, one, 0, t, one, 0, NULL, 1, ops, 4, &out) ==
        ZDIFF_ARG); /* NULL dp with nonzero cell count */
  CHECK(zdiff_run(t, one, 0, t, one, 0, dp, 4, NULL, 1, &out) ==
        ZDIFF_ARG); /* NULL ops with nonzero cap */
  CHECK(zdiff_texts(NULL, 1, one, 1, t, 1, one, 1, dp, 4, ops, 4,
                    &out) == ZDIFF_ARG);
  CHECK(zdiff_run(t, one, 0, t, one, 0, dp, 4, ops, 4, NULL) ==
        ZDIFF_OK); /* ops_out may be NULL */
  CHECK(strcmp(zdiff_status_name(ZDIFF_BOUND), "bound") == 0);
  CHECK(zdiff_status_name(ZDIFF_OK) != NULL);
  return 0;
}

static uint64_t rng_state = 0x243f6a8885a308d3ull;
static uint64_t rnd(void) {
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 7;
  rng_state ^= rng_state << 17;
  return rng_state;
}

/* Build a random text of up to max_lines lines drawn from a tiny
 * alphabet, forcing frequent common subsequences. */
static size_t gen_text(char *buf, size_t cap, size_t max_lines) {
  static const char *pool[] = {"alpha", "beta", "gamma", "delta", ""};
  size_t n = 0;
  size_t lines = rnd() % (max_lines + 1);
  for (size_t i = 0; i < lines; i++) {
    const char *s = pool[rnd() % 5];
    size_t sl = strlen(s);
    if (n + sl + 1 >= cap)
      break;
    memcpy(buf + n, s, sl);
    n += sl;
    buf[n++] = '\n';
  }
  if (lines && (rnd() & 1) && n) /* sometimes drop the final newline */
    n--;
  return n;
}

static int script_append_line(const char *t, size_t len, uint32_t line,
                              char *re, size_t cap, size_t *used) {
  size_t idx = 0, off = 0;
  for (size_t i = 0; i < len && idx < line; i++)
    if (t[i] == '\n')
      idx++, off = i + 1;
  size_t eol = off;
  while (eol < len && t[eol] != '\n')
    eol++;
  size_t l = eol - off;
  if (*used + l + 1 >= cap)
    return 1;
  memcpy(re + *used, t + off, l);
  *used += l;
  re[(*used)++] = '\n';
  return 0;
}

static int verify_reconstruction(const char *old_t, size_t old_len,
                                 const char *re_old, size_t ro,
                                 const char *new_t, size_t new_len,
                                 const char *re_new, size_t rn) {
  static zdiff_line a[512], b[512];
  size_t ca = zdiff_split(old_t, old_len, a, 512);
  size_t cb = zdiff_split(new_t, new_len, b, 512);
  static zdiff_line ra[512], rb[512];
  size_t cra = zdiff_split(re_old, ro, ra, 512);
  size_t crb = zdiff_split(re_new, rn, rb, 512);
  CHECK(cra == ca && crb == cb);
  for (size_t i = 0; i < ca; i++)
    CHECK(a[i].len == ra[i].len &&
          memcmp(old_t + a[i].off, re_old + ra[i].off, a[i].len) == 0);
  for (size_t i = 0; i < cb; i++)
    CHECK(b[i].len == rb[i].len &&
          memcmp(new_t + b[i].off, re_new + rb[i].off, b[i].len) == 0);
  return 0;
}

/* Apply a script: reconstruct old from KEEP/DEL, new from KEEP/INS,
 * and require both to match the inputs exactly. */
static int verify_script(const char *old_t, size_t old_len,
                         const char *new_t, size_t new_len,
                         const zdiff_op *ops, size_t n) {
  static char re_old[8192], re_new[8192];
  size_t ro = 0, rn = 0;
  uint32_t prev_keep_old = 0, prev_keep_new = 0;
  bool first_keep = true;
  for (size_t k = 0; k < n; k++) {
    const zdiff_op *op = &ops[k];
    if (op->kind == ZDIFF_KEEP || op->kind == ZDIFF_DEL) {
      /* locate old line op->old_line */
      if (script_append_line(old_t, old_len, op->old_line, re_old,
                             sizeof re_old, &ro) != 0)
        return 1;
    }
    if (op->kind == ZDIFF_KEEP || op->kind == ZDIFF_INS) {
      if (script_append_line(new_t, new_len, op->new_line, re_new,
                             sizeof re_new, &rn) != 0)
        return 1;
    }
    if (op->kind == ZDIFF_KEEP) {
      if (!first_keep) {
        CHECK(op->old_line > prev_keep_old);
        CHECK(op->new_line > prev_keep_new);
      }
      first_keep = false;
      prev_keep_old = op->old_line;
      prev_keep_new = op->new_line;
    }
  }
  /* reconstruction adds a newline per line; compare line-by-line
   * against the inputs instead of byte equality. */
  return verify_reconstruction(old_t, old_len, re_old, ro, new_t, new_len,
                               re_new, rn);
}

static int test_property(void) {
  static char old_t[8192], new_t[8192];
  static zdiff_line ol[512], nl[512];
  static uint32_t dp[513 * 513];
  static zdiff_op ops[1025];

  for (unsigned trial = 0; trial < 4000; trial++) {
    size_t old_len = gen_text(old_t, sizeof old_t, 24);
    size_t new_len = gen_text(new_t, sizeof new_t, 24);
    size_t oc = zdiff_split(old_t, old_len, ol, 512);
    size_t nc = zdiff_split(new_t, new_len, nl, 512);
    CHECK(oc <= 24 && nc <= 24);
    size_t n = 0;
    zdiff_status st =
        zdiff_run(old_t, ol, oc, new_t, nl, nc, dp, 513 * 513, ops,
                  1025, &n);
    CHECK(st == ZDIFF_OK);
    CHECK(n <= oc + nc);
    CHECK(n >= (oc > nc ? oc : nc)); /* every line is covered once */
    if (verify_script(old_t, old_len, new_t, new_len, ops, n) != 0)
      return 1;
  }
  return 0;
}

/* Supply read_file a real bounded temporary file, without public paths. */
static size_t audit_file_len;
static FILE *audit_diff_fopen(const char *path, const char *mode) {
  (void)path; (void)mode;
  FILE *f = tmpfile();
  if (!f) return NULL;
  char block[1024]; memset(block, 'x', sizeof block);
  for (size_t done = 0; done < audit_file_len;) {
    size_t n = audit_file_len - done; if (n > sizeof block) n = sizeof block;
    if (fwrite(block, 1, n, f) != n) { fclose(f); return NULL; }
    done += n;
  }
  rewind(f); return f;
}
#define fopen audit_diff_fopen
#define main audit_diff_main
#include "../app/main.c"
#undef main
#undef fopen

static int test_cli_inclusive_read_bound(void) {
  static const size_t caps[] = { 1, 17, MAX_FILE };
  const char *selected = getenv("AUDIT_ROW");
  for (size_t row = 0; row < sizeof caps / sizeof caps[0]; row++) {
    if (selected && strtoul(selected, NULL, 10) != row + 1) continue;
    audit_file_len = caps[row]; size_t len = 0;
    bool ok = read_file("private-fixture", old_text, caps[row], &len);
    printf("diff inclusive read row %zu cap=%zu ok=%d length=%zu\n", row + 1, caps[row], ok, len);
    CHECK(ok && len == caps[row] && old_text[0] == 'x' && old_text[len - 1] == 'x');
  }
  return 0;
}

static int test_script_capacity_boundary(void) {
  const char old[] = "a\nb\n", next[] = "b\na\n";
  zdiff_line ol[2], nl[2];
  uint32_t dp[9];
  zdiff_op ops[3], saved[3];
  size_t out = 99;
  CHECK(zdiff_split(old, sizeof old - 1, ol, 2) == 2);
  CHECK(zdiff_split(next, sizeof next - 1, nl, 2) == 2);
  memset(ops, 0xa5, sizeof ops);
  memcpy(saved, ops, sizeof ops);
  CHECK(zdiff_run(old, ol, 2, next, nl, 2, dp, 9, ops, 2, &out) == ZDIFF_SPACE);
  CHECK(out == 3 && memcmp(ops, saved, sizeof ops) == 0 && dp[0] == 1);
  out = 99;
  CHECK(zdiff_run(old, ol, 2, next, nl, 2, dp, 9, NULL, 1, &out) == ZDIFF_ARG);
  CHECK(out == 3 && dp[0] == 1);
  CHECK(zdiff_run(old, ol, 2, next, nl, 2, dp, 9, NULL, 0, &out) == ZDIFF_SPACE);
  CHECK(out == 3);
  CHECK(zdiff_run(old, ol, 2, next, nl, 2, dp, 9, ops, 3, &out) == ZDIFF_OK);
  CHECK(out == 3 && ops[0].kind == ZDIFF_DEL && ops[0].old_line == 0 &&
        ops[0].new_line == 0 && ops[1].kind == ZDIFF_KEEP &&
        ops[1].old_line == 1 && ops[1].new_line == 0 &&
        ops[2].kind == ZDIFF_INS && ops[2].old_line == 2 && ops[2].new_line == 1);
  return 0;
}

int main(void) {
  if (test_script_capacity_boundary() != 0) return 1;
  if (test_cli_inclusive_read_bound() != 0) return 1;
  struct {
    const char *name;
    int (*fn)(void);
  } tests[] = {
      {"split", test_split},         {"kat", test_kat},
      {"bounds", test_bounds},       {"null_safety", test_null_safety},
      {"property", test_property},
  };
  for (size_t i = 0; i < sizeof tests / sizeof tests[0]; i++) {
    if (tests[i].fn() != 0) {
      fprintf(stderr, "test %s FAILED\n", tests[i].name);
      return 1;
    }
  }
  printf("all %zu zdiff tests passed\n", sizeof tests / sizeof tests[0]);
  return 0;
}
