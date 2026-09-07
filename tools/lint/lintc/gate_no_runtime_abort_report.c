/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: check-no-runtime-abort's PASS/FAIL/UPDATE report — byte-parity
 * port of the reporting half of tools/lint/check_no_runtime_abort.sh (at
 * 89fca9905), split out of gate_no_runtime_abort.c under the cyclomatic
 * complexity cap. Builds the same violation text the shell's DETAIL[]
 * array produces: a "  <path> — N runtime abort site(s), ..." header
 * followed by one "      <path>:<lineno>: <text>" line per counted site,
 * in scan order, with violating files sorted by path (matching the
 * shell's `sort` over the flattened printf stream, whose long shared
 * per-file path prefix keeps every file's header+detail lines adjacent).
 *
 * Gates: check-no-runtime-abort
 * Single-gate family (see gate_no_runtime_abort.c for the shared header).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "gate_no_runtime_abort_priv.h"

/* ── small growable buffer for one violation's header+detail block ──────── */

struct nra_buf { char *v; size_t n, cap; };

static int nra_buf_put(struct nra_buf *b, const char *s, size_t n)
{
    if (b->n + n + 1 > b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 256;
        while (nc < b->n + n + 1)
            nc *= 2;
        char *nv = realloc(b->v, nc); // raw-alloc-ok:lint-runtime
        if (!nv)
            return die("z23-lint: out of memory\n", "");
        b->v = nv;
        b->cap = nc;
    }
    memcpy(b->v + b->n, s, n);
    b->n += n;
    b->v[b->n] = '\0';
    return 0;
}

static int nra_buf_line(struct nra_buf *b, const char *line)
{
    int rc = nra_buf_put(b, line, strlen(line));
    return rc == 0 ? nra_buf_put(b, "\n", 1) : rc;
}

static int nra_path_cmp(const void *a, const void *b)
{
    const struct nra_base_row *ra = a;
    const struct nra_base_row *rb = b;
    return strcmp(ra->path, rb->path);
}

/* Appends one "      <path>:<lineno>: <text>" line per counted (kind ==
 * NRA_SITE) row belonging to `path`, in scan order — the same lines the
 * shell's DETAIL["$path"] accumulates. */
static int nra_append_path_details(const struct nra_rows *rows,
                                   const char *path, struct nra_buf *buf)
{
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < rows->n; i++) {
        const struct nra_row *r = &rows->v[i];
        if (r->kind != NRA_SITE || strcmp(r->path, path) != 0)
            continue;
        char line[NRA_PATH + 32 + sizeof r->text];
        if (ovf(snprintf(line, sizeof line, "      %s:%d: %s", r->path,
                         r->lineno, r->text),
                sizeof line))
            return die("z23-lint: derived buffer overflow\n", "");
        rc = nra_buf_line(buf, line);
    }
    return rc;
}

int nra_write_update(const struct nra_ctx *c, const struct nra_rows *rows,
                     FILE *out)
{
    struct nra_baseline live; memset(&live, 0, sizeof live);
    int rc = 0, total = 0, hatched = 0;
    for (size_t i = 0; rc == 0 && i < rows->n; i++) {
        if (rows->v[i].kind == NRA_HATCH) { hatched++; continue; }
        total++;
        struct nra_base_row *r = nra_base_find(&live, rows->v[i].path);
        if (r) r->allowed++;
        else rc = nra_base_push(&live, rows->v[i].path, 1);
    }
    if (rc == 0) {
        FILE *f = fopen(c->baseline, "w");
        if (!f) { rc = die("z23-lint: cannot open %s\n", c->baseline); }
        else {
            fputs("# check_no_runtime_abort baseline — files in network-reachable code that still\n"
                  "# hold RUNTIME assert()/abort() sites. assert() is LIVE in this\n"
                  "# build (-DNDEBUG is set only for vendored LevelDB), so each of\n"
                  "# these is a process kill on a failed assumption.\n"
                  "# Format: <path> <site-count>.  COUNTS MAY ONLY SHRINK.\n"
                  "#\n"
                  "# Fix a row by returning an error instead: fail the call, log the\n"
                  "# reason with LOG_FAIL/LOG_ERR, and let the caller reject the\n"
                  "# input — then lower (or delete) the number here. Adding a row is\n"
                  "# not a fix. An assertion about a layout or a constant becomes\n"
                  "# _Static_assert, which this gate deliberately does not count.\n"
                  "#\n"
                  "# An abort that is CORRECT (softening it would trade a crash for\n"
                  "# a key compromise or a plaintext leak) does not belong here at\n"
                  "# all — annotate it in place with // abort-ok:<reason>.\n"
                  "#\n"
                  "# core/ is byte-sealed: its rows are counted and frozen, and are\n"
                  "# only editable through the owner unseal ritual (make core-unseal).\n"
                  "# Regenerate: ZCL_LINT_MODE=UPDATE tools/lint/check_no_runtime_abort.sh\n",
                  f);
            for (size_t i = 0; i < live.n; i++)
                fprintf(f, "%s %d\n", live.v[i].path, live.v[i].allowed);
            rc = fclose(f) != 0 ? die("z23-lint: fclose failed: %s\n", c->baseline) : 0;
        }
    }
    if (rc == 0)
        fprintf(out, "[%s] baseline UPDATED: %s (%zu files, %d sites, %d annotated)\n",
                nra_gate_name, c->baseline, live.n, total, hatched);
    nra_baseline_free(&live);
    return rc;
}

/* Per-file site counts (kind==NRA_SITE only); *hatched gets the annotated
 * (kind==NRA_HATCH) count, *total the counted-site total. */
static int nra_count_rows(const struct nra_rows *rows, struct nra_baseline *counts,
                          int *total, int *hatched)
{
    int rc = 0;
    *total = 0;
    *hatched = 0;
    for (size_t i = 0; rc == 0 && i < rows->n; i++) {
        if (rows->v[i].kind == NRA_HATCH) { (*hatched)++; continue; }
        (*total)++;
        struct nra_base_row *r = nra_base_find(counts, rows->v[i].path);
        if (r) r->allowed++;
        else rc = nra_base_push(counts, rows->v[i].path, 1);
    }
    return rc;
}

/* Builds one violation's full text block: the "  <path> — ..." header
 * plus its per-site detail lines, with the header's single trailing
 * newline trimmed off the last detail line — matching the shell's
 * "$header"$'\n'"${DETAIL[$path]%$'\n'}" construction. */
static int nra_build_violation(const struct nra_rows *rows, const char *header,
                               const char *path, struct nra_list *violations)
{
    struct nra_buf buf = { NULL, 0, 0 };
    int rc = nra_buf_line(&buf, header);
    if (rc == 0)
        rc = nra_append_path_details(rows, path, &buf);
    if (rc == 0 && buf.n && buf.v[buf.n - 1] == '\n')
        buf.v[--buf.n] = '\0';
    if (rc == 0)
        rc = nra_push_s(violations, buf.v);
    free(buf.v);
    return rc;
}

/* Ratchet each observed per-file count against the baseline: a file not in
 * the baseline, or over its allowed count, is a violation; otherwise
 * tolerated. Marks each matched baseline row used=1 for the stale pass.
 * Violating files are visited in path order (qsort), matching the
 * shell's `sort` over the flattened printf stream. */
static int nra_judge_files(const struct nra_rows *rows, struct nra_baseline *counts,
                           struct nra_baseline *base,
                           struct nra_list *violations, int *tolerated)
{
    int rc = 0;
    *tolerated = 0;
    if (counts->n > 1)
        qsort(counts->v, counts->n, sizeof counts->v[0], nra_path_cmp);
    for (size_t i = 0; rc == 0 && i < counts->n; i++) {
        struct nra_base_row *b = nra_base_find(base, counts->v[i].path);
        if (b)
            b->used = 1;
        char header[1024];
        if (!b)
            snprintf(header, sizeof header, "%s — %d runtime abort site(s), not in the baseline",
                     counts->v[i].path, counts->v[i].allowed);
        else if (counts->v[i].allowed > b->allowed)
            snprintf(header, sizeof header,
                     "%s — %d runtime abort site(s), baseline allows %d",
                     counts->v[i].path, counts->v[i].allowed, b->allowed);
        else {
            (*tolerated)++;
            continue;
        }
        rc = nra_build_violation(rows, header, counts->v[i].path, violations);
    }
    return rc;
}

static int nra_print_violations(const struct nra_ctx *c,
                                const struct nra_list *violations, FILE *out)
{
    fprintf(out, "\n[%s] %zu file(s) gained a runtime abort primitive on a\n"
            "        network-reachable path. assert() is LIVE in this build, so each\n"
            "        of these kills the process on a failed assumption:\n",
            nra_gate_name, violations->n);
    for (size_t i = 0; i < violations->n; i++)
        fprintf(out, "  %s\n", violations->v[i]);
    fputs("\n  Reject the input instead of aborting on it:\n"
          "    return false / -1, log the reason with LOG_FAIL/LOG_ERR/LOG_NULL,\n"
          "    and let the caller report it. That is how every other rejection\n"
          "    in this tree behaves, and the node keeps running.\n"
          "  An assertion about a LAYOUT or a CONSTANT becomes _Static_assert,\n"
          "  which this gate deliberately does not count.\n"
          "  An abort that is CORRECT — where continuing would leak plaintext,\n"
          "  forge a key, or silently mis-verify a signature — is annotated in\n"
          "  place with:  // abort-ok:<reason>   (reason required, >= 6 chars).\n"
          "  Worked examples: core/modules/sapling/src/note_encryption.c (esk repeat),\n"
          "  contexts/wallet/modules/keys/src/pubkey.c (process-wide verify context lifecycle).\n",
          out);
    return fprintf(out, "  Raising a number in %s is NOT a fix; counts may only shrink.\n",
                  c->baseline) < 0;
}

int nra_report(const struct nra_ctx *c, const struct nra_rows *rows,
              const struct nra_list *files, struct nra_baseline *base,
              FILE *out)
{
    struct nra_baseline counts; memset(&counts, 0, sizeof counts);
    int total = 0, hatched = 0;
    int rc = nra_count_rows(rows, &counts, &total, &hatched);

    struct nra_list violations = { NULL, 0, 0 };
    int tolerated = 0;
    if (rc == 0)
        rc = nra_judge_files(rows, &counts, base, &violations, &tolerated);

    struct nra_list stale = { NULL, 0, 0 };
    for (size_t i = 0; rc == 0 && i < base->n; i++)
        if (!base->v[i].used)
            rc = nra_push_s(&stale, base->v[i].path);

    int fail = 0;
    if (rc == 0 && violations.n) {
        fail = 1;
        rc = nra_print_violations(c, &violations, out);
    }
    if (rc == 0 && stale.n) {
        fail = 1;
        fprintf(out, "\n[%s] %zu STALE baseline row(s) — the file has no runtime\n"
                "        abort sites left. Delete them from %s:\n",
                nra_gate_name, stale.n, c->baseline);
        for (size_t i = 0; i < stale.n; i++)
            fprintf(out, "  %s\n", stale.v[i]);
    }
    if (rc == 0) {
        if (fail && c->mode == NRA_MODE_FAIL)
            rc = 1;
        else
            fprintf(out, "[%s] PASS (%zu files scanned, %d runtime site(s) across %zu file(s), "
                    "%d of %zu baselined row(s) tolerated, %d annotated abort-ok)\n",
                    nra_gate_name, files->n, total, counts.n, tolerated, base->n, hatched);
    }
    nra_free(&violations);
    nra_free(&stale);
    nra_baseline_free(&counts);
    return rc;
}
