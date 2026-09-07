/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared declarations for the check-no-runtime-abort C23 lint
 * family (gate_no_runtime_abort.c, its report-building sibling
 * gate_no_runtime_abort_report.c, and the _selftest.c sibling). Private to
 * this family — never included outside tools/lint/lintc/.
 */
#ifndef GATE_NO_RUNTIME_ABORT_PRIV_H
#define GATE_NO_RUNTIME_ABORT_PRIV_H

#include <stdio.h>
#include <stddef.h>

enum { NRA_PATH = 512, NRA_ROOTS_MAX = 32, NRA_ROOT_LEN = 256 };

enum nra_mode { NRA_MODE_FAIL, NRA_MODE_WARN, NRA_MODE_UPDATE };

struct nra_ctx {
    const char *baseline;
    const char *const *roots;
    int nroots;
    int file_floor;
    int site_floor;
    enum nra_mode mode;
};

/* ── generic string list (scan_files / violation / stale) ───────────────── */

struct nra_list { char **v; size_t n, cap; };

int nra_push(struct nra_list *l, const char *s, size_t n);
int nra_push_s(struct nra_list *l, const char *s);
void nra_free(struct nra_list *l);

/* ── per-site rows (the awk comment/string state machine's output) ──────── */

enum { NRA_SITE, NRA_HATCH };

struct nra_row { int kind; char path[NRA_PATH]; int lineno; char text[512]; };
struct nra_rows { struct nra_row *v; size_t n, cap; };

/* ── baseline (gate_lib.sh gate_load_kv_file: "<path> <count>") ─────────── */

struct nra_base_row { char path[NRA_PATH]; int allowed; int used; };
struct nra_baseline { struct nra_base_row *v; size_t n, cap; };

int nra_base_push(struct nra_baseline *b, const char *path, int n);
struct nra_base_row *nra_base_find(struct nra_baseline *b, const char *path);
void nra_baseline_free(struct nra_baseline *b);

/* Gate name, shared by every diagnostic in the family. Defined in
 * gate_no_runtime_abort.c. */
extern const char nra_gate_name[];

/* ── report (gate_no_runtime_abort_report.c) ─────────────────────────────
 * Both write the same PASS/FAIL/UPDATE report check_no_runtime_abort.sh
 * does, byte-for-byte, including the per-site "      path:lineno: text"
 * detail lines under each violated file. */
int nra_write_update(const struct nra_ctx *c, const struct nra_rows *rows,
                     FILE *out);
int nra_report(const struct nra_ctx *c, const struct nra_rows *rows,
              const struct nra_list *files, struct nra_baseline *base,
              FILE *out);

/* Runs the full gate (scan, ratchet against the baseline, report) exactly
 * as check_no_runtime_abort.sh does, writing to out/err and returning its
 * exit code (0 clean/WARN, 1 FAIL-mode violation, 2 hollow scan). Shared by
 * the production entry point (env-derived ctx) and the selftest (fixture
 * ctx), so both paths run the identical logic. */
int nra_run_gate(const struct nra_ctx *c, FILE *out, FILE *err);

#endif
