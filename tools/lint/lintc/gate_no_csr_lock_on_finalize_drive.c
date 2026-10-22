/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-no-csr-lock-on-finalize-drive — LOCK-ORDER LAW: the
 * post-finalize reducer DRIVE callgraph must never acquire csr->lock or run
 * the chain-evidence DRAIN machinery. Ported from
 * tools/lint/gate_no_csr_lock_on_finalize_drive.sh (deleted). Selftest:
 * gate_no_csr_lock_on_finalize_drive_selftest.c.
 *
 * WHY (highest-severity never-stuck; prior live deadlock 873ba9955 / 2026-06-12)
 * ------------------------------------------------------------------------------
 * The reducer/ingest drive holds the coins_kv AUTHORITY mutex for the whole
 * drive. The health/evidence DRAIN path takes csr->lock THEN coins_kv
 * (csr_snapshot -> coins_kv_is_proven_authority). If anything ON the drive
 * takes csr->lock (directly, or by calling a drain/record/snapshot/init helper
 * that does), the two acquire orders invert — a classic ABBA cycle that is a
 * LIVE TOTAL-NODE DEADLOCK at tip (net thread in record_finalized_tip wanting
 * csr->lock; an RPC healthcheck holding csr->lock wanting coins_kv).
 *
 * The safe split is note+drain: the drive only NOTES the published tip via a
 * LEAF mutex (chain_evidence_note_finalized_tip, engine/services/src/
 * chain_evidence_live_advance.c:80, called from engine/jobs/src/
 * tip_finalize_post_step.c:53). A SEPARATE thread DRAINS in the correct
 * csr->lock-then-coins_kv order (node_health_service.c:476 ->
 * chain_evidence_drain_pending_tip). This gate freezes that boundary.
 *
 * WHAT IS SCANNED (the drive callgraph ONLY — comments stripped)
 * --------------------------------------------------------------
 *   A) ALL of engine/jobs/src/tip_finalize_post_step.c — entirely the drive
 *      post-finalize side-effect path.
 *   B) ONLY the chain_evidence_note_finalized_tip() function body in
 *      engine/services/src/chain_evidence_live_advance.c. The OTHER functions in
 *      that file ARE the drain path and legitimately take csr->lock / call the
 *      record + snapshot helpers — they must NOT be scanned, so we extract just
 *      the note function (the single drive-side entry; its only caller is the
 *      drive at tip_finalize_post_step.c:53).
 *
 * Comments are stripped first so the explanatory "csr->lock" mentions in those
 * files (e.g. tip_finalize_post_step.c:47) do not false-trip the gate; only
 * real code tokens count. Only comments are stripped: string literal bodies
 * are scanned, as the shell original scanned them.
 *
 * FORBIDDEN TOKENS (any one = the ABBA edge)
 * ------------------------------------------
 *   csr->lock                                        direct acquire of the csr mutex
 *   csr_snapshot                                     takes csr->lock
 *   csr_align_coins_best_block                       writes under csr->lock
 *   chain_evidence_drain_pending_tip                 the drain (csr->lock + node.db)
 *   chain_evidence_controller_record_finalized_tip   the record (csr->lock + node.db)
 *   chain_evidence_controller_snapshot               reads under csr->lock
 *   chain_evidence_controller_init                   constructs the drain controller
 *
 * PASSES on the current tree by construction; FAILS the instant a drive-side
 * function gains any of the above. Exit 0 = pass; non-zero + message = fail.
 *
 * If a NEW drive-side helper legitimately needs to be on this scan, add it to
 * the scan set below — never silence the gate by weakening the token list.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <regex.h>
#include <stdio.h>
#include <string.h>
#include "lintc.h"
#include "gate_no_csr_lock_on_finalize_drive_priv.h"

static const char k_cnf_gate[] = "check-no-csr-lock-on-finalize-drive";
static const char k_cnf_drive_rel[] =
    "engine/jobs/src/tip_finalize_post_step.c";
static const char k_cnf_note_rel[] =
    "engine/services/src/chain_evidence_live_advance.c";
static const char k_cnf_note_fn[] = "chain_evidence_note_finalized_tip";
static const char k_cnf_drive_label[] = "post-finalize drive";
static const char k_cnf_note_label[] = "chain_evidence_note_finalized_tip body";
static const char *const k_cnf_forbidden[] = {
    "csr->lock",
    "csr_snapshot",
    "csr_align_coins_best_block",
    "chain_evidence_drain_pending_tip",
    "chain_evidence_controller_record_finalized_tip",
    "chain_evidence_controller_snapshot",
    "chain_evidence_controller_init",
};

enum { CNF_ROWS = 64, CNF_ROW = 640, CNF_LINE = CSTRIP_LINE_MAX,
       CNF_PATH = 1024 };

/* Comment-stripper state: true while inside a block comment. The state runs
 * across the lines of one file (or one function body), never across files. */
struct cnf_strip { int inblk; };

struct cnf_hits {
    char row[CNF_ROWS][CNF_ROW];
    int n;     /* rows stored */
    int total; /* offending lines seen, stored or not */
};

struct cnf_scan {
    struct cnf_strip st;
    struct cnf_hits *hits;
    const regex_t *def; /* NULL: scan the whole file; else the body only */
    const char *path;
    const char *label;
    long lineno;
    int in_fn;
    int fn_seen;
};

/* Copies in[0..n) to out with every block comment removed (the state in
 * *st carries an open block across calls). Mirrors the awk pass of the shell
 * original. out must hold n+1 bytes; it is NUL-terminated. */
static size_t cnf_block_strip(struct cnf_strip *st, const char *in, size_t n,
                              char *out)
{
    size_t o = 0, i = 0;
    while (i < n) {
        if (st->inblk) {
            if (i + 1 < n && in[i] == '*' && in[i + 1] == '/') {
                st->inblk = 0;
                i += 2;
            } else {
                i++;
            }
        } else if (i + 1 < n && in[i] == '/' && in[i + 1] == '*') {
            st->inblk = 1;
            i += 2;
        } else {
            out[o++] = in[i++];
        }
    }
    out[o] = '\0';
    return o;
}

/* First forbidden token contained in the stripped code line, or NULL. */
static const char *cnf_forbidden_in(const char *code)
{
    for (size_t i = 0; i < sizeof k_cnf_forbidden / sizeof k_cnf_forbidden[0];
         i++)
        if (strstr(code, k_cnf_forbidden[i]))
            return k_cnf_forbidden[i];
    return NULL;
}

static void cnf_hit_add(struct cnf_scan *s, const char *code)
{
    struct cnf_hits *h = s->hits;
    h->total++;
    if (h->n >= CNF_ROWS)
        return;
    (void)snprintf(h->row[h->n], CNF_ROW, "  %s:%ld (%s): %.400s", s->path,
                   s->lineno, s->label, code);
    h->n++;
}

/* Strips comments from one raw source line (no newline) and records it when
 * the code part carries a forbidden token. The "//" cut runs after the block
 * pass, as the sed pass of the shell original did. */
static void cnf_strip_hit(struct cnf_scan *s, const char *raw, size_t n)
{
    char code[CNF_LINE];
    (void)cnf_block_strip(&s->st, raw, n, code);
    char *cut = strstr(code, "//");
    if (cut)
        *cut = '\0';
    if (cnf_forbidden_in(code))
        cnf_hit_add(s, code);
}

/* lc_each_line callback. In body mode it skips every line until the note
 * definition, then scans through the first column-0 closing brace. */
static int cnf_scan_line(void *ctx, const char *line, size_t len)
{
    struct cnf_scan *s = ctx;
    char raw[CNF_LINE];
    size_t n = len;
    s->lineno++;
    if (n > 0 && line[n - 1] == '\n')
        n--;
    if (n >= sizeof raw) {
        fprintf(stderr, "%s: line %ld of %s exceeds %d bytes\n", k_cnf_gate,
                s->lineno, s->path, CNF_LINE);
        return 2;
    }
    memcpy(raw, line, n);
    raw[n] = '\0';
    if (s->def && !s->in_fn) {
        if (regexec(s->def, raw, 0, NULL, 0) != 0)
            return 0;
        s->in_fn = 1;
        s->fn_seen = 1;
    }
    cnf_strip_hit(s, raw, n);
    return s->def && raw[0] == '}' ? 1 : 0;
}

/* Scans one repo-relative file (whole file, or the body when def is set).
 * Returns 0 scanned, 1 when the file is missing (fail closed), 2 on error. */
static int cnf_scan_file(const char *root, const char *rel, const char *label,
                         const regex_t *def, struct cnf_hits *h, int *fn_seen,
                         FILE *out)
{
    char path[CNF_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, rel), sizeof path))
        return 2;
    struct cnf_scan s;
    memset(&s, 0, sizeof s);
    s.hits = h;
    s.def = def;
    s.path = rel;
    s.label = label;
    int rc = lc_each_line(path, cnf_scan_line, &s, 1);
    if (rc == 1) {
        fprintf(out,
                "%s: MISSING tracked file: %s\n"
                "  A drive/note source moved or was renamed -- update this gate deliberately\n"
                "  (and re-verify the LOCK-ORDER LAW boundary).\n",
                k_cnf_gate, rel);
        return 1;
    }
    if (rc)
        return 2;
    *fn_seen = s.fn_seen;
    return 0;
}

static int cnf_def_compile(regex_t *def)
{
    return compile_pat(def, REG_EXTENDED, "^void[[:space:]]+",
                       k_cnf_note_fn, "[(]", "");
}

static void cnf_report_fail(FILE *out, const struct cnf_hits *h)
{
    fprintf(out,
            "\n%s: FAIL -- LOCK-ORDER LAW violated\n\n"
            "The post-finalize reducer DRIVE acquired csr->lock or ran the chain-evidence\n"
            "DRAIN/record/snapshot machinery. The drive already holds the coins_kv\n"
            "authority mutex; that path takes csr->lock THEN coins_kv -- an inverted ABBA\n"
            "acquire that is a LIVE TOTAL-NODE DEADLOCK at tip (prior wedge 873ba9955).\n\n"
            "Offending token(s):\n",
            k_cnf_gate);
    for (int i = 0; i < h->n; i++)
        fprintf(out, "%s\n", h->row[i]);
    if (h->total > h->n)
        fprintf(out, "  ... and %d more\n", h->total - h->n);
    fprintf(out,
            "\nFIX: the drive must ONLY note the tip via the leaf-mutex slot\n"
            "(chain_evidence_note_finalized_tip). The actual evidence record must run on\n"
            "the health-collect DRAIN path (node_health_service.c -> "
            "chain_evidence_drain_pending_tip), which owns the csr->lock-then-coins_kv\n"
            "order. Do NOT call csr_snapshot / record_finalized_tip / drain / controller_\n"
            "init / controller_snapshot / csr_align_coins_best_block from the drive.\n");
}

/* Runs both scopes under root. Missing files and a missing note function
 * return 1 before any verdict (fail closed, never a silent empty scope). */
int cnf_check_root(const char *root, FILE *out)
{
    regex_t def;
    int rc = cnf_def_compile(&def);
    if (rc)
        return 2;
    struct cnf_hits h;
    memset(&h, 0, sizeof h);
    int drive_fn = 0, note_fn = 0;
    rc = cnf_scan_file(root, k_cnf_drive_rel, k_cnf_drive_label, NULL, &h,
                       &drive_fn, out);
    if (rc == 0)
        rc = cnf_scan_file(root, k_cnf_note_rel, k_cnf_note_label, &def, &h,
                           &note_fn, out);
    regfree(&def);
    if (rc)
        return rc;
    if (!note_fn) {
        fprintf(out,
                "%s: could not find 'void %s(' in %s\n"
                "  The drive-side note entry was renamed -- update this gate deliberately.\n",
                k_cnf_gate, k_cnf_note_fn, k_cnf_note_rel);
        return 1;
    }
    if (h.total == 0) {
        fprintf(out,
                "%s: OK -- post-finalize drive takes no csr->lock and runs no drain machinery\n",
                k_cnf_gate);
        return 0;
    }
    cnf_report_fail(out, &h);
    return 1;
}

int check_no_csr_lock_on_finalize_drive_run(int argc, char **argv)
{
    const char *root = argc >= 1 ? argv[0] : ".";
    return cnf_check_root(root, stdout);
}
