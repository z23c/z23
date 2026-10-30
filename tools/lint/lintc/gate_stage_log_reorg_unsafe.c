/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-stage-log-reorg-unsafe — ratchet on the reorg-UNSAFE
 * "INSERT OR REPLACE keyed by height alone" pattern across the stage-log
 * stores. Ported from tools/scripts/gate_stage_log_reorg_unsafe_ratchet.sh
 * (deleted). Selftest: gate_stage_log_reorg_unsafe_selftest.c.
 *
 * WHAT IT GUARDS
 * --------------
 * Each stage-log store records per-height witness rows in a table whose
 * PRIMARY KEY is `height` and writes them with `INSERT OR REPLACE` (e.g.
 * engine/jobs/src/utxo_apply_log_store.c:18 `height INTEGER PRIMARY KEY` +
 * :68 `INSERT OR REPLACE INTO utxo_apply_log`). That UPSERT is keyed by
 * height alone, so a reorg that re-applies a DIFFERENT block at the same
 * height silently overwrites the prior witness instead of being a distinct,
 * replayable record. The 8 existing stores share this shape; it is the
 * current baseline. The danger is the pattern SPREADING to a new stage log
 * without anyone re-examining reorg-correctness.
 *
 * THE RATCHET
 * -----------
 * Counts the case-insensitive `INSERT OR REPLACE` occurrences in the eight
 * known stage-log store files and bakes 8 as the baseline. PASSES today by
 * construction. FAILS (exit 1) if the count INCREASES — a 9th such store or
 * a second UPSERT in an existing store. The count may FREELY DECREASE
 * (a store made reorg-correct removes its UPSERT); that still passes, with
 * a NOTE telling the author to lower the baseline.
 *
 * Fail-loud preflight: the tracked FILES list must be non-empty (floor 1)
 * and every entry must exist, else exit 2 — a drifted scan surface never
 * reports a clean count. ZCL_REORG_RATCHET_FILES (space-separated) overrides
 * the file list, as the shell original did for its self-test.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "lintc_text.h"
#include "gate_stage_log_reorg_unsafe_priv.h"

static const char k_slr_gate[] = "gate_stage_log_reorg_unsafe_ratchet";
static const char k_slr_needle[] = "insert or replace";
static const char *const k_slr_default_files[SLR_BASELINE] = {
    "engine/models/src/header_admit_log.c",
    "engine/jobs/src/body_fetch_log_store.c",
    "engine/jobs/src/script_validate_log_store.c",
    "engine/jobs/src/utxo_apply_log_store.c",
    "engine/jobs/src/validate_headers_log_store.c",
    "engine/jobs/src/tip_finalize_log_store.c",
    "engine/jobs/src/proof_validate_log_store.c",
    "engine/jobs/src/body_persist_log_store.c",
};

struct slr_scan {
    const char *file; /* repo-relative label for site rows */
    long lineno;
    char (*sites)[SLR_SITE];
    int *nsites; /* the running count: every matching line is one site */
};

/* Case-insensitive substring test for the UPSERT needle. */
static int slr_ci_contains(const char *hay)
{
    const size_t nl = sizeof k_slr_needle - 1;
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (i < nl && p[i] &&
               tolower((unsigned char)p[i]) == (unsigned char)k_slr_needle[i])
            i++;
        if (i == nl)
            return 1;
    }
    return 0;
}

/* Records one "file:lineno" row. Past SLR_SITES rows the gate refuses
 * (2) rather than report a truncated list. */
static int slr_site_add(struct slr_scan *s)
{
    if (*s->nsites >= SLR_SITES) {
        fprintf(stderr, "%s: site list exceeds %d\n", k_slr_gate, SLR_SITES);
        return 2;
    }
    if (ovf(snprintf(s->sites[*s->nsites], SLR_SITE, "%s:%ld", s->file,
                     s->lineno), SLR_SITE))
        return 2;
    (*s->nsites)++;
    return 0;
}

/* lc_each_line callback: counts each line carrying the needle once, the
 * way `grep -ni` listed one row per matching line. */
static int slr_line(void *ctx, const char *line, size_t len)
{
    struct slr_scan *s = ctx;
    char buf[SLR_LINE];
    size_t n = len;
    s->lineno++;
    if (n > 0 && line[n - 1] == '\n')
        n--;
    if (n >= sizeof buf) {
        fprintf(stderr, "%s: line %ld of %s exceeds %d bytes\n", k_slr_gate,
                s->lineno, s->file, SLR_LINE);
        return 2;
    }
    memcpy(buf, line, n);
    buf[n] = '\0';
    if (slr_ci_contains(buf))
        return slr_site_add(s);
    return 0;
}

/* Counts the UPSERT rows in one file into sites/nsites. 0 counted, 2 fatal:
 * an unreadable file is never masked as "no match". */
static int slr_count_file(const char *path, char (*sites)[SLR_SITE],
                          int *nsites)
{
    struct slr_scan s = { path, 0, sites, nsites };
    return lc_each_line(path, slr_line, &s, 0) == 0 ? 0 : 2;
}

static int slr_count_all(const char *const *files, int nfiles,
                         char (*sites)[SLR_SITE], int *nsites)
{
    for (int i = 0; i < nfiles; i++) {
        if (slr_count_file(files[i], sites, nsites))
            return 2;
    }
    return 0;
}

/* A tracked store must be a readable regular file (shell `-f`). */
static int slr_is_file(const char *path)
{
    return lct_readable(path) && !lintc_is_dir(path);
}

/* Preflight: floor on the list size, then every entry must exist. */
static int slr_preflight(const char *const *files, int nfiles)
{
    if (gate_require_scanned(nfiles, 1, k_slr_gate,
                             "the tracked stage-log store list is empty"))
        return 2;
    int missing = 0;
    for (int i = 0; i < nfiles; i++) {
        if (!slr_is_file(files[i])) {
            fprintf(stderr, "%s: MISSING tracked file: %s\n", k_slr_gate,
                    files[i]);
            missing = 1;
        }
    }
    if (missing) {
        fprintf(stderr,
                "%s: a stage-log store was moved/renamed.\n"
                "Update the FILES list (and re-verify the baseline) deliberately.\n"
                "Refusing to report a clean count off a drifted (partial) scan surface.\n",
                k_slr_gate);
        return 2;
    }
    return 0;
}

static void slr_report_ok(int count, char (*sites)[SLR_SITE], FILE *out)
{
    fprintf(out,
            "%s: OK — %d height-keyed INSERT OR REPLACE site(s) (baseline %d)\n",
            k_slr_gate, count, SLR_BASELINE);
    for (int i = 0; i < count; i++)
        fprintf(out, "    %s\n", sites[i]);
    if (count < SLR_BASELINE)
        fprintf(out,
                "\n"
                "NOTE: count (%d) is BELOW the baseline (%d) — debt was\n"
                "removed. Lower SLR_BASELINE in\n"
                "tools/lint/lintc/gate_stage_log_reorg_unsafe_priv.h to %d to re-tighten\n"
                "the ratchet.\n",
                count, SLR_BASELINE, count);
}

static void slr_report_fail(int count, char (*sites)[SLR_SITE], FILE *out)
{
    fprintf(out,
            "\n"
            "%s: FAIL — %d height-keyed INSERT OR REPLACE site(s), baseline is %d\n"
            "\n"
            "A NEW reorg-unsafe stage-log UPSERT appeared. Current sites:\n",
            k_slr_gate, count, SLR_BASELINE);
    for (int i = 0; i < count; i++)
        fprintf(out, "    %s\n", sites[i]);
    fprintf(out,
            "\n"
            "These stage-log stores key their witness rows by height alone and write\n"
            "with INSERT OR REPLACE, so a reorg replacing the block at a height\n"
            "silently overwrites the prior witness instead of recording a distinct,\n"
            "replayable row. Do NOT spread the shape:\n"
            "  - Make the new stage log reorg-correct (key by block hash, or be\n"
            "    append-only) so re-application at a height does not clobber history; OR\n"
            "  - If the new site is genuinely reorg-safe and reviewed, raise SLR_BASELINE\n"
            "    in tools/lint/lintc/gate_stage_log_reorg_unsafe_priv.h deliberately,\n"
            "    citing why.\n");
}

int slr_check(const char *const *files, int nfiles, FILE *out)
{
    static char sites[SLR_SITES][SLR_SITE];
    int count = 0;
    int rc = slr_preflight(files, nfiles);
    if (rc)
        return rc;
    rc = slr_count_all(files, nfiles, sites, &count);
    if (rc)
        return rc;
    if (count <= SLR_BASELINE) {
        slr_report_ok(count, sites, out);
        return 0;
    }
    slr_report_fail(count, sites, out);
    return 1;
}

/* bash `read -a` default IFS: space, tab and newline separate tokens. */
static int slr_is_sep(char c)
{
    return c == ' ' || c == '\t' || c == '\n';
}

/* Copies one override token into store[slot] and points files[slot] at it. */
static int slr_store_token(const char *start, size_t n,
                           char (*store)[SLR_PATH], const char **files,
                           int slot)
{
    if (n >= SLR_PATH) {
        fprintf(stderr, "%s: override path exceeds %d bytes\n", k_slr_gate,
                SLR_PATH);
        return 2;
    }
    memcpy(store[slot], start, n);
    store[slot][n] = '\0';
    files[slot] = store[slot];
    return 0;
}

/* Splits the space-separated ZCL_REORG_RATCHET_FILES override into
 * store/files; *nfiles is the token count. */
static int slr_parse_override(const char *s, char (*store)[SLR_PATH],
                              const char **files, int *nfiles)
{
    const char *p = s;
    *nfiles = 0;
    for (;;) {
        while (*p && slr_is_sep(*p))
            p++;
        if (!*p)
            return 0;
        const char *start = p;
        while (*p && !slr_is_sep(*p))
            p++;
        if (*nfiles >= SLR_MAX_FILES) {
            fprintf(stderr, "%s: override file list exceeds %d\n", k_slr_gate,
                    SLR_MAX_FILES);
            return 2;
        }
        if (slr_store_token(start, (size_t)(p - start), store, files, *nfiles))
            return 2;
        (*nfiles)++;
    }
}

int check_stage_log_reorg_unsafe_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    static char store[SLR_MAX_FILES][SLR_PATH];
    const char *files[SLR_MAX_FILES];
    int nfiles = 0;
    const char *ov = getenv("ZCL_REORG_RATCHET_FILES");
    if (ov && *ov) {
        int rc = slr_parse_override(ov, store, files, &nfiles);
        if (rc)
            return rc;
    } else {
        for (int i = 0; i < SLR_BASELINE; i++)
            files[i] = k_slr_default_files[i];
        nfiles = SLR_BASELINE;
    }
    return slr_check(files, nfiles, stdout);
}
