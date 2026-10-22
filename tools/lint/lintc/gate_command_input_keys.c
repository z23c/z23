/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-command-input-keys, the C23 port of
 * tools/lint/lintc/gate_command_input_keys_run.c. The kernel rejects any input key a
 * command leaf does not declare, so a key a handler reads but the .def omits
 * is unreachable from the real CLI. The gate reads the leaf macros in the
 * .def files and the C that defines their handlers, follows calls across the
 * indexed functions and fails on a read-but-undeclared key, on two leaves of
 * one handler and schema that declare different keys, and on a stale
 * baseline pin. Floors on every scanned population abort with status 2
 * rather than judge a hollow scan. Environment: ZCL_COMMAND_INPUT_KEYS_
 * {DEF_DIR,BASELINE,VERBOSE,LEAF_FLOOR,FN_FLOOR,BOUND_FLOOR,RESOLVED_FLOOR}
 * and ZCL_LINT_MODE.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdlib.h>
#include <string.h>
#include "gate_command_input_keys_priv.h"
#include "lintc_sig.h"

struct cik_run {
    const struct cik_cfg *cfg;
    FILE *out, *err;
    struct cik_defs defs;
    struct cik_index x;
    struct cik_report rep;
    struct cik_list pats, srcs;
};

void cik_list_add(struct cik_list *l, const char *s, size_t n)
{
    if (l->n == l->cap) {
        l->cap = l->cap ? l->cap * 2 : 64;
        l->v = cik_mem(l->v, l->cap * sizeof *l->v, "cik_list");
    }
    l->v[l->n++] = cik_dup(s, n);
}

void cik_list_free(struct cik_list *l)
{
    for (size_t i = 0; i < l->n; i++)
        free(l->v[i]);
    free(l->v);
    *l = (struct cik_list){ 0 };
}

/* True, after saying why, when count is under the floor or the floor is not
 * a number. */
static bool cik_short(FILE *err, long count, const char *floor, const char *hint)
{
    char *end;
    long f = strtol(floor, &end, 10);
    if (floor[0] && !*end && count >= f)
        return false;
    fprintf(err, "check_command_input_keys: FATAL — scan set is '%ld' (< floor"
            " %s).\n  The scan producer (find/glob/grep) returned too little;"
            " a\n  scanned dir/file was likely renamed, moved, or deleted.\n"
            "  Refusing to report 'clean' off a hollow (empty) scan.\n",
            count, floor);
    if (hint[0])
        fprintf(err, "  %s\n", hint);
    return true;
}

static bool cik_short_fmt(FILE *err, long count, const char *floor,
                          const char *fmt, long arg)
{
    char hint[512];
    snprintf(hint, sizeof hint, fmt, arg);
    return cik_short(err, count, floor, hint);
}

static int cik_stage_defs(struct cik_run *r, const struct cik_list *defs)
{
    char hint[4400];
    snprintf(hint, sizeof hint, "no *.def under: %s", r->cfg->def_dir);
    if (cik_short(r->err, (long)defs->n, "1", hint))
        return 2;
    if (cik_defs_parse(&r->defs, defs->v, defs->n, r->err) != 0)
        return 2;
    if (r->defs.fatals) {
        fputs("check_command_input_keys: FATAL — command macro grammar"
              " drift.\n", r->err);
        return 2;
    }
    if (cik_short_fmt(r->err, r->defs.nleaf, r->cfg->leaf_floor,
                      "leaf population collapsed under floor (parsed %ld)",
                      r->defs.nleaf))
        return 2;
    return cik_short_fmt(r->err, (long)r->defs.n, r->cfg->bound_floor,
                         "handler-binding leaf population collapsed under"
                         " floor (parsed %ld)", (long)r->defs.n) ? 2 : 0;
}

/* One "handler(" pattern per distinct handler, in first-use order. */
static void cik_patterns(struct cik_run *r)
{
    struct cik_set seen = { 0 };
    for (size_t i = 0; i < r->defs.n; i++) {
        struct cik_leaf *l = &r->defs.leaf[i];
        l->hid = cik_intern(&r->x.dict, l->handler, strlen(l->handler));
        if (cik_set_add(&seen, l->hid)) {
            struct cik_buf p = { 0 };
            cik_buf_puts(&p, l->handler);
            cik_buf_putc(&p, '(');
            cik_list_add(&r->pats, p.p, p.n);
            cik_buf_free(&p);
        }
    }
    cik_set_free(&seen);
}

static int cik_stage_sources(struct cik_run *r, cik_find_fn find, void *fctx)
{
    char hint[4400];
    int grc;
    cik_patterns(r);
    snprintf(hint, sizeof hint, "no handler symbols parsed out of %s/*.def",
             r->cfg->def_dir);
    if (cik_short(r->err, (long)r->pats.n, r->cfg->resolved_floor, hint))
        return 2;
    grc = find(fctx, &r->pats, &r->srcs);
    if (lsc_pending())
        return 2;
    if (grc >= 2) {
        fprintf(r->err, "check_command_input_keys: FATAL — git grep for"
                " handler definitions\n  failed (exit %d); refusing to report"
                " a verdict.\n", grc);
        return 2;
    }
    return cik_short(r->err, (long)r->srcs.n, "5",
                     "no .c file names any registered handler symbol — the"
                     " handler naming or the source layout moved; re-point"
                     " this gate.") ? 2 : 0;
}

static int cik_stage_index(struct cik_run *r)
{
    if (cik_index_files(&r->x, r->srcs.v, r->srcs.n, r->err) != 0)
        return 2;
    return cik_short_fmt(r->err, r->x.defs, r->cfg->fn_floor,
                         "C function index collapsed under floor (indexed"
                         " %ld)", r->x.defs) ? 2 : 0;
}

static int cik_stage_analyze(struct cik_run *r)
{
    char hint[256];
    int rc = cik_analyze(r->cfg->baseline, &r->x, &r->defs, &r->rep, r->err);
    if (rc == 3) {
        fputs("FATAL\tclosure did not reach a fixpoint in 64 rounds\n"
              "check_command_input_keys: FATAL — analysis did not"
              " converge.\n", r->err);
        return 2;
    }
    if (rc != 0)
        return rc;
    snprintf(hint, sizeof hint, "only %ld of %ld handler symbols resolved to C"
             " source — the handler-definition scan is hollow; re-point it"
             " before trusting a verdict.", r->rep.resolved, (long)r->defs.n);
    return cik_short(r->err, r->rep.resolved, r->cfg->resolved_floor, hint)
        ? 2 : 0;
}

static void cik_print_missing(struct cik_run *r)
{
    fprintf(r->out, "\ncheck_command_input_keys: %ld input key(s) READ by a"
            " handler but NOT declared in the leaf's input_keys:\n%s\n"
            "  zcl_command_registry_input_validate() rejects any key not in"
            " the\n  leaf's input_keys CSV, so passing one of these is"
            " INVALID_INPUT and\n  omitting it is whatever the handler does"
            " without it: the key is\n  unreachable from the real CLI and the"
            " command is partly or wholly\n  UNCALLABLE. Add the key to"
            " input_keys in %s/*.def and\n  regenerate the catalog doc (make"
            " docs-api-reference). If the read\n  is genuinely unreachable,"
            " add '<leaf> <key>' to %s with the\n  reason on the same"
            " line.\n", r->rep.nmiss, cik_buf_str(&r->rep.miss),
            r->cfg->def_dir, r->cfg->baseline);
}

static void cik_print_divergent(struct cik_run *r)
{
    fprintf(r->out, "\ncheck_command_input_keys: %ld leaf pair(s) share a"
            " handler AND an input schema but declare DIFFERENT input"
            " keys:\n%s\n  One contract under two names: the input schema"
            " says the inputs are\n  identical, so the handler cannot be"
            " routing on the path to justify\n  the difference. Whichever"
            " leaf is missing a key answers\n  INVALID_INPUT for an input its"
            " twin accepts. Make the input_keys\n  CSVs agree in %s/*.def"
            " and regenerate the catalog doc\n  (make docs-api-reference)."
            "\n", r->rep.ndiv, cik_buf_str(&r->rep.divg), r->cfg->def_dir);
}

static void cik_print_stale(struct cik_run *r)
{
    fprintf(r->out, "\ncheck_command_input_keys: %ld STALE baseline"
            " entry(ies) — the violation is gone:\n%s  Good: the key got"
            " declared. Delete each line from %s in the\n  same commit so the"
            " ratchet can only shrink.\n", r->rep.nstale,
            cik_buf_str(&r->rep.stale), r->cfg->baseline);
}

/* Prints every finding block; returns true when any of them gates. */
static bool cik_print_findings(struct cik_run *r)
{
    bool fail = r->rep.nmiss > 0 || r->rep.ndiv > 0 || r->rep.nstale > 0;
    if (r->rep.nmiss > 0)
        cik_print_missing(r);
    if (r->rep.ndiv > 0)
        cik_print_divergent(r);
    if (r->rep.nstale > 0)
        cik_print_stale(r);
    if (r->rep.unresolved > 0) {
        fprintf(r->out, "check_command_input_keys: note — %ld bound handler"
                " symbol(s) were not found in the scanned C (not gated):\n\n",
                r->rep.unresolved);
        fputs(cik_buf_str(&r->rep.unres), r->out);
    }
    if (r->rep.nunread > 0 && strcmp(r->cfg->verbose, "1") == 0)
        fprintf(r->out, "check_command_input_keys: declared-but-not-read"
                " (WARN, not gated):\n%s", cik_buf_str(&r->rep.unread));
    return fail;
}

static int cik_verdict(struct cik_run *r)
{
    if (cik_print_findings(r) && strcmp(r->cfg->mode, "FAIL") == 0)
        return 1;
    fprintf(r->out, "[check_command_input_keys] PASS (%ld leaf handler(s)"
            " resolved over %ld function(s); every key they read is declared;"
            " %ld leaf(s) on a shared dispatcher not attributable; %ld"
            " declared-but-unread (ZCL_COMMAND_INPUT_KEYS_VERBOSE=1 to list);"
            " %ld grandfathered; shared-handler input contracts agree)\n",
            r->rep.resolved, r->x.defs, r->rep.nshared, r->rep.nunread,
            r->rep.ngrand);
    return 0;
}

int cik_check(const struct cik_cfg *cfg, const struct cik_list *defs,
              cik_find_fn find, void *fctx, FILE *out, FILE *err)
{
    struct cik_run *r = cik_mem(NULL, sizeof *r, "cik_run");
    int rc;
    memset(r, 0, sizeof *r);
    r->cfg = cfg;
    r->out = out;
    r->err = err;
    rc = cik_index_open(&r->x);
    if (rc == 0)
        rc = cik_stage_defs(r, defs);
    if (rc == 0 && !lsc_pending())
        rc = cik_stage_sources(r, find, fctx);
    if (rc == 0 && !lsc_pending())
        rc = cik_stage_index(r);
    if (rc == 0 && !lsc_pending())
        rc = cik_stage_analyze(r);
    if (rc == 0 && !lsc_pending())
        rc = cik_verdict(r);
    cik_report_free(&r->rep);
    cik_list_free(&r->pats);
    cik_list_free(&r->srcs);
    cik_defs_free(&r->defs);
    cik_index_close(&r->x);
    free(r);
    return lsc_pending() ? -1 : rc;
}
