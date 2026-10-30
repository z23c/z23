/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check_blocker_handoff_declared — a blocker id that a
 * production call site can raise with an EMPTY escape_action must carry an
 * automatic remedy in blocker_remedy_bindings.def or a human-decision row in
 * blocker_operator_decisions.def; otherwise it must be listed in the
 * shrink-only baseline tools/lint/blocker_handoff_baseline.txt. Ported from
 * tools/lint/check_blocker_handoff_declared.sh (deleted). The source passes
 * live in gate_blocker_handoff_declared_scan.c; the selftest in
 * gate_blocker_handoff_declared_selftest.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "gate_blocker_handoff_declared_priv.h"

static const char k_bhd_gate[] = "check_blocker_handoff_declared";
static const char *const k_bhd_wrappers[3] = {
    "engine/services/src/invariant_sentinel.c",
    "core/modules/validation/src/chain_linkage_check.c",
    "engine/services/src/sticky_escalator.c",
};

static int bh_floor(FILE *err, int count, int floor, const char *hint)
{
    if (count >= floor)
        return 0;
    fprintf(err, "%s: FATAL — scan set is '%d' (< floor %d).\n",
            k_bhd_gate, count, floor);
    fputs("  The scan producer (find/glob) returned too little; a\n", err);
    fputs("  scanned dir/file was likely renamed, moved, or deleted.\n", err);
    fputs("  Refusing to report 'clean' off a hollow (empty) scan.\n", err);
    if (hint && *hint)
        fprintf(err, "  %s\n", hint);
    return 2;
}

struct bh_pat { char id[BH_IDLEN]; char head[BH_HEAD]; };
static struct bh_pat bh_remedy[BH_PAT];
static int bh_nremedy;
static char bh_decide[BH_PAT][BH_IDLEN];
static int bh_ndecide;
static struct { char id[BH_IDLEN]; char loc[BH_LOC]; } bh_ee[BH_EE];
static int bh_nee;
static char bh_base_ids[BH_BASE][BH_IDLEN];
static int bh_base_hit[BH_BASE];
static int bh_nbase;
static struct bln_set bh_base;

struct bh_viol { char id[BH_IDLEN]; char msg[BH_LOC + BH_PATH + 96]; };
static struct bh_viol bh_viol[BH_LST];
static int bh_nviol;
static char bh_tol[BH_LST][BH_IDLEN];
static int bh_ntol;
static char bh_stale[BH_LST][BH_IDLEN];
static int bh_nstale;
static int bh_n_auto, bh_n_declared;
static const char *bh_cfg_remedy, *bh_cfg_decision, *bh_cfg_baseline;

/* Parses one ZCL_BLOCKER_* table row. Returns 0 stored, 1 no row, 2 error. */
static void bh_trim_tail(char *s)
{
    size_t n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t'))
        s[--n] = '\0';
}

/* Copies the text inside `MACRO(` ... `)` into s, dropping a trailing
 * comment. Returns 0, 1 when the line is not this macro, 2 on overflow. */
static int bh_def_strip(const char *line, const char *macro, char *s,
                        size_t scap)
{
    size_t mlen = strlen(macro);
    if (strncmp(line, macro, mlen) != 0 || line[mlen] != '(')
        return 1;
    /* Cut the row comment before the length check: a long row comment must
     * not count against the id/head buffer (the shell cut it first too). */
    const char *body = line + mlen + 1;
    const char *cm = strstr(body, "/*");
    size_t blen = cm ? (size_t)(cm - body) : strlen(body);
    if (blen >= scap)
        return 2;
    memcpy(s, body, blen);
    s[blen] = '\0';
    bh_trim_tail(s);
    size_t n = strlen(s);
    if (n && s[n - 1] == ')')
        s[--n] = '\0';
    bh_trim_tail(s);
    return 0;
}

/* Cuts s at its first comma. *rest points at the trimmed text after the
 * comma, or at the empty tail of s when there is no comma. */
static void bh_def_split(char *s, char **rest)
{
    char *comma = strchr(s, ',');
    *rest = s + strlen(s);
    if (!comma)
        return;
    *comma = '\0';
    char *rp = comma + 1;
    while (*rp == ' ' || *rp == '\t' || *rp == '\n')
        rp++;
    bh_trim_tail(rp);
    *rest = rp;
}

/* Parses one ZCL_BLOCKER_* table row. Returns 0 stored, 1 no row, 2 error. */
static int bh_def_row(const char *line, char *id, size_t idcap, char *rest,
                      size_t restcap)
{
    static char s[512];
    const char *macro = rest ? "ZCL_BLOCKER_REMEDY" : "ZCL_BLOCKER_DECISION";
    int rc = bh_def_strip(line, macro, s, sizeof s);
    if (rc)
        return rc;
    char *rp = NULL;
    bh_def_split(s, &rp);
    char *idp = s;
    while (*idp == ' ' || *idp == '\t')
        idp++;
    bh_trim_tail(idp);
    if (!*idp)
        return 1;
    if (strlen(idp) >= idcap)
        return 2;
    strcpy(id, idp);
    if (rest) {
        if (strlen(rp) >= restcap)
            return 2;
        strcpy(rest, rp);
    }
    return 0;
}

struct bh_tbl_ctx { int kind; };

static int bh_tbl_row(char *line, int kind)
{
    char id[BH_IDLEN], rest[BH_HEAD];
    int rc = bh_def_row(line, id, sizeof id, kind ? NULL : rest, sizeof rest);
    if (rc == 1)
        return 0; /* not a row (comment, blank, #define): keep reading */
    if (rc != 0)
        return rc;
    if (kind) {
        if (bh_ndecide >= BH_PAT)
            return 2;
        strcpy(bh_decide[bh_ndecide++], id);
        return 0;
    }
    if (bh_nremedy >= BH_PAT)
        return 2;
    strcpy(bh_remedy[bh_nremedy].id, id);
    strcpy(bh_remedy[bh_nremedy].head, rest);
    bh_nremedy++;
    return 0;
}

static int bh_tbl_line(void *ctx, const char *line, size_t len)
{
    char buf[BH_LLINE];
    if (len && line[len - 1] == '\n')
        len--;
    if (len >= sizeof buf) {
        fprintf(stderr, "%s: table line exceeds %d\n", k_bhd_gate, BH_LLINE);
        return 2;
    }
    memcpy(buf, line, len);
    buf[len] = '\0';
    return bh_tbl_row(buf, ((struct bh_tbl_ctx *)ctx)->kind);
}

static int bh_load_table(const char *path, int kind)
{
    struct bh_tbl_ctx ctx = { kind };
    int rc = lc_each_line(path, bh_tbl_line, &ctx, 1);
    if (rc)
        return 2;
    return 0;
}

static int bh_exists(const char *path)
{
    FILE *f = fopen(path, "r");
    if (f)
        fclose(f);
    return f != NULL;
}

/* The wrapper raise helpers are assumed to never set an escape action; this
 * re-verifies that from their bodies and aborts LOUD when it is stale. */
static int bh_wrapper_check(FILE *err)
{
    for (int i = 0; i < 3; i++) {
        char path[BH_PATH];
        if (bh_path(path, sizeof path, k_bhd_wrappers[i]))
            return 2;
        if (!bh_exists(path))
            continue;
        FILE *f = fopen(path, "r");
        if (!f)
            continue;
        int hit = 0;
        char line[BH_LLINE];
        while (!hit && fgets(line, sizeof line, f))
            if (strstr(line, ".escape_action") ||
                strstr(line, "->escape_action"))
                hit = 1;
        fclose(f);
        if (hit) {
            fprintf(err,
                    "%s: FATAL — %s now assigns escape_action; the wrapper\n"
                    "  table in this gate assumes it never does. Re-derive it.\n",
                    k_bhd_gate, k_bhd_wrappers[i]);
            return 2;
        }
    }
    return 0;
}

static int bh_macro_get(const char *name, char *out)
{
    for (int i = 0; i < bh_nmacros; i++)
        if (strcmp(bh_macros[i][0], name) == 0) {
            strcpy(out, bh_macros[i][1]);
            return 1;
        }
    return 0;
}

static int bh_split_markers(int fidx, char ids[][BH_IDLEN], int max)
{
    static char buf[BH_MARKLEN];
    strcpy(buf, bh_fmark[fidx]);
    int n = 0;
    for (char *t = strtok(buf, " "); t; t = strtok(NULL, " ")) {
        if (n >= max)
            return -1;
        if (strlen(t) >= BH_IDLEN)
            return -1;
        strcpy(ids[n++], t);
    }
    return n;
}

static int bh_ee_find(const char *id)
{
    for (int i = 0; i < bh_nee; i++)
        if (strcmp(bh_ee[i].id, id) == 0)
            return i;
    return -1;
}

/* Folds raise sites into the set of ids raisable with an empty escape. */
static int bh_fold_site(const struct bh_site *st)
{
    char ids[16][BH_IDLEN];
    int n = 0;
    if (st->kind == 'l') {
        strcpy(ids[0], st->val);
        n = 1;
    } else if (st->kind == 'i' && bh_macro_get(st->val, ids[0])) {
        n = 1;
    } else {
        n = bh_split_markers(st->fidx, ids, 16);
        if (n < 0)
            return 2;
    }
    for (int j = 0; j < n; j++) {
        if (!ids[j][0] || st->has_esc == 1)
            continue;
        if (bh_ee_find(ids[j]) >= 0)
            continue;
        if (bh_nee >= BH_EE || strlen(ids[j]) >= BH_IDLEN)
            return 2;
        strcpy(bh_ee[bh_nee].id, ids[j]);
        if (ovf(snprintf(bh_ee[bh_nee].loc, BH_LOC, "%s:%d",
                         bh_files[st->fidx], st->line), BH_LOC))
            return 2;
        bh_nee++;
    }
    return 0;
}

static int bh_fold(void)
{
    for (int i = 0; i < bh_nsites; i++) {
        int rc = bh_fold_site(&bh_sites[i]);
        if (rc)
            return rc;
    }
    return 0;
}

static int bh_base_load(const char *path)
{
    char full[BH_PATH], line[BH_LLINE];
    if (bh_path(full, sizeof full, path))
        return 2;
    memset(&bh_base, 0, sizeof bh_base);
    bln_load(&bh_base, full);
    bh_nbase = 0;
    FILE *f = fopen(full, "r");
    if (!f)
        return 0; /* missing baseline: empty, same as the shell original */
    while (fgets(line, sizeof line, f)) {
        char *h = strchr(line, '#');
        if (h)
            *h = '\0';
        char *p = line;
        while (*p == ' ' || *p == '\t' || *p == '\n')
            p++;
        char *e = p + strlen(p);
        while (e > p && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\n'))
            e--;
        *e = '\0';
        if (!*p)
            continue;
        if (bh_nbase >= BH_BASE || strlen(p) >= BH_IDLEN)
            return 2;
        strcpy(bh_base_ids[bh_nbase++], p);
    }
    fclose(f);
    return 0;
}

static int bh_best_remedy(const char *id)
{
    int best = -1;
    size_t bestlen = 0;
    for (int i = 0; i < bh_nremedy; i++) {
        const char *p = bh_remedy[i].id;
        if (strcmp(p, id) == 0)
            return i;
        if (strchr(p, '*') && fnmatch(p, id, 0) == 0 && strlen(p) > bestlen) {
            best = i;
            bestlen = strlen(p);
        }
    }
    return best;
}

static int bh_best_decide(const char *id)
{
    int best = -1;
    size_t bestlen = 0;
    for (int i = 0; i < bh_ndecide; i++) {
        const char *p = bh_decide[i];
        if (strcmp(p, id) == 0)
            return i;
        if (strchr(p, '*') && fnmatch(p, id, 0) == 0 && strlen(p) > bestlen) {
            best = i;
            bestlen = strlen(p);
        }
    }
    return best;
}

static int bh_add_viol(const char *id, const char *loc, const char *tail)
{
    if (bh_nviol >= BH_LST)
        return 2;
    struct bh_viol *v = &bh_viol[bh_nviol];
    if (strlen(id) >= sizeof v->id)
        return 2;
    if (ovf(snprintf(v->msg, sizeof v->msg, "%s  (%s) — %s", id, loc, tail),
            sizeof v->msg))
        return 2;
    strcpy(v->id, id);
    bh_nviol++;
    return 0;
}

static int bh_classify_id(int i)
{
    const char *id = bh_ee[i].id;
    int ri = bh_best_remedy(id);
    if (ri >= 0 && strcmp(bh_remedy[ri].head, "OWNER") != 0) {
        bh_n_auto++;
        return 0;
    }
    if (bh_best_decide(id) >= 0) {
        bh_n_declared++;
        return 0;
    }
    for (int b = 0; b < bh_nbase; b++)
        if (strcmp(bh_base_ids[b], id) == 0) {
            bh_base_hit[b] = 1;
            if (bh_ntol < BH_LST)
                strcpy(bh_tol[bh_ntol++], id);
            return 0;
        }
    if (ri < 0) {
        char tail[BH_LLINE];
        if (ovf(snprintf(tail, sizeof tail,
                         "empty escape_action, NO row in %s", bh_cfg_remedy),
                sizeof tail))
            return 2;
        return bh_add_viol(id, bh_ee[i].loc, tail);
    }
    return bh_add_viol(id, bh_ee[i].loc,
                       "empty escape_action, bound OWNER, no "
                       "ZCL_BLOCKER_DECISION row");
}

static int bh_classify(void)
{
    for (int i = 0; i < bh_nee; i++) {
        int rc = bh_classify_id(i);
        if (rc)
            return rc;
    }
    for (int b = 0; b < bh_nbase; b++)
        if (!bh_base_hit[b] && bh_nstale < BH_LST)
            strcpy(bh_stale[bh_nstale++], bh_base_ids[b]);
    return 0;
}

static void bh_sort_print(FILE *out, const char *const *ptrs, int n,
                          const char *pre)
{
    qsort((void *)ptrs, (size_t)n, sizeof *ptrs, lintc_strcmp_ptr);
    for (int i = 0; i < n; i++)
        fprintf(out, "%s%s\n", pre, ptrs[i]);
}

static void bh_print_fix(FILE *out)
{
    fprintf(out,
            "\n"
            "  Fix ONE of:\n"
            "   1. Bind it to a real auto-remedy in %s\n"
            "      (a condition-engine healer name, or ESCAPE(<registered action>)).\n"
            "   2. Keep it OWNER and add a ZCL_BLOCKER_DECISION row to\n"
            "      %s stating the\n"
            "      decision the operator owns and the tradeoff between the options.\n"
            "      An honest 'a person must choose between X and Y' is a CORRECT\n"
            "      outcome — do not invent a risky automatic repair, especially for\n"
            "      anything that would mutate consensus state.\n"
            "   3. Arm a real escape_action at the raise site (must resolve to a\n"
            "      blocker_register_escape(...) registration — check-blocker-escape-\n"
            "      registered enforces that).\n"
            "  Adding a line to %s is NOT a fix; that file may only shrink.\n",
            bh_cfg_remedy, bh_cfg_decision, bh_cfg_baseline);
}

static int bh_report(FILE *out)
{
    const char *mode = env_or("ZCL_LINT_MODE", "FAIL");
    int fail = 0;
    if (bh_nviol > 0) {
        const char *ptrs[BH_LST];
        fprintf(out, "\n[%s] %d blocker id(s) can be raised with an empty "
                "escape action\n        and carry neither an automatic remedy "
                "nor a human-decision marker:\n",
                k_bhd_gate, bh_nviol);
        for (int i = 0; i < bh_nviol; i++)
            ptrs[i] = bh_viol[i].msg;
        bh_sort_print(out, ptrs, bh_nviol, "  ");
        bh_print_fix(out);
        fail = 1;
    }
    if (bh_nstale > 0) {
        const char *ptrs[BH_LST];
        fprintf(out, "\n[%s] %d STALE baseline entry(ies) — no longer "
                "raisable with an\n        empty, undeclared hand-off. "
                "Delete them from %s:\n",
                k_bhd_gate, bh_nstale, bh_cfg_baseline);
        for (int i = 0; i < bh_nstale; i++)
            ptrs[i] = bh_stale[i];
        bh_sort_print(out, ptrs, bh_nstale, "  ");
        fail = 1;
    }
    if (fail && strcmp(mode, "FAIL") == 0)
        return 1;
    fprintf(out,
            "[%s] PASS (%d files, %d raise site(s), %d id(s) raisable with an "
            "empty escape action: %d auto-remedied, %d decision-declared, "
            "%d baselined of %d)\n",
            k_bhd_gate, bh_nfiles, bh_nsites, bh_nee, bh_n_auto,
            bh_n_declared, bh_ntol, bh_nbase);
    return 0;
}

static int bh_update_baseline(const char *path, FILE *out)
{
    char full[BH_PATH];
    const char *ids[BH_LST * 2];
    int n = 0;
    if (bh_path(full, sizeof full, path))
        return 2;
    for (int i = 0; i < bh_ntol; i++)
        ids[n++] = bh_tol[i];
    for (int i = 0; i < bh_nviol; i++)
        ids[n++] = bh_viol[i].id;
    qsort((void *)ids, (size_t)n, sizeof *ids, lintc_strcmp_ptr);
    FILE *f = fopen(full, "w");
    if (!f) {
        fprintf(stderr, "%s: cannot write baseline %s\n", k_bhd_gate, path);
        return 2;
    }
    fprintf(f,
            "# %s baseline — ids raisable with an EMPTY escape_action that are\n"
            "# bound OWNER with no ZCL_BLOCKER_DECISION row yet. SHRINK ONLY.\n"
            "# Regenerate: ZCL_LINT_MODE=UPDATE build/bin/z23-lint "
            "check-blocker-handoff-declared\n",
            k_bhd_gate);
    for (int i = 0; i < n; i++)
        if (i == 0 || strcmp(ids[i], ids[i - 1]) != 0)
            fprintf(f, "%s\n", ids[i]);
    fclose(f);
    fprintf(out, "[%s] baseline UPDATED: %s\n", k_bhd_gate, path);
    return 0;
}

static int bh_stage_paths(const char *root, FILE *err)
{
    char r[BH_PATH], d[BH_PATH], b[BH_PATH];
    (void)root;
    bh_cfg_remedy = env_or("ZCL_BLOCKER_HANDOFF_REMEDY_TABLE",
                           "engine/conditions/include/conditions/"
                           "blocker_remedy_bindings.def");
    bh_cfg_decision = env_or("ZCL_BLOCKER_HANDOFF_DECISION_TABLE",
                             "engine/conditions/include/conditions/"
                             "blocker_operator_decisions.def");
    bh_cfg_baseline = env_or("ZCL_BLOCKER_HANDOFF_BASELINE",
                             "tools/lint/blocker_handoff_baseline.txt");
    if (bh_path(r, sizeof r, bh_cfg_remedy) ||
        bh_path(d, sizeof d, bh_cfg_decision) ||
        bh_path(b, sizeof b, bh_cfg_baseline))
        return 2;
    if (!bh_exists(r)) {
        fprintf(err, "%s: FATAL — missing %s\n", k_bhd_gate, bh_cfg_remedy);
        return 2;
    }
    if (!bh_exists(d)) {
        fprintf(err, "%s: FATAL — missing %s\n", k_bhd_gate, bh_cfg_decision);
        return 2;
    }
    return 0;
}

static int bh_load_table_kind(int kind)
{
    char path[BH_PATH];
    const char *cfg = kind ? bh_cfg_decision : bh_cfg_remedy;
    if (bh_path(path, sizeof path, cfg))
        return 2;
    return bh_load_table(path, kind);
}

static int bh_stage_tables(FILE *err)
{
    if (bh_load_table_kind(0))
        return 2;
    if (bh_floor(err, bh_nremedy,
                 atoi(env_or("ZCL_BLOCKER_HANDOFF_REMEDY_FLOOR", "80")),
                 "parsed too few ZCL_BLOCKER_REMEDY rows"))
        return 2;
    if (bh_load_table_kind(1))
        return 2;
    return bh_floor(err, bh_ndecide,
                    atoi(env_or("ZCL_BLOCKER_HANDOFF_DECISION_FLOOR", "1")),
                    "parsed zero ZCL_BLOCKER_DECISION rows");
}

int bhd_run_gate(const char *root, FILE *out, FILE *err)
{
    bh_reset();
    bh_nremedy = bh_ndecide = bh_nee = bh_nbase = 0;
    bh_nviol = bh_ntol = bh_nstale = 0;
    bh_n_auto = bh_n_declared = 0;
    memset(bh_base_hit, 0, sizeof bh_base_hit);
    if (bh_set_root(root) || bh_stage_paths(root, err))
        return 2;
    const char *roots = env_or("ZCL_BLOCKER_HANDOFF_SCAN_ROOTS",
                               "core engine contexts cognition platform");
    if (bh_collect_files(roots))
        return 2;
    if (bh_floor(err, bh_nfiles,
                 atoi(env_or("ZCL_BLOCKER_HANDOFF_FILE_FLOOR", "200")),
                 "no production .c/.h under: core engine contexts cognition platform"))
        return 2;
    if (bh_wrapper_check(err))
        return 2;
    if (bh_scan_all())
        return 2;
    if (bh_floor(err, bh_nsites,
                 atoi(env_or("ZCL_BLOCKER_HANDOFF_SITE_FLOOR", "100")),
                 "raise-site extraction collapsed — the awk pass matched "
                 "almost nothing"))
        return 2;
    if (bh_stage_tables(err))
        return 2;
    if (bh_fold())
        return 2;
    if (bh_base_load(bh_cfg_baseline))
        return 2;
    if (bh_classify())
        return 2;
    if (strcmp(env_or("ZCL_LINT_MODE", "FAIL"), "UPDATE") == 0)
        return bh_update_baseline(bh_cfg_baseline, out);
    return bh_report(out);
}

int check_blocker_handoff_declared_run(int argc, char **argv)
{
    const char *root = argc >= 1 ? argv[0] : ".";
    return bhd_run_gate(root, stdout, stderr);
}
