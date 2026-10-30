/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: phase 4 of check-read-leaf-no-boot-ceremony -- reverse taint
 * closure over the function index, per-READ-leaf verdict against the
 * banned boot-ceremony symbols, shrink-only baseline handling, and the
 * exact report blocks of the deleted shell gate (violations, stale
 * baseline entries, unresolved-handler note).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "gate_read_leaf_no_boot_ceremony_priv.h"

static int rlb_taintv[RLB_FNS + RLB_NBAN];
static int rlb_order[RLB_FNS];
static const struct rlb_fnidx *rlb_fig;

struct rlb_bline {
    char path[256];
    char sym[128];
    int hit;
};

struct rlb_vrow {
    char leaf[256];
    char sym[128];
    char chain[RLB_CHAIN];
    char file[256];
    int line;
};

static struct rlb_bline rlb_base[RLB_BASE];
static int rlb_nbase;
static struct rlb_vrow rlb_viol[RLB_VIOL];
static int rlb_nviol, rlb_nviol_tot;
static char rlb_unres[RLB_READS * 320];
static size_t rlb_unres_len;
static int g_resolved, g_unresolved, g_ngrand, g_nstale;

static const char *rlb_name(const struct rlb_fnidx *fi, int idx)
{
    return idx < fi->n ? fi->v[idx].name : rlb_banned[idx - fi->n];
}

static int rlb_cmp_idx(const void *a, const void *b)
{
    return strcmp(rlb_fig->v[*(const int *)a].name,
                  rlb_fig->v[*(const int *)b].name);
}

static int rlb_cmp_name(const void *key, const void *elem)
{
    return strcmp((const char *)key, rlb_fig->v[*(const int *)elem].name);
}

/* Banned names win over any same-named defined function, as the awk
 * TAINT seed did. Unresolved names return -1. */
static int rlb_find(const struct rlb_fnidx *fi, const char *name)
{
    for (int k = 0; k < RLB_NBAN; k++)
        if (!strcmp(name, rlb_banned[k]))
            return fi->n + k;
    int *p = bsearch(name, rlb_order, (size_t)fi->n, sizeof rlb_order[0],
                     rlb_cmp_name);
    return p ? *p : -1;
}

static int rlb_isblank(char c)
{
    return c == ' ' || c == '\t';
}

/* Next blank-separated token of s from *p. 0 at the end, or when the token
 * does not fit cap (callers size cap above every token they can see). */
static int rlb_tok(const char *s, size_t *p, char *out, size_t cap)
{
    while (rlb_isblank(s[*p]))
        (*p)++;
    if (!s[*p]) {
        out[0] = '\0';
        return 0;
    }
    size_t o = 0;
    while (s[*p] && !rlb_isblank(s[*p])) {
        if (o + 1 >= cap)
            return 0;
        out[o++] = s[(*p)++];
    }
    out[o] = '\0';
    return 1;
}

static int rlb_taint_step(const struct rlb_fnidx *fi, int i)
{
    if (rlb_taintv[i] >= 0)
        return 0;
    const char *s = fi->pool + fi->v[i].off;
    char tok[192];
    size_t p = 0;
    while (rlb_tok(s, &p, tok, sizeof tok)) {
        if (!tok[0] || !strcmp(tok, fi->v[i].name))
            continue;
        int j = rlb_find(fi, tok);
        if (j >= 0 && rlb_taintv[j] >= 0) {
            rlb_taintv[i] = j;
            return 1;
        }
    }
    return 0;
}

static int rlb_taint_run(const struct rlb_fnidx *fi)
{
    for (int i = 0; i < fi->n; i++)
        rlb_taintv[i] = -1;
    for (int k = 0; k < RLB_NBAN; k++)
        rlb_taintv[fi->n + k] = fi->n + k;
    int changed = 1, rounds = 0;
    while (changed && rounds < 128) {
        changed = 0;
        rounds++;
        for (int i = 0; i < fi->n; i++)
            if (rlb_taint_step(fi, i))
                changed = 1;
    }
    return rounds < 128;
}

/* A baseline line is `<leaf> <symbol>`: the first token is the key and the
 * second is the symbol. Any later token is ignored, as awk's split did. */
static int rlb_tokens(const char *line, char *key, char *val)
{
    size_t p = 0;
    char tok[256];
    key[0] = val[0] = '\0';
    if (rlb_tok(line, &p, tok, sizeof tok) &&
        ovf(snprintf(key, 256, "%s", tok), 256))
        return 2;
    if (rlb_tok(line, &p, tok, sizeof tok) &&
        ovf(snprintf(val, 256, "%s", tok), 256))
        return 2;
    return 0;
}

static int rlb_base_load(const char *path)
{
    rlb_nbase = 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char line[RLB_LINE], buf[RLB_LINE], key[256], val[256];
    while (fgets(line, sizeof line, f)) {
        char *h = strchr(line, '#');
        if (h)
            *h = '\0';
        if (rlb_trim(buf, sizeof buf, line))
            return 2;
        if (!buf[0])
            continue;
        if (rlb_tokens(buf, key, val))
            return 2;
        if (!key[0])
            continue;
        if (rlb_nbase >= RLB_BASE) {
            fclose(f);
            fprintf(stderr, "%s: baseline entries exceed %d\n", RLB_GATE,
                    RLB_BASE);
            return 2;
        }
        struct rlb_bline *b = &rlb_base[rlb_nbase++];
        if (ovf(snprintf(b->path, sizeof b->path, "%s", key),
                sizeof b->path) ||
            ovf(snprintf(b->sym, sizeof b->sym, "%s", val), sizeof b->sym))
            return 2;
        b->hit = 0;
    }
    fclose(f);
    return 0;
}

static int rlb_base_hit(const char *path, const char *sym)
{
    for (int b = 0; b < rlb_nbase; b++)
        if (!strcmp(rlb_base[b].path, path) && !strcmp(rlb_base[b].sym, sym)) {
            rlb_base[b].hit = 1;
            return 1;
        }
    return 0;
}

static int rlb_chain(const struct rlb_fnidx *fi, int h, char *chain,
                     char *sym, size_t scap)
{
    int cur = h, hops = 0;
    chain[0] = '\0';
    if (ovf(snprintf(chain, RLB_CHAIN, "%s", rlb_name(fi, cur)), RLB_CHAIN))
        return 2;
    while (rlb_taintv[cur] != cur && rlb_taintv[cur] >= 0 && hops < 64) {
        cur = rlb_taintv[cur];
        size_t l = strlen(chain);
        if (l + strlen(rlb_name(fi, cur)) + 5 >= RLB_CHAIN)
            return 2;
        strcat(chain, " -> ");
        strcat(chain, rlb_name(fi, cur));
        hops++;
    }
    if (ovf(snprintf(sym, scap, "%s", rlb_name(fi, cur)), scap))
        return 2;
    return 0;
}

static int rlb_unres_add(const char *path, const char *handler)
{
    int w = snprintf(rlb_unres + rlb_unres_len,
                     sizeof rlb_unres - rlb_unres_len, "    %s -> %s\n", path,
                     handler);
    if (ovf(w, sizeof rlb_unres - rlb_unres_len))
        return 2;
    rlb_unres_len += (size_t)w;
    return 0;
}

static int rlb_viol_add(const struct rlb_read *r, const char *chain,
                        const char *sym)
{
    rlb_nviol_tot++;
    if (rlb_nviol >= RLB_VIOL) {
        fprintf(stderr, "%s: violation rows exceed %d\n", RLB_GATE,
                RLB_VIOL);
        return 2;
    }
    struct rlb_vrow *v = &rlb_viol[rlb_nviol++];
    if (ovf(snprintf(v->leaf, sizeof v->leaf, "%s", r->path),
            sizeof v->leaf) ||
        ovf(snprintf(v->sym, sizeof v->sym, "%s", sym), sizeof v->sym) ||
        ovf(snprintf(v->chain, sizeof v->chain, "%s", chain),
            sizeof v->chain) ||
        ovf(snprintf(v->file, sizeof v->file, "%s", r->file),
            sizeof v->file))
        return 2;
    v->line = r->line;
    return 0;
}

static int rlb_v4_scan(const struct rlb_readset *rs, const struct rlb_fnidx *fi)
{
    for (int n = 0; n < rs->n; n++) {
        const struct rlb_read *r = &rs->v[n];
        int h = rlb_find(fi, r->handler);
        if (h < 0) {
            g_unresolved++;
            if (rlb_unres_add(r->path, r->handler))
                return 2;
            continue;
        }
        g_resolved++;
        if (rlb_taintv[h] < 0)
            continue;
        char chain[RLB_CHAIN], sym[192];
        if (rlb_chain(fi, h, chain, sym, sizeof sym))
            return 2;
        if (rlb_base_hit(r->path, sym)) {
            g_ngrand++;
            continue;
        }
        if (rlb_viol_add(r, chain, sym))
            return 2;
    }
    for (int b = 0; b < rlb_nbase; b++)
        if (!rlb_base[b].hit)
            g_nstale++;
    return 0;
}

static void rlb_v4_viol_block(FILE *out, const char *baseline)
{
    fprintf(out, "\n%s: %d leaf(s) declared READ reach"
                 " the datadir boot ceremony:\n",
            RLB_GATE, rlb_nviol_tot);
    for (int i = 0; i < rlb_nviol; i++)
        fprintf(out, "  %s:%d: %s reaches %s\n      %s\n", rlb_viol[i].file,
                rlb_viol[i].line, rlb_viol[i].leaf, rlb_viol[i].sym,
                rlb_viol[i].chain);
    fprintf(out,
            "\n"
            "  A READ leaf takes a caller-supplied datadir that DEFAULTS to the\n"
            "  operator's live one. The boot ceremony opens node.db\n"
            "  READWRITE|CREATE, quarantines it on a failed quick_check,\n"
            "  create_schema()s it, migrates it, and DELETEs the\n"
            "  snapshot_staging rows — to whatever datadir the leaf was pointed\n"
            "  at. Route the read through\n"
            "  zcl_native_node_db_open_readonly() / _require_readonly()\n"
            "  (tools/command/native_node_db_ro.c), which is SQLITE_OPEN_READONLY\n"
            "  plus PRAGMA query_only=ON. If the leaf genuinely needs to write,\n"
            "  it is not a READ leaf: redeclare it ZCL_COMMAND_READY_COMMAND.\n"
            "  A known-open violation goes in %s as\n"
            "  '<leaf> <symbol>' with the reason on the same line.\n",
            baseline);
}

static void rlb_v4_stale_block(FILE *out, const char *baseline)
{
    fprintf(out, "\n%s: %d STALE baseline entry(ies)"
                 " — the violation is gone:\n",
            RLB_GATE, g_nstale);
    for (int b = 0; b < rlb_nbase; b++)
        if (!rlb_base[b].hit)
            fprintf(out, "  %s %s\n", rlb_base[b].path, rlb_base[b].sym);
    fprintf(out,
            "  Good: the leaf stopped reaching the ceremony. Delete each line\n"
            "  from %s in the same commit so the ratchet can only shrink.\n",
            baseline);
}

int rlb_verdict(const struct rlb_readset *rs, const struct rlb_fnidx *fi,
                const char *baseline, const char *shown,
                struct rlb_counts *c, FILE *out)
{
    g_resolved = g_unresolved = g_ngrand = g_nstale = 0;
    rlb_nviol = rlb_nviol_tot = 0;
    rlb_unres_len = 0;
    rlb_unres[0] = '\0';
    if (rlb_base_load(baseline))
        return 2;
    rlb_fig = fi;
    for (int i = 0; i < fi->n; i++)
        rlb_order[i] = i;
    qsort(rlb_order, (size_t)fi->n, sizeof rlb_order[0], rlb_cmp_idx);
    if (!rlb_taint_run(fi)) {
        fputs("FATAL\ttaint closure did not reach a fixpoint in 128 rounds\n",
              stderr);
        fprintf(stderr, "%s: FATAL — analysis did not converge.\n", RLB_GATE);
        return 2;
    }
    if (rlb_v4_scan(rs, fi))
        return 2;
    int fail = 0;
    if (rlb_nviol_tot > 0) {
        fail = 1;
        rlb_v4_viol_block(out, shown);
    }
    if (g_nstale > 0) {
        fail = 1;
        rlb_v4_stale_block(out, shown);
    }
    if (g_unresolved > 0) {
        fprintf(out,
                "%s: note — %d READ handler(s)"
                " were not found in the scanned corpus (not gated):\n",
                RLB_GATE, g_unresolved);
        fputc('\n', out);
        fputs(rlb_unres, out);
    }
    c->resolved = g_resolved;
    c->unresolved = g_unresolved;
    c->nviol = rlb_nviol_tot;
    c->ngrand = g_ngrand;
    c->nstale = g_nstale;
    c->nbase = rlb_nbase;
    return fail;
}
