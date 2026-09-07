/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: C23 lint gate — check-byte-order-codec-single. Port of
 * tools/lint/check_byte_order_codec_single.sh: loading or storing a
 * 16/32/64-bit integer at a byte address in a declared byte order must
 * live in exactly one place (platform/modules/base/include/base/
 * serialize_le.h). Any other production .c/.h that hand-rolls the shift
 * ladder, the unrolled form, or a byte-swap mask is a violation, at file
 * granularity, against a shrink-only baseline
 * (tools/lint/byte_order_codec_baseline.txt). A coverage check compares
 * the realized filesystem scan against an independent git-index-derived
 * expectation so a scan that silently lost roots is UNPROVEN, never a
 * quiet pass.
 *
 * Single-gate family file (new port, 2026-09-07); selftest lives in the
 * sibling gate_byte_order_codec_single_selftest.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <fnmatch.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "gate_byte_order_codec_single_priv.h"

/* An indexed shift loop: a right or left shift by 8 (optionally 8u) times
 * a loop index, in either operand order. */
static const char k_bo_re_loop[] =
    "(>>|<<) *\\( *8u? *\\* *[a-z_][a-z_0-9]* *\\)|"
    "(>>|<<) *\\( *[a-z_][a-z_0-9]* *\\* *8u? *\\)";
/* An unrolled ladder: a top-byte shift AND a byte-array subscript, same
 * line. Split from the shell's single alternation so the GNU word-boundary token after
 * "(24|56)" in its FIRST arm becomes an explicit trailing-boundary check
 * (bo_flat_a) while its second arm keeps no boundary at all (bo_flat_b),
 * exactly reproducing the two different behaviors under one name. */
static const char k_bo_re_flat_a[] = "\\[[^]]*\\][^;]*(>>|<<) *(24|56)";
static const char k_bo_re_flat_b[] = "(>>|<<) *(24|56)[^;]*\\[[^]]*\\]";
/* A hand-rolled byte swap. Each mask literal is split across an adjacent
 * string-literal line break (the compiler concatenates them back to the
 * exact intended pattern) so this constant's own source text never carries
 * one of the four masks it detects — otherwise this gate would flag its
 * own detector definition when it scans tools/. */
static const char k_bo_re_bswap[] =
    "0x00FF00"
    "FF|0x00ff00"
    "ff|0x00FF0000"
    "00FF0000"
    "|0xFF00FF00"
    "FF00FF00";

static const char *const k_bo_excl[BO_NEXCL] = {
    "platform/modules/base/", "contexts/commons/packages/",
    "tests/harness/include/test/"
};
static const char *const k_bo_extra_roots[3] = {
    "engine/composition", "engine/entry", "tools"
};

int bo_excluded(const char *path)
{
    for (int i = 0; i < BO_NEXCL; i++) {
        size_t n = strlen(k_bo_excl[i]);
        if (strncmp(path, k_bo_excl[i], n) == 0)
            return 1;
    }
    return 0;
}

/* SCAN_ROOTS_DEFAULT: every existing app authority/shape room, every
 * physical lib module directory, plus the three fixed extras. */
int bo_default_roots(char out[][RS_PATH], int max, int *n)
{
    *n = 0;
    int rc = repo_shape_dirs("app", "", out, max, n);
    if (rc)
        return rc;
    int napp = *n;
    char libs[RS_MAX][RS_PATH];
    int nlib = 0;
    rc = repo_shape_dirs("lib", "", libs, RS_MAX, &nlib);
    if (rc)
        return rc;
    for (int i = 0; i < nlib; i++) {
        if (napp + i >= max)
            return die("z23-lint: byte-order-codec root set overflow\n", "");
        memcpy(out[napp + i], libs[i], strlen(libs[i]) + 1);
    }
    *n = napp + nlib;
    for (int i = 0; i < 3; i++) {
        if (*n >= max)
            return die("z23-lint: byte-order-codec root set overflow\n", "");
        memcpy(out[*n], k_bo_extra_roots[i], strlen(k_bo_extra_roots[i]) + 1);
        (*n)++;
    }
    return 0;
}

int bo_split_ws(const char *s, char out[][RS_PATH], int max, int *n)
{
    *n = 0;
    const char *p = s;
    while (*p) {
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        const char *start = p;
        while (*p && *p != ' ' && *p != '\t')
            p++;
        size_t len = (size_t)(p - start);
        if (*n >= max || len >= RS_PATH)
            return die("z23-lint: byte-order-codec root set overflow\n", "");
        memcpy(out[*n], start, len);
        out[*n][len] = '\0';
        (*n)++;
    }
    return 0;
}

int bo_comp_regexes(struct bo_regexes *r)
{
    int rc = pair_comp(&r->loop, REG_EXTENDED, k_bo_re_loop, "", "", "",
                       &r->bswap, REG_EXTENDED, k_bo_re_bswap, "", "", "");
    if (rc)
        return rc;
    rc = pair_comp(&r->flat_a, REG_EXTENDED, k_bo_re_flat_a, "", "", "",
                   &r->flat_b, REG_EXTENDED, k_bo_re_flat_b, "", "", "");
    if (rc) {
        drop2(&r->loop, &r->bswap);
        return rc;
    }
    return 0;
}

void bo_drop_regexes(struct bo_regexes *r)
{
    drop2(&r->loop, &r->bswap);
    drop2(&r->flat_a, &r->flat_b);
}

static int bo_ident(unsigned char c)
{
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z')
        || (c >= 'a' && c <= 'z') || c == '_';
}

/* flat_a alone carries the shell's trailing word-boundary token after
 * "(24|56)": reject a match whose next byte is still an identifier byte
 * (so "240" is not mistaken for a top-byte shift by "24"). */
static int bo_flat_a_hit(const regex_t *re, const char *line)
{
    size_t off = 0;
    for (;;) {
        regmatch_t m;
        int flags = off ? REG_NOTBOL : 0;
        if (regexec(re, line + off, 1, &m, flags) != 0)
            return 0;
        m.rm_eo += (regoff_t)off;
        if (!bo_ident((unsigned char)line[m.rm_eo]))
            return 1;
        size_t nxt = (size_t)m.rm_eo;
        if (nxt <= off)
            nxt = off + 1;
        off = nxt;
        if (line[off] == '\0')
            return 0;
    }
}

int bo_line_hits(const struct bo_regexes *r, const char *line)
{
    return regexec(&r->loop, line, 0, NULL, 0) == 0
        || regexec(&r->bswap, line, 0, NULL, 0) == 0
        || bo_flat_a_hit(&r->flat_a, line)
        || regexec(&r->flat_b, line, 0, NULL, 0) == 0;
}

/* A file already named by the directory walk that this process cannot
 * open is UNPROVEN, never a silent "no match". */
int bo_detect_file(const char *path, const struct bo_regexes *r, int *hit)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    *hit = 0;
    while (!*hit && (n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (bo_line_hits(r, line))
            *hit = 1;
    }
    return fin(f, line, path, 0);
}

struct bo_collect_ctx {
    struct bo_pathset *set;
};

static int bo_collect_cb(const char *path, void *vctx)
{
    struct bo_collect_ctx *ctx = vctx;
    if (bo_excluded(path))
        return 0;
    return bo_pathset_add(ctx->set, path);
}

int bo_collect(const char roots[][RS_PATH], int nroots, struct bo_pathset *set)
{
    set->n = 0;
    struct bo_collect_ctx ctx = { .set = set };
    int rc = 0;
    for (int i = 0; rc == 0 && i < nroots; i++)
        rc = walk_src(roots[i], 1, bo_collect_cb, &ctx);
    return rc;
}

int bo_pathset_add(struct bo_pathset *set, const char *path)
{
    size_t n = strlen(path);
    if (set->n >= BO_SET_MAX || n >= RS_PATH)
        return die("z23-lint: byte-order-codec scan set overflow\n", "");
    memcpy(set->p[set->n++], path, n + 1);
    return 0;
}

int bo_pathset_has(const struct bo_pathset *set, const char *path)
{
    for (int i = 0; i < set->n; i++)
        if (strcmp(set->p[i], path) == 0)
            return 1;
    return 0;
}

static int bo_cmp_str(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

void bo_pathset_sort(struct bo_pathset *set)
{
    if (set->n > 1)
        qsort(set->p, (size_t)set->n, RS_PATH, bo_cmp_str);
}

int bo_find_hits(const struct bo_pathset *scan, const struct bo_regexes *r,
                struct bo_pathset *found)
{
    found->n = 0;
    for (int i = 0; i < scan->n; i++) {
        int hit = 0;
        int rc = bo_detect_file(scan->p[i], r, &hit);
        if (rc)
            return rc;
        if (hit) {
            int arc = bo_pathset_add(found, scan->p[i]);
            if (arc)
                return arc;
        }
    }
    return 0;
}

/* The exact "git ls-files -- <pathspecs>" text the shell original ran for
 * its coverage oracle (SCAN_ROOTS_DEFAULT's per-root .c/.h globs, then
 * the three ":!:"-prefixed carve-outs) — reproduced here only so an
 * UNPROVEN "could not run" message names the same pathspec set the shell
 * gate printed, when the native index reader fails (e.g. no .git at all,
 * as in a git-archive sandbox). */
int bo_pathspec_msg(const char roots[][RS_PATH], int nroots, char *out,
                    size_t cap)
{
    size_t used = 0;
    out[0] = '\0';
    for (int i = 0; i < nroots; i++) {
        int n = snprintf(out + used, cap - used, "%s%s/*.c %s/*.h",
                         i ? " " : "", roots[i], roots[i]);
        if (n < 0 || used + (size_t)n >= cap)
            return die("z23-lint: byte-order-codec pathspec overflow\n", "");
        used += (size_t)n;
    }
    for (int i = 0; i < BO_NEXCL; i++) {
        int n = snprintf(out + used, cap - used, " :!:%s*", k_bo_excl[i]);
        if (n < 0 || used + (size_t)n >= cap)
            return die("z23-lint: byte-order-codec pathspec overflow\n", "");
        used += (size_t)n;
    }
    return 0;
}
