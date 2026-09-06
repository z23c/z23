/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

/*
 * Gates: check-architecture-tree
 * Default landing spot for a FUTURE gate port: a filesystem-tree-walking
 * gate (walk_src/clock_walk/repo_shape_room_dirs) joins gate_tree_walk.c;
 * a git-tracked-enumeration gate (each_zpath/each_zpath_st) joins whichever
 * of gate_git_scan_a.c/gate_git_scan_b.c is currently smaller by wc -l;
 * a proof/landing/receipt-shaped gate joins gate_landing_proof.c; a
 * build-flag/CI-toggle-shaped gate joins gate_build_config.c; only once
 * EVERY existing family is within ~200 lines of the ~1500 cap does a new
 * gate warrant a new family file — name it for its own subject the same
 * way the seven above are named for theirs. This file exists because the
 * eight-check architecture-tree port plus selftest would push
 * gate_git_scan_a.c over the gated 1500-line ceiling.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"

enum { AT_SET = RS_MAX, AT_NAME = RS_NAME, AT_PATH = RS_PATH, AT_HIT = 64 };

static const char *const k_at_roots[] = {
    "AGENTS.md", "CLAUDE.md", "COPYING", "LICENSE", "Makefile", "NOTICE",
    "README.md", ".clangd", ".claude", ".gitattributes", ".github",
    ".gitignore", ".gitmodules", ".grok", ".ignore", "apps", "cognition",
    "contexts", "core", "docs", "engine", "platform", "tests", "tools",
    "vendor"
};
static const char *const k_at_obs[] = {
    "app", "lib", "config", "adapters", "ports", "domain", "application",
    "packages", "src", "examples"
};
static const char *const k_at_reg[] = {
    "source_roots.def", "source_prune_dirs.def"
};
static const char k_at_reg_own[] =
    "cognition/modules/codeindex/include/codeindex/";
static const char k_at_red[] = "(^|/)reducer([^/]*)(/|\\.)";
static const char *const k_at_auth[] = {
    "core", "engine", "cognition", "platform"
};

struct at_set { char n[AT_SET][AT_NAME]; int count; };
struct at_paths { char n[AT_HIT][AT_PATH]; int count; };
struct at_acc {
    struct at_set roots, ctxs, mods, rooms, pairs;
    struct at_paths reg[2], red;
    int obs[10];
    regex_t *redre;
};

static int at_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static void at_sort(struct at_set *s)
{
    if (s->count > 1)
        qsort(s->n, (size_t)s->count, sizeof s->n[0], at_cmp);
}

static int at_has(const struct at_set *s, const char *n)
{
    for (int i = 0; i < s->count; i++)
        if (!strcmp(s->n[i], n))
            return 1;
    return 0;
}

static int at_add(struct at_set *s, const char *n)
{
    size_t len = strlen(n);
    if (at_has(s, n))
        return 0;
    if (s->count >= AT_SET || len >= AT_NAME)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(s->n[s->count++], n, len + 1);
    return 0;
}

static int at_add_path(struct at_paths *s, const char *n)
{
    size_t len = strlen(n);
    for (int i = 0; i < s->count; i++)
        if (!strcmp(s->n[i], n))
            return 0;
    if (s->count >= AT_HIT || len >= AT_PATH)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(s->n[s->count++], n, len + 1);
    return 0;
}

static int at_nf(const char *p)
{
    int n = 1;
    for (; *p; p++)
        if (*p == '/')
            n++;
    return n;
}

static int at_fld(const char *path, int k, char *out, size_t cap)
{
    const char *s = path;
    for (int i = 1; i < k; i++) {
        s = strchr(s, '/');
        if (!s) {
            out[0] = '\0';
            return 0;
        }
        s++;
    }
    const char *e = strchr(s, '/');
    size_t n = e ? (size_t)(e - s) : strlen(s);
    if (n >= cap)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(out, s, n);
    out[n] = '\0';
    return 1;
}

static int at_same(const struct at_set *a, const struct at_set *b)
{
    if (a->count != b->count)
        return 0;
    for (int i = 0; i < a->count; i++)
        if (strcmp(a->n[i], b->n[i]) != 0)
            return 0;
    return 1;
}

static int at_say(FILE *err, const char *s)
{
    if (!err)
        return 0;
    return fputs(s, err) < 0 ? die("z23-lint: write failed\n", "") : 0;
}

static int at_sayf(FILE *err, const char *fmt, const char *a)
{
    if (!err)
        return 0;
    return fprintf(err, fmt, a) < 0 ? die("z23-lint: write failed\n", "") : 0;
}

static int at_diff(FILE *err, const struct at_set *exp, const struct at_set *act)
{
    int i = 0, j = 0, rc = 0;
    while (rc == 0 && (i < exp->count || j < act->count)) {
        int c;
        if (i >= exp->count)
            c = 1;
        else if (j >= act->count)
            c = -1;
        else
            c = strcmp(exp->n[i], act->n[j]);
        if (c < 0) {
            rc = at_sayf(err, "-%s\n", exp->n[i]);
            i++;
        } else if (c > 0) {
            rc = at_sayf(err, "+%s\n", act->n[j]);
            j++;
        } else {
            i++;
            j++;
        }
    }
    return rc;
}

static int at_room_ok(const char *allowed, const char *room)
{
    size_t n = strlen(room);
    for (const char *p = allowed; *p; ) {
        while (*p == ' ')
            p++;
        if (!*p)
            break;
        const char *s = p;
        while (*p && *p != ' ')
            p++;
        if ((size_t)(p - s) == n && memcmp(s, room, n) == 0)
            return 1;
    }
    return 0;
}

static const char *at_allowed(const char *prefix)
{
    if (!strcmp(prefix, "core"))
        return "chainparams consensus math modules params";
    if (!strcmp(prefix, "engine"))
        return "application composition conditions controllers entry jobs models "
               "modules reducer services supervisors";
    if (!strcmp(prefix, "cognition"))
        return "controllers models modules services";
    if (!strcmp(prefix, "platform"))
        return "adapters deploy domain modules packaging ports";
    if (!strncmp(prefix, "contexts/", 9))
        return "apps conditions controllers corpus domain jobs models modules "
               "packages services supervisors views";
    return "";
}

static int at_feed_room(struct at_acc *a, const char *path, const char *prefix)
{
    size_t n = strlen(prefix);
    if (strncmp(path, prefix, n) != 0 || path[n] != '/')
        return 0;
    const char *rest = path + n + 1;
    const char *sl = strchr(rest, '/');
    if (!sl || rest[0] == '\0')
        return 0;
    char key[AT_NAME];
    int k = snprintf(key, sizeof key, "%s\t%.*s", prefix, (int)(sl - rest), rest);
    if (ovf(k, sizeof key))
        return 2;
    return at_add(&a->rooms, key);
}

static int at_got(int rc, int *out)
{
    if (rc == 2)
        return 2;
    *out = rc;
    return 0;
}

static int at_feed(struct at_acc *a, const char *path)
{
    char s1[AT_NAME], s2[AT_NAME], s3[AT_NAME], s4[AT_NAME], key[AT_NAME];
    int has, rc, nf;
    rc = at_got(at_fld(path, 1, s1, sizeof s1), &has);
    if (rc)
        return rc;
    if (has)
        rc = at_add(&a->roots, s1);
    for (size_t i = 0; rc == 0 && i < sizeof k_at_obs / sizeof k_at_obs[0]; i++) {
        size_t n = strlen(k_at_obs[i]);
        if (!strncmp(path, k_at_obs[i], n) && path[n] == '/')
            a->obs[i] = 1;
    }
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    for (size_t i = 0; rc == 0 && i < sizeof k_at_reg / sizeof k_at_reg[0]; i++)
        if (!strcmp(base, k_at_reg[i]))
            rc = at_add_path(&a->reg[i], path);
    nf = at_nf(path);
    if (rc == 0 && has && !strcmp(s1, "contexts") && nf > 1) {
        rc = at_got(at_fld(path, 2, s2, sizeof s2), &has);
        if (rc == 0 && has)
            rc = at_add(&a->ctxs, s2);
    }
    if (rc == 0 && !strcmp(s1, "contexts") && nf > 3) {
        int h3 = 0, h4 = 0;
        rc = at_got(at_fld(path, 3, s3, sizeof s3), &h3);
        if (rc == 0)
            rc = at_got(at_fld(path, 4, s4, sizeof s4), &h4);
        if (rc == 0 && h3 && h4 && !strcmp(s3, "modules")) {
            rc = at_add(&a->mods, s4);
            if (rc == 0 && ovf(snprintf(key, sizeof key, "%s/%s/%s\t%s",
                                        s1, s2, s3, s4), sizeof key))
                rc = 2;
            else if (rc == 0)
                rc = at_add(&a->pairs, key);
        }
    }
    if (rc == 0) {
        int auth = 0;
        for (size_t i = 0; i < sizeof k_at_auth / sizeof k_at_auth[0]; i++)
            if (!strcmp(s1, k_at_auth[i]))
                auth = 1;
        if (auth && nf > 2) {
            int h2 = 0, h3 = 0;
            rc = at_got(at_fld(path, 2, s2, sizeof s2), &h2);
            if (rc == 0)
                rc = at_got(at_fld(path, 3, s3, sizeof s3), &h3);
            if (rc == 0 && h2 && h3 && !strcmp(s2, "modules")) {
                rc = at_add(&a->mods, s3);
                if (rc == 0 && ovf(snprintf(key, sizeof key, "%s/%s\t%s",
                                            s1, s2, s3), sizeof key))
                    rc = 2;
                else if (rc == 0)
                    rc = at_add(&a->pairs, key);
            }
        }
    }
    if (rc == 0)
        rc = at_feed_room(a, path, "core");
    if (rc == 0)
        rc = at_feed_room(a, path, "engine");
    if (rc == 0)
        rc = at_feed_room(a, path, "cognition");
    if (rc == 0)
        rc = at_feed_room(a, path, "platform");
    for (int i = 0; rc == 0 && i < g_n_ctx; i++) {
        char pfx[AT_NAME];
        if (ovf(snprintf(pfx, sizeof pfx, "contexts/%s", g_ctx[i]), sizeof pfx))
            return 2;
        rc = at_feed_room(a, path, pfx);
    }
    if (rc == 0 && a->redre && !strcmp(s1, "engine")) {
        int h2 = 0;
        rc = at_got(at_fld(path, 2, s2, sizeof s2), &h2);
        if (rc == 0 && h2 && strcmp(s2, "reducer") != 0
            && regexec(a->redre, path, 0, NULL, 0) == 0)
            rc = at_add_path(&a->red, path);
    }
    return rc;
}

static int at_on_path(const char *path, void *ctx)
{
    return at_feed(ctx, path);
}

static int at_fill_exp(struct at_set *s, const char *const *v, size_t n)
{
    int rc = 0;
    s->count = 0;
    for (size_t i = 0; rc == 0 && i < n; i++)
        rc = at_add(s, v[i]);
    at_sort(s);
    return rc;
}

static int at_fill_g(struct at_set *s, char src[][RS_NAME], int n)
{
    int rc = 0;
    s->count = 0;
    for (int i = 0; rc == 0 && i < n; i++)
        rc = at_add(s, src[i]);
    at_sort(s);
    return rc;
}

static int at_check_roots(struct at_acc *a, FILE *err, int *fail)
{
    struct at_set exp = {0};
    int rc = at_fill_exp(&exp, k_at_roots, sizeof k_at_roots / sizeof k_at_roots[0]);
    at_sort(&a->roots);
    if (rc || at_same(&exp, &a->roots))
        return rc;
    *fail = 1;
    rc = at_say(err, "check-architecture-tree: root entries differ from the declared set\n");
    if (rc == 0)
        rc = at_say(err, "check-architecture-tree: place the new entry under its owning authority,\n");
    if (rc == 0)
        rc = at_say(err, "check-architecture-tree: or declare it in tools/lint/check_architecture_tree.sh\n");
    if (rc == 0)
        rc = at_diff(err, &exp, &a->roots);
    return rc;
}

static int at_check_obs(struct at_acc *a, FILE *err, int *fail)
{
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < sizeof k_at_obs / sizeof k_at_obs[0]; i++) {
        if (!a->obs[i])
            continue;
        *fail = 1;
        char msg[80];
        if (ovf(snprintf(msg, sizeof msg,
                         "check-architecture-tree: obsolete root still tracked: %s/\n",
                         k_at_obs[i]), sizeof msg))
            return 2;
        rc = at_say(err, msg);
    }
    return rc;
}

static int at_check_reg(struct at_acc *a, FILE *err, int *fail)
{
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < sizeof k_at_reg / sizeof k_at_reg[0]; i++) {
        char want[AT_PATH];
        if (ovf(snprintf(want, sizeof want, "%s%s", k_at_reg_own, k_at_reg[i]),
                sizeof want))
            return 2;
        if (a->reg[i].count == 1 && !strcmp(a->reg[i].n[0], want))
            continue;
        *fail = 1;
        rc = at_sayf(err,
                     "check-architecture-tree: %s must have one codeindex owner: ",
                     k_at_reg[i]);
        if (rc == 0)
            rc = at_sayf(err, "%s\n", want);
        for (int j = 0; rc == 0 && j < a->reg[i].count; j++)
            rc = at_sayf(err, "%s\n", a->reg[i].n[j]);
    }
    return rc;
}

static int at_check_ctx(struct at_acc *a, FILE *err, int *fail)
{
    struct at_set exp = {0};
    int rc = at_fill_g(&exp, g_ctx, g_n_ctx);
    at_sort(&a->ctxs);
    if (rc || at_same(&exp, &a->ctxs))
        return rc;
    *fail = 1;
    rc = at_say(err, "check-architecture-tree: contexts/ differs from PRODUCT_CONTEXTS\n");
    if (rc == 0)
        rc = at_diff(err, &exp, &a->ctxs);
    return rc;
}

static int at_check_mods(struct at_acc *a, FILE *err, int *fail)
{
    struct at_set exp = {0};
    int rc = at_fill_g(&exp, g_libs, g_n_libs);
    at_sort(&a->mods);
    if (rc || at_same(&exp, &a->mods))
        return rc;
    *fail = 1;
    rc = at_say(err, "check-architecture-tree: physical modules differ from the module declaration\n");
    if (rc == 0)
        rc = at_diff(err, &exp, &a->mods);
    return rc;
}

static int at_check_dups(struct at_acc *a, FILE *err, int *fail)
{
    struct at_set dups = {0};
    int rc = 0;
    for (int i = 0; rc == 0 && i < a->pairs.count; i++) {
        const char *tab = strchr(a->pairs.n[i], '\t');
        if (!tab)
            continue;
        const char *mod = tab + 1;
        int owners = 0;
        for (int j = 0; j < a->pairs.count; j++) {
            const char *t2 = strchr(a->pairs.n[j], '\t');
            if (t2 && !strcmp(t2 + 1, mod))
                owners++;
        }
        if (owners > 1)
            rc = at_add(&dups, mod);
    }
    if (rc || !dups.count)
        return rc;
    *fail = 1;
    at_sort(&dups);
    rc = at_say(err, "check-architecture-tree: module has more than one physical owner:\n");
    for (int i = 0; rc == 0 && i < dups.count; i++)
        rc = at_sayf(err, "%s\n", dups.n[i]);
    return rc;
}

static int at_check_rooms(struct at_acc *a, FILE *err, int *fail)
{
    int rc = 0;
    at_sort(&a->rooms);
    for (int i = 0; rc == 0 && i < a->rooms.count; i++) {
        char prefix[AT_NAME], room[AT_NAME];
        const char *tab = strchr(a->rooms.n[i], '\t');
        if (!tab)
            continue;
        size_t pn = (size_t)(tab - a->rooms.n[i]);
        if (pn >= sizeof prefix || strlen(tab + 1) >= sizeof room)
            return die("z23-lint: derived buffer overflow\n", "");
        memcpy(prefix, a->rooms.n[i], pn);
        prefix[pn] = '\0';
        memcpy(room, tab + 1, strlen(tab + 1) + 1);
        if (at_room_ok(at_allowed(prefix), room))
            continue;
        *fail = 1;
        char msg[192];
        if (ovf(snprintf(msg, sizeof msg,
                         "check-architecture-tree: %s/%s has no declared room shape\n",
                         prefix, room), sizeof msg))
            return 2;
        rc = at_say(err, msg);
    }
    return rc;
}

static int at_check_red(struct at_acc *a, FILE *err, int *fail)
{
    if (!a->red.count)
        return 0;
    *fail = 1;
    int rc = at_say(err, "check-architecture-tree: reducer-owned path escaped engine/reducer/:\n");
    for (int i = 0; rc == 0 && i < a->red.count; i++)
        rc = at_sayf(err, "%s\n", a->red.n[i]);
    return rc;
}

static int at_eval(struct at_acc *a, FILE *err, int *fail)
{
    int rc = at_check_roots(a, err, fail);
    if (rc == 0)
        rc = at_check_obs(a, err, fail);
    if (rc == 0)
        rc = at_check_reg(a, err, fail);
    if (rc == 0)
        rc = at_check_ctx(a, err, fail);
    if (rc == 0)
        rc = at_check_mods(a, err, fail);
    if (rc == 0)
        rc = at_check_dups(a, err, fail);
    if (rc == 0)
        rc = at_check_rooms(a, err, fail);
    if (rc == 0)
        rc = at_check_red(a, err, fail);
    return rc;
}

int check_architecture_tree_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    int rc = rs_init();
    if (rc)
        return rc;
    regex_t re;
    rc = reg_fail(&re, regcomp(&re, k_at_red, REG_EXTENDED));
    if (rc)
        return rc;
    struct at_acc a = { .redre = &re };
    rc = each_zpath(k_ls_all, at_on_path, &a);
    int fail = 0;
    if (rc == 0)
        rc = at_eval(&a, stderr, &fail);
    regfree(&re);
    if (rc)
        return rc;
    if (fail)
        return 1;
    return printf("check-architecture-tree: PASS — five authorities, %d contexts, %d single-owner modules\n",
                  g_n_ctx, g_n_libs) < 0
               ? die("z23-lint: write failed\n", "") : 0;
}

static int at_st_chk(struct at_acc *a, int *fail,
                     int (*chk)(struct at_acc *, FILE *, int *), int want)
{
    *fail = 0;
    int rc = chk(a, NULL, fail);
    return rc || (*fail != 0) != (want != 0);
}

int check_architecture_tree_selftest(void)
{
    int rc = rs_init();
    if (rc)
        return rc;
    regex_t re;
    rc = reg_fail(&re, regcomp(&re, k_at_red, REG_EXTENDED));
    if (rc)
        return rc;
    int bad = 0, fail = 0, i;
    struct at_acc a;
    size_t nr = sizeof k_at_roots / sizeof k_at_roots[0];
    memset(&a, 0, sizeof a);
    for (i = 0; i < (int)nr; i++)
        if (at_feed(&a, k_at_roots[i]))
            bad = 1;
    bad |= at_st_chk(&a, &fail, at_check_roots, 0);
    if (at_feed(&a, "extra"))
        bad = 1;
    bad |= at_st_chk(&a, &fail, at_check_roots, 1);
    memset(&a, 0, sizeof a);
    if (at_feed(&a, "app/foo.c"))
        bad = 1;
    bad |= at_st_chk(&a, &fail, at_check_obs, 1);
    memset(&a, 0, sizeof a);
    if (at_feed(&a, "cognition/modules/codeindex/include/codeindex/source_roots.def")
        || at_feed(&a, "cognition/modules/codeindex/include/codeindex/source_prune_dirs.def"))
        bad = 1;
    bad |= at_st_chk(&a, &fail, at_check_reg, 0);
    if (at_feed(&a, "tools/source_roots.def"))
        bad = 1;
    bad |= at_st_chk(&a, &fail, at_check_reg, 1);
    memset(&a, 0, sizeof a);
    for (i = 0; i < g_n_ctx; i++) {
        char p[RS_PATH];
        if (ovf(snprintf(p, sizeof p, "contexts/%s/x.c", g_ctx[i]), sizeof p)
            || at_feed(&a, p))
            bad = 1;
    }
    bad |= at_st_chk(&a, &fail, at_check_ctx, 0);
    memset(&a, 0, sizeof a);
    if (at_feed(&a, "contexts/notacontext/x.c"))
        bad = 1;
    bad |= at_st_chk(&a, &fail, at_check_ctx, 1);
    memset(&a, 0, sizeof a);
    for (i = 0; i < g_n_libs; i++) {
        char p[RS_PATH];
        if (ovf(snprintf(p, sizeof p, "core/modules/%s/src/x.c", g_libs[i]),
                sizeof p) || at_feed(&a, p))
            bad = 1;
    }
    bad |= at_st_chk(&a, &fail, at_check_mods, 0);
    memset(&a, 0, sizeof a);
    if (at_feed(&a, "core/modules/notamodule/src/x.c"))
        bad = 1;
    bad |= at_st_chk(&a, &fail, at_check_mods, 1);
    memset(&a, 0, sizeof a);
    if (at_feed(&a, "core/modules/dupmod/src/x.c")
        || at_feed(&a, "engine/modules/dupmod/src/y.c"))
        bad = 1;
    bad |= at_st_chk(&a, &fail, at_check_dups, 1);
    memset(&a, 0, sizeof a);
    if (at_feed(&a, "core/modules/x.c"))
        bad = 1;
    bad |= at_st_chk(&a, &fail, at_check_rooms, 0);
    memset(&a, 0, sizeof a);
    if (at_feed(&a, "core/notashape/x.c"))
        bad = 1;
    bad |= at_st_chk(&a, &fail, at_check_rooms, 1);
    memset(&a, 0, sizeof a);
    a.redre = &re;
    if (at_feed(&a, "engine/reducer/src/foo.c")
        || at_feed(&a, "engine/services/src/foo.c"))
        bad = 1;
    bad |= at_st_chk(&a, &fail, at_check_red, 0);
    memset(&a, 0, sizeof a);
    a.redre = &re;
    if (at_feed(&a, "engine/services/src/reducer.c"))
        bad = 1;
    bad |= at_st_chk(&a, &fail, at_check_red, 1);
    regfree(&re);
    return st_ok(bad, "check_architecture_tree selftest: OK\n");
}
