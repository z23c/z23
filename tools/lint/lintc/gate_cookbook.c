/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family - check-cookbook of the C23 lint runtime, the
 * replacement for the bash body of tools/lint/check_cookbook.sh. Every
 * cookbook recipe still works (RUN rows are executed and must print their
 * token, ASK rows must still be described by the command registry, READ rows
 * cite a tracked file that still holds the symbol) and docs/dev/COOKBOOK.md still
 * matches the registry byte for byte; --fix regenerates it. The tool set is
 * closed (z23-dev), arguments are split without a shell and any character
 * outside [A-Za-z0-9_./= -] is refused before anything runs.
 *
 * Exit: 0 clean, 1 a stale recipe or a drifted document, 2 hollow scan.
 * SIGINT, SIGTERM and SIGHUP stop the running child group and are
 * re-raised. Parsing and document text: gate_cookbook_parse.c. Selftest:
 * gate_cookbook_selftest.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "gate_cookbook_priv.h"
#include "lintc.h"
#include "lintc_proc.h"
#include "lintc_sig.h"

struct ck_run {
    const struct ck_cfg *cfg;
    char *z23;
    int runnable;
    int fail;
    int runs, asks, reads;
    struct ck_str seen;
};

static void ck_bad(struct ck_run *g, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs("FAIL: ", stdout);
    vprintf(fmt, ap);
    fputc('\n', stdout);
    va_end(ap);
    g->fail = 1;
}

static int ck_regular(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static int ck_slurp(const char *path, struct ck_str *out)
{
    char buf[8192];
    FILE *f = fopen(path, "r");
    size_t n;
    *out = (struct ck_str){ 0 };
    if (!f)
        return -1;
    if (ck_cat(out, "") != 0) {
        fclose(f);
        return -1;
    }
    while ((n = fread(buf, 1, sizeof buf - 1, f)) > 0) {
        buf[n] = '\0';
        if (memchr(buf, '\0', n) || ck_cat(out, buf) != 0)
            break;
    }
    int bad = ferror(f) || !feof(f);
    fclose(f);
    if (bad)
        ck_str_free(out);
    return bad ? -1 : 0;
}

/* Exit status of argv with all output discarded; 127 when it cannot start. */
static int ck_status(const struct ck_cfg *cfg, char *const argv[])
{
    struct lcp_spec s = { argv, NULL, NULL, LCP_QUIET, cfg->grace_ms, NULL };
    int code = 127;
    return lcp_run(&s, NULL, &code) == 0 ? code : 127;
}

/* Output of argv, stderr merged, or NULL. *lost is nonzero when the output
 * could not be kept whole (LCP_LOST_*) and must not be judged. */
static char *ck_capture(const struct ck_cfg *cfg, char *const argv[], int *lost)
{
    struct lcp_buf out = { 0 };
    struct lcp_spec s = { argv, NULL, NULL, LCP_BOTH, cfg->grace_ms, NULL };
    int code = 0, rc = lcp_run(&s, &out, &code);
    char *copy = NULL;
    if (rc == 0) {
        lcp_buf_subst(&out);
        copy = strdup(out.data ? out.data : "");
    }
    *lost = out.lost ? out.lost : (rc == 0 && !copy ? LCP_LOST_NOMEM : 0);
    lcp_buf_free(&out);
    return copy;
}

static void ck_observed(const char *out)
{
    printf("  observed (first 2048 bytes): %.2048s\n", out);
}

/* argv for `timeout T z23 [a [b]] <args split on blanks> [last]`, or NULL
 * when memory runs out. args is split in place. */
static char **ck_argv(const struct ck_run *g, const char *a, const char *b, char *args, char *last)
{
    size_t n = 0, cnt = 8;
    char *p;
    for (p = args; p && *p;) {
        p += strspn(p, " \t\n");
        if (*p) {
            cnt++;
            p += strcspn(p, " \t\n");
        }
    }
    char **v = malloc(cnt * sizeof *v); // raw-alloc-ok:lint-runtime
    if (!v)
        return NULL;
    v[n++] = (char *)"timeout";
    v[n++] = (char *)g->cfg->timeout;
    v[n++] = g->z23;
    if (a)
        v[n++] = (char *)a;
    if (b)
        v[n++] = (char *)b;
    for (p = args; p && *p;) {
        p += strspn(p, " \t\n");
        if (!*p)
            break;
        v[n++] = p;
        p += strcspn(p, " \t\n");
        if (*p)
            *p++ = '\0';
    }
    if (last)
        v[n++] = last;
    v[n] = NULL;
    return v;
}

static void ck_lost(struct ck_run *g, const char *id, int lost)
{
    ck_bad(g, "recipe '%s': %s", id,
           lost == LCP_LOST_NOMEM ? "out of memory while capturing the output"
                                  : "the output exceeded the capture limit and cannot be judged");
}

/* Runs argv and reports a missing token with the RUN or the ASK message.
 * Returns early after a termination signal. */
static void ck_judge(struct ck_run *g, char *const *f, char *const *argv)
{
    int lost = 0;
    char *out = ck_capture(g->cfg, argv, &lost);
    if (lsc_pending()) {
        free(out);
        return;
    }
    if (lost) {
        ck_lost(g, f[1], lost);
    } else if (!out || !strstr(out, f[4])) {
        if (strcmp(f[0], "RECIPE_RUN") == 0) {
            ck_bad(g, "recipe '%s': 'z23 %s' no longer prints '%s'", f[1], f[3], f[4]);
            ck_observed(out ? out : "");
        } else {
            ck_bad(g, "recipe '%s': command '%s' is no longer '%s'", f[1], f[3], f[4]);
        }
    }
    free(out);
}

static void ck_check_run(struct ck_run *g, char *const *f)
{
    char *args = strdup(f[3]);
    g->runs++;
    if (strcmp(f[5], "Z23_DEV") != 0)
        ck_bad(g, "recipe '%s' names an unknown tool", f[1]);
    if (!ck_args_safe(f[3])) {
        ck_bad(g, "recipe '%s' has unsafe or empty arguments: '%s'", f[1], f[3]);
    } else if (!g->runnable) {
        ck_bad(g, "recipe '%s' cannot be checked: '%s' is not built", f[1], g->z23);
    } else {
        char **argv = args ? ck_argv(g, NULL, NULL, args, NULL) : NULL;
        if (argv)
            ck_judge(g, f, argv);
        else
            ck_lost(g, f[1], LCP_LOST_NOMEM);
        free(argv);
    }
    free(args);
}

static void ck_check_ask(struct ck_run *g, char *const *f)
{
    g->asks++;
    if (!ck_args_safe(f[3])) {
        ck_bad(g, "recipe '%s' names an unsafe command path: '%s'", f[1], f[3]);
    } else if (!g->runnable) {
        ck_bad(g, "recipe '%s' cannot be checked: '%s' is not built", f[1], g->z23);
    } else {
        char **argv = ck_argv(g, "discover", "describe", NULL, f[3]);
        if (argv)
            ck_judge(g, f, argv);
        else
            ck_lost(g, f[1], LCP_LOST_NOMEM);
        free(argv);
    }
}

static void ck_check_read(struct ck_run *g, char *const *f)
{
    char *track[] = { (char *)"git", (char *)"ls-files", (char *)"--error-unmatch", (char *)"--",
                      f[3], NULL };
    char *grep[] = { (char *)"grep", (char *)"-qF", (char *)"--", f[4], f[3], NULL };
    g->reads++;
    if (ck_status(g->cfg, track) != 0) {
        if (!lsc_pending())
            ck_bad(g, "recipe '%s' cites '%s', which is not a tracked file", f[1], f[3]);
    } else if (ck_status(g->cfg, grep) != 0 && !lsc_pending()) {
        ck_bad(g, "recipe '%s' cites '%s' for '%s', which is no longer in it", f[1], f[3], f[4]);
    }
}

static int ck_kebab(const char *id)
{
    if (!*id)
        return 0;
    for (; *id; id++) {
        if (!((*id >= 'a' && *id <= 'z') || (*id >= '0' && *id <= '9') || *id == '-'))
            return 0;
    }
    return 1;
}

static int ck_seen_has(const struct ck_str *seen, const char *id)
{
    size_t n = strlen(id) + strlen(seen->p ? seen->p : "") + 8;
    char *hay = malloc(n), *needle = malloc(strlen(id) + 3); // raw-alloc-ok:lint-runtime
    int hit = 0;
    if (hay && needle) {
        snprintf(hay, n, " %s ", seen->p ? seen->p : "");
        snprintf(needle, strlen(id) + 3, " %s ", id);
        hit = strstr(hay, needle) != NULL;
    }
    free(hay);
    free(needle);
    return hit;
}

static void ck_check_row(struct ck_run *g, char *const *f)
{
    if (strcmp(f[0], "SECTION") == 0) {
        if (!*f[1])
            ck_bad(g, "an empty SECTION title");
        return;
    }
    if (!ck_kebab(f[1]))
        ck_bad(g, "recipe id '%s' is not kebab-case", f[1]);
    if (ck_seen_has(&g->seen, f[1]))
        ck_bad(g, "duplicate recipe id '%s'", f[1]);
    else if (ck_cat(&g->seen, " ") != 0 || ck_cat(&g->seen, f[1]) != 0)
        ck_bad(g, "out of memory");
    if (!*f[2])
        ck_bad(g, "recipe '%s' has no question", f[1]);
    if (strcmp(f[0], "RECIPE_RUN") == 0)
        ck_check_run(g, f);
    else if (strcmp(f[0], "RECIPE_ASK") == 0)
        ck_check_ask(g, f);
    else if (strcmp(f[0], "RECIPE_READ") == 0)
        ck_check_read(g, f);
    else
        ck_bad(g, "unknown row kind '%s'", f[0]);
}

static void ck_check_rows(struct ck_run *g, const struct ck_recs *recs)
{
    for (size_t i = 0; i < recs->n && !lsc_pending(); i++) {
        char *copy = strdup(recs->line[i]), *f[CK_FIELDS];
        if (!copy) {
            ck_bad(g, "out of memory");
            return;
        }
        ck_split(copy, f);
        ck_check_row(g, f);
        free(copy);
    }
}

static int ck_below_floor(size_t rows, const char *floor)
{
    char *end;
    errno = 0;
    while (*floor == ' ' || *floor == '\t' || *floor == '\n')
        floor++;
    long long v = strtoll(floor, &end, 10);
    if (end == floor || errno != 0)
        return 0;
    while (*end == ' ' || *end == '\t' || *end == '\n')
        end++;
    return *end == '\0' && (long long)rows < v;
}

/* Compares the generated document with the committed one; with --fix the
 * committed one is rewritten instead. Returns -1 when it cannot be written. */
static int ck_check_doc(struct ck_run *g, const struct ck_str *gen)
{
    const struct ck_cfg *cfg = g->cfg;
    struct ck_str cur = { 0 };
    int same = ck_regular(cfg->doc) && ck_slurp(cfg->doc, &cur) == 0
               && cur.n == gen->n && memcmp(cur.p, gen->p, gen->n) == 0;
    ck_str_free(&cur);
    if (cfg->fix) {
        FILE *f = same ? NULL : fopen(cfg->doc, "w");
        if (!same && (!f || fwrite(gen->p, 1, gen->n, f) != gen->n || fclose(f) != 0)) {
            fprintf(stderr, "check_cookbook: cannot write %s: %s\n", cfg->doc, strerror(errno));
            return -1;
        }
        if (!same)
            printf("fixed: %s regenerated from %s\n", cfg->doc, cfg->def);
    } else if (!ck_regular(cfg->doc)) {
        ck_bad(g, "%s does not exist; run tools/lint/check_cookbook.sh --fix", cfg->doc);
    } else if (!same) {
        ck_bad(g, "%s has drifted from %s; run tools/lint/check_cookbook.sh --fix", cfg->doc, cfg->def);
    }
    return 0;
}

static int ck_verdict(struct ck_run *g, const struct ck_recs *recs)
{
    struct ck_str gen;
    if (ck_doc(recs, &gen) != 0 || ck_check_doc(g, &gen) != 0) {
        ck_str_free(&gen);
        return 1;
    }
    ck_str_free(&gen);
    if (g->fail) {
        puts("check_cookbook: FAILED");
        return 1;
    }
    printf("check_cookbook: clean — %d run, %d ask, %d read recipe(s) from %s; %s matches\n",
           g->runs, g->asks, g->reads, g->cfg->def, g->cfg->doc);
    return 0;
}

static int ck_scan(struct ck_run *g)
{
    const struct ck_cfg *cfg = g->cfg;
    struct ck_str text;
    struct ck_recs recs;
    int rc;
    if (!ck_regular(cfg->def)) {
        printf("FAIL: check_cookbook — registry '%s' is missing\n", cfg->def);
        return 2;
    }
    if (ck_slurp(cfg->def, &text) != 0)
        text = (struct ck_str){ 0 };
    if (ck_parse(text.p ? text.p : "", &recs) != 0)
        recs = (struct ck_recs){ 0 };
    ck_str_free(&text);
    if (ck_below_floor(recs.n, cfg->floor)) {
        printf("FAIL: check_cookbook — parsed only %zu row(s) from %s, floor is %s.\n"
               "  A registry that stopped parsing must not read as clean.\n",
               recs.n, cfg->def, cfg->floor);
        ck_recs_free(&recs);
        return 2;
    }
    size_t zn = strlen(cfg->bin_dir) + sizeof "/z23-dev";
    g->z23 = malloc(zn); // raw-alloc-ok:lint-runtime
    if (!g->z23) {
        fprintf(stderr, "check_cookbook: out of memory\n");
        ck_recs_free(&recs);
        return 2;
    }
    snprintf(g->z23, zn, "%s/z23-dev", cfg->bin_dir);
    g->runnable = access(g->z23, X_OK) == 0;
    ck_check_rows(g, &recs);
    rc = lsc_pending() ? 1 : ck_verdict(g, &recs);
    ck_recs_free(&recs);
    return rc;
}

int ck_gate(const struct ck_cfg *cfg)
{
    struct ck_run g = { .cfg = cfg };
    int rc, sig;
    if (lsc_install() != 0 || chdir(cfg->root) != 0) {
        fprintf(stderr, "z23-lint: check-cookbook: cannot enter %s\n", cfg->root);
        return 2;
    }
    rc = ck_scan(&g);
    ck_str_free(&g.seen);
    free(g.z23);
    fflush(stdout);
    sig = lsc_pending();
    if (sig)
        lsc_finish(sig);
    return rc;
}

int check_cookbook_run(int argc, char **argv)
{
    int fix = 0, selftest = 0;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--fix") == 0)
            fix = 1;
        else if (strcmp(argv[i], "--selftest") == 0)
            selftest = 1;
        else {
            fprintf(stderr, "check_cookbook: unknown argument '%s'\n", argv[i]);
            return 2;
        }
    }
    if (selftest)
        return check_cookbook_selftest();
    char *root = malloc(CK_ROOT_CAP); // raw-alloc-ok:lint-runtime
    if (!root || cic_repo_root(root, CK_ROOT_CAP)) {
        free(root);
        return 2;
    }
    struct ck_cfg cfg = {
        .root = root,
        .def = env_or("ZCL_COOKBOOK_DEF", "engine/composition/cookbook.def"),
        .doc = env_or("ZCL_COOKBOOK_DOC", "docs/dev/COOKBOOK.md"),
        .bin_dir = env_or("ZCL_LINT_BIN_DIR", "build/bin"),
        .floor = env_or("ZCL_COOKBOOK_ROW_FLOOR", "10"),
        .timeout = env_or("ZCL_COOKBOOK_TIMEOUT", "120"),
        .fix = fix,
        .grace_ms = CK_GRACE_MS,
    };
    int rc = ck_gate(&cfg);
    free(root);
    return rc;
}
