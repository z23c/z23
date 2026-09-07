/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — supervisor registration ratchet
 * (check-supervisor-registration). Tracked files via lint_git_index_foreach;
 * filesystem walk when .git is absent.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum { SR_MAX = 4096, SR_LINE = 8192 };

struct sr_files { char p[SR_MAX][RS_PATH]; int n; };
struct sr_base { char p[SR_MAX][RS_PATH]; int n; };

static const char k_sr_base[] = "tools/scripts/supervisor_baseline.txt";
static const char k_sr_cover[] =
    "supervisor_register(_in_domain)?\\(|thread_liveness_register(_restartable)?"
    "\\(|boot_register_worker_supervisor\\(";
static const char k_sr_ok[] = "//[[:space:]]*supervisor-ok:[A-Za-z][A-Za-z0-9_-]*";
static const char k_sr_spawn[] = "thread_registry_spawn|health_register_periodic\\(";
static const char k_sr_pt[] = "pthread_create[[:space:]]*\\(";

static int srg_add(struct sr_files *s, const char *path)
{
    size_t n;
    int i;
    for (i = 0; i < s->n; i++)
        if (strcmp(s->p[i], path) == 0)
            return 0;
    n = strlen(path);
    if (s->n >= SR_MAX || n >= RS_PATH)
        return die("z23-lint: supervisor-registration overflow\n", "");
    memcpy(s->p[s->n++], path, n + 1);
    return 0;
}

static int sr_depth1(const char *path, const char *root)
{
    size_t n = strlen(root);
    const char *rest;
    if (strncmp(path, root, n) != 0 || path[n] != '/')
        return 0;
    rest = path + n + 1;
    return strchr(rest, '/') == NULL;
}

static int sr_is_c(const char *path)
{
    size_t n = strlen(path);
    return n >= 2 && path[n - 2] == '.' && path[n - 1] == 'c';
}

struct sr_idx { struct sr_files *s; const char (*roots)[RS_PATH]; int nr; };

static int sr_on_idx(const char *path, int stage, void *ctx)
{
    struct sr_idx *c = ctx;
    int i;
    (void)stage;
    if (!sr_is_c(path) || lint_path_is_excluded(path))
        return 0;
    for (i = 0; i < c->nr; i++)
        if (sr_depth1(path, c->roots[i]))
            return srg_add(c->s, path);
    return 0;
}

static int sr_unreadable(const char *path)
{
    fprintf(stderr, "check_supervisor_registration: UNPROVEN — cannot read %s\n",
            path);
    return 2;
}
static int sr_walk_root(const char *root, struct sr_files *s)
{
    struct dirent **names = NULL;
    int n = scandir(root, &names, NULL, alphasort);
    int rc = 0, i;
    if (n < 0)
        return errno == ENOENT ? 0 : sr_unreadable(root);
    for (i = 0; i < n; i++) {
        char path[4096];
        struct stat st;
        size_t kn = strlen(names[i]->d_name);
        if (rc == 0 && kn >= 2 && strcmp(names[i]->d_name + kn - 2, ".c") == 0
            && !ovf(snprintf(path, sizeof path, "%s/%s", root,
                             names[i]->d_name), sizeof path)
            && lstat(path, &st) == 0 && S_ISREG(st.st_mode)
            && !lint_path_is_excluded(path))
            rc = srg_add(s, path);
        free(names[i]);
    }
    free(names);
    return rc;
}

static int sr_fill_default(char out[][RS_PATH], int *n)
{
    const char *shapes[] = { "services", "controllers", "conditions", "jobs" };
    char rooms[RS_MAX][RS_PATH];
    int i, j, nr, rc;
    const char *extra[] = {
        "engine/composition/src", "engine/reducer/conditions/src",
        "engine/reducer/jobs/src", "engine/reducer/services/src",
        "core/modules/net/src", "engine/modules/health/src",
        "engine/modules/rpc/src"
    };
    *n = 0;
    for (i = 0; i < 4; i++) {
        rc = repo_shape_room_dirs(shapes[i], rooms, RS_MAX, &nr);
        if (rc)
            return rc;
        for (j = 0; j < nr; j++) {
            char src[RS_PATH];
            struct stat st;
            if (ovf(snprintf(src, RS_PATH, "%s/src", rooms[j]), RS_PATH))
                return 2;
            if (stat(src, &st) != 0 || !S_ISDIR(st.st_mode))
                continue;
            if (ovf(snprintf(out[*n], RS_PATH, "%s", src), RS_PATH))
                return 2;
            (*n)++;
        }
    }
    for (i = 0; i < (int)(sizeof extra / sizeof extra[0]); i++) {
        if (ovf(snprintf(out[*n], RS_PATH, "%s", extra[i]), RS_PATH))
            return 2;
        (*n)++;
    }
    return 0;
}

static int sr_split(const char *s, char out[][RS_PATH], int max, int *n)
{
    char buf[8192], *p;
    *n = 0;
    if (ovf(snprintf(buf, sizeof buf, "%s", s), sizeof buf))
        return 2;
    p = buf;
    while (*p) {
        char *t, save;
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        if (*n >= max)
            return die("z23-lint: supervisor-registration overflow\n", "");
        t = p;
        while (*p && *p != ' ' && *p != '\t')
            p++;
        save = *p;
        *p = '\0';
        if (ovf(snprintf(out[*n], RS_PATH, "%s", t), RS_PATH))
            return 2;
        (*n)++;
        if (!save)
            break;
        *p++ = save;
    }
    return 0;
}

static int sr_collect(struct sr_files *s, const char (*roots)[RS_PATH], int nr)
{
    struct sr_idx ix = { .s = s, .roots = roots, .nr = nr };
    struct stat st;
    char bad[8] = {0};
    int rc, i;
    s->n = 0;
    if (stat(".git", &st) == 0) {
        rc = lint_git_index_foreach(sr_on_idx, &ix, bad);
        if (rc)
            return die("check_supervisor_registration: UNPROVEN — git index\n",
                       "");
        return 0;
    }
    for (i = 0; i < nr; i++) {
        rc = sr_walk_root(roots[i], s);
        if (rc)
            return rc;
    }
    return 0;
}

static int sr_bhas(const struct sr_base *b, const char *p)
{
    int i;
    for (i = 0; i < b->n; i++)
        if (strcmp(b->p[i], p) == 0)
            return 1;
    return 0;
}

static int sr_load_base(struct sr_base *b, const char *path)
{
    FILE *f = fopen(path, "r");
    char buf[SR_LINE];
    b->n = 0;
    if (!f)
        return 0;
    while (fgets(buf, (int)sizeof buf, f)) {
        size_t n = strlen(buf);
        if (n && buf[n - 1] == '\n')
            buf[--n] = '\0';
        if (n && buf[n - 1] == '\r')
            buf[--n] = '\0';
        if (buf[0] == '\0' || buf[0] == '#')
            continue;
        if (b->n >= SR_MAX)
            return die("z23-lint: supervisor-registration overflow\n", "");
        snprintf(b->p[b->n++], RS_PATH, "%s", buf);
    }
    fclose(f);
    return 0;
}

static int sr_file_has(const char *path, const regex_t *re)
{
    FILE *f = fopen(path, "r");
    char buf[SR_LINE];
    int hit = 0;
    if (!f) {
        sr_unreadable(path);
        return -1;
    }
    while (fgets(buf, (int)sizeof buf, f))
        if (regexec(re, buf, 0, NULL, 0) == 0) {
            hit = 1;
            break;
        }
    fclose(f);
    return hit;
}

static int sr_unmarked_pthread(const char *path, const regex_t *pt)
{
    FILE *f = fopen(path, "r");
    char cur[SR_LINE], prev[SR_LINE];
    int hit = 0;
    prev[0] = '\0';
    if (!f) {
        sr_unreadable(path);
        return -1;
    }
    while (fgets(cur, (int)sizeof cur, f)) {
        if (regexec(pt, cur, 0, NULL, 0) == 0
            && strstr(cur, "raw-pthread-ok") == NULL
            && strstr(prev, "raw-pthread-ok") == NULL)
            hit = 1;
        memcpy(prev, cur, strlen(cur) + 1);
        if (hit)
            break;
    }
    fclose(f);
    return hit;
}

static int sr_long_running(const char *path, const regex_t *spawn,
                           const regex_t *pt)
{
    int a = sr_file_has(path, spawn);
    int b;
    if (a < 0)
        return -1;
    if (a)
        return 1;
    b = sr_unmarked_pthread(path, pt);
    return b;
}

static int sr_cov(const struct sr_files *got, const char (*def)[RS_PATH],
                  int nd, int allow)
{
    struct sr_files exp = {0};
    struct sr_idx ix = { .s = &exp, .roots = def, .nr = nd };
    struct stat st;
    char bad[8] = {0};
    int rc, i, miss = 0;
    if (stat(".git", &st) != 0)
        return 0;
    for (i = 0; i < nd; i++) {
        struct sr_files one = {0};
        struct sr_idx o = { .s = &one, .roots = def + i, .nr = 1 };
        rc = lint_git_index_foreach(sr_on_idx, &o, bad);
        if (rc)
            return rc;
        if (one.n == 0) {
            fprintf(stderr, "check_supervisor_registration: UNPROVEN — "
                            "declared scan root\n  '%s' tracks no *.c at all.\n",
                    def[i]);
            return 2;
        }
    }
    rc = lint_git_index_foreach(sr_on_idx, &ix, bad);
    if (rc)
        return rc;
    for (i = 0; i < exp.n; i++) {
        int j, found = 0;
        for (j = 0; j < got->n; j++)
            if (strcmp(exp.p[i], got->p[j]) == 0)
                found = 1;
        if (!found)
            miss++;
    }
    if (allow > 0 && miss == 0) {
        fprintf(stderr, "check_supervisor_registration: stale coverage "
                        "allowance %d (true shortfall 0)\n", allow);
        return 1;
    }
    if (miss > allow) {
        fprintf(stderr, "check_supervisor_registration: UNPROVEN — coverage "
                        "shortfall %d allowance=%d\n", miss, allow);
        return 2;
    }
    return 0;
}

static int sr_one(const char *path, const regex_t *cover, const regex_t *ok,
                  const regex_t *spawn, const regex_t *pt,
                  const struct sr_base *base, int *keep)
{
    int lr = sr_long_running(path, spawn, pt);
    int h;
    *keep = 0;
    if (lr < 0)
        return 2;
    if (!lr)
        return 0;
    h = sr_file_has(path, cover);
    if (h < 0)
        return 2;
    if (h)
        return 0;
    h = sr_file_has(path, ok);
    if (h < 0)
        return 2;
    if (h || sr_bhas(base, path))
        return 0;
    *keep = 1;
    return 0;
}
static int sr_grade(struct sr_files *files, struct sr_base *base,
                    char viol[][RS_PATH], int *nv)
{
    regex_t cover, ok, spawn, pt;
    int i, rc = 0, keep;
    *nv = 0;
    if (reg_fail(&cover, regcomp(&cover, k_sr_cover, REG_EXTENDED))
        || reg_fail(&ok, regcomp(&ok, k_sr_ok, REG_EXTENDED))
        || reg_fail(&spawn, regcomp(&spawn, k_sr_spawn, REG_EXTENDED))
        || reg_fail(&pt, regcomp(&pt, k_sr_pt, REG_EXTENDED)))
        return 2;
    for (i = 0; rc == 0 && i < files->n; i++) {
        rc = sr_one(files->p[i], &cover, &ok, &spawn, &pt, base, &keep);
        if (rc == 0 && keep && *nv < 256)
            snprintf(viol[(*nv)++], RS_PATH, "%s", files->p[i]);
    }
    drop2(&cover, &ok);
    drop2(&spawn, &pt);
    return rc;
}
static int sr_report(int nv, char viol[][RS_PATH], int nb, const char *bp)
{
    int i;
    if (!nv) {
        printf("check_supervisor_registration: clean — %d grandfathered, no "
               "new ones\n", nb);
        return 0;
    }
    printf("\ncheck_supervisor_registration: %d NEW long-running service(s) "
           "without supervisor_register_in_domain\n\n", nv);
    for (i = 0; i < nv; i++)
        printf("  %s\n", viol[i]);
    fputs("\nFix options (preferred → fallback):\n"
          "  1. Add a liveness contract: declare struct liveness_contract,\n"
          "     init it, register it. See engine/services/src/"
          "sync_watchdog_service.c\n"
          "     (g_wd_contract + supervisor_register) for the canonical "
          "pattern.\n"
          "  2. Add a per-file override marker '// supervisor-ok:<tag>' "
          "explaining\n"
          "     why this service intentionally manages its own lifecycle.\n"
          "  3. As last resort, add the file to ", stdout);
    fputs(bp, stdout);
    fputs(".\n", stdout);
    return 1;
}
static int sr_run(void)
{
    static struct sr_files files;
    static struct sr_base base;
    char def[RS_MAX][RS_PATH], roots[RS_MAX][RS_PATH];
    char viol[256][RS_PATH];
    int nd = 0, nr = 0, nv = 0, rc, allow, cov, only;
    const char *ov, *bp;
    FILE *bf;
    rc = sr_fill_default(def, &nd);
    if (rc)
        return rc;
    ov = env_or("ZCL_SERVICES_DIR", "");
    rc = ov[0] ? sr_split(ov, roots, RS_MAX, &nr)
               : (memcpy(roots, def, sizeof def), nr = nd, 0);
    if (rc)
        return rc;
    bp = env_or("ZCL_SUPREG_BASELINE", k_sr_base);
    bf = fopen(bp, "a");
    if (bf)
        fclose(bf);
    rc = sr_load_base(&base, bp);
    if (rc)
        return rc;
    rc = sr_collect(&files, roots, nr);
    if (rc)
        return rc;
    rc = gate_require_scanned(files.n, 1, "check_supervisor_registration",
                              "no *.c under scanned roots");
    if (rc)
        return rc;
    allow = atoi(env_or("ZCL_SUPREG_COVERAGE_ALLOWANCE", "0"));
    cov = strcmp(env_or("ZCL_SUPREG_COVERAGE", "1"), "1") == 0;
    only = strcmp(env_or("ZCL_SUPREG_COVERAGE_ONLY", "0"), "1") == 0;
    if (cov) {
        rc = sr_cov(&files, def, nd, allow);
        if (rc)
            return rc;
    }
    if (only) {
        printf("check_supervisor_registration: coverage-only PASS (%d files "
               "reached)\n", files.n);
        return 0;
    }
    rc = sr_grade(&files, &base, viol, &nv);
    if (rc)
        return rc;
    return sr_report(nv, viol, base.n, bp);
}

static int sr_quiet(void)
{
    int nfd, oldo, olde, rc;
    fflush(stdout);
    fflush(stderr);
    nfd = open("/dev/null", O_WRONLY);
    if (nfd < 0)
        return 2;
    oldo = dup(1);
    olde = dup(2);
    dup2(nfd, 1);
    dup2(nfd, 2);
    close(nfd);
    rc = sr_run();
    fflush(stdout);
    fflush(stderr);
    dup2(oldo, 1);
    dup2(olde, 2);
    close(oldo);
    close(olde);
    return rc;
}

static int sr_st_want(int got, int want, const char *msg)
{
    if (got == want)
        return 0;
    fprintf(stderr, "check_supervisor_registration: SELFTEST FAILED — %s "
                    "(wanted exit %d, got %d)\n", msg, want, got);
    return 2;
}

int check_supervisor_registration_selftest(void)
{
    char rooms[RS_MAX][RS_PATH];
    char two[4096];
    int nr = 0, rc;
    if (repo_shape_room_dirs("services", rooms, RS_MAX, &nr) || nr < 2)
        return 2;
    if (setenv("ZCL_LINT_PRODUCTION_SCAN", "1", 1)
        || setenv("ZCL_SUPREG_COVERAGE_ONLY", "1", 1))
        return 2;
    rc = sr_st_want(sr_quiet(), 0,
                    "the complete scan did not pass its coverage expectation");
    if (rc)
        return rc;
    if (ovf(snprintf(two, sizeof two, "%s/src %s/src", rooms[0], rooms[1]),
            sizeof two)
        || setenv("ZCL_SERVICES_DIR", two, 1))
        return 2;
    rc = sr_st_want(sr_quiet(), 2,
                    "a scan missing whole declared roots was not UNPROVEN");
    unsetenv("ZCL_SERVICES_DIR");
    if (rc)
        return rc;
    if (setenv("ZCL_SUPREG_COVERAGE_ALLOWANCE", "1", 1))
        return 2;
    rc = sr_st_want(sr_quiet(), 1,
                    "an allowance above the true shortfall was silently "
                    "tolerated");
    unsetenv("ZCL_SUPREG_COVERAGE_ALLOWANCE");
    unsetenv("ZCL_SUPREG_COVERAGE_ONLY");
    unsetenv("ZCL_LINT_PRODUCTION_SCAN");
    if (rc)
        return rc;
    fputs("[check_supervisor_registration] SELFTEST PASS (a full scan passes "
          "coverage, a scan short six declared roots is UNPROVEN exit 2, and "
          "an allowance above the true shortfall is a stale-ratchet exit 1)\n",
          stdout);
    return 0;
}

int check_supervisor_registration_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return sr_run();
}
