/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — systemd finite MemoryMax budget of the C23 lint
 * runtime (check-systemd-memory-budget). Tracked units via
 * lint_git_index_foreach; filesystem walk when .git is absent.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum { SMB_MAX = 512, SMB_LINE = 4096, SMB_ABSENT = 0, SMB_FIN = 1,
       SMB_INF = 2 };

struct smb_set { char p[SMB_MAX][RS_PATH]; int n; };
struct smb_lim { int mem, swap, high; uint64_t mem_b, swap_b, high_b; };

static int smb_dot_git(void)
{
    struct stat st;
    return stat(".git", &st) == 0;
}

static void smb_trim(char *s)
{
    char *e;
    while (*s == ' ' || *s == '\t' || *s == '\r')
        memmove(s, s + 1, strlen(s));
    e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r'
                     || e[-1] == '\n'))
        *--e = '\0';
}

static uint64_t smb_unit(char c)
{
    if (c == 'k')
        return 1024;
    if (c == 'm')
        return 1024ull * 1024;
    if (c == 'g')
        return 1024ull * 1024 * 1024;
    if (c == 't')
        return 1024ull * 1024 * 1024 * 1024;
    if (c == 'p')
        return 1024ull * 1024 * 1024 * 1024 * 1024;
    return 0;
}

static int smb_digits(char **pp, uint64_t *n)
{
    char *p = *pp;
    if (*p < '0' || *p > '9')
        return 1;
    while (*p >= '0' && *p <= '9') {
        if (*n > (UINT64_MAX - (uint64_t)(*p - '0')) / 10)
            return 1;
        *n = *n * 10 + (uint64_t)(*p - '0');
        p++;
    }
    *pp = p;
    return 0;
}

static int smb_suffix(char **pp, uint64_t *mult)
{
    char *p = *pp;
    uint64_t u = smb_unit(*p);
    if (u) {
        *mult = u;
        p++;
    } else if (*p && *p != 'i' && *p != 'b') {
        return 1;
    } else {
        *mult = 1;
    }
    if (*p == 'i')
        p++;
    if (*p == 'b')
        p++;
    if (*p != '\0')
        return 1;
    *pp = p;
    return 0;
}

static int smb_parse_size(const char *raw, int *st, uint64_t *bytes)
{
    char buf[128], *p;
    uint64_t n = 0, mult = 1;
    if (ovf(snprintf(buf, sizeof buf, "%s", raw), sizeof buf))
        return 1;
    smb_trim(buf);
    for (p = buf; *p; p++)
        if (*p >= 'A' && *p <= 'Z')
            *p = (char)(*p - 'A' + 'a');
    if (buf[0] == '\0' || strcmp(buf, "infinity") == 0) {
        *st = SMB_INF;
        *bytes = 0;
        return 0;
    }
    p = buf;
    if (smb_digits(&p, &n) || smb_suffix(&p, &mult))
        return 1;
    if (mult != 1 && n > UINT64_MAX / mult)
        return 1;
    *st = SMB_FIN;
    *bytes = n * mult;
    return 0;
}

static int smb_add(struct smb_set *s, const char *path)
{
    int i;
    size_t n = strlen(path);
    for (i = 0; i < s->n; i++)
        if (strcmp(s->p[i], path) == 0)
            return 0;
    if (s->n >= SMB_MAX || n >= RS_PATH)
        return die("z23-lint: systemd-memory-budget overflow\n", "");
    memcpy(s->p[s->n++], path, n + 1);
    return 0;
}

static int smb_under(const char *path, const char *root, const char *dir)
{
    char pre[RS_PATH];
    size_t n;
    if (ovf(snprintf(pre, sizeof pre, "%s/%s/",
                     strcmp(root, ".") == 0 ? "" : root, dir), sizeof pre))
        return 0;
    if (pre[0] == '/')
        memmove(pre, pre + 1, strlen(pre));
    n = strlen(pre);
    return strncmp(path, pre, n) == 0;
}

struct smb_idx { struct smb_set *s; const char *root, *dirs; };

static int smb_on_idx(const char *path, int stage, void *ctx)
{
    struct smb_idx *c = ctx;
    const char *d, *p;
    char dir[RS_PATH];
    size_t n = strlen(path);
    (void)stage;
    if (n < 8 || strcmp(path + n - 8, ".service") != 0)
        return 0;
    p = c->dirs;
    while (*p) {
        size_t k = 0;
        while (*p == ' ' || *p == '\t')
            p++;
        d = p;
        while (*p && *p != ' ' && *p != '\t')
            p++;
        k = (size_t)(p - d);
        if (!k || k >= sizeof dir)
            continue;
        memcpy(dir, d, k);
        dir[k] = '\0';
        if (smb_under(path, c->root, dir))
            return smb_add(c->s, path);
    }
    return 0;
}

static int smb_walk(const char *dir, struct smb_set *s);

static int smb_visit(const char *dir, const char *nm, struct smb_set *s)
{
    char path[4096];
    struct stat st;
    size_t n = strlen(nm);
    if (strcmp(nm, ".") == 0 || strcmp(nm, "..") == 0)
        return 0;
    if (ovf(snprintf(path, sizeof path, "%s/%s", dir, nm), sizeof path))
        return 2;
    if (lstat(path, &st) != 0)
        return die("z23-lint: cannot stat %s\n", path);
    if (S_ISDIR(st.st_mode))
        return smb_walk(path, s);
    if (S_ISREG(st.st_mode) && n >= 8 && strcmp(nm + n - 8, ".service") == 0)
        return smb_add(s, path);
    return 0;
}

static int smb_walk(const char *dir, struct smb_set *s)
{
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    int rc = 0, i;
    if (n < 0)
        return errno == ENOENT ? 0 : die("z23-lint: cannot scan %s\n", dir);
    for (i = 0; i < n; i++) {
        if (rc == 0)
            rc = smb_visit(dir, names[i]->d_name, s);
        free(names[i]);
    }
    free(names);
    return rc;
}

static int smb_collect(struct smb_set *s, const char *root, const char *dirs)
{
    char bad[8] = {0};
    const char *p = dirs;
    int rc = 0;
    s->n = 0;
    if (strcmp(root, ".") == 0 && smb_dot_git()) {
        struct smb_idx c = { .s = s, .root = root, .dirs = dirs };
        rc = lint_git_index_foreach(smb_on_idx, &c, bad);
        if (rc && bad[0])
            fprintf(stderr, "z23-lint: UNPROVEN — git index extension %s\n",
                    bad);
        return rc;
    }
    while (rc == 0 && *p) {
        char dir[RS_PATH], path[4096];
        size_t k;
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        k = 0;
        while (p[k] && p[k] != ' ' && p[k] != '\t')
            k++;
        if (k >= sizeof dir)
            return 2;
        memcpy(dir, p, k);
        dir[k] = '\0';
        p += k;
        if (ovf(snprintf(path, sizeof path, "%s/%s", root, dir), sizeof path))
            return 2;
        rc = smb_walk(path, s);
    }
    return rc;
}

static int smb_dropins(const char *unit, char out[][RS_PATH], int max, int *n)
{
    char ddir[4096];
    struct dirent **names = NULL;
    int i, nd, rc = 0;
    *n = 0;
    if (ovf(snprintf(ddir, sizeof ddir, "%s.d", unit), sizeof ddir))
        return 2;
    nd = scandir(ddir, &names, NULL, alphasort);
    if (nd < 0)
        return 0;
    for (i = 0; i < nd; i++) {
        size_t kn = strlen(names[i]->d_name);
        if (rc == 0 && kn >= 5
            && strcmp(names[i]->d_name + kn - 5, ".conf") == 0) {
            if (*n >= max)
                rc = die("z23-lint: systemd-memory-budget overflow\n", "");
            else if (ovf(snprintf(out[*n], RS_PATH, "%s/%s", ddir,
                                  names[i]->d_name), RS_PATH))
                rc = 2;
            else
                (*n)++;
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

static int smb_apply_line(const char *file, char *line, int in_svc,
                          struct smb_lim *lim)
{
    char *eq, *key, *val;
    int st;
    uint64_t b;
    if (!in_svc)
        return 0;
    eq = strchr(line, '=');
    if (!eq)
        return 0;
    *eq = '\0';
    key = line;
    val = eq + 1;
    smb_trim(key);
    smb_trim(val);
    if (strcmp(key, "MemoryMax") != 0 && strcmp(key, "MemorySwapMax") != 0
        && strcmp(key, "MemoryHigh") != 0)
        return 0;
    if (smb_parse_size(val, &st, &b)) {
        fprintf(stderr, "FAIL: %s: invalid %s=%s\n", file, key, val);
        return 1;
    }
    if (strcmp(key, "MemoryMax") == 0) {
        lim->mem = st;
        lim->mem_b = b;
    } else if (strcmp(key, "MemorySwapMax") == 0) {
        lim->swap = st;
        lim->swap_b = b;
    } else {
        lim->high = st;
        lim->high_b = b;
    }
    return 0;
}

static int smb_read_file(const char *path, struct smb_lim *lim)
{
    FILE *f = fopen(path, "r");
    char buf[SMB_LINE];
    int in_svc = 0, rc = 0;
    if (!f) {
        fprintf(stderr, "z23-lint: UNPROVEN — cannot read %s\n", path);
        return 2;
    }
    while (rc == 0 && fgets(buf, (int)sizeof buf, f)) {
        char *h = strchr(buf, '#');
        if (h)
            *h = '\0';
        smb_trim(buf);
        if (buf[0] == '\0')
            continue;
        if (buf[0] == '[') {
            size_t n = strlen(buf);
            if (n >= 2 && buf[n - 1] == ']')
                buf[n - 1] = '\0';
            in_svc = strcmp(buf, "[Service") == 0;
            continue;
        }
        rc = smb_apply_line(path, buf, in_svc, lim);
    }
    if (rc == 0 && ferror(f))
        rc = die("z23-lint: read failed: %s\n", path);
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", path);
    return rc;
}

static int smb_read_unit(const char *unit, struct smb_lim *lim)
{
    char drops[64][RS_PATH];
    int nd = 0, i, rc;
    memset(lim, 0, sizeof *lim);
    rc = smb_dropins(unit, drops, 64, &nd);
    if (rc)
        return rc;
    rc = smb_read_file(unit, lim);
    for (i = 0; rc == 0 && i < nd; i++)
        rc = smb_read_file(drops[i], lim);
    return rc;
}

static void smb_fmt(int st, uint64_t b, char *out, size_t cap)
{
    if (st == SMB_INF)
        snprintf(out, cap, "INF");
    else if (st == SMB_ABSENT)
        snprintf(out, cap, "ABSENT");
    else
        snprintf(out, cap, "%" PRIu64, b);
}

static int smb_budget(uint64_t mem, uint64_t *out)
{
    const char *lim = env_or("ZCL_SYSTEMD_MEMORY_BUDGET_LIMIT_BYTES", "");
    const char *pcts;
    unsigned long pct;
    char *e = NULL;
    if (lim[0]) {
        *out = strtoull(lim, NULL, 10);
        return 0;
    }
    pcts = env_or("ZCL_SYSTEMD_MEMORY_BUDGET_LIMIT_PCT", "70");
    pct = strtoul(pcts, &e, 10);
    if (!e || *e || pct == 0 || pct > 100) {
        fprintf(stderr, "FAIL: invalid ZCL_SYSTEMD_MEMORY_BUDGET_LIMIT_PCT=%s\n",
                pcts);
        return 1;
    }
    *out = mem * (uint64_t)pct / 100;
    return 0;
}

static int smb_run_check(void)
{
    struct smb_set set = {0};
    const char *root = env_or("ZCL_SYSTEMD_MEMORY_BUDGET_ROOT", ".");
    const char *dirs = env_or("ZCL_SYSTEMD_MEMORY_BUDGET_DIRS", "deploy");
    const char *mems = env_or("ZCL_SYSTEMD_MEMORY_BUDGET_MEMTOTAL_BYTES", "");
    uint64_t mem, budget, total = 0, swap_total = 0;
    int rc, i, fail = 0;
    mem = mems[0] ? strtoull(mems, NULL, 10)
                  : 96ull * 1024 * 1024 * 1024;
    rc = smb_budget(mem, &budget);
    if (rc)
        return rc;
    rc = smb_collect(&set, root, dirs);
    if (rc)
        return rc;
    for (i = 0; i < set.n; i++) {
        struct smb_lim lim;
        const char *rel;
        char ms[32], ss[32];
        rc = smb_read_unit(set.p[i], &lim);
        if (rc == 2)
            return 2;
        if (rc) {
            fail = 1;
            continue;
        }
        rel = set.p[i];
        if (strncmp(rel, root, strlen(root)) == 0 && rel[strlen(root)] == '/')
            rel += strlen(root) + 1;
        if (lim.mem == SMB_INF) {
            printf("FAIL: %s explicitly sets MemoryMax=infinity\n", rel);
            fail = 1;
            continue;
        }
        if (lim.mem != SMB_FIN)
            continue;
        total += lim.mem_b;
        if (lim.swap == SMB_FIN) {
            swap_total += lim.swap_b;
            total += lim.swap_b;
        }
        smb_fmt(lim.mem, lim.mem_b, ms, sizeof ms);
        smb_fmt(lim.swap, lim.swap_b, ss, sizeof ss);
        printf("  counted %-55s MemoryMax=%s MemorySwapMax=%s\n", rel, ms, ss);
    }
    if (fail)
        return 1;
    printf("check_systemd_memory_budget: total=%" PRIu64 " bytes, "
           "swap_component=%" PRIu64 " bytes, budget=%" PRIu64
           " bytes, memtotal=%" PRIu64 " bytes\n",
           total, swap_total, budget, mem);
    if (total >= budget) {
        fputs("FAIL: systemd finite MemoryMax(+MemorySwapMax) sum "
              "reaches/exceeds budget\n"
              "      Lower MemoryMax caps or raise the explicit budget only "
              "with an ops note.\n", stdout);
        return 1;
    }
    fputs("  OK: systemd finite memory budget is below the host guardrail\n",
          stdout);
    return 0;
}

static int smb_st_write(const char *path, const char *text)
{
    return csr_write(path, text);
}

static int smb_st_one(const char *name, int want_fail, const char *a,
                      const char *drop)
{
    char tmp[] = "/tmp/zcl-smb-XXXXXX";
    char unit[4096], dconf[4096];
    int rc, got;
    if (!mkdtemp(tmp))
        return die("z23-lint: mkdtemp failed\n", "");
    if (ovf(snprintf(unit, sizeof unit, "%s/deploy/a.service", tmp),
            sizeof unit)
        || smb_st_write(unit, a)) {
        rap_rm_rf(tmp);
        return 2;
    }
    if (drop) {
        if (ovf(snprintf(dconf, sizeof dconf,
                         "%s/deploy/a.service.d/10-cap.conf", tmp),
                sizeof dconf)
            || smb_st_write(dconf, drop)) {
            rap_rm_rf(tmp);
            return 2;
        }
    }
    if (setenv("ZCL_SYSTEMD_MEMORY_BUDGET_ROOT", tmp, 1)
        || setenv("ZCL_SYSTEMD_MEMORY_BUDGET_DIRS", "deploy", 1)
        || setenv("ZCL_SYSTEMD_MEMORY_BUDGET_MEMTOTAL_BYTES",
                  "68719476736", 1)
        || setenv("ZCL_SYSTEMD_MEMORY_BUDGET_LIMIT_PCT", "100", 1)) {
        rap_rm_rf(tmp);
        return 2;
    }
    unsetenv("ZCL_SYSTEMD_MEMORY_BUDGET_SELFTEST");
    unsetenv("ZCL_SYSTEMD_MEMORY_BUDGET_LIMIT_BYTES");
    {
        int nfd = open("/dev/null", O_WRONLY), oldo, olde;
        if (nfd < 0)
            got = 2;
        else {
            fflush(stdout);
            fflush(stderr);
            oldo = dup(1);
            olde = dup(2);
            dup2(nfd, 1);
            dup2(nfd, 2);
            close(nfd);
            got = smb_run_check();
            fflush(stdout);
            fflush(stderr);
            dup2(oldo, 1);
            dup2(olde, 2);
            close(oldo);
            close(olde);
        }
    }
    unsetenv("ZCL_SYSTEMD_MEMORY_BUDGET_ROOT");
    unsetenv("ZCL_SYSTEMD_MEMORY_BUDGET_DIRS");
    unsetenv("ZCL_SYSTEMD_MEMORY_BUDGET_MEMTOTAL_BYTES");
    unsetenv("ZCL_SYSTEMD_MEMORY_BUDGET_LIMIT_PCT");
    rap_rm_rf(tmp);
    rc = (got != 0) != want_fail;
    if (rc)
        fprintf(stderr, "SELFTEST FAIL: expected %s: %s\n",
                want_fail ? "failure" : "pass", name);
    return rc ? 1 : 0;
}

static int smb_selftest(void)
{
    int bad = 0;
    bad |= smb_st_one("finite caps below budget", 0,
                      "[Service]\nMemoryMax = 24G # hard cap\n"
                      "MemorySwapMax=512M\n", NULL);
    bad |= smb_st_one("finite caps over budget", 1,
                      "[Service]\nMemoryMax=80G\n", NULL);
    bad |= smb_st_one("explicit infinity fails", 1,
                      "[Service]\nMemoryMax=infinity\n", NULL);
    bad |= smb_st_one("absent MemoryMax passes", 0,
                      "[Service]\nMemoryHigh=6G\n", NULL);
    bad |= smb_st_one("invalid swap directive fails", 1,
                      "[Service]\nMemoryMax=1G\nMemorySwapMax=bogus\n", NULL);
    bad |= smb_st_one("drop-in lower override wins", 0,
                      "[Service]\nMemoryMax=80G\n",
                      "[Service]\nMemoryMax=24G\n");
    bad |= smb_st_one("drop-in higher override wins", 1,
                      "[Service]\nMemoryMax=24G\n",
                      "[Service]\nMemoryMax=80G\n");
    if (bad)
        return 1;
    fputs("check_systemd_memory_budget: selftest OK\n", stdout);
    return 0;
}

int check_systemd_memory_budget_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    if (strcmp(env_or("ZCL_SYSTEMD_MEMORY_BUDGET_SELFTEST", "0"), "1") == 0)
        return smb_selftest();
    return smb_run_check();
}

int check_systemd_memory_budget_selftest(void)
{
    return smb_selftest();
}
