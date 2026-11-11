/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Run one semantic-facts fuzz case: lay out the project tree, compile and sense every TU before and after the edit with the sensor's clang, then hand the facts to the plan-and-judge oracle. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "semantic_fuzz_case_priv.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "platform/clock.h"
#include "test/test_core.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/prctl.h>
#endif

#define SFZ_ARGV_MAX 48
#define SFZ_EXTRA_MAX 16
/* A compile, sensor or gcc run of a small generated TU takes well under a
 * second; one still running after this is killed and fails its case. */
#define SFZ_JOB_BUDGET_S 120

/* ---- path sets --------------------------------------------------------------- */

bool sfz_paths_add(struct sfz_paths *p, const char *path)
{
    if (p->n == p->cap) {
        size_t cap = p->cap ? p->cap * 2 : 16;
        char **v = zcl_realloc(p->v, cap * sizeof(*v), "sfz.paths");
        if (v == NULL)
            return false;
        p->v = v;
        p->cap = cap;
    }
    p->v[p->n] = zcl_strdup(path, "sfz.path");
    return p->v[p->n] != NULL && ++p->n > 0;
}

bool sfz_paths_has(const struct sfz_paths *p, const char *path)
{
    for (size_t k = 0; k < p->n; k++)
        if (strcmp(p->v[k], path) == 0)
            return true;
    return false;
}

static int cmp_str(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

void sfz_paths_sort(struct sfz_paths *p)
{
    if (p->n > 1)
        qsort(p->v, p->n, sizeof(*p->v), cmp_str);
}

void sfz_paths_free(struct sfz_paths *p)
{
    for (size_t k = 0; k < p->n; k++)
        free(p->v[k]);
    free(p->v);
    memset(p, 0, sizeof(*p));
}

void sfz_why(struct sfz_outcome *out, const char *fmt, ...)
{
    size_t at = strlen(out->why);
    va_list ap;
    if (at + 1 >= sizeof(out->why))
        return;
    va_start(ap, fmt);
    (void)vsnprintf(out->why + at, sizeof(out->why) - at, fmt, ap);
    va_end(ap);
}

/* ---- files ------------------------------------------------------------------- */

bool sfz_slurp(const char *path, uint8_t **out, size_t *len)
{
    FILE *fp = fopen(path, "rb");
    long size;
    bool ok = false;
    *out = NULL;
    *len = 0;
    if (fp == NULL)
        return false;
    if (fseek(fp, 0, SEEK_END) == 0 && (size = ftell(fp)) >= 0 &&
        fseek(fp, 0, SEEK_SET) == 0) {
        *out = zcl_malloc((size_t)size + 1, "sfz.slurp");
        ok = *out != NULL && fread(*out, 1, (size_t)size, fp) == (size_t)size;
        *len = (size_t)size;
    }
    (void)fclose(fp);
    if (!ok) {
        free(*out);
        *out = NULL;
    }
    return ok;
}

bool sfz_object(char *buf, size_t n, const char *dir, const char *tu)
{
    int written = snprintf(buf, n, "%s/%s.o", dir, tu);
    return written >= 0 && (size_t)written < n;
}

static bool sfz_parent(const char *path)
{
    char copy[PATH_MAX];
    int n = snprintf(copy, sizeof copy, "%s", path);
    if (n < 0 || (size_t)n >= sizeof copy)
        return false;
    char *slash = strrchr(copy, '/');
    if (!slash)
        return false;
    *slash = '\0';
    return sfz_mkdirs(copy);
}

/* Every regular file under <root>/<rel>, as paths relative to root. */
static bool list_tree(const char *root, const char *rel, struct sfz_paths *out)
{
    char dir[PATH_MAX], sub[PATH_MAX];
    DIR *d;
    struct dirent *e;
    bool ok = true;
    (void)snprintf(dir, sizeof(dir), "%s%s%s", root, rel[0] ? "/" : "", rel);
    d = opendir(dir);
    if (d == NULL)
        LOG_FAIL("sfz", "opendir %s: %s", dir, strerror(errno));
    while (ok && (e = readdir(d)) != NULL) {
        struct stat st;
        char full[PATH_MAX * 2];
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        (void)snprintf(sub, sizeof(sub), "%s%s%s", rel, rel[0] ? "/" : "",
                       e->d_name);
        (void)snprintf(full, sizeof(full), "%s/%s", root, sub);
        if (lstat(full, &st) != 0)
            ok = false;
        else if (S_ISDIR(st.st_mode))
            ok = list_tree(root, sub, out);
        else if (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode))
            ok = sfz_paths_add(out, sub); /* a link is one path, not followed */
    }
    (void)closedir(d);
    return ok;
}

/* The target text of symbolic link `path` into buf; false when it is none. */
static bool link_text(const char *path, char *buf, size_t cap)
{
    struct stat st;
    ssize_t n;
    if (lstat(path, &st) != 0 || !S_ISLNK(st.st_mode))
        return false;
    n = readlink(path, buf, cap - 1);
    if (n < 0)
        return false;
    buf[n] = '\0';
    return true;
}

/* The same path on both sides, as git compares it: two links with one
 * target text, or two files with the same bytes. A link against a file
 * differs even when the file it names has those bytes. */
static bool same_file(const char *a, const char *b)
{
    char la[PATH_MAX], lb[PATH_MAX];
    uint8_t *x = NULL, *y = NULL;
    size_t xn = 0, yn = 0;
    bool al = link_text(a, la, sizeof(la)), bl = link_text(b, lb, sizeof(lb));
    bool same;
    if (al || bl)
        return al && bl && strcmp(la, lb) == 0;
    same = sfz_slurp(a, &x, &xn) && sfz_slurp(b, &y, &yn) && xn == yn &&
           memcmp(x, y, xn) == 0;
    free(x);
    free(y);
    return same;
}

/* Copy <from_root>/<rel> to <to_root>/<rel><suffix>. A link is laid out
 * as the same link unless `follow`, which copies the bytes it names (the
 * facts directory's .before texts); a file replaces a link at the
 * destination rather than writing through it. */
static bool unlink_link(const char *root, const char *rel)
{
    char path[PATH_MAX * 3], target[PATH_MAX];
    (void)snprintf(path, sizeof(path), "%s/%s", root, rel);
    if (link_text(path, target, sizeof(target)) && unlink(path) != 0)
        LOG_FAIL("sfz", "unlink %s: %s", path, strerror(errno));
    return true;
}

static bool copy_file(const char *from_root, const char *rel, const char *to_root,
                      const char *suffix, bool follow)
{
    char src[PATH_MAX * 2], dst[PATH_MAX * 2], target[PATH_MAX];
    uint8_t *b = NULL;
    size_t n = 0;
    bool ok;
    (void)snprintf(src, sizeof(src), "%s/%s", from_root, rel);
    (void)snprintf(dst, sizeof(dst), "%s%s", rel, suffix);
    if (!follow && link_text(src, target, sizeof(target)))
        return sfz_symlink(to_root, dst, target);
    if (!sfz_slurp(src, &b, &n))
        LOG_FAIL("sfz", "cannot read %s", src);
    ok = unlink_link(to_root, dst) && sfz_put(to_root, dst, (const char *)b, n);
    free(b);
    return ok;
}

static bool is_c(const char *path)
{
    size_t n = strlen(path);
    return n > 2 && strcmp(path + n - 2, ".c") == 0;
}

/* ---- processes --------------------------------------------------------------- */

struct sfz_job {
    const char *argv[SFZ_ARGV_MAX];
    char s[4][PATH_MAX]; /* per-job argument storage */
    char log[PATH_MAX];
    pid_t pid;
    int64_t deadline;    /* monotonic ns after which it is killed */
    int status;          /* exit status, -1 when it did not exit normally */
    bool killed;         /* it outran SFZ_JOB_BUDGET_S */
};

/* The whole environment of a compile, sensor or gcc run, and nothing
 * else: an inherited CPATH or C_INCLUDE_PATH would change what clang and
 * the sensor read (the sensor records both in its facts), and any other
 * variable could steer a tool unseen. PATH lets gcc find its helpers,
 * LC_ALL=C keeps diagnostics stable, HOME is what the sensor normalizes
 * paths under, and TMPDIR keeps any temporary file inside the case. */
static void envp_init(struct sfz_run *r)
{
    const char *path = getenv("PATH"), *home = getenv("HOME");
    size_t n = 0;
    if (path == NULL || (size_t)snprintf(r->env_path, sizeof(r->env_path),
                                         "PATH=%s", path) >= sizeof(r->env_path))
        (void)snprintf(r->env_path, sizeof(r->env_path), "PATH=/usr/bin:/bin");
    r->envp[n++] = r->env_path;
    r->envp[n++] = "LC_ALL=C";
    if (home != NULL && (size_t)snprintf(r->env_home, sizeof(r->env_home),
                                         "HOME=%s", home) < sizeof(r->env_home))
        r->envp[n++] = r->env_home;
    (void)snprintf(r->env_tmp, sizeof(r->env_tmp), "TMPDIR=%s", r->log);
    r->envp[n++] = r->env_tmp;
    r->envp[n] = NULL;
}

static pid_t job_start(struct sfz_job *j, const char *cwd,
                       const char *const *envp)
{
    pid_t parent = getpid();
    pid_t pid = fork();
    j->deadline = clock_now_monotonic_ns() + (int64_t)SFZ_JOB_BUDGET_S * 1000000000;
    if (pid != 0)
        return pid;
#if defined(__linux__)
    /* dies with its case process, even one killed at its deadline */
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent)
        _exit(125);
#else
    (void)parent;
#endif
    int fd = open(j->log, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        (void)dup2(fd, STDOUT_FILENO);
        (void)dup2(fd, STDERR_FILENO);
        (void)close(fd);
    }
    if (chdir(cwd) != 0)
        _exit(126);
    execve(j->argv[0], (char *const *)j->argv, (char *const *)envp);
    _exit(127);
}

/* Reap j, killing it at its deadline. */
static void job_wait(struct sfz_job *j)
{
    int st = 0;
    pid_t got;
    j->status = -1;
    if (j->pid <= 0)
        return;
    while ((got = waitpid(j->pid, &st, WNOHANG)) == 0 ||
           (got < 0 && errno == EINTR)) {
        if (clock_now_monotonic_ns() >= j->deadline) {
            (void)kill(j->pid, SIGKILL);
            j->killed = true;
            (void)waitpid(j->pid, &st, 0);
            return;
        }
        (void)poll(NULL, 0, 5);
    }
    if (got == j->pid && WIFEXITED(st))
        j->status = WEXITSTATUS(st);
}

static void job_complain(const struct sfz_job *j)
{
    if (j->killed)
        fprintf(stderr, "sfz: %s killed after %d s (log %s)\n", j->argv[0],
                SFZ_JOB_BUDGET_S, j->log);
    else
        fprintf(stderr, "sfz: %s exited %d (log %s)\n", j->argv[0], j->status,
                j->log);
}

/* Run the jobs in the case tree, r->env->jobs at once, oldest reaped
 * first; the number that failed, adding those killed to r->killed. */
static size_t run_jobs(struct sfz_run *r, struct sfz_job *jobs, size_t n)
{
    size_t bad = 0, par = (size_t)r->env->jobs;
    for (size_t k = 0; k < n; k++) {
        if (k >= par)
            job_wait(&jobs[k - par]);
        jobs[k].pid = job_start(&jobs[k], r->tree, r->envp);
        if (jobs[k].pid < 0)
            fprintf(stderr, "sfz: fork failed for %s\n", jobs[k].argv[0]);
    }
    for (size_t k = n > par ? n - par : 0; k < n; k++)
        job_wait(&jobs[k]);
    for (size_t k = 0; k < n; k++) {
        if (jobs[k].status == 0)
            continue;
        bad++;
        r->killed += jobs[k].killed;
        job_complain(&jobs[k]);
    }
    return bad;
}

/* ---- the phases ----------------------------------------------------------------- */

/* The controlled compile flags plus the project's CFLAGS_EXTRA. */
struct sfz_flags {
    char map[PATH_MAX + 32];
    char extra[512];
    char opt[128];
    const char *v[SFZ_ARGV_MAX / 2];
    size_t n;
};

/* Append each `sep`-separated token of s (edited in place) to f->v. */
static bool add_tokens(struct sfz_flags *f, char *s, const char *sep,
                       const char *what)
{
    char *save = NULL;
    for (char *t = strtok_r(s, sep, &save); t != NULL;
         t = strtok_r(NULL, sep, &save)) {
        if (f->n + 1 >= sizeof(f->v) / sizeof(f->v[0]))
            LOG_FAIL("sfz", "too many flags in %s", what);
        f->v[f->n++] = t;
    }
    return true;
}

/* The case's optimizer flags for one side's compile (sensor false) or
 * sensor run. opt is BEFORE>AFTER when the flags drift between the sides.
 * Each side's flags are COMPILE or COMPILE/SENSOR, a sensor handed other
 * flags than the compile it describes, as a build whose per-object flags
 * never reach the sensor's rule does. An empty half is -O1. */
static void pick_opt(const char *opt, bool after, bool sensor, char *out,
                     size_t n)
{
    char side[128];
    const char *gt = strchr(opt, '>');
    if (gt == NULL)
        (void)snprintf(side, sizeof(side), "%s", opt);
    else if (after)
        (void)snprintf(side, sizeof(side), "%s", gt + 1);
    else
        (void)snprintf(side, sizeof(side), "%.*s", (int)(gt - opt), opt);
    const char *slash = strchr(side, '/');
    if (slash == NULL)
        (void)snprintf(out, n, "%s", side);
    else if (sensor)
        (void)snprintf(out, n, "%s", slash + 1);
    else
        (void)snprintf(out, n, "%.*s", (int)(slash - side), side);
    if (out[0] == '\0')
        (void)snprintf(out, n, "-O1");
}

/* The argv of a compile (sensor false) or of a sensor run: the fixed
 * flags, then the case's optimizer flags (which may override -g0), then
 * the project's. */
static bool read_flags(const struct sfz_run *r, bool after, bool sensor,
                       struct sfz_flags *f)
{
    static const char *const fixed[] = {"-std=c23", "-g0", "-w",
                                        "-ffunction-sections", "-fdata-sections"};
    char path[PATH_MAX * 2];
    uint8_t *mk = NULL;
    size_t n = 0;
    const char *line;
    (void)snprintf(path, sizeof(path), "%s/Makefile", r->tree);
    memset(f, 0, sizeof(*f));
    if (sfz_slurp(path, &mk, &n) && (line = strstr((char *)mk, "CFLAGS_EXTRA =")))
        (void)sscanf(line + strlen("CFLAGS_EXTRA ="), "%511[^\n]", f->extra);
    free(mk);
    for (size_t k = 0; k < sizeof(fixed) / sizeof(fixed[0]); k++)
        f->v[f->n++] = fixed[k];
    pick_opt(r->c->opt, after, sensor, f->opt, sizeof(f->opt));
    if (!add_tokens(f, f->opt, ",", "the case's optimizer flags"))
        return false;
    (void)snprintf(f->map, sizeof(f->map), "-ffile-prefix-map=%s=/zclassic23",
                   r->tree);
    f->v[f->n++] = f->map;
    f->v[f->n++] = "-Iinc1";
    f->v[f->n++] = "-Iinc2";
    return add_tokens(f, f->extra, " \t", path);
}

static size_t put_flags(struct sfz_job *j, size_t k, const struct sfz_flags *f)
{
    for (size_t q = 0; q < f->n; q++)
        j->argv[k++] = f->v[q];
    return k;
}

/* The sorted TU ordinal uniquely names its depfile across both phases. */
static bool compile_job(struct sfz_job *j, const char *tool, const char *mode,
                        const struct sfz_flags *f, const char *tu, const char *obj,
                        size_t ordinal)
{
    size_t k = 0;
    int a = snprintf(j->s[0], sizeof(j->s[0]), "build/deps/tu-%zu.d", ordinal);
    int b = snprintf(j->s[1], sizeof(j->s[1]), "%s.o", tu);
    int c = snprintf(j->s[3], sizeof(j->s[3]), "%s", obj);
    if (a < 0 || (size_t)a >= sizeof(j->s[0]) || b < 0 ||
        (size_t)b >= sizeof(j->s[1]) || c < 0 || (size_t)c >= sizeof(j->s[3]))
        return false;
    j->argv[k++] = tool;
    k = put_flags(j, k, f);
    j->argv[k++] = "-MMD";
    j->argv[k++] = "-MF";
    j->argv[k++] = j->s[0];
    j->argv[k++] = "-MT";
    j->argv[k++] = j->s[1];
    j->argv[k++] = mode;
    j->argv[k++] = tu;
    j->argv[k++] = "-o";
    j->argv[k++] = j->s[3];
    j->argv[k] = NULL;
    return true;
}

/* The fuzz case's --cc and --toolchain-id: the actual object compiler (the
 * facts rule's own $(CC) as it names it, clang or gcc), and a fixed
 * toolchain identity ($(BUILD_COMPILER_ID) in the real build; the cases
 * run no Make parse, so this fixed stand-in is that identity on both
 * sides). Both sides of every case run the same sensor, so a fixed
 * identity is one known value shared by every pair; without --cc IDENTITY
 * says "object-cc unknown" and the plan can never narrow past a TU. */
#define SFZ_TOOLCHAIN_ID \
    "6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f"

/* sensor emit --root . --source <tu> --out facts/<tu>.<phase>.zsm --facts
 * --cc <cc> --toolchain-id <id> -- flags */
static bool sensor_job(struct sfz_job *j, const char *sensor, const char *cc,
                       const char *phase, const struct sfz_flags *f,
                       const char *tu)
{
    size_t k = 0;
    int n = snprintf(j->s[2], sizeof(j->s[2]), "facts/%s.%s.zsm", tu, phase);
    if (n < 0 || (size_t)n >= sizeof(j->s[2]))
        return false;
    j->argv[k++] = sensor;
    j->argv[k++] = "emit";
    j->argv[k++] = "--root";
    j->argv[k++] = ".";
    j->argv[k++] = "--source";
    j->argv[k++] = tu;
    j->argv[k++] = "--out";
    j->argv[k++] = j->s[2];
    j->argv[k++] = "--facts";
    j->argv[k++] = "--cc";
    j->argv[k++] = cc;
    j->argv[k++] = "--toolchain-id";
    j->argv[k++] = SFZ_TOOLCHAIN_ID;
    j->argv[k++] = "--";
    k = put_flags(j, k, f);
    j->argv[k] = NULL;
    return true;
}

static bool job_log(struct sfz_job *j, const struct sfz_run *r, const char *tu,
                    const char *what, const char *phase)
{
    int n = snprintf(j->log, sizeof(j->log), "%s/%s.%s.%s", r->log, tu, phase, what);
    return n >= 0 && (size_t)n < sizeof(j->log) && sfz_parent(j->log);
}

/* gcc -E over every TU, rewriting each depfile as the dev compile does. */
static size_t gcc_depfiles(struct sfz_run *r, const char *ph,
                           const struct sfz_flags *f, struct sfz_job *jobs)
{
    for (size_t k = 0; k < r->tus.n; k++) {
        if (!compile_job(&jobs[k], r->env->gcc, "-E", f, r->tus.v[k], "/dev/null", k) ||
            !job_log(&jobs[k], r, r->tus.v[k], "gcc", ph))
            return 1;
    }
    return run_jobs(r, jobs, r->tus.n);
}

static bool phase_job(struct sfz_run *r, struct sfz_job *jobs, size_t k,
                      const char *ph, const char *objdir, const char *cc,
                      const struct sfz_flags *f, const struct sfz_flags *fs)
{
    const char *tu = r->tus.v[k];
    char obj[PATH_MAX], sensor_path[PATH_MAX];
    bool ok = sfz_object(obj, sizeof(obj), objdir, tu) && sfz_parent(obj) &&
              compile_job(&jobs[2 * k], cc, "-c", f, tu, obj, k) &&
              job_log(&jobs[2 * k], r, tu, "cc", ph) &&
              sensor_job(&jobs[2 * k + 1], r->env->sensor, cc, ph, fs, tu) &&
              job_log(&jobs[2 * k + 1], r, tu, "sensor", ph);
    int n = snprintf(sensor_path, sizeof sensor_path, "%s/%s", r->tree,
                     jobs[2 * k + 1].s[2]);
    return ok && n >= 0 && (size_t)n < sizeof sensor_path && sfz_parent(sensor_path);
}

/* Compile and sense every TU of one side; with gcc_deps, gcc then rewrites
 * each depfile as the dev compile would. */
static bool phase(struct sfz_run *r, const char *ph, const char *objdir)
{
    size_t n = r->tus.n, bad;
    struct sfz_flags f, fs;
    struct sfz_job *jobs = zcl_calloc(2 * n + 1, sizeof(*jobs), "sfz.jobs");
    char facts[PATH_MAX + 16];
    bool ok;
    int facts_n = snprintf(facts, sizeof(facts), "%s/facts/src", r->tree);
    bool after = objdir == r->oa;
    /* the side's object compiler, which the sensor names as the facts
     * rule has it do */
    const char *cc = r->c->cc[after][0] ? r->c->cc[after] : r->env->clang;
    ok = facts_n >= 0 && (size_t)facts_n < sizeof facts && jobs != NULL &&
         read_flags(r, after, false, &f) &&
         read_flags(r, after, true, &fs) &&
         sfz_mkdirs(facts);
    for (size_t k = 0; ok && k < n; k++) {
        ok = phase_job(r, jobs, k, ph, objdir, cc, &f, &fs);
    }
    bad = ok ? run_jobs(r, jobs, 2 * n) : 1;
    if (bad == 0 && r->c->gcc_deps)
        bad = gcc_depfiles(r, ph, &f, jobs);
    free(jobs);
    if (!ok || bad != 0)
        sfz_why(r->out, "%s: %zu compile or sensor run(s) failed, %zu killed "
                "after %d s (logs %s)\n", ph, bad, r->killed, SFZ_JOB_BUDGET_S,
                r->log);
    return ok && bad == 0;
}

/* ---- the layout ------------------------------------------------------------------ */

/* Path p of either side: a TU when it is a .c under src/, changed when one
 * side lacks it or the bytes differ. The .keep markers are neither. */
static bool classify(struct sfz_run *r, const char *p,
                     const struct sfz_paths *before,
                     const struct sfz_paths *after, const char *bdir,
                     const char *adir)
{
    char x[PATH_MAX * 2], y[PATH_MAX * 2];
    const char *slash = strrchr(p, '/');
    if (sfz_paths_has(&r->changed, p) || sfz_paths_has(&r->tus, p) ||
        strcmp(slash ? slash + 1 : p, ".keep") == 0)
        return true;
    if (strncmp(p, "src/", 4) == 0 && is_c(p) && !sfz_paths_add(&r->tus, p))
        return false;
    (void)snprintf(x, sizeof(x), "%s/%s", bdir, p);
    (void)snprintf(y, sizeof(y), "%s/%s", adir, p);
    if (sfz_paths_has(before, p) && sfz_paths_has(after, p) && same_file(x, y))
        return true;
    r->header_changed = r->header_changed || !is_c(p);
    return sfz_paths_add(&r->changed, p);
}

static bool collect(struct sfz_run *r, struct sfz_paths *before,
                    struct sfz_paths *after, const char *bdir, const char *adir)
{
    bool ok = list_tree(bdir, "", before) && list_tree(adir, "", after);
    for (size_t k = 0; ok && k < before->n + after->n; k++)
        ok = classify(r, k < before->n ? before->v[k] : after->v[k - before->n],
                      before, after, bdir, adir);
    sfz_paths_sort(&r->tus);
    sfz_paths_sort(&r->changed);
    return ok;
}

/* The before text of every changed file the before side has, then the
 * after side over the tree, deleting what it no longer has. */
static bool apply_after(struct sfz_run *r, const struct sfz_paths *before,
                        const struct sfz_paths *after, const char *bdir,
                        const char *adir)
{
    char facts[PATH_MAX + 8], gone[PATH_MAX * 2];
    bool ok = true;
    (void)snprintf(facts, sizeof(facts), "%s/facts", r->tree);
    for (size_t k = 0; ok && k < r->changed.n; k++)
        if (sfz_paths_has(before, r->changed.v[k]))
            ok = copy_file(bdir, r->changed.v[k], facts, ".before", true);
    for (size_t k = 0; ok && k < after->n; k++)
        ok = copy_file(adir, after->v[k], r->tree, "", false);
    for (size_t k = 0; ok && k < before->n; k++) {
        if (sfz_paths_has(after, before->v[k]))
            continue;
        (void)snprintf(gone, sizeof(gone), "%s/%s", r->tree, before->v[k]);
        ok = unlink(gone) == 0;
    }
    return ok;
}

static bool layout(struct sfz_run *r, const struct sfz_paths *before)
{
    char bdir[PATH_MAX + 8], deps[PATH_MAX + 16];
    bool ok = true;
    (void)snprintf(bdir, sizeof(bdir), "%s/before", r->c->dir);
    (void)snprintf(r->tree, sizeof(r->tree), "%s/tree", r->c->dir);
    (void)snprintf(r->ob, sizeof(r->ob), "%s/ob", r->c->dir);
    (void)snprintf(r->oa, sizeof(r->oa), "%s/oa", r->c->dir);
    (void)snprintf(r->log, sizeof(r->log), "%s/log", r->c->dir);
    envp_init(r);
    (void)snprintf(deps, sizeof(deps), "%s/build/deps", r->tree);
    for (size_t k = 0; ok && k < before->n; k++)
        ok = copy_file(bdir, before->v[k], r->tree, "", false);
    return ok && sfz_mkdirs(deps) && sfz_mkdirs(r->ob) && sfz_mkdirs(r->oa) &&
           sfz_mkdirs(r->log);
}

static bool run_sides(struct sfz_run *r, const struct sfz_paths *before,
                      const struct sfz_paths *after)
{
    char bdir[PATH_MAX + 8], adir[PATH_MAX + 8];
    (void)snprintf(bdir, sizeof(bdir), "%s/before", r->c->dir);
    (void)snprintf(adir, sizeof(adir), "%s/after", r->c->dir);
    if (!layout(r, before) || !phase(r, "before", r->ob))
        return false;
    if (!apply_after(r, before, after, bdir, adir)) {
        sfz_why(r->out, "cannot lay the after side over %s\n", r->tree);
        return false;
    }
    return phase(r, "after", r->oa);
}

static void run_case(struct sfz_run *r)
{
    struct sfz_paths before = {0}, after = {0};
    char bdir[PATH_MAX + 8], adir[PATH_MAX + 8];
    (void)snprintf(bdir, sizeof(bdir), "%s/before", r->c->dir);
    (void)snprintf(adir, sizeof(adir), "%s/after", r->c->dir);
    r->out->status = SFZ_ERROR;
    if (!collect(r, &before, &after, bdir, adir))
        sfz_why(r->out, "cannot read the case trees under %s\n", r->c->dir);
    else if (r->changed.n == 0)
        r->out->status = SFZ_NOOP;
    else if (run_sides(r, &before, &after) && !sfz_plan_and_judge(r))
        sfz_why(r->out, "the planner failed on %s\n", r->tree);
    sfz_paths_free(&before);
    sfz_paths_free(&after);
}

bool sfz_run_case(const struct sfz_env *env, const struct sfz_case *c,
                  struct sfz_outcome *out)
{
    struct sfz_run r = {.env = env, .c = c, .out = out};
    memset(out, 0, sizeof(*out));
    run_case(&r);
    sfz_paths_free(&r.changed);
    sfz_paths_free(&r.tus);
    if (out->status == SFZ_PASS || out->status == SFZ_NOOP)
        (void)test_rm_rf_recursive(c->dir);
    return out->status != SFZ_ERROR;
}
