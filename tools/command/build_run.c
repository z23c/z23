/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: run one admitted command in a systemd user scope with CPU and
 *          memory limits, a disposable scratch directory and one accounting
 *          line — the execution half of command/build_admit.h.
 */

#include "command/build_admit.h"

#ifndef _WIN32

#include "base/safe_alloc.h"
#include "platform/clock.h"
#include "util/file_tree_ops.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum { BA_CMD_LOG_MAX = 300, BA_CORES_MAX = 1024, BA_SCOPE_FIXED = 40,
       BA_WAIT_POLL_MS = 20 };

struct ba_cores {
    struct { unsigned core, socket; } seen[BA_CORES_MAX];
    size_t count;
};

/* Position of a physical core in order of first appearance. */
static size_t ba_core_index(struct ba_cores *c, unsigned core, unsigned socket)
{
    size_t at = 0;
    while (at < c->count &&
           !(c->seen[at].core == core && c->seen[at].socket == socket))
        at++;
    if (at == c->count && c->count < BA_CORES_MAX) {
        c->seen[c->count].core = core;
        c->seen[c->count++].socket = socket;
    }
    return at;
}

static bool ba_list_add(char *list, size_t cap, size_t *used, unsigned cpu,
                        unsigned count)
{
    int n = snprintf(list + *used, cap - *used, "%s%u", count ? "," : "", cpu);
    if (n < 0 || (size_t)n >= cap - *used)
        return false;
    *used += (size_t)n;
    return true;
}

bool ba_cpu_plan_parse(const char *text, char *list, size_t cap,
                       unsigned *workers)
{
    struct ba_cores cores = { .count = 0 };
    size_t used = 0;
    unsigned count = 0;
    if (!text || !list || cap == 0)
        return false;
    list[0] = '\0';
    for (const char *line = text; line && *line; line = strchr(line, '\n')) {
        unsigned cpu, core, socket;
        if (*line == '\n')
            line++;
        if (sscanf(line, "%u,%u,%u", &cpu, &core, &socket) != 3)
            continue;
        if (ba_core_index(&cores, core, socket) < 2)
            continue;
        if (!ba_list_add(list, cap, &used, cpu, count++))
            return false;
    }
    *workers = count;
    return count >= 4;
}

unsigned ba_reserve_gib_from_env(void)
{
    const char *v = getenv("DEVBUILD_RESERVE_GIB");
    char *end = NULL;
    unsigned long n;
    if (!v || !v[0])
        return BA_DEFAULT_RESERVE_GIB;
    n = strtoul(v, &end, 10);
    return (*end || n > (1ul << 20)) ? BA_DEFAULT_RESERVE_GIB : (unsigned)n;
}

static int ba_disk_admit(const struct ba_config *cfg)
{
    struct statvfs sv;
    if (cfg->reserve_gib == 0)
        return 0;
    if (statvfs(cfg->disk_path, &sv) != 0) {
        (void)fprintf(stderr, "devbuild: cannot measure %s: %s; deferred\n",
                      cfg->disk_path, strerror(errno));
        return BA_EXIT_DEFERRED;
    }
    unsigned long long avail =
        (unsigned long long)sv.f_bavail * (unsigned long long)sv.f_frsize;
    if (avail < ((unsigned long long)cfg->reserve_gib << 30)) {
        (void)fprintf(stderr,
                      "devbuild: %s has fewer than %u GiB available; "
                      "deferred to preserve disk headroom\n",
                      cfg->disk_path, cfg->reserve_gib);
        return BA_EXIT_DEFERRED;
    }
    return 0;
}

static uint64_t ba_mem_available_kib(void)
{
    char line[256];
    unsigned long long kib = 0;
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f)
        return 0;
    while (fgets(line, sizeof(line), f))
        if (sscanf(line, "MemAvailable: %llu", &kib) == 1)
            break;
    fclose(f);
    return kib;
}

static int ba_mem_admit(const struct ba_config *cfg)
{
    if (cfg->need_mem_kib == 0 || ba_mem_available_kib() >= cfg->need_mem_kib)
        return 0;
    (void)fprintf(stderr, "devbuild: fewer than %llu GiB available; deferred\n",
                  (unsigned long long)(cfg->need_mem_kib >> 20));
    return BA_EXIT_DEFERRED;
}

/* ---- scratch ---------------------------------------------------------- */

struct ba_scratch {
    char dir[BA_PATH_MAX];
    int fd; /* holds the job's exclusive flock; inherited by descendants */
};

static int ba_scratch_open(const struct ba_config *cfg, struct ba_scratch *sc)
{
    char pool[BA_PATH_MAX];
    sc->fd = -1;
    int n = snprintf(pool, sizeof(pool), "%s/z23", cfg->scratch_root);
    if (n <= 0 || (size_t)n >= sizeof(pool) ||
        !zcl_mkdir_p(pool, 0700).ok ||
        snprintf(sc->dir, sizeof(sc->dir), "%s/job.XXXXXX", pool) >=
            (int)sizeof(sc->dir) ||
        !mkdtemp(sc->dir)) {
        (void)fprintf(stderr, "devbuild: cannot create scratch under %s: %s\n",
                      cfg->scratch_root, strerror(errno));
        return BA_EXIT_SCRATCH;
    }
    sc->fd = open(sc->dir, O_RDONLY | O_DIRECTORY);
    if (sc->fd < 0 || flock(sc->fd, LOCK_EX) != 0) {
        (void)fprintf(stderr, "devbuild: cannot lock scratch %s: %s\n",
                      sc->dir, strerror(errno));
        return BA_EXIT_SCRATCH;
    }
    (void)fprintf(stderr,
                  "devbuild: disposable build scratch %s (released on "
                  "success; failures retained; live jobs locked)\n", sc->dir);
    return 0;
}

/* A tree the job left read-only cannot be removed; give the owner access
 * to every directory first. */
static void ba_make_writable(const char *path, int depth)
{
    struct stat sb;
    DIR *d;
    if (depth > 64 || lstat(path, &sb) != 0 || !S_ISDIR(sb.st_mode))
        return;
    (void)chmod(path, (sb.st_mode & 07777) | S_IRWXU);
    d = opendir(path);
    for (struct dirent *e = d ? readdir(d) : NULL; e; e = readdir(d)) {
        char child[BA_PATH_MAX];
        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0 &&
            snprintf(child, sizeof(child), "%s/%s", path, e->d_name) <
                (int)sizeof(child))
            ba_make_writable(child, depth + 1);
    }
    if (d)
        closedir(d);
}

static bool ba_remove_scratch(const char *dir)
{
    ba_make_writable(dir, 0);
    return zcl_tree_remove(dir).ok;
}

static bool ba_link_under(const char *link, const char *dir, size_t len)
{
    char target[BA_PATH_MAX];
    ssize_t n = readlink(link, target, sizeof(target) - 1u);
    if (n <= 0)
        return false;
    target[n] = '\0';
    return strncmp(target, dir, len) == 0 &&
           (target[len] == '\0' || target[len] == '/');
}

static bool ba_proc_holds(const char *pid, const char *dir, size_t len)
{
    char path[64], fdpath[320];
    static const char *const fixed[] = { "cwd", "root", "exe" };
    for (size_t i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++) {
        (void)snprintf(path, sizeof(path), "/proc/%s/%s", pid, fixed[i]);
        if (ba_link_under(path, dir, len))
            return true;
    }
    (void)snprintf(path, sizeof(path), "/proc/%s/fd", pid);
    DIR *d = opendir(path);
    for (struct dirent *e = d ? readdir(d) : NULL; e; e = readdir(d)) {
        (void)snprintf(fdpath, sizeof(fdpath), "%s/%s", path, e->d_name);
        if (e->d_name[0] != '.' && ba_link_under(fdpath, dir, len)) {
            closedir(d);
            return true;
        }
    }
    if (d)
        closedir(d);
    return false;
}

/* True when another process of this user has `dir` as cwd, root, binary or
 * an open file, or when /proc cannot be read: removal is then unsafe. */
static bool ba_scratch_in_use(const char *dir)
{
    size_t len = strlen(dir);
    DIR *proc = opendir("/proc");
    if (!proc)
        return true;
    for (struct dirent *e = readdir(proc); e; e = readdir(proc)) {
        char path[64];
        struct stat sb;
        if (e->d_name[0] < '1' || e->d_name[0] > '9' ||
            atoi(e->d_name) == (int)getpid())
            continue;
        (void)snprintf(path, sizeof(path), "/proc/%s", e->d_name);
        if (stat(path, &sb) == 0 && sb.st_uid == geteuid() &&
            ba_proc_holds(e->d_name, dir, len)) {
            closedir(proc);
            return true;
        }
    }
    closedir(proc);
    return false;
}

/* Release the scratch of a successful job; keep it for a failed one, for
 * DEVBUILD_KEEP_SCRATCH, and whenever a descendant still holds its lock or
 * any process still has a path in it open. */
static void ba_scratch_finish(const struct ba_config *cfg,
                              struct ba_scratch *sc, int rc)
{
    int check;
    close(sc->fd);
    if (rc != 0 || cfg->keep_scratch) {
        (void)fprintf(stderr, "devbuild: retained scratch %s (exit %d)\n",
                      sc->dir, rc);
        return;
    }
    check = open(sc->dir, O_RDONLY | O_DIRECTORY);
    if (check < 0 || flock(check, LOCK_EX | LOCK_NB) != 0)
        (void)fprintf(stderr,
                      "devbuild: scratch still held by a descendant: %s\n",
                      sc->dir);
    else if (ba_scratch_in_use(sc->dir))
        (void)fprintf(stderr, "devbuild: retaining scratch because open-path "
                      "safety is unresolved: %s\n", sc->dir);
    else if (ba_remove_scratch(sc->dir))
        (void)fprintf(stderr, "devbuild: released successful scratch %s\n",
                      sc->dir);
    else
        (void)fprintf(stderr, "devbuild: scratch cleanup incomplete: %s\n",
                      sc->dir);
    if (check >= 0)
        close(check);
}

/* ---- scope command line ------------------------------------------------ */

struct ba_scope {
    char unit[112], quota[64], memory[48], weight[48];
    char env_active[40], env_zcc[40], env_tmp[BA_PATH_MAX + 16];
    const char **argv;
};

static const char *ba_fmt(char *slot, size_t cap, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static const char *ba_fmt(char *slot, size_t cap, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(slot, cap, fmt, ap);
    va_end(ap);
    return slot;
}

/* The wrapper's systemd-run line, property for property. */
static size_t ba_scope_head(const struct ba_config *cfg, struct ba_scope *s,
                            const char **v)
{
    struct timespec ts;
    size_t n = 0;
    (void)clock_gettime(CLOCK_REALTIME, &ts); // platform-ok: unit names need sub-second uniqueness only
    v[n++] = cfg->scope_launcher;
    v[n++] = "--user";
    v[n++] = "--scope";
    v[n++] = "--quiet";
    v[n++] = ba_fmt(s->unit, sizeof(s->unit),
                    "--unit=devbuild-%d-%lld%09ld.scope", (int)getpid(),
                    (long long)ts.tv_sec, ts.tv_nsec);
    v[n++] = "--slice=development.slice";
    v[n++] = ba_fmt(s->quota, sizeof(s->quota), "--property=CPUQuota=%u%%",
                    cfg->cpu_workers * 100u);
    v[n++] = "--property=MemoryMax=24G";
    v[n++] = "--property=MemorySwapMax=0";
    v[n++] = "--property=CPUWeight=20";
    v[n++] = "--property=IOWeight=20";
    v[n++] = "--";
    return n;
}

static size_t ba_scope_env(const struct ba_config *cfg,
                           const struct ba_scratch *sc, struct ba_scope *s,
                           const char **v, size_t n)
{
    v[n++] = "/usr/bin/env";
    v[n++] = "DEVBUILD_ACTIVE=z23";
    v[n++] = ba_fmt(s->env_zcc, sizeof(s->env_zcc), "ZCC_MAX_MB=%u",
                    cfg->zcc_max_mb);
    if (sc)
        v[n++] = ba_fmt(s->env_tmp, sizeof(s->env_tmp), "TMPDIR=%s", sc->dir);
    v[n++] = "/usr/bin/nice";
    v[n++] = "-n";
    v[n++] = "10";
    v[n++] = "/usr/bin/ionice";
    v[n++] = "-c";
    v[n++] = "2";
    v[n++] = "-n";
    v[n++] = "7";
    v[n++] = "/usr/bin/taskset";
    v[n++] = "--cpu-list";
    v[n++] = cfg->cpu_list;
    return n;
}

static bool ba_scope_build(const struct ba_config *cfg,
                           const struct ba_scratch *sc,
                           const char *const *cmd, int argc,
                           struct ba_scope *s)
{
    const char **v = zcl_calloc((size_t)argc + BA_SCOPE_FIXED, sizeof(*v),
                              "build_scope_argv");
    size_t n;
    if (!v)
        return false;
    n = ba_scope_env(cfg, sc, s, v, ba_scope_head(cfg, s, v));
    for (int i = 0; i < argc; i++)
        v[n++] = cmd[i];
    v[n] = NULL;
    s->argv = v;
    return true;
}

/* ---- execution --------------------------------------------------------- */

static void ba_run_nap(unsigned ms)
{
    struct timespec ts = { .tv_sec = ms / 1000u,
                           .tv_nsec = (long)(ms % 1000u) * 1000000L };
    (void)nanosleep(&ts, NULL);
}

static void ba_default_signals(void)
{
    static const int sigs[] = { SIGINT, SIGTERM, SIGHUP, SIGCHLD };
    for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++)
        (void)signal(sigs[i], SIG_DFL);
}

/* Wait for `pid`, forwarding a stop signal as soon as one is pending. The
 * flag is polled between short naps, so a signal that arrived before the
 * first wait is forwarded too. Returns the wait status, or -1 on failure. */
static int ba_wait_forwarding(pid_t pid)
{
    int status = 0;
    for (;;) {
        pid_t done = waitpid(pid, &status, WNOHANG);
        int sig = ba_stop_signal();
        if (done == pid)
            return status;
        if (done < 0 && errno != EINTR)
            return -1;
        if (sig) {
            (void)kill(pid, sig);
            ba_request_stop(0);
        }
        if (done == 0)
            ba_run_nap(BA_WAIT_POLL_MS);
    }
}

/* fork and exec with the caller's stdio; an exec failure travels back over a
 * close-on-exec pipe so it is reported rather than mistaken for a job exit.
 * SIGCHLD is default in the parent while it waits and in the child, so an
 * inherited SIG_IGN neither discards the exit status nor reaches the job. */
static int ba_exec_wait(char *const *argv, mode_t command_umask,
                        struct rusage *usage)
{
    int err = 0, status, ep[2];
    pid_t pid;
    ssize_t got;
    struct sigaction chld_saved, chld_dfl;
    if (pipe(ep) != 0)
        return 71;
    (void)fcntl(ep[0], F_SETFD, FD_CLOEXEC);
    (void)fcntl(ep[1], F_SETFD, FD_CLOEXEC);
    memset(&chld_dfl, 0, sizeof(chld_dfl));
    chld_dfl.sa_handler = SIG_DFL;
    sigemptyset(&chld_dfl.sa_mask);
    (void)sigaction(SIGCHLD, &chld_dfl, &chld_saved);
    pid = fork();
    if (pid < 0) {
        close(ep[0]);
        close(ep[1]);
        (void)sigaction(SIGCHLD, &chld_saved, NULL);
        return 71;
    }
    if (pid == 0) {
        ba_default_signals();
        (void)umask(command_umask);
        execvp(argv[0], argv);
        err = errno;
        (void)!write(ep[1], &err, sizeof(err));
        _exit(127);
    }
    close(ep[1]);
    do {
        got = read(ep[0], &err, sizeof(err));
    } while (got < 0 && errno == EINTR);
    close(ep[0]);
    status = ba_wait_forwarding(pid);
    (void)sigaction(SIGCHLD, &chld_saved, NULL);
    if (status < 0)
        return 71;
    (void)getrusage(RUSAGE_CHILDREN, usage);
    if (got == (ssize_t)sizeof(err))
        (void)fprintf(stderr, "devbuild: cannot execute %s: %s\n", argv[0],
                      strerror(err));
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

/* ---- accounting -------------------------------------------------------- */

static void ba_clean_text(char *dst, size_t cap, const char *src)
{
    size_t n = 0;
    for (; *src && n + 1u < cap; src++)
        if ((unsigned char)*src >= 0x20 && *src != '"' && *src != '\\')
            dst[n++] = *src;
    dst[n] = '\0';
}

static void ba_command_text(char *dst, size_t cap, const char *const *argv,
                            int argc)
{
    char joined[BA_CMD_LOG_MAX + 1];
    size_t n = 0;
    for (int i = 0; i < argc && n < BA_CMD_LOG_MAX; i++) {
        for (const char *p = argv[i]; *p && n < BA_CMD_LOG_MAX; p++)
            joined[n++] = *p;
        if (n < BA_CMD_LOG_MAX)
            joined[n++] = ' ';
    }
    joined[n] = '\0';
    ba_clean_text(dst, cap, joined);
}

struct ba_times {
    time_t queued, started;
};

/* One JSON line per job, appended in the wrapper's field order. Best effort;
 * it never fails the build. Peak memory and the checkout fingerprint are not
 * measured here and are written as 0 and "". */
static void ba_account(const struct ba_config *cfg, const char *const *argv,
                       int argc, const struct ba_times *t, int rc, int lane,
                       const struct rusage *usage)
{
    char cwd[BA_PATH_MAX] = "", clean_cwd[BA_PATH_MAX], cmd[BA_CMD_LOG_MAX + 1];
    char path[BA_PATH_MAX], line[2 * BA_PATH_MAX + 512];
    time_t ended = (time_t)(clock_now_wall_ms() / 1000);
    long cpu_s = (long)(usage->ru_utime.tv_sec + usage->ru_stime.tv_sec);
    int n, fd;
    if (!getcwd(cwd, sizeof(cwd)))
        cwd[0] = '\0';
    ba_clean_text(clean_cwd, sizeof(clean_cwd), cwd);
    ba_command_text(cmd, sizeof(cmd), argv, argc);
    n = snprintf(line, sizeof(line),
                 "{\"project\":\"z23\",\"pid\":%d,\"cwd\":\"%s\",\"queued\":%lld,"
                 "\"started\":%lld,\"ended\":%lld,\"wait_s\":%lld,\"run_s\":%lld,"
                 "\"rc\":%d,\"lane\":%d,\"mem_peak_mib\":0,\"cpu_s\":%ld,"
                 "\"tree\":\"\",\"cmd\":\"%s\"}\n",
                 (int)getpid(), clean_cwd, (long long)t->queued,
                 (long long)t->started, (long long)ended,
                 (long long)(t->started - t->queued),
                 (long long)(ended - t->started), rc, lane, cpu_s, cmd);
    if (n <= 0 || (size_t)n >= sizeof(line) ||
        snprintf(path, sizeof(path), "%s/devbuild.jobs.jsonl",
                 cfg->state_dir) >= (int)sizeof(path))
        return;
    fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
    if (fd >= 0) {
        (void)!write(fd, line, (size_t)n);
        close(fd);
    }
}

/* ---- run ---------------------------------------------------------------- */

static const int ba_signals[] = { SIGINT, SIGTERM, SIGHUP };

static void ba_signals_install(struct sigaction saved[3])
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = ba_request_stop;
    sigemptyset(&sa.sa_mask);
    for (size_t i = 0; i < 3; i++)
        (void)sigaction(ba_signals[i], &sa, &saved[i]);
    ba_request_stop(0);
}

static void ba_signals_restore(const struct sigaction saved[3])
{
    for (size_t i = 0; i < 3; i++)
        (void)sigaction(ba_signals[i], &saved[i], NULL);
}

/* Memory and reserve checks, then the scoped command. Called with the slot
 * held; the scratch is created here and settled after the command. */
static int ba_run_admitted(const struct ba_config *cfg,
                           const char *const *argv, int argc,
                           mode_t command_umask, const struct ba_slot *slot,
                           struct rusage *usage)
{
    struct ba_scratch sc = { .fd = -1 };
    struct ba_scope scope;
    bool use_scratch = !cfg->tmpdir_set;
    int rc = ba_mem_admit(cfg);
    if (rc == 0)
        rc = ba_disk_admit(cfg);
    if (rc != 0)
        return rc;
    (void)fprintf(stderr, "devbuild: z23 lane %d, CPUs %s, memory 24G\n",
                  slot->lane, cfg->cpu_list);
    if (use_scratch && (rc = ba_scratch_open(cfg, &sc)) != 0)
        return rc;
    if (!ba_scope_build(cfg, use_scratch ? &sc : NULL, argv, argc, &scope)) {
        (void)fprintf(stderr, "devbuild: out of memory\n");
        return 71;
    }
    rc = ba_exec_wait((char *const *)scope.argv, command_umask, usage);
    free(scope.argv);
    if (use_scratch)
        ba_scratch_finish(cfg, &sc, rc);
    return rc;
}

int ba_run(const struct ba_config *cfg, const char *const *argv, int argc)
{
    struct sigaction saved[3];
    struct ba_slot slot;
    struct ba_times t = { .queued = (time_t)(clock_now_wall_ms() / 1000) };
    struct rusage usage;
    mode_t command_umask = umask(077);
    int rc = ba_disk_admit(cfg);
    memset(&usage, 0, sizeof(usage));
    if (argc <= 0 || rc != 0) {
        (void)umask(command_umask);
        return rc ? rc : BA_EXIT_USAGE;
    }
    ba_signals_install(saved);
    rc = ba_admit(cfg, &slot);
    if (rc == 0) {
        t.started = (time_t)(clock_now_wall_ms() / 1000);
        rc = ba_run_admitted(cfg, argv, argc, command_umask, &slot, &usage);
        ba_account(cfg, argv, argc, &t, rc, slot.lane, &usage);
        ba_slot_release(&slot);
    }
    ba_signals_restore(saved);
    (void)umask(command_umask);
    return rc;
}

#endif /* _WIN32 */
