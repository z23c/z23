/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: `z23-lint unit-exec` — run one lint unit inside a Landlock domain
 * that can read exactly its declared premise, so a premise that is missing
 * an input fails closed instead of silently reading it.
 *
 *   z23-lint unit-exec --root=DIR --premise=FILE --scratch=DIR
 *       [--toolchain=PATH]... [--env=NAME=VALUE]... [--no-landlock]
 *       -- COMMAND [ARGS...]
 *
 * The premise file lists root-relative regular files, one per line; each
 * becomes a read-only Landlock rule on that one file, so no repository
 * directory is listable and no undeclared file is readable. The toolchain
 * roots (system bin/lib/include trees plus any --toolchain) are read and
 * execute, the private scratch is read/write/create and becomes HOME and
 * TMPDIR, and /dev/null is read/write. The child gets a scrubbed
 * environment, no inherited descriptors above stderr, no_new_privs, and a
 * seccomp filter that kills any socket-family call (no TCP, no Unix IPC).
 *
 * Verdict (last stderr line `unit-exec: verdict=...`, and the exit code):
 *   PASS 0 | FAIL 1 | PREMISE_INCOMPLETE 3 (an EACCES / "Permission denied"
 *   reached the unit's stderr) | UNCONFINED 4 (Landlock unavailable or
 *   forced off: the unit is NOT run and nothing may inherit) |
 *   REFUSED 5 (killed by the syscall filter) | 2 usage or setup refusal.
 * Enforcement is through platform/os_sandbox.h only.
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "premise.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/syscall.h>
#endif

#include "platform/os_sandbox.h"

enum {
    UE_PASS = 0, UE_FAIL = 1, UE_USAGE = 2, UE_PREMISE_INCOMPLETE = 3,
    UE_UNCONFINED = 4, UE_REFUSED = 5, UE_SETUP = 125,
    UE_MAX_ENV = 32, UE_MAX_TOOLCHAIN = 32,
};

static const char *const k_toolchain_roots[] = {
    "/usr/bin", "/bin", "/usr/lib", "/lib", "/lib64", "/usr/lib64",
    "/usr/libexec", "/usr/include", "/usr/local/include",
    "/usr/x86_64-w64-mingw32", "/etc/ld.so.cache",
};

#if defined(__linux__)
static const int k_denied[] = {
    SYS_socket, SYS_socketpair, SYS_connect, SYS_bind, SYS_listen,
    SYS_accept, SYS_accept4, SYS_sendto, SYS_recvfrom, SYS_sendmsg,
    SYS_recvmsg, SYS_shutdown, SYS_setsockopt, SYS_getsockopt,
    SYS_getsockname, SYS_getpeername,
#ifdef SYS_socketcall
    SYS_socketcall,
#endif
    SYS_ptrace, SYS_process_vm_readv, SYS_process_vm_writev,
    SYS_mount, SYS_umount2, SYS_pivot_root, SYS_setns, SYS_unshare,
    SYS_bpf, SYS_perf_event_open, SYS_open_by_handle_at,
};
#endif

struct ue_opts {
    const char *root;
    const char *premise;
    const char *scratch;
    const char *toolchain[UE_MAX_TOOLCHAIN];
    size_t ntoolchain;
    const char *env[UE_MAX_ENV];
    size_t nenv;
    bool no_landlock;
    char **cmd;
    char root_abs[PREMISE_PATH_MAX];
    char scratch_abs[PREMISE_PATH_MAX];
};

struct ue_rules {
    struct os_sandbox_path_rule *v;
    size_t n;
    char **owned;
    size_t nowned;
};

static bool opt_val(const char *arg, const char *name, const char **out)
{
    size_t n = strlen(name);
    if (strncmp(arg, name, n) != 0 || arg[n] != '=')
        return false;
    *out = arg + n + 1;
    return true;
}

static int parse_one(struct ue_opts *o, const char *a)
{
    const char *v = NULL;
    if (opt_val(a, "--root", &o->root) || opt_val(a, "--premise", &o->premise)
        || opt_val(a, "--scratch", &o->scratch))
        return 0;
    if (opt_val(a, "--toolchain", &v) && o->ntoolchain < UE_MAX_TOOLCHAIN) {
        o->toolchain[o->ntoolchain++] = v;
        return 0;
    }
    if (opt_val(a, "--env", &v) && strchr(v, '=') && o->nenv < UE_MAX_ENV) {
        o->env[o->nenv++] = v;
        return 0;
    }
    if (strcmp(a, "--no-landlock") == 0) {
        o->no_landlock = true;
        return 0;
    }
    return 2;
}

static int parse(struct ue_opts *o, int argc, char **argv)
{
    memset(o, 0, sizeof *o);
    int i = 0;
    for (; i < argc && strcmp(argv[i], "--") != 0; i++)
        if (parse_one(o, argv[i])) {
            fprintf(stderr, "unit-exec: unknown argument %s\n", argv[i]);
            return 2;
        }
    if (i + 1 >= argc || !o->root || !o->premise || !o->scratch)
        return 2;
    o->cmd = argv + i + 1;
    /* Rules are opened in the child after chdir(root): absolute only. */
    if (!realpath(o->root, o->root_abs) || !realpath(o->scratch, o->scratch_abs)) {
        fprintf(stderr, "unit-exec: root and scratch must exist\n");
        return 2;
    }
    o->root = o->root_abs;
    o->scratch = o->scratch_abs;
    return 0;
}

static int rule_add(struct ue_rules *r, const char *path, bool read, bool write,
                    bool exec, bool create)
{
    struct os_sandbox_path_rule *grown = realloc(r->v, (r->n + 1) * sizeof *grown); // raw-alloc-ok:lint-runtime
    if (!grown)
        return 2;
    r->v = grown;
    r->v[r->n++] = (struct os_sandbox_path_rule){
        .path = path, .allow_read = read, .allow_write = write,
        .allow_execute = exec, .allow_create = create };
    return 0;
}

static int own(struct ue_rules *r, char *s)
{
    char **grown = realloc(r->owned, (r->nowned + 1) * sizeof *grown); // raw-alloc-ok:lint-runtime
    if (!grown) {
        free(s);
        return 2;
    }
    r->owned = grown;
    r->owned[r->nowned++] = s;
    return 0;
}

static bool rel_path_ok(const char *p)
{
    if (!p[0] || p[0] == '/' || strstr(p, "//"))
        return false;
    for (const char *c = p; c;) {
        if (strncmp(c, "..", 2) == 0 && (c[2] == '/' || c[2] == '\0'))
            return false;
        if (c[0] == '.' && (c[1] == '/' || c[1] == '\0'))
            return false;
        c = strchr(c, '/');
        c = c ? c + 1 : NULL;
    }
    return true;
}

/* One declared premise file: root-relative, a regular file (never a
 * directory — a directory rule would grant its whole subtree — and never
 * a symlink, whose target could leave the premise). */
static int premise_line(struct ue_rules *r, const char *root, const char *rel)
{
    size_t cap = strlen(root) + strlen(rel) + 2;
    char *full = malloc(cap); // raw-alloc-ok:lint-runtime
    if (!full)
        return 2;
    snprintf(full, cap, "%s/%s", root, rel);
    struct stat st;
    if (!rel_path_ok(rel) || lstat(full, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "unit-exec: premise entry is not a regular file under "
                        "the root: %s\n", rel);
        free(full);
        return 2;
    }
    if (own(r, full))
        return 2;
    return rule_add(r, full, true, false, false, false);
}

static int load_premise(struct ue_rules *r, const struct ue_opts *o)
{
    FILE *f = fopen(o->premise, "r");
    if (!f) {
        fprintf(stderr, "unit-exec: cannot read premise %s\n", o->premise);
        return 2;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
            line[--n] = '\0';
        if (n > 0)
            rc = premise_line(r, o->root, line);
    }
    free(line);
    fclose(f);
    return rc;
}

static int toolchain_rules(struct ue_rules *r, const struct ue_opts *o)
{
    int rc = 0;
    struct stat st;
    for (size_t i = 0; rc == 0 && i < sizeof k_toolchain_roots / sizeof *k_toolchain_roots; i++)
        if (stat(k_toolchain_roots[i], &st) == 0)
            rc = rule_add(r, k_toolchain_roots[i], true, false, true, false);
    for (size_t i = 0; rc == 0 && i < o->ntoolchain; i++)
        rc = rule_add(r, o->toolchain[i], true, false, true, false);
    if (rc == 0)
        rc = rule_add(r, "/dev/null", true, true, false, false);
    if (rc == 0)
        rc = rule_add(r, o->scratch, true, true, false, true);
    return rc;
}

static void rules_free(struct ue_rules *r)
{
    for (size_t i = 0; i < r->nowned; i++)
        free(r->owned[i]);
    free(r->owned);
    free(r->v);
}

static void close_above(int keep)
{
    long max = sysconf(_SC_OPEN_MAX);
    for (int fd = 3; fd < (max > 0 && max < 65536 ? (int)max : 65536); fd++)
        if (fd != keep)
            (void)close(fd);
}

struct ue_env {
    char *v[UE_MAX_ENV + 5];
    char store[UE_MAX_ENV + 4][PREMISE_PATH_MAX + 16];
};

static void child_env(const struct ue_opts *o, struct ue_env *e)
{
    size_t n = 0;
    snprintf(e->store[n++], sizeof e->store[0], "PATH=/usr/bin:/bin");
    snprintf(e->store[n++], sizeof e->store[0], "LC_ALL=C");
    snprintf(e->store[n++], sizeof e->store[0], "HOME=%s", o->scratch);
    snprintf(e->store[n++], sizeof e->store[0], "TMPDIR=%s", o->scratch);
    for (size_t i = 0; i < o->nenv; i++)
        snprintf(e->store[n++], sizeof e->store[0], "%s", o->env[i]);
    for (size_t i = 0; i < n; i++)
        e->v[i] = e->store[i];
    e->v[n] = NULL;
}

/* execvp without the caller's PATH: a bare name resolves in /usr/bin then
 * /bin, exactly the PATH the unit itself sees. */
static void exec_unit(char **cmd, char **envp)
{
    static const char *const k_dirs[] = { "/usr/bin", "/bin" };
    if (strchr(cmd[0], '/')) {
        execve(cmd[0], cmd, envp);
        return;
    }
    for (size_t i = 0; i < sizeof k_dirs / sizeof *k_dirs; i++) {
        char path[PREMISE_PATH_MAX];
        int k = snprintf(path, sizeof path, "%s/%s", k_dirs[i], cmd[0]);
        if (k > 0 && (size_t)k < sizeof path)
            execve(path, cmd, envp);
    }
}

static struct zcl_result deny_syscalls(void)
{
#if defined(__linux__)
    return os_sandbox_seccomp_deny(k_denied, sizeof k_denied / sizeof *k_denied,
                                   false);
#else
    return ZCL_ERR(OS_SANDBOX_ERR_SECCOMP_UNAVAILABLE,
                   "no syscall filter on this host");
#endif
}

static void child_run(const struct ue_opts *o, const struct ue_rules *r,
                      int err_fd)
{
    if (dup2(err_fd, 2) < 0)
        _exit(UE_SETUP);
    close_above(-1);
    if (chdir(o->root) != 0)
        _exit(UE_SETUP);
    static struct ue_env env;
    child_env(o, &env);
    if (!os_sandbox_no_new_privs()) {
        fputs("unit-exec: SETUP no_new_privs refused\n", stderr);
        _exit(UE_SETUP);
    }
    struct zcl_result lr = os_sandbox_landlock_restrict(r->v, r->n);
    struct zcl_result sr = lr.ok ? deny_syscalls() : lr;
    if (!sr.ok) {
        fprintf(stderr, "unit-exec: SETUP confinement refused: %s\n", sr.message);
        _exit(UE_SETUP);
    }
    exec_unit(o->cmd, env.v);
    fprintf(stderr, "unit-exec: exec %s: %s\n", o->cmd[0], strerror(errno));
    _exit(127);
}

struct ue_scan {
    char carry[64];
    size_t ncarry;
    bool denied;
    bool setup_refused;
};

static void scan_chunk(struct ue_scan *s, const char *buf, size_t n)
{
    char window[64 + 4096];
    memcpy(window, s->carry, s->ncarry);
    memcpy(window + s->ncarry, buf, n);
    size_t len = s->ncarry + n;
    window[len] = '\0';
    if (strstr(window, "Permission denied") || strstr(window, "EACCES"))
        s->denied = true;
    if (strstr(window, "unit-exec: SETUP"))
        s->setup_refused = true;
    s->ncarry = len < 32 ? len : 32;
    memmove(s->carry, window + len - s->ncarry, s->ncarry);
}

static void relay(int fd, struct ue_scan *s)
{
    char buf[4096];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf - 1);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return;
        (void)!write(2, buf, (size_t)n);
        scan_chunk(s, buf, (size_t)n);
    }
}

static int verdict(int st, const struct ue_scan *s, size_t nfiles)
{
    const char *name = "FAIL";
    int code = UE_FAIL;
    if (WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS) {
        name = "REFUSED";
        code = UE_REFUSED;
    } else if (s->setup_refused || (WIFEXITED(st) && WEXITSTATUS(st) == UE_SETUP)) {
        name = "UNCONFINED";
        code = UE_UNCONFINED;
    } else if (s->denied) {
        name = "PREMISE_INCOMPLETE";
        code = UE_PREMISE_INCOMPLETE;
    } else if (WIFEXITED(st) && WEXITSTATUS(st) == 0) {
        name = "PASS";
        code = UE_PASS;
    }
    fprintf(stderr, "unit-exec: verdict=%s rc=%d signal=%d confined=%d "
                    "premise_files=%zu\n", name,
            WIFEXITED(st) ? WEXITSTATUS(st) : -1,
            WIFSIGNALED(st) ? WTERMSIG(st) : 0, code != UE_UNCONFINED, nfiles);
    return code;
}

static int run_confined(const struct ue_opts *o, const struct ue_rules *r,
                        size_t nfiles)
{
    int p[2];
    if (pipe(p) != 0)
        return UE_USAGE;
    fflush(NULL);
    pid_t pid = fork();
    if (pid == 0) {
        close(p[0]);
        child_run(o, r, p[1]);
    }
    close(p[1]);
    if (pid < 0) {
        close(p[0]);
        return UE_USAGE;
    }
    struct ue_scan scan = { .ncarry = 0 };
    relay(p[0], &scan);
    close(p[0]);
    int st = 0;
    while (waitpid(pid, &st, 0) < 0)
        if (errno != EINTR)
            return UE_USAGE;
    return verdict(st, &scan, nfiles);
}

static bool landlock_available(const struct ue_opts *o, int *abi)
{
    *abi = o->no_landlock ? -1 : os_sandbox_landlock_abi();
    return *abi >= 1;
}

int lint_unit_exec_main(int argc, char **argv)
{
    struct ue_opts o;
    if (parse(&o, argc, argv)) {
        fprintf(stderr, "z23-lint: usage: z23-lint unit-exec --root=DIR "
                        "--premise=FILE --scratch=DIR [--toolchain=PATH]... "
                        "[--env=NAME=VALUE]... [--no-landlock] -- COMMAND "
                        "[ARGS...]\n");
        return UE_USAGE;
    }
    int abi = -1;
    if (!landlock_available(&o, &abi)) {
        fprintf(stderr, "unit-exec: verdict=UNCONFINED rc=-1 signal=0 "
                        "confined=0 reason=%s — the unit was not run and "
                        "nothing may inherit\n",
                o.no_landlock ? "landlock-forced-off" : "landlock-unavailable");
        return UE_UNCONFINED;
    }
    struct ue_rules r = { 0 };
    int rc = load_premise(&r, &o);
    size_t nfiles = r.n;
    if (rc == 0)
        rc = toolchain_rules(&r, &o);
    rc = rc ? UE_USAGE : run_confined(&o, &r, nfiles);
    rules_free(&r);
    return rc;
}
