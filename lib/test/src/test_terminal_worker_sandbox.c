/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Attack acceptance for the TERMINAL WORKER confinement profile
 * (os_sandbox_terminal_worker_profile) — the cage the confined fbsh shell
 * actually runs in. The worker, unlike the session child, KEEPS the
 * fork/exec family (the shell must spawn its own children), so these tests
 * pin the exact distinction: Landlock bounds what execve can reach (the
 * per-terminal tmpdir plus the one granted shell binary), the deny-list
 * keeps the socket/debug/escape surface, W^X holds, and the rlimit budget
 * bites. Per the operating rule the tests ATTACK: read /etc/shadow, open
 * sockets, exec outside the grant, overrun budgets — the sandbox has to
 * WIN those fights; and when build/bin/fbsh is present the granted shell
 * must still WORK inside the cage (and its own escape attempts must fail).
 *
 * Every destructive assertion runs in a FRESHLY FORKED child judged by
 * exit status / terminating signal, mirroring test_os_sandbox. The fbsh
 * cases SKIP (never fail) when build/bin/fbsh is absent — it is a
 * standalone `make fbsh` artifact, deliberately outside the test
 * binaries' prerequisites.
 */

#define _GNU_SOURCE  /* fork, mmap — must precede every include */

#include "test/test_core.h"

#include <stdio.h>

#if defined(__linux__)
#include "platform/os_sandbox.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#if !defined(__linux__)

static int test_terminal_worker_sandbox_platform_arm(void)
{
    printf("\n=== terminal worker sandbox tests ===\n");
    printf("terminal_worker_sandbox: Linux confinement — not applicable here\n");
    return 0;
}

#else

#define FBSH_BIN "build/bin/fbsh"

static char g_tw_dir[160];
/* Absolutized once at runner start: Landlock rules resolve against the
 * cwd at enter() time, and the fbsh children chdir into the grant before
 * entering, so a relative rule path would break resolution. */
static char g_tw_fbsh[600];

static const char *tw_fbsh_path(void)
{
    return g_tw_fbsh[0] ? g_tw_fbsh : FBSH_BIN;
}

static bool fbsh_available(void)
{
    struct stat st;
    return stat(tw_fbsh_path(), &st) == 0 && (st.st_mode & S_IXUSR) != 0;
}

/* Generic attacks need only the per-terminal tmpdir grant.  The executable
 * grant belongs only to the fbsh-specific cases, and only when the standalone
 * artifact actually exists.  Keeping that choice explicit prevents an
 * ambient `make fbsh` from silently broadening every generic attack profile. */
static size_t tw_rules(struct os_sandbox_path_rule *rules, bool include_fbsh)
{
    rules[0] = (struct os_sandbox_path_rule){
        .path = g_tw_dir, .allow_read = true, .allow_write = true,
        .allow_execute = true, .allow_create = true,
    };
    if (include_fbsh && fbsh_available()) {
        rules[1] = (struct os_sandbox_path_rule){
            .path = tw_fbsh_path(), .allow_read = true, .allow_execute = true,
        };
        return 2;
    }
    return 1;
}

/* Run fn() in a forked child. Returns the child's exit code (>= 0) or the
 * NEGATED terminating signal (< 0). The parent (the test-group process)
 * is never sandboxed. */
static int tw_run_child(int (*fn)(void))
{
    pid_t pid = fork();
    if (pid < 0) return -1000;
    if (pid == 0) _exit(fn());
    int st = 0;
    if (waitpid(pid, &st, 0) != pid) return -1001;
    if (WIFSIGNALED(st)) return -WTERMSIG(st);
    return WEXITSTATUS(st);
}

static int tw_enter(bool include_fbsh)
{
    struct os_sandbox_path_rule rules[2];
    size_t rule_count = tw_rules(rules, include_fbsh);
    struct os_sandbox_profile p =
        os_sandbox_terminal_worker_profile(rules, rule_count);
    return os_sandbox_enter(&p).ok ? 0 : 70;
}

/* Run one attack child and record the verdict, printing the raw rc on
 * failure (exit code, or negated signal) so a red names its evidence. */
static int tw_attack(const char *label, int (*fn)(void), bool (*expect)(int))
{
    int rc = tw_run_child(fn);
    printf("terminal_worker_sandbox: %s... ", label);
    if (expect(rc)) {
        printf("OK\n");
        return 0;
    }
    printf("FAIL (rc=%d)\n", rc);
    return 1;
}

static bool e_zero(int rc)   { return rc == 0; }
static bool e_sigsys(int rc) { return rc == -SIGSYS; }
static bool e_sigxfsz(int rc){ return rc == -SIGXFSZ; }

/* A THROUGH-THE-SHELL attack must fail with the SHELL's own refusal, not
 * with one of this harness's staging codes — otherwise a cage that never
 * came up (enter failed) would count as a pass. Harness codes 69-72 are
 * excluded; everything else nonzero is the shell saying no. */
static bool e_shell_attack_fail(int rc)
{
    return rc > 0 && rc != 69 && rc != 70 && rc != 71 && rc != 72;
}

static bool denyset_contains(const int *set, size_t n, long nr)
{
    for (size_t i = 0; i < n; i++)
        if (set[i] == (int)nr) return true;
    return false;
}

/* ── attack children ─────────────────────────────────────────────────── */

/* The cage still lets the shell LIVE: create and write inside its
 * per-terminal tmpdir. Reading the host's secrets must EACCES. */
static int c_tw_alive_but_confined(void)
{
    if (tw_enter(false) != 0) return 70;
    char inside[256];
    snprintf(inside, sizeof inside, "%s/in.txt", g_tw_dir);
    int in = open(inside, O_CREAT | O_RDWR, 0600);
    if (in < 0) return 71;              /* grant is writable */
    if (write(in, "x", 1) != 1) { close(in); return 72; }
    close(in);
    int shadow = open("/etc/shadow", O_RDONLY);
    if (shadow >= 0) { close(shadow); return 73; }  /* must NOT read */
    if (errno != EACCES) return 74;
    int passwd = open("/etc/passwd", O_RDONLY);
    if (passwd >= 0) { close(passwd); return 75; }
    if (errno != EACCES) return 76;
    return 0;
}

static int c_tw_socket_killed(void)
{
    if (tw_enter(false) != 0) return 70;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    (void)s;
    return 6; /* reached only if socket() was not denied */
}

/* execve itself stays ALLOWED (the shell spawns children) — but the
 * target outside the grant must be refused by Landlock. If exec ever
 * SUCCEEDS here the process image becomes /bin/true and exits 0 with no
 * marker; the parent distinguishes by requiring exit 42 AND the marker. */
static int c_tw_exec_outside_refused(void)
{
    if (tw_enter(false) != 0) return 70;
    execve("/bin/true", (char *const[]){"/bin/true", NULL},
           (char *const[]){NULL});
    if (errno != EACCES && errno != ENOENT) return 71;
    char marker[256];
    snprintf(marker, sizeof marker, "%s/exec_refused.marker", g_tw_dir);
    int f = open(marker, O_CREAT | O_WRONLY, 0600);
    if (f < 0) return 72;
    close(f);
    return 42;
}

/* The granted shell binary must actually RUN inside the cage — from the
 * grant directory, exactly as the real worker stages it (cwd = the
 * per-terminal workdir) — and its writes must land inside the grant. */
static int c_tw_exec_granted_fbsh_runs(void)
{
    if (chdir(g_tw_dir) != 0) return 69;
    if (tw_enter(true) != 0) return 70;
    char script[512];
    snprintf(script, sizeof script,
             "echo caged > out.txt; echo $((6 * 7)) >> out.txt; exit 7");
    char *const argv[] = {(char *)tw_fbsh_path(), (char *)"-c", script, NULL};
    char *const envp[] = {NULL};
    execve(tw_fbsh_path(), argv, envp);
    return 71; /* reached only if the granted exec failed */
}

/* Attack THROUGH the shell: `cat /etc/shadow` needs exec(cat) — refused
 * by the grant — so fbsh must exit nonzero without leaking anything. */
static int c_tw_fbsh_cat_shadow_fails(void)
{
    if (chdir(g_tw_dir) != 0) return 69;
    if (tw_enter(true) != 0) return 70;
    char *const argv[] = {(char *)tw_fbsh_path(), (char *)"-c",
                          (char *)"cat /etc/shadow", NULL};
    char *const envp[] = {NULL};
    execve(tw_fbsh_path(), argv, envp);
    return 71;
}

/* Attack THROUGH the shell: a redirect at /etc/passwd must be refused. */
static int c_tw_fbsh_write_outside_fails(void)
{
    if (chdir(g_tw_dir) != 0) return 69;
    if (tw_enter(true) != 0) return 70;
    char *const argv[] = {(char *)tw_fbsh_path(), (char *)"-c",
                          (char *)"echo pwned > /etc/passwd", NULL};
    char *const envp[] = {NULL};
    execve(tw_fbsh_path(), argv, envp);
    return 71;
}

/* The shell forks children — that is the point of this profile. NPROC is
 * deliberately KEEP (an RLIMIT_NPROC ceiling counts the whole uid's
 * tasks, and would deadlock the shell on any loaded uid); the process
 * budget is the parent's pgid census, proven at the worker layer. */
static int c_tw_fork_ok(void)
{
    if (tw_enter(false) != 0) return 70;
    pid_t c = fork();
    if (c == 0) _exit(0);
    if (c < 0) return 71;
    int st;
    waitpid(c, &st, 0);
    return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 0 : 72;
}

/* W^X: anonymous W|X mmap is killed outright... */
static int c_tw_wx_mmap_killed(void)
{
    if (tw_enter(false) != 0) return 70;
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    (void)p;
    return 8; /* reached only if W^X was not enforced */
}

/* ...and the mprotect route to executable memory must not succeed either:
 * the filter KILLs the process, and if a refusal ever arrives as an
 * errno instead, that is the same named "no" — accepted. Only a
 * SUCCESSFUL W|X mprotect fails this cage. The page probed is one this
 * child ALREADY has (no fresh mapping: a non-exec child inherits the
 * harness image, which can already sit at the AS ceiling and refuse new
 * maps for reasons that have nothing to do with W^X). */
static int c_tw_mprotect_wx_refused(void)
{
    if (tw_enter(false) != 0) return 70;
    static char page[8192] __attribute__((aligned(4096)));
    uintptr_t addr = (uintptr_t)page;
    (void)page[0]; /* keep it in the image */
    if (mprotect((void *)addr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        return (errno == ENOMEM || errno == EACCES || errno == EPERM)
                   ? 0 : 72;
    return 8; /* mprotect to W|X must not return */
}

static bool e_mprotect_refused(int rc)
{
    return rc == 0 || rc == -SIGSYS;
}

/* AS=256 MiB budget bites: a 512 MiB anonymous mapping is refused. (The
 * forked child inherits this fat test process's address space, so the
 * refusal here is trivially guaranteed; the honest AS proof is the live
 * worker, not the harness. This assertion pins that the limit is SET.) */
static int c_tw_as_budget_refused(void)
{
    if (tw_enter(false) != 0) return 70;
    void *p = mmap(NULL, (size_t)512 * 1024 * 1024, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p != MAP_FAILED) return 9;
    return errno == ENOMEM ? 0 : 71;
}

/* FSIZE=1 MiB: a 2 MiB write to the grant dies with SIGXFSZ. */
static int c_tw_fsize_killed(void)
{
    if (tw_enter(false) != 0) return 70;
    char path[256];
    snprintf(path, sizeof path, "%s/big.bin", g_tw_dir);
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) return 71;
    static char buf[65536];
    memset(buf, 'x', sizeof buf);
    for (int i = 0; i < 32; i++) {
        if (write(fd, buf, sizeof buf) < 0) { close(fd); return 72; }
    }
    close(fd);
    return 10; /* reached only if FSIZE was not enforced */
}

/* NOFILE=64: opening past the ceiling must fail with EMFILE. */
static int c_tw_nofile_budget(void)
{
    if (tw_enter(false) != 0) return 70;
    char path[256];
    snprintf(path, sizeof path, "%s/fds.txt", g_tw_dir);
    int fd = open(path, O_CREAT | O_RDWR, 0600);
    if (fd < 0) return 71;
    int fds[128];
    for (int i = 0; i < 128; i++) {
        /* EMFILE here can only be the NOFILE budget: the file exists and
         * the grant allows the open. Where exactly the ceiling lands
         * depends on how many fds this harness handed the child. */
        fds[i] = open(path, O_RDONLY);
        if (fds[i] < 0)
            return errno == EMFILE ? 0 : 72;
    }
    return 11; /* 128 opens succeeded — NOFILE was not enforced */
}

/* The debug surface stays denied: attaching to the parent must SIGSYS. */
static int c_tw_ptrace_killed(void)
{
    if (tw_enter(false) != 0) return 70;
    ptrace(PTRACE_ATTACH, getppid(), NULL, NULL);
    return 12; /* reached only if ptrace was not denied */
}

static int test_terminal_worker_sandbox_platform_arm(void)
{
    printf("\n=== terminal worker sandbox attack tests ===\n");
    int failures = 0;

    test_make_tmpdir(g_tw_dir, sizeof g_tw_dir, "terminal_worker", "work");
    (void)test_abs_path(FBSH_BIN, g_tw_fbsh, sizeof g_tw_fbsh);

    /* ── profile construction (no fork needed) ─────────────────────── */
    {
        struct os_sandbox_path_rule rules[2];
        size_t rule_count = tw_rules(rules, false);
        struct os_sandbox_profile p =
            os_sandbox_terminal_worker_profile(rules, rule_count);

        printf("terminal_worker_sandbox: profile shape... ");
        bool shape_ok = p.name && strcmp(p.name, "terminal_worker") == 0 &&
                        p.no_new_privs && p.apply_rlimits && p.landlock &&
                        p.seccomp && p.seccomp_deny_exec_mmap &&
                        p.n_fs_rules == 1 && p.fs_rules == rules;
        printf("%s\n", shape_ok ? "OK" : "FAIL");
        if (!shape_ok) failures++;

        struct os_sandbox_rlimits lim = os_sandbox_terminal_worker_rlimits();
        printf("terminal_worker_sandbox: rlimits (AS=256MiB CPU=300 "
               "NPROC=KEEP FSIZE=1MiB NOFILE=64 CORE=0)... ");
        bool lim_ok =
            lim.as_bytes == (uint64_t)256 * 1024 * 1024 &&
            lim.cpu_seconds == 300 &&
            lim.nproc == OS_SANDBOX_RLIMIT_KEEP &&
            lim.fsize_bytes == (uint64_t)1024 * 1024 &&
            lim.nofile == 64 &&
            lim.core_bytes == 0 &&
            p.apply_rlimits &&
            memcmp(&p.rlimits, &lim, sizeof(lim)) == 0;
        printf("%s\n", lim_ok ? "OK" : "FAIL");
        if (!lim_ok) failures++;

        /* Structural pin: the worker deny-set is EXACTLY the session set
         * minus the fork/exec family — no syscall leaves the session set
         * except those, and nothing new appears. */
        size_t n_tw = 0, n_sess = 0;
        const int *tw = os_sandbox_terminal_worker_denied_syscalls(&n_tw);
        const int *sess = os_sandbox_session_denied_syscalls(&n_sess);
        static const int spawn_family[] = {
#ifdef __NR_fork
            __NR_fork,
#endif
#ifdef __NR_vfork
            __NR_vfork,
#endif
#ifdef __NR_clone
            __NR_clone,
#endif
#ifdef __NR_clone3
            __NR_clone3,
#endif
#ifdef __NR_execve
            __NR_execve,
#endif
#ifdef __NR_execveat
            __NR_execveat,
#endif
        };
        bool pin_ok = true;
        for (size_t i = 0; i < n_tw && pin_ok; i++)
            if (!denyset_contains(sess, n_sess, tw[i]))
                pin_ok = false; /* a syscall the session set never denied */
        for (size_t i = 0; i < n_sess && pin_ok; i++) {
            bool in_spawn_family = false;
            for (size_t j = 0; j < sizeof(spawn_family) / sizeof(spawn_family[0]);
                 j++)
                if (sess[i] == spawn_family[j]) in_spawn_family = true;
            if (in_spawn_family) continue;
            if (!denyset_contains(tw, n_tw, sess[i]))
                pin_ok = false; /* a session denial silently dropped */
        }
        printf("terminal_worker_sandbox: deny-set == session set minus "
               "fork/exec family... %s\n", pin_ok ? "OK" : "FAIL");
        if (!pin_ok) failures++;

        printf("terminal_worker_sandbox: socket family denied, spawn family "
               "allowed... ");
        bool family_ok = denyset_contains(tw, n_tw, __NR_socket) &&
                         denyset_contains(tw, n_tw, __NR_connect) &&
                         denyset_contains(tw, n_tw, __NR_ptrace) &&
                         denyset_contains(tw, n_tw, __NR_mount) &&
                         denyset_contains(tw, n_tw, __NR_keyctl) &&
                         denyset_contains(tw, n_tw, __NR_open_by_handle_at) &&
#ifdef __NR_execve
                         !denyset_contains(tw, n_tw, __NR_execve) &&
#endif
#ifdef __NR_clone
                         !denyset_contains(tw, n_tw, __NR_clone) &&
#endif
                         true;
        printf("%s\n", family_ok ? "OK" : "FAIL");
        if (!family_ok) failures++;
    }

    /* ── the attacks (forked children; the sandbox must win) ────────── */
    failures += tw_attack(
        "alive-but-confined (grant writable, /etc/shadow EACCES)",
        c_tw_alive_but_confined, e_zero);
    failures += tw_attack("socket() -> SIGSYS",
                          c_tw_socket_killed, e_sigsys);

    printf("terminal_worker_sandbox: exec outside grant refused (exit 42 + "
           "marker, not /bin/true)... ");
    {
        char marker[256];
        snprintf(marker, sizeof marker, "%s/exec_refused.marker", g_tw_dir);
        unlink(marker);
        int rc = tw_run_child(c_tw_exec_outside_refused);
        bool ok = rc == 42 && access(marker, F_OK) == 0;
        printf("%s\n", ok ? "OK" : "FAIL");
        if (!ok) {
            printf("  rc=%d marker=%s\n", rc,
                   access(marker, F_OK) == 0 ? "present" : "absent");
            failures++;
        }
        unlink(marker);
    }

    failures += tw_attack("fork allowed inside the cage",
                          c_tw_fork_ok, e_zero);
    failures += tw_attack("W|X mmap -> SIGSYS",
                          c_tw_wx_mmap_killed, e_sigsys);
    failures += tw_attack("mprotect -> W|X refused (kill or errno)",
                          c_tw_mprotect_wx_refused, e_mprotect_refused);
    failures += tw_attack("512 MiB mapping refused (AS budget set)",
                          c_tw_as_budget_refused, e_zero);
    failures += tw_attack("2 MiB write -> SIGXFSZ (FSIZE budget)",
                          c_tw_fsize_killed, e_sigxfsz);
    failures += tw_attack("fd exhaustion -> EMFILE (NOFILE budget)",
                          c_tw_nofile_budget, e_zero);
    failures += tw_attack("ptrace(parent) -> SIGSYS",
                          c_tw_ptrace_killed, e_sigsys);

    /* ── the granted shell works — and its own attacks fail ─────────── */
    if (!fbsh_available()) {
        printf("terminal_worker_sandbox: " FBSH_BIN " not built — SKIP the "
               "fbsh-in-cage cases (run `make fbsh` first)\n");
    } else {
        printf("terminal_worker_sandbox: granted fbsh runs, writes stay in "
               "grant... ");
        {
            char out[256];
            snprintf(out, sizeof out, "%s/out.txt", g_tw_dir);
            unlink(out);
            int rc = tw_run_child(c_tw_exec_granted_fbsh_runs);
            char got[64] = {0};
            int f = open(out, O_RDONLY);
            if (f >= 0) {
                ssize_t rd = read(f, got, sizeof got - 1);
                (void)rd;
                close(f);
            }
            bool ok = rc == 7 && strcmp(got, "caged\n42\n") == 0;
            printf("%s\n", ok ? "OK" : "FAIL");
            if (!ok) {
                printf("  rc=%d out=\"%.48s\"\n", rc, got);
                failures++;
            }
            unlink(out);
        }

        failures += tw_attack("fbsh `cat /etc/shadow` fails inside the cage",
                              c_tw_fbsh_cat_shadow_fails, e_shell_attack_fail);
        failures += tw_attack("fbsh `> /etc/passwd` fails inside the cage",
                              c_tw_fbsh_write_outside_fails,
                              e_shell_attack_fail);
    }

    printf("terminal_worker_sandbox: %d failures\n", failures);
    return failures;
}

#endif /* __linux__ */

int test_terminal_worker_sandbox(void)
{
    return test_terminal_worker_sandbox_platform_arm();
}
