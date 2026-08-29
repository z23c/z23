/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the S4 benchmark executor's sandbox canary self-check — three
 * forked probes that prove the confinement backend actually confines.
 *
 * Split out of app/services/src/zcode_benchmark_executor.c when that file
 * passed its shape ceiling. This TU owns the escape suite and nothing
 * else: a granted-directory probe that must stay usable while /etc is
 * denied, a socket probe that must be killed by seccomp, and an exec probe
 * that must be killed by seccomp. It runs no benchmark, loads no CAS
 * object, and writes no receipt. The confined runner, admission, and
 * receipt verification stay in zcode_benchmark_executor.c, which also
 * carries this entry point's Windows refusal stub — hence the same
 * platform guard here.
 *
 * zcode_benchmark_executor_sandbox_selfcheck() is already declared in
 * services/zcode_benchmark_executor.h, so this is a pure move with no
 * linkage change.
 */

#include "services/zcode_benchmark_executor.h"

#if !defined(_WIN32)

#include "zcode_benchmark_executor_internal.h"

#include "platform/os_sandbox.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* ── the sandbox canary self-check (escape-suite pattern) ────────────── */

static int exec_canary_fs(const char *bench_dir)
{
    char probe[EXEC_PATH_MAX];
    int n = snprintf(probe, sizeof(probe), "%s/selfcheck.probe", bench_dir);
    if (n <= 0 || (size_t)n >= sizeof(probe)) return 71;
    struct os_sandbox_path_rule rules[] = {
        { .path = bench_dir, .allow_read = true, .allow_write = true,
          .allow_create = true },
    };
    struct os_sandbox_profile profile =
        os_sandbox_session_child_profile(rules, 1);
    profile.rlimits.as_bytes = OS_SANDBOX_RLIMIT_KEEP;
    profile.rlimits.nproc = OS_SANDBOX_RLIMIT_KEEP;
    /* KEEP nofile too: the canary inherits the parent's fds across fork and
     * rlimits apply before the Landlock ruleset fd exists (see the runner
     * child for why the session default of 16 fails EMFILE). */
    profile.rlimits.nofile = OS_SANDBOX_RLIMIT_KEEP;
    if (!os_sandbox_enter(&profile).ok) return 70;
    if (!os_sandbox_active()) return 71;
    int in = open(probe, O_CREAT | O_RDWR, 0600);
    if (in < 0) return 72; /* granted dir must stay usable */
    close(in);
    int out = open("/etc/passwd", O_RDONLY);
    if (out >= 0) {
        close(out);
        return 73; /* escape: outside the grant */
    }
    if (errno != EACCES) return 74;
    return 0;
}

static int exec_canary_socket(const char *bench_dir)
{
    struct os_sandbox_path_rule rules[] = {
        { .path = bench_dir, .allow_read = true },
    };
    struct os_sandbox_profile profile =
        os_sandbox_session_child_profile(rules, 1);
    profile.rlimits.as_bytes = OS_SANDBOX_RLIMIT_KEEP;
    profile.rlimits.nproc = OS_SANDBOX_RLIMIT_KEEP;
    /* KEEP nofile too: the canary inherits the parent's fds across fork and
     * rlimits apply before the Landlock ruleset fd exists (see the runner
     * child for why the session default of 16 fails EMFILE). */
    profile.rlimits.nofile = OS_SANDBOX_RLIMIT_KEEP;
    if (!os_sandbox_enter(&profile).ok) return 70;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    (void)s;
    return 6; /* reached only if socket was not denied */
}

static int exec_canary_exec(const char *bench_dir)
{
    struct os_sandbox_path_rule rules[] = {
        { .path = bench_dir, .allow_read = true },
    };
    struct os_sandbox_profile profile =
        os_sandbox_session_child_profile(rules, 1);
    profile.rlimits.as_bytes = OS_SANDBOX_RLIMIT_KEEP;
    profile.rlimits.nproc = OS_SANDBOX_RLIMIT_KEEP;
    /* KEEP nofile too: the canary inherits the parent's fds across fork and
     * rlimits apply before the Landlock ruleset fd exists (see the runner
     * child for why the session default of 16 fails EMFILE). */
    profile.rlimits.nofile = OS_SANDBOX_RLIMIT_KEEP;
    if (!os_sandbox_enter(&profile).ok) return 70;
    execve("/bin/true", (char *const[]){ "/bin/true", NULL },
           (char *const[]){ NULL });
    return 5; /* reached only if exec was not denied */
}

typedef int (*exec_canary_fn)(const char *);

static bool exec_canary_wait(pid_t pid, int *status)
{
    for (;;) {
        pid_t w = waitpid(pid, status, 0);
        if (w == pid) return true;
        if (w < 0 && errno == EINTR) continue;
        return false;
    }
}

struct zcl_result zcode_benchmark_executor_sandbox_selfcheck(
    const char *bench_dir)
{
    if (!bench_dir)
        return ZCL_ERR(-1, "selfcheck: no bench dir");
    if (os_sandbox_landlock_abi() < 1 || !os_sandbox_seccomp_supported())
        return ZCL_ERR(-1, "confinement backend unavailable");
    static const struct {
        exec_canary_fn fn;
        const char *name;
    } canaries[] = {
        { exec_canary_fs, "fs-grant" },
        { exec_canary_socket, "socket-deny" },
        { exec_canary_exec, "exec-deny" },
    };
    for (size_t i = 0; i < sizeof(canaries) / sizeof(canaries[0]); i++) {
        pid_t pid = fork();
        if (pid < 0)
            return ZCL_ERR(-1, "canary fork failed");
        if (pid == 0)
            _exit(canaries[i].fn(bench_dir));
        int status = 0;
        if (!exec_canary_wait(pid, &status))
            return ZCL_ERR(-1, "canary wait failed");
        bool ok;
        if (i == 0) {
            ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
        } else {
            ok = WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS;
        }
        if (!ok)
            return ZCL_ERR(-1, "canary %s: unexpected status %#x",
                           canaries[i].name, (unsigned)status);
    }
    char probe[EXEC_PATH_MAX];
    int n = snprintf(probe, sizeof(probe), "%s/selfcheck.probe", bench_dir);
    if (n > 0 && (size_t)n < sizeof(probe))
        (void)unlink(probe);
    return ZCL_OK;
}

#endif /* !_WIN32 */
