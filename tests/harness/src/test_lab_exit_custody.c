/* Purpose: Refuse unobservable child exits rather than inventing outcomes. */
#include "test/test_core.h"
#include "command/lab_exec.h"

#if defined(__linux__)
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/syscall.h>

static volatile sig_atomic_t custody_reaped;

static void custody_other_waiter(int signal_number)
{
    (void)signal_number;
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0) {
        custody_reaped = 1;
    }
    errno = saved_errno;
}

static bool custody_run(const char *program, const char *argument,
                         struct lab_proc *result)
{
    const char *arguments[] = { program, argument, NULL };
    const char *environment[] = { "LC_ALL=C", NULL };
    struct lab_spawn spawn = {
        .profile = LAB_PROFILE_COMPILE, .confine = false,
        .argv = arguments, .env = environment, .cwd = "/",
        .timeout_ms = 100, .as_bytes = OS_SANDBOX_RLIMIT_KEEP,
        .fsize_bytes = OS_SANDBOX_RLIMIT_KEEP, .nofile = 256,
    };
    if (!lab_proc_init(result))
        return false;
    lab_spawn_run(&spawn, result);
    return true;
}

static bool custody_configure(unsigned mode)
{
    (void)lab_pidns_available();
    custody_reaped = 0;
    struct sigaction action = { .sa_handler = mode == 1 ? SIG_IGN : SIG_DFL,
                                .sa_flags = mode == 2 ? SA_NOCLDWAIT : 0 };
    if (mode == 3)
        action.sa_handler = custody_other_waiter;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGCHLD, &action, NULL) != 0)
        return false;
    sigset_t signals;
    sigemptyset(&signals);
    sigaddset(&signals, SIGCHLD);
    if (sigprocmask(SIG_UNBLOCK, &signals, NULL) != 0)
        return false;
    if (mode == 4) {
        const int denied[] = { SYS_waitid };
        return os_sandbox_no_new_privs() &&
            zcl_result_is_ok(os_sandbox_seccomp_deny_ext(
                NULL, 0, false, denied, 1, false));
    }
    return true;
}

static bool custody_expected(unsigned mode, const struct lab_proc *result)
{
    if (mode == 0)
        return result->launch == LAB_LAUNCHED && result->exit_code == 1 &&
               !result->timed_out && !result->term_signal;
    const char *diagnostic = mode >= 3 ? "exit status" : "SIGCHLD";
    return result->launch == LAB_LAUNCH_FAILED && result->exit_code == -1 &&
           !result->timed_out && strstr(result->detail, diagnostic) != NULL;
}

static int custody_child(unsigned mode)
{
    if (!custody_configure(mode))
        return 2;
    struct lab_proc result;
    if (!custody_run(mode == 4 ? "/bin/sleep" : "/bin/false",
                     mode == 4 ? "30" : NULL, &result))
        return 3;
    fprintf(stderr, "exit custody mode=%u launch=%d exit=%d timeout=%d detail=%s\n",
            mode, result.launch, result.exit_code, result.timed_out, result.detail);
    bool correct = custody_expected(mode, &result);
    if (mode == 3)
        correct = correct && custody_reaped;
    if (mode == 4)
        correct = correct && waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD;
    lab_proc_free(&result);
    return correct ? 0 : 4;
}

/* Signal dispositions are process-wide. Exercise them only in this isolated
 * child, leaving the registered runner and its sibling groups untouched. */
static bool custody_policy(unsigned mode)
{
    pid_t child = fork();
    if (child < 0)
        return false;
    if (child == 0)
        _exit(custody_child(mode));
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    return waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
#endif

int test_lab_exit_custody(void)
{
    int failures = 0;
#if defined(__linux__)
    TEST("lab refuses SIGCHLD policies which discard exit evidence") {
        struct sigaction previous, normal = { .sa_handler = SIG_DFL };
        sigemptyset(&normal.sa_mask);
        ASSERT(sigaction(SIGCHLD, &normal, &previous) == 0);
        bool ordinary = custody_policy(0);
        bool ignored = custody_policy(1);
        bool discarded = custody_policy(2);
        bool stolen = custody_policy(3);
        bool observation_failed = true;
        if (os_sandbox_seccomp_supported())
            observation_failed = custody_policy(4);
        else
            fprintf(stderr, "waitid denial control unavailable: no seccomp support\n");
        ASSERT(sigaction(SIGCHLD, &previous, NULL) == 0);
        ASSERT(ordinary);
        ASSERT(ignored);
        ASSERT(discarded);
        ASSERT(stolen);
        ASSERT(observation_failed);
        PASS();
    } _test_next:;
#endif
    return failures;
}
