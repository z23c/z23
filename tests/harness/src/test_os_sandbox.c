/* Copyright 2026 Rhett Creighton - Apache License 2.0
    SB_CHECK("seccomp deny_ext: reserved 512 as an ENOSYS rule -> SIGSYS, not ENOSYS (guard precedes ENOSYS compares)",
             sb_run_child(c_abi_enosys_reserved_ext) == -SIGSYS);
    SB_CHECK("seccomp deny_ext: x32-tagged number as an ENOSYS rule -> SIGSYS, not ENOSYS",
             sb_run_child(c_abi_enosys_tagged_ext) == -SIGSYS);
    SB_CHECK("seccomp deny: reserved 512 in the deny list -> SIGSYS",
             sb_run_child(c_abi_enosys_reserved_deny) == -SIGSYS);
    SB_CHECK("seccomp deny: x32-tagged number in the deny list -> SIGSYS",
             sb_run_child(c_abi_enosys_tagged_deny) == -SIGSYS);
    SB_CHECK("seccomp deny_ext: a count pair that wraps size_t is refused, not built",
             sb_run_child(c_abi_count_wrap) == 0);
 *
 * Tests for the os_sandbox process-confinement builders
 * (platform/modules/platform/src/os_sandbox_linux.c).
 *
 * These builders MUTATE the calling process IRREVERSIBLY (no_new_privs,
 * seccomp, Landlock, lowered rlimits are all one-way). So every destructive
 * assertion runs in a FRESHLY FORKED child and is judged by the child's exit
 * status / terminating signal — mirroring the fork-and-check pattern of the
 * substrate probes (docs/work/session-substrate-probes.md, probes 3 and 4).
 * The parent (the test-group process the harness forked) is never sandboxed.
 *
 * Coverage:
 *   - os_sandbox_no_new_privs() succeeds
 *   - os_sandbox_landlock_abi() reports a supported ABI on this kernel
 *   - os_sandbox_set_rlimits(): FSIZE cap -> SIGXFSZ; NPROC=1 -> 2nd fork EAGAIN
 *   - os_sandbox_seccomp_deny(): normal glibc code runs; execve -> SIGSYS;
 *     socket -> SIGSYS
 *   - os_sandbox_landlock_restrict(): outside open -> EACCES; inside -> ok;
 *     pre-opened fd survives restrict
 *   - os_sandbox_landlock_apply_to_self(): a thread that PREDATES the domain
 *     (spawned before landlock_restrict) is unconfined until it calls this
 *     itself, confined after; idempotent (a 2nd call doesn't double-count);
 *     calling it before ANY domain exists is a non-fatal non-ok
 *   - os_sandbox_userns_available(): reports the box's true verdict
 *   - os_sandbox_write_userns_maps(): a userns child sees the mapped uid
 *   - os_sandbox_enter(SANDBOX_SESSION_CHILD): child is alive-but-confined
 *     (reads a granted path, cannot open /etc/passwd, cannot exec, cannot
 *     socket)
 *
 * userns-DEPENDENT assertions are gated on os_sandbox_userns_available() so
 * this suite still passes on a host that answers the userns gate differently.
 */

#define _GNU_SOURCE  /* unshare/CLONE_* — must precede every include */

#include "test/test_core.h"
#include "platform/os_sandbox.h"

/* Defined in test_os_sandbox_exec_tier.c (pure tier-picker cases). */
int test_exec_tier_cases(void);
int test_exec_tier_pure_cases(void);

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#if !defined(_WIN32)
#include <sched.h>
#endif
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#if !defined(_WIN32)
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#endif

#if defined(__APPLE__)
#include <signal.h>
#include <spawn.h>
#include <time.h>

extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

#define SB_CHECK(name, expr) do { \
    printf("os_sandbox: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static char g_macos_allowed[256];
static char g_macos_denied[256];

static int sb_run_child(int (*fn)(void))
{
    pid_t pid = fork();
    if (pid < 0) return -1000;
    if (pid == 0) _exit(fn());
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) return -1001;
    if (WIFSIGNALED(status)) return -WTERMSIG(status);
    return WEXITSTATUS(status);
}

static size_t macos_rules(struct os_sandbox_path_rule rules[6])
{
    size_t n = 0;
    rules[n++] = (struct os_sandbox_path_rule){
        .path = g_macos_allowed, .allow_read = true, .allow_write = true,
        .allow_execute = true, .allow_create = true };
    rules[n++] = (struct os_sandbox_path_rule){
        .path = "/usr", .allow_read = true, .allow_execute = true };
    rules[n++] = (struct os_sandbox_path_rule){
        .path = "/System", .allow_read = true, .allow_execute = true };
    rules[n++] = (struct os_sandbox_path_rule){
        .path = "/Library", .allow_read = true, .allow_execute = true };
    rules[n++] = (struct os_sandbox_path_rule){
        .path = "/dev", .allow_read = true, .allow_write = true };
    return n;
}

/* Enter the package Seatbelt scope, then create and write the granted
 * output file (failure codes 70-73). */
static int macos_seatbelt_write_granted_output(void)
{
    struct os_sandbox_path_rule rules[6];
    size_t count = macos_rules(rules);
    struct zcl_result result = os_sandbox_package_restrict(rules, count);
    if (!result.ok) return 70;
    char allowed_file[320];
    int n = snprintf(allowed_file, sizeof(allowed_file), "%s/output",
                     g_macos_allowed);
    if (n <= 0 || (size_t)n >= sizeof(allowed_file)) return 71;
    int fd = open(allowed_file, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) return 72;
    if (write(fd, "ok", 2) != 2 || close(fd) != 0) return 73;
    return 0;
}

/* Opening the denied path must be refused with EPERM/EACCES (74/75). */
static int macos_seatbelt_denied_open_refused(void)
{
    int fd = open(g_macos_denied, O_RDONLY);
    if (fd >= 0) { close(fd); return 74; }
    if (errno != EPERM && errno != EACCES) return 75;
    return 0;
}

/* An AF_INET connect outside the grant must be refused at socket() or
 * connect() with EPERM/EACCES (failure codes 76/77). */
static int macos_seatbelt_inet_connect_refused(void)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        if (errno != EPERM && errno != EACCES) return 76;
        return 0;
    }
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(9);
    address.sin_addr.s_addr = htonl(UINT32_C(0x7f000001));
    errno = 0;
    int connected = connect(sock, (const struct sockaddr *)&address,
                            sizeof(address));
    int connect_errno = errno;
    close(sock);
    if (connected == 0 ||
        (connect_errno != EPERM && connect_errno != EACCES))
        return 77;
    return 0;
}

static int c_macos_seatbelt_scope(void)
{
    int rc = macos_seatbelt_write_granted_output();
    if (rc) return rc;
    rc = macos_seatbelt_denied_open_refused();
    if (rc) return rc;
    rc = macos_seatbelt_inet_connect_refused();
    if (rc) return rc;
    int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0) {
        if (errno != EPERM && errno != EACCES) return 78;
    } else {
        struct sockaddr_un address;
        memset(&address, 0, sizeof(address));
        address.sun_family = AF_UNIX;
        (void)snprintf(address.sun_path, sizeof(address.sun_path), "%s",
                       "/private/var/run/syslog");
        errno = 0;
        int connected = connect(sock, (const struct sockaddr *)&address,
                                sizeof(address));
        int connect_errno = errno;
        close(sock);
        if (connected == 0 ||
            (connect_errno != EPERM && connect_errno != EACCES))
            return 79;
    }
    return 0;
}

static int macos_descriptor_grant_refusal(bool leaf)
{
    int granted = open(g_macos_denied, O_RDONLY);
    if (granted < 0) return 90;
    struct os_sandbox_path_rule rules[6];
    size_t count = macos_rules(rules);
    /* The path is deliberately a different object: using it as fallback
     * would silently replace descriptor authority with pathname authority. */
    rules[0].has_fd = true;
    rules[0].fd = granted;
    struct zcl_result result = leaf ?
        os_sandbox_package_leaf_restrict(rules, count) :
        os_sandbox_package_restrict(rules, count);
    if (close(granted) != 0) return 91;
    if (result.ok || result.code != OS_SANDBOX_ERR_CONFINEMENT_UNAVAILABLE)
        return 92;
    int outside = open(g_macos_denied, O_RDONLY);
    if (outside < 0) return 93;
    return close(outside) == 0 ? 0 : 94;
}

static int c_macos_package_descriptor_refusal(void)
{
    return macos_descriptor_grant_refusal(false);
}

static int c_macos_leaf_descriptor_refusal(void)
{
    return macos_descriptor_grant_refusal(true);
}

static int c_macos_seatbelt_exec(void)
{
    struct os_sandbox_path_rule rules[6];
    size_t count = macos_rules(rules);
    struct zcl_result result = os_sandbox_package_restrict(rules, count);
    if (!result.ok) return 70;
    execl("/usr/bin/true", "true", (char *)NULL);
    return 71;
}

static int macos_reap_created(pid_t child, bool leaf)
{
    /* Reap unexpected leaf children too; creation always fails that case. */
    int status = 0;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); }
    while (waited < 0 && errno == EINTR);
    if (waited != child) return 82;
    if (leaf) return 83;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 84;
}

/* Each wrapper runs in sb_run_child: the test parent retains its authority. */
static int macos_process_creation(bool leaf, bool spawn)
{
    struct os_sandbox_path_rule rules[6];
    size_t count = macos_rules(rules);
    struct zcl_result result = leaf ?
        os_sandbox_package_leaf_restrict(rules, count) :
        os_sandbox_package_restrict(rules, count);
    if (!result.ok) return 80;
    pid_t child = -1;
    int error;
    if (spawn) {
        char *const argv[] = {"true", NULL};
        char *const env[] = {NULL};
        error = posix_spawn(&child, "/usr/bin/true", NULL, NULL, argv, env);
    } else {
        child = fork();
        if (child == 0) _exit(0);
        error = child < 0 ? errno : 0;
    }
    if (error != 0)
        return leaf && (error == EPERM || error == EACCES) ? 0 : 81;
    return macos_reap_created(child, leaf);
}

static int c_macos_package_fork(void)
{
    return macos_process_creation(false, false);
}

static int c_macos_package_spawn(void)
{
    return macos_process_creation(false, true);
}

static int c_macos_leaf_fork(void)
{
    return macos_process_creation(true, false);
}

static int c_macos_leaf_spawn(void)
{
    return macos_process_creation(true, true);
}

/* SETEXEC replaces this confined child; it grants no new-process authority. */
static int macos_leaf_setexec_flags(const char *image, char *const argv[], short flags)
{
    struct os_sandbox_path_rule rules[6];
    size_t count = macos_rules(rules);
    rules[count++] = (struct os_sandbox_path_rule){
        .path = image, .allow_read = true, .allow_execute = true };
    if (!os_sandbox_package_leaf_restrict(rules, count).ok) return 85;
    posix_spawnattr_t attributes;
    if (posix_spawnattr_init(&attributes) != 0) return 86;
    if (posix_spawnattr_setflags(&attributes, flags) != 0) {
        (void)posix_spawnattr_destroy(&attributes);
        return 87;
    }
    char *const env[] = {NULL};
    pid_t unexpected = -1;
    (void)posix_spawn(&unexpected, image, NULL, &attributes, argv, env);
    /* Successful replacement never returns. Even a returned success status
     * fails this claim; reap any new process before the fixture exits. */
    (void)posix_spawnattr_destroy(&attributes);
    if (unexpected > 0 && unexpected != getpid())
        (void)macos_reap_created(unexpected, true);
    return 88;
}

static int macos_leaf_setexec(const char *image, char *const argv[])
{
    return macos_leaf_setexec_flags(image, argv, POSIX_SPAWN_SETEXEC);
}

static int c_macos_leaf_setexec(void)
{
    char *const argv[] = {"true", NULL};
    return macos_leaf_setexec("/usr/bin/true", argv);
}

static int macos_leaf_fixture(const char *operation, const char *argument)
{
    char image[4096];
    if (!realpath("build/fixtures/rcc_child", image)) return 89;
    char *const argv[] = {image, (char *)operation, (char *)argument, NULL};
    return macos_leaf_setexec(image, argv);
}

static int c_macos_leaf_replaced_open_allowed(void)
{
    /* The existing scope case creates this file before replacement checks. */
    char path[320];
    int length = snprintf(path, sizeof(path), "%s/output", g_macos_allowed);
    if (length <= 0 || (size_t)length >= sizeof(path)) return 89;
    return macos_leaf_fixture("open", path);
}

static int c_macos_leaf_replaced_open_denied(void)
{
    return macos_leaf_fixture("open", g_macos_denied);
}

static int c_macos_leaf_replaced_fork(void)
{
    return macos_leaf_fixture("fork", "");
}

static int macos_leaf_replaced_policy_cases(void)
{
    int failures = 0;
    SB_CHECK("replaced leaf opens granted file read-only",
             sb_run_child(c_macos_leaf_replaced_open_allowed) == 0);
    int denied_open = sb_run_child(c_macos_leaf_replaced_open_denied);
    SB_CHECK("replaced leaf retains file denial",
             denied_open == EPERM || denied_open == EACCES);
    int denied_fork = sb_run_child(c_macos_leaf_replaced_fork);
    SB_CHECK("replaced leaf retains process-fork denial",
             denied_fork == EPERM || denied_fork == EACCES);
    return failures;
}

static int64_t macos_test_monotonic_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

/* No blocking wait: both elapsed time and attempt count bound observation. */
static bool macos_wait_event(pid_t child, int options, int *status)
{
    int64_t start = macos_test_monotonic_ms();
    if (start < 0) return false;
    for (unsigned attempt = 0; attempt < 1000; attempt++) {
        pid_t waited = waitpid(child, status, options | WNOHANG);
        if (waited == child) return true;
        if (waited < 0 && errno != EINTR) return false;
        int64_t now = macos_test_monotonic_ms();
        if (now < start || now - start >= 5000) break;
        struct timespec pause = {.tv_nsec = 5000000};
        (void)nanosleep(&pause, NULL); /* real-clock: bounded wait for kernel child stop/exit; requires wall-clock progress */
    }
    errno = ETIMEDOUT;
    return false;
}

static bool macos_cleanup_failure(pid_t child, const char *operation)
{
    int error = errno;
    fprintf(stderr, "os_sandbox: child cleanup failed pid=%ld operation=%s errno=%d\n",
            (long)child, operation, error);
    errno = error;
    return false;
}

static bool macos_kill_reap_test_child(pid_t *child)
{
    if (*child <= 0) return true;
    if (kill(*child, SIGKILL) != 0 && errno != ESRCH)
        return macos_cleanup_failure(*child, "kill");
    int status = 0;
    bool reaped = macos_wait_event(*child, 0, &status);
    if (!reaped && errno != ECHILD)
        return macos_cleanup_failure(*child, "bounded reap");
    *child = -1;
    return true;
}

static bool macos_nonzero_cdhash(pid_t child, unsigned char hash[20])
{
    enum { TEST_CS_OPS_CDHASH = 5 };
    if (csops(child, TEST_CS_OPS_CDHASH, hash, 20) != 0) return false;
    unsigned char any = 0;
    for (size_t i = 0; i < 20; i++) any |= hash[i];
    return any != 0;
}

/* The reference is a mapped control, not descriptor-derived image evidence. */
static bool macos_control_cdhash(const char *image, unsigned char expected[20])
{
    posix_spawnattr_t attributes;
    if (posix_spawnattr_init(&attributes) != 0) return false;
    int error = posix_spawnattr_setflags(&attributes, POSIX_SPAWN_START_SUSPENDED);
    char *const argv[] = {(char *)image, "exit", "37", NULL};
    char *const env[] = {NULL};
    pid_t child = -1;
    if (error == 0)
        error = posix_spawn(&child, image, NULL, &attributes, argv, env);
    (void)posix_spawnattr_destroy(&attributes);
    int status = 0;
    bool stopped = error == 0 && macos_wait_event(child, WUNTRACED, &status);
    if (stopped && !WIFSTOPPED(status)) child = -1;
    bool matched = stopped && WIFSTOPPED(status) && macos_nonzero_cdhash(child, expected);
    bool cleaned = macos_kill_reap_test_child(&child);
    return matched && cleaned;
}

static bool macos_marker_byte(const char *marker)
{
    int fd = open(marker, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat st;
    char bytes[2] = {0};
    bool exact = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size == 1 &&
                 read(fd, bytes, sizeof(bytes)) == 1 && bytes[0] == 'x';
    bool closed = close(fd) == 0;
    return exact && closed;
}

static bool macos_observe_leaf_replacement(pid_t *child, const char *marker,
                                           const unsigned char expected[20])
{
    int status = 0;
    if (!macos_wait_event(*child, WUNTRACED, &status)) return false;
    if (!WIFSTOPPED(status)) { *child = -1; return false; }
    unsigned char mapped[20] = {0};
    if (!macos_nonzero_cdhash(*child, mapped) || memcmp(mapped, expected, 20) != 0)
        return false;
    struct stat st;
    if (lstat(marker, &st) == 0 || errno != ENOENT) return false;
    if (kill(*child, SIGCONT) != 0) return false;
    if (!macos_wait_event(*child, 0, &status)) return false;
    *child = -1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 && macos_marker_byte(marker);
}

static int macos_leaf_suspended_replacement(void)
{
    char image[4096], marker[320];
    if (!realpath("build/fixtures/rcc_child", image)) return 1;
    int length = snprintf(marker, sizeof(marker), "%s/suspended-marker", g_macos_allowed);
    if (length <= 0 || (size_t)length >= sizeof(marker)) return 1;
    struct stat st;
    if (lstat(marker, &st) == 0 || errno != ENOENT) return 1;
    unsigned char expected[20] = {0};
    if (!macos_control_cdhash(image, expected)) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        char *const argv[] = {image, "write", marker, NULL};
        _exit(macos_leaf_setexec_flags(image, argv,
            POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED));
    }
    bool observed = macos_observe_leaf_replacement(&child, marker, expected);
    bool cleaned = macos_kill_reap_test_child(&child);
    (void)unlink(marker);
    return observed && cleaned ? 0 : 1;
}

static int c_macos_rlimit_fsize(void)
{
    struct os_sandbox_rlimits limits = {
        .as_bytes = OS_SANDBOX_RLIMIT_KEEP,
        .cpu_seconds = OS_SANDBOX_RLIMIT_KEEP,
        .nproc = OS_SANDBOX_RLIMIT_KEEP,
        .fsize_bytes = 4096,
        .nofile = OS_SANDBOX_RLIMIT_KEEP,
        .core_bytes = 0,
    };
    if (!os_sandbox_set_rlimits(&limits).ok) return 70;
    char output[320];
    int n = snprintf(output, sizeof(output), "%s/oversize",
                     g_macos_allowed);
    if (n <= 0 || (size_t)n >= sizeof(output)) return 71;
    int fd = open(output, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) return 72;
    char bytes[8192];
    memset(bytes, 'x', sizeof(bytes));
    errno = 0;
    ssize_t wrote = write(fd, bytes, sizeof(bytes));
    int write_errno = errno;
    if (close(fd) != 0) return 73;
    struct stat st;
    if (stat(output, &st) != 0) return 74;
    return wrote < (ssize_t)sizeof(bytes) && st.st_size <= 4096 &&
           (write_errno == EFBIG || wrote == 4096) ? 0 : 75;
}

int test_os_sandbox(void)
{
    int failures = 0;
    char root[] = "/private/tmp/z23-seatbelt-test.XXXXXX";
    if (!mkdtemp(root)) return 1;
    int n1 = snprintf(g_macos_allowed, sizeof(g_macos_allowed),
                      "%s/allowed", root);
    int n2 = snprintf(g_macos_denied, sizeof(g_macos_denied),
                      "%s/denied", root);
    if (n1 <= 0 || (size_t)n1 >= sizeof(g_macos_allowed) ||
        n2 <= 0 || (size_t)n2 >= sizeof(g_macos_denied) ||
        mkdir(g_macos_allowed, 0700) != 0) {
        (void)rmdir(root);
        return 1;
    }
    int denied = open(g_macos_denied, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (denied < 0) return 1;
    (void)write(denied, "secret", 6);
    (void)close(denied);

    printf("\n=== os_sandbox macOS package confinement ===\n");
    SB_CHECK("mechanism reports Seatbelt",
             os_sandbox_package_confinement() ==
                 OS_SANDBOX_PACKAGE_CONFINEMENT_SEATBELT &&
             strcmp(os_sandbox_package_confinement_name(
                        OS_SANDBOX_PACKAGE_CONFINEMENT_SEATBELT),
                    "seatbelt") == 0);
    SB_CHECK("Seatbelt scopes files and denies network",
             sb_run_child(c_macos_seatbelt_scope) == 0);
    SB_CHECK("package Seatbelt refuses descriptor grants before sandbox entry",
             sb_run_child(c_macos_package_descriptor_refusal) == 0);
    SB_CHECK("leaf Seatbelt refuses descriptor grants before sandbox entry",
             sb_run_child(c_macos_leaf_descriptor_refusal) == 0);
    SB_CHECK("Seatbelt permits explicitly granted execution",
             sb_run_child(c_macos_seatbelt_exec) == 0);
    SB_CHECK("package Seatbelt permits fork",
             sb_run_child(c_macos_package_fork) == 0);
    SB_CHECK("package Seatbelt permits posix_spawn of granted executable",
             sb_run_child(c_macos_package_spawn) == 0);
    SB_CHECK("leaf Seatbelt refuses fork with policy error",
             sb_run_child(c_macos_leaf_fork) == 0);
    SB_CHECK("leaf Seatbelt refuses posix_spawn with policy error",
             sb_run_child(c_macos_leaf_spawn) == 0);
    SB_CHECK("leaf Seatbelt permits same-process POSIX_SPAWN_SETEXEC replacement",
             sb_run_child(c_macos_leaf_setexec) == 0);
    failures += macos_leaf_replaced_policy_cases();
    SB_CHECK("leaf replacement stops before target write, matches control CDHash, then resumes",
             macos_leaf_suspended_replacement() == 0);
    SB_CHECK("POSIX resource limits are enforced",
             sb_run_child(c_macos_rlimit_fsize) == 0);

    char generated[320];
    (void)snprintf(generated, sizeof(generated), "%s/output",
                   g_macos_allowed);
    (void)unlink(generated);
    (void)snprintf(generated, sizeof(generated), "%s/oversize",
                   g_macos_allowed);
    (void)unlink(generated);
    (void)unlink(g_macos_denied);
    (void)rmdir(g_macos_allowed);
    (void)rmdir(root);
    failures += test_exec_tier_pure_cases();
    return failures ? 1 : 0;
}

#elif !defined(__linux__)

int test_os_sandbox(void)
{
    struct os_sandbox_caps caps = os_sandbox_probe_caps();
    int failures = test_exec_tier_pure_cases();
    printf("\n=== os_sandbox platform availability ===\n");
    printf("os_sandbox: userns=%d landlock_abi=%d seccomp=%d; "
           "Linux confinement tests are not applicable\n",
           (int)caps.userns, caps.landlock_abi, (int)caps.seccomp);
    return failures == 0 && !caps.userns && caps.landlock_abi < 1 && !caps.seccomp ? 0 : 1;
}

#else

#define SB_CHECK(name, expr) do { \
    printf("os_sandbox: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Run fn() in a forked child. Returns the child's exit code (>= 0) or the
 * NEGATED terminating signal (< 0) so callers can assert on WTERMSIG. */
static int sb_run_child(int (*fn)(void))
{
    pid_t pid = fork();
    if (pid < 0) return -1000;
    if (pid == 0) _exit(fn());
    int st = 0;
    if (waitpid(pid, &st, 0) != pid) return -1001;
    if (WIFSIGNALED(st)) return -WTERMSIG(st);
    return WEXITSTATUS(st);
}

/* ── individual builder children ───────────────────────────────────────── */

static int c_no_new_privs(void)
{
    return os_sandbox_no_new_privs() ? 0 : 1;
}

static int c_seccomp_exec(void)
{
    size_t n = 0;
    const int *d = os_sandbox_session_denied_syscalls(&n);
    if (!os_sandbox_no_new_privs()) return 70;
    struct zcl_result r = os_sandbox_seccomp_deny(d, n, true);
    if (!r.ok) return 71;
    /* Prove normal glibc work still runs under the filter (default ALLOW). */
    volatile uint64_t sum = 0;
    for (int i = 0; i < 100000; i++) sum += i;
    if (sum == 0) return 73;
    char *p = (char *)malloc(4096);
    if (!p) return 72;
    memset(p, 0x42, 4096);
    free(p);
    /* Now the denied syscall — must SIGSYS-kill the whole process. */
    execve("/bin/true", (char *const[]){"/bin/true", NULL}, (char *const[]){NULL});
    return 5; /* reached only if the filter failed to block execve */
}

/* W^X variants. mode 1 = strict, 2 = file-backed exec allowed. Each child
 * installs the filter, then performs ONE memory call; kind selects which. */
enum { WXK_FILE_EXEC, WXK_ANON_EXEC, WXK_MPROTECT_EXEC, WXK_NOFD_EXEC, WXK_PLAIN, WXK_FILE_RWX };
static int sb_wx(int mode, int kind)
{
    int fd = open("/proc/self/exe", O_RDONLY);
    if (fd < 0 || !os_sandbox_no_new_privs()) return 70;
    if (!os_sandbox_seccomp_deny_ext(NULL, 0, (enum os_sandbox_wx)mode,
                                     NULL, 0, false).ok)
        return 71;
    void *p = MAP_FAILED;
    switch (kind) {
    case WXK_FILE_EXEC:
        p = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
        break;
    case WXK_FILE_RWX:
        p = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0);
        break;
    case WXK_ANON_EXEC:
        p = mmap(NULL, 4096, PROT_READ | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        break;
    case WXK_MPROTECT_EXEC:
        p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED && mprotect(p, 4096, PROT_READ | PROT_EXEC) != 0)
            return 72;
        break;
    case WXK_NOFD_EXEC:
        p = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, -1, 0);
        break;
    default:
        p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        break;
    }
    return p == MAP_FAILED ? 73 : 0;
}
static int c_wx_strict_file(void) { return sb_wx(1, WXK_FILE_EXEC); }
static int c_wx_file_file(void) { return sb_wx(2, WXK_FILE_EXEC); }
static int c_wx_file_rwx(void) { return sb_wx(2, WXK_FILE_RWX); }
static int c_wx_file_anon(void) { return sb_wx(2, WXK_ANON_EXEC); }
static int c_wx_file_mprot(void) { return sb_wx(2, WXK_MPROTECT_EXEC); }
static int c_wx_file_nofd(void) { return sb_wx(2, WXK_NOFD_EXEC); }
static int c_wx_file_plain(void) { return sb_wx(2, WXK_PLAIN); }

static int c_seccomp_socket(void)
{
    size_t n = 0;
    const int *d = os_sandbox_session_denied_syscalls(&n);
    if (!os_sandbox_no_new_privs()) return 70;
    struct zcl_result r = os_sandbox_seccomp_deny(d, n, true);
    if (!r.ok) return 71;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    (void)s;
    return 6; /* reached only if socket() was not blocked */
}

#if defined(__x86_64__) && defined(__linux__)
static int c_seccomp_abi_probe(long nr, bool filtered)
{
    if (filtered) {
        size_t count = 0;
        const int *denied = os_sandbox_session_denied_syscalls(&count);
        if (!os_sandbox_no_new_privs()) return 70;
        if (!os_sandbox_seccomp_deny(denied, count, false).ok) return 71;
    }
    errno = 0;
    long result = os_sandbox_raw_syscall_for_testing(nr, -1L, 0L, 0L);
    if (nr == __NR_getpid) return result == (long)getpid() ? 0 : 72;
    fprintf(stderr, "os_sandbox: ABI probe nr=%ld result=%ld errno=%d filtered=%d\n",
             nr, result, errno, (int)filtered);
    return filtered ? 5 : 0;
}

static int c_seccomp_x32_raw(void)
{ return c_seccomp_abi_probe((long)((uint32_t)__NR_getpid | UINT32_C(0x40000000)), false); }
static int c_seccomp_reserved_raw(void)
{ return c_seccomp_abi_probe(521, false); }
static int c_seccomp_native_getpid(void)
{ return c_seccomp_abi_probe(__NR_getpid, true); }
static int c_seccomp_x32_getpid(void)
{ return c_seccomp_abi_probe((long)((uint32_t)__NR_getpid | UINT32_C(0x40000000)), true); }
static int c_seccomp_reserved_first(void)
{ return c_seccomp_abi_probe(512, true); }
static int c_seccomp_reserved_ptrace(void)
{ return c_seccomp_abi_probe(521, true); }
static int c_seccomp_reserved_last(void)
{ return c_seccomp_abi_probe(547, true); }

static int c_seccomp_abi_filter_bound(void)
{
    int denied[244];
    for (size_t i = 0; i < sizeof(denied) / sizeof(denied[0]); ++i)
        denied[i] = __NR_getpid;
    if (!os_sandbox_no_new_privs()) return 70;
    struct zcl_result rejected = os_sandbox_seccomp_deny(denied, 244, true);
    if (rejected.ok || rejected.code != OS_SANDBOX_ERR_TOO_MANY_RULES)
        return 71;
    return os_sandbox_seccomp_deny(denied, 243, true).ok ? 0 : 72;
}

/* ── x32 / reserved-ABI coverage beyond the first deny-filter cases ─────────
 * Every deny-style builder variant: 0 deny, 1 deny+W^X, 2 ext (+W^X, ENOSYS
 * list, clone gate), 3 ext (no W^X, no clone gate). */
#define SB_X32_BIT 0x40000000L
static int sb_abi_install(int mode)
{
    size_t n = 0;
    const int *d = os_sandbox_session_denied_syscalls(&n);
    static const int enosys[1] = {__NR_clone3};
    if (!os_sandbox_no_new_privs()) return 70;
    struct zcl_result r = mode < 2
        ? os_sandbox_seccomp_deny(d, n, mode == 1)
        : os_sandbox_seccomp_deny_ext(d, n, mode == 2, enosys, 1, mode == 2);
    return r.ok ? 0 : 71;
}

/* Install variant `mode`, then issue `nr`; the caller expects SIGSYS. */
static int sb_abi_kill(int mode, long nr, long a0, long a1, long a2)
{
    int rc = sb_abi_install(mode);
    if (rc) return rc;
    (void)os_sandbox_raw_syscall_for_testing(nr, a0, a1, a2);
    return 5; /* reached only if the call was allowed */
}

/* Install variant `mode`, then issue `nr`; it must come back ENOSYS. */
static int sb_abi_enosys(int mode, long nr)
{
    int rc = sb_abi_install(mode);
    if (rc) return rc;
    errno = 0;
    long r = os_sandbox_raw_syscall_for_testing(nr, -1L, 0L, 0L);
    return r == -1 && errno == ENOSYS ? 0 : 6;
}

/* ORDER: execve is in the deny list, so execve|bit must die from the guard
 * even though a guard placed after the compares would let it through. */
static int c_abi_order_deny(void) { return sb_abi_kill(0, __NR_execve | SB_X32_BIT, -1L, 0L, 0L); }
static int c_abi_order_ext(void) { return sb_abi_kill(3, __NR_execve | SB_X32_BIT, -1L, 0L, 0L); }
/* W^X on: an x32-tagged mmap with PROT_EXEC must die. */
static int c_abi_wx_deny(void) { return sb_abi_kill(1, __NR_mmap | SB_X32_BIT, 0L, 4096L, 4L); }
static int c_abi_wx_ext(void) { return sb_abi_kill(2, __NR_mmap | SB_X32_BIT, 0L, 4096L, 4L); }
/* Extended builder: bit-tagged and reserved-alias calls. */
static int c_abi_ext_bit(void) { return sb_abi_kill(3, __NR_getpid | SB_X32_BIT, -1L, 0L, 0L); }
static int c_abi_ext_alias_first(void) { return sb_abi_kill(3, 512, -1L, 0L, 0L); }
static int c_abi_ext_alias_last(void) { return sb_abi_kill(2, 547, -1L, 0L, 0L); }
static int c_abi_deny_alias_last(void) { return sb_abi_kill(0, 547, -1L, 0L, 0L); }
static int c_abi_ext_native_ok(void)
{
    int rc = sb_abi_install(2);
    if (rc) return rc;
    return os_sandbox_raw_syscall_for_testing(__NR_getpid, 0L, 0L, 0L) == (long)getpid() ? 0 : 7;
}
/* Boundaries: 511 and 548 are outside the guard range and behave as without
 * it (ENOSYS: unassigned on every x86-64 kernel). */
static int c_abi_edge_511_deny(void) { return sb_abi_enosys(0, 511); }
static int c_abi_edge_548_deny(void) { return sb_abi_enosys(0, 548); }
static int c_abi_edge_511_ext(void) { return sb_abi_enosys(3, 511); }
static int c_abi_edge_548_ext(void) { return sb_abi_enosys(2, 548); }

/* Host controls with the actual result: with no filter the high-bit call is
 * ENOSYS (x32 not built into this kernel) or runs as x32 getpid, and a bare
 * reserved alias is ENOSYS (kernel 5.4 and later). */
static int c_abi_host_bit(void)
{
    errno = 0;
    long r = os_sandbox_raw_syscall_for_testing(__NR_getpid | SB_X32_BIT, -1L, 0L, 0L);
    if (r == (long)getpid()) return 0; /* kernel has the x32 ABI enabled */
    return r == -1 && errno == ENOSYS ? 0 : 5;
}
static int c_abi_host_alias(void)
{
    errno = 0;
    long r = os_sandbox_raw_syscall_for_testing(512, -1L, 0L, 0L);
    return r == -1 && errno == ENOSYS ? 0 : 5;
}

/* Capacity: with the maximum rule count the built length equals the computed
 * bound exactly, and one more rule is refused before any filter is built. */
static int c_abi_capacity(int mode)
{
    bool wx = mode == 0 || mode == 2;
    bool clone = mode == 2;
    size_t extra = 4u + 5u + 1u + (wx ? 15u : 0u) + (clone ? 6u : 0u);
    size_t most = (512u - extra) / 2u;
    int denied[300];
    static const int enosys[1] = {__NR_clone3};
    struct zcl_result over, ok;
    for (size_t i = 0; i < sizeof(denied) / sizeof(denied[0]); ++i) denied[i] = __NR_getppid;
    if (!os_sandbox_no_new_privs()) return 70;
    over = mode < 2 ? os_sandbox_seccomp_deny(denied, most + 1u, wx)
                    : os_sandbox_seccomp_deny_ext(denied, most, wx, enosys, 2, clone);
    if (over.ok || over.code != OS_SANDBOX_ERR_TOO_MANY_RULES) return 71;
    ok = mode < 2 ? os_sandbox_seccomp_deny(denied, most, wx)
                  : os_sandbox_seccomp_deny_ext(denied, most - 1u, wx, enosys, 1, clone);
    if (!ok.ok) return 72;
    return os_sandbox_seccomp_last_len_for_testing() == extra + 2u * most ? 0 : 73;
}
static int c_abi_cap_deny_wx(void) { return c_abi_capacity(0); }
static int c_abi_cap_deny(void) { return c_abi_capacity(1); }
static int c_abi_cap_ext_wx(void) { return c_abi_capacity(2); }
static int c_abi_cap_ext(void) { return c_abi_capacity(3); }

/* ORDER against the ENOSYS compares: a rule set holding a reserved number and
 * an x32-tagged number as ENOSYS entries. The guard runs first, so both die;
 * a guard placed after the ENOSYS compares would answer ENOSYS instead. */
static int sb_abi_enosys_rules(bool via_ext, long nr)
{
    static const int rules[2] = {512, (int)(__NR_getpid | 0x40000000L)};
    if (!os_sandbox_no_new_privs()) return 70;
    struct zcl_result r = via_ext
        ? os_sandbox_seccomp_deny_ext(NULL, 0, false, rules, 2, false)
        : os_sandbox_seccomp_deny(rules, 2, false); /* deny-list twin: same numbers */
    if (!r.ok) return 71;
    (void)os_sandbox_raw_syscall_for_testing(nr, -1L, 0L, 0L);
    return 5;
}
static int c_abi_enosys_reserved_ext(void) { return sb_abi_enosys_rules(true, 512); }
static int c_abi_enosys_tagged_ext(void) { return sb_abi_enosys_rules(true, __NR_getpid | 0x40000000L); }
static int c_abi_enosys_reserved_deny(void) { return sb_abi_enosys_rules(false, 512); }
static int c_abi_enosys_tagged_deny(void) { return sb_abi_enosys_rules(false, __NR_getpid | 0x40000000L); }

/* A count pair whose sum wraps to a tiny value must still be refused. */
static int c_abi_count_wrap(void)
{
    static const int one[1] = {__NR_getppid};
    if (!os_sandbox_no_new_privs()) return 70;
    struct zcl_result r = os_sandbox_seccomp_deny_ext(one, SIZE_MAX, false, one, 1, false);
    if (r.ok || r.code != OS_SANDBOX_ERR_TOO_MANY_RULES) return 71;
    r = os_sandbox_seccomp_deny_ext(one, 1, false, one, SIZE_MAX, false);
    return !r.ok && r.code == OS_SANDBOX_ERR_TOO_MANY_RULES ? 0 : 72;
}
#endif

static char g_fsize_path[128];

static int c_rlimit_fsize(void)
{
    struct os_sandbox_rlimits lim = {
        OS_SANDBOX_RLIMIT_KEEP, OS_SANDBOX_RLIMIT_KEEP,
        OS_SANDBOX_RLIMIT_KEEP, 4096 /*FSIZE*/,
        OS_SANDBOX_RLIMIT_KEEP, 0 /*CORE*/,
    };
    if (!os_sandbox_set_rlimits(&lim).ok) return 70;
    int fd = open(g_fsize_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) return 71;
    char buf[65536];
    memset(buf, 'x', sizeof buf);
    for (int i = 0; i < 64; i++) {
        if (write(fd, buf, sizeof buf) < 0) { close(fd); return 9; }
    }
    close(fd);
    return 8; /* reached only if FSIZE was not enforced (expect SIGXFSZ) */
}

static int c_rlimit_nproc(void)
{
    struct os_sandbox_rlimits lim = os_sandbox_session_rlimits();
    /* Isolate NPROC — leave everything else alone so this child can report. */
    lim.as_bytes = OS_SANDBOX_RLIMIT_KEEP;
    lim.fsize_bytes = OS_SANDBOX_RLIMIT_KEEP;
    lim.nofile = OS_SANDBOX_RLIMIT_KEEP;
    lim.core_bytes = OS_SANDBOX_RLIMIT_KEEP;
    if (!os_sandbox_set_rlimits(&lim).ok) return 70;
    pid_t p = fork();
    if (p == 0) _exit(0);
    if (p < 0 && errno == EAGAIN) return 0;   /* the expected NPROC=1 outcome */
    if (p > 0) { int s; waitpid(p, &s, 0); return 20; }
    return 21;
}

static char g_ll_dir[128];

static int c_landlock(void)
{
    char inside[192], preopen_probe[192];
    snprintf(inside, sizeof inside, "%s/in.txt", g_ll_dir);
    snprintf(preopen_probe, sizeof preopen_probe, "%s/pre.txt", g_ll_dir);
    int f = open(inside, O_CREAT | O_RDWR, 0600); if (f >= 0) close(f);

    /* An fd to a file OUTSIDE the grant, opened BEFORE restrict — must remain
     * usable afterwards (probe 4's pre-opened-fd-survives property). */
    int pre = open("/etc/hostname", O_RDONLY | O_CLOEXEC);
    if (pre < 0) return 70;

    struct os_sandbox_path_rule rules[] = {{ .path = g_ll_dir, .allow_read = true, .allow_write = true }};
    if (!os_sandbox_no_new_privs()) return 71;
    struct zcl_result r = os_sandbox_landlock_restrict(rules, 1);
    if (!r.ok) return 72;

    /* inside grant: allowed */
    int in = open(inside, O_RDWR);
    if (in < 0) return 73;
    close(in);
    /* outside grant, fresh open: denied EACCES */
    int out = open("/etc/passwd", O_RDONLY);
    if (out >= 0) { close(out); return 74; }
    if (errno != EACCES) return 75;
    /* pre-opened outside fd: still usable */
    char b[8];
    ssize_t rd = read(pre, b, sizeof b);
    close(pre);
    if (rd < 0) return 76;
    return 0;
}

/* ── Landlock retrofit join: os_sandbox_landlock_apply_to_self() ────────────
 *
 * The retrofit's whole point (the seccomp analogue is
 * c_tsync_covers_preexisting_thread below): a thread spawned BEFORE
 * os_sandbox_landlock_restrict() runs is NOT confined by it (no TSYNC
 * equivalent for Landlock). It stays unconfined until it calls
 * os_sandbox_landlock_apply_to_self() on ITSELF, from inside its own loop —
 * exactly how the health sweeper / the metrics printer use it (the
 * supervisor dispatch thread deliberately does NOT — see supervisor.c:
 * supervisor_thread_main — since it fans out to every registered child's
 * on_tick and confining the dispatcher would confine all of them). This
 * child proves both halves: unconfined before the join,
 * confined after, idempotent on a repeat call, and the witness count moves by
 * exactly one per distinct joining thread. */

static char g_ll2_dir[128];
static _Atomic int g_retro_thread_ready;
static _Atomic int g_retro_go;
static _Atomic int g_retro_before;  /* 0 = unconfined (expected pre-join) */
static _Atomic int g_retro_after;   /* 0 = confined + idempotent (expected) */

static void *retro_preexisting_thread(void *arg)
{
    (void)arg;
    atomic_store(&g_retro_thread_ready, 1);
    while (atomic_load(&g_retro_go) == 0) { /* spin until the domain exists */ }

    /* Pre-join: this thread predates the domain, so an outside-grant open
     * must still SUCCEED (the retrofit gap, proven present). */
    int f = open("/etc/hostname", O_RDONLY);
    atomic_store(&g_retro_before, (f >= 0) ? 0 : 1);
    if (f >= 0) close(f);

    struct zcl_result r1 = os_sandbox_landlock_apply_to_self();
    if (!r1.ok) { atomic_store(&g_retro_after, 2); return NULL; }
    /* Idempotent: a second join call from the same thread must still be ok
     * (and must not be observable as a second confinement layer failing). */
    struct zcl_result r2 = os_sandbox_landlock_apply_to_self();
    if (!r2.ok) { atomic_store(&g_retro_after, 3); return NULL; }

    /* Post-join: the same outside-grant open must now be denied. */
    int f2 = open("/etc/hostname", O_RDONLY);
    if (f2 >= 0) { close(f2); atomic_store(&g_retro_after, 4); return NULL; }
    atomic_store(&g_retro_after, (errno == EACCES) ? 0 : 5);
    return NULL;
}

static int c_landlock_retrofit_join(void)
{
    atomic_store(&g_retro_thread_ready, 0);
    atomic_store(&g_retro_go, 0);
    atomic_store(&g_retro_before, -1);
    atomic_store(&g_retro_after, -1);

    pthread_t th;
    if (pthread_create(&th, NULL, retro_preexisting_thread, NULL) != 0)
        return 70;
    while (atomic_load(&g_retro_thread_ready) == 0) { /* spin */ }

    int before_count = os_sandbox_landlock_restricted_count();

    struct os_sandbox_path_rule rules[] = {{ .path = g_ll2_dir, .allow_read = true, .allow_write = true }};
    if (!os_sandbox_no_new_privs()) return 71;
    struct zcl_result r = os_sandbox_landlock_restrict(rules, 1);
    if (!r.ok) return 72;

    /* The entering (this) thread's own join is counted once. */
    if (os_sandbox_landlock_restricted_count() != before_count + 1) return 73;

    atomic_store(&g_retro_go, 1);
    pthread_join(th, NULL);

    if (atomic_load(&g_retro_before) != 0) return 74;  /* was NOT confined pre-join */
    if (atomic_load(&g_retro_after) != 0) return 75;   /* IS confined post-join */

    /* Exactly one MORE join counted for the retrofitting thread — the
     * idempotent second call must not have double-counted. */
    if (os_sandbox_landlock_restricted_count() != before_count + 2) return 76;

    return 0;
}

/* Calling the retrofit join before ANY Landlock domain exists in this process
 * is a non-fatal non-ok (OS_SANDBOX_ERR_LANDLOCK_UNAVAILABLE) — never a crash,
 * since health/metrics call it unconditionally on every tick from boot
 * onward, long before -sandbox=steady (if ever) enters one. */
static int c_landlock_apply_before_any_domain(void)
{
    struct zcl_result r = os_sandbox_landlock_apply_to_self();
    if (r.ok) return 1;
    return (r.code == OS_SANDBOX_ERR_LANDLOCK_UNAVAILABLE) ? 0 : 2;
}

/* ── enter(SANDBOX_SESSION_CHILD) children ─────────────────────────────── */

static char g_sess_dir[128];

/* Build the session profile but leave AS/NPROC unclamped: this child must
 * survive to report, and it does not fork, so those two caps only add
 * flakiness (the test process already maps > 256 MiB). exec/socket/landlock
 * are what we are actually asserting. */
static struct os_sandbox_profile sess_profile(struct os_sandbox_path_rule *r)
{
    struct os_sandbox_profile p = os_sandbox_session_child_profile(r, 1);
    p.rlimits.as_bytes = OS_SANDBOX_RLIMIT_KEEP;
    p.rlimits.nproc = OS_SANDBOX_RLIMIT_KEEP;
    return p;
}

static int c_enter_alive(void)
{
    char inside[192];
    snprintf(inside, sizeof inside, "%s/f.txt", g_sess_dir);
    int f = open(inside, O_CREAT | O_RDWR, 0600); if (f >= 0) close(f);
    struct os_sandbox_path_rule rules[] = {{ .path = g_sess_dir, .allow_read = true, .allow_write = true }};
    struct os_sandbox_profile p = sess_profile(rules);
    if (!os_sandbox_enter(&p).ok) return 70;
    if (!os_sandbox_active()) return 71;
    int in = open(inside, O_RDWR);
    if (in < 0) return 72;              /* can read/write its granted dir */
    close(in);
    int out = open("/etc/passwd", O_RDONLY);
    if (out >= 0) { close(out); return 73; }  /* cannot escape the grant */
    if (errno != EACCES) return 74;
    return 0;
}

static int c_enter_exec(void)
{
    struct os_sandbox_path_rule rules[] = {{ .path = g_sess_dir, .allow_read = true, .allow_write = true }};
    struct os_sandbox_profile p = sess_profile(rules);
    if (!os_sandbox_enter(&p).ok) return 70;
    execve("/bin/true", (char *const[]){"/bin/true", NULL}, (char *const[]){NULL});
    return 5; /* reached only if exec was not denied */
}

static int c_enter_socket(void)
{
    struct os_sandbox_path_rule rules[] = {{ .path = g_sess_dir, .allow_read = true, .allow_write = true }};
    struct os_sandbox_profile p = sess_profile(rules);
    if (!os_sandbox_enter(&p).ok) return 70;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    (void)s;
    return 6; /* reached only if socket was not denied */
}

/* ── node steady-state profile (the boot-wired resident-node confinement) ─
 *
 * Unlike the session child, the node profile MUST keep socket()/clone() (the
 * node opens peer sockets + spawns threads) while still denying execve and the
 * escape family. These children prove that distinction. The record-registration
 * half of the wiring lives in engine/composition/src/boot.c and is pinned by
 * tools/lint/lintc/gate_boot_wiring.c (a full boot in a unit test is
 * impractical). Multi-thread coverage is proven at the primitive level here:
 * seccomp TSYNC below, and the Landlock retrofit join
 * (os_sandbox_landlock_apply_to_self, tested above) — end-to-end proof that
 * the wired-in threads actually join at boot is a soak/live-node concern. */

static char g_node_dir[128];

static int c_node_enter_socket_ok(void)
{
    struct os_sandbox_path_rule rules[] = {{ .path = g_node_dir, .allow_read = true, .allow_write = true }};
    struct os_sandbox_profile p = os_sandbox_node_steady_state_profile(rules, 1);
    if (!os_sandbox_enter(&p).ok) return 70;
    if (!os_sandbox_active()) return 71;
    /* socket() must be ALLOWED under the node deny-set (session denies it). */
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 72;
    close(s);
    return 0;
}

static int c_node_enter_fork_ok(void)
{
    struct os_sandbox_path_rule rules[] = {{ .path = g_node_dir, .allow_read = true, .allow_write = true }};
    struct os_sandbox_profile p = os_sandbox_node_steady_state_profile(rules, 1);
    if (!os_sandbox_enter(&p).ok) return 70;
    /* clone/fork must be ALLOWED (the node spawns threads). No nproc clamp. */
    pid_t c = fork();
    if (c == 0) _exit(0);
    if (c < 0) return 73;
    int s; waitpid(c, &s, 0);
    return (WIFEXITED(s) && WEXITSTATUS(s) == 0) ? 0 : 74;
}

static int c_node_enter_exec_denied(void)
{
    struct os_sandbox_path_rule rules[] = {{ .path = g_node_dir, .allow_read = true, .allow_write = true }};
    struct os_sandbox_profile p = os_sandbox_node_steady_state_profile(rules, 1);
    if (!os_sandbox_enter(&p).ok) return 70;
    execve("/bin/true", (char *const[]){"/bin/true", NULL}, (char *const[]){NULL});
    return 5; /* reached only if exec was not denied */
}

static bool denyset_contains(const int *set, size_t n, long nr)
{
    for (size_t i = 0; i < n; i++) if (set[i] == (int)nr) return true;
    return false;
}

/* ── seccomp TSYNC: the filter must reach a PRE-EXISTING thread ─────────────
 *
 * The retrofit's whole point: os_sandbox_seccomp_deny installs via
 * seccomp(2)+SECCOMP_FILTER_FLAG_TSYNC so a thread that was ALREADY RUNNING
 * before the install is covered too (prctl(PR_SET_SECCOMP) would confine only
 * the caller + its later descendants). These children run inside a fork so the
 * SIGSYS kill is contained to the child. */

static _Atomic int g_tsync_thread_ready;
static _Atomic int g_tsync_go;

/* Spawned BEFORE the filter is installed; when released it makes a DENIED
 * syscall (execve). If TSYNC covered this pre-existing thread the syscall
 * SIGSYS-kills the whole process; if it did not, execve would replace the
 * process image with /bin/true (exit 0) — the negative outcome the parent
 * distinguishes by terminating signal vs exit code. */
static void *tsync_preexisting_thread(void *arg)
{
    (void)arg;
    atomic_store(&g_tsync_thread_ready, 1);
    while (atomic_load(&g_tsync_go) == 0) { /* spin until released */ }
    execve("/bin/true", (char *const[]){"/bin/true", NULL},
           (char *const[]){NULL});
    return NULL; /* reached only if execve was neither denied nor performed */
}

static int c_tsync_covers_preexisting_thread(void)
{
    atomic_store(&g_tsync_thread_ready, 0);
    atomic_store(&g_tsync_go, 0);

    pthread_t th;
    if (pthread_create(&th, NULL, tsync_preexisting_thread, NULL) != 0)
        return 70;
    /* Ensure the thread exists BEFORE the filter is installed. */
    while (atomic_load(&g_tsync_thread_ready) == 0) { /* spin */ }

    size_t n = 0;
    const int *d = os_sandbox_node_steady_denied_syscalls(&n);
    if (!os_sandbox_no_new_privs()) return 71;
    struct zcl_result r = os_sandbox_seccomp_deny(d, n, false);
    if (!r.ok) return 72;
    /* On this kernel TSYNC must be the path that ran. */
    if (!os_sandbox_seccomp_tsync_active()) return 73;

    atomic_store(&g_tsync_go, 1);
    /* The pre-existing thread's execve must SIGSYS-kill the whole process. If
     * it instead exec'd /bin/true, join returns and we report the miss. */
    pthread_join(th, NULL);
    return 8; /* reached only if the pre-existing thread was NOT confined */
}

/* Records which install mechanism ran: on a >= 3.17 kernel it must be TSYNC. */
static int c_tsync_method_is_tsync(void)
{
    size_t n = 0;
    const int *d = os_sandbox_node_steady_denied_syscalls(&n);
    if (!os_sandbox_no_new_privs()) return 70;
    if (!os_sandbox_seccomp_deny(d, n, false).ok) return 71;
    const char *m = os_sandbox_seccomp_install_method();
    if (!m || strcmp(m, "tsync") != 0) return 72;
    return 0;
}

/* ── Landlock: every right handled, not just read/write ──────────────────
 *
 * Landlock ALLOWS a right the ruleset does not handle. These children are
 * granted ONE scratch dir (read+write+create) and then try each right the
 * old builder left unhandled against a sibling dir OUTSIDE the grant that
 * the same uid owns. Each attempt must fail with EACCES. Every child first
 * performs the same operation on the outside dir BEFORE restricting, so a
 * pass cannot come from the filesystem refusing the operation anyway. */

static char g_adv_grant[1024];
static char g_adv_out[1024];

static int adv_path(char *buf, size_t n, const char *dir, const char *leaf)
{
    int w = snprintf(buf, n, "%s/%s", dir, leaf);
    return w > 0 && (size_t)w < n ? 0 : 1;
}

static int adv_confine_to_grant(void)
{
    struct os_sandbox_path_rule rules[] = {{
        .path = g_adv_grant, .allow_read = true, .allow_write = true,
        .allow_create = true }};
    if (!os_sandbox_no_new_privs()) return 70;
    return os_sandbox_landlock_restrict(rules, 1).ok ? 0 : 71;
}

static int adv_denied(int rc) { return rc != 0 && errno == EACCES ? 0 : 1; }

static int c_adv_symlink_outside(void)
{
    char ctl[1100], probe[1100], inside[1100];
    if (adv_path(ctl, sizeof ctl, g_adv_out, "ctl.link") ||
        adv_path(probe, sizeof probe, g_adv_out, "evil.link") ||
        adv_path(inside, sizeof inside, g_adv_grant, "ok.link")) return 60;
    if (symlink("/etc/passwd", ctl) != 0) return 61;
    if (adv_confine_to_grant() != 0) return 62;
    if (adv_denied(symlink("/etc/passwd", probe))) return 10;
    if (symlink("/etc/passwd", inside) != 0) return 11;
    return 0;
}

static int c_adv_mkfifo_outside(void)
{
    char ctl[1100], probe[1100], inside[1100];
    if (adv_path(ctl, sizeof ctl, g_adv_out, "ctl.fifo") ||
        adv_path(probe, sizeof probe, g_adv_out, "evil.fifo") ||
        adv_path(inside, sizeof inside, g_adv_grant, "ok.fifo")) return 60;
    if (mkfifo(ctl, 0600) != 0) return 61;
    if (adv_confine_to_grant() != 0) return 62;
    if (adv_denied(mkfifo(probe, 0600))) return 10;
    if (mkfifo(inside, 0600) != 0) return 11;
    return 0;
}

static int adv_bind_unix(const char *leaf)
{
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return -2;
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    (void)snprintf(a.sun_path, sizeof a.sun_path, "%s", leaf);
    int rc = bind(s, (struct sockaddr *)&a, sizeof a);
    int e = errno;
    close(s);
    errno = e;
    return rc;
}

static int c_adv_bind_unix_outside(void)
{
    /* Relative socket names keep sun_path short however deep the checkout
     * is; the kernel still resolves (and Landlock still checks) the full
     * path beneath the cwd. */
    if (chdir(g_adv_out) != 0) return 60;
    if (adv_bind_unix("ctl.sock") != 0) return 61;
    if (adv_confine_to_grant() != 0) return 62;
    if (adv_denied(adv_bind_unix("evil.sock"))) return 10;
    if (chdir(g_adv_grant) != 0) return 63;
    if (adv_bind_unix("ok.sock") != 0) return 11;
    return 0;
}

static int c_adv_truncate_outside(void)
{
    char victim[1100];
    if (adv_path(victim, sizeof victim, g_adv_out, "victim.key")) return 60;
    int fd = open(victim, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return 61;
    ssize_t w = write(fd, "secret-key-bytes", 16);
    close(fd);
    if (w != 16) return 62;
    if (truncate(victim, 16) != 0) return 63;  /* control: uid may truncate */
    if (adv_confine_to_grant() != 0) return 64;
    if (adv_denied(truncate(victim, 0))) return 10;
    struct stat st;
    if (stat(victim, &st) != 0 || st.st_size != 16) return 12;
    return 0;
}

static int c_adv_mknod_outside(void)
{
    char ctl[1100], probe[1100];
    if (adv_path(ctl, sizeof ctl, g_adv_out, "ctl.node") ||
        adv_path(probe, sizeof probe, g_adv_out, "evil.node")) return 60;
    /* Control: an unprivileged mknod of a character device reaches the
     * capability check and fails EPERM; confined, Landlock's MAKE_CHAR check
     * runs first and answers EACCES. A regular-file mknod is MAKE_REG. */
    dev_t null_dev = (dev_t)((1u << 8) | 3u);
    if (mknod(ctl, S_IFCHR | 0600, null_dev) == 0 || errno != EPERM) return 61;
    if (mknod(ctl, S_IFREG | 0600, 0) != 0) return 62;
    if (adv_confine_to_grant() != 0) return 63;
    if (adv_denied(mknod(probe, S_IFCHR | 0600, null_dev))) return 10;
    if (adv_denied(mknod(probe, S_IFREG | 0600, 0))) return 11;
    if (adv_denied(mkdir(probe, 0700))) return 12;
    return 0;
}

static int c_adv_rename_across_dirs_inside(void)
{
    char a[1100], b[1100], from[1100], to[1100];
    if (adv_path(a, sizeof a, g_adv_grant, "ra") ||
        adv_path(b, sizeof b, g_adv_grant, "rb") ||
        adv_path(from, sizeof from, a, "moved") ||
        adv_path(to, sizeof to, b, "moved")) return 60;
    if (mkdir(a, 0700) != 0 || mkdir(b, 0700) != 0) return 61;
    int fd = open(from, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
    if (fd < 0) return 62;
    close(fd);
    if (adv_confine_to_grant() != 0) return 63;
    if (rename(from, to) != 0) return 10;
    if (access(to, F_OK) != 0 || access(from, F_OK) == 0) return 11;
    return 0;
}

/* A caller that never sets allow_create (the node profiles) keeps create and
 * unlink beneath its WRITE grant — SQLite needs its WAL/journal — but no
 * longer anywhere else. */
static int c_adv_write_implies_create_only_inside(void)
{
    char inside[1100], outside[1100];
    if (adv_path(inside, sizeof inside, g_adv_grant, "wal") ||
        adv_path(outside, sizeof outside, g_adv_out, "evil.dir")) return 60;
    struct os_sandbox_path_rule rules[] = {{
        .path = g_adv_grant, .allow_read = true, .allow_write = true }};
    if (!os_sandbox_no_new_privs()) return 70;
    if (!os_sandbox_landlock_restrict(rules, 1).ok) return 71;
    int fd = open(inside, O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return 10;
    close(fd);
    if (unlink(inside) != 0) return 11;
    if (adv_denied(mkdir(outside, 0700))) return 12;
    return 0;
}

static int c_adv_no_rules_denies_all_writes(void)
{
    char outside[1100];
    if (adv_path(outside, sizeof outside, g_adv_out, "nothing")) return 60;
    if (!os_sandbox_no_new_privs()) return 70;
    if (!os_sandbox_landlock_restrict(NULL, 0).ok) return 71;
    if (adv_denied(mkdir(outside, 0700))) return 10;
    if (adv_denied(symlink("/etc/passwd", outside))) return 11;
    if (adv_denied(mkfifo(outside, 0600))) return 12;
    return 0;
}

/* ── Landlock TCP port rules (ABI >= 4) ──────────────────────────────── */

static int adv_free_tcp_port(uint16_t *port)
{
    int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return 1;
    struct sockaddr_in a = { .sin_family = AF_INET,
                             .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t len = sizeof a;
    int rc = bind(s, (struct sockaddr *)&a, sizeof a) != 0 ||
             getsockname(s, (struct sockaddr *)&a, &len) != 0;
    close(s);
    *port = ntohs(a.sin_port);
    return rc || *port == 0;
}

static int adv_tcp(uint16_t port, bool do_bind)
{
    int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return -2;
    int one = 1;
    (void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port),
                             .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    int rc = do_bind ? bind(s, (struct sockaddr *)&a, sizeof a)
                     : connect(s, (struct sockaddr *)&a, sizeof a);
    int e = errno;
    close(s);
    errno = e;
    return rc;
}

static int c_tcp_port_rules(void)
{
    uint16_t granted = 0, other = 0;
    if (adv_free_tcp_port(&granted) || adv_free_tcp_port(&other)) return 60;
    if (granted == other) return 61;
    struct os_sandbox_tcp_port_rule tcp[] = {{ .port = granted,
                                               .allow_bind = true }};
    struct os_sandbox_landlock_policy policy = {
        .restrict_tcp = true, .tcp_rules = tcp, .n_tcp_rules = 1 };
    if (!os_sandbox_no_new_privs()) return 70;
    struct zcl_result r = os_sandbox_landlock_restrict_policy(&policy);
    if (!r.ok) return 71;
    if (adv_tcp(granted, true) != 0) return 10;
    if (adv_denied(adv_tcp(other, true))) return 11;
    /* A closed loopback port answers ECONNREFUSED; only Landlock says EACCES. */
    if (adv_denied(adv_tcp(other, false))) return 12;
    return 0;
}

static int c_tcp_policy_refusals(void)
{
    struct os_sandbox_tcp_port_rule open_port = { .port = 1, .allow_bind = true };
    struct os_sandbox_tcp_port_rule empty = { .port = 1 };
    struct os_sandbox_landlock_policy unrestricted = {
        .tcp_rules = &open_port, .n_tcp_rules = 1 };
    struct os_sandbox_landlock_policy no_access = {
        .restrict_tcp = true, .tcp_rules = &empty, .n_tcp_rules = 1 };
    if (!os_sandbox_no_new_privs()) return 70;
    struct zcl_result a = os_sandbox_landlock_restrict_policy(&unrestricted);
    struct zcl_result b = os_sandbox_landlock_restrict_policy(&no_access);
    struct zcl_result c = os_sandbox_landlock_restrict_policy(NULL);
    if (a.ok || a.code != OS_SANDBOX_ERR_INVALID_ARG) return 10;
    if (b.ok || b.code != OS_SANDBOX_ERR_INVALID_ARG) return 11;
    if (c.ok || c.code != OS_SANDBOX_ERR_INVALID_ARG) return 12;
    /* Nothing was applied: this process is still unconfined. */
    int fd = open("/etc/passwd", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 13;
    close(fd);
    if (os_sandbox_landlock_restricted_count() != 0) return 14;
    return 0;
}

/* On a kernel below ABI 4 the TCP half cannot be enforced: the call must
 * refuse with the named code and apply NOTHING, not a filesystem-only
 * domain. Runs on every host; on ABI >= 4 it proves the opposite branch. */
static int c_tcp_fail_closed_contract(void)
{
    struct os_sandbox_path_rule rules[] = {{
        .path = g_adv_grant, .allow_read = true }};
    struct os_sandbox_landlock_policy policy = {
        .fs_rules = rules, .n_fs_rules = 1, .restrict_tcp = true };
    if (!os_sandbox_no_new_privs()) return 70;
    struct zcl_result r = os_sandbox_landlock_restrict_policy(&policy);
    if (os_sandbox_landlock_tcp_supported())
        return r.ok ? 0 : 10;
    if (r.ok || r.code != OS_SANDBOX_ERR_LANDLOCK_NET_UNAVAILABLE) return 11;
    if (os_sandbox_landlock_restricted_count() != 0) return 12;
    int fd = open("/etc/passwd", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 13;
    close(fd);
    return 0;
}

/* ── userns map round-trip (userns-gated) ──────────────────────────────── */

static int userns_map_roundtrip(void)
{
    int pr[2], pc[2];
    if (pipe(pr) != 0 || pipe(pc) != 0) return 90;
    pid_t pid = fork();
    if (pid == 0) {
        close(pr[0]); close(pc[1]);
        char b = (unshare(CLONE_NEWUSER) == 0) ? 'U' : 'E';
        ssize_t w = write(pr[1], &b, 1); (void)w;
        if (b == 'E') _exit(91);
        char go;
        ssize_t rd = read(pc[0], &go, 1); (void)rd;  /* wait for parent maps */
        _exit(getuid() == 1000 ? 0 : 92);
    }
    close(pr[1]); close(pc[0]);
    char b = 0;
    ssize_t rd = read(pr[0], &b, 1); (void)rd;
    if (b != 'U') { int s; waitpid(pid, &s, 0); return 93; }
    struct zcl_result r = os_sandbox_write_userns_maps(pid, 1000, 1000);
    char go = 'G';
    ssize_t w = write(pc[1], &go, 1); (void)w;
    int st = 0;
    waitpid(pid, &st, 0);
    if (!r.ok) return 94;
    if (!WIFEXITED(st)) return -WTERMSIG(st);
    return WEXITSTATUS(st);
}

int test_os_sandbox(void)
{
    printf("\n=== platform os_sandbox tests ===\n");
    int failures = 0;

    test_make_tmpdir(g_ll_dir, sizeof g_ll_dir, "os_sandbox", "ll");
    test_make_tmpdir(g_ll2_dir, sizeof g_ll2_dir, "os_sandbox", "ll2");
    test_make_tmpdir(g_sess_dir, sizeof g_sess_dir, "os_sandbox", "sess");
    test_make_tmpdir(g_node_dir, sizeof g_node_dir, "os_sandbox", "node");
    test_fmt_tmpdir(g_fsize_path, sizeof g_fsize_path, "os_sandbox", "fsize");
    test_make_tmpdir(g_adv_grant, sizeof g_adv_grant, "os_sandbox", "grant");
    test_make_tmpdir(g_adv_out, sizeof g_adv_out, "os_sandbox", "outside");

    /* ── builders in isolation ─────────────────────────────────────── */
    SB_CHECK("no_new_privs succeeds in child", sb_run_child(c_no_new_privs) == 0);

    int abi = os_sandbox_landlock_abi();
    printf("os_sandbox: landlock ABI = %d\n", abi);
    SB_CHECK("landlock ABI >= 1 (>=5.13 kernel)", abi >= 1);

    /* seccomp: normal code runs, denied syscalls SIGSYS-kill the process */
    SB_CHECK("seccomp deny: execve -> SIGSYS", sb_run_child(c_seccomp_exec) == -SIGSYS);
    SB_CHECK("seccomp deny: socket -> SIGSYS", sb_run_child(c_seccomp_socket) == -SIGSYS);
    SB_CHECK("seccomp W^X strict: file-backed PROT_EXEC mmap -> SIGSYS",
             sb_run_child(c_wx_strict_file) == -SIGSYS);
    SB_CHECK("seccomp W^X file-exec: file-backed PROT_EXEC mmap allowed",
             sb_run_child(c_wx_file_file) == 0);
    SB_CHECK("seccomp W^X file-exec: file-backed PROT_WRITE|PROT_EXEC mmap -> SIGSYS",
             sb_run_child(c_wx_file_rwx) == -SIGSYS);
    SB_CHECK("seccomp W^X file-exec: anonymous PROT_EXEC mmap -> SIGSYS",
             sb_run_child(c_wx_file_anon) == -SIGSYS);
    SB_CHECK("seccomp W^X file-exec: mprotect PROT_EXEC -> SIGSYS",
             sb_run_child(c_wx_file_mprot) == -SIGSYS);
    SB_CHECK("seccomp W^X file-exec: PROT_EXEC mmap with fd -1 -> SIGSYS",
             sb_run_child(c_wx_file_nofd) == -SIGSYS);
    SB_CHECK("seccomp W^X file-exec: non-exec anonymous mmap unaffected",
             sb_run_child(c_wx_file_plain) == 0);
#if defined(__x86_64__) && defined(__linux__)
    if (!os_sandbox_seccomp_supported()) {
        printf("os_sandbox: SKIP x32/reserved ABI cases (seccomp unavailable in this build)\n");
    } else {
    SB_CHECK("seccomp ABI host control: raw x32 returns without SIGSYS",
             sb_run_child(c_seccomp_x32_raw) == 0);
    SB_CHECK("seccomp ABI host control: raw reserved ptrace alias returns without SIGSYS",
             sb_run_child(c_seccomp_reserved_raw) == 0);
    SB_CHECK("seccomp deny: native getpid remains allowed",
             sb_run_child(c_seccomp_native_getpid) == 0);
    SB_CHECK("seccomp deny: x32 syscall bit -> SIGSYS",
             sb_run_child(c_seccomp_x32_getpid) == -SIGSYS);
    SB_CHECK("seccomp deny: reserved ABI range first -> SIGSYS",
             sb_run_child(c_seccomp_reserved_first) == -SIGSYS);
    SB_CHECK("seccomp deny: reserved ptrace alias -> SIGSYS",
             sb_run_child(c_seccomp_reserved_ptrace) == -SIGSYS);
    SB_CHECK("seccomp deny: reserved ABI range last -> SIGSYS",
             sb_run_child(c_seccomp_reserved_last) == -SIGSYS);
    SB_CHECK("seccomp deny: ABI preamble fits maximum filter and refuses overflow",
             sb_run_child(c_seccomp_abi_filter_bound) == 0);
    SB_CHECK("abi host control: high-bit call is ENOSYS or x32 getpid, alias 512 is ENOSYS",
             sb_run_child(c_abi_host_bit) == 0 && sb_run_child(c_abi_host_alias) == 0);
    SB_CHECK("seccomp deny: x32-tagged execve (denied) -> SIGSYS (guard precedes compares)",
             sb_run_child(c_abi_order_deny) == -SIGSYS);
    SB_CHECK("seccomp deny_ext: x32-tagged execve (denied) -> SIGSYS (guard precedes compares)",
             sb_run_child(c_abi_order_ext) == -SIGSYS);
    SB_CHECK("seccomp deny W^X: x32-tagged mmap PROT_EXEC -> SIGSYS",
             sb_run_child(c_abi_wx_deny) == -SIGSYS);
    SB_CHECK("seccomp deny_ext W^X: x32-tagged mmap PROT_EXEC -> SIGSYS",
             sb_run_child(c_abi_wx_ext) == -SIGSYS);
    SB_CHECK("seccomp deny_ext: x32 syscall bit -> SIGSYS",
             sb_run_child(c_abi_ext_bit) == -SIGSYS);
    SB_CHECK("seccomp deny_ext: reserved alias 512 -> SIGSYS",
             sb_run_child(c_abi_ext_alias_first) == -SIGSYS);
    SB_CHECK("seccomp deny_ext: reserved alias 547 -> SIGSYS",
             sb_run_child(c_abi_ext_alias_last) == -SIGSYS);
    SB_CHECK("seccomp deny: reserved alias 547 -> SIGSYS",
             sb_run_child(c_abi_deny_alias_last) == -SIGSYS);
    SB_CHECK("seccomp deny_ext: native getpid remains allowed",
             sb_run_child(c_abi_ext_native_ok) == 0);
    SB_CHECK("seccomp deny: nr 511 is outside the guard (ENOSYS, not killed)",
             sb_run_child(c_abi_edge_511_deny) == 0);
    SB_CHECK("seccomp deny: nr 548 is outside the guard (ENOSYS, not killed)",
             sb_run_child(c_abi_edge_548_deny) == 0);
    SB_CHECK("seccomp deny_ext: nr 511 is outside the guard (ENOSYS, not killed)",
             sb_run_child(c_abi_edge_511_ext) == 0);
    SB_CHECK("seccomp deny_ext: nr 548 is outside the guard (ENOSYS, not killed)",
             sb_run_child(c_abi_edge_548_ext) == 0);
    SB_CHECK("seccomp deny W^X on: maximum rules build to the exact bound, one more is refused",
             sb_run_child(c_abi_cap_deny_wx) == 0);
    SB_CHECK("seccomp deny W^X off: maximum rules build to the exact bound, one more is refused",
             sb_run_child(c_abi_cap_deny) == 0);
    SB_CHECK("seccomp deny_ext W^X+clone on: maximum rules build to the exact bound, one more is refused",
             sb_run_child(c_abi_cap_ext_wx) == 0);
    SB_CHECK("seccomp deny_ext W^X+clone off: maximum rules build to the exact bound, one more is refused",
             sb_run_child(c_abi_cap_ext) == 0);
    SB_CHECK("seccomp deny_ext: reserved 512 as an ENOSYS rule -> SIGSYS, not ENOSYS (guard precedes ENOSYS compares)",
             sb_run_child(c_abi_enosys_reserved_ext) == -SIGSYS);
    SB_CHECK("seccomp deny_ext: x32-tagged number as an ENOSYS rule -> SIGSYS, not ENOSYS",
             sb_run_child(c_abi_enosys_tagged_ext) == -SIGSYS);
    SB_CHECK("seccomp deny: reserved 512 in the deny list -> SIGSYS",
             sb_run_child(c_abi_enosys_reserved_deny) == -SIGSYS);
    SB_CHECK("seccomp deny: x32-tagged number in the deny list -> SIGSYS",
             sb_run_child(c_abi_enosys_tagged_deny) == -SIGSYS);
    SB_CHECK("seccomp deny_ext: a count pair that wraps size_t is refused, not built",
             sb_run_child(c_abi_count_wrap) == 0);
    }
#endif

    /* rlimits: real enforcement */
    SB_CHECK("rlimit FSIZE -> SIGXFSZ on oversize write",
             sb_run_child(c_rlimit_fsize) == -SIGXFSZ);
    SB_CHECK("rlimit NPROC=1 -> 2nd fork EAGAIN",
             sb_run_child(c_rlimit_nproc) == 0);

    /* Landlock: outside denied, inside allowed, pre-opened fd survives */
    SB_CHECK("landlock: deny outside / allow inside / preopened-fd survives",
             sb_run_child(c_landlock) == 0);

    /* Landlock retrofit join: the whole point of this ticket */
    SB_CHECK("landlock retrofit: apply_to_self before any domain -> non-ok, non-fatal",
             sb_run_child(c_landlock_apply_before_any_domain) == 0);
    SB_CHECK("landlock retrofit: pre-existing thread unconfined pre-join, "
             "confined post-join, idempotent 2nd call, count +2 total",
             sb_run_child(c_landlock_retrofit_join) == 0);

    /* Landlock: every right handled. Outside the one grant each of these
     * is EACCES; inside it the same operations still work. */
    SB_CHECK("landlock: symlink outside grant -> EACCES, inside ok",
             sb_run_child(c_adv_symlink_outside) == 0);
    SB_CHECK("landlock: mkfifo outside grant -> EACCES, inside ok",
             sb_run_child(c_adv_mkfifo_outside) == 0);
    SB_CHECK("landlock: bind AF_UNIX path outside grant -> EACCES, inside ok",
             sb_run_child(c_adv_bind_unix_outside) == 0);
    SB_CHECK("landlock: mknod chr/reg + mkdir outside grant -> EACCES",
             sb_run_child(c_adv_mknod_outside) == 0);
    SB_CHECK("landlock: no rules -> mkdir/symlink/mkfifo anywhere EACCES",
             sb_run_child(c_adv_no_rules_denies_all_writes) == 0);
    SB_CHECK("landlock: write-only grant keeps create inside, not outside",
             sb_run_child(c_adv_write_implies_create_only_inside) == 0);
    if (abi >= 3)
        SB_CHECK("landlock: truncate() of an owned file outside grant -> EACCES",
                 sb_run_child(c_adv_truncate_outside) == 0);
    else
        printf("os_sandbox: SKIP truncate (Landlock ABI %d < 3 cannot "
               "handle TRUNCATE)\n", abi);
    if (abi >= 2)
        SB_CHECK("landlock: cross-directory rename inside grant succeeds",
                 sb_run_child(c_adv_rename_across_dirs_inside) == 0);
    else
        printf("os_sandbox: SKIP cross-dir rename (Landlock ABI %d < 2 "
               "always denies reparenting)\n", abi);
    SB_CHECK("landlock policy: malformed TCP rules refused, nothing applied",
             sb_run_child(c_tcp_policy_refusals) == 0);
    SB_CHECK("landlock policy: TCP needs ABI>=4 or refuses applying nothing",
             sb_run_child(c_tcp_fail_closed_contract) == 0);
    if (os_sandbox_landlock_tcp_supported())
        SB_CHECK("landlock policy: TCP bind/connect limited to granted port",
                 sb_run_child(c_tcp_port_rules) == 0);
    else
        printf("os_sandbox: SKIP TCP port enforcement (Landlock ABI %d < 4)\n",
               abi);

    /* ── the composed profile ──────────────────────────────────────── */
    SB_CHECK("enter(SESSION_CHILD): alive, reads grant, /etc/passwd EACCES",
             sb_run_child(c_enter_alive) == 0);
    SB_CHECK("enter(SESSION_CHILD): exec denied -> SIGSYS",
             sb_run_child(c_enter_exec) == -SIGSYS);
    SB_CHECK("enter(SESSION_CHILD): socket denied -> SIGSYS",
             sb_run_child(c_enter_socket) == -SIGSYS);

    /* ── node steady-state profile: construction + child probe ─────── */
    {
        struct os_sandbox_path_rule r = {
            .path = g_node_dir, .allow_read = true, .allow_write = true };
        struct os_sandbox_profile np = os_sandbox_node_steady_state_profile(&r, 1);
        SB_CHECK("node profile is named node_steady_state",
                 np.name && strcmp(np.name, "node_steady_state") == 0);
        SB_CHECK("node profile: no rlimit clamp (many threads)",
                 !np.apply_rlimits);
        SB_CHECK("node profile: seccomp + landlock + no_new_privs on",
                 np.seccomp && np.landlock && np.no_new_privs);
        size_t nn = 0;
        const int *nd = os_sandbox_node_steady_denied_syscalls(&nn);
        SB_CHECK("node profile denied set == node deny-set",
                 np.denied_syscalls == nd && np.n_denied == nn);
        SB_CHECK("node deny-set includes execve", denyset_contains(nd, nn, __NR_execve));
        SB_CHECK("node deny-set includes ptrace", denyset_contains(nd, nn, __NR_ptrace));
        SB_CHECK("node deny-set EXCLUDES socket (node needs it)",
                 !denyset_contains(nd, nn, __NR_socket));
        SB_CHECK("node deny-set EXCLUDES clone (node spawns threads)",
                 !denyset_contains(nd, nn, __NR_clone));
    }
    SB_CHECK("enter(NODE): socket allowed (unlike session)",
             sb_run_child(c_node_enter_socket_ok) == 0);
    SB_CHECK("enter(NODE): fork/clone allowed",
             sb_run_child(c_node_enter_fork_ok) == 0);
    SB_CHECK("enter(NODE): exec denied -> SIGSYS",
             sb_run_child(c_node_enter_exec_denied) == -SIGSYS);

    /* ── seccomp TSYNC retrofit: covers a pre-existing thread ──────────── */
    SB_CHECK("seccomp install method is TSYNC on this kernel",
             sb_run_child(c_tsync_method_is_tsync) == 0);
    SB_CHECK("seccomp TSYNC: pre-existing thread's exec -> SIGSYS (whole process)",
             sb_run_child(c_tsync_covers_preexisting_thread) == -SIGSYS);

    /* ── capability probe + userns-gated assertions ────────────────── */
    struct os_sandbox_caps caps = os_sandbox_probe_caps();
    printf("os_sandbox: caps userns=%d landlock_abi=%d seccomp=%d\n",
           caps.userns, caps.landlock_abi, caps.seccomp);
    SB_CHECK("caps: seccomp reported available", caps.seccomp);
    SB_CHECK("caps: landlock_abi matches direct probe", caps.landlock_abi == abi);

    bool userns = os_sandbox_userns_available();
    if (userns) {
        /* On the target box (rootless, AppArmor-unconfined) this is the path. */
        printf("os_sandbox: userns available -> running userns-gated assertions\n");
        SB_CHECK("caps.userns agrees with userns_available", caps.userns);
        SB_CHECK("userns map round-trip: child sees mapped uid 1000",
                 userns_map_roundtrip() == 0);
        int flags = os_sandbox_session_ns_flags();
        SB_CHECK("session ns flags include NEWUSER|NEWNET|NEWPID",
                 (flags & CLONE_NEWUSER) && (flags & CLONE_NEWNET) &&
                 (flags & CLONE_NEWPID));
    } else {
        /* Degraded host: skip userns assertions so the suite still passes. */
        printf("os_sandbox: SKIP (userns unavailable on host) — "
               "degraded profile still covered by the builder tests above\n");
    }

    test_rm_rf_recursive(g_ll_dir);
    test_rm_rf_recursive(g_ll2_dir);
    test_rm_rf_recursive(g_sess_dir);
    test_rm_rf_recursive(g_node_dir);
    test_rm_rf_recursive(g_adv_grant);
    test_rm_rf_recursive(g_adv_out);
    unlink(g_fsize_path);

    failures += test_exec_tier_cases();

    printf("=== os_sandbox tests done: %d failure(s) ===\n", failures);
    return failures;
}

#endif
