/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: Linux immutable descriptor execution and trusted descendant cleanup. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "test/test_core.h"
#include "platform/supervised_process.h"
#include "util/supervised_retirement.h"
#include "util/thread_registry.h"
/* Exact resource sentinels, not elapsed-time subtraction. */
enum { FIXTURE_NO_PID = -1, FIXTURE_NO_FD = -1, FIXTURE_ERROR = -1 };
#include "platform/clock.h"
#if defined(__linux__)
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <elf.h>
#include "sha3/sha3.h"

static int64_t fixture_deadline(void)
{
    return clock_now_monotonic_ns() + INT64_C(5000000000);
}

static int fixture_echo(int argc, char **argv)
{
    if (argc != 5 || !getenv("SUPERVISED_ALLOWED") || getenv("SUPERVISED_AMBIENT")) return 31;
    int ambient = atoi(argv[2]), writer = atoi(argv[3]), reader = atoi(argv[4]);
    if (fcntl(ambient, F_GETFD) >= 0 || errno != EBADF) return 32;
    if ((fcntl(writer, F_GETFL) & O_ACCMODE) != O_WRONLY ||
        (fcntl(reader, F_GETFL) & O_ACCMODE) != O_RDONLY) return 33;
    uint8_t bytes[4096];
    ssize_t n;
    while ((n = read(STDIN_FILENO, bytes, sizeof(bytes))) > 0) {
        size_t offset = 0;
        while (offset < (size_t)n) {
            ssize_t written = write(STDOUT_FILENO, bytes + offset, (size_t)n - offset);
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) return 34;
            offset += (size_t)written;
        }
    }
    return n == 0 ? 0 : 35;
}

static int fixture_tree(bool locked)
{
    pid_t intermediate = fork();
    if (intermediate < 0) return 36;
    if (!intermediate) {
        if (setsid() < 0) _exit(37);
        pid_t leaf = fork();
        if (leaf < 0) _exit(38);
        if (leaf) _exit(0);
        if (locked && flock(3, LOCK_EX | LOCK_NB) < 0) _exit(42);
        pid_t self = getpid();
        if (write(STDOUT_FILENO, &self, sizeof(self)) != (ssize_t)sizeof(self)) _exit(39);
        for (;;) pause();
    }
    if (locked) close(3);
    for (;;) pause();
}

static int fixture_cwd(void)
{
    char path[1024];
    if (!getcwd(path, sizeof(path))) return 40;
    size_t length = strlen(path);
    return write(STDOUT_FILENO, path, length) == (ssize_t)length ? 0 : 41;
}

static int fixture_stack(void)
{
    struct rlimit limit;
    if (getrlimit(RLIMIT_STACK, &limit) != 0) return 64;
    return write(1, &limit, sizeof(limit)) == (ssize_t)sizeof(limit) ? 0 : 65;
}

static int fixture_retirement_owner(char **argv);
static int fixture_vectors(int argc, char **argv)
{
    extern char **environ;
    for (int vector = 0; vector < 2; ++vector) {
        char **entries = vector ? environ : argv;
        size_t start = vector ? 0 : 2;
        for (size_t i = start; entries[i]; ++i) {
            size_t n = strlen(entries[i]);
            if (n > UINT8_MAX) return 61;
            uint8_t length = (uint8_t)n;
            if (write(1, &length, 1) != 1 || write(1, entries[i], n) != (ssize_t)n) return 62;
        }
    }
    return argc > 1 ? 0 : 63;
}
static int fixture_retirement_idle(void)
{
    int live = thread_registry_live_count(), owned = thread_registry_unreaped_count();
    if (!zcl_supervised_retirement_begin()) return 50;
    if (thread_registry_live_count() != live + 1 ||
        thread_registry_unreaped_count() != owned + 1) return 51;
    /* No wake notification: the worker must observe the atomic-only setter. */
    thread_registry_request_shutdown();
    if (thread_registry_join_all(5) != 0) return 52;
    if (zcl_supervised_retirement_phase() != ZCL_RETIREMENT_STOPPED ||
        thread_registry_live_count() != live || thread_registry_unreaped_count() != owned) return 53;
    return zcl_supervised_retirement_begin() ? 54 : 0;
}

static int fixture_dispatch_pair(const char *mode)
{
    if (!strcmp(mode, "--supervised-fixture-empty-env")) {
        extern char **environ;
        return !environ || !environ[0] ? 0 : 66;
    }
    if (!strcmp(mode, "--supervised-fixture-tree")) return fixture_tree(false);
    if (!strcmp(mode, "--supervised-fixture-locked-tree")) return fixture_tree(true);
    if (!strcmp(mode, "--supervised-fixture-hold")) for (;;) pause();
    if (!strcmp(mode, "--supervised-fixture-exit-one")) return 1;
    if (!strcmp(mode, "--supervised-fixture-cwd")) return fixture_cwd();
    if (!strcmp(mode, "--supervised-fixture-stack")) return fixture_stack();
    if (!strcmp(mode, "--supervised-fixture-retire-idle")) return fixture_retirement_idle();
    return -1;
}
int supervised_fixture_dispatch(int argc, char **argv);
int supervised_fixture_dispatch(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "--supervised-fixture-marker")) {
        int fd = open(argv[2], O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0) return 70;
        return close(fd) == 0 ? 0 : 71;
    }
    if (argc > 1 && !strcmp(argv[1], "--supervised-fixture-vectors"))
        return fixture_vectors(argc, argv);
    if (argc == 5 && !strcmp(argv[1], "--supervised-fixture-echo")) return fixture_echo(argc, argv);
    if (argc == 2) return fixture_dispatch_pair(argv[1]);
    if (argc == 7 && !strcmp(argv[1], "--supervised-fixture-retire-owner"))
        return fixture_retirement_owner(argv);
    return -1;
}

static int sealed_snapshot(const char *path)
{
    int input = open(path, O_RDONLY | O_CLOEXEC);
    int image = memfd_create("supervised-fixture", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (input < 0 || image < 0) {
        if (input >= 0) close(input);
        if (image >= 0) close(image);
        return -1;
    }
    uint8_t bytes[65536];
    ssize_t n;
    bool ok = true;
    while ((n = read(input, bytes, sizeof(bytes))) > 0) {
        size_t offset = 0;
        while (offset < (size_t)n) {
            ssize_t written = write(image, bytes + offset, (size_t)n - offset);
            if (written <= 0) { ok = false; break; }
            offset += (size_t)written;
        }
        if (!ok) break;
    }
    close(input);
    int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    if (n < 0 || !ok || fcntl(image, F_ADD_SEALS, seals) < 0) {
        close(image); return -1;
    }
    return image;
}

static bool wait_bytes(int fd, void *output, size_t length)
{
    uint8_t *bytes = output;
    size_t offset = 0;
    int64_t deadline = fixture_deadline();
    while (offset < length && clock_now_monotonic_ns() < deadline) {
        struct pollfd entry = {.fd = fd, .events = POLLIN};
        if (poll(&entry, 1, 20) <= 0) continue;
        ssize_t n = read(fd, bytes + offset, length - offset);
        if (n <= 0) return false;
        offset += (size_t)n;
    }
    return offset == length;
}

static bool exact_eof(int fd)
{
    struct pollfd entry = {.fd = fd, .events = POLLIN};
    int64_t deadline = fixture_deadline();
    while (clock_now_monotonic_ns() < deadline) {
        if (poll(&entry, 1, 20) <= 0) continue;
        uint8_t byte;
        return read(fd, &byte, 1) == 0;
    }
    return false;
}

static struct platform_supervised_spec tree_spec(int image, int null_fd, int output,
    struct platform_supervised_fd_map maps[3])
{
    static const char *const argv[] = {"supervised-fixture", "--supervised-fixture-tree", NULL};
    static const char *const env[] = {NULL};
    maps[0] = (struct platform_supervised_fd_map){null_fd, 0};
    maps[1] = (struct platform_supervised_fd_map){output, 1};
    maps[2] = (struct platform_supervised_fd_map){null_fd, 2};
    return (struct platform_supervised_spec){.executable_fd = image, .argv = argv,
        .env = env, .maps = maps, .map_count = 3, .launch_deadline_ns = fixture_deadline(),
        .cleanup_timeout_ms = 1000};
}

/* Failed fixture cleanup retains explicit handle custody for the final retry.
 * These are test-local ownership slots, not a runtime queue or authority. */
static struct platform_supervised_process retained_custody[8];
static size_t retained_count;
/* Token-bearing handles need stable addresses even if fixture cleanup refuses.
 * Allocate these slots before launch and release only after CLEAN or transfer. */
static struct platform_supervised_process retirement_handles[ZCL_SUPERVISED_RETIREMENT_SLOTS + 8];
static bool retirement_handle_used[ZCL_SUPERVISED_RETIREMENT_SLOTS + 8];

static struct platform_supervised_process *fixture_retirement_handle(void)
{
    for (size_t i = 0; i < sizeof(retirement_handles) / sizeof(retirement_handles[0]); ++i) {
        if (retirement_handle_used[i]) continue;
        retirement_handle_used[i] = true;
        platform_supervised_init(&retirement_handles[i]);
        return &retirement_handles[i];
    }
    return NULL;
}

static void fixture_retirement_release(struct platform_supervised_process *process)
{
    if (!process || process->supervisor_pid >= 0 || zcl_supervised_retirement_fixture_token(process)) return;
    for (size_t i = 0; i < sizeof(retirement_handles) / sizeof(retirement_handles[0]); ++i)
        if (process == &retirement_handles[i]) retirement_handle_used[i] = false;
}

static bool fixture_cleanup_until(struct platform_supervised_process *process, int64_t deadline)
{
    if (process->supervisor_pid < 0) return true;
    enum platform_supervised_state state = zcl_supervised_retirement_stop(process, deadline);
    if (state == PLATFORM_SUPERVISED_CLEAN) return true;
    fprintf(stderr, "supervised fixture cleanup incomplete: supervisor=%lld state=%d errno=%d\n",
        (long long)process->supervisor_pid, (int)state, process->observation.error_number);
    if (zcl_supervised_retirement_fixture_token(process)) {
        (void)zcl_supervised_retirement_transfer(process);
        return false; /* Refusal retains the original stable slot; never copy/reset. */
    }
    if (retained_count < sizeof(retained_custody) / sizeof(retained_custody[0])) {
        retained_custody[retained_count++] = *process;
        platform_supervised_init(process);
    }
    return false;
}

static bool fixture_cleanup(struct platform_supervised_process *process)
{
    return fixture_cleanup_until(process, fixture_deadline());
}

static bool tree_cleanup(struct platform_supervised_process *process, int leaf_fd)
{
    if (leaf_fd >= 0) {
        if (!platform_supervised_fixture_pidfd_kill(leaf_fd))
            fprintf(stderr, "supervised fixture: owned descendant emergency kill failed errno=%d\n", errno);
        close(leaf_fd);
    }
    return fixture_cleanup(process);
}

static enum platform_supervised_state await_clean(struct platform_supervised_process *process);

static int supervised_stack_limits(int image)
{
    int failures = 0;
    struct platform_supervised_process process;
    platform_supervised_init(&process);
    int pipes[2] = {-1, -1}, null_fd = -1;
    TEST_CASE("supervised_process: unlimited stack changes only the engine") {
        struct rlimit before, after, child;
        ASSERT_EQ(getrlimit(RLIMIT_STACK, &before), 0);
        ASSERT(pipe2(pipes, O_CLOEXEC) == 0);
        null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        ASSERT(null_fd >= 0);
        struct platform_supervised_fd_map maps[3];
        struct platform_supervised_spec spec = tree_spec(image, null_fd, pipes[1], maps);
        const char *argv[] = {"fixture", "--supervised-fixture-stack", NULL}; spec.argv = argv;
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_RUNNING);
        ASSERT(wait_bytes(pipes[0], &child, sizeof(child)));
        ASSERT_EQ(await_clean(&process), PLATFORM_SUPERVISED_CLEAN);
        ASSERT(child.rlim_cur == before.rlim_cur && child.rlim_max == before.rlim_max);
        spec.stack_policy = PLATFORM_SUPERVISED_STACK_UNLIMITED;
        spec.launch_deadline_ns = fixture_deadline();
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_RUNNING);
        close(pipes[1]); pipes[1] = -1;
        ASSERT(wait_bytes(pipes[0], &child, sizeof(child)));
        ASSERT_EQ(await_clean(&process), PLATFORM_SUPERVISED_CLEAN);
        ASSERT(child.rlim_cur == RLIM_INFINITY && child.rlim_max == RLIM_INFINITY);
        ASSERT_EQ(getrlimit(RLIMIT_STACK, &after), 0);
        ASSERT(before.rlim_cur == after.rlim_cur && before.rlim_max == after.rlim_max);
    } TEST_END
    if (!fixture_cleanup(&process)) failures++;
    if (pipes[0] >= 0) close(pipes[0]);
    if (pipes[1] >= 0) close(pipes[1]);
    if (null_fd >= 0) close(null_fd);
    return failures;
}

static int supervised_complete_e2big(int image)
{
    int failures = 0, null_fd = -1;
    char *large = NULL;
    struct platform_supervised_process process;
    platform_supervised_init(&process);
    TEST_CASE("supervised_process: complete environment E2BIG is a launch failure") {
        long page = sysconf(_SC_PAGESIZE);
        ASSERT(page > 0 && (size_t)page <= SIZE_MAX / 33);
        size_t bytes = (size_t)page * 33;
        large = malloc(bytes);
        ASSERT(large != NULL);
        memset(large, 'x', bytes - 1); large[bytes - 1] = 0;
        large[0] = 'X'; large[1] = '=';
        const char *env[] = {large, NULL};
        null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        ASSERT(null_fd >= 0);
        struct platform_supervised_fd_map maps[3];
        struct platform_supervised_spec spec = tree_spec(image, null_fd, null_fd, maps);
        spec.env = env; spec.env_policy = PLATFORM_SUPERVISED_ENV_COMPLETE; spec.env_count = 1;
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_LAUNCH_FAILED);
        ASSERT_EQ(process.observation.error_number, E2BIG);
        ASSERT_EQ(await_clean(&process), PLATFORM_SUPERVISED_CLEAN);
        ASSERT(process.observation.no_children);
    } TEST_END
    if (!fixture_cleanup(&process)) failures++;
    if (null_fd >= 0) close(null_fd);
    free(large);
    return failures;
}

static int fixture_stack_refusal(int image, const char *marker)
{
    const struct rlimit finite = {1024 * 1024, 1024 * 1024};
    if (setrlimit(RLIMIT_STACK, &finite) != 0) return 67;
    int fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (fd < 0) return 68;
    struct platform_supervised_fd_map maps[3];
    struct platform_supervised_spec spec = tree_spec(image, fd, fd, maps);
    const char *argv[] = {"fixture", "--supervised-fixture-marker", marker, NULL};
    spec.argv = argv;
    spec.stack_policy = PLATFORM_SUPERVISED_STACK_UNLIMITED;
    struct platform_supervised_process process;
    platform_supervised_init(&process);
    enum platform_supervised_state state = platform_supervised_start(&process, &spec);
    bool refused = state == PLATFORM_SUPERVISED_LAUNCH_FAILED &&
        process.observation.error_number == EPERM;
    state = platform_supervised_stop(&process, fixture_deadline());
    close(fd);
    return refused && state == PLATFORM_SUPERVISED_CLEAN && process.observation.no_children ? 0 : 69;
}

static int supervised_stack_refusal(int image, const char *directory)
{
    int failures = 0;
    TEST_CASE("supervised_process: isolated finite hard stack refuses unlimited before exec") {
        struct rlimit before, after;
        char marker[1200];
        ASSERT(snprintf(marker, sizeof(marker), "%s/stack-must-not-exec", directory) > 0);
        ASSERT(access(marker, F_OK) != 0 && errno == ENOENT);
        ASSERT_EQ(getrlimit(RLIMIT_STACK, &before), 0);
        pid_t child = fork();
        ASSERT(child >= 0);
        if (child == 0) _exit(fixture_stack_refusal(image, marker));
        int status = 0;
        pid_t observed = 0;
        int64_t deadline = fixture_deadline();
        while (clock_now_monotonic_ns() < deadline && observed == 0) {
            observed = waitpid(child, &status, WNOHANG);
            if (observed < 0 && errno == EINTR) observed = 0;
            if (observed == 0) (void)poll(NULL, 0, 10);
        }
        if (observed != child) {
            (void)kill(child, SIGKILL);
            (void)waitpid(child, &status, 0);
        }
        ASSERT_EQ(observed, child);
        ASSERT(WIFEXITED(status)); ASSERT_EQ(WEXITSTATUS(status), 0);
        ASSERT(access(marker, F_OK) != 0 && errno == ENOENT);
        ASSERT_EQ(getrlimit(RLIMIT_STACK, &after), 0);
        ASSERT(before.rlim_cur == after.rlim_cur && before.rlim_max == after.rlim_max);
    } TEST_END
    return failures;
}

static int supervised_complete_vectors(int image)
{
    int failures = 0;
    int pipes[2] = {-1, -1}, null_fd = -1;
    struct platform_supervised_process process;
    platform_supervised_init(&process);
    TEST_CASE("supervised_process: complete environment and extended argv preserve exact bytes") {
        ASSERT(pipe2(pipes, O_CLOEXEC) == 0);
        null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        ASSERT(null_fd >= 0);
        const char *argv[PLATFORM_SUPERVISED_ARGV_EXTENDED_MAX + 2];
        const char *env[66];
        char values[65][32];
        uint8_t expected[8192], observed[8192];
        size_t length = 0;
        argv[0] = "fixture"; argv[1] = "--supervised-fixture-vectors";
        static const char *const tokens[] = {"", "a b", "quote\"", "back\\slash", "utf8-\xc3\xa9"};
        for (size_t i = 2; i < PLATFORM_SUPERVISED_ARGV_EXTENDED_MAX; ++i) {
            argv[i] = tokens[i % 5];
            size_t n = strlen(argv[i]); expected[length++] = (uint8_t)n;
            memcpy(expected + length, argv[i], n); length += n;
        }
        argv[PLATFORM_SUPERVISED_ARGV_EXTENDED_MAX] = NULL;
        for (size_t i = 0; i < 65; ++i) {
            (void)snprintf(values[i], sizeof(values[i]), "COMPLETE_%zu=%s", i, tokens[i % 5]);
            env[i] = values[i]; size_t n = strlen(env[i]);
            expected[length++] = (uint8_t)n; memcpy(expected + length, env[i], n); length += n;
        }
        env[65] = NULL;
        struct platform_supervised_fd_map maps[3];
        struct platform_supervised_spec spec = tree_spec(image, null_fd, pipes[1], maps);
        spec.argv = argv; spec.env = env;
        spec.argv_policy = PLATFORM_SUPERVISED_ARGV_EXTENDED;
        spec.env_policy = PLATFORM_SUPERVISED_ENV_COMPLETE; spec.env_count = 65;
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_RUNNING);
        close(pipes[1]); pipes[1] = -1;
        ASSERT(wait_bytes(pipes[0], observed, length));
        ASSERT(memcmp(expected, observed, length) == 0);
        ASSERT_EQ(await_clean(&process), PLATFORM_SUPERVISED_CLEAN);
        ASSERT(process.observation.no_children && process.observation.engine_exit_observed);
        ASSERT_EQ(process.observation.engine_wait_status, 0);
        ASSERT(exact_eof(pipes[0]));
        spec.maps = maps; maps[1].source = null_fd; maps[2].source = null_fd;
        spec.launch_deadline_ns = fixture_deadline();
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_RUNNING);
        ASSERT_EQ(await_clean(&process), PLATFORM_SUPERVISED_CLEAN);
        spec.env_policy = PLATFORM_SUPERVISED_ENV_DEFAULT;
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_INVALID);
        spec.env_policy = PLATFORM_SUPERVISED_ENV_COMPLETE;
        spec.env_count = 64;
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_INVALID);
        spec.env_count = 66;
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_INVALID);
        spec.env_count = SIZE_MAX;
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_INVALID);
        spec.env_count = 65; spec.env_policy = (enum platform_supervised_env_policy)99;
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_INVALID);
        spec.env_policy = PLATFORM_SUPERVISED_ENV_COMPLETE;
        spec.argv_policy = (enum platform_supervised_argv_policy)99;
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_INVALID);
        spec.argv_policy = PLATFORM_SUPERVISED_ARGV_EXTENDED;
        spec.stack_policy = (enum platform_supervised_stack_policy)99;
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_INVALID);
        spec.stack_policy = PLATFORM_SUPERVISED_STACK_INHERIT;
        argv[PLATFORM_SUPERVISED_ARGV_EXTENDED_MAX] = "overflow";
        argv[PLATFORM_SUPERVISED_ARGV_EXTENDED_MAX + 1] = NULL;
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_INVALID);
        ASSERT_EQ(process.supervisor_pid, FIXTURE_NO_PID);
        argv[PLATFORM_SUPERVISED_ARGV_EXTENDED_MAX] = NULL;
        spec.argv_policy = PLATFORM_SUPERVISED_ARGV_DEFAULT;
        const char *at64 = argv[64]; argv[64] = NULL;
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_RUNNING);
        ASSERT_EQ(await_clean(&process), PLATFORM_SUPERVISED_CLEAN);
        argv[64] = at64; const char *at65 = argv[65]; argv[65] = NULL;
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_INVALID);
        ASSERT_EQ(process.supervisor_pid, FIXTURE_NO_PID);
        argv[65] = at65; spec.argv_policy = PLATFORM_SUPERVISED_ARGV_EXTENDED;
        const char *empty[] = {NULL}; spec.env = empty; spec.env_count = 0;
        const char *empty_argv[] = {"fixture", "--supervised-fixture-empty-env", NULL};
        spec.argv = empty_argv;
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_RUNNING);
        ASSERT_EQ(await_clean(&process), PLATFORM_SUPERVISED_CLEAN);
        ASSERT_EQ(process.observation.engine_wait_status, 0);
    } TEST_END
    if (!fixture_cleanup(&process)) failures++;
    if (pipes[0] >= 0) close(pipes[0]);
    if (pipes[1] >= 0) close(pipes[1]);
    if (null_fd >= 0) close(null_fd);
    return failures;
}

static int supervised_tree(int image, bool owner_eof)
{
    int failures = 0;
    int pipes[2] = {-1, -1}, null_fd = -1, leaf_fd = -1;
    struct platform_supervised_process process;
    platform_supervised_init(&process);
    TEST_CASE("supervised_process: setsid double-fork descendant cleanup gives EOF and ECHILD") {
        ASSERT(pipe2(pipes, O_CLOEXEC) == 0);
        null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        ASSERT(null_fd >= 0);
        struct platform_supervised_fd_map maps[3];
        struct platform_supervised_spec spec = tree_spec(image, null_fd, pipes[1], maps);
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_RUNNING);
        close(pipes[1]); pipes[1] = -1;
        pid_t leaf = -1;
        ASSERT(wait_bytes(pipes[0], &leaf, sizeof(leaf)));
        ASSERT(leaf > 1);
        leaf_fd = platform_supervised_fixture_pidfd_open(leaf);
        ASSERT(leaf_fd >= 0);
        if (owner_eof) {
            platform_supervised_owner_eof(&process);
            ASSERT_EQ(await_clean(&process), PLATFORM_SUPERVISED_CLEAN);
        } else ASSERT_EQ(zcl_supervised_retirement_stop(&process, fixture_deadline()), PLATFORM_SUPERVISED_CLEAN);
        ASSERT(process.observation.no_children);
        ASSERT(process.observation.engine_exit_observed);
        ASSERT_EQ(process.supervisor_pid, FIXTURE_NO_PID);
        ASSERT(exact_eof(pipes[0]));
        struct pollfd exited = {.fd = leaf_fd, .events = POLLIN};
        ASSERT(poll(&exited, 1, 0) > 0);
    } TEST_END
    if (!tree_cleanup(&process, leaf_fd)) failures++;
    if (null_fd >= 0) close(null_fd);
    for (size_t i = 0; i < 2; ++i) if (pipes[i] >= 0) close(pipes[i]);
    return failures;
}

static enum platform_supervised_state await_clean(struct platform_supervised_process *process)
{
    int64_t deadline = fixture_deadline();
    while (clock_now_monotonic_ns() < deadline) {
        enum platform_supervised_state state = zcl_supervised_retirement_poll(process);
        if (process->supervisor_pid < 0) return state;
        struct pollfd delay = {.fd = -1};
        (void)poll(&delay, 0, 20);
    }
    return PLATFORM_SUPERVISED_INCOMPLETE;
}

static bool send_step(int fd, const uint8_t *input, size_t length,
    size_t *sent, bool *ended)
{
    if (*sent < length) {
        ssize_t n = send(fd, input + *sent, length - *sent, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n > 0) *sent += (size_t)n;
        else if (n < 0 && errno != EAGAIN && errno != EINTR) return false;
    }
    if (*sent == length && !*ended) {
        if (shutdown(fd, SHUT_WR) < 0) return false;
        *ended = true;
    }
    return true;
}

static bool receive_step(int fd, uint8_t *output, size_t length, size_t *received)
{
    ssize_t n = recv(fd, output + *received, length - *received, MSG_DONTWAIT);
    if (n > 0) *received += (size_t)n;
    else if (n == 0) return false;
    else if (errno != EAGAIN && errno != EINTR) return false;
    return true;
}

static bool binary_roundtrip(int fd)
{
    uint8_t input[65536], output[65536];
    for (size_t i = 0; i < sizeof(input); ++i) input[i] = (uint8_t)i;
    size_t sent = 0, received = 0;
    bool ended = false;
    int64_t deadline = fixture_deadline();
    while (received < sizeof(output) && clock_now_monotonic_ns() < deadline) {
        if (!send_step(fd, input, sizeof(input), &sent, &ended) ||
            !receive_step(fd, output, sizeof(output), &received)) return false;
        struct pollfd ready = {.fd = fd, .events = POLLIN | POLLOUT};
        (void)poll(&ready, 1, 20);
    }
    return sent == sizeof(input) && received == sizeof(output) && !memcmp(input, output, sizeof(input));
}

static int supervised_mapping(int image)
{
    int failures = 0;
    int sockets[2] = {-1, -1}, read_fd = -1, write_fd = -1, ambient = -1;
    const char *prior = getenv("SUPERVISED_AMBIENT");
    char *saved = prior ? strdup(prior) : NULL;
    bool changed_env = false;
    struct platform_supervised_process process;
    platform_supervised_init(&process);
    TEST_CASE("supervised_process: collision-safe mapping, exact binary stdio, no ambient FD or environment") {
        ASSERT(!prior || saved);
        ASSERT(setenv("SUPERVISED_AMBIENT", "must-not-leak", 1) == 0);
        changed_env = true;
        ASSERT(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
        int original = open("/dev/null", O_RDONLY | O_CLOEXEC);
        ASSERT(original >= 0);
        read_fd = fcntl(original, F_DUPFD_CLOEXEC, 32);
        close(original);
        original = open("/dev/null", O_WRONLY | O_CLOEXEC);
        ASSERT(original >= 0);
        write_fd = fcntl(original, F_DUPFD_CLOEXEC, 32);
        ambient = fcntl(original, F_DUPFD, 90);
        close(original);
        ASSERT(read_fd >= 32 && read_fd <= 63);
        ASSERT(write_fd >= 32 && write_fd <= 63);
        ASSERT(ambient >= 90);
        char ambient_text[24], writer_text[24], reader_text[24];
        ASSERT(snprintf(ambient_text, sizeof(ambient_text), "%d", ambient) > 0);
        ASSERT(snprintf(writer_text, sizeof(writer_text), "%d", read_fd) > 0);
        ASSERT(snprintf(reader_text, sizeof(reader_text), "%d", write_fd) > 0);
        const char *const argv[] = {"supervised-fixture", "--supervised-fixture-echo",
            ambient_text, writer_text, reader_text, NULL};
        const char *const env[] = {"SUPERVISED_ALLOWED=ok", NULL};
        struct platform_supervised_fd_map maps[] = {
            {sockets[1], 0}, {sockets[1], 1}, {write_fd, 2},
            {write_fd, read_fd}, {read_fd, write_fd}};
        struct platform_supervised_spec spec = {.executable_fd = image, .argv = argv,
            .env = env, .maps = maps, .map_count = 5,
            .launch_deadline_ns = fixture_deadline(), .cleanup_timeout_ms = 1000};
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_RUNNING);
        close(sockets[1]); sockets[1] = -1;
        ASSERT(binary_roundtrip(sockets[0]));
        ASSERT_EQ(await_clean(&process), PLATFORM_SUPERVISED_CLEAN);
        ASSERT(process.observation.no_children);
        ASSERT(process.observation.engine_exit_observed);
        ASSERT(WIFEXITED(process.observation.engine_wait_status));
        ASSERT_EQ(WEXITSTATUS(process.observation.engine_wait_status), 0);
        ASSERT(exact_eof(sockets[0]));
        ASSERT_EQ(zcl_supervised_retirement_stop(&process, fixture_deadline()), PLATFORM_SUPERVISED_CLEAN);
    } TEST_END
    if (!fixture_cleanup(&process)) failures++;
    for (size_t i = 0; i < 2; ++i) if (sockets[i] >= 0) close(sockets[i]);
    if (read_fd >= 0) close(read_fd);
    if (write_fd >= 0) close(write_fd);
    if (ambient >= 0) close(ambient);
    if (changed_env) {
        if (saved) (void)setenv("SUPERVISED_AMBIENT", saved, 1);
        else (void)unsetenv("SUPERVISED_AMBIENT");
    }
    free(saved);
    return failures;
}

static int supervised_failures(int image)
{
    int failures = 0;
    int null_fd = -1, invalid = -1;
    struct platform_supervised_process process;
    platform_supervised_init(&process);
    TEST_CASE("supervised_process: invalid sealing, actual exec failure, and exhausted cleanup deadline retain truth") {
        null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        ASSERT(null_fd >= 0);
        struct platform_supervised_fd_map maps[3];
        struct platform_supervised_spec spec = tree_spec(image, null_fd, null_fd, maps);
        spec.executable_fd = null_fd;
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_INVALID);
        ASSERT_EQ(process.supervisor_pid, FIXTURE_NO_PID);
        invalid = memfd_create("invalid-elf", MFD_CLOEXEC | MFD_ALLOW_SEALING);
        ASSERT(invalid >= 0);
        ASSERT_EQ(write(invalid, "\177ELF", 4), 4);
        ASSERT(fcntl(invalid, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) == 0);
        spec.executable_fd = invalid;
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_LAUNCH_FAILED);
        ASSERT(process.observation.error_number != 0);
        ASSERT_EQ(await_clean(&process), PLATFORM_SUPERVISED_CLEAN);
        spec.executable_fd = image;
        static const char *const hold[] = {"supervised-fixture", "--supervised-fixture-hold", NULL};
        spec.argv = hold;
        spec.launch_deadline_ns = fixture_deadline();
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_RUNNING);
        ASSERT_EQ(zcl_supervised_retirement_stop(&process, 0), PLATFORM_SUPERVISED_INCOMPLETE);
        ASSERT(process.supervisor_pid > 0);
        ASSERT_EQ(zcl_supervised_retirement_stop(&process, fixture_deadline()), PLATFORM_SUPERVISED_CLEAN);
        ASSERT(process.observation.no_children);
    } TEST_END
    if (!fixture_cleanup(&process)) failures++;
    if (invalid >= 0) close(invalid);
    if (null_fd >= 0) close(null_fd);
    return failures;
}

static int supervised_fast_exit(int image)
{
    int failures = 0;
    int null_fd = -1;
    struct platform_supervised_process process;
    platform_supervised_init(&process);
    TEST_CASE("supervised_process: successful exec exit one is observed separately from launch") {
        null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        ASSERT(null_fd >= 0);
        struct platform_supervised_fd_map maps[3];
        struct platform_supervised_spec spec = tree_spec(image, null_fd, null_fd, maps);
        static const char *const argv[] = {"supervised-fixture", "--supervised-fixture-exit-one", NULL};
        spec.argv = argv;
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_RUNNING);
        ASSERT_EQ(await_clean(&process), PLATFORM_SUPERVISED_CLEAN);
        ASSERT(process.observation.engine_exit_observed);
        ASSERT(WIFEXITED(process.observation.engine_wait_status));
        ASSERT_EQ(WEXITSTATUS(process.observation.engine_wait_status), 1);
        ASSERT(process.observation.no_children);
        ASSERT_EQ(zcl_supervised_retirement_poll(&process), PLATFORM_SUPERVISED_CLEAN);
    } TEST_END
    if (!fixture_cleanup(&process)) failures++;
    if (null_fd >= 0) close(null_fd);
    return failures;
}

static int supervised_wait_custody(int image)
{
    int failures = 0;
    int null_fd = -1;
    struct platform_supervised_process process;
    platform_supervised_init(&process);
    TEST_CASE("supervised_process: automatic supervisor reaping refuses before fork") {
        null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        ASSERT(null_fd >= 0);
        struct platform_supervised_fd_map maps[3];
        struct platform_supervised_spec spec = tree_spec(image, null_fd, null_fd, maps);
        static const char *const argv[] = {"supervised-fixture", "--supervised-fixture-hold", NULL};
        spec.argv = argv;
        struct sigaction prior;
        ASSERT(sigaction(SIGCHLD, NULL, &prior) == 0);
        for (unsigned policy = 0; policy < 2; ++policy) {
            struct sigaction changed = {.sa_handler = policy ? SIG_DFL : SIG_IGN};
            sigemptyset(&changed.sa_mask);
            if (policy) changed.sa_flags = SA_NOCLDWAIT;
            int installed = sigaction(SIGCHLD, &changed, NULL);
            enum platform_supervised_state state = installed == 0 ?
                platform_supervised_start(&process, &spec) : PLATFORM_SUPERVISED_OBSERVATION_FAILED;
            /* Restore BEFORE every assertion/TEST_CASE longjmp exit. */
            int restored = sigaction(SIGCHLD, &prior, NULL);
            ASSERT_EQ(restored, 0);
            ASSERT_EQ(installed, 0);
            ASSERT_EQ(state, PLATFORM_SUPERVISED_INVALID);
            ASSERT_EQ(process.supervisor_pid, FIXTURE_NO_PID);
            ASSERT_EQ(process.control_fd, FIXTURE_NO_FD);
        }
    } TEST_END
    if (!fixture_cleanup(&process)) failures++;
    if (null_fd >= 0) close(null_fd);
    return failures;
}

static int retry_retained_custody(void)
{
    int failures = 0;
    for (size_t i = 0; i < retained_count; ++i) {
        struct platform_supervised_process *process = &retained_custody[i];
        enum platform_supervised_state state = zcl_supervised_retirement_stop(process, fixture_deadline());
        if (state != PLATFORM_SUPERVISED_CLEAN) {
            fprintf(stderr, "supervised fixture retains incomplete custody: supervisor=%lld fd=%d state=%d\n",
                (long long)process->supervisor_pid, process->control_fd, (int)state);
            platform_supervised_owner_eof(process);
            failures++;
        }
    }
    return failures;
}


static void image_fixture(uint8_t bytes[1024], bool dynamic)
{
    memset(bytes, 0, 1024);
    Elf64_Ehdr h = {.e_type = ET_EXEC, .e_version = EV_CURRENT, .e_entry = 0x400300,
        .e_phoff = sizeof(h), .e_ehsize = sizeof(h), .e_phentsize = sizeof(Elf64_Phdr),
        .e_phnum = dynamic ? 3 : 1};
    memcpy(h.e_ident, ELFMAG, SELFMAG); h.e_ident[EI_CLASS] = ELFCLASS64;
    h.e_ident[EI_DATA] = ELFDATA2LSB; h.e_ident[EI_VERSION] = EV_CURRENT;
#if defined(__x86_64__)
    h.e_machine = EM_X86_64;
    const char *loader = "/lib64/ld-linux-x86-64.so.2";
#else
    h.e_machine = EM_AARCH64;
    const char *loader = "/lib/ld-linux-aarch64.so.1";
#endif
    Elf64_Phdr ph[3] = {{.p_type = PT_LOAD, .p_flags = PF_R | PF_X,
        .p_filesz = 1024, .p_memsz = 1024, .p_vaddr = 0x400000, .p_align = 4096}};
    ph[1] = (Elf64_Phdr){.p_type = PT_DYNAMIC, .p_offset = 256, .p_vaddr = 0x400100,
        .p_filesz = 5 * sizeof(Elf64_Dyn), .p_memsz = 5 * sizeof(Elf64_Dyn)};
    ph[2] = (Elf64_Phdr){.p_type = PT_INTERP, .p_offset = 512, .p_filesz = strlen(loader) + 1};
    Elf64_Dyn entries[5] = {{.d_tag = DT_STRTAB, .d_un.d_ptr = 0x400190},
        {.d_tag = DT_STRSZ, .d_un.d_val = 10}, {.d_tag = DT_NEEDED, .d_un.d_val = 0},
        {.d_tag = DT_NULL}, {.d_tag = DT_NULL}};
    memcpy(bytes, &h, sizeof(h)); memcpy(bytes + sizeof(h), ph, h.e_phnum * sizeof(ph[0]));
    memcpy(bytes + 256, entries, sizeof(entries)); memcpy(bytes + 400, "libc.so.6", 10);
    memcpy(bytes + 512, loader, strlen(loader) + 1);
}

static void image_fixture_hash(const uint8_t *bytes, size_t length, uint8_t digest[32])
{
    struct sha3_256_ctx hash; sha3_256_init(&hash);
    sha3_256_write(&hash, bytes, length); sha3_256_finalize(&hash, digest);
}

static bool image_fixture_refused(const uint8_t bytes[1024])
{
    uint8_t digest[32]; image_fixture_hash(bytes, 1024, digest);
    int fd = -1;
    enum platform_supervised_image_result result = platform_supervised_image_capture(bytes, 1024, digest, &fd);
    if (fd >= 0) close(fd);
    return result == PLATFORM_SUPERVISED_IMAGE_REFUSED && fd == -1;
}

static int supervised_image_capture(void)
{
    int failures = 0, fd = -1; uint8_t bytes[1024], digest[32], copied[1024];
    TEST_CASE("supervised_process: native image capture policy and immutable digest") {
        image_fixture(bytes, false); image_fixture_hash(bytes, sizeof(bytes), digest);
        ASSERT_EQ(platform_supervised_image_capture(bytes, sizeof(bytes), digest, &fd), PLATFORM_SUPERVISED_IMAGE_OK);
        ASSERT_EQ(pread(fd, copied, sizeof(copied), 0), sizeof(copied));
        ASSERT(!memcmp(bytes, copied, sizeof(bytes)));
        ASSERT_EQ(pwrite(fd, "x", 1, 0), -1); ASSERT_EQ(errno, EPERM);
        close(fd); fd = -1;
        image_fixture(bytes, true); image_fixture_hash(bytes, sizeof(bytes), digest);
        ASSERT_EQ(platform_supervised_image_capture(bytes, sizeof(bytes), digest, &fd), PLATFORM_SUPERVISED_IMAGE_OK);
        close(fd); fd = -1;
        digest[0] ^= 1;
        ASSERT(platform_supervised_image_capture(bytes, sizeof(bytes), digest, &fd) != PLATFORM_SUPERVISED_IMAGE_OK);
        ASSERT_EQ(fd, FIXTURE_NO_FD);
        ASSERT_EQ(platform_supervised_image_capture(bytes, PLATFORM_SUPERVISED_IMAGE_MAX + 1u, digest, &fd), PLATFORM_SUPERVISED_IMAGE_REFUSED);
    } TEST_END
    if (fd >= 0) close(fd);
    return failures;
}

static int supervised_image_refusals(void)
{
    int failures = 0; uint8_t bytes[1024];
    const int64_t forbidden[] = {DT_RPATH, DT_RUNPATH, DT_AUDIT, DT_DEPAUDIT, DT_FILTER, DT_AUXILIARY, DT_TEXTREL};
    TEST_CASE("supervised_process: loader authority and malformed ELF refuse") {
        for (size_t i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); ++i) {
            image_fixture(bytes, true); Elf64_Dyn entry = {.d_tag = forbidden[i]};
            memcpy(bytes + 256 + 3 * sizeof(entry), &entry, sizeof(entry));
            ASSERT(image_fixture_refused(bytes));
        }
        image_fixture(bytes, true); memcpy(bytes + 400, "/BAD/x.so", 10);
        ASSERT(image_fixture_refused(bytes));
        image_fixture(bytes, true); bytes[513] = 'x'; ASSERT(image_fixture_refused(bytes));
        image_fixture(bytes, false); bytes[EI_CLASS] = ELFCLASS32; ASSERT(image_fixture_refused(bytes));
        image_fixture(bytes, false); bytes[EI_DATA] = ELFDATA2MSB; ASSERT(image_fixture_refused(bytes));
        image_fixture(bytes, false); Elf64_Phdr ph;
        memcpy(&ph, bytes + sizeof(Elf64_Ehdr), sizeof(ph)); ph.p_flags |= PF_W;
        memcpy(bytes + sizeof(Elf64_Ehdr), &ph, sizeof(ph)); ASSERT(image_fixture_refused(bytes));
        image_fixture(bytes, true); memcpy(&ph, bytes + sizeof(Elf64_Ehdr) + sizeof(ph), sizeof(ph));
        ph.p_vaddr++; memcpy(bytes + sizeof(Elf64_Ehdr) + sizeof(ph), &ph, sizeof(ph));
        ASSERT(image_fixture_refused(bytes));
    } TEST_END
    return failures;
}

static int supervised_image_geometry(void)
{
    int failures = 0; uint8_t bytes[1024];
    TEST_CASE("supervised_process: native machine, bounds and page permissions") {
        image_fixture(bytes, false); Elf64_Ehdr h;
        memcpy(&h, bytes, sizeof(h)); h.e_machine = EM_NONE;
        memcpy(bytes, &h, sizeof(h)); ASSERT(image_fixture_refused(bytes));
        image_fixture(bytes, false); memcpy(&h, bytes, sizeof(h)); h.e_phoff = UINT64_MAX;
        memcpy(bytes, &h, sizeof(h)); ASSERT(image_fixture_refused(bytes));
        image_fixture(bytes, false); memcpy(&h, bytes, sizeof(h));
        h.e_phnum = 2; h.e_entry = 0x400100; memcpy(bytes, &h, sizeof(h));
        Elf64_Phdr ph[2]; memcpy(&ph[0], bytes + sizeof(h), sizeof(ph[0]));
        ph[0].p_filesz = 768; ph[0].p_memsz = 768;
        ph[1] = (Elf64_Phdr){.p_type = PT_LOAD, .p_flags = PF_R | PF_W,
            .p_offset = 768, .p_vaddr = 0x400300, .p_filesz = 128, .p_memsz = 128, .p_align = 1};
        memcpy(bytes + sizeof(h), ph, sizeof(ph));
        ASSERT(image_fixture_refused(bytes)); /* Byte-disjoint RX/RW still share a native page. */
    } TEST_END
    return failures;
}

static int supervised_cwd(int image, const char *directory)
{
    int failures = 0, cwd = -1, null_fd = -1, sockets[2] = {-1, -1};
    struct platform_supervised_process process; platform_supervised_init(&process);
    TEST_CASE("supervised_process: trusted CWD descriptor and default parent custody") {
        cwd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        ASSERT(cwd >= 0); ASSERT(null_fd >= 0);
        ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets), 0);
        struct platform_supervised_fd_map maps[3];
        struct platform_supervised_spec spec = tree_spec(image, null_fd, sockets[1], maps);
        const char *const argv[] = {"supervised-fixture", "--supervised-fixture-cwd", NULL};
        spec.argv = argv; spec.use_cwd_fd = true; spec.cwd_fd = null_fd;
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_INVALID);
        ASSERT_EQ(process.supervisor_pid, FIXTURE_NO_PID);
        spec.cwd_fd = cwd;
        ASSERT_EQ(platform_supervised_start(&process, &spec), PLATFORM_SUPERVISED_RUNNING);
        close(sockets[1]); sockets[1] = -1;
        ASSERT_EQ(await_clean(&process), PLATFORM_SUPERVISED_CLEAN);
        char observed[1024] = {0};
        ASSERT_EQ(read(sockets[0], observed, sizeof(observed) - 1), (ssize_t)strlen(directory));
        ASSERT(!strcmp(observed, directory));
        ASSERT(exact_eof(sockets[0]));
    } TEST_END
    if (!fixture_cleanup(&process)) failures++;
    if (cwd >= 0) close(cwd);
    if (null_fd >= 0) close(null_fd);
    for (size_t i = 0; i < 2; ++i) if (sockets[i] >= 0) close(sockets[i]);
    return failures;
}

static bool retirement_settled(void)
{
    int64_t deadline = fixture_deadline();
    while (zcl_supervised_retirement_fixture_pending() && clock_now_monotonic_ns() < deadline) {
        struct pollfd delay = {.fd = -1};
        (void)poll(&delay, 0, 20);
    }
    return zcl_supervised_retirement_fixture_pending() == 0;
}

static int supervised_retirement(int image, const char *directory, unsigned scenario)
{
    int failures = 0, null_fd = -1, lock_fd = -1, probe = -1, leaf_fd = -1;
    int pipes[2] = {-1, -1};
    struct platform_supervised_process *process = fixture_retirement_handle(), empty;
    platform_supervised_init(&empty);
    static const char *const labels[] = {
        "supervised_process: pending retirement owns cleanup and reaps supervisor",
        "supervised_process: live observation error transfers the same custody",
        "supervised_process: interrupted wake refuses without losing caller ownership"};
    char path[1200];
    TEST_CASE(labels[scenario]) {
        ASSERT(process != NULL);
        ASSERT(snprintf(path, sizeof(path), "%s/retirement-lock-%u", directory, scenario) > 0);
        lock_fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        probe = open(path, O_RDWR | O_CLOEXEC);
        null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        ASSERT(lock_fd >= 0 && probe >= 0 && null_fd >= 0);
        ASSERT(pipe2(pipes, O_CLOEXEC) == 0);
        struct platform_supervised_fd_map maps[4];
        struct platform_supervised_spec spec = tree_spec(image, null_fd, pipes[1], maps);
        static const char *const argv[] = {"supervised-fixture", "--supervised-fixture-locked-tree", NULL};
        spec.argv = argv;
        maps[3] = (struct platform_supervised_fd_map){lock_fd, 3}; spec.map_count = 4;
        unsigned reaps = zcl_supervised_retirement_fixture_reaps();
        struct sigaction before, after;
        ASSERT(sigaction(SIGCHLD, NULL, &before) == 0);
        ASSERT_EQ(zcl_supervised_retirement_start(process, &spec), PLATFORM_SUPERVISED_RUNNING);
        close(lock_fd); lock_fd = -1;
        close(pipes[1]); pipes[1] = -1;
        pid_t leaf = FIXTURE_NO_PID;
        ASSERT(wait_bytes(pipes[0], &leaf, sizeof(leaf)));
        leaf_fd = platform_supervised_fixture_pidfd_open(leaf);
        ASSERT(leaf_fd >= 0);
        ASSERT_EQ(flock(probe, LOCK_EX | LOCK_NB), FIXTURE_ERROR);
        ASSERT_EQ(errno, EWOULDBLOCK);
        int64_t supervisor = process->supervisor_pid;
        if (scenario == 1) {
            platform_supervised_fixture_observation_error_once();
            ASSERT_EQ(zcl_supervised_retirement_poll(process), PLATFORM_SUPERVISED_OBSERVATION_FAILED);
        } else if (scenario == 0)
            ASSERT_EQ(zcl_supervised_retirement_stop(process, 0), PLATFORM_SUPERVISED_INCOMPLETE);
        ASSERT_EQ(process->supervisor_pid, supervisor);
        if (scenario == 2) {
            int control = process->control_fd;
            uint64_t token = zcl_supervised_retirement_fixture_token(process);
            size_t old_retained = retained_count;
            struct platform_supervised_process *original = process;
            zcl_supervised_retirement_fixture_wake_error_once();
            ASSERT(!fixture_cleanup_until(process, 0));
            ASSERT(process == original);
            ASSERT_EQ(process->supervisor_pid, supervisor);
            ASSERT_EQ(process->control_fd, control);
            ASSERT_EQ(zcl_supervised_retirement_fixture_token(process), token);
            ASSERT_EQ(retained_count, old_retained);
            ASSERT_EQ(zcl_supervised_retirement_fixture_pending(), 1);
        }
        ASSERT_EQ(zcl_supervised_retirement_transfer(process), ZCL_RETIREMENT_TRANSFERRED);
        ASSERT_EQ(process->supervisor_pid, empty.supervisor_pid);
        ASSERT_EQ(process->control_fd, empty.control_fd);
        ASSERT_EQ(zcl_supervised_retirement_fixture_token(process), zcl_supervised_retirement_fixture_token(&empty));
        ASSERT(process->observation.state != PLATFORM_SUPERVISED_CLEAN);
        ASSERT_EQ(zcl_supervised_retirement_transfer(process), ZCL_RETIREMENT_REFUSED);
        ASSERT(retirement_settled());
        ASSERT_EQ(zcl_supervised_retirement_fixture_reaps(), reaps + 1);
        ASSERT_EQ(waitpid((pid_t)supervisor, NULL, WNOHANG), FIXTURE_ERROR);
        ASSERT_EQ(errno, ECHILD);
        struct pollfd ended = {.fd = leaf_fd, .events = POLLIN};
        ASSERT(poll(&ended, 1, 0) > 0);
        ASSERT_EQ(flock(probe, LOCK_EX | LOCK_NB), 0);
        ASSERT(exact_eof(pipes[0]));
        ASSERT(sigaction(SIGCHLD, NULL, &after) == 0);
        ASSERT(before.sa_handler == after.sa_handler);
        ASSERT_EQ(before.sa_flags, after.sa_flags);
    } TEST_END
    if (process && !tree_cleanup(process, leaf_fd)) failures++;
    fixture_retirement_release(process);
    if (lock_fd >= 0) close(lock_fd);
    if (probe >= 0) close(probe);
    if (null_fd >= 0) close(null_fd);
    for (size_t i = 0; i < 2; ++i) if (pipes[i] >= 0) close(pipes[i]);
    return failures;
}

static int supervised_retirement_refusal(int image)
{
    int failures = 0, null_fd = -1;
    struct platform_supervised_process *process = fixture_retirement_handle();
    TEST_CASE("supervised_process: reservation refusal and old handles never transfer") {
        ASSERT(process != NULL);
        null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        ASSERT(null_fd >= 0);
        struct platform_supervised_fd_map maps[3];
        struct platform_supervised_spec spec = tree_spec(image, null_fd, null_fd, maps);
        static const char *const argv[] = {"supervised-fixture", "--supervised-fixture-hold", NULL};
        spec.argv = argv;
        zcl_supervised_retirement_fixture_refuse(true);
        enum platform_supervised_state refused = zcl_supervised_retirement_start(process, &spec);
        zcl_supervised_retirement_fixture_refuse(false);
        ASSERT_EQ(refused, PLATFORM_SUPERVISED_LAUNCH_FAILED);
        ASSERT_EQ(process->supervisor_pid, FIXTURE_NO_PID);
        ASSERT_EQ(process->control_fd, FIXTURE_NO_FD);
        ASSERT_EQ(zcl_supervised_retirement_fixture_token(process), 0);
        ASSERT_EQ(zcl_supervised_retirement_fixture_pending(), 0);
        ASSERT_EQ(platform_supervised_start(process, &spec), PLATFORM_SUPERVISED_RUNNING);
        int64_t supervisor = process->supervisor_pid;
        int control = process->control_fd;
        ASSERT_EQ(zcl_supervised_retirement_transfer(process), ZCL_RETIREMENT_REFUSED);
        ASSERT_EQ(process->supervisor_pid, supervisor);
        ASSERT_EQ(process->control_fd, control);
        ASSERT_EQ(zcl_supervised_retirement_stop(process, fixture_deadline()), PLATFORM_SUPERVISED_CLEAN);
        spec.executable_fd = null_fd;
        ASSERT_EQ(zcl_supervised_retirement_start(process, &spec), PLATFORM_SUPERVISED_INVALID);
        ASSERT_EQ(zcl_supervised_retirement_fixture_pending(), 0);
        ASSERT_EQ(zcl_supervised_retirement_fixture_token(process), 0);
    } TEST_END
    zcl_supervised_retirement_fixture_refuse(false);
    if (process && !fixture_cleanup(process)) failures++;
    fixture_retirement_release(process);
    if (null_fd >= 0) close(null_fd);
    return failures;
}

static int supervised_retirement_fork(int image)
{
    int failures = 0, null_fd = -1;
    struct platform_supervised_process *process = fixture_retirement_handle();
    TEST_CASE("supervised_process: fork child refuses inherited cleanup ownership before locks") {
        ASSERT(process != NULL);
        null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        ASSERT(null_fd >= 0);
        struct platform_supervised_fd_map maps[3];
        struct platform_supervised_spec spec = tree_spec(image, null_fd, null_fd, maps);
        static const char *const argv[] = {"supervised-fixture", "--supervised-fixture-hold", NULL};
        spec.argv = argv;
        ASSERT_EQ(zcl_supervised_retirement_start(process, &spec), PLATFORM_SUPERVISED_RUNNING);
        uint64_t token = zcl_supervised_retirement_fixture_token(process);
        pid_t child = fork();
        ASSERT(child >= 0);
        if (!child) {
            struct platform_supervised_process fresh;
            platform_supervised_init(&fresh);
            bool refused = zcl_supervised_retirement_start(&fresh, &spec) == PLATFORM_SUPERVISED_UNSUPPORTED;
            refused = refused && zcl_supervised_retirement_transfer(process) == ZCL_RETIREMENT_REFUSED;
            _exit(refused ? 0 : 1);
        }
        int status = 0;
        ASSERT_EQ(waitpid(child, &status, 0), child);
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        ASSERT_EQ(zcl_supervised_retirement_fixture_token(process), token);
        ASSERT_EQ(zcl_supervised_retirement_fixture_pending(), 1);
        ASSERT_EQ(zcl_supervised_retirement_stop(process, fixture_deadline()), PLATFORM_SUPERVISED_CLEAN);
        ASSERT_EQ(zcl_supervised_retirement_fixture_pending(), 0);
    } TEST_END
    if (process && !fixture_cleanup(process)) failures++;
    fixture_retirement_release(process);
    if (null_fd >= 0) close(null_fd);
    return failures;
}

static int supervised_retirement_capacity(int image)
{
    int failures = 0, null_fd = -1;
    struct platform_supervised_process *handles[ZCL_SUPERVISED_RETIREMENT_SLOTS + 1];
    for (size_t i = 0; i < sizeof(handles) / sizeof(handles[0]); ++i)
        handles[i] = fixture_retirement_handle();
    TEST_CASE("supervised_process: all fixed reservations saturate before fork and are reusable") {
        for (size_t i = 0; i < sizeof(handles) / sizeof(handles[0]); ++i) ASSERT(handles[i] != NULL);
        null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        ASSERT(null_fd >= 0);
        struct platform_supervised_fd_map maps[3];
        static const char *const argv[] = {"supervised-fixture", "--supervised-fixture-hold", NULL};
        for (size_t i = 0; i < ZCL_SUPERVISED_RETIREMENT_SLOTS; ++i) {
            struct platform_supervised_spec spec = tree_spec(image, null_fd, null_fd, maps);
            spec.argv = argv;
            ASSERT_EQ(zcl_supervised_retirement_start(handles[i], &spec), PLATFORM_SUPERVISED_RUNNING);
        }
        ASSERT_EQ(zcl_supervised_retirement_fixture_pending(), ZCL_SUPERVISED_RETIREMENT_SLOTS);
        struct platform_supervised_process *overflow = handles[ZCL_SUPERVISED_RETIREMENT_SLOTS];
        struct platform_supervised_spec spec = tree_spec(image, null_fd, null_fd, maps);
        spec.argv = argv;
        ASSERT_EQ(zcl_supervised_retirement_start(overflow, &spec), PLATFORM_SUPERVISED_LAUNCH_FAILED);
        ASSERT_EQ(overflow->supervisor_pid, FIXTURE_NO_PID);
        ASSERT_EQ(overflow->control_fd, FIXTURE_NO_FD);
        ASSERT_EQ(zcl_supervised_retirement_fixture_token(overflow), 0);
        for (size_t i = 0; i < ZCL_SUPERVISED_RETIREMENT_SLOTS; ++i)
            ASSERT_EQ(zcl_supervised_retirement_stop(handles[i], fixture_deadline()), PLATFORM_SUPERVISED_CLEAN);
        ASSERT_EQ(zcl_supervised_retirement_fixture_pending(), 0);
        spec.launch_deadline_ns = fixture_deadline();
        ASSERT_EQ(zcl_supervised_retirement_start(overflow, &spec), PLATFORM_SUPERVISED_RUNNING);
        ASSERT_EQ(zcl_supervised_retirement_transfer(overflow), ZCL_RETIREMENT_TRANSFERRED);
        ASSERT(retirement_settled());
    } TEST_END
    for (size_t i = 0; i < sizeof(handles) / sizeof(handles[0]); ++i) {
        if (handles[i] && !fixture_cleanup(handles[i])) failures++;
        fixture_retirement_release(handles[i]);
    }
    if (null_fd >= 0) close(null_fd);
    return failures;
}

struct retirement_exit_ack {
    int64_t supervisor, empty_supervisor;
    uint64_t token;
    unsigned transferred, state, pending;
};

/* Fresh exec is required: the outer fixture deliberately inherited a parent
 * whose retirement thread exists, and that fork branch must keep refusing. */
static int fixture_retirement_owner(char **argv)
{
    if (!zcl_supervised_retirement_begin()) return 49;
    int image = atoi(argv[2]), gate = atoi(argv[3]);
    int output = atoi(argv[4]), ack = atoi(argv[5]);
    int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    int lock_fd = open(argv[6], O_RDWR | O_CLOEXEC);
    if (null_fd < 0 || lock_fd < 0) return 43;
    struct platform_supervised_process *process = fixture_retirement_handle();
    if (!process) return 48;
    struct platform_supervised_fd_map maps[4];
    struct platform_supervised_spec spec = tree_spec(image, null_fd, output, maps);
    static const char *const child_argv[] = {"supervised-fixture", "--supervised-fixture-locked-tree", NULL};
    spec.argv = child_argv;
    maps[3] = (struct platform_supervised_fd_map){lock_fd, 3}; spec.map_count = 4;
    platform_supervised_fixture_cleanup_gate(gate);
    enum platform_supervised_state started = zcl_supervised_retirement_start(process, &spec);
    platform_supervised_fixture_cleanup_gate(FIXTURE_NO_FD);
    close(gate); close(lock_fd); close(null_fd); close(output);
    int64_t supervisor = process->supervisor_pid;
    enum zcl_supervised_retirement_result transferred = zcl_supervised_retirement_transfer(process);
    struct retirement_exit_ack reply = {.supervisor = supervisor,
        .empty_supervisor = process->supervisor_pid, .token = zcl_supervised_retirement_fixture_token(process),
        .transferred = (unsigned)transferred, .state = (unsigned)process->observation.state,
        .pending = zcl_supervised_retirement_fixture_pending()};
    ssize_t written = write(ack, &reply, sizeof(reply));
    close(ack);
    if (started != PLATFORM_SUPERVISED_RUNNING || transferred != ZCL_RETIREMENT_TRANSFERRED) {
        (void)fixture_cleanup(process);
        return 44;
    }
    return written == (ssize_t)sizeof(reply) ? 0 : 45;
}

static bool retirement_wait_child(pid_t child, int *status)
{
    int64_t deadline = fixture_deadline();
    while (clock_now_monotonic_ns() < deadline) {
        pid_t got = waitpid(child, status, WNOHANG);
        if (got == child) return true;
        if (got < 0 && errno != EINTR) return false;
        struct pollfd delay = {.fd = -1};
        (void)poll(&delay, 0, 20);
    }
    return false;
}

static void retirement_exec_owner(int image, int gate, int output, int ack, const char *lock)
{
    int fds[] = {image, gate, output, ack};
    char values[4][32];
    for (size_t i = 0; i < 4; ++i) {
        if (fcntl(fds[i], F_SETFD, 0) < 0) _exit(46);
        snprintf(values[i], sizeof(values[i]), "%d", fds[i]);
    }
    char *const argv[] = {"supervised-fixture", "--supervised-fixture-retire-owner",
        values[0], values[1], values[2], values[3], (char *)lock, NULL};
    execv("/proc/self/exe", argv);
    _exit(47);
}

struct retirement_exit_resources {
    int probe, owner_fd, leaf_fd, supervisor_fd;
    int gate[2], output[2], ack[2];
    pid_t owner, supervisor;
    bool owner_reaped, supervisor_reaped;
};

static void retirement_exit_emergency(struct retirement_exit_resources *state)
{
    if (state->leaf_fd >= 0) (void)platform_supervised_fixture_pidfd_kill(state->leaf_fd);
    if (state->gate[1] >= 0) { close(state->gate[1]); state->gate[1] = FIXTURE_NO_FD; }
    int status;
    if (!state->owner_reaped && state->owner_fd >= 0) {
        (void)platform_supervised_fixture_pidfd_kill(state->owner_fd);
        (void)retirement_wait_child(state->owner, &status);
    }
    if (!state->supervisor_reaped && state->supervisor_fd >= 0 &&
        !retirement_wait_child(state->supervisor, &status)) {
        (void)platform_supervised_fixture_pidfd_kill(state->supervisor_fd);
        (void)retirement_wait_child(state->supervisor, &status);
    }
}

static void retirement_exit_close(struct retirement_exit_resources *state, bool failed)
{
    /* Emergency signals ONLY on failure, never mask success-path cleanup. */
    if (failed) retirement_exit_emergency(state);
    int descriptors[] = {state->probe, state->owner_fd, state->leaf_fd, state->supervisor_fd,
        state->gate[0], state->gate[1], state->output[0], state->output[1], state->ack[0], state->ack[1]};
    for (size_t i = 0; i < sizeof(descriptors) / sizeof(descriptors[0]); ++i)
        if (descriptors[i] >= 0) close(descriptors[i]);
}

/* Runs only in an isolated outer process. Its subreaper role models the host
 * adopter; it never changes the main test process's signal or wait policy. */
static int retirement_exit_model(int image, const char *directory)
{
    int failures = 0, probe = -1, owner_fd = -1, leaf_fd = -1, supervisor_fd = -1;
    int gate[2] = {-1, -1}, output[2] = {-1, -1}, ack[2] = {-1, -1};
    pid_t owner = FIXTURE_NO_PID, supervisor = FIXTURE_NO_PID;
    bool owner_reaped = false, supervisor_reaped = false;
    TEST_CASE("supervised_process: transfer ACK then owner exit precedes descendant cleanup") {
        ASSERT(platform_supervised_fixture_subreaper());
        ASSERT(pipe2(gate, O_CLOEXEC) == 0 && pipe2(output, O_CLOEXEC) == 0 && pipe2(ack, O_CLOEXEC) == 0);
        char lock[1200];
        ASSERT(snprintf(lock, sizeof(lock), "%s/owner-exit-lock", directory) > 0);
        probe = open(lock, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        ASSERT(probe >= 0);
        owner = fork();
        ASSERT(owner >= 0);
        if (!owner) retirement_exec_owner(image, gate[0], output[1], ack[1], lock);
        owner_fd = platform_supervised_fixture_pidfd_open(owner);
        ASSERT(owner_fd >= 0);
        close(gate[0]); gate[0] = -1;
        close(output[1]); output[1] = -1;
        close(ack[1]); ack[1] = -1;
        struct retirement_exit_ack reply;
        ASSERT(wait_bytes(ack[0], &reply, sizeof(reply)));
        ASSERT_EQ(reply.transferred, ZCL_RETIREMENT_TRANSFERRED);
        ASSERT_EQ(reply.empty_supervisor, FIXTURE_NO_PID);
        ASSERT_EQ(reply.token, 0);
        ASSERT_EQ(reply.state, PLATFORM_SUPERVISED_INVALID);
        ASSERT_EQ(reply.pending, 1);
        ASSERT(reply.supervisor > 1 && reply.supervisor <= INT32_MAX);
        supervisor = (pid_t)reply.supervisor;
        supervisor_fd = platform_supervised_fixture_pidfd_open(supervisor);
        ASSERT(supervisor_fd >= 0);
        pid_t leaf = FIXTURE_NO_PID;
        ASSERT(wait_bytes(output[0], &leaf, sizeof(leaf)));
        leaf_fd = platform_supervised_fixture_pidfd_open(leaf);
        ASSERT(leaf_fd >= 0);
        int status = 0;
        owner_reaped = retirement_wait_child(owner, &status);
        ASSERT(owner_reaped && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        /* Owner is gone but cleanup is still gated: prove real adoption and
         * held lock before allowing the existing supervisor to finish. */
        ASSERT_EQ(waitpid(supervisor, &status, WNOHANG), 0);
        ASSERT_EQ(flock(probe, LOCK_EX | LOCK_NB), FIXTURE_ERROR);
        ASSERT_EQ(errno, EWOULDBLOCK);
        puts("retirement exit fixture: owner reaped, supervisor adopted, leaf still holds lock");
        fflush(stdout);
        uint8_t release = 1;
        ASSERT_EQ(write(gate[1], &release, sizeof(release)), (ssize_t)sizeof(release));
        close(gate[1]); gate[1] = -1;
        supervisor_reaped = retirement_wait_child(supervisor, &status);
        ASSERT(supervisor_reaped && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        ASSERT_EQ(waitpid(supervisor, &status, WNOHANG), FIXTURE_ERROR);
        ASSERT_EQ(errno, ECHILD);
        struct pollfd dead = {.fd = leaf_fd, .events = POLLIN};
        ASSERT(poll(&dead, 1, 0) > 0);
        ASSERT_EQ(flock(probe, LOCK_EX | LOCK_NB), 0);
        ASSERT(exact_eof(output[0]));
        puts("retirement exit fixture: supervisor reaped exactly once, leaf lock released, pipe EOF");
    } TEST_END
    struct retirement_exit_resources resources = {.probe = probe, .owner_fd = owner_fd,
        .leaf_fd = leaf_fd, .supervisor_fd = supervisor_fd, .gate = {gate[0], gate[1]},
        .output = {output[0], output[1]}, .ack = {ack[0], ack[1]}, .owner = owner,
        .supervisor = supervisor, .owner_reaped = owner_reaped, .supervisor_reaped = supervisor_reaped};
    retirement_exit_close(&resources, failures != 0);
    return failures;
}

static int supervised_retirement_owner_exit(int image, const char *directory)
{
    int failures = 0;
    TEST_CASE("supervised_process: isolated host reaps retired supervisor after embedding owner exits") {
        fflush(NULL);
        pid_t outer = fork();
        ASSERT(outer >= 0);
        if (!outer) {
            int failed = retirement_exit_model(image, directory);
            fflush(NULL);
            _exit(failed ? 1 : 0);
        }
        int status = 0; pid_t got;
        do { got = waitpid(outer, &status, 0); } while (got < 0 && errno == EINTR);
        ASSERT_EQ(got, outer);
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    } TEST_END
    return failures;
}

static int retry_stable_retirement_custody(void)
{
    int failures = 0;
    for (size_t i = 0; i < sizeof(retirement_handles) / sizeof(retirement_handles[0]); ++i) {
        if (!retirement_handle_used[i]) continue;
        struct platform_supervised_process *process = &retirement_handles[i];
        if (!fixture_cleanup(process)) failures++;
        fixture_retirement_release(process);
    }
    if (!retirement_settled()) failures++;
    return failures;
}


struct retirement_launch_context {
    struct platform_supervised_process *process;
    struct platform_supervised_spec spec;
    int notify, resume;
    enum platform_supervised_state result;
};
static struct retirement_launch_context retirement_launch;

static void *retirement_launch_entry(void *arg)
{
    struct retirement_launch_context *context = arg;
    zcl_supervised_retirement_fixture_reservation_gate(context->notify, context->resume);
    context->result = zcl_supervised_retirement_start(context->process, &context->spec);
    zcl_supervised_retirement_fixture_reservation_gate(FIXTURE_NO_FD, FIXTURE_NO_FD);
    return NULL;
}

static int supervised_retirement_idle(void)
{
    int failures = 0;
    TEST_CASE("supervised_process: idle registry shutdown joins retirement worker") {
        pid_t owner = fork();
        ASSERT(owner >= 0);
        if (!owner) {
            execl("/proc/self/exe", "supervised-fixture", "--supervised-fixture-retire-idle", (char *)NULL);
            _exit(55);
        }
        int status = 0;
        ASSERT(retirement_wait_child(owner, &status));
        ASSERT(WIFEXITED(status));
        ASSERT_EQ(WEXITSTATUS(status), 0);
    } TEST_END
    return failures;
}

/* Last service test: shutdown is terminal, not a hidden per-operation restart.
 * Reservation is paused before fork; main requests stop while launch is live. */
static int supervised_retirement_draining(int image)
{
    int failures = 0;
    int notified[2] = {-1, -1}, resume[2] = {-1, -1};
    int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    struct platform_supervised_process *process = fixture_retirement_handle();
    struct platform_supervised_fd_map maps[3];
    pthread_t launcher;
    bool spawned = false, released = false;
    TEST_CASE("supervised_process: stop preserves in-flight reservation and late transfer") {
        ASSERT(process && null_fd >= 0);
        ASSERT(pipe2(notified, O_CLOEXEC) == 0);
        ASSERT(pipe2(resume, O_CLOEXEC) == 0);
        retirement_launch = (struct retirement_launch_context){
            .process = process, .spec = tree_spec(image, null_fd, null_fd, maps),
            .notify = notified[1], .resume = resume[0], .result = PLATFORM_SUPERVISED_INVALID};
        ASSERT_EQ(thread_registry_spawn("retirement-launch", retirement_launch_entry,
            &retirement_launch, &launcher), 0);
        spawned = true;
        uint8_t byte = 0;
        ASSERT_EQ(read(notified[0], &byte, 1), 1);
        ASSERT_EQ(zcl_supervised_retirement_fixture_pending(), 1);
        zcl_supervised_retirement_request_stop();
        ASSERT_EQ(zcl_supervised_retirement_phase(), ZCL_RETIREMENT_DRAINING);
        ASSERT(!zcl_supervised_retirement_drain(clock_now_monotonic_ns()));
        struct platform_supervised_process rejected;
        platform_supervised_init(&rejected);
        ASSERT_EQ(zcl_supervised_retirement_start(&rejected, &retirement_launch.spec),
            PLATFORM_SUPERVISED_LAUNCH_FAILED);
        ASSERT_EQ(rejected.supervisor_pid, FIXTURE_NO_PID);
        ASSERT_EQ(write(resume[1], &byte, 1), 1);
        released = true;
        ASSERT_EQ(pthread_join(launcher, NULL), 0);
        spawned = false;
        ASSERT_EQ(retirement_launch.result, PLATFORM_SUPERVISED_RUNNING);
        ASSERT_EQ(zcl_supervised_retirement_transfer(process), ZCL_RETIREMENT_TRANSFERRED);
        ASSERT_EQ(process->supervisor_pid, FIXTURE_NO_PID);
        ASSERT(zcl_supervised_retirement_drain(fixture_deadline()));
        ASSERT_EQ(zcl_supervised_retirement_phase(), ZCL_RETIREMENT_STOPPED);
        ASSERT_EQ(thread_registry_join_all(5), 0);
        ASSERT(!zcl_supervised_retirement_begin());
    } TEST_END
    if (spawned) {
        if (!released && resume[1] >= 0) {
            close(resume[1]); /* EOF refuses the paused launch and releases its reservation. */
            resume[1] = FIXTURE_NO_FD;
        }
        (void)pthread_join(launcher, NULL);
    }
    if (process) {
        if (!fixture_cleanup(process)) failures++;
        fixture_retirement_release(process);
    }
    for (size_t i = 0; i < 2; ++i) {
        if (notified[i] >= 0) close(notified[i]);
        if (resume[i] >= 0) close(resume[i]);
    }
    if (null_fd >= 0) close(null_fd);
    return failures;
}

int supervised_image_policy_tests(void);
int test_supervised_process(void);
int test_supervised_process(void)
{
    int failures = 0;
    if (!zcl_supervised_retirement_begin()) return 1;
    int image = -1;
    char directory[1024] = {0}, path[1200];
    TEST_CASE("supervised_process: sealed registered fixture image") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "supervised-image"));
        ASSERT(snprintf(path, sizeof(path), "%s/image", directory) > 0);
        ASSERT(symlink("/proc/self/exe", path) == 0);
        image = sealed_snapshot(path);
        ASSERT(image >= 0);
        ASSERT(unlink(path) == 0);
        int replacement = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        ASSERT(replacement >= 0);
        ssize_t written = write(replacement, "replaced path", 13);
        close(replacement);
        ASSERT_EQ(written, 13);
        ASSERT_EQ(pwrite(image, "x", 1, 0), -1);
        ASSERT_EQ(errno, EPERM);
        failures += supervised_mapping(image);
        failures += supervised_complete_vectors(image);
        failures += supervised_stack_limits(image);
        failures += supervised_complete_e2big(image);
        failures += supervised_stack_refusal(image, directory);
        failures += supervised_tree(image, false);
        failures += supervised_tree(image, true);
        failures += supervised_failures(image);
        failures += supervised_fast_exit(image);
        failures += supervised_wait_custody(image);
        failures += supervised_cwd(image, directory);
        failures += supervised_image_capture();
        failures += supervised_image_refusals();
        failures += supervised_image_geometry();
        failures += supervised_image_policy_tests();
        failures += supervised_retirement_refusal(image);
        for (unsigned scenario = 0; scenario < 3; ++scenario)
            failures += supervised_retirement(image, directory, scenario);
        failures += supervised_retirement_fork(image);
        failures += supervised_retirement_capacity(image);
        failures += supervised_retirement_owner_exit(image, directory);
        failures += supervised_retirement_idle();
        failures += supervised_retirement_draining(image);
    } TEST_END
    if (image >= 0) close(image);
    failures += retry_stable_retirement_custody();
    if (directory[0]) test_rm_rf(directory);
    failures += retry_retained_custody();
    return failures;
}
#else
int supervised_fixture_dispatch(int argc, char **argv);
int supervised_fixture_dispatch(int argc, char **argv)
{
    (void)argc; (void)argv;
    return -1;
}
int test_supervised_process(void);
int test_supervised_process(void)
{
    int failures = 0;
    TEST_CASE("supervised_process: unqualified platform refuses before launch") {
        struct platform_supervised_process process;
        platform_supervised_init(&process);
        ASSERT_EQ(platform_supervised_start(&process, NULL), PLATFORM_SUPERVISED_UNSUPPORTED);
        ASSERT_EQ(process.supervisor_pid, FIXTURE_NO_PID);
    } TEST_END
    return failures;
}
#endif
void supervised_fixture_exit_if_requested(int argc, char **argv);
void supervised_fixture_exit_if_requested(int argc, char **argv)
{
    int status = supervised_fixture_dispatch(argc, argv);
    if (status >= 0) exit(status);
}
