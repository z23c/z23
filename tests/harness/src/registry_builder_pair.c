/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "registry_builder_pair.h"
#include "services/package_lifecycle.h"
#include <stdio.h>

bool registry_builder_build_one(const char *datadir, const char *root, int64_t now)
{
    struct package_lifecycle_plan_report plan;
    struct zcl_result planned = package_lifecycle_plan(datadir, root, now, &plan);
    if (!planned.ok || !plan.ready) {
        printf("  zcode_package_registry: plan %s failed rule=%s detail=%s message=%s\n",
               root, plan.rule, plan.detail, planned.message);
        return false;
    }
    struct package_lifecycle_commit_report commit;
    struct zcl_result committed = package_lifecycle_commit(datadir, plan.plan_id, now + 1, &commit);
    if (!committed.ok || !commit.installed) {
        printf("  zcode_package_registry: commit %s failed rule=%s detail=%s message=%s\n",
               root, commit.rule, commit.detail, committed.message);
        return false;
    }
    return true;
}

#if defined(__linux__)
#include "chain/chainparams.h"
#include "event/event.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "vcs/package_store.h"
#include "platform/supervised_process.h"
#include "platform/clock.h"
#include "sha3/sha3.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#define ZCODE_PACKAGE(name, dir, sequence, content, release, recipe, lock, capsule, publisher, signature) content,
static const char *const registry_fixture_roots[] = {
#include "../../../engine/composition/zcode_package_registry.def"
#include "../../../engine/composition/zcode_c23_commons_app.def"
};
#undef ZCODE_PACKAGE

static bool registry_fixture_directory(char *path, size_t cap)
{
    struct stat self, pinned, dir, resolved;
    ssize_t len = readlink("/proc/self/fd/4", path, cap - 1);
    if (len <= 0 || (size_t)len >= cap - 1) return false;
    path[len] = '\0';
    return stat("/proc/self/exe", &self) == 0 && fstat(3, &pinned) == 0 &&
           self.st_dev == pinned.st_dev && self.st_ino == pinned.st_ino &&
           fstat(4, &dir) == 0 && S_ISDIR(dir.st_mode) && dir.st_uid == geteuid() &&
           (dir.st_mode & 0777) == 0700 && stat(path, &resolved) == 0 &&
           dir.st_dev == resolved.st_dev && dir.st_ino == resolved.st_ino;
}

static bool registry_fixture_args(const char *root, const char *text, int64_t *now)
{
    bool known = false;
    for (size_t i = 0; i < sizeof(registry_fixture_roots) / sizeof(registry_fixture_roots[0]); ++i)
        if (strcmp(root, registry_fixture_roots[i]) == 0) known = true;
    char *end = NULL;
    errno = 0;
    intmax_t stamp = strtoimax(text, &end, 10);
    if (!known || errno || !end || *end || stamp <= 0 || stamp >= INT64_MAX) return false;
    *now = (int64_t)stamp;
    return true;
}

void registry_builder_exit_if_requested(int argc, char **argv)
{
    if (argc < 2 || strcmp(argv[1], "--registry-builder-fixture") != 0) return;
    char path[PATH_MAX];
    int64_t stamp;
    if (argc != 4 || !registry_fixture_directory(path, sizeof(path)) ||
        !registry_fixture_args(argv[2], argv[3], &stamp)) _exit(2);
    close(3);
    close(4);
    vcs_package_store_set_deferred_sync(true);
    chain_params_select(CHAIN_MAIN);
    ecc_start();
    ecc_verify_init();
    event_log_init();
    exit(registry_builder_build_one(path, argv[2], stamp) ? 0 : 1);
}

static int registry_launcher_image(void)
{
    int fd = open("build/bin/process-group-exec", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (fd < 0) return -1;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        (uint64_t)st.st_size > PLATFORM_SUPERVISED_IMAGE_MAX) {
        close(fd); return -1;
    }
    size_t len = (size_t)st.st_size, used = 0;
    unsigned char *bytes = malloc(len);
    if (!bytes) { close(fd); return -1; }
    while (used < len) {
        ssize_t n = read(fd, bytes + used, len - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        used += (size_t)n;
    }
    bool ok = close(fd) == 0 && used == len;
    int image = -1;
    if (ok) {
        uint8_t digest[32];
        zcl_sha3_256(bytes, len, digest);
        ok = platform_supervised_image_capture(bytes, len, digest, &image) ==
             PLATFORM_SUPERVISED_IMAGE_OK;
    }
    free(bytes);
    return ok ? image : -1;
}

static bool registry_parallel_enabled;
void registry_builder_pair_enable(void) { registry_parallel_enabled = true; }
bool registry_builder_pair_available(void) { return registry_parallel_enabled; }

enum registry_pair_result { PAIR_OK, PAIR_LAUNCH_FAILED, PAIR_CHILD_FAILED, PAIR_TIMEOUT };

static bool registry_child_success(const struct platform_supervised_process *child)
{
    return child->observation.state == PLATFORM_SUPERVISED_CLEAN &&
           child->observation.no_children && child->observation.engine_exit_observed &&
           WIFEXITED(child->observation.engine_wait_status) &&
           WEXITSTATUS(child->observation.engine_wait_status) == 0;
}

static enum registry_pair_result registry_pair_monitor(
    struct platform_supervised_process children[2], int64_t deadline)
{
    for (;;) {
        bool all_done = true;
        for (size_t i = 0; i < 2; ++i) {
            struct platform_supervised_process *child = &children[i];
            if (child->supervisor_pid >= 0 &&
                platform_supervised_poll(child) != PLATFORM_SUPERVISED_RUNNING &&
                child->supervisor_pid >= 0) return PAIR_CHILD_FAILED;
            if (child->supervisor_pid >= 0) { all_done = false; continue; }
            if (!registry_child_success(child)) return PAIR_CHILD_FAILED;
        }
        if (all_done) return PAIR_OK;
        if (clock_now_monotonic_ns() >= deadline) return PAIR_TIMEOUT;
        (void)poll(NULL, 0, 5);
    }
}

static bool registry_pair_cleanup(struct platform_supervised_process children[2])
{
    for (size_t i = 0; i < 2; ++i) {
        if (children[i].supervisor_pid >= 0)
            (void)platform_supervised_stop(&children[i], clock_now_monotonic_ns() + INT64_C(10000000000));
        if (children[i].supervisor_pid >= 0) {
            platform_supervised_owner_eof(&children[i]);
            fprintf(stderr, "registry builder cleanup incomplete\n");
            _exit(2);
        }
    }
    return children[0].observation.no_children && children[1].observation.no_children &&
           children[0].observation.state == PLATFORM_SUPERVISED_CLEAN &&
           children[1].observation.state == PLATFORM_SUPERVISED_CLEAN;
}

static bool registry_fds_valid(int image, int runner, int input, const int dirs[2])
{
    return image >= 0 && runner >= 0 && input >= 0 && dirs[0] >= 0 && dirs[1] >= 0;
}

static void registry_close_fds(int image, int runner, int input, const int dirs[2])
{
    if (image >= 0) close(image);
    if (runner >= 0) close(runner);
    if (input >= 0) close(input);
    for (size_t i = 0; i < 2; ++i) if (dirs[i] >= 0) close(dirs[i]);
}

static enum registry_pair_result registry_pair_run(
    const char *a, const char *b, const char *root, int64_t now,
    const char *const fixture_modes[2], int64_t duration, bool *reaped)
{
    char stamp[32];
    int n = snprintf(stamp, sizeof(stamp), "%" PRId64, now);
    if (n <= 0 || (size_t)n >= sizeof(stamp)) return PAIR_LAUNCH_FAILED;
    int image = registry_launcher_image();
    int runner = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    int dirs[2] = {open(a, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW),
                   open(b, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)};
    struct platform_supervised_process children[2];
    for (size_t i = 0; i < 2; ++i) platform_supervised_init(&children[i]);
    size_t env_count = 0;
    while (environ[env_count]) ++env_count;
    const char *args[] = {"process-group-exec", "/proc/self/fd/3",
                          "--registry-builder-fixture", root, stamp, NULL};
    if (fixture_modes) {
        args[3] = NULL;
    }
    struct platform_supervised_fd_map maps[] = {{input, 0}, {1, 1}, {2, 2},
                                                {runner, 3}, {-1, 4}};
    /* Match the runner's default five-minute group watchdog. */
    int64_t deadline = clock_now_monotonic_ns() + duration;
    struct platform_supervised_spec spec = {
        .executable_fd = image, .argv = args,
        .env = (const char *const *)environ, .env_count = env_count,
        .env_policy = PLATFORM_SUPERVISED_ENV_COMPLETE, .maps = maps,
        .map_count = 5, .launch_deadline_ns = deadline,
        .cleanup_timeout_ms = 5000
    };
    bool ok = registry_fds_valid(image, runner, input, dirs);
    for (size_t i = 0; i < 2; ++i) {
        maps[4].source = dirs[i];
        if (fixture_modes) args[2] = fixture_modes[i];
        if (ok) ok = platform_supervised_start(&children[i], &spec) == PLATFORM_SUPERVISED_RUNNING;
    }
    registry_close_fds(image, runner, input, dirs);
    enum registry_pair_result result = ok ? registry_pair_monitor(children, deadline) : PAIR_LAUNCH_FAILED;
    bool cleaned = registry_pair_cleanup(children);
    if (reaped) *reaped = cleaned;
    return result;
}

bool registry_builder_pair_run(const char *a, const char *b,
                               const char *root, int64_t now)
{
    return registry_pair_run(a, b, root, now, NULL, INT64_C(300000000000), NULL) == PAIR_OK;
}

bool registry_builder_pair_cleanup_test(const char *a, const char *b)
{
    bool reaped = false;
    const char *failure[] = {"--supervised-fixture-hold", "--supervised-fixture-exit-one"};
    enum registry_pair_result result = registry_pair_run(a, b, NULL, 1, failure,
                                                         INT64_C(10000000000), &reaped);
    if (result != PAIR_CHILD_FAILED || !reaped) return false;
    reaped = false;
    const char *timeout[] = {"--supervised-fixture-hold", "--supervised-fixture-hold"};
    result = registry_pair_run(a, b, NULL, 1, timeout, INT64_C(1000000000), &reaped);
    return result == PAIR_TIMEOUT && reaped;
}
#else
void registry_builder_exit_if_requested(int argc, char **argv)
{ (void)argc; (void)argv; }
void registry_builder_pair_enable(void) { }
bool registry_builder_pair_available(void) { return false; }
bool registry_builder_pair_run(const char *a, const char *b, const char *root, int64_t now)
{ (void)a; (void)b; (void)root; (void)now; return false; }
bool registry_builder_pair_cleanup_test(const char *a, const char *b)
{ (void)a; (void)b; return false; }
#endif
