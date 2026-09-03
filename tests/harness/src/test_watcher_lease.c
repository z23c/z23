/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native watcher-launch acceptance.  POSIX runs the real parent-to-child
 * capability transfer, immutable binding readback, stop signal, and FIFO
 * cleanup.  The Windows-specific spawn contract remains in its standalone
 * acceptance program; this group still pins the public API's fail-closed
 * argument handling on every host. */

#include "test/test_core.h"

#include "platform/os_proc.h"
#include "platform/watcher_lease.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#if !defined(_WIN32)
#include <sys/wait.h>
#include <unistd.h>
#endif

#define WL_CHECK(name, expr) do {                                      \
    printf("watcher_lease: %s... ", (name));                          \
    if (expr) printf("OK\n");                                        \
    else { printf("FAIL\n"); failures++; }                           \
} while (0)

static const char watcher_hash[] =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#if !defined(_WIN32)
static bool wl_io_exact(int fd, void *data, size_t size, bool writing)
{
    unsigned char *bytes = data;
    size_t done = 0;
    while (done < size) {
        ssize_t count = writing ? write(fd, bytes + done, size - done)
                                : read(fd, bytes + done, size - done);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return false;
        done += (size_t)count;
    }
    return true;
}

static bool wl_wait_child(pid_t child, int *status)
{
    pid_t waited;
    do {
        waited = waitpid(child, status, 0);
    } while (waited < 0 && errno == EINTR);
    return waited == child;
}

static bool wl_abandoned_launch_cleans_fifo(const char *root,
                                             const char *image)
{
    struct platform_watcher_launch launch;
    platform_watcher_launch_init(&launch);
    if (!platform_watcher_launch_prepare(&launch, root, image, watcher_hash))
        return false;
    char locator[sizeof(launch.stop_locator)];
    memcpy(locator, launch.stop_locator, sizeof(locator));
    bool existed = access(locator, F_OK) == 0;
    platform_watcher_launch_close(&launch);
    errno = 0;
    return existed && access(locator, F_OK) != 0 && errno == ENOENT;
}

static bool wl_parent_child_roundtrip(const char *root, const char *image)
{
    struct platform_watcher_launch launch;
    platform_watcher_launch_init(&launch);
    if (!platform_watcher_launch_prepare(&launch, root, image, watcher_hash))
        return false;
    char locator[sizeof(launch.stop_locator)];
    memcpy(locator, launch.stop_locator, sizeof(locator));

    int report[2] = {-1, -1};
    if (pipe(report) != 0) {
        platform_watcher_launch_close(&launch);
        return false;
    }
    pid_t child = fork();
    if (child < 0) {
        close(report[0]);
        close(report[1]);
        platform_watcher_launch_close(&launch);
        return false;
    }
    if (child == 0) {
        close(report[0]);
        close((int)launch.private_write);
        close((int)launch.stop_native);
        struct platform_watcher_lease lease;
        struct platform_watcher_accepted_binding binding;
        platform_watcher_lease_init(&lease);
        bool accepted = platform_watcher_lease_accept(
            &lease, launch.inherited_read, root, image, watcher_hash);
        bool bound = accepted && platform_watcher_lease_binding(
            &lease, &binding) &&
            binding.creator_pid == (uint64_t)getppid() &&
            binding.creator_start_token != 0 &&
            strcmp(binding.canonical_root, root) == 0 &&
            strcmp(binding.canonical_image, image) == 0 &&
            strcmp(binding.image_sha256, watcher_hash) == 0;
        unsigned char ready = bound ? 1u : 0u;
        bool reported = wl_io_exact(report[1], &ready, sizeof(ready), true);
        unsigned char stopped = bound &&
            platform_watcher_lease_wait_stop(&lease, 3000) ? 1u : 0u;
        reported = wl_io_exact(report[1], &stopped, sizeof(stopped), true) &&
                   reported;
        platform_watcher_lease_close(&lease);
        close(report[1]);
        _exit(reported && ready && stopped ? 0 : 1);
    }

    close(report[1]);
    close((int)launch.inherited_read);
    launch.inherited_read = UINTPTR_MAX;
    bool published = platform_watcher_launch_publish(&launch);
    unsigned char ready = 0, stopped = 0;
    bool ready_read = wl_io_exact(report[0], &ready, sizeof(ready), false);
    bool signaled = ready_read && ready == 1u &&
                    platform_watcher_lease_signal_stop(launch.nonce);
    bool stopped_read = wl_io_exact(report[0], &stopped,
                                    sizeof(stopped), false);
    close(report[0]);
    int status = 0;
    bool reaped = wl_wait_child(child, &status);
    platform_watcher_launch_close(&launch);
    errno = 0;
    bool removed = access(locator, F_OK) != 0 && errno == ENOENT;
    return published && ready_read && ready == 1u && signaled &&
           stopped_read && stopped == 1u && reaped && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0 && removed;
}
#endif

int test_watcher_lease(void)
{
    int failures = 0;
    struct platform_watcher_launch launch = {0};
    platform_watcher_launch_init(&launch);
    WL_CHECK("launch initialization uses closed sentinels",
             launch.inherited_read == UINTPTR_MAX &&
             launch.private_write == UINTPTR_MAX &&
             launch.stop_native == UINTPTR_MAX &&
             launch.record_native == UINTPTR_MAX);
    WL_CHECK("NULL launch has no inherited capability",
             platform_watcher_launch_inherited(NULL) == UINTPTR_MAX);
    WL_CHECK("NULL launch cannot publish",
             !platform_watcher_launch_publish(NULL));
    WL_CHECK("prepare refuses a NULL root",
             !platform_watcher_launch_prepare(
                 &launch, NULL, "/no/such/image", watcher_hash));
    WL_CHECK("prepare refuses a NULL image",
             !platform_watcher_launch_prepare(
                 &launch, "/no/such/root", NULL, watcher_hash));
    WL_CHECK("prepare refuses a NULL digest",
             !platform_watcher_launch_prepare(
                 &launch, "/no/such/root", "/no/such/image", NULL));
    WL_CHECK("prepare refuses a malformed digest",
             !platform_watcher_launch_prepare(
                 &launch, "/no/such/root", "/no/such/image", "bad"));
    platform_watcher_launch_close(NULL);

    struct platform_watcher_lease lease;
    struct platform_watcher_accepted_binding binding;
    platform_watcher_lease_init(&lease);
    WL_CHECK("unaccepted lease has no immutable binding",
             !platform_watcher_lease_binding(&lease, &binding));
    WL_CHECK("unaccepted lease cannot wait for stop",
             !platform_watcher_lease_wait_stop(&lease, 0));
    WL_CHECK("malformed stop nonce is refused",
             !platform_watcher_lease_signal_stop("bad"));
    platform_watcher_lease_close(&lease);
    platform_watcher_lease_close(NULL);

#if !defined(_WIN32)
    char root[PATH_MAX], image[PATH_MAX];
    test_make_tmpdir(root, sizeof(root), "watcher_lease", "native");
    bool have_image = os_proc_exe_path(image, sizeof(image));
    WL_CHECK("current executable path resolves", have_image);
    WL_CHECK("abandoned launch removes its private FIFO",
             have_image && wl_abandoned_launch_cleans_fifo(root, image));
    WL_CHECK("parent-child lease authenticates, binds, stops, and cleans",
             have_image && wl_parent_child_roundtrip(root, image));
    (void)test_rm_rf_recursive(root);
#endif
    return failures;
}
