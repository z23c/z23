/* Copyright 2026 Rhett Creighton - Apache 2.0 */
/*
 * Exact resident-launch acceptance. Proves the four invariants the seam
 * sells: a live image that differs from the accepted record is refused
 * before any process exists; a result frame from another launch is refused
 * by name; a failed candidate leaves an already-serving launch intact; a
 * full launch/cancel cycle leaves neither descriptors nor children behind.
 * The real spawn path runs on POSIX (Linux fexecve proof, macOS suspended
 * CodeDirectory proof); Windows asserts the named refusal.
 */
#include "test/test_core.h"

#include "base/hex.h"
#include "platform/positioned_file.h"
#include "platform/resident_launch.h"
#include "sha3/sha3.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#if !defined(_WIN32)
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#define RL_CHECK(name, expr) do {                                         \
    printf("resident_launch: %s... ", (name));                            \
    fflush(stdout);                                                       \
    if (expr) printf("OK\n");                                             \
    else { printf("FAIL\n"); failures++; }                                \
} while (0)

/* A tiny executable fixture: enough for prepare()'s digest/triple checks
 * (no exec happens on the refusal paths). */
static const char rl_script[] = "#!/bin/sh\nexit 0\n";

static bool rl_write_fixture(const char *path)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = fwrite(rl_script, 1, sizeof(rl_script) - 1, f) ==
              sizeof(rl_script) - 1;
    if (fclose(f) != 0) ok = false;
    if (ok && chmod(path, 0755) != 0) ok = false;
    return ok;
}

/* Capture the acceptance record for a file as it stands right now. */
static bool rl_accept_of(const char *path, struct resident_launch_accepted *a)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot snap;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path) ||
        !platform_positioned_file_snapshot(&file, &snap)) {
        platform_positioned_file_close(&file);
        return false;
    }
    unsigned char digest[32];
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    unsigned char chunk[4096];
    uint64_t offset = 0;
    for (;;) {
        int64_t got = platform_positioned_file_read(&file, chunk, sizeof(chunk),
                                                    offset);
        if (got < 0) { platform_positioned_file_close(&file); return false; }
        if (got == 0) break;
        sha3_256_write(&ctx, chunk, (size_t)got);
        offset += (uint64_t)got;
    }
    sha3_256_finalize(&ctx, digest);
    platform_positioned_file_close(&file);
    zcl_hex_encode(digest, sizeof(digest), a->image_sha3_hex);
    a->image_volume = snap.volume;
    a->image_low = snap.file_low;
    a->image_high = snap.file_high;
    a->image_size = snap.size;
    return true;
}

#if defined(_WIN32)
int test_resident_launch(void)
{
    int failures = 0;
    struct resident_launch wrong;
    struct resident_launch_accepted accepted = {{0}, 0, 0, 0, 0};
    char error[RESIDENT_LAUNCH_ERROR_MAX];
    resident_launch_init(&wrong);
    RL_CHECK("prepare refuses on a platform without descriptor-bound exec",
             !resident_launch_prepare(&wrong, "no-such-image", &accepted,
                                      error, sizeof(error)) &&
             errno == ENOTSUP && error[0]);
    resident_launch_close(&wrong);
    printf("resident_launch: %s (%d failure(s))\n",
           failures ? "FAIL" : "PASS", failures);
    return failures;
}
#else /* POSIX */

static int rl_open_fd_count(void)
{
    int count = 0;
    for (int fd = 3; fd < 1024; fd++) {
        if (fcntl(fd, F_GETFD) != -1) count++;
    }
    return count;
}

static bool rl_wait_reaped(uint64_t pid)
{
    return waitpid((pid_t)pid, NULL, WNOHANG) == -1 && errno == ECHILD;
}

/* Everything prepare() must refuse, before any process exists. */
static int rl_refusal_checks(const char *fixture,
                             const struct resident_launch_accepted *accepted)
{
    int failures = 0;
    char error[RESIDENT_LAUNCH_ERROR_MAX];
    struct resident_launch wrong;
    struct resident_launch_accepted tampered = *accepted;
    tampered.image_sha3_hex[0] = tampered.image_sha3_hex[0] == '0' ? '1' : '0';
    resident_launch_init(&wrong);
    error[0] = '\0';
    RL_CHECK("prepare refuses a tampered digest before any process exists",
             !resident_launch_prepare(&wrong, fixture, &tampered, error,
                                      sizeof(error)) &&
             errno == ESTALE &&
             strstr(error, "accepted record") != NULL);
    resident_launch_close(&wrong);

    struct resident_launch_accepted wrong_triple = *accepted;
    wrong_triple.image_low ^= 1;
    resident_launch_init(&wrong);
    error[0] = '\0';
    RL_CHECK("prepare refuses a replaced positioned-file identity",
             !resident_launch_prepare(&wrong, fixture, &wrong_triple, error,
                                      sizeof(error)) &&
             errno == ESTALE);
    resident_launch_close(&wrong);

    /* Mutate the file AFTER capturing acceptance: the live bytes must not
     * match the accepted record even though the digest field claims it. */
    FILE *swap = fopen(fixture, "wb");
    bool swapped = swap &&
        fputs("#!/bin/sh\nexit 3\n", swap) >= 0 && fclose(swap) == 0 &&
        chmod(fixture, 0755) == 0;
    RL_CHECK("mutate the fixture on disk", swapped);
    struct resident_launch stale_live;
    resident_launch_init(&stale_live);
    error[0] = '\0';
    RL_CHECK("prepare refuses mutated live bytes against the old record",
             !resident_launch_prepare(&stale_live, fixture, accepted, error,
                                      sizeof(error)) &&
             errno == ESTALE);
    resident_launch_close(&stale_live);
    (void)rl_write_fixture(fixture);
    return failures;
}

/* The frame codec: current-nonce results accepted, stale-nonce refused by
 * name. No child process is needed — the peer end of the channel is driven
 * from this test. */
static int rl_codec_checks(const char *fixture,
                           const struct resident_launch_accepted *accepted)
{
    int failures = 0;
    char error[RESIDENT_LAUNCH_ERROR_MAX];
    struct resident_launch codec;
    resident_launch_init(&codec);
    RL_CHECK("prepare accepts the intact image",
             resident_launch_prepare(&codec, fixture, accepted, error,
                                     sizeof(error)));
    int peer[2] = {-1, -1};
    RL_CHECK("codec test channel",
             socketpair(AF_UNIX, SOCK_STREAM, 0, peer) == 0);
    codec.ipc_native = (uintptr_t)peer[0];
    codec.spawned = true;
    struct resident_result_header header;
    unsigned char payload[64];
    struct resident_result_header frame;
    memset(&frame, 0, sizeof(frame));
    (void)snprintf(frame.magic, sizeof(frame.magic), "%s", "z23-res-run-v1");
    (void)snprintf(frame.nonce, sizeof(frame.nonce), "%s", codec.nonce);
    frame.payload_len = 3;
    error[0] = '\0';
    (void)send(peer[1], &frame, sizeof(frame), 0);
    (void)send(peer[1], "ok!", 3, 0);
    RL_CHECK("current-nonce result frame is accepted",
             resident_result_read(&codec, &header, payload, sizeof(payload),
                                  2000, error, sizeof(error)) &&
             header.payload_len == 3 && memcmp(payload, "ok!", 3) == 0);
    memset(&frame, 0, sizeof(frame));
    (void)snprintf(frame.magic, sizeof(frame.magic), "%s", "z23-res-run-v1");
    memset(frame.nonce, 'f', RESIDENT_LAUNCH_NONCE_HEX);
    frame.payload_len = 0;
    (void)send(peer[1], &frame, sizeof(frame), 0);
    error[0] = '\0';
    RL_CHECK("stale-nonce result frame is refused by name",
             !resident_result_read(&codec, &header, payload, sizeof(payload),
                                   2000, error, sizeof(error)) &&
             errno == ESTALE && strstr(error, "result_stale_launch") != NULL);
    close(peer[0]);
    close(peer[1]);
    codec.ipc_native = (uintptr_t)-1;
    codec.spawned = false;
    resident_launch_close(&codec);
    return failures;
}

/* A real, long-lived executable: the receipt's start_token and the
 * /proc/<pid>/exe re-proof are only observable while the child lives, and
 * the cancel path must prove real reaping of a live process. Then a failed
 * candidate against the steady state, and the no-leak proof. */
static int rl_cycle_checks(void)
{
    int failures = 0;
#if defined(__APPLE__)
    const char *sleeper_path = "build/fixtures/rlc_child_v1";
#else
    const char *sleeper_path = "/bin/sleep";
#endif
    char error[RESIDENT_LAUNCH_ERROR_MAX];
    struct resident_launch_accepted sleeper;
    RL_CHECK("capture sleeper acceptance record",
             rl_accept_of(sleeper_path, &sleeper));
    int fds_before = rl_open_fd_count();
    struct resident_launch serving;
    resident_launch_init(&serving);
    error[0] = '\0';
    RL_CHECK("prepare the serving launch",
             resident_launch_prepare(&serving, sleeper_path, &sleeper, error,
                                     sizeof(error)));
    struct resident_receipt receipt;
    memset(&receipt, 0, sizeof(receipt));
#if defined(__APPLE__)
    /* The native thin fixture is within the Darwin launch contract;
     * the system sleep executable may be a universal Mach-O. */
    char *const argv[] = {"rlc_child_v1", "--resident", serving.nonce, "park", NULL};
#else
    char *const argv[] = {"sleep", "30", NULL};
#endif
    char *const envp[] = {NULL};
    bool spawned_serving = resident_launch_spawn(
        &serving, argv, envp, &receipt, error, sizeof(error));
    if (!spawned_serving)
        printf("resident_launch: spawn error: %s (errno=%d)\n",
               error[0] ? error : "<none>", errno);
    RL_CHECK("spawn proves the exact mapped image and issues a receipt",
             spawned_serving && receipt.pid > 0 &&
             receipt.image_sha3_hex[0] &&
             (strcmp(receipt.mapped_proof, "fexecve_inode") == 0 ||
              strcmp(receipt.mapped_proof, "proc_exe_triple") == 0 ||
              strcmp(receipt.mapped_proof, "cdhash_suspended") == 0) &&
             receipt.start_token > 0);
#if defined(__linux__)
    /* The post-exec re-proof must actually run: the receipt names
     * "proc_exe_triple"; "fexecve_inode" means the proof was skipped. */
    RL_CHECK("the /proc/<pid>/exe re-proof ran and named itself on the"
             " receipt",
             strcmp(receipt.mapped_proof, "proc_exe_triple") == 0);
#endif

    int fds_steady = rl_open_fd_count();
    struct resident_launch candidate;
    struct resident_launch_accepted bad_candidate = sleeper;
    bad_candidate.image_high ^= 1;
    resident_launch_init(&candidate);
    error[0] = '\0';
    RL_CHECK("failed candidate is refused before any process exists",
             !resident_launch_prepare(&candidate, sleeper_path,
                                      &bad_candidate, error, sizeof(error)) &&
             errno == ESTALE);
    resident_launch_close(&candidate);
    RL_CHECK("refused candidate leaked no descriptors",
             rl_open_fd_count() == fds_steady);
    RL_CHECK("the serving launch is still current after the refusal",
             serving.spawned && serving.pid == receipt.pid);

    error[0] = '\0';
    RL_CHECK("cancel stops and reaps the resident",
             resident_launch_cancel(&serving, 300, error, sizeof(error)));
    RL_CHECK("the resident left no child behind", rl_wait_reaped(receipt.pid));
    resident_launch_close(&serving);
    RL_CHECK("full cycle leaked no descriptors",
             rl_open_fd_count() == fds_before);
    return failures;
}

/* Stream `in` into the already-open `out`, recording the byte count. */
static bool rl_copy_stream(FILE *in, FILE *out, size_t *size_out)
{
    unsigned char buf[4096];
    size_t total = 0;
    for (;;) {
        size_t got = fread(buf, 1, sizeof(buf), in);
        if (got > 0 && fwrite(buf, 1, got, out) != got) return false;
        total += got;
        if (got < sizeof(buf)) {
            *size_out = total;
            return !ferror(in);
        }
    }
}

/* Copy `src` to `dst`, append `pad` zero bytes (trailing bytes past the
 * ELF's own layout do not change how it executes), and record the original
 * byte count so the caller can flip a byte inside the padding: that yields
 * a same-inode, same-size, different-bytes image that still runs. */
static bool rl_copy_padded(const char *src, const char *dst, size_t pad,
                           size_t *plain_size_out)
{
    FILE *in = fopen(src, "rb");
    if (!in) return false;
    FILE *out = fopen(dst, "wb");
    if (!out) { (void)fclose(in); return false; }
    bool ok = rl_copy_stream(in, out, plain_size_out);
    unsigned char zeros[512] = {0};
    size_t left = pad;
    while (ok && left > 0) {
        size_t chunk = left < sizeof(zeros) ? left : sizeof(zeros);
        if (fwrite(zeros, 1, chunk, out) != chunk) { ok = false; break; }
        left -= chunk;
    }
    if (fclose(out) != 0) ok = false;
    (void)fclose(in);
    if (ok && chmod(dst, 0755) != 0) ok = false;
    return ok;
}

/* Overwrite one byte IN PLACE at `offset`: same inode, same size, changed
 * content — exactly the swap a metadata-only check cannot reliably see on
 * a multigrain-timestamp kernel. */
static bool rl_flip_byte(const char *path, size_t offset)
{
    FILE *f = fopen(path, "r+b");
    if (!f) return false;
    bool ok = fseek(f, (long)offset, SEEK_SET) == 0 && fputc('X', f) == 'X';
    if (fclose(f) != 0) ok = false;
    return ok;
}

/* A same-size, same-inode content swap between prepare and spawn must
 * refuse before fork: ESTALE, a named byte change, and no child. The
 * flipped byte sits in zero padding past the ELF layout, so the swapped
 * image still executes and a missing refusal shows as a successful spawn. */
static int rl_swap_refusal_checks(const char *dir)
{
    int failures = 0;
    char error[RESIDENT_LAUNCH_ERROR_MAX];
    char image[512];
    (void)snprintf(image, sizeof(image), "%s/padded-true", dir);
    size_t plain_size = 0;
#if defined(__APPLE__)
    const char *image_source = "build/fixtures/rlc_child_v1";
#else
    const char *image_source = "/bin/true";
#endif
    RL_CHECK("stage a padded executable image",
             rl_copy_padded(image_source, image, 4096, &plain_size));
    struct resident_launch_accepted accepted;
    RL_CHECK("capture the padded image acceptance record",
             rl_accept_of(image, &accepted));
    int fds_before = rl_open_fd_count();
    struct resident_launch swap;
    resident_launch_init(&swap);
    error[0] = '\0';
    RL_CHECK("prepare accepts the padded image",
             resident_launch_prepare(&swap, image, &accepted, error,
                                     sizeof(error)));
    RL_CHECK("swap same-size bytes in place after prepare",
             rl_flip_byte(image, plain_size + 100));
    struct resident_receipt receipt;
    memset(&receipt, 0, sizeof(receipt));
    char *const argv[] = {"true", NULL};
    char *const envp[] = {NULL};
    error[0] = '\0';
    bool spawned = resident_launch_spawn(&swap, argv, envp, &receipt, error,
                                         sizeof(error));
    RL_CHECK("spawn refuses a same-size content swap before fork",
             !spawned && errno == ESTALE && !swap.spawned && swap.pid == 0 &&
             strstr(error, "bytes changed") != NULL);
    if (spawned) {
        /* Reap the child if the refusal failed so
         * the regression leaves no process behind. */
        char cleanup_error[RESIDENT_LAUNCH_ERROR_MAX];
        (void)resident_launch_cancel(&swap, 300, cleanup_error,
                                     sizeof(cleanup_error));
    }
    resident_launch_close(&swap);
    RL_CHECK("the pre-fork refusal leaked no descriptors",
             rl_open_fd_count() == fds_before);
    return failures;
}

/* Child-only redirection is tested in a forked fixture so fd 3 can be
 * occupied deliberately without replacing a descriptor in the harness. */
static bool rl_stdio_unchanged(const struct stat before[3], const int flags[3])
{
    for (int fd = 0; fd < 3; ++fd) {
        struct stat now;
        if (fstat(fd, &now) != 0 || fcntl(fd, F_GETFD) != flags[fd] ||
            now.st_dev != before[fd].st_dev || now.st_ino != before[fd].st_ino ||
            now.st_rdev != before[fd].st_rdev) return false;
    }
    return true;
}

static bool rl_stdio_wait_log(int fd)
{
    char body[128];
    for (unsigned i = 0; i < 500; ++i) {
        ssize_t n = pread(fd, body, sizeof(body) - 1, 0);
        if (n > 0) {
            body[n] = 0;
            if (strstr(body, "stdout-marker\n") && strstr(body, "stderr-marker\n")) return true;
        }
        struct timespec delay = { .tv_nsec = 10000000 };
        nanosleep(&delay, NULL); /* real-clock: a forked OS child writes these log markers; its scheduling has no injected clock seam. */
    }
    return false;
}

static int rl_stdio_refusals(struct resident_launch *launch, char *const argv[], char *const envp[],
    int logfd, const char *path)
{
    int failures = 0;
    char error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    struct resident_receipt receipt;
    int closedfd = fcntl(logfd, F_DUPFD_CLOEXEC, 20);
    if (closedfd >= 0) close(closedfd);
    launch->log_stdio_fd = closedfd;
    RL_CHECK("closed log refused before spawn", closedfd >= 0 &&
        !resident_launch_spawn(launch, argv, envp, &receipt, error, RESIDENT_LAUNCH_ERROR_MAX) && !launch->spawned);
    int readonly = open(path, O_RDONLY | O_CLOEXEC);
    launch->log_stdio_fd = readonly;
    RL_CHECK("read-only log refused before spawn", readonly >= 0 &&
        !resident_launch_spawn(launch, argv, envp, &receipt, error, RESIDENT_LAUNCH_ERROR_MAX) && !launch->spawned);
    if (readonly >= 0) close(readonly);
    launch->log_stdio_fd = logfd; launch->null_stdio = true;
    RL_CHECK("conflicting stdio policies refused", !resident_launch_spawn(launch, argv, envp, &receipt, error, RESIDENT_LAUNCH_ERROR_MAX) && !launch->spawned);
    launch->null_stdio = false;
    return failures;
}

static int rl_stdio_closed_standard(const char *image, int logfd, int closed_fd)
{
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(closed_fd);
        struct resident_launch_accepted accepted;
        struct resident_launch launch; resident_launch_init(&launch);
        char error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
        bool prepared = rl_accept_of(image, &accepted) &&
            resident_launch_prepare(&launch, image, &accepted, error, sizeof(error));
        char *const argv[] = { "rlc_child_v1", "--stdio-probe", NULL };
        char *const envp[] = { NULL };
        struct resident_receipt receipt;
        launch.log_stdio = true; launch.log_stdio_fd = logfd;
        bool refused = prepared && !resident_launch_spawn(&launch, argv, envp, &receipt, error, sizeof(error)) && !launch.spawned;
        if (prepared) resident_launch_close(&launch);
        _exit(refused ? 0 : 1);
    }
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return 1;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 1;
}

static int rl_stdio_no_inherited_log(const char *image, int logfd)
{
    int failures = 0;
    int borrowed = fcntl(logfd, F_DUPFD, 20);
    RL_CHECK("non-CLOEXEC borrowed log available", borrowed >= 20 && !(fcntl(borrowed, F_GETFD) & FD_CLOEXEC));
    if (borrowed < 0) return failures + 1;
    char number[32], error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    (void)snprintf(number, sizeof(number), "%d", borrowed);
    char *const argv[] = { "rlc_child_v1", "--stdio-probe", number, NULL };
    char *const envp[] = { NULL };
    struct resident_launch_accepted accepted;
    struct resident_launch launch; resident_launch_init(&launch);
    bool prepared = rl_accept_of(image, &accepted) && resident_launch_prepare(&launch, image, &accepted, error, sizeof(error));
    RL_CHECK("non-CLOEXEC fixture prepared", prepared);
    if (prepared) {
        struct resident_receipt receipt;
        launch.log_stdio = true; launch.log_stdio_fd = borrowed;
        RL_CHECK("clear previous output", ftruncate(logfd, 0) == 0 && lseek(logfd, 0, SEEK_SET) == 0);
        bool spawned = resident_launch_spawn(&launch, argv, envp, &receipt, error, sizeof(error));
        RL_CHECK("child cannot inherit original log descriptor", spawned && rl_stdio_wait_log(logfd));
        RL_CHECK("borrowed parent fd and flags preserved", fcntl(borrowed, F_GETFD) == 0);
        if (spawned) RL_CHECK("non-CLOEXEC child reaped", resident_launch_cancel(&launch, 20, error, sizeof(error)) && rl_wait_reaped(receipt.pid));
        resident_launch_close(&launch);
    }
    close(borrowed);
    return failures;
}

static bool rl_stdio_parent_signals_unchanged(void)
{
    sigset_t current;
    struct sigaction after;
    return sigprocmask(SIG_SETMASK, NULL, &current) == 0 &&
        sigismember(&current, SIGTERM) == 1 &&
        sigaction(SIGPIPE, NULL, &after) == 0 && after.sa_handler == SIG_IGN;
}

static int rl_stdio_signal_child(const char *image, int logfd)
{
    sigset_t blocked;
    sigemptyset(&blocked); sigaddset(&blocked, SIGTERM);
    struct sigaction ignored = {.sa_handler = SIG_IGN};
    if (sigprocmask(SIG_BLOCK, &blocked, NULL) != 0 || sigaction(SIGPIPE, &ignored, NULL) != 0)
        return 1;
    struct resident_launch_accepted accepted;
    struct resident_launch launch; resident_launch_init(&launch);
    char error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    if (!rl_accept_of(image, &accepted) || !resident_launch_prepare(&launch, image, &accepted, error, sizeof(error))) return 1;
    char *const argv[] = { "rlc_child_v1", "--stdio-probe", "signals", NULL };
    char *const envp[] = { NULL };
    struct resident_receipt receipt;
    launch.log_stdio = true; launch.log_stdio_fd = logfd; launch.desktop_signals = true;
    bool cleared = ftruncate(logfd, 0) == 0 && lseek(logfd, 0, SEEK_SET) == 0;
    bool spawned = cleared && resident_launch_spawn(&launch, argv, envp, &receipt, error, sizeof(error));
    bool ok = spawned && rl_stdio_wait_log(logfd) && rl_stdio_parent_signals_unchanged();
    if (spawned) ok = resident_launch_cancel(&launch, 20, error, sizeof(error)) && rl_wait_reaped(receipt.pid) && ok;
    resident_launch_close(&launch);
    return ok ? 0 : 1;
}

static int rl_stdio_signals(const char *image, int logfd)
{
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) _exit(rl_stdio_signal_child(image, logfd));
    int status = 0;
    while (waitpid(child, &status, 0) < 0) if (errno != EINTR) return 1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 1;
}

static bool rl_stdio_capture_parent(struct stat parent[3], int flags[3])
{
    for (int i = 0; i < 3; ++i) {
        flags[i] = fcntl(i, F_GETFD);
        if (flags[i] < 0 || fstat(i, &parent[i]) != 0) return false;
    }
    return true;
}

static int rl_stdio_child(const char *directory)
{
    int failures = 0;
    const char *image = "build/fixtures/rlc_child_v1";
    char path[1024], error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    (void)snprintf(path, sizeof(path), "%s/stdio.log", directory);
    (void)close(3);
    int logfd = open(path, O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
    RL_CHECK("stdio test occupies IPC slot 3", logfd == RESIDENT_LAUNCH_CHILD_FD);
    if (logfd != RESIDENT_LAUNCH_CHILD_FD) { if (logfd >= 0) close(logfd); return failures + 1; }
    int fds_before = rl_open_fd_count();
    struct stat parent[3] = {0}; int flags[3];
    if (!rl_stdio_capture_parent(parent, flags)) { close(logfd); return failures + 1; }
    struct resident_launch_accepted accepted;
    struct resident_launch launch; resident_launch_init(&launch);
    bool prepared = rl_accept_of(image, &accepted) &&
        resident_launch_prepare(&launch, image, &accepted, error, sizeof(error));
    RL_CHECK("stdio fixture exact image prepared", prepared);
    if (!prepared) { close(logfd); return failures; }
    char *const argv[] = { "rlc_child_v1", "--stdio-probe", NULL };
    char *const envp[] = { NULL };
    struct resident_receipt receipt;
    launch.log_stdio = true;
    failures += rl_stdio_refusals(&launch, argv, envp, logfd, path);
    bool spawned = resident_launch_spawn(&launch, argv, envp, &receipt, error, sizeof(error));
    if (!spawned) fprintf(stderr, "resident stdio spawn: %s\n", error);
    RL_CHECK("stdio spawn retains exact image proof", spawned && receipt.pid > 0 &&
        (strcmp(receipt.mapped_proof, "fexecve_inode") == 0 ||
         strcmp(receipt.mapped_proof, "proc_exe_triple") == 0 ||
         strcmp(receipt.mapped_proof, "cdhash_suspended") == 0));
    RL_CHECK("stdout and stderr captured; stdin is EOF", spawned && rl_stdio_wait_log(logfd));
    RL_CHECK("parent standard descriptors unchanged", rl_stdio_unchanged(parent, flags));
    if (spawned) RL_CHECK("stdio child canceled and reaped", resident_launch_cancel(&launch, 20, error, sizeof(error)) && rl_wait_reaped(receipt.pid));
    resident_launch_close(&launch);
    RL_CHECK("borrowed log remains open", fcntl(logfd, F_GETFD) >= 0);
    RL_CHECK("stdio spawn closes temporary descriptors", rl_open_fd_count() == fds_before);
    failures += rl_stdio_no_inherited_log(image, logfd);
    RL_CHECK("desktop child signals reset and parent unchanged", rl_stdio_signals(image, logfd) == 0);
    for (int fd = 0; fd < 3; ++fd)
        RL_CHECK("closed standard descriptor refused", rl_stdio_closed_standard(image, logfd, fd) == 0);
    close(logfd);
    RL_CHECK("stdio log removed", unlink(path) == 0);
    return failures;
}

static int rl_stdio_checks(const char *directory)
{
    pid_t child = fork();
    if (child < 0) { perror("resident stdio test fork"); return 1; }
    if (child == 0) _exit(rl_stdio_child(directory) ? 1 : 0);
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno == EINTR) continue;
        return 1;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 1;
}

int test_resident_launch(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "resident_launch", "x");
    char fixture[512];
    (void)snprintf(fixture, sizeof(fixture), "%s/app.sh", dir);
    RL_CHECK("write executable fixture", rl_write_fixture(fixture));
    struct resident_launch_accepted accepted;
    RL_CHECK("capture the acceptance record",
             rl_accept_of(fixture, &accepted));
    failures += rl_refusal_checks(fixture, &accepted);
    failures += rl_codec_checks(fixture, &accepted);
    failures += rl_swap_refusal_checks(dir);
    failures += rl_cycle_checks();
    failures += rl_stdio_checks(dir);
    test_rm_rf(dir);
    { extern int resident_result_fragments_run(void);
      failures += resident_result_fragments_run(); }
    printf("resident_launch: %s (%d failure(s))\n",
           failures ? "FAIL" : "PASS", failures);
    return failures;
}
#endif /* POSIX */
