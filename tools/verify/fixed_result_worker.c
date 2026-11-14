/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * One test-fast non-LTO GCC14 result.c compiler worker speaking the
 * z23verify.fixed_result.v2 launch request and result packet. It holds no
 * signing key and makes no attestation decision. Production mode requires
 * the two installed UIDs and a read-only jail; local qualification mode
 * always reports ineligible. */
#define _GNU_SOURCE
#include "base/hex.h"
#include "base/serialize_le.h"
#include "platform/os_proc.h"
#include "sha3/sha3.h"
#include "verify/fixed_result_contract.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define LAUNCHER_UID 0u
#define COMPILER_UID ZCL_FR_COMPILER_UID
#define PROFILE "/etc/z23verify/fixed_result_fast.args"
#define SOURCE ZCL_FR_SOURCE
#define MAX_ARGS ZCL_FR_PROFILE_ARGC
#define MAX_PROFILE 65536u
#define MAX_REQUEST 8192u
#define MAX_PACKET 2048u

/* The only v2 environment (fixed_result_contract.h); main() refuses to
 * start if this table and the contract ever disagree. */
static char *const compiler_env[] = {
    "LC_ALL=C", "TZ=UTC", "TMPDIR=/tmp", "PATH=/usr/bin:/bin", NULL
};

static const char *refusal;
static volatile sig_atomic_t cancelled;

struct pinned_input {
    const char *path;
    const char *sha3;
};

static const struct pinned_input pinned_inputs[] = {
    {SOURCE, "f8a4357fa0cd51537c90b476512c18869a940fd6442a1f140baacec1367a923a"},
    {"platform/modules/base/include/base/result.h",
     "e92c831f3170655fd955fcc8ca3ec7d886c7b15416e4c9045822bc87029fdd68"},
    {"platform/modules/base/include/base/format_attribute.h",
     "1667ffb42ea55553d38f931037cae523dfe61cabe6ec8a1f7c78b3b6b960d9be"}
};

static void on_cancel(int sig)
{
    (void)sig;
    cancelled = 1;
}

static int fail(const char *why)
{
    fprintf(stderr, "fixed_result_worker_refuse=%s\n", why);
    return 2;
}

static bool target_ok(const char *target)
{
    return zcl_fr_target_check(target, strlen(target)) == NULL;
}

static bool cwd_ok(const char *cwd)
{
    if (cwd[0] != '/' || strlen(cwd) >= PATH_MAX) return false;
    char real[PATH_MAX], source[PATH_MAX];
    if (!realpath(cwd, real) || strcmp(real, cwd) != 0) return false;
    int n = snprintf(source, sizeof(source), "%s/%s", cwd, SOURCE);
    if (n < 0 || n >= (int)sizeof(source)) return false;
    struct stat st;
    return lstat(source, &st) == 0 && S_ISREG(st.st_mode) &&
           (st.st_mode & 0022) == 0;
}

static bool profile_bytes(const char *path, char bytes[MAX_PROFILE],
                          ssize_t *size)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) { refusal = "profile_missing"; return false; }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
        (st.st_mode & 0022) != 0 || st.st_size <= 0 ||
        st.st_size >= (off_t)MAX_PROFILE) {
        refusal = "profile_unsafe";
        close(fd);
        return false;
    }
    ssize_t got = read(fd, bytes, MAX_PROFILE);
    int close_result = close(fd);
    if (got != st.st_size || close_result != 0) {
        refusal = "profile_read_failed";
        return false;
    }
    struct sha3_256_ctx hash;
    uint8_t digest[32];
    char encoded[65];
    sha3_256_init(&hash);
    sha3_256_write(&hash, (const uint8_t *)bytes, (size_t)got);
    sha3_256_finalize(&hash, digest);
    zcl_hex_encode(digest, sizeof(digest), encoded);
    if (strcmp(encoded, ZCL_FR_PROFILE_SHA3) != 0) {
        refusal = "profile_digest_mismatch";
        return false;
    }
    if (bytes[got - 1] != '\n' || memchr(bytes, '\0', (size_t)got)) {
        refusal = "profile_malformed";
        return false;
    }
    bytes[got] = '\0';
    *size = got;
    return true;
}

static bool profile_lines(char bytes[MAX_PROFILE], ssize_t size,
                          char *args[MAX_ARGS + 1])
{
    size_t count = 0;
    char *line = bytes;
    for (ssize_t i = 0; i < size; i++) {
        if (bytes[i] != '\n') continue;
        bytes[i] = '\0';
        if (!*line || count == MAX_ARGS) {
            refusal = "profile_malformed";
            return false;
        }
        args[count++] = line;
        line = bytes + i + 1;
    }
    if (count != MAX_ARGS || strcmp(args[0], "cc") != 0) {
        refusal = "profile_shape_mismatch";
        return false;
    }
    args[count] = NULL;
    return true;
}

static bool profile_cwd(char *args[MAX_ARGS + 1], const char *cwd,
                        char expanded[PATH_MAX * 2])
{
    size_t replacements = 0;
    for (size_t i = 1; i < MAX_ARGS; i++) {
        char *tag = strstr(args[i], "@CWD@");
        if (!tag) continue;
        if (replacements++ != 0 || strstr(tag + 5, "@CWD@")) {
            refusal = "profile_placeholder_malformed";
            return false;
        }
        size_t head = (size_t)(tag - args[i]), tail = strlen(tag + 5);
        size_t need = head + strlen(cwd) + tail + 1;
        if (need > PATH_MAX * 2) {
            refusal = "profile_expansion_limit";
            return false;
        }
        memcpy(expanded, args[i], head);
        memcpy(expanded + head, cwd, strlen(cwd));
        memcpy(expanded + head + strlen(cwd), tag + 5, tail + 1);
        args[i] = expanded;
    }
    if (replacements != 1) {
        refusal = "profile_placeholder_malformed";
        return false;
    }
    return true;
}

static bool read_profile(const char *path, const char *cwd,
                         char bytes[MAX_PROFILE], char *args[MAX_ARGS + 1],
                         char expanded[PATH_MAX * 2])
{
    ssize_t size;
    if (!profile_bytes(path, bytes, &size) ||
        !profile_lines(bytes, size, args) ||
        !profile_cwd(args, cwd, expanded)) return false;
    return true;
}

static bool read_only_mount(const char *path)
{
    struct statvfs fs;
    return statvfs(path, &fs) == 0 && (fs.f_flag & ST_RDONLY) != 0;
}

static bool root_directory(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0 && S_ISDIR(st.st_mode) &&
           st.st_uid == 0 && (st.st_mode & 0022) == 0;
}

static bool profile_root_chain_ok(void)
{
    struct stat st;
    return root_directory("/") && root_directory("/etc") &&
           root_directory("/etc/z23verify") &&
           lstat(PROFILE, &st) == 0 && S_ISREG(st.st_mode) &&
           st.st_uid == 0 && st.st_nlink == 1 &&
           (st.st_mode & 0022) == 0;
}

static bool compiler_identity_ok(void)
{
    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;
    if (getresuid(&ruid, &euid, &suid) != 0 ||
        getresgid(&rgid, &egid, &sgid) != 0 ||
        ruid != COMPILER_UID || euid != COMPILER_UID ||
        suid != COMPILER_UID || rgid != COMPILER_UID ||
        egid != COMPILER_UID || sgid != COMPILER_UID ||
        getgroups(0, NULL) != 0 || prctl(PR_GET_NO_NEW_PRIVS) != 1 ||
        prctl(PR_GET_SECCOMP) != 2 ||
        !os_proc_unprivileged_no_capabilities()) {
        return false;
    }
    return true;
}

static bool jail_paths_ok(const char *cwd)
{
    return strcmp(cwd, "/zclassic23") == 0 &&
           read_only_mount(cwd) && read_only_mount("/usr") &&
           root_directory(cwd) && profile_root_chain_ok();
}

static bool installed_jail_ok(const char *cwd)
{
    if (!compiler_identity_ok()) {
        refusal = "compiler_uid_mismatch";
        return false;
    }
    if (!jail_paths_ok(cwd)) {
        refusal = "jail_mount_unverified";
        return false;
    }
    struct stat st;
    struct stat hidden;
    errno = 0;
    int key_seen = lstat("/var/lib/z23verify/key", &hidden);
    int key_error = errno;
    errno = 0;
    int store_seen = lstat("/var/lib/z23verify/store", &hidden);
    int store_error = errno;
    if (stat("/", &st) != 0 || st.st_uid != 0 ||
        (st.st_mode & 0022) != 0 ||
        key_seen == 0 || key_error != ENOENT ||
        store_seen == 0 || store_error != ENOENT) {
        refusal = "jail_root_unverified";
        return false;
    }
    return true;
}

static bool pinned_stat_ok(const struct stat *st, uid_t owner)
{
    return S_ISREG(st->st_mode) && st->st_uid == owner && st->st_nlink == 1 &&
           (st->st_mode & 0022) == 0 && st->st_size >= 0 &&
           st->st_size <= 1048576;
}

static bool pinned_stat_same(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_size == b->st_size &&
           a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
           a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
           a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
           a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

static bool pinned_file_ok(const char *path, const char *expected, uid_t owner)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) { refusal = "pinned_input_missing"; return false; }
    struct stat before, after;
    if (fstat(fd, &before) != 0 || !pinned_stat_ok(&before, owner)) {
        refusal = "pinned_input_unsafe";
        close(fd);
        return false;
    }
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    uint8_t buf[8192], digest[32];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0)
        sha3_256_write(&hash, buf, (size_t)n);
    bool stable = n == 0 && fstat(fd, &after) == 0 &&
                  pinned_stat_same(&before, &after);
    close(fd);
    if (!stable) { refusal = "pinned_input_changed"; return false; }
    sha3_256_finalize(&hash, digest);
    char actual[65];
    zcl_hex_encode(digest, sizeof(digest), actual);
    if (strcmp(actual, expected) != 0) {
        refusal = "pinned_input_digest_mismatch";
        return false;
    }
    return true;
}

static bool pinned_inputs_ok(bool installed)
{
    uid_t owner = installed ? 0 : getuid();
    for (size_t i = 0; i < sizeof(pinned_inputs) / sizeof(pinned_inputs[0]); i++)
        if (!pinned_file_ok(pinned_inputs[i].path, pinned_inputs[i].sha3,
                            owner)) return false;
    return true;
}

static bool monotonic_now(struct timespec *ts)
{
    return clock_gettime(CLOCK_MONOTONIC, ts) == 0; // platform-ok:standalone fixed-result worker has no platform clock link
}

static void gcc_args(char *args[MAX_ARGS + 16],
                     char *const profile[MAX_ARGS + 1], const char *target,
                     const char *out, const char *dep, bool preprocess)
{
    size_t n = 0;
    for (size_t i = 0; i < MAX_ARGS; i++) args[n++] = profile[i];
    args[n++] = "-MMD";
    args[n++] = "-MP";
    args[n++] = "-MF";
    args[n++] = (char *)dep;
    args[n++] = "-MT";
    args[n++] = (char *)target;
    /* GCC 14's raw -E stream otherwise starts with a physical-cwd marker.
     * The real strict -c argv stays exact; this checker-only flag removes
     * that marker. The pinned TU's cross-cwd object equality is tested. */
    if (preprocess) args[n++] = "-fno-working-directory";
    args[n++] = preprocess ? "-E" : "-c";
    args[n++] = "-o";
    args[n++] = (char *)out;
    args[n++] = SOURCE;
    args[n] = NULL;
}

/* Exec argv v2: SHA3-256 of F(exec_argv domain) then F("arg") F(arg). */
static bool argv_sha3(char *const args[MAX_ARGS + 16], uint8_t out[32])
{
    size_t count = 0;
    while (count < MAX_ARGS + 16 && args[count]) count++;
    if (count == MAX_ARGS + 16) return false;
    for (size_t i = 0; i < count; i++)
        if (strlen(args[i]) > PATH_MAX * 2) return false;
    return zcl_fr_exec_argv_sha3((const char *const *)args, count, out);
}

static pid_t start_gcc(char *const args[MAX_ARGS + 16], const char *err)
{
    int stderr_fd = open(err, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                         0600);
    if (stderr_fd < 0) { refusal = "stderr_open_failed"; return -1; }
    pid_t pid = fork();
    if (pid < 0) { close(stderr_fd); refusal = "compiler_fork_failed"; return -1; }
    if (pid == 0) {
        if (setpgid(0, 0) != 0) _exit(127);
        int nullfd = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (nullfd < 0 || dup2(nullfd, STDIN_FILENO) < 0 ||
            dup2(nullfd, STDOUT_FILENO) < 0 ||
            dup2(stderr_fd, STDERR_FILENO) < 0) _exit(127);
        if (close_range(3, ~0u, 0) != 0) _exit(127);
        execve("/usr/bin/cc", args, compiler_env);
        _exit(127);
    }
    close(stderr_fd);
    (void)setpgid(pid, pid);
    return pid;
}

static void stop_gcc(pid_t pid)
{
    (void)kill(-pid, SIGKILL);
    (void)kill(pid, SIGKILL);
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
}

static bool wait_gcc_loop(pid_t pid, const struct timespec *start, int *status)
{
    for (;;) {
        pid_t done = waitpid(pid, status, WNOHANG);
        if (done == pid) return true;
        if (done < 0 && errno != EINTR) {
            refusal = "compiler_wait_failed";
            return false;
        }
        struct timespec now;
        if (cancelled || !monotonic_now(&now) ||
            now.tv_sec - start->tv_sec >= 30) {
            refusal = cancelled ? "compiler_cancelled" : "compiler_deadline";
            return false;
        }
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};
        (void)nanosleep(&pause, NULL);
    }
}

static bool run_gcc(char *const profile[MAX_ARGS + 1], const char *target,
                    const char *out, const char *dep, const char *err,
                    bool preprocess, uint8_t digest[32])
{
    if (cancelled) { refusal = "compiler_cancelled"; return false; }
    char *args[MAX_ARGS + 16];
    gcc_args(args, profile, target, out, dep, preprocess);
    if (!argv_sha3(args, digest)) {
        refusal = "compiler_argv_malformed";
        return false;
    }
    pid_t pid = start_gcc(args, err);
    if (pid < 0) return false;
    struct timespec start;
    if (!monotonic_now(&start)) {
        stop_gcc(pid);
        refusal = "clock_unavailable";
        return false;
    }
    int status = 0;
    if (!wait_gcc_loop(pid, &start, &status)) { stop_gcc(pid); return false; }
    if (cancelled) { refusal = "compiler_cancelled"; return false; }
    if (!WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
        refusal = preprocess ? "preprocess_failed" : "compile_failed";
        return false;
    }
    return true;
}

static bool files_equal(const char *a, const char *b)
{
    int x = open(a, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    int y = open(b, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (x < 0 || y < 0) { if (x >= 0) close(x); if (y >= 0) close(y); return false; }
    struct stat sx, sy;
    bool same = fstat(x, &sx) == 0 && fstat(y, &sy) == 0 &&
                S_ISREG(sx.st_mode) && S_ISREG(sy.st_mode) &&
                sx.st_size == sy.st_size;
    char bx[8192], by[8192];
    while (same) {
        ssize_t nx = read(x, bx, sizeof(bx));
        ssize_t ny = read(y, by, sizeof(by));
        if (nx < 0 || ny != nx || (nx > 0 && memcmp(bx, by, (size_t)nx) != 0))
            same = false;
        if (nx <= 0) break;
    }
    close(x);
    close(y);
    return same;
}

static bool result_path(char out[PATH_MAX], const char *dir, const char *name)
{
    int n = snprintf(out, PATH_MAX, "%s/%s", dir, name);
    return n > 0 && n < PATH_MAX;
}

static bool output_paths(const char *outdir, char paths[4][PATH_MAX],
                         char pp_dep[PATH_MAX], char pp_err[PATH_MAX])
{
    return result_path(paths[0], outdir, "result.o") &&
           result_path(paths[1], outdir, "deps.d") &&
           result_path(paths[2], outdir, "stderr.bin") &&
           result_path(paths[3], outdir, "result.i") &&
           result_path(pp_dep, outdir, "preprocess.d") &&
           result_path(pp_err, outdir, "preprocess.stderr");
}

static bool compile_request_ok(const char *cwd, const char *target)
{
    if (cwd_ok(cwd) && target_ok(target)) return true;
    refusal = "request_profile_mismatch";
    return false;
}

static bool compile_one(const char *cwd, const char *target, const char *outdir,
                        bool installed, char paths[4][PATH_MAX],
                        uint8_t argv_hashes[2][32])
{
    if (!compile_request_ok(cwd, target)) return false;
    if (installed && !installed_jail_ok(cwd)) return false;
    char profile[MAX_PROFILE];
    char expanded[PATH_MAX * 2];
    char *args[MAX_ARGS + 1];
    if (!read_profile(installed ? PROFILE :
                      "tools/verify/fixed_result_fast.args", cwd,
                      profile, args, expanded)) return false;
    char pp_dep[PATH_MAX], pp_err[PATH_MAX];
    if (!output_paths(outdir, paths, pp_dep, pp_err)) {
        refusal = "output_path_limit";
        return false;
    }
    if (chdir(cwd) != 0) { refusal = "cwd_open_failed"; return false; }
    if (!pinned_inputs_ok(installed)) return false;
    if (!run_gcc(args, target, paths[3], pp_dep, pp_err, true,
                 argv_hashes[0])) return false;
    if (cancelled) { refusal = "compiler_cancelled"; return false; }
    if (!run_gcc(args, target, paths[0], paths[1], paths[2], false,
                 argv_hashes[1])) return false;
    if (!pinned_inputs_ok(installed)) return false;
    if (!files_equal(pp_dep, paths[1])) {
        refusal = "preprocess_dep_mismatch";
        return false;
    }
    if (cancelled) { refusal = "compiler_cancelled"; return false; }
    return true;
}

static bool request_peer_ok(void)
{
    struct ucred peer;
    socklen_t peer_len = sizeof(peer);
    if (getsockopt(STDIN_FILENO, SOL_SOCKET, SO_PEERCRED, &peer, &peer_len) != 0 ||
        peer_len != sizeof(peer) || peer.uid != LAUNCHER_UID) {
        refusal = "launcher_peer_mismatch";
        return false;
    }
    int socket_type = 0;
    socklen_t type_len = sizeof(socket_type);
    if (getsockopt(STDIN_FILENO, SOL_SOCKET, SO_TYPE,
                   &socket_type, &type_len) != 0 ||
        type_len != sizeof(socket_type) || socket_type != SOCK_SEQPACKET) {
        refusal = "request_socket_type";
        return false;
    }
    return true;
}

static bool receive_frame(uint8_t buffer[MAX_REQUEST], size_t *len)
{
    struct pollfd ready = {.fd = STDIN_FILENO, .events = POLLIN};
    if (poll(&ready, 1, 30000) != 1 || !(ready.revents & POLLIN) || cancelled) {
        refusal = cancelled ? "request_cancelled" : "request_deadline";
        return false;
    }
    ssize_t n = recv(STDIN_FILENO, buffer, MAX_REQUEST, MSG_TRUNC);
    if (n <= 0 || n >= MAX_REQUEST) {
        refusal = "request_frame_malformed";
        return false;
    }
    *len = (size_t)n;
    return true;
}

/* Launch request v2: profile test_fast, recorded_cwd /zclassic23 and one
 * epoch target. A v1 text request or any framing fault refuses by its
 * contract token. */
static bool receive_request(char target[ZCL_FR_TARGET_LEN + 1u])
{
    uint8_t buffer[MAX_REQUEST];
    size_t len = 0;
    const char *why = NULL;
    if (!request_peer_ok() || !receive_frame(buffer, &len)) return false;
    if (!zcl_fr_request_parse(buffer, len, target, &why)) {
        refusal = why;
        return false;
    }
    return true;
}

static bool open_result_fds(const char paths[4][PATH_MAX], int fd[4])
{
    for (size_t i = 0; i < 4; i++) {
        fd[i] = open(paths[i], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd[i] < 0) {
            for (size_t j = 0; j < i; j++) close(fd[j]);
            refusal = "artifact_open_failed";
            return false;
        }
        struct stat st;
        off_t limit = i == 0 ? 8 * 1024 * 1024 : 4 * 1024 * 1024;
        if (fstat(fd[i], &st) != 0 || !S_ISREG(st.st_mode) ||
            st.st_uid != COMPILER_UID || st.st_nlink != 1 ||
            (st.st_mode & 0022) != 0 || st.st_size < 0 ||
            st.st_size > limit || (i != 2 && st.st_size == 0)) {
            for (size_t j = 0; j <= i; j++) close(fd[j]);
            refusal = "artifact_unsafe";
            return false;
        }
    }
    return true;
}

/* Result packet v2 plus the four artifact FDs in canonical order: object.o,
 * deps.d, stderr.bin, preprocessed.i. */
static bool send_result(const char paths[4][PATH_MAX], const char *scratch,
                        const char *target, const uint8_t hashes[2][32])
{
    struct zcl_fr_packet packet;
    uint8_t frame[MAX_PACKET];
    size_t used = 0;
    const char *why = NULL;
    memset(&packet, 0, sizeof(packet));
    if (strlen(scratch) != ZCL_FR_SCRATCH_LEN ||
        strlen(target) != ZCL_FR_TARGET_LEN) {
        refusal = "artifact_frame_limit";
        return false;
    }
    memcpy(packet.scratch, scratch, ZCL_FR_SCRATCH_LEN);
    memcpy(packet.target, target, ZCL_FR_TARGET_LEN);
    memcpy(packet.compile_argv_sha3, hashes[1], 32u);
    memcpy(packet.preprocess_argv_sha3, hashes[0], 32u);
    zcl_fr_env_fixed_root(packet.environment_sha3);
    if (!zcl_fr_packet_encode(&packet, frame, sizeof(frame), &used, &why)) {
        refusal = why;
        return false;
    }
    int fd[4];
    if (!open_result_fds(paths, fd)) return false;
    struct iovec io = {.iov_base = frame, .iov_len = used};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(fd))]; } control = {0};
    struct msghdr msg = {.msg_iov = &io, .msg_iovlen = 1,
                         .msg_control = control.bytes,
                         .msg_controllen = sizeof(control.bytes)};
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(fd));
    memcpy(CMSG_DATA(c), fd, sizeof(fd));
    bool ok = sendmsg(STDIN_FILENO, &msg, MSG_NOSIGNAL) == (ssize_t)used;
    for (size_t i = 0; i < 4; i++) close(fd[i]);
    if (!ok) refusal = "artifact_send_failed";
    return ok;
}

static bool wait_launcher_ack(void)
{
    struct pollfd ready = {.fd = STDIN_FILENO, .events = POLLIN};
    if (poll(&ready, 1, 30000) != 1 || !(ready.revents & POLLIN) ||
        (ready.revents & (POLLHUP | POLLERR | POLLNVAL)) || cancelled) {
        refusal = cancelled ? "launcher_ack_cancelled" : "launcher_ack_deadline";
        return false;
    }
    char byte[2] = {0};
    char control[CMSG_SPACE(sizeof(int))] = {0};
    struct iovec io = {.iov_base = byte, .iov_len = sizeof(byte)};
    struct msghdr msg = {.msg_iov = &io, .msg_iovlen = 1,
                         .msg_control = control,
                         .msg_controllen = sizeof(control)};
    ssize_t n = recvmsg(STDIN_FILENO, &msg, MSG_TRUNC);
    if (n != 1 || byte[0] != 'A' || (msg.msg_flags & ~MSG_EOR) != 0 ||
        msg.msg_controllen != 0 || cancelled) {
        refusal = "launcher_ack_invalid";
        return false;
    }
    return true;
}

static void cleanup_scratch(const char *dir)
{
    static const char *const names[] = {
        "result.o", "deps.d", "stderr.bin", "result.i",
        "preprocess.d", "preprocess.stderr"
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        char path[PATH_MAX];
        if (result_path(path, dir, names[i])) (void)unlink(path);
    }
    (void)rmdir(dir);
}

static int qualify_main(char **argv)
{
    char paths[4][PATH_MAX];
    uint8_t argv_hashes[2][32];
    if (!compile_one(argv[2], argv[3], argv[4], false, paths, argv_hashes))
        return fail(refusal ? refusal : "qualification_failed");
    printf("object=%s\ndep=%s\nstderr=%s\npreprocessed=%s\n"
           "compiler_launches=1 preprocess_launches=1 "
           "proof_launches_avoided=0 attest_eligible=0\n",
           paths[0], paths[1], paths[2], paths[3]);
    return 0;
}

static int serve_main(void)
{
    if (close_range(3, ~0u, 0) != 0)
        return fail("inherited_fd_close_failed");
    char target[ZCL_FR_TARGET_LEN + 1u];
    if (!receive_request(target)) return fail(refusal);
    char scratch[] = "/work/result.XXXXXX";
    if (!mkdtemp(scratch)) return fail("scratch_unavailable");
    char paths[4][PATH_MAX];
    uint8_t argv_hashes[2][32];
    if (!compile_one(ZCL_FR_CWD, target, scratch, true, paths, argv_hashes)) {
        cleanup_scratch(scratch);
        return fail(refusal ? refusal : "compile_failed");
    }
    if (cancelled) {
        cleanup_scratch(scratch);
        return fail("worker_cancelled");
    }
    bool sent = send_result(paths, scratch, target, argv_hashes);
    if (sent) sent = wait_launcher_ack();
    cleanup_scratch(scratch);
    if (!sent) return fail(refusal);
    if (cancelled) return fail("worker_cancelled_after_send");
    return 0;
}

int main(int argc, char **argv)
{
    umask(0077);
    struct sigaction action = {.sa_handler = on_cancel};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) != 0 ||
        sigaction(SIGINT, &action, NULL) != 0)
        return fail("signal_setup_failed");
    if (zcl_fr_env_check((const char *const *)compiler_env, 4u) != NULL)
        return fail(ZCL_FR_WHY_ENV);
    if (argc == 5 && strcmp(argv[1], "qualify") == 0)
        return qualify_main(argv);
    if (argc == 2 && strcmp(argv[1], "serve") == 0)
        return serve_main();
    return fail("request_shape_unsupported");
}
