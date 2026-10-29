/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the defensive path-input checkers
 * (platform/modules/util/src/path_check.c).
 *
 * Both helpers are pure: deterministic, no I/O, no global state. So
 * tests are simple table-driven assertions. */

/* realpath() needs __USE_MISC; -D_POSIX_C_SOURCE=200809L alone does not
 * declare it. */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "test/test_core.h"
#include "net/https_frontdoor.h"
#include "net/https_server.h"
#include "platform/time_compat.h"
#include "util/file_io.h"
#include "util/path_check.h"
#include <errno.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/socket.h>
#endif
#include <sys/stat.h>
#include <unistd.h>

#if defined(_WIN32)
#include "platform/socket_compat.h"

#include <stdint.h>

#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 1
#endif
#ifndef SHUT_WR
#define SHUT_WR SD_SEND
#endif

/* Fixture peer sockets held as int fds; socketpair becomes the verified
 * loopback-TCP pair, dup() a WSADuplicateSocketW in-process duplicate, and
 * the I/O verbs the platform socket calls. Every close()/dup() in this TU
 * targets one of those sockets. */
static int pc_socketpair(int sv[2])
{
    platform_socket_t pair[2];
    if (!platform_socket_pair(pair))
        return -1;
    sv[0] = (int)(intptr_t)pair[0];
    sv[1] = (int)(intptr_t)pair[1];
    return 0;
}

static int pc_dup(int fd)
{
    WSAPROTOCOL_INFOW info;
    if (WSADuplicateSocketW((platform_socket_t)(intptr_t)fd,
                            GetCurrentProcessId(), &info) != 0)
        return -1;
    platform_socket_t s = WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO,
                                     FROM_PROTOCOL_INFO, &info, 0, 0);
    return s == PLATFORM_SOCKET_INVALID ? -1 : (int)(intptr_t)s;
}

static ssize_t pc_recv(int fd, void *buf, size_t len, int flags)
{
    platform_socket_t sock = (platform_socket_t)(intptr_t)fd;
    if (flags == MSG_DONTWAIT)
        return platform_socket_receive_nonblocking(sock, buf, len);
    return platform_socket_receive(sock, buf, len);
}

static ssize_t pc_send(int fd, const void *buf, size_t len, int flags)
{
    (void)flags;
    return platform_socket_send((platform_socket_t)(intptr_t)fd, buf, len);
}

#define socketpair(domain, type, protocol, sv) pc_socketpair(sv)
#define dup(fd) pc_dup(fd)
#define recv(fd, buf, len, flags) pc_recv(fd, buf, len, flags)
#define send(fd, buf, len, flags) pc_send(fd, buf, len, flags)
#define close(fd) \
    (platform_socket_close((platform_socket_t)(intptr_t)(fd)) == 0 ? 0 : -1)
#define shutdown(fd, how) shutdown((platform_socket_t)(intptr_t)(fd), how)
#endif

#define PC_CHECK(name, expr) do { \
    printf("path_check: %s... ", (name)); \
    if ((expr)) printf("OK\n");           \
    else { printf("FAIL\n"); failures++; } \
} while (0)

int file_io_stream_retirement_cases(void);
int file_io_short_read_retirement_cases(void);

static bool write_small_file(const char *path, const char *body)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = fputs(body, f) >= 0;
    fclose(f);
    return ok;
}

struct https_deadline_script {
    const char *bytes;
    size_t pos;
    _Atomic unsigned clock_reads;
};

static int https_deadline_script_read(void *opaque, char *c)
{
    struct https_deadline_script *script = opaque;
    if (!script->bytes[script->pos])
        return 0;
    *c = script->bytes[script->pos++];
    return 1;
}

static int64_t https_deadline_monotonic_us(void *opaque)
{
    struct https_deadline_script *script = opaque;
    unsigned read = atomic_fetch_add_explicit(&script->clock_reads, 1,
                                               memory_order_relaxed);
    return (int64_t)(read + 1u) * 1000000LL;
}

static int64_t https_deadline_wall_unix(void *opaque)
{
    (void)opaque;
    return 1;
}

struct https_fixed_clock {
    _Atomic int64_t monotonic_us;
};

static int64_t https_fixed_monotonic_us(void *opaque)
{
    struct https_fixed_clock *clock = opaque;
    return atomic_load_explicit(&clock->monotonic_us, memory_order_relaxed);
}

static int64_t https_fixed_wall_unix(void *opaque)
{
    (void)opaque;
    return 1;
}

static bool https_queue_push_fd(struct https_frontdoor_queue *queue, int fd,
                                int64_t deadline_ms)
{
    struct https_frontdoor_client client = {
        .fd = fd,
        .tls = false,
        .deadline_ms = deadline_ms,
    };
    return https_frontdoor_queue_push(queue, &client);
}

static int path_check_node_db_path_cases(void)
{
    int failures = 0;

    /* ── zcl_node_db_path: canonical node.db path helper ─────── */
    {
        char db_path[64];
        PC_CHECK("node_db_path builds under datadir",
            strcmp(zcl_node_db_path(db_path, sizeof(db_path), "/tmp/zcl"),
                   "/tmp/zcl/node.db") == 0 &&
            strcmp(db_path, "/tmp/zcl/node.db") == 0);
        PC_CHECK("node_db_path rejects NULL buffer",
            strcmp(zcl_node_db_path(NULL, sizeof(db_path), "/tmp/zcl"), "") == 0);
        PC_CHECK("node_db_path rejects zero buffer",
            strcmp(zcl_node_db_path(db_path, 0, "/tmp/zcl"), "") == 0);
        PC_CHECK("node_db_path rejects NULL datadir",
            strcmp(zcl_node_db_path(db_path, sizeof(db_path), NULL), "") == 0);
    }
    return failures;
}

static int https_slow_drip_deadline_case(void)
{
    int failures = 0;

    /* One front-door budget spans every byte, even when each individual
     * read makes progress before the socket inactivity timeout. */
    {
        struct https_deadline_script script = {
            .bytes = "abcdef\n",
        };
        struct platform_clock_source source = {
            .monotonic_us = https_deadline_monotonic_us,
            .wall_unix = https_deadline_wall_unix,
            .user = &script,
        };
        char line[32];
        platform_clock_set_source(&source);
        bool accepted = https_frontdoor_read_line(
            &script, https_deadline_script_read, line, sizeof(line), 5000);
        platform_clock_clear_source();
        PC_CHECK("https line reader rejects slow drip at absolute deadline",
                 !accepted && script.pos == 4 &&
                 atomic_load_explicit(&script.clock_reads,
                                      memory_order_relaxed) == 5);
    }
    return failures;
}

struct https_queue_expiry_fx {
    struct https_fixed_clock clock;
    struct platform_clock_source source;
    int expired_pair[2];
    int replacement_pair[2];
    int first_fd;
    bool first_owned;
    bool expired_owned;
    bool replacement_owned;
    bool queue_ready;
    struct https_frontdoor_queue queue;
};

static void https_queue_expiry_fill_to_cap(struct https_queue_expiry_fx *fx)
{
    for (size_t i = 2; fx->queue_ready &&
         i < HTTPS_FRONTDOOR_QUEUE_CAP; i++) {
        int fd = dup(fx->replacement_pair[1]);
        if (fd < 0 || !https_queue_push_fd(&fx->queue, fd, 2000)) {
            if (fd >= 0)
                close(fd);
            fx->queue_ready = false;
        }
    }
}

static void https_queue_expiry_fill(struct https_queue_expiry_fx *fx)
{
    fx->queue_ready = socketpair(AF_UNIX, SOCK_STREAM, 0,
                                 fx->expired_pair) == 0 &&
                      socketpair(AF_UNIX, SOCK_STREAM, 0,
                                 fx->replacement_pair) == 0;
    platform_clock_set_source(&fx->source);
    if (fx->queue_ready) {
        fx->first_fd = dup(fx->replacement_pair[1]);
        fx->first_owned = fx->first_fd >= 0 &&
            https_queue_push_fd(&fx->queue, fx->first_fd, 2000);
        if (fx->first_owned)
            fx->expired_owned =
                https_queue_push_fd(&fx->queue, fx->expired_pair[0], 500);
        fx->queue_ready = fx->first_owned && fx->expired_owned;
    }
    https_queue_expiry_fill_to_cap(fx);
}

static int https_queue_expiry_observe(struct https_queue_expiry_fx *fx)
{
    int failures = 0;
    atomic_store_explicit(&fx->clock.monotonic_us, 1000000,
                          memory_order_relaxed);
    fx->replacement_owned = fx->queue_ready &&
        https_queue_push_fd(&fx->queue, fx->replacement_pair[0], 2000);
    struct https_frontdoor_client popped = {.fd = -1};
    bool fifo_preserved = fx->replacement_owned &&
        https_frontdoor_queue_pop(&fx->queue, &popped) &&
        (int)(intptr_t)popped.fd == fx->first_fd && !popped.tls &&
        popped.deadline_ms == 2000;
    char byte = 0;
    bool expired_closed = fx->replacement_owned &&
        recv(fx->expired_pair[1], &byte, 1, MSG_DONTWAIT) == 0;
    PC_CHECK("https queue reclaims out-of-order expiry and preserves FIFO",
             fifo_preserved && expired_closed);
    if ((int)(intptr_t)popped.fd >= 0)
        close(popped.fd);
    https_frontdoor_queue_close_all(&fx->queue);
    platform_clock_clear_source();
    return failures;
}

static void https_queue_expiry_release(struct https_queue_expiry_fx *fx)
{
    if (!fx->first_owned && fx->first_fd >= 0)
        close(fx->first_fd);
    if (!fx->expired_owned && fx->expired_pair[0] >= 0)
        close(fx->expired_pair[0]);
    if (!fx->replacement_owned && fx->replacement_pair[0] >= 0)
        close(fx->replacement_pair[0]);
    if (fx->expired_pair[1] >= 0)
        close(fx->expired_pair[1]);
    if (fx->replacement_pair[1] >= 0)
        close(fx->replacement_pair[1]);
}

static int https_queue_out_of_order_expiry_case(void)
{
    /* Listener threads can stamp deadlines in one order but reach the shared
     * queue in another. A full queue must reclaim every expired descriptor,
     * not merely an expired prefix, while retaining live FIFO order. */
    struct https_queue_expiry_fx fx = {
        .clock = {.monotonic_us = 100000},
        .expired_pair = {-1, -1},
        .replacement_pair = {-1, -1},
        .first_fd = -1,
        .first_owned = false,
        .expired_owned = false,
        .replacement_owned = false,
        .queue_ready = false,
    };
    fx.source = (struct platform_clock_source){
        .monotonic_us = https_fixed_monotonic_us,
        .wall_unix = https_fixed_wall_unix,
        .user = &fx.clock,
    };
    https_queue_expiry_fill(&fx);
    int failures = https_queue_expiry_observe(&fx);
    https_queue_expiry_release(&fx);
    return failures;
}

static int https_incomplete_headers_case(void)
{
    int failures = 0;

    /* A peer closing before the blank line cannot turn a partial request into
     * an explorer response. The handler owns and closes the accepted fd. */
    {
        struct https_fixed_clock clock = {.monotonic_us = 1000000};
        struct platform_clock_source source = {
            .monotonic_us = https_fixed_monotonic_us,
            .wall_unix = https_fixed_wall_unix,
            .user = &clock,
        };
        int pair[2] = {-1, -1};
        bool ready = socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0;
        const char request[] = "GET / HTTP/1.1\r\nHost: example.test\r\n";
        if (ready)
            ready = send(pair[1], request, sizeof(request) - 1, 0) ==
                    (ssize_t)(sizeof(request) - 1) &&
                    shutdown(pair[1], SHUT_WR) == 0;
        platform_clock_set_source(&source);
        if (ready)
            https_server_handle_http_for_testing(pair[0], 2000);
        platform_clock_clear_source();
        char response = 0;
        bool refused = ready && recv(pair[1], &response, 1, 0) == 0;
        PC_CHECK("https plaintext handler refuses incomplete headers",
                 refused);
        if (!ready && pair[0] >= 0)
            close(pair[0]);
        if (pair[1] >= 0)
            close(pair[1]);
    }
    return failures;
}

static int https_acme_redirect_containment_cases(void)
{
    int failures = 0;

    /* ── ACME redirect passthrough containment ───────────────── */
    {
        char dir[256];
        char root[PATH_MAX];
        char token_path[PATH_MAX];
        char outside_path[PATH_MAX];
        char link_path[PATH_MAX];
        char out[PATH_MAX];
        char real_token[PATH_MAX];

        test_make_tmpdir(dir, sizeof(dir), "path_check", "acme");
        snprintf(root, sizeof(root), "%s/acme", dir);
        PC_CHECK("acme root mkdir", mkdir(root, 0700) == 0);

        snprintf(token_path, sizeof(token_path), "%s/token", root);
        PC_CHECK("acme token fixture",
                 write_small_file(token_path, "challenge"));
        PC_CHECK("acme resolver accepts token",
                 realpath(token_path, real_token) &&
                 https_server_acme_challenge_filepath_for_testing(
                     root, "/.well-known/acme-challenge/token",
                     out, sizeof(out)) &&
                 strcmp(out, real_token) == 0);

        PC_CHECK("acme resolver rejects traversal segment",
                 !https_server_acme_challenge_filepath_for_testing(
                     root, "/.well-known/acme-challenge/../token",
                     out, sizeof(out)));
        PC_CHECK("acme resolver rejects empty challenge token",
                 !https_server_acme_challenge_filepath_for_testing(
                     root, "/.well-known/acme-challenge/",
                     out, sizeof(out)));

        snprintf(outside_path, sizeof(outside_path), "%s/outside", dir);
        snprintf(link_path, sizeof(link_path), "%s/link", root);
        PC_CHECK("acme outside fixture",
                 write_small_file(outside_path, "outside") &&
                 symlink("../outside", link_path) == 0);
        PC_CHECK("acme resolver rejects symlink escape",
                 !https_server_acme_challenge_filepath_for_testing(
                     root, "/.well-known/acme-challenge/link",
                     out, sizeof(out)));

        test_cleanup_tmpdir(dir);
    }
    return failures;
}

static int https_public_install_jail_cases(void)
{
    int failures = 0;

    /* ── public-install path jail ────────────────────────────── */
    {
        char dir[256];
        char root[PATH_MAX];
        char shim_path[PATH_MAX];
        char boot_dir[PATH_MAX];
        char boot_path[PATH_MAX];
        char outside_path[PATH_MAX];
        char link_path[PATH_MAX];
        char out[PATH_MAX];
        char real_shim[PATH_MAX];

        test_make_tmpdir(dir, sizeof(dir), "path_check", "pubinst");
        snprintf(root, sizeof(root), "%s/public-install", dir);
        PC_CHECK("public-install root mkdir", mkdir(root, 0700) == 0);
        snprintf(shim_path, sizeof(shim_path), "%s/install.sh", root);
        PC_CHECK("public-install shim fixture",
                 write_small_file(shim_path, "#!/bin/sh\n"));
        PC_CHECK("GET / maps to install.sh",
                 realpath(shim_path, real_shim) &&
                 https_server_public_install_filepath_for_testing(
                     root, "/", out, sizeof(out)) &&
                 strcmp(out, real_shim) == 0);
        PC_CHECK("GET /install.sh maps to the same shim",
                 https_server_public_install_filepath_for_testing(
                     root, "/install.sh", out, sizeof(out)) &&
                 strcmp(out, real_shim) == 0);
        PC_CHECK("GET /explorer is not a public-install URL",
                 !https_server_public_install_filepath_for_testing(
                     root, "/explorer", out, sizeof(out)));
        PC_CHECK("traversal segment is refused",
                 !https_server_public_install_filepath_for_testing(
                     root, "/release/../install.sh", out, sizeof(out)));

        snprintf(boot_dir, sizeof(boot_dir), "%s/bootstrap/linux-x86_64",
                 root);
        PC_CHECK("bootstrap dir mkdir",
                 mkdir(root, 0700) == 0 || errno == EEXIST);
        {
            char parent[PATH_MAX];
            snprintf(parent, sizeof(parent), "%s/bootstrap", root);
            PC_CHECK("bootstrap parent mkdir", mkdir(parent, 0700) == 0);
            PC_CHECK("bootstrap platform mkdir", mkdir(boot_dir, 0700) == 0);
        }
        snprintf(boot_path, sizeof(boot_path), "%s/z23-bootstrap", boot_dir);
        PC_CHECK("bootstrap fixture",
                 write_small_file(boot_path, "bootstrap"));
        PC_CHECK("GET /bootstrap/linux-x86_64/z23-bootstrap maps",
                 https_server_public_install_filepath_for_testing(
                     root, "/bootstrap/linux-x86_64/z23-bootstrap",
                     out, sizeof(out)));

        snprintf(outside_path, sizeof(outside_path), "%s/outside", dir);
        snprintf(link_path, sizeof(link_path), "%s/install.sh", root);
        PC_CHECK("public-install outside fixture",
                 write_small_file(outside_path, "outside") &&
                 remove(link_path) == 0 &&
                 symlink("../outside", link_path) == 0);
        PC_CHECK("public-install rejects symlink escape on GET /",
                 !https_server_public_install_filepath_for_testing(
                     root, "/", out, sizeof(out)));

        test_cleanup_tmpdir(dir);
    }
    return failures;
}

/* The public-install mapping refuses every input it cannot place under the
 * root before it reaches the disk, and a too-small output buffer is a
 * refusal, not a truncated path. */
static int https_public_install_refusal_cases(void)
{
    int failures = 0;
    char dir[256];
    char root[PATH_MAX];
    char plain[PATH_MAX];
    char missing_root[PATH_MAX];
    char shim_path[PATH_MAX];
    char shim_real[PATH_MAX];
    char out[PATH_MAX];

    test_make_tmpdir(dir, sizeof(dir), "path_check", "pubinst_refuse");
    snprintf(root, sizeof(root), "%s/public-install", dir);
    snprintf(plain, sizeof(plain), "%s/plainfile", dir);
    snprintf(missing_root, sizeof(missing_root), "%s/no-such-root", dir);
    snprintf(shim_path, sizeof(shim_path), "%s/install.sh", root);
    PC_CHECK("refusal fixture: root mkdir", mkdir(root, 0700) == 0);
    PC_CHECK("refusal fixture: install.sh",
             write_small_file(shim_path, "#!/bin/sh\n"));
    PC_CHECK("refusal fixture: plain file",
             write_small_file(plain, "not a directory"));
    PC_CHECK("refusal fixture: shim realpath",
             realpath(shim_path, shim_real) != NULL);

    PC_CHECK("refusal: NULL root",
             !https_server_public_install_filepath_for_testing(
                 NULL, "/", out, sizeof(out)));
    PC_CHECK("refusal: empty root",
             !https_server_public_install_filepath_for_testing(
                 "", "/", out, sizeof(out)));
    PC_CHECK("refusal: NULL url",
             !https_server_public_install_filepath_for_testing(
                 root, NULL, out, sizeof(out)));
    PC_CHECK("refusal: NULL output buffer",
             !https_server_public_install_filepath_for_testing(
                 root, "/", NULL, sizeof(out)));
    PC_CHECK("refusal: zero-length output buffer",
             !https_server_public_install_filepath_for_testing(
                 root, "/", out, 0));
    PC_CHECK("refusal: bare /bootstrap/ names no file",
             !https_server_public_install_filepath_for_testing(
                 root, "/bootstrap/", out, sizeof(out)));
    PC_CHECK("refusal: bare /release/ names no file",
             !https_server_public_install_filepath_for_testing(
                 root, "/release/", out, sizeof(out)));
    PC_CHECK("refusal: missing root directory",
             !https_server_public_install_filepath_for_testing(
                 missing_root, "/", out, sizeof(out)));
    PC_CHECK("refusal: root that is a regular file",
             !https_server_public_install_filepath_for_testing(
                 plain, "/", out, sizeof(out)));
    PC_CHECK("refusal: output one byte short of the path",
             !https_server_public_install_filepath_for_testing(
                 root, "/", out, strlen(shim_real)));
    PC_CHECK("exact-size output buffer accepts the same path",
             https_server_public_install_filepath_for_testing(
                 root, "/", out, strlen(shim_real) + 1) &&
             strcmp(out, shim_real) == 0);

    test_cleanup_tmpdir(dir);
    return failures;
}

/* Builds "/release/" followed by ten 200-byte directory segments and a
 * name_len-byte file name, so the URL length is 2019 + name_len. */
static void build_cap_url(char *url, size_t name_len)
{
    size_t len = strlen("/release/");

    memcpy(url, "/release/", len);
    for (int i = 0; i < 10; i++) {
        memset(url + len, 'a', 200);
        len += 200;
        url[len++] = '/';
    }
    memset(url + len, 'f', name_len);
    url[len + name_len] = '\0';
}

/* Creates every directory the URL names below root, then the file itself. */
static bool make_url_file(const char *root, const char *url)
{
    char path[PATH_MAX];
    const char *slash = url;
    int n;

    while ((slash = strchr(slash + 1, '/')) != NULL) {
        n = snprintf(path, sizeof(path), "%s%.*s", root,
                     (int)(slash - url), url);
        if (n < 0 || (size_t)n >= sizeof(path))
            return false;
        if (mkdir(path, 0700) != 0 && errno != EEXIST)
            return false;
    }
    n = snprintf(path, sizeof(path), "%s%s", root, url);
    if (n < 0 || (size_t)n >= sizeof(path))
        return false;
    return write_small_file(path, "routed");
}

/* Each refusal here names a file that exists, so realpath() cannot be the
 * reason for the refusal: only the control-byte check or the URL length cap
 * can refuse it. The exact-cap URL proves the boundary is 2047 bytes. */
static int https_public_install_routed_refusal_cases(void)
{
    int failures = 0;
    char dir[256];
    char root[PATH_MAX];
    char ctrl_url[32];
    char cap_ok[2049];
    char cap_over[2049];
    char cap_path[PATH_MAX];
    char cap_real[PATH_MAX];
    char out[PATH_MAX];

    test_make_tmpdir(dir, sizeof(dir), "path_check", "pubinst_routed");
    snprintf(root, sizeof(root), "%s/public-install", dir);
    snprintf(ctrl_url, sizeof(ctrl_url), "/release/x\x01y");
    build_cap_url(cap_ok, 28);
    build_cap_url(cap_over, 29);
    PC_CHECK("routed fixture: root mkdir", mkdir(root, 0700) == 0);
    PC_CHECK("routed fixture: control-byte file",
             make_url_file(root, ctrl_url));
    PC_CHECK("routed fixture: 2047-byte file", make_url_file(root, cap_ok));
    PC_CHECK("routed fixture: 2048-byte file", make_url_file(root, cap_over));
    snprintf(cap_path, sizeof(cap_path), "%s%s", root, cap_ok);
    PC_CHECK("routed fixture: 2047-byte realpath",
             realpath(cap_path, cap_real) != NULL);

    PC_CHECK("refusal: control byte in a routed URL with an existing file",
             !https_server_public_install_filepath_for_testing(
                 root, ctrl_url, out, sizeof(out)));
    PC_CHECK("refusal: routed URL of 2048 bytes is over the 2047 cap",
             !https_server_public_install_filepath_for_testing(
                 root, cap_over, out, sizeof(out)));
    PC_CHECK("routed URL of exactly 2047 bytes is accepted",
             https_server_public_install_filepath_for_testing(
                 root, cap_ok, out, sizeof(out)) &&
             strcmp(out, cap_real) == 0);

    test_cleanup_tmpdir(dir);
    return failures;
}

/* A URL maps to the file it names, a directory maps as a directory (the
 * server's regular-file check is what refuses it), and an absent file under
 * the root is refused. */
static int https_public_install_mapping_cases(void)
{
    int failures = 0;
    char dir[256];
    char root[PATH_MAX];
    char empty_root[PATH_MAX];
    char script_path[PATH_MAX];
    char script_real[PATH_MAX];
    char release[PATH_MAX];
    char tar_path[PATH_MAX];
    char tar_real[PATH_MAX];
    char sub[PATH_MAX];
    char sub_real[PATH_MAX];
    char out[PATH_MAX];

    test_make_tmpdir(dir, sizeof(dir), "path_check", "pubinst_map");
    snprintf(root, sizeof(root), "%s/public-install", dir);
    snprintf(empty_root, sizeof(empty_root), "%s/empty-install", dir);
    snprintf(script_path, sizeof(script_path), "%s/install_z23.sh", root);
    snprintf(release, sizeof(release), "%s/release", root);
    snprintf(tar_path, sizeof(tar_path), "%s/z23.tar.gz", release);
    snprintf(sub, sizeof(sub), "%s/sub", release);
    PC_CHECK("mapping fixture: root mkdir", mkdir(root, 0700) == 0);
    PC_CHECK("mapping fixture: empty root mkdir",
             mkdir(empty_root, 0700) == 0);
    PC_CHECK("mapping fixture: release mkdir", mkdir(release, 0700) == 0);
    PC_CHECK("mapping fixture: release subdirectory", mkdir(sub, 0700) == 0);
    PC_CHECK("mapping fixture: install_z23.sh",
             write_small_file(script_path, "#!/bin/sh\n"));
    PC_CHECK("mapping fixture: release tarball",
             write_small_file(tar_path, "tarball"));

    PC_CHECK("GET /install_z23.sh maps to its own file",
             realpath(script_path, script_real) != NULL &&
             https_server_public_install_filepath_for_testing(
                 root, "/install_z23.sh", out, sizeof(out)) &&
             strcmp(out, script_real) == 0);
    PC_CHECK("GET /release/z23.tar.gz maps to the release file",
             realpath(tar_path, tar_real) != NULL &&
             https_server_public_install_filepath_for_testing(
                 root, "/release/z23.tar.gz", out, sizeof(out)) &&
             strcmp(out, tar_real) == 0);
    PC_CHECK("GET /release/sub maps to the directory itself",
             realpath(sub, sub_real) != NULL &&
             https_server_public_install_filepath_for_testing(
                 root, "/release/sub", out, sizeof(out)) &&
             strcmp(out, sub_real) == 0);
    PC_CHECK("GET / under an empty root names no file",
             !https_server_public_install_filepath_for_testing(
                 empty_root, "/", out, sizeof(out)));
    PC_CHECK("GET /install.sh under an empty root names no file",
             !https_server_public_install_filepath_for_testing(
                 empty_root, "/install.sh", out, sizeof(out)));
    PC_CHECK("GET /install_z23.sh under an empty root names no file",
             !https_server_public_install_filepath_for_testing(
                 empty_root, "/install_z23.sh", out, sizeof(out)));
    PC_CHECK("GET /release/z23.tar.gz under an empty root names no file",
             !https_server_public_install_filepath_for_testing(
                 empty_root, "/release/z23.tar.gz", out, sizeof(out)));

    test_cleanup_tmpdir(dir);
    return failures;
}

/* Points `link` at `target`, replacing any earlier link; false when the
 * symlink could not be made. */
static bool pi_relink(const char *link, const char *target)
{
    (void)remove(link);
    return symlink(target, link) == 0;
}

static bool pi_maps_to(const char *root, const char *url, const char *want)
{
    char out[PATH_MAX];

    return https_server_public_install_filepath_for_testing(
               root, url, out, sizeof(out)) &&
           strcmp(out, want) == 0;
}

static bool pi_refused(const char *root, const char *url)
{
    char out[PATH_MAX];

    return !https_server_public_install_filepath_for_testing(
        root, url, out, sizeof(out));
}

/* A symlink is judged by the place it resolves to. A target outside the
 * root is refused, whether it is absolute or climbs out with "..", and so is
 * a sibling directory whose name shares the root's name as a string prefix
 * ("public-install-evil"): only the '/' boundary test keeps that one out.
 * A symlink to a file inside the root maps to that file. */
static int https_public_install_symlink_cases(void)
{
    int failures = 0;
    char dir[256];
    char root[PATH_MAX];
    char release[PATH_MAX];
    char evil_dir[PATH_MAX];
    char evil_file[PATH_MAX];
    char outside[PATH_MAX];
    char shim[PATH_MAX];
    char tar_path[PATH_MAX];
    char tar_real[PATH_MAX];

    test_fmt_tmpdir(dir, sizeof(dir), "path_check", "pubinst_escape");
    (void)test_ensure_tmproot();
    test_cleanup_tmpdir(dir);
    (void)mkdir(dir, 0700);
    snprintf(root, sizeof(root), "%s/public-install", dir);
    snprintf(release, sizeof(release), "%s/release", root);
    snprintf(evil_dir, sizeof(evil_dir), "%s/public-install-evil", dir);
    snprintf(evil_file, sizeof(evil_file), "%s/file", evil_dir);
    snprintf(outside, sizeof(outside), "%s/outside.bin", dir);
    snprintf(shim, sizeof(shim), "%s/install.sh", root);
    snprintf(tar_path, sizeof(tar_path), "%s/z23.tar.gz", release);
    PC_CHECK("symlink fixture: root and release mkdir",
             mkdir(root, 0700) == 0 && mkdir(release, 0700) == 0);
    PC_CHECK("symlink fixture: sibling directory with a file",
             mkdir(evil_dir, 0700) == 0 && write_small_file(evil_file, "evil"));
    PC_CHECK("symlink fixture: tarball inside the root",
             write_small_file(tar_path, "tarball") &&
             realpath(tar_path, tar_real) != NULL);
    PC_CHECK("symlink fixture: file outside the root",
             write_small_file(outside, "outside"));

    PC_CHECK("symlink to an absolute path outside the root is refused",
             pi_relink(shim, outside) && pi_refused(root, "/"));
    PC_CHECK("symlink climbing out with .. is refused",
             pi_relink(shim, "../outside.bin") && pi_refused(root, "/"));
    PC_CHECK("symlink into a sibling sharing the root's name prefix is refused",
             pi_relink(shim, "../public-install-evil/file") &&
             pi_refused(root, "/"));
    PC_CHECK("symlink to a file inside the root maps to that file",
             pi_relink(shim, "release/z23.tar.gz") &&
             pi_maps_to(root, "/", tar_real));

    test_cleanup_tmpdir(dir);
    return failures;
}

/* Spellings of the root and of the URL over a regular shim. A root given
 * with a trailing slash, or reached through a symlink, resolves to the same
 * real root. A URL that is not an exact mapped name is refused before any
 * disk access. A trailing slash on a directory resolves to that directory,
 * and on a regular file it is refused (realpath() fails with ENOTDIR). */
static int https_public_install_spelling_cases(void)
{
    int failures = 0;
    char dir[256];
    char root[PATH_MAX];
    char root_slash[PATH_MAX];
    char root_alias[PATH_MAX];
    char release[PATH_MAX];
    char sub[PATH_MAX];
    char sub_real[PATH_MAX];
    char shim[PATH_MAX];
    char shim_real[PATH_MAX];
    char tar_path[PATH_MAX];
    char tar_real[PATH_MAX];

    test_fmt_tmpdir(dir, sizeof(dir), "path_check", "pubinst_spell");
    (void)test_ensure_tmproot();
    test_cleanup_tmpdir(dir);
    (void)mkdir(dir, 0700);
    snprintf(root, sizeof(root), "%s/public-install", dir);
    snprintf(root_slash, sizeof(root_slash), "%s/", root);
    snprintf(root_alias, sizeof(root_alias), "%s/alias-root", dir);
    snprintf(release, sizeof(release), "%s/release", root);
    snprintf(sub, sizeof(sub), "%s/sub", release);
    snprintf(shim, sizeof(shim), "%s/install.sh", root);
    snprintf(tar_path, sizeof(tar_path), "%s/z23.tar.gz", release);
    PC_CHECK("spelling fixture: root and release mkdir",
             mkdir(root, 0700) == 0 && mkdir(release, 0700) == 0);
    PC_CHECK("spelling fixture: release subdirectory", mkdir(sub, 0700) == 0);
    PC_CHECK("spelling fixture: shim and tarball",
             write_small_file(shim, "#!/bin/sh\n") &&
             write_small_file(tar_path, "tarball"));
    PC_CHECK("spelling fixture: realpaths",
             realpath(shim, shim_real) != NULL &&
             realpath(tar_path, tar_real) != NULL &&
             realpath(sub, sub_real) != NULL);

    PC_CHECK("a root with a trailing slash maps GET / to the shim",
             pi_maps_to(root_slash, "/", shim_real));
    PC_CHECK("a root reached through a symlink maps GET / to the shim",
             symlink(root, root_alias) == 0 &&
             pi_maps_to(root_alias, "/", shim_real));
    PC_CHECK("a URL with a leading doubled slash is refused",
             pi_refused(root, "//install.sh"));
    PC_CHECK("a URL without a leading slash is refused",
             pi_refused(root, "install.sh"));
    PC_CHECK("a trailing slash on the install URL is refused",
             pi_refused(root, "/install.sh/"));
    PC_CHECK("a dot segment in front of the install URL is refused",
             pi_refused(root, "/./install.sh"));
    PC_CHECK("a trailing slash on a regular file is refused",
             pi_refused(root, "/release/z23.tar.gz/"));
    PC_CHECK("a trailing slash on a directory resolves to that directory",
             pi_maps_to(root, "/release/sub/", sub_real));
    PC_CHECK("a doubled slash inside a release URL resolves to the file",
             pi_maps_to(root, "/release//z23.tar.gz", tar_real));

    test_cleanup_tmpdir(dir);
    return failures;
}

static int path_check_read_whole_file_binary_cases(const char *present,
                                                   const char *empty,
                                                   const char *missing)
{
    int failures = 0;

    {
        uint8_t *buf = NULL;
        size_t len = 0;
        PC_CHECK("read_whole_file reads full contents",
                 zcl_read_whole_file(present, 0, &buf, &len, "test") &&
                 len == strlen("hello world") &&
                 memcmp(buf, "hello world", len) == 0);
        free(buf);
    }

    {
        uint8_t *buf = (uint8_t *)0x1;
        size_t len = 99;
        PC_CHECK("read_whole_file on empty file yields NULL/0",
                 zcl_read_whole_file(empty, 0, &buf, &len, "test") &&
                 buf == NULL && len == 0);
    }

    {
        uint8_t *buf = (uint8_t *)0x1;
        size_t len = 99;
        PC_CHECK("read_whole_file on missing path fails and zeroes out",
                 !zcl_read_whole_file(missing, 0, &buf, &len, "test") &&
                 buf == NULL && len == 0);
    }

    {
        uint8_t *buf = (uint8_t *)0x1;
        size_t len = 99;
        PC_CHECK("read_whole_file refuses a file over max_len",
                 !zcl_read_whole_file(present, 4, &buf, &len, "test") &&
                 buf == NULL && len == 0);
    }

    {
        uint8_t *buf = NULL;
        size_t len = 0;
        PC_CHECK("read_whole_file accepts a file exactly at max_len",
                 zcl_read_whole_file(present, strlen("hello world"),
                                     &buf, &len, "test") &&
                 len == strlen("hello world"));
        free(buf);
    }
    return failures;
}

static int path_check_read_whole_file_text_cases(const char *present,
                                                 const char *empty)
{
    int failures = 0;

    {
        char *text = NULL;
        size_t len = 0;
        PC_CHECK("read_whole_file_text NUL-terminates",
                 zcl_read_whole_file_text(present, 0, &text, &len, "test") &&
                 len == strlen("hello world") &&
                 strcmp(text, "hello world") == 0);
        free(text);
    }

    {
        char *text = NULL;
        size_t len = 99;
        PC_CHECK("read_whole_file_text on empty file yields empty string",
                 zcl_read_whole_file_text(empty, 0, &text, &len, "test") &&
                 text != NULL && text[0] == '\0' && len == 0);
        free(text);
    }
    return failures;
}

static int path_check_whole_file_cases(void)
{
    int failures = 0;

    /* ── zcl_read_whole_file / zcl_read_whole_file_text ──────── */
    {
        char dir[256];
        char present[PATH_MAX];
        char empty[PATH_MAX];
        char missing[PATH_MAX];

        test_make_tmpdir(dir, sizeof(dir), "path_check", "file_io");
        snprintf(present, sizeof(present), "%s/present.bin", dir);
        snprintf(empty, sizeof(empty), "%s/empty.bin", dir);
        snprintf(missing, sizeof(missing), "%s/missing.bin", dir);

        PC_CHECK("file_io present fixture",
                 write_small_file(present, "hello world"));
        PC_CHECK("file_io empty fixture",
                 write_small_file(empty, ""));

        failures += path_check_read_whole_file_binary_cases(present, empty,
                                                           missing);
        failures += path_check_read_whole_file_text_cases(present, empty);

        test_cleanup_tmpdir(dir);
    }
    return failures;
}

int test_path_check(void)
{
    printf("\n=== path_check tests ===\n");
    int failures = file_io_stream_retirement_cases();
    failures += file_io_short_read_retirement_cases();

    /* ── fs_arg: rejects NULL / empty / over-length ──────────── */
    PC_CHECK("fs_arg(NULL) rejected",
        !path_check_fs_arg(NULL, 16));
    PC_CHECK("fs_arg(\"\") rejected",
        !path_check_fs_arg("", 16));
    PC_CHECK("fs_arg too long rejected (cap=4, input=5)",
        !path_check_fs_arg("hello", 4));

    /* Boundary: exactly max_len bytes is accepted. */
    PC_CHECK("fs_arg exactly at cap accepted",
        path_check_fs_arg("hello", 5));

    /* ── fs_arg: rejects control characters ──────────────────── */
    {
        char with_nul[8] = "abc\0def";  /* strnlen will stop at \0 */
        /* strnlen stops at an embedded NUL, so the checker sees a printable
         * string; verify non-NUL control-char rejection instead. */
        PC_CHECK("fs_arg with NUL-truncated string still accepted",
            path_check_fs_arg(with_nul, 8));
    }
    PC_CHECK("fs_arg with 0x01 (SOH) rejected",
        !path_check_fs_arg("a\x01" "b", 8));
    PC_CHECK("fs_arg with 0x1F (US) rejected",
        !path_check_fs_arg("a\x1f" "b", 8));
    PC_CHECK("fs_arg with 0x7F (DEL) rejected",
        !path_check_fs_arg("a\x7f" "b", 8));
    PC_CHECK("fs_arg with newline rejected",
        !path_check_fs_arg("a\nb", 8));
    PC_CHECK("fs_arg with tab rejected",
        !path_check_fs_arg("a\tb", 8));

    /* ── fs_arg: accepts legitimate paths ────────────────────── */
    PC_CHECK("fs_arg accepts \"foo.txt\"",
        path_check_fs_arg("foo.txt", 32));
    PC_CHECK("fs_arg accepts relative path",
        path_check_fs_arg("subdir/file", 32));
    PC_CHECK("fs_arg accepts absolute path (operator intent)",
        path_check_fs_arg("/tmp/zcl.dat", 64));
    PC_CHECK("fs_arg accepts \"..\" (operator intent, not filtered)",
        path_check_fs_arg("../foo", 16));

    failures += path_check_node_db_path_cases();

    /* ── url_arg: inherits fs_arg checks ─────────────────────── */
    PC_CHECK("url_arg(NULL) rejected",
        !path_check_url_arg(NULL, 16));
    PC_CHECK("url_arg(\"\") rejected",
        !path_check_url_arg("", 16));
    PC_CHECK("url_arg with control char rejected",
        !path_check_url_arg("/a\x01" "b", 16));

    /* ── url_arg: requires leading '/' ───────────────────────── */
    PC_CHECK("url_arg without leading / rejected",
        !path_check_url_arg("status", 16));
    PC_CHECK("url_arg \"/\" accepted",
        path_check_url_arg("/", 16));
    PC_CHECK("url_arg \"/status\" accepted",
        path_check_url_arg("/status", 16));

    /* ── url_arg: rejects ".." path segments ─────────────────── */
    PC_CHECK("url_arg \"/..\" rejected",
        !path_check_url_arg("/..", 16));
    PC_CHECK("url_arg \"/../foo\" rejected",
        !path_check_url_arg("/../foo", 16));
    PC_CHECK("url_arg \"/foo/..\" rejected",
        !path_check_url_arg("/foo/..", 16));
    PC_CHECK("url_arg \"/foo/../bar\" rejected",
        !path_check_url_arg("/foo/../bar", 16));

    /* 3 dots is NOT a `..` segment — accept. */
    PC_CHECK("url_arg \"/.../foo\" accepted (3 dots != ..)",
        path_check_url_arg("/.../foo", 16));

    /* A single dot segment is not rejected (it's a no-op, not an escape).
     * This is documented behavior: the helper filters only what is never
     * legitimate, and `/./foo` resolves to `/foo`. */
    PC_CHECK("url_arg \"/./foo\" accepted",
        path_check_url_arg("/./foo", 16));

    /* Nested directory paths accepted. */
    PC_CHECK("url_arg \"/api/health\" accepted",
        path_check_url_arg("/api/health", 32));
    PC_CHECK("url_arg \"/directory.json\" accepted",
        path_check_url_arg("/directory.json", 32));

    failures += https_slow_drip_deadline_case();
    failures += https_queue_out_of_order_expiry_case();
    failures += https_incomplete_headers_case();
    failures += https_acme_redirect_containment_cases();
    failures += https_public_install_jail_cases();
    failures += https_public_install_refusal_cases();
    failures += https_public_install_routed_refusal_cases();
    failures += https_public_install_mapping_cases();
    failures += https_public_install_symlink_cases();
    failures += https_public_install_spelling_cases();
    failures += path_check_whole_file_cases();

    return failures;
}
