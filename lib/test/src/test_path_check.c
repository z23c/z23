/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the defensive path-input checkers
 * (lib/util/src/path_check.c).
 *
 * Both helpers are pure: deterministic, no I/O, no global state. So
 * tests are simple table-driven assertions. */

/* realpath() needs __USE_MISC; -D_POSIX_C_SOURCE=200809L alone does not
 * declare it. Without this the TU only builds by accident of the glibc
 * fortify inline at -O3. */
#define _DEFAULT_SOURCE

#include "test/test_core.h"
#include "net/https_frontdoor.h"
#include "net/https_server.h"
#include "platform/time_compat.h"
#include "util/file_io.h"
#include "util/path_check.h"
#include <limits.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define PC_CHECK(name, expr) do { \
    printf("path_check: %s... ", (name)); \
    if ((expr)) printf("OK\n");           \
    else { printf("FAIL\n"); failures++; } \
} while (0)

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

int test_path_check(void)
{
    printf("\n=== path_check tests ===\n");
    int failures = 0;

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
        /* strnlen('abc\0', max>3) returns 3; that's the full string the
         * checker sees, and it's printable — so this string is accepted.
         * The real NUL guard is: caller passing a string that *contains*
         * a NUL as data is impossible via JSON since JSON strings can't
         * have embedded NULs that survive the decoder. Verify the
         * non-NUL control-char rejection instead. */
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

    /* Listener threads can stamp deadlines in one order but reach the shared
     * queue in another. A full queue must reclaim every expired descriptor,
     * not merely an expired prefix, while retaining live FIFO order. */
    {
        struct https_fixed_clock clock = {.monotonic_us = 100000};
        struct platform_clock_source source = {
            .monotonic_us = https_fixed_monotonic_us,
            .wall_unix = https_fixed_wall_unix,
            .user = &clock,
        };
        int expired_pair[2] = {-1, -1};
        int replacement_pair[2] = {-1, -1};
        int first_fd = -1;
        bool first_owned = false;
        bool expired_owned = false;
        struct https_frontdoor_queue queue = {0};
        bool queue_ready = socketpair(AF_UNIX, SOCK_STREAM, 0,
                                      expired_pair) == 0 &&
                           socketpair(AF_UNIX, SOCK_STREAM, 0,
                                      replacement_pair) == 0;
        platform_clock_set_source(&source);
        if (queue_ready) {
            first_fd = dup(replacement_pair[1]);
            first_owned = first_fd >= 0 &&
                https_queue_push_fd(&queue, first_fd, 2000);
            if (first_owned)
                expired_owned =
                    https_queue_push_fd(&queue, expired_pair[0], 500);
            queue_ready = first_owned && expired_owned;
        }
        for (size_t i = 2; queue_ready &&
             i < HTTPS_FRONTDOOR_QUEUE_CAP; i++) {
            int fd = dup(replacement_pair[1]);
            if (fd < 0 || !https_queue_push_fd(&queue, fd, 2000)) {
                if (fd >= 0)
                    close(fd);
                queue_ready = false;
            }
        }
        atomic_store_explicit(&clock.monotonic_us, 1000000,
                              memory_order_relaxed);
        bool replacement_owned = queue_ready &&
            https_queue_push_fd(&queue, replacement_pair[0], 2000);
        struct https_frontdoor_client popped = {.fd = -1};
        bool fifo_preserved = replacement_owned &&
            https_frontdoor_queue_pop(&queue, &popped) &&
            popped.fd == first_fd && !popped.tls &&
            popped.deadline_ms == 2000;
        char byte = 0;
        bool expired_closed = replacement_owned &&
            recv(expired_pair[1], &byte, 1, MSG_DONTWAIT) == 0;
        PC_CHECK("https queue reclaims out-of-order expiry and preserves FIFO",
                 fifo_preserved && expired_closed);
        if (popped.fd >= 0)
            close(popped.fd);
        https_frontdoor_queue_close_all(&queue);
        platform_clock_clear_source();
        if (!first_owned && first_fd >= 0)
            close(first_fd);
        if (!expired_owned && expired_pair[0] >= 0)
            close(expired_pair[0]);
        if (!replacement_owned && replacement_pair[0] >= 0)
            close(replacement_pair[0]);
        if (expired_pair[1] >= 0)
            close(expired_pair[1]);
        if (replacement_pair[1] >= 0)
            close(replacement_pair[1]);
    }

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

        test_cleanup_tmpdir(dir);
    }

    return failures;
}
