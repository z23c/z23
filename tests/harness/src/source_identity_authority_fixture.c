/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Isolated hooked source identity cache and metadata fixtures. */
#include "test/test_core.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if !defined(_WIN32)
static bool sia_write_file(const char *path, const char *content)
{
    FILE *f = fopen(path, "w");
    if (!f) return false;
    bool ok = fputs(content, f) >= 0;
    if (fclose(f) != 0) ok = false;
    return ok;
}
static bool sia_capture(const char *cmd, char *out, size_t out_len)
{
    FILE *p = popen(cmd, "r");
    if (!p)
        return false;
    size_t used = fread(out, 1, out_len - 1, p);
    out[used] = '\0';
    while (used > 0 && (out[used - 1] == '\n' || out[used - 1] == '\r'))
        out[--used] = '\0';
    return pclose(p) == 0;
}
/* Exercise the actual cache publisher with an enforced A-open/B-open/A-rename/B-write schedule. */
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
static FILE *sia_cache_stage(FILE *file);
static int sia_cache_rename(const char *from, const char *to);
int sia_batch_fixture_main(int argc, char **argv);
#define ZCL_SOURCE_IDENTITY_BATCH_INPUT_ID "fixture"
#define main sia_batch_fixture_main
#define fopen(path, mode) sia_cache_stage(fopen(path, mode))
#define fdopen(fd, mode) sia_cache_stage(fdopen(fd, mode))
#define rename sia_cache_rename
#include "../../../tools/dev/source_identity_batch.c"
#undef rename
#undef fdopen
#undef fopen
#undef main
#undef ZCL_SOURCE_IDENTITY_BATCH_INPUT_ID
static int sia_racing, sia_writer_b, sia_ready[2] = {-1, -1}, sia_resume[2] = {-1, -1}, sia_child_status;
static pid_t sia_child;
static bool sia_a_whole;
static struct digest_row sia_row_a = {.path = "a.c", .size = 999999999};
static struct digest_row sia_row_b = {.path = "b.c", .size = 1};
static bool sia_cache_whole(const char *path, const struct digest_row *row)
{
    char actual[512] = {0}, expected[512], hex[65];
    zcl_hex_encode(row->digest, 32, hex);
    snprintf(expected, sizeof(expected), "0 0 0 %" PRIu64 " 0 0 0 0 %s %s\n", row->size, hex, row->path);
    FILE *f = fopen(path, "r");
    if (!f) return false;
    size_t n = fread(actual, 1, sizeof(actual) - 1, f);
    bool ok = feof(f) && !ferror(f) && n == strlen(expected);
    if (fclose(f) != 0) ok = false;
    return ok && strcmp(actual, expected) == 0;
}
static FILE *sia_cache_stage(FILE *file)
{
    if (!sia_racing || !file) return file;
    char byte = 0;
    if (sia_writer_b) {
        if (write(sia_ready[1], &byte, 1) != 1 || read(sia_resume[0], &byte, 1) != 1) _exit(2);
        return file;
    }
    sia_child = fork();
    if (sia_child == 0) {
        alarm(5);
        if (fclose(file) != 0) _exit(3);
        sia_writer_b = 1; g_rows = &sia_row_b;
        cache_save();
        _exit(0);
    }
    struct pollfd ready = {.fd = sia_ready[0], .events = POLLIN};
    if (sia_child < 0 || poll(&ready, 1, 5000) != 1 || read(sia_ready[0], &byte, 1) != 1) {
        if (sia_child > 0) { kill(sia_child, SIGKILL); waitpid(sia_child, NULL, 0); }
        fclose(file); return NULL;
    }
    return file;
}
static int sia_cache_rename(const char *from, const char *to)
{
    int rc = rename(from, to);
    if (sia_racing && !sia_writer_b) {
        sia_racing = 0;
        sia_a_whole = rc == 0 && sia_cache_whole(to, &sia_row_a);
        char byte = 0;
        if (write(sia_resume[1], &byte, 1) != 1) kill(sia_child, SIGKILL);
        if (waitpid(sia_child, &sia_child_status, 0) != sia_child) sia_child_status = -1;
    }
    return rc;
}
static void sia_stat_child(const char *work, const char *mode, bool full)
{
    if (chdir(work) != 0) _exit(120);
    if (!freopen("stat-input", "rb", stdin) ||
        !freopen(full ? "/dev/full" : "stat-output", "wb", stdout)) _exit(121);
    char *argv[] = {"source-identity-batch", (char *)mode, NULL};
    _exit(sia_batch_fixture_main(2, argv));
}
static int sia_stat_run(const char *work, const char *mode, const void *input,
                        size_t length, bool full)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/stat-input", work) >= (int)sizeof(path)) return -1;
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    bool wrote = fwrite(input, 1, length, f) == length;
    if (fclose(f) != 0 || !wrote) return -1;
    fflush(NULL);
    pid_t child = fork();
    if (child == 0) sia_stat_child(work, mode, full);
    if (child < 0) return -1;
    int status; pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    return waited == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}
static bool sia_stat_read(const char *work, char *out, size_t cap)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/stat-output", work) >= (int)sizeof(path)) return false;
    FILE *f = fopen(path, "rb"); if (!f) return false;
    size_t n = fread(out, 1, cap - 1, f); bool ok = feof(f) && !ferror(f);
    if (fclose(f) != 0) ok = false;
    out[n] = 0; return ok;
}
static bool sia_stat_expected(const char *work, const char *path, bool follow,
                              char *out, size_t cap)
{
    char full[PATH_MAX], hex[PATH_MAX * 2]; struct stat st;
    if (snprintf(full, sizeof(full), "%s/%s", work, path) >= (int)sizeof(full)) return false;
    if ((follow ? stat(full, &st) : lstat(full, &st)) != 0 || strlen(path) * 2 + 1 > sizeof(hex)) return false;
    zcl_hex_encode((const uint8_t *)path, strlen(path), hex);
#if defined(__APPLE__)
    struct timespec mt = st.st_mtimespec, ct = st.st_ctimespec;
#else
    struct timespec mt = st.st_mtim, ct = st.st_ctim;
#endif
    int n = snprintf(out, cap, "%s\t%" PRIuMAX ":%" PRIuMAX ":%" PRIdMAX ":%" PRIdMAX ":%ld:%" PRIdMAX ":%ld\n",
        hex, (uintmax_t)st.st_dev, (uintmax_t)st.st_ino, (intmax_t)st.st_size,
        (intmax_t)mt.tv_sec, mt.tv_nsec, (intmax_t)ct.tv_sec, ct.tv_nsec);
    return n > 0 && (size_t)n < cap;
}
static bool sia_stat_one(const char *work, const char *mode, const char *path, bool follow)
{
    char expected[PATH_MAX * 2 + 256], actual[PATH_MAX * 2 + 256];
    return sia_stat_expected(work, path, follow, expected, sizeof(expected)) &&
        sia_stat_run(work, mode, path, strlen(path) + 1, false) == 0 &&
        sia_stat_read(work, actual, sizeof(actual)) && !strcmp(actual, expected);
}
static bool sia_stat_multiple(const char *work)
{
    static const char input[] = "file\0line\nfile\0";
    char first[1024], second[1024], actual[2048], expected[2048];
    if (!sia_stat_expected(work, "file", true, first, sizeof(first)) ||
        !sia_stat_expected(work, "line\nfile", true, second, sizeof(second))) return false;
    int n = snprintf(expected, sizeof(expected), "%s%s", first, second);
    return n > 0 && (size_t)n < sizeof(expected) &&
        sia_stat_run(work, "stat-follow", input, sizeof(input) - 1, false) == 0 &&
        sia_stat_read(work, actual, sizeof(actual)) && !strcmp(actual, expected);
}
static bool sia_stat_setup(const char *work)
{
    char p[PATH_MAX];
    if (snprintf(p, sizeof(p), "%s/file", work) >= (int)sizeof(p) || !sia_write_file(p, "data")) return false;
    if (snprintf(p, sizeof(p), "%s/line\nfile", work) >= (int)sizeof(p) || !sia_write_file(p, "newline")) return false;
    if (snprintf(p, sizeof(p), "%s/dir", work) >= (int)sizeof(p) || mkdir(p, 0700)) return false;
    if (snprintf(p, sizeof(p), "%s/link", work) >= (int)sizeof(p) || symlink("file", p)) return false;
    if (snprintf(p, sizeof(p), "%s/dirlink", work) >= (int)sizeof(p) || symlink("dir", p)) return false;
    if (snprintf(p, sizeof(p), "%s/dangling", work) >= (int)sizeof(p) || symlink("absent", p)) return false;
    return true;
}
static bool sia_stat_nanoseconds(const char *work)
{
    char path[PATH_MAX], a[1024], b[1024];
    if (snprintf(path, sizeof(path), "%s/file", work) >= (int)sizeof(path)) return false;
    struct timespec times[2] = {{1700000000, 123456789}, {1700000000, 123456789}};
    if (utimensat(AT_FDCWD, path, times, 0) || !sia_stat_one(work, "stat-follow", "file", true) ||
        !sia_stat_read(work, a, sizeof(a))) return false;
    times[0].tv_nsec = times[1].tv_nsec = 987654321;
    return !utimensat(AT_FDCWD, path, times, 0) && sia_stat_one(work, "stat-follow", "file", true) &&
        sia_stat_read(work, b, sizeof(b)) && strcmp(a, b) != 0;
}
static bool sia_stat_hex_boundaries(const char *work)
{
    static const size_t lengths[] = {127, 128, 129, 255};
    char name[256], path[PATH_MAX];
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        memset(name, 'a' + (int)i, lengths[i]);
        name[lengths[i]] = 0;
        if (snprintf(path, sizeof(path), "%s/%s", work, name) >= (int)sizeof(path) ||
            !sia_write_file(path, "boundary") ||
            !sia_stat_one(work, "stat-follow", name, true) ||
            !sia_stat_one(work, "stat-link", name, false)) return false;
    }
    return true;
}
static int sia_stat_modes(void)
{
    int failures = 0; char work[512] = {0}, out[256];
    TEST("source identity stat modes preserve exact link and newline metadata") {
        test_make_tmpdir(work, sizeof(work), "sia", "stat-modes");
        ASSERT(sia_stat_setup(work));
        ASSERT(sia_stat_one(work, "stat-follow", "file", true));
        ASSERT(sia_stat_one(work, "stat-follow", "dir", true));
        ASSERT(sia_stat_one(work, "stat-link", "dir", false));
        ASSERT(sia_stat_one(work, "stat-follow", "link", true));
        ASSERT(sia_stat_one(work, "stat-link", "link", false));
        ASSERT(sia_stat_one(work, "stat-follow", "dirlink", true));
        ASSERT(sia_stat_one(work, "stat-link", "dirlink", false));
        ASSERT(sia_stat_one(work, "stat-link", "dangling", false));
        ASSERT(sia_stat_one(work, "stat-follow", "line\nfile", true));
        ASSERT(sia_stat_multiple(work));
        ASSERT(sia_stat_nanoseconds(work));
        ASSERT(sia_stat_hex_boundaries(work));
        PASS();
    }
    TEST("source identity stat modes refuse bad streams and output errors") {
        ASSERT(sia_stat_run(work, "stat-follow", "", 0, false) == 0);
        ASSERT(sia_stat_read(work, out, sizeof(out)) && !out[0]);
        ASSERT(sia_stat_run(work, "stat-follow", "\0", 1, false) != 0);
        ASSERT(sia_stat_run(work, "stat-follow", "file", 4, false) != 0);
        ASSERT(sia_stat_run(work, "stat-follow", "absent\0", 7, false) != 0);
        ASSERT(sia_stat_run(work, "stat-follow", "dangling\0", 9, false) != 0);
        if (access("/dev/full", W_OK) == 0)
            ASSERT(sia_stat_run(work, "stat-follow", "file\0", 5, true) != 0);
        PASS();
    } _test_next:;
    if (work[0]) test_rm_rf_recursive(work);
    return failures;
}


static int sia_digest_cache_concurrent(void)
{
    int failures = 0;
    char work[512] = {0};
    bool loaded = false;
    TEST("digest cache concurrent publication retains whole rows and validates metadata") {
        test_make_tmpdir(work, sizeof(work), "sia", "cache-concurrent");
        ASSERT(snprintf(g_cache_path, sizeof(g_cache_path), "%s/cache", work) < (int)sizeof(g_cache_path));
        ASSERT_EQ(pipe(sia_ready), 0); ASSERT_EQ(pipe(sia_resume), 0);
        g_rows = &sia_row_a; g_row_count = 1; g_cache_dirty = 1; g_cache_ready = 1;
        sia_racing = 1; cache_save(); sia_racing = 0;
        ASSERT(sia_a_whole); ASSERT_EQ(sia_child_status, 0);
        ASSERT(sia_cache_whole(g_cache_path, &sia_row_b));
        g_rows = &sia_row_b; g_row_count = 0; g_row_cap = 1; g_cache_ready = 0;
        loaded = true; sia_row_b.path = NULL; cache_load();
        ASSERT_EQ(g_row_count, 1);
        struct stat snapshot; row_apply(&snapshot, &sia_row_b);
        uint8_t digest[32];
        ASSERT_EQ(reuse_snapshot("b.c", &snapshot, digest), 1);
        snapshot.st_size++;
        ASSERT_EQ(reuse_snapshot("b.c", &snapshot, digest), 0);
        PASS();
    } _test_next:;
    close(sia_ready[0]); close(sia_ready[1]); close(sia_resume[0]); close(sia_resume[1]);
    if (loaded) cache_release_path(sia_row_b.path);
    sia_row_b.path = "b.c";
    g_rows = NULL; g_row_count = 0; g_row_cap = 0; g_cache_ready = 0; g_cache_path[0] = '\0';
    if (work[0]) test_rm_rf_recursive(work);
    return failures;
}
static int sia_digest_cache_absent_directory(void)
{
    int failures = 0;
    char work[512] = {0}, root[PATH_MAX], path[PATH_MAX];
    char cmd[PATH_MAX * 4], out[512];
    TEST("digest cache absent directory quietly preserves successful hashing") {
        ASSERT(getcwd(root, sizeof(root)) != NULL);
        test_make_tmpdir(work, sizeof(work), "sia", "cache-absent");
        ASSERT(snprintf(path, sizeof(path), "%s/input", work) < (int)sizeof(path));
        ASSERT(sia_write_file(path, "abc"));
        ASSERT(snprintf(cmd, sizeof(cmd),
            "cd '%s' && { printf 'input\\0' | '%s/build/bin/source-identity-batch' "
            "hash --cache absent/cache >result 2>error; status=$?; "
            "printf 'status=%%s\\n' \"$status\"; cat error; tr '\\000' '\\n' <result; }",
            work, root) < (int)sizeof(cmd));
        ASSERT(sia_capture(cmd, out, sizeof(out)));
        ASSERT(strcmp(out, "status=0\n"
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad "
            "*input") == 0);
        ASSERT(snprintf(path, sizeof(path), "%s/absent", work) < (int)sizeof(path));
        struct stat snapshot;
        ASSERT(lstat(path, &snapshot) != 0 && errno == ENOENT);
        PASS();
    } _test_next:;
    if (work[0]) test_rm_rf_recursive(work);
    return failures;
}
/* Corrupt cache framing must not qualify metadata-matched digest reuse. */
static int sia_digest_cache_framing(void)
{
    int failures = 0;
    char work[512] = {0}, root[PATH_MAX], cmd[PATH_MAX * 3], out[256];
    TEST("digest cache rejects NUL and continuation records") {
        ASSERT(getcwd(root, sizeof(root)) != NULL);
        test_make_tmpdir(work, sizeof(work), "sia", "cache-framing");
        char path[PATH_MAX];
        ASSERT(snprintf(path, sizeof(path), "%s/input", work) < (int)sizeof(path));
        ASSERT(sia_write_file(path, "abc"));
        ASSERT(snprintf(cmd, sizeof(cmd),
            "cd '%s' && printf 'input\\0' | '%s/build/bin/source-identity-batch' "
            "hash --cache cache --report-bytes 2>&1 | tr '\\000' '\\n'",
            work, root) < (int)sizeof(cmd));
        ASSERT(sia_capture(cmd, out, sizeof(out)));
        ASSERT(strstr(out, "content_bytes_read=3") != NULL);
        ASSERT(snprintf(path, sizeof(path), "%s/cache", work) < (int)sizeof(path));
        FILE *f = fopen(path, "rb");
        ASSERT(f != NULL);
        char row[8192];
        size_t n = fread(row, 1, sizeof(row), f);
        bool complete = feof(f) && !ferror(f);
        ASSERT_EQ(fclose(f), 0);
        ASSERT(complete && n > 0 && row[n - 1] == '\n');
        for (int kind = 0; kind < 5; kind++) {
            f = fopen(path, "wb");
            ASSERT(f != NULL);
            if (kind == 4) ASSERT_EQ(fwrite(row, 1, n, f), n);
            if (kind == 2) for (int i = 0; i < 8191; i++) ASSERT(fputc('x', f) != EOF);
            ASSERT_EQ(fwrite(row, 1, n - 1, f), n - 1);
            if (kind == 1 || kind == 4) ASSERT_EQ(fwrite("\0extra", 1, 6, f), 6);
            if (kind != 3) ASSERT(fputc('\n', f) != EOF);
            ASSERT_EQ(fclose(f), 0);
            ASSERT(sia_capture(cmd, out, sizeof(out)));
            ASSERT(strstr(out, kind == 1 || kind == 2 || kind == 4 ?
                          "content_bytes_read=3" : "content_bytes_read=0") != NULL);
        }
        PASS();
    } _test_next:;
    if (work[0]) test_rm_rf_recursive(work);
    return failures;
}

int sia_source_identity_fixture_before(void);
int sia_source_identity_fixture_before(void)
{
    int failures = 0;
    failures += sia_digest_cache_concurrent();
    failures += sia_stat_modes();
    return failures;
}

int sia_source_identity_fixture_after(void);
int sia_source_identity_fixture_after(void)
{
    int failures = 0;
    failures += sia_digest_cache_absent_directory();
    failures += sia_digest_cache_framing();
    return failures;
}
#endif
