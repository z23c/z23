/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_core.h"
#include "config/file_ops.h"
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static bool write_text_file(const char *path, const char *contents)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    size_t len = strlen(contents);
    bool ok = fwrite(contents, 1, len, f) == len;
    fclose(f);
    return ok;
}

static bool read_text_file(const char *path, char *out, size_t out_size)
{
    FILE *f = fopen(path, "rb");
    if (!f || out_size == 0)
        return false;
    size_t n = fread(out, 1, out_size - 1, f);
    out[n] = '\0';
    fclose(f);
    return true;
}

static int test_dir_copy_success(void)
{
    int failures = 0;

    TEST("file_ops dir_copy copies regular files and reports success") {
        char root[PATH_MAX];
        char *dir = test_mkdtemp(root, sizeof(root), "zcl_file_ops_success");
        char src[1024], dst[1024], a[1024], b[1024], copied[1024];
        char buf[64];
        bool ok = dir != NULL;

        snprintf(src, sizeof(src), "%s/src", dir ? dir : "");
        snprintf(dst, sizeof(dst), "%s/dst", dir ? dir : "");
        snprintf(a, sizeof(a), "%s/one.txt", src);
        snprintf(b, sizeof(b), "%s/two.txt", src);
        snprintf(copied, sizeof(copied), "%s/two.txt", dst);

        ok = ok && mkdir(src, 0700) == 0;
        ok = ok && write_text_file(a, "alpha");
        ok = ok && write_text_file(b, "beta");
        ok = ok && dir_copy(src, dst);
        ok = ok && read_text_file(copied, buf, sizeof(buf));
        ok = ok && strcmp(buf, "beta") == 0;

        if (dir)
            dir_remove_tree(dir);
        ASSERT(ok);
        PASS();
    } _test_next:;

    return failures;
}

static int test_file_copy_overwrites_regular_files(void)
{
    int failures = 0;

    TEST("file_ops file_copy overwrites files and rejects directories") {
        char root[PATH_MAX];
        char *dir = test_mkdtemp(root, sizeof(root), "zcl_file_copy");
        char src[1024], dst[1024], bad_src[1024];
        char buf[64];
        bool ok = dir != NULL;

        snprintf(src, sizeof(src), "%s/src.txt", dir ? dir : "");
        snprintf(dst, sizeof(dst), "%s/dst.txt", dir ? dir : "");
        snprintf(bad_src, sizeof(bad_src), "%s/not-a-file", dir ? dir : "");

        ok = ok && write_text_file(src, "new");
        ok = ok && write_text_file(dst, "old");
        ok = ok && file_copy(src, dst);
        ok = ok && read_text_file(dst, buf, sizeof(buf));
        ok = ok && strcmp(buf, "new") == 0;
        ok = ok && mkdir(bad_src, 0700) == 0;
        ok = ok && !file_copy(bad_src, dst);

        if (dir)
            dir_remove_tree(dir);
        ASSERT(ok);
        PASS();
    } _test_next:;

    return failures;
}

static int test_dir_copy_partial_failure(void)
{
    int failures = 0;

    TEST("file_ops dir_copy fails closed when a source entry cannot be copied") {
        char root[PATH_MAX];
        char *dir = test_mkdtemp(root, sizeof(root), "zcl_file_ops_partial");
        char src[1024], dst[1024], ok_file[1024], bad_dir[1024];
        bool ok = dir != NULL;

        snprintf(src, sizeof(src), "%s/src", dir ? dir : "");
        snprintf(dst, sizeof(dst), "%s/dst", dir ? dir : "");
        snprintf(ok_file, sizeof(ok_file), "%s/ok.txt", src);
        snprintf(bad_dir, sizeof(bad_dir), "%s/not-a-file", src);

        ok = ok && mkdir(src, 0700) == 0;
        ok = ok && write_text_file(ok_file, "ok");
        ok = ok && mkdir(bad_dir, 0700) == 0;
        ok = ok && !dir_copy(src, dst);

        if (dir)
            dir_remove_tree(dir);
        ASSERT(ok);
        PASS();
    } _test_next:;

    return failures;
}

static int test_block_files_copy_rev_failure(void)
{
    int failures = 0;

    TEST("file_ops block_files_copy fails when rev file copy fails") {
        char root[PATH_MAX];
        char *dir = test_mkdtemp(root, sizeof(root), "zcl_block_files_fail");
        char src[1024], dst[1024], blk[1024], rev_dir[1024];
        bool ok = dir != NULL;
        int copied = 0;

        snprintf(src, sizeof(src), "%s/src", dir ? dir : "");
        snprintf(dst, sizeof(dst), "%s/dst", dir ? dir : "");
        snprintf(blk, sizeof(blk), "%s/blk00000.dat", src);
        snprintf(rev_dir, sizeof(rev_dir), "%s/rev00000.dat", src);

        ok = ok && mkdir(src, 0700) == 0;
        ok = ok && mkdir(dst, 0700) == 0;
        ok = ok && write_text_file(blk, "block");
        ok = ok && mkdir(rev_dir, 0700) == 0;
        copied = ok ? block_files_copy(src, dst) : 0;
        ok = ok && copied == -1;

        if (dir)
            dir_remove_tree(dir);
        ASSERT(ok);
        PASS();
    } _test_next:;

    return failures;
}

/* ---- fixtures for the mutation-measured gaps ---- */

static void fo_path(char *out, size_t cap, const char *dir, const char *name)
{
    snprintf(out, cap, "%s/%s", dir, name);
}

static bool fo_exists(const char *path)
{
    return access(path, F_OK) == 0;
}

/* A fresh private root under its real path, so a path built from it keeps
 * its length through the destination resolver's realpath. */
static bool fo_root(char *real, const char *tag)
{
    char raw[PATH_MAX] = "";
    real[0] = '\0';
    char *dir = test_mkdtemp(raw, sizeof(raw), tag);
    if (!dir)
        return false;
    if (!realpath(dir, real)) {
        real[0] = '\0';
        return false;
    }
    return true;
}

/* Remove a fixture root only when fo_root wrote one. */
static void fo_cleanup(const char *root)
{
    if (root[0] != '\0')
        dir_remove_tree(root);
}

static bool fo_write_pattern(const char *path, size_t size)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = true;
    for (size_t i = 0; ok && i < size; i++)
        ok = fputc((int)((i * 31 + 7) & 0xFF), f) != EOF;
    return fclose(f) == 0 && ok;
}

static bool fo_check_pattern(const char *path, size_t size)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    bool ok = true;
    for (size_t i = 0; ok && i < size; i++)
        ok = fgetc(f) == (int)((i * 31 + 7) & 0xFF);
    ok = ok && fgetc(f) == EOF;
    fclose(f);
    return ok;
}

static int fo_fd_count(void)
{
    DIR *d = opendir("/proc/self/fd");
    if (!d) {
        /* No /proc (macOS): count live numeric /dev/fd entries, not the
         * directory's own descriptor. */
        d = opendir("/dev/fd");
        if (!d)
            return -1;
        int live = 0;
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            char *end;
            long fd = strtol(e->d_name, &end, 10);
            if (end != e->d_name && *end == '\0' && fd >= 0 &&
                fd != dirfd(d) && fcntl((int)fd, F_GETFD) >= 0)
                live++;
        }
        closedir(d);
        return live;
    }
    int n = 0;
    while (readdir(d))
        n++;
    closedir(d);
    return n;
}

/* Entries in dir other than . and ..; *staging counts the ones that look
 * like a leftover staging file. */
static int fo_entries(const char *dir, int *staging)
{
    DIR *d = opendir(dir);
    if (!d)
        return -1;
    int n = 0;
    *staging = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        n++;
        if (strstr(e->d_name, ".tmp."))
            (*staging)++;
    }
    closedir(d);
    return n;
}

/* Capture of stdout and stderr into two files while dir_copy runs. */
struct fo_capture {
    int saved[2];
    int file[2];
};

static bool fo_capture_begin(struct fo_capture *c, const char *out_path,
                             const char *err_path)
{
    fflush(stdout);
    fflush(stderr);
    c->file[0] = open(out_path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    c->file[1] = open(err_path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    c->saved[0] = dup(1);
    c->saved[1] = dup(2);
    bool ok = c->file[0] >= 0 && c->file[1] >= 0 && c->saved[0] >= 0 &&
              c->saved[1] >= 0;
    return ok && dup2(c->file[0], 1) >= 0 && dup2(c->file[1], 2) >= 0;
}

static void fo_capture_end(struct fo_capture *c, char *out, size_t out_size,
                           char *err, size_t err_size)
{
    fflush(stdout);
    fflush(stderr);
    if (c->saved[0] >= 0)
        dup2(c->saved[0], 1);
    if (c->saved[1] >= 0)
        dup2(c->saved[1], 2);
    ssize_t n = c->file[0] >= 0 ? pread(c->file[0], out, out_size - 1, 0) : -1;
    out[n > 0 ? n : 0] = '\0';
    n = c->file[1] >= 0 ? pread(c->file[1], err, err_size - 1, 0) : -1;
    err[n > 0 ? n : 0] = '\0';
    for (int i = 0; i < 2; i++) {
        if (c->saved[i] >= 0)
            close(c->saved[i]);
        if (c->file[i] >= 0)
            close(c->file[i]);
    }
}

/* dir_copy with its stdout and stderr captured. Returns 1 or 0 for the
 * result, -1 when the capture could not be set up. */
static int fo_dir_copy_captured(const char *dir, const char *src,
                                const char *dst, char *out, char *err)
{
    char out_path[PATH_MAX], err_path[PATH_MAX];
    struct fo_capture c = {{-1, -1}, {-1, -1}};
    fo_path(out_path, sizeof(out_path), dir, "capture.out");
    fo_path(err_path, sizeof(err_path), dir, "capture.err");
    bool begun = fo_capture_begin(&c, out_path, err_path);
    int result = begun ? (dir_copy(src, dst) ? 1 : 0) : -1;
    fo_capture_end(&c, out, 256, err, 256);
    return result;
}

/* mkdir -p style: root/tag followed by components until the path is exactly
 * total bytes long. */
static bool fo_long_dir(const char *root, const char *tag, size_t total,
                        char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/%s", root, tag);
    if (n <= 0 || (size_t)n > total || total >= cap || mkdir(out, 0700) != 0)
        return false;
    size_t len = (size_t)n;
    while (len < total) {
        size_t remaining = total - len;
        if (remaining < 2)
            return false;
        size_t comp = remaining - 1 <= 200 ? remaining - 1 : 100;
        out[len++] = '/';
        memset(out + len, 'd', comp);
        len += comp;
        out[len] = '\0';
        if (mkdir(out, 0700) != 0)
            return false;
    }
    return len == total;
}

static bool fo_roundtrip(const char *dir, size_t size)
{
    char src[PATH_MAX], dst[PATH_MAX];
    int staging = 0;
    fo_path(src, sizeof(src), dir, "src.bin");
    fo_path(dst, sizeof(dst), dir, "dst.bin");
    bool ok = fo_write_pattern(src, size) && file_copy(src, dst) &&
              fo_check_pattern(dst, size);
    return ok && fo_entries(dir, &staging) == 2 && staging == 0;
}

static int test_file_copy_chunk_boundaries(void)
{
    int failures = 0;

    TEST("file_ops file_copy is byte-exact across chunk edges, leaves no staging, closes its files") {
        char dir[PATH_MAX] = "";
        static const size_t sizes[] = {0, 1, 65535, 65536, 65537, 131079};
        bool ok = fo_root(dir, "zcl_file_copy_chunks");
        int before = ok ? fo_fd_count() : -1;
        for (size_t i = 0; ok && i < sizeof(sizes) / sizeof(sizes[0]); i++)
            ok = fo_roundtrip(dir, sizes[i]);
        int after = ok ? fo_fd_count() : -2;
        fo_cleanup(dir);
        ASSERT(ok);
        ASSERT(before > 0 && before == after);
        PASS();
    } _test_next:;

    return failures;
}

struct fo_refusal_paths {
    char src[PATH_MAX], empty[PATH_MAX], gone[PATH_MAX], target[PATH_MAX];
    char nodir[PATH_MAX], out[PATH_MAX], rel[PATH_MAX];
};

static bool fo_refusal_fixture(const char *dir, struct fo_refusal_paths *p)
{
    fo_path(p->src, sizeof(p->src), dir, "src.txt");
    fo_path(p->empty, sizeof(p->empty), dir, "empty.txt");
    fo_path(p->gone, sizeof(p->gone), dir, "gone.txt");
    fo_path(p->target, sizeof(p->target), dir, "target");
    fo_path(p->out, sizeof(p->out), dir, "out.txt");
    fo_path(p->rel, sizeof(p->rel), dir, "relative-out.txt");
    snprintf(p->nodir, sizeof(p->nodir), "%s/nodir/out", dir);
    return fo_write_pattern(p->src, 100) && fo_write_pattern(p->empty, 0) &&
           mkdir(p->target, 0700) == 0;
}

/* Every refusal. The relative destination resolves against the process
 * cwd, so it runs from inside the fixture (nothing can land in the repo)
 * and the cwd is restored, which *restored reports. */
static bool fo_refusals_run(const char *dir, const struct fo_refusal_paths *p,
                            bool *restored)
{
    char cwd[PATH_MAX] = "";
    bool in_fixture = getcwd(cwd, sizeof(cwd)) != NULL && chdir(dir) == 0;
    bool refused = in_fixture && !file_copy(p->src, "relative-out.txt");
    *restored = !in_fixture || chdir(cwd) == 0;
    return refused && !file_copy(p->gone, p->out) &&
           !file_copy(p->src, p->nodir) && !file_copy(p->empty, p->nodir) &&
           !file_copy(p->src, p->target) && !file_copy(p->empty, p->target);
}

static int test_file_copy_refusals(void)
{
    int failures = 0;

    TEST("file_ops file_copy refuses bad sources and destinations with no residue") {
        char dir[PATH_MAX] = "";
        struct fo_refusal_paths paths;
        int staging = 0;
        bool restored = true;
        memset(&paths, 0, sizeof(paths));
        bool ok = fo_root(dir, "zcl_file_copy_refuse");
        ok = ok && fo_refusal_fixture(dir, &paths);
        int before = ok ? fo_fd_count() : -1;
        bool refused = ok && fo_refusals_run(dir, &paths, &restored);
        int after = ok ? fo_fd_count() : -2;
        bool clean = ok && fo_entries(dir, &staging) == 3 && staging == 0 &&
                     !fo_exists(paths.out) && !fo_exists(paths.rel);
        fo_cleanup(dir);
        ASSERT(ok);
        ASSERT(restored);
        ASSERT(refused);
        ASSERT(clean);
        ASSERT(before > 0 && before == after);
        PASS();
    } _test_next:;

    return failures;
}

static int test_dir_copy_semantics(void)
{
    int failures = 0;

    TEST("file_ops dir_copy empties the destination, skips dot files and LOCK, counts copies") {
        char dir[PATH_MAX] = "", src[PATH_MAX], dst[PATH_MAX], name[PATH_MAX];
        char out[256] = "", err[256] = "";
        bool ok = fo_root(dir, "zcl_dir_copy_sem");
        fo_path(src, sizeof(src), dir, "src");
        fo_path(dst, sizeof(dst), dir, "dst");
        ok = ok && mkdir(src, 0700) == 0 && mkdir(dst, 0700) == 0;
        const char *names[] = {"one.txt", "two.txt", ".hidden", "LOCK"};
        for (size_t i = 0; ok && i < 4; i++) {
            fo_path(name, sizeof(name), src, names[i]);
            ok = fo_write_pattern(name, 10 + i);
        }
        fo_path(name, sizeof(name), dst, "stale.txt");
        ok = ok && fo_write_pattern(name, 3);
        int result = ok ? fo_dir_copy_captured(dir, src, dst, out, err) : -1;
        char one[PATH_MAX], two[PATH_MAX], hidden[PATH_MAX], lock[PATH_MAX];
        fo_path(one, sizeof(one), dst, "one.txt");
        fo_path(two, sizeof(two), dst, "two.txt");
        fo_path(hidden, sizeof(hidden), dst, ".hidden");
        fo_path(lock, sizeof(lock), dst, "LOCK");
        bool copied = ok && fo_check_pattern(one, 10) && fo_check_pattern(two, 11);
        bool skipped = ok && !fo_exists(hidden) && !fo_exists(lock) && !fo_exists(name);
        fo_cleanup(dir);
        ASSERT(ok);
        ASSERT_EQ(result, 1);
        ASSERT(copied);
        ASSERT(skipped);
        ASSERT(ok && strcmp(out, " 2 files") == 0);
        ASSERT(ok && strstr(err, "Warning") == NULL);
        PASS();
    } _test_next:;

    return failures;
}

static int test_dir_copy_refusal_reports(void)
{
    int failures = 0;

    TEST("file_ops dir_copy refuses a missing source or unusable destination and says so") {
        char dir[PATH_MAX] = "", src[PATH_MAX], dst[PATH_MAX], file[PATH_MAX];
        char sub[PATH_MAX], bad[PATH_MAX], out[256] = "", err[256] = "";
        bool ok = fo_root(dir, "zcl_dir_copy_refuse");
        fo_path(src, sizeof(src), dir, "src");
        fo_path(dst, sizeof(dst), dir, "dst");
        fo_path(file, sizeof(file), dir, "plain");
        fo_path(sub, sizeof(sub), src, "sub");
        fo_path(bad, sizeof(bad), file, "child");
        ok = ok && mkdir(src, 0700) == 0 && fo_write_pattern(file, 1);
        int missing = ok ? fo_dir_copy_captured(dir, "/nonexistent-src-dir", dst, out, err) : -1;
        int under_file = ok ? fo_dir_copy_captured(dir, src, bad, out, err) : -1;
        bool refused_msg = ok && strstr(err, "private directory refused") != NULL;
        char one[PATH_MAX];
        fo_path(one, sizeof(one), src, "ok.txt");
        ok = ok && fo_write_pattern(one, 4) && mkdir(sub, 0700) == 0;
        int partial = ok ? fo_dir_copy_captured(dir, src, dst, out, err) : -1;
        /* A subdirectory is refused before anything is copied or removed. */
        bool counted = ok && out[0] == '\0' &&
                       strstr(err, "1 subdirectories") != NULL;
        fo_cleanup(dir);
        ASSERT(ok);
        ASSERT_EQ(missing, 0);
        ASSERT_EQ(under_file, 0);
        ASSERT(refused_msg);
        ASSERT_EQ(partial, 0);
        ASSERT(counted);
        PASS();
    } _test_next:;

    return failures;
}

static bool fo_series_file(const char *dir, const char *name, size_t size)
{
    char path[PATH_MAX];
    fo_path(path, sizeof(path), dir, name);
    return fo_write_pattern(path, size);
}

static bool fo_series_has(const char *dir, const char *name, size_t size)
{
    char path[PATH_MAX];
    fo_path(path, sizeof(path), dir, name);
    return fo_check_pattern(path, size);
}

static bool fo_series_fixture(const char *src, const char *dst, const char *bad)
{
    return mkdir(src, 0700) == 0 && mkdir(dst, 0700) == 0 &&
           mkdir(bad, 0700) == 0 && fo_series_file(src, "blk00000.dat", 5) &&
           fo_series_file(src, "rev00000.dat", 6) &&
           fo_series_file(src, "blk00001.dat", 7) &&
           fo_series_file(src, "blk00003.dat", 8);
}

static bool fo_series_landed(const char *dst)
{
    char absent[PATH_MAX], gap[PATH_MAX];
    fo_path(absent, sizeof(absent), dst, "rev00001.dat");
    fo_path(gap, sizeof(gap), dst, "blk00003.dat");
    return fo_series_has(dst, "blk00000.dat", 5) &&
           fo_series_has(dst, "rev00000.dat", 6) &&
           fo_series_has(dst, "blk00001.dat", 7) && !fo_exists(absent) &&
           !fo_exists(gap);
}

static int test_block_files_copy_series(void)
{
    int failures = 0;

    TEST("file_ops block_files_copy copies every pair, treats a gap as the end, refuses a planted directory") {
        char dir[PATH_MAX] = "", src[PATH_MAX] = "", dst[PATH_MAX] = "";
        char bad[PATH_MAX] = "", bad_blk[PATH_MAX] = "";
        bool ok = fo_root(dir, "zcl_block_series");
        if (ok) {
            fo_path(src, sizeof(src), dir, "src");
            fo_path(dst, sizeof(dst), dir, "dst");
            fo_path(bad, sizeof(bad), dir, "bad");
            fo_path(bad_blk, sizeof(bad_blk), bad, "blk00000.dat");
        }
        ok = ok && fo_series_fixture(src, dst, bad);
        int copied = ok ? block_files_copy(src, dst) : -9;
        bool landed = ok && fo_series_landed(dst);
        int none = ok ? block_files_copy(dir, dst) : -9;
        ok = ok && mkdir(bad_blk, 0700) == 0;
        int planted = ok ? block_files_copy(bad, dst) : -9;
        fo_cleanup(dir);
        ASSERT(ok);
        ASSERT_EQ(copied, 2);
        ASSERT(landed);
        ASSERT_EQ(none, 0);
        ASSERT_EQ(planted, -1);
        PASS();
    } _test_next:;

    return failures;
}

/* The node spells file 255 blk_sync.dat / rev_sync.dat (disk_block_io.c) and
 * carries on at 256: the copy must follow the series across that name. */
static bool fo_sync_fixture(const char *src, const char *dst)
{
    bool ok = mkdir(src, 0700) == 0 && mkdir(dst, 0700) == 0;
    for (int i = 0; ok && i < 255; i++) {
        char name[32];
        snprintf(name, sizeof(name), "blk%05d.dat", i);
        ok = fo_series_file(src, name, 4);
    }
    return ok && fo_series_file(src, "blk_sync.dat", 5) &&
           fo_series_file(src, "rev_sync.dat", 6) &&
           fo_series_file(src, "blk00256.dat", 7);
}

static int test_block_files_copy_sync_spelling(void)
{
    int failures = 0;

    TEST("file_ops block_files_copy carries the series across the file 255 spelling") {
        char dir[PATH_MAX] = "", src[PATH_MAX] = "", dst[PATH_MAX] = "";
        bool ok = fo_root(dir, "zcl_block_sync");
        if (ok) {
            fo_path(src, sizeof(src), dir, "src");
            fo_path(dst, sizeof(dst), dir, "dst");
        }
        ok = ok && fo_sync_fixture(src, dst);
        int copied = ok ? block_files_copy(src, dst) : -9;
        bool landed = ok && fo_series_has(dst, "blk00254.dat", 4) &&
                      fo_series_has(dst, "blk_sync.dat", 5) &&
                      fo_series_has(dst, "rev_sync.dat", 6) &&
                      fo_series_has(dst, "blk00256.dat", 7);
        fo_cleanup(dir);
        ASSERT(ok);
        ASSERT_EQ(copied, 257);
        ASSERT(landed);
        PASS();
    } _test_next:;

    return failures;
}

/* True when every name in the list is present with size pattern bytes
 * (present) or absent (!present). */
static bool fo_names_state(const char *dir, const char *const *names,
                           size_t count, size_t size, bool present)
{
    bool good = true;
    for (size_t i = 0; good && i < count; i++) {
        char path[PATH_MAX];
        fo_path(path, sizeof(path), dir, names[i]);
        good = present ? fo_check_pattern(path, size) : !fo_exists(path);
    }
    return good;
}

static bool fo_names_write(const char *dir, const char *const *names,
                           size_t count)
{
    bool good = true;
    for (size_t i = 0; good && i < count; i++)
        good = fo_series_file(dir, names[i], 4);
    return good;
}

static int test_block_files_clean_selection(void)
{
    int failures = 0;

    TEST("file_ops block_files_clean removes only blk*.dat and rev*.dat regular files") {
        char dir[PATH_MAX] = "", sub[PATH_MAX] = "";
        bool ok = fo_root(dir, "zcl_block_clean");
        static const char *const gone[] = {"blk00000.dat", "rev00001.dat"};
        static const char *const kept[] = {"blkx", "blz00.dat", "notes.txt",
                                           "other.dat", "rez00.dat", "revx"};
        ok = ok && fo_names_write(dir, gone, 2) && fo_names_write(dir, kept, 6);
        if (ok)
            fo_path(sub, sizeof(sub), dir, "blk99.dat");
        ok = ok && mkdir(sub, 0700) == 0;
        if (ok)
            block_files_clean(dir);
        bool removed = ok && fo_names_state(dir, gone, 2, 0, false);
        bool retained = ok && fo_exists(sub) &&
                        fo_names_state(dir, kept, 6, 4, true);
        int before = ok ? fo_fd_count() : -1;
        if (ok)
            block_files_clean(dir);
        int after = ok ? fo_fd_count() : -2;
        fo_cleanup(dir);
        ASSERT(ok);
        ASSERT(removed);
        ASSERT(retained);
        ASSERT(before > 0 && before == after);
        PASS();
    } _test_next:;

    return failures;
}

/* The short side of a path-limit scenario only has to be a modest, valid
 * path. It was a fixed 100 bytes, which is shorter than root + "/<tag>" once
 * the fixture root (test-tmp under a long checkout path, or a long
 * ZCL_TEST_TMPROOT) passes ~97 bytes, so fo_long_dir refused it and the
 * scenario never reached the code under test. FO_SHORT asks for the root
 * length plus slack instead; the long side still lands on exactly 1023/1024. */
#define FO_SHORT ((size_t)0)

static size_t fo_short_total(const char *root, size_t total)
{
    if (total != FO_SHORT)
        return total;
    size_t floor = strlen(root) + 3 + 50; /* "/<tag>" is 3 bytes here */
    return floor > 100 ? floor : 100;
}

/* ---- path-length edges: scratch buffers are exactly 1024 and 4096 ---- */

/* The product joins entry names into 1024-byte buffers and spells staging
 * and quarantine names in 4096-byte buffers. Linux lets the kernel address
 * every one of those bytes. macOS caps a path at 1023 bytes plus NUL
 * (ENAMETOOLONG), so there:
 *  - an entry whose joined path is 1024 bytes cannot be created or probed by
 *    full path. The "over" cases create and probe it through the directory's
 *    descriptor (openat/faccessat), so the kernel only sees the short name
 *    while the product still has to refuse the 1024-byte join.
 *  - file_copy stages "<dst>.tmp.<16 hex>" (21 bytes) and block_files_clean
 *    retires to "<path>.z23-retire.<pid>.<seq>" (under 40 bytes), so a
 *    destination or file at the join limit leaves the kernel no room for the
 *    staging or quarantine name. The "fits" cases sit at the longest length
 *    whose extra name the kernel still accepts, and the 4096-byte staging
 *    case is checked at that kernel limit instead. */
#if defined(__APPLE__)
#define FO_BLOCK_DST_FITS ((size_t)989)  /* file 1002 + 21 = 1023 */
#define FO_DIR_DST_FITS ((size_t)1000)   /* entry 1002 + 21 = 1023 */
#define FO_CLEAN_FITS ((size_t)970)      /* file 983 + 40 = 1023 */
#define FO_STAGE_FITS ((size_t)1002)     /* dst 1002 + 21 = 1023 */
#define FO_STAGE_OVER ((size_t)1003)     /* staging name is 1024 */
#else
#define FO_BLOCK_DST_FITS ((size_t)1010)
#define FO_DIR_DST_FITS ((size_t)1021)
#define FO_CLEAN_FITS ((size_t)1010)
#define FO_STAGE_FITS ((size_t)4074)
#define FO_STAGE_OVER ((size_t)4075)
#endif

/* Create dir/name through the directory's descriptor, so the full spelling
 * never reaches the kernel. */
static bool fo_series_file_at(const char *dir, const char *name, size_t size)
{
    int dfd = open(dir, O_RDONLY | O_DIRECTORY);
    if (dfd < 0)
        return false;
    int fd = openat(dfd, name, O_WRONLY | O_CREAT | O_EXCL, 0600);
    close(dfd);
    if (fd < 0)
        return false;
    bool ok = true;
    for (size_t i = 0; ok && i < size; i++) {
        unsigned char byte = (unsigned char)((i * 31 + 7) & 0xFF);
        ok = write(fd, &byte, 1) == 1;
    }
    return close(fd) == 0 && ok;
}

static bool fo_exists_at(const char *dir, const char *name)
{
    int dfd = open(dir, O_RDONLY | O_DIRECTORY);
    if (dfd < 0)
        return false;
    bool found = faccessat(dfd, name, F_OK, 0) == 0;
    close(dfd);
    return found;
}

static bool fo_block_scenario(const char *root, const char *tag, size_t src_len,
                              size_t dst_len, int expected)
{
    char src_tag[16], dst_tag[16], src[PATH_MAX], dst[PATH_MAX];
    snprintf(src_tag, sizeof(src_tag), "%ss", tag);
    snprintf(dst_tag, sizeof(dst_tag), "%sd", tag);
    if (!fo_long_dir(root, src_tag, fo_short_total(root, src_len), src, sizeof(src)) ||
        !fo_long_dir(root, dst_tag, fo_short_total(root, dst_len), dst, sizeof(dst)) ||
        !fo_series_file_at(src, "blk00000.dat", 9))
        return false;
    return block_files_copy(src, dst) == expected;
}

static int test_block_files_copy_path_limits(void)
{
    int failures = 0;

    TEST("file_ops block_files_copy joins paths up to 1023 bytes and refuses 1024") {
        char root[PATH_MAX] = "";
        bool ok = fo_root(root, "zcl_block_long");
        /* dir + '/' + "blk00000.dat" (12) is 1023 for a 1010-byte dir. */
        bool src_fits = ok && fo_block_scenario(root, "a", 1010, FO_SHORT, 1);
        bool src_over = ok && fo_block_scenario(root, "b", 1011, FO_SHORT, -1);
        bool dst_fits = ok && fo_block_scenario(root, "c", FO_SHORT, FO_BLOCK_DST_FITS, 1);
        bool dst_over = ok && fo_block_scenario(root, "e", FO_SHORT, 1011, -1);
        fo_cleanup(root);
        ASSERT(ok);
        ASSERT(src_fits);
        ASSERT(src_over);
        ASSERT(dst_fits);
        ASSERT(dst_over);
        PASS();
    } _test_next:;

    return failures;
}

static int fo_dir_scenario(const char *root, const char *tag, size_t src_len,
                           size_t dst_len)
{
    char src_tag[16], dst_tag[16], src[PATH_MAX], dst[PATH_MAX];
    char out[256] = "", err[256] = "";
    snprintf(src_tag, sizeof(src_tag), "%ss", tag);
    snprintf(dst_tag, sizeof(dst_tag), "%sd", tag);
    if (!fo_long_dir(root, src_tag, fo_short_total(root, src_len), src, sizeof(src)) ||
        !fo_long_dir(root, dst_tag, fo_short_total(root, dst_len), dst, sizeof(dst)) ||
        !fo_series_file_at(src, "f", 9))
        return -1;
    return fo_dir_copy_captured(root, src, dst, out, err);
}

static int test_dir_copy_path_limits(void)
{
    int failures = 0;

    TEST("file_ops dir_copy joins entry paths up to 1023 bytes and refuses 1024") {
        char root[PATH_MAX] = "";
        bool ok = fo_root(root, "zcl_dir_long");
        int src_fits = ok ? fo_dir_scenario(root, "a", 1021, FO_SHORT) : -1;
        int src_over = ok ? fo_dir_scenario(root, "b", 1022, FO_SHORT) : -1;
        int dst_fits = ok ? fo_dir_scenario(root, "c", FO_SHORT, FO_DIR_DST_FITS) : -1;
        int dst_over = ok ? fo_dir_scenario(root, "e", FO_SHORT, 1022) : -1;
        fo_cleanup(root);
        ASSERT(ok);
        ASSERT_EQ(src_fits, 1);
        ASSERT_EQ(src_over, 0);
        ASSERT_EQ(dst_fits, 1);
        ASSERT_EQ(dst_over, 0);
        PASS();
    } _test_next:;

    return failures;
}

static bool fo_clean_scenario(const char *root, const char *tag, size_t len,
                              bool expect_removed)
{
    char dir[PATH_MAX] = "";
    if (!fo_long_dir(root, tag, len, dir, sizeof(dir)) ||
        !fo_series_file_at(dir, "blk00000.dat", 4))
        return false;
    block_files_clean(dir);
    return fo_exists_at(dir, "blk00000.dat") != expect_removed;
}

static int test_block_files_clean_path_limits(void)
{
    int failures = 0;

    TEST("file_ops block_files_clean reaches files at 1023 bytes and leaves 1024") {
        char root[PATH_MAX] = "";
        bool ok = fo_root(root, "zcl_clean_long");
        bool fits = ok && fo_clean_scenario(root, "a", FO_CLEAN_FITS, true);
        bool over = ok && fo_clean_scenario(root, "b", 1011, false);
        fo_cleanup(root);
        ASSERT(ok);
        ASSERT(fits);
        ASSERT(over);
        PASS();
    } _test_next:;

    return failures;
}

static bool fo_stage_scenario(const char *root, const char *tag, size_t dst_len,
                              bool expect_copy)
{
    char dir[PATH_MAX] = "", src[PATH_MAX], dst[PATH_MAX];
    int staging = 0;
    /* dst is dir + "/x", so the staging name adds 21 bytes to dst_len. */
    if (!fo_long_dir(root, tag, dst_len - 2, dir, sizeof(dir)))
        return false;
    fo_path(src, sizeof(src), root, "stage-src.bin");
    fo_path(dst, sizeof(dst), dir, "x");
    if (!fo_write_pattern(src, 33))
        return false;
    bool copied = file_copy(src, dst);
    bool good = copied == expect_copy && fo_check_pattern(dst, 33) == expect_copy;
    return good && fo_entries(dir, &staging) == (expect_copy ? 1 : 0) && staging == 0;
}

static int test_file_copy_staging_name_limit(void)
{
    int failures = 0;

    TEST("file_ops file_copy fits its staging name in 4095 bytes and refuses 4096") {
        char root[PATH_MAX] = "";
        bool ok = fo_root(root, "zcl_stage_long");
        bool fits = ok && fo_stage_scenario(root, "a", FO_STAGE_FITS, true);
        bool over = ok && fo_stage_scenario(root, "b", FO_STAGE_OVER, false);
        fo_cleanup(root);
        ASSERT(ok);
        ASSERT(fits);
        ASSERT(over);
        PASS();
    } _test_next:;

    return failures;
}

/* ---- dir_copy must validate before it empties the destination ---- */

static int test_dir_copy_missing_source_keeps_destination(void)
{
    int failures = 0;

    TEST("file_ops dir_copy leaves the destination intact when the source is missing") {
        char dir[PATH_MAX] = "", dst[PATH_MAX] = "", stale[PATH_MAX] = "";
        char gone[PATH_MAX] = "", out[256] = "", err[256] = "";
        bool ok = fo_root(dir, "zcl_dir_copy_missing");
        if (ok) {
            fo_path(dst, sizeof(dst), dir, "dst");
            fo_path(stale, sizeof(stale), dst, "stale.txt");
            fo_path(gone, sizeof(gone), dir, "gone");
        }
        ok = ok && mkdir(dst, 0700) == 0 && fo_write_pattern(stale, 7);
        int result = ok ? fo_dir_copy_captured(dir, gone, dst, out, err) : -1;
        bool kept = ok && fo_check_pattern(stale, 7);
        fo_cleanup(dir);
        ASSERT(ok);
        ASSERT_EQ(result, 0);
        ASSERT(kept);
        PASS();
    } _test_next:;

    return failures;
}

static int test_dir_copy_subdirectory_source_keeps_destination(void)
{
    int failures = 0;

    TEST("file_ops dir_copy leaves the destination intact when the source holds a subdirectory") {
        char dir[PATH_MAX] = "", src[PATH_MAX] = "", dst[PATH_MAX] = "";
        char stale[PATH_MAX] = "", sub[PATH_MAX] = "", one[PATH_MAX] = "";
        char out[256] = "", err[256] = "";
        bool ok = fo_root(dir, "zcl_dir_copy_subdir");
        if (ok) {
            fo_path(src, sizeof(src), dir, "src");
            fo_path(dst, sizeof(dst), dir, "dst");
            fo_path(stale, sizeof(stale), dst, "stale.txt");
            fo_path(sub, sizeof(sub), src, "sub");
            fo_path(one, sizeof(one), src, "one.txt");
        }
        ok = ok && mkdir(src, 0700) == 0 && mkdir(dst, 0700) == 0 &&
             mkdir(sub, 0700) == 0 && fo_write_pattern(one, 5) &&
             fo_write_pattern(stale, 7);
        int result = ok ? fo_dir_copy_captured(dir, src, dst, out, err) : -1;
        bool kept = ok && fo_check_pattern(stale, 7);
        fo_cleanup(dir);
        ASSERT(ok);
        ASSERT_EQ(result, 0);
        ASSERT(kept);
        PASS();
    } _test_next:;

    return failures;
}

static int test_dir_copy_same_directory_keeps_source(void)
{
    int failures = 0;

    TEST("file_ops dir_copy refuses src equal to dst, spelled two ways, and keeps it") {
        char dir[PATH_MAX] = "", src[PATH_MAX] = "", alias[PATH_MAX] = "";
        char file[PATH_MAX] = "", out[256] = "", err[256] = "";
        bool ok = fo_root(dir, "zcl_dir_copy_same");
        if (ok) {
            fo_path(src, sizeof(src), dir, "src");
            fo_path(file, sizeof(file), src, "one.txt");
            snprintf(alias, sizeof(alias), "%s/src/../src/.", dir);
        }
        ok = ok && mkdir(src, 0700) == 0 && fo_write_pattern(file, 9);
        int same = ok ? fo_dir_copy_captured(dir, src, src, out, err) : -1;
        bool kept = ok && fo_check_pattern(file, 9);
        int aliased = ok ? fo_dir_copy_captured(dir, src, alias, out, err) : -1;
        bool kept_alias = ok && fo_check_pattern(file, 9);
        fo_cleanup(dir);
        ASSERT(ok);
        ASSERT_EQ(same, 0);
        ASSERT(kept);
        ASSERT_EQ(aliased, 0);
        ASSERT(kept_alias);
        PASS();
    } _test_next:;

    return failures;
}

static int test_dir_copy_nested_directories_keep_source(void)
{
    int failures = 0;

    TEST("file_ops dir_copy refuses a destination that is an ancestor or descendant of the source") {
        char dir[PATH_MAX] = "", top[PATH_MAX] = "", inner[PATH_MAX] = "";
        char deep[PATH_MAX] = "", inner_file[PATH_MAX] = "";
        char top_file[PATH_MAX] = "", out[256] = "", err[256] = "";
        bool ok = fo_root(dir, "zcl_dir_copy_nested");
        if (ok) {
            fo_path(top, sizeof(top), dir, "top");
            fo_path(inner, sizeof(inner), top, "inner");
            fo_path(deep, sizeof(deep), top, "inner/deep");
            fo_path(inner_file, sizeof(inner_file), inner, "one.txt");
            fo_path(top_file, sizeof(top_file), top, "two.txt");
        }
        ok = ok && mkdir(top, 0700) == 0 && mkdir(inner, 0700) == 0 &&
             fo_write_pattern(inner_file, 9) && fo_write_pattern(top_file, 4);
        /* dst is an ancestor of src: the old wipe deleted the source tree. */
        int up = ok ? fo_dir_copy_captured(dir, inner, top, out, err) : -1;
        bool inner_kept = ok && fo_check_pattern(inner_file, 9);
        bool top_kept = ok && fo_check_pattern(top_file, 4);
        /* dst is inside src. */
        int down = ok ? fo_dir_copy_captured(dir, top, deep, out, err) : -1;
        bool top_kept_again = ok && fo_check_pattern(top_file, 4) &&
                              fo_check_pattern(inner_file, 9);
        fo_cleanup(dir);
        ASSERT(ok);
        ASSERT_EQ(up, 0);
        ASSERT(inner_kept);
        ASSERT(top_kept);
        ASSERT_EQ(down, 0);
        ASSERT(top_kept_again);
        PASS();
    } _test_next:;

    return failures;
}

static int test_block_files_clean_exact_names(void)
{
    int failures = 0;

    TEST("file_ops block_files_clean keeps backups and odd names, removes only blk/rev digits .dat") {
        char dir[PATH_MAX] = "";
        bool ok = fo_root(dir, "zcl_block_clean_exact");
        static const char *const gone[] = {"blk00000.dat", "rev00000.dat",
                                           "blk_sync.dat", "rev_sync.dat",
                                           "blk123456.dat"};
        static const char *const kept[] = {
            "blk00000.dat.bak", "rev00000.dat.bak", "blkfoo.dat.old",
            "blkfoo.dat", "blk.dat", "blk1.dat", "blk00000.dat~",
            "blk00000dat", "xblk00000.dat", "blk0000a.dat"};
        for (size_t i = 0; ok && i < 5; i++)
            ok = fo_series_file(dir, gone[i], 4);
        for (size_t i = 0; ok && i < 10; i++)
            ok = fo_series_file(dir, kept[i], 4);
        if (ok)
            block_files_clean(dir);
        bool removed = ok, retained = ok;
        for (size_t i = 0; ok && i < 5; i++) {
            char path[PATH_MAX];
            fo_path(path, sizeof(path), dir, gone[i]);
            removed = removed && !fo_exists(path);
        }
        for (size_t i = 0; ok && i < 10; i++)
            retained = retained && fo_series_has(dir, kept[i], 4);
        fo_cleanup(dir);
        ASSERT(ok);
        ASSERT(removed);
        ASSERT(retained);
        PASS();
    } _test_next:;

    return failures;
}

int test_file_ops(void)
{
    int failures = 0;

    failures += test_file_copy_overwrites_regular_files();
    failures += test_dir_copy_success();
    failures += test_dir_copy_partial_failure();
    failures += test_block_files_copy_rev_failure();
    failures += test_file_copy_chunk_boundaries();
    failures += test_file_copy_refusals();
    failures += test_dir_copy_semantics();
    failures += test_dir_copy_refusal_reports();
    failures += test_block_files_copy_series();
    failures += test_block_files_copy_sync_spelling();
    failures += test_block_files_clean_selection();
    failures += test_block_files_copy_path_limits();
    failures += test_dir_copy_path_limits();
    failures += test_block_files_clean_path_limits();
    failures += test_file_copy_staging_name_limit();
    failures += test_dir_copy_missing_source_keeps_destination();
    failures += test_dir_copy_subdirectory_source_keeps_destination();
    failures += test_dir_copy_same_directory_keeps_source();
    failures += test_dir_copy_nested_directories_keep_source();
    failures += test_block_files_clean_exact_names();

    return failures;
}
