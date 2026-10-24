/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Coverage for the fd-based file-tree primitive
 * (platform/modules/util/src/file_tree_ops.c): zcl_tree_copy /
 * zcl_tree_remove / zcl_mkdir_p.
 *
 *   - nested-tree copy: byte + mtime_ns FNV-signature parity vs the source
 *     (ZCL_COPY_PRESERVE_TIMES matches `cp -a`; mirrors
 *     chainstate_dir_signature in utxo_recovery_ldb_copy.c);
 *   - ZCL_COPY_UPDATE_ONLY skips a newer destination, copies an older one;
 *   - identical paths and hardlinks refuse without losing source bytes;
 *   - a filter skips "LOCK" + a prefix/suffix pattern;
 *   - a symlink root and a symlink entry inside a tree are refused;
 *   - zcl_tree_remove empties a nested tree and treats ENOENT as success;
 *   - an unwritable destination propagates a populated error result;
 *   - the recursion depth bound trips with a real error.
 *
 * Pure filesystem I/O under a mkdtemp scratch dir; no node, network, RNG or
 * wall clock. */

#include "test/test_core.h"

#include "util/file_tree_ops.h"

#if !defined(_WIN32)

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* ── helpers ─────────────────────────────────────────────────────── */

static bool fto_write(const char *path, const char *contents)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    size_t len = strlen(contents);
    bool ok = fwrite(contents, 1, len, f) == len;
    fclose(f);
    return ok;
}

static bool fto_read(const char *path, char *out, size_t out_size)
{
    FILE *f = fopen(path, "rb");
    if (!f || out_size == 0)
        return false;
    size_t n = fread(out, 1, out_size - 1, f);
    out[n] = '\0';
    fclose(f);
    return true;
}

/* Order-independent fold over (relative-name, size, mtime_ns) of every
 * regular file and directory under `root`: each entry is hashed
 * independently and XORed (readdir order is not a contract). Equal
 * signatures across a copy prove names, sizes and mtime_ns were preserved.
 * Symlinks are ignored (the walker refuses them). */
static void fto_sig_walk(const char *root, const char *rel, uint64_t *sig)
{
    DIR *d = opendir(root);
    if (!d)
        return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char fp[2048];
        char rp[1600];
        int n = snprintf(fp, sizeof(fp), "%s/%s", root, e->d_name);
        int m = snprintf(rp, sizeof(rp), "%s/%s", rel, e->d_name);
        if (n <= 0 || (size_t)n >= sizeof(fp) ||
            m <= 0 || (size_t)m >= sizeof(rp))
            continue;
        struct stat st;
        if (lstat(fp, &st) != 0 || S_ISLNK(st.st_mode))
            continue;
        /* Fold the RELATIVE path so both trees hash to the same value even
         * though their absolute roots differ. */
        uint64_t entry_sig = 14695981039346656037ULL;
        const char *c = rp;
        while (*c) {
            entry_sig ^= (uint8_t)*c++;
            entry_sig *= 1099511628211ULL;
        }
        uint64_t fields[4] = { (uint64_t)st.st_size,
                               (uint64_t)st.st_mtim.tv_sec,
                               (uint64_t)st.st_mtim.tv_nsec,
                               (uint64_t)(S_ISDIR(st.st_mode) ? 1 : 0) };
        const uint8_t *b = (const uint8_t *)fields;
        for (size_t i = 0; i < sizeof(fields); i++) {
            entry_sig ^= b[i];
            entry_sig *= 1099511628211ULL;
        }
        *sig ^= entry_sig;
        if (S_ISDIR(st.st_mode))
            fto_sig_walk(fp, rp, sig);
    }
    closedir(d);
}

static uint64_t fto_signature(const char *root)
{
    uint64_t sig = 0;
    fto_sig_walk(root, "", &sig);
    return sig;
}

/* Set an mtime `delta_sec` relative to now on a path (for UPDATE_ONLY). */
static bool fto_set_mtime(const char *path, time_t sec, long nsec)
{
    struct timespec ts[2];
    ts[0].tv_sec = sec; ts[0].tv_nsec = nsec;   /* atime */
    ts[1].tv_sec = sec; ts[1].tv_nsec = nsec;   /* mtime */
    return utimensat(AT_FDCWD, path, ts, 0) == 0;
}

/* Filter: skip "LOCK" and any name beginning "tmp" or ending ".bak". */
static bool fto_filter(const char *name, bool is_dir, void *ctx)
{
    (void)is_dir; (void)ctx;
    if (strcmp(name, "LOCK") == 0)
        return false;
    if (strncmp(name, "tmp", 3) == 0)
        return false;
    size_t len = strlen(name);
    if (len >= 4 && strcmp(name + len - 4, ".bak") == 0)
        return false;
    return true;
}

/* ── cases ───────────────────────────────────────────────────────── */

/* Populate `src` with the signature fixture: a nested dir and three files,
 * each with an explicit mtime_ns, so PRESERVE_TIMES has something non-default
 * to reproduce. */
static bool fto_make_sig_tree(const char *src)
{
    char sub[1024], a[1024], b[1024], cfile[1024];
    snprintf(sub, sizeof(sub), "%s/nested", src);
    snprintf(a, sizeof(a), "%s/one.txt", src);
    snprintf(b, sizeof(b), "%s/two.dat", src);
    snprintf(cfile, sizeof(cfile), "%s/deep.bin", sub);

    bool ok = mkdir(src, 0755) == 0;
    ok = ok && mkdir(sub, 0755) == 0;
    ok = ok && fto_write(a, "alpha");
    ok = ok && fto_write(b, "beta-bytes-0123456789");
    ok = ok && fto_write(cfile, "deep-content");
    ok = ok && fto_set_mtime(a, 1600000000, 123456789L);
    ok = ok && fto_set_mtime(b, 1600000100, 987654321L);
    ok = ok && fto_set_mtime(cfile, 1600000200, 424242424L);
    ok = ok && fto_set_mtime(sub, 1600000300, 111222333L);
    ok = ok && fto_set_mtime(src, 1600000400, 444555666L);
    return ok;
}

/* UPDATE_ONLY fixture: newer.txt is OLDER in src than the pre-existing dst
 * (keep dst); older.txt is NEWER in src than dst (overwrite). */
static bool fto_make_update_fixture(const char *src, const char *dst)
{
    char s_new[1024], s_old[1024], d_new[1024], d_old[1024];
    snprintf(s_new, sizeof(s_new), "%s/newer.txt", src);
    snprintf(s_old, sizeof(s_old), "%s/older.txt", src);
    snprintf(d_new, sizeof(d_new), "%s/newer.txt", dst);
    snprintf(d_old, sizeof(d_old), "%s/older.txt", dst);

    bool ok = mkdir(src, 0755) == 0;
    ok = ok && mkdir(dst, 0755) == 0;
    ok = ok && fto_write(s_new, "SRC-new");
    ok = ok && fto_write(d_new, "DST-keep");
    ok = ok && fto_set_mtime(s_new, 1600000000, 0);
    ok = ok && fto_set_mtime(d_new, 1700000000, 0);   /* dst newer */
    ok = ok && fto_write(s_old, "SRC-overwrite");
    ok = ok && fto_write(d_old, "DST-stale");
    ok = ok && fto_set_mtime(s_old, 1700000000, 0);   /* src newer */
    ok = ok && fto_set_mtime(d_old, 1600000000, 0);
    return ok;
}

/* True when the file at `path` reads back exactly `want`. */
static bool fto_content_is(const char *path, const char *want)
{
    char buf[64];
    return fto_read(path, buf, sizeof(buf)) && strcmp(buf, want) == 0;
}

/* Copy src -> dst with no flags. True when the copy is refused with a
 * populated message; the copy runs even when `ok` is already false. */
static bool fto_copy_refused(const char *src, const char *dst, bool ok)
{
    struct zcl_result r = zcl_tree_copy(src, dst, 0, NULL, NULL);
    ok = ok && !r.ok;                        /* refused */
    ok = ok && r.message[0] != '\0';         /* populated context */
    return ok;
}

/* (a) a symlink ROOT is refused. */
static bool fto_symlink_root_refused(const char *dir, bool ok)
{
    const char *base = dir ? dir : "";
    char realfile[1024], link_root[1024], dst1[1024];
    snprintf(realfile, sizeof(realfile), "%s/real.txt", base);
    snprintf(link_root, sizeof(link_root), "%s/link.txt", base);
    snprintf(dst1, sizeof(dst1), "%s/copy1.txt", base);
    ok = ok && fto_write(realfile, "real");
    ok = ok && symlink(realfile, link_root) == 0;
    return fto_copy_refused(link_root, dst1, ok);
}

/* (b) a symlink ENTRY inside a tree is refused. */
static bool fto_symlink_entry_refused(const char *dir, bool ok)
{
    const char *base = dir ? dir : "";
    char src[1024], inner_target[1024], inner_link[1024], dst2[1024];
    snprintf(src, sizeof(src), "%s/tree", base);
    snprintf(inner_target, sizeof(inner_target), "%s/target.txt", src);
    snprintf(inner_link, sizeof(inner_link), "%s/alias.txt", src);
    snprintf(dst2, sizeof(dst2), "%s/tree_copy", base);
    ok = ok && mkdir(src, 0755) == 0;
    ok = ok && fto_write(inner_target, "target");
    ok = ok && symlink(inner_target, inner_link) == 0;
    return fto_copy_refused(src, dst2, ok);
}

/* Create `src` plus ZCL_TREE_MAX_DEPTH + 4 nested "d" levels below it, so
 * the walker must descend past its cap. */
static bool fto_make_deep_tree(const char *src)
{
    if (mkdir(src, 0755) != 0)
        return false;
    char path[8192];
    int off = snprintf(path, sizeof(path), "%s", src);
    for (int i = 0; i < ZCL_TREE_MAX_DEPTH + 4; i++) {
        int n = snprintf(path + off, sizeof(path) - (size_t)off, "/d");
        off += n;
        if ((size_t)off >= sizeof(path))
            return false;
        if (mkdir(path, 0755) != 0)
            return false;
    }
    return true;
}

/* Manual bottom-up teardown of a deep chain under `root`: src and the
 * partial dst exceed ZCL_TREE_MAX_DEPTH, so zcl_tree_remove would trip the
 * cap. rmdir is best-effort; ENOENT/ENOTEMPTY are ignored. */
static void fto_rmdir_deep_chain(const char *root)
{
    for (int k = ZCL_TREE_MAX_DEPTH + 6; k >= 0; k--) {
        char p[8192];
        int o = snprintf(p, sizeof(p), "%s", root);
        for (int i = 0; i < k && (size_t)o < sizeof(p); i++)
            o += snprintf(p + o, sizeof(p) - (size_t)o, "/d");
        rmdir(p);
    }
}

static int test_copy_null_source(void)
{
    int failures = 0;
    TEST("file_tree_ops NULL source names the missing field and repair") {
        char root[PATH_MAX], dst[PATH_MAX + 16];
        char *dir = test_mkdtemp(root, sizeof(root), "fto_null");
        ASSERT(dir != NULL);
        snprintf(dst, sizeof(dst), "%s/copied", dir);
        struct zcl_result r = zcl_tree_copy(NULL, dst, 0, NULL, NULL);
        bool refused = !r.ok && r.code == -1;
        bool named = strstr(r.message, "NULL src;") != NULL;
        bool repair = strstr(r.message, "supply a source path") != NULL;
        bool untouched = access(dst, F_OK) == -1 && errno == ENOENT;
        struct zcl_result cleanup = zcl_tree_remove(dir);
        ASSERT(cleanup.ok);
        ASSERT(refused && untouched);
        ASSERT(named && repair);
        PASS();
    } _test_next:;
    return failures;
}

#if defined(__linux__)
static bool fto_source_read_failure(const char *dst)
{
    /* Qualify the exact read-EIO fixture; an unavailable proc entry fails. */
    int fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    char byte;
    ssize_t got = pread(fd, &byte, 1, 0);
    int cause = errno;
    bool closed = close(fd) == 0;
    if (!closed || got != -1 || cause != EIO)
        return false;
    struct zcl_result r = zcl_tree_copy("/proc/self/mem", dst, 0, NULL, NULL);
    char expected[32];
    snprintf(expected, sizeof(expected), "errno=%d:", EIO);
    if (r.ok || r.code != -1)
        return false;
    if (!strstr(r.message, "read failed: /proc/self/mem:"))
        return false;
    if (!strstr(r.message, expected))
        return false;
    return strstr(r.message, "inspect source readability") != NULL;
}

static int test_copy_source_read_failure(void)
{
    int failures = 0;
    TEST("file_tree_ops read EIO identifies source and readability repair") {
        char root[PATH_MAX], dst[PATH_MAX + 16];
        char *dir = test_mkdtemp(root, sizeof(root), "fto_read");
        ASSERT(dir != NULL);
        snprintf(dst, sizeof(dst), "%s/copied", dir);
        pid_t child = fork();
        if (child == 0) {
            alarm(10);
            _exit(fto_source_read_failure(dst) ? 0 : 1);
        }
        int status = 0;
        pid_t waited = -1;
        if (child > 0) {
            do { waited = waitpid(child, &status, 0); }
            while (waited < 0 && errno == EINTR);
        }
        struct zcl_result cleanup = zcl_tree_remove(dir);
        ASSERT(cleanup.ok);
        ASSERT(child > 0 && waited == child);
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        PASS();
    } _test_next:;
    return failures;
}
#endif

static int test_nested_copy_signature_parity(void)
{
    int failures = 0;

    TEST("file_tree_ops nested copy preserves bytes + mtime_ns (signature)") {
        char root[] = "/tmp/zcl_fto_sig_XXXXXX";
        char *dir = mkdtemp(root);
        char src[1024], dst[1024], copied[1024], buf[64];
        bool ok = dir != NULL;

        snprintf(src, sizeof(src), "%s/src", dir ? dir : "");
        snprintf(dst, sizeof(dst), "%s/dst", dir ? dir : "");
        snprintf(copied, sizeof(copied), "%s/nested/deep.bin", dst);

        ok = ok && fto_make_sig_tree(src);

        uint64_t src_sig = ok ? fto_signature(src) : 0;

        struct zcl_result r =
            zcl_tree_copy(src, dst, ZCL_COPY_PRESERVE_TIMES, NULL, NULL);
        ok = ok && r.ok;

        uint64_t dst_sig = ok ? fto_signature(dst) : 1;
        ok = ok && src_sig != 0 && src_sig == dst_sig;

        /* Bytes really landed. */
        ok = ok && fto_read(copied, buf, sizeof(buf));
        ok = ok && strcmp(buf, "deep-content") == 0;

        if (dir) {
            struct zcl_result rr = zcl_tree_remove(dir);
            ok = ok && rr.ok;
        }
        ASSERT(ok);
        PASS();
    } _test_next:;

    return failures;
}

static bool fto_same_inode_preserved(bool hardlink)
{
    char root[PATH_MAX];
    char *dir = test_mkdtemp(root, sizeof(root), "fto_same");
    if (!dir)
        return false;
    /* The helper bounds root to PATH_MAX; these fixed suffixes fit. */
    char src[PATH_MAX + 16], alias[PATH_MAX + 16], buf[8];
    snprintf(src, sizeof(src), "%s/src", dir);
    snprintf(alias, sizeof(alias), "%s/alias", dir);
    bool ok = fto_write(src, "KEEP");
    if (hardlink)
        ok = ok && link(src, alias) == 0;
    if (ok) {
        const char *dst = hardlink ? alias : src;
        struct zcl_result r = zcl_tree_copy(src, dst, 0, NULL, NULL);
        ok = !r.ok && strstr(r.message, "same-inode") != NULL;
        struct stat st;
        ok = ok && stat(src, &st) == 0 && st.st_size == 4;
        ok = ok && fto_read(src, buf, sizeof(buf)) && strcmp(buf, "KEEP") == 0;
        ok = ok && fto_read(dst, buf, sizeof(buf)) && strcmp(buf, "KEEP") == 0;
    }
    struct zcl_result rr = zcl_tree_remove(dir);
    return rr.ok && ok;
}

static int test_same_inode_refuse(bool hardlink)
{
    int failures = 0;
    TEST(hardlink ? "file_tree_ops hardlink refuses without losing KEEP"
                  : "file_tree_ops identical path refuses without losing KEEP") {
        ASSERT(fto_same_inode_preserved(hardlink));
        PASS();
    } _test_next:;
    return failures;
}

static int test_update_only(void)
{
    int failures = 0;

    TEST("file_tree_ops UPDATE_ONLY skips newer dst, copies older dst") {
        char root[] = "/tmp/zcl_fto_upd_XXXXXX";
        char *dir = mkdtemp(root);
        char src[1024], dst[1024], d_new[1024], d_old[1024];
        bool ok = dir != NULL;

        snprintf(src, sizeof(src), "%s/src", dir ? dir : "");
        snprintf(dst, sizeof(dst), "%s/dst", dir ? dir : "");
        snprintf(d_new, sizeof(d_new), "%s/newer.txt", dst);
        snprintf(d_old, sizeof(d_old), "%s/older.txt", dst);

        ok = ok && fto_make_update_fixture(src, dst);

        struct zcl_result r =
            zcl_tree_copy(src, dst, ZCL_COPY_UPDATE_ONLY, NULL, NULL);
        ok = ok && r.ok;

        /* dst newer -> untouched. */
        ok = ok && fto_content_is(d_new, "DST-keep");
        /* dst older -> replaced by source content. */
        ok = ok && fto_content_is(d_old, "SRC-overwrite");

        if (dir) {
            struct zcl_result rr = zcl_tree_remove(dir);
            ok = ok && rr.ok;
        }
        ASSERT(ok);
        PASS();
    } _test_next:;

    return failures;
}

static int test_filter(void)
{
    int failures = 0;

    TEST("file_tree_ops filter skips LOCK + prefix/suffix patterns") {
        char root[] = "/tmp/zcl_fto_filt_XXXXXX";
        char *dir = mkdtemp(root);
        char src[1024], dst[1024];
        char keep[1024], lock[1024], tmp[1024], bak[1024];
        char d_keep[1024], d_lock[1024], d_tmp[1024], d_bak[1024];
        bool ok = dir != NULL;

        snprintf(src, sizeof(src), "%s/src", dir ? dir : "");
        snprintf(dst, sizeof(dst), "%s/dst", dir ? dir : "");
        snprintf(keep, sizeof(keep), "%s/keep.txt", src);
        snprintf(lock, sizeof(lock), "%s/LOCK", src);
        snprintf(tmp, sizeof(tmp), "%s/tmpfile", src);
        snprintf(bak, sizeof(bak), "%s/data.bak", src);
        snprintf(d_keep, sizeof(d_keep), "%s/keep.txt", dst);
        snprintf(d_lock, sizeof(d_lock), "%s/LOCK", dst);
        snprintf(d_tmp, sizeof(d_tmp), "%s/tmpfile", dst);
        snprintf(d_bak, sizeof(d_bak), "%s/data.bak", dst);

        ok = ok && mkdir(src, 0755) == 0;
        ok = ok && fto_write(keep, "keep");
        ok = ok && fto_write(lock, "lock");
        ok = ok && fto_write(tmp, "tmp");
        ok = ok && fto_write(bak, "bak");

        struct zcl_result r = zcl_tree_copy(src, dst, 0, fto_filter, NULL);
        ok = ok && r.ok;

        ok = ok && access(d_keep, F_OK) == 0;   /* kept */
        ok = ok && access(d_lock, F_OK) != 0;   /* skipped */
        ok = ok && access(d_tmp, F_OK) != 0;    /* skipped */
        ok = ok && access(d_bak, F_OK) != 0;    /* skipped */

        if (dir) {
            struct zcl_result rr = zcl_tree_remove(dir);
            ok = ok && rr.ok;
        }
        ASSERT(ok);
        PASS();
    } _test_next:;

    return failures;
}

static int test_symlink_refuse(void)
{
    int failures = 0;

    TEST("file_tree_ops refuses symlink root and symlink entries") {
        char root[] = "/tmp/zcl_fto_lnk_XXXXXX";
        char *dir = mkdtemp(root);
        bool ok = dir != NULL;

        /* (a) symlink ROOT is refused; (b) symlink ENTRY inside a tree is
         * refused. Each step keeps the running ok so later writes stay
         * skipped after an earlier failure. */
        ok = fto_symlink_root_refused(dir, ok);
        ok = fto_symlink_entry_refused(dir, ok);

        if (dir) {
            struct zcl_result rr = zcl_tree_remove(dir);
            ok = ok && rr.ok;
        }
        ASSERT(ok);
        PASS();
    } _test_next:;

    return failures;
}

static int test_remove_and_enoent(void)
{
    int failures = 0;

    TEST("file_tree_ops remove clears nested tree; ENOENT is success") {
        char root[] = "/tmp/zcl_fto_rm_XXXXXX";
        char *dir = mkdtemp(root);
        char tree[1024], sub[1024], f1[1024], f2[1024], missing[1024];
        bool ok = dir != NULL;

        snprintf(tree, sizeof(tree), "%s/tree", dir ? dir : "");
        snprintf(sub, sizeof(sub), "%s/a/b/c", tree);
        snprintf(missing, sizeof(missing), "%s/does-not-exist", dir ? dir : "");

        ok = ok && zcl_mkdir_p(sub, 0755).ok;
        snprintf(f1, sizeof(f1), "%s/top.txt", tree);
        snprintf(f2, sizeof(f2), "%s/leaf.txt", sub);
        ok = ok && fto_write(f1, "top");
        ok = ok && fto_write(f2, "leaf");

        struct zcl_result r = zcl_tree_remove(tree);
        ok = ok && r.ok;
        ok = ok && access(tree, F_OK) != 0;      /* gone */

        /* ENOENT path is success (rm -rf semantics). */
        struct zcl_result r2 = zcl_tree_remove(missing);
        ok = ok && r2.ok;

        if (dir) {
            struct zcl_result rr = zcl_tree_remove(dir);
            ok = ok && rr.ok;
        }
        ASSERT(ok);
        PASS();
    } _test_next:;

    return failures;
}

static int test_unwritable_dest(void)
{
    int failures = 0;

    TEST("file_tree_ops surfaces an unwritable destination with context") {
        char root[] = "/tmp/zcl_fto_perm_XXXXXX";
        char *dir = mkdtemp(root);
        char src[1024], f[1024], ro[1024], dst[1024];
        bool ok = dir != NULL;
        bool as_root = (geteuid() == 0);

        snprintf(src, sizeof(src), "%s/src", dir ? dir : "");
        snprintf(f, sizeof(f), "%s/file.txt", src);
        snprintf(ro, sizeof(ro), "%s/ro", dir ? dir : "");
        snprintf(dst, sizeof(dst), "%s/ro/dst", dir ? dir : "");

        ok = ok && mkdir(src, 0755) == 0;
        ok = ok && fto_write(f, "payload");
        ok = ok && mkdir(ro, 0500) == 0;         /* read+exec, no write */

        struct zcl_result r = zcl_tree_copy(src, dst, 0, NULL, NULL);
        if (as_root) {
            /* root bypasses DAC write bits, so only require a well-formed
             * result. */
            ok = ok && (r.ok || r.message[0] != '\0');
        } else {
            ok = ok && !r.ok;                    /* mkdir(dst) denied */
            ok = ok && r.message[0] != '\0';     /* populated context */
        }

        if (dir) {
            chmod(ro, 0755);                     /* so cleanup can recurse */
            struct zcl_result rr = zcl_tree_remove(dir);
            ok = ok && rr.ok;
        }
        ASSERT(ok);
        PASS();
    } _test_next:;

    return failures;
}

static int test_depth_bound(void)
{
    int failures = 0;

    TEST("file_tree_ops copy refuses a tree deeper than the depth bound") {
        char root[] = "/tmp/zcl_fto_deep_XXXXXX";
        char *dir = mkdtemp(root);
        char src[1024], dst[1024];
        bool ok = dir != NULL;

        snprintf(src, sizeof(src), "%s/src", dir ? dir : "");
        snprintf(dst, sizeof(dst), "%s/dst", dir ? dir : "");

        ok = ok && fto_make_deep_tree(src);

        struct zcl_result r = zcl_tree_copy(src, dst, 0, NULL, NULL);
        ok = ok && !r.ok;                        /* depth cap tripped */
        ok = ok && r.message[0] != '\0';

        if (dir) {
            fto_rmdir_deep_chain(src);
            fto_rmdir_deep_chain(dst);
            struct zcl_result rr = zcl_tree_remove(dir);
            ok = ok && rr.ok;                    /* dir now shallow + empty */
        }
        ASSERT(ok);
        PASS();
    } _test_next:;

    return failures;
}

static int test_file_tree_ops_platform_arm(void)
{
    int failures = 0;

    failures += test_copy_null_source();
#if defined(__linux__)
    failures += test_copy_source_read_failure();
#endif
    failures += test_nested_copy_signature_parity();
    failures += test_same_inode_refuse(false);
    failures += test_same_inode_refuse(true);
    failures += test_update_only();
    failures += test_filter();
    failures += test_symlink_refuse();
    failures += test_remove_and_enoent();
    failures += test_unwritable_dest();
    failures += test_depth_bound();

    return failures;
}

#else /* _WIN32 */

/* Production file_tree_ops refuses every recursive mutation on Windows
 * ("disabled pending handle-bound no-reparse qualification"), so no case
 * here can run. */
static int test_file_tree_ops_platform_arm(void)
{
    printf("test_file_tree_ops: SKIP (Windows): file_tree_ops recursive "
           "mutation is disabled on Windows by production refusal\n");
    return 0;
}

#endif /* !_WIN32 */

int test_file_tree_ops(void)
{
    return test_file_tree_ops_platform_arm();
}
