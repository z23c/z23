/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: coverage for codeindex_is_stale(), the freshness verdict the
 * rebuild/refresh lanes consult before trusting an on-disk store. Its
 * contract: compare the live source digest AND depfile stats AND the
 * store format/schema metadata against what the store recorded; *stale
 * reports the verdict, the out-param is optional, and a null codeindex
 * fails closed with a stale verdict. */

#include "test/test_core.h"

#include "codeindex/codeindex.h"
#include "codeindex/codeindex_build.h"

#include <errno.h>
#if defined(__linux__)
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#endif
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool cis_write(const char *root, const char *rel, const char *content)
{
    char full[512];
    int n = snprintf(full, sizeof(full), "%s/%s", root, rel);
    if (n <= 0 || (size_t)n >= sizeof(full)) {
        fprintf(stderr, "codeindex stale: fixture path too long: %s/%s\n",
                root, rel);
        return false;
    }
    for (char *p = full + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(full, 0755) != 0 && errno != EEXIST) {
                perror(full);
                return false;
            }
            *p = '/';
        }
    }
    FILE *f = fopen(full, "wb");
    if (!f) {
        perror(full);
        return false;
    }
    size_t len = strlen(content);
    bool ok = fwrite(content, 1, len, f) == len;
    bool closed = fclose(f) == 0;
    if (!ok || !closed)
        fprintf(stderr, "codeindex stale: fixture write/close failed: %s\n",
                full);
    return closed && ok;
}

static bool cis_seed(const char *root)
{
    return cis_write(root, "core/modules/net/src/foo.c",
                     "int foo(void) { return 1; }\n") &&
           cis_write(root, "core/modules/net/include/net/foo.h",
                     "#ifndef FOO_H\n#define FOO_H\nint foo(void);\n#endif\n");
}

static int test_cis_null_refuses(void)
{
    int failures = 0;
    TEST("codeindex stale: null codeindex fails closed") {
        bool stale = false;
        ASSERT(!codeindex_is_stale(NULL, &stale));
        ASSERT(stale);
        ASSERT(!codeindex_is_stale(NULL, NULL));
        PASS();
    } _test_next:;
    return failures;
}

static int test_cis_fresh_index_is_current(void)
{
    int failures = 0;
    char dir[256] = {0};
    struct codeindex *ci = NULL;
    TEST("codeindex stale: a freshly built index is current") {
        test_make_tmpdir(dir, sizeof(dir), "cistale", "fresh");
        ASSERT(cis_seed(dir));
        ci = codeindex_open(dir);
        ASSERT(ci != NULL);
        bool stale = true;
        ASSERT(codeindex_is_stale(ci, &stale));
        ASSERT(!stale);
        /* The out-param is documented optional. */
        ASSERT(codeindex_is_stale(ci, NULL));
        PASS();
    } _test_next:;
    codeindex_close(ci);
    if (dir[0]) test_rm_rf_recursive(dir);
    return failures;
}

static int test_cis_source_edit_stales_then_rebuild_clears(void)
{
    int failures = 0;
    char dir[256] = {0};
    struct codeindex *ci = NULL;
    TEST("codeindex stale: a source edit stales; rebuild clears") {
        test_make_tmpdir(dir, sizeof(dir), "cistale", "edit");
        ASSERT(cis_seed(dir));
        ci = codeindex_open(dir);
        ASSERT(ci != NULL);
        bool stale = false;
        ASSERT(codeindex_is_stale(ci, &stale) && !stale);
        ASSERT(cis_write(dir, "core/modules/net/src/foo.c",
                         "int foo(void) { return 200; }\n"));
        ASSERT(codeindex_is_stale(ci, &stale));
        ASSERT(stale);
        ASSERT(codeindex_rebuild(ci));
        ASSERT(codeindex_is_stale(ci, &stale));
        ASSERT(!stale);
        PASS();
    } _test_next:;
    codeindex_close(ci);
    if (dir[0]) test_rm_rf_recursive(dir);
    return failures;
}

static int test_cis_deleted_source_stales(void)
{
    int failures = 0;
    char dir[256] = {0};
    struct codeindex *ci = NULL;
    TEST("codeindex stale: deleting a watched source stales the store") {
        test_make_tmpdir(dir, sizeof(dir), "cistale", "delete");
        ASSERT(cis_seed(dir));
        ci = codeindex_open(dir);
        ASSERT(ci != NULL);
        char header[512];
        int n = snprintf(header, sizeof(header),
                         "%s/core/modules/net/include/net/foo.h", dir);
        ASSERT(n > 0 && (size_t)n < sizeof(header));
        ASSERT(unlink(header) == 0);
        bool stale = false;
        ASSERT(codeindex_is_stale(ci, &stale));
        ASSERT(stale);
        PASS();
    } _test_next:;
    codeindex_close(ci);
    if (dir[0]) test_rm_rf_recursive(dir);
    return failures;
}

/* Change-watched freshness memo. A second open must not walk the tree; any
 * change the walk would see must still reach the verdict. */
static bool cis_ready(const char *dir, struct codeindex **ci)
{
    if (!cis_seed(dir) ||
        !cis_write(dir, "tools/deep/er/x.c", "int x(void) { return 0; }\n"))
        return false;
    *ci = codeindex_open(dir);
    bool stale = true;
    return *ci && codeindex_is_stale(*ci, &stale) && !stale;
}

static bool cis_verdict(struct codeindex *ci, bool want_stale)
{
    bool stale = !want_stale;
    return codeindex_is_stale(ci, &stale) && stale == want_stale;
}

static int test_cis_memo_second_open_skips_walk(void)
{
    int failures = 0;
    char dir[256] = {0};
    struct codeindex *ci = NULL;
    TEST("codeindex stale: a warm second check performs no tree walk") {
        test_make_tmpdir(dir, sizeof(dir), "cistale", "memo");
        ASSERT(cis_ready(dir, &ci));
        uint64_t before = codeindex_test_freshness_walks();
        ASSERT(cis_verdict(ci, false));
        ASSERT(cis_verdict(ci, false));
        ASSERT(codeindex_test_freshness_walks() == before);
        PASS();
    } _test_next:;
    codeindex_close(ci);
    if (dir[0]) test_rm_rf_recursive(dir);
    return failures;
}

static int test_cis_memo_inplace_write_walks(void)
{
    int failures = 0;
    char dir[256] = {0}, path[512];
    struct codeindex *ci = NULL;
    TEST("codeindex stale: an in-place write after the memo walks and sees stale") {
        test_make_tmpdir(dir, sizeof(dir), "cistale", "memowrite");
        ASSERT(cis_ready(dir, &ci));
        ASSERT(cis_verdict(ci, false));
        snprintf(path, sizeof(path), "%s/tools/deep/er/x.c", dir);
        FILE *f = fopen(path, "r+b");
        ASSERT(f != NULL);
        ASSERT(fwrite("xyz", 1, 3, f) == 3);
        ASSERT(fclose(f) == 0);
        uint64_t before = codeindex_test_freshness_walks();
        ASSERT(cis_verdict(ci, true));
        ASSERT(codeindex_test_freshness_walks() == before + 1);
        PASS();
    } _test_next:;
    codeindex_close(ci);
    if (dir[0]) test_rm_rf_recursive(dir);
    return failures;
}

static int test_cis_memo_new_nested_file_walks(void)
{
    int failures = 0;
    char dir[256] = {0};
    struct codeindex *ci = NULL;
    TEST("codeindex stale: a new file in a nested dir walks and sees stale") {
        test_make_tmpdir(dir, sizeof(dir), "cistale", "memonew");
        ASSERT(cis_ready(dir, &ci));
        ASSERT(cis_verdict(ci, false));
        ASSERT(cis_write(dir, "tools/deep/er/y.c", "int y(void) { return 1; }\n"));
        ASSERT(cis_verdict(ci, true));
        PASS();
    } _test_next:;
    codeindex_close(ci);
    if (dir[0]) test_rm_rf_recursive(dir);
    return failures;
}

static int test_cis_memo_new_nested_dir_walks(void)
{
    int failures = 0;
    char dir[256] = {0};
    struct codeindex *ci = NULL;
    TEST("codeindex stale: a new source directory walks and sees stale") {
        test_make_tmpdir(dir, sizeof(dir), "cistale", "memodir");
        ASSERT(cis_ready(dir, &ci));
        ASSERT(cis_verdict(ci, false));
        ASSERT(cis_write(dir, "src/brandnew/z.c", "int z(void) { return 2; }\n"));
        ASSERT(cis_verdict(ci, true));
        PASS();
    } _test_next:;
    codeindex_close(ci);
    if (dir[0]) test_rm_rf_recursive(dir);
    return failures;
}

static int test_cis_memo_rename_and_delete_walk(void)
{
    int failures = 0;
    char dir[256] = {0}, from[512], to[512];
    struct codeindex *ci = NULL;
    TEST("codeindex stale: rename then delete each walk and see stale") {
        test_make_tmpdir(dir, sizeof(dir), "cistale", "memomove");
        ASSERT(cis_ready(dir, &ci));
        ASSERT(cis_verdict(ci, false));
        snprintf(from, sizeof(from), "%s/tools/deep/er/x.c", dir);
        snprintf(to, sizeof(to), "%s/tools/deep/er/w.c", dir);
        ASSERT(rename(from, to) == 0);
        ASSERT(cis_verdict(ci, true));
        ASSERT(codeindex_rebuild(ci));
        ASSERT(cis_verdict(ci, false));
        ASSERT(cis_verdict(ci, false));
        ASSERT(unlink(to) == 0);
        ASSERT(cis_verdict(ci, true));
        PASS();
    } _test_next:;
    codeindex_close(ci);
    if (dir[0]) test_rm_rf_recursive(dir);
    return failures;
}

static int test_cis_memo_watch_failure_walks_every_time(void)
{
    int failures = 0;
    char dir[256] = {0};
    struct codeindex *ci = NULL;
    TEST("codeindex stale: a watch that cannot be armed walks every check") {
        test_make_tmpdir(dir, sizeof(dir), "cistale", "memofail");
        codeindex_test_force_watch_failure(true);
        ASSERT(cis_ready(dir, &ci));
        uint64_t before = codeindex_test_freshness_walks();
        ASSERT(cis_verdict(ci, false));
        ASSERT(cis_verdict(ci, false));
        ASSERT(cis_verdict(ci, false));
        ASSERT(codeindex_test_freshness_walks() == before + 3);
        PASS();
    } _test_next:;
    codeindex_test_force_watch_failure(false);
    codeindex_close(ci);
    if (dir[0]) test_rm_rf_recursive(dir);
    return failures;
}

#if defined(__linux__)
/* Keep the alias outside every directory watched for this index. Each test
 * owns its unique parent; even an assertion failure reaches the cleanup. */
static int test_cis_memo_external_hardlink(void)
{
    int failures = 0;
    char parent[] = "test-tmp/cistale-alias-XXXXXX";
    char root[512], path[512], alias[512];
    bool owned = false;
    int fd = -1;
    struct codeindex *ci = NULL;
    TEST("codeindex stale: writes through an outside hardlink invalidate live answers") {
        ASSERT(mkdtemp(parent) != NULL);
        owned = true;
        ASSERT((size_t)snprintf(root, sizeof(root), "%s/tree", parent) < sizeof(root));
        ASSERT(cis_seed(root));
        ASSERT(cis_write(root, "tools/deep/er/x.c", "int x(void) { return 0; }\n"));
        ASSERT((size_t)snprintf(path, sizeof(path), "%s/tools/deep/er/x.c", root) < sizeof(path));
        ASSERT((size_t)snprintf(alias, sizeof(alias), "%s/alias.c", parent) < sizeof(alias));
        ASSERT(link(path, alias) == 0);
        /* The alias exists before the index and its watch are established. */
        ci = codeindex_open(root);
        ASSERT(ci != NULL);
        ASSERT(cis_verdict(ci, false));
        ASSERT(cis_verdict(ci, false));
        fd = open(alias, O_WRONLY | O_CLOEXEC);
        ASSERT(fd >= 0);
        ASSERT(pwrite(fd, "xyz", 3, 0) == 3);
        int close_rc = close(fd);
        fd = -1;
        ASSERT(close_rc == 0);
        ASSERT(cis_verdict(ci, true));
        PASS();
    } _test_next:;
    if (fd >= 0) close(fd);
    codeindex_close(ci);
    if (owned) test_rm_rf_recursive(parent);
    return failures;
}

static int test_cis_memo_existing_shared_mapping(void)
{
    int failures = 0;
    char parent[] = "test-tmp/cistale-map-XXXXXX";
    char root[512], path[512];
    bool owned = false;
    int fd = -1;
    const size_t len = sizeof("int x(void) { return 0; }\n") - 1;
    char *mapping = MAP_FAILED;
    struct codeindex *ci = NULL;
    TEST("codeindex stale: established shared mapping remains live across rebuilds") {
        ASSERT(mkdtemp(parent) != NULL);
        owned = true;
        ASSERT((size_t)snprintf(root, sizeof(root), "%s/tree", parent) < sizeof(root));
        ASSERT(cis_ready(root, &ci));
        ASSERT((size_t)snprintf(path, sizeof(path), "%s/tools/deep/er/x.c", root) < sizeof(path));
        fd = open(path, O_RDWR | O_CLOEXEC);
        ASSERT(fd >= 0);
        mapping = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        ASSERT(mapping != MAP_FAILED);
        int close_rc = close(fd);
        fd = -1;
        ASSERT(close_rc == 0);
        fd = open(path, O_RDONLY | O_CLOEXEC);
        ASSERT(fd >= 0);
        /* Establish the writable mapping before priming. The retained
         * read-only descriptor witnesses page-cache bytes without flushing. */
        ASSERT(cis_verdict(ci, false));
        ASSERT(cis_verdict(ci, false));
        char *digit = memchr(mapping, '0', len);
        ASSERT(digit != NULL);
        *digit = '1';
        char observed;
        ASSERT(pread(fd, &observed, 1, (off_t)(digit - mapping)) == 1);
        ASSERT(observed == *digit);
        ASSERT(cis_verdict(ci, true));
        ASSERT(codeindex_rebuild(ci));
        ASSERT(cis_verdict(ci, false));
        ASSERT(cis_verdict(ci, false));
        /* The same writable mapping survives: a one-time mapping/mtime
         * observation is insufficient for this second mutation. */
        *digit = '2';
        ASSERT(pread(fd, &observed, 1, (off_t)(digit - mapping)) == 1);
        ASSERT(observed == *digit);
        ASSERT(cis_verdict(ci, true));
        PASS();
    } _test_next:;
    if (mapping != MAP_FAILED) munmap(mapping, len);
    if (fd >= 0) close(fd);
    codeindex_close(ci);
    if (owned) test_rm_rf_recursive(parent);
    return failures;
}
#endif

int test_codeindex_stale(void)
{
    int failures = 0;
    failures += test_cis_null_refuses();
    failures += test_cis_fresh_index_is_current();
    failures += test_cis_source_edit_stales_then_rebuild_clears();
    failures += test_cis_deleted_source_stales();
    failures += test_cis_memo_second_open_skips_walk();
    failures += test_cis_memo_inplace_write_walks();
    failures += test_cis_memo_new_nested_file_walks();
    failures += test_cis_memo_new_nested_dir_walks();
    failures += test_cis_memo_rename_and_delete_walk();
    failures += test_cis_memo_watch_failure_walks_every_time();
#if defined(__linux__)
    failures += test_cis_memo_external_hardlink();
    failures += test_cis_memo_existing_shared_mapping();
#endif
    printf("=== codeindex_stale: %d failures ===\n", failures);
    return failures;
}
