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
#if defined(__APPLE__)
#include <dirent.h>
#endif
#if defined(__linux__) || defined(__APPLE__)
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
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

#if defined(__linux__) || defined(__APPLE__)
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

/* Active depfiles are freshness inputs even though build/ is not a source
 * Merkle root. Establish the outside alias before any directory watch. */
static int test_cis_memo_external_depfile_hardlink(void)
{
    int failures = 0;
    char parent[] = "test-tmp/cistale-depalias-XXXXXX";
    char root[512], path[512], alias[512];
    bool owned = false;
    int fd = -1;
    struct codeindex *ci = NULL;
    TEST("codeindex stale: outside active-depfile writes invalidate a proven memo") {
        ASSERT(mkdtemp(parent) != NULL);
        owned = true;
        ASSERT((size_t)snprintf(root, sizeof(root), "%s/tree", parent) < sizeof(root));
        ASSERT(cis_seed(root));
        /* No epochs directory: this regular .d is in the active inventory. */
        ASSERT(cis_write(root, "build/foo.d",
            "build/foo.o: core/modules/net/src/foo.c core/modules/net/include/net/foo.h\n"));
        ASSERT((size_t)snprintf(path, sizeof(path), "%s/build/foo.d", root) < sizeof(path));
        ASSERT((size_t)snprintf(alias, sizeof(alias), "%s/alias.d", parent) < sizeof(alias));
        ASSERT(link(path, alias) == 0);
        size_t depfiles = 0;
        int64_t newest = 0;
        ASSERT(codeindex_depfile_graph(root, &depfiles, &newest));
        ASSERT(depfiles == 1);
        ci = codeindex_open(root);
        ASSERT(ci != NULL);
        ASSERT(cis_verdict(ci, false));
        uint64_t primed = codeindex_test_freshness_walks();
        ASSERT(cis_verdict(ci, false));
        /* A host without a working memo cannot qualify this regression. */
        ASSERT(codeindex_test_freshness_walks() == primed);
        struct stat before, after;
        ASSERT(stat(path, &before) == 0);
        fd = open(alias, O_WRONLY | O_APPEND | O_CLOEXEC);
        ASSERT(fd >= 0);
        ASSERT(write(fd, "\n", 1) == 1);
        int close_rc = close(fd);
        fd = -1;
        ASSERT(close_rc == 0);
        ASSERT(stat(path, &after) == 0 && after.st_size == before.st_size + 1);
        bool memo_stale = false;
        bool memo_ok = codeindex_is_stale(ci, &memo_stale);
        /* Force an independent full-path observation before asserting the
         * candidate verdict. The marker causes a build-directory event but
         * is ignored by depfile collection and is outside source Merkle roots.
         * The existing fault switch alone does not evict an armed memo. */
        codeindex_test_force_watch_failure(true);
        ASSERT(cis_write(root, "build/.control-marker", "ignored\n"));
        uint64_t walked = codeindex_test_freshness_walks();
        ASSERT(cis_verdict(ci, true));
        ASSERT(codeindex_test_freshness_walks() == walked + 1);
        ASSERT(memo_ok && memo_stale);
        PASS();
    } _test_next:;
    codeindex_test_force_watch_failure(false);
    if (fd >= 0) close(fd);
    codeindex_close(ci);
    if (owned) test_rm_rf_recursive(parent);
    return failures;
}

#define CIS_DEP_TEXT \
    "build/foo.o: core/modules/net/src/foo.c core/modules/net/include/net/foo.h\n"

/* Seed a tree whose build/ already holds one active depfile, open it, and
 * leave the store proven fresh once (the memo armed or about to arm). */
static bool cis_open_with_depfile(const char *root, struct codeindex **ci)
{
    return cis_seed(root) && cis_write(root, "build/foo.d", CIS_DEP_TEXT) &&
           (*ci = codeindex_open(root)) != NULL;
}

static char g_cis_hook_alias[512];
static bool g_cis_hook_fired;

/* Runs after the verifying walk, before the memo is sealed: an outside alias
 * writes the active depfile exactly there, raising no watch event. */
static void cis_bracket_hook(const char *root)
{
    (void)root;
    int fd = open(g_cis_hook_alias, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd < 0) return;
    if (write(fd, "\n", 1) == 1) g_cis_hook_fired = true;
    close(fd);
}

/* The depfile keys must bracket the digest observation: a write between the
 * walk's verification and the seal may not be sealed in as the baseline. */
static int test_cis_memo_depfile_write_in_seal_bracket(void)
{
    int failures = 0;
    char parent[] = "test-tmp/cistale-bracket-XXXXXX";
    char root[512], path[512];
    bool owned = false;
    struct codeindex *ci = NULL;
    TEST("codeindex stale: a depfile alias write between verify and seal is not sealed") {
        ASSERT(mkdtemp(parent) != NULL);
        owned = true;
        ASSERT((size_t)snprintf(root, sizeof(root), "%s/tree", parent) < sizeof(root));
        ASSERT(cis_seed(root));
        ASSERT(cis_write(root, "build/foo.d", CIS_DEP_TEXT));
        ASSERT((size_t)snprintf(path, sizeof(path), "%s/build/foo.d", root) < sizeof(path));
        ASSERT((size_t)snprintf(g_cis_hook_alias, sizeof(g_cis_hook_alias),
                                "%s/alias.d", parent) < sizeof(g_cis_hook_alias));
        /* Link before open: link() itself moves the inode's ctime. */
        ASSERT(link(path, g_cis_hook_alias) == 0);
        ci = codeindex_open(root);
        ASSERT(ci != NULL);
        g_cis_hook_fired = false;
        codeindex_test_set_bracket_hook(cis_bracket_hook);
        ASSERT(cis_verdict(ci, false)); /* the walk itself saw a fresh tree */
        codeindex_test_set_bracket_hook(NULL);
        ASSERT(g_cis_hook_fired);
        /* Sealed against the pre-write baseline it would be a memo hit
         * (fresh); the bracket refuses to arm, so the next open walks. */
        ASSERT(cis_verdict(ci, true));
        PASS();
    } _test_next:;
    codeindex_test_set_bracket_hook(NULL);
    codeindex_close(ci);
    if (owned) test_rm_rf_recursive(parent);
    return failures;
}

/* A source mutation after snapshot capture must reject the seal itself, not
 * merely become visible to the next hit's leaf restat. */
static void cis_source_seal_hook(const char *root)
{
    g_cis_hook_fired = cis_write(root, "core/modules/net/src/foo.c",
                                "int foo(void) { return 22; }\n");
}

static int test_cis_memo_source_write_in_seal_bracket(void)
{
    int failures = 0;
    char dir[256] = {0};
    struct codeindex *ci = NULL;
    TEST("codeindex stale: a source write in the seal bracket publishes no memo") {
        test_make_tmpdir(dir, sizeof(dir), "cistale", "sourceseal");
        ASSERT(cis_seed(dir));
        ci = codeindex_open(dir);
        ASSERT(ci != NULL);
        uint64_t seals = codeindex_test_freshness_seals();
        g_cis_hook_fired = false;
        codeindex_test_set_bracket_hook(cis_source_seal_hook);
        ASSERT(cis_verdict(ci, false));
        codeindex_test_set_bracket_hook(NULL);
        ASSERT(g_cis_hook_fired);
        ASSERT(codeindex_test_freshness_seals() == seals);
        ASSERT(cis_verdict(ci, true));
        PASS();
    } _test_next:;
    codeindex_test_set_bracket_hook(NULL);
    codeindex_close(ci);
    if (dir[0]) test_rm_rf_recursive(dir);
    return failures;
}

static void cis_hit_create_hook(const char *root)
{
    g_cis_hook_fired = cis_write(root, "core/modules/net/src/new.c",
                                "int added(void) { return 1; }\n");
}

static int test_cis_memo_create_in_hit_bracket(void)
{
    int failures = 0;
    char dir[256] = {0};
    struct codeindex *ci = NULL;
    TEST("codeindex stale: a create after hit restats walks in that same call") {
        test_make_tmpdir(dir, sizeof(dir), "cistale", "hitbracket");
        ASSERT(cis_ready(dir, &ci));
        uint64_t walks = codeindex_test_freshness_walks();
        g_cis_hook_fired = false;
        codeindex_test_set_hit_hook(cis_hit_create_hook);
        ASSERT(cis_verdict(ci, true));
        codeindex_test_set_hit_hook(NULL);
        ASSERT(g_cis_hook_fired);
        ASSERT(codeindex_test_freshness_walks() == walks + 1);
        PASS();
    } _test_next:;
    codeindex_test_set_hit_hook(NULL);
    codeindex_close(ci);
    if (dir[0]) test_rm_rf_recursive(dir);
    return failures;
}

static int test_cis_memo_missing_roots_created(void)
{
    int failures = 0;
    char dir[256] = {0};
    struct codeindex *ci = NULL;
    TEST("codeindex stale: creation of missing source and build roots invalidates") {
        test_make_tmpdir(dir, sizeof(dir), "cistale", "missingroots");
        ASSERT(cis_ready(dir, &ci));
        ASSERT(cis_write(dir, "app/new.c", "int app(void) { return 1; }\n"));
        ASSERT(cis_verdict(ci, true));
        ASSERT(codeindex_rebuild(ci));
        ASSERT(cis_verdict(ci, false));
        uint64_t walks = codeindex_test_freshness_walks();
        ASSERT(cis_write(dir, "build/foo.d", CIS_DEP_TEXT));
        ASSERT(cis_verdict(ci, true));
        ASSERT(codeindex_test_freshness_walks() == walks + 1);
        PASS();
    } _test_next:;
    codeindex_close(ci);
    if (dir[0]) test_rm_rf_recursive(dir);
    return failures;
}

#if defined(__APPLE__)
static int cis_fd_count(void)
{
    DIR *d = opendir("/dev/fd");
    if (!d) return -1;
    int count = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        char *end;
        long fd = strtol(e->d_name, &end, 10);
        if (end != e->d_name && *end == '\0' && fd >= 0 &&
            fd != dirfd(d) && fcntl((int)fd, F_GETFD) >= 0)
            count++;
    }
    if (closedir(d) != 0) return -1;
    return count;
}

/* First arming opens root/core watchers before rejecting dangling src.
 * Isolate the census so parent activity cannot hide or manufacture leaks. */
static int cis_partial_arm_child(struct codeindex *ci)
{
    int before = cis_fd_count();
    int probe = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (probe < 0) return 2;
    int with_probe = cis_fd_count();
    if (close(probe) != 0) return 3;
    int restored = cis_fd_count();
    /* Prove the census observes both descriptor admission and release;
     * a parser returning a constant zero must not validate cleanup. */
    if (before < 0 || with_probe != before + 1 || restored != before)
        return 4;
    bool stale = true;
    bool fresh = codeindex_is_stale(ci, &stale) && !stale;
    int after = cis_fd_count();
    return before >= 0 && before == after && fresh ? 0 : 1;
}

static bool cis_partial_arm_cleanup(struct codeindex *ci)
{
    pid_t child = fork();
    if (child == 0) _exit(cis_partial_arm_child(ci));
    if (child < 0) return false;
    int status;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); }
    while (waited < 0 && errno == EINTR);
    return waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
#endif

static int test_cis_memo_dangling_source_root(void)
{
    int failures = 0;
    char parent[] = "test-tmp/cistale-dangling-XXXXXX";
    char root[512], linkpath[512];
    bool owned = false;
    struct codeindex *ci = NULL;
    TEST("codeindex stale: a dangling source-root target cannot become a false hit") {
        ASSERT(mkdtemp(parent) != NULL);
        owned = true;
        ASSERT((size_t)snprintf(root, sizeof(root), "%s/tree", parent) < sizeof(root));
        ASSERT(cis_seed(root));
        ASSERT((size_t)snprintf(linkpath, sizeof(linkpath), "%s/src", root) < sizeof(linkpath));
        ASSERT(symlink("../future-src", linkpath) == 0);
        ci = codeindex_open(root);
        ASSERT(ci != NULL);
#if defined(__APPLE__)
        ASSERT(cis_partial_arm_cleanup(ci));
#endif
        ASSERT(cis_verdict(ci, false));
        uint64_t walks = codeindex_test_freshness_walks();
        ASSERT(cis_verdict(ci, false));
        ASSERT(codeindex_test_freshness_walks() == walks + 1);
        /* Neither creating nor populating the target changes tree/. The
         * canonical beneath-root file reader refuses the external symlink,
         * so this must return unavailable with stale=true, never fresh. */
        ASSERT(cis_write(parent, "future-src/new.c", "int arrived(void) { return 1; }\n"));
        bool stale = false;
        ASSERT(!codeindex_is_stale(ci, &stale));
        ASSERT(stale);
        ASSERT(codeindex_test_freshness_walks() == walks + 2);
        /* A real in-tree root is enumerable and reports the new source as
         * stale. Preserve that valid stale verdict rather than weakening it. */
        ASSERT(unlink(linkpath) == 0);
        ASSERT(cis_write(root, "src/new.c", "int arrived(void) { return 1; }\n"));
        ASSERT(cis_verdict(ci, true));
        PASS();
    } _test_next:;
    codeindex_close(ci);
    if (owned) test_rm_rf_recursive(parent);
    return failures;
}

static int test_cis_memo_fork_rearms(void)
{
    int failures = 0;
    char dir[256] = {0};
    struct codeindex *ci = NULL;
    TEST("codeindex stale: a single-threaded fork walks and rearms only the child") {
        test_make_tmpdir(dir, sizeof(dir), "cistale", "fork");
        ASSERT(cis_ready(dir, &ci));
        uint64_t walks = codeindex_test_freshness_walks();
        pid_t child = fork();
        ASSERT(child >= 0);
        if (child == 0) {
            bool ok = cis_verdict(ci, false) &&
                codeindex_test_freshness_walks() == walks + 1 &&
                cis_verdict(ci, false) &&
                codeindex_test_freshness_walks() == walks + 1;
            codeindex_close(ci);
            _exit(ok ? 0 : 1);
        }
        int status;
        pid_t waited;
        do { waited = waitpid(child, &status, 0); }
        while (waited < 0 && errno == EINTR);
        ASSERT(waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        ASSERT(cis_verdict(ci, false));
        ASSERT(codeindex_test_freshness_walks() == walks);
        PASS();
    } _test_next:;
    codeindex_close(ci);
    if (dir[0]) test_rm_rf_recursive(dir);
    return failures;
}

static int test_cis_memo_new_depfile_in_new_build_dir(void)
{
    int failures = 0;
    char dir[256] = {0};
    struct codeindex *ci = NULL;
    TEST("codeindex stale: a depfile in a new nested build dir walks and sees stale") {
        test_make_tmpdir(dir, sizeof(dir), "cistale", "newdep");
        ASSERT(cis_open_with_depfile(dir, &ci));
        ASSERT(cis_verdict(ci, false));
        uint64_t primed = codeindex_test_freshness_walks();
        ASSERT(cis_verdict(ci, false));
        ASSERT(codeindex_test_freshness_walks() == primed);
        ASSERT(cis_write(dir, "build/sub/deeper/new.d", CIS_DEP_TEXT));
        ASSERT(cis_verdict(ci, true));
        ASSERT(codeindex_test_freshness_walks() == primed + 1);
        PASS();
    } _test_next:;
    codeindex_close(ci);
    if (dir[0]) test_rm_rf_recursive(dir);
    return failures;
}

#define CIS_EPOCH_A "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define CIS_EPOCH_B "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

static int test_cis_memo_epoch_retarget_walks(void)
{
    int failures = 0;
    char dir[256] = {0};
    struct codeindex *ci = NULL;
    TEST("codeindex stale: retargeting the current epoch walks and sees stale") {
        test_make_tmpdir(dir, sizeof(dir), "cistale", "epoch");
        ASSERT(cis_seed(dir));
        ASSERT(cis_write(dir, "build/epochs/" CIS_EPOCH_A "/foo.d", CIS_DEP_TEXT));
        ASSERT(cis_write(dir, "build/epochs/" CIS_EPOCH_B "/bar.d", CIS_DEP_TEXT));
        ASSERT(cis_write(dir, "build/.current-epoch", CIS_EPOCH_A "\n"));
        ci = codeindex_open(dir);
        ASSERT(ci != NULL);
        ASSERT(cis_verdict(ci, false));
        uint64_t primed = codeindex_test_freshness_walks();
        ASSERT(cis_verdict(ci, false));
        ASSERT(codeindex_test_freshness_walks() == primed);
        ASSERT(cis_write(dir, "build/.current-epoch", CIS_EPOCH_B "\n"));
        ASSERT(cis_verdict(ci, true));
        ASSERT(codeindex_test_freshness_walks() == primed + 1);
        PASS();
    } _test_next:;
    codeindex_close(ci);
    if (dir[0]) test_rm_rf_recursive(dir);
    return failures;
}

static int test_cis_memo_epoch_alias_and_replacement(void)
{
    int failures = 0;
    char parent[] = "test-tmp/cistale-selector-XXXXXX";
    char root[512], selector[512], alias[512], replacement[512];
    bool owned = false;
    struct codeindex *ci = NULL;
    TEST("codeindex stale: outside selector writes and selector replacement invalidate") {
        ASSERT(mkdtemp(parent) != NULL);
        owned = true;
        ASSERT((size_t)snprintf(root, sizeof(root), "%s/tree", parent) < sizeof(root));
        ASSERT(cis_seed(root));
        ASSERT(cis_write(root, "build/epochs/" CIS_EPOCH_A "/foo.d", CIS_DEP_TEXT));
        ASSERT(cis_write(root, "build/epochs/" CIS_EPOCH_B "/bar.d", CIS_DEP_TEXT));
        ASSERT(cis_write(root, "build/.current-epoch", CIS_EPOCH_A "\n"));
        ASSERT((size_t)snprintf(selector, sizeof(selector), "%s/build/.current-epoch", root) < sizeof(selector));
        ASSERT((size_t)snprintf(alias, sizeof(alias), "%s/selector-alias", parent) < sizeof(alias));
        ASSERT(link(selector, alias) == 0);
        ci = codeindex_open(root);
        ASSERT(ci != NULL);
        ASSERT(cis_verdict(ci, false));
        uint64_t walks = codeindex_test_freshness_walks();
        int fd = open(alias, O_WRONLY | O_TRUNC | O_CLOEXEC);
        ASSERT(fd >= 0);
        ssize_t wrote = write(fd, CIS_EPOCH_B "\n", sizeof(CIS_EPOCH_B "\n") - 1);
        int closed = close(fd);
        ASSERT(wrote == (ssize_t)(sizeof(CIS_EPOCH_B "\n") - 1) && closed == 0);
        ASSERT(cis_verdict(ci, true));
        ASSERT(codeindex_test_freshness_walks() == walks + 1);
        ASSERT(codeindex_rebuild(ci));
        ASSERT(cis_verdict(ci, false));
        ASSERT(cis_write(root, "build/next-selector", CIS_EPOCH_A "\n"));
        /* Prime after creating the replacement so only rename is under test. */
        ASSERT(cis_verdict(ci, false));
        walks = codeindex_test_freshness_walks();
        ASSERT((size_t)snprintf(replacement, sizeof(replacement), "%s/build/next-selector", root) < sizeof(replacement));
        ASSERT(rename(replacement, selector) == 0);
        ASSERT(cis_verdict(ci, true));
        ASSERT(codeindex_test_freshness_walks() == walks + 1);
        PASS();
    } _test_next:;
    codeindex_close(ci);
    if (owned) test_rm_rf_recursive(parent);
    return failures;
}

static int test_cis_memo_depfile_cap_overflow_walks(void)
{
    int failures = 0;
    char dir[256] = {0};
    struct codeindex *ci = NULL;
    TEST("codeindex stale: more depfiles than the cap never arm the memo") {
        test_make_tmpdir(dir, sizeof(dir), "cistale", "depcap");
        ASSERT(cis_seed(dir));
        ASSERT(cis_write(dir, "build/a.d", CIS_DEP_TEXT));
        ASSERT(cis_write(dir, "build/b.d", CIS_DEP_TEXT));
        codeindex_test_set_dep_key_cap(1);
        ci = codeindex_open(dir);
        ASSERT(ci != NULL);
        ASSERT(cis_verdict(ci, false));
        uint64_t before = codeindex_test_freshness_walks();
        ASSERT(cis_verdict(ci, false));
        ASSERT(cis_verdict(ci, false));
        ASSERT(codeindex_test_freshness_walks() == before + 2);
        ASSERT(cis_write(dir, "build/b.d", CIS_DEP_TEXT "# edit\n"));
        ASSERT(cis_verdict(ci, true));
        PASS();
    } _test_next:;
    codeindex_test_set_dep_key_cap(0);
    codeindex_close(ci);
    if (dir[0]) test_rm_rf_recursive(dir);
    return failures;
}

static bool cis_append_newline(const char *path)
{
    int fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd < 0) return false;
    bool ok = write(fd, "\n", 1) == 1;
    return close(fd) == 0 && ok;
}

/* Prime, then prove a second check is a memo hit (no walk). */
static bool cis_prime_hit(struct codeindex *ci)
{
    if (!cis_verdict(ci, false)) return false;
    uint64_t walks = codeindex_test_freshness_walks();
    return cis_verdict(ci, false) && codeindex_test_freshness_walks() == walks;
}

/* One outside-alias write must be seen as stale by a walking verdict. */
static bool cis_alias_seen(struct codeindex *ci, const char *alias)
{
    uint64_t walks = codeindex_test_freshness_walks();
    return cis_append_newline(alias) && cis_verdict(ci, true) &&
           codeindex_test_freshness_walks() == walks + 1;
}

/* Eight depfiles in two build subdirectories with par_min=4: four slices of
 * two, so the parallel re-stat, the per-directory switch and the inline
 * fallback are all reached. Looping over every depfile covers every slice
 * whatever order the inventory is collected in. */
static int test_cis_memo_parallel_depfile_slices(void)
{
    enum { N = 8 };
    int failures = 0;
    char parent[] = "test-tmp/cistale-par-XXXXXX";
    char root[512], path[512], alias[N][512];
    bool owned = false;
    struct codeindex *ci = NULL;
    TEST("codeindex stale: every parallel depfile slice sees an alias write") {
        ASSERT(mkdtemp(parent) != NULL);
        owned = true;
        ASSERT((size_t)snprintf(root, sizeof(root), "%s/tree", parent) < sizeof(root));
        ASSERT(cis_seed(root));
        for (int i = 0; i < N; i++) {
            ASSERT(snprintf(path, sizeof(path), "build/%c/f%d.d", i < N / 2 ? 'a' : 'b', i) > 0);
            ASSERT(cis_write(root, path, CIS_DEP_TEXT));
            char full[512];
            ASSERT((size_t)snprintf(full, sizeof(full), "%s/%s", root, path) < sizeof(full));
            ASSERT((size_t)snprintf(alias[i], sizeof(alias[i]), "%s/alias%d.d", parent, i) < sizeof(alias[i]));
            /* Link before open: link() itself moves the inode's ctime. */
            ASSERT(link(full, alias[i]) == 0);
        }
        ci = codeindex_open(root);
        ASSERT(ci != NULL);
        codeindex_test_set_dep_par_min(4);
        ASSERT(cis_prime_hit(ci));
        for (int i = 0; i < N; i++) {
            ASSERT(cis_alias_seen(ci, alias[i]));
            ASSERT(codeindex_rebuild(ci));
            ASSERT(cis_prime_hit(ci));
        }
        /* Every worker thread fails to start: the inline fallback must give
         * the same answers. */
        codeindex_test_force_dep_thread_create_failure(true);
        ASSERT(cis_prime_hit(ci));
        ASSERT(cis_alias_seen(ci, alias[5]));
        ASSERT(codeindex_rebuild(ci));
        ASSERT(cis_prime_hit(ci));
        PASS();
    } _test_next:;
    codeindex_test_force_dep_thread_create_failure(false);
    codeindex_test_set_dep_par_min(0);
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
    TEST("codeindex stale: a synced shared-mapping write is seen, across a rebuild") {
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
        /* POSIX marks st_mtime/st_ctime for update between a MAP_SHARED write
         * and the next msync; each asserted write is therefore synced before
         * the verdict. An unsynced store to an already-dirty page that leaves
         * the metadata unchanged is the documented LIMIT above fw_key_matches,
         * and this fixture does not claim to detect it. */
        ASSERT(msync(mapping, len, MS_SYNC) == 0);
        char observed;
        ASSERT(pread(fd, &observed, 1, (off_t)(digit - mapping)) == 1);
        ASSERT(observed == *digit);
        ASSERT(cis_verdict(ci, true));
        ASSERT(codeindex_rebuild(ci));
        ASSERT(cis_verdict(ci, false));
        ASSERT(cis_verdict(ci, false));
        /* The established mapping survives the rebuild. */
        *digit = '2';
        ASSERT(msync(mapping, len, MS_SYNC) == 0);
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
#if defined(__linux__) || defined(__APPLE__)
    failures += test_cis_memo_external_hardlink();
    failures += test_cis_memo_external_depfile_hardlink();
    failures += test_cis_memo_depfile_write_in_seal_bracket();
    failures += test_cis_memo_source_write_in_seal_bracket();
    failures += test_cis_memo_create_in_hit_bracket();
    failures += test_cis_memo_missing_roots_created();
    failures += test_cis_memo_dangling_source_root();
    failures += test_cis_memo_fork_rearms();
    failures += test_cis_memo_new_depfile_in_new_build_dir();
    failures += test_cis_memo_epoch_retarget_walks();
    failures += test_cis_memo_epoch_alias_and_replacement();
    failures += test_cis_memo_depfile_cap_overflow_walks();
    failures += test_cis_memo_parallel_depfile_slices();
    failures += test_cis_memo_existing_shared_mapping();
#endif
    printf("=== codeindex_stale: %d failures ===\n", failures);
    return failures;
}
