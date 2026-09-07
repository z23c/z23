/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Reject multiply-linked generated dependencies in a worktree. */

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "dev/dependency_links.h"
#include "platform/directory_compat.h"
#include "util/file_tree_ops.h"
#include "base/result.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <direct.h>
#include <io.h>
#include <windows.h>
#define unlink _unlink
#define rmdir _rmdir
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

static bool path_join(char out[ZCL_DEPENDENCY_LINK_PATH_MAX], const char *left,
                      const char *right)
{
    const size_t n = strlen(left);
    const int wrote = snprintf(out, ZCL_DEPENDENCY_LINK_PATH_MAX, "%s%s%s",
                               left, n && left[n - 1] == '/' ? "" : "/",
                               right);
    return wrote > 0 && (size_t)wrote < ZCL_DEPENDENCY_LINK_PATH_MAX;
}

static bool report_link(const char *relative_path, uint64_t links,
                        void *context)
{
    (void)context;
    fprintf(stderr,
            "hardlink-seeding: multiply-linked dependency %s (links=%llu)\n",
            relative_path, (unsigned long long)links);
    return true;
}

static bool check_root(const char *root)
{
    struct zcl_dependency_link_stats stats;
    char why[ZCL_DEPENDENCY_LINK_PATH_MAX];
    if (!zcl_dependency_links_scan(root, report_link, NULL, &stats, why,
                                   sizeof(why))) {
        fprintf(stderr, "hardlink-seeding: scan refused: %s\n",
                why[0] ? why : "invalid_arguments");
        return false;
    }
    if (!stats.linked)
        return true;
    fprintf(stderr, "hardlink-seeding: FAIL (%zu linked file%s)\n",
            stats.linked, stats.linked == 1 ? "" : "s");
    fprintf(stderr, "Run repairs only when no proof is in flight: replacing "
            "a shared path changes its donor's ctime.\nFor each affected "
            "file, set f to its quoted path and use a fresh temporary name:\n"
            "  cp -a --reflink=auto -- \"$f\" \"$f.tmp\" && "
            "mv -f -- \"$f.tmp\" \"$f\"\n");
    return false;
}

/* --count: the machine-readable half of check_root(), used by
 * tools/ship.sh instead of its own `find | wc -l` (which ran a second,
 * differently-scoped walk under `set -o pipefail` and could abort the whole
 * ship silently on a transient walk error — a command substitution's exit
 * status is not a pipe, so there is no such hazard here). Prints only the
 * count; never writes. */
static int count_root(const char *root)
{
    struct zcl_dependency_link_stats stats;
    char why[ZCL_DEPENDENCY_LINK_PATH_MAX];
    if (!zcl_dependency_links_scan(root, NULL, NULL, &stats, why,
                                   sizeof(why))) {
        fprintf(stderr, "hardlink-seeding: scan refused: %s\n",
                why[0] ? why : "invalid_arguments");
        return 1;
    }
    printf("%zu\n", stats.linked);
    return 0;
}

struct hardlink_repair_ctx {
    const char *root;
    size_t repaired;
};

/* One file: copy the shared inode's bytes to a fresh temporary name
 * (mode/mtime preserved by zcl_tree_copy) and rename it over the original
 * path — the same reflink-then-rename shape the FAIL message advises, done
 * natively instead of shelling out. rename() is atomic on one filesystem, so
 * an already-open reader of the old inode is never disturbed. Any failure is
 * printed with the offending path and aborts the whole repair (no silent
 * partial dedupe); files already repaired before it stay repaired. */
static bool hardlink_repair_one(const char *relative_path, uint64_t links,
                                void *context)
{
    (void)links;
    struct hardlink_repair_ctx *ctx = context;
    char full[ZCL_DEPENDENCY_LINK_PATH_MAX];
    char tmp[ZCL_DEPENDENCY_LINK_PATH_MAX + 16];
    if (!path_join(full, ctx->root, relative_path)) {
        fprintf(stderr, "hardlink-seeding: repair FAILED: %s: path_too_long\n",
                relative_path);
        return false;
    }
    int wrote = snprintf(tmp, sizeof(tmp), "%s.dedupe.tmp", full);
    if (wrote <= 0 || (size_t)wrote >= sizeof(tmp)) {
        fprintf(stderr,
                "hardlink-seeding: repair FAILED: %s: tmp_path_too_long\n",
                relative_path);
        return false;
    }
    struct zcl_result copied =
        zcl_tree_copy(full, tmp, ZCL_COPY_PRESERVE_TIMES, NULL, NULL);
    if (!copied.ok) {
        (void)unlink(tmp);
        fprintf(stderr, "hardlink-seeding: repair FAILED: %s: %s\n",
                relative_path, copied.message);
        return false;
    }
    if (rename(tmp, full) != 0) {
        (void)unlink(tmp);
        fprintf(stderr, "hardlink-seeding: repair FAILED: %s: rename: %s\n",
                relative_path, strerror(errno));
        return false;
    }
    ctx->repaired++;
    printf("hardlink-seeding: repaired %s\n", relative_path);
    return true;
}

/* --repair: dedupe exactly the file set check_root()/count_root() scan —
 * never a second, independently-scoped walk. Whether a z23-land-train* unit
 * is active is decided by the caller (this tool has no process-spawn seam);
 * callers must not invoke this while one is running. */
static bool repair_root(const char *root)
{
    struct hardlink_repair_ctx ctx = { .root = root, .repaired = 0 };
    struct zcl_dependency_link_stats stats;
    char why[ZCL_DEPENDENCY_LINK_PATH_MAX];
    if (!zcl_dependency_links_scan(root, hardlink_repair_one, &ctx, &stats,
                                   why, sizeof(why))) {
        fprintf(stderr, "hardlink-seeding: repair aborted: %s\n",
                why[0] ? why : "invalid_arguments");
        return false;
    }
    printf("hardlink-seeding: repaired %zu file(s)\n", ctx.repaired);
    return true;
}

static bool write_file(const char *path)
{
    FILE *file = fopen(path, "wb");
    if (!file)
        return false;
    const bool wrote = fwrite("fixture\n", 1, 8, file) == 8;
    return fclose(file) == 0 && wrote;
}

static int selftest(void)
{
#if defined(_WIN32)
    char base[ZCL_DEPENDENCY_LINK_PATH_MAX];
    char temp[ZCL_DEPENDENCY_LINK_PATH_MAX];
    DWORD n = GetTempPathA((DWORD)sizeof(temp), temp);
    if (!n || n >= sizeof(temp) || !GetTempFileNameA(temp, "zhl", 0, base) ||
        !DeleteFileA(base) || !CreateDirectoryA(base, NULL))
        return 1;
#else
    char base[] = "/tmp/z23-hardlink-seeding.XXXXXX";
    if (!mkdtemp(base))
        return 1;
#endif
    char vendor[ZCL_DEPENDENCY_LINK_PATH_MAX] = {0};
    char nested[ZCL_DEPENDENCY_LINK_PATH_MAX] = {0};
    char source[ZCL_DEPENDENCY_LINK_PATH_MAX] = {0};
    char peer[ZCL_DEPENDENCY_LINK_PATH_MAX] = {0};
    char outside[ZCL_DEPENDENCY_LINK_PATH_MAX] = {0};
    char outside_peer[ZCL_DEPENDENCY_LINK_PATH_MAX] = {0};
    char outside_link[ZCL_DEPENDENCY_LINK_PATH_MAX] = {0};
    char build[ZCL_DEPENDENCY_LINK_PATH_MAX] = {0};
    char hotswap[ZCL_DEPENDENCY_LINK_PATH_MAX] = {0};
    char external[ZCL_DEPENDENCY_LINK_PATH_MAX] = {0};
    char external_hotswap[ZCL_DEPENDENCY_LINK_PATH_MAX] = {0};
    char module[ZCL_DEPENDENCY_LINK_PATH_MAX] = {0};
    char module_peer[ZCL_DEPENDENCY_LINK_PATH_MAX] = {0};
    bool ok = path_join(vendor, base, "vendor")
        && path_join(nested, vendor, "include")
        && path_join(source, nested, "generated.h")
        && path_join(peer, nested, "generated-copy.h")
        && path_join(outside, base, "outside.a")
        && path_join(outside_peer, base, "outside-peer.a")
        && path_join(outside_link, vendor, "outside")
        && path_join(build, base, "build")
        && path_join(hotswap, build, "hotswap")
        && path_join(external, base, "external-build")
        && path_join(external_hotswap, external, "hotswap")
        && path_join(module, hotswap, "fixture.so")
        && path_join(module_peer, base, "fixture-peer.so")
        && platform_directory_ensure(vendor, 0700)
        && platform_directory_ensure(nested, 0700)
        && platform_directory_ensure(build, 0700)
        && platform_directory_ensure(hotswap, 0700)
        && write_file(source) && write_file(outside)
#if defined(_WIN32)
        && CreateHardLinkA(outside_peer, outside, NULL)
#else
        && link(outside, outside_peer) == 0
        && symlink(base, outside_link) == 0
#endif
        && check_root(base);
    char hooks[ZCL_DEPENDENCY_LINK_PATH_MAX] = {0};
    char a[ZCL_DEPENDENCY_LINK_PATH_MAX] = {0};
    char b[ZCL_DEPENDENCY_LINK_PATH_MAX] = {0};
    char linked[ZCL_DEPENDENCY_LINK_PATH_MAX] = {0};
    if (ok)
        ok = path_join(hooks, build, "githooks")
            && path_join(a, hooks, "pre-push")
            && path_join(b, hooks, "post-merge")
            && path_join(linked, hooks, "pre-push-linked")
            && platform_directory_ensure(hooks, 0700)
            && write_file(a) && write_file(b) && check_root(base);
#if defined(_WIN32)
    if (ok) ok = CreateHardLinkA(linked, a, NULL) && !check_root(base);
#else
    if (ok) ok = link(a, linked) == 0 && !check_root(base);
#endif
    if (linked[0]) (void)unlink(linked);
    if (a[0]) (void)unlink(a);
    if (b[0]) (void)unlink(b);
    if (hooks[0]) (void)rmdir(hooks);
#if defined(ZCL_TESTING)
    if (ok) {
        struct zcl_dependency_link_stats edge, over;
        char why[128];
        ok = zcl_dependency_links_scan_directory_for_testing(
                 nested, ZCL_DEPENDENCY_LINK_ENTRIES_MAX - 1u, &edge, why,
                 sizeof(why))
            && edge.entries == ZCL_DEPENDENCY_LINK_ENTRIES_MAX
            && !zcl_dependency_links_scan_directory_for_testing(
                nested, ZCL_DEPENDENCY_LINK_ENTRIES_MAX, &over, why,
                sizeof(why));
    }
#endif
    if (ok) {
#if defined(_WIN32)
        ok = CreateHardLinkA(peer, source, NULL) && !check_root(base);
#else
        ok = link(source, peer) == 0 && !check_root(base);
#endif
    }
    if (peer[0]) (void)unlink(peer);
    if (source[0]) (void)unlink(source);
    if (ok)
        ok = write_file(module)
#if defined(_WIN32)
            && CreateHardLinkA(module_peer, module, NULL)
#else
            && link(module, module_peer) == 0
#endif
            && !check_root(base);
    if (module_peer[0]) (void)unlink(module_peer);
    if (module[0]) (void)unlink(module);
    if (hotswap[0]) (void)rmdir(hotswap);
    if (build[0]) (void)rmdir(build);
#if !defined(_WIN32)
    if (ok)
        ok = platform_directory_ensure(external, 0700)
            && platform_directory_ensure(external_hotswap, 0700)
            && symlink(external, build) == 0 && !check_root(base);
#endif
    if (build[0]) (void)unlink(build);
    if (external_hotswap[0]) (void)rmdir(external_hotswap);
    if (external[0]) (void)rmdir(external);
    if (outside_link[0]) (void)unlink(outside_link);
    if (outside_peer[0]) (void)unlink(outside_peer);
    if (outside[0]) (void)unlink(outside);
    if (nested[0]) (void)rmdir(nested);
    if (vendor[0]) (void)rmdir(vendor);
    (void)rmdir(base);
    if (!ok) {
        fprintf(stderr, "hardlink-seeding: selftest FAIL\n");
        return 1;
    }
    printf("hardlink-seeding: selftest PASS\n");
    return 0;
}

/* The three fixtures below build real hardlinks with POSIX link()/stat()/
 * chmod()/mkdtemp() directly, the same way selftest() above already does for
 * the report path. A Windows build of this tool still gets --repair itself
 * (it is plain zcl_tree_copy + rename(), both portable); only this POSIX
 * fixture harness is skipped there. */
#if !defined(_WIN32)
static bool same_file_bytes(const char *a, const char *b)
{
    FILE *fa = fopen(a, "rb");
    FILE *fb = fopen(b, "rb");
    if (!fa || !fb) {
        if (fa) fclose(fa);
        if (fb) fclose(fb);
        return false;
    }
    int ca, cb;
    bool eq = true;
    do {
        ca = fgetc(fa);
        cb = fgetc(fb);
        if (ca != cb) {
            eq = false;
            break;
        }
    } while (ca != EOF);
    fclose(fa);
    fclose(fb);
    return eq;
}

/* --repair on a real hardlinked pair: afterward the two paths are
 * independent inodes with identical bytes and preserved mode/mtime. */
struct hl_pair_fixture {
    char vendor[ZCL_DEPENDENCY_LINK_PATH_MAX];
    char src[ZCL_DEPENDENCY_LINK_PATH_MAX];
    char peer[ZCL_DEPENDENCY_LINK_PATH_MAX];
};

static bool hl_pair_create(const char *base, struct hl_pair_fixture *p)
{
    return path_join(p->vendor, base, "vendor")
        && path_join(p->src, p->vendor, "generated.h")
        && path_join(p->peer, p->vendor, "generated-copy.h")
        && platform_directory_ensure(p->vendor, 0700)
        && write_file(p->src) && link(p->src, p->peer) == 0;
}

static void hl_pair_cleanup(const struct hl_pair_fixture *p)
{
    if (p->peer[0]) (void)unlink(p->peer);
    if (p->src[0]) (void)unlink(p->src);
    if (p->vendor[0]) (void)rmdir(p->vendor);
}

static bool hl_pair_deduped(const struct hl_pair_fixture *p,
                            const struct stat *before_src,
                            const struct stat *before_peer)
{
    struct stat after_src = {0}, after_peer = {0};
    if (stat(p->src, &after_src) != 0 || stat(p->peer, &after_peer) != 0)
        return false;
    return after_src.st_ino != after_peer.st_ino &&
        after_src.st_mode == before_src->st_mode &&
        after_peer.st_mode == before_peer->st_mode &&
        after_src.st_mtime == before_src->st_mtime &&
        after_peer.st_mtime == before_peer->st_mtime &&
        same_file_bytes(p->src, p->peer);
}

/* --repair on a real hardlinked pair: afterward the two paths are
 * independent inodes with identical bytes and preserved mode/mtime. */
static bool selftest_repair_success(const char *base)
{
    struct hl_pair_fixture p = {0};
    bool ok = hl_pair_create(base, &p);
    struct stat before_src = {0}, before_peer = {0};
    if (ok)
        ok = stat(p.src, &before_src) == 0 && stat(p.peer, &before_peer) == 0 &&
             before_src.st_ino == before_peer.st_ino;
    if (ok)
        ok = repair_root(base);
    if (ok)
        ok = hl_pair_deduped(&p, &before_src, &before_peer);
    hl_pair_cleanup(&p);
    return ok;
}

/* --repair over a read-only directory refuses loudly (non-zero); nothing is
 * silently left half-done. */
static bool selftest_repair_refusal(const char *base)
{
    struct hl_pair_fixture p = {0};
    bool ok = hl_pair_create(base, &p) && chmod(p.vendor, 0500) == 0;
    if (ok)
        ok = !repair_root(base);
    if (p.vendor[0]) (void)chmod(p.vendor, 0700);
    hl_pair_cleanup(&p);
    return ok;
}

struct hl_git_fixture {
    char dotgit[ZCL_DEPENDENCY_LINK_PATH_MAX];
    char objects[ZCL_DEPENDENCY_LINK_PATH_MAX];
    char obj_a[ZCL_DEPENDENCY_LINK_PATH_MAX];
    char obj_b[ZCL_DEPENDENCY_LINK_PATH_MAX];
};

static bool hl_git_fixture_create(const char *base, struct hl_git_fixture *g)
{
    return path_join(g->dotgit, base, ".git")
        && path_join(g->objects, g->dotgit, "objects")
        && path_join(g->obj_a, g->objects, "blob-a")
        && path_join(g->obj_b, g->objects, "blob-b")
        && platform_directory_ensure(g->dotgit, 0700)
        && platform_directory_ensure(g->objects, 0700)
        && write_file(g->obj_a) && link(g->obj_a, g->obj_b) == 0;
}

static void hl_git_fixture_cleanup(const struct hl_git_fixture *g)
{
    if (g->obj_b[0]) (void)unlink(g->obj_b);
    if (g->obj_a[0]) (void)unlink(g->obj_a);
    if (g->objects[0]) (void)rmdir(g->objects);
    if (g->dotgit[0]) (void)rmdir(g->dotgit);
}

/* A hardlink outside the scanner's scope (vendor/, build/hotswap/,
 * build/githooks/) — the shape of a real .git/objects pair — must never be
 * touched by --repair. */
static bool selftest_repair_leaves_git_objects(const char *base)
{
    struct hl_git_fixture g = {0};
    bool ok = hl_git_fixture_create(base, &g);
    struct stat before = {0}, after = {0};
    if (ok)
        ok = stat(g.obj_a, &before) == 0 && before.st_nlink >= 2;
    if (ok)
        ok = repair_root(base);
    if (ok)
        ok = stat(g.obj_a, &after) == 0 && after.st_ino == before.st_ino &&
             after.st_nlink == before.st_nlink;
    hl_git_fixture_cleanup(&g);
    return ok;
}

static int selftest_repair(void)
{
    char base[] = "/tmp/z23-hardlink-repair.XXXXXX";
    if (!mkdtemp(base))
        return 1;
    bool ok = selftest_repair_success(base) &&
        selftest_repair_refusal(base) &&
        selftest_repair_leaves_git_objects(base);
    (void)rmdir(base);
    if (!ok) {
        fprintf(stderr, "hardlink-seeding: repair selftest FAIL\n");
        return 1;
    }
    printf("hardlink-seeding: repair selftest PASS (dedupe leaves "
           "independent inodes with mode+mtime preserved and identical "
           "bytes; a read-only directory refuses loudly; a .git/objects "
           "hardlink outside the scan scope is never touched)\n");
    return 0;
}
#else
static int selftest_repair(void)
{
    printf("hardlink-seeding: repair selftest SKIPPED (Windows: --repair "
           "itself is portable; this fixture harness uses POSIX "
           "link/stat/chmod/mkdtemp directly, same as selftest() above)\n");
    return 0;
}
#endif

static bool is_known_verb(const char *s)
{
    return s && (strcmp(s, "--selftest") == 0 || strcmp(s, "--count") == 0 ||
                strcmp(s, "--repair") == 0 || strcmp(s, "--dry-run") == 0);
}

static int dispatch(const char *verb, const char *root)
{
    if (strcmp(verb, "--selftest") == 0)
        return (selftest() == 0 && selftest_repair() == 0) ? 0 : 1;
    if (strcmp(verb, "--count") == 0)
        return count_root(root);
    if (strcmp(verb, "--dry-run") == 0)
        return check_root(root) ? 0 : 1;
    return repair_root(root) ? 0 : 1; /* only --repair remains */
}

int main(int argc, char **argv)
{
    static const char usage[] =
        "usage: %s [--selftest|--count|--repair|--dry-run] [worktree]\n";
    if (argc > 3) {
        fprintf(stderr, usage, argv[0]);
        return 2;
    }
    const char *verb = (argc >= 2 && is_known_verb(argv[1])) ? argv[1] : NULL;
    if (argc == 3 && !verb) {
        fprintf(stderr, usage, argv[0]);
        return 2;
    }
    const char *root = verb ? (argc == 3 ? argv[2] : ".")
                            : (argc >= 2 ? argv[1] : ".");
    if (verb)
        return dispatch(verb, root);
    if (platform_directory_probe_real(root) == PLATFORM_DIRECTORY_PROBE_MISSING) {
        fprintf(stderr, "hardlink-seeding: scan root is missing: %s\n", root);
        return 2;
    }
    return check_root(root) ? 0 : 1;
}
