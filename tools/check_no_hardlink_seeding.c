/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Reject multiply-linked generated dependencies in a worktree. */

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "dev/dependency_links.h"
#include "platform/directory_compat.h"

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

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0)
        return selftest();
    if (argc > 2) {
        fprintf(stderr, "usage: %s [--selftest|worktree]\n", argv[0]);
        return 2;
    }
    const char *root = argc == 2 ? argv[1] : ".";
    if (platform_directory_probe_real(root) == PLATFORM_DIRECTORY_PROBE_MISSING) {
        fprintf(stderr, "hardlink-seeding: scan root is missing: %s\n", root);
        return 2;
    }
    return check_root(root) ? 0 : 1;
}
