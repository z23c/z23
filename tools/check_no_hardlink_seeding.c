/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Reject multiply-linked generated dependencies in a worktree. */

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "platform/directory_compat.h"
#include "platform/file_metadata.h"

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

#define GUARD_PATH_MAX 4096u
#define GUARD_DEPTH_MAX 32u
#define GUARD_ENTRIES_MAX 50000u

struct guard_scan {
    size_t entries;
    size_t linked;
};

static bool path_join(char out[GUARD_PATH_MAX], const char *left,
                      const char *right)
{
    const size_t n = strlen(left);
    const int wrote = snprintf(out, GUARD_PATH_MAX, "%s%s%s", left,
                               n && left[n - 1] == '/' ? "" : "/", right);
    return wrote > 0 && (size_t)wrote < GUARD_PATH_MAX;
}

static bool scan_directory(const char *path, unsigned depth,
                           struct guard_scan *scan)
{
    if (depth > GUARD_DEPTH_MAX) {
        fprintf(stderr, "hardlink-seeding: traversal depth exceeded at %s\n",
                path);
        return false;
    }
    if (platform_directory_probe_real(path) != PLATFORM_DIRECTORY_PROBE_OK) {
        fprintf(stderr, "hardlink-seeding: refusing non-real directory %s\n",
                path);
        return false;
    }

    struct platform_directory_list directories = {0}, files = {0};
    if (!platform_directory_list_children_sorted(path, &directories, &files)) {
        fprintf(stderr, "hardlink-seeding: cannot inspect directory %s\n",
                path);
        return false;
    }
    bool ok = true;
    for (size_t i = 0; ok && i < files.count; i++) {
        if (++scan->entries > GUARD_ENTRIES_MAX) {
            fprintf(stderr, "hardlink-seeding: entry limit exceeded\n");
            ok = false;
            break;
        }
        char child[GUARD_PATH_MAX];
        struct platform_file_metadata metadata = {0};
        if (!path_join(child, path, files.entries[i].name) ||
            platform_file_metadata_read(child, &metadata) !=
                PLATFORM_FILE_METADATA_OK) {
            fprintf(stderr, "hardlink-seeding: cannot inspect file under %s\n",
                    path);
            ok = false;
            break;
        }
        if (metadata.links > 1) {
            fprintf(stderr,
                    "hardlink-seeding: multiply-linked dependency %s "
                    "(links=%llu)\n", child,
                    (unsigned long long)metadata.links);
            scan->linked++;
        }
    }
    for (size_t i = 0; ok && i < directories.count; i++) {
        if (++scan->entries > GUARD_ENTRIES_MAX) {
            fprintf(stderr, "hardlink-seeding: entry limit exceeded\n");
            ok = false;
            break;
        }
        char child[GUARD_PATH_MAX];
        if (!path_join(child, path, directories.entries[i].name) ||
            !scan_directory(child, depth + 1u, scan))
            ok = false;
    }
    platform_directory_list_free(&files);
    platform_directory_list_free(&directories);
    return ok;
}

static bool scan_optional_root(const char *root, const char *relative,
                               struct guard_scan *scan)
{
    char path[GUARD_PATH_MAX];
    if (!path_join(path, root, relative)) {
        fprintf(stderr, "hardlink-seeding: root path is too long\n");
        return false;
    }
    const enum platform_directory_probe_result probe =
        platform_directory_probe_real(path);
    if (probe == PLATFORM_DIRECTORY_PROBE_MISSING)
        return true;
    if (probe != PLATFORM_DIRECTORY_PROBE_OK) {
        fprintf(stderr, "hardlink-seeding: refusing dependency root %s\n",
                path);
        return false;
    }
    return scan_directory(path, 0, scan);
}

static bool check_root(const char *root)
{
    struct guard_scan scan = {0};
    if (!root || !root[0] ||
        platform_directory_probe_real(root) != PLATFORM_DIRECTORY_PROBE_OK) {
        fprintf(stderr, "hardlink-seeding: refusing non-real worktree root\n");
        return false;
    }
    char build[GUARD_PATH_MAX];
    if (!path_join(build, root, "build")) {
        fprintf(stderr, "hardlink-seeding: build path is too long\n");
        return false;
    }
    const enum platform_directory_probe_result build_probe =
        platform_directory_probe_real(build);
    bool inspected = scan_optional_root(root, "vendor", &scan);
    if (build_probe == PLATFORM_DIRECTORY_PROBE_OK)
        inspected = inspected && scan_optional_root(build, "hotswap", &scan)
            && scan_optional_root(build, "githooks", &scan);
    else if (build_probe != PLATFORM_DIRECTORY_PROBE_MISSING) {
        fprintf(stderr, "hardlink-seeding: refusing non-real build root %s\n",
                build);
        inspected = false;
    }
    if (!inspected)
        return false;
    if (scan.linked) {
        fprintf(stderr, "hardlink-seeding: FAIL (%zu linked file%s)\n",
                scan.linked, scan.linked == 1 ? "" : "s");
        fprintf(stderr, "Run repairs only when no proof is in flight: "
                "replacing a shared path changes its donor's ctime.\n"
                "For each affected file, set f to its quoted path and use "
                "a fresh temporary name:\n"
                "  cp -a --reflink=auto -- \"$f\" \"$f.tmp\" && "
                "mv -f -- \"$f.tmp\" \"$f\"\n");
        return false;
    }
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
    char base[GUARD_PATH_MAX], temp[GUARD_PATH_MAX];
    DWORD n = GetTempPathA((DWORD)sizeof(temp), temp);
    if (!n || n >= sizeof(temp) || !GetTempFileNameA(temp, "zhl", 0, base) ||
        !DeleteFileA(base) || !CreateDirectoryA(base, NULL))
        return 1;
#else
    char base[] = "/tmp/z23-hardlink-seeding.XXXXXX";
    if (!mkdtemp(base))
        return 1;
#endif
    char vendor[GUARD_PATH_MAX] = {0}, nested[GUARD_PATH_MAX] = {0};
    char source[GUARD_PATH_MAX] = {0}, peer[GUARD_PATH_MAX] = {0};
    char outside[GUARD_PATH_MAX] = {0}, outside_peer[GUARD_PATH_MAX] = {0};
    char outside_link[GUARD_PATH_MAX] = {0}, build[GUARD_PATH_MAX] = {0};
    char hotswap[GUARD_PATH_MAX] = {0}, external[GUARD_PATH_MAX] = {0};
    char external_hotswap[GUARD_PATH_MAX] = {0};
    char module[GUARD_PATH_MAX] = {0}, module_peer[GUARD_PATH_MAX] = {0};
    bool ok = path_join(vendor, base, "vendor")
        && path_join(nested, vendor, "include")
        && path_join(source, nested, "generated.h")
        && path_join(peer, nested, "generated-copy.h")
        && path_join(outside, base, "outside.a")
        && path_join(outside_peer, base, "outside-peer.a")
        && path_join(outside_link, vendor, "outside")
        && path_join(build, base, "build")
        && path_join(hotswap, base, "build/hotswap")
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
    char hooks[GUARD_PATH_MAX] = {0}, a[GUARD_PATH_MAX] = {0};
    char b[GUARD_PATH_MAX] = {0}, linked[GUARD_PATH_MAX] = {0};
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
    if (ok) {
        struct guard_scan edge = { .entries = GUARD_ENTRIES_MAX - 1u };
        struct guard_scan over = { .entries = GUARD_ENTRIES_MAX };
        ok = scan_directory(nested, 0, &edge)
            && edge.entries == GUARD_ENTRIES_MAX
            && !scan_directory(nested, 0, &over);
    }
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
    if (peer[0]) (void)unlink(peer);
    if (source[0]) (void)unlink(source);
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
