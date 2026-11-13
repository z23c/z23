/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Assemble and register the app bundle from an already verified generation. */
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#include "z23_app_macos_install.h"
#include "util/write_all.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
#define BUNDLE "Z23 Apps.app"
#define EXECUTABLE "z23-app-macos"
#define PLIST_SOURCE "Z23Apps-Info.plist"

static int directory_at(int parent, const char *name)
{
    return openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}
static int open_generation(const char *path)
{
    if (!path || path[0] != '/') { errno = EINVAL; return -1; }
    return open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}
static int regular_at(int dir, const char *name)
{
    int fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd); errno = EINVAL; return -1;
    }
    return fd;
}
static bool copy_file(int source_dir, const char *source, int dest_dir,
                      const char *destination, mode_t mode)
{
    int in = regular_at(source_dir, source);
    if (in < 0) return false;
    int out = openat(dest_dir, destination, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (out < 0) { close(in); return false; }
    char data[8192]; bool ok = true;
    for (;;) {
        ssize_t n = read(in, data, sizeof(data));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { ok = false; break; }
        if (!n) break;
        if (!zcl_write_all(out, data, (size_t)n)) { ok = false; break; }
    }
    if (ok && fchmod(out, mode) != 0) ok = false;
    if (close(in) != 0) ok = false;
    if (close(out) != 0) ok = false;
    return ok;
}
static ssize_t read_retry(int fd, void *data, size_t size)
{
    ssize_t n;
    do { n = read(fd, data, size); } while (n < 0 && errno == EINTR);
    return n;
}
static bool read_exact(int fd, char *data, size_t size)
{
    while (size) {
        ssize_t n = read_retry(fd, data, size);
        if (n <= 0) return false;
        data += n; size -= (size_t)n;
    }
    return true;
}
static bool files_equal(int first, int second)
{
    char x[8192], y[8192];
    for (;;) {
        ssize_t n = read_retry(first, x, sizeof(x));
        if (n < 0) return false;
        if (!n) return read_retry(second, y, 1) == 0;
        if (!read_exact(second, y, (size_t)n) || memcmp(x, y, (size_t)n)) return false;
    }
}
static bool same_file(int parent, const char *source, int dest, const char *name, mode_t mode)
{
    int a = regular_at(parent, source), b = regular_at(dest, name);
    if (a < 0 || b < 0) { if (a >= 0) close(a); if (b >= 0) close(b); return false; }
    struct stat st;
    bool ok = fstat(b, &st) == 0 && (st.st_mode & 07777) == mode && files_equal(a, b);
    if (close(a) != 0) ok = false;
    if (close(b) != 0) ok = false;
    return ok;
}
static bool dir_mode(int fd)
{
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) && (st.st_mode & 07777) == 0555;
}
static bool directory_entries(int fd, const char *first, const char *second)
{
    int copy = dup(fd);
    if (copy < 0) return false;
    DIR *dir = fdopendir(copy);
    if (!dir) { close(copy); return false; }
    unsigned found = 0; bool ok = true;
    errno = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (!strcmp(entry->d_name, first)) found |= 1u;
        else if (second && !strcmp(entry->d_name, second)) found |= 2u;
        else { ok = false; break; }
    }
    if (errno) ok = false;
    if (closedir(dir) != 0) ok = false;
    return ok && found == (second ? 3u : 1u);
}
struct bundle_dirs { int root, bundle, contents, macos; };
static bool bundle_open(struct bundle_dirs *d, const char *path, bool create)
{
    d->root = open_generation(path);
    if (d->root < 0) return false;
    if (create && mkdirat(d->root, BUNDLE, 0700) != 0) return false;
    d->bundle = directory_at(d->root, BUNDLE);
    if (d->bundle < 0) return false;
    if (create && mkdirat(d->bundle, "Contents", 0700) != 0) return false;
    d->contents = directory_at(d->bundle, "Contents");
    if (d->contents < 0) return false;
    if (create && mkdirat(d->contents, "MacOS", 0700) != 0) return false;
    d->macos = directory_at(d->contents, "MacOS");
    return d->macos >= 0;
}
static bool bundle_close(struct bundle_dirs *d)
{
    bool ok = true;
    if (d->macos >= 0 && close(d->macos) != 0) ok = false;
    if (d->contents >= 0 && close(d->contents) != 0) ok = false;
    if (d->bundle >= 0 && close(d->bundle) != 0) ok = false;
    if (d->root >= 0 && close(d->root) != 0) ok = false;
    return ok;
}
static bool bundle_create(struct bundle_dirs *d)
{
    return copy_file(d->root, EXECUTABLE, d->macos, EXECUTABLE, 0555) &&
        copy_file(d->root, PLIST_SOURCE, d->contents, "Info.plist", 0444) &&
        fchmod(d->macos, 0555) == 0 && fchmod(d->contents, 0555) == 0 && fchmod(d->bundle, 0555) == 0;
}
static bool bundle_check(struct bundle_dirs *d)
{
    return dir_mode(d->bundle) && dir_mode(d->contents) && dir_mode(d->macos) &&
        directory_entries(d->bundle, "Contents", NULL) &&
        directory_entries(d->contents, "MacOS", "Info.plist") &&
        directory_entries(d->macos, EXECUTABLE, NULL) &&
        same_file(d->root, EXECUTABLE, d->macos, EXECUTABLE, 0555) &&
        same_file(d->root, PLIST_SOURCE, d->contents, "Info.plist", 0444);
}
static bool bundle_action(const char *path, bool assemble)
{
    struct bundle_dirs d = {.root = -1, .bundle = -1, .contents = -1, .macos = -1};
    bool ok = bundle_open(&d, path, assemble);
    if (ok) ok = assemble ? bundle_create(&d) : bundle_check(&d);
    if (ok && assemble) ok = bundle_check(&d);
    if (!bundle_close(&d)) ok = false;
    return ok;
}
static bool matching_link(int dir, const char *name, const char *target)
{
    char value[PATH_MAX];
    ssize_t n = readlinkat(dir, name, value, sizeof(value) - 1u);
    if (n < 0 || (size_t)n >= sizeof(value) - 1u) return false;
    value[n] = 0;
    return strcmp(value, target) == 0;
}
static bool current_bundle_valid(const char *prefix)
{
    char current[PATH_MAX], resolved[PATH_MAX];
    int n = snprintf(current, sizeof(current), "%s/lib/z23/current", prefix);
    if (n < 0 || (size_t)n >= sizeof(current)) { errno = ENAMETOOLONG; return false; }
    return realpath(current, resolved) && bundle_action(resolved, false);
}
struct register_paths { char applications[PATH_MAX], target[PATH_MAX]; };
static bool register_paths(const char *prefix, char *link_path, size_t cap,
                           struct register_paths *paths)
{
    const char *home = getenv("HOME");
    if (!home || home[0] != '/' || !prefix || prefix[0] != '/') { errno = EINVAL; return false; }
    if (!current_bundle_valid(prefix)) return false;
    int n = snprintf(paths->applications, sizeof(paths->applications), "%s/Applications", home);
    int m = snprintf(paths->target, sizeof(paths->target), "%s/lib/z23/current/%s", prefix, BUNDLE);
    int l = snprintf(link_path, cap, "%s/%s", paths->applications, BUNDLE);
    if (n < 0 || (size_t)n >= sizeof(paths->applications) || m < 0 || (size_t)m >= sizeof(paths->target) ||
        l < 0 || (size_t)l >= cap) { errno = ENAMETOOLONG; return false; }
    return true;
}
static bool managed_link(const struct register_paths *paths)
{
    if (mkdir(paths->applications, 0700) != 0 && errno != EEXIST) return false;
    int dir = open(paths->applications, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) return false;
    if (matching_link(dir, BUNDLE, paths->target)) { close(dir); return true; }
    /* Exclusive creation preserves every pre-existing foreign entry. */
    bool ok = symlinkat(paths->target, dir, BUNDLE) == 0;
    if (!ok && errno == EEXIST) ok = matching_link(dir, BUNDLE, paths->target);
    if (close(dir) != 0) ok = false;
    return ok;
}
static bool register_link(const char *prefix, char *link_path, size_t cap)
{
    struct register_paths paths;
    return register_paths(prefix, link_path, cap, &paths) && managed_link(&paths);
}
static bool launch_register(const char *path)
{
    static const char tool[] = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister";
    char *args[] = {(char *)tool, "-f", (char *)path, NULL};
    pid_t pid; int error = posix_spawn(&pid, tool, NULL, NULL, args, environ);
    if (error) { errno = error; return false; }
    int status; pid_t done;
    do { done = waitpid(pid, &status, 0); } while (done < 0 && errno == EINTR);
    return done == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
int z23_app_macos_install(int argc, char **argv)
{
    if (argc != 3) { fputs("usage: z23-app-macos --assemble|--check-bundle GENERATION | --register PREFIX\n", stderr); return 2; }
    bool ok; errno = 0;
    if (!strcmp(argv[1], "--assemble")) ok = bundle_action(argv[2], true);
    else if (!strcmp(argv[1], "--check-bundle")) ok = bundle_action(argv[2], false);
    else if (!strcmp(argv[1], "--register")) {
        char path[PATH_MAX]; ok = register_link(argv[2], path, sizeof(path)) && launch_register(path);
    } else { fputs("z23-app-macos: unrecognized install operation\n", stderr); return 2; }
    if (!ok) { if (!errno) errno = EINVAL; fprintf(stderr, "z23-app-macos: %s failed: %s\n", argv[1], strerror(errno)); return 1; }
    return 0;
}
