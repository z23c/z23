/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Implement recursive native directory change observation. */
#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "platform/directory_watcher.h"
#include "platform/directory_compat.h"
#include "base/safe_alloc.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define WATCH_SLICE_MS 50u

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

struct watcher_state {
    HANDLE directory, event;
    OVERLAPPED overlapped;
    unsigned char buffer[65536];
    bool pending;
};

static wchar_t *watch_wide(const char *utf8)
{
    int n = utf8 ? MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8,
                                       -1, NULL, 0) : 0;
    wchar_t *wide = n > 0
        ? zcl_malloc((size_t)n * sizeof(*wide), "directory-watcher-path")
        : NULL;
    if (!wide || MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1,
                                     wide, n) != n) { free(wide); return NULL; }
    return wide;
}

static bool arm(struct watcher_state *s)
{
    if (s->pending) return true;
    ResetEvent(s->event);
    memset(&s->overlapped, 0, sizeof(s->overlapped));
    s->overlapped.hEvent = s->event;
    DWORD filter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                   FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE |
                   FILE_NOTIFY_CHANGE_CREATION;
    s->pending = ReadDirectoryChangesW(s->directory, s->buffer,
        (DWORD)sizeof(s->buffer), TRUE, filter, NULL, &s->overlapped, NULL) != 0;
    return s->pending;
}

void platform_directory_watcher_init(struct platform_directory_watcher *w)
{ if (w) w->native = UINTPTR_MAX; }

bool platform_directory_watcher_open(struct platform_directory_watcher *w,
                                     const char *root)
{
    if (!w || w->native != UINTPTR_MAX) return false;
    char canonical[32768];
    if (!platform_directory_canonical_real(root, canonical, sizeof(canonical)))
        return false;
    wchar_t *wide = watch_wide(canonical);
    struct watcher_state *s = wide
        ? zcl_calloc(1, sizeof(*s), "directory-watcher-state") : NULL;
    if (!s) { free(wide); return false; }
    s->directory = CreateFileW(wide, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT |
        FILE_FLAG_OVERLAPPED, NULL);
    free(wide);
    BY_HANDLE_FILE_INFORMATION info = {0};
    bool ok = s->directory != INVALID_HANDLE_VALUE &&
        GetFileInformationByHandle(s->directory, &info) &&
        (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
        (s->event = CreateEventW(NULL, TRUE, FALSE, NULL)) != NULL && arm(s);
    if (!ok) {
        if (s->directory != INVALID_HANDLE_VALUE) CloseHandle(s->directory);
        if (s->event) CloseHandle(s->event); free(s); return false;
    }
    w->native = (uintptr_t)s; return true;
}

enum platform_directory_watch_result platform_directory_watcher_wait(
    struct platform_directory_watcher *w, uint32_t timeout,
    platform_directory_watcher_stop stop, void *opaque)
{
    if (!w || w->native == UINTPTR_MAX) return PLATFORM_DIRECTORY_WATCH_ERROR;
    struct watcher_state *s = (struct watcher_state *)w->native;
    uint32_t elapsed = 0;
    for (;;) {
        if (stop && stop(opaque)) return PLATFORM_DIRECTORY_WATCH_STOPPED;
        uint32_t remain = timeout - elapsed;
        DWORD slice = remain < WATCH_SLICE_MS ? remain : WATCH_SLICE_MS;
        DWORD result = WaitForSingleObject(s->event, slice);
        if (result == WAIT_OBJECT_0) {
            DWORD bytes = 0;
            bool ok = GetOverlappedResult(s->directory, &s->overlapped,
                                          &bytes, FALSE) != 0;
            s->pending = false;
            if (!ok || !arm(s)) return PLATFORM_DIRECTORY_WATCH_ERROR;
            return bytes == 0 ? PLATFORM_DIRECTORY_WATCH_OVERFLOW
                              : PLATFORM_DIRECTORY_WATCH_CHANGED;
        }
        if (result != WAIT_TIMEOUT) return PLATFORM_DIRECTORY_WATCH_ERROR;
        elapsed += slice;
        if (elapsed >= timeout) return PLATFORM_DIRECTORY_WATCH_TIMEOUT;
    }
}

void platform_directory_watcher_close(struct platform_directory_watcher *w)
{
    if (!w || w->native == UINTPTR_MAX) return;
    struct watcher_state *s = (struct watcher_state *)w->native;
    if (s->pending) {
        (void)CancelIoEx(s->directory, &s->overlapped);
        (void)WaitForSingleObject(s->event, 1000);
    }
    CloseHandle(s->event); CloseHandle(s->directory); free(s);
    platform_directory_watcher_init(w);
}

#elif defined(__linux__)
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

struct watch_item { int wd; char *path; };
struct watcher_state { int fd; struct watch_item *items; size_t count; };

static bool add_tree(struct watcher_state *s, const char *path)
{
    int wd = inotify_add_watch(s->fd, path, IN_CREATE | IN_DELETE | IN_MOVED_FROM |
        IN_MOVED_TO | IN_CLOSE_WRITE | IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF);
    if (wd < 0) return false;
    struct watch_item *items = zcl_realloc(
        s->items, (s->count + 1) * sizeof(*items), "directory-watch-items");
    if (!items) { inotify_rm_watch(s->fd, wd); return false; }
    s->items = items; s->items[s->count].wd = wd;
    s->items[s->count].path = zcl_strdup(path, "directory-watch-path");
    if (!s->items[s->count].path) return false;
    s->count++;
    DIR *dir = opendir(path); if (!dir) return false;
    int dfd = dirfd(dir); struct dirent *entry; bool ok = true;
    while (ok && (entry = readdir(dir)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        struct stat st;
        if (fstatat(dfd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) { ok = false; break; }
        if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) continue;
        size_t n = strlen(path) + strlen(entry->d_name) + 2;
        char *child = zcl_malloc(n, "directory-watch-child");
        if (!child) { ok = false; break; }
        (void)snprintf(child, n, "%s/%s", path, entry->d_name);
        ok = add_tree(s, child); free(child);
    }
    closedir(dir); return ok;
}

void platform_directory_watcher_init(struct platform_directory_watcher *w)
{ if (w) w->native = UINTPTR_MAX; }

bool platform_directory_watcher_open(struct platform_directory_watcher *w,
                                     const char *root)
{
    char canonical[PATH_MAX];
    if (!w || w->native != UINTPTR_MAX ||
        !platform_directory_canonical_real(root, canonical, sizeof(canonical))) return false;
    struct watcher_state *s = zcl_calloc(1, sizeof(*s), "directory-watcher-state");
    if (!s) return false;
    s->fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
    if (s->fd < 0 || !add_tree(s, canonical)) {
        struct platform_directory_watcher temp = {.native=(uintptr_t)s};
        platform_directory_watcher_close(&temp); return false;
    }
    w->native = (uintptr_t)s; return true;
}

enum platform_directory_watch_result platform_directory_watcher_wait(
    struct platform_directory_watcher *w, uint32_t timeout,
    platform_directory_watcher_stop stop, void *opaque)
{
    if (!w || w->native == UINTPTR_MAX) return PLATFORM_DIRECTORY_WATCH_ERROR;
    struct watcher_state *s = (struct watcher_state *)w->native;
    uint32_t elapsed = 0;
    for (;;) {
        if (stop && stop(opaque)) return PLATFORM_DIRECTORY_WATCH_STOPPED;
        uint32_t remain = timeout - elapsed, slice = remain < WATCH_SLICE_MS ? remain : WATCH_SLICE_MS;
        struct pollfd p = {.fd=s->fd,.events=POLLIN};
        int rc; do { rc = poll(&p, 1, (int)slice); } while (rc < 0 && errno == EINTR);
        if (rc < 0) return PLATFORM_DIRECTORY_WATCH_ERROR;
        if (rc > 0) {
            unsigned char buffer[65536]; ssize_t n = read(s->fd, buffer, sizeof(buffer));
            if (n <= 0) return PLATFORM_DIRECTORY_WATCH_ERROR;
            bool overflow = false;
            for (size_t at = 0; at + sizeof(struct inotify_event) <= (size_t)n;) {
                const struct inotify_event *e = (const void *)(buffer + at);
                if (e->mask & IN_Q_OVERFLOW) overflow = true;
                if ((e->mask & (IN_CREATE | IN_MOVED_TO)) && (e->mask & IN_ISDIR) && e->len) {
                    const char *base = NULL;
                    for (size_t i=0;i<s->count;i++) if(s->items[i].wd==e->wd){base=s->items[i].path;break;}
                    if (base) { size_t z=strlen(base)+strlen(e->name)+2; char *child=zcl_malloc(z,"directory-watch-child");
                        if (!child) overflow=true; else { (void)snprintf(child,z,"%s/%s",base,e->name);
                            struct stat st; if(lstat(child,&st)==0 && S_ISDIR(st.st_mode)&&!S_ISLNK(st.st_mode)&&!add_tree(s,child)) overflow=true; free(child); } }
                }
                at += sizeof(*e) + e->len;
            }
            return overflow ? PLATFORM_DIRECTORY_WATCH_OVERFLOW : PLATFORM_DIRECTORY_WATCH_CHANGED;
        }
        elapsed += slice; if (elapsed >= timeout) return PLATFORM_DIRECTORY_WATCH_TIMEOUT;
    }
}

void platform_directory_watcher_close(struct platform_directory_watcher *w)
{
    if (!w || w->native == UINTPTR_MAX) return;
    struct watcher_state *s=(struct watcher_state *)w->native;
    if (s->fd >= 0) close(s->fd);
    for(size_t i=0;i<s->count;i++) free(s->items[i].path);
    free(s->items); free(s); platform_directory_watcher_init(w);
}
#elif defined(__APPLE__)
/* Darwin: no inotify. The watcher is fail-closed unavailable until a
 * kqueue(FSEvents) implementation is landed (separate lane). */
#include <errno.h>
struct watcher_state { int unused; };
void platform_directory_watcher_init(struct platform_directory_watcher *w)
{ if (w) w->native = UINTPTR_MAX; }
bool platform_directory_watcher_open(struct platform_directory_watcher *w,
                                     const char *root)
{ (void)w; (void)root; return false; }
enum platform_directory_watch_result platform_directory_watcher_wait(
    struct platform_directory_watcher *w, uint32_t timeout,
    platform_directory_watcher_stop stop, void *opaque)
{ (void)w; (void)timeout; (void)stop; (void)opaque;
  return PLATFORM_DIRECTORY_WATCH_ERROR; }
void platform_directory_watcher_close(struct platform_directory_watcher *w)
{ platform_directory_watcher_init(w); }
#endif
