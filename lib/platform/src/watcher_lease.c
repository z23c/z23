/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "platform/watcher_lease.h"

#include "platform/current_identity.h"
#include "platform/directory_compat.h"
#include "platform/os_proc.h"
#include "platform/positioned_file.h"
#include "platform/rng.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define WL_MAGIC "z23-watch-lease-v1"
#define WL_PATH 4096u
#define WL_IDENTITY 192u

struct watcher_record {
    char magic[24];
    char nonce[65];
    char identity[WL_IDENTITY];
    char parent_image[WL_PATH];
    char root[WL_PATH];
    char image[WL_PATH];
    char image_sha256[65];
    uint64_t creator_pid;
    uint64_t creator_start_token;
    uint64_t root_volume, root_low, root_high;
    uint64_t image_volume, image_low, image_high, image_size;
};

static bool hex64(const char *s)
{
    return s && strlen(s) == 64 &&
           strspn(s, "0123456789abcdef") == 64;
}

static void hex_bytes(const uint8_t bytes[32], char out[65])
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) {
        out[i * 2] = digits[bytes[i] >> 4];
        out[i * 2 + 1] = digits[bytes[i] & 15];
    }
    out[64] = 0;
}

static bool file_identity(const char *path, uint64_t *volume, uint64_t *low,
                          uint64_t *high, uint64_t *size,
                          char *canonical, size_t canonical_size)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot snapshot;
    platform_positioned_file_init(&file);
    bool ok = platform_positioned_file_open(&file, path) &&
              platform_positioned_file_snapshot(&file, &snapshot) &&
              (!canonical || platform_positioned_file_path(
                   &file, canonical, canonical_size));
    if (ok) {
        *volume = snapshot.volume; *low = snapshot.file_low;
        *high = snapshot.file_high; *size = snapshot.size;
    }
    platform_positioned_file_close(&file);
    return ok;
}

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <aclapi.h>
#include <tlhelp32.h>
#include <windows.h>
#include "private_acl_internal.h"

static bool root_identity(const char *path, uint64_t *volume, uint64_t *low,
                          uint64_t *high)
{
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1,
                                    NULL, 0);
    wchar_t *wide = count > 0 ? malloc((size_t)count * sizeof(*wide)) : NULL;
    if (!wide || MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1,
                                     wide, count) != count) { free(wide); return false; }
    HANDLE handle = CreateFileW(wide, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        NULL);
    free(wide);
    BY_HANDLE_FILE_INFORMATION info;
    bool ok = handle != INVALID_HANDLE_VALUE &&
              GetFileInformationByHandle(handle, &info) &&
              (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
              !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
    if (ok) { *volume = info.dwVolumeSerialNumber; *low = info.nFileIndexLow;
              *high = info.nFileIndexHigh; }
    if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
    return ok;
}

static uint64_t parent_pid(void)
{
    DWORD self = GetCurrentProcessId(), parent = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry = {.dwSize = sizeof(entry)};
    if (snapshot != INVALID_HANDLE_VALUE && Process32FirstW(snapshot, &entry))
        do { if (entry.th32ProcessID == self) { parent = entry.th32ParentProcessID; break; } }
        while (Process32NextW(snapshot, &entry));
    if (snapshot != INVALID_HANDLE_VALUE) CloseHandle(snapshot);
    return parent;
}

static bool parent_matches(const struct watcher_record *record)
{
    if (parent_pid() != record->creator_pid) return false;
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                 (DWORD)record->creator_pid);
    HANDLE token = NULL, own_token = NULL;
    DWORD parent_size = 0, own_size = 0;
    TOKEN_USER *parent = NULL, *own = NULL;
    char image[WL_PATH]; DWORD count = sizeof(image);
    bool ok = process && QueryFullProcessImageNameA(process, 0, image, &count) &&
              strcmp(image, record->parent_image) == 0 &&
              OpenProcessToken(process, TOKEN_QUERY, &token) &&
              OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &own_token) &&
              !GetTokenInformation(token, TokenUser, NULL, 0, &parent_size) &&
              GetLastError() == ERROR_INSUFFICIENT_BUFFER &&
              !GetTokenInformation(own_token, TokenUser, NULL, 0, &own_size) &&
              GetLastError() == ERROR_INSUFFICIENT_BUFFER;
    if (ok) { parent = malloc(parent_size); own = malloc(own_size); }
    ok = ok && parent && own &&
         GetTokenInformation(token, TokenUser, parent, parent_size, &parent_size) &&
         GetTokenInformation(own_token, TokenUser, own, own_size, &own_size) &&
         EqualSid(parent->User.Sid, own->User.Sid);
    free(parent); free(own);
    if (token) CloseHandle(token); if (own_token) CloseHandle(own_token);
    if (process) CloseHandle(process);
    return ok;
}

static bool io_exact(HANDLE h, void *data, DWORD size, bool write)
{
    BYTE *p = data; DWORD done = 0;
    while (done < size) {
        DWORD part = 0;
        bool ok = write ? WriteFile(h, p + done, size - done, &part, NULL) != 0
                        : ReadFile(h, p + done, size - done, &part, NULL) != 0;
        if (!ok || part == 0) return false;
        done += part;
    }
    return true;
}

static bool make_stop(const char nonce[65], char out[320], HANDLE *event)
{
    if (snprintf(out, 320, "Local\\z23-watch-stop-%s", nonce) <= 0) return false;
    struct platform_private_acl acl; platform_private_acl_init_empty(&acl);
    if (!platform_private_acl_create(&acl)) return false;
    SECURITY_ATTRIBUTES sa = {.nLength = sizeof(sa),
        .lpSecurityDescriptor = platform_private_acl_descriptor(&acl)};
    *event = CreateEventA(&sa, TRUE, FALSE, out);
    bool ok = *event && GetLastError() != ERROR_ALREADY_EXISTS;
    if (!ok && *event) { CloseHandle(*event); *event = NULL; }
    platform_private_acl_destroy(&acl);
    return ok;
}
#else
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <unistd.h>

static bool root_identity(const char *path, uint64_t *volume, uint64_t *low,
                          uint64_t *high)
{
    struct stat st;
    if (lstat(path, &st) != 0 || !S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode))
        return false;
    *volume = (uint64_t)st.st_dev; *low = (uint64_t)st.st_ino; *high = 0;
    return true;
}
static uint64_t parent_pid(void) { return (uint64_t)getppid(); }
static bool parent_matches(const struct watcher_record *record)
{
    char image[WL_PATH], proc[64]; struct stat st;
    int n = snprintf(proc, sizeof(proc), "/proc/%llu",
                     (unsigned long long)record->creator_pid);
    return parent_pid() == record->creator_pid && n > 0 && n < (int)sizeof(proc) &&
           stat(proc, &st) == 0 && st.st_uid == geteuid() &&
           os_proc_pid_exe_path(record->creator_pid, image, sizeof(image)) &&
           strcmp(image, record->parent_image) == 0;
}
static bool io_exact(int fd, void *data, size_t size, bool writing)
{
    unsigned char *p = data; size_t done = 0;
    while (done < size) {
        ssize_t n = writing ? write(fd, p + done, size - done)
                          : read(fd, p + done, size - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        done += (size_t)n;
    }
    return true;
}
static bool make_stop(const char nonce[65], char out[320], int *fd)
{
    int n = snprintf(out, 320, "/tmp/z23-watch-stop-%lu-%s",
                     (unsigned long)geteuid(), nonce);
    if (n <= 0 || n >= 320 || mkfifo(out, 0600) != 0) return false;
    *fd = open(out, O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (*fd < 0) { unlink(out); return false; }
    struct stat st;
    bool ok = fstat(*fd, &st) == 0 && S_ISFIFO(st.st_mode) &&
              st.st_uid == geteuid() && (st.st_mode & 0777) == 0600;
    if (!ok) { close(*fd); unlink(out); *fd = -1; }
    return ok;
}
#endif

void platform_watcher_launch_init(struct platform_watcher_launch *launch)
{
    if (launch) *launch = (struct platform_watcher_launch){
        .inherited_read = UINTPTR_MAX, .private_write = UINTPTR_MAX,
        .stop_native = UINTPTR_MAX, .record_native = UINTPTR_MAX};
}

bool platform_watcher_launch_prepare(struct platform_watcher_launch *launch,
                                     const char *root, const char *image,
                                     const char hash[65])
{
    if (!launch || launch->inherited_read != UINTPTR_MAX || !hex64(hash)) return false;
    struct watcher_record record = {0};
    uint8_t nonce[32];
    if (!platform_directory_canonical_real(root, record.root, sizeof(record.root)) ||
        !file_identity(image, &record.image_volume, &record.image_low,
                       &record.image_high, &record.image_size,
                       record.image, sizeof(record.image)) ||
        !root_identity(record.root, &record.root_volume, &record.root_low,
                       &record.root_high) ||
        !platform_current_identity(record.identity, sizeof(record.identity)) ||
        !os_proc_exe_path(record.parent_image, sizeof(record.parent_image)) ||
        !rng_fill(nonce, sizeof(nonce))) return false;
    memcpy(record.magic, WL_MAGIC, sizeof(WL_MAGIC));
    memcpy(record.image_sha256, hash, 65); record.creator_pid = os_proc_current_pid();
    if (!os_proc_pid_start_token(record.creator_pid,
                                 &record.creator_start_token))
        return false;
    hex_bytes(nonce, record.nonce); memcpy(launch->nonce, record.nonce, 65);
#if defined(_WIN32)
    SECURITY_ATTRIBUTES sa = {.nLength = sizeof(sa), .bInheritHandle = TRUE};
    HANDLE read_handle = NULL, write_handle = NULL, event = NULL;
    if (!CreatePipe(&read_handle, &write_handle, &sa, sizeof(record)) ||
        !SetHandleInformation(write_handle, HANDLE_FLAG_INHERIT, 0) ||
        !make_stop(record.nonce, launch->stop_locator, &event)) {
        if (read_handle) CloseHandle(read_handle); if (write_handle) CloseHandle(write_handle);
        return false;
    }
    launch->inherited_read = (uintptr_t)read_handle;
    launch->private_write = (uintptr_t)write_handle; launch->stop_native = (uintptr_t)event;
#else
    int pipefd[2]; int stop = -1;
    if (pipe(pipefd) != 0 || fcntl(pipefd[0], F_SETFD, 0) != 0 ||
        fcntl(pipefd[1], F_SETFD, FD_CLOEXEC) != 0 ||
        !make_stop(record.nonce, launch->stop_locator, &stop)) return false;
    launch->inherited_read = (uintptr_t)pipefd[0];
    launch->private_write = (uintptr_t)pipefd[1]; launch->stop_native = (uintptr_t)stop;
#endif
    struct watcher_record *saved = malloc(sizeof(*saved));
    if (!saved) { platform_watcher_launch_close(launch); return false; }
    *saved = record;
    launch->record_native = (uintptr_t)saved;
    return true;
}

uintptr_t platform_watcher_launch_inherited(const struct platform_watcher_launch *launch)
{ return launch ? launch->inherited_read : UINTPTR_MAX; }

bool platform_watcher_launch_publish(struct platform_watcher_launch *launch)
{
    if (!launch || launch->private_write == UINTPTR_MAX ||
        launch->record_native == UINTPTR_MAX) return false;
    struct watcher_record *record = (struct watcher_record *)launch->record_native;
#if defined(_WIN32)
    bool ok = io_exact((HANDLE)launch->private_write, record,
                       sizeof(*record), true);
    CloseHandle((HANDLE)launch->private_write);
#else
    bool ok = io_exact((int)launch->private_write, record,
                       sizeof(*record), true);
    close((int)launch->private_write);
#endif
    launch->private_write = UINTPTR_MAX; memset(record, 0, sizeof(*record));
    free(record); launch->record_native = UINTPTR_MAX; return ok;
}

void platform_watcher_launch_close(struct platform_watcher_launch *launch)
{
    if (!launch) return;
#if defined(_WIN32)
    if (launch->inherited_read != UINTPTR_MAX) CloseHandle((HANDLE)launch->inherited_read);
    if (launch->private_write != UINTPTR_MAX) CloseHandle((HANDLE)launch->private_write);
    if (launch->stop_native != UINTPTR_MAX) CloseHandle((HANDLE)launch->stop_native);
#else
    if (launch->inherited_read != UINTPTR_MAX) close((int)launch->inherited_read);
    if (launch->private_write != UINTPTR_MAX) close((int)launch->private_write);
    if (launch->stop_native != UINTPTR_MAX) close((int)launch->stop_native);
#endif
    if (launch->record_native != UINTPTR_MAX) {
        struct watcher_record *record = (struct watcher_record *)launch->record_native;
        memset(record, 0, sizeof(*record)); free(record);
    }
    platform_watcher_launch_init(launch);
}

void platform_watcher_lease_init(struct platform_watcher_lease *lease)
{ if (lease) *lease = (struct platform_watcher_lease){.stop_native = UINTPTR_MAX}; }

bool platform_watcher_lease_accept(struct platform_watcher_lease *lease,
                                   uintptr_t inherited, const char *root,
                                   const char *image, const char hash[65])
{
    if (inherited == UINTPTR_MAX) return false;
    if (!lease || lease->stop_native != UINTPTR_MAX || !root || !image ||
        !hex64(hash)) {
#if defined(_WIN32)
        CloseHandle((HANDLE)inherited);
#else
        close((int)inherited);
#endif
        return false;
    }
    struct watcher_record record = {0};
#if defined(_WIN32)
    bool ok = io_exact((HANDLE)inherited, &record, sizeof(record), false);
    CloseHandle((HANDLE)inherited);
#else
    bool ok = io_exact((int)inherited, &record, sizeof(record), false);
    close((int)inherited);
#endif
    char identity[WL_IDENTITY], canonical[WL_PATH], parent_image[WL_PATH];
    uint64_t rv, rl, rh, iv, il, ih, size;
    ok = ok && memcmp(record.magic, WL_MAGIC, sizeof(WL_MAGIC)) == 0 &&
         hex64(record.nonce) && platform_current_identity(identity, sizeof(identity)) &&
         strcmp(identity, record.identity) == 0 && parent_matches(&record) &&
         platform_directory_canonical_real(root, canonical, sizeof(canonical)) &&
         strcmp(canonical, record.root) == 0 &&
         root_identity(canonical, &rv, &rl, &rh) && rv == record.root_volume &&
         rl == record.root_low && rh == record.root_high &&
         file_identity(image, &iv, &il, &ih, &size, parent_image,
                       sizeof(parent_image)) &&
         strcmp(parent_image, record.image) == 0 &&
         strcmp(hash, record.image_sha256) == 0 && iv == record.image_volume &&
         il == record.image_low && ih == record.image_high && size == record.image_size;
#if defined(_WIN32)
    int stop_name = ok ? snprintf(
        lease->stop_locator, sizeof(lease->stop_locator),
        "Local\\z23-watch-stop-%s", record.nonce) : -1;
    HANDLE event = stop_name > 0 &&
                           stop_name < (int)sizeof(lease->stop_locator)
                       ? OpenEventA(SYNCHRONIZE, FALSE, lease->stop_locator)
                       : NULL;
    ok = ok && event; if (ok) lease->stop_native = (uintptr_t)event;
#else
    int n = snprintf(lease->stop_locator, sizeof(lease->stop_locator),
        "/tmp/z23-watch-stop-%lu-%s", (unsigned long)geteuid(), record.nonce);
    int stop = ok && n > 0 && n < (int)sizeof(lease->stop_locator)
        ? open(lease->stop_locator, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW) : -1;
    ok = ok && stop >= 0; if (ok) lease->stop_native = (uintptr_t)stop;
#endif
    uint64_t creator_start = 0;
    ok = ok && os_proc_pid_start_token(record.creator_pid, &creator_start) &&
         creator_start == record.creator_start_token;
    if (ok) {
        struct platform_watcher_accepted_binding *accepted =
            calloc(1, sizeof(*accepted));
        if (!accepted) ok = false;
        else {
            memcpy(accepted->nonce, record.nonce, 65);
            accepted->creator_pid = record.creator_pid;
            accepted->creator_start_token = record.creator_start_token;
            memcpy(accepted->canonical_root, record.root,
                   sizeof(accepted->canonical_root));
            accepted->root_volume = record.root_volume;
            accepted->root_low = record.root_low;
            accepted->root_high = record.root_high;
            memcpy(accepted->canonical_image, record.image,
                   sizeof(accepted->canonical_image));
            accepted->image_volume = record.image_volume;
            accepted->image_low = record.image_low;
            accepted->image_high = record.image_high;
            accepted->image_size = record.image_size;
            memcpy(accepted->image_sha256, record.image_sha256, 65);
            lease->accepted = accepted;
            memcpy(lease->nonce, record.nonce, 65);
        }
    }
    if (!ok && lease->stop_native != UINTPTR_MAX) {
#if defined(_WIN32)
        CloseHandle((HANDLE)lease->stop_native);
#else
        close((int)lease->stop_native);
#endif
        lease->stop_native = UINTPTR_MAX;
        lease->stop_locator[0] = 0;
    }
    return ok;
}

bool platform_watcher_lease_binding(
    const struct platform_watcher_lease *lease,
    struct platform_watcher_accepted_binding *out)
{
    if (!lease || !out || !lease->accepted ||
        lease->stop_native == UINTPTR_MAX) return false;
    *out = *lease->accepted;
    return true;
}

bool platform_watcher_lease_signal_stop(const char nonce[65])
{
    if (!hex64(nonce)) return false;
#if defined(_WIN32)
    char name[320]; if (snprintf(name, sizeof(name), "Local\\z23-watch-stop-%s", nonce) <= 0) return false;
    HANDLE event = OpenEventA(EVENT_MODIFY_STATE, FALSE, name);
    bool ok = event && SetEvent(event); if (event) CloseHandle(event); return ok;
#else
    char path[320]; int n = snprintf(path, sizeof(path), "/tmp/z23-watch-stop-%lu-%s",
                                     (unsigned long)geteuid(), nonce);
    int fd = n > 0 && n < (int)sizeof(path) ? open(path, O_WRONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW) : -1;
    char byte = 1; bool ok = fd >= 0 && write(fd, &byte, 1) == 1; if (fd >= 0) close(fd); return ok;
#endif
}

bool platform_watcher_lease_wait_stop(struct platform_watcher_lease *lease,
                                     uint32_t timeout_ms)
{
    if (!lease || lease->stop_native == UINTPTR_MAX) return false;
#if defined(_WIN32)
    return WaitForSingleObject((HANDLE)lease->stop_native, timeout_ms) == WAIT_OBJECT_0;
#else
    struct pollfd p = {.fd = (int)lease->stop_native, .events = POLLIN};
    return poll(&p, 1, timeout_ms > INT_MAX ? INT_MAX : (int)timeout_ms) == 1 && (p.revents & POLLIN);
#endif
}

void platform_watcher_lease_close(struct platform_watcher_lease *lease)
{
    if (!lease) return;
#if defined(_WIN32)
    if (lease->stop_native != UINTPTR_MAX) CloseHandle((HANDLE)lease->stop_native);
#else
    if (lease->stop_native != UINTPTR_MAX) close((int)lease->stop_native);
    if (lease->stop_locator[0]) unlink(lease->stop_locator);
#endif
    free(lease->accepted);
    platform_watcher_lease_init(lease);
}
