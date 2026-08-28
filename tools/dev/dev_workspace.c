/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Resolve dev workspaces and publish monotonic sealed cycle state. */

#if !defined(_WIN32)
#define _GNU_SOURCE
#endif
#include "devloop.h"

#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/directory_transaction.h"
#include "platform/private_directory.h"
#include "platform/time_compat.h"

#include <errno.h>
#if !defined(_WIN32)
#include <fcntl.h>
#endif
#include <limits.h>
#if defined(__linux__)
#include <poll.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/file.h>
#endif
#if defined(__linux__)
#include <sys/inotify.h>
#endif
#if !defined(_WIN32)
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#if defined(_WIN32)
/* Keep the protocol implementation below platform-neutral without pretending
 * that Win32 handles are POSIX descriptors.  These bounded, process-local
 * indices retain the audited directory/file/lock capabilities and map the
 * small *at-style vocabulary used by this module onto them. */
typedef int64_t ssize_t;
struct stat { off_t st_size; unsigned st_mode, st_uid, st_nlink; };
#define WS_MODE_DIR 0040000u
#define WS_MODE_REG 0100000u
#define S_ISDIR(mode) (((mode) & 0170000u) == WS_MODE_DIR)
#define S_ISREG(mode) (((mode) & 0170000u) == WS_MODE_REG)
#define O_RDONLY 0x0001
#define O_WRONLY 0x0002
#define O_RDWR 0x0004
#define O_CREAT 0x0008
#define O_EXCL 0x0010
#define O_DIRECTORY 0x0020
#define O_CLOEXEC 0
#define O_NOFOLLOW 0
#define LOCK_SH 1
#define LOCK_EX 2
#define AT_REMOVEDIR 1

enum ws_cap_kind { WS_CAP_FREE, WS_CAP_DIR, WS_CAP_FILE, WS_CAP_LOCK };
struct ws_cap {
    enum ws_cap_kind kind;
    int parent;
    uint64_t cursor;
    union {
        struct platform_directory_transaction dir;
        struct platform_directory_child file;
        struct platform_directory_lock lock;
    } value;
};
#define WS_CAP_LIMIT 64
static _Thread_local struct ws_cap ws_caps[WS_CAP_LIMIT];

static void ws_result_errno(enum platform_directory_result result)
{
    errno = result == PLATFORM_DIRECTORY_MISSING ? ENOENT
            : result == PLATFORM_DIRECTORY_EXISTS ? EEXIST
            : result == PLATFORM_DIRECTORY_REFUSED ? EACCES : EIO;
}

static int ws_cap_take(enum ws_cap_kind kind)
{
    for (int i = 0; i < WS_CAP_LIMIT; i++) {
        if (ws_caps[i].kind == WS_CAP_FREE) {
            memset(&ws_caps[i], 0, sizeof(ws_caps[i]));
            ws_caps[i].kind = kind;
            ws_caps[i].parent = -1;
            return i;
        }
    }
    return -1;
}

static int ws_close(int fd)
{
    if (fd < 0 || fd >= WS_CAP_LIMIT || ws_caps[fd].kind == WS_CAP_FREE)
        return -1;
    if (ws_caps[fd].kind == WS_CAP_DIR)
        platform_directory_transaction_close(&ws_caps[fd].value.dir);
    else if (ws_caps[fd].kind == WS_CAP_FILE)
        platform_directory_child_close(&ws_caps[fd].value.file);
    else
        platform_directory_lock_release(&ws_caps[fd].value.lock);
    memset(&ws_caps[fd], 0, sizeof(ws_caps[fd]));
    return 0;
}

static int ws_open(const char *path, int flags, ...)
{
    if (!path || !(flags & O_DIRECTORY))
        return -1;
    int fd = ws_cap_take(WS_CAP_DIR);
    if (fd < 0)
        return -1;
    platform_directory_transaction_init(&ws_caps[fd].value.dir);
    if (!platform_directory_transaction_open(&ws_caps[fd].value.dir, path)) {
        errno = platform_directory_probe_real(path) ==
                        PLATFORM_DIRECTORY_PROBE_MISSING
                    ? ENOENT : EACCES;
        (void)ws_close(fd);
        return -1;
    }
    return fd;
}

static int ws_openat(int dirfd, const char *leaf, int flags, ...)
{
    if (dirfd < 0 || dirfd >= WS_CAP_LIMIT ||
        ws_caps[dirfd].kind != WS_CAP_DIR)
        return -1;
    if (flags & O_DIRECTORY) {
        int child = ws_cap_take(WS_CAP_DIR);
        if (child < 0)
            return -1;
        platform_directory_transaction_init(&ws_caps[child].value.dir);
        enum platform_directory_result result =
            platform_directory_transaction_open_child(
                &ws_caps[dirfd].value.dir, leaf, false,
                &ws_caps[child].value.dir);
        if (result != PLATFORM_DIRECTORY_OK) {
            ws_result_errno(result);
            (void)ws_close(child);
            return -1;
        }
        ws_caps[child].parent = dirfd;
        return child;
    }
    int child = ws_cap_take(WS_CAP_FILE);
    if (child < 0)
        return -1;
    platform_directory_child_init(&ws_caps[child].value.file);
    bool created = false;
    enum platform_directory_result result = platform_directory_child_open_result(
        &ws_caps[dirfd].value.dir, leaf, (flags & O_CREAT) != 0,
        (flags & O_EXCL) == 0, &ws_caps[child].value.file, &created);
    (void)created;
    if (result != PLATFORM_DIRECTORY_OK) {
        ws_result_errno(result);
        (void)ws_close(child);
        return -1;
    }
    ws_caps[child].parent = dirfd;
    return child;
}

static int ws_fstat(int fd, struct stat *st)
{
    if (!st || fd < 0 || fd >= WS_CAP_LIMIT)
        return -1;
    memset(st, 0, sizeof(*st));
    if (ws_caps[fd].kind == WS_CAP_DIR) {
        st->st_mode = WS_MODE_DIR | 0700u;
        st->st_uid = 1u;
        return 0;
    }
    if (ws_caps[fd].kind != WS_CAP_FILE)
        return -1;
    struct platform_directory_child_info info;
    if (!platform_directory_child_info(&ws_caps[fd].value.file, &info))
        return -1;
    st->st_mode = WS_MODE_REG | 0600u;
    st->st_size = (off_t)info.size;
    st->st_nlink = (unsigned)info.link_count;
    st->st_uid = info.current_user_only ? 1u : 0u;
    return 0;
}

static unsigned ws_geteuid(void) { return 1u; }

static int ws_flock(int fd, int operation)
{
    if (fd < 0 || fd >= WS_CAP_LIMIT || ws_caps[fd].kind != WS_CAP_FILE ||
        ws_caps[fd].parent < 0)
        return -1;
    int parent = ws_caps[fd].parent;
    char leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u];
    (void)snprintf(leaf, sizeof(leaf), "%s", ws_caps[fd].value.file.leaf);
    platform_directory_child_close(&ws_caps[fd].value.file);
    ws_caps[fd].kind = WS_CAP_LOCK;
    platform_directory_lock_init(&ws_caps[fd].value.lock);
    enum platform_directory_result result = platform_directory_lock_acquire(
        &ws_caps[parent].value.dir, leaf, false,
        operation == LOCK_EX ? PLATFORM_DIRECTORY_LOCK_EXCLUSIVE
                             : PLATFORM_DIRECTORY_LOCK_SHARED,
        &ws_caps[fd].value.lock);
    if (result != PLATFORM_DIRECTORY_OK) {
        memset(&ws_caps[fd], 0, sizeof(ws_caps[fd]));
        return -1;
    }
    return 0;
}

static ssize_t ws_pread(int fd, void *data, size_t size, off_t offset)
{
    if (fd < 0 || fd >= WS_CAP_LIMIT || ws_caps[fd].kind != WS_CAP_FILE ||
        offset < 0)
        return -1;
    return platform_directory_child_read(&ws_caps[fd].value.file, data, size,
                                         (uint64_t)offset);
}

static ssize_t ws_pwrite(int fd, const void *data, size_t size, off_t offset)
{
    if (fd < 0 || fd >= WS_CAP_LIMIT || ws_caps[fd].kind != WS_CAP_FILE ||
        offset < 0)
        return -1;
    return platform_directory_child_write(&ws_caps[fd].value.file, data, size,
                                           (uint64_t)offset)
        ? (ssize_t)size : -1;
}

static ssize_t ws_write(int fd, const void *data, size_t size)
{
    ssize_t result = ws_pwrite(fd, data, size, (off_t)ws_caps[fd].cursor);
    if (result > 0)
        ws_caps[fd].cursor += (uint64_t)result;
    return result;
}

static int ws_ftruncate(int fd, off_t size)
{
    return fd >= 0 && fd < WS_CAP_LIMIT && ws_caps[fd].kind == WS_CAP_FILE &&
           size >= 0 && platform_directory_child_truncate(
               &ws_caps[fd].value.file, (uint64_t)size) ? 0 : -1;
}

static int ws_fsync(int fd)
{
    if (fd < 0 || fd >= WS_CAP_LIMIT)
        return -1;
    if (ws_caps[fd].kind == WS_CAP_DIR)
        return platform_directory_transaction_flush(&ws_caps[fd].value.dir)
                   ? 0 : -1;
    if (ws_caps[fd].kind == WS_CAP_FILE)
        return platform_directory_child_flush(&ws_caps[fd].value.file) ? 0 : -1;
    return -1;
}

static int ws_unlinkat(int dirfd, const char *leaf, int flags)
{
    (void)flags;
    return dirfd >= 0 && dirfd < WS_CAP_LIMIT &&
           ws_caps[dirfd].kind == WS_CAP_DIR &&
           platform_directory_child_unlink(&ws_caps[dirfd].value.dir, leaf,
                                           true) ? 0 : -1;
}

static int ws_renameat(int fromfd, const char *from, int tofd, const char *to)
{
    if (fromfd != tofd || fromfd < 0 || fromfd >= WS_CAP_LIMIT ||
        ws_caps[fromfd].kind != WS_CAP_DIR)
        return -1;
    struct platform_directory_child staged;
    platform_directory_child_init(&staged);
    if (!platform_directory_child_open(&ws_caps[fromfd].value.dir, from,
                                       &staged))
        return -1;
    bool ok = platform_directory_child_replace(&ws_caps[fromfd].value.dir,
                                               &staged, to, false);
    platform_directory_child_close(&staged);
    return ok ? 0 : -1;
}

static int ws_mkdirat(int dirfd, const char *leaf, int mode)
{
    (void)mode;
    if (dirfd < 0 || dirfd >= WS_CAP_LIMIT ||
        ws_caps[dirfd].kind != WS_CAP_DIR)
        return -1;
    struct platform_directory_transaction child;
    platform_directory_transaction_init(&child);
    enum platform_directory_result result =
        platform_directory_transaction_open_child(
            &ws_caps[dirfd].value.dir, leaf, true, &child);
    platform_directory_transaction_close(&child);
    return result == PLATFORM_DIRECTORY_OK ? 0 : -1;
}

static int ws_mkdir(const char *path, int mode)
{
    (void)mode;
    return platform_private_directory_ensure(path) ? 0 : -1;
}

static int ws_getpid(void) { return 1; }

#define open ws_open
#define openat ws_openat
#define close ws_close
#define fstat ws_fstat
#define geteuid ws_geteuid
#define flock ws_flock
#define pread ws_pread
#define pwrite ws_pwrite
#define write ws_write
#define ftruncate ws_ftruncate
#define fsync ws_fsync
#define unlinkat ws_unlinkat
#define renameat ws_renameat
#define mkdirat ws_mkdirat
#define mkdir ws_mkdir
#define getpid ws_getpid
#endif

#define CYCLE_CANONICAL_MAX ZCL_DEVLOOP_CYCLE_JSON_MAX
#define CYCLE_RECORD_MAX (ZCL_DEVLOOP_CYCLE_JSON_MAX + 4096)
#define CYCLE_EVENTS_DIR "cycle-events"
#define CYCLE_EVENTS_ABSENT (-1)
#define CYCLE_EVENTS_INVALID (-2)
#define CYCLE_STREAM_NAME "native-events.ring"
#define CYCLE_STREAM_HEADER_SIZE 136u
#define CYCLE_STREAM_SLOT_COUNT 64u
#define CYCLE_STREAM_BODY_MAX CYCLE_CANONICAL_MAX
#define CYCLE_STREAM_SLOT_SIZE (44u + CYCLE_STREAM_BODY_MAX)
#define CYCLE_STREAM_FILE_SIZE                                           \
    (CYCLE_STREAM_HEADER_SIZE +                                         \
     CYCLE_STREAM_SLOT_COUNT * CYCLE_STREAM_SLOT_SIZE)

static const unsigned char cycle_stream_magic[16] = {
    'Z', 'C', 'L', 'D', 'E', 'V', 'S', 'T', 'R', 'E', 'A', 'M', '1', 0, 0, 0
};

static _Thread_local char g_event_edit_epoch[65];

static void set_why(char *why, size_t why_len, const char *value)
{
    if (why && why_len)
        (void)snprintf(why, why_len, "%s", value ? value : "");
}

static void hash_field(struct sha3_256_ctx *ctx, const char *name,
                       const char *value)
{
    const unsigned char zero = 0;
    sha3_256_write(ctx, (const unsigned char *)name, strlen(name));
    sha3_256_write(ctx, &zero, 1);
    sha3_256_write(ctx, (const unsigned char *)(value ? value : ""),
                   strlen(value ? value : ""));
    sha3_256_write(ctx, &zero, 1);
}

static void digest_hex(struct sha3_256_ctx *ctx, char out[65])
{
    static const char digits[] = "0123456789abcdef";
    unsigned char digest[32];
    sha3_256_finalize(ctx, digest);
    for (size_t i = 0; i < sizeof(digest); i++) {
        out[2 * i] = digits[digest[i] >> 4];
        out[2 * i + 1] = digits[digest[i] & 15];
    }
    out[64] = 0;
}

static bool valid_hex64(const char *value)
{
    if (!value || strlen(value) != 64)
        return false;
    return strspn(value, "0123456789abcdef") == 64;
}

bool zcl_devloop_event_edit_epoch_set(const char *edit_epoch)
{
    if (!edit_epoch || !edit_epoch[0]) {
        g_event_edit_epoch[0] = 0;
        return true;
    }
    if (!valid_hex64(edit_epoch))
        return false;
    (void)snprintf(g_event_edit_epoch, sizeof(g_event_edit_epoch), "%s",
                   edit_epoch);
    return true;
}

const char *zcl_devloop_event_edit_epoch(void)
{
    return g_event_edit_epoch;
}

static bool workspace_identity(const char *repo_root, char out[65])
{
    char canonical[PATH_MAX];
#if defined(_WIN32)
    if (!repo_root || !out ||
        !platform_directory_canonical_real(repo_root, canonical,
                                           sizeof(canonical)))
        return false;
#else
    struct stat st;
    if (!repo_root || !out || !realpath(repo_root, canonical) ||
        stat(canonical, &st) != 0 || !S_ISDIR(st.st_mode))
        return false;
#endif
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    hash_field(&ctx, "domain", "zcl.dev_workspace.v1");
    hash_field(&ctx, "canonical_root", canonical);
    digest_hex(&ctx, out);
    return true;
}

bool zcl_devloop_workspace_id(const char *repo_root, char out[65])
{
    return workspace_identity(repo_root, out);
}

bool zcl_devloop_workspace_resolve(const char *repo_root, char out_id[65],
                                   char *out_dir, size_t out_dir_len)
{
#if defined(_WIN32)
    const char *home = getenv("LOCALAPPDATA");
#else
    const char *home = getenv("HOME");
#endif
    if (!home || !home[0] || !out_id || !out_dir || out_dir_len == 0 ||
        !workspace_identity(repo_root, out_id))
        return false;
    int n = snprintf(out_dir, out_dir_len,
#if defined(_WIN32)
                     "%s/z23/dev/workspaces/%s",
#else
                     "%s/.local/state/zclassic23-dev/workspaces/%s",
#endif
                     home, out_id);
    return n > 0 && (size_t)n < out_dir_len;
}

bool zcl_devloop_workspace_state_dir(const char *repo_root,
                                     char *out, size_t out_len)
{
    char workspace[65];
    return zcl_devloop_workspace_resolve(repo_root, workspace, out, out_len);
}

static bool mkdirs(const char *path)
{
    char copy[PATH_MAX];
    if (!path || !path[0] || strlen(path) >= sizeof(copy))
        return false;
    (void)snprintf(copy, sizeof(copy), "%s", path);
#if defined(_WIN32)
    const char *local = getenv("LOCALAPPDATA");
    size_t local_len = local ? strlen(local) : 0;
    if (!local_len || strncmp(copy, local, local_len) != 0 ||
        (copy[local_len] != '/' && copy[local_len] != '\\'))
        return false;
    char *start = copy + local_len + 1u;
#else
    char *start = copy + 1;
#endif
    for (char *p = start; *p; p++) {
        if (*p != '/')
            continue;
        *p = 0;
        if (mkdir(copy, 0700) != 0 && errno != EEXIST)
            return false;
        *p = '/';
    }
    return mkdir(copy, 0700) == 0 || errno == EEXIST;
}

static bool private_dir_fd(int fd)
{
    struct stat st;
    return fd >= 0 && fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) &&
           st.st_uid == geteuid() && (st.st_mode & 0077) == 0;
}

static bool private_regular_fd(int fd, struct stat *st_out)
{
    struct stat st;
    bool ok = fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
              st.st_uid == geteuid() && st.st_nlink == 1 &&
              (st.st_mode & 0077) == 0;
    if (ok && st_out)
        *st_out = st;
    return ok;
}

static int cycle_lock_open(int dirfd, bool create, int operation)
{
    int flags = (create ? O_RDWR : O_RDONLY) | O_CLOEXEC | O_NOFOLLOW;
    if (create)
        flags |= O_CREAT;
    int fd = openat(dirfd, "cycle-state.lock", flags, 0600);
    if (!private_regular_fd(fd, NULL) || flock(fd, operation) != 0) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    return fd;
}

static bool write_all(int fd, const char *body, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, body + off, len - off);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        off += (size_t)n;
    }
    return true;
}

static bool cycle_digest(const char *workspace, int64_t epoch,
                         const char *canonical,
                         char out[65])
{
    if (!valid_hex64(workspace) || epoch <= 0 || !canonical)
        return false;
    char epoch_text[32];
    int n = snprintf(epoch_text, sizeof(epoch_text), "%lld",
                     (long long)epoch);
    if (n <= 0 || (size_t)n >= sizeof(epoch_text))
        return false;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    hash_field(&ctx, "domain", "zcl.dev_cycle_record.v1");
    hash_field(&ctx, "workspace_id", workspace);
    hash_field(&ctx, "epoch", epoch_text);
    hash_field(&ctx, "cycle_json", canonical);
    digest_hex(&ctx, out);
    return true;
}

static bool cycle_canonicalize(const struct json_value *cycle,
                               char out[CYCLE_CANONICAL_MAX], size_t *len_out)
{
    if (!cycle || cycle->type != JSON_OBJ || cycle->num_children == 0)
        return false;
    const struct json_value *schema = json_get(cycle, "schema");
    if (!schema || schema->type != JSON_STR ||
        strcmp(json_get_str(schema), "zcl.dev_cycle.v1") != 0 ||
        json_get(cycle, "epoch") != NULL)
        return false;
    size_t len = json_write(cycle, out, CYCLE_CANONICAL_MAX);
    if (len == 0 || len >= CYCLE_CANONICAL_MAX)
        return false;
    out[len] = 0;
    *len_out = len;
    return true;
}

static bool pwrite_all(int fd, const void *body, size_t len, off_t offset)
{
    const unsigned char *bytes = body;
    size_t off = 0;
    while (off < len) {
        ssize_t n = pwrite(fd, bytes + off, len - off,
                           offset + (off_t)off);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        off += (size_t)n;
    }
    return true;
}

static bool pread_all(int fd, void *body, size_t len, off_t offset)
{
    unsigned char *bytes = body;
    size_t off = 0;
    while (off < len) {
        ssize_t n = pread(fd, bytes + off, len - off,
                          offset + (off_t)off);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        off += (size_t)n;
    }
    return true;
}

static void cycle_stream_header_seal(const unsigned char header[96],
                                     unsigned char out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const char domain[] = "zcl.dev_cycle_stream.header.v1";
    hash_field(&sha, "domain", domain);
    sha3_256_write(&sha, header, 80);
    sha3_256_write(&sha, header + 88, 8);
    sha3_256_finalize(&sha, out);
}

static void cycle_stream_event_digest(const char *workspace, int64_t epoch,
                                      const char *canonical, size_t len,
                                      unsigned char out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    hash_field(&sha, "domain", "zcl.dev_cycle_stream.event.v1");
    hash_field(&sha, "workspace_id", workspace);
    unsigned char encoded[8];
    zcl_write_u64_le(encoded, (uint64_t)epoch);
    sha3_256_write(&sha, encoded, sizeof(encoded));
    sha3_256_write(&sha, (const unsigned char *)canonical, len);
    sha3_256_finalize(&sha, out);
}

static bool cycle_stream_header_valid(const unsigned char header[136],
                                      const char *workspace)
{
    unsigned char seal[32];
    cycle_stream_header_seal(header, seal);
    return memcmp(header, cycle_stream_magic, sizeof(cycle_stream_magic)) == 0 &&
           memcmp(header + 16, workspace, 64) == 0 &&
           zcl_read_u32_le(header + 88) == CYCLE_STREAM_SLOT_COUNT &&
           zcl_read_u32_le(header + 92) == CYCLE_STREAM_BODY_MAX &&
           memcmp(header + 96, seal, sizeof(seal)) == 0;
}

static int cycle_stream_open_at(int dirfd, const char *workspace,
                                unsigned char header[136])
{
    int fd = openat(dirfd, CYCLE_STREAM_NAME,
                    O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (!private_regular_fd(fd, &st) ||
        st.st_size != (off_t)CYCLE_STREAM_FILE_SIZE ||
        !pread_all(fd, header, CYCLE_STREAM_HEADER_SIZE, 0) ||
        !cycle_stream_header_valid(header, workspace)) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    return fd;
}

bool zcl_devloop_cycle_stream_reset(const char *repo_root,
                                    int64_t durable_epoch,
                                    char *why, size_t why_len)
{
    if (why && why_len)
        why[0] = 0;
    char dir[PATH_MAX], workspace[65];
    if (durable_epoch < 0 ||
        !zcl_devloop_workspace_resolve(repo_root, workspace, dir,
                                       sizeof(dir)) ||
        !mkdirs(dir)) {
        set_why(why, why_len, "cycle_stream_workspace_unavailable");
        return false;
    }
    int dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (!private_dir_fd(dirfd)) {
        if (dirfd >= 0)
            close(dirfd);
        set_why(why, why_len, "cycle_stream_directory_invalid");
        return false;
    }
    int fd = openat(dirfd, CYCLE_STREAM_NAME,
                    O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    /* Reset is a new volatile generation. Shrinking first is load-bearing:
     * ftruncate to an unchanged size leaves old ring slots intact, and a
     * reader could otherwise mistake an old durable_epoch+1 slot for a new
     * event before the watcher publishes anything. Startup is outside the
     * reflex path, so clearing the bounded image costs no edit latency. */
    bool ok = private_regular_fd(fd, NULL) && ftruncate(fd, 0) == 0 &&
              ftruncate(fd, (off_t)CYCLE_STREAM_FILE_SIZE) == 0;
    unsigned char header[CYCLE_STREAM_HEADER_SIZE] = {0};
    if (ok) {
        memcpy(header, cycle_stream_magic, sizeof(cycle_stream_magic));
        memcpy(header + 16, workspace, 64);
        header[80] = 0;
        zcl_write_u64_le(header + 80, (uint64_t)durable_epoch);
        zcl_write_u32_le(header + 88, CYCLE_STREAM_SLOT_COUNT);
        zcl_write_u32_le(header + 92, CYCLE_STREAM_BODY_MAX);
        cycle_stream_header_seal(header, header + 96);
        zcl_write_u64_le(header + 128, (uint64_t)durable_epoch);
        ok = pwrite_all(fd, header, sizeof(header), 0);
    }
    if (fd >= 0 && close(fd) != 0)
        ok = false;
    close(dirfd);
    if (!ok)
        set_why(why, why_len, "cycle_stream_reset_failed");
    return ok;
}

static bool cycle_stream_publish_at(const char *repo_root, int64_t epoch,
                                    const char *canonical, size_t len,
                                    bool require_next, char *why,
                                    size_t why_len)
{
    char dir[PATH_MAX], workspace[65];
    if (epoch <= 0 || !canonical || len == 0 ||
        len >= CYCLE_STREAM_BODY_MAX ||
        !zcl_devloop_workspace_resolve(repo_root, workspace, dir,
                                       sizeof(dir))) {
        set_why(why, why_len, "cycle_stream_event_invalid");
        return false;
    }
    int dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (!private_dir_fd(dirfd)) {
        if (dirfd >= 0)
            close(dirfd);
        set_why(why, why_len, "cycle_stream_directory_invalid");
        return false;
    }
    unsigned char header[CYCLE_STREAM_HEADER_SIZE];
    int fd = cycle_stream_open_at(dirfd, workspace, header);
    close(dirfd);
    if (fd < 0) {
        set_why(why, why_len, "cycle_stream_unavailable");
        return false;
    }
    uint64_t latest = zcl_read_u64_le(header + 80);
    if ((require_next && (latest == INT64_MAX || epoch != (int64_t)latest + 1)) ||
        (!require_next && epoch > (int64_t)latest + 1)) {
        close(fd);
        set_why(why, why_len, "cycle_stream_epoch_mismatch");
        return false;
    }
    unsigned char slot[CYCLE_STREAM_SLOT_SIZE];
    memset(slot, 0, sizeof(slot));
    zcl_write_u64_le(slot, (uint64_t)epoch);
    zcl_write_u32_le(slot + 8, (uint32_t)len);
    cycle_stream_event_digest(workspace, epoch, canonical, len, slot + 12);
    memcpy(slot + 44, canonical, len);
    off_t offset = (off_t)CYCLE_STREAM_HEADER_SIZE +
        (off_t)(((uint64_t)epoch - 1) % CYCLE_STREAM_SLOT_COUNT) *
            (off_t)CYCLE_STREAM_SLOT_SIZE;
    bool ok = pwrite_all(fd, slot, sizeof(slot), offset);
    unsigned char encoded[8];
    zcl_write_u64_le(encoded, (uint64_t)epoch);
    if (ok)
        ok = pwrite_all(fd, encoded, sizeof(encoded), 80);
    if (close(fd) != 0)
        ok = false;
    if (!ok)
        set_why(why, why_len, "cycle_stream_publish_failed");
    return ok;
}

static bool cycle_stream_mark_durable(const char *repo_root, int64_t epoch)
{
    char dir[PATH_MAX], workspace[65];
    if (epoch < 0 ||
        !zcl_devloop_workspace_resolve(repo_root, workspace, dir,
                                       sizeof(dir)))
        return false;
    int dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    unsigned char header[CYCLE_STREAM_HEADER_SIZE];
    int fd = private_dir_fd(dirfd)
        ? cycle_stream_open_at(dirfd, workspace, header) : -1;
    if (dirfd >= 0)
        close(dirfd);
    if (fd < 0)
        return false;
    uint64_t latest = zcl_read_u64_le(header + 80);
    uint64_t durable = zcl_read_u64_le(header + 128);
    bool ok = (uint64_t)epoch <= latest && (uint64_t)epoch >= durable;
    unsigned char encoded[8];
    zcl_write_u64_le(encoded, (uint64_t)epoch);
    if (ok)
        ok = pwrite_all(fd, encoded, sizeof(encoded), 128);
    if (close(fd) != 0)
        ok = false;
    return ok;
}

bool zcl_devloop_cycle_stream_publish(const char *repo_root,
                                      const char *cycle_json,
                                      size_t cycle_len, int64_t *epoch_out,
                                      char *why, size_t why_len)
{
    if (why && why_len)
        why[0] = 0;
    if (epoch_out)
        *epoch_out = 0;
    struct json_value cycle;
    json_init(&cycle);
    char canonical[CYCLE_CANONICAL_MAX];
    size_t canonical_len = 0;
    bool ok = cycle_json && cycle_len > 0 &&
        json_read(&cycle, cycle_json, cycle_len) &&
        cycle_canonicalize(&cycle, canonical, &canonical_len);
    json_free(&cycle);
    if (!ok) {
        set_why(why, why_len, "cycle_stream_input_invalid");
        return false;
    }
    char dir[PATH_MAX], workspace[65];
    if (!zcl_devloop_workspace_resolve(repo_root, workspace, dir,
                                       sizeof(dir))) {
        set_why(why, why_len, "cycle_stream_workspace_unavailable");
        return false;
    }
    int dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    unsigned char header[CYCLE_STREAM_HEADER_SIZE];
    int fd = private_dir_fd(dirfd)
        ? cycle_stream_open_at(dirfd, workspace, header) : -1;
    if (dirfd >= 0)
        close(dirfd);
    if (fd < 0) {
        set_why(why, why_len, "cycle_stream_unavailable");
        return false;
    }
    uint64_t latest = zcl_read_u64_le(header + 80);
    close(fd);
    if (latest >= INT64_MAX) {
        set_why(why, why_len, "cycle_stream_epoch_exhausted");
        return false;
    }
    int64_t epoch = (int64_t)latest + 1;
    ok = cycle_stream_publish_at(repo_root, epoch, canonical, canonical_len,
                                 true, why, why_len);
    if (ok && epoch_out)
        *epoch_out = epoch;
    return ok;
}

static enum zcl_devloop_state_lookup cycle_stream_read_after(
    int dirfd, const char *workspace, int64_t after_epoch, char *out,
    size_t out_len, size_t *len_out, int64_t *epoch_out)
{
    unsigned char header[CYCLE_STREAM_HEADER_SIZE];
    int fd = cycle_stream_open_at(dirfd, workspace, header);
    if (fd < 0)
        return ZCL_DEVLOOP_STATE_ABSENT;
    int64_t wanted = after_epoch + 1;
    if ((uint64_t)wanted <= zcl_read_u64_le(header + 128)) {
        close(fd);
        return ZCL_DEVLOOP_STATE_ABSENT;
    }
    off_t offset = (off_t)CYCLE_STREAM_HEADER_SIZE +
        (off_t)(((uint64_t)wanted - 1) % CYCLE_STREAM_SLOT_COUNT) *
            (off_t)CYCLE_STREAM_SLOT_SIZE;
    unsigned char slot[CYCLE_STREAM_SLOT_SIZE];
    bool read_ok = pread_all(fd, slot, sizeof(slot), offset);
    close(fd);
    if (!read_ok || zcl_read_u64_le(slot) != (uint64_t)wanted)
        return ZCL_DEVLOOP_STATE_ABSENT;
    uint32_t len = zcl_read_u32_le(slot + 8);
    if (len == 0 || len >= CYCLE_STREAM_BODY_MAX || len >= out_len)
        return ZCL_DEVLOOP_STATE_ABSENT;
    unsigned char digest[32];
    cycle_stream_event_digest(workspace, wanted, (const char *)slot + 44,
                              len, digest);
    if (memcmp(digest, slot + 12, sizeof(digest)) != 0)
        return ZCL_DEVLOOP_STATE_ABSENT;
    struct json_value cycle;
    json_init(&cycle);
    char canonical[CYCLE_CANONICAL_MAX];
    size_t canonical_len = 0;
    bool valid = json_read(&cycle, (const char *)slot + 44, len) &&
                 cycle_canonicalize(&cycle, canonical, &canonical_len) &&
                 canonical_len == len &&
                 memcmp(canonical, slot + 44, len) == 0;
    json_free(&cycle);
    if (!valid)
        return ZCL_DEVLOOP_STATE_ABSENT;
    memcpy(out, canonical, len + 1);
    *len_out = len;
    if (epoch_out)
        *epoch_out = wanted;
    return ZCL_DEVLOOP_STATE_FOUND;
}

static bool cycle_event_name(int64_t epoch, char out[32])
{
    if (epoch <= 0)
        return false;
    int n = snprintf(out, 32, "%020lld.json", (long long)epoch);
    return n == 25;
}

static enum zcl_devloop_state_lookup cycle_record_read_named(
    int dirfd, const char *name, const char *workspace, char *out,
    size_t out_len, size_t *len_out, int64_t *epoch_out)
{
    int fd = openat(dirfd, name,
                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 && errno == ENOENT)
        return ZCL_DEVLOOP_STATE_ABSENT;
    struct stat st;
    if (!private_regular_fd(fd, &st) || st.st_size <= 0 ||
        (uint64_t)st.st_size >= CYCLE_RECORD_MAX) {
        if (fd >= 0)
            close(fd);
        return ZCL_DEVLOOP_STATE_INVALID;
    }
    char body[CYCLE_RECORD_MAX];
    size_t need = (size_t)st.st_size, off = 0;
    while (off < need) {
        ssize_t n = pread(fd, body + off, need - off, (off_t)off);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        off += (size_t)n;
    }
    close(fd);
    if (off != need)
        return ZCL_DEVLOOP_STATE_INVALID;

    struct json_value record;
    json_init(&record);
    if (!json_read(&record, body, off) || record.type != JSON_OBJ ||
        record.num_children != 5) {
        json_free(&record);
        return ZCL_DEVLOOP_STATE_INVALID;
    }
    const struct json_value *schema = json_get(&record, "schema");
    const struct json_value *stored_workspace =
        json_get(&record, "workspace_id");
    const struct json_value *stored_epoch = json_get(&record, "epoch");
    const struct json_value *cycle = json_get(&record, "cycle");
    const struct json_value *stored_digest = json_get(&record, "cycle_sha3");
    char canonical[CYCLE_CANONICAL_MAX], recomputed[65];
    size_t canonical_len = 0;
    int64_t epoch = stored_epoch && stored_epoch->type == JSON_INT
                        ? json_get_int(stored_epoch) : 0;
    bool ok = schema && schema->type == JSON_STR &&
              strcmp(json_get_str(schema), "zcl.dev_cycle_record.v1") == 0 &&
              stored_workspace && stored_workspace->type == JSON_STR &&
              strcmp(json_get_str(stored_workspace), workspace) == 0 &&
              epoch > 0 && stored_digest && stored_digest->type == JSON_STR &&
              valid_hex64(json_get_str(stored_digest)) &&
              cycle_canonicalize(cycle, canonical, &canonical_len) &&
              cycle_digest(workspace, epoch, canonical, recomputed) &&
              strcmp(recomputed, json_get_str(stored_digest)) == 0 &&
              canonical_len < out_len;
    if (ok) {
        memcpy(out, canonical, canonical_len);
        out[canonical_len] = 0;
        *len_out = canonical_len;
        *epoch_out = epoch;
    }
    json_free(&record);
    return ok ? ZCL_DEVLOOP_STATE_FOUND : ZCL_DEVLOOP_STATE_INVALID;
}

static enum zcl_devloop_state_lookup cycle_record_read_at(
    int dirfd, const char *workspace, char *out, size_t out_len,
    size_t *len_out, int64_t *epoch_out)
{
    return cycle_record_read_named(dirfd, "native-cycle.json", workspace,
                                   out, out_len, len_out, epoch_out);
}

static int cycle_events_open(int dirfd, bool create)
{
    if (create && mkdirat(dirfd, CYCLE_EVENTS_DIR, 0700) != 0 &&
        errno != EEXIST)
        return CYCLE_EVENTS_INVALID;
    int fd = openat(dirfd, CYCLE_EVENTS_DIR,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 && errno == ENOENT && !create)
        return CYCLE_EVENTS_ABSENT;
    if (!private_dir_fd(fd)) {
        if (fd >= 0)
            close(fd);
        return CYCLE_EVENTS_INVALID;
    }
    return fd;
}

static enum zcl_devloop_state_lookup cycle_event_read_at(
    int events_fd, int64_t wanted_epoch, const char *workspace, char *out,
    size_t out_len, size_t *len_out, int64_t *epoch_out)
{
    char name[32];
    if (!cycle_event_name(wanted_epoch, name))
        return ZCL_DEVLOOP_STATE_INVALID;
    int64_t actual_epoch = 0;
    enum zcl_devloop_state_lookup result = cycle_record_read_named(
        events_fd, name, workspace, out, out_len, len_out, &actual_epoch);
    if (result == ZCL_DEVLOOP_STATE_FOUND && actual_epoch != wanted_epoch)
        return ZCL_DEVLOOP_STATE_INVALID;
    if (result == ZCL_DEVLOOP_STATE_FOUND && epoch_out)
        *epoch_out = actual_epoch;
    return result;
}

static bool cycle_record_publish_named(int dirfd, const char *name,
                                       const char *body, size_t body_len,
                                       bool replace)
{
    char temp[96] = {0};
    int fd = -1;
    if (!replace) {
        fd = openat(dirfd, name,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    0600);
        bool ok = private_regular_fd(fd, NULL) &&
                  write_all(fd, body, body_len) && fsync(fd) == 0;
        if (fd >= 0 && close(fd) != 0)
            ok = false;
        if (!ok)
            (void)unlinkat(dirfd, name, 0);
        return ok;
    }
    for (unsigned attempt = 0; attempt < 100; attempt++) {
        int n = snprintf(temp, sizeof(temp), ".cycle.%ld.%u.tmp",
                         (long)getpid(), attempt);
        if (n <= 0 || (size_t)n >= sizeof(temp))
            break;
        fd = openat(dirfd, temp,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    0600);
        if (fd >= 0 || errno != EEXIST)
            break;
    }
    bool ok = private_regular_fd(fd, NULL) && write_all(fd, body, body_len) &&
              fsync(fd) == 0;
    if (fd >= 0 && close(fd) != 0)
        ok = false;
    if (ok)
        ok = renameat(dirfd, temp, dirfd, name) == 0;
    if (!ok)
        (void)unlinkat(dirfd, temp, 0);
    return ok;
}

static bool cycle_state_write_impl(const char *repo_root,
                                   int64_t reserved_epoch,
                                   const char *cycle_json, size_t cycle_len,
                                   bool mirror_stream,
                                   char *why, size_t why_len)
{
    if (why && why_len)
        why[0] = 0;
    char dir[PATH_MAX], workspace[65];
    if (!cycle_json || cycle_len == 0 ||
        !zcl_devloop_workspace_resolve(repo_root, workspace, dir,
                                       sizeof(dir)) ||
        !mkdirs(dir)) {
        set_why(why, why_len, "cycle_state_workspace_unavailable");
        return false;
    }
    struct json_value cycle;
    json_init(&cycle);
    if (!json_read(&cycle, cycle_json, cycle_len) || cycle.type != JSON_OBJ) {
        json_free(&cycle);
        set_why(why, why_len, "cycle_state_input_invalid");
        return false;
    }
    char canonical[CYCLE_CANONICAL_MAX];
    size_t canonical_len = 0;
    bool ok = cycle_canonicalize(&cycle, canonical, &canonical_len);
    int dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (!private_dir_fd(dirfd)) {
        if (dirfd >= 0)
            close(dirfd);
        json_free(&cycle);
        set_why(why, why_len, "cycle_state_directory_invalid");
        return false;
    }
    int lock_fd = cycle_lock_open(dirfd, true, LOCK_EX);
    if (lock_fd < 0) {
        close(dirfd);
        json_free(&cycle);
        set_why(why, why_len, "cycle_state_lock_invalid");
        return false;
    }

    char previous[CYCLE_CANONICAL_MAX];
    size_t previous_len = 0;
    int64_t previous_epoch = 0;
    enum zcl_devloop_state_lookup current = cycle_record_read_at(
        dirfd, workspace, previous, sizeof(previous), &previous_len,
        &previous_epoch);
    if (!ok || current == ZCL_DEVLOOP_STATE_INVALID ||
        (current == ZCL_DEVLOOP_STATE_FOUND && previous_epoch == INT64_MAX)) {
        close(lock_fd);
        close(dirfd);
        json_free(&cycle);
        set_why(why, why_len,
                !ok ? "cycle_state_record_overflow"
                    : current == ZCL_DEVLOOP_STATE_INVALID
                          ? "cycle_state_current_invalid"
                          : "cycle_state_epoch_exhausted");
        return false;
    }
    int events_fd = cycle_events_open(dirfd, true);
    if (events_fd < 0) {
        close(lock_fd);
        close(dirfd);
        json_free(&cycle);
        set_why(why, why_len, "cycle_event_directory_invalid");
        return false;
    }
    /* Normally the latest pointer and journal tail agree, making this one
     * failed open. If a process died after sealing an event but before moving
     * the compatibility pointer, recover monotonically instead of reusing or
     * overwriting that epoch. */
    int64_t tail_epoch = current == ZCL_DEVLOOP_STATE_FOUND
                             ? previous_epoch : 0;
    while (tail_epoch < INT64_MAX) {
        char recovered[CYCLE_CANONICAL_MAX];
        size_t recovered_len = 0;
        int64_t recovered_epoch = 0;
        enum zcl_devloop_state_lookup tail = cycle_event_read_at(
            events_fd, tail_epoch + 1, workspace, recovered,
            sizeof(recovered), &recovered_len, &recovered_epoch);
        if (tail == ZCL_DEVLOOP_STATE_ABSENT)
            break;
        if (tail != ZCL_DEVLOOP_STATE_FOUND) {
            close(events_fd);
            close(lock_fd);
            close(dirfd);
            json_free(&cycle);
            set_why(why, why_len, "cycle_event_integrity_invalid");
            return false;
        }
        tail_epoch = recovered_epoch;
    }
    if (tail_epoch == INT64_MAX) {
        close(events_fd);
        close(lock_fd);
        close(dirfd);
        json_free(&cycle);
        set_why(why, why_len, "cycle_state_epoch_exhausted");
        return false;
    }
    int64_t epoch = tail_epoch + 1;
    if (reserved_epoch > 0 && reserved_epoch != epoch) {
        close(events_fd);
        close(lock_fd);
        close(dirfd);
        json_free(&cycle);
        set_why(why, why_len, "cycle_state_reserved_epoch_mismatch");
        return false;
    }
    char digest[65];
    ok = cycle_digest(workspace, epoch, canonical, digest);
    struct json_value record;
    json_init(&record);
    json_set_object(&record);
    ok = ok &&
         json_push_kv_str(&record, "schema", "zcl.dev_cycle_record.v1") &&
         json_push_kv_str(&record, "workspace_id", workspace) &&
         json_push_kv_int(&record, "epoch", epoch) &&
         json_push_kv(&record, "cycle", &cycle) &&
         json_push_kv_str(&record, "cycle_sha3", digest);
    json_free(&cycle);
    char body[CYCLE_RECORD_MAX];
    size_t body_len = ok ? json_write(&record, body, sizeof(body) - 2) : 0;
    json_free(&record);
    if (!ok || body_len == 0 || body_len >= sizeof(body) - 2) {
        close(lock_fd);
        close(dirfd);
        set_why(why, why_len, "cycle_state_record_overflow");
        return false;
    }
    body[body_len++] = '\n';

    char event_name[32];
    ok = cycle_event_name(epoch, event_name) &&
         cycle_record_publish_named(events_fd, event_name, body, body_len,
                                    false) &&
         fsync(events_fd) == 0 &&
         cycle_record_publish_named(dirfd, "native-cycle.json", body,
                                    body_len, true) &&
         fsync(dirfd) == 0;
    close(events_fd);
    if (ok && mirror_stream) {
        char stream_why[96] = {0};
        bool mirrored = cycle_stream_publish_at(
            repo_root, epoch, canonical, canonical_len, true, stream_why,
            sizeof(stream_why));
        if (mirrored)
            (void)cycle_stream_mark_durable(repo_root, epoch);
    } else if (ok && reserved_epoch > 0) {
        /* The sealed append-only journal is authority. Advancing the volatile
         * watermark is only a read optimization: the same canonical event is
         * already in both places, so its failure must not turn a completed
         * durable write into a false-negative retry with an epoch collision. */
        (void)cycle_stream_mark_durable(repo_root, epoch);
    }
    close(lock_fd);
    close(dirfd);
    if (!ok)
        set_why(why, why_len, "cycle_state_publication_failed");
    return ok;
}

bool zcl_devloop_cycle_state_write(const char *repo_root,
                                   const char *cycle_json, size_t cycle_len,
                                   char *why, size_t why_len)
{
    return cycle_state_write_impl(repo_root, 0, cycle_json, cycle_len, true,
                                  why, why_len);
}

bool zcl_devloop_cycle_state_write_epoch(const char *repo_root,
                                         int64_t reserved_epoch,
                                         const char *cycle_json,
                                         size_t cycle_len,
                                         char *why, size_t why_len)
{
    if (reserved_epoch <= 0) {
        set_why(why, why_len, "cycle_state_reserved_epoch_invalid");
        return false;
    }
    return cycle_state_write_impl(repo_root, reserved_epoch, cycle_json,
                                  cycle_len, false, why, why_len);
}

enum zcl_devloop_state_lookup zcl_devloop_cycle_state_read(
    const char *repo_root, char *out, size_t out_len, size_t *len_out,
    int64_t *epoch_out, char *why, size_t why_len)
{
    if (why && why_len)
        why[0] = 0;
    if (!out || out_len < 2 || !len_out) {
        set_why(why, why_len, "cycle_state_output_invalid");
        return ZCL_DEVLOOP_STATE_INVALID;
    }
    *len_out = 0;
    if (epoch_out)
        *epoch_out = 0;
    char dir[PATH_MAX], workspace[65];
    if (!zcl_devloop_workspace_resolve(repo_root, workspace, dir,
                                       sizeof(dir))) {
        set_why(why, why_len, "cycle_state_workspace_unavailable");
        return ZCL_DEVLOOP_STATE_INVALID;
    }
    int dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0 && errno == ENOENT)
        return ZCL_DEVLOOP_STATE_ABSENT;
    if (!private_dir_fd(dirfd)) {
        if (dirfd >= 0)
            close(dirfd);
        set_why(why, why_len, "cycle_state_directory_invalid");
        return ZCL_DEVLOOP_STATE_INVALID;
    }
    int lock_fd = cycle_lock_open(dirfd, false, LOCK_SH);
    if (lock_fd < 0) {
        char probe[CYCLE_CANONICAL_MAX];
        size_t probe_len = 0;
        int64_t probe_epoch = 0;
        enum zcl_devloop_state_lookup probe_result = cycle_record_read_at(
            dirfd, workspace, probe, sizeof(probe), &probe_len, &probe_epoch);
        if (probe_result == ZCL_DEVLOOP_STATE_ABSENT) {
            close(dirfd);
            return ZCL_DEVLOOP_STATE_ABSENT;
        }
        /* A first writer may have created the lock between the initial miss
         * and the state probe. Retry once; a record without its protocol lock
         * is otherwise untrusted. */
        lock_fd = cycle_lock_open(dirfd, false, LOCK_SH);
        if (lock_fd < 0) {
            close(dirfd);
            set_why(why, why_len, "cycle_state_lock_missing_or_invalid");
            return ZCL_DEVLOOP_STATE_INVALID;
        }
    }
    int64_t epoch = 0;
    enum zcl_devloop_state_lookup result = cycle_record_read_at(
        dirfd, workspace, out, out_len, len_out, &epoch);
    close(lock_fd);
    close(dirfd);
    if (result == ZCL_DEVLOOP_STATE_INVALID) {
        set_why(why, why_len, "cycle_state_integrity_invalid");
    } else if (result == ZCL_DEVLOOP_STATE_FOUND && epoch_out) {
        *epoch_out = epoch;
    }
    return result;
}

enum zcl_devloop_state_lookup zcl_devloop_cycle_state_read_after(
    const char *repo_root, int64_t after_epoch, char *out, size_t out_len,
    size_t *len_out, int64_t *epoch_out, char *why, size_t why_len)
{
    if (why && why_len)
        why[0] = 0;
    if (after_epoch < 0 || after_epoch == INT64_MAX || !out || out_len < 2 ||
        !len_out) {
        set_why(why, why_len, "cycle_event_request_invalid");
        return ZCL_DEVLOOP_STATE_INVALID;
    }
    *len_out = 0;
    if (epoch_out)
        *epoch_out = 0;
    char dir[PATH_MAX], workspace[65];
    if (!zcl_devloop_workspace_resolve(repo_root, workspace, dir,
                                       sizeof(dir))) {
        set_why(why, why_len, "cycle_state_workspace_unavailable");
        return ZCL_DEVLOOP_STATE_INVALID;
    }
    int dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0 && errno == ENOENT)
        return ZCL_DEVLOOP_STATE_ABSENT;
    if (!private_dir_fd(dirfd)) {
        if (dirfd >= 0)
            close(dirfd);
        set_why(why, why_len, "cycle_state_directory_invalid");
        return ZCL_DEVLOOP_STATE_INVALID;
    }
    enum zcl_devloop_state_lookup volatile_event = cycle_stream_read_after(
        dirfd, workspace, after_epoch, out, out_len, len_out, epoch_out);
    if (volatile_event == ZCL_DEVLOOP_STATE_FOUND) {
        close(dirfd);
        return volatile_event;
    }
    int lock_fd = cycle_lock_open(dirfd, false, LOCK_SH);
    if (lock_fd < 0) {
        close(dirfd);
        set_why(why, why_len, "cycle_state_lock_missing_or_invalid");
        return ZCL_DEVLOOP_STATE_INVALID;
    }
    char latest[CYCLE_CANONICAL_MAX];
    size_t latest_len = 0;
    int64_t latest_epoch = 0;
    enum zcl_devloop_state_lookup current = cycle_record_read_at(
        dirfd, workspace, latest, sizeof(latest), &latest_len,
        &latest_epoch);
    if (current == ZCL_DEVLOOP_STATE_INVALID) {
        close(lock_fd);
        close(dirfd);
        set_why(why, why_len, "cycle_state_integrity_invalid");
        return current;
    }

    int events_fd = cycle_events_open(dirfd, false);
    if (events_fd == CYCLE_EVENTS_INVALID) {
        close(lock_fd);
        close(dirfd);
        set_why(why, why_len, "cycle_event_directory_invalid");
        return ZCL_DEVLOOP_STATE_INVALID;
    }
    enum zcl_devloop_state_lookup event = ZCL_DEVLOOP_STATE_ABSENT;
    if (events_fd >= 0) {
        event = cycle_event_read_at(events_fd, after_epoch + 1, workspace,
                                    out, out_len, len_out, epoch_out);
        close(events_fd);
    }
    if (event == ZCL_DEVLOOP_STATE_FOUND) {
        close(lock_fd);
        close(dirfd);
        return event;
    }
    if (event == ZCL_DEVLOOP_STATE_INVALID) {
        close(lock_fd);
        close(dirfd);
        set_why(why, why_len, "cycle_event_integrity_invalid");
        return event;
    }

    if (current == ZCL_DEVLOOP_STATE_FOUND && latest_epoch > after_epoch) {
        /* Migration compatibility: a workspace may have a pre-journal latest
         * record. Only an unanchored initial read may take that snapshot;
         * anchored readers fail closed rather than skip an event. */
        if (after_epoch == 0 && latest_len < out_len) {
            memcpy(out, latest, latest_len + 1);
            *len_out = latest_len;
            if (epoch_out)
                *epoch_out = latest_epoch;
            current = ZCL_DEVLOOP_STATE_FOUND;
        } else {
            current = ZCL_DEVLOOP_STATE_INVALID;
            set_why(why, why_len, "cycle_event_gap");
        }
    } else if (current == ZCL_DEVLOOP_STATE_FOUND) {
        current = ZCL_DEVLOOP_STATE_ABSENT;
    }
    close(lock_fd);
    close(dirfd);
    if (current == ZCL_DEVLOOP_STATE_INVALID && (!why || !why[0]))
        set_why(why, why_len, "cycle_state_integrity_invalid");
    return current;
}

bool zcl_devloop_cycle_stream_flush_through(const char *repo_root,
                                            int64_t through_epoch,
                                            char *why, size_t why_len)
{
    if (why && why_len)
        why[0] = 0;
    if (!repo_root || !repo_root[0] || through_epoch <= 0) {
        set_why(why, why_len, "cycle_stream_flush_request_invalid");
        return false;
    }
    char body[CYCLE_CANONICAL_MAX];
    size_t body_len = 0;
    int64_t durable_epoch = 0;
    enum zcl_devloop_state_lookup latest = zcl_devloop_cycle_state_read(
        repo_root, body, sizeof(body), &body_len, &durable_epoch,
        why, why_len);
    if (latest == ZCL_DEVLOOP_STATE_INVALID)
        return false;
    if (latest == ZCL_DEVLOOP_STATE_ABSENT)
        durable_epoch = 0;
    if (durable_epoch >= through_epoch)
        return true;
    if (through_epoch - durable_epoch > CYCLE_STREAM_SLOT_COUNT) {
        set_why(why, why_len, "cycle_stream_flush_range_evicted");
        return false;
    }
    while (durable_epoch < through_epoch) {
        int64_t event_epoch = 0;
        enum zcl_devloop_state_lookup event =
            zcl_devloop_cycle_state_read_after(
                repo_root, durable_epoch, body, sizeof(body), &body_len,
                &event_epoch, why, why_len);
        if (event != ZCL_DEVLOOP_STATE_FOUND ||
            event_epoch != durable_epoch + 1) {
            if (!why || !why[0])
                set_why(why, why_len, "cycle_stream_flush_event_missing");
            return false;
        }
        if (!zcl_devloop_cycle_state_write_epoch(
                repo_root, event_epoch, body, body_len, why, why_len))
            return false;
        durable_epoch = event_epoch;
    }
    return true;
}

enum zcl_devloop_state_lookup zcl_devloop_cycle_state_wait_after(
    const char *repo_root, int64_t after_epoch, int timeout_ms,
    char *out, size_t out_len, size_t *len_out, int64_t *epoch_out,
    char *why, size_t why_len)
{
    if (timeout_ms < 1 || timeout_ms > 300000) {
        set_why(why, why_len, "cycle_event_wait_invalid");
        return ZCL_DEVLOOP_STATE_INVALID;
    }
    char dir[PATH_MAX], workspace[65];
    if (!zcl_devloop_workspace_resolve(repo_root, workspace, dir,
                                       sizeof(dir))) {
        set_why(why, why_len, "cycle_state_workspace_unavailable");
        return ZCL_DEVLOOP_STATE_INVALID;
    }
    (void)workspace;
#if defined(__linux__)
    int notify_fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
    int watch = notify_fd >= 0
        ? inotify_add_watch(notify_fd, dir,
            IN_CREATE | IN_MOVED_TO | IN_CLOSE_WRITE | IN_MODIFY |
            IN_DELETE_SELF | IN_MOVE_SELF)
        : -1;
    if (watch < 0) {
        if (notify_fd >= 0)
            close(notify_fd);
        set_why(why, why_len, "cycle_event_watch_unavailable");
        return ZCL_DEVLOOP_STATE_INVALID;
    }
    /* Observe both producers directly. The reflex producer modifies the
     * existing ring file, while its asynchronous evidence consumer creates
     * sealed records below cycle-events. A parent-directory watch normally
     * sees the ring write and native-cycle pointer move, but under sustained
     * watcher turnover that indirect notification was once lost: the sealed
     * story existed while drive slept to timeout. Direct watches make the
     * producer/victim relationship explicit without polling or retries. */
    char stream_path[PATH_MAX], events_path[PATH_MAX];
    int stream_watch = -1, events_watch = -1;
    int sn = snprintf(stream_path, sizeof(stream_path), "%s/%s", dir,
                      CYCLE_STREAM_NAME);
    int en = snprintf(events_path, sizeof(events_path), "%s/%s", dir,
                      CYCLE_EVENTS_DIR);
    if (sn > 0 && (size_t)sn < sizeof(stream_path))
        stream_watch = inotify_add_watch(
            notify_fd, stream_path,
            IN_CLOSE_WRITE | IN_MODIFY | IN_ATTRIB | IN_DELETE_SELF |
                IN_MOVE_SELF);
    if (en > 0 && (size_t)en < sizeof(events_path))
        events_watch = inotify_add_watch(
            notify_fd, events_path,
            IN_CREATE | IN_MOVED_TO | IN_CLOSE_WRITE | IN_MODIFY |
                IN_DELETE_SELF | IN_MOVE_SELF);
#endif

    int64_t deadline = platform_time_monotonic_us() +
        (int64_t)timeout_ms * 1000;
    enum zcl_devloop_state_lookup result;
    for (;;) {
        result = zcl_devloop_cycle_state_read_after(
            repo_root, after_epoch, out, out_len, len_out, epoch_out,
            why, why_len);
        if (result != ZCL_DEVLOOP_STATE_ABSENT)
            break;
        int64_t remaining = deadline - platform_time_monotonic_us();
        if (remaining <= 0)
            break;
        int wait_ms = (int)((remaining + 999) / 1000);
#if defined(__linux__)
        struct pollfd pfd = {.fd = notify_fd, .events = POLLIN};
        int ready = poll(&pfd, 1, wait_ms);
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready <= 0)
            break;
        char events[4096];
        while (read(notify_fd, events, sizeof(events)) > 0) {}
#else
        int slice_ms = wait_ms < 25 ? wait_ms : 25;
        platform_sleep_ms((uint32_t)slice_ms);
#endif
    }
#if defined(__linux__)
    if (events_watch >= 0)
        (void)inotify_rm_watch(notify_fd, events_watch);
    if (stream_watch >= 0)
        (void)inotify_rm_watch(notify_fd, stream_watch);
    (void)inotify_rm_watch(notify_fd, watch);
    close(notify_fd);
#endif
    return result;
}
