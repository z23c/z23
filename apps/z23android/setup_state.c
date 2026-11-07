/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "setup_state.h"
#include "sha3/sha3.h"
#include <errno.h>
#include <stdatomic.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

static atomic_bool preload_invalidated;
bool zapp_setup_preload_allowed(void) { return !atomic_load(&preload_invalidated); }
void zapp_setup_preload_invalidate(void) { atomic_store(&preload_invalidated, true); }

#define BLOB "wallet_key.blob"
#define DONE "wallet_setup_done"
#define KIND "wallet_setup_kind"
#define CONFIRMED "wallet_setup_confirmed"

static bool path_of(const char *files, const char *name, char *out, size_t cap)
{
    return files && files[0] && snprintf(out, cap, "%s/%s", files, name) < (int)cap;
}
static bool regular_file(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0 && S_ISREG(st.st_mode);
}
enum zapp_setup_state zapp_setup_state(const char *files)
{
    char blob[PATH_MAX], done[PATH_MAX];
    if (!path_of(files, BLOB, blob, sizeof(blob)) || !path_of(files, DONE, done, sizeof(done)) || !regular_file(blob))
        return ZAPP_SETUP_NEEDED;
    return regular_file(done) ? ZAPP_SETUP_READY : ZAPP_SETUP_INTERRUPTED;
}
static bool sync_directory(const char *files)
{
    int fd = open(files, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return false;
    bool ok = fsync(fd) == 0;
    return close(fd) == 0 && ok;
}
static bool write_marker(const char *files, const char *name, const char *tmp_name, const char *text)
{
    char done[PATH_MAX], tmp[PATH_MAX];
    if (!path_of(files, name, done, sizeof(done)) || !path_of(files, tmp_name, tmp, sizeof(tmp))) return false;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    size_t length = strlen(text);
    bool ok = (length == 0 || write(fd, text, length) == (ssize_t)length) && fsync(fd) == 0;
    ok = close(fd) == 0 && ok && rename(tmp, done) == 0 && sync_directory(files);
    if (!ok) (void)unlink(tmp);
    return ok;
}
bool zapp_setup_mark_done(const char *files)
{
    return write_marker(files, DONE, DONE ".tmp", "");
}
bool zapp_setup_kind_write(const char *files, enum zapp_setup_kind kind)
{
    if (kind != ZAPP_KIND_CREATE && kind != ZAPP_KIND_RESTORE) return false;
    return write_marker(files, KIND, KIND ".tmp", kind == ZAPP_KIND_CREATE ? "create" : "restore");
}
enum zapp_setup_kind zapp_setup_kind_read(const char *files)
{
    char path[PATH_MAX], text[16] = "";
    if (!path_of(files, KIND, path, sizeof(path))) return ZAPP_KIND_NONE;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    ssize_t n = fd >= 0 ? read(fd, text, sizeof(text) - 1) : -1;
    if (fd >= 0) close(fd);
    if (n <= 0) return ZAPP_KIND_NONE;
    text[n] = 0;
    if (!strcmp(text, "create")) return ZAPP_KIND_CREATE;
    return !strcmp(text, "restore") ? ZAPP_KIND_RESTORE : ZAPP_KIND_NONE;
}
void zapp_setup_kind_forget(const char *files)
{
    char path[PATH_MAX];
    if (path_of(files, KIND, path, sizeof(path))) (void)unlink(path);
}
/* The path of a file and of the same file set aside at now_s. */
static bool aside_paths(const char *dir, const char *name, int64_t now_s, char *from, char *to, size_t cap)
{
    char stamp[32];
    time_t when = (time_t)now_s;
    struct tm utc;
    return path_of(dir, name, from, cap) && now_s > 0 && gmtime_r(&when, &utc) && strftime(stamp, sizeof(stamp), "%Y%m%dT%H%M%SZ", &utc) != 0 &&
           snprintf(to, cap, "%s.unused-%s", from, stamp) < (int)cap;
}
enum zapp_aside zapp_setup_set_aside(const char *dir, const char *name, int64_t now_s)
{
    char from[PATH_MAX], to[PATH_MAX];
    struct stat st;
    if (!aside_paths(dir, name, now_s, from, to, PATH_MAX)) return ZAPP_ASIDE_FAILED;
    if (lstat(from, &st) != 0) return errno == ENOENT ? ZAPP_ASIDE_ABSENT : ZAPP_ASIDE_FAILED;
    if (lstat(to, &st) == 0) return ZAPP_ASIDE_FAILED;
    return rename(from, to) == 0 && sync_directory(dir) ? ZAPP_ASIDE_MOVED : ZAPP_ASIDE_FAILED;
}
bool zapp_setup_undo_aside(const char *dir, const char *name, int64_t now_s)
{
    char from[PATH_MAX], to[PATH_MAX];
    struct stat st;
    if (!aside_paths(dir, name, now_s, from, to, PATH_MAX) || lstat(to, &st) != 0 || lstat(from, &st) == 0) return false;
    return rename(to, from) == 0 && sync_directory(dir);
}
bool zapp_setup_aside_path(const char *dir, const char *name, int64_t now_s, char *out, size_t cap)
{
    char from[PATH_MAX], to[PATH_MAX];
    return aside_paths(dir, name, now_s, from, to, PATH_MAX) && snprintf(out, cap, "%s", to) < (int)cap;
}
/* The confirmation names the key file it was made for: "<start|-> <SHA3-256 of wallet_key.blob in hex>". A confirmation left from a
 * key that was set aside or replaced therefore never confirms a new wallet. */
#define BLOB_MAX 65536
#define HASH_HEX (2 * 32)
#define CONFIRMATION_MAX (5 + 1 + HASH_HEX + 1)
static bool blob_hash_hex(const char *files, char out[HASH_HEX + 1])
{
    static const char hex[] = "0123456789abcdef";
    char path[PATH_MAX];
    unsigned char data[BLOB_MAX], digest[32];
    if (!path_of(files, BLOB, path, sizeof(path))) return false;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    ssize_t n = fd >= 0 ? read(fd, data, sizeof(data)) : -1;
    if (fd >= 0) close(fd);
    if (n <= 0 || n >= (ssize_t)sizeof(data)) return false;
    zcl_sha3_256(data, (size_t)n, digest);
    for (size_t i = 0; i < sizeof(digest); ++i) {
        out[2 * i] = hex[digest[i] >> 4];
        out[2 * i + 1] = hex[digest[i] & 15];
    }
    out[HASH_HEX] = 0;
    return true;
}
bool zapp_setup_mark_confirmed(const char *files, bool start_known)
{
    char hash[HASH_HEX + 1], text[CONFIRMATION_MAX];
    if (!blob_hash_hex(files, hash)) return false;
    snprintf(text, sizeof(text), "%s %s", start_known ? "start" : "-", hash);
    return write_marker(files, CONFIRMED, CONFIRMED ".tmp", text);
}
/* The confirmation text when it names the key file now in place, else false. */
static bool read_confirmation(const char *files, char text[CONFIRMATION_MAX])
{
    char path[PATH_MAX], hash[HASH_HEX + 1];
    if (!path_of(files, CONFIRMED, path, sizeof(path)) || !blob_hash_hex(files, hash)) return false;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    ssize_t n = fd >= 0 ? read(fd, text, CONFIRMATION_MAX - 1) : -1;
    if (fd >= 0) close(fd);
    if (n <= 0) return false;
    text[n] = 0;
    const char *space = strchr(text, ' ');
    return space && (space - text == 1 || space - text == 5) && !strcmp(space + 1, hash);
}
bool zapp_setup_confirmed_start(const char *files)
{
    char text[CONFIRMATION_MAX];
    return read_confirmation(files, text) && !strncmp(text, "start ", 6);
}
bool zapp_setup_confirmed(const char *files)
{
    char text[CONFIRMATION_MAX];
    return read_confirmation(files, text);
}

bool zapp_setup_identity(const char *files, char out[65])
{
    if (!out) return false;
    out[0] = 0;
    return zapp_setup_state(files) == ZAPP_SETUP_READY &&
           zapp_setup_confirmed(files) && blob_hash_hex(files, out) &&
           zapp_setup_confirmed(files);
}

static bool setup_nonce_valid(const char *nonce)
{
    if (!nonce || strlen(nonce) != 64) return false;
    for (size_t i = 0; i < 64; i++)
        if (!((nonce[i] >= '0' && nonce[i] <= '9') || (nonce[i] >= 'a' && nonce[i] <= 'f'))) return false;
    return true;
}
bool zapp_setup_nonce_write(const char *files, const char *nonce)
{
    return setup_nonce_valid(nonce) && write_marker(files, "wallet_setup_nonce", "wallet_setup_nonce.tmp", nonce);
}
bool zapp_setup_nonce_read(const char *files, char nonce[65])
{
    char path[PATH_MAX], text[66] = {0}; nonce[0] = 0;
    if (!path_of(files, "wallet_setup_nonce", path, sizeof(path))) return false;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    ssize_t n = read(fd, text, sizeof(text)); bool closed = close(fd) == 0;
    if (!closed || n != 64 || !setup_nonce_valid(text)) return false;
    memcpy(nonce, text, 65); return true;
}
bool zapp_setup_nonce_exists(const char *files)
{
    char path[PATH_MAX]; struct stat st;
    if (!path_of(files, "wallet_setup_nonce", path, sizeof(path))) return true;
    return lstat(path, &st) == 0 || errno != ENOENT;
}
