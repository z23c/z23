/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "device_key.h"
#include "base/cleanse.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#define BLOB_HEADER 6u
#define BLOB_SIZE (BLOB_HEADER + ZAPP_DEVKEY_IV + ZAPP_DEVKEY_SEALED)
static const uint8_t magic[4] = {'Z', 'D', 'K', '2'};
static const uint8_t magic_v1[4] = {'Z', 'D', 'K', '1'};

static bool system_random(uint8_t *out, size_t len)
{
    while (len) {
        ssize_t got = getrandom(out, len, 0);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return false;
        out += got; len -= (size_t)got;
    }
    return true;
}

const char *zapp_devkey_status_name(enum zapp_devkey_status status)
{
    static const char *const names[] = {"ok", "declined", "invalidated", "no_screen_lock", "not_hardware",
        "not_per_use", "not_found", "exists", "corrupt", "old_format", "strongbox_unavailable", "error"};
    return (unsigned)status < sizeof(names) / sizeof(names[0]) ? names[status] : "error";
}
enum zapp_devkey_level zapp_devkey_level_of(int security_level)
{
    switch (security_level) {
    case 2: return ZAPP_DEVKEY_LEVEL_STRONGBOX;
    case 1: case -1: return ZAPP_DEVKEY_LEVEL_SECURE_HARDWARE;
    case 0: return ZAPP_DEVKEY_LEVEL_SOFTWARE;
    default: return ZAPP_DEVKEY_LEVEL_UNKNOWN;
    }
}
const char *zapp_devkey_level_name(enum zapp_devkey_level level)
{
    static const char *const names[] = {"unknown", "software", "secure_hardware", "strongbox"};
    return (unsigned)level < sizeof(names) / sizeof(names[0]) ? names[level] : "unknown";
}

/* Creates the key, asking for StrongBox first. Only StrongBox being unavailable falls back. */
static enum zapp_devkey_status create_best(const struct zapp_devkey_ops *ops, struct zapp_devkey_info *info)
{
    enum zapp_devkey_status st = ops->create_key(ops->ctx, true);
    if (st == ZAPP_DEVKEY_OK) return st;
    if (st != ZAPP_DEVKEY_STRONGBOX_UNAVAILABLE) return ZAPP_DEVKEY_ERROR;
    info->strongbox_fallback = true;
    st = ops->create_key(ops->ctx, false);
    return st == ZAPP_DEVKEY_OK ? st : ZAPP_DEVKEY_ERROR;
}
enum zapp_devkey_status zapp_devkey_classify_chain(const unsigned kinds[], size_t depth)
{
    for (size_t at = 0; at < depth; ++at) {
        unsigned kind = kinds[at];
        if (kind & ZAPP_DEVKEY_EX_PERMANENTLY_INVALIDATED) return ZAPP_DEVKEY_INVALIDATED;
        if (kind & ZAPP_DEVKEY_EX_UNRECOVERABLE_KEY) return at + 1 == depth && !(kind & ZAPP_DEVKEY_EX_UNKNOWN_ALGORITHM) ? ZAPP_DEVKEY_INVALIDATED : ZAPP_DEVKEY_ERROR;
        if (kind & ZAPP_DEVKEY_EX_BAD_TAG) return ZAPP_DEVKEY_CORRUPT;
        if (kind & ZAPP_DEVKEY_EX_STRONGBOX_UNAVAILABLE) return ZAPP_DEVKEY_STRONGBOX_UNAVAILABLE;
    }
    return ZAPP_DEVKEY_ERROR;
}
static bool blob_exists(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0;
}
/* Why a key may not hold the wallet secret: software-only, or not authenticated for every use. */
static enum zapp_devkey_status key_refusal(enum zapp_devkey_level level, bool per_use)
{
    if (level != ZAPP_DEVKEY_LEVEL_SECURE_HARDWARE && level != ZAPP_DEVKEY_LEVEL_STRONGBOX) return ZAPP_DEVKEY_NOT_HARDWARE;
    return per_use ? ZAPP_DEVKEY_OK : ZAPP_DEVKEY_NOT_PER_USE;
}
enum zapp_devkey_status zapp_devkey_prepare(const struct zapp_devkey_ops *ops, const char *path, struct zapp_devkey_info *out)
{
    struct zapp_devkey_info info = {ZAPP_DEVKEY_LEVEL_UNKNOWN, false};
    bool created = false, per_use = false;
    enum zapp_devkey_status st = ops->device_secure(ops->ctx);
    if (st != ZAPP_DEVKEY_OK) return st == ZAPP_DEVKEY_NO_SCREEN_LOCK ? st : ZAPP_DEVKEY_ERROR;
    st = ops->key_policy(ops->ctx, &info.level, &per_use);
    if (st == ZAPP_DEVKEY_NOT_FOUND && path && blob_exists(path)) return ZAPP_DEVKEY_INVALIDATED;
    if (st == ZAPP_DEVKEY_NOT_FOUND) {
        st = create_best(ops, &info);
        created = st == ZAPP_DEVKEY_OK;
        if (created) st = ops->key_policy(ops->ctx, &info.level, &per_use);
    }
    if (st != ZAPP_DEVKEY_OK) return st == ZAPP_DEVKEY_INVALIDATED ? st : ZAPP_DEVKEY_ERROR;
    st = key_refusal(info.level, per_use);
    if (st != ZAPP_DEVKEY_OK) {
        if (created) ops->delete_key(ops->ctx);
        return st;
    }
    if (out) *out = info;
    return ZAPP_DEVKEY_OK;
}

static bool write_all(int fd, const uint8_t *data, size_t len)
{
    while (len) {
        ssize_t put = write(fd, data, len);
        if (put < 0 && errno == EINTR) continue;
        if (put <= 0) return false;
        data += put; len -= (size_t)put;
    }
    return true;
}
static bool sync_directory(const char *path)
{
    char dir[PATH_MAX];
    const char *slash = strrchr(path, '/');
    size_t len = slash ? (size_t)(slash - path) : 0;
    if (len >= sizeof(dir)) return false;
    if (len) memcpy(dir, path, len);
    else dir[len++] = '.';
    dir[len] = '\0';
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return false;
    bool ok = fsync(fd) == 0;
    return close(fd) == 0 && ok;
}
/* Writes a private temporary file, then renames it into place without replacing: Android forbids
 * link() for apps, and RENAME_NOREPLACE fails with EEXIST when the blob appeared meanwhile. */
static enum zapp_devkey_status blob_store(const char *path, const uint8_t blob[BLOB_SIZE])
{
    char tmp[PATH_MAX];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp)) return ZAPP_DEVKEY_ERROR;
    (void)unlink(tmp);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return ZAPP_DEVKEY_ERROR;
    bool ok = fchmod(fd, 0600) == 0 && write_all(fd, blob, BLOB_SIZE) && fsync(fd) == 0;
    ok = close(fd) == 0 && ok;
    enum zapp_devkey_status st = ZAPP_DEVKEY_ERROR;
    if (ok && renameat2(AT_FDCWD, tmp, AT_FDCWD, path, RENAME_NOREPLACE) == 0) st = ZAPP_DEVKEY_OK;
    else if (ok && errno == EEXIST) st = ZAPP_DEVKEY_EXISTS;
    (void)unlink(tmp);
    if (st == ZAPP_DEVKEY_OK && !sync_directory(path)) { (void)unlink(path); st = ZAPP_DEVKEY_ERROR; }
    return st;
}
static void blob_pack(uint8_t blob[BLOB_SIZE], const uint8_t iv[ZAPP_DEVKEY_IV], const uint8_t sealed[ZAPP_DEVKEY_SEALED])
{
    memcpy(blob, magic, sizeof(magic));
    blob[4] = ZAPP_DEVKEY_IV; blob[5] = ZAPP_DEVKEY_SEALED;
    memcpy(blob + BLOB_HEADER, iv, ZAPP_DEVKEY_IV);
    memcpy(blob + BLOB_HEADER + ZAPP_DEVKEY_IV, sealed, ZAPP_DEVKEY_SEALED);
}
static enum zapp_devkey_status blob_load(const char *path, uint8_t blob[BLOB_SIZE])
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return errno == ENOENT ? ZAPP_DEVKEY_NOT_FOUND : ZAPP_DEVKEY_ERROR;
    struct stat st;
    uint8_t extra;
    ssize_t got = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size == (off_t)BLOB_SIZE ? read(fd, blob, BLOB_SIZE) : -1;
    bool whole = got == (ssize_t)BLOB_SIZE && read(fd, &extra, 1) == 0;
    (void)close(fd);
    if (!whole) return ZAPP_DEVKEY_CORRUPT;
    if (!memcmp(blob, magic_v1, sizeof(magic_v1))) return ZAPP_DEVKEY_OLD_FORMAT;
    bool shaped = !memcmp(blob, magic, sizeof(magic)) && blob[4] == ZAPP_DEVKEY_IV && blob[5] == ZAPP_DEVKEY_SEALED;
    return shaped ? ZAPP_DEVKEY_OK : ZAPP_DEVKEY_CORRUPT;
}

/* The statuses an op may hand back for a prompted operation; anything else is an error. */
static enum zapp_devkey_status refusal_or_ok(enum zapp_devkey_status st)
{
    switch (st) {
    case ZAPP_DEVKEY_OK: case ZAPP_DEVKEY_DECLINED: case ZAPP_DEVKEY_INVALIDATED: case ZAPP_DEVKEY_NO_SCREEN_LOCK:
    case ZAPP_DEVKEY_CORRUPT: return st;
    default: return ZAPP_DEVKEY_ERROR;
    }
}

enum zapp_devkey_status zapp_devkey_wrap_new(const struct zapp_devkey_ops *ops, const char *path,
                                             uint8_t secret[ZAPP_DEVKEY_SECRET])
{
    uint8_t iv[ZAPP_DEVKEY_IV], sealed[ZAPP_DEVKEY_SEALED], blob[BLOB_SIZE];
    memory_cleanse(secret, ZAPP_DEVKEY_SECRET);
    enum zapp_devkey_status st = blob_exists(path) ? ZAPP_DEVKEY_EXISTS : zapp_devkey_prepare(ops, path, NULL);
    if (st == ZAPP_DEVKEY_OK) {
        bool drawn = ops->random ? ops->random(ops->ctx, secret, ZAPP_DEVKEY_SECRET) : system_random(secret, ZAPP_DEVKEY_SECRET);
        st = drawn ? refusal_or_ok(ops->seal(ops->ctx, secret, ZAPP_DEVKEY_SECRET, iv, sealed)) : ZAPP_DEVKEY_ERROR;
    }
    if (st == ZAPP_DEVKEY_OK) { blob_pack(blob, iv, sealed); st = blob_store(path, blob); }
    memory_cleanse(iv, sizeof(iv)); memory_cleanse(sealed, sizeof(sealed)); memory_cleanse(blob, sizeof(blob));
    if (st != ZAPP_DEVKEY_OK) memory_cleanse(secret, ZAPP_DEVKEY_SECRET);
    return st;
}

/* Checks, before any prompt, that the screen lock is set and that the stored key is hardware backed and
 * authenticates every use: an unwrap never trusts that prepare ran or that the key is still the one it checked. */
static enum zapp_devkey_status open_precheck(const struct zapp_devkey_ops *ops)
{
    enum zapp_devkey_status st = ops->device_secure(ops->ctx);
    if (st != ZAPP_DEVKEY_OK) return st == ZAPP_DEVKEY_NO_SCREEN_LOCK ? st : ZAPP_DEVKEY_ERROR;
    enum zapp_devkey_level level = ZAPP_DEVKEY_LEVEL_UNKNOWN;
    bool per_use = false;
    st = ops->key_policy(ops->ctx, &level, &per_use);
    if (st == ZAPP_DEVKEY_NOT_FOUND || st == ZAPP_DEVKEY_INVALIDATED) return ZAPP_DEVKEY_INVALIDATED;
    return st == ZAPP_DEVKEY_OK ? key_refusal(level, per_use) : ZAPP_DEVKEY_ERROR;
}
enum zapp_devkey_status zapp_devkey_unwrap(const struct zapp_devkey_ops *ops, const char *path,
                                           enum zapp_devkey_purpose purpose, uint8_t secret[ZAPP_DEVKEY_SECRET])
{
    uint8_t blob[BLOB_SIZE];
    memory_cleanse(secret, ZAPP_DEVKEY_SECRET);
    enum zapp_devkey_status st = purpose == ZAPP_DEVKEY_PURPOSE_UNLOCK || purpose == ZAPP_DEVKEY_PURPOSE_PAYMENT ? blob_load(path, blob) : ZAPP_DEVKEY_ERROR;
    if (st == ZAPP_DEVKEY_OK) st = open_precheck(ops);
    if (st == ZAPP_DEVKEY_OK) {
        st = ops->open(ops->ctx, purpose, blob + BLOB_HEADER, blob + BLOB_HEADER + ZAPP_DEVKEY_IV, secret, ZAPP_DEVKEY_SECRET);
        st = st == ZAPP_DEVKEY_NOT_FOUND ? ZAPP_DEVKEY_INVALIDATED : refusal_or_ok(st);
    }
    memory_cleanse(blob, sizeof(blob));
    if (st != ZAPP_DEVKEY_OK) memory_cleanse(secret, ZAPP_DEVKEY_SECRET);
    return st;
}

void zapp_devkey_discard(const struct zapp_devkey_ops *ops, const char *path)
{
    (void)unlink(path);
    ops->delete_key(ops->ctx);
}

enum zapp_devkey_answer zapp_devkey_answer_for_error(int biometric_error)
{
    enum { CANCELED = 5, USER_CANCELED = 10, NO_BIOMETRICS = 11, NEGATIVE_BUTTON = 13, NO_DEVICE_CREDENTIAL = 14 };
    switch (biometric_error) {
    case CANCELED: case USER_CANCELED: case NEGATIVE_BUTTON: return ZAPP_DEVKEY_ANSWER_DECLINED;
    case NO_BIOMETRICS: case NO_DEVICE_CREDENTIAL: return ZAPP_DEVKEY_ANSWER_NO_LOCK;
    default: return ZAPP_DEVKEY_ANSWER_FAILED;
    }
}
enum zapp_devkey_status zapp_devkey_status_for_answer(enum zapp_devkey_answer answer)
{
    switch (answer) {
    case ZAPP_DEVKEY_ANSWER_SUCCEEDED: return ZAPP_DEVKEY_OK;
    case ZAPP_DEVKEY_ANSWER_DECLINED: case ZAPP_DEVKEY_ANSWER_ABANDONED: return ZAPP_DEVKEY_DECLINED;
    case ZAPP_DEVKEY_ANSWER_NO_LOCK: return ZAPP_DEVKEY_NO_SCREEN_LOCK;
    default: return ZAPP_DEVKEY_ERROR;
    }
}

unsigned long zapp_devkey_wait_begin(struct zapp_devkey_wait *wait)
{
    pthread_mutex_lock(&wait->lock);
    unsigned long ticket = 0;
    if (!wait->ticket) {
        ticket = wait->ticket = ++wait->next;
        wait->answer = ZAPP_DEVKEY_ANSWER_NONE;
    }
    pthread_mutex_unlock(&wait->lock);
    return ticket;
}
bool zapp_devkey_wait_answer(struct zapp_devkey_wait *wait, unsigned long ticket, enum zapp_devkey_answer answer)
{
    pthread_mutex_lock(&wait->lock);
    bool taken = ticket && wait->ticket == ticket && wait->answer == ZAPP_DEVKEY_ANSWER_NONE;
    if (taken) { wait->answer = answer; pthread_cond_broadcast(&wait->cond); }
    pthread_mutex_unlock(&wait->lock);
    return taken;
}
enum zapp_devkey_answer zapp_devkey_wait_end(struct zapp_devkey_wait *wait, unsigned long ticket, unsigned timeout_ms)
{
    struct timespec limit;
    clock_gettime(CLOCK_MONOTONIC, &limit);
    limit.tv_sec += timeout_ms / 1000u;
    limit.tv_nsec += (long)(timeout_ms % 1000u) * 1000000L;
    if (limit.tv_nsec >= 1000000000L) { limit.tv_sec++; limit.tv_nsec -= 1000000000L; }
    pthread_mutex_lock(&wait->lock);
    int rc = 0;
    while (wait->ticket == ticket && wait->answer == ZAPP_DEVKEY_ANSWER_NONE && rc == 0)
        rc = pthread_cond_clockwait(&wait->cond, &wait->lock, CLOCK_MONOTONIC, &limit);
    enum zapp_devkey_answer answer = wait->ticket == ticket ? wait->answer : ZAPP_DEVKEY_ANSWER_FAILED;
    if (answer == ZAPP_DEVKEY_ANSWER_NONE) answer = ZAPP_DEVKEY_ANSWER_TIMED_OUT;
    if (wait->ticket == ticket) wait->ticket = 0;
    pthread_mutex_unlock(&wait->lock);
    return answer;
}
bool zapp_devkey_wait_abandon(struct zapp_devkey_wait *wait)
{
    pthread_mutex_lock(&wait->lock);
    bool pending = wait->ticket && wait->answer == ZAPP_DEVKEY_ANSWER_NONE;
    if (pending) { wait->answer = ZAPP_DEVKEY_ANSWER_ABANDONED; pthread_cond_broadcast(&wait->cond); }
    pthread_mutex_unlock(&wait->lock);
    return pending;
}
