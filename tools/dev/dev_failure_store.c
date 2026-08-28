/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Persist workspace-scoped, SHA3-sealed compiler failure receipts. */

#define _GNU_SOURCE
#include "dev_failure_store.h"
#include "devloop.h"

#include "base/hex.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "platform/rng.h"
#include "platform/directory_transaction.h"
#include "platform/private_directory.h"
#include "platform/process_lock.h"
#include "platform/rename_compat.h"
#include "platform/time_compat.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define FAILURE_JSON_MAX 4096
#define LATEST_JSON_MAX 2048
#define OBSERVATION_JSON_MAX 1024

struct failure_dir {
#if defined(_WIN32)
    struct platform_directory_transaction value;
    char path[PATH_MAX];
#else
    int value;
#endif
};

struct failure_lock {
#if defined(_WIN32)
    struct platform_process_lock value;
#else
    int value;
#endif
};

struct failure_store {
    struct failure_dir workspace;
    struct failure_dir failures;
    char workspace_id[ZCL_DEV_FAILURE_HEX_LEN + 1];
};

struct failure_latest {
    char failure_id[ZCL_DEV_FAILURE_HEX_LEN + 1];
    char workspace_id[ZCL_DEV_FAILURE_HEX_LEN + 1];
    char source_id[ZCL_DEV_FAILURE_HEX_LEN + 1];
    char source_mutation[ZCL_DEV_FAILURE_HEX_LEN + 1];
    char execution_id[ZCL_DEV_FAILURE_HEX_LEN + 1];
    char phase[ZCL_DEV_FAILURE_PHASE_MAX];
    char digest[ZCL_DEV_FAILURE_HEX_LEN + 1];
};

struct failure_observation {
    char failure_id[ZCL_DEV_FAILURE_HEX_LEN + 1];
    char digest[ZCL_DEV_FAILURE_HEX_LEN + 1];
    uint64_t count;
    int64_t last_seen_unix_ms;
};

enum store_open_result {
    STORE_OPEN_INVALID = -1,
    STORE_OPEN_ABSENT = 0,
    STORE_OPEN_OK = 1
};

static void set_why(char *why, size_t why_len, const char *fmt, ...)
{
    if (!why || why_len == 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(why, why_len, fmt, ap);
    va_end(ap);
}

static bool valid_hex64(const char *value)
{
    if (!value || strlen(value) != ZCL_DEV_FAILURE_HEX_LEN)
        return false;
    for (size_t i = 0; i < ZCL_DEV_FAILURE_HEX_LEN; i++) {
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f')))
            return false;
    }
    return true;
}

static bool valid_phase(const char *phase)
{
    if (!phase || !phase[0] || strlen(phase) >= ZCL_DEV_FAILURE_PHASE_MAX)
        return false;
    return strspn(phase,
                  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                  "0123456789_.-") == strlen(phase);
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

static void digest_finish(struct sha3_256_ctx *ctx, char out[65])
{
    unsigned char digest[32];
    sha3_256_finalize(ctx, digest);
    zcl_hex_encode(digest, 32, out);
}

bool zcl_dev_failure_normalize_error(const char *input,
                                     char out[ZCL_DEV_FAILURE_ERROR_MAX])
{
    if (!input || !out)
        return false;
    size_t pos = 0;
    bool pending_space = false;
    const unsigned char *p = (const unsigned char *)input;
    while (*p && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n'))
        p++;
    for (; *p; p++) {
        unsigned char c = *p;
        if (c == '\r' || c == '\n')
            break;
        if (c == ' ' || c == '\t') {
            pending_space = pos > 0;
            continue;
        }
        if (c < 0x20 || c == 0x7f)
            continue;
        if (c >= 0x80)
            c = '?';
        if (pending_space) {
            if (pos + 1 >= ZCL_DEV_FAILURE_ERROR_MAX)
                return false;
            out[pos++] = ' ';
            pending_space = false;
        }
        if (pos + 1 >= ZCL_DEV_FAILURE_ERROR_MAX)
            return false;
        out[pos++] = (char)c;
    }
    out[pos] = 0;
    return pos > 0;
}

/* Failure capsules are diagnostic text, never an arbitrary byte transport.
 * Canonical printable ASCII keeps every sealed record and native JSON reply
 * valid while retaining a dense, bounded human-readable clue. */
static bool normalize_capsule(const char *input,
                              char out[ZCL_DEV_FAILURE_CAPSULE_MAX])
{
    if (!input || !out)
        return false;
    size_t pos = 0;
    bool pending_space = false;
    for (const unsigned char *p = (const unsigned char *)input; *p; p++) {
        unsigned char c = *p;
        if (c <= 0x20 || c == 0x7f) {
            pending_space = pos > 0;
            continue;
        }
        if (c >= 0x80)
            c = '?';
        if (pending_space) {
            if (pos + 1 >= ZCL_DEV_FAILURE_CAPSULE_MAX)
                return false;
            out[pos++] = ' ';
            pending_space = false;
        }
        if (pos + 1 >= ZCL_DEV_FAILURE_CAPSULE_MAX)
            return false;
        out[pos++] = (char)c;
    }
    out[pos] = 0;
    return true;
}

bool zcl_dev_failure_compute_id(
    const char source_id[ZCL_DEV_FAILURE_HEX_LEN + 1],
    const char *phase, const char *first_error,
    char out[ZCL_DEV_FAILURE_HEX_LEN + 1])
{
    char normalized[ZCL_DEV_FAILURE_ERROR_MAX];
    if (!valid_hex64(source_id) || !valid_phase(phase) ||
        !zcl_dev_failure_normalize_error(first_error, normalized))
        return false;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    hash_field(&ctx, "domain", "zcl.dev_failure_id.v1");
    hash_field(&ctx, "source_id_sha256", source_id);
    hash_field(&ctx, "phase", phase);
    hash_field(&ctx, "first_error", normalized);
    digest_finish(&ctx, out);
    return true;
}

static bool mkdirs(const char *path)
{
#if defined(_WIN32)
    return platform_private_directory_ensure(path);
#else
    char copy[PATH_MAX];
    if (!path || !path[0] || strlen(path) >= sizeof(copy))
        return false;
    (void)snprintf(copy, sizeof(copy), "%s", path);
    for (char *p = copy + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = 0;
        if (mkdir(copy, 0700) != 0 && errno != EEXIST)
            return false;
        *p = '/';
    }
    return mkdir(copy, 0700) == 0 || errno == EEXIST;
#endif
}

#if !defined(_WIN32)
static bool private_dir_fd(int fd)
{
    struct stat st;
    return fd >= 0 && fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) &&
           st.st_uid == geteuid() && (st.st_mode & 0077) == 0;
}
static bool private_regular_fd(int fd)
{
    struct stat st;
    return fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
           st.st_uid == geteuid() && st.st_nlink == 1 &&
           (st.st_mode & 0077) == 0;
}
#endif

static void store_close(struct failure_store *store)
{
    if (!store)
        return;
#if defined(_WIN32)
    platform_directory_transaction_close(&store->failures.value);
    platform_directory_transaction_close(&store->workspace.value);
#else
    if (store->failures.value >= 0) close(store->failures.value);
    if (store->workspace.value >= 0) close(store->workspace.value);
    store->failures.value = -1;
    store->workspace.value = -1;
#endif
}

static enum store_open_result store_open(const char *repo_root, bool create,
                                         struct failure_store *store,
                                         char *why, size_t why_len)
{
    memset(store, 0, sizeof(*store));
#if defined(_WIN32)
    platform_directory_transaction_init(&store->workspace.value);
    platform_directory_transaction_init(&store->failures.value);
#else
    store->workspace.value = -1;
    store->failures.value = -1;
#endif
    char path[PATH_MAX];
    if (!zcl_devloop_workspace_resolve(repo_root, store->workspace_id,
                                       path, sizeof(path))) {
        set_why(why, why_len, "failure_store_workspace_unavailable");
        return STORE_OPEN_INVALID;
    }
    if (create && !mkdirs(path)) {
        set_why(why, why_len, "failure_store_workspace_create_failed");
        return STORE_OPEN_INVALID;
    }
#if defined(_WIN32)
    if (strlen(path) >= sizeof(store->workspace.path))
        return STORE_OPEN_INVALID;
    (void)snprintf(store->workspace.path, sizeof(store->workspace.path), "%s", path);
    if (!platform_directory_transaction_open(&store->workspace.value, path)) {
        if (!create) return STORE_OPEN_ABSENT;
        set_why(why, why_len, "failure_store_workspace_not_private");
        return STORE_OPEN_INVALID;
    }
    enum platform_directory_result child = platform_directory_transaction_open_child(
        &store->workspace.value, "failures", create, &store->failures.value);
    if (child == PLATFORM_DIRECTORY_MISSING && !create) {
        store_close(store); return STORE_OPEN_ABSENT;
    }
    if (child != PLATFORM_DIRECTORY_OK) {
        set_why(why, why_len, "failure_store_failures_not_private");
        store_close(store); return STORE_OPEN_INVALID;
    }
    int pn = snprintf(store->failures.path, sizeof(store->failures.path),
                      "%s/failures", path);
    if (pn <= 0 || (size_t)pn >= sizeof(store->failures.path)) {
        store_close(store); return STORE_OPEN_INVALID;
    }
#else
    store->workspace.value = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                      O_NOFOLLOW);
    if (store->workspace.value < 0 && !create && errno == ENOENT)
        return STORE_OPEN_ABSENT;
    if (!private_dir_fd(store->workspace.value)) {
        set_why(why, why_len, "failure_store_workspace_not_private");
        store_close(store);
        return STORE_OPEN_INVALID;
    }
    if (create && mkdirat(store->workspace.value, "failures", 0700) != 0 &&
        errno != EEXIST) {
        set_why(why, why_len, "failure_store_failures_create_failed");
        store_close(store);
        return STORE_OPEN_INVALID;
    }
    store->failures.value = openat(store->workspace.value, "failures",
                                O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                    O_NOFOLLOW);
    if (store->failures.value < 0 && !create && errno == ENOENT) {
        store_close(store);
        return STORE_OPEN_ABSENT;
    }
    if (!private_dir_fd(store->failures.value)) {
        set_why(why, why_len, "failure_store_failures_not_private");
        store_close(store);
        return STORE_OPEN_INVALID;
    }
#endif
    return STORE_OPEN_OK;
}

static bool store_lock(const struct failure_store *store, bool exclusive,
                       bool create, struct failure_lock *lock,
                       char *why, size_t why_len)
{
#if defined(_WIN32)
    (void)exclusive;
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/failure-store.lock",
                     store->workspace.path);
    platform_process_lock_init(&lock->value);
    if (n <= 0 || (size_t)n >= sizeof(path) ||
        !platform_process_lock_try_acquire(&lock->value, path, create)) {
        set_why(why, why_len, "failure_store_lock_failed");
        return false;
    }
    return true;
#else
    int flags = O_RDWR | O_CLOEXEC | O_NOFOLLOW;
    if (create)
        flags |= O_CREAT;
    int fd = openat(store->workspace.value, "failure-store.lock",
                    flags, 0600);
    if (!private_regular_fd(fd) ||
        flock(fd, exclusive ? LOCK_EX : LOCK_SH) != 0) {
        set_why(why, why_len, "failure_store_lock_failed");
        if (fd >= 0)
            close(fd);
        return false;
    }
    lock->value = fd;
    return true;
#endif
}

static void store_unlock(struct failure_lock *lock)
{
#if defined(_WIN32)
    platform_process_lock_release(&lock->value);
#else
    if (lock->value >= 0) close(lock->value);
#endif
}

#if !defined(_WIN32)
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
#endif

static bool write_new_file_at(struct failure_dir *dir, const char *name,
                              const char *body, size_t len)
{
#if defined(_WIN32)
    struct platform_directory_child file;
    platform_directory_child_init(&file);
    bool created = platform_directory_child_create(&dir->value, name, &file);
    bool ok = created && platform_directory_child_write_exact(
                  &file, body, len, 0) &&
              platform_directory_child_flush(&file) &&
              platform_directory_transaction_flush(&dir->value);
    platform_directory_child_close(&file);
    if (created && !ok)
        (void)platform_directory_child_unlink(&dir->value, name, true);
    return ok;
#else
    int dirfd = dir->value;
    int fd = openat(dirfd, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC |
                                     O_NOFOLLOW, 0600);
    if (fd < 0)
        return false;
    bool ok = private_regular_fd(fd) && write_all(fd, body, len) &&
              fsync(fd) == 0;
    if (close(fd) != 0)
        ok = false;
    fd = -1;
    if (!ok) {
        (void)unlinkat(dirfd, name, 0);
    }
    return ok;
#endif
}

static bool unique_temp_name(const char *kind, char out[96])
{
    unsigned char random[16];
    if (!rng_fill(random, sizeof(random)))
        return false;
    char suffix[sizeof(random) * 2 + 1];
    zcl_hex_encode(random, sizeof(random), suffix);
    int n = snprintf(out, 96, ".%s.%s.tmp", kind, suffix);
    return n > 0 && n < 96;
}

static bool atomic_replace_at(struct failure_dir *dir, const char *final_name,
                              const char *kind, const char *body, size_t len)
{
#if defined(_WIN32)
    char temp[96] = {0};
    struct platform_directory_child file;
    platform_directory_child_init(&file);
    bool created = false;
    for (unsigned attempt = 0; attempt < 8 && !created; attempt++) {
        if (!unique_temp_name(kind, temp)) return false;
        created = platform_directory_child_create(&dir->value, temp, &file);
    }
    bool ok = created && platform_directory_child_write_exact(
                  &file, body, len, 0) &&
              platform_directory_child_flush(&file) &&
              platform_directory_child_replace(&dir->value, &file,
                                               final_name, false) &&
              platform_directory_transaction_flush(&dir->value);
    platform_directory_child_close(&file);
    if (created && !ok)
        (void)platform_directory_child_unlink(&dir->value, temp, true);
    return ok;
#else
    int dirfd = dir->value;
    char temp[96] = {0};
    int fd = -1;
    for (unsigned attempt = 0; attempt < 8; attempt++) {
        if (!unique_temp_name(kind, temp))
            return false;
        fd = openat(dirfd, temp,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    0600);
        if (fd >= 0 || errno != EEXIST)
            break;
    }
    if (fd < 0)
        return false;
    bool ok = private_regular_fd(fd) && write_all(fd, body, len) &&
              fsync(fd) == 0;
    if (close(fd) != 0)
        ok = false;
    if (ok)
        ok = renameat(dirfd, temp, dirfd, final_name) == 0 &&
             fsync(dirfd) == 0;
    if (!ok)
        (void)unlinkat(dirfd, temp, 0);
    return ok;
#endif
}

static enum zcl_dev_failure_lookup read_file_at(struct failure_dir *dir,
                                                const char *name,
                                                char *body, size_t cap,
                                                size_t *len_out)
{
#if defined(_WIN32)
    struct platform_directory_child file;
    struct platform_directory_child_info before, after;
    platform_directory_child_init(&file);
    enum platform_directory_result opened = platform_directory_child_open_result(
        &dir->value, name, false, false, &file, NULL);
    if (opened == PLATFORM_DIRECTORY_MISSING)
        return ZCL_DEV_FAILURE_LOOKUP_ABSENT;
    bool ok = opened == PLATFORM_DIRECTORY_OK &&
        platform_directory_child_info(&file, &before) && before.size > 0 &&
        before.size < cap && before.current_user_only && before.link_count == 1;
    if (ok) ok = platform_directory_child_read_exact(
        &file, body, (size_t)before.size, 0) &&
        platform_directory_child_info(&file, &after) &&
        before.volume == after.volume && before.file_low == after.file_low &&
        before.file_high == after.file_high && before.size == after.size &&
        before.modified_seconds == after.modified_seconds &&
        before.modified_nanoseconds == after.modified_nanoseconds &&
        before.changed_seconds == after.changed_seconds &&
        before.changed_nanoseconds == after.changed_nanoseconds;
    platform_directory_child_close(&file);
    if (!ok) return ZCL_DEV_FAILURE_LOOKUP_INVALID;
    body[before.size] = 0; *len_out = (size_t)before.size;
    return ZCL_DEV_FAILURE_LOOKUP_FOUND;
#else
    int dirfd = dir->value;
    int fd = openat(dirfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 && errno == ENOENT)
        return ZCL_DEV_FAILURE_LOOKUP_ABSENT;
    if (!private_regular_fd(fd)) {
        if (fd >= 0)
            close(fd);
        return ZCL_DEV_FAILURE_LOOKUP_INVALID;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0 ||
        (uint64_t)st.st_size >= cap) {
        close(fd);
        return ZCL_DEV_FAILURE_LOOKUP_INVALID;
    }
    size_t need = (size_t)st.st_size;
    size_t off = 0;
    while (off < need) {
        ssize_t n = pread(fd, body + off, need - off, (off_t)off);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            close(fd);
            return ZCL_DEV_FAILURE_LOOKUP_INVALID;
        }
        off += (size_t)n;
    }
    close(fd);
    body[off] = 0;
    *len_out = off;
    return ZCL_DEV_FAILURE_LOOKUP_FOUND;
#endif
}

static void record_digest(const struct zcl_dev_failure_record *record,
                          char out[65])
{
    char seen[32];
    (void)snprintf(seen, sizeof(seen), "%lld",
                   (long long)record->first_seen_unix_ms);
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    hash_field(&ctx, "domain", "zcl.dev_failure_record.v1");
    hash_field(&ctx, "failure_id", record->failure_id);
    hash_field(&ctx, "workspace_id", record->workspace_id);
    hash_field(&ctx, "source_id_sha256", record->source_id);
    hash_field(&ctx, "first_source_mutation_sha256",
               record->first_source_mutation);
    hash_field(&ctx, "first_execution_id_sha3",
               record->first_execution_id);
    hash_field(&ctx, "phase", record->phase);
    hash_field(&ctx, "first_error", record->first_error);
    hash_field(&ctx, "failure_capsule", record->capsule);
    hash_field(&ctx, "retry_command", record->retry_command);
    hash_field(&ctx, "first_seen_unix_ms", seen);
    digest_finish(&ctx, out);
}

static bool record_json(const struct zcl_dev_failure_record *record,
                        char body[FAILURE_JSON_MAX], size_t *len_out)
{
    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);
    bool ok = json_push_kv_str(&doc, "schema",
                               "zcl.dev_failure_record.v1") &&
              json_push_kv_str(&doc, "failure_id", record->failure_id) &&
              json_push_kv_str(&doc, "workspace_id", record->workspace_id) &&
              json_push_kv_str(&doc, "source_id_sha256", record->source_id) &&
              json_push_kv_str(&doc, "first_source_mutation_sha256",
                               record->first_source_mutation) &&
              json_push_kv_str(&doc, "first_execution_id_sha3",
                               record->first_execution_id) &&
              json_push_kv_str(&doc, "phase", record->phase) &&
              json_push_kv_str(&doc, "first_error", record->first_error) &&
              json_push_kv_str(&doc, "failure_capsule", record->capsule) &&
              json_push_kv_str(&doc, "retry_command",
                               record->retry_command) &&
              json_push_kv_int(&doc, "first_seen_unix_ms",
                               record->first_seen_unix_ms) &&
              json_push_kv_str(&doc, "record_sha3", record->record_digest);
    size_t len = ok ? json_write(&doc, body, FAILURE_JSON_MAX - 2) : 0;
    json_free(&doc);
    if (!ok || len == 0 || len >= FAILURE_JSON_MAX - 2)
        return false;
    body[len++] = '\n';
    body[len] = 0;
    *len_out = len;
    return true;
}

static const char *required_string(const struct json_value *doc,
                                   const char *key)
{
    const struct json_value *value = json_get(doc, key);
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static bool copy_string(char *out, size_t cap, const char *value)
{
    if (!out || cap == 0 || !value || strlen(value) >= cap)
        return false;
    (void)snprintf(out, cap, "%s", value);
    return true;
}

static void observation_digest(const struct failure_observation *observation,
                               char out[65])
{
    char count[32], seen[32];
    (void)snprintf(count, sizeof(count), "%llu",
                   (unsigned long long)observation->count);
    (void)snprintf(seen, sizeof(seen), "%lld",
                   (long long)observation->last_seen_unix_ms);
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    hash_field(&ctx, "domain", "zcl.dev_failure_observations.v1");
    hash_field(&ctx, "failure_id", observation->failure_id);
    hash_field(&ctx, "count", count);
    hash_field(&ctx, "last_seen_unix_ms", seen);
    digest_finish(&ctx, out);
}

static bool observation_json(const struct failure_observation *observation,
                             char body[OBSERVATION_JSON_MAX], size_t *len_out)
{
    if (!observation || observation->count == 0 ||
        observation->count > INT64_MAX || observation->last_seen_unix_ms < 0)
        return false;
    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);
    bool ok = json_push_kv_str(&doc, "schema",
                               "zcl.dev_failure_observations.v1") &&
              json_push_kv_str(&doc, "failure_id",
                               observation->failure_id) &&
              json_push_kv_int(&doc, "count", (int64_t)observation->count) &&
              json_push_kv_int(&doc, "last_seen_unix_ms",
                               observation->last_seen_unix_ms) &&
              json_push_kv_str(&doc, "observations_sha3",
                               observation->digest);
    size_t len = ok ? json_write(&doc, body, OBSERVATION_JSON_MAX - 2) : 0;
    json_free(&doc);
    if (!ok || len == 0 || len >= OBSERVATION_JSON_MAX - 2)
        return false;
    body[len++] = '\n';
    body[len] = 0;
    *len_out = len;
    return true;
}

static bool observation_read(struct failure_dir *failure,
                             const char *failure_id,
                             struct failure_observation *out)
{
    char body[OBSERVATION_JSON_MAX];
    size_t len = 0;
    if (read_file_at(failure, "observations.json", body, sizeof(body),
                     &len) != ZCL_DEV_FAILURE_LOOKUP_FOUND)
        return false;
    struct json_value doc;
    json_init(&doc);
    if (!json_read(&doc, body, len) || doc.type != JSON_OBJ ||
        doc.num_children != 5) {
        json_free(&doc);
        return false;
    }
    const char *schema = required_string(&doc, "schema");
    const char *id = required_string(&doc, "failure_id");
    const char *digest = required_string(&doc, "observations_sha3");
    const struct json_value *count = json_get(&doc, "count");
    const struct json_value *seen = json_get(&doc, "last_seen_unix_ms");
    memset(out, 0, sizeof(*out));
    bool ok = schema &&
              strcmp(schema, "zcl.dev_failure_observations.v1") == 0 &&
              id && strcmp(id, failure_id) == 0 && valid_hex64(id) &&
              valid_hex64(digest) && count && count->type == JSON_INT &&
              json_get_int(count) > 0 && seen && seen->type == JSON_INT &&
              json_get_int(seen) >= 0 &&
              copy_string(out->failure_id, sizeof(out->failure_id), id) &&
              copy_string(out->digest, sizeof(out->digest), digest);
    if (ok) {
        out->count = (uint64_t)json_get_int(count);
        out->last_seen_unix_ms = json_get_int(seen);
    }
    json_free(&doc);
    char recomputed[65];
    if (!ok)
        return false;
    observation_digest(out, recomputed);
    return strcmp(recomputed, out->digest) == 0;
}

static bool observation_publish(struct failure_dir *failure,
                                struct failure_observation *observation)
{
    observation_digest(observation, observation->digest);
    char body[OBSERVATION_JSON_MAX];
    size_t len = 0;
    return observation_json(observation, body, &len) &&
           atomic_replace_at(failure, "observations.json", "observations",
                             body, len);
}

static bool observation_increment(struct failure_dir *failure,
                                  const char *failure_id,
                                  uint64_t *count_out)
{
    struct failure_observation observation;
    if (!observation_read(failure, failure_id, &observation) ||
        observation.count >= INT64_MAX)
        return false;
    observation.count++;
    observation.last_seen_unix_ms = platform_time_realtime_us() / 1000;
    if (observation.last_seen_unix_ms < 0)
        observation.last_seen_unix_ms = 0;
    if (!observation_publish(failure, &observation))
        return false;
    *count_out = observation.count;
    return true;
}

static bool read_record_fd(struct failure_dir *failure,
                           const char *expected_id,
                           const char *expected_workspace,
                           struct zcl_dev_failure_record *out)
{
    char body[FAILURE_JSON_MAX];
    size_t len = 0;
    if (read_file_at(failure, "base.json", body, sizeof(body), &len) !=
        ZCL_DEV_FAILURE_LOOKUP_FOUND)
        return false;
    struct json_value doc;
    json_init(&doc);
    if (!json_read(&doc, body, len) || doc.type != JSON_OBJ) {
        json_free(&doc);
        return false;
    }
    memset(out, 0, sizeof(*out));
    const char *schema = required_string(&doc, "schema");
    const char *id = required_string(&doc, "failure_id");
    const char *workspace = required_string(&doc, "workspace_id");
    const char *source = required_string(&doc, "source_id_sha256");
    const char *mutation =
        required_string(&doc, "first_source_mutation_sha256");
    const char *execution = required_string(&doc, "first_execution_id_sha3");
    const char *phase = required_string(&doc, "phase");
    const char *first = required_string(&doc, "first_error");
    const char *capsule = required_string(&doc, "failure_capsule");
    const char *retry = required_string(&doc, "retry_command");
    const char *digest = required_string(&doc, "record_sha3");
    const struct json_value *seen = json_get(&doc, "first_seen_unix_ms");
    bool ok = doc.num_children == 12 && schema &&
              strcmp(schema, "zcl.dev_failure_record.v1") == 0 &&
              valid_hex64(id) && valid_hex64(workspace) &&
              valid_hex64(source) && valid_hex64(mutation) &&
              valid_hex64(execution) && valid_hex64(digest) &&
              valid_phase(phase) && first && capsule && retry &&
              seen && seen->type == JSON_INT && json_get_int(seen) >= 0 &&
              strcmp(id, expected_id) == 0 &&
              strcmp(workspace, expected_workspace) == 0 &&
              copy_string(out->failure_id, sizeof(out->failure_id), id) &&
              copy_string(out->workspace_id, sizeof(out->workspace_id),
                          workspace) &&
              copy_string(out->source_id, sizeof(out->source_id), source) &&
              copy_string(out->first_source_mutation,
                          sizeof(out->first_source_mutation), mutation) &&
              copy_string(out->first_execution_id,
                          sizeof(out->first_execution_id), execution) &&
              copy_string(out->phase, sizeof(out->phase), phase) &&
              copy_string(out->first_error, sizeof(out->first_error), first) &&
              copy_string(out->capsule, sizeof(out->capsule), capsule) &&
              copy_string(out->retry_command, sizeof(out->retry_command),
                          retry) &&
              copy_string(out->record_digest, sizeof(out->record_digest),
                          digest);
    if (ok)
        out->first_seen_unix_ms = json_get_int(seen);
    json_free(&doc);
    char recomputed_id[65], recomputed_record[65];
    char normalized_first[ZCL_DEV_FAILURE_ERROR_MAX];
    char normalized_capsule[ZCL_DEV_FAILURE_CAPSULE_MAX];
    if (!ok || strcmp(out->retry_command, "dev.ff") != 0 ||
        !zcl_dev_failure_normalize_error(out->first_error,
                                         normalized_first) ||
        strcmp(normalized_first, out->first_error) != 0 ||
        !normalize_capsule(out->capsule, normalized_capsule) ||
        strcmp(normalized_capsule, out->capsule) != 0 ||
        !zcl_dev_failure_compute_id(out->source_id, out->phase,
                                            out->first_error,
                                            recomputed_id) ||
        strcmp(recomputed_id, out->failure_id) != 0)
        return false;
    record_digest(out, recomputed_record);
    struct failure_observation observation;
    if (strcmp(recomputed_record, out->record_digest) != 0 ||
        !observation_read(failure, out->failure_id, &observation))
        return false;
    out->repeat_count = observation.count;
    return true;
}

static enum zcl_dev_failure_lookup record_read_store(
    const struct failure_store *store, const char *failure_id,
    struct zcl_dev_failure_record *out)
{
    if (!valid_hex64(failure_id))
        return ZCL_DEV_FAILURE_LOOKUP_INVALID;
#if defined(_WIN32)
    struct failure_dir failure;
    platform_directory_transaction_init(&failure.value);
    enum platform_directory_result opened = platform_directory_transaction_open_child(
        (struct platform_directory_transaction *)&store->failures.value,
        failure_id, false, &failure.value);
    if (opened == PLATFORM_DIRECTORY_MISSING)
        return ZCL_DEV_FAILURE_LOOKUP_ABSENT;
    if (opened != PLATFORM_DIRECTORY_OK)
        return ZCL_DEV_FAILURE_LOOKUP_INVALID;
    bool ok = read_record_fd(&failure, failure_id, store->workspace_id, out);
    platform_directory_transaction_close(&failure.value);
#else
    int fd = openat(store->failures.value, failure_id,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 && errno == ENOENT)
        return ZCL_DEV_FAILURE_LOOKUP_ABSENT;
    if (!private_dir_fd(fd)) {
        if (fd >= 0)
            close(fd);
        return ZCL_DEV_FAILURE_LOOKUP_INVALID;
    }
    struct failure_dir failure = {.value = fd};
    bool ok = read_record_fd(&failure, failure_id, store->workspace_id, out);
    close(fd);
#endif
    return ok ? ZCL_DEV_FAILURE_LOOKUP_FOUND
              : ZCL_DEV_FAILURE_LOOKUP_INVALID;
}

static void latest_digest(const struct failure_latest *latest, char out[65])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    hash_field(&ctx, "domain", "zcl.dev_failure_latest.v1");
    hash_field(&ctx, "failure_id", latest->failure_id);
    hash_field(&ctx, "workspace_id", latest->workspace_id);
    hash_field(&ctx, "source_id_sha256", latest->source_id);
    hash_field(&ctx, "source_mutation_sha256", latest->source_mutation);
    hash_field(&ctx, "execution_id_sha3", latest->execution_id);
    hash_field(&ctx, "phase", latest->phase);
    digest_finish(&ctx, out);
}

static bool latest_json(const struct failure_latest *latest,
                        char body[LATEST_JSON_MAX], size_t *len_out)
{
    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);
    bool ok = json_push_kv_str(&doc, "schema", "zcl.dev_failure_latest.v1") &&
              json_push_kv_str(&doc, "failure_id", latest->failure_id) &&
              json_push_kv_str(&doc, "workspace_id", latest->workspace_id) &&
              json_push_kv_str(&doc, "source_id_sha256", latest->source_id) &&
              json_push_kv_str(&doc, "source_mutation_sha256",
                               latest->source_mutation) &&
              json_push_kv_str(&doc, "execution_id_sha3",
                               latest->execution_id) &&
              json_push_kv_str(&doc, "phase", latest->phase) &&
              json_push_kv_str(&doc, "latest_sha3", latest->digest);
    size_t len = ok ? json_write(&doc, body, LATEST_JSON_MAX - 2) : 0;
    json_free(&doc);
    if (!ok || len == 0 || len >= LATEST_JSON_MAX - 2)
        return false;
    body[len++] = '\n';
    body[len] = 0;
    *len_out = len;
    return true;
}

static bool latest_publish(const struct failure_store *store,
                           const struct failure_latest *latest)
{
    char body[LATEST_JSON_MAX];
    size_t len = 0;
    if (!latest_json(latest, body, &len))
        return false;
    return atomic_replace_at((struct failure_dir *)&store->workspace,
                             "latest-failure.json",
                             "latest", body, len);
}

static enum zcl_dev_failure_lookup latest_read(
    const struct failure_store *store, struct failure_latest *latest)
{
    char body[LATEST_JSON_MAX];
    size_t len = 0;
    enum zcl_dev_failure_lookup read =
        read_file_at((struct failure_dir *)&store->workspace,
                     "latest-failure.json", body,
                     sizeof(body), &len);
    if (read != ZCL_DEV_FAILURE_LOOKUP_FOUND)
        return read;
    struct json_value doc;
    json_init(&doc);
    if (!json_read(&doc, body, len) || doc.type != JSON_OBJ) {
        json_free(&doc);
        return ZCL_DEV_FAILURE_LOOKUP_INVALID;
    }
    memset(latest, 0, sizeof(*latest));
    const char *schema = required_string(&doc, "schema");
    const char *id = required_string(&doc, "failure_id");
    const char *workspace = required_string(&doc, "workspace_id");
    const char *source = required_string(&doc, "source_id_sha256");
    const char *mutation = required_string(&doc, "source_mutation_sha256");
    const char *execution = required_string(&doc, "execution_id_sha3");
    const char *phase = required_string(&doc, "phase");
    const char *digest = required_string(&doc, "latest_sha3");
    bool ok = doc.num_children == 8 && schema &&
              strcmp(schema, "zcl.dev_failure_latest.v1") == 0 &&
              valid_hex64(id) && valid_hex64(workspace) &&
              valid_hex64(source) && valid_hex64(mutation) &&
              valid_hex64(execution) && valid_hex64(digest) &&
              valid_phase(phase) &&
              strcmp(workspace, store->workspace_id) == 0 &&
              copy_string(latest->failure_id, sizeof(latest->failure_id), id) &&
              copy_string(latest->workspace_id, sizeof(latest->workspace_id),
                          workspace) &&
              copy_string(latest->source_id, sizeof(latest->source_id),
                          source) &&
              copy_string(latest->source_mutation,
                          sizeof(latest->source_mutation), mutation) &&
              copy_string(latest->execution_id,
                          sizeof(latest->execution_id), execution) &&
              copy_string(latest->phase, sizeof(latest->phase), phase) &&
              copy_string(latest->digest, sizeof(latest->digest), digest);
    json_free(&doc);
    char recomputed[65];
    if (!ok)
        return ZCL_DEV_FAILURE_LOOKUP_INVALID;
    latest_digest(latest, recomputed);
    return strcmp(recomputed, latest->digest) == 0
               ? ZCL_DEV_FAILURE_LOOKUP_FOUND
               : ZCL_DEV_FAILURE_LOOKUP_INVALID;
}

bool zcl_dev_failure_record_failure(
    const char *repo_root,
    const char source_id[ZCL_DEV_FAILURE_HEX_LEN + 1],
    const char source_mutation[ZCL_DEV_FAILURE_HEX_LEN + 1],
    const char execution_id[ZCL_DEV_FAILURE_HEX_LEN + 1],
    const char *phase, const char *first_error, const char *capsule,
    const char *retry_command, struct zcl_dev_failure_record *out,
    char *why, size_t why_len)
{
    if (why && why_len)
        why[0] = 0;
    char normalized[ZCL_DEV_FAILURE_ERROR_MAX];
    char normalized_capsule[ZCL_DEV_FAILURE_CAPSULE_MAX], id[65];
    if (!valid_hex64(source_id) || !valid_hex64(source_mutation) ||
        !valid_hex64(execution_id) || !valid_phase(phase) || !capsule ||
        strlen(capsule) >= ZCL_DEV_FAILURE_CAPSULE_MAX || !retry_command ||
        strcmp(retry_command, "dev.ff") != 0 ||
        !zcl_dev_failure_normalize_error(first_error, normalized) ||
        !normalize_capsule(capsule, normalized_capsule) ||
        !zcl_dev_failure_compute_id(source_id, phase, normalized, id)) {
        set_why(why, why_len, "failure_record_input_invalid");
        return false;
    }
    struct failure_store store;
    if (store_open(repo_root, true, &store, why, why_len) != STORE_OPEN_OK)
        return false;
    struct failure_lock lock;
    if (!store_lock(&store, true, true, &lock, why, why_len)) {
        store_close(&store);
        return false;
    }
#if defined(_WIN32)
    struct failure_dir failure;
    platform_directory_transaction_init(&failure.value);
    enum platform_directory_result failure_open =
        platform_directory_transaction_open_child(&store.failures.value, id,
                                                  false, &failure.value);
    if (failure_open != PLATFORM_DIRECTORY_OK &&
        failure_open != PLATFORM_DIRECTORY_MISSING) {
        set_why(why, why_len, "failure_record_directory_invalid");
        store_unlock(&lock); store_close(&store); return false;
    }
    bool failure_present = failure_open == PLATFORM_DIRECTORY_OK;
#else
    int failure_fd = openat(store.failures.value, id,
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (failure_fd < 0 && errno != ENOENT) {
        set_why(why, why_len, "failure_record_directory_invalid");
        store_unlock(&lock);
        store_close(&store);
        return false;
    }
#endif
    bool created = false;
    struct zcl_dev_failure_record record, candidate;
    memset(&candidate, 0, sizeof(candidate));
    (void)snprintf(candidate.failure_id, sizeof(candidate.failure_id), "%s",
                   id);
    (void)snprintf(candidate.workspace_id, sizeof(candidate.workspace_id), "%s",
                   store.workspace_id);
    (void)snprintf(candidate.source_id, sizeof(candidate.source_id), "%s",
                   source_id);
    (void)snprintf(candidate.first_source_mutation,
                   sizeof(candidate.first_source_mutation), "%s",
                   source_mutation);
    (void)snprintf(candidate.first_execution_id,
                   sizeof(candidate.first_execution_id), "%s", execution_id);
    (void)snprintf(candidate.phase, sizeof(candidate.phase), "%s", phase);
    (void)snprintf(candidate.first_error, sizeof(candidate.first_error), "%s",
                   normalized);
    (void)snprintf(candidate.capsule, sizeof(candidate.capsule), "%s",
                   normalized_capsule);
    (void)snprintf(candidate.retry_command, sizeof(candidate.retry_command),
                   "%s", retry_command);
    candidate.first_seen_unix_ms = platform_time_realtime_us() / 1000;
    if (candidate.first_seen_unix_ms < 0)
        candidate.first_seen_unix_ms = 0;
    candidate.repeat_count = 1;
    record_digest(&candidate, candidate.record_digest);

    bool ok = true;
#if defined(_WIN32)
    if (!failure_present) {
        char stage[96] = {0};
        struct failure_dir staged;
        platform_directory_transaction_init(&staged.value);
        bool staged_open = false;
        for (unsigned attempt = 0; attempt < 8 && !staged_open; attempt++) {
            if (!unique_temp_name("failure", stage)) { ok = false; break; }
            staged_open = platform_directory_transaction_open_child(
                &store.failures.value, stage, true, &staged.value) ==
                PLATFORM_DIRECTORY_OK;
        }
        char body[FAILURE_JSON_MAX], observation_body[OBSERVATION_JSON_MAX];
        size_t len = 0, observation_len = 0;
        struct failure_observation observation = {0};
        (void)snprintf(observation.failure_id,
                       sizeof(observation.failure_id), "%s", id);
        observation.count = 1;
        observation.last_seen_unix_ms = candidate.first_seen_unix_ms;
        observation_digest(&observation, observation.digest);
        ok = ok && staged_open && record_json(&candidate, body, &len) &&
            observation_json(&observation, observation_body,
                             &observation_len) &&
            write_new_file_at(&staged, "base.json", body, len) &&
            write_new_file_at(&staged, "observations.json", observation_body,
                              observation_len) &&
            platform_directory_transaction_flush(&staged.value);
        platform_directory_transaction_close(&staged.value);
        char stage_path[PATH_MAX], final_path[PATH_MAX];
        int sn = snprintf(stage_path, sizeof(stage_path), "%s/%s",
                          store.failures.path, stage);
        int fn = snprintf(final_path, sizeof(final_path), "%s/%s",
                          store.failures.path, id);
        if (ok && sn > 0 && (size_t)sn < sizeof(stage_path) && fn > 0 &&
            (size_t)fn < sizeof(final_path) &&
            platform_private_directory_publish_no_clobber(stage_path,
                                                           final_path)) {
            created = true;
        }
        failure_open = platform_directory_transaction_open_child(
            &store.failures.value, id, false, &failure.value);
        failure_present = failure_open == PLATFORM_DIRECTORY_OK;
        if (!created && stage[0]) {
            struct failure_dir cleanup;
            platform_directory_transaction_init(&cleanup.value);
            if (platform_directory_transaction_open(&cleanup.value, stage_path)) {
                (void)platform_directory_child_unlink(&cleanup.value,
                                                       "observations.json", true);
                (void)platform_directory_child_unlink(&cleanup.value,
                                                       "base.json", true);
                platform_directory_transaction_close(&cleanup.value);
                (void)platform_private_directory_remove_empty(stage_path);
            }
        }
        ok = ok && failure_present;
    }
#else
    if (failure_fd < 0) {
        char stage[96] = {0};
        int stage_fd = -1;
        for (unsigned attempt = 0; attempt < 8; attempt++) {
            if (!unique_temp_name("failure", stage)) {
                ok = false;
                break;
            }
            if (mkdirat(store.failures.value, stage, 0700) == 0) {
                stage_fd = openat(store.failures.value, stage,
                                  O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                      O_NOFOLLOW);
                break;
            }
            if (errno != EEXIST) {
                ok = false;
                break;
            }
        }
        if (stage_fd < 0 || !private_dir_fd(stage_fd))
            ok = false;
        char body[FAILURE_JSON_MAX], observation_body[OBSERVATION_JSON_MAX];
        size_t len = 0, observation_len = 0;
        struct failure_observation observation = {0};
        (void)snprintf(observation.failure_id,
                       sizeof(observation.failure_id), "%s", id);
        observation.count = 1;
        observation.last_seen_unix_ms = candidate.first_seen_unix_ms;
        observation_digest(&observation, observation.digest);
        if (ok)
            ok = record_json(&candidate, body, &len) &&
                 observation_json(&observation, observation_body,
                                  &observation_len) &&
                 write_new_file_at(&(struct failure_dir){.value = stage_fd},
                                   "base.json", body, len) &&
                 write_new_file_at(&(struct failure_dir){.value = stage_fd},
                                   "observations.json",
                                   observation_body, observation_len) &&
                 fsync(stage_fd) == 0;
        if (ok) {
            if (platform_renameat_noreplace(store.failures.value, stage,
                                            store.failures.value, id) == 0) {
                created = true;
                failure_fd = stage_fd;
                stage_fd = -1;
                stage[0] = 0;
                ok = fsync(store.failures.value) == 0;
            } else if (errno == EEXIST) {
                ok = true;
            } else {
                ok = false;
            }
        }
        if (stage_fd >= 0) {
            (void)unlinkat(stage_fd, "observations.json", 0);
            (void)unlinkat(stage_fd, "base.json", 0);
            close(stage_fd);
        }
        if (stage[0]) {
            (void)unlinkat(store.failures.value, stage, AT_REMOVEDIR);
            (void)fsync(store.failures.value);
        }
        if (ok && !created)
            failure_fd = openat(store.failures.value, id,
                                O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                    O_NOFOLLOW);
    }
    struct failure_dir failure = {.value = failure_fd};
#endif
    if (!ok ||
#if defined(_WIN32)
        !failure_present
#else
        !private_dir_fd(failure_fd)
#endif
    ) {
        set_why(why, why_len, "failure_record_directory_publication_failed");
#if defined(_WIN32)
        platform_directory_transaction_close(&failure.value);
#else
        if (failure_fd >= 0) close(failure_fd);
#endif
        store_unlock(&lock);
        store_close(&store);
        return false;
    }
    if (created) {
        record = candidate;
    } else {
        ok = read_record_fd(&failure, id, store.workspace_id, &record) &&
             strcmp(record.source_id, source_id) == 0 &&
             strcmp(record.phase, phase) == 0 &&
             strcmp(record.first_error, normalized) == 0 &&
             observation_increment(&failure, id, &record.repeat_count);
    }
    struct failure_latest latest = {0};
    if (ok) {
        (void)snprintf(latest.failure_id, sizeof(latest.failure_id), "%s", id);
        (void)snprintf(latest.workspace_id, sizeof(latest.workspace_id), "%s",
                       store.workspace_id);
        (void)snprintf(latest.source_id, sizeof(latest.source_id), "%s",
                       source_id);
        (void)snprintf(latest.source_mutation,
                       sizeof(latest.source_mutation), "%s", source_mutation);
        (void)snprintf(latest.execution_id, sizeof(latest.execution_id), "%s",
                       execution_id);
        (void)snprintf(latest.phase, sizeof(latest.phase), "%s", phase);
        latest_digest(&latest, latest.digest);
        ok = latest_publish(&store, &latest);
    }
    if (!ok)
        set_why(why, why_len, "failure_record_publication_failed");
    if (ok && out)
        *out = record;
#if defined(_WIN32)
    platform_directory_transaction_close(&failure.value);
#else
    if (failure_fd >= 0) close(failure_fd);
#endif
    store_unlock(&lock);
    store_close(&store);
    return ok;
}

enum zcl_dev_failure_lookup zcl_dev_failure_read(
    const char *repo_root,
    const char failure_id[ZCL_DEV_FAILURE_HEX_LEN + 1],
    struct zcl_dev_failure_record *out, char *why, size_t why_len)
{
    if (why && why_len)
        why[0] = 0;
    if (!out || !valid_hex64(failure_id)) {
        set_why(why, why_len, "failure_id_invalid");
        return ZCL_DEV_FAILURE_LOOKUP_INVALID;
    }
    struct failure_store store;
    enum store_open_result opened =
        store_open(repo_root, false, &store, why, why_len);
    if (opened == STORE_OPEN_ABSENT) {
        set_why(why, why_len, "failure_record_absent");
        return ZCL_DEV_FAILURE_LOOKUP_ABSENT;
    }
    if (opened != STORE_OPEN_OK)
        return ZCL_DEV_FAILURE_LOOKUP_INVALID;
    struct failure_lock lock;
    if (!store_lock(&store, false, false, &lock, why, why_len)) {
        store_close(&store);
        return ZCL_DEV_FAILURE_LOOKUP_INVALID;
    }
    enum zcl_dev_failure_lookup result =
        record_read_store(&store, failure_id, out);
    if (result == ZCL_DEV_FAILURE_LOOKUP_ABSENT)
        set_why(why, why_len, "failure_record_absent");
    else if (result == ZCL_DEV_FAILURE_LOOKUP_INVALID)
        set_why(why, why_len, "failure_record_invalid");
    store_unlock(&lock);
    store_close(&store);
    return result;
}

enum zcl_dev_failure_lookup zcl_dev_failure_read_latest(
    const char *repo_root, struct zcl_dev_failure_record *out,
    char *why, size_t why_len)
{
    if (why && why_len)
        why[0] = 0;
    if (!out) {
        set_why(why, why_len, "failure_output_missing");
        return ZCL_DEV_FAILURE_LOOKUP_INVALID;
    }
    struct failure_store store;
    enum store_open_result opened =
        store_open(repo_root, false, &store, why, why_len);
    if (opened == STORE_OPEN_ABSENT) {
        set_why(why, why_len, "no_failure_recorded");
        return ZCL_DEV_FAILURE_LOOKUP_ABSENT;
    }
    if (opened != STORE_OPEN_OK)
        return ZCL_DEV_FAILURE_LOOKUP_INVALID;
    struct failure_lock lock;
    if (!store_lock(&store, false, false, &lock, why, why_len)) {
        store_close(&store);
        return ZCL_DEV_FAILURE_LOOKUP_INVALID;
    }
    struct failure_latest latest;
    enum zcl_dev_failure_lookup result = latest_read(&store, &latest);
    if (result == ZCL_DEV_FAILURE_LOOKUP_FOUND)
        result = record_read_store(&store, latest.failure_id, out);
    if (result == ZCL_DEV_FAILURE_LOOKUP_FOUND &&
        (strcmp(out->source_id, latest.source_id) != 0 ||
         strcmp(out->phase, latest.phase) != 0))
        result = ZCL_DEV_FAILURE_LOOKUP_INVALID;
    if (result == ZCL_DEV_FAILURE_LOOKUP_ABSENT)
        set_why(why, why_len, "no_failure_recorded");
    else if (result == ZCL_DEV_FAILURE_LOOKUP_INVALID)
        set_why(why, why_len, "latest_failure_invalid");
    store_unlock(&lock);
    store_close(&store);
    return result;
}

bool zcl_dev_failure_match_latest(
    const char *repo_root,
    const char source_id[ZCL_DEV_FAILURE_HEX_LEN + 1],
    const char source_mutation[ZCL_DEV_FAILURE_HEX_LEN + 1],
    const char execution_id[ZCL_DEV_FAILURE_HEX_LEN + 1],
    const char *phase, struct zcl_dev_failure_record *out,
    char *why, size_t why_len)
{
    if (why && why_len)
        why[0] = 0;
    if (!out || !valid_hex64(source_id) || !valid_hex64(source_mutation) ||
        !valid_hex64(execution_id) || !valid_phase(phase)) {
        set_why(why, why_len, "failure_match_input_invalid");
        return false;
    }
    struct failure_store store;
    enum store_open_result opened =
        store_open(repo_root, false, &store, why, why_len);
    if (opened == STORE_OPEN_ABSENT)
        return false;
    if (opened != STORE_OPEN_OK)
        return false;
    struct failure_lock lock;
    if (!store_lock(&store, false, false, &lock, why, why_len)) {
        store_close(&store);
        return false;
    }
    struct failure_latest latest;
    enum zcl_dev_failure_lookup latest_result = latest_read(&store, &latest);
    if (latest_result != ZCL_DEV_FAILURE_LOOKUP_FOUND) {
        if (latest_result == ZCL_DEV_FAILURE_LOOKUP_INVALID)
            set_why(why, why_len, "latest_failure_invalid");
        store_unlock(&lock);
        store_close(&store);
        return false;
    }
    if (strcmp(latest.source_id, source_id) != 0 ||
        strcmp(latest.source_mutation, source_mutation) != 0 ||
        strcmp(latest.execution_id, execution_id) != 0 ||
        strcmp(latest.phase, phase) != 0) {
        store_unlock(&lock);
        store_close(&store);
        return false;
    }
    bool ok = record_read_store(&store, latest.failure_id, out) ==
                  ZCL_DEV_FAILURE_LOOKUP_FOUND &&
              strcmp(out->source_id, source_id) == 0 &&
              strcmp(out->phase, phase) == 0;
    if (!ok)
        set_why(why, why_len, "latest_failure_record_invalid");
    store_unlock(&lock);
    store_close(&store);
    return ok;
}

bool zcl_dev_failure_note_coalesced(
    const char *repo_root,
    const char failure_id[ZCL_DEV_FAILURE_HEX_LEN + 1],
    const char source_id[ZCL_DEV_FAILURE_HEX_LEN + 1],
    const char source_mutation[ZCL_DEV_FAILURE_HEX_LEN + 1],
    const char execution_id[ZCL_DEV_FAILURE_HEX_LEN + 1],
    const char *phase,
    struct zcl_dev_failure_record *out, char *why, size_t why_len)
{
    if (why && why_len)
        why[0] = 0;
    if (!out || !valid_hex64(failure_id) || !valid_hex64(source_id) ||
        !valid_hex64(source_mutation) || !valid_hex64(execution_id) ||
        !valid_phase(phase)) {
        set_why(why, why_len, "coalesced_failure_input_invalid");
        return false;
    }
    struct failure_store store;
    if (store_open(repo_root, false, &store, why, why_len) != STORE_OPEN_OK)
        return false;
    struct failure_lock lock;
    if (!store_lock(&store, true, false, &lock, why, why_len)) {
        store_close(&store);
        return false;
    }
    struct failure_latest latest;
    bool ok = latest_read(&store, &latest) ==
                  ZCL_DEV_FAILURE_LOOKUP_FOUND &&
              strcmp(latest.failure_id, failure_id) == 0 &&
              strcmp(latest.source_id, source_id) == 0 &&
              strcmp(latest.source_mutation, source_mutation) == 0 &&
              strcmp(latest.execution_id, execution_id) == 0 &&
              strcmp(latest.phase, phase) == 0;
#if defined(_WIN32)
    struct failure_dir failure;
    platform_directory_transaction_init(&failure.value);
    enum platform_directory_result opened = ok
        ? platform_directory_transaction_open_child(&store.failures.value,
                                                     failure_id, false,
                                                     &failure.value)
        : PLATFORM_DIRECTORY_REFUSED;
    struct zcl_dev_failure_record before;
    ok = ok && opened == PLATFORM_DIRECTORY_OK &&
         read_record_fd(&failure, failure_id, store.workspace_id, &before) &&
         strcmp(before.source_id, source_id) == 0 &&
         strcmp(before.phase, phase) == 0 &&
         observation_increment(&failure, failure_id, &before.repeat_count) &&
         read_record_fd(&failure, failure_id, store.workspace_id, out);
    platform_directory_transaction_close(&failure.value);
#else
    int failure_fd = ok
        ? openat(store.failures.value, failure_id,
                 O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        : -1;
    struct zcl_dev_failure_record before;
    ok = ok && private_dir_fd(failure_fd) &&
         read_record_fd(&(struct failure_dir){.value = failure_fd}, failure_id,
                        store.workspace_id, &before) &&
         strcmp(before.source_id, source_id) == 0 &&
         strcmp(before.phase, phase) == 0 &&
         observation_increment(&(struct failure_dir){.value = failure_fd}, failure_id,
                               &before.repeat_count) &&
         read_record_fd(&(struct failure_dir){.value = failure_fd}, failure_id,
                        store.workspace_id, out);
    if (!ok)
        set_why(why, why_len, "coalesced_failure_append_failed_or_superseded");
    if (failure_fd >= 0)
        close(failure_fd);
#endif
    store_unlock(&lock);
    store_close(&store);
    return ok;
}
