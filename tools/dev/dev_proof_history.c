/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded read-only history of native proof failure archives. */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "dev_proof.h"
#include "platform/directory_compat.h"
#include "base/hex.h"
#include "sha3/sha3.h"
#include <errno.h>
#include <stdlib.h>
#if !defined(_WIN32)
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#define HISTORY_ENTRIES_MAX 4096u

static bool history_private(const struct stat *st, bool directory)
{
    return st->st_uid == geteuid() &&
           (st->st_mode & (S_IWGRP | S_IWOTH)) == 0 &&
           (directory ? S_ISDIR(st->st_mode) : S_ISREG(st->st_mode));
}

static int history_directory(int parent, const char *leaf)
{
    int fd = openat(parent, leaf, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    struct stat st;
    if (fd < 0) return -1;
    if (fstat(fd, &st) == 0 && history_private(&st, true)) return fd;
    (void)close(fd);
    errno = EINVAL;
    return -1;
}

static bool history_read(int fd, char *text, size_t size)
{
    size_t used = 0;
    while (used < size) {
        ssize_t n = read(fd, text + used, size - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        used += (size_t)n;
    }
    char extra;
    return read(fd, &extra, 1) == 0 && memchr(text, 0, size) == NULL;
}

static bool history_text_shape(const char *text, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        unsigned char c = (unsigned char)text[i];
        if ((c < 32 && c != '\n' && c != '\t') || c == 127) return false;
    }
    return true;
}

/* 1 complete text, 0 absent, -1 unsafe/malformed. No path from record bytes. */
static int history_text(int parent, const char *leaf, char *text, size_t cap)
{
    int fd = openat(parent, leaf, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    struct stat st;
    bool ok = fstat(fd, &st) == 0 && history_private(&st, false) &&
              st.st_size > 0 && (uint64_t)st.st_size < cap;
    if (ok) ok = history_read(fd, text, (size_t)st.st_size) &&
                 history_text_shape(text, (size_t)st.st_size);
    (void)close(fd);
    if (!ok) return -1;
    text[(size_t)st.st_size] = 0;
    return 1;
}

static bool history_pair_leaf(const char *leaf,
                              struct zcl_dev_proof_history_failure *out)
{
    size_t n = strcspn(leaf, "-");
    if (n != 40 && n != 64) return false;
    size_t len = strlen(leaf);
    if (len != 2 * n + 8 || leaf[2 * n + 1] != '.') return false;
    static const char hex[] = "0123456789abcdef";
    static const char suffix[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    if (strspn(leaf, hex) != n || strspn(leaf + n + 1, hex) != n ||
        strspn(leaf + 2 * n + 2, suffix) != 6) return false;
    memcpy(out->local, leaf, n);
    memcpy(out->base, leaf + n + 1, n);
    memcpy(out->attempt, leaf, len + 1);
    return true;
}

static bool history_positive(const char *text, int64_t *value)
{
    if (!text[0]) return false;
    for (const char *p = text; *p; p++)
        if (*p < '0' || *p > '9') return false;
    errno = 0;
    char *end = NULL;
    long long parsed = strtoll(text, &end, 10);
    if (errno || !end || *end || parsed <= 0) return false;
    *value = (int64_t)parsed;
    return true;
}

static void history_hash(const char *domain, const char *text, char out[65])
{
    struct sha3_256_ctx sha;
    uint8_t digest[32];
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, strlen(domain) + 1);
    sha3_256_write(&sha, (const uint8_t *)text, strlen(text));
    sha3_256_finalize(&sha, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
}

static bool history_lines(char *text, char **lines, size_t count)
{
    char *next = text;
    for (size_t i = 0; i < count; i++) {
        lines[i] = next;
        char *nl = strchr(next, '\n');
        if (!nl) return false;
        *nl = 0;
        next = nl + 1;
    }
    return !*next;
}

static bool history_request(int fd, struct zcl_dev_proof_history_failure *out,
                             char root[65], char observation_root[65])
{
    char text[320], *lines[5];
    if (history_text(fd, "request", text, sizeof(text)) != 1) return false;
    history_hash("zcl.dev_proof_failure_recorded.request.v1", text, root);
    history_hash("zcl.dev_proof_failure_observed.request.v1", text, observation_root);
    return history_lines(text, lines, 5) &&
           strcmp(lines[0], "zcl.dev_proof_request.v1") == 0 &&
           strcmp(lines[1], out->local) == 0 &&
           strcmp(lines[2], out->base) == 0 &&
           history_positive(lines[3], &out->request_started_unix) &&
           history_positive(lines[4], &out->request_started_monotonic_us);
}

static bool history_time_fields(char *text, const char *schema,
                                 const char *wall_key, const char *mono_key, char *values[7])
{
    char *lines[8];
    const char *const keys[] = {"attempt=", "local=", "base=", "request_sha3=",
        "failure_sha3=", wall_key, mono_key};
    if (!history_lines(text, lines, 8) ||
        strcmp(lines[0], schema) != 0) return false;
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        size_t n = strlen(keys[i]);
        if (strncmp(lines[i + 1], keys[i], n) != 0) return false;
        values[i] = lines[i + 1] + n;
    }
    return true;
}

static bool history_time_binding(char *const values[7],
    const struct zcl_dev_proof_history_failure *out,
    const char *request, const char *failure, int64_t *wall, int64_t *mono)
{
    /* Equal-to-computed roots also pins exact 64-character lowercase hex. */
    return strcmp(values[0], out->attempt) == 0 &&
           strcmp(values[1], out->local) == 0 && strcmp(values[2], out->base) == 0 &&
           strcmp(values[3], request) == 0 && strcmp(values[4], failure) == 0 &&
           history_positive(values[5], wall) && history_positive(values[6], mono) &&
           *wall >= out->request_started_unix && *mono >= out->request_started_monotonic_us;
}

static void history_time(int logs, struct zcl_dev_proof_history_failure *out,
                          const char *request, const char *failure)
{
    char text[1024], *values[7];
    int result = history_text(logs, "failure-time.v1", text, sizeof(text));
    if (result == 0) return;
    out->time_state = ZCL_PROOF_HISTORY_TIME_UNUSABLE;
    int64_t wall, mono;
    if (result != 1 || !history_time_fields(text, "zcl.dev_proof_failure_recorded.v1",
        "recorded_unix=", "recorded_monotonic_us=", values) ||
        !history_time_binding(values, out, request, failure, &wall, &mono)) return;
    out->time_state = ZCL_PROOF_HISTORY_TIME_BOUND_RECORDING;
    out->recorded_unix = wall;
    out->recorded_monotonic_us = mono;
}

static void history_observation(int logs, struct zcl_dev_proof_history_failure *out,
                                 const char *request, const char *failure)
{
    char text[1024], *values[7];
    int result = history_text(logs, "failure-observed.v1", text, sizeof(text));
    if (result == 0) return;
    out->observation_state = ZCL_PROOF_HISTORY_OBSERVATION_UNUSABLE;
    int64_t wall, mono;
    /* An observer must not launder corrupt producer metadata into timed use. */
    if (out->time_state == ZCL_PROOF_HISTORY_TIME_UNUSABLE || result != 1 ||
        !history_time_fields(text, "zcl.dev_proof_failure_observed.v1",
            "observed_upper_unix=", "observed_upper_monotonic_us=", values) ||
        !history_time_binding(values, out, request, failure, &wall, &mono)) return;
    out->observation_state = ZCL_PROOF_HISTORY_OBSERVATION_BOUND_UPPER;
    out->observed_upper_unix = wall;
    out->observed_upper_monotonic_us = mono;
}

static bool history_failure(char *text, struct zcl_dev_proof_history_failure *out)
{
    size_t first = strcspn(text, "\n");
    if (!first || first >= sizeof(out->reason)) return false;
    /* The native writer accepts contextual reason text, not a token enum. */
    if (memchr(text, '\t', first) != NULL) return false;
    memcpy(out->reason, text, first);
    const char *digest = text[first] ? text + first + 1 : "";
    memcpy(out->digest, digest, strlen(digest) + 1);
    if (zcl_dev_proof_failure_interrupted(out->reason))
        out->classification = ZCL_PROOF_HISTORY_INTERRUPTED;
    else if (strcmp(out->reason, "proof_producer_source_mismatch") == 0 ||
             strcmp(out->reason, "proof_producer_source_id_unavailable") == 0)
        out->classification = ZCL_PROOF_HISTORY_NO_VERDICT;
    else
        out->classification = ZCL_PROOF_HISTORY_FAILURE;
    return true;
}

static bool history_archive(int logs, char *text, struct zcl_dev_proof_history_failure *out,
    const char request[65], const char observed_request[65])
{
    char failure[65], observed_failure[65], bound_attempt[144], bound_request[65]; size_t payload;
    history_hash("zcl.dev_proof_failure_recorded.failure.v1", text, failure);
    memcpy(out->request_sha3, request, sizeof(out->request_sha3));
    memcpy(out->archive_sha3, failure, sizeof(out->archive_sha3));
    history_time(logs, out, request, failure);
    history_hash("zcl.dev_proof_failure_observed.failure.v1", text, observed_failure);
    history_observation(logs, out, observed_request, observed_failure);
    if (zcl_dev_proof_failure_binding_decode(text, strlen(text), bound_attempt, bound_request, &payload) == 1 &&
        strcmp(bound_attempt, out->attempt) == 0 && strcmp(bound_request, request) == 0) {
        out->attempt_binding_valid = true;
        text[payload] = 0; /* metadata never becomes learned gate evidence */
    }
    return history_failure(text, out);
}

static int history_attempt(int parent, const char *leaf,
                           struct zcl_dev_proof_history_failure *out)
{
    /* Only exact native mkdtemp names qualify; unrelated entries are ignored. */
    if (!history_pair_leaf(leaf, out)) return 0;
    int fd = history_directory(parent, leaf);
    if (fd < 0) return -1;
    int logs = history_directory(fd, "logs");
    if (logs < 0) {
        int error = errno;
        (void)close(fd);
        return error == ENOENT ? 0 : -1;
    }
    char text[2049], request[65], observed_request[65];
    int result = history_text(logs, "failure.txt", text, sizeof(text));
    if (result == 1) {
        if (!history_request(fd, out, request, observed_request) ||
            !history_archive(logs, text, out, request, observed_request)) result = -1;
    }
    (void)close(logs);
    (void)close(fd);
    return result;
}

static enum zcl_dev_proof_history_result history_walk(int fd,
    bool (*visit)(const struct zcl_dev_proof_history_failure *, void *), void *context)
{
    DIR *dir = fdopendir(fd);
    if (!dir) { (void)close(fd); return ZCL_PROOF_HISTORY_UNAVAILABLE; }
    size_t count = 0;
    enum zcl_dev_proof_history_result result = ZCL_PROOF_HISTORY_COMPLETE;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (!entry) {
            if (errno) result = ZCL_PROOF_HISTORY_UNAVAILABLE;
            break;
        }
        if (++count > HISTORY_ENTRIES_MAX) { result = ZCL_PROOF_HISTORY_LIMIT; break; }
        struct zcl_dev_proof_history_failure record = {0};
        int read_result = history_attempt(dirfd(dir), entry->d_name, &record);
        if (read_result < 0) { result = ZCL_PROOF_HISTORY_INVALID; break; }
        if (read_result == 1 && !visit(&record, context)) {
            result = ZCL_PROOF_HISTORY_LIMIT;
            break;
        }
    }
    (void)closedir(dir);
    return result;
}
static enum zcl_dev_proof_history_result history_store(const char *canonical_root,
                                                       int *store)
{
    *store = -1;
    char actual[PATH_MAX];
    if (!canonical_root ||
        !platform_directory_canonical_real(canonical_root, actual, sizeof(actual)) ||
        strcmp(actual, canonical_root) != 0) return ZCL_PROOF_HISTORY_INVALID;
    int fd = open(canonical_root, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0) return ZCL_PROOF_HISTORY_UNAVAILABLE;
    const char *parts[] = {".cache", "zcl-dev-proof", "attempts"};
    for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); i++) {
        int next = history_directory(fd, parts[i]);
        int error = errno;
        (void)close(fd);
        if (next < 0) return error == ENOENT ? ZCL_PROOF_HISTORY_COMPLETE
                                           : ZCL_PROOF_HISTORY_INVALID;
        fd = next;
    }
    *store = fd;
    return ZCL_PROOF_HISTORY_COMPLETE;
}
#endif

enum zcl_dev_proof_history_result zcl_dev_proof_history_failures(
    const char *canonical_root,
    bool (*visit)(const struct zcl_dev_proof_history_failure *, void *), void *context)
{
#if defined(_WIN32)
    (void)canonical_root; (void)visit; (void)context;
    return ZCL_PROOF_HISTORY_UNAVAILABLE;
#else
    if (!visit) return ZCL_PROOF_HISTORY_INVALID;
    int fd;
    enum zcl_dev_proof_history_result result = history_store(canonical_root, &fd);
    return result == ZCL_PROOF_HISTORY_COMPLETE && fd >= 0
        ? history_walk(fd, visit, context) : result;
#endif
}

bool zcl_dev_proof_history_failure_read(const char *canonical_root,
    const char *attempt, struct zcl_dev_proof_history_failure *out)
{
#if defined(_WIN32)
    (void)canonical_root; (void)attempt; (void)out;
    return false;
#else
    if (!attempt || !out) return false;
    memset(out, 0, sizeof(*out));
    if (!history_pair_leaf(attempt, out)) return false;
    int fd;
    if (history_store(canonical_root, &fd) != ZCL_PROOF_HISTORY_COMPLETE || fd < 0) return false;
    int result = history_attempt(fd, attempt, out);
    (void)close(fd);
    return result == 1;
#endif
}
