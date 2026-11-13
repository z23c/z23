/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Telegram poll offset, sent-key ring and atomic private writes under
 * the z23 state root. */
#include "command/native_telegram.h"
#include "platform/private_directory.h"
#include "platform/state_root.h"
#include "base/hex.h"
#include "sha3/sha3.h"
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define TG_SENT_MAX 128u
#define TG_SENT_BYTES 16384u

bool tg_state_dir(char *out, size_t cap)
{
    char root[TG_PATH_MAX];
    if (!platform_state_root(root, sizeof(root)))
        return false;
    int n = snprintf(out, cap, "%s/telegram", root);
    return n > 0 && (size_t)n < cap && platform_private_directory_ensure(out);
}

#if !defined(_WIN32)
static bool tg_write_all(int fd, const char *data, size_t len)
{
    while (len) {
        ssize_t n = write(fd, data, len);
        if (n <= 0)
            return false;
        data += n;
        len -= (size_t)n;
    }
    return true;
}

static bool tg_atomic_write_posix(const char *path, const char *data, size_t len)
{
    char tmp[TG_PATH_MAX + 32];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid()) >= (int)sizeof(tmp))
        return false;
    (void)unlink(tmp);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return false;
    bool ok = tg_write_all(fd, data, len) && fchmod(fd, 0600) == 0 && fsync(fd) == 0;
    ok = close(fd) == 0 && ok;
    if (ok && rename(tmp, path) == 0)
        return true;
    (void)unlink(tmp);
    return false;
}

/* 1 read, 0 absent, -1 error. */
static int tg_read_small(const char *path, char *buf, size_t cap, size_t *len)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return errno == ENOENT ? 0 : -1;
    ssize_t n = read(fd, buf, cap - 1);
    close(fd);
    if (n < 0)
        return -1;
    buf[n] = 0;
    *len = (size_t)n;
    return 1;
}
#else
static bool tg_atomic_write_posix(const char *path, const char *data, size_t len)
{
    (void)path; (void)data; (void)len;
    return false;
}
static int tg_read_small(const char *path, char *buf, size_t cap, size_t *len)
{
    (void)path; (void)buf; (void)cap; (void)len;
    return -1;
}
#endif

bool tg_atomic_write_private(const char *path, const char *data, size_t len)
{
    return tg_atomic_write_posix(path, data, len);
}

/* Offsets are per bot: the numeric id before the colon names the file. */
static bool tg_offset_path(const char *dir, const char *token, char *out, size_t cap)
{
    size_t id = strcspn(token, ":");
    int n = snprintf(out, cap, "%s/offset-%.*s", dir, (int)id, token);
    return n > 0 && (size_t)n < cap;
}

bool tg_offset_load(const char *dir, const char *token, int64_t *offset)
{
    char path[TG_PATH_MAX + 64], buf[32];
    size_t len = 0;
    *offset = 0;
    if (!tg_offset_path(dir, token, path, sizeof(path)))
        return false;
    int got = tg_read_small(path, buf, sizeof(buf), &len);
    if (got == 0)
        return true;
    if (got < 0)
        return false;
    while (len && isspace((unsigned char)buf[len - 1]))
        len--;
    return tg_parse_i64(buf, len, offset) && *offset >= 0;
}

bool tg_offset_store(const char *dir, const char *token, int64_t offset)
{
    char path[TG_PATH_MAX + 64], text[32];
    int n = snprintf(text, sizeof(text), "%lld\n", (long long)offset);
    return n > 0 && tg_offset_path(dir, token, path, sizeof(path)) &&
           tg_atomic_write_private(path, text, (size_t)n);
}

#if !defined(_WIN32)
static bool tg_pending_path(const char *dir, const char *token, char *out, size_t cap)
{
    size_t id = strcspn(token, ":");
    int n = snprintf(out, cap, "%s/pending-%.*s", dir, (int)id, token);
    return n > 0 && (size_t)n < cap;
}

#endif

bool tg_state_sync(const char *dir)
{
#if !defined(_WIN32)
    int fd = open(dir, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0) return false;
    bool ok = fsync(fd) == 0;
    return close(fd) == 0 && ok;
#else
    (void)dir;
    return false;
#endif
}

#if !defined(_WIN32)
static bool tg_pending_private(int fd, size_t cap, size_t *length)
{
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 077) != 0 || st.st_size <= 0 || (uintmax_t)st.st_size >= cap)
        return false;
    *length = (size_t)st.st_size;
    return true;
}

static bool tg_pending_bytes(int fd, char *out, size_t length)
{
    size_t used = 0;
    while (used < length) {
        ssize_t n = read(fd, out + used, length - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        used += (size_t)n;
    }
    char extra;
    ssize_t n = read(fd, &extra, 1);
    return n == 0 && memchr(out, '\0', length) == NULL;
}
#endif

int tg_pending_read(const char *dir, const char *token, char *out, size_t cap)
{
#if !defined(_WIN32)
    char path[TG_PATH_MAX + 64];
    size_t length = 0;
    if (!tg_pending_path(dir, token, path, sizeof path) || cap < 2) return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    bool ok = tg_pending_private(fd, cap, &length) && tg_pending_bytes(fd, out, length);
    ok = close(fd) == 0 && ok;
    if (ok) out[length] = '\0';
    return ok ? 1 : -1;
#else
    (void)dir; (void)token; (void)out; (void)cap;
    return -1;
#endif
}

bool tg_pending_write(const char *dir, const char *token, const char *data, size_t len)
{
#if !defined(_WIN32)
    char path[TG_PATH_MAX + 64];
    return tg_pending_path(dir, token, path, sizeof path) &&
           tg_atomic_write_private(path, data, len) && tg_state_sync(dir);
#else
    (void)dir; (void)token; (void)data; (void)len;
    return false;
#endif
}

bool tg_pending_delete(const char *dir, const char *token)
{
#if !defined(_WIN32)
    char path[TG_PATH_MAX + 64];
    return tg_pending_path(dir, token, path, sizeof path) &&
           unlink(path) == 0 && tg_state_sync(dir);
#else
    (void)dir; (void)token;
    return false;
#endif
}

bool tg_key_valid(const char *key)
{
    size_t n = key ? strlen(key) : 0;
    if (n == 0 || n > TG_KEY_MAX)
        return false;
    for (size_t i = 0; i < n; i++) {
        if (!isalnum((unsigned char)key[i]) && !strchr("._:-", key[i]))
            return false;
    }
    return true;
}

/* sent: one line per accepted send, newest last, bounded to TG_SENT_MAX lines.
 * Current format: `<key> <first message id> <chunk count> <request hash>`.
 * Legacy format, written before the hash was added: `<key> <first message id>
 * <chunk count>`; a legacy record has no hash, so it matches any request with
 * the same key (the pre-upgrade behaviour). */
static bool tg_sent_path(const char *dir, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/sent", dir);
    return n > 0 && (size_t)n < cap;
}

void tg_request_hash(int64_t chat_id, const char *text, char hash[TG_HASH_HEX])
{
    struct sha3_256_ctx ctx;
    uint8_t digest[32];
    char head[32];
    int n = snprintf(head, sizeof(head), "%lld\n", (long long)chat_id);
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)head, (size_t)n);
    sha3_256_write(&ctx, (const unsigned char *)text, strlen(text));
    sha3_256_finalize(&ctx, digest);
    zcl_hex_encode(digest, 16, hash);
}

enum tg_sent tg_sent_lookup(const char *dir, const char *key, const char *hash,
                            int64_t *first_id, int64_t *count)
{
    char path[TG_PATH_MAX + 16], buf[TG_SENT_BYTES];
    size_t len = 0, klen = strlen(key);
    if (!tg_sent_path(dir, path, sizeof(path)) || tg_read_small(path, buf, sizeof(buf), &len) != 1)
        return TG_SENT_NONE;
    for (char *line = buf; *line;) {
        char *nl = strchr(line, '\n');
        long long id = 0, chunks = 0;
        char stored[TG_HASH_HEX] = "";
        /* Bound the record: %s skips newlines, so a legacy line without a hash
         * would otherwise read the next record's key as its hash. */
        if (nl)
            *nl = '\0';
        if (!strncmp(line, key, klen) && line[klen] == ' ' &&
            sscanf(line + klen + 1, "%lld %lld %32s", &id, &chunks, stored) >= 2) {
            *first_id = id;
            *count = chunks;
            if (stored[0] == '\0')
                return TG_SENT_SAME;
            return strcmp(stored, hash) == 0 ? TG_SENT_SAME : TG_SENT_DIFFERENT;
        }
        if (!nl)
            break;
        line = nl + 1;
    }
    return TG_SENT_NONE;
}

bool tg_sent_record(const char *dir, const char *key, const char *hash, int64_t first_id,
                    int64_t count)
{
    char path[TG_PATH_MAX + 16], buf[TG_SENT_BYTES + 128];
    size_t len = 0, lines = 0;
    if (!tg_sent_path(dir, path, sizeof(path)))
        return false;
    if (tg_read_small(path, buf, TG_SENT_BYTES, &len) != 1)
        len = 0;
    for (size_t i = 0; i < len; i++)
        lines += buf[i] == '\n';
    char *keep = buf;
    while (lines >= TG_SENT_MAX || (len - (size_t)(keep - buf)) > TG_SENT_BYTES - 256) {
        char *nl = strchr(keep, '\n');
        if (!nl)
            break;
        keep = nl + 1;
        lines--;
    }
    len -= (size_t)(keep - buf);
    memmove(buf, keep, len);
    int n = snprintf(buf + len, sizeof(buf) - len, "%s %lld %lld %s\n", key, (long long)first_id,
                     (long long)count, hash);
    return n > 0 && tg_atomic_write_private(path, buf, len + (size_t)n);
}
/* Receipt commits the bot id, group filter and complete serialized batch. */
static bool tg_batch_receipt(const char *token, int64_t group,
                             const struct json_value *data, char out[65])
{
    char wire[TG_PENDING_MAX], prefix[128];
    size_t len = json_write(data, wire, sizeof wire);
    int n = snprintf(prefix, sizeof prefix, "zcl.telegram.pending.v1:%.*s:%lld\n",
                     (int)strcspn(token, ":"), token, (long long)group);
    if (!len || len >= sizeof wire || n <= 0 || (size_t)n >= sizeof prefix) return false;
    struct sha3_256_ctx h;
    uint8_t digest[32];
    sha3_256_init(&h);
    sha3_256_write(&h, (const unsigned char *)prefix, (size_t)n);
    sha3_256_write(&h, (const unsigned char *)wire, len);
    sha3_256_finalize(&h, digest);
    zcl_hex_encode(digest, sizeof digest, out);
    return true;
}

bool tg_batch_save(const struct tg_config *cfg, const char *dir, int64_t group,
                   const struct json_value *data, char receipt[65])
{
    char wire[TG_PENDING_MAX];
    struct json_value record = {0};
    json_set_object(&record);
    bool ok = tg_batch_receipt(cfg->token, group, data, receipt) &&
              json_push_kv_int(&record, "group", group) &&
              json_push_kv(&record, "batch", data) &&
              json_push_kv_str(&record, "receipt", receipt);
    size_t n = ok ? json_write(&record, wire, sizeof wire) : 0;
    ok = n > 0 && n < sizeof wire && tg_pending_write(dir, cfg->token, wire, n);
    json_free(&record);
    return ok;
}

static bool tg_batch_counts(const struct json_value *batch)
{
    const struct json_value *messages = json_get(batch, "messages");
    const struct json_value *count = json_get(batch, "count");
    const struct json_value *dropped = json_get(batch, "dropped");
    return messages && messages->type == JSON_ARR &&
        count && count->type == JSON_INT && json_get_int(count) >= 0 &&
        (uint64_t)json_get_int(count) == json_size(messages) && dropped &&
        dropped->type == JSON_INT && json_get_int(dropped) >= 0;
}

static bool tg_batch_shape(const struct json_value *batch)
{
    const struct json_value *offset = json_get(batch, "next_offset");
    const struct json_value *more = json_get(batch, "more");
    return batch && batch->type == JSON_OBJ && offset && offset->type == JSON_INT &&
        json_get_int(offset) >= 0 && more && more->type == JSON_BOOL &&
        tg_batch_counts(batch) &&
        !strcmp(json_get_str(json_get(batch, "schema")), "zcl.telegram.inbox.v1");
}

static bool tg_json_unique(const struct json_value *value)
{
    if (!value) return false;
    for (size_t i = 0; i < value->num_children; i++) {
        if (value->type == JSON_OBJ) {
            if (!value->keys[i]) return false;
            for (size_t j = 0; j < i; j++)
                if (!strcmp(value->keys[i], value->keys[j])) return false;
        }
        if (!tg_json_unique(&value->children[i])) return false;
    }
    return true;
}

bool tg_batch_validate(const struct tg_config *cfg, int64_t group,
                       const struct json_value *record, int64_t *next)
{
    const struct json_value *g = json_get(record, "group");
    const struct json_value *batch = json_get(record, "batch");
    const struct json_value *offset = json_get(batch, "next_offset");
    const struct json_value *receipt = json_get(record, "receipt");
    char expected[65];
    if (!tg_json_unique(record) || !g || g->type != JSON_INT || json_get_int(g) != group ||
        !tg_batch_shape(batch) || !receipt || receipt->type != JSON_STR ||
        !tg_batch_receipt(cfg->token, group, batch, expected) ||
        strcmp(json_get_str(receipt), expected) != 0) return false;
    *next = json_get_int(offset);
    return true;
}
