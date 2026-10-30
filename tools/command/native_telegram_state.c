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
