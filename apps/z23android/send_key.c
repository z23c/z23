/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "send_key.h"
#include "base/cleanse.h"
#include "sha3/sha3.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#define ID_FILE "wallet_id"
#define DOMAIN "z23-pay-v1"

static bool random_bytes(uint8_t *out, size_t len)
{
    while (len) {
        ssize_t got = getrandom(out, len, 0);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return false;
        out += got;
        len -= (size_t)got;
    }
    return true;
}
static bool write_all(int fd, const uint8_t *data, size_t len)
{
    while (len) {
        ssize_t put = write(fd, data, len);
        if (put < 0 && errno == EINTR) continue;
        if (put <= 0) return false;
        data += put;
        len -= (size_t)put;
    }
    return true;
}
static bool path_of(const char *dir, const char *suffix, char *out, size_t cap)
{
    return dir && dir[0] && snprintf(out, cap, "%s/" ID_FILE "%s", dir, suffix) < (int)cap;
}
/* 1 read, 0 absent, -1 present but unreadable or of another size. */
static int read_id(const char *path, struct zapp_send_id *id)
{
    uint8_t extra;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    struct stat st;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size == (off_t)sizeof(id->bytes);
    size_t got = 0;
    while (ok && got < sizeof(id->bytes)) {
        ssize_t n = read(fd, id->bytes + got, sizeof(id->bytes) - got);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) ok = false;
        else got += (size_t)n;
    }
    if (ok && read(fd, &extra, 1) != 0) ok = false;
    (void)close(fd);
    if (!ok) memory_cleanse(id, sizeof(*id));
    return ok ? 1 : -1;
}
/* A private temporary file renamed into place without replacing, so two starts cannot make two ids. */
static bool store_id(const char *path, const char *tmp, const struct zapp_send_id *id)
{
    (void)unlink(tmp);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    bool ok = fchmod(fd, 0600) == 0 && write_all(fd, id->bytes, sizeof(id->bytes)) && fsync(fd) == 0;
    ok = close(fd) == 0 && ok;
    ok = ok && renameat2(AT_FDCWD, tmp, AT_FDCWD, path, RENAME_NOREPLACE) == 0;
    (void)unlink(tmp);
    return ok;
}
bool zapp_send_id_load(const char *dir, struct zapp_send_id *id)
{
    char path[PATH_MAX], tmp[PATH_MAX];
    if (!path_of(dir, "", path, sizeof(path)) || !path_of(dir, ".tmp", tmp, sizeof(tmp))) return false;
    int found = read_id(path, id);
    if (found != 0) return found > 0;
    struct zapp_send_id fresh;
    if (random_bytes(fresh.bytes, sizeof(fresh.bytes))) (void)store_id(path, tmp, &fresh);
    memory_cleanse(&fresh, sizeof(fresh));
    /* Read back what is stored: another start may have made the id between the first read and the rename. */
    return read_id(path, id) == 1;
}

static void put_be(uint8_t *out, uint64_t v, size_t bytes)
{
    for (size_t i = 0; i < bytes; ++i) out[i] = (uint8_t)(v >> (8 * (bytes - 1 - i)));
}
bool zapp_send_key_derive(const struct zapp_send_id *id, const struct zapp_payment *pay, char out[ZAPP_SEND_KEY_HEX + 1])
{
    static const char hex[] = "0123456789abcdef";
    uint8_t message[sizeof(DOMAIN) - 1 + ZAPP_SEND_KEY_ID + 4 + ZAPP_PAY_ADDRESS_MAX + 8 + 4 + ZAPP_PAY_MEMO_MAX];
    uint8_t digest[32];
    size_t n = 0, address_len = strnlen(pay->address, sizeof(pay->address));
    if (!pay->has_amount || address_len == 0 || address_len == sizeof(pay->address) || pay->memo_len > ZAPP_PAY_MEMO_MAX) return false;
    memcpy(message, DOMAIN, sizeof(DOMAIN) - 1);
    n += sizeof(DOMAIN) - 1;
    memcpy(message + n, id->bytes, sizeof(id->bytes));
    n += sizeof(id->bytes);
    put_be(message + n, address_len, 4);
    n += 4;
    memcpy(message + n, pay->address, address_len);
    n += address_len;
    put_be(message + n, pay->amount_zat, 8);
    n += 8;
    put_be(message + n, pay->memo_len, 4);
    n += 4;
    memcpy(message + n, pay->memo, pay->memo_len);
    n += pay->memo_len;
    zcl_sha3_256(message, n, digest);
    for (size_t i = 0; i < ZAPP_SEND_KEY_HEX / 2; ++i) {
        out[2 * i] = hex[digest[i] >> 4];
        out[2 * i + 1] = hex[digest[i] & 15];
    }
    out[ZAPP_SEND_KEY_HEX] = 0;
    memory_cleanse(message, sizeof(message));
    memory_cleanse(digest, sizeof(digest));
    return true;
}
