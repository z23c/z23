/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "send_key.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char priv[ZAPP_PAY_ADDRESS_MAX], priv2[ZAPP_PAY_ADDRESS_MAX];

static struct zapp_payment pay_of(const char *address, const char *tail)
{
    char text[512];
    struct zapp_payment p;
    snprintf(text, sizeof(text), "zclassic:%s%s", address, tail);
    assert(zapp_payment_parse(text, strlen(text), ZAPP_PAY_MAINNET, &p) == ZAPP_PAY_OK);
    return p;
}
static void key_of(const struct zapp_send_id *id, const struct zapp_payment *p, char out[ZAPP_SEND_KEY_HEX + 1])
{
    assert(zapp_send_key_derive(id, p, out));
}
static void write_file(const char *path, const void *data, size_t len)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0 && write(fd, data, len) == (ssize_t)len && close(fd) == 0);
}

/* The key is the first 16 bytes of SHA3-256 over the documented message, pinned by values computed outside this program. */
static void the_key_is_the_documented_hash(void)
{
    struct zapp_send_id id;
    char key[ZAPP_SEND_KEY_HEX + 1];
    memset(id.bytes, 7, sizeof(id.bytes));
    struct zapp_payment p = pay_of(priv, "?amount=1");
    key_of(&id, &p, key);
    assert(!strcmp(key, "26c611288eef348e82fa949628466814"));
    p = pay_of(priv, "?amount=1&memo=aGk");
    key_of(&id, &p, key);
    assert(!strcmp(key, "977f381c27c0e2bd8ca5cef42f4cffc6"));
}
static void the_key_follows_the_request_and_the_wallet(void)
{
    struct zapp_send_id a, b;
    char k[ZAPP_SEND_KEY_HEX + 1], same[ZAPP_SEND_KEY_HEX + 1], other[ZAPP_SEND_KEY_HEX + 1];
    memset(a.bytes, 1, sizeof(a.bytes));
    memset(b.bytes, 1, sizeof(b.bytes));
    b.bytes[31] = 2;
    struct zapp_payment base = pay_of(priv, "?amount=1.5&memo=aGk");
    key_of(&a, &base, k);
    assert(strlen(k) == ZAPP_SEND_KEY_HEX);
    for (size_t i = 0; i < strlen(k); ++i) assert((k[i] >= '0' && k[i] <= '9') || (k[i] >= 'a' && k[i] <= 'f'));
    key_of(&a, &base, same);
    assert(!strcmp(k, same));
    struct zapp_payment again = pay_of(priv, "?amount=1.5&memo=aGk&label=ignored");   /* a label is not part of the payment */
    key_of(&a, &again, same);
    assert(!strcmp(k, same));
    struct zapp_payment variants[] = {
        pay_of(priv, "?amount=1.50000001&memo=aGk"),   /* amount */
        pay_of(priv, "?amount=1.5&memo=aGo"),          /* memo */
        pay_of(priv, "?amount=1.5"),                   /* no memo */
        pay_of(priv2, "?amount=1.5&memo=aGk"),         /* address */
    };
    for (size_t i = 0; i < sizeof(variants) / sizeof(variants[0]); ++i) {
        key_of(&a, &variants[i], other);
        assert(strcmp(k, other) != 0);
    }
    key_of(&b, &base, other);
    assert(strcmp(k, other) != 0);   /* another wallet */
    struct zapp_payment no_amount = pay_of(priv, "");
    assert(!zapp_send_key_derive(&a, &no_amount, other));
}
static void the_wallet_id_is_made_once_and_kept(const char *dir)
{
    struct zapp_send_id first, second;
    char path[512];
    snprintf(path, sizeof(path), "%s/wallet_id", dir);
    assert(zapp_send_id_load(dir, &first));
    struct stat st;
    assert(stat(path, &st) == 0 && st.st_size == ZAPP_SEND_KEY_ID && (st.st_mode & 0777) == 0600);
    struct zapp_send_id zero = {{0}};
    assert(memcmp(first.bytes, zero.bytes, sizeof(zero.bytes)) != 0);
    /* a later start reads the same id, so a rescan after a restart derives the same key */
    assert(zapp_send_id_load(dir, &second));
    assert(!memcmp(first.bytes, second.bytes, sizeof(first.bytes)));
    char a[ZAPP_SEND_KEY_HEX + 1], b[ZAPP_SEND_KEY_HEX + 1];
    struct zapp_payment p = pay_of(priv, "?amount=2");
    key_of(&first, &p, a);
    key_of(&second, &p, b);
    assert(!strcmp(a, b));
    char tmp[520];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    assert(access(tmp, F_OK) != 0);   /* the temporary file does not stay */
}
static void another_wallet_gets_another_id(const char *dir)
{
    struct zapp_send_id one, two;
    char sub[512];
    snprintf(sub, sizeof(sub), "%s/other", dir);
    assert(mkdir(sub, 0700) == 0);
    assert(zapp_send_id_load(dir, &one) && zapp_send_id_load(sub, &two));
    assert(memcmp(one.bytes, two.bytes, sizeof(one.bytes)) != 0);
}
/* An id that is present and not exactly 32 bytes is never replaced: a new id could not match the keys already sent. */
static void a_damaged_id_is_never_replaced(const char *dir)
{
    char sub[512], path[600], link[600];
    struct zapp_send_id id;
    snprintf(sub, sizeof(sub), "%s/damaged", dir);
    assert(mkdir(sub, 0700) == 0);
    snprintf(path, sizeof(path), "%s/wallet_id", sub);
    write_file(path, "short", 5);
    assert(!zapp_send_id_load(sub, &id));
    uint8_t big[ZAPP_SEND_KEY_ID + 1] = {0};
    write_file(path, big, sizeof(big));
    assert(!zapp_send_id_load(sub, &id));
    struct stat st;
    assert(stat(path, &st) == 0 && st.st_size == (off_t)sizeof(big));
    snprintf(link, sizeof(link), "%s/wallet_id", dir);
    assert(unlink(path) == 0 && symlink(link, path) == 0);   /* a link is not followed */
    assert(!zapp_send_id_load(sub, &id));
    assert(!zapp_send_id_load("", &id) && !zapp_send_id_load(NULL, &id));
    char missing[600];
    snprintf(missing, sizeof(missing), "%s/no/such/dir", dir);
    assert(!zapp_send_id_load(missing, &id));
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    memcpy(priv, "zs1", 3); memset(priv + 3, 'q', 75); priv[78] = 0;
    memcpy(priv2, "zs1", 3); memset(priv2 + 3, 'p', 75); priv2[78] = 0;
    the_key_is_the_documented_hash();
    the_key_follows_the_request_and_the_wallet();
    the_wallet_id_is_made_once_and_kept(argv[1]);
    another_wallet_gets_another_id(argv[1]);
    a_damaged_id_is_never_replaced(argv[1]);
    puts("send_key_test: ok");
    return 0;
}
