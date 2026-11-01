/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "wallet_send_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* A keystore in memory that records which purpose each open was asked under, and what the owner answers. */
struct fake {
    bool has_key;
    enum zapp_devkey_status open_status;
    int prompts, opens, ops_calls;
    enum zapp_devkey_purpose purposes[8];
    bool no_ops;
};
static bool f_random(void *c, uint8_t *out, size_t len) { (void)c; for (size_t i = 0; i < len; ++i) out[i] = (uint8_t)(0x40 + i); return true; }
static enum zapp_devkey_status f_secure(void *c) { (void)c; return ZAPP_DEVKEY_OK; }
static enum zapp_devkey_status f_create(void *c, bool strongbox) { (void)strongbox; ((struct fake *)c)->has_key = true; return ZAPP_DEVKEY_OK; }
static enum zapp_devkey_status f_policy(void *c, enum zapp_devkey_level *level, bool *per_use)
{
    if (!((struct fake *)c)->has_key) return ZAPP_DEVKEY_NOT_FOUND;
    *level = ZAPP_DEVKEY_LEVEL_SECURE_HARDWARE;
    *per_use = true;
    return ZAPP_DEVKEY_OK;
}
static enum zapp_devkey_status f_seal(void *c, const uint8_t *plain, size_t len, uint8_t iv[ZAPP_DEVKEY_IV], uint8_t sealed[ZAPP_DEVKEY_SEALED])
{
    (void)c;
    for (size_t i = 0; i < ZAPP_DEVKEY_IV; ++i) iv[i] = (uint8_t)(0xC0 + i);
    for (size_t i = 0; i < len; ++i) sealed[i] = plain[i] ^ 0x5A;
    for (size_t i = len; i < ZAPP_DEVKEY_SEALED; ++i) sealed[i] = 0x77;
    return ZAPP_DEVKEY_OK;
}
static enum zapp_devkey_status f_open(void *c, enum zapp_devkey_purpose purpose, const uint8_t iv[ZAPP_DEVKEY_IV],
                                      const uint8_t sealed[ZAPP_DEVKEY_SEALED], uint8_t *plain, size_t cap)
{
    struct fake *f = c;
    (void)iv;
    memset(plain, 0xEE, cap);   /* garbage a failing backend may leave behind */
    if (f->opens < 8) f->purposes[f->opens] = purpose;
    f->opens++;
    f->prompts++;
    if (f->open_status != ZAPP_DEVKEY_OK) return f->open_status;
    for (size_t i = 0; i < cap; ++i) plain[i] = sealed[i] ^ 0x5A;
    return ZAPP_DEVKEY_OK;
}
static void f_delete(void *c) { (void)c; }
static bool give_ops(void *ctx, struct zapp_devkey_ops *out)
{
    struct fake *f = ctx;
    f->ops_calls++;
    if (f->no_ops) return false;
    *out = (struct zapp_devkey_ops){f, f_random, f_secure, f_create, f_policy, f_seal, f_open, f_delete};
    return true;
}
static bool all_zero(const uint8_t *bytes, size_t len)
{
    for (size_t i = 0; i < len; ++i) if (bytes[i]) return false;
    return true;
}

/* Every status string the device key can give, by the enum, so a renamed or added status shows here. */
static void every_real_status_maps(void)
{
    static const struct { enum zapp_devkey_status status; enum wss_key_status want; } table[] = {
        {ZAPP_DEVKEY_OK, WSS_KEY_OK}, {ZAPP_DEVKEY_DECLINED, WSS_KEY_DECLINED},
        {ZAPP_DEVKEY_INVALIDATED, WSS_KEY_GONE}, {ZAPP_DEVKEY_NOT_FOUND, WSS_KEY_GONE}, {ZAPP_DEVKEY_CORRUPT, WSS_KEY_GONE},
        {ZAPP_DEVKEY_OLD_FORMAT, WSS_KEY_GONE}, {ZAPP_DEVKEY_NOT_HARDWARE, WSS_KEY_GONE}, {ZAPP_DEVKEY_NOT_PER_USE, WSS_KEY_GONE},
        {ZAPP_DEVKEY_NO_SCREEN_LOCK, WSS_KEY_NO_SCREEN_LOCK},
        {ZAPP_DEVKEY_EXISTS, WSS_KEY_ERROR}, {ZAPP_DEVKEY_STRONGBOX_UNAVAILABLE, WSS_KEY_ERROR}, {ZAPP_DEVKEY_ERROR, WSS_KEY_ERROR},
    };
    size_t count = sizeof(table) / sizeof(table[0]);
    assert(count == (size_t)ZAPP_DEVKEY_ERROR + 1);   /* a new status needs a row and a decision */
    for (size_t i = 0; i < count; ++i) {
        const char *name = zapp_devkey_status_name(table[i].status);
        assert(name && name[0] && strcmp(name, "unknown"));
        assert(wss_key_status_of_devkey(name) == table[i].want);
    }
    assert(wss_key_status_of_devkey("not_per_use") == WSS_KEY_GONE);   /* a key that does not ask every time is never used */
    assert(wss_key_status_of_devkey("something new") == WSS_KEY_ERROR && wss_key_status_of_devkey(NULL) == WSS_KEY_ERROR);
}

static void make_blob(struct fake *f, const char *files, struct wsd *device, uint8_t secret[32])
{
    struct zapp_devkey_ops ops;
    f->has_key = true;
    assert(wsd_init(device, f, give_ops, files));
    assert(give_ops(f, &ops));
    f->ops_calls = 0;
    assert(zapp_devkey_wrap_new(&ops, device->blob, secret) == ZAPP_DEVKEY_OK);
}

/* A payment opens the wallet secret under the payment purpose, once, and never under the unlock purpose. */
static void unwrap_is_a_payment(const char *files)
{
    struct fake f = {0};
    struct wsd device;
    struct wss_device_ops ops;
    uint8_t made[32], secret[32];
    make_blob(&f, files, &device, made);
    f.opens = f.prompts = 0;
    wsd_ops(&device, &ops);
    assert(ops.unwrap(ops.ctx, secret) == WSS_KEY_OK);
    assert(f.opens == 1 && f.prompts == 1 && f.purposes[0] == ZAPP_DEVKEY_PURPOSE_PAYMENT);
    assert(!memcmp(secret, made, 32) && f.ops_calls == 1);
    /* A second payment is a second prompt on a fresh set of operations: nothing is remembered. */
    assert(ops.unwrap(ops.ctx, secret) == WSS_KEY_OK);
    assert(f.opens == 2 && f.prompts == 2 && f.purposes[1] == ZAPP_DEVKEY_PURPOSE_PAYMENT && f.ops_calls == 2);
    for (int i = 0; i < f.opens; ++i) assert(f.purposes[i] != ZAPP_DEVKEY_PURPOSE_UNLOCK);
    assert(unlink(device.blob) == 0);
}

/* Every refusal leaves the caller's secret zero, whatever the backend left behind. */
static void refusals_leave_no_secret(const char *files)
{
    static const struct { enum zapp_devkey_status status; enum wss_key_status want; } cases[] = {
        {ZAPP_DEVKEY_DECLINED, WSS_KEY_DECLINED}, {ZAPP_DEVKEY_INVALIDATED, WSS_KEY_GONE}, {ZAPP_DEVKEY_NO_SCREEN_LOCK, WSS_KEY_NO_SCREEN_LOCK},
        {ZAPP_DEVKEY_ERROR, WSS_KEY_ERROR},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        struct fake f = {0};
        struct wsd device;
        struct wss_device_ops ops;
        uint8_t made[32], secret[32];
        make_blob(&f, files, &device, made);
        f.open_status = cases[i].status;
        memset(secret, 0xAB, sizeof(secret));
        wsd_ops(&device, &ops);
        enum wss_key_status got = ops.unwrap(ops.ctx, secret);
        assert(got == cases[i].want && all_zero(secret, sizeof(secret)));
        assert(unlink(device.blob) == 0);
    }
}

/* A worker with no JVM or no activity gets no keystore: the unwrap fails and no prompt is shown. */
static void no_keystore_no_prompt(const char *files)
{
    struct fake f = {0};
    struct wsd device;
    struct wss_device_ops ops;
    uint8_t made[32], secret[32];
    make_blob(&f, files, &device, made);
    f.no_ops = true;
    f.opens = f.prompts = 0;
    memset(secret, 0xAB, sizeof(secret));
    wsd_ops(&device, &ops);
    assert(ops.unwrap(ops.ctx, secret) == WSS_KEY_ERROR && f.prompts == 0 && all_zero(secret, sizeof(secret)));
    assert(unlink(device.blob) == 0);
    assert(!wsd_init(&device, &f, NULL, files) && !wsd_init(&device, &f, give_ops, NULL));
}

int main(int argc, char **argv)
{
    assert(argc == 2 && argv[1][0] == '/');
    every_real_status_maps();
    unwrap_is_a_payment(argv[1]);
    refusals_leave_no_secret(argv[1]);
    no_keystore_no_prompt(argv[1]);
    puts("wallet_send_device_test: ok");
    return 0;
}
