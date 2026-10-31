/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "device_key.h"
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void put_file(const char *path, const void *data, size_t len);

/* What the owner does with a prompt. */
enum owner { OWNER_ACCEPTS, OWNER_DECLINES, OWNER_DESTROYS_ACTIVITY, OWNER_NO_LOCK, OWNER_FAILS };

/* A keystore in memory: XOR sealing with a check tag. Every seal and every open is exactly one
 * prompt, and no authentication is remembered between operations. With wait_mode the answer travels
 * through the module's wait primitives from a second thread, as it does in the JNI backend. */
struct fake {
    bool secure, has_key, invalidated, strongbox_ok, random_ok, per_use, wait_mode;
    bool vanish_after_policy;    /* The key is deleted right after the policy read, before the prompt. */
    enum owner owner;
    int prompts;
    enum zapp_devkey_purpose last_purpose;
    struct zapp_devkey_wait wait;
    enum zapp_devkey_level level_if_created;
    int creates, strongbox_tries, deletes, key_id, ids;
    uint8_t counter;
    enum zapp_devkey_status level_error, strongbox_error;
    const char *race_path;       /* A blob that appears while the secret is being sealed. */
};
static struct fake fake_new(void)
{
    return (struct fake){.secure = true, .per_use = true, .strongbox_ok = true, .random_ok = true,
                         .wait = ZAPP_DEVKEY_WAIT_INIT, .level_if_created = ZAPP_DEVKEY_LEVEL_STRONGBOX};
}
static bool f_random(void *c, uint8_t *out, size_t len)
{
    struct fake *f = c;
    for (size_t i = 0; i < len; ++i) out[i] = (uint8_t)(0x40 + f->counter + i);
    f->counter++;
    return f->random_ok;
}
static enum zapp_devkey_status f_secure(void *c) { return ((struct fake *)c)->secure ? ZAPP_DEVKEY_OK : ZAPP_DEVKEY_NO_SCREEN_LOCK; }
static enum zapp_devkey_status f_create(void *c, bool strongbox)
{
    struct fake *f = c;
    f->creates++;
    if (strongbox) {
        f->strongbox_tries++;
        if (f->strongbox_error != ZAPP_DEVKEY_OK) return f->strongbox_error;
        if (!f->strongbox_ok) return ZAPP_DEVKEY_STRONGBOX_UNAVAILABLE;
    }
    f->has_key = true; f->key_id = ++f->ids;
    if (!strongbox && f->level_if_created == ZAPP_DEVKEY_LEVEL_STRONGBOX) f->level_if_created = ZAPP_DEVKEY_LEVEL_SECURE_HARDWARE;
    return ZAPP_DEVKEY_OK;
}
static enum zapp_devkey_status f_policy(void *c, enum zapp_devkey_level *level, bool *per_use)
{
    struct fake *f = c;
    if (!f->has_key) return ZAPP_DEVKEY_NOT_FOUND;
    if (f->level_error != ZAPP_DEVKEY_OK) return f->level_error;
    *level = f->level_if_created;
    *per_use = f->per_use;
    if (f->vanish_after_policy) f->has_key = false;
    return ZAPP_DEVKEY_OK;
}
static void f_delete(void *c) { struct fake *f = c; f->has_key = false; f->deletes++; }

struct answering { struct fake *fake; unsigned long ticket; };
static void *owner_thread(void *arg)
{
    struct answering *a = arg;
    struct timespec pause = {0, 20 * 1000 * 1000};
    nanosleep(&pause, NULL);
    switch (a->fake->owner) {
    case OWNER_ACCEPTS: zapp_devkey_wait_answer(&a->fake->wait, a->ticket, ZAPP_DEVKEY_ANSWER_SUCCEEDED); break;
    case OWNER_DECLINES: zapp_devkey_wait_answer(&a->fake->wait, a->ticket, zapp_devkey_answer_for_error(10)); break;
    case OWNER_NO_LOCK: zapp_devkey_wait_answer(&a->fake->wait, a->ticket, zapp_devkey_answer_for_error(14)); break;
    case OWNER_FAILS: zapp_devkey_wait_answer(&a->fake->wait, a->ticket, zapp_devkey_answer_for_error(1)); break;
    case OWNER_DESTROYS_ACTIVITY: zapp_devkey_wait_abandon(&a->fake->wait); break;
    }
    return NULL;
}
/* One prompt. Returns the status the backend would return; OK means the operation may run. */
static enum zapp_devkey_status f_prompt(struct fake *f)
{
    f->prompts++;
    if (!f->wait_mode) {
        switch (f->owner) {
        case OWNER_ACCEPTS: return ZAPP_DEVKEY_OK;
        case OWNER_DECLINES: case OWNER_DESTROYS_ACTIVITY: return ZAPP_DEVKEY_DECLINED;
        case OWNER_NO_LOCK: return ZAPP_DEVKEY_NO_SCREEN_LOCK;
        case OWNER_FAILS: return ZAPP_DEVKEY_ERROR;
        }
    }
    unsigned long ticket = zapp_devkey_wait_begin(&f->wait);
    struct answering a = {f, ticket};
    pthread_t thread;
    assert(ticket && pthread_create(&thread, NULL, owner_thread, &a) == 0);
    enum zapp_devkey_answer answer = zapp_devkey_wait_end(&f->wait, ticket, 5000);
    assert(pthread_join(thread, NULL) == 0);
    return zapp_devkey_status_for_answer(answer);
}
static enum zapp_devkey_status f_seal(void *c, const uint8_t *plain, size_t len, uint8_t iv[ZAPP_DEVKEY_IV], uint8_t sealed[ZAPP_DEVKEY_SEALED])
{
    struct fake *f = c;
    if (!f->has_key) return ZAPP_DEVKEY_NOT_FOUND;
    enum zapp_devkey_status st = f_prompt(f);
    if (st != ZAPP_DEVKEY_OK) return st;
    for (size_t i = 0; i < ZAPP_DEVKEY_IV; ++i) iv[i] = (uint8_t)(0xC0 + i);
    for (size_t i = 0; i < len; ++i) sealed[i] = plain[i] ^ 0x5A;
    for (size_t i = len; i < ZAPP_DEVKEY_SEALED; ++i) sealed[i] = 0x77;
    sealed[ZAPP_DEVKEY_SEALED - 1] = (uint8_t)f->key_id;
    if (f->race_path) put_file(f->race_path, "raced-blob", 10);
    return ZAPP_DEVKEY_OK;
}
static enum zapp_devkey_status f_open(void *c, enum zapp_devkey_purpose purpose, const uint8_t iv[ZAPP_DEVKEY_IV],
                                      const uint8_t sealed[ZAPP_DEVKEY_SEALED], uint8_t *plain, size_t cap)
{
    struct fake *f = c;
    memset(plain, 0xEE, cap); /* Garbage a failing backend may leave behind. */
    if (!f->has_key) return ZAPP_DEVKEY_NOT_FOUND;
    if (f->invalidated) return ZAPP_DEVKEY_INVALIDATED;
    f->last_purpose = purpose;
    enum zapp_devkey_status st = f_prompt(f);
    if (st != ZAPP_DEVKEY_OK) return st;
    if (iv[0] != 0xC0 || sealed[40] != 0x77 || sealed[ZAPP_DEVKEY_SEALED - 1] != (uint8_t)f->key_id) return ZAPP_DEVKEY_CORRUPT;
    for (size_t i = 0; i < cap; ++i) plain[i] = sealed[i] ^ 0x5A;
    return ZAPP_DEVKEY_OK;
}
static struct zapp_devkey_ops ops_for(struct fake *f)
{
    return (struct zapp_devkey_ops){f, f_random, f_secure, f_create, f_policy, f_seal, f_open, f_delete};
}
static bool all_zero(const uint8_t *bytes, size_t len)
{
    for (size_t i = 0; i < len; ++i) if (bytes[i]) return false;
    return true;
}
static void blob_path(char *out, const char *dir, const char *name) { snprintf(out, PATH_MAX, "%s/%s", dir, name); }
static size_t file_size(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 ? (size_t)st.st_size : (size_t)-1;
}
static void put_file(const char *path, const void *data, size_t len)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0 && write(fd, data, len) == (ssize_t)len && close(fd) == 0);
}
static void get_file(const char *path, uint8_t *out, size_t len)
{
    int fd = open(path, O_RDONLY);
    assert(fd >= 0 && read(fd, out, len) == (ssize_t)len && close(fd) == 0);
}
static double now_seconds(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static void refuses_without_screen_lock(const char *dir)
{
    struct fake f = fake_new(); f.secure = false;
    struct zapp_devkey_ops ops = ops_for(&f);
    char path[PATH_MAX]; blob_path(path, dir, "nolock.blob");
    uint8_t secret[ZAPP_DEVKEY_SECRET]; memset(secret, 0xAA, sizeof(secret));
    assert(zapp_devkey_wrap_new(&ops, path, secret) == ZAPP_DEVKEY_NO_SCREEN_LOCK);
    assert(f.creates == 0 && !f.has_key && f.prompts == 0);
    assert(all_zero(secret, sizeof(secret)));
    assert(access(path, F_OK) != 0);
}
static void unwrap_refuses_without_screen_lock_before_any_prompt(const char *dir)
{
    struct fake f = fake_new(); struct zapp_devkey_ops ops = ops_for(&f);
    char path[PATH_MAX]; blob_path(path, dir, "lockgone.blob");
    uint8_t secret[ZAPP_DEVKEY_SECRET];
    assert(zapp_devkey_wrap_new(&ops, path, secret) == ZAPP_DEVKEY_OK && f.prompts == 1);
    f.secure = false; memset(secret, 0xAA, sizeof(secret));
    assert(zapp_devkey_unwrap(&ops, path, ZAPP_DEVKEY_PURPOSE_UNLOCK, secret) == ZAPP_DEVKEY_NO_SCREEN_LOCK);
    assert(f.prompts == 1 && all_zero(secret, sizeof(secret)) && file_size(path) == 66);
}
static void prepare_prefers_strongbox_and_reports_fallback(void)
{
    struct fake f = fake_new(); struct zapp_devkey_info info;
    struct zapp_devkey_ops ops = ops_for(&f);
    assert(zapp_devkey_prepare(&ops, NULL, &info) == ZAPP_DEVKEY_OK);
    assert(info.level == ZAPP_DEVKEY_LEVEL_STRONGBOX && !info.strongbox_fallback && f.creates == 1);
    assert(zapp_devkey_prepare(&ops, NULL, &info) == ZAPP_DEVKEY_OK && f.creates == 1);
    struct fake g = fake_new(); g.strongbox_ok = false;
    ops = ops_for(&g);
    assert(zapp_devkey_prepare(&ops, NULL, &info) == ZAPP_DEVKEY_OK);
    assert(g.strongbox_tries == 1 && g.creates == 2);
    assert(info.level == ZAPP_DEVKEY_LEVEL_SECURE_HARDWARE && info.strongbox_fallback);
    assert(f.prompts == 0 && g.prompts == 0);
}
static void refuses_software_keys(void)
{
    struct fake f = fake_new(); f.strongbox_ok = false; f.level_if_created = ZAPP_DEVKEY_LEVEL_SOFTWARE;
    struct zapp_devkey_ops ops = ops_for(&f); struct zapp_devkey_info info;
    assert(zapp_devkey_prepare(&ops, NULL, &info) == ZAPP_DEVKEY_NOT_HARDWARE);
    assert(f.deletes == 1 && !f.has_key);
}
static void refuses_keys_that_are_not_per_use(const char *dir)
{
    struct fake f = fake_new(); f.per_use = false;
    struct zapp_devkey_ops ops = ops_for(&f); struct zapp_devkey_info info;
    char path[PATH_MAX]; blob_path(path, dir, "weak.blob");
    uint8_t secret[ZAPP_DEVKEY_SECRET];
    assert(zapp_devkey_prepare(&ops, NULL, &info) == ZAPP_DEVKEY_NOT_PER_USE);
    assert(f.deletes == 1 && !f.has_key);
    assert(zapp_devkey_wrap_new(&ops, path, secret) == ZAPP_DEVKEY_NOT_PER_USE && f.prompts == 0);
    assert(access(path, F_OK) != 0 && all_zero(secret, sizeof(secret)));
    /* A key found in the keystore is refused but never deleted. */
    struct fake g = fake_new(); g.has_key = true; g.key_id = 1; g.per_use = false;
    ops = ops_for(&g);
    assert(zapp_devkey_prepare(&ops, NULL, &info) == ZAPP_DEVKEY_NOT_PER_USE && g.deletes == 0 && g.has_key);
}
static void round_trip_and_blob_shape(const char *dir)
{
    struct fake f = fake_new(); struct zapp_devkey_ops ops = ops_for(&f);
    char path[PATH_MAX], tmp[PATH_MAX]; blob_path(path, dir, "ok.blob"); blob_path(tmp, dir, "ok.blob.tmp");
    uint8_t made[ZAPP_DEVKEY_SECRET], again[ZAPP_DEVKEY_SECRET], expect[ZAPP_DEVKEY_SECRET];
    assert(zapp_devkey_wrap_new(&ops, path, made) == ZAPP_DEVKEY_OK);
    for (size_t i = 0; i < sizeof(expect); ++i) expect[i] = (uint8_t)(0x40 + i);
    assert(!memcmp(made, expect, sizeof(made)));
    struct stat st; assert(stat(path, &st) == 0);
    assert((st.st_mode & 0777) == 0600 && S_ISREG(st.st_mode) && st.st_size == 66);
    assert(access(tmp, F_OK) != 0);
    uint8_t blob[66]; get_file(path, blob, 66);
    assert(!memcmp(blob, "ZDK2", 4) && blob[4] == 12 && blob[5] == 48);
    for (size_t i = 0; i + sizeof(made) <= sizeof(blob); ++i) assert(memcmp(blob + i, made, sizeof(made)));
    assert(zapp_devkey_unwrap(&ops, path, ZAPP_DEVKEY_PURPOSE_UNLOCK, again) == ZAPP_DEVKEY_OK);
    assert(!memcmp(again, made, sizeof(made)));
}
static void system_random_differs(const char *dir)
{
    struct fake f = fake_new(); struct zapp_devkey_ops ops = ops_for(&f); ops.random = NULL;
    char one[PATH_MAX], two[PATH_MAX]; blob_path(one, dir, "r1.blob"); blob_path(two, dir, "r2.blob");
    uint8_t a[ZAPP_DEVKEY_SECRET], b[ZAPP_DEVKEY_SECRET];
    assert(zapp_devkey_wrap_new(&ops, one, a) == ZAPP_DEVKEY_OK && zapp_devkey_wrap_new(&ops, two, b) == ZAPP_DEVKEY_OK);
    assert(memcmp(a, b, sizeof(a)) && !all_zero(a, sizeof(a)) && !all_zero(b, sizeof(b)));
}

/* Rule: every unwrap is its own prompt. A second call, a retry and a call right after a success
 * never reuse an earlier authentication, and the module remembers no secret between calls. */
static void every_unwrap_costs_one_prompt(const char *dir)
{
    struct fake f = fake_new(); struct zapp_devkey_ops ops = ops_for(&f);
    char path[PATH_MAX]; blob_path(path, dir, "once.blob");
    uint8_t made[ZAPP_DEVKEY_SECRET], a[ZAPP_DEVKEY_SECRET], b[ZAPP_DEVKEY_SECRET], c[ZAPP_DEVKEY_SECRET];
    assert(zapp_devkey_wrap_new(&ops, path, made) == ZAPP_DEVKEY_OK && f.prompts == 1);
    assert(zapp_devkey_unwrap(&ops, path, ZAPP_DEVKEY_PURPOSE_UNLOCK, a) == ZAPP_DEVKEY_OK && f.prompts == 2);
    assert(f.last_purpose == ZAPP_DEVKEY_PURPOSE_UNLOCK);
    assert(zapp_devkey_unwrap(&ops, path, ZAPP_DEVKEY_PURPOSE_PAYMENT, b) == ZAPP_DEVKEY_OK && f.prompts == 3);
    assert(f.last_purpose == ZAPP_DEVKEY_PURPOSE_PAYMENT);
    assert(zapp_devkey_unwrap(&ops, path, ZAPP_DEVKEY_PURPOSE_PAYMENT, c) == ZAPP_DEVKEY_OK && f.prompts == 4);
    assert(!memcmp(a, made, sizeof(a)) && !memcmp(b, made, sizeof(b)) && !memcmp(c, made, sizeof(c)));
}
/* Rule: a declined prompt yields no secret, does not touch the blob or the key, and does not make
 * the next call succeed without its own prompt (Back, then resume or retry, asks again). */
static void decline_is_typed_and_does_not_latch(const char *dir)
{
    struct fake f = fake_new(); struct zapp_devkey_ops ops = ops_for(&f);
    char path[PATH_MAX]; blob_path(path, dir, "decline.blob");
    uint8_t made[ZAPP_DEVKEY_SECRET], secret[ZAPP_DEVKEY_SECRET], before[66], after[66];
    assert(zapp_devkey_wrap_new(&ops, path, made) == ZAPP_DEVKEY_OK);
    get_file(path, before, 66);
    f.owner = OWNER_DECLINES; memset(secret, 0xAA, sizeof(secret));
    assert(zapp_devkey_unwrap(&ops, path, ZAPP_DEVKEY_PURPOSE_UNLOCK, secret) == ZAPP_DEVKEY_DECLINED);
    assert(all_zero(secret, sizeof(secret)) && f.prompts == 2);
    assert(zapp_devkey_unwrap(&ops, path, ZAPP_DEVKEY_PURPOSE_UNLOCK, secret) == ZAPP_DEVKEY_DECLINED && f.prompts == 3);
    assert(f.has_key && f.deletes == 0);
    get_file(path, after, 66); assert(!memcmp(before, after, 66));
    f.owner = OWNER_ACCEPTS;
    assert(zapp_devkey_unwrap(&ops, path, ZAPP_DEVKEY_PURPOSE_UNLOCK, secret) == ZAPP_DEVKEY_OK && f.prompts == 4);
    assert(!memcmp(secret, made, sizeof(made)));
}
static void declined_creation_leaves_nothing(const char *dir)
{
    struct fake f = fake_new(); f.owner = OWNER_DECLINES;
    struct zapp_devkey_ops ops = ops_for(&f);
    char path[PATH_MAX], tmp[PATH_MAX]; blob_path(path, dir, "nocreate.blob"); blob_path(tmp, dir, "nocreate.blob.tmp");
    uint8_t secret[ZAPP_DEVKEY_SECRET]; memset(secret, 0xAA, sizeof(secret));
    assert(zapp_devkey_wrap_new(&ops, path, secret) == ZAPP_DEVKEY_DECLINED && f.prompts == 1);
    assert(all_zero(secret, sizeof(secret)) && access(path, F_OK) != 0 && access(tmp, F_OK) != 0);
}
/* Rule: a gone or invalidated key is its own refusal, and a prompt is not shown for it. */
static void key_gone_or_invalidated_is_distinct(const char *dir)
{
    struct fake f = fake_new(); struct zapp_devkey_ops ops = ops_for(&f);
    char path[PATH_MAX]; blob_path(path, dir, "inv.blob");
    uint8_t secret[ZAPP_DEVKEY_SECRET];
    assert(zapp_devkey_wrap_new(&ops, path, secret) == ZAPP_DEVKEY_OK);
    int prompts = f.prompts;
    f.invalidated = true; memset(secret, 0xAA, sizeof(secret));
    assert(zapp_devkey_unwrap(&ops, path, ZAPP_DEVKEY_PURPOSE_PAYMENT, secret) == ZAPP_DEVKEY_INVALIDATED && all_zero(secret, sizeof(secret)));
    f.invalidated = false; f.has_key = false; memset(secret, 0xAA, sizeof(secret));
    assert(zapp_devkey_unwrap(&ops, path, ZAPP_DEVKEY_PURPOSE_PAYMENT, secret) == ZAPP_DEVKEY_INVALIDATED && all_zero(secret, sizeof(secret)));
    assert(f.prompts == prompts);
    f.has_key = true; f.vanish_after_policy = true; memset(secret, 0xAA, sizeof(secret));
    assert(zapp_devkey_unwrap(&ops, path, ZAPP_DEVKEY_PURPOSE_PAYMENT, secret) == ZAPP_DEVKEY_INVALIDATED && all_zero(secret, sizeof(secret)));
    assert(f.prompts == prompts);
    assert(strcmp(zapp_devkey_status_name(ZAPP_DEVKEY_INVALIDATED), zapp_devkey_status_name(ZAPP_DEVKEY_DECLINED)));
}
/* Rule: the owner losing the lock screen or a backend failure are typed, leave no secret, and
 * nothing else a backend might say passes through as a success or a new kind of refusal. */
static void no_lock_and_errors_are_typed(const char *dir)
{
    struct fake f = fake_new(); struct zapp_devkey_ops ops = ops_for(&f);
    char path[PATH_MAX]; blob_path(path, dir, "lockerr.blob");
    uint8_t secret[ZAPP_DEVKEY_SECRET];
    assert(zapp_devkey_wrap_new(&ops, path, secret) == ZAPP_DEVKEY_OK);
    f.owner = OWNER_NO_LOCK; memset(secret, 0xAA, sizeof(secret));
    assert(zapp_devkey_unwrap(&ops, path, ZAPP_DEVKEY_PURPOSE_UNLOCK, secret) == ZAPP_DEVKEY_NO_SCREEN_LOCK && all_zero(secret, sizeof(secret)));
    f.owner = OWNER_FAILS; memset(secret, 0xAA, sizeof(secret));
    assert(zapp_devkey_unwrap(&ops, path, ZAPP_DEVKEY_PURPOSE_UNLOCK, secret) == ZAPP_DEVKEY_ERROR && all_zero(secret, sizeof(secret)));
}
/* Rule: the activity being destroyed during a prompt ends the wait with a refusal and no secret. */
static void activity_destroyed_during_prompt(const char *dir)
{
    struct fake f = fake_new(); struct zapp_devkey_ops ops = ops_for(&f);
    char path[PATH_MAX], tmp[PATH_MAX]; blob_path(path, dir, "destroyed.blob"); blob_path(tmp, dir, "destroyed.blob.tmp");
    uint8_t made[ZAPP_DEVKEY_SECRET], secret[ZAPP_DEVKEY_SECRET];
    f.wait_mode = true;
    assert(zapp_devkey_wrap_new(&ops, path, made) == ZAPP_DEVKEY_OK);
    f.owner = OWNER_DESTROYS_ACTIVITY; memset(secret, 0xAA, sizeof(secret));
    double start = now_seconds();
    assert(zapp_devkey_unwrap(&ops, path, ZAPP_DEVKEY_PURPOSE_PAYMENT, secret) == ZAPP_DEVKEY_DECLINED);
    assert(now_seconds() - start < 2.0 && all_zero(secret, sizeof(secret)) && f.has_key);
    /* The same during creation: no blob, no temporary file. */
    char fresh[PATH_MAX]; blob_path(fresh, dir, "destroyed-new.blob");
    assert(zapp_devkey_wrap_new(&ops, fresh, secret) == ZAPP_DEVKEY_DECLINED && access(fresh, F_OK) != 0);
    f.owner = OWNER_ACCEPTS;
    assert(zapp_devkey_unwrap(&ops, path, ZAPP_DEVKEY_PURPOSE_PAYMENT, secret) == ZAPP_DEVKEY_OK && !memcmp(secret, made, sizeof(made)));
    (void)tmp;
}
/* Rule: no secret stays behind. A backend that writes plaintext and then fails (the fake writes
 * garbage first) leaves the caller's buffer zero on every refusal. */
static void failures_leave_no_secret_and_no_file(const char *dir)
{
    struct fake f = fake_new(); struct zapp_devkey_ops ops = ops_for(&f);
    char path[PATH_MAX], gone[PATH_MAX]; blob_path(path, dir, "rnd.blob"); blob_path(gone, dir, "missing/x.blob");
    uint8_t secret[ZAPP_DEVKEY_SECRET]; memset(secret, 0xAA, sizeof(secret));
    f.random_ok = false;
    assert(zapp_devkey_wrap_new(&ops, path, secret) == ZAPP_DEVKEY_ERROR && all_zero(secret, sizeof(secret)));
    assert(access(path, F_OK) != 0);
    f.random_ok = true;
    assert(zapp_devkey_wrap_new(&ops, gone, secret) == ZAPP_DEVKEY_ERROR && all_zero(secret, sizeof(secret)));
}
static void garbage_never_reaches_the_caller(const char *dir)
{
    struct fake f = fake_new(); struct zapp_devkey_ops ops = ops_for(&f);
    char path[PATH_MAX]; blob_path(path, dir, "garbage.blob");
    uint8_t secret[ZAPP_DEVKEY_SECRET];
    assert(zapp_devkey_wrap_new(&ops, path, secret) == ZAPP_DEVKEY_OK);
    enum owner refusals[] = {OWNER_DECLINES, OWNER_NO_LOCK, OWNER_FAILS};
    for (size_t i = 0; i < sizeof(refusals) / sizeof(refusals[0]); ++i) {
        f.owner = refusals[i]; memset(secret, 0xAA, sizeof(secret));
        assert(zapp_devkey_unwrap(&ops, path, ZAPP_DEVKEY_PURPOSE_UNLOCK, secret) != ZAPP_DEVKEY_OK);
        assert(all_zero(secret, sizeof(secret)));
    }
}
/* Rule: unwrap checks the stored key's policy itself, before any prompt: a key that is not per-use
 * (or not hardware) never opens a blob, even when prepare was skipped or the key was replaced. */
static void unwrap_checks_key_policy_before_prompt(const char *dir)
{
    struct fake f = fake_new(); struct zapp_devkey_ops ops = ops_for(&f);
    char path[PATH_MAX]; blob_path(path, dir, "policy.blob");
    uint8_t made[ZAPP_DEVKEY_SECRET], secret[ZAPP_DEVKEY_SECRET];
    assert(zapp_devkey_wrap_new(&ops, path, made) == ZAPP_DEVKEY_OK);
    int prompts = f.prompts;
    f.per_use = false; memset(secret, 0xAA, sizeof(secret));
    assert(zapp_devkey_unwrap(&ops, path, ZAPP_DEVKEY_PURPOSE_PAYMENT, secret) == ZAPP_DEVKEY_NOT_PER_USE);
    assert(f.prompts == prompts && all_zero(secret, sizeof(secret)) && f.has_key && f.deletes == 0);
    f.per_use = true; f.level_if_created = ZAPP_DEVKEY_LEVEL_SOFTWARE;
    assert(zapp_devkey_unwrap(&ops, path, ZAPP_DEVKEY_PURPOSE_PAYMENT, secret) == ZAPP_DEVKEY_NOT_HARDWARE);
    assert(f.prompts == prompts && all_zero(secret, sizeof(secret)));
    f.level_if_created = ZAPP_DEVKEY_LEVEL_STRONGBOX; f.level_error = ZAPP_DEVKEY_ERROR;
    assert(zapp_devkey_unwrap(&ops, path, ZAPP_DEVKEY_PURPOSE_PAYMENT, secret) == ZAPP_DEVKEY_ERROR && f.prompts == prompts);
    f.level_error = ZAPP_DEVKEY_OK;
    assert(zapp_devkey_unwrap(&ops, path, ZAPP_DEVKEY_PURPOSE_PAYMENT, secret) == ZAPP_DEVKEY_OK && !memcmp(secret, made, sizeof(made)));
}
/* Rule: only unlock and payment may open a blob; the create purpose names a different action and is
 * refused before any prompt, so the owner is never told "Protect this wallet" while a secret is read. */
static void unwrap_refuses_the_create_purpose(const char *dir)
{
    struct fake f = fake_new(); struct zapp_devkey_ops ops = ops_for(&f);
    char path[PATH_MAX]; blob_path(path, dir, "purpose.blob");
    uint8_t secret[ZAPP_DEVKEY_SECRET];
    assert(zapp_devkey_wrap_new(&ops, path, secret) == ZAPP_DEVKEY_OK);
    int prompts = f.prompts; memset(secret, 0xAA, sizeof(secret));
    assert(zapp_devkey_unwrap(&ops, path, ZAPP_DEVKEY_PURPOSE_CREATE, secret) == ZAPP_DEVKEY_ERROR);
    assert(f.prompts == prompts && all_zero(secret, sizeof(secret)));
    assert(zapp_devkey_unwrap(&ops, path, (enum zapp_devkey_purpose)7, secret) == ZAPP_DEVKEY_ERROR && f.prompts == prompts);
}
/* Rule: a blob from the 30 second window design is refused with its own reason and never opened. */
static void old_format_blob_is_refused(const char *dir)
{
    struct fake f = fake_new(); struct zapp_devkey_ops ops = ops_for(&f);
    char good[PATH_MAX], old[PATH_MAX]; blob_path(good, dir, "new.blob"); blob_path(old, dir, "old.blob");
    uint8_t secret[ZAPP_DEVKEY_SECRET], blob[66], again[66];
    assert(zapp_devkey_wrap_new(&ops, good, secret) == ZAPP_DEVKEY_OK);
    get_file(good, blob, 66); blob[3] = '1';
    put_file(old, blob, 66);
    int prompts = f.prompts; memset(secret, 0xAA, sizeof(secret));
    assert(zapp_devkey_unwrap(&ops, old, ZAPP_DEVKEY_PURPOSE_UNLOCK, secret) == ZAPP_DEVKEY_OLD_FORMAT);
    assert(f.prompts == prompts && all_zero(secret, sizeof(secret)));
    get_file(old, again, 66); assert(!memcmp(blob, again, 66));
    assert(zapp_devkey_wrap_new(&ops, old, secret) == ZAPP_DEVKEY_EXISTS);
    assert(strcmp(zapp_devkey_status_name(ZAPP_DEVKEY_OLD_FORMAT), zapp_devkey_status_name(ZAPP_DEVKEY_CORRUPT)));
}
static void existing_blob_is_never_replaced(const char *dir)
{
    struct fake f = fake_new(); struct zapp_devkey_ops ops = ops_for(&f);
    char path[PATH_MAX]; blob_path(path, dir, "keep.blob");
    uint8_t first[ZAPP_DEVKEY_SECRET], second[ZAPP_DEVKEY_SECRET], before[66], after[66];
    assert(zapp_devkey_wrap_new(&ops, path, first) == ZAPP_DEVKEY_OK);
    get_file(path, before, 66);
    assert(zapp_devkey_wrap_new(&ops, path, second) == ZAPP_DEVKEY_EXISTS && all_zero(second, sizeof(second)));
    get_file(path, after, 66);
    assert(!memcmp(before, after, 66));
}
static void malformed_blobs_are_corrupt(const char *dir)
{
    struct fake f = fake_new(); struct zapp_devkey_ops ops = ops_for(&f);
    char good[PATH_MAX], bad[PATH_MAX]; blob_path(good, dir, "src.blob"); blob_path(bad, dir, "bad.blob");
    uint8_t secret[ZAPP_DEVKEY_SECRET], blob[67] = {0};
    assert(zapp_devkey_unwrap(&ops, bad, ZAPP_DEVKEY_PURPOSE_UNLOCK, secret) == ZAPP_DEVKEY_NOT_FOUND);
    assert(zapp_devkey_wrap_new(&ops, good, secret) == ZAPP_DEVKEY_OK);
    get_file(good, blob, 66);
    put_file(bad, blob, 65); assert(zapp_devkey_unwrap(&ops, bad, ZAPP_DEVKEY_PURPOSE_UNLOCK, secret) == ZAPP_DEVKEY_CORRUPT);
    put_file(bad, blob, 67); assert(zapp_devkey_unwrap(&ops, bad, ZAPP_DEVKEY_PURPOSE_UNLOCK, secret) == ZAPP_DEVKEY_CORRUPT);
    blob[0] = 'X'; put_file(bad, blob, 66); assert(zapp_devkey_unwrap(&ops, bad, ZAPP_DEVKEY_PURPOSE_UNLOCK, secret) == ZAPP_DEVKEY_CORRUPT);
    blob[0] = 'Z'; blob[4] = 16; put_file(bad, blob, 66); assert(zapp_devkey_unwrap(&ops, bad, ZAPP_DEVKEY_PURPOSE_UNLOCK, secret) == ZAPP_DEVKEY_CORRUPT);
    blob[4] = 12; blob[6] ^= 1; put_file(bad, blob, 66); assert(zapp_devkey_unwrap(&ops, bad, ZAPP_DEVKEY_PURPOSE_UNLOCK, secret) == ZAPP_DEVKEY_CORRUPT);
    blob[6] ^= 1; blob[6 + 12 + 40] ^= 1; put_file(bad, blob, 66);
    assert(zapp_devkey_unwrap(&ops, bad, ZAPP_DEVKEY_PURPOSE_UNLOCK, secret) == ZAPP_DEVKEY_CORRUPT && all_zero(secret, sizeof(secret)));
    assert(file_size(bad) == 66);
}
static void discard_removes_blob_and_key(const char *dir)
{
    struct fake f = fake_new(); struct zapp_devkey_ops ops = ops_for(&f);
    char path[PATH_MAX]; blob_path(path, dir, "gone.blob");
    uint8_t secret[ZAPP_DEVKEY_SECRET];
    assert(zapp_devkey_wrap_new(&ops, path, secret) == ZAPP_DEVKEY_OK);
    zapp_devkey_discard(&ops, path);
    assert(access(path, F_OK) != 0 && !f.has_key && f.deletes == 1);
}
static void concurrent_blob_is_never_replaced(const char *dir)
{
    struct fake f = fake_new(); struct zapp_devkey_ops ops = ops_for(&f);
    char path[PATH_MAX], tmp[PATH_MAX]; blob_path(path, dir, "race.blob"); blob_path(tmp, dir, "race.blob.tmp");
    uint8_t secret[ZAPP_DEVKEY_SECRET], after[10];
    f.race_path = path;
    assert(zapp_devkey_wrap_new(&ops, path, secret) == ZAPP_DEVKEY_EXISTS && all_zero(secret, sizeof(secret)));
    get_file(path, after, 10);
    assert(file_size(path) == 10 && !memcmp(after, "raced-blob", 10) && access(tmp, F_OK) != 0);
}
static void lost_key_is_not_replaced(const char *dir)
{
    struct fake f = fake_new(); struct zapp_devkey_ops ops = ops_for(&f);
    char path[PATH_MAX]; blob_path(path, dir, "lost.blob");
    uint8_t secret[ZAPP_DEVKEY_SECRET];
    assert(zapp_devkey_wrap_new(&ops, path, secret) == ZAPP_DEVKEY_OK);
    f.has_key = false;
    int creates = f.creates;
    assert(zapp_devkey_wrap_new(&ops, path, secret) == ZAPP_DEVKEY_EXISTS);
    assert(zapp_devkey_prepare(&ops, path, NULL) == ZAPP_DEVKEY_INVALIDATED);
    assert(f.creates == creates && !f.has_key);
    assert(zapp_devkey_unwrap(&ops, path, ZAPP_DEVKEY_PURPOSE_UNLOCK, secret) == ZAPP_DEVKEY_INVALIDATED && all_zero(secret, sizeof(secret)));
    assert(zapp_devkey_prepare(&ops, NULL, NULL) == ZAPP_DEVKEY_OK && f.has_key);
    assert(zapp_devkey_unwrap(&ops, path, ZAPP_DEVKEY_PURPOSE_UNLOCK, secret) == ZAPP_DEVKEY_CORRUPT && all_zero(secret, sizeof(secret)));
}
static void invalidated_key_is_reported(const char *dir)
{
    struct fake f = fake_new(); struct zapp_devkey_ops ops = ops_for(&f);
    char path[PATH_MAX]; blob_path(path, dir, "invkey.blob");
    uint8_t secret[ZAPP_DEVKEY_SECRET];
    assert(zapp_devkey_prepare(&ops, NULL, NULL) == ZAPP_DEVKEY_OK);
    f.level_error = ZAPP_DEVKEY_INVALIDATED;
    assert(zapp_devkey_prepare(&ops, NULL, NULL) == ZAPP_DEVKEY_INVALIDATED);
    assert(zapp_devkey_wrap_new(&ops, path, secret) == ZAPP_DEVKEY_INVALIDATED && all_zero(secret, sizeof(secret)));
    assert(f.deletes == 0 && access(path, F_OK) != 0);
    f.level_error = ZAPP_DEVKEY_ERROR;
    assert(zapp_devkey_prepare(&ops, NULL, NULL) == ZAPP_DEVKEY_ERROR);
}
static void existing_keys_are_never_deleted(void)
{
    struct fake f = fake_new(); struct zapp_devkey_ops ops = ops_for(&f);
    f.has_key = true; f.key_id = 1; f.level_if_created = ZAPP_DEVKEY_LEVEL_UNKNOWN;
    assert(zapp_devkey_prepare(&ops, NULL, NULL) == ZAPP_DEVKEY_NOT_HARDWARE);
    assert(f.deletes == 0 && f.has_key && f.creates == 0);
    f.level_if_created = ZAPP_DEVKEY_LEVEL_SOFTWARE;
    assert(zapp_devkey_prepare(&ops, NULL, NULL) == ZAPP_DEVKEY_NOT_HARDWARE && f.deletes == 0 && f.has_key);
}
static void only_strongbox_unavailable_falls_back(void)
{
    struct fake f = fake_new(); struct zapp_devkey_ops ops = ops_for(&f);
    f.strongbox_error = ZAPP_DEVKEY_ERROR;
    assert(zapp_devkey_prepare(&ops, NULL, NULL) == ZAPP_DEVKEY_ERROR);
    assert(f.creates == 1 && f.strongbox_tries == 1 && !f.has_key);
}
static void exception_chains_map_to_statuses(void)
{
    const unsigned gone[] = {ZAPP_DEVKEY_EX_UNRECOVERABLE_KEY};
    const unsigned wrapped[] = {ZAPP_DEVKEY_EX_UNRECOVERABLE_KEY, 0};
    const unsigned invalidated[] = {0, ZAPP_DEVKEY_EX_PERMANENTLY_INVALIDATED};
    const unsigned unknown_alg[] = {ZAPP_DEVKEY_EX_UNRECOVERABLE_KEY | ZAPP_DEVKEY_EX_UNKNOWN_ALGORITHM};
    const unsigned tag[] = {ZAPP_DEVKEY_EX_BAD_TAG};
    const unsigned strongbox[] = {0, ZAPP_DEVKEY_EX_STRONGBOX_UNAVAILABLE};
    const unsigned provider[] = {0, 0};
    assert(zapp_devkey_classify_chain(gone, 1) == ZAPP_DEVKEY_INVALIDATED);
    assert(zapp_devkey_classify_chain(unknown_alg, 1) == ZAPP_DEVKEY_ERROR);
    assert(zapp_devkey_classify_chain(wrapped, 2) == ZAPP_DEVKEY_ERROR);
    assert(zapp_devkey_classify_chain(invalidated, 2) == ZAPP_DEVKEY_INVALIDATED);
    assert(zapp_devkey_classify_chain(tag, 1) == ZAPP_DEVKEY_CORRUPT);
    assert(zapp_devkey_classify_chain(strongbox, 2) == ZAPP_DEVKEY_STRONGBOX_UNAVAILABLE);
    assert(zapp_devkey_classify_chain(provider, 2) == ZAPP_DEVKEY_ERROR && zapp_devkey_classify_chain(provider, 0) == ZAPP_DEVKEY_ERROR);
}

/* The wait primitives the JNI backend shares with the fake above. */
struct late { struct zapp_devkey_wait *wait; unsigned long ticket; enum zapp_devkey_answer answer; bool abandon; };
static void *late_answer(void *arg)
{
    struct late *l = arg;
    struct timespec pause = {0, 30 * 1000 * 1000};
    nanosleep(&pause, NULL);
    if (l->abandon) zapp_devkey_wait_abandon(l->wait);
    else zapp_devkey_wait_answer(l->wait, l->ticket, l->answer);
    return NULL;
}
static void wait_answers_and_retires(void)
{
    struct zapp_devkey_wait w = ZAPP_DEVKEY_WAIT_INIT;
    unsigned long t = zapp_devkey_wait_begin(&w);
    assert(t != 0 && zapp_devkey_wait_begin(&w) == 0);           /* One prompt at a time. */
    assert(zapp_devkey_wait_answer(&w, t, ZAPP_DEVKEY_ANSWER_DECLINED));
    assert(!zapp_devkey_wait_answer(&w, t, ZAPP_DEVKEY_ANSWER_SUCCEEDED));   /* First answer wins. */
    assert(zapp_devkey_wait_end(&w, t, 1000) == ZAPP_DEVKEY_ANSWER_DECLINED);
    assert(!zapp_devkey_wait_answer(&w, t, ZAPP_DEVKEY_ANSWER_SUCCEEDED));   /* Retired. */
    unsigned long u = zapp_devkey_wait_begin(&w);
    assert(u != 0 && u != t);
    assert(!zapp_devkey_wait_answer(&w, t, ZAPP_DEVKEY_ANSWER_SUCCEEDED));   /* A late answer of the old prompt. */
    assert(zapp_devkey_wait_end(&w, u, 30) == ZAPP_DEVKEY_ANSWER_TIMED_OUT);
    assert(!zapp_devkey_wait_answer(&w, u, ZAPP_DEVKEY_ANSWER_SUCCEEDED));   /* Answer after the timeout. */
    assert(!zapp_devkey_wait_answer(&w, 0, ZAPP_DEVKEY_ANSWER_SUCCEEDED) && !zapp_devkey_wait_abandon(&w));
}
static void wait_wakes_on_answer_and_on_abandon(void)
{
    struct zapp_devkey_wait w = ZAPP_DEVKEY_WAIT_INIT;
    struct late l = {&w, 0, ZAPP_DEVKEY_ANSWER_SUCCEEDED, false};
    pthread_t thread;
    l.ticket = zapp_devkey_wait_begin(&w);
    assert(pthread_create(&thread, NULL, late_answer, &l) == 0);
    double start = now_seconds();
    assert(zapp_devkey_wait_end(&w, l.ticket, 10000) == ZAPP_DEVKEY_ANSWER_SUCCEEDED);
    assert(now_seconds() - start < 2.0 && pthread_join(thread, NULL) == 0);
    l.abandon = true;
    l.ticket = zapp_devkey_wait_begin(&w);
    assert(pthread_create(&thread, NULL, late_answer, &l) == 0);
    start = now_seconds();
    assert(zapp_devkey_wait_end(&w, l.ticket, 10000) == ZAPP_DEVKEY_ANSWER_ABANDONED);
    assert(now_seconds() - start < 2.0 && pthread_join(thread, NULL) == 0);
    assert(!zapp_devkey_wait_abandon(&w));
}
static void answers_map_to_typed_statuses(void)
{
    assert(zapp_devkey_status_for_answer(ZAPP_DEVKEY_ANSWER_SUCCEEDED) == ZAPP_DEVKEY_OK);
    assert(zapp_devkey_status_for_answer(ZAPP_DEVKEY_ANSWER_DECLINED) == ZAPP_DEVKEY_DECLINED);
    assert(zapp_devkey_status_for_answer(ZAPP_DEVKEY_ANSWER_ABANDONED) == ZAPP_DEVKEY_DECLINED);
    assert(zapp_devkey_status_for_answer(ZAPP_DEVKEY_ANSWER_NO_LOCK) == ZAPP_DEVKEY_NO_SCREEN_LOCK);
    assert(zapp_devkey_status_for_answer(ZAPP_DEVKEY_ANSWER_FAILED) == ZAPP_DEVKEY_ERROR);
    assert(zapp_devkey_status_for_answer(ZAPP_DEVKEY_ANSWER_TIMED_OUT) == ZAPP_DEVKEY_ERROR);
    assert(zapp_devkey_status_for_answer(ZAPP_DEVKEY_ANSWER_NONE) == ZAPP_DEVKEY_ERROR);
    /* BiometricPrompt codes: CANCELED 5, USER_CANCELED 10, NEGATIVE_BUTTON 13 decline; NO_BIOMETRICS 11
     * and NO_DEVICE_CREDENTIAL 14 mean no lock screen; lockout 7 and 9, HW_UNAVAILABLE 1 fail. */
    const int declined[] = {5, 10, 13}, no_lock[] = {11, 14}, failed[] = {1, 2, 3, 4, 7, 8, 9, 12, 15, 16, 0, -1};
    for (size_t i = 0; i < sizeof(declined) / sizeof(declined[0]); ++i) assert(zapp_devkey_answer_for_error(declined[i]) == ZAPP_DEVKEY_ANSWER_DECLINED);
    for (size_t i = 0; i < sizeof(no_lock) / sizeof(no_lock[0]); ++i) assert(zapp_devkey_answer_for_error(no_lock[i]) == ZAPP_DEVKEY_ANSWER_NO_LOCK);
    for (size_t i = 0; i < sizeof(failed) / sizeof(failed[0]); ++i) assert(zapp_devkey_answer_for_error(failed[i]) == ZAPP_DEVKEY_ANSWER_FAILED);
}
int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: device_key_test <scratch directory>\n"); return 2; }
    refuses_without_screen_lock(argv[1]);
    unwrap_refuses_without_screen_lock_before_any_prompt(argv[1]);
    prepare_prefers_strongbox_and_reports_fallback();
    refuses_software_keys();
    refuses_keys_that_are_not_per_use(argv[1]);
    round_trip_and_blob_shape(argv[1]);
    system_random_differs(argv[1]);
    every_unwrap_costs_one_prompt(argv[1]);
    decline_is_typed_and_does_not_latch(argv[1]);
    declined_creation_leaves_nothing(argv[1]);
    key_gone_or_invalidated_is_distinct(argv[1]);
    no_lock_and_errors_are_typed(argv[1]);
    activity_destroyed_during_prompt(argv[1]);
    failures_leave_no_secret_and_no_file(argv[1]);
    garbage_never_reaches_the_caller(argv[1]);
    old_format_blob_is_refused(argv[1]);
    unwrap_checks_key_policy_before_prompt(argv[1]);
    unwrap_refuses_the_create_purpose(argv[1]);
    existing_blob_is_never_replaced(argv[1]);
    malformed_blobs_are_corrupt(argv[1]);
    discard_removes_blob_and_key(argv[1]);
    concurrent_blob_is_never_replaced(argv[1]);
    lost_key_is_not_replaced(argv[1]);
    invalidated_key_is_reported(argv[1]);
    existing_keys_are_never_deleted();
    only_strongbox_unavailable_falls_back();
    exception_chains_map_to_statuses();
    wait_answers_and_retires();
    wait_wakes_on_answer_and_on_abandon();
    answers_map_to_typed_statuses();
    puts("device_key_test: ok");
    return 0;
}
