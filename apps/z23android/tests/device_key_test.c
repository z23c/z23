/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "device_key.h"
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void put_file(const char *path, const void *data, size_t len);

/* A keystore in memory: XOR sealing with a check tag, the 30 second window as a flag. */
struct fake {
    bool secure, has_key, fresh, invalidated, strongbox_ok, random_ok;
    enum zapp_devkey_level level_if_created;
    int creates, strongbox_tries, deletes, key_id, ids;
    uint8_t counter;
    enum zapp_devkey_status level_error, strongbox_error;
    const char *race_path;       /* A blob that appears while the secret is being sealed. */
};
static struct fake fake_new(void)
{
    return (struct fake){.secure = true, .fresh = true, .strongbox_ok = true, .random_ok = true,
                         .level_if_created = ZAPP_DEVKEY_LEVEL_STRONGBOX};
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
static enum zapp_devkey_status f_level(void *c, enum zapp_devkey_level *level)
{
    struct fake *f = c;
    if (!f->has_key) return ZAPP_DEVKEY_NOT_FOUND;
    if (f->level_error != ZAPP_DEVKEY_OK) return f->level_error;
    *level = f->level_if_created;
    return ZAPP_DEVKEY_OK;
}
static void f_delete(void *c) { struct fake *f = c; f->has_key = false; f->deletes++; }
static enum zapp_devkey_status f_seal(void *c, const uint8_t *plain, size_t len, uint8_t iv[ZAPP_DEVKEY_IV], uint8_t sealed[ZAPP_DEVKEY_SEALED])
{
    struct fake *f = c;
    if (!f->has_key) return ZAPP_DEVKEY_NOT_FOUND;
    if (!f->fresh) return ZAPP_DEVKEY_NEEDS_AUTH;
    for (size_t i = 0; i < ZAPP_DEVKEY_IV; ++i) iv[i] = (uint8_t)(0xC0 + i);
    for (size_t i = 0; i < len; ++i) sealed[i] = plain[i] ^ 0x5A;
    for (size_t i = len; i < ZAPP_DEVKEY_SEALED; ++i) sealed[i] = 0x77;
    sealed[ZAPP_DEVKEY_SEALED - 1] = (uint8_t)f->key_id;
    if (f->race_path) put_file(f->race_path, "raced-blob", 10);
    return ZAPP_DEVKEY_OK;
}
static enum zapp_devkey_status f_open(void *c, const uint8_t iv[ZAPP_DEVKEY_IV], const uint8_t sealed[ZAPP_DEVKEY_SEALED], uint8_t *plain, size_t cap)
{
    struct fake *f = c;
    memset(plain, 0xEE, cap); /* Garbage a failing backend may leave behind. */
    if (!f->has_key) return ZAPP_DEVKEY_NOT_FOUND;
    if (f->invalidated) return ZAPP_DEVKEY_INVALIDATED;
    if (!f->fresh) return ZAPP_DEVKEY_NEEDS_AUTH;
    if (iv[0] != 0xC0 || sealed[40] != 0x77 || sealed[ZAPP_DEVKEY_SEALED - 1] != (uint8_t)f->key_id) return ZAPP_DEVKEY_CORRUPT;
    for (size_t i = 0; i < cap; ++i) plain[i] = sealed[i] ^ 0x5A;
    return ZAPP_DEVKEY_OK;
}
static struct zapp_devkey_ops ops_for(struct fake *f)
{
    return (struct zapp_devkey_ops){f, f_random, f_secure, f_create, f_level, f_seal, f_open, f_delete};
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

static void refuses_without_screen_lock(const char *dir)
{
    struct fake f = fake_new(); f.secure = false;
    struct zapp_devkey_ops ops = ops_for(&f);
    char path[PATH_MAX]; blob_path(path, dir, "nolock.blob");
    uint8_t secret[ZAPP_DEVKEY_SECRET]; memset(secret, 0xAA, sizeof(secret));
    assert(zapp_devkey_wrap_new(&ops, path, secret) == ZAPP_DEVKEY_NO_SCREEN_LOCK);
    assert(f.creates == 0 && !f.has_key);
    assert(all_zero(secret, sizeof(secret)));
    assert(access(path, F_OK) != 0);
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
}
static void refuses_software_keys(void)
{
    struct fake f = fake_new(); f.strongbox_ok = false; f.level_if_created = ZAPP_DEVKEY_LEVEL_SOFTWARE;
    struct zapp_devkey_ops ops = ops_for(&f); struct zapp_devkey_info info;
    assert(zapp_devkey_prepare(&ops, NULL, &info) == ZAPP_DEVKEY_NOT_HARDWARE);
    assert(f.deletes == 1 && !f.has_key);
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
    uint8_t blob[66]; int fd = open(path, O_RDONLY); assert(fd >= 0 && read(fd, blob, 66) == 66); close(fd);
    assert(!memcmp(blob, "ZDK1", 4) && blob[4] == 12 && blob[5] == 48);
    for (size_t i = 0; i + sizeof(made) <= sizeof(blob); ++i) assert(memcmp(blob + i, made, sizeof(made)));
    assert(zapp_devkey_unwrap(&ops, path, again) == ZAPP_DEVKEY_OK);
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
static void needs_authentication_is_typed_and_leaves_nothing(const char *dir)
{
    struct fake f = fake_new(); struct zapp_devkey_ops ops = ops_for(&f);
    char path[PATH_MAX], tmp[PATH_MAX]; blob_path(path, dir, "auth.blob"); blob_path(tmp, dir, "auth.blob.tmp");
    uint8_t secret[ZAPP_DEVKEY_SECRET]; memset(secret, 0xAA, sizeof(secret));
    f.fresh = false;
    assert(zapp_devkey_wrap_new(&ops, path, secret) == ZAPP_DEVKEY_NEEDS_AUTH);
    assert(all_zero(secret, sizeof(secret)) && access(path, F_OK) != 0 && access(tmp, F_OK) != 0);
    f.fresh = true;
    assert(zapp_devkey_wrap_new(&ops, path, secret) == ZAPP_DEVKEY_OK);
    f.fresh = false; memset(secret, 0xAA, sizeof(secret));
    assert(zapp_devkey_unwrap(&ops, path, secret) == ZAPP_DEVKEY_NEEDS_AUTH);
    assert(all_zero(secret, sizeof(secret)));
    f.fresh = true;
    assert(zapp_devkey_unwrap(&ops, path, secret) == ZAPP_DEVKEY_OK && !all_zero(secret, sizeof(secret)));
}
static void invalidation_is_distinct(const char *dir)
{
    struct fake f = fake_new(); struct zapp_devkey_ops ops = ops_for(&f);
    char path[PATH_MAX]; blob_path(path, dir, "inv.blob");
    uint8_t secret[ZAPP_DEVKEY_SECRET];
    assert(zapp_devkey_wrap_new(&ops, path, secret) == ZAPP_DEVKEY_OK);
    f.invalidated = true;
    assert(zapp_devkey_unwrap(&ops, path, secret) == ZAPP_DEVKEY_INVALIDATED && all_zero(secret, sizeof(secret)));
    f.invalidated = false; f.has_key = false;
    assert(zapp_devkey_unwrap(&ops, path, secret) == ZAPP_DEVKEY_INVALIDATED && all_zero(secret, sizeof(secret)));
    assert(strcmp(zapp_devkey_status_name(ZAPP_DEVKEY_INVALIDATED), zapp_devkey_status_name(ZAPP_DEVKEY_NEEDS_AUTH)));
}
static void existing_blob_is_never_replaced(const char *dir)
{
    struct fake f = fake_new(); struct zapp_devkey_ops ops = ops_for(&f);
    char path[PATH_MAX]; blob_path(path, dir, "keep.blob");
    uint8_t first[ZAPP_DEVKEY_SECRET], second[ZAPP_DEVKEY_SECRET], before[66], after[66];
    assert(zapp_devkey_wrap_new(&ops, path, first) == ZAPP_DEVKEY_OK);
    int fd = open(path, O_RDONLY); assert(read(fd, before, 66) == 66); close(fd);
    assert(zapp_devkey_wrap_new(&ops, path, second) == ZAPP_DEVKEY_EXISTS && all_zero(second, sizeof(second)));
    fd = open(path, O_RDONLY); assert(read(fd, after, 66) == 66); close(fd);
    assert(!memcmp(before, after, 66));
}
static void malformed_blobs_are_corrupt(const char *dir)
{
    struct fake f = fake_new(); struct zapp_devkey_ops ops = ops_for(&f);
    char good[PATH_MAX], bad[PATH_MAX]; blob_path(good, dir, "src.blob"); blob_path(bad, dir, "bad.blob");
    uint8_t secret[ZAPP_DEVKEY_SECRET], blob[67] = {0};
    assert(zapp_devkey_unwrap(&ops, bad, secret) == ZAPP_DEVKEY_NOT_FOUND);
    assert(zapp_devkey_wrap_new(&ops, good, secret) == ZAPP_DEVKEY_OK);
    int fd = open(good, O_RDONLY); assert(read(fd, blob, 66) == 66); close(fd);
    put_file(bad, blob, 65); assert(zapp_devkey_unwrap(&ops, bad, secret) == ZAPP_DEVKEY_CORRUPT);
    put_file(bad, blob, 67); assert(zapp_devkey_unwrap(&ops, bad, secret) == ZAPP_DEVKEY_CORRUPT);
    blob[0] = 'X'; put_file(bad, blob, 66); assert(zapp_devkey_unwrap(&ops, bad, secret) == ZAPP_DEVKEY_CORRUPT);
    blob[0] = 'Z'; blob[4] = 16; put_file(bad, blob, 66); assert(zapp_devkey_unwrap(&ops, bad, secret) == ZAPP_DEVKEY_CORRUPT);
    blob[4] = 12; blob[6] ^= 1; put_file(bad, blob, 66); assert(zapp_devkey_unwrap(&ops, bad, secret) == ZAPP_DEVKEY_CORRUPT);
    blob[6] ^= 1; blob[6 + 12 + 40] ^= 1; put_file(bad, blob, 66);
    assert(zapp_devkey_unwrap(&ops, bad, secret) == ZAPP_DEVKEY_CORRUPT && all_zero(secret, sizeof(secret)));
    assert(file_size(bad) == 66);
}
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
    int fd = open(path, O_RDONLY); assert(fd >= 0 && read(fd, after, 10) == 10 && close(fd) == 0);
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
    assert(zapp_devkey_unwrap(&ops, path, secret) == ZAPP_DEVKEY_INVALIDATED && all_zero(secret, sizeof(secret)));
    assert(zapp_devkey_prepare(&ops, NULL, NULL) == ZAPP_DEVKEY_OK && f.has_key);
    assert(zapp_devkey_unwrap(&ops, path, secret) == ZAPP_DEVKEY_CORRUPT && all_zero(secret, sizeof(secret)));
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
    const unsigned wrapped_auth[] = {ZAPP_DEVKEY_EX_UNRECOVERABLE_KEY, ZAPP_DEVKEY_EX_NOT_AUTHENTICATED};
    const unsigned invalidated[] = {0, ZAPP_DEVKEY_EX_PERMANENTLY_INVALIDATED};
    const unsigned unknown_alg[] = {ZAPP_DEVKEY_EX_UNRECOVERABLE_KEY | ZAPP_DEVKEY_EX_UNKNOWN_ALGORITHM};
    const unsigned auth[] = {ZAPP_DEVKEY_EX_NOT_AUTHENTICATED};
    const unsigned tag[] = {ZAPP_DEVKEY_EX_BAD_TAG};
    const unsigned strongbox[] = {0, ZAPP_DEVKEY_EX_STRONGBOX_UNAVAILABLE};
    const unsigned provider[] = {0, 0};
    assert(zapp_devkey_classify_chain(gone, 1) == ZAPP_DEVKEY_INVALIDATED);
    assert(zapp_devkey_classify_chain(unknown_alg, 1) == ZAPP_DEVKEY_ERROR);
    assert(zapp_devkey_classify_chain(wrapped, 2) == ZAPP_DEVKEY_ERROR);
    assert(zapp_devkey_classify_chain(wrapped_auth, 2) == ZAPP_DEVKEY_ERROR);
    assert(zapp_devkey_classify_chain(invalidated, 2) == ZAPP_DEVKEY_INVALIDATED);
    assert(zapp_devkey_classify_chain(auth, 1) == ZAPP_DEVKEY_NEEDS_AUTH);
    assert(zapp_devkey_classify_chain(tag, 1) == ZAPP_DEVKEY_CORRUPT);
    assert(zapp_devkey_classify_chain(strongbox, 2) == ZAPP_DEVKEY_STRONGBOX_UNAVAILABLE);
    assert(zapp_devkey_classify_chain(provider, 2) == ZAPP_DEVKEY_ERROR && zapp_devkey_classify_chain(provider, 0) == ZAPP_DEVKEY_ERROR);
}
int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: device_key_test <scratch directory>\n"); return 2; }
    refuses_without_screen_lock(argv[1]);
    prepare_prefers_strongbox_and_reports_fallback();
    refuses_software_keys();
    round_trip_and_blob_shape(argv[1]);
    system_random_differs(argv[1]);
    needs_authentication_is_typed_and_leaves_nothing(argv[1]);
    invalidation_is_distinct(argv[1]);
    existing_blob_is_never_replaced(argv[1]);
    malformed_blobs_are_corrupt(argv[1]);
    failures_leave_no_secret_and_no_file(argv[1]);
    discard_removes_blob_and_key(argv[1]);
    concurrent_blob_is_never_replaced(argv[1]);
    lost_key_is_not_replaced(argv[1]);
    invalidated_key_is_reported(argv[1]);
    existing_keys_are_never_deleted();
    only_strongbox_unavailable_falls_back();
    exception_chains_map_to_statuses();
    puts("device_key_test: ok");
    return 0;
}
