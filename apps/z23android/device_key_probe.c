/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "device_key_probe.h"
#include "base/cleanse.h"
#include "device_key.h"
#include "secure_window.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static bool paused;
static bool confirm_started;

static void note(const char *dir, const char *line)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/probe.out", dir);
    FILE *out = fopen(path, "a");
    if (!out) return;
    fprintf(out, "%lld %s\n", (long long)time(NULL), line);
    fclose(out);
}
static bool read_command(const char *dir, char *cmd, size_t cap)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/probe.cmd", dir);
    FILE *in = fopen(path, "r");
    if (!in) return false;
    bool ok = fgets(cmd, (int)cap, in) != NULL;
    fclose(in);
    cmd[strcspn(cmd, "\r\n")] = '\0';
    return ok;
}
static enum zapp_devkey_status roundtrip(const struct zapp_devkey_ops *ops, const char *blob, bool *match)
{
    uint8_t made[ZAPP_DEVKEY_SECRET], read[ZAPP_DEVKEY_SECRET];
    (void)unlink(blob);
    enum zapp_devkey_status st = zapp_devkey_wrap_new(ops, blob, made);
    if (st == ZAPP_DEVKEY_OK) st = zapp_devkey_unwrap(ops, blob, read);
    *match = st == ZAPP_DEVKEY_OK && !memcmp(made, read, sizeof(made));
    memory_cleanse(made, sizeof(made)); memory_cleanse(read, sizeof(read));
    return st;
}
/* Keystore stand-in for the store command: real file writes, no key and no authentication. The
 * seal step can create the blob path, as a concurrent writer would after the existence check. */
struct store_state { const char *race_path; };
static bool store_random(void *ctx, uint8_t *out, size_t len) { (void)ctx; memset(out, 0x5C, len); return true; }
static enum zapp_devkey_status store_secure(void *ctx) { (void)ctx; return ZAPP_DEVKEY_OK; }
static enum zapp_devkey_status store_level(void *ctx, enum zapp_devkey_level *level)
{ (void)ctx; *level = ZAPP_DEVKEY_LEVEL_SECURE_HARDWARE; return ZAPP_DEVKEY_OK; }
static enum zapp_devkey_status store_seal(void *ctx, const uint8_t *plain, size_t len, uint8_t iv[ZAPP_DEVKEY_IV], uint8_t sealed[ZAPP_DEVKEY_SEALED])
{
    const struct store_state *state = ctx;
    (void)plain; (void)len;
    memset(iv, 0x11, ZAPP_DEVKEY_IV); memset(sealed, 0x22, ZAPP_DEVKEY_SEALED);
    if (state->race_path) {
        FILE *out = fopen(state->race_path, "wb");
        if (out) { fputs("raced-blob", out); fclose(out); }
    }
    return ZAPP_DEVKEY_OK;
}
static enum zapp_devkey_status store_open(void *ctx, const uint8_t iv[ZAPP_DEVKEY_IV], const uint8_t sealed[ZAPP_DEVKEY_SEALED], uint8_t *plain, size_t cap)
{ (void)ctx; (void)iv; (void)sealed; (void)plain; (void)cap; return ZAPP_DEVKEY_ERROR; }
static void store_delete(void *ctx) { (void)ctx; }
static long file_length(const char *path)
{
    FILE *in = fopen(path, "rb");
    long size = -1;
    if (in && fseek(in, 0, SEEK_END) == 0) size = ftell(in);
    if (in) fclose(in);
    return size;
}
/* Stores a blob through the production no-replace path, then again with a blob that appears after
 * the existence check: the first must succeed, the second must report exists and leave it alone. */
static enum zapp_devkey_status store_probe(const char *dir, char *detail, size_t cap)
{
    struct store_state state = {NULL};
    struct zapp_devkey_ops ops = {&state, store_random, store_secure, NULL, store_level, store_seal, store_open, store_delete};
    char blob[512], tmp[512];
    uint8_t secret[ZAPP_DEVKEY_SECRET];
    snprintf(blob, sizeof(blob), "%s/probe-store.blob", dir);
    snprintf(tmp, sizeof(tmp), "%s.tmp", blob);
    (void)unlink(blob); (void)unlink(tmp);
    enum zapp_devkey_status first = zapp_devkey_wrap_new(&ops, blob, secret);
    long first_size = file_length(blob);
    (void)unlink(blob);
    state.race_path = blob;
    enum zapp_devkey_status second = zapp_devkey_wrap_new(&ops, blob, secret);
    long second_size = file_length(blob);
    snprintf(detail, cap, "first=%s size=%ld race=%s size=%ld tmp_left=%d", zapp_devkey_status_name(first), first_size,
             zapp_devkey_status_name(second), second_size, access(tmp, F_OK) == 0);
    (void)unlink(blob); (void)unlink(tmp);
    memory_cleanse(secret, sizeof(secret));
    return first == ZAPP_DEVKEY_OK && first_size == 66 && second == ZAPP_DEVKEY_EXISTS && second_size == 10 ? ZAPP_DEVKEY_OK : ZAPP_DEVKEY_ERROR;
}
static enum zapp_devkey_status run(ANativeActivity *activity, const char *dir, const char *cmd, char *detail, size_t cap)
{
    struct zapp_devkey_jni state = {activity->env, activity->clazz};
    struct zapp_devkey_ops ops;
    char blob[512];
    uint8_t secret[ZAPP_DEVKEY_SECRET];
    struct zapp_devkey_info info = {0};
    bool match = false;
    enum zapp_devkey_status st = ZAPP_DEVKEY_ERROR;
    zapp_devkey_jni_ops(&ops, &state);
    snprintf(blob, sizeof(blob), "%s/probe.blob", dir);
    detail[0] = '\0';
    if (!strcmp(cmd, "prepare")) {
        st = zapp_devkey_prepare(&ops, blob, &info);
        if (st == ZAPP_DEVKEY_OK) snprintf(detail, cap, "level=%s strongbox_fallback=%d", zapp_devkey_level_name(info.level), info.strongbox_fallback);
    } else if (!strcmp(cmd, "wrap")) st = zapp_devkey_wrap_new(&ops, blob, secret);
    else if (!strcmp(cmd, "unwrap")) st = zapp_devkey_unwrap(&ops, blob, secret);
    else if (!strcmp(cmd, "roundtrip")) { st = roundtrip(&ops, blob, &match); snprintf(detail, cap, "match=%d", match); }
    else if (!strcmp(cmd, "store")) st = store_probe(dir, detail, cap);
    else if (!strcmp(cmd, "discard")) { zapp_devkey_discard(&ops, blob); st = ZAPP_DEVKEY_OK; }
    else if (!strncmp(cmd, "secure ", 7)) {
        bool on = !strcmp(cmd + 7, "on");
        st = zapp_secure_window(activity, on) ? ZAPP_DEVKEY_OK : ZAPP_DEVKEY_ERROR;
        snprintf(detail, cap, "secure=%d", on);
    }
    memory_cleanse(secret, sizeof(secret));
    return st;
}
void zapp_devkey_probe(ANativeActivity *activity, enum zapp_devkey_probe_event event)
{
    if (event == ZAPP_DEVKEY_PROBE_PAUSE) { paused = true; return; }
    if (confirm_started && !paused) return;
    paused = false;
    const char *dir = activity->internalDataPath;
    char cmd[64], detail[96], path[512], tag[256];
    if (!dir || !read_command(dir, cmd, sizeof(cmd))) return;
    enum zapp_devkey_status st = run(activity, dir, cmd, detail, sizeof(detail));
    if (st == ZAPP_DEVKEY_NEEDS_AUTH && !confirm_started) {
        confirm_started = zapp_devkey_confirm_credential(activity->env, activity->clazz);
        snprintf(tag, sizeof(tag), "%s needs_authentication confirm_started=%d", cmd, confirm_started);
        note(dir, tag); return;
    }
    confirm_started = false;
    snprintf(tag, sizeof(tag), "%s %s%s %s", cmd, zapp_devkey_status_name(st),
             st == ZAPP_DEVKEY_NEEDS_AUTH ? " after_confirm" : "", detail);
    note(dir, tag);
    snprintf(path, sizeof(path), "%s/probe.cmd", dir);
    (void)unlink(path);
}
