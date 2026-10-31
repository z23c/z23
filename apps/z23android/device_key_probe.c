/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "device_key_probe.h"
#include "base/cleanse.h"
#include "device_key.h"
#include "secure_window.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static atomic_flag busy = ATOMIC_FLAG_INIT;

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
    if (st == ZAPP_DEVKEY_OK) st = zapp_devkey_unwrap(ops, blob, ZAPP_DEVKEY_PURPOSE_UNLOCK, read);
    *match = st == ZAPP_DEVKEY_OK && !memcmp(made, read, sizeof(made));
    memory_cleanse(made, sizeof(made)); memory_cleanse(read, sizeof(read));
    return st;
}
/* Keystore stand-in for the store command: real file writes, no key and no authentication. The
 * seal step can create the blob path, as a concurrent writer would after the existence check. */
struct store_state { const char *race_path; };
static bool store_random(void *ctx, uint8_t *out, size_t len) { (void)ctx; memset(out, 0x5C, len); return true; }
static enum zapp_devkey_status store_secure(void *ctx) { (void)ctx; return ZAPP_DEVKEY_OK; }
static enum zapp_devkey_status store_policy(void *ctx, enum zapp_devkey_level *level, bool *per_use)
{ (void)ctx; *level = ZAPP_DEVKEY_LEVEL_SECURE_HARDWARE; *per_use = true; return ZAPP_DEVKEY_OK; }
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
static enum zapp_devkey_status store_open(void *ctx, enum zapp_devkey_purpose purpose, const uint8_t iv[ZAPP_DEVKEY_IV], const uint8_t sealed[ZAPP_DEVKEY_SEALED], uint8_t *plain, size_t cap)
{ (void)ctx; (void)purpose; (void)iv; (void)sealed; (void)plain; (void)cap; return ZAPP_DEVKEY_ERROR; }
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
    struct zapp_devkey_ops ops = {&state, store_random, store_secure, NULL, store_policy, store_seal, store_open, store_delete};
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
static long elapsed_ms(const struct timespec *from)
{
    struct timespec to;
    clock_gettime(CLOCK_MONOTONIC, &to);
    return (long)((to.tv_sec - from->tv_sec) * 1000 + (to.tv_nsec - from->tv_nsec) / 1000000);
}
/* Unwraps twice in a row. Every unwrap must show its own prompt: a second `ok` that arrives within a
 * few milliseconds of the first means Keystore accepted an earlier authentication. */
static enum zapp_devkey_status twice(const struct zapp_devkey_ops *ops, const char *blob, char *detail, size_t cap)
{
    uint8_t secret[ZAPP_DEVKEY_SECRET];
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    enum zapp_devkey_status first = zapp_devkey_unwrap(ops, blob, ZAPP_DEVKEY_PURPOSE_UNLOCK, secret);
    long first_ms = elapsed_ms(&start);
    clock_gettime(CLOCK_MONOTONIC, &start);
    enum zapp_devkey_status second = zapp_devkey_unwrap(ops, blob, ZAPP_DEVKEY_PURPOSE_PAYMENT, secret);
    snprintf(detail, cap, "first=%s/%ldms second=%s/%ldms", zapp_devkey_status_name(first), first_ms,
             zapp_devkey_status_name(second), elapsed_ms(&start));
    memory_cleanse(secret, sizeof(secret));
    return second;
}
/* Plants a blob of the 30 second window design and unwraps it: expected old_format with no prompt. */
static enum zapp_devkey_status old_blob(const struct zapp_devkey_ops *ops, const char *dir, char *detail, size_t cap)
{
    char path[512];
    uint8_t blob[66] = {'Z', 'D', 'K', '1', ZAPP_DEVKEY_IV, ZAPP_DEVKEY_SEALED}, secret[ZAPP_DEVKEY_SECRET];
    snprintf(path, sizeof(path), "%s/probe-old.blob", dir);
    FILE *out = fopen(path, "wb");
    if (!out) return ZAPP_DEVKEY_ERROR;
    bool wrote = fwrite(blob, 1, sizeof(blob), out) == sizeof(blob);
    if (fclose(out) != 0 || !wrote) return ZAPP_DEVKEY_ERROR;
    enum zapp_devkey_status st = zapp_devkey_unwrap(ops, path, ZAPP_DEVKEY_PURPOSE_UNLOCK, secret);
    (void)unlink(path);
    snprintf(detail, cap, "planted=ZDK1");
    memory_cleanse(secret, sizeof(secret));
    return st;
}
static enum zapp_devkey_status run(ANativeActivity *activity, JNIEnv *env, const char *dir, const char *cmd, char *detail, size_t cap)
{
    struct zapp_devkey_jni state = {env, activity->clazz};
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
        if (st == ZAPP_DEVKEY_OK) snprintf(detail, cap, "level=%s strongbox_fallback=%d per_use=1", zapp_devkey_level_name(info.level), info.strongbox_fallback);
    } else if (!strcmp(cmd, "wrap")) st = zapp_devkey_wrap_new(&ops, blob, secret);
    else if (!strcmp(cmd, "unwrap")) st = zapp_devkey_unwrap(&ops, blob, ZAPP_DEVKEY_PURPOSE_UNLOCK, secret);
    else if (!strcmp(cmd, "pay")) st = zapp_devkey_unwrap(&ops, blob, ZAPP_DEVKEY_PURPOSE_PAYMENT, secret);
    else if (!strcmp(cmd, "twice")) st = twice(&ops, blob, detail, cap);
    else if (!strcmp(cmd, "oldblob")) st = old_blob(&ops, dir, detail, cap);
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
struct job { ANativeActivity *activity; char cmd[64]; };
/* Runs one command on its own thread attached to the JVM: a prompt blocks until the owner answers
 * and the UI thread must stay free to show it. */
static void *job_main(void *arg)
{
    struct job *job = arg;
    ANativeActivity *activity = job->activity;
    JNIEnv *env = NULL;
    const char *dir = activity->internalDataPath;
    char detail[96], tag[256];
    if ((*activity->vm)->AttachCurrentThread(activity->vm, &env, NULL) == JNI_OK) {
        enum zapp_devkey_status st = run(activity, env, dir, job->cmd, detail, sizeof(detail));
        snprintf(tag, sizeof(tag), "%s %s %s", job->cmd, zapp_devkey_status_name(st), detail);
        note(dir, tag);
        (*activity->vm)->DetachCurrentThread(activity->vm);
    } else note(dir, "attach failed");
    free(job);
    atomic_flag_clear(&busy);
    return NULL;
}
void zapp_devkey_probe(ANativeActivity *activity, enum zapp_devkey_probe_event event)
{
    const char *dir = activity->internalDataPath;
    char path[512];
    if (event == ZAPP_DEVKEY_PROBE_PAUSE || !dir || atomic_flag_test_and_set(&busy)) return;
    struct job *job = calloc(1, sizeof(*job));
    pthread_t thread;
    if (!job) { atomic_flag_clear(&busy); return; }
    job->activity = activity;
    if (!read_command(dir, job->cmd, sizeof(job->cmd))) { free(job); atomic_flag_clear(&busy); return; }
    snprintf(path, sizeof(path), "%s/probe.cmd", dir);
    (void)unlink(path);
    if (pthread_create(&thread, NULL, job_main, job) != 0) { free(job); atomic_flag_clear(&busy); return; }
    pthread_detach(thread);
}
