/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Read and explicitly select the owner's desktop app profile. */
#include "command/native_command.h"
#include "command/native_app_launch.h"
#include "command/native_app_receive_command.h"
#include "json/json.h"
#include "base/hex.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"
#include "platform/directory_compat.h"
#include "platform/directory_transaction.h"
#include "platform/state_root.h"
#include "platform/os_proc.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AP_RECORD "desktop-profile"
#define AP_HEADER 32u
#define AP_LOCK ".desktop-profile.lock"

static void ap_fail(struct zcl_command_reply *reply, const char *message)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                           "APP_PROFILE_REFUSED", "profile", false, false, message, "ops.host.app-profile");
}
static bool ap_printable(const char *path, size_t n)
{
    for (size_t i = 0; i < n; ++i)
        if ((unsigned char)path[i] < 32 || (unsigned char)path[i] == 127) return false;
    return true;
}

static bool ap_syntax(const char *path)
{
    size_t n = path ? strlen(path) : 0;
    if (!n || n >= APP_LAUNCH_PATH_MAX || path[0] != '/') return false;
    return ap_printable(path, n) && !(n > 1 && path[n - 1] == '/') && !strstr(path, "//") && !strstr(path, "/./") && !strstr(path, "/../") &&
        !(n >= 2 && !strcmp(path + n - 2, "/.")) && !(n >= 3 && !strcmp(path + n - 3, "/.."));
}
static bool ap_path(const char *path, struct zcl_command_reply *reply)
{
    char anchor[APP_LAUNCH_PATH_MAX];
    return ap_syntax(path) && app_receive_profile_validate(path, anchor, sizeof(anchor), reply);
}
static bool ap_selected_path(const char *path, struct zcl_command_reply *reply,
                             struct platform_directory_identity *identity)
{
    struct platform_directory_transaction dir; platform_directory_transaction_init(&dir);
    bool ok = path && strlen(path) + sizeof("--datadir=") <= APP_LAUNCH_ARG_MAX &&
        ap_path(path, reply) && platform_directory_transaction_open(&dir, path) &&
        platform_directory_transaction_identity(&dir, identity);
    platform_directory_transaction_close(&dir); return ok;
}
static bool ap_same(const struct platform_directory_identity *a, const struct platform_directory_identity *b)
{
    return a->volume == b->volume && a->file_low == b->file_low && a->file_high == b->file_high;
}
static void ap_encode_identity(uint8_t wire[24], const struct platform_directory_identity *id)
{
    zcl_write_u64_le(wire, id->volume); zcl_write_u64_le(wire + 8, id->file_low); zcl_write_u64_le(wire + 16, id->file_high);
}
static bool ap_env(struct app_launch_env *env, struct zcl_command_reply *reply)
{
    char why[256], anchor[APP_LAUNCH_PATH_MAX];
    return app_launch_env_from_process(env, why, sizeof(why)) &&
        app_receive_profile_validate(env->state_dir, anchor, sizeof(anchor), reply);
}
static bool ap_info_stable(const struct platform_directory_child_info *a,
                           const struct platform_directory_child_info *b)
{
    return b->current_user_only && b->link_count == 1 && a->size == b->size && a->volume == b->volume &&
        a->file_low == b->file_low && a->file_high == b->file_high &&
        a->modified_seconds == b->modified_seconds && a->modified_nanoseconds == b->modified_nanoseconds &&
        a->changed_seconds == b->changed_seconds && a->changed_nanoseconds == b->changed_nanoseconds;
}

static bool ap_read(struct platform_directory_transaction *dir, char *path, size_t cap, bool *selected,
                    struct platform_directory_identity *identity)
{
    struct platform_directory_child f; struct platform_directory_child_info info, after; uint8_t header[AP_HEADER];
    platform_directory_child_init(&f);
    enum platform_directory_result rc = platform_directory_child_open_result(dir, AP_RECORD, false, false, &f, NULL);
    if (rc == PLATFORM_DIRECTORY_MISSING) { *selected = false; return true; }
    bool ok = rc == PLATFORM_DIRECTORY_OK && platform_directory_child_info(&f, &info) &&
        info.current_user_only && info.link_count == 1 && info.size > AP_HEADER && info.size - AP_HEADER < cap &&
        platform_directory_child_read_exact(&f, header, sizeof(header), 0) && !memcmp(header, "Z23AP01", 8) &&
        platform_directory_child_read_exact(&f, path, (size_t)info.size - AP_HEADER, AP_HEADER) &&
        platform_directory_child_info(&f, &after) && ap_info_stable(&info, &after);
    if (ok) {
        size_t n = (size_t)info.size - AP_HEADER; ok = memchr(path, 0, n) == NULL; path[n] = 0; *selected = ok;
        identity->volume = zcl_read_u64_le(header + 8); identity->file_low = zcl_read_u64_le(header + 16);
        identity->file_high = zcl_read_u64_le(header + 24);
    }
    platform_directory_child_close(&f);
    return ok;
}
static void ap_token(const char *prior, bool selected, const struct platform_directory_identity *old,
                     const char *target, const struct platform_directory_identity *current, char token[65])
{
    struct sha3_256_ctx sha; uint8_t out[32], identity[24], marker = selected ? 1 : 0;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)"zcl.desktop-profile.v1", sizeof("zcl.desktop-profile.v1"));
    sha3_256_write(&sha, &marker, 1);
    if (selected) {
        sha3_256_write(&sha, (const uint8_t *)prior, strlen(prior) + 1);
        ap_encode_identity(identity, old); sha3_256_write(&sha, identity, sizeof(identity));
    }
    sha3_256_write(&sha, (const uint8_t *)target, strlen(target) + 1);
    ap_encode_identity(identity, current); sha3_256_write(&sha, identity, sizeof(identity));
    sha3_256_finalize(&sha, out); zcl_hex_encode(out, sizeof(out), token);
}

static bool ap_result(struct zcl_command_reply *reply, const char *path, bool selected)
{
    return json_push_kv_str(&reply->data, "profile", path) && json_push_kv_bool(&reply->data, "selected", selected);
}
void zcl_native_handle_app_profile_get(const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
#if defined(_WIN32)
    (void)request; ap_fail(reply, "Desktop profile selection is not supported on this platform."); return;
#endif
    (void)request;
    struct app_launch_env env; struct platform_directory_transaction dir; char path[APP_LAUNCH_PATH_MAX]; bool selected = false;
    struct platform_directory_identity saved = {0}, current = {0};
    platform_directory_transaction_init(&dir);
    if (!ap_env(&env, reply)) { ap_fail(reply, "The app state location is unsafe."); return; }
    enum platform_directory_probe_result state = platform_directory_probe_real(env.state_dir);
    bool ok = state == PLATFORM_DIRECTORY_PROBE_MISSING || (state == PLATFORM_DIRECTORY_PROBE_OK &&
        platform_directory_transaction_open(&dir, env.state_dir) && ap_read(&dir, path, sizeof(path), &selected, &saved));
    platform_directory_transaction_close(&dir);
    if (!ok) { ap_fail(reply, "The saved app profile is unsafe or unreadable."); return; }
    if (selected && (!ap_selected_path(path, reply, &current) || !ap_same(&saved, &current))) {
        ap_fail(reply, "The saved app profile changed. Select the intended directory again with --app-datadir."); return;
    }
    if (!selected) {
        const char *home = getenv("HOME"); int n = home ? snprintf(path, sizeof(path), "%s/.local/share/z23-app-data", home) : -1;
        if (n <= 0 || (size_t)n >= sizeof(path) || !ap_path(path, reply)) { ap_fail(reply, "Cannot resolve the default app profile."); return; }
    }
    if (!ap_result(reply, path, selected)) ap_fail(reply, "The app profile cannot be reported.");
}

static atomic_uint ap_serial;
static bool ap_publish(struct platform_directory_transaction *dir, const char *path, bool selected,
                       const struct platform_directory_identity *identity)
{
    struct platform_directory_child f; char pending[96]; platform_directory_child_init(&f);
    bool created = false;
    for (unsigned i = 0; i < 32 && !created; ++i) {
        unsigned serial = atomic_fetch_add(&ap_serial, 1);
        int n = snprintf(pending, sizeof(pending), ".desktop-profile.%llu.%u", (unsigned long long)os_proc_current_pid(), serial);
        if (n <= 0 || (size_t)n >= sizeof(pending)) return false;
        created = platform_directory_child_create(dir, pending, &f);
    }
    if (!created) return false;
    uint8_t header[AP_HEADER] = "Z23AP01"; ap_encode_identity(header + 8, identity);
    bool ready = platform_directory_child_write_exact(&f, header, sizeof(header), 0) &&
        platform_directory_child_write_exact(&f, path, strlen(path), AP_HEADER) && platform_directory_child_flush(&f);
    enum platform_directory_result moved = ready ? platform_directory_child_move_between(dir, &f, dir, AP_RECORD, !selected) : PLATFORM_DIRECTORY_IO;
    platform_directory_child_close(&f);
    if (!ready) (void)platform_directory_child_unlink(dir, pending, true);
    return moved == PLATFORM_DIRECTORY_OK;
}
static bool ap_set_locked(struct platform_directory_transaction *dir, const char *path, const char *expected,
                          const struct platform_directory_identity *initial, struct zcl_command_reply *reply)
{
    char prior[APP_LAUNCH_PATH_MAX], token[65]; bool selected = false;
    struct platform_directory_identity old = {0}, current = {0};
    if (!ap_read(dir, prior, sizeof(prior), &selected, &old) || (selected && !ap_syntax(prior)) ||
        !ap_selected_path(path, reply, &current) || !ap_same(initial, &current)) return false;
    ap_token(prior, selected, &old, path, &current, token);
    if (strcmp(token, expected) || !ap_publish(dir, path, selected, &current)) return false;
    struct platform_directory_identity after = {0};
    return ap_selected_path(path, reply, &after) && ap_same(&current, &after);
}
void zcl_native_handle_app_profile_set(const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
#if defined(_WIN32)
    (void)request; ap_fail(reply, "Desktop profile selection is not supported on this platform."); return;
#endif
    const char *path = json_get_str(json_get(request->input, "path"));
    const char *expected = json_get_str(json_get(request->input, "plan_id"));
    struct app_launch_env env; struct platform_directory_transaction dir; struct platform_directory_lock lock;
    struct platform_directory_identity initial = {0}; char root[APP_LAUNCH_PATH_MAX];
    platform_directory_transaction_init(&dir); platform_directory_lock_init(&lock);
    if (!expected || !ap_selected_path(path, reply, &initial) || !ap_env(&env, reply)) { ap_fail(reply, "The requested app profile or state location is unsafe."); return; }
    if (!platform_application_state_root(root, sizeof(root)) || strcmp(root, env.state_dir) || !platform_directory_transaction_open(&dir, root)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID, "APP_PROFILE_REFUSED", "profile", false, true,
                               "The app state location could not be prepared; directories may have been created.", "ops.host.app-profile"); return;
    }
    bool ok = platform_directory_lock_acquire(&dir, AP_LOCK, true, PLATFORM_DIRECTORY_LOCK_EXCLUSIVE, &lock) == PLATFORM_DIRECTORY_OK &&
        ap_set_locked(&dir, path, expected, &initial, reply);
    platform_directory_lock_release(&lock); platform_directory_transaction_close(&dir);
    if (!ok || !ap_result(reply, path, true))
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID, "APP_PROFILE_REFUSED", "profile", false, true,
                               "The app profile could not be safely saved; state may have changed.", "ops.host.app-profile");
}
void zcl_native_handle_app_profile_check(const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
#if defined(_WIN32)
    (void)request; ap_fail(reply, "Desktop profile selection is not supported on this platform."); return;
#endif
    const char *path = json_get_str(json_get(request->input, "path"));
    struct app_launch_env env; struct platform_directory_transaction dir; char prior[APP_LAUNCH_PATH_MAX]; bool selected = false;
    struct platform_directory_identity old = {0}, initial = {0}, current = {0};
    platform_directory_transaction_init(&dir);
    if (!ap_selected_path(path, reply, &initial) || !ap_env(&env, reply)) { ap_fail(reply, "The requested app profile or state location is unsafe."); return; }
    enum platform_directory_probe_result state = platform_directory_probe_real(env.state_dir);
    bool ok = state == PLATFORM_DIRECTORY_PROBE_MISSING || (state == PLATFORM_DIRECTORY_PROBE_OK &&
        platform_directory_transaction_open(&dir, env.state_dir) && ap_read(&dir, prior, sizeof(prior), &selected, &old) &&
        (!selected || ap_syntax(prior)));
    platform_directory_transaction_close(&dir);
    ok = ok && ap_selected_path(path, reply, &current) && ap_same(&initial, &current);
    char token[65]; ap_token(prior, selected, &old, path, &current, token);
    if (!ok || !json_push_kv_str(&reply->data, "profile", path) || !json_push_kv_str(&reply->data, "plan_id", token))
        ap_fail(reply, "The app profile cannot be safely selected.");
}
