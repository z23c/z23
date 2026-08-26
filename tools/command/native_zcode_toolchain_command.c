/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Agent-readable local GCC toolchain capsule identity. */

#include "command/native_command.h"
#include "command/native_zcode_join.h"

#include "base/hex.h"
#include "json/json.h"
#include "platform/os_proc.h"
#include "util/spawn.h"
#include "vcs/build_action.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static bool ztc_first_line(const char *const argv[], char *out, size_t cap)
{
    if (!argv || !out || cap == 0) return false;
    if (zcl_spawn_capture(argv, out, cap, 10000) != 0 || !out[0])
        return false;
    out[strcspn(out, "\r\n")] = '\0';
    return out[0] != '\0';
}

static bool ztc_verifier_name(const char **name_out)
{
    static const char *const names[] = {
        "zclassic23-package-verify-dev",
        "zclassic23-package-verify",
    };
    char exe[4096], path[4400];
    if (!os_proc_exe_path(exe, sizeof(exe))) return false;
    char *deleted = strstr(exe, " (deleted)");
    if (deleted) *deleted = '\0';
    char *slash = strrchr(exe, '/');
    if (!slash) return false;
    *slash = '\0';
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        int n = snprintf(path, sizeof(path), "%s/%s", exe, names[i]);
        if (n > 0 && (size_t)n < sizeof(path) && access(path, X_OK) == 0) {
            if (name_out) *name_out = names[i];
            return true;
        }
    }
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        int n = snprintf(path, sizeof(path), "build/bin/%s", names[i]);
        if (n > 0 && (size_t)n < sizeof(path) && access(path, X_OK) == 0) {
            if (name_out) *name_out = names[i];
            return true;
        }
    }
    return false;
}

void zcl_native_handle_zcode_toolchain_show(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    if (request->input && request->input->type == JSON_OBJ &&
        request->input->num_children != 0) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "BAD_TOOLCHAIN_SHOW_INPUT", "status", false, false,
            "zcode work toolchain accepts no input keys",
            "zcode.work.toolchain");
        return;
    }
    struct vcs_toolchain_capsule_v1 capsule;
    uint8_t root[32];
    if (!vcs_toolchain_capsule_v1_capture_gcc(&capsule) ||
        !vcs_toolchain_capsule_v1_root(&capsule, root)) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "TOOLCHAIN_CAPTURE_FAILED", "status", false, false,
            "the fixed GCC toolchain capsule could not be captured",
            "zcode.work.toolchain");
        return;
    }
    char capsule_hex[65], machine[256], full_version[256], as_version[512];
    zcl_hex_encode(root, 32, capsule_hex);
    machine[0] = '\0';
    full_version[0] = '\0';
    as_version[0] = '\0';
    {
        const char *const cc_machine[] = { VCS_BUILD_COMPILER_V1, "-dumpmachine",
                                           NULL };
        const char *const cc_full[] = { VCS_BUILD_COMPILER_V1, "-dumpfullversion",
                                        NULL };
        const char *const as_ver[] = { "/usr/bin/as", "--version", NULL };
        (void)ztc_first_line(cc_machine, machine, sizeof(machine));
        (void)ztc_first_line(cc_full, full_version, sizeof(full_version));
        (void)ztc_first_line(as_ver, as_version, sizeof(as_version));
    }
    (void)json_push_kv_str(&reply->data, "schema", "zcl.zcode_toolchain_show.v1");
    (void)json_push_kv_str(&reply->data, "capsule_root", capsule_hex);
    (void)json_push_kv_str(&reply->data, "target", capsule.target[0]
                                                     ? capsule.target
                                                     : VCS_BUILD_TARGET_V1);
    (void)json_push_kv_str(&reply->data, "compiler", VCS_BUILD_COMPILER_V1);
    if (machine[0])
        (void)json_push_kv_str(&reply->data, "dumpmachine", machine);
    if (full_version[0])
        (void)json_push_kv_str(&reply->data, "dumpfullversion", full_version);
    if (as_version[0])
        (void)json_push_kv_str(&reply->data, "assembler_version", as_version);
    const char *verifier_name = "";
    bool verifier_present = ztc_verifier_name(&verifier_name);
    struct zcl_zcode_join_posture join;
    if (!zcl_zcode_join_posture_fill(&join)) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "JOIN_POSTURE_FAILED", "status", false, false,
            "the Commons join posture could not be read",
            "zcode.work.toolchain");
        return;
    }
    const char *blocker = !verifier_present ? "VERIFIER_MISSING" :
        !join.joined ? "NOT_JOINED" : "NONE";
    (void)json_push_kv_bool(&reply->data, "verifier_present", verifier_present);
    (void)json_push_kv_bool(&reply->data, "can_prove", verifier_present);
    if (!zcl_zcode_join_posture_push_json(&reply->data, &join)) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "JOIN_POSTURE_FAILED", "status", false, false,
            "the Commons join posture could not be rendered",
            "zcode.work.toolchain");
        return;
    }
    (void)json_push_kv_str(&reply->data, "blocker", blocker);
    if (verifier_present && verifier_name[0])
        (void)json_push_kv_str(&reply->data, "verifier_name", verifier_name);
    /* A live package-host flag does not prove the durable config also carries
     * buildworker=1. `z23 join` is idempotent and detects the compiler before
     * writing that fact, so it is the truthful action until both live flags
     * prove this process joined compile work. */
    (void)json_push_kv_str(
        &reply->data, "next_action",
        !join.joined
            ? "z23 join"
            : !verifier_present
            ? "Place zclassic23-package-verify next to this binary, then rerun "
              "zcode work toolchain. A worker cannot prove without the "
              "confined verifier."
            : "Compare capsule_root with zcode work toolchain on the proving "
              "node. Independent compile evidence needs the same capsule.");
    (void)json_push_kv_str(&reply->data, "next_safe_command",
                           !join.joined
                               ? "join"
                               : "zcode work toolchain");
}
