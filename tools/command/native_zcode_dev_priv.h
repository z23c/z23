/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Internal wiring shared by the ZCODE dev-loop native adapters. Not a public
 * surface: only native_zcode_dev_command.c and its sibling translation units
 * (native_zcode_dev_capture.c, native_zcode_dev_tasks.c,
 * native_zcode_dev_improve.c, native_zcode_dev_publish.c) include this. It
 * exposes the exact JSON-field readers, canonical-root pushers, ledger
 * ownership/live-forwarding primitives, and candidate-capture helpers those
 * files share, so the improve/tasks/publish handlers keep one immutable
 * canonical-object admission story instead of five reimplementations. */
#ifndef ZCL_TOOLS_NATIVE_ZCODE_DEV_PRIV_H
#define ZCL_TOOLS_NATIVE_ZCODE_DEV_PRIV_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

struct json_value;
struct zcl_command_reply;
struct node_db;
struct vcs_zcode_task_v1;
struct vcs_zcode_write_scope_v1;
struct zcode_lane_status;

#define ZDEV_PATH_MAX 4096

/* ── small JSON/root readers shared by every sibling ─────────────────── */
const char *zdev_str(const struct json_value *input, const char *key);
int64_t zdev_int(const struct json_value *input, const char *key,
                 int64_t fallback);
void zdev_fail(struct zcl_command_reply *reply, const char *code,
              const char *detail);
bool zdev_root(const struct json_value *input, const char *key,
              uint8_t out[32], struct zcl_command_reply *reply);
void zdev_push_root(struct json_value *out, const char *key,
                    const uint8_t root[32]);
uint8_t *zdev_hex_wire(const struct json_value *input, const char *key,
                       size_t max_bytes, size_t *len_out);
bool zdev_paths_overlap(const char *a, const char *b);
bool zdev_candidate_input_path(
    const char *candidate_arg, const char *fixed_path, const char *claimed,
    char *out, struct zcl_command_reply *reply);
void zdev_push_lane(struct json_value *out,
                    const struct zcode_lane_status *status);

/* ── ledger ownership and live-daemon forwarding (native_zcode_dev_capture.c) */
bool zdev_open_db(const char *datadir, struct node_db *ndb);
bool zdev_open_build_ledger(
    struct node_db *ndb, const char *path, const char *reason);
bool zdev_runtime_owns_ledger(const char *datadir);
bool zdev_forward_live_input(
    const struct json_value *input, const char *datadir,
    const char *rpc_method, const char *fallback_code,
    const char *fallback_phase, const char *evidence,
    struct zcl_command_reply *reply);

/* ── candidate/write-scope capture (native_zcode_dev_capture.c) ─────────── */
bool zdev_load_write_scope(
    const char *workspace, const uint8_t root[32],
    struct vcs_zcode_write_scope_v1 *out);
bool zdev_capture_source_root(
    const char *workspace, uint8_t out[32], struct zcl_command_reply *reply);
bool zdev_capture_write_scope(
    const char *workspace, const char *csv, uint8_t out[32],
    struct zcl_command_reply *reply);
bool zdev_capture_candidate(
    const char *workspace, const char *candidate_arg,
    const struct vcs_zcode_task_v1 *task, uint8_t candidate_root[32],
    uint8_t patch_root[32], uint8_t source_sha256[32],
    uint32_t *changed_files, uint64_t *patch_bytes,
    struct zcl_command_reply *reply);

#endif /* ZCL_TOOLS_NATIVE_ZCODE_DEV_PRIV_H */
