/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Private terminal-worker environment policy and Windows dispatch.
 * The allowlist is shared by inspection and native environment construction. */
#ifndef ZCL_MESH_TERMINAL_WORKER_INTERNAL_H
#define ZCL_MESH_TERMINAL_WORKER_INTERNAL_H

#include "session/mesh_terminal_worker.h"

enum tw_env_source { TW_ENV_PASS, TW_ENV_WORKDIR, TW_ENV_TERM };

struct tw_env_entry {
    const char *name;
    enum tw_env_source source;
};

static const struct tw_env_entry tw_env_table[] = {
    { "APPDATA", TW_ENV_PASS },        { "ComSpec", TW_ENV_PASS },
    { "HOME", TW_ENV_WORKDIR },        { "LOCALAPPDATA", TW_ENV_PASS },
    { "PATH", TW_ENV_PASS },           { "SystemRoot", TW_ENV_PASS },
    { "TEMP", TW_ENV_PASS },           { "TERM", TW_ENV_TERM },
    { "TMP", TW_ENV_PASS },            { "USERPROFILE", TW_ENV_WORKDIR },
    { "windir", TW_ENV_PASS },
};

#if defined(_WIN32)
struct zcl_result mesh_terminal_worker_spawn_platform_arm(
    const struct mesh_terminal_worker_config *cfg, int64_t now_unix,
    struct mesh_terminal_worker *out);
struct zcl_result mesh_terminal_worker_input_platform_arm(
    struct mesh_terminal_worker *w, const uint8_t *bytes, size_t n,
    int64_t now_unix);
struct zcl_result mesh_terminal_worker_output_platform_arm(
    struct mesh_terminal_worker *w, uint8_t *buf, size_t cap,
    size_t *out_len, int64_t now_unix);
struct zcl_result mesh_terminal_worker_resize_platform_arm(
    struct mesh_terminal_worker *w, uint16_t cols, uint16_t rows);
bool mesh_terminal_worker_budget_exceeded_platform_arm(
    struct mesh_terminal_worker *w, int64_t now_unix);
bool mesh_terminal_worker_alive_platform_arm(struct mesh_terminal_worker *w);
void mesh_terminal_worker_kill_platform_arm(struct mesh_terminal_worker *w);
#endif

#endif
