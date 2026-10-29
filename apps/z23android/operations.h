/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_OPERATIONS_H
#define ZAPP_OPERATIONS_H
#include "app.h"
#include <pthread.h>
#include <sys/types.h>
struct zapp_runtime {
    pthread_mutex_t mutex;
    char directory[1024];
    char state_root[1024];
    char temporary_root[1024];
    char executable[1024];
    pid_t node;
    bool stopping;
};
bool zapp_runtime_init(struct zapp_runtime *r, const char *files, const char *libs);
void zapp_runtime_signal_stop(struct zapp_runtime *r);
void zapp_runtime_destroy(struct zapp_runtime *r);
bool zapp_node_running(struct zapp_runtime *r);
bool zapp_node_start(struct zapp_runtime *r, char *out, size_t cap);
bool zapp_node_stop(struct zapp_runtime *r, char *out, size_t cap);
/* True after the owner chose Start node, until Stop node runs. */
bool zapp_node_wanted(const struct zapp_runtime *r);
bool zapp_operation_run(struct zapp_runtime *r, const char *id, char *out, size_t cap);
bool zapp_fleet_join_run(struct zapp_runtime *r, const char *token, char *out, size_t cap);
bool zapp_balance_format(const char *json, char *out, size_t cap);
/* One plain line per fleet doctor detail, naming the checks that share it ("Identity and wiki: detail"),
 * as many lines as fit. Informational checks and next-step commands are left out. */
bool zapp_fleet_doctor_format(const char *json, char *out, size_t cap);
/* Replaces a JSON command result with its error message, or a plain notice when it has none, so
 * raw JSON never reaches the screen. Text that does not start with { is left as it is. */
void zapp_plain_text(char *text, size_t cap);
void zapp_device_info(char *out, size_t cap);
#endif
