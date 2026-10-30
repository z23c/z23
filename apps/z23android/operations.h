/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_OPERATIONS_H
#define ZAPP_OPERATIONS_H
#include "app.h"
#include "nodelog.h"
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
    /* The preview package never runs a node. */
    bool preview;
    /* Shutdown was requested from a node that has not exited yet. */
    bool stop_sent;
    /* Forwards the node console log to logcat and tracks its boot stage. */
    struct zapp_nodelog log;
};
bool zapp_runtime_init(struct zapp_runtime *r, const char *files, const char *libs, bool preview);
void zapp_runtime_signal_stop(struct zapp_runtime *r);
void zapp_runtime_destroy(struct zapp_runtime *r);
bool zapp_node_running(struct zapp_runtime *r);
/* True from a successful stop request until the node exits. */
bool zapp_node_stopping(struct zapp_runtime *r);
bool zapp_node_start(struct zapp_runtime *r, char *out, size_t cap);
bool zapp_node_stop(struct zapp_runtime *r, char *out, size_t cap);
/* What the node is doing after its latest boot stage, as a short plain phrase such as "opening the
 * database"; "starting the node" before it reports one. */
const char *zapp_node_stage(struct zapp_runtime *r);
/* True after the owner chose Start node, until Stop node runs; always false in the preview package. */
bool zapp_node_wanted(const struct zapp_runtime *r);
bool zapp_operation_run(struct zapp_runtime *r, const char *id, char *out, size_t cap);
bool zapp_fleet_join_run(struct zapp_runtime *r, const char *token, char *out, size_t cap);
bool zapp_balance_format(const char *json, char *out, size_t cap);
/* The JSON object in command output: at its start, or on the first line beginning with {, after
 * warnings the command wrote first. NULL when there is none. */
const char *zapp_json_object(const char *text);
/* Replaces command output that holds a JSON object with that object's error message, or a plain
 * notice when it has none, so raw JSON never reaches the screen. Other text is left as it is. */
void zapp_plain_text(char *text, size_t cap);
#endif
