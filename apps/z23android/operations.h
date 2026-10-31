/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_OPERATIONS_H
#define ZAPP_OPERATIONS_H
#include "app.h"
#include "nodelog.h"
#include "thermal.h"
#include <pthread.h>
#include <stdatomic.h>
#include <sys/types.h>
struct zapp_runtime {
    pthread_mutex_t mutex;
    /* The app files directory; the proving parameters are copied below it. */
    char files[1024];
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
    /* Last pace written to <directory>/pace; unset until the first write. Callers serialize. */
    bool pace_set;
    enum zapp_pace pace;
    /* Forwards the node console log to logcat and tracks its boot stage. */
    struct zapp_nodelog log;
    /* The last direct node query failed and its reason is logged; cleared by the next success. */
    atomic_bool direct_reported;
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
/* The pace last written by zapp_node_pace_write, normal before the first write. */
enum zapp_pace zapp_node_pace(const struct zapp_runtime *r);
/* Tells the node how hard to sync by atomically replacing <directory>/pace with the pace word
 * (normal, gentle or pause). The first call always writes, replacing a file left by an earlier run;
 * later calls with an unchanged pace do nothing. Returns false and logs when the file cannot be
 * replaced, leaving the recorded pace unchanged. Not thread safe; callers serialize. */
bool zapp_node_pace_write(struct zapp_runtime *r, enum zapp_pace pace);
/* Runs one read-only operation and leaves its JSON reply in out. The reply comes from the running
 * node over its local RPC port; when that fails the same operation runs through the CLI, and the
 * reason is logged once until the next success. */
bool zapp_operation_run(struct zapp_runtime *r, const char *id, char *out, size_t cap);
bool zapp_fleet_join_run(struct zapp_runtime *r, const char *token, char *out, size_t cap);
/* True when the node has published its onion address: a valid Tor v3 hostname file. */
bool zapp_onion_ready(const struct zapp_runtime *r);
enum zapp_onion { ZAPP_ONION_READY, ZAPP_ONION_NODE_STOPPED, ZAPP_ONION_TIMEOUT };
/* Re-checks once a second for up to the given seconds. waiting runs once, when the address is not
 * yet there. Returns early if the node exits. */
enum zapp_onion zapp_onion_wait(struct zapp_runtime *r, unsigned seconds, void (*waiting)(void *), void *arg);
/* The JSON object in command output: at its start, or on the first line beginning with {, after
 * warnings the command wrote first. NULL when there is none. */
const char *zapp_json_object(const char *text);
/* Replaces command output that holds a JSON object with that object's error message, or a plain
 * notice when it has none, so raw JSON never reaches the screen. Other text is left as it is. */
void zapp_plain_text(char *text, size_t cap);
#endif
