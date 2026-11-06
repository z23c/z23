/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_OPERATIONS_H
#define ZAPP_OPERATIONS_H
#include "app.h"
#include "nodelog.h"
#include "thermal.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
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
    /* The largest app-console.log kept before it is rotated or truncated; 0 means ZAPP_CONSOLE_CAP. Tests set it small. */
    off_t console_cap;
    /* The limit of a read command in milliseconds; 0 means 15 s. Tests set it short. */
    unsigned read_ms;
    /* The last direct node query failed and its reason is logged; cleared by the next success. */
    atomic_bool direct_reported;
    /* A wallet setup command is running: the node is not started until it ends. */
    atomic_bool setup_running;
    atomic_bool start_cancel;
    bool start_pending, start_executing, start_preload_allowed;
    uint64_t start_epoch, reserved_epoch;
    unsigned preload_ms; /* 0 means 2000 ms */
    char preload_reply[8192];
    char preload_identity[65];
    uint64_t preload_epoch;
    bool preload_ok;
    atomic_bool preload_ready;
};
bool zapp_runtime_init(struct zapp_runtime *r, const char *files, const char *libs, bool preview);
void zapp_runtime_signal_stop(struct zapp_runtime *r);
void zapp_runtime_destroy(struct zapp_runtime *r);
bool zapp_node_running(struct zapp_runtime *r);
/* Setup waits until a reserved or executing start has fully stopped. */
bool zapp_node_start_pending(struct zapp_runtime *r);
/* Setup's single snapshot for a node or a start in progress. */
bool zapp_node_start_pending_or_running(struct zapp_runtime *r);
/* True from a successful stop request until the node exits. */
bool zapp_node_stopping(struct zapp_runtime *r);
/* Nonblocking hint; the getter still revalidates the binding. */
bool zapp_node_preload_ready(const struct zapp_runtime *r);
/* Copy a current public status reply and its setup binding. */
bool zapp_node_preload_get(struct zapp_runtime *r, char *out, size_t cap,
    char identity[65], uint64_t *epoch, bool *command_ok);
bool zapp_node_start_reserve(struct zapp_runtime *r, uint64_t *ticket, char *out, size_t cap);
bool zapp_node_start_reserved(struct zapp_runtime *r, uint64_t ticket, char *out, size_t cap);
void zapp_node_start_discard(struct zapp_runtime *r, uint64_t ticket);
bool zapp_node_start(struct zapp_runtime *r, char *out, size_t cap);
bool zapp_node_stop(struct zapp_runtime *r, char *out, size_t cap);
/* Asks the node to exit exactly as zapp_node_stop does but leaves the marker that starts it when the app opens, so a stop made by
 * wallet setup never changes the owner's choice. */
bool zapp_node_stop_for_setup(struct zapp_runtime *r, char *out, size_t cap);
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
/* Every command below has a limit. A command that has not answered by then, one still stuck between fork and exec included,
 * is killed by its own pid and then by the process group it made, reaped and logged, and its call returns false with "The
 * command timed out." in out. */
/* Runs one read-only operation and leaves its JSON reply in out. The reply comes from the running
 * node over its local RPC port; when that fails the same operation runs through the CLI, and the
 * reason is logged once until the next success. */
bool zapp_operation_run(struct zapp_runtime *r, const char *id, char *out, size_t cap);
/* Runs one wallet command for the wallet screens and leaves its reply in out: op is "summary", "fleet",
 * "latest", "broadcast", "receive", "history" (arg is the cursor of the page, "" for the newest) or "detail"
 * (arg is the transaction id). Command line only, never logged. False, with a plain sentence or the node
 * error text in out, when the command fails, does not exist or is given an argument that is not valid. */
bool zapp_wallet_run(struct zapp_runtime *r, const char *op, const char *arg, char *out, size_t cap);
/* The commit of a send may take this long at the least; a shorter request is raised to it. */
#define ZAPP_WALLET_COMMIT_MIN_MS 300000u
#define ZAPP_WALLET_SEND_TIMEOUT_MAX_MS 600000u
/* Runs one step of a send and leaves its reply in out. op is "summary", "fleet", "latest" or "broadcast" (the read commands of
 * zapp_wallet_run, no input), "validateaddress" (input is the JSON-RPC parameter array, sent to the node over its local
 * RPC port), "lock" (no input), or "unlock", "plan", "commit", "shieldplan" or "shieldcommit" (input is the request; the
 * last two are the plan and the commit of the move of public funds into the private balance). The request of those five goes
 * to the node on standard input, never on the command line, and is read as is: the caller cleanses it. A command is
 * killed after timeout_ms, and a commit never sooner than ZAPP_WALLET_COMMIT_MIN_MS. False when the step fails, is
 * killed, or does not exist; out then holds the node reply, which may still be a typed error, or a plain sentence. */
bool zapp_wallet_send_run(struct zapp_runtime *r, const char *op, const char *input, unsigned timeout_ms, char *out, size_t cap);
/* The setup of a wallet, run while the node is stopped: op is "create" or "restore" and input is the request, which holds
 * the datadir and the passphrase (and, for a restore, the words). It goes to the command on standard input, never on the
 * command line or in the environment, and is read as is: the caller cleanses it. Or op is "blockhash" and input is the
 * JSON-RPC parameter array [height], answered by the running node over its local RPC port. A command is refused, with a
 * plain sentence in out, while a node runs: it holds the files the wallet is written into. While one runs, zapp_node_start
 * refuses. A command is killed after timeout_ms. */
#define ZAPP_WALLET_SETUP_TIMEOUT_MAX_MS 900000u
bool zapp_wallet_setup_run(struct zapp_runtime *r, const char *op, const char *input, unsigned timeout_ms, char *out, size_t cap);
bool zapp_fleet_join_run(struct zapp_runtime *r, const char *token, char *out, size_t cap);
enum zapp_preview_result { ZAPP_PREVIEW_OK, ZAPP_PREVIEW_FAILED, ZAPP_PREVIEW_CANCELLED };
enum zapp_preview_result zapp_fleet_preview_cancelable(struct zapp_runtime *, const char *, char *, size_t, const atomic_bool *);
enum zapp_preview_result zapp_fleet_machine_preview_cancelable(struct zapp_runtime *, const char *, char *, size_t, const atomic_bool *);
/* Verify an invitation without enrolling this phone or creating a key. */
bool zapp_fleet_preview_run(struct zapp_runtime *r, const char *token, char *out, size_t cap);
bool zapp_fleet_preview_text(const char *text, char *out, size_t cap);
/* True when the node has published its onion address: a valid Tor v3 hostname file. */
bool zapp_onion_ready(const struct zapp_runtime *r);
/* True when boot_status.json in the node's datadir is a zcl.boot_status.v1 document of at most ZAPP_BOOT_STATUS_MAX bytes
 * whose serving is true: the node finished starting and serves. The file is opened without following a link. */
#define ZAPP_BOOT_STATUS_MAX 4096
bool zapp_node_serving(const struct zapp_runtime *r);
enum zapp_onion { ZAPP_ONION_READY, ZAPP_ONION_NODE_STOPPED, ZAPP_ONION_TIMEOUT };
/* Re-checks once a second for up to the given seconds. waiting runs once, when the address is not
 * yet there. Returns early if the node exits. */
enum zapp_onion zapp_onion_wait(struct zapp_runtime *r, unsigned seconds, void (*waiting)(void *), void *arg);
/* The JSON object in command output: at its start, or on the first line beginning with {, after
 * warnings the command wrote first. NULL when there is none. */
const char *zapp_json_object(const char *text);
/* Extracts a successful join receipt after any command warnings. A refused or
 * incomplete reply leaves the previous receipt unchanged. */
bool zapp_fleet_machine_preview_run(struct zapp_runtime *r, const char *line, char *out, size_t cap);
bool zapp_fleet_machine_preview_text(const char *text, char *out, size_t cap, char *onion, size_t onion_cap);
bool zapp_fleet_connect_run(struct zapp_runtime *r, const char *line, const char *onion, char *out, size_t cap);
bool zapp_fleet_join_receipt(const char *text, char *receipt, size_t cap);
/* Replaces command output that holds a JSON object with that object's error message, or a plain
 * notice when it has none, so raw JSON never reaches the screen. Other text is left as it is. */
void zapp_plain_text(char *text, size_t cap);
#endif
