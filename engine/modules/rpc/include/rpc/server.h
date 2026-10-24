/* Copyright (c) 2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_RPC_SERVER_H
#define ZCL_RPC_SERVER_H

#include "rpc/protocol.h"
#include "core/amount.h"
#include <stdbool.h>
#include <stdint.h>

struct json_request {
    struct json_value id;
    char method[128];
    struct json_value params;
};

void json_request_init(struct json_request *req);
void json_request_free(struct json_request *req);
/* Parse a JSON-RPC request object into req. Returns false on a NULL
 * argument or a malformed request (non-object, missing/invalid method). */
bool json_request_parse(struct json_request *req,
                        const struct json_value *val_request);

typedef bool (*rpc_fn)(const struct json_value *params, bool help,
                       struct json_value *result);

/* Readiness class: which boot-time dependency a command needs before it may
 * answer. The zero value is the STRICTEST (needs every class ready), so a
 * command that does not declare a class is never exposed by omission.
 * rpc_table_append() fills an undeclared class from the command category
 * (rpc_ready_class_default) when it stores the entry; rpc_table_set_ready_class
 * declares one explicitly. */
enum rpc_ready_class {
    RPC_READY_UNCLASSIFIED = 0,
    RPC_READY_CHAIN,
    RPC_READY_WALLET,
    RPC_READY_PROJECTION,
    RPC_READY_CLASS_COUNT
};

struct rpc_command {
    const char *category;
    const char *name;
    rpc_fn actor;
    bool ok_safe_mode;
};

#define MAX_RPC_COMMANDS 512

struct rpc_table {
    struct rpc_command commands[MAX_RPC_COMMANDS];
    /* Parallel to commands[]: the readiness class of each entry, kept beside
     * the commands (not in them) so the many positional command initialisers
     * stay valid. */
    enum rpc_ready_class ready_class[MAX_RPC_COMMANDS];
    size_t num_commands;
    bool running;
};

void rpc_table_init(struct rpc_table *t);
bool rpc_table_append(struct rpc_table *t, const struct rpc_command *cmd);
/* Boot-time variant: aborts (with a precise reason in node.log + stderr)
 * if the registration fails. Failed registration during boot is a
 * programmer error (duplicate name, MAX_RPC_COMMANDS cap, or table
 * already running) — not a recoverable runtime fault. Use this in
 * every register_*_rpc_commands() callsite. */
void rpc_table_must_append(struct rpc_table *t, const struct rpc_command *cmd);
const struct rpc_command *rpc_table_find(const struct rpc_table *t,
                                         const char *name);
/* Declare a command's readiness class explicitly (overrides the category
 * default). False when the command is not registered. */
bool rpc_table_set_ready_class(struct rpc_table *t, const char *name,
                               enum rpc_ready_class cls);
/* Execute a method by name. Returns true on success with the handler's
 * value in *result. On failure (server still in warmup, method not found,
 * or the handler itself failing) it returns false AND writes a structured
 * error object into *result — callers must build their response from
 * *result, not merely branch on the bool. */
bool rpc_table_execute(const struct rpc_table *t, const char *method,
                       const struct json_value *params,
                       struct json_value *result);


/* ── RPC warmup: a lifecycle, not a one-shot latch ───────────────────
 * While warmup is armed, rpc_table_execute() refuses every method with
 * RPC_IN_WARMUP plus the reason string, so a client gets "still starting
 * up" instead of an answer computed from half-built state.
 *
 * Both edges are needed because the frontend service kernel genuinely
 * supports stop_all -> start_all: the rpc_http start hook disarms, and its
 * paired stop hook re-arms, so a restarted node re-enters warmup instead of
 * coming back up still claiming ready. Both calls are idempotent. */

/* Arm warmup and set the reason clients will be told. NULL/empty status
 * falls back to a generic "RPC server starting". */
void set_rpc_warmup_started(const char *status);
/* Replace the reason without changing whether warmup is armed. */
void set_rpc_warmup_status(const char *status);
/* Disarm warmup; methods start answering. */
void set_rpc_warmup_finished(void);
bool rpc_is_in_warmup(char *status_out, size_t status_size);

/* ── Per-class readiness, layered under the global warmup flag ────────
 * While the global flag is armed every method is refused (unchanged).
 * Once it is disarmed, a method is additionally refused with RPC_IN_WARMUP
 * and a class reason ("wallet loading", "projections loading") until its
 * class bit is set. set_rpc_warmup_finished() sets every class bit and
 * set_rpc_warmup_started() clears them all, so today the classes become
 * ready together with the flag. UNCLASSIFIED needs every bit. */
void rpc_ready_set(enum rpc_ready_class cls, bool ready);
bool rpc_ready_is(enum rpc_ready_class cls);
const char *rpc_ready_reason(enum rpc_ready_class cls);
/* Category/name based default for a command that declares no class. */
enum rpc_ready_class rpc_ready_class_default(const struct rpc_command *cmd);

void value_from_amount(CAmount amount, struct json_value *out);

#endif
