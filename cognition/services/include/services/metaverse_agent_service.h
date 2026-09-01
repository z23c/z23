/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * metaverse_agent_service — the read side of the confined-agent broker, for
 * the `metaverse agent status` / `metaverse agent audit` leaves.
 *
 * The broker runs as its own process (`zclassic23 --metaverse-broker`), so its
 * state is a DIRECTORY, not in-process memory. These two calls are therefore
 * pure readers over that directory: they open nothing outside it, create
 * nothing, and answer "not present" for a directory that has never hosted a
 * broker. That is deliberate — a read leaf that mkdir'd its own subject would
 * make "no broker has run here" indistinguishable from "a broker ran and left
 * nothing", and would write into whatever datadir a caller named.
 *
 * Both calls return struct zcl_result. The refusal REASON travels with the
 * refusal: `code` is one of the MVS_ERR_* values below, so the controller can
 * map it onto a named command error, and `message` carries the detail an
 * operator needs to fix the call.
 */

#ifndef ZCL_SERVICES_METAVERSE_AGENT_SERVICE_H
#define ZCL_SERVICES_METAVERSE_AGENT_SERVICE_H

#include "base/result.h"

#include <stddef.h>
#include <stdint.h>

/* Controller-owned loopback transport. Keeping it explicit and above services
 * preserves the shape dependency direction and prevents module-owned mutable
 * state. NULL remains a fail-closed unreachable reader. */
typedef char *(*metaverse_agent_rpc_fn)(const char *node_datadir, int rpc_port,
                                        const char *method,
                                        const char *params_json,
                                        long connect_ms, long total_ms);

/* Refusal codes carried in struct zcl_result::code. */
enum {
    MVS_ERR_BAD_ARGS = -1,      /* dir NULL/empty, too long, or not absolute */
    MVS_ERR_NOT_A_DIR = -2,     /* dir does not exist, or is not a directory */
    MVS_ERR_RENDER_FAILED = -3, /* the document did not fit `out_cap`        */
};

/* Render the broker's recorded state for `dir` into `out`, writing the byte
 * length to `*out_len` on success. */
struct zcl_result metaverse_agent_service_status(const char *dir, char *out,
                                                 size_t out_cap,
                                                 size_t *out_len);

/* Render the verified audit trail for `dir` into `out`, tail-bounded by
 * `limit` (0 selects the default). The tamper verdict always covers the whole
 * log even when the rendered tail is shorter. */
struct zcl_result metaverse_agent_service_audit(const char *dir, size_t limit,
                                                char *out, size_t out_cap,
                                                size_t *out_len);

/* Reconcile the broker's owner-created dev/prod bindings against each live
 * node. Missing/unreachable/conflicting readers stay explicit; no endpoint or
 * datadir path is rendered. */
struct zcl_result metaverse_agent_service_money(
    const char *dir, metaverse_agent_rpc_fn rpc,
    char *out, size_t out_cap, size_t *out_len);

/* Ask one explicitly bound wallet for aggregate-only parallel-spend
 * readiness. The result is advisory and never creates addresses, reserves
 * coins, or broadcasts the optional self-fanout it describes. */
struct zcl_result metaverse_agent_service_liquidity(
    const char *dir, const char *wallet_scope, int64_t recipient_value_zat,
    int64_t maximum_fee_zat, int requested_concurrency,
    metaverse_agent_rpc_fn rpc, char *out, size_t out_cap, size_t *out_len);

#endif /* ZCL_SERVICES_METAVERSE_AGENT_SERVICE_H */
