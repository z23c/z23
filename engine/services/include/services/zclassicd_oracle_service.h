/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zclassicd Oracle Service — continuous independent-implementation drift
 * detection. Periodically asks the local zclassicd (the legacy C++ ZClassic
 * node, running at RPC port 8232) for getblockhash(H) at random heights
 * and verifies that the answer matches our own block_index.
 *
 * Why this exists:
 *   We treat zclassicd as a high-quality oracle for the same chain. Any
 *   disagreement is a strong signal of a consensus bug in either node.
 *   Emitting EV_ORACLE_AGREE / EV_ORACLE_DISAGREE makes drift visible to
 *   operators without manual comparison.
 *
 * Architecture:
 *   - One periodic tick registered with the chain supervisor. No
 *     dedicated pthread and no engine/modules/health dependency.
 *   - Each tick: pick `heights_per_tick` random heights in [0, tip-100]
 *     and probe each.
 *   - zclassicd_oracle_probe() is also exposed synchronously for the
 *     oracle diagnostics and unit tests.
 *
 * See CLAUDE.md "Adding state introspection" — this module follows the
 * *_dump_state_json convention and is wired into `z23 dumpstate oracle`
 * dispatcher.
 */

#ifndef ZCL_SERVICES_ZCLASSICD_ORACLE_SERVICE_H
#define ZCL_SERVICES_ZCLASSICD_ORACLE_SERVICE_H

#include <stdbool.h>
#include <stdint.h>

#include "util/result.h"

struct json_value;

struct zclassicd_oracle_config {
    const char *rpc_host;        /* default "127.0.0.1" */
    int         rpc_port;        /* default 8232 */
    const char *rpc_user;        /* read from zclassic.conf if NULL */
    const char *rpc_password;    /* read from zclassic.conf if NULL */
    int         cadence_secs;    /* default 60 */
    int         heights_per_tick;/* default 3 */
};

/* Apply config + load credentials. Safe to call before start to override
 * the defaults. Idempotent. Returns non-ok only on a missing
 * zclassic.conf when no user/password were supplied. */
struct zcl_result zclassicd_oracle_init(const struct zclassicd_oracle_config *cfg);

/* Register the periodic tick with the supervisor. Idempotent. */
struct zcl_result zclassicd_oracle_start(void);

/* Disable the periodic supervisor tick. Idempotent. */
void zclassicd_oracle_stop(void);

struct zclassicd_oracle_probe_result {
    int    height;
    char   our_hash[65];     /* hex, 64 chars + NUL; "" if we have no block */
    char   their_hash[65];   /* hex, 64 chars + NUL; "" on RPC error */
    bool   match;
    bool   our_have_block;
    bool   error;            /* RPC unreachable / parse fail */
    char   error_msg[128];
};

/* Synchronous probe. Returns ZCL_OK if the call completed (regardless
 * of agreement); returns non-ok only on a logic-level failure (NULL
 * out, out-of-range height, etc.). RPC unreachability sets
 * `error=true` and still returns ZCL_OK. */
struct zcl_result zclassicd_oracle_probe(int height,
                            struct zclassicd_oracle_probe_result *out);

/* Reentrant-safe dispatcher entry for `z23 dumpstate oracle`. */
bool zclassicd_oracle_dump_state_json(struct json_value *out, const char *key);

struct zclassicd_oracle_stats {
    int64_t attempts_total;
    int64_t probes_total;
    int64_t probes_agree;
    int64_t probes_disagree;
    int64_t rpc_errors;
    int64_t last_probe_unix_us;
    int     last_probed_height;
    int64_t last_attempt_unix_us;
    int     last_attempt_height;
    int64_t last_error_unix_us;
    int     last_error_height;
    int     last_error_code;    /* JSON-RPC code when known; 0 otherwise */
    bool    rpc_transport_reachable;
    bool    oracle_usable;
    bool    reachable;          /* compatibility alias for oracle_usable */
    char    last_error[128];    /* last RPC/parse failure, empty when usable */
};

void zclassicd_oracle_stats_snapshot(struct zclassicd_oracle_stats *out);

/* Test hooks — reset state between unit tests. */
void zclassicd_oracle_reset_for_test(void);

#endif /* ZCL_SERVICES_ZCLASSICD_ORACLE_SERVICE_H */
