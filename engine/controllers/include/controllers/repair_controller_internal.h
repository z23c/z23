/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Internal shared includes + repair context for the repair RPC
 * controller. Included by repair_controller*.c only — not public. */

#ifndef ZCL_CONTROLLERS_REPAIR_CONTROLLER_INTERNAL_H
#define ZCL_CONTROLLERS_REPAIR_CONTROLLER_INTERNAL_H

#include "platform/time_compat.h"
#include "controllers/repair_controller.h"
#include "controllers/rpc_chainstate_guard.h"
#include "services/chain_activation_service.h"
#include "controllers/strong_params.h"
#include "coins/coins.h"
#include "coins/coins_view.h"
#include "core/uint256.h"
#include "json/json.h"
#include "models/utxo.h"
#include "rpc/client.h"
#include "rpc/zclassicd_port.h"
#include "script/script.h"
#include "validation/main_state.h"
#include "validation/process_block.h"
#include "config/boot_internal.h"
#include <limits.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

struct repair_context {
    struct main_state *main_state;
    struct coins_view_cache *coins_tip;
    struct node_db *node_db;
    const char *datadir;
    const struct chain_params *params;
};

extern struct repair_context g_repair_ctx;

static inline struct repair_context *repair_ctx(void)
{
    return &g_repair_ctx;
}

/* JSON int extractor for parsing zclassicd RPC responses. */
static inline int64_t repair_json_int(const char *json, const char *key)
{
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return -1; // raw-return-ok:sentinel
    p += strlen(pat);
    while (*p == ' ' || *p == ':' || *p == '\t') p++;
    return strtoll(p, NULL, 10);
}

#define REPAIRUTXOS_DEFAULT_SCAN_BLOCKS 10000
#define REPAIRUTXOS_MAX_SCAN_BLOCKS 50000
#define REPAIRUTXOS_MAX_CREDS_LEN 256

/* repair_controller_utxo.c — repairutxos RPC + UTXO refetch helpers */
bool rpc_repairutxos(const struct json_value *params, bool help,
                     struct json_value *result);

#endif /* ZCL_CONTROLLERS_REPAIR_CONTROLLER_INTERNAL_H */
