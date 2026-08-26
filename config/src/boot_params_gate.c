/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The zk-parameter boot gate: decide what a mainnet node can do when
 * ~/.zcash-params is absent.
 *
 * A Zcash parameter file is a verifying key followed by a proving key.
 * Consensus validation reads only the verifying-key prefix — 6357 bytes
 * across all four files — and those are compiled into this binary
 * (lib/sapling/src/params_vk_embedded.c). The remaining ~777 MB is
 * proving-key material, reached only through sapling_get_spend_pk() /
 * sapling_get_output_pk(), whose sole callers build a shielded output the
 * operator is SENDING.
 *
 * So a missing parameter directory costs exactly one capability. This gate
 * used to park the whole node for it — no listener, no RPC, no peers, no
 * validation, no serving — which is every capability. The gate was placed on
 * the node when the thing actually unavailable was the wallet's spend path.
 *
 * Now: install the compiled-in verifying keys, name the one capability that
 * really is gone, page the operator once, and let the node sync, validate and
 * serve. Proving stays fail-closed on its own — with no proving keys loaded
 * the native prover remains NATIVE_PROVER_UNINITIALIZED, and both
 * shielded-send paths refuse on zclassic_sapling_prover_is_ready() rather
 * than emitting an unproven output.
 *
 * Parking remains correct in exactly one case: the compiled-in keys failing
 * their own integrity check. That means this binary cannot verify shielded
 * proofs at all, and a node that cannot do that must not pretend to validate
 * the chain.
 *
 * Operator-facing detail: docs/PARAMS.md.
 */

#include "config/boot_params_gate.h"

#include "config/boot.h"
#include "chain/chainparams.h"
#include "controllers/event_controller.h"
#include "event/event.h"
#include "sapling/params_vk_embedded.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* The four files a proving-capable node needs. Their absence is what this
 * gate reasons about; their contents are checked by sapling_init_params. */
static const char *const kRequiredParams[] = {
    "sapling-spend.params", "sapling-output.params",
    "sprout-groth16.params", "sprout-verifying.key",
};

enum boot_params_gate_result
boot_params_gate_evaluate(const struct app_context *ctx,
                          const struct chain_params *params,
                          const char *params_dir)
{
    /* -mint-anchor-fast passes the crypto stages through without running
     * (jobs/mint_skip_crypto.h), so offline self-mint legitimately needs no zk
     * params. Non-mainnet never enforced this gate. */
    if (!params || strcmp(params->strNetworkID, "main") != 0 ||
        !ctx || ctx->mint_anchor_fast)
        return BOOT_PARAMS_GATE_PRESENT;

    const char *missing = NULL;
    char missing_path[1100] = {0};
    if (!ctx->params_dir) {
        missing = "(no -paramsdir configured)";
    } else {
        for (size_t i = 0; i < sizeof(kRequiredParams) / sizeof(kRequiredParams[0]); i++) {
            char p[1100];
            snprintf(p, sizeof(p), "%s/%s", params_dir, kRequiredParams[i]);
            if (access(p, R_OK) != 0) {
                missing = kRequiredParams[i];
                snprintf(missing_path, sizeof(missing_path), "%s", p);
                break;
            }
        }
    }
    if (!missing)
        return BOOT_PARAMS_GATE_PRESENT;

    /* Load-bearing step. A failure here is the original fatal condition. */
    if (!sapling_install_embedded_vks()) {
        struct blocker_record rec;
        if (blocker_init(&rec, "params_missing", "crypto.params",
                         BLOCKER_PERMANENT,
                         "compiled-in zk verifying keys failed their integrity "
                         "check — proof validation cannot run") &&
            blocker_set(&rec) == 0)
            event_emitf(EV_OPERATOR_NEEDED, 0,
                        "check=params_missing reason=embedded_vk_integrity");
        LOG_WARN("crypto.params",
                 "[crypto.params] compiled-in verifying keys failed integrity "
                 "verification — this binary cannot validate shielded proofs; "
                 "NOT advancing CRYPTO_READY, parking alive-degraded after "
                 "paging the operator");
        return BOOT_PARAMS_GATE_PARK;
    }

    /* Validation is armed. Name the one capability that is not, so "cannot
     * send shielded" is a reported state and never a surprise at spend time.
     * A capability blocker, not a boot blocker: the caller carries on. */
    struct blocker_record rec;
    if (blocker_init(&rec, "shielded_spend_unavailable", "crypto.params",
                     BLOCKER_PERMANENT,
                     "zk PROVING parameters are not installed — this node "
                     "validates every shielded proof but cannot create "
                     "shielded transactions; see docs/PARAMS.md") &&
        blocker_set(&rec) == 0)
        event_emitf(EV_OPERATOR_NEEDED, 0,
                    "check=shielded_spend_unavailable file=%s path=%s",
                    missing, missing_path[0] ? missing_path : "");
    LOG_WARN("crypto.params",
             "[crypto.params] proving parameter '%s' is missing/unreadable "
             "(dir=%s) — using compiled-in verifying keys: shielded proof "
             "VALIDATION is active and this node will sync and serve normally. "
             "Creating shielded transactions is unavailable until the proving "
             "parameters are installed (tools/scripts/zcash_params.sh, "
             "docs/PARAMS.md).",
             missing, ctx->params_dir ? ctx->params_dir : "(unset)");
    return BOOT_PARAMS_GATE_EMBEDDED;
}
