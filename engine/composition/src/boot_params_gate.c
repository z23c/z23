/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The zk-parameter boot gate: decide what a mainnet node can do when
 * ~/.zcash-params is absent.
 *
 * A Zcash parameter file is a verifying key followed by a proving key.
 * Consensus validation reads only the verifying-key prefix — 6357 bytes
 * across all four files — and those are compiled into this binary
 * (core/modules/sapling/src/params_vk_embedded.c). The remaining ~777 MB is
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

bool boot_params_gate_on_load_refused(const char *params_dir)
{
    /* The files WERE present, so the gate above said PRESENT and the loader
     * ran; it then refused them for a pinned SHA-512 mismatch or a parse
     * failure. sapling_init_params has already dropped every refused byte —
     * nothing that failed its pin is parsed or installed — and that does not
     * change here.
     *
     * What changes is the conclusion. The loader used to declare a PERMANENT
     * params_missing blocker meaning "proof validation cannot proceed" for the
     * life of the process, conflating the same two capabilities this file
     * separates for the absent case. VALIDATION reads only the verifying-key
     * prefix, compiled in and SHA-256 pinned; it was never on disk, so a
     * corrupt download cannot touch it. PROVING needs the ~777 MB only the
     * file carries. A refused file therefore costs exactly what an absent one
     * costs and is named the same way — with a reason saying REFUSED rather
     * than absent, because an operator re-fetches for one and installs for the
     * other.
     *
     * Consensus-safe: the installed keys equal the verifying-key prefix a good
     * file would have yielded (pinned by test_params_vk_embedded), so no proof
     * is accepted that a fully-parameterised node would reject. */
    const char *dir = params_dir ? params_dir : "(unset)";
    const struct chain_params *cp = chain_params_get();
    bool mainnet = cp && strcmp(cp->strNetworkID, "main") == 0;

    if (sapling_install_embedded_vks()) {
        if (mainnet) {
            struct blocker_record rec;
            if (blocker_init(&rec, "shielded_spend_unavailable", "crypto.params",
                             BLOCKER_PERMANENT,
                             "zk proving parameters were REFUSED (failed their "
                             "pinned SHA-512, or did not parse) — this node "
                             "validates every shielded proof from its "
                             "compiled-in verifying keys but cannot create "
                             "shielded transactions; re-fetch the parameter "
                             "files, see docs/PARAMS.md") &&
                blocker_set(&rec) == 0)
                event_emitf(EV_OPERATOR_NEEDED, 0,
                            "check=shielded_spend_unavailable reason=params_refused dir=%s",
                            dir);
        }
        LOG_WARN("crypto.params",
                 "[crypto.params] zk parameter files in %s were REFUSED "
                 "(pinned SHA-512 mismatch or parse failure); none of their "
                 "bytes were used. Falling back to the compiled-in verifying "
                 "keys: shielded proof VALIDATION is active and this node "
                 "syncs and serves normally. Creating shielded transactions "
                 "needs the files re-fetched (docs/PARAMS.md).", dir);
        return true;
    }

    /* Disk parameters refused AND the compiled-in keys failed their own
     * integrity check: no key material this process is willing to verify
     * against. Here "proof validation cannot proceed" is literally true. */
    if (mainnet) {
        struct blocker_record rec;
        if (blocker_init(&rec, "params_missing", "crypto.params",
                         BLOCKER_PERMANENT,
                         "mainnet zk parameters were refused AND the compiled-in "
                         "verifying keys failed their integrity check — proof "
                         "validation cannot proceed") &&
            blocker_set(&rec) == 0)
            event_emitf(EV_OPERATOR_NEEDED, 0,
                        "check=params_missing reason=disk_refused_and_embedded_bad dir=%s",
                        dir);
    }
    LOG_WARN("crypto.params",
             "[crypto.params] zk params refused from %s and the compiled-in "
             "verifying keys also failed integrity — proof validation BLOCKED "
             "(params_missing); operator paged once", dir);
    return false;
}
