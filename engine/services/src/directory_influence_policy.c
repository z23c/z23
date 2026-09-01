/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * directory_influence_policy — degraded mode for the peer/name directory.
 * Contract, rationale and blast-radius argument: see
 * services/directory_influence_policy.h.
 *
 * one-result-type-ok:pure-total-policy-lookup — directory_influence_decide /
 * directory_influence_caps are total, infallible folds over named facts; a
 * zcl_result would be noise. Unknown input fails closed (not admitted). */

// one-result-type-ok:pure-total-policy-lookup — total infallible admission
// fold over named facts; a zcl_result would be noise (fails closed).
#include "services/directory_influence_policy.h"

#include "base/text_fit.h"
#include "net/directory_influence_port.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* ── The pure fold ────────────────────────────────────────────────────── */

void directory_influence_decide(const struct directory_influence_input *in,
                                struct directory_influence_decision *out)
{
    if (!out)
        return;
    if (!in) {
        /* Fail closed: no input is not evidence of a whole network. */
        out->influence_admitted = false;
        out->fallback_to_roots = true;
        out->token = DIRECTORY_INFLUENCE_TOKEN_NO_INPUT;
        return;
    }

    /* The always-present roots are what degraded mode falls back TO, so they
     * are never gated by it. Gating them would turn a bad-weather signal into
     * a self-inflicted eclipse. */
    if (in->entry_is_root) {
        out->influence_admitted = true;
        out->fallback_to_roots = in->netsplit_suspected;
        out->token = DIRECTORY_INFLUENCE_TOKEN_ROOT;
        return;
    }

    if (!in->netsplit_suspected) {
        out->influence_admitted = true;
        out->fallback_to_roots = false;
        out->token = DIRECTORY_INFLUENCE_TOKEN_GRANTED;
        return;
    }

    /* Degraded mode. An entry the whole network already agreed on — final
     * STRICTLY BELOW the height at which suspicion began — is not the split's
     * testimony and keeps working untouched. Everything newer, and anything
     * whose finality we cannot place relative to the onset, gains nothing. */
    out->fallback_to_roots = true;
    if (in->split_onset_height >= 0 &&
        in->entry_final_height >= 0 &&
        in->entry_final_height < in->split_onset_height) {
        out->influence_admitted = true;
        out->token = DIRECTORY_INFLUENCE_TOKEN_PRE_SPLIT;
        return;
    }
    out->influence_admitted = false;
    out->token = DIRECTORY_INFLUENCE_TOKEN_CONTESTED;
}

uint32_t directory_influence_caps(const struct sync_evidence *base,
                                  bool network_uncontested,
                                  struct sync_capability_denials *why)
{
    struct sync_evidence e = {0};
    if (base)
        e = *base;
    e.network_uncontested = network_uncontested;
    return sync_capabilities_from_evidence(&e, why);
}

/* ── Standing state ───────────────────────────────────────────────────── */

/* Suspicion currently stands. */
static atomic_bool g_suspected;
/* Our height at the false->true edge; -1 when no suspicion stands. */
static _Atomic int32_t g_onset_height = -1;

bool directory_influence_granted(void)
{
    return !atomic_load(&g_suspected);
}

int32_t directory_influence_split_onset_height(void)
{
    if (!atomic_load(&g_suspected))
        return -1;  // raw-return-ok:not an error -- -1 is the documented "no suspicion stands" value of this accessor, read by the pure fold as "unknown onset"
    return atomic_load(&g_onset_height);
}

bool directory_influence_observe(bool netsplit_suspected, int32_t our_height,
                                 const char *reason)
{
    const bool was = atomic_load(&g_suspected);

    if (!netsplit_suspected) {
        if (was) {
            atomic_store(&g_suspected, false);
            atomic_store(&g_onset_height, -1);
            blocker_clear(DIRECTORY_INFLUENCE_BLOCKER_ID);
            LOG_INFO("directory_influence",
                     "network no longer contested — directory influence "
                     "restored (degraded mode off)");
        }
        return true;
    }

    if (!was) {
        atomic_store(&g_onset_height, our_height);
        atomic_store(&g_suspected, true);
    }

    /* Name it every pass. blocker_set de-duplicates inside its rate-limit
     * window, so refreshing here keeps the record's reason current without
     * becoming a stuck horn. The evidence prefix is bounded to 60 bytes so the
     * operator-facing half of the sentence — what is withheld and, just as
     * importantly, what is NOT — survives in the common case.
     *
     * It does NOT always survive, which the previous version of this comment
     * claimed: at the full 60-byte prefix the sentence is 280 bytes and the
     * closing "explorer and wallet-view unaffected." is cut. So build it whole
     * and let zcl_text_fit mark and log the cut instead of asserting one cannot
     * happen. */
    char full[BLOCKER_REASON_MAX * 2];
    snprintf(full, sizeof(full),
             "%.60s | DEGRADED: directory influence withheld for entries "
             "final at/after h=%d (earlier entries keep working; discovery "
             "falls back to compiled seeds + addr gossip). Tip-follow, relay, "
             "explorer and wallet-view unaffected.",
             (reason && reason[0]) ? reason : "SUSPECTED_NETSPLIT standing",
             (int)atomic_load(&g_onset_height));
    char text[BLOCKER_REASON_MAX];
    (void)zcl_text_fit(text, sizeof(text), full, "network_monitor",
                       "directory_influence.reason");

    struct blocker_record r;
    if (blocker_init(&r, DIRECTORY_INFLUENCE_BLOCKER_ID, "network_monitor",
                     BLOCKER_TRANSIENT, text))
        (void)blocker_set(&r);
    return false;
}

bool directory_influence_admit_entry(int32_t entry_final_height,
                                     bool entry_is_root,
                                     struct directory_influence_decision *out)
{
    struct directory_influence_input in = {
        .netsplit_suspected = atomic_load(&g_suspected),
        .split_onset_height = directory_influence_split_onset_height(),
        .entry_final_height = entry_final_height,
        .entry_is_root = entry_is_root,
    };
    struct directory_influence_decision d = {0};
    directory_influence_decide(&in, &d);
    if (out)
        *out = d;
    return d.influence_admitted;
}

/* ── Port implementation (core/modules/net reaches the policy through this) ────── */

static enum directory_influence_verdict di_port_verdict(void)
{
    return directory_influence_granted() ? DIRECTORY_INFLUENCE_GRANTED
                                         : DIRECTORY_INFLUENCE_WITHHELD;
}

static bool di_port_admit_entry(int32_t entry_final_height, bool entry_is_root)
{
    return directory_influence_admit_entry(entry_final_height, entry_is_root,
                                           NULL);
}

static const struct directory_influence_port g_di_port = {
    .verdict = di_port_verdict,
    .admit_entry = di_port_admit_entry,
};

void directory_influence_register_port(void)
{
    directory_influence_port_set(&g_di_port);
}

#ifdef ZCL_TESTING
void directory_influence_test_reset(void)
{
    atomic_store(&g_suspected, false);
    atomic_store(&g_onset_height, -1);
    blocker_clear(DIRECTORY_INFLUENCE_BLOCKER_ID);
}
#endif
