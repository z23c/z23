/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * chain_reorg_uncorroborated condition — see
 * conditions/chain_reorg_uncorroborated.h. Promotes the header corroboration
 * policy's HOLD state (net/header_corroboration.h) to a typed healer: DETECT a
 * currently-held un-corroborated best-header switch, REMEDY by naming the
 * transient blocker + widening peering to solicit a second corroborating
 * address group, WITNESS by the hold clearing (corroborated or abandoned).
 * Local policy overlay only; never touches chain selection or bans the peer. */

#include "conditions/chain_reorg_uncorroborated.h"

#include "framework/condition.h"
#include "services/sync_monitor.h"
#include "net/connman.h"
#include "net/header_corroboration.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include <stdio.h>

#define CHAIN_REORG_UNCORROBORATED_BLOCKER_ID "chain.reorg_uncorroborated"
#define CHAIN_REORG_UNCORROBORATED_OWNER      "header_corroboration"

static bool detect_chain_reorg_uncorroborated(void)
{
    return header_corroboration_hold_active();
}

static enum condition_remedy_result remedy_chain_reorg_uncorroborated(void)
{
    struct header_corroboration_hold h;
    if (!header_corroboration_hold_get(&h)) {
        /* Raced with a clear — nothing to name. */
        blocker_clear(CHAIN_REORG_UNCORROBORATED_BLOCKER_ID);
        return COND_REMEDY_OK;
    }

    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "un-corroborated header switch: fork_h=%d depth=%d cand_h=%d "
             "(cur_h=%d) work_delta=0x%.16s peer=%s — awaiting a 2nd address "
             "group",
             h.fork_height, h.switch_depth, h.candidate_height,
             h.current_height, h.work_delta_hex, h.peer_name);

    struct blocker_record r;
    if (blocker_init(&r, CHAIN_REORG_UNCORROBORATED_BLOCKER_ID,
                     CHAIN_REORG_UNCORROBORATED_OWNER,
                     BLOCKER_TRANSIENT, reason))
        (void)blocker_set(&r);
    LOG_WARN("condition", "[condition:chain_reorg_uncorroborated] %s", reason);

    /* Actively solicit an independent corroborator — pull fresh clearnet +
     * onion seeds so a peer from a distinct address group can serve (and thus
     * corroborate) the contested branch. Best-effort; the witness confirms. */
    struct connman *cm = sync_monitor_connman();
    if (!cm)
        return COND_REMEDY_FAILED;
    connman_kick_seed_discovery(cm);
    connman_kick_onion_seeds(cm);
    return COND_REMEDY_OK;
}

static bool witness_chain_reorg_uncorroborated(int64_t target_at_detect)
{
    (void)target_at_detect;
    // honest-witness-ok: the hold bit is NOT poison-absence and NOT a flag this
    // remedy set (the remedy sets the separate blocker registry entry). It is
    // cleared exclusively by the network header-ingest path (msg_headers.c ->
    // header_corroboration_gate_switch) on OBSERVABLE progress: a second
    // distinct address group actually served the contested branch (real peer
    // header delivery noted from the wire), or the honest chain's best header
    // advanced past the candidate's work (real block_index movement). So
    // hold_active()==false genuinely reflects network progress, not FSM state.
    bool resolved = !header_corroboration_hold_active();
    if (resolved)
        blocker_clear(CHAIN_REORG_UNCORROBORATED_BLOCKER_ID);
    return resolved;
}

static struct condition c_chain_reorg_uncorroborated = {
    .name = "chain_reorg_uncorroborated",
    .severity = COND_WARN,
    .poll_secs = 15,
    .backoff_secs = 60,
    .max_attempts = 3,
    /* External-dependency class (peer discovery): re-arm after a backoff
     * instead of latching permanently — a persistent single-source branch may
     * need repeated widening attempts. */
    .cooldown_secs = 300,
    .cooldown_max_rearms = 0,
    .detect = detect_chain_reorg_uncorroborated,
    .remedy = remedy_chain_reorg_uncorroborated,
    .witness = witness_chain_reorg_uncorroborated,
    .witness_window_secs = 120,
};

void register_chain_reorg_uncorroborated(void)
{
    (void)condition_register(&c_chain_reorg_uncorroborated);
}

#ifdef ZCL_TESTING

#endif
