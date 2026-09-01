/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * netsplit_degraded_mode condition — see
 * conditions/netsplit_degraded_mode.h. Drives the directory-influence
 * posture off the netsplit detector and names the standing condition. */

#include "conditions/netsplit_degraded_mode.h"

#include "framework/condition.h"
#include "services/directory_influence_policy.h"
#include "services/network_monitor.h"
#include "services/sync_monitor.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "util/log_macros.h"

#include <stdint.h>

/* Our height now, or -1 when the chain state is not reachable yet. Used as
 * the suspicion ONSET height, which is what separates a directory entry that
 * was already final network-wide from one minted after the split. */
static int32_t ndm_our_height(void)
{
    struct main_state *ms = sync_monitor_main_state();
    if (!ms)
        return -1;  // raw-return-ok:not an error -- chain state is simply not reachable yet at this point in boot; -1 is this helper's documented "height unknown" value and the policy treats it as an unknown onset (withhold, never guess)
    int h = active_chain_height(&ms->chain_active);
    return h < 0 ? -1 : (int32_t)h;
}

/* Reading the detector is cheap and side-effect free; folding the answer into
 * the policy is what makes the posture follow it in BOTH directions. Putting
 * that fold here rather than in remedy/witness is deliberate: the condition
 * engine guarantees detect runs on the poll cadence, so degraded mode can
 * neither latch on after the split heals nor wait on a witness window. */
static bool detect_netsplit_degraded_mode(void)
{
    struct network_partition_view pv = {0};
    bool suspected = network_monitor_netsplit_suspected(&pv);
    (void)directory_influence_observe(suspected, ndm_our_height(),
                                      pv.ready ? pv.reason : NULL);
    return suspected;
}

static enum condition_remedy_result remedy_netsplit_degraded_mode(void)
{
    LOG_WARN("condition",
             "[condition:netsplit_degraded_mode] SUSPECTED_NETSPLIT standing "
             "— directory influence withheld from entries finalized at/after "
             "height %d; tip-following, relay, explorer and wallet viewing "
             "unaffected",
             (int)directory_influence_split_onset_height());
    /* No local cure exists for a network split. The blocker is already named
     * by directory_influence_observe() and the posture is already correct;
     * reporting a successful remedy here would be a false claim. */
    return COND_REMEDY_FAILED;
}

static bool witness_netsplit_degraded_mode(int64_t target_at_detect)
{
    (void)target_at_detect;
    // honest-witness-ok:the verdict IS the observation (see below)
    /* network_monitor_netsplit_suspected() is not FSM or poison-absence
     * state: it is the standing result of a fold over live peer tip
     * observations (distinct address groups behind a rival hash at OUR
     * height) and over block arrival intervals measured against the chain's
     * own nBits. No cursor, H* or block_map read could witness "we are no
     * longer on the minority side" — a node on the wrong side of a split
     * advances its own tip perfectly happily, which is exactly why this
     * detector exists. Reading anything more local would be the DIShonest
     * witness here. The restore + blocker_clear are owned by the detect
     * pass, so this stays a pure read. */
    return !network_monitor_netsplit_suspected(NULL);
}

static struct condition c_netsplit_degraded_mode = {
    .name = "netsplit_degraded_mode",
    .severity = COND_WARN,
    .poll_secs = 30,
    .backoff_secs = 120,
    .max_attempts = 1,
    .cooldown_secs = 600,
    .cooldown_max_rearms = 0,
    .detect = detect_netsplit_degraded_mode,
    .remedy = remedy_netsplit_degraded_mode,
    .witness = witness_netsplit_degraded_mode,
    .witness_window_secs = 60,
};

void register_netsplit_degraded_mode(void)
{
    /* Install the policy behind core/modules/net's port here rather than in the
     * composition root: this condition is what DRIVES the posture, so the
     * port must be live before its first detect pass can publish a verdict,
     * and registering both in one place removes any chance of a boot ordering
     * where the condition runs while core/modules/net still reads UNGOVERNED. */
    directory_influence_register_port();
    (void)condition_register(&c_netsplit_degraded_mode);
}

#ifdef ZCL_TESTING
bool netsplit_degraded_mode_test_detect(void)
{
    return detect_netsplit_degraded_mode();
}
#endif
