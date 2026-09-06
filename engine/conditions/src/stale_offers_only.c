/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stale_offers_only condition — see conditions/stale_offers_only.h. The ZRC-
 * 0011 bounded first-boot wait (config/state_offer_store.h) already decides,
 * clocklessly, whether any peer offered an acceptable state in time. This
 * condition only turns a FALL_BACK decision into LOUD, self-clearing signage:
 * bootstrap.stale_offers_only, carrying the newest height any peer offered so
 * an operator learns "your peers are all stale, and this is how stale" rather
 * than watching a silent genesis fold. The node itself does not "fix" the
 * situation — it self-heals via normal from-genesis IBD, or an operator drops
 * a fresher bundle — this only makes the cause loud and self-clearing. */

#include "framework/condition.h"

#include "conditions/stale_offers_only.h"

#include "config/state_offer_store.h"
#include "jobs/reducer_frontier.h"  /* reducer_frontier_provable_tip_cached */
#include "util/blocker.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define SOO_SUBSYS "condition"
#define SOO_NAME   "stale_offers_only"
#define STALE_OFFERS_ONLY_BLOCKER_ID "bootstrap.stale_offers_only"
#define STALE_OFFERS_ONLY_OWNER      "bootstrap"

/* ZRC-0011: an offer is stale once its bundle height trails the offering
 * peer's own tip by more than this many blocks — UNLESS the bundle sits at
 * exactly the compiled checkpoint height, which is exempt from this window
 * (net/state_offer.h state_offer_height_is_fresh(): the installer already
 * grants that one bundle full sovereign trust by height alone, so its age
 * is irrelevant). Matches the contract text verbatim ("more than 576 blocks
 * behind"); used only in the reason string below, never in a runtime
 * comparison this condition performs itself — the store already applied the
 * rule before it ever falls back. */
#define STALE_OFFERS_ONLY_FRESHNESS_WINDOW_BLOCKS 576

/* false = "not raised this process": the remedy keepalive no-ops until the
 * bounded wait actually falls back. */
static _Atomic bool    g_active = false;
static _Atomic int32_t g_newest_height_seen = 0;
static _Atomic uint32_t g_peers_offering = 0;
static _Atomic uint32_t g_offers_seen = 0;
static _Atomic int32_t g_baseline_hstar = 0;

/* STABLE reason — no volatile heights, so the blocker's identity is constant
 * across re-fires (blocker.h keys rate-limit + escalation on it). The newest
 * height an operator needs lives in the log line and the test-visible facts,
 * not here.
 *
 * Length matters: blocker_init truncates at BLOCKER_REASON_MAX (256) and the
 * actionable tail — the bundles/ path an operator can act on — sits at the
 * END, so this wording is kept under that cap deliberately (228 bytes
 * formatted). A longer one silently loses the only sentence that says what to
 * do about it. */
static void build_reason(char *out, size_t cap)
{
    snprintf(out, cap,
             "no connected peer offered a state bundle within %d blocks of "
             "its own tip — the node is doing full from-genesis IBD; see "
             "node.log for the newest height any peer offered, or drop a "
             "fresher consensus bundle in <datadir>/bundles/",
             STALE_OFFERS_ONLY_FRESHNESS_WINDOW_BLOCKS);
}

static void raise_blocker(void)
{
    char reason[BLOCKER_REASON_MAX];
    build_reason(reason, sizeof(reason));
    struct blocker_record r;
    if (!blocker_init(&r, STALE_OFFERS_ONLY_BLOCKER_ID, STALE_OFFERS_ONLY_OWNER,
                      BLOCKER_DEPENDENCY, reason))
        return; // raw-return-ok:blocker-init-failed-already-logged
    r.retry_budget = -1; /* unbounded: clears on H* climb / an offer landing, never a TTL */
    (void)blocker_set(&r);
}

void stale_offers_only_raise(const struct stale_offers_only_facts *f)
{
    if (!f)
        return;
    atomic_store(&g_newest_height_seen, f->newest_height_seen);
    atomic_store(&g_peers_offering, f->peers_offering);
    atomic_store(&g_offers_seen, f->offers_seen);
    atomic_store(&g_baseline_hstar, f->baseline_hstar);
    atomic_store(&g_active, true);
    raise_blocker();
    LOG_WARN(SOO_SUBSYS,
             "[condition:%s] all connected peers' state offers are stale "
             "(newest_height_seen=%d peers_offering=%u offers_seen=%u "
             "baseline_hstar=%d) — named blocker %s; node proceeds with "
             "from-genesis IBD (clears on H* climb past %d or an acceptable "
             "offer landing)",
             SOO_NAME, f->newest_height_seen, f->peers_offering,
             f->offers_seen, f->baseline_hstar, STALE_OFFERS_ONLY_BLOCKER_ID,
             f->newest_height_seen);
}

static bool detect_stale_offers_only(void)
{
    /* Tracks the caller-raised blocker: active only while it stands. */
    return blocker_exists(STALE_OFFERS_ONLY_BLOCKER_ID);
}

static enum condition_remedy_result remedy_stale_offers_only(void)
{
    if (!atomic_load(&g_active))
        return COND_REMEDY_SKIP; // raw-return-ok:not-raised-this-process
    /* Observational: nothing to actively DO — the node self-heals via IBD or
     * an operator-provided fresher offer/bundle. Keepalive re-raise (stable
     * reason -> a rate-limited dup) so a stray external clear cannot silence
     * live signage, then report FAILED like no_state_source. The witness
     * clears the instant H* climbs past the newest stale height or an
     * acceptable offer is chosen. */
    raise_blocker();
    return COND_REMEDY_FAILED;
}

static bool witness_stale_offers_only(int64_t target_at_detect)
{
    (void)target_at_detect;
    struct state_offer_store_status st;
    state_offer_store_status_get(&st);
    /* Honest witness: clear only on OBSERVABLE forward progress — the fold's
     * provable tip (H*) climbed past the newest stale height any peer
     * offered, or the store went on to choose an acceptable offer after all.
     * Never a wall-time clear. */
    bool resolved =
        reducer_frontier_provable_tip_cached() >
            atomic_load(&g_newest_height_seen) ||
        st.chosen_height > 0;
    if (resolved) {
        blocker_clear(STALE_OFFERS_ONLY_BLOCKER_ID);
        atomic_store(&g_active, false); /* episode over: stop the keepalive re-raise */
    }
    return resolved;
}

static struct condition c_stale_offers_only = {
    .name = SOO_NAME,
    .severity = COND_WARN,
    .poll_secs = 20,
    .backoff_secs = 60,
    .max_attempts = 1,
    /* Continue-with-cooldown: this is a RECOVERABLE external-dependency wait
     * (a fresher offer can land / IBD can reach a serving peer), so never
     * latch forever — re-arm on a long backoff, unbounded, exactly like
     * no_state_source. */
    .cooldown_secs = 600,
    .cooldown_max_rearms = 0,
    .detect = detect_stale_offers_only,
    .remedy = remedy_stale_offers_only,
    .witness = witness_stale_offers_only,
    .witness_window_secs = 60,
};

void register_stale_offers_only(void)
{
    (void)condition_register(&c_stale_offers_only);
}

#ifdef ZCL_TESTING
void stale_offers_only_test_reset(void)
{
    atomic_store(&g_active, false);
    atomic_store(&g_newest_height_seen, 0);
    atomic_store(&g_peers_offering, 0);
    atomic_store(&g_offers_seen, 0);
    atomic_store(&g_baseline_hstar, 0);
    blocker_clear(STALE_OFFERS_ONLY_BLOCKER_ID);
    condition_reset_state(&c_stale_offers_only);
}

bool stale_offers_only_test_detect(void)
{
    return detect_stale_offers_only();
}

bool stale_offers_only_test_witness(void)
{
    return witness_stale_offers_only(0);
}

int32_t stale_offers_only_test_newest_height_seen(void)
{
    return atomic_load(&g_newest_height_seen);
}
#endif
