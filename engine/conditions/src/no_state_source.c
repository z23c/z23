/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * no_state_source condition — see conditions/no_state_source.h. Observational:
 * boot_select_state_source RAISES the bootstrap.no_state_source blocker the
 * instant it concludes with no fast-start state source; this condition tracks
 * that blocker and clears it on the honest witness (H* climbed past the genesis
 * baseline, or a state source landed), never on wall time. The node itself does
 * not "fix" the situation here — it self-heals via normal from-genesis IBD or an
 * operator-provided source; this only makes the cause LOUD and self-clearing. */

#include "framework/condition.h"

#include "conditions/no_state_source.h"

#include "config/boot_consensus_bundle_marker.h"   /* boot_consensus_bundle_marker_exists */
#include "controllers/agent_controller.h"           /* agent_runtime_context_datadir */
#include "jobs/reducer_frontier.h"                   /* reducer_frontier_provable_tip_cached */
#include "util/blocker.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define NSS_SUBSYS "condition"
#define NSS_NAME   "no_state_source"
#define NO_STATE_SOURCE_BLOCKER_ID "bootstrap.no_state_source"
#define NO_STATE_SOURCE_OWNER      "bootstrap"

/* -1 = "not raised this process": the remedy keepalive no-ops until
 * boot_select_state_source names the situation. */
static _Atomic int     g_fetch_outcome = -1;
static _Atomic int     g_bundle_status = 0;
static _Atomic int32_t g_baseline_hstar = 0;

#ifdef ZCL_TESTING
static const char *g_test_datadir;
#endif

static const char *fetch_token(enum no_state_source_fetch_outcome o)
{
    switch (o) {
    case NO_STATE_SOURCE_FETCH_SKIPPED:         return "skipped";
    case NO_STATE_SOURCE_FETCH_NO_SEED:         return "no_seed";
    case NO_STATE_SOURCE_FETCH_DOWNLOAD_FAILED: return "download_failed";
    case NO_STATE_SOURCE_FETCH_SEEDS_EMPTY:     return "seeds_empty";
    }
    return "unknown";
}

static const char *bundle_token(enum no_state_source_bundle_status b)
{
    switch (b) {
    case NO_STATE_SOURCE_BUNDLE_NONE:   return "none";
    case NO_STATE_SOURCE_BUNDLE_FAILED: return "failed";
    }
    return "unknown";
}

/* STABLE reason — no volatile heights/timestamps, so the blocker's identity is
 * constant across re-fires (blocker.h keys rate-limit + escalation on it). */
static void build_reason(char *out, size_t cap,
                         enum no_state_source_fetch_outcome fetch,
                         enum no_state_source_bundle_status bundle)
{
    snprintf(out, cap,
             "no fast-start state source selected (fetch=%s bundle=%s) — the "
             "node is doing full from-genesis IBD; to fast-start, pass "
             "-fileservice=HOST:PORT or drop a consensus bundle in "
             "<datadir>/bundles/",
             fetch_token(fetch), bundle_token(bundle));
}

static void raise_blocker(enum no_state_source_fetch_outcome fetch,
                          enum no_state_source_bundle_status bundle)
{
    char reason[BLOCKER_REASON_MAX];
    build_reason(reason, sizeof(reason), fetch, bundle);
    struct blocker_record r;
    if (!blocker_init(&r, NO_STATE_SOURCE_BLOCKER_ID, NO_STATE_SOURCE_OWNER,
                      BLOCKER_DEPENDENCY, reason))
        return; // raw-return-ok:blocker-init-failed-already-logged
    r.retry_budget = -1; /* unbounded: clears on H* climb / source landing, never a TTL */
    (void)blocker_set(&r);
}

void no_state_source_raise(const struct no_state_source_facts *f)
{
    if (!f)
        return;
    atomic_store(&g_fetch_outcome, (int)f->fetch);
    atomic_store(&g_bundle_status, (int)f->bundle);
    atomic_store(&g_baseline_hstar, f->baseline_hstar);
    raise_blocker(f->fetch, f->bundle);
    LOG_WARN(NSS_SUBSYS,
             "[condition:%s] no fast-start state source (fetch=%s bundle=%s) — "
             "named blocker %s; node proceeds with from-genesis IBD (clears on "
             "H* climb or a state source landing)",
             NSS_NAME, fetch_token(f->fetch), bundle_token(f->bundle),
             NO_STATE_SOURCE_BLOCKER_ID);
}

static const char *nss_datadir(void)
{
#ifdef ZCL_TESTING
    if (g_test_datadir && g_test_datadir[0])
        return g_test_datadir;
#endif
    return agent_runtime_context_datadir();
}

/* A sovereign consensus-state install landed on this datadir after the raise —
 * a state source arrived, so the signage is stale. */
static bool nss_source_landed(void)
{
    const char *dd = nss_datadir();
    return dd && dd[0] && boot_consensus_bundle_marker_exists(dd);
}

static bool detect_no_state_source(void)
{
    /* Tracks the boot-raised blocker: active only while it stands. */
    return blocker_exists(NO_STATE_SOURCE_BLOCKER_ID);
}

static enum condition_remedy_result remedy_no_state_source(void)
{
    int fetch = atomic_load(&g_fetch_outcome);
    if (fetch < 0)
        return COND_REMEDY_SKIP; // raw-return-ok:not-raised-this-process
    /* Observational: nothing to actively DO — the node self-heals via IBD or an
     * operator-provided source. Keepalive re-raise (stable reason → a
     * rate-limited dup) so a stray external clear cannot silence live signage,
     * then report FAILED like net_fork_detected. The witness clears the instant
     * a source lands / H* climbs; if the node stays genuinely stuck, the engine
     * pages the operator once the episode ages out with the actionable hint. */
    raise_blocker((enum no_state_source_fetch_outcome)fetch,
                  (enum no_state_source_bundle_status)atomic_load(&g_bundle_status));
    return COND_REMEDY_FAILED;
}

static bool witness_no_state_source(int64_t target_at_detect)
{
    (void)target_at_detect;
    /* Honest witness: clear only on OBSERVABLE forward progress — the fold's
     * provable tip (H*) climbed past the genesis baseline captured at raise, or a
     * sovereign state source landed. Never a wall-time / poison-absence clear. */
    bool resolved =
        reducer_frontier_provable_tip_cached() > atomic_load(&g_baseline_hstar) ||
        nss_source_landed();
    if (resolved) {
        blocker_clear(NO_STATE_SOURCE_BLOCKER_ID);
        atomic_store(&g_fetch_outcome, -1); /* episode over: stop the keepalive re-raise */
    }
    return resolved;
}

static struct condition c_no_state_source = {
    .name = NSS_NAME,
    .severity = COND_WARN,
    .poll_secs = 20,
    .backoff_secs = 60,
    .max_attempts = 1,
    /* Continue-with-cooldown: this is a RECOVERABLE external-dependency wait (a
     * source can land / IBD can reach a serving peer), so never latch forever —
     * re-arm on a long backoff, unbounded, exactly like net_fork_detected. */
    .cooldown_secs = 600,
    .cooldown_max_rearms = 0,
    .detect = detect_no_state_source,
    .remedy = remedy_no_state_source,
    .witness = witness_no_state_source,
    .witness_window_secs = 60,
};

void register_no_state_source(void)
{
    (void)condition_register(&c_no_state_source);
}

#ifdef ZCL_TESTING
void no_state_source_test_reset(void)
{
    atomic_store(&g_fetch_outcome, -1);
    atomic_store(&g_bundle_status, 0);
    atomic_store(&g_baseline_hstar, 0);
    g_test_datadir = NULL;
    blocker_clear(NO_STATE_SOURCE_BLOCKER_ID);
    condition_reset_state(&c_no_state_source);
}

void no_state_source_test_set_datadir(const char *datadir)
{
    g_test_datadir = datadir;
}

bool no_state_source_test_detect(void)
{
    return detect_no_state_source();
}

bool no_state_source_test_witness(void)
{
    return witness_no_state_source(0);
}
#endif
