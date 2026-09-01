/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "conditions/utxo_activation_paused.h"
#include "util/log_macros.h"
#include "framework/condition.h"

#include "platform/time_compat.h"
#include "services/chain_activation_service.h"
#include "services/gap_fill_service.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/process_block.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static _Atomic int64_t g_paused_height_at_detect = -1;
static _Atomic int64_t g_paused_since_unix = 0;
static _Atomic int64_t g_pause_age_at_detect = 0;
static _Atomic int64_t g_tip_at_detect = -1;
static char g_pause_reason[128];

#ifdef ZCL_TESTING
static _Atomic int g_test_resume_calls;
static _Atomic int g_test_repair_calls;
static _Atomic bool g_test_remedy_clear_enabled = true;
#endif

static const char *pause_reason(void)
{
    return g_pause_reason[0] ? g_pause_reason : "utxo_activation_paused";
}

static bool pause_reason_is_drift(void)
{
    return strstr(pause_reason(), "utxo_audit_drift") != NULL;
}

static bool detect_utxo_activation_paused(void)
{
    int paused = process_block_get_utxo_activation_paused_height();
    int64_t now = platform_time_wall_unix();
    if (paused < 0) {
        atomic_store(&g_paused_since_unix, 0);
        atomic_store(&g_paused_height_at_detect, -1);
        atomic_store(&g_pause_age_at_detect, 0);
        atomic_store(&g_tip_at_detect, -1);
        return false;
    }

    int64_t first_seen = atomic_load(&g_paused_since_unix);
    if (first_seen == 0) {
        atomic_store(&g_paused_since_unix, now);
        return false;
    }

    int64_t age = now - first_seen;
    if (age < 300)
        return false;

    struct main_state *ms = condition_engine_main_state();
    atomic_store(&g_tip_at_detect,
                 ms ? (int64_t)active_chain_height(&ms->chain_active) : -1);
    atomic_store(&g_paused_height_at_detect, paused);
    atomic_store(&g_pause_age_at_detect, age);
    return true;
}

static void kick_local_activation(const char *reason)
{
    gap_fill_kick();

    struct chain_activation_controller *ctl = boot_activation_controller();
    if (!ctl || !ctl->ms || !ctl->coins_tip || !ctl->params || !ctl->datadir)
        return;

    enum activation_state state = activation_get_state(ctl);
    if (state != ACTIVATION_READY && state != ACTIVATION_AT_TIP)
        return;

    struct activation_exec_outcome outcome;
    memset(&outcome, 0, sizeof(outcome));
    activation_request_connect(ctl, ACTIVATION_SRC_HEADERS_ALL_DATA,
                               NULL, &outcome);
    if (outcome.result == ACTIVATION_EXEC_FAILED) {
        LOG_WARN("condition", "[condition:utxo_activation_paused] activation kick failed " "reason=%s outcome=%s", reason ? reason : "unspecified", outcome.reason[0] ? outcome.reason : "unknown");
    }
}

static enum condition_remedy_result remedy_utxo_activation_paused(void)
{
    int paused = process_block_get_utxo_activation_paused_height();
    if (paused < 0)
        return COND_REMEDY_SKIP;

    bool drift = pause_reason_is_drift();
    LOG_WARN("condition", "[condition:utxo_activation_paused] h=%d paused_for=%llds " "reason=%s action=%s", paused, (long long)atomic_load(&g_pause_age_at_detect), pause_reason(), drift ? "repair" : "resume");

#ifdef ZCL_TESTING
    bool clear_enabled = atomic_load(&g_test_remedy_clear_enabled);
#else
    bool clear_enabled = true;
#endif
    if (clear_enabled) {
        process_block_clear_utxo_activation_pause_range(paused, paused);
        kick_local_activation(drift ? "condition:utxo_activation_paused:repair"
                                    : "condition:utxo_activation_paused:resume");
    }

#ifdef ZCL_TESTING
    if (drift)
        atomic_fetch_add(&g_test_repair_calls, 1);
    else
        atomic_fetch_add(&g_test_resume_calls, 1);
#endif

    return COND_REMEDY_OK;
}

static bool witness_utxo_activation_paused(int64_t target_at_detect)
{
    (void)target_at_detect;
    /* Law 7: the remedy itself calls
     * process_block_clear_utxo_activation_pause_range(), so reading
     * "is the pause flag clear?" would let the remedy self-certify a clear
     * even if the stuck block never activated. An honest post-condition
     * requires the symptom to MOVE: the pause must be gone AND the active
     * chain tip must have advanced past the height that was paused (the
     * previously-wedged block actually activated and the chain moved
     * forward). The remedy unpauses + kicks activation; only real forward
     * progress, not the flag clear, satisfies this. */
    if (process_block_get_utxo_activation_paused_height() >= 0)
        return false;

    struct main_state *ms = condition_engine_main_state();
    int64_t tip = ms ? (int64_t)active_chain_height(&ms->chain_active) : -1;
    int64_t paused_h = atomic_load(&g_paused_height_at_detect);
    int64_t tip_at_detect = atomic_load(&g_tip_at_detect);
    if (tip < 0)
        return false;
    /* Tip reached the previously-paused height, or advanced past where it
     * was when we detected the stall — either proves the activation pipeline
     * resumed moving rather than just flipping a flag. */
    return tip >= paused_h || tip > tip_at_detect;
}

static struct condition c_utxo_activation_paused = {
    .name = "utxo_activation_paused",
    .severity = COND_CRITICAL,
    .poll_secs = 5,
    .backoff_secs = 30,
    .max_attempts = 2,
    .detect = detect_utxo_activation_paused,
    .remedy = remedy_utxo_activation_paused,
    .witness = witness_utxo_activation_paused,
    .witness_window_secs = 60,
};

void register_utxo_activation_paused(void)
{
    (void)condition_register(&c_utxo_activation_paused);
}

#ifdef ZCL_TESTING
void utxo_activation_paused_test_reset(void)
{
    atomic_store(&g_paused_height_at_detect, -1);
    atomic_store(&g_paused_since_unix, 0);
    atomic_store(&g_pause_age_at_detect, 0);
    atomic_store(&g_tip_at_detect, -1);
    atomic_store(&g_test_resume_calls, 0);
    atomic_store(&g_test_repair_calls, 0);
    atomic_store(&g_test_remedy_clear_enabled, true);
    g_pause_reason[0] = '\0';
}

void utxo_activation_paused_test_set_reason(const char *reason)
{
    snprintf(g_pause_reason, sizeof(g_pause_reason), "%s",
             reason ? reason : "");
}

void utxo_activation_paused_test_set_remedy_clear_enabled(bool enabled)
{
    atomic_store(&g_test_remedy_clear_enabled, enabled);
}

int utxo_activation_paused_test_resume_calls(void)
{
    return atomic_load(&g_test_resume_calls);
}

int utxo_activation_paused_test_repair_calls(void)
{
    return atomic_load(&g_test_repair_calls);
}
#endif
