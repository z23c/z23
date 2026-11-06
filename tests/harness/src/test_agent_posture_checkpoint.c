/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_agent_posture_checkpoint — a node whose chain state was installed from
 * a consensus bundle at a height whose complete commitment is compiled into
 * the binary (CHECKPOINT_ROM keystone or ladder rung) reports the distinct
 * posture state `checkpoint_verified` and is ready for local use, while the
 * public-serving and soak gate (review_required) keeps its full-history
 * requirement.
 *
 * Fixtures are isolated tmp progress stores seeded with exactly the durable
 * facts the bundle activate writes (consensus_state_snapshot_install_
 * activate.c): migration-complete, coins_applied_height = H+1, the external
 * seed floor H, and either self_folded (sovereign tier) or the assisted seam
 * (assisted tier). The compiled checkpoint is the ROM override at H. The
 * spend guard's decision on each fixture is pinned so this surface can never
 * drift from it. */

#include "test/test_core.h"

#include "chain/checkpoints.h"
#include "config/consensus_state_snapshot_install.h"
#include "controllers/agent_security_posture.h"
#include "controllers/operator_needed_policy.h"
#include "controllers/sovereignty_controller.h"
#include "controllers/status_native_handlers.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "models/database.h"
#include "services/chain_evidence_authority_service.h"
#include "services/operator_snapshot_service.h"
#include "storage/anchor_kv.h"
#include "storage/coins_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "../../../engine/controllers/src/api_controller_internal.h"
#include "../../../cognition/controllers/src/event_agent_summary_internal.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CP_HEIGHT 3200000

#define CP_CHECK(name, expr) do {                                 \
    printf("agent_posture_checkpoint: %s... ", (name));           \
    if (expr) { printf("OK\n"); }                                 \
    else { printf("FAIL\n"); failures++; }                        \
} while (0)

/* Which install shape a fixture reproduces. */
struct cp_shape {
    bool self_folded;     /* sovereign tier stamp */
    bool assisted_seam;   /* assisted tier seam */
    bool seed_floor;      /* external-seed floor (any bundle install) */
    int64_t history_cursor; /* anchor + nullifier activation cursor */
    int32_t baked_height; /* compiled ROM commitment height */
    int stamp_kind;       /* install authority stamp; 0 = none written */
    int32_t stamp_height; /* stamp height; 0 = CP_HEIGHT */
    bool stamp_root_mismatch; /* stamp a UTXO root the ROM does not hold */
    int32_t first_floor;  /* a floor declared earlier (kept first); 0 = none */
    int32_t applied_skew; /* coins_applied_height = CP_HEIGHT + 1 + skew */
};

struct cp_fixture {
    char dir[256];
    struct node_db ndb;
    struct rom_state_checkpoint rom;
    bool open;
};

static void cp_fill_rom(struct rom_state_checkpoint *rom, int32_t height)
{
    memset(rom, 0, sizeof(*rom));
    rom->height = height;
    memset(rom->block_hash, 0x21, 32);
    memset(rom->utxo_root, 0x22, 32);
    memset(rom->anchor_digest, 0x23, 32);
    memset(rom->sprout_frontier_root, 0x24, 32);
    memset(rom->sapling_frontier_root, 0x25, 32);
    memset(rom->nullifier_digest, 0x26, 32);
    memset(rom->rom_state_root, 0x27, 32);
    rom->utxo_count = 1;
}

static bool cp_seed_schema(sqlite3 *pdb, int64_t cursor)
{
    static const uint8_t txid[32] = {0x5a};
    static const uint8_t script[] = {0x51};
    return coins_kv_ensure_schema(pdb) && progress_meta_table_ensure(pdb) &&
           anchor_kv_ensure_schema(pdb) && nullifier_kv_ensure_schema(pdb) &&
           anchor_kv_initialize_history(pdb, cursor) &&
           nullifier_kv_initialize_history(pdb, cursor) &&
           coins_kv_add(pdb, txid, 0, 4242, CP_HEIGHT, false, script,
                        sizeof(script));
}

/* The authority stamp the activate writes, bound to the compiled ROM
 * (cp_fill_rom) unless the shape asks for a mismatched root. */
static bool cp_seed_stamp(sqlite3 *pdb, const struct cp_shape *shape)
{
    if (!shape->stamp_kind)
        return true;
    struct consensus_state_install_stamp st = {
        .kind = (enum consensus_state_install_stamp_kind)shape->stamp_kind,
        .height = shape->stamp_height ? shape->stamp_height : CP_HEIGHT,
    };
    memset(st.block_hash, 0x21, 32);
    memset(st.utxo_root, shape->stamp_root_mismatch ? 0x99 : 0x22, 32);
    return consensus_state_install_record_authority_stamp(pdb, &st);
}

/* The activate's tier markers, in one transaction under the store lock. */
static bool cp_seed_markers(sqlite3 *pdb, const struct cp_shape *shape)
{
    static const uint8_t one = 1;
    uint8_t root[32];
    memset(root, 0x33, sizeof(root));
    progress_store_tx_lock();
    bool ok = sqlite3_exec(pdb, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK;
    ok = ok && progress_meta_set_in_tx(pdb, COINS_KV_MIGRATION_COMPLETE_KEY,
                                       &one, 1) &&
         coins_kv_set_applied_height_in_tx(pdb,
                                           CP_HEIGHT + 1 + shape->applied_skew);
    if (ok && shape->self_folded)
        ok = progress_meta_set_in_tx(pdb, COINS_KV_SELF_FOLDED_KEY, &one, 1);
    if (ok && shape->assisted_seam)
        ok = consensus_state_install_record_assisted_seam(pdb, CP_HEIGHT, root,
                                                          root, root);
    if (ok && shape->first_floor)
        ok = reducer_seed_floor_declare_if_absent(pdb, shape->first_floor);
    if (ok && shape->seed_floor)
        ok = reducer_seed_floor_declare_if_absent(pdb, CP_HEIGHT);
    if (ok)
        ok = cp_seed_stamp(pdb, shape);
    ok = sqlite3_exec(pdb, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL) ==
             SQLITE_OK && ok;
    progress_store_tx_unlock();
    return ok;
}

static bool cp_open(struct cp_fixture *fx, const char *label,
                    const struct cp_shape *shape)
{
    memset(fx, 0, sizeof(*fx));
    test_make_tmpdir(fx->dir, sizeof(fx->dir), "agent_posture_checkpoint",
                     label);
    progress_store_close();
    if (!progress_store_open(fx->dir)) {
        test_cleanup_tmpdir(fx->dir);
        return false;
    }
    if (!node_db_open(&fx->ndb, ":memory:")) {
        progress_store_close();
        test_cleanup_tmpdir(fx->dir);
        return false;
    }
    fx->open = true;
    cp_fill_rom(&fx->rom, shape->baked_height);
    checkpoints_set_rom_state_override_for_test(&fx->rom);
    /* Replace the compiled ladder (it bakes a real rung at 3,200,000) with
     * one unbaked placeholder, so the keystone override is the only commitment. */
    static const struct rom_state_rung placeholder = { .cp = { .height = 7 } };
    checkpoints_set_rom_state_rungs_override_for_test(&placeholder, 1);
    reducer_frontier_provable_tip_set(CP_HEIGHT);
    sqlite3 *pdb = progress_store_db();
    return cp_seed_schema(pdb, shape->history_cursor) &&
           cp_seed_markers(pdb, shape);
}

static void cp_close(struct cp_fixture *fx)
{
    if (!fx->open)
        return;
    reducer_frontier_provable_tip_reset();
    checkpoints_reset_rom_state_rungs_override_for_test();
    checkpoints_reset_rom_state_override_for_test();
    node_db_close(&fx->ndb);
    progress_store_close();
    test_cleanup_tmpdir(fx->dir);
    fx->open = false;
}

/* The posture rendered exactly as status renders it. */
static bool cp_json_has(const struct agent_security_posture *p,
                        const char *needle)
{
    struct json_value root = {0};
    static char text[8192];
    json_set_object(&root);
    agent_push_security_posture_snapshot_json(&root, "security_posture", p);
    size_t n = json_write(&root, text, sizeof(text));
    json_free(&root);
    return n < sizeof(text) && strstr(text, needle) != NULL;
}

/* The /api/status ladder on an otherwise healthy node. */
static enum node_status_reason cp_ladder(const struct agent_security_posture *p)
{
    struct node_health_snapshot health = {0};
    struct download_stats_snapshot download = {0};
    health.serving = true;
    health.healthy = true;
    health.has_peers = true;
    return api_node_summary_select_reason(&health, p, NULL, false, &download)
        .reason;
}

/* The `agent` status ladder (the phone's path) on an otherwise clean node:
 * true when a leading rung stops it. */
static bool cp_agent_rung_stops(const struct agent_security_posture *p)
{
    static struct agent_fast_snapshot health;
    enum node_status_reason reason = ZCL_STATUS_REASON_NONE;
    const char *primary = "none", *next = "none";
    memset(&health, 0, sizeof(health));
    health.peer_snapshot_available = true;
    health.has_peers = true;
    return agent_summary_pick_leading_reason(&health, p, &reason, &primary,
                                             &next) ||
           reason != ZCL_STATUS_REASON_NONE;
}

/* /health and healthcheck on a node whose own health is green: the HTTP code
 * follows public serving; local readiness is a body field. */
static struct api_health_flags cp_health_flags(const struct agent_security_posture *p)
{
    struct node_health_snapshot health = {0};
    health.serving = true;
    health.healthy = true;
    return api_health_flags(&health, p, NULL);
}

static bool cp_spend_allowed(void)
{
    char reason[128];
    return sovereignty_guard_peek("wallet_spend", reason, sizeof(reason));
}

static bool cp_str_is(const struct json_value *v, const char *want)
{
    const char *s = v ? json_get_str(v) : NULL;
    return s && strcmp(s, want) == 0;
}

/* The phone-facing trust object. No background walk runs in the harness, so
 * the check reads not_running at 0%. */
static int cp_check_trust(const struct agent_security_posture *p)
{
    int failures = 0;
    struct json_value root = {0};
    json_set_object(&root);
    agent_push_status_trust_json(&root, "trust", p, true);
    const struct json_value *t = json_get(&root, "trust");
    const struct json_value *hc = json_get(t, "history_check");
    const char *summary = json_get_str(json_get(t, "summary"));
    printf("agent_posture_checkpoint: summary=\"%s\"\n",
           summary ? summary : "(null)");
    CP_CHECK("trust: typed schema, checkpoint source and height",
             cp_str_is(json_get(t, "schema"), "zcl.status_trust.v1") &&
             cp_str_is(json_get(t, "source"), "checkpoint") &&
             json_get_int(json_get(t, "checkpoint_height")) == CP_HEIGHT);
    CP_CHECK("trust: history check is visible and not claimed done",
             cp_str_is(json_get(hc, "state"), "not_running") &&
             json_get_int(json_get(hc, "percent")) == 0);
    CP_CHECK("trust: one plain summary line",
             summary && strcmp(summary,
                 "Ready. Verified from checkpoint 3,200,000 built into this "
                 "version; background check 0%.") == 0);
    json_free(&root);
    return failures;
}

static int case_checkpoint_install_is_verified(void)
{
    int failures = 0;
    struct cp_fixture fx;
    const struct cp_shape shape = {
        .self_folded = true, .seed_floor = true, .baked_height = CP_HEIGHT,
        .stamp_kind = CONSENSUS_INSTALL_STAMP_CHECKPOINT_ROM,
    };
    bool ok = cp_open(&fx, "rom", &shape);
    CP_CHECK("rom: sovereign-tier install fixture seeds", ok);
    if (!ok) {
        cp_close(&fx);
        return failures;
    }
    struct agent_security_posture p;
    agent_security_posture_collect(&p, &fx.ndb);
    CP_CHECK("rom: posture state is checkpoint_verified",
             strcmp(p.status, "checkpoint_verified") == 0);
    CP_CHECK("rom: next action waits for the history check, no operator",
             strcmp(p.next_action, "wait_for_full_history_check") == 0);
    CP_CHECK("rom: rendered posture names the checkpoint and its height",
             cp_json_has(&p, "\"checkpoint_verified\":true") &&
             cp_json_has(&p, "\"checkpoint_height\":3200000"));
    CP_CHECK("rom: never claims full-history validation",
             !p.full_history_validation_complete &&
             strcmp(p.full_history_validation_origin, "genesis_history") != 0 &&
             strcmp(p.full_history_validation_origin, "assisted_snapshot") != 0);
    CP_CHECK("rom: public serving and soak gate keep full-history requirement",
             p.review_required && !agent_security_posture_allows_public_serving(&p));
    CP_CHECK("rom: status ladder does not stop at the posture rung",
             cp_ladder(&p) == ZCL_STATUS_REASON_NONE);
    CP_CHECK("rom: agent status ladder passes the posture rung",
             !cp_agent_rung_stops(&p));
    CP_CHECK("rom: spend guard allows (pinned, unchanged)", cp_spend_allowed());
    CP_CHECK("rom: local readiness allowed, review not needed",
             p.checkpoint_verified && p.checkpoint_height == CP_HEIGHT &&
             agent_security_posture_allows_local_ready(&p) &&
             !agent_security_posture_needs_review(&p));
    struct api_health_flags hf = cp_health_flags(&p);
    CP_CHECK("rom: /health stays not-serving (503); local_ready is a body fact",
             !hf.public_serving && !hf.public_healthy && hf.local_ready);
    CP_CHECK("rom: one Ready definition for every status surface",
             agent_security_posture_local_ready(&p, true, true, false) &&
             !agent_security_posture_local_ready(&p, false, true, false) &&
             !agent_security_posture_local_ready(&p, true, false, false) &&
             !agent_security_posture_local_ready(&p, true, true, true));
    failures += cp_check_trust(&p);
    cp_close(&fx);
    return failures;
}

/* Every non-checkpoint shape keeps the bootstrap-trust review. */
static int cp_expect_review(const char *label, const struct cp_shape *shape,
                            const char *want_status, bool want_spend)
{
    int failures = 0;
    struct cp_fixture fx;
    char name[160];
    bool ok = cp_open(&fx, label, shape);
    snprintf(name, sizeof(name), "%s: fixture seeds", label);
    CP_CHECK(name, ok);
    if (!ok) {
        cp_close(&fx);
        return failures;
    }
    struct agent_security_posture p;
    agent_security_posture_collect(&p, &fx.ndb);
    snprintf(name, sizeof(name), "%s: status stays %s", label, want_status);
    CP_CHECK(name, strcmp(p.status, want_status) == 0);
    snprintf(name, sizeof(name), "%s: not checkpoint verified", label);
    CP_CHECK(name, !cp_json_has(&p, "\"checkpoint_verified\":true"));
    snprintf(name, sizeof(name), "%s: posture rung still stops the ladder",
             label);
    CP_CHECK(name, cp_ladder(&p) == ZCL_STATUS_REASON_POSTURE_REVIEW &&
                   p.review_required && !p.checkpoint_verified &&
                   agent_security_posture_needs_review(&p) &&
                   !agent_security_posture_allows_local_ready(&p));
    snprintf(name, sizeof(name), "%s: agent status ladder stops at posture",
             label);
    CP_CHECK(name, cp_agent_rung_stops(&p));
    struct api_health_flags hf = cp_health_flags(&p);
    snprintf(name, sizeof(name), "%s: not ready, /health not serving", label);
    CP_CHECK(name, !hf.public_serving && !hf.public_healthy && !hf.local_ready &&
                   !agent_security_posture_local_ready(&p, true, true, false));
    snprintf(name, sizeof(name), "%s: spend guard %s (pinned, unchanged)",
             label, want_spend ? "allows" : "refuses");
    CP_CHECK(name, cp_spend_allowed() == want_spend);
    cp_close(&fx);
    return failures;
}

#define CP_ROM CONSENSUS_INSTALL_STAMP_CHECKPOINT_ROM

static int case_other_installs_stay_reviewed(void)
{
    int failures = 0;
    const struct cp_shape assisted = {
        .assisted_seam = true, .seed_floor = true, .baked_height = CP_HEIGHT,
        .stamp_kind = CONSENSUS_INSTALL_STAMP_ASSISTED,
    };
    failures += cp_expect_review("assisted", &assisted,
                                 "review_required_bootstrap_trust", false);
    const struct cp_shape promoted = {
        .self_folded = true, .assisted_seam = true, .seed_floor = true,
        .baked_height = CP_HEIGHT, .stamp_kind = CP_ROM,
    };
    failures += cp_expect_review("promoted_assisted", &promoted,
                                 "review_required_bootstrap_trust", true);
    const struct cp_shape unbaked = {
        .self_folded = true, .seed_floor = true, .baked_height = CP_HEIGHT + 1,
        .stamp_kind = CP_ROM,
    };
    failures += cp_expect_review("unbaked_height", &unbaked,
                                 "review_required_bootstrap_trust", true);
    const struct cp_shape unseeded = {
        .self_folded = true, .baked_height = CP_HEIGHT,
    };
    failures += cp_expect_review("genesis_mid_fold", &unseeded,
                                 "review_required_bootstrap_trust", true);
    const struct cp_shape gap = {
        .self_folded = true, .seed_floor = true, .baked_height = CP_HEIGHT,
        .history_cursor = 500, .stamp_kind = CP_ROM,
    };
    failures += cp_expect_review("anchor_gap", &gap,
                                 "review_required_anchor_backfill_gap", true);
    return failures;
}

/* The floor alone never proves a CHECKPOINT_ROM install: it is written by
 * every authority and by cold import, and it keeps the first declaration.
 * Only the activate's authority stamp, at the floor and bound to the compiled
 * commitment, does. Each shape is sovereign, so the spend guard allows. */
static int case_floor_alone_is_not_rom(void)
{
    int failures = 0;
    const struct cp_shape unstamped = {
        .self_folded = true, .seed_floor = true, .baked_height = CP_HEIGHT,
    };
    failures += cp_expect_review("no_install_stamp", &unstamped,
                                 "review_required_bootstrap_trust", true);
    const struct cp_shape receipt = {
        .self_folded = true, .seed_floor = true, .baked_height = CP_HEIGHT,
        .stamp_kind = CONSENSUS_INSTALL_STAMP_RECEIPT,
    };
    failures += cp_expect_review("receipt_at_baked_height", &receipt,
                                 "review_required_bootstrap_trust", true);
    const struct cp_shape content = {
        .self_folded = true, .seed_floor = true, .baked_height = CP_HEIGHT,
        .stamp_kind = CONSENSUS_INSTALL_STAMP_CHECKPOINT_CONTENT,
    };
    failures += cp_expect_review("content_at_baked_height", &content,
                                 "review_required_bootstrap_trust", true);
    const struct cp_shape reinstall = {
        .self_folded = true, .first_floor = CP_HEIGHT,
        .baked_height = CP_HEIGHT,
        .stamp_kind = CONSENSUS_INSTALL_STAMP_RECEIPT,
        .stamp_height = CP_HEIGHT + 5,
    };
    failures += cp_expect_review("stale_floor_then_receipt", &reinstall,
                                 "review_required_bootstrap_trust", true);
    const struct cp_shape moved = {
        .self_folded = true, .first_floor = CP_HEIGHT,
        .baked_height = CP_HEIGHT, .stamp_kind = CP_ROM,
        .stamp_height = CP_HEIGHT + 5,
    };
    failures += cp_expect_review("stale_floor_rom_elsewhere", &moved,
                                 "review_required_bootstrap_trust", true);
    const struct cp_shape mismatch = {
        .self_folded = true, .seed_floor = true, .baked_height = CP_HEIGHT,
        .stamp_kind = CP_ROM, .stamp_root_mismatch = true,
    };
    failures += cp_expect_review("rom_stamp_root_mismatch", &mismatch,
                                 "review_required_bootstrap_trust", true);
    return failures;
}

/* The spend guard's own trust derivation decides: a borrowed seed with no
 * seam and no refold marker, or coins applied off H*+1, is not sovereign, so
 * neither is labeled and spend refuses (pinned). */
static int case_trust_shapes_stay_reviewed(void)
{
    int failures = 0;
    const struct cp_shape borrowed = {
        .seed_floor = true, .baked_height = CP_HEIGHT, .stamp_kind = CP_ROM,
    };
    failures += cp_expect_review("borrowed_no_seam", &borrowed,
                                 "review_required_bootstrap_trust", false);
    const struct cp_shape skewed = {
        .self_folded = true, .seed_floor = true, .baked_height = CP_HEIGHT,
        .stamp_kind = CP_ROM, .applied_skew = 1,
    };
    failures += cp_expect_review("applied_not_hstar_plus_one", &skewed,
                                 "review_required_bootstrap_trust", false);
    return failures;
}

/* A fold re-stamps what the reseed reset cleared: migration-complete, the
 * refold marker and coins applied at H*+1. The floor and the ROM stamp are
 * untouched by both. */
static bool cp_refold_after_reset(sqlite3 *pdb)
{
    static const uint8_t txid[32] = {0x6b};
    static const uint8_t script[] = {0x51};
    static const uint8_t one = 1;
    if (!coins_kv_reset_for_reseed(pdb) ||
        !coins_kv_add(pdb, txid, 0, 77, 50000, false, script, sizeof(script)))
        return false;
    progress_store_tx_lock();
    bool ok = sqlite3_exec(pdb, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK;
    ok = ok && progress_meta_set_in_tx(pdb, COINS_KV_MIGRATION_COMPLETE_KEY,
                                       &one, 1) &&
         progress_meta_set_in_tx(pdb, COINS_KV_SELF_FOLDED_KEY, &one, 1) &&
         coins_kv_set_applied_height_in_tx(pdb, CP_HEIGHT + 1);
    ok = sqlite3_exec(pdb, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL) ==
             SQLITE_OK && ok;
    progress_store_tx_unlock();
    return ok;
}

/* -reindex, a staged or genesis refold and a mint-anchor reset all reset the
 * coins through coins_kv_reset_for_reseed. Coins folded afterwards are not the
 * checkpoint install, even when they reach H*+1 again under the same floor. */
static int case_reseed_after_rom_drops_checkpoint(void)
{
    int failures = 0;
    struct cp_fixture fx;
    const struct cp_shape shape = {
        .self_folded = true, .seed_floor = true, .baked_height = CP_HEIGHT,
        .stamp_kind = CP_ROM,
    };
    bool ok = cp_open(&fx, "reseed", &shape);
    CP_CHECK("reseed: checkpoint install fixture seeds", ok);
    struct agent_security_posture p;
    if (ok) {
        agent_security_posture_collect(&p, &fx.ndb);
        CP_CHECK("reseed: checkpoint verified before the reset",
                 p.checkpoint_verified);
    }
    ok = ok && cp_refold_after_reset(progress_store_db());
    CP_CHECK("reseed: reset then refold to H*+1 commits", ok);
    if (ok) {
        agent_security_posture_collect(&p, &fx.ndb);
        CP_CHECK("reseed: no longer labeled checkpoint verified",
                 !p.checkpoint_verified &&
                 !cp_json_has(&p, "\"checkpoint_verified\":true") &&
                 strcmp(p.status, "review_required_bootstrap_trust") == 0);
        CP_CHECK("reseed: review kept, posture rung stops the ladder",
                 p.review_required && agent_security_posture_needs_review(&p) &&
                 cp_ladder(&p) == ZCL_STATUS_REASON_POSTURE_REVIEW);
        CP_CHECK("reseed: spend guard allows sovereign refold (pinned, unchanged)",
                 cp_spend_allowed());
    }
    cp_close(&fx);
    return failures;
}

struct cp_holder {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    bool held;
    bool release;
};

static void *cp_hold_progress_lock(void *arg)
{
    struct cp_holder *h = arg;
    progress_store_tx_lock();
    pthread_mutex_lock(&h->mu);
    h->held = true;
    pthread_cond_broadcast(&h->cv);
    while (!h->release)
        pthread_cond_wait(&h->cv, &h->mu);
    pthread_mutex_unlock(&h->mu);
    progress_store_tx_unlock();
    return NULL;
}

/* A busy progress store answers the labeled busy partial: never the
 * checkpoint label, never a lifted gate. */
static int case_busy_store_is_not_checkpoint(void)
{
    int failures = 0;
    struct cp_fixture fx;
    const struct cp_shape shape = {
        .self_folded = true, .seed_floor = true, .baked_height = CP_HEIGHT,
        .stamp_kind = CP_ROM,
    };
    bool ok = cp_open(&fx, "busy", &shape);
    CP_CHECK("busy: checkpoint fixture seeds", ok);
    struct cp_holder h = { .mu = PTHREAD_MUTEX_INITIALIZER,
                           .cv = PTHREAD_COND_INITIALIZER };
    pthread_t th;
    if (ok && pthread_create(&th, NULL, cp_hold_progress_lock, &h) == 0) {
        pthread_mutex_lock(&h.mu);
        while (!h.held)
            pthread_cond_wait(&h.cv, &h.mu);
        pthread_mutex_unlock(&h.mu);
        struct agent_security_posture p;
        agent_security_posture_collect(&p, &fx.ndb);
        pthread_mutex_lock(&h.mu);
        h.release = true;
        pthread_cond_broadcast(&h.cv);
        pthread_mutex_unlock(&h.mu);
        pthread_join(th, NULL);
        CP_CHECK("busy: labeled busy, not checkpoint verified, review kept",
                 strcmp(p.status, "review_required_progress_store_busy") == 0 &&
                 !p.checkpoint_verified && p.review_required &&
                 agent_security_posture_needs_review(&p));
    }
    cp_close(&fx);
    return failures;
}

static int case_genesis_full_history_unchanged(void)
{
    int failures = 0;
    struct cp_fixture fx;
    const struct cp_shape genesis = {
        .self_folded = true, .baked_height = CP_HEIGHT,
    };
    bool ok = cp_open(&fx, "genesis", &genesis) &&
        node_db_state_set(&fx.ndb, "cec.sync_state", "fully_validated",
                          sizeof "fully_validated") &&
        node_db_state_set_int(&fx.ndb, "cec.full_validation_origin",
                              CEC_FULL_VALIDATION_GENESIS_HISTORY);
    CP_CHECK("genesis: full-history fixture seeds", ok);
    if (ok) {
        struct agent_security_posture p;
        agent_security_posture_collect(&p, &fx.ndb);
        CP_CHECK("genesis: status ok, no review, public serving allowed",
                 strcmp(p.status, "ok") == 0 && !p.review_required &&
                 agent_security_posture_allows_public_serving(&p));
        CP_CHECK("genesis: not labeled as a checkpoint install",
                 !cp_json_has(&p, "\"checkpoint_verified\":true"));
        CP_CHECK("genesis: ladder passes the posture rung",
                 cp_ladder(&p) == ZCL_STATUS_REASON_NONE);
        struct api_health_flags hf = cp_health_flags(&p);
        CP_CHECK("genesis: /health serving and healthy, locally ready",
                 hf.public_serving && hf.public_healthy && hf.local_ready);
    }
    cp_close(&fx);
    return failures;
}

/* The soak and operator-snapshot verdict reads review_required; only the
 * label it quotes may differ between the two posture states. */
static int case_soak_verdict_unchanged(void)
{
    int failures = 0;
    static struct operator_capture before, after;
    memset(&before, 0, sizeof(before));
    before.security_review_required = true;
    snprintf(before.security_posture_status,
             sizeof(before.security_posture_status), "%s",
             "review_required_bootstrap_trust");
    snprintf(before.security_posture_next_action,
             sizeof(before.security_posture_next_action), "%s",
             "finish_sovereign_refold_and_full_history_validation");
    after = before;
    snprintf(after.security_posture_status,
             sizeof(after.security_posture_status), "%s",
             "checkpoint_verified");
    snprintf(after.security_posture_next_action,
             sizeof(after.security_posture_next_action), "%s",
             "wait_for_full_history_check");
    struct operator_verdict a = operator_snapshot_classify(&before);
    struct operator_verdict b = operator_snapshot_classify(&after);
    CP_CHECK("soak: operator verdict class, health and serving are identical",
             strcmp(a.status, b.status) == 0 && a.healthy == b.healthy &&
             a.serving == b.serving && a.operator_needed == b.operator_needed);
    CP_CHECK("soak: only the quoted posture label differs",
             strcmp(b.primary, "checkpoint_verified") == 0);
    return failures;
}

/* The native status journey on a healthy checkpoint node with a ready wallet:
 * receive is on and the trust object reaches the phone unchanged. */
static int case_journey_receive_with_trust(void)
{
    int failures = 0;
    static const char brief[] =
        "{\"hstar\":3300000,\"header_height\":3300000,\"gap\":0,"
        "\"peer_count\":8,\"healthy\":true,\"serving\":false,"
        "\"tip_follow\":true,\"wallet_view_ready\":true,"
        "\"wallet_spend_allowed\":true,\"sync_state\":\"at_tip\","
        "\"primary_blocker\":\"none\",\"trust\":{"
        "\"schema\":\"zcl.status_trust.v1\",\"source\":\"checkpoint\","
        "\"checkpoint_height\":3200000,\"history_check\":{\"state\":"
        "\"running\",\"percent\":12},\"ready\":true,\"summary\":\"Ready. "
        "Verified from checkpoint 3,200,000 built into this version; "
        "background check 12%.\"}}";
    static const char wallet[] =
        "{\"persistence\":{\"healthy\":true},\"lock\":{\"encrypted_at_rest\":"
        "true,\"unlocked\":false},\"sapling\":{\"prover_ready\":true,"
        "\"checkpoint_healthy\":true,\"witness_ready\":true,"
        "\"witness_state\":\"ready\"}}";
    static const char backup[] =
        "{\"healthy\":true,\"encrypted_backup_available\":true}";
    static const char money[] =
        "{\"ok\":true,\"snapshot\":{\"status\":\"CURRENT\",\"complete\":true,"
        "\"confirmed_zat\":0,\"transparent_spendable_zat\":0,"
        "\"shielded_spendable_zat\":0,\"pending_zat\":0,"
        "\"encumbered_zat\":0,\"intent_reserved_zat\":0,"
        "\"agent_available_zat\":0}}";
    const struct zcl_status_journey_sources src = {
        .brief = brief, .money = money, .wallet = wallet, .backup = backup,
        .mempool = "{\"size\":0}", .pace = "{\"pace\":\"normal\"}",
    };
    struct zcl_native_body_err err = {0};
    char *body = zcl_native_status_journey_compose(&src, &err);
    struct json_value out = {0};
    bool parsed = body && json_read(&out, body, strlen(body));
    CP_CHECK("journey: composes from fixed sources", parsed);
    if (parsed) {
        CP_CHECK("journey: healthy checkpoint node with ready wallet can receive",
                 json_get_bool(json_get(&out, "node_healthy")) &&
                 json_get_bool(json_get(&out, "can_receive")));
        CP_CHECK("journey: no owner review on a checkpoint node",
                 !json_get_bool(json_get(&out, "owner_review_required")));
        const struct json_value *t = json_get(&out, "trust");
        CP_CHECK("journey: trust object carried to the phone",
                 cp_str_is(json_get(t, "source"), "checkpoint") &&
                 json_get_int(json_get(t, "checkpoint_height")) == CP_HEIGHT &&
                 cp_str_is(json_get(t, "summary"),
                           "Ready. Verified from checkpoint 3,200,000 built "
                           "into this version; background check 12%."));
        json_free(&out);
    }
    free(body);
    return failures;
}

int test_agent_posture_checkpoint_cases(void)
{
    int failures = 0;
    failures += case_journey_receive_with_trust();
    failures += case_checkpoint_install_is_verified();
    failures += case_other_installs_stay_reviewed();
    failures += case_floor_alone_is_not_rom();
    failures += case_trust_shapes_stay_reviewed();
    failures += case_reseed_after_rom_drops_checkpoint();
    failures += case_busy_store_is_not_checkpoint();
    failures += case_genesis_full_history_unchanged();
    failures += case_soak_verdict_unchanged();
    return failures;
}
