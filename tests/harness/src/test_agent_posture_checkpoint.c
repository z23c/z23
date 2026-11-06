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

#include <sqlite3.h>
#include <stdio.h>
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
         coins_kv_set_applied_height_in_tx(pdb, CP_HEIGHT + 1);
    if (ok && shape->self_folded)
        ok = progress_meta_set_in_tx(pdb, COINS_KV_SELF_FOLDED_KEY, &one, 1);
    if (ok && shape->assisted_seam)
        ok = consensus_state_install_record_assisted_seam(pdb, CP_HEIGHT, root,
                                                          root, root);
    if (ok && shape->seed_floor)
        ok = reducer_seed_floor_declare_if_absent(pdb, CP_HEIGHT);
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

static bool cp_spend_allowed(void)
{
    char reason[128];
    return sovereignty_guard_peek("wallet_spend", reason, sizeof(reason));
}

static int case_checkpoint_install_is_verified(void)
{
    int failures = 0;
    struct cp_fixture fx;
    const struct cp_shape shape = {
        .self_folded = true, .seed_floor = true, .baked_height = CP_HEIGHT,
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
    CP_CHECK("rom: spend guard allows (pinned, unchanged)", cp_spend_allowed());
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
                   p.review_required);
    snprintf(name, sizeof(name), "%s: spend guard %s (pinned, unchanged)",
             label, want_spend ? "allows" : "refuses");
    CP_CHECK(name, cp_spend_allowed() == want_spend);
    cp_close(&fx);
    return failures;
}

static int case_other_installs_stay_reviewed(void)
{
    int failures = 0;
    const struct cp_shape assisted = {
        .assisted_seam = true, .seed_floor = true, .baked_height = CP_HEIGHT,
    };
    failures += cp_expect_review("assisted", &assisted,
                                 "review_required_bootstrap_trust", false);
    const struct cp_shape promoted = {
        .self_folded = true, .assisted_seam = true, .seed_floor = true,
        .baked_height = CP_HEIGHT,
    };
    failures += cp_expect_review("promoted_assisted", &promoted,
                                 "review_required_bootstrap_trust", true);
    const struct cp_shape unbaked = {
        .self_folded = true, .seed_floor = true, .baked_height = CP_HEIGHT + 1,
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
        .history_cursor = 500,
    };
    failures += cp_expect_review("anchor_gap", &gap,
                                 "review_required_anchor_backfill_gap", true);
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

int test_agent_posture_checkpoint_cases(void)
{
    int failures = 0;
    failures += case_checkpoint_install_is_verified();
    failures += case_other_installs_stay_reviewed();
    failures += case_genesis_full_history_unchanged();
    failures += case_soak_verdict_unchanged();
    return failures;
}
