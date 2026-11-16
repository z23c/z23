/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: Prove the boot-time fresh-genesis seed (boot_seed_fresh_genesis,
 * engine/composition/src/boot_genesis_seed.c) leaves a header-seeded node
 * that has applied nothing at cursors 0 when a restart resolves its active
 * tip to genesis and an installable bundle is staged (the header chain owns
 * the compiled checkpoint, every cursor 0, empty tip_finalize_log, no coins
 * frontier key, no install stamp), while the same node with no bundles
 * directory or only a .failed bundle, a genesis-only node, a header chain
 * that does not own the checkpoint, a node with a coins frontier or an
 * install stamp, and a node an earlier boot already seeded at genesis keep
 * the seed decision exactly as before; an unreadable progress store counts
 * as applied. Real files in the fixture's temp datadir. Included from
 * test_reducer_ingest_e2e.c after reducer_reseed_unbacked_test.h; uses its
 * rru_* helpers and the rie_* environment.
 */

#include "chain/chainparams.h"
#include "chain/checkpoints.h"
#include "config/boot_internal.h" /* boot_seed_fresh_genesis + its gate */
#include "config/consensus_state_snapshot_install.h"

#define SRG_TIP 7  /* header frontier of the seeded fixture */
#define SRG_CKPT 4 /* fixture checkpoint height, inside the header chain */
#define SRG_BUNDLE "consensus-state-bundle-4.sqlite"

enum srg_bundle {
    SRG_NO_BUNDLES_DIR = 0, /* no <datadir>/bundles at all */
    SRG_BUNDLE_STAGED,      /* an installable staged bundle */
    SRG_BUNDLE_FAILED,      /* the only bundle carries a .failed sibling */
};

struct srg_case {
    const char *label;
    int rows;           /* header rows, genesis included */
    bool owns_ckpt;     /* the checkpoint names the chain's own block */
    bool coins_key;     /* a coins frontier key is on disk */
    bool prior_anchor;  /* an earlier boot already seeded genesis */
    bool expect_stamp;  /* the genesis seed runs (cursors end at 1) */
    enum srg_bundle bundle;
    bool install_stamp; /* an install authority stamp is on disk */
};

/* <dir>/bundles/<name><suffix>, or false when it does not fit. */
static bool srg_bundle_path(char *out, size_t cap, const char *dir,
                            const char *suffix)
{
    int n = snprintf(out, cap, "%s/bundles%s%s%s", dir, suffix ? "/" : "",
                     suffix ? SRG_BUNDLE : "", suffix ? suffix : "");
    return n > 0 && (size_t)n < cap;
}

static bool srg_touch(const char *path)
{
    FILE *f = fopen(path, "wb");
    if (!f) {
        printf("reducer_ingest_e2e: genesis-seed cannot create %s: %s\n",
               path, strerror(errno));
        return false;
    }
    return fclose(f) == 0;
}

/* Stage the case's bundle files (the discovery is name-based, so empty
 * files are enough). True when the shape is on disk. */
static bool srg_stage_bundle(const char *dir, enum srg_bundle kind)
{
    char d[512], b[512], f[512];
    if (kind == SRG_NO_BUNDLES_DIR)
        return true;
    if (!srg_bundle_path(d, sizeof(d), dir, NULL) ||
        !srg_bundle_path(b, sizeof(b), dir, "") ||
        !srg_bundle_path(f, sizeof(f), dir, ".failed"))
        return false;
    if (mkdir(d, 0700) != 0 && errno != EEXIST) {
        printf("reducer_ingest_e2e: genesis-seed cannot create %s: %s\n", d,
               strerror(errno));
        return false;
    }
    return srg_touch(b) && (kind != SRG_BUNDLE_FAILED || srg_touch(f));
}

/* The env's flat cleanup removes no subdirectory: drop bundles/ here. */
static void srg_unstage_bundle(const char *dir)
{
    char d[512], b[512], f[512];
    if (!srg_bundle_path(d, sizeof(d), dir, NULL) ||
        !srg_bundle_path(b, sizeof(b), dir, "") ||
        !srg_bundle_path(f, sizeof(f), dir, ".failed"))
        return;
    (void)unlink(f);
    (void)unlink(b);
    if (rmdir(d) != 0 && errno != ENOENT)
        printf("reducer_ingest_e2e: genesis-seed cannot remove %s: %s\n", d,
               strerror(errno));
}

/* The authority stamp an install's activate leaves. */
static bool srg_record_install_stamp(const struct rie_branch *C)
{
    struct consensus_state_install_stamp st = {
        .kind = CONSENSUS_INSTALL_STAMP_CHECKPOINT_ROM,
        .height = SRG_CKPT,
    };
    memcpy(st.block_hash, C->hashes[SRG_CKPT].data, 32);
    memset(st.utxo_root, 0x22, sizeof(st.utxo_root));
    return consensus_state_install_record_authority_stamp(progress_store_db(),
                                                          &st);
}

/* Genesis keeps its body; every later row is a validated header without
 * data, as the bound header-seed import leaves it. */
static bool srg_build(struct rie_branch *br, int rows)
{
    if (!branch_build(br, 0x5C, rows, -1, 0, NULL))
        return false;
    for (int h = 1; h < br->n; h++)
        br->blocks[h].nStatus = BLOCK_VALID_TREE;
    return true;
}

/* The restart's in-memory shape: every header row in the map, the best
 * header at the frontier, the active tip rolled back to genesis. */
static void srg_install_restart_shape(struct rie_env *e, struct rie_branch *C)
{
    for (int h = 0; h < C->n; h++)
        test_block_map_insert(&e->ms.map_block_index, C->blocks[h].phashBlock,
                              &C->blocks[h]);
    e->ms.pindex_best_header = &C->blocks[C->n - 1];
    active_chain_move_window_tip(&e->ms.chain_active, &C->blocks[0]);
}

static void srg_checkpoint(struct sha3_utxo_checkpoint *cp,
                           const struct rie_branch *C, bool owns)
{
    memset(cp, 0, sizeof(*cp));
    cp->height = SRG_CKPT;
    if (owns && C->n > SRG_CKPT)
        memcpy(cp->block_hash, C->hashes[SRG_CKPT].data, 32);
    else
        memset(cp->block_hash, 0xC7, sizeof(cp->block_hash));
}

static int srg_check_outcome(const struct srg_case *k,
                             const struct rru_state *b,
                             const struct rru_state *a, bool withheld)
{
    int failures = 0;
    char name[192];
    snprintf(name, sizeof(name), "genesis-seed[%s]: withhold verdict %s",
             k->label, k->expect_stamp ? "false" : "true");
    RIE_CHECK(name, withheld == !k->expect_stamp);
    uint64_t want = k->expect_stamp ? 1u : 0u;
    snprintf(name, sizeof(name),
             "genesis-seed[%s]: upstream cursors %s", k->label,
             k->expect_stamp ? "end at 1" : "stay 0");
    RIE_CHECK(name, a->header_admit == want && a->body_fetch == want &&
                    a->utxo_apply == want);
    snprintf(name, sizeof(name),
             "genesis-seed[%s]: tip_finalize cursor stays 0, %s", k->label,
             k->expect_stamp ? "one genesis anchor row" : "no anchor row");
    RIE_CHECK(name, a->tf_cursor == 0 && a->tf_rows == (int64_t)want);
    snprintf(name, sizeof(name), "genesis-seed[%s]: no seed failure counted",
             k->label);
    RIE_CHECK(name, a->failures == b->failures);
    return failures;
}

/* The restart's durable and in-memory state for one case. Returns false
 * (after printing which step) when any setup step failed. */
static bool srg_setup(struct rie_env *e, struct rie_branch *C,
                      const struct srg_case *k, struct node_db *ndb,
                      struct sha3_utxo_checkpoint *cp)
{
    bool wired = rru_node_db_open(ndb, C);
    bool coins_ok = !k->coins_key ||
        coins_kv_set_applied_height_in_tx(progress_store_db(), 1);
    coins_ok = coins_ok && srg_stage_bundle(e->dir, k->bundle) &&
               (!k->install_stamp || srg_record_install_stamp(C));
    srg_checkpoint(cp, C, k->owns_ckpt);
    checkpoints_set_sha3_override_for_test(cp);
    srg_install_restart_shape(e, C);
    /* The anchor row and cursors an earlier boot's genesis seed left. */
    bool prior_ok = !k->prior_anchor ||
        tip_finalize_stage_seed_anchor(0, C->hashes[0].data, false);
    bool reinit = prior_ok && rru_reinit_tip_finalize(e);
    printf("reducer_ingest_e2e: genesis-seed[%s] setup ok: node_db=%d "
           "coins_key+bundle+stamp=%d prior_anchor=%d reinit=%d "
           "served_tip=%d\n",
           k->label, wired, coins_ok, prior_ok, reinit,
           rru_served_tip_height(e));
    return wired && coins_ok && reinit;
}

/* The live chain params with the fixture's genesis hash; false when the
 * test process selected no chain. */
static bool srg_params(struct chain_params *params, const struct rie_branch *C)
{
    const struct chain_params *live = chain_params_get();
    if (!live) {
        memset(params, 0, sizeof(*params));
        return false;
    }
    *params = *live;
    params->consensus.hashGenesisBlock = C->hashes[0];
    return true;
}

static int srg_check_shape(struct rie_env *e, const struct srg_case *k,
                           const struct rru_state *before, bool setup_ok)
{
    int failures = 0;
    char name[192];
    uint64_t prior = k->prior_anchor ? 1u : 0u;
    snprintf(name, sizeof(name),
             "genesis-seed[%s]: restart shape (served tip %s, tip_finalize "
             "cursor 0, upstream cursors %" PRIu64 ", %" PRIu64
             " log rows)", k->label, k->prior_anchor ? "none" : "genesis",
             prior, prior);
    /* An anchor-only store has durable history but no finalized row, so
     * tip_finalize init publishes no served tip and the boot seed returns
     * before its decision, on base and here alike; the verdict call below
     * proves the new gate stays open for it. */
    int want_tip = k->prior_anchor ? -1 : 0;
    RIE_CHECK(name, setup_ok && rru_served_tip_height(e) == want_tip &&
                    before->tf_cursor == 0 &&
                    before->header_admit == prior &&
                    before->utxo_apply == prior &&
                    before->tf_rows == (int64_t)prior);
    return failures;
}

/* A progress store that cannot be read (here: a handle with no tables)
 * counts as applied, so the same withheld shape is seeded as before. */
static int srg_check_read_error(struct rie_env *e, const struct srg_case *k)
{
    int failures = 0;
    char name[192];
    sqlite3 *empty = NULL;
    bool opened = sqlite3_open(":memory:", &empty) == SQLITE_OK;
    snprintf(name, sizeof(name),
             "genesis-seed[%s]: unreadable progress store -> not withheld",
             k->label);
    RIE_CHECK(name, opened && !boot_genesis_seed_withheld_for_header_seed(
                                  &e->ms, empty, e->dir, NULL, 0));
    sqlite3_close(empty);
    return failures;
}

/* A withheld verdict names the staged bundle; any other leaves it empty. */
static int srg_check_bundle_named(const struct srg_case *k, bool withheld,
                                  const char *bundle)
{
    int failures = 0;
    char name[192];
    const char *tail = strrchr(bundle, '/');
    bool named = tail && strcmp(tail + 1, SRG_BUNDLE) == 0;
    snprintf(name, sizeof(name), "genesis-seed[%s]: verdict %s", k->label,
             withheld ? "names the staged bundle" : "names no bundle");
    RIE_CHECK(name, withheld ? named : bundle[0] == '\0');
    return failures;
}

static int srg_run_env(struct rie_env *e, struct rie_branch *C,
                       const struct srg_case *k)
{
    int failures = 0;
    struct node_db ndb;
    struct sha3_utxo_checkpoint cp;
    bool setup_ok = srg_setup(e, C, k, &ndb, &cp);
    struct chain_params params;
    setup_ok = srg_params(&params, C) && setup_ok;

    struct rru_state before, after;
    rru_read_state(&before, 0);
    rru_print("genesis-seed before", &before);
    failures += srg_check_shape(e, k, &before, setup_ok);

    if (!k->expect_stamp)
        failures += srg_check_read_error(e, k);
    char bundle[512];
    bool withheld = boot_genesis_seed_withheld_for_header_seed(
        &e->ms, progress_store_db(), e->dir, bundle, sizeof(bundle));
    failures += srg_check_bundle_named(k, withheld, bundle);
    boot_seed_fresh_genesis(&e->ms, &params, e->dir);
    rru_read_state(&after, 0);
    rru_print("genesis-seed after", &after);
    failures += srg_check_outcome(k, &before, &after, withheld);
    srg_unstage_bundle(e->dir);
    checkpoints_reset_sha3_override_for_test();
    e->ms.pindex_best_header = NULL;
    rru_node_db_close(&ndb);
    return failures;
}

static int srg_run_case(const struct srg_case *k)
{
    int failures = 0;
    struct rie_branch C;
    bool built = srg_build(&C, k->rows);
    struct rie_env e;
    bool opened = built && rie_env_open(&e, k->label, &C, NULL, 0);
    char name[192];
    snprintf(name, sizeof(name), "genesis-seed[%s]: fixture opens", k->label);
    RIE_CHECK(name, opened);
    if (opened) {
        failures += srg_run_env(&e, &C, k);
        rie_env_close(&e);
    }
    branch_free(&C);
    tip_finalize_stage_test_reset();
    return failures;
}

static int srg_run_all(void)
{
    /* Every stamped case but the two bundle ones stages an installable
     * bundle, so each proves its own clause keeps the old decision. */
    static const struct srg_case cases[] = {
        /* The journey: a restart seconds after the header-seed import, the
         * state bundle already staged by the boot-time fetch. */
        { "seeded-restart", SRG_TIP + 1, true, false, false, false,
          SRG_BUNDLE_STAGED, false },
        /* R-1: no installable bundle, so no fast start is possible at this
         * boot; a restart stays the way out (stamp, sync from block 1). */
        { "seeded-restart-no-bundles-dir", SRG_TIP + 1, true, false, false,
          true, SRG_NO_BUNDLES_DIR, false },
        { "seeded-restart-failed-bundle", SRG_TIP + 1, true, false, false,
          true, SRG_BUNDLE_FAILED, false },
        /* G2: no header rows above genesis (offline first start, regtest). */
        { "genesis-only", 1, true, false, false, true, SRG_BUNDLE_STAGED,
          false },
        /* Headers that do not hold the compiled checkpoint block. */
        { "checkpoint-not-owned", SRG_TIP + 1, false, false, false, true,
          SRG_BUNDLE_STAGED, false },
        /* G1: a coins frontier key means something was applied. */
        { "coins-frontier", SRG_TIP + 1, true, true, false, true,
          SRG_BUNDLE_STAGED, false },
        /* G1: an install authority stamp means an install committed. */
        { "install-stamp", SRG_TIP + 1, true, false, false, true,
          SRG_BUNDLE_STAGED, true },
        /* G1: a tip_finalize_log row. Also the restart of a node that
         * crawled headers past the checkpoint itself: its first boot seeded
         * genesis before any header arrived, and that anchor row keeps the
         * seed decision exactly as before. */
        { "earlier-genesis-anchor", SRG_TIP + 1, true, false, true, true,
          SRG_BUNDLE_STAGED, false },
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        failures += srg_run_case(&cases[i]);
    return failures;
}
