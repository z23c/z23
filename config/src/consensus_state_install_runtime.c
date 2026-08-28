/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * consensus_state_install_runtime.c — the NON-TERMINAL install ENGINE of the
 * sovereign consensus-state install (contract in
 * config/consensus_state_install_runtime.h).
 *
 * The install pipeline (containment classify → admit+validate → producer source
 * receipt → publication CAS with the compiled SHA3 + CHECKPOINT_ROM authority →
 * reload durable ADMIT → atomic consensus_state_snapshot_install_activate →
 * derived-state invalidation → durable marker → utxos mirror reset) was factored
 * out of the -install-consensus-bundle terminal verb so it can run inside a live
 * boot and RETURN a result instead of _exit()ing. The terminal verb
 * (boot_install_consensus_bundle) is now a thin wrapper.
 *
 * The BOOT WIRINGS that ride on this engine — the zero-flag autodetect (1b), the
 * durable install-on-next-boot request (1c), and the app_init selection seam —
 * live in the sibling config/src/boot_auto_install_bundle.c. Every install still
 * routes through consensus_state_snapshot_install_activate; no new state writer. */

#include "config/consensus_state_install_runtime.h"

#if defined(_WIN32)

struct zcl_result consensus_state_install_from_bundle(
    struct node_db *ndb, struct main_state *ms, const char *bundle_path,
    const char *datadir, struct consensus_state_install_runtime_result *out)
{
    (void)ndb;
    (void)ms;
    (void)bundle_path;
    (void)datadir;
    (void)out;
    return ZCL_ERR(
        -1,
        "consensus-state installation is disabled on Windows until SID/ACL "
        "owner policy and directory-handle-relative activation qualify");
}

#else

#include "config/boot.h"                              /* node_db, main_state, test-surface decls */
#include "config/boot_consensus_bundle_marker.h"       /* installed-bundle marker */
#include "config/consensus_state_snapshot_install.h"
#include "consensus_state_snapshot_install_internal.h" /* candidate_lease_begin/end */
#include "chain/chain.h"                              /* block_index, active_chain_at */
#include "chain/checkpoints.h"                        /* get_sha3_utxo_checkpoint */
#include "controllers/sync_controller.h"              /* sapling_tree_persist_pair */
#include "core/serialize.h"                           /* byte_stream */
#include "framework/condition.h"                     /* condition_engine_*_main_state */
#include "jobs/reducer_frontier.h"                    /* reducer_frontier_provable_tip_reset */
#include "jobs/tip_finalize_stage.h"                 /* tip_finalize_stage_warm_authority_caches */
#include "jobs/validate_headers_stage.h"             /* validate_headers_stage_ensure_pass_record */
#include "models/database.h"                          /* node_db state helpers */
#include "sapling/incremental_merkle_tree.h"
#include "services/consensus_state_chain_binding_service.h"
#include "services/consensus_state_publication_cas.h"
#include "services/utxo_mirror_sync_service.h"        /* UTXO_MIRROR_SYNC_CURSOR_KEY */
#include "storage/anchor_kv.h"
#include "storage/consensus_state_bundle_codec.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"                    /* active_chain_at */
#include "validation/main_state.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ICB_SUBSYS "install_consensus_bundle"
#define ICB_DECISION_RECORD_NAME "consensus_state_publication_decision.v1"

/* ── Containment classification (verbatim from the terminal verb) ──────────── */

static bool icb_same_directory(int target_fd, const char *candidate, bool *same)
{
    *same = false;
    int candidate_fd = open(candidate, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (candidate_fd < 0)
        return errno == ENOENT;
    struct stat target_st;
    struct stat candidate_st;
    bool ok = fstat(target_fd, &target_st) == 0 &&
              fstat(candidate_fd, &candidate_st) == 0;
    if (ok)
        *same = target_st.st_dev == candidate_st.st_dev &&
                target_st.st_ino == candidate_st.st_ino;
    (void)close(candidate_fd);
    return ok;
}

static bool icb_canonical_candidate(int target_fd, const char *home,
                                    bool *canonical)
{
    if (!home || !home[0])
        return true;
    char candidate[PATH_MAX];
    int n = snprintf(candidate, sizeof(candidate), "%s/.zclassic-c23", home);
    if (n <= 0 || (size_t)n >= sizeof(candidate))
        return false;
    bool same = false;
    if (!icb_same_directory(target_fd, candidate, &same))
        return false;
    *canonical = *canonical || same;
    return true;
}

/* Open the target once and compare directory identities, not spelling. Both the
 * account home and HOME are considered: an altered/unset HOME must not turn the
 * real daily-driver into a copy-proof lane, while test/service homes still
 * receive the same conservative gate. The returned descriptor is also the
 * capability used for the CAS decision record. */
static struct zcl_result icb_datadir_open_classify(const char *datadir,
                                                   int *out_fd,
                                                   bool *out_canonical)
{
    if (out_fd)
        *out_fd = -1;
    if (out_canonical)
        *out_canonical = false;
    if (!datadir || !datadir[0] || !out_fd || !out_canonical)
        return ZCL_ERR(-1, "datadir classification arguments are missing");

    int target_fd = open(datadir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (target_fd < 0)
        return ZCL_ERR(-2, "could not open datadir: %s", strerror(errno));

    bool canonical = false;
    bool have_home = false;
    char pwbuf[16384];
    struct passwd pwd;
    struct passwd *pw = NULL;
    if (getpwuid_r(geteuid(), &pwd, pwbuf, sizeof(pwbuf), &pw) == 0 &&
        pw && pw->pw_dir && pw->pw_dir[0]) {
        have_home = true;
        if (!icb_canonical_candidate(target_fd, pw->pw_dir, &canonical)) {
            (void)close(target_fd);
            return ZCL_ERR(-3, "could not resolve account canonical datadir");
        }
    }

    const char *env_home = getenv("HOME");
    if (env_home && env_home[0]) {
        have_home = true;
        if (!icb_canonical_candidate(target_fd, env_home, &canonical)) {
            (void)close(target_fd);
            return ZCL_ERR(-4, "could not resolve HOME canonical datadir");
        }
    }
    if (!have_home) {
        (void)close(target_fd);
        return ZCL_ERR(-5, "no account or HOME directory for lane authority");
    }

    *out_fd = target_fd;
    *out_canonical = canonical;
    return ZCL_OK;
}

static bool icb_canonical_authorized(const char *authorization)
{
    return authorization && strcmp(authorization, "1") == 0;
}

/* Read the producer source receipt from the pinned, already-validated bundle
 * handle. The CAS re-checks the receipt's self-consistency and its binding to
 * the manifest source digest, so a misread fails closed there. */
static bool icb_read_source_receipt(sqlite3 *bundle_db,
                                    struct consensus_state_source_receipt *out)
{
    static const char sql[] =
        "SELECT schema,source_epoch_digest,source_tree_root,running_binary_digest,"
        "toolchain_digest,build_inputs_digest,chain_corpus_digest,source_clean,"
        "validation_profile,producer_commit,fold_cursor,receipt_digest "
        "FROM source_receipt WHERE singleton=1";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(bundle_db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    memset(out, 0, sizeof(*out));
    bool ok = sqlite3_step(st) == SQLITE_ROW; // raw-sql-ok:read-only-introspection
    const struct { int col; uint8_t *dst; } blobs[] = {
        {1, out->source_epoch_digest}, {2, out->source_tree_root},
        {3, out->running_binary_digest}, {4, out->toolchain_digest},
        {5, out->build_inputs_digest}, {6, out->chain_corpus_digest},
        {11, out->receipt_digest},
    };
    for (size_t i = 0; ok && i < sizeof(blobs) / sizeof(blobs[0]); i++) {
        ok = sqlite3_column_type(st, blobs[i].col) == SQLITE_BLOB &&
             sqlite3_column_bytes(st, blobs[i].col) == 32;
        if (ok)
            memcpy(blobs[i].dst, sqlite3_column_blob(st, blobs[i].col), 32);
    }
    if (ok) {
        const unsigned char *schema =
            sqlite3_column_type(st, 0) == SQLITE_TEXT
                ? sqlite3_column_text(st, 0) : NULL;
        int schema_len = schema ? sqlite3_column_bytes(st, 0) : -1;
        const unsigned char *commit =
            sqlite3_column_type(st, 9) == SQLITE_TEXT
                ? sqlite3_column_text(st, 9) : NULL;
        int commit_len = commit ? sqlite3_column_bytes(st, 9) : -1;
        uint8_t receipt_version = CONSENSUS_STATE_SOURCE_RECEIPT_INVALID;
        ok = schema && schema_len >= 0 &&
             consensus_state_source_receipt_schema_version(
                 (const char *)schema, (size_t)schema_len,
                 &receipt_version) &&
             commit && commit_len >= 0 &&
             consensus_state_source_receipt_commit_valid(
                 receipt_version, (const char *)commit,
                 (size_t)commit_len) &&
             sqlite3_column_type(st, 7) == SQLITE_INTEGER &&
             (sqlite3_column_int(st, 7) == 0 ||
              sqlite3_column_int(st, 7) == 1) &&
             sqlite3_column_type(st, 8) == SQLITE_INTEGER &&
             (sqlite3_column_int(st, 8) == CONSENSUS_STATE_VALIDATION_FULL ||
              sqlite3_column_int(st, 8) ==
                  CONSENSUS_STATE_VALIDATION_CHECKPOINT_FOLD) &&
             sqlite3_column_type(st, 10) == SQLITE_INTEGER;
        if (ok) {
            out->schema_version = receipt_version;
            memcpy(out->producer_commit, commit, (size_t)commit_len);
            out->producer_commit[commit_len] = '\0';
            out->source_clean = sqlite3_column_int(st, 7) == 1;
            out->validation_profile = (uint8_t)sqlite3_column_int(st, 8);
            out->fold_cursor = sqlite3_column_int64(st, 10);
        }
    }
    sqlite3_finalize(st);
    return ok;
}

/* MAX(coins.height) on the installed progress store. found=false on an empty
 * coins table (MAX over 0 rows is SQL NULL). */
static bool icb_coins_max_height(sqlite3 *progress_db, int64_t *out, bool *found)
{
    *out = -1;
    *found = false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(progress_db, "SELECT MAX(height) FROM coins", -1,
                           &st, NULL) != SQLITE_OK)
        return false;
    bool ok = true;
    if (sqlite3_step(st) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        if (sqlite3_column_type(st, 0) != SQLITE_NULL) {
            *out = sqlite3_column_int64(st, 0);
            *found = true;
        }
    } else {
        ok = false;
    }
    sqlite3_finalize(st);
    return ok;
}

/* The activated bundle already installed every Sapling anchor row, including
 * the verified current frontier tree. Persist that frontier into node.db's
 * boot cache as the bundle-height state instead of deleting the cache and
 * forcing an O(chain) block replay. The latest stored anchor may have been
 * created below bundle_height when intervening blocks carried no Sapling
 * outputs; its unchanged root still represents the Sapling state at the
 * bundle height, which admission/activation bound to the selected header.
 *
 * The bundle ships the complete sapling tree, so a successful install must
 * leave boot able to load it and skip the Sapling rebuild. The pair writer is
 * atomic: a stale pre-install blob can never survive beside the new height. */
static bool icb_install_bundle_sapling_tree(struct node_db *ndb,
                                            sqlite3 *progress_db,
                                            int32_t bundle_height)
{
    if (!ndb || !progress_db || bundle_height < 0)
        LOG_FAIL(ICB_SUBSYS,
                 "post-install Sapling cache: invalid ndb/progress_db/height");

    struct incremental_merkle_tree tree;
    sapling_tree_init(&tree);
    int64_t frontier_height = -1;
    enum anchor_kv_lookup_result found = anchor_kv_latest_tree(
        progress_db, ANCHOR_POOL_SAPLING, &tree, NULL, &frontier_height);
    if (found != ANCHOR_KV_FOUND || frontier_height < 0 ||
        frontier_height > bundle_height)
        LOG_FAIL(ICB_SUBSYS,
                 "post-install Sapling cache: installed frontier unavailable "
                 "or out of range (result=%d frontier_h=%lld bundle_h=%d)",
                 (int)found, (long long)frontier_height, bundle_height);

    struct byte_stream encoded;
    stream_init(&encoded, 4096);
    bool serialized = incremental_tree_serialize(&tree, &encoded) &&
                      !encoded.error && encoded.size > 0;
    if (!serialized) {
        stream_free(&encoded);
        LOG_FAIL(ICB_SUBSYS,
                 "post-install Sapling cache: frontier serialization failed "
                 "at bundle height=%d", bundle_height);
    }

    bool persisted = sapling_tree_persist_pair(
        ndb, encoded.data, encoded.size, (int64_t)bundle_height);
    stream_free(&encoded);
    if (!persisted)
        LOG_FAIL(ICB_SUBSYS,
                 "post-install Sapling cache: atomic tree/height persist failed "
                 "at bundle height=%d", bundle_height);

    LOG_INFO(ICB_SUBSYS,
             "post-install Sapling cache installed from bundle frontier_h=%lld "
             "at bundle_h=%d (boot skips Sapling rebuild)",
             (long long)frontier_height, bundle_height);
    return true;
}

/* Post-install derived-state reconciliation. The atomic activate step resets the
 * kernel store's (consensus.db) reducer/tip_finalize authority to the installed
 * anchor, but two derived surfaces live OUTSIDE that store and would fight the new
 * kernel on the next boot. Returns true iff every derived
 * store is now consistent with the freshly installed bundle at bundle_height. */
static bool icb_invalidate_derived_state(struct node_db *ndb,
                                         sqlite3 *progress_db,
                                         int32_t bundle_height)
{
    if (!ndb || !progress_db)
        LOG_FAIL(ICB_SUBSYS, "post-install invalidation: null ndb/progress_db");

    /* (1) tip_finalize provable-tip cache. Its DURABLE source (tip_finalize_log
     * + the 8 stage cursors) was already reset to the installed anchor AND
     * post-install-verified inside consensus_state_snapshot_install_activate.
     * This path pre-warmed the process-local reducer_frontier provable-tip cache
     * from the PRE-install store, so drop that stale in-memory value: nothing may
     * republish the old tip if this path returns rather than _exit()ing. */
    reducer_frontier_provable_tip_reset();

    /* (2) The installed coin set must sit exactly at the bundle height. */
    int64_t coins_max = -1;
    bool have_coins = false;
    if (!icb_coins_max_height(progress_db, &coins_max, &have_coins))
        LOG_FAIL(ICB_SUBSYS,
                 "post-install invalidation: reading MAX(coins.height) failed");
    if (!have_coins || coins_max != (int64_t)bundle_height) {
        LOG_ERROR(ICB_SUBSYS,
                  "post-install invalidation: MAX(coins.height)=%lld != bundle "
                  "height=%d (installed coin tip is not at the bundle tip)",
                  (long long)coins_max, bundle_height);
        return false;
    }

    /* (3) Replace any stale node.db Sapling tree pair with the complete,
     * destination-verified frontier that activation just installed. */
    if (!icb_install_bundle_sapling_tree(ndb, progress_db, bundle_height))
        return false;

    LOG_INFO(ICB_SUBSYS,
             "post-install derived-state reconciliation OK: bundle Sapling "
             "tree cached, provable-tip cache reset, coins tip=%lld == bundle "
             "height=%d", (long long)coins_max, bundle_height);
    return true;
}

/* node.db `utxos` is a DERIVED, rebuildable read-model projection —
 * utxo_mirror_sync_service.h's own design doc: consensus reads never depend on
 * it, its sole writer is this background service, and every drift shape it
 * detects (cursor lag OR a row-count mismatch) is healed by a wholesale rebuild
 * straight from coins_kv. A bundle install SWAPS coins/anchors/nullifiers to a
 * possibly different-provenance dataset — not a continuation of whatever the
 * mirror was tracking before — so rows the mirror already held (at ANY height,
 * not just above the bundle height) are not guaranteed to match the freshly
 * installed coins_kv content byte-for-byte.
 *
 * Left alone, a stale mirror bites on the very next boot: utxo_recovery_
 * clean_above_tip's bounded guard (utxo_recovery_service.c,
 * UTXO_BOOT_REWIND_MAX_ROWS=32) only auto-heals a single-block, <=32-row
 * overshoot, so a larger stale-mirror overshoot raises the PERMANENT
 * utxo_recovery.rewind_overshoot blocker — a wedge on a table that carries no
 * consensus weight at all.
 *
 * Reset wholesale (not a height-bounded delete) plus the sync cursor, so
 * utxo_mirror_sync_service's own drift detector fires on its first pass after
 * boot and rebuilds the mirror straight from the just-installed coins_kv —
 * reusing the service's existing contract rather than a bespoke partial patch
 * here. Best-effort: the activation itself already durably succeeded, so a reset
 * failure is loud but must not turn a successful install into a refusal. */
static bool icb_reset_utxo_mirror(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        LOG_FAIL(ICB_SUBSYS, "post-install mirror reset: node.db not open");

    bool ok = node_db_exec(ndb, "DELETE FROM utxos");
    if (!ok)
        LOG_WARN(ICB_SUBSYS, "post-install mirror reset: DELETE FROM utxos failed");
    bool commitment_ok = node_db_exec(ndb,
        "DELETE FROM node_state WHERE key='utxo_commitment'");
    if (!commitment_ok)
        LOG_WARN(ICB_SUBSYS,
                 "post-install mirror reset: utxo_commitment cache clear failed");
    /* -1 is never a valid mirror height — guarantees the next sync pass sees
     * cursor != the newly installed coins_kv applied frontier and rebuilds, even
     * in the edge case where DELETE FROM utxos above already left the table empty
     * (row-count-divergence drift would also catch that, but don't rely on two
     * guards firing when one explicit reset is simpler). */
    bool cursor_ok = node_db_state_set_int(ndb, UTXO_MIRROR_SYNC_CURSOR_KEY, -1);
    if (!cursor_ok)
        LOG_WARN(ICB_SUBSYS, "post-install mirror reset: sync cursor reset failed");
    return ok && commitment_ok && cursor_ok;
}

/* True iff this node's validated header chain has reached `height` and the block
 * at that height on the selected header chain carries `block_hash`. The assisted
 * above-checkpoint chain-binding needs the bundle-height header (and its Sapling
 * frontier) present; a fresh FRESHEST bundle deferred here retries, never .fails
 * (the cded07d40 bug class). Read-only header-chain walk — no chain mutation. */
static bool install_bundle_header_ready(struct main_state *ms, int32_t height,
                                        const uint8_t block_hash[32])
{
    if (!ms || height < 0)
        return false;
    struct block_index *header = ms->pindex_best_header;
    if (!header || header->nHeight < height)
        return false;
    struct block_index *at = block_index_get_ancestor(header, (int)height);
    return at && at->phashBlock &&
           memcmp(at->phashBlock->data, block_hash, 32) == 0;
}

/* Assisted (above-checkpoint FRESHEST-bundle) admission is owner-approved and
 * default ON. The env kill switch ZCL_INSTALL_ASSISTED=0 forces it OFF, in which
 * case an above-checkpoint bundle gets no assisted opt-in and refuses at the
 * chain-binding -4 gate exactly as before this feature. The canonical-lane
 * ZCL_DEPLOY_ALLOW_CANONICAL guard is enforced UPSTREAM (see the classification
 * block), so the sovereign lane is untouched. */
static bool install_assisted_opt_in(void)
{
    const char *kill = getenv("ZCL_INSTALL_ASSISTED");
    return !(kill && strcmp(kill, "0") == 0);
}

/* ── The NON-TERMINAL install core ─────────────────────────────────────────── */

struct zcl_result consensus_state_install_from_bundle(
    struct node_db *ndb, struct main_state *ms, const char *bundle_path,
    const char *datadir, struct consensus_state_install_runtime_result *out)
{
    struct consensus_state_install_runtime_result local;
    if (!out)
        out = &local;
    memset(out, 0, sizeof(*out));
    out->status = CONSENSUS_INSTALL_REFUSED;
    out->height = -1;
    out->hstar = -1;

    if (!bundle_path || !bundle_path[0] || !datadir || !datadir[0]) {
        LOG_WARN(ICB_SUBSYS, "empty bundle path or datadir");
        snprintf(out->reason, sizeof(out->reason), "empty bundle path or datadir");
        return ZCL_ERR(-1, "empty bundle path or datadir");
    }

    struct zcl_result rc = ZCL_OK;
    int dir_fd = -1;
    bool canonical_datadir = false;
    struct consensus_state_artifact_evidence *artifact = NULL;
    struct consensus_state_bundle_manifest manifest;
    memset(&manifest, 0, sizeof(manifest));

    /* (1) Containment: descriptor-classify the target once, then retain that
     * exact directory capability through the CAS decision write. */
    struct zcl_result classified =
        icb_datadir_open_classify(datadir, &dir_fd, &canonical_datadir);
    if (!classified.ok) {
        rc = ZCL_ERR(classified.code, "datadir lane classification failed: %s",
                     classified.message);
        goto done;
    }
    if (canonical_datadir &&
        !icb_canonical_authorized(getenv("ZCL_DEPLOY_ALLOW_CANONICAL"))) {
        rc = ZCL_ERR(-1,
                     "datadir %s is the canonical lane; set "
                     "ZCL_DEPLOY_ALLOW_CANONICAL=1 to cut over the daily-driver, "
                     "or run the install on a dev/copy datadir first", datadir);
        goto done;
    }

    enum consensus_state_target_lane lane =
        canonical_datadir ? CONSENSUS_STATE_TARGET_LANE_CANONICAL
                          : CONSENSUS_STATE_TARGET_LANE_COPY_PROOF;

    /* (2) Admit + strictly validate the immutable bundle. */
    struct zcl_result admitted =
        consensus_state_artifact_evidence_open(bundle_path, dir_fd, &artifact);
    if (!admitted.ok) {
        rc = ZCL_ERR(admitted.code, "bundle admission/validation failed: %s",
                     admitted.message);
        goto done;
    }
    if (!consensus_state_artifact_evidence_manifest_copy(artifact, &manifest)) {
        rc = ZCL_ERR(-1, "artifact evidence became stale after admission");
        goto done;
    }

    /* (2b) Deferral gate — distinguish a RETRIABLE WAIT from a genuine refusal.
     * The bundle has already passed strict admission (byte integrity + manifest
     * self-bind) above, so a flipped-byte / corrupt bundle never reaches here.
     * When this is the compiled-checkpoint bundle (manifest sits at exactly the
     * compiled checkpoint height) BUT this node's validated header chain has not
     * yet reached the checkpoint block, the below-checkpoint chain-binding
     * predicates cannot bind yet — NOT because the bundle is bad, but because the
     * node has not caught up. Refuse WITHOUT the state_installed flag and mark it
     * retriable so the boot seam does not permanently .fail a good bundle; the
     * install retries (this session's condition OR a future boot) once the
     * checkpoint header is genuinely on-chain. A non-checkpoint bundle, or one
     * whose header IS present, falls through to the unchanged full gate. */
    {
        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        const struct rom_state_checkpoint *rom = get_rom_state_checkpoint();
        bool checkpoint_bundle =
            cp && rom && cp->height == rom->height &&
            manifest.height == (int32_t)cp->height;
        bool above_checkpoint_bundle =
            cp && manifest.height > (int32_t)cp->height;
        if (checkpoint_bundle && ms) {
            (void)consensus_state_install_restore_checkpoint_header_frontier(
                ms);
        }
        if (checkpoint_bundle && ms &&
            !consensus_state_checkpoint_header_ready(ms)) {
            out->retriable_headers_not_ready = true;
            int hdr_h = (ms->pindex_best_header)
                            ? ms->pindex_best_header->nHeight : -1;
            rc = ZCL_ERR(-2,
                         "checkpoint bundle deferred: validated header chain has "
                         "not yet reached checkpoint height %d (header frontier "
                         "h=%d) — retriable wait, not a bundle rejection",
                         (int)cp->height, hdr_h);
            goto done;
        }
        /* Assisted above-checkpoint FRESHEST bundle: same retriable deferral,
         * generalized from the checkpoint height to the BUNDLE height. Until this
         * node's validated header chain reaches the bundle height with the
         * bundle's own block hash present, the assisted chain-binding cannot bind
         * — NOT because the bundle is bad, but because headers have not caught up.
         * Only when the assisted opt-in is on (the sovereign lane is untouched). */
        if (above_checkpoint_bundle && install_assisted_opt_in() && ms &&
            !install_bundle_header_ready(ms, manifest.height,
                                         manifest.block_hash)) {
            out->retriable_headers_not_ready = true;
            int hdr_h = (ms->pindex_best_header)
                            ? ms->pindex_best_header->nHeight : -1;
            rc = ZCL_ERR(-2,
                         "assisted bundle deferred: validated header chain has "
                         "not yet reached bundle height %d (header frontier h=%d) "
                         "— retriable wait, not a bundle rejection",
                         manifest.height, hdr_h);
            goto done;
        }
    }

    /* (3) Read the producer source receipt from the pinned bundle handle. */
    struct consensus_state_source_receipt receipt;
    {
        struct consensus_state_bundle_manifest leased;
        uint8_t receipt_digest[32];
        sqlite3 *bundle_db = NULL;
        bool leased_ok = consensus_state_artifact_evidence_candidate_lease_begin(
            artifact, &leased, receipt_digest, &bundle_db);
        bool read_ok = leased_ok && icb_read_source_receipt(bundle_db, &receipt);
        if (leased_ok)
            consensus_state_artifact_evidence_candidate_lease_end(artifact);
        if (!read_ok) {
            rc = ZCL_ERR(-1,
                         "could not read the producer source receipt from the "
                         "bundle");
            goto done;
        }
    }

    /* (4) Gate through the publication CAS. Both the chain-evidence build and the
     * CAS run assert the process singleton (condition_engine_main_state() ==
     * request->main); at this boot stage the singleton is not yet wired to the
     * reducer, so set it for the duration of the decision and restore it.
     * Single-threaded boot — no reducer thread observes the transient value. */
    struct main_state *prev_singleton = condition_engine_main_state();
    condition_engine_set_main_state(ms);

    /* (3b) Boot-order warm: this runs BEFORE tip_finalize_stage_init, so the
     * runtime authority pair + provable-tip cache the chain-binding evidence
     * consults are still unpublished and every target — copy or live — would
     * refuse "selected frontier changed or is not durable" regardless of durable
     * truth. Warm from the durable store with the same primitives the stage init
     * uses; a genuinely torn target still refuses on real durable disagreement. */
    tip_finalize_stage_warm_authority_caches(
        progress_store_db(),
        ms ? active_chain_tip(&ms->chain_active) : NULL, "install_runtime_warm");

    struct consensus_state_chain_binding_request chain_req = {
        .main = ms, .artifact = artifact, .target_lane = lane,
    };
    /* (3c) Compiled-checkpoint content authority. A snapshot-seeded target floors
     * its block index / header-pass / script-validate logs ABOVE the checkpoint
     * height, so the checkpoint block and its Sapling source are never
     * materialized there — every below-checkpoint chain-binding predicate would
     * refuse on absent index evidence even for the byte-correct compiled
     * checkpoint bundle. Feed the compiled SHA3 checkpoint (height + block_hash)
     * and the compiled ROM keystone (Sapling frontier root + height) as the
     * substitute trust root. The binding decision uses it ONLY when the bundle
     * sits at exactly this height and reproduces this content byte-for-byte; a
     * bundle at any other height, or one that disagrees, is unaffected. */
    const struct sha3_utxo_checkpoint *sha3_cp = get_sha3_utxo_checkpoint();
    const struct rom_state_checkpoint *rom_cp = get_rom_state_checkpoint();
    if (sha3_cp && rom_cp && sha3_cp->height == rom_cp->height) {
        chain_req.checkpoint_authority.available = true;
        chain_req.checkpoint_authority.height = sha3_cp->height;
        memcpy(chain_req.checkpoint_authority.block_hash, sha3_cp->block_hash, 32);
        chain_req.checkpoint_authority.sapling_frontier_height =
            (int32_t)rom_cp->sapling_frontier_height;
        memcpy(chain_req.checkpoint_authority.sapling_frontier_root,
               rom_cp->sapling_frontier_root, 32);
    }
    /* (3c-assisted) Opt in to the FRESHEST above-checkpoint borrowed-state tier.
     * The chain-binding assisted relaxation only fires when this is on AND the
     * bundle sits strictly above the compiled checkpoint; it needs the compiled
     * checkpoint present as the eventual promotion anchor. Default ON (owner-
     * approved BOOM posture); ZCL_INSTALL_ASSISTED=0 forces it off → an above-
     * checkpoint bundle then refuses at -4 exactly as before. */
    chain_req.allow_assisted_above_checkpoint =
        install_assisted_opt_in() && sha3_cp &&
        manifest.height > (int32_t)sha3_cp->height;

    /* (3d) Gap C — instant-on checkpoint-header pass record. A headers-first
     * (--importblockindex / fast-sync) substrate bulk-loads the block index but
     * never runs the forward reducer, so validate_headers_log carries no pass
     * records. The -4 header-bootstrap crypto anchor requires a full-Equihash-PoW
     * pass record at EXACTLY the checkpoint height, so — under compiled-checkpoint
     * authority only — genuinely PoW-validate the ONE imported checkpoint header
     * now and durably record the pass, exactly as a P2P node's stage would have.
     * Idempotent + fail-open: a node that already validated it (real P2P), or one
     * whose checkpoint header is absent / wrong-block / PoW-invalid, is unchanged
     * here and the chain-binding gate below still refuses. A non-checkpoint
     * bundle (authority unavailable) never triggers this. */
    if (chain_req.checkpoint_authority.available && ms &&
        !validate_headers_stage_ensure_pass_record(
            ms, chain_req.checkpoint_authority.height))
        LOG_INFO(ICB_SUBSYS,
                 "instant-on checkpoint-header pass record not established at "
                 "h=%d (header absent / already-present miss / validate failed) "
                 "— chain-binding gate decides", chain_req.checkpoint_authority.height);

    /* (3d-assisted) Same instant-on seam at the BUNDLE height: the assisted -4
     * bind requires a full-Equihash pass record at exactly manifest.height, so
     * genuinely PoW-validate the imported bundle-height header now. Idempotent +
     * fail-open (a wrong/absent/invalid header leaves no record and the assisted
     * gate still refuses). */
    if (chain_req.allow_assisted_above_checkpoint && ms &&
        !validate_headers_stage_ensure_pass_record(ms, manifest.height))
        LOG_INFO(ICB_SUBSYS,
                 "assisted bundle-height header pass record not established at "
                 "h=%d (header absent / already-present miss / validate failed) "
                 "— chain-binding gate decides", manifest.height);

    struct consensus_state_chain_evidence *chain_evidence = NULL;
    struct zcl_result chain_built =
        consensus_state_chain_evidence_build(&chain_req, &chain_evidence);
    bool used_checkpoint_authority =
        chain_built.ok &&
        consensus_state_chain_evidence_used_checkpoint_authority(chain_evidence);
    bool used_assisted_authority =
        chain_built.ok &&
        consensus_state_chain_evidence_used_assisted_authority(chain_evidence);

    struct consensus_state_publication_decision_record decision;
    struct zcl_result cas = ZCL_ERR(-1, "chain evidence unavailable");
    if (chain_built.ok) {
        struct consensus_state_publication_cas_request cas_req = {
            .main = ms, .artifact = artifact,
            .chain_evidence = chain_evidence,
            .source_receipt = &receipt, .target_lane = lane,
            .output_dir_fd = dir_fd,
            .output_name = ICB_DECISION_RECORD_NAME,
        };
        cas = consensus_state_publication_cas_run(&cas_req, &decision);
    }

    condition_engine_set_main_state(prev_singleton);
    if (chain_evidence)
        consensus_state_chain_evidence_free(chain_evidence);

    if (!chain_built.ok) {
        /* Retriable classification — from the chain-binding refusal CODE
         * (consensus_state_chain_binding_decide returns -3..-11), not the pass
         * record alone. -3 (selected frontier not durable — e.g. the coins tip is
         * not yet trust-rooted) is SOLUTION-INDEPENDENT (proof-5's actual
         * refusal), so it MUST stay retriable even AFTER the fetch mints the
         * checkpoint pass record — the prior "no pass record" test flipped an
         * identical -3 to non-retriable the instant the solution landed, so
         * boot_auto_install_bundle wrote .failed on the byte-good bundle and
         * autodetect skipped it FOREVER (cure permanently dead). -4/-11 are
         * header-bootstrap-dependent (retriable while the pass record is absent);
         * below-checkpoint CONTENT/keystone mismatches (-5..-10) are genuine
         * rejections and fall through to .fail. */
        int cb = chain_built.code;
        bool no_pass_record = false;
        if (chain_req.checkpoint_authority.available) {
            struct uint256 cp_hash;
            memcpy(cp_hash.data, chain_req.checkpoint_authority.block_hash, 32);
            no_pass_record = !validate_headers_stage_has_pass_record(
                chain_req.checkpoint_authority.height, &cp_hash);
        }
        bool content_refusal = (cb <= -5 && cb >= -10);
        if (cb == -3 || (!content_refusal && no_pass_record))
            out->retriable_headers_not_ready = true;
        rc = ZCL_ERR(chain_built.code,
                     "selected-chain binding failed (the bundle's height/hash is "
                     "not on this node's validated header chain, or the node is "
                     "not the open singleton): %s", chain_built.message);
        goto done;
    }
    /* Auditable, not silent: state whether the below-checkpoint predicates were
     * bound from the compiled checkpoint (the sovereignty anchor) or from the
     * target's own materialized index. The same flag is folded into the chain
     * evidence digest, so this decision is also durable in the ADMIT record. */
    if (used_checkpoint_authority)
        LOG_INFO(ICB_SUBSYS,
                 "selected-chain binding used compiled-checkpoint content "
                 "authority (bundle height==checkpoint height=%d; block_hash + "
                 "Sapling frontier match the compiled keystone byte-for-byte)",
                 manifest.height);
    else if (used_assisted_authority)
        LOG_INFO(ICB_SUBSYS,
                 "selected-chain binding used the ASSISTED above-checkpoint tier "
                 "(bundle height=%d > compiled checkpoint; LOCATION + shielded "
                 "TIP root are PoW-bound, CONTENT below the seam is borrowed — "
                 "install will be RELEASE_ASSISTED until promotion ratifies it)",
                 manifest.height);
    else
        LOG_INFO(ICB_SUBSYS,
                 "selected-chain binding used the target's materialized index "
                 "(no checkpoint-content substitution)");
    if (!cas.ok) {
        rc = ZCL_ERR(cas.code, "publication CAS run failed: %s", cas.message);
        goto done;
    }
    if (decision.decision != CONSENSUS_PUBLICATION_ADMIT) {
        rc = ZCL_ERR(-1, "publication CAS did not ADMIT (refusal=%s): %s",
                     consensus_state_publication_refusal_name(decision.refusal),
                     decision.reason);
        goto done;
    }
    struct consensus_state_publication_decision_record durable_decision;
    struct zcl_result loaded = consensus_state_publication_cas_load(
        dir_fd, ICB_DECISION_RECORD_NAME, &durable_decision);
    if (!loaded.ok) {
        rc = ZCL_ERR(loaded.code,
                     "durable publication ADMIT could not be reloaded exactly: %s",
                     loaded.message);
        goto done;
    }
    if (memcmp(durable_decision.decision_digest, decision.decision_digest,
               32) != 0) {
        rc = ZCL_ERR(-1, "durable publication ADMIT changed between write and load");
        goto done;
    }

    /* The activate step re-opens and must reproduce the exact artifact receipt
     * bound into the ADMIT record; height/hash alone carry no state authority. */
    consensus_state_artifact_evidence_free(artifact);
    artifact = NULL;

    /* (4b) CHECKPOINT_CONTENT authority input. If this node's validated header
     * chain owns the compiled SHA3 UTXO checkpoint block, read that header's
     * PoW-committed hashFinalSaplingRoot so activate can bind a checkpoint-content
     * bundle's Sapling tip frontier to PoW. An absent / mismatched / zero-root
     * header leaves the authority unavailable: a content-matching bundle then only
     * VERIFY-CONTAINS, never activates on an unverifiable root. This never gates
     * the receipt authority, which needs no header. */
    bool checkpoint_root_from_header = false;
    uint8_t checkpoint_sapling_root[32];
    memset(checkpoint_sapling_root, 0, sizeof(checkpoint_sapling_root));
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (cp && ms) {
        const struct block_index *cp_bi =
            active_chain_at(&ms->chain_active, cp->height);
        struct uint256 zero_root;
        memset(&zero_root, 0, sizeof(zero_root));
        if (cp_bi && cp_bi->phashBlock &&
            memcmp(cp_bi->phashBlock->data, cp->block_hash, 32) == 0 &&
            memcmp(cp_bi->hashFinalSaplingRoot.data, zero_root.data, 32) != 0) {
            memcpy(checkpoint_sapling_root, cp_bi->hashFinalSaplingRoot.data, 32);
            checkpoint_root_from_header = true;
        }
    }

    /* (4b-assisted) ASSISTED authority input. When the chain-binding admitted via
     * the assisted above-checkpoint tier, read the BUNDLE-height header's PoW-
     * committed hashFinalSaplingRoot from this node's own validated header chain
     * so activate can bind the borrowed bundle's shielded TIP frontier to PoW at
     * the bundle height (not the compiled checkpoint height). A headers-first node
     * may have its connected chain floored at genesis, so resolve via the header
     * chain (pindex_best_header ancestor), not active_chain_at. An absent /
     * mismatched / zero-root header leaves the ASSISTED authority unavailable → a
     * VERIFIED_CONTAINED refusal, never an install on an unverifiable root. */
    bool assisted_root_from_header = false;
    uint8_t assisted_sapling_root[32];
    memset(assisted_sapling_root, 0, sizeof(assisted_sapling_root));
    if (used_assisted_authority && !used_checkpoint_authority && ms) {
        struct block_index *hdr = ms->pindex_best_header;
        struct block_index *at = (hdr && hdr->nHeight >= manifest.height)
            ? block_index_get_ancestor(hdr, (int)manifest.height)
            : NULL;
        struct uint256 zero_root;
        memset(&zero_root, 0, sizeof(zero_root));
        if (at && at->phashBlock &&
            memcmp(at->phashBlock->data, manifest.block_hash, 32) == 0 &&
            memcmp(at->hashFinalSaplingRoot.data, zero_root.data, 32) != 0) {
            memcpy(assisted_sapling_root, at->hashFinalSaplingRoot.data, 32);
            assisted_root_from_header = true;
        }
    }

    /* (5) ADMIT — atomically install the complete state. */
    struct consensus_state_activate_request areq;
    memset(&areq, 0, sizeof(areq));
    areq.bundle_path = bundle_path;
    memcpy(areq.expected_artifact_receipt_digest,
           durable_decision.artifact_receipt_digest, 32);
    areq.expected_height = manifest.height;
    memcpy(areq.expected_block_hash, manifest.block_hash, 32);
    areq.publication_decision = &durable_decision;
    areq.datadir_fd = dir_fd;
    areq.datadir_display = datadir;
    areq.checkpoint_sapling_root_from_validated_header = checkpoint_root_from_header;
    memcpy(areq.checkpoint_sapling_root, checkpoint_sapling_root, 32);
    /* Assisted tier — the exact regression-guarded expression: set ONLY when the
     * chain-binding used the assisted relaxation AND did NOT use compiled-
     * checkpoint authority. A sovereign install (cp_auth / self-validated) always
     * has used_assisted_authority=false here, so assisted_tier stays false and the
     * activate stamps self_folded → SOVEREIGN. The activate re-resolves the
     * ASSISTED authority from this flag + the Sapling bind below (defense in
     * depth) before withholding self_folded. */
    areq.assisted_tier = used_assisted_authority && !used_checkpoint_authority;
    areq.assisted_sapling_root_from_validated_header = assisted_root_from_header;
    memcpy(areq.assisted_sapling_root, assisted_sapling_root, 32);
    struct consensus_state_activate_result ares;
    if (!consensus_state_snapshot_install_activate(progress_store_db(), &areq,
                                                   &ares)) {
        out->status = ares.status; /* VERIFIED_CONTAINED / COMMIT_OUTCOME_UNKNOWN */
        rc = ZCL_ERR(-1, "activation install failed after ADMIT: %s", ares.reason);
        goto done;
    }

    /* The atomic swap committed. From here every failure is post-install: the
     * state IS on disk, so mark it so callers never fall through to a wipe. */
    out->state_installed = true;
    out->status = ares.status; /* CONSENSUS_INSTALL_ACTIVATED */
    out->height = manifest.height;
    out->hstar = ares.hstar;

    /* (6) Post-install: invalidate the derived stores that live OUTSIDE the
     * activated kernel store (consensus.db) — the persisted Sapling tree pair +
     * the in-process provable-tip cache — and verify the installed coin tip
     * matches the bundle height. A mismatch means the install did not land where
     * the ADMIT record says — refuse loudly rather than continue onto an
     * inconsistent kernel. */
    if (!icb_invalidate_derived_state(ndb, progress_store_db(), manifest.height)) {
        rc = ZCL_ERR(-1,
                     "post-install derived-state invalidation failed (installed "
                     "coin tip != bundle height, or sapling_tree pair could not be "
                     "cleared) — see ERROR log above");
        goto done;
    }

    /* (7) Durable marker: record that a sovereign bundle is now installed here so
     * a future boot never auto-loads a leftover borrowed starter-pack seed back
     * over the installed state. Best-effort — the install is already durable; a
     * marker write failure is loud but not fatal. */
    if (!boot_consensus_bundle_marker_write(datadir, manifest.height,
                                            manifest.artifact_digest))
        LOG_ERROR(ICB_SUBSYS,
                  "consensus-bundle-installed marker could not be written in %s — "
                  "install is durable, but a future boot may re-autodetect a "
                  "leftover borrowed seed; remove any utxo-seed-*.snapshot from "
                  "the datadir root manually", datadir);
    else
        out->marker_written = true;

    /* (8) Post-install: reset the node.db `utxos` mirror — see
     * icb_reset_utxo_mirror. Best-effort by design (see its doc comment). */
    if (!icb_reset_utxo_mirror(ndb))
        LOG_WARN(ICB_SUBSYS,
                 "post-install utxos mirror reset incomplete — the mirror may "
                 "retain stale rows until utxo_mirror_sync_service's own drift "
                 "detector next fires; the installed consensus state itself is "
                 "unaffected (node.db utxos carries no consensus weight)");

    snprintf(out->reason, sizeof(out->reason), "%s", ares.reason);
    rc = ZCL_OK;

done:
    if (artifact)
        consensus_state_artifact_evidence_free(artifact);
    if (dir_fd >= 0)
        (void)close(dir_fd);
    if (!rc.ok) {
        snprintf(out->reason, sizeof(out->reason), "%s", rc.message);
        LOG_WARN(ICB_SUBSYS, "%s", rc.message);
    }
    return rc;
}

#ifdef ZCL_TESTING
bool boot_install_consensus_bundle_gate_allows_for_test(
    const char *datadir, const char *authorization, bool *out_canonical)
{
    int dir_fd = -1;
    bool canonical = false;
    struct zcl_result classified =
        icb_datadir_open_classify(datadir, &dir_fd, &canonical);
    if (!classified.ok)
        return false;
    (void)close(dir_fd);
    if (out_canonical)
        *out_canonical = canonical;
    return !canonical || icb_canonical_authorized(authorization);
}

bool boot_install_consensus_bundle_invalidate_derived_for_test(
    struct node_db *ndb, sqlite3 *progress_db, int32_t bundle_height)
{
    return icb_invalidate_derived_state(ndb, progress_db, bundle_height);
}

bool boot_install_consensus_bundle_reset_utxo_mirror_for_test(struct node_db *ndb)
{
    return icb_reset_utxo_mirror(ndb);
}
#endif

#endif
