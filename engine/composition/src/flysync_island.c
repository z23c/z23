/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: FlySync island start: verify and seed the rung header window, hold
 * header sync until the rung bundle installs, and fall back loudly. See
 * config/flysync_island.h. */

#include "config/flysync_island.h"

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/checkpoints.h"
#include "chain/pow.h"
#include "config/boot.h"
#include "config/boot_consensus_bundle_marker.h"
#include "config/boot_error.h"
#include "config/boot_internal.h"
#include "config/consensus_state_install_runtime.h"
#include "config/state_offer_store.h"
#include "controllers/agent_controller.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "jobs/block_header_emit.h"
#include "jobs/validate_headers_stage.h"
#include "net/msgprocessor.h"
#include "net/checkpoint_header_fetch.h"
#include "platform/time_compat.h"
#include "primitives/block.h"
#include "services/block_row_verify.h"
#include "services/chain_state_service.h"
#include "services/island_anchor.h"
#include "services/sync_monitor.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FSI_SUBSYS "flysync"

static _Atomic bool g_requested = false;
static _Atomic int g_phase = FLYSYNC_OFF;
static int64_t g_phase_since_ms;        /* tick thread only */
static int g_walk_attempts;             /* tick thread only */
static _Atomic uint64_t g_window_headers_seeded;

#ifdef ZCL_TESTING
static _Atomic(flysync_frozen_verify_fn) g_test_verify;
static _Atomic int64_t g_test_now_ms = -1;
static struct rom_state_rung g_test_rung;
static _Atomic bool g_test_rung_set = false;
#endif

const char *flysync_phase_name(enum flysync_phase p)
{
    static const char *const names[] = {
        "off", "wait", "walk", "seeded", "done", "fell_back",
    };
    return (p >= FLYSYNC_OFF && p <= FLYSYNC_FELL_BACK) ? names[p] : "unknown";
}

static int64_t fsi_now_ms(void)
{
#ifdef ZCL_TESTING
    int64_t t = atomic_load(&g_test_now_ms);
    if (t >= 0)
        return t;
#endif
    return platform_time_monotonic_ms();
}

static void fsi_set_phase(enum flysync_phase p)
{
    enum flysync_phase was = (enum flysync_phase)atomic_exchange(&g_phase, p);
    g_phase_since_ms = fsi_now_ms();
    if (was != p)
        LOG_INFO(FSI_SUBSYS, "FlySync phase %s -> %s", flysync_phase_name(was),
                 flysync_phase_name(p));
}

void flysync_island_set_requested(bool on) { atomic_store(&g_requested, on); }
bool flysync_island_requested(void) { return atomic_load(&g_requested); }
enum flysync_phase flysync_island_phase(void)
{
    return (enum flysync_phase)atomic_load(&g_phase);
}

bool flysync_island_holds_header_sync(void)
{
    int p = atomic_load(&g_phase);
    return p == FLYSYNC_WAIT || p == FLYSYNC_WALK || p == FLYSYNC_SEEDED;
}

/* ── Window verification ─────────────────────────────────────────────────── */

static const struct rom_state_rung *fsi_rung_at(int32_t height)
{
#ifdef ZCL_TESTING
    if (atomic_load(&g_test_rung_set))
        return g_test_rung.cp.height == height ? &g_test_rung : NULL;
#endif
    size_t n = get_rom_state_rung_count();
    for (size_t i = 0; i < n; i++) {
        const struct rom_state_rung *r = get_rom_state_rung_at(i);
        if (r && r->cp.height == height)
            return r;
    }
    return NULL;
}

static bool fsi_frozen_verify(const struct uint256 *hash,
                              const struct block_header *hdr)
{
#ifdef ZCL_TESTING
    flysync_frozen_verify_fn ov = atomic_load(&g_test_verify);
    if (ov)
        return ov(hash, hdr);
#endif
    const struct chain_params *cp = chain_params_get();
    return cp && block_row_verify(hash->data, hdr->nBits, hdr, cp, true) ==
                     BLOCK_ROW_VERIFY_OK;
}

static struct arith_uint256 fsi_header_proof(const struct block_header *h)
{
    struct block_index tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp.nBits = h->nBits;
    return GetBlockProof(&tmp);
}

/* Links, then frozen PoW + Equihash, top first. */
static bool fsi_check_links(const struct block_header *w, int n,
                            const struct uint256 *top_hash, int32_t top_h,
                            char *why, size_t why_cap)
{
    struct uint256 expect = *top_hash;
    for (int i = 0; i < n; i++) {
        struct uint256 got;
        block_header_get_hash(&w[i], &got);
        if (!uint256_eq(&got, &expect)) {
            snprintf(why, why_cap, "header h=%d does not hash to its link",
                     (int)(top_h - i));
            return false;
        }
        if (!fsi_frozen_verify(&got, &w[i])) {
            snprintf(why, why_cap, "header h=%d fails PoW/Equihash",
                     (int)(top_h - i));
            return false;
        }
        expect = w[i].hashPrevBlock;
    }
    return true;
}

bool flysync_island_verify_window(const struct block_header *w, int n,
                                  int32_t top_h, struct island_anchor *out,
                                  char *why, size_t why_cap)
{
    char sink[8];
    if (!why || why_cap == 0) {
        why = sink;
        why_cap = sizeof(sink);
    }
    why[0] = '\0';
    const struct rom_state_rung *rung = fsi_rung_at(top_h);
    if (!w || !out || n != ISLAND_ANCHOR_WINDOW || !rung) {
        snprintf(why, why_cap, "window of %d at h=%d is not a %d-row window "
                 "at a baked rung", n, (int)top_h, ISLAND_ANCHOR_WINDOW);
        return false;
    }
    struct uint256 rung_hash;
    memcpy(rung_hash.data, rung->cp.block_hash, 32);
    if (!fsi_check_links(w, n, &rung_hash, top_h, why, why_cap))
        return false;

    struct arith_uint256 work, above;
    island_anchor_work_from_be(&work, rung->chainwork);
    arith_uint256_set_zero(&above);
    for (int i = 0; i < n - 1; i++) {
        struct arith_uint256 p = fsi_header_proof(&w[i]), sum;
        arith_uint256_add(&sum, &above, &p);
        above = sum;
    }
    struct arith_uint256 root_proof = fsi_header_proof(&w[n - 1]);
    struct arith_uint256 root_work;
    arith_uint256_sub(&root_work, &work, &above);
    if (arith_uint256_compare(&work, &above) <= 0 ||
        arith_uint256_compare(&root_work, &root_proof) < 0) {
        snprintf(why, why_cap, "window work exceeds the compiled rung "
                 "chainwork");
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->rung_height = top_h;
    out->rung_hash = rung_hash;
    out->root_height = top_h - (n - 1);
    block_header_get_hash(&w[n - 1], &out->root_hash);
    out->root_work = root_work;
    return true;
}

/* ── Seeding ─────────────────────────────────────────────────────────────── */

static bool fsi_fill_row(struct block_index *bi, const struct block_header *h,
                         int32_t height, struct block_index *prev,
                         const struct arith_uint256 *root_work)
{
    bi->nVersion = h->nVersion;
    bi->hashFinalSaplingRoot = h->hashFinalSaplingRoot;
    bi->nTime = h->nTime;
    bi->nBits = h->nBits;
    if (!block_index_set_hdrext(bi, &h->hashMerkleRoot, &h->nNonce,
                                h->nSolution, h->nSolutionSize))
        return false;
    bi->nHeight = height;
    bi->pprev = prev;
    if (prev) {
        struct arith_uint256 proof = GetBlockProof(bi);
        arith_uint256_add(&bi->nChainWork, &prev->nChainWork, &proof);
        block_index_build_skip(bi);
    } else {
        bi->nChainWork = *root_work;
    }
    if ((bi->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TREE)
        bi->nStatus = (bi->nStatus & ~BLOCK_VALID_MASK) | BLOCK_VALID_TREE;
    return true;
}

/* The durable row: the same EV_BLOCK_HEADER the header-admit stage writes.
 * The root carries its real hashPrevBlock (a parent this node never holds). */
static bool fsi_emit_row(struct block_index *bi, const struct block_header *h)
{
    if (bi->pprev)
        return block_index_emit_header_event(bi, FSI_SUBSYS, NULL, NULL);
    struct block_index parent;
    memset(&parent, 0, sizeof(parent));
    struct uint256 parent_hash = h->hashPrevBlock;
    parent.phashBlock = &parent_hash;
    parent.nHeight = bi->nHeight - 1;
    bi->pprev = &parent;   /* not yet published: the row is not in any chain */
    bool ok = block_index_emit_header_event(bi, FSI_SUBSYS, NULL, NULL);
    bi->pprev = NULL;
    return ok;
}

static struct block_index *fsi_insert_window(struct main_state *ms,
                                             const struct block_header *w,
                                             int n,
                                             const struct island_anchor *a)
{
    struct block_index *prev = NULL;
    for (int i = n - 1; i >= 0; i--) {
        struct uint256 hash;
        block_header_get_hash(&w[i], &hash);
        struct block_index *bi = block_map_find(&ms->map_block_index, &hash);
        if (!bi)
            bi = chainstate_insert_block_index((struct chainstate *)ms, &hash);
        int32_t height = a->rung_height - i;
        if (!bi || !fsi_fill_row(bi, &w[i], height, prev, &a->root_work)) {
            LOG_WARN(FSI_SUBSYS, "island row h=%d could not be inserted",
                     (int)height);
            return NULL;
        }
        if (!fsi_emit_row(bi, &w[i]))
            LOG_WARN(FSI_SUBSYS, "island row h=%d: durable header event not "
                     "written (event log not open?)", (int)height);
        prev = bi;
    }
    return prev;
}

static bool fsi_work_matches_rung(const struct block_index *top,
                                  const struct island_anchor *a)
{
    const struct rom_state_rung *rung = fsi_rung_at(a->rung_height);
    if (!top || !rung)
        return false;
    struct arith_uint256 want;
    island_anchor_work_from_be(&want, rung->chainwork);
    return arith_uint256_compare(&top->nChainWork, &want) == 0;
}

bool flysync_island_seed(struct main_state *ms, const struct block_header *w,
                         int n, const struct island_anchor *a)
{
    if (!ms || !w || !a || n != ISLAND_ANCHOR_WINDOW)
        return false;
    /* The fact goes down before any row: a crash after it leaves a fact whose
     * rows are missing (reconcile falls back), never rows without a fact (a
     * datadir that -flysync would refuse forever). */
    if (!island_anchor_save(progress_store_db(), a) ||
        !island_anchor_register(a))
        return false;
    zcl_mutex_lock(&ms->cs_main);
    struct block_index *top = fsi_insert_window(ms, w, n, a);
    zcl_mutex_unlock(&ms->cs_main);
    if (!top || !fsi_work_matches_rung(top, a)) {
        LOG_WARN(FSI_SUBSYS, "island seed refused: %s",
                 top ? "rung chainwork mismatch" : "insert failed");
        island_anchor_note_fallback(progress_store_db(),
                                    "the verified window could not be seeded");
        return false;
    }
    bool promoted = false;
    enum csr_result rc = csr_promote_header_tip(
        csr_instance(), &ms->chain_active, &ms->pindex_best_header, top,
        "flysync_island", &promoted);
    if (rc != CSR_OK)
        LOG_WARN(FSI_SUBSYS, "island top not promoted to best header: %s",
                 csr_result_name(rc));
    if (!validate_headers_stage_ensure_pass_record(ms, a->rung_height))
        LOG_WARN(FSI_SUBSYS, "pass row at rung h=%d not minted yet",
                 (int)a->rung_height);
    atomic_store(&g_window_headers_seeded, (uint64_t)n);
    LOG_WARN(FSI_SUBSYS,
             "FlySync island seeded: %d verified headers h=%d..%d hash-linked "
             "to the compiled rung, chainwork equals the compiled rung", n,
             (int)a->root_height, (int)a->rung_height);
    return true;
}

/* ── Boot ────────────────────────────────────────────────────────────────── */

static bool fsi_datadir_has_chain_state(struct main_state *ms)
{
    return ms && (active_chain_height(&ms->chain_active) > 0 ||
                  ms->map_block_index.size > 1);
}

bool flysync_island_boot_gate(const char *datadir, struct main_state *ms,
                              char *why, size_t why_cap)
{
    sqlite3 *db = progress_store_db();
    enum island_anchor_state st = island_anchor_state_load(db);
    /* A seeded island continues with or without the flag: a respawn or an app
     * restart may drop -flysync from argv, and the island must still finish. */
    if (st == ISLAND_ANCHOR_STATE_SEEDED) {
        bool installed = datadir && boot_consensus_bundle_marker_exists(datadir);
        fsi_set_phase(installed ? FLYSYNC_DONE : FLYSYNC_SEEDED);
        return true;
    }
    if (!atomic_load(&g_requested))
        return true;
    if (st == ISLAND_ANCHOR_STATE_FELL_BACK) {
        LOG_WARN(FSI_SUBSYS, "-flysync: this datadir fell back to normal sync "
                 "earlier; continuing with normal sync");
        fsi_set_phase(FLYSYNC_FELL_BACK);
        return true;
    }
    if (fsi_datadir_has_chain_state(ms)) {
        snprintf(why, why_cap,
                 "-flysync applies only to a datadir with no chain state; this "
                 "one already holds %zu block index entries and is not a "
                 "FlySync island. Start without -flysync, or use a new datadir",
                 ms->map_block_index.size);
        return false;
    }
    fsi_set_phase(FLYSYNC_WAIT);
    return true;
}

static bool fsi_reconcile_walk(struct main_state *ms,
                               const struct island_anchor *a,
                               const char **why)
{
    struct uint256 rung_hash = a->rung_hash;
    struct block_index *top = block_map_find(&ms->map_block_index, &rung_hash);
    if (!top || top->nHeight != a->rung_height) {
        *why = "the rung header is not in the loaded block index";
        return false;
    }
    const struct block_index *p = top;
    for (int i = 0; i < ISLAND_ANCHOR_WINDOW - 1; i++) {
        if (!p->pprev || p->pprev->nHeight != p->nHeight - 1) {
            *why = "the rung does not link down to the island root";
            return false;
        }
        p = p->pprev;
    }
    if (!island_anchor_is_root(p) || p->pprev) {
        *why = "the island root does not match the recorded fact";
        return false;
    }
    if (!fsi_work_matches_rung(top, a)) {
        *why = "the rung header's chainwork is not the compiled rung chainwork";
        return false;
    }
    return true;
}

bool flysync_island_boot_reconcile(struct main_state *ms)
{
    struct island_anchor a;
    if (!ms || !island_anchor_get(&a))
        return false;
    const char *why = NULL;
    if (fsi_reconcile_walk(ms, &a, &why)) {
        LOG_INFO(FSI_SUBSYS, "island reloaded: root h=%d .. rung h=%d, "
                 "chainwork equals the compiled rung", (int)a.root_height,
                 (int)a.rung_height);
        return true;
    }
    LOG_WARN(FSI_SUBSYS, "island does not stand after load: %s", why);
    island_anchor_note_fallback(progress_store_db(), why);
    fsi_set_phase(FLYSYNC_FELL_BACK);
    return false;
}

/* ── Phase machine ───────────────────────────────────────────────────────── */

static void fsi_fall_back(const char *why)
{
    checkpoint_header_fetch_disarm();
    island_anchor_note_fallback(progress_store_db(), why);
    fsi_set_phase(FLYSYNC_FELL_BACK);
}

static struct main_state *fsi_main_state(void)
{
    return sync_monitor_main_state();
}

static void fsi_tick_wait(int64_t now)
{
    const char *datadir = agent_runtime_context_datadir();
    char *bundle = datadir ? boot_autodetect_consensus_bundle(datadir) : NULL;
    if (bundle) {
        int32_t h = -1;
        uint8_t hash[32];
        bool ok = boot_staged_bundle_wait_target(bundle, &h, hash);
        free(bundle);
        if (!ok || !fsi_rung_at(h)) {
            fsi_fall_back("the staged bundle is not at a baked ladder rung");
            return;
        }
        struct uint256 top;
        memcpy(top.data, hash, 32);
        checkpoint_header_fetch_arm_window(h, &top, ISLAND_ANCHOR_WINDOW);
        g_walk_attempts++;
        fsi_set_phase(FLYSYNC_WALK);
        return;
    }
    struct state_offer_store_status st;
    state_offer_store_status_get(&st);
    if (st.last_decision == STATE_OFFER_DECIDE_FALL_BACK)
        fsi_fall_back("no acceptable rung offer inside the state-offer wait");
    else if (st.wait_armed && st.chosen_height == 0 &&
             now - st.wait_started_ms >= STATE_OFFER_WAIT_MS + 30000)
        fsi_fall_back("no rung offer chosen inside the state-offer wait");
}

static void fsi_tick_walk(int64_t now)
{
    struct block_header w[CHECKPOINT_HEADER_FETCH_WINDOW_MAX];
    int32_t top_h = -1;
    int n = checkpoint_header_fetch_take_window(
        w, CHECKPOINT_HEADER_FETCH_WINDOW_MAX, &top_h);
    if (n > 0) {
        struct island_anchor a;
        char why[160];
        struct main_state *ms = fsi_main_state();
        if (flysync_island_verify_window(w, n, top_h, &a, why, sizeof(why))) {
            if (ms && flysync_island_seed(ms, w, n, &a))
                fsi_set_phase(FLYSYNC_SEEDED);
            else
                fsi_fall_back("the verified header window could not be seeded");
            return;
        }
        LOG_WARN(FSI_SUBSYS, "header window refused (attempt %d/%d): %s",
                 g_walk_attempts, FLYSYNC_WALK_ATTEMPTS, why);
        if (g_walk_attempts >= FLYSYNC_WALK_ATTEMPTS)
            fsi_fall_back("the header window failed verification");
        else
            fsi_set_phase(FLYSYNC_WAIT);   /* re-arms from the staged bundle */
        return;
    }
    if (now - g_phase_since_ms >= FLYSYNC_WALK_TIMEOUT_MS)
        fsi_fall_back("the header window walk timed out (no peer served "
                      "the rung window)");
}

static void fsi_tick_seeded(int64_t now)
{
    const char *datadir = agent_runtime_context_datadir();
    if (datadir && boot_consensus_bundle_marker_exists(datadir)) {
        fsi_set_phase(FLYSYNC_DONE);
        LOG_WARN(FSI_SUBSYS, "FlySync: rung bundle installed; header sync "
                 "continues from the rung");
        return;
    }
    char *bundle = datadir ? boot_autodetect_consensus_bundle(datadir) : NULL;
    bool staged = bundle != NULL;
    free(bundle);
    if (!staged)
        fsi_fall_back("the rung bundle is no longer installable (failed or "
                      "removed)");
    else if (now - g_phase_since_ms >= FLYSYNC_INSTALL_TIMEOUT_MS)
        fsi_fall_back("the rung bundle did not install within its bound");
}

void flysync_island_boot_register(void)
{
    (void)island_anchor_boot_register(progress_store_db());
}

bool flysync_island_boot_after_index(struct app_context *ctx,
                                     struct main_state *ms)
{
    char why[320];
    why[0] = '\0';
    if (!flysync_island_boot_gate(ctx ? ctx->datadir : NULL, ms, why,
                                  sizeof(why))) {
        LOG_ERROR(FSI_SUBSYS, "-flysync refused: %s", why);
        static const struct boot_error_next next[] = {
            {"z23 -datadir=<new empty directory> -flysync",
             "FlySync starts only a datadir with no chain state"},
        };
        return boot_refuse_at_permanent_gate("flysync_datadir", why, next, 1,
                                             NULL);
    }
    if (island_anchor_registered())
        (void)flysync_island_boot_reconcile(ms);
    enum flysync_phase p = flysync_island_phase();
    if (p != FLYSYNC_OFF && p != FLYSYNC_FELL_BACK) {
        msg_processor_set_header_sync_hold(flysync_island_holds_header_sync);
        net_set_advertise_full_history(false);
        LOG_WARN(FSI_SUBSYS, "FlySync phase %s: header sync %s; NODE_NETWORK "
                 "not advertised (no history below the rung)",
                 flysync_phase_name(p),
                 flysync_island_holds_header_sync() ? "held until the rung "
                 "bundle installs" : "runs from the rung");
    }
    return true;
}

void flysync_island_tick(void)
{
    if (atomic_load(&g_phase) == FLYSYNC_OFF)
        return;
    int64_t now = fsi_now_ms();
    switch ((enum flysync_phase)atomic_load(&g_phase)) {
    case FLYSYNC_WAIT:   fsi_tick_wait(now);   break;
    case FLYSYNC_WALK:   fsi_tick_walk(now);   break;
    case FLYSYNC_SEEDED: fsi_tick_seeded(now); break;
    default: break;
    }
}

#ifdef ZCL_TESTING
void flysync_island_test_set_frozen_verifier(flysync_frozen_verify_fn fn)
{
    atomic_store(&g_test_verify, fn);
}

void flysync_island_test_reset(void)
{
    atomic_store(&g_requested, false);
    atomic_store(&g_phase, FLYSYNC_OFF);
    atomic_store(&g_test_verify, NULL);
    atomic_store(&g_test_now_ms, -1);
    atomic_store(&g_test_rung_set, false);
    g_walk_attempts = 0;
    g_phase_since_ms = 0;
    island_anchor_unregister();
}

void flysync_island_test_set_clock_ms(int64_t now_ms)
{
    atomic_store(&g_test_now_ms, now_ms);
}
#endif

#ifdef ZCL_TESTING
void flysync_island_test_set_rung(const struct rom_state_rung *rung)
{
    if (rung)
        g_test_rung = *rung;
    atomic_store(&g_test_rung_set, rung != NULL);
}
#endif
