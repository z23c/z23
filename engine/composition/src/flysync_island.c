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
#include "services/block_index_loader.h"
#include "services/block_row_verify.h"
#include "services/chain_state_service.h"
#include "services/chain_tip_watchdog.h"
#include "services/island_anchor.h"
#include "services/sync_monitor.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/thread_registry.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FSI_SUBSYS "flysync"

static _Atomic bool g_requested = false;
static _Atomic int g_phase = FLYSYNC_OFF;
/* The tick runs from two swarm call sites; g_tick_busy admits one at a time. */
static _Atomic int64_t g_phase_since_ms;
static _Atomic int g_walk_attempts;
static _Atomic bool g_tick_busy = false;
static _Atomic uint64_t g_window_headers_seeded;

#ifdef ZCL_TESTING
static _Atomic int g_test_respawns = 0;
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
    atomic_store(&g_phase_since_ms, fsi_now_ms());
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

/* Record a fall-back durably. The in-process fall-back stands either way; an
 * unrecorded one is logged with its reason (the next boot then sees the fact
 * as SEEDED and its reconcile decides again). */
static void fsi_note_fallback(const char *why)
{
    struct zcl_result r = island_anchor_note_fallback(progress_store_db(), why);
    if (!r.ok)
        LOG_ERROR(FSI_SUBSYS, "%s", r.message);
}

/* True only when the installed-bundle marker names exactly the fact's rung
 * height: INSTALLED is never undone, so it keys on the fact like every other
 * island exemption. A marker at another height is logged and ignored. */
static bool fsi_rung_installed(const char *datadir)
{
    int32_t h = -1;
    if (!datadir || !boot_consensus_bundle_marker_height(datadir, &h))
        return false;
    struct island_anchor a;
    bool found = false;
    if (!island_anchor_load(progress_store_db(), &a, &found) || !found) {
        LOG_WARN(FSI_SUBSYS, "bundle marker h=%d present but the island fact "
                 "is unreadable; the island is not marked installed", h);
        return false;
    }
    if (h == a.rung_height)
        return true;
    static _Atomic bool warned = false;   /* the seeded tick asks repeatedly */
    if (!atomic_exchange(&warned, true))
        LOG_WARN(FSI_SUBSYS, "bundle marker h=%d is not the island rung h=%d; "
                 "the island is not marked installed", h, a.rung_height);
    return false;
}

static bool fsi_note_installed(void)
{
    struct zcl_result r = island_anchor_note_installed(progress_store_db());
    if (!r.ok)
        LOG_ERROR(FSI_SUBSYS, "%s", r.message);
    return r.ok;
}

static void fsi_fall_back_at(struct main_state *ms, const char *why,
                             bool respawn);

/* ── Detaching a fallen-back island ──────────────────────────────────────────
 * After a fall-back the island rows are real headers whose root has no parent
 * here, and they carry the rung's chainwork: left alone they would stay the
 * best header and steer header sync above the rung, where normal sync can
 * fetch no block. So every window row still off the chain, and every entry
 * descending from one (headers admitted above the rung), is detached: no
 * parent, no skip, and work FSI_DETACHED_WORK, below
 * any real entry's (genesis included). Not zero: the boot block-index scan
 * ranks a zero-work entry by height, which would make the rung row the best
 * header again. Every work comparison passes over the rows, and when normal
 * sync re-delivers these headers from their real parent, accept_block_header's
 * known-header relink sets each parent and derives its work, so the rows
 * rejoin the chain as ordinary headers. Keyed on the durable fact: the listed
 * rows at their exact heights and hashes (with or without the root in the
 * index); if the list cannot be read, every off-chain entry at the fact's
 * heights. It runs at the fall-back and again at every boot whose durable
 * state is FELL_BACK, after the canonical forward pass over the map (the
 * loader brings the rows back with work, and work above rows that rejoined in
 * memory only is stale), so a crash anywhere between the durable FELL_BACK and
 * a saved rejoin is repaired by the next boot. The fact retires once the rung
 * row is on the chain. Idempotent. */
#define FSI_DETACHED_WORK 1u

static bool fsi_work_is_detached(const struct block_index *bi)
{
    return arith_uint256_equal_u64(&bi->nChainWork, FSI_DETACHED_WORK);
}
struct fsi_rows {
    struct block_index **v;
    size_t n, cap;
};

static bool fsi_rows_push(struct fsi_rows *r, struct block_index *bi)
{
    if (r->n == r->cap) {
        size_t cap = r->cap ? r->cap * 2 : 64;
        struct block_index **v =
            zcl_realloc(r->v, cap * sizeof(*v), "flysync_detach_rows");
        if (!v)
            return false;
        r->v = v;
        r->cap = cap;
    }
    r->v[r->n++] = bi;
    return true;
}

/* Off the chain: its ancestor at the island root's height is missing or has no
 * parent. A row that rejoined sits on its real parent's chain; a row the
 * island seeded, or a flushed detach stored parentless (all of them, or after
 * a crash mid-flush one parentless row with the rows above still linked to
 * it), does not, and loads with work. */
static bool fsi_off_chain(struct block_index *bi, int32_t root_h)
{
    struct block_index *anc = block_index_get_ancestor(bi, root_h);
    return !anc || !anc->pprev;
}

static void fsi_detach_row(struct block_index *bi)
{
    bi->pprev = NULL;
    bi->pskip = NULL;
    arith_uint256_set_u64(&bi->nChainWork, FSI_DETACHED_WORK);
}

/* The window's rows, each by the exact (height, hash) in the durable row list,
 * whether or not the root reached the index. False with *have = false when
 * the list is missing or unreadable. */
static bool fsi_collect_listed(struct main_state *ms,
                               const struct island_anchor *a,
                               struct fsi_rows *rows, bool *have)
{
    struct island_anchor_rows list;
    bool found = false;
    *have = island_anchor_rows_load(progress_store_db(), &list, &found) &&
            found;
    for (int i = 0; *have && i < ISLAND_ANCHOR_WINDOW; i++) {
        struct block_index *bi = block_map_find(&ms->map_block_index,
                                                &list.hash[i]);
        if (bi && bi->nHeight == a->root_height + i &&
            fsi_off_chain(bi, a->root_height) && !fsi_rows_push(rows, bi))
            return false;
    }
    return *have;
}

/* Fail closed when the row list cannot be read: every off-chain entry at the
 * fact's heights is taken as an island row (an unrelated one rejoins the same
 * way when its header is delivered again). */
static bool fsi_collect_range(struct main_state *ms,
                              const struct island_anchor *a,
                              struct fsi_rows *rows)
{
    LOG_ERROR(FSI_SUBSYS, "island row list missing or unreadable; detaching "
              "every off-chain entry at the fact's heights h=%d .. %d",
              (int)a->root_height, (int)a->rung_height);
    size_t it = 0;
    struct block_index *bi = NULL;
    while (block_map_next(&ms->map_block_index, &it, NULL, &bi)) {
        if (bi && bi->nHeight >= a->root_height &&
            bi->nHeight <= a->rung_height &&
            fsi_off_chain(bi, a->root_height) && !fsi_rows_push(rows, bi))
            return false;
    }
    return true;
}

static int fsi_cmp_height(const void *x, const void *y)
{
    const struct block_index *a = *(struct block_index *const *)x;
    const struct block_index *b = *(struct block_index *const *)y;
    return (a->nHeight > b->nHeight) - (a->nHeight < b->nHeight);
}

/* Every entry above the root that descends from a detached row (headers normal
 * sync admitted above the rung after the rows rejoined in memory only): in
 * height order, an entry whose parent carries the detached token is detached
 * in turn, so its re-delivered header relinks it with real work. */
static bool fsi_detach_descendants(struct main_state *ms, int32_t root_h,
                                   struct fsi_rows *rows)
{
    struct fsi_rows up = {0};
    size_t it = 0;
    struct block_index *bi = NULL;
    bool ok = true;
    while (ok && block_map_next(&ms->map_block_index, &it, NULL, &bi)) {
        if (bi && bi->nHeight > root_h && bi->pprev && !fsi_work_is_detached(bi))
            ok = fsi_rows_push(&up, bi);
    }
    if (ok && up.n)
        qsort(up.v, up.n, sizeof(*up.v), fsi_cmp_height);
    for (size_t i = 0; ok && i < up.n; i++) {
        if (!up.v[i]->pprev || !fsi_work_is_detached(up.v[i]->pprev))
            continue;
        ok = fsi_rows_push(rows, up.v[i]);
        fsi_detach_row(up.v[i]);
    }
    free(up.v);
    return ok;
}

/* The most-work entry that still has real work, else the active tip. */
static struct block_index *fsi_best_remaining(struct main_state *ms)
{
    struct block_index *best = active_chain_tip(&ms->chain_active);
    size_t it = 0;
    struct block_index *bi = NULL;
    while (block_map_next(&ms->map_block_index, &it, NULL, &bi)) {
        if (!bi || arith_uint256_is_zero(&bi->nChainWork) ||
            fsi_work_is_detached(bi))
            continue;
        if (!best || arith_uint256_compare(&bi->nChainWork,
                                           &best->nChainWork) > 0)
            best = bi;
    }
    return best;
}

static void fsi_reset_best_header(struct main_state *ms)
{
    struct block_index *cur = ms->pindex_best_header;
    if (cur && !arith_uint256_is_zero(&cur->nChainWork) &&
        !fsi_work_is_detached(cur))
        return;
    struct block_index *best = fsi_best_remaining(ms);
    if (!best)
        return;
    struct chain_state_rollback_authorization auth = {
        .source = CSR_ROLLBACK_SOURCE_HEADER_SYNC,
        .decision = POLICY_ALLOW,
        .from_height = cur ? cur->nHeight : -1,
        .to_height = best->nHeight,
        .max_depth = INT64_MAX,
        .evidence_class = "flysync_island_fallback",
        .reason = "the fallen-back island is not a chain to sync from",
    };
    struct chain_state_header_commit commit = {
        .new_header_tip = best,
        .rollback_auth = &auth,
        .reason = "flysync_island_fallback",
    };
    enum csr_result rc = csr_commit_header_tip(csr_instance(), &commit);
    if (rc != CSR_OK)
        LOG_ERROR(FSI_SUBSYS, "best header not moved off the fallen-back "
                  "island (h=%d -> h=%d): %s", cur ? cur->nHeight : -1,
                  best->nHeight, csr_result_name(rc));
}

size_t flysync_island_detach(struct main_state *ms,
                             const struct island_anchor *a)
{
    if (!ms || !a)
        return 0;
    zcl_mutex_lock(&ms->cs_main);
    struct fsi_rows rows = {0};
    bool have = false;
    bool ok = fsi_collect_listed(ms, a, &rows, &have) ||
              (!have && fsi_collect_range(ms, a, &rows));
    size_t seeds = ok ? rows.n : 0;
    for (size_t i = 0; i < seeds; i++)
        fsi_detach_row(rows.v[i]);
    ok = ok && fsi_detach_descendants(ms, a->root_height, &rows);
    zcl_mutex_unlock(&ms->cs_main);
    if (rows.n)
        fsi_reset_best_header(ms);
    if (!ok)
        LOG_ERROR(FSI_SUBSYS, "fallen-back island not fully detached: out of "
                  "memory listing its rows (%zu detached)", rows.n);
    else if (rows.n)
        LOG_WARN(FSI_SUBSYS, "fallen-back island detached: %zu rows from h=%d "
                 "(%zu above the window) no longer steer header sync; they "
                 "rejoin when normal sync reaches their parent", rows.n,
                 (int)a->root_height, rows.n - seeds);
    size_t n = rows.n;
    free(rows.v);
    return n;
}

bool flysync_island_seed(struct main_state *ms, const struct block_header *w,
                         int n, const struct island_anchor *a)
{
    if (!ms || !w || !a || n != ISLAND_ANCHOR_WINDOW)
        return false;
    /* The fact goes down before any row: a crash after it leaves a fact whose
     * rows are missing (reconcile falls back), never rows without a fact (a
     * datadir that -flysync would refuse forever). */
    struct island_anchor_rows rows;
    for (int i = 0; i < n; i++)   /* w[0] is the rung, w[n - 1] the root */
        block_header_get_hash(&w[n - 1 - i], &rows.hash[i]);
    struct zcl_result saved = island_anchor_save(progress_store_db(), a, &rows);
    if (!saved.ok) {
        LOG_WARN(FSI_SUBSYS, "island seed refused: %s", saved.message);
        return false;
    }
    if (!island_anchor_register(a))
        return false;
    zcl_mutex_lock(&ms->cs_main);
    struct block_index *top = fsi_insert_window(ms, w, n, a);
    zcl_mutex_unlock(&ms->cs_main);
    if (!top || !fsi_work_matches_rung(top, a)) {
        LOG_WARN(FSI_SUBSYS, "island seed refused: %s (the caller falls "
                 "back and detaches the rows)",
                 top ? "rung chainwork mismatch" : "insert failed");
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
             "FlySync island seeded: %d headers h=%d..%d, each passing PoW and "
             "Equihash, hash-linked down from the compiled rung hash (root "
             "work is set from the compiled rung chainwork)", n,
             (int)a->root_height, (int)a->rung_height);
    return true;
}

/* ── Boot ────────────────────────────────────────────────────────────────── */

static bool fsi_datadir_has_chain_state(struct main_state *ms)
{
    return ms && (active_chain_height(&ms->chain_active) > 0 ||
                  ms->map_block_index.size > 1);
}

/* The datadir the boot gate saw; the agent runtime's otherwise. */
static char g_datadir[1024];

static const char *fsi_datadir(void)
{
    return g_datadir[0] ? g_datadir : agent_runtime_context_datadir();
}

static bool fsi_gate_fresh(sqlite3 *db, struct main_state *ms, char *why,
                           size_t why_cap);

/* The island state could not be read: never decide on it (a SEEDED island
 * misread as fresh would be written FELL_BACK for good). Refuse this start
 * when -flysync is set or an island fact is present. A start without the flag
 * and without a readable fact continues as a node without FlySync does: it
 * holds nothing and writes no island state (a durable fall-back refuses on an
 * unreadable state). */
static bool fsi_gate_unreadable(sqlite3 *db, char *why, size_t why_cap)
{
    struct island_anchor a;
    bool found = false;
    bool no_fact = !(island_anchor_load(db, &a, &found) && found);
    if (!atomic_load(&g_requested) && no_fact) {
        LOG_WARN(FSI_SUBSYS, "island state unreadable and no readable island "
                 "fact: continuing without FlySync");
        return true;
    }
    snprintf(why, why_cap,
             "the FlySync island state in the progress store is unreadable, so "
             "this start cannot tell a seeded or installed island from a fresh "
             "or fallen-back one and decides nothing; start again, and if it "
             "persists check the progress store (%s)",
             no_fact ? "-flysync is set" : "an island fact is present");
    return false;
}

bool flysync_island_boot_gate(const char *datadir, struct main_state *ms,
                              char *why, size_t why_cap)
{
    if (datadir)
        snprintf(g_datadir, sizeof(g_datadir), "%s", datadir);
    sqlite3 *db = progress_store_db();
    enum island_anchor_state st = island_anchor_state_load(db);
    if (st == ISLAND_ANCHOR_STATE_UNREADABLE)
        return fsi_gate_unreadable(db, why, why_cap);
    /* A seeded island continues with or without the flag: a respawn or an app
     * restart may drop -flysync from argv, and the island must still finish. */
    if (st == ISLAND_ANCHOR_STATE_SEEDED && fsi_rung_installed(datadir) &&
        fsi_note_installed())
        st = ISLAND_ANCHOR_STATE_INSTALLED;
    if (st == ISLAND_ANCHOR_STATE_INSTALLED ||
        st == ISLAND_ANCHOR_STATE_SEEDED) {
        fsi_set_phase(st == ISLAND_ANCHOR_STATE_INSTALLED ? FLYSYNC_DONE
                                                          : FLYSYNC_SEEDED);
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
    return fsi_gate_fresh(db, ms, why, why_cap);
}

/* -flysync on a datadir that never seeded: start the wait on an empty one;
 * one that FlySync already held (headers below the rung admitted while it
 * waited) falls back instead of being refused forever; refuse the rest. */
static bool fsi_gate_fresh(sqlite3 *db, struct main_state *ms, char *why,
                           size_t why_cap)
{
    if (fsi_datadir_has_chain_state(ms) && island_anchor_hold_recorded(db)) {
        LOG_WARN(FSI_SUBSYS, "-flysync: FlySync waited on this datadir before "
                 "and it now holds chain state below the rung; continuing "
                 "with normal sync");
        fsi_note_fallback("chain state admitted below the rung while waiting");
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
        LOG_INFO(FSI_SUBSYS, "island reloaded: the compiled rung hash links "
                 "down to the recorded root, h=%d .. %d", (int)a.root_height,
                 (int)a.rung_height);
        return true;
    }
    if (island_anchor_state_load(progress_store_db()) ==
        ISLAND_ANCHOR_STATE_INSTALLED) {
        /* Installed state stands on the bundle, not on these rows: keep the
         * registration the reorg floor and the loader rely on, and say so. */
        LOG_ERROR(FSI_SUBSYS, "installed island: %s; the island stays "
                  "registered (no fall-back once installed)", why);
        return true;
    }
    LOG_WARN(FSI_SUBSYS, "island does not stand after load: %s", why);
    fsi_fall_back_at(ms, why, false);
    return false;
}

/* ── Phase machine ───────────────────────────────────────────────────────── */

/* Set at boot: a mainnet node whose boot skipped the compiled keystone header
 * capture because FlySync owned the state source. Fall-back re-arms it, so
 * normal sync gets exactly what a node without -flysync gets. */
static _Atomic bool g_rearm_keystone_on_fall_back = false;

static struct main_state *fsi_main_state(void)
{
    return sync_monitor_main_state();
}

/* A fall-back in the running node ends in a restart: the boot that follows
 * sees FELL_BACK and runs as a node without -flysync (full-history service
 * bit, keystone capture, weld and header-seed import, a fresh offer wait),
 * detaching any island rows the loader brings back. Off systemd main()
 * re-execs; under systemd the unit restarts it. */
static void fsi_request_respawn(void)
{
    LOG_WARN(FSI_SUBSYS, "FlySync fell back: restarting so normal sync boots "
             "as a node without -flysync");
#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_respawns, 1);
#else
    chain_tip_watchdog_request_respawn();
    thread_registry_request_shutdown();
#endif
}

/* Order: the durable FELL_BACK first, then the in-memory detach, then the
 * phase (which lifts the hold), then the restart. A crash after the first
 * step is finished by the next boot's detach (flysync_island_boot_after_index).
 * The boot-time reconcile calls this before the network starts, so it does
 * not restart: that boot continues as the fallen-back node. */
static void fsi_fall_back_at(struct main_state *ms, const char *why,
                             bool respawn)
{
    enum island_anchor_state st = island_anchor_state_load(progress_store_db());
    if (st == ISLAND_ANCHOR_STATE_INSTALLED) {
        LOG_ERROR(FSI_SUBSYS, "fall-back refused, the rung bundle is "
                  "installed: %s", why);
        fsi_set_phase(FLYSYNC_DONE);
        return;
    }
    if (st == ISLAND_ANCHOR_STATE_UNREADABLE) {
        /* Never decide on an unreadable state: stay held, the next tick (or
         * the next boot) reads it again. */
        LOG_ERROR(FSI_SUBSYS, "fall-back deferred, the island state is "
                  "unreadable (it may be installed): %s", why);
        return;
    }
    struct island_anchor a;
    bool island = island_anchor_get(&a);
    checkpoint_header_fetch_disarm();
    fsi_note_fallback(why);
    if (island && ms)
        (void)flysync_island_detach(ms, &a);
    else if (island)
        LOG_ERROR(FSI_SUBSYS, "fallen-back island not detached in process (no "
                  "main state); the next boot detaches it");
    fsi_set_phase(FLYSYNC_FELL_BACK);
    if (atomic_exchange(&g_rearm_keystone_on_fall_back, false))
        checkpoint_header_fetch_arm_compiled();
    if (respawn)
        fsi_request_respawn();
}

static void fsi_fall_back(const char *why)
{
    fsi_fall_back_at(fsi_main_state(), why, true);
}

/* The chosen offer's download progress: the verified-chunk count last seen and
 * when it last moved (this process's clock). 0 = no chosen offer seen yet. */
static _Atomic uint32_t g_fetch_chunks_seen = 0;
static _Atomic int64_t g_fetch_moved_ms = 0;
static _Atomic int64_t g_fetch_started_ms = 0;   /* first sighting: FETCH start */

/* True when the chosen offer's download has stalled: no new verified chunk
 * for FLYSYNC_FETCH_STALL_MS. The first sighting of a chosen offer starts the
 * clock, so a resumed download counts from this boot. */
static bool fsi_fetch_stalled(const struct state_offer_store_status *st,
                              int64_t now)
{
    if (atomic_load(&g_fetch_moved_ms) == 0)
        atomic_store(&g_fetch_started_ms, now);
    if (atomic_load(&g_fetch_moved_ms) == 0 ||
        st->fetch_chunks_done != atomic_load(&g_fetch_chunks_seen)) {
        atomic_store(&g_fetch_chunks_seen, st->fetch_chunks_done);
        atomic_store(&g_fetch_moved_ms, now);
        return false;
    }
    return now - atomic_load(&g_fetch_moved_ms) >= FLYSYNC_FETCH_STALL_MS;
}

static void fsi_tick_wait_offers(int64_t now)
{
    struct state_offer_store_status st;
    state_offer_store_status_get(&st);
    if (st.last_decision == STATE_OFFER_DECIDE_FALL_BACK)
        fsi_fall_back("no acceptable rung offer inside the state-offer wait");
    else if (st.wait_armed && st.chosen_height == 0 &&
             now - st.wait_started_ms >= STATE_OFFER_WAIT_MS + 30000)
        fsi_fall_back("no rung offer chosen inside the state-offer wait");
    else if (st.chosen_height != 0 && fsi_fetch_stalled(&st, now))
        fsi_fall_back("the chosen rung offer's download stalled: no new "
                      "verified chunk within its bound");
    else if (st.chosen_height != 0 &&
             now - atomic_load(&g_fetch_started_ms) >= FLYSYNC_FETCH_CAP_MS)
        fsi_fall_back("the chosen rung offer was not fetched and staged "
                      "within the running-time cap");
}

static void fsi_tick_wait(int64_t now)
{
    const char *datadir = fsi_datadir();
    char *bundle = datadir ? boot_autodetect_consensus_bundle(datadir) : NULL;
    if (bundle) {
        int32_t h = -1;
        uint8_t hash[32];
        bool ok = boot_staged_bundle_wait_target(bundle, &h, hash);
        free(bundle);
        const struct rom_state_rung *rung = ok ? fsi_rung_at(h) : NULL;
        if (!rung || memcmp(hash, rung->cp.block_hash, 32) != 0) {
            fsi_fall_back("the staged bundle is not at a baked ladder rung "
                          "with the compiled rung hash");
            return;
        }
        struct uint256 top;   /* the walk starts from the compiled hash */
        memcpy(top.data, rung->cp.block_hash, 32);
        checkpoint_header_fetch_arm_window(h, &top, ISLAND_ANCHOR_WINDOW);
        atomic_fetch_add(&g_walk_attempts, 1);
        fsi_set_phase(FLYSYNC_WALK);
        return;
    }
    fsi_tick_wait_offers(now);
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
        int attempts = atomic_load(&g_walk_attempts);
        LOG_WARN(FSI_SUBSYS, "header window refused (attempt %d/%d): %s",
                 attempts, FLYSYNC_WALK_ATTEMPTS, why);
        if (attempts >= FLYSYNC_WALK_ATTEMPTS)
            fsi_fall_back("the header window failed verification");
        else
            fsi_set_phase(FLYSYNC_WAIT);   /* re-arms from the staged bundle */
        return;
    }
    if (now - atomic_load(&g_phase_since_ms) >= FLYSYNC_WALK_TIMEOUT_MS)
        fsi_fall_back("the header window walk timed out (no peer served "
                      "the rung window)");
}

static void fsi_tick_seeded(int64_t now)
{
    const char *datadir = fsi_datadir();
    if (fsi_rung_installed(datadir)) {
        (void)fsi_note_installed();
        fsi_set_phase(FLYSYNC_DONE);
        LOG_WARN(FSI_SUBSYS, "FlySync: rung bundle installed; header sync "
                 "continues from the rung");
        return;
    }
    char *bundle = datadir ? boot_autodetect_consensus_bundle(datadir) : NULL;
    bool staged = bundle != NULL;
    free(bundle);
    if (datadir && boot_install_bundle_terminal(datadir))
        fsi_fall_back("the rung bundle's bounded install budget is spent");
    else if (!staged)
        fsi_fall_back("the rung bundle is no longer installable (failed or "
                      "removed)");
    else if (now - atomic_load(&g_phase_since_ms) >= FLYSYNC_INSTALL_TIMEOUT_MS)
        fsi_fall_back("the rung bundle did not install within its bound");
}

bool flysync_island_wants_offer_height(int32_t height)
{
    int p = atomic_load(&g_phase);
    if (p == FLYSYNC_DONE)
        return false;      /* the rung bundle is installed: no second bundle */
    if (p != FLYSYNC_WAIT && p != FLYSYNC_WALK && p != FLYSYNC_SEEDED)
        return true;
    return fsi_rung_at(height) != NULL;
}

/* Every boot whose durable state is FELL_BACK: the loader relinked the island
 * rows from their durable records; detach them again until normal sync gives
 * the root its parent (then the root has one and nothing is detached). With
 * no fact (a fall-back before seeding) there is nothing to detach. */
static void fsi_boot_detach_fallen_back(struct main_state *ms)
{
    sqlite3 *db = progress_store_db();
    if (!ms || island_anchor_state_load(db) != ISLAND_ANCHOR_STATE_FELL_BACK)
        return;
    struct island_anchor a;
    bool found = false;
    if (!island_anchor_load(db, &a, &found) || !found)
        return;
    /* Derive every entry's work from its stored links first (the loader's
     * per-row work is stale above rows that rejoined in memory only and were
     * not saved relinked); then the detach sets its token on what stays off
     * the chain. Running it after the detach would hand the detached rows
     * their own proof again. */
    zcl_mutex_lock(&ms->cs_main);
    size_t total = block_map_count(&ms->map_block_index);
    struct block_index **sorted =
        total ? zcl_malloc(total * sizeof(*sorted), "flysync_forward_pass")
              : NULL;
    if (sorted)
        (void)block_index_forward_pass_over_map(ms, sorted, total);
    zcl_mutex_unlock(&ms->cs_main);
    free(sorted);
    if (total && !sorted)
        LOG_ERROR(FSI_SUBSYS, "fallen-back island: forward pass not run (out "
                  "of memory for %zu entries); work above the island may be "
                  "stale until the next boot", total);
    struct block_index *rung = block_map_find(&ms->map_block_index,
                                              &a.rung_hash);
    if (rung && rung->nHeight == a.rung_height &&
        !fsi_off_chain(rung, a.root_height)) {
        struct zcl_result r = island_anchor_retire(db);
        if (!r.ok)
            LOG_ERROR(FSI_SUBSYS, "%s", r.message);
        return;
    }
    (void)flysync_island_detach(ms, &a);
}

/* Count this holding boot durably; past FLYSYNC_HOLD_BOOTS, fall back here,
 * before the state source is chosen, so this boot already runs as a node
 * without -flysync (no restart needed). */
static void fsi_boot_count_hold(struct main_state *ms)
{
    uint64_t boots = 0;
    struct zcl_result r = island_anchor_hold_boot(progress_store_db(), &boots);
    if (!r.ok) {
        LOG_ERROR(FSI_SUBSYS, "%s; the per-boot bounds still apply",
                  r.message);
        return;
    }
    if (boots <= FLYSYNC_HOLD_BOOTS)
        return;
    char why[160];
    snprintf(why, sizeof(why), "header sync was held across %llu boots "
             "(bound %d)", (unsigned long long)boots, FLYSYNC_HOLD_BOOTS);
    fsi_fall_back_at(ms, why, false);
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
            {"z23 (the same command again)",
             "an unreadable island state is never decided; a transient read "
             "error clears on the next start"},
        };
        return boot_refuse_at_permanent_gate("flysync_datadir", why, next, 2,
                                             NULL);
    }
    if (island_anchor_registered())
        (void)flysync_island_boot_reconcile(ms);
    fsi_boot_detach_fallen_back(ms);
    if (flysync_island_holds_header_sync())
        fsi_boot_count_hold(ms);
    enum flysync_phase p = flysync_island_phase();
    if (p != FLYSYNC_OFF && p != FLYSYNC_FELL_BACK) {
        msg_processor_set_header_sync_hold(flysync_island_holds_header_sync);
        state_offer_store_set_height_filter(flysync_island_wants_offer_height);
        net_set_advertise_full_history(false);
        atomic_store(&g_rearm_keystone_on_fall_back,
                     ctx && !ctx->regtest && !ctx->testnet &&
                     !boot_consensus_bundle_marker_exists(ctx->datadir));
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
    bool idle = false;
    if (!atomic_compare_exchange_strong(&g_tick_busy, &idle, true))
        return;   /* the other swarm call site is inside the tick */
    int64_t now = fsi_now_ms();
    switch ((enum flysync_phase)atomic_load(&g_phase)) {
    case FLYSYNC_WAIT:   fsi_tick_wait(now);   break;
    case FLYSYNC_WALK:   fsi_tick_walk(now);   break;
    case FLYSYNC_SEEDED: fsi_tick_seeded(now); break;
    default: break;
    }
    atomic_store(&g_tick_busy, false);
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
    g_datadir[0] = '\0';
    atomic_store(&g_walk_attempts, 0);
    atomic_store(&g_phase_since_ms, 0);
    atomic_store(&g_tick_busy, false);
    atomic_store(&g_test_respawns, 0);
    atomic_store(&g_fetch_chunks_seen, 0);
    atomic_store(&g_fetch_moved_ms, 0);
    atomic_store(&g_fetch_started_ms, 0);
    island_anchor_unregister();
}

void flysync_island_test_set_clock_ms(int64_t now_ms)
{
    atomic_store(&g_test_now_ms, now_ms);
}

void flysync_island_test_hold_tick(bool held)
{
    atomic_store(&g_tick_busy, held);
}

int flysync_island_test_respawns(void)
{
    return atomic_load(&g_test_respawns);
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

bool flysync_island_owns_state_source(void)
{
    int p = atomic_load(&g_phase);
    return p != FLYSYNC_OFF && p != FLYSYNC_FELL_BACK;
}
