/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Worker-start proof state: complete a staged publication, restore
 *          the signed issuer log, rebuild the receiver from CAS under the
 *          worker table's trust policy, each bounded by the catalog size. */

#include "build_fabric_proof_context_internal.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "crypto/ed25519.h"
#include "models/build_fabric.h"
#include "platform/time_compat.h"
#include "services/build_fabric_proof_recovery.h"
#include "vcs/package_store.h"
#include "vcs/proof_reuse.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BFPC_LOG "build_fabric"
#define BFPC_PATH_MAX 4096

#ifdef ZCL_TESTING
static _Atomic int g_bfpc_fault;

void build_fabric_proof_test_fault(enum build_fabric_proof_fault fault)
{
    atomic_store(&g_bfpc_fault, (int)fault);
}

enum build_fabric_proof_fault bfpc_test_fault_armed(void)
{
    return (enum build_fabric_proof_fault)atomic_load(&g_bfpc_fault);
}
#endif

static void bfpc_state(_Atomic(const char *) *slot, const char *token,
                       const char *what, const char *worker_id)
{
    atomic_store(slot, token);
    if (strcmp(token, BUILD_FABRIC_PROOF_STATE_READY) != 0)
        LOG_ERROR(BFPC_LOG, "proof %s for worker %s refused: %s", what,
                  worker_id, token);
}

/* One handle per store directory in this process: the node-global handle
 * when it owns <datadir>/zcode, else a private one only this worker uses. */
static struct vcs_package_store *bfpc_store_select(const char *datadir,
                                                   bool *owns)
{
    *owns = false;
    char want[BFPC_PATH_MAX];
    int n = snprintf(want, sizeof(want), "%s/zcode", datadir);
    if (n <= 0 || (size_t)n >= sizeof(want)) return NULL;
    struct vcs_package_store *global = vcs_package_store_global();
    const char *root = vcs_package_store_root_dir(global);
    if (global && root && strcmp(root, want) == 0) return global;
    *owns = true;
    return vcs_package_store_open(datadir, vcs_package_store_quota_bytes());
}

/* Catalog size, first catching a stale handle up with other writers. */
static enum vcs_package_store_page_result bfpc_catalog(
    struct vcs_package_store *store, size_t *rows, uint64_t *generation)
{
    enum vcs_package_store_page_result sized =
        vcs_package_store_catalog_rows(store, rows, generation);
    if (sized == VCS_PACKAGE_STORE_PAGE_STALE &&
        vcs_package_store_refresh(store))
        sized = vcs_package_store_catalog_rows(store, rows, generation);
    return sized;
}

static bool bfpc_catalog_moved(struct vcs_package_store *store,
                               uint64_t generation)
{
    size_t rows = 0;
    uint64_t now = 0;
    enum vcs_package_store_page_result sized =
        bfpc_catalog(store, &rows, &now);
    return sized != VCS_PACKAGE_STORE_PAGE_OK || now != generation;
}

/* ── Trust policy: the worker table ─────────────────────────────────── */

static bool bfpc_worker_live(const struct db_build_worker *w, int64_t now)
{
    return w->approved && !w->revoked &&
           (w->expires_at == 0 || now < w->expires_at);
}

static bool bfpc_trust_add(uint8_t (*set)[32], size_t *count,
                           const char *hex)
{
    if (!zcl_hex_decode_lower(hex, set[*count], 32)) return false;
    (*count)++;
    return true;
}

static bool bfpc_trust_fill(const struct db_build_worker *rows, int count,
                            int64_t now, struct bfpc_trust *out)
{
    for (int i = 0; i < count; i++) {
        bool ok = true;
        if (rows[i].revoked)
            ok = bfpc_trust_add(out->revoked, &out->revoked_count,
                                rows[i].signer_pubkey);
        else if (bfpc_worker_live(&rows[i], now))
            ok = bfpc_trust_add(out->verifiers, &out->verifier_count,
                                rows[i].signer_pubkey);
        if (!ok) return false;
    }
    return true;
}

struct zcl_result bfpc_trust_load(struct node_db *ndb, int64_t now,
                                  struct bfpc_trust *out)
{
    memset(out, 0, sizeof(*out));
    const size_t cap = BUILD_FABRIC_PROOF_HEADS_MAX;
    struct db_build_worker *rows = zcl_calloc(cap + 1u, sizeof(*rows),
                                              "proof trust workers");
    out->verifiers = zcl_calloc(cap, sizeof(*out->verifiers),
                                "proof trust verifiers");
    out->revoked = zcl_calloc(cap, sizeof(*out->revoked),
                              "proof trust revoked");
    if (!rows || !out->verifiers || !out->revoked) {
        free(rows);
        bfpc_trust_free(out);
        return ZCL_ERR(-1, "proof-trust-allocation");
    }
    int count = db_build_workers_list_checked(ndb, rows, cap + 1u);
    bool ok = count >= 0 && (size_t)count <= cap &&
              bfpc_trust_fill(rows, count, now, out);
    free(rows);
    if (ok) return ZCL_OK;
    bfpc_trust_free(out);
    return ZCL_ERR(-1, "proof-trust-worker-table-incomplete count=%d", count);
}

void bfpc_trust_free(struct bfpc_trust *trust)
{
    if (!trust) return;
    free(trust->verifiers);
    free(trust->revoked);
    memset(trust, 0, sizeof(*trust));
}

/* ── Issuer: the writable signed log at the durable head ────────────── */

static const char *bfpc_issuer_attempt(struct build_fabric_proof_context *c,
                                       const uint8_t *head, bool *moved)
{
    *moved = false;
    size_t rows = 0;
    uint64_t generation = 0;
    enum vcs_package_store_page_result sized =
        bfpc_catalog(c->store, &rows, &generation);
    if (sized != VCS_PACKAGE_STORE_PAGE_OK) {
        *moved = sized == VCS_PACKAGE_STORE_PAGE_STALE ||
                 sized == VCS_PACKAGE_STORE_PAGE_INCOMPLETE;
        return BUILD_FABRIC_PROOF_STATE_CATALOG_UNREADABLE;
    }
    if (rows == 0) {
        if (head) return BUILD_FABRIC_PROOF_STATE_HISTORY_MISSING;
        c->issuer = vcs_proof_issuer_log_new(c->seed);
        return c->issuer ? BUILD_FABRIC_PROOF_STATE_READY
                         : BUILD_FABRIC_PROOF_STATE_ALLOCATION;
    }
    c->issuer = vcs_proof_issuer_log_restore_from_store(
        c->seed, c->store, head, rows, rows);
    if (c->issuer) return BUILD_FABRIC_PROOF_STATE_READY;
    *moved = bfpc_catalog_moved(c->store, generation);
    return BUILD_FABRIC_PROOF_STATE_RESTORE_REFUSED;
}

void bfpc_issuer_pause(struct build_fabric_proof_context *ctx,
                       const char *state)
{
    vcs_proof_issuer_log_free(ctx->issuer);
    ctx->issuer = NULL;
    ctx->staged = false;
    memset(&ctx->staged_row, 0, sizeof(ctx->staged_row));
    bfpc_state(&ctx->live.issuer_state, state, "issuer", ctx->worker_id);
}

/* Worker start only: the restore replays the issuer's whole history. */
static void bfpc_issuer_resync(struct build_fabric_proof_context *ctx,
                               struct node_db *ndb)
{
    vcs_proof_issuer_log_free(ctx->issuer);
    ctx->issuer = NULL;
    struct db_build_worker row;
    uint8_t head[32];
    const char *state = BUILD_FABRIC_PROOF_STATE_WORKER_UNREADABLE;
    if (db_build_worker_find_checked(ndb, ctx->worker_id, &row) == 1 &&
        strcmp(row.signer_pubkey, ctx->signer_hex) == 0 &&
        (!row.proof_checkpoint_head_sha3[0] ||
         zcl_hex_decode_lower(row.proof_checkpoint_head_sha3, head, 32))) {
        const uint8_t *anchor = row.proof_checkpoint_head_sha3[0] ? head : NULL;
        bool moved = true;
        for (unsigned a = 0; moved && a < BUILD_FABRIC_PROOF_OPEN_ATTEMPTS;
             a++)
            state = bfpc_issuer_attempt(ctx, anchor, &moved);
        if (moved) state = BUILD_FABRIC_PROOF_STATE_CATALOG_MOVED;
    }
    atomic_store(&ctx->live.issuer_leaves,
                 vcs_proof_issuer_log_count(ctx->issuer));
    bfpc_state(&ctx->live.issuer_state, state, "issuer", ctx->worker_id);
}

/* ── Receiver: rebuilt from CAS, anchored on every durable local head ── */

struct bfpc_anchors {
    struct vcs_proof_receiver_anchor *items;
    size_t count;
};

static bool bfpc_anchors_load(struct node_db *ndb, struct bfpc_anchors *out)
{
    memset(out, 0, sizeof(*out));
    const size_t cap = BUILD_FABRIC_PROOF_HEADS_MAX;
    struct db_build_worker_proof_head *heads =
        zcl_calloc(cap, sizeof(*heads), "proof receiver heads");
    out->items = zcl_calloc(cap, sizeof(*out->items), "proof anchors");
    int count = heads && out->items
        ? db_build_worker_proof_heads_snapshot(ndb, heads, cap) : -1;
    bool ok = count >= 0;
    for (int i = 0; ok && i < count; i++)
        ok = zcl_hex_decode_lower(heads[i].signer_pubkey,
                                  out->items[i].issuer_pubkey, 32) &&
             zcl_hex_decode_lower(heads[i].checkpoint_blob_root,
                                  out->items[i].checkpoint_blob_root, 32);
    free(heads);
    if (ok) out->count = (size_t)count;
    else {
        free(out->items);
        out->items = NULL;
    }
    return ok;
}

struct bfpc_rebuild {
    struct vcs_proof_receiver *receiver;
    size_t rows, tickets, checkpoints, skipped;
};

static const char *bfpc_rebuild_attempt(struct build_fabric_proof_context *c,
                                        const struct bfpc_anchors *anchors,
                                        const struct vcs_proof_reuse_policy *trust,
                                        struct bfpc_rebuild *out, bool *moved)
{
    *moved = false;
    memset(out, 0, sizeof(*out));
    uint64_t generation = 0;
    enum vcs_package_store_page_result sized =
        bfpc_catalog(c->store, &out->rows, &generation);
    if (sized != VCS_PACKAGE_STORE_PAGE_OK) {
        *moved = sized == VCS_PACKAGE_STORE_PAGE_STALE ||
                 sized == VCS_PACKAGE_STORE_PAGE_INCOMPLETE;
        return BUILD_FABRIC_PROOF_STATE_CATALOG_UNREADABLE;
    }
    out->receiver = vcs_proof_receiver_new();
    if (!out->receiver) return BUILD_FABRIC_PROOF_STATE_ALLOCATION;
    if (out->rows == 0 && anchors->count == 0)
        return BUILD_FABRIC_PROOF_STATE_READY;
    uint64_t published = 0;
    if (out->rows && vcs_proof_receiver_rebuild_with_policy(
            out->receiver, c->store, trust, anchors->items, anchors->count,
            out->rows, &out->tickets, &out->checkpoints, &out->skipped,
            &published))
        return BUILD_FABRIC_PROOF_STATE_READY;
    vcs_proof_receiver_free(out->receiver);
    out->receiver = NULL;
    *moved = bfpc_catalog_moved(c->store, generation);
    return out->rows ? BUILD_FABRIC_PROOF_STATE_REBUILD_REFUSED
                     : BUILD_FABRIC_PROOF_STATE_HISTORY_MISSING;
}

static const char *bfpc_receiver_rebuild(struct build_fabric_proof_context *c,
                                         const struct bfpc_anchors *anchors,
                                         const struct bfpc_trust *trust)
{
    struct vcs_proof_reuse_policy policy = {
        .verifiers = (const uint8_t (*)[32])trust->verifiers,
        .verifier_count = trust->verifier_count,
        .revoked = (const uint8_t (*)[32])trust->revoked,
        .revoked_count = trust->revoked_count,
        .quorum = 1,
    };
    struct bfpc_rebuild built = {0};
    const char *state = BUILD_FABRIC_PROOF_STATE_CATALOG_MOVED;
    bool moved = true;
    for (unsigned a = 0; moved && a < BUILD_FABRIC_PROOF_OPEN_ATTEMPTS; a++)
        state = bfpc_rebuild_attempt(c, anchors, &policy, &built, &moved);
    if (moved) state = BUILD_FABRIC_PROOF_STATE_CATALOG_MOVED;
    c->receiver = built.receiver;
    atomic_store(&c->live.receiver_catalog_rows, built.rows);
    atomic_store(&c->live.receiver_tickets, built.tickets);
    atomic_store(&c->live.receiver_checkpoints, built.checkpoints);
    atomic_store(&c->live.receiver_skipped, built.skipped);
    return state;
}

static void bfpc_receiver_open(struct build_fabric_proof_context *c,
                               struct node_db *ndb)
{
    struct bfpc_anchors anchors;
    struct bfpc_trust trust;
    const char *state = BUILD_FABRIC_PROOF_STATE_HEADS_REFUSED;
    if (bfpc_anchors_load(ndb, &anchors)) {
        state = BUILD_FABRIC_PROOF_STATE_POLICY_REFUSED;
        if (bfpc_trust_load(ndb, (int64_t)platform_time_wall_unix(),
                            &trust).ok) {
            state = bfpc_receiver_rebuild(c, &anchors, &trust);
            bfpc_trust_free(&trust);
        }
        free(anchors.items);
    }
    bfpc_state(&c->live.receiver_state, state, "receiver", c->worker_id);
}

/* ── Lifecycle ──────────────────────────────────────────────────────── */

static struct build_fabric_proof_context *bfpc_new(const char *worker_id,
                                                   const uint8_t seed[32])
{
    if (BFPC_FAULT(BUILD_FABRIC_PROOF_FAULT_OPEN_ALLOCATION)) return NULL;
    struct build_fabric_proof_context *c =
        zcl_calloc(1, sizeof(*c), "build proof context");
    if (!c) return NULL;
    (void)snprintf(c->worker_id, sizeof(c->worker_id), "%s", worker_id);
    memcpy(c->seed, seed, sizeof(c->seed));
    uint8_t secret[32];
    ed25519_keypair(c->pubkey, secret, seed);
    memset(secret, 0, sizeof(secret));
    zcl_hex_encode(c->pubkey, sizeof(c->pubkey), c->signer_hex);
    c->quorum = 1;
    atomic_store(&c->live.issuer_state, BUILD_FABRIC_PROOF_STATE_NOT_STARTED);
    atomic_store(&c->live.receiver_state,
                 BUILD_FABRIC_PROOF_STATE_NOT_STARTED);
    atomic_store(&c->live.last_issue_refusal, "none");
    atomic_store(&c->live.last_attach, "none");
    atomic_store(&c->live.last_ticket_outcome, "none");
    atomic_store(&c->live.last_ticket_reason, "none");
    return c;
}

/* No store: a staged row cannot be completed and nothing can be issued or
 * decided. Both states name it; the row, if any, stays staged. */
static void bfpc_open_without_store(struct build_fabric_proof_context *c)
{
    bfpc_state(&c->live.issuer_state,
               BUILD_FABRIC_PROOF_STATE_STORE_UNAVAILABLE, "issuer",
               c->worker_id);
    bfpc_state(&c->live.receiver_state,
               BUILD_FABRIC_PROOF_STATE_STORE_UNAVAILABLE, "receiver",
               c->worker_id);
}

/* A staged row recovery cannot complete stays staged for the next worker
 * start, and this issuer stays closed: restoring at the old head and
 * appending would sign a second ticket at the staged sequence. The
 * receiver still opens under its own rules, which refuse an incomplete
 * head set while any row is staged. */
static void bfpc_open_with_store(struct build_fabric_proof_context *c,
                                 struct node_db *ndb)
{
    struct zcl_result recovered =
        BFPC_FAULT(BUILD_FABRIC_PROOF_FAULT_OPEN_RECOVERY)
            ? ZCL_ERR(-1, "proof-pending-recover-fault-injected")
            : build_fabric_proof_pending_recover(ndb, c->store, c->worker_id,
                                                 c->seed);
    if (recovered.ok)
        bfpc_issuer_resync(c, ndb);
    else {
        LOG_ERROR(BFPC_LOG, "proof pending recovery for worker %s: %s",
                  c->worker_id, recovered.message);
        bfpc_state(&c->live.issuer_state,
                   BUILD_FABRIC_PROOF_STATE_PENDING_REFUSED, "issuer",
                   c->worker_id);
    }
    bfpc_receiver_open(c, ndb);
}

struct zcl_result build_fabric_proof_context_open(
    struct node_db *ndb, const char *datadir, const char *worker_id,
    const uint8_t seed[32], struct build_fabric_proof_context **out)
{
    if (out) *out = NULL;
    if (!ndb || !datadir || !worker_id || !seed || !out ||
        strlen(worker_id) != BUILD_FABRIC_ID_HEX)
        return ZCL_ERR(-1, "build proof context requires db, datadir, "
                           "worker and seed");
    struct build_fabric_proof_context *c = bfpc_new(worker_id, seed);
    if (!c) return ZCL_ERR(-1, "build proof context allocation failed");
    c->store = bfpc_store_select(datadir, &c->owns_store);
    if (c->store)
        bfpc_open_with_store(c, ndb);
    else
        bfpc_open_without_store(c);
    *out = c;
    return ZCL_OK;
}

void build_fabric_proof_context_close(struct build_fabric_proof_context *ctx)
{
    if (!ctx) return;
    vcs_proof_issuer_log_free(ctx->issuer);
    vcs_proof_receiver_free(ctx->receiver);
    if (ctx->owns_store) vcs_package_store_close(ctx->store);
    memset(ctx->seed, 0, sizeof(ctx->seed));
    free(ctx);
}

struct zcl_result build_fabric_proof_context_set_quorum(
    struct build_fabric_proof_context *ctx, uint32_t quorum)
{
    if (!ctx || quorum == 0)
        return ZCL_ERR(-1, "proof shadow quorum must be >= 1");
    ctx->quorum = quorum;
    return ZCL_OK;
}

const struct vcs_proof_receiver *build_fabric_proof_context_receiver(
    const struct build_fabric_proof_context *ctx)
{
    return ctx ? ctx->receiver : NULL;
}

static uint64_t bfpc_load(const _Atomic uint64_t *slot)
{
    return atomic_load((_Atomic uint64_t *)slot);
}

static const char *bfpc_token(_Atomic(const char *) const *slot)
{
    return atomic_load((_Atomic(const char *) *)slot);
}

void build_fabric_proof_context_stats(
    const struct build_fabric_proof_context *ctx,
    struct build_fabric_proof_stats *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->issuer_state = out->receiver_state =
        BUILD_FABRIC_PROOF_STATE_NOT_STARTED;
    out->last_issue_refusal = out->last_attach = "none";
    out->last_ticket_outcome = out->last_ticket_reason = "none";
    if (!ctx) return;
    const struct bfpc_live *l = &ctx->live;
    out->issuer_state = bfpc_token(&l->issuer_state);
    out->receiver_state = bfpc_token(&l->receiver_state);
    out->last_issue_refusal = bfpc_token(&l->last_issue_refusal);
    out->last_attach = bfpc_token(&l->last_attach);
    out->last_ticket_outcome = bfpc_token(&l->last_ticket_outcome);
    out->last_ticket_reason = bfpc_token(&l->last_ticket_reason);
    out->issuer_leaves = bfpc_load(&l->issuer_leaves);
    out->receiver_tickets = bfpc_load(&l->receiver_tickets);
    out->receiver_checkpoints = bfpc_load(&l->receiver_checkpoints);
    out->receiver_skipped = bfpc_load(&l->receiver_skipped);
    out->receiver_catalog_rows = bfpc_load(&l->receiver_catalog_rows);
    out->issued = bfpc_load(&l->issued);
    out->issue_refused = bfpc_load(&l->issue_refused);
    out->shadow_decisions = bfpc_load(&l->shadow_decisions);
    out->shadow_unavailable = bfpc_load(&l->shadow_unavailable);
    out->ticket_hit = bfpc_load(&l->ticket_hit);
    out->ticket_hit_fail = bfpc_load(&l->ticket_hit_fail);
    out->ticket_miss = bfpc_load(&l->ticket_miss);
    out->ticket_refuse = bfpc_load(&l->ticket_refuse);
    out->attach_hit = bfpc_load(&l->attach_hit);
    out->attach_miss = bfpc_load(&l->attach_miss);
    out->attach_refused = bfpc_load(&l->attach_refused);
    out->agree = bfpc_load(&l->agree);
    out->disagree = bfpc_load(&l->disagree);
    out->disagree_attach_only = bfpc_load(&l->disagree_attach_only);
    out->disagree_ticket_only = bfpc_load(&l->disagree_ticket_only);
}
