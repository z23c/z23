/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Restart-anywhere proof publication for the build_fabric group.
 *          A real child process dies between the writes of one staged
 *          publication; a fresh open of the same database and store must
 *          publish nothing partial, keep old eligible observations HIT and
 *          conflicts REFUSE, then finish the exact staged head. Worker-start
 *          recovery sizes its budget from the catalog itself, re-derives it
 *          when the catalog moves, and returns a typed retryable error when
 *          the catalog never holds still. */

#include "test/test_core.h"
#include "test/proof_ticket_fixture.h"

#include "base/hex.h"
#include "models/build_fabric.h"
#include "models/database.h"
#include "services/build_fabric_proof_recovery.h"
#include "vcs/blob_store.h"
#include "vcs/package_store.h"
#include "vcs/proof_ticket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif

#define BFH_QUOTA (UINT64_C(1024) * 1024 * 1024)
#define BFH_CAP 16u
#define BFH_CRASHED 42
#define BFH_REBUILD_ROWS 200000u

static const char bfh_worker_id[] =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

/* A worker whose signer is fixture issuer A. A's first observation of
 * k_old is published and durable; its second (k_new) is the staged
 * publication a crash interrupts. B and C are independent verifiers whose
 * signed logs are already in CAS: B+C disagree on k_conflict. */
struct bfh {
    struct ptf f;
    char dir[256];
    char path[320];
    struct node_db ndb;
    struct vcs_package_store *store;
    struct vcs_component_proof_key_v1 k_old, k_new, k_conflict;
    char first_head[65];
    char second_head[65];
    struct db_build_worker_proof_pending pending;
};

static void bfh_key(const struct ptf *f, const char *unit,
                    struct vcs_component_proof_key_v1 *k)
{
    *k = f->base;
    ptf_root(VCS_CPK_UNIT_ID, unit, k->roots[VCS_CPK_UNIT_ID]);
}

static bool bfh_put(struct vcs_package_store *store, const uint8_t *wire,
                    size_t len, char hex_out[65])
{
    uint8_t root[32];
    if (!vcs_proof_ticket_store_put(store, wire, len, root)) return false;
    if (hex_out) zcl_hex_encode(root, sizeof(root), hex_out);
    return true;
}

static bool bfh_open(struct bfh *h)
{
    memset(&h->ndb, 0, sizeof(h->ndb));
    if (!node_db_open(&h->ndb, h->path)) return false;
    h->store = vcs_package_store_open(h->dir, BFH_QUOTA);
    return h->store != NULL;
}

static void bfh_close(struct bfh *h)
{
    if (h->store) vcs_package_store_close(h->store);
    h->store = NULL;
    node_db_close(&h->ndb);
}

static void bfh_free(struct bfh *h)
{
    bfh_close(h);
    ptf_free(&h->f);
    test_rm_rf(h->dir);
}

static bool bfh_save_worker(struct bfh *h)
{
    struct db_build_worker worker;
    memset(&worker, 0, sizeof(worker));
    (void)snprintf(worker.worker_id, sizeof(worker.worker_id), "%s",
                   bfh_worker_id);
    zcl_hex_encode(h->f.pub[PTF_A], 32, worker.signer_pubkey);
    (void)snprintf(worker.capabilities, sizeof(worker.capabilities),
                   "linux,x86-64-v3,gcc");
    worker.approved = 1;
    worker.approved_at = 102;
    worker.last_seen_at = 102;
    return db_build_worker_save(&h->ndb, &worker);
}

static void bfh_pending(struct bfh *h, const char *expected_head,
                        const uint8_t *ticket, const uint8_t *checkpoint,
                        struct db_build_worker_proof_pending *out)
{
    memset(out, 0, sizeof(*out));
    (void)snprintf(out->worker_id, sizeof(out->worker_id), "%s",
                   bfh_worker_id);
    zcl_hex_encode(h->f.pub[PTF_A], 32, out->signer_pubkey);
    (void)snprintf(out->expected_head, sizeof(out->expected_head), "%s",
                   expected_head);
    memcpy(out->ticket_wire, ticket, sizeof(out->ticket_wire));
    memcpy(out->checkpoint_wire, checkpoint, sizeof(out->checkpoint_wire));
}

/* The published first head: A's k_old PASS, staged then recovered through
 * the same publication path the worker uses. */
static bool bfh_first_head(struct bfh *h)
{
    uint8_t ticket[VCS_PROOF_TICKET_WIRE_BYTES];
    uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
    struct db_build_worker_proof_pending first;
    if (!ptf_emit(&h->f, PTF_A, &h->k_old, ptf_pass(), ticket, NULL) ||
        !vcs_proof_issuer_log_checkpoint(h->f.logs[PTF_A], 31, cp))
        return false;
    bfh_pending(h, "", ticket, cp, &first);
    uint8_t root[32];
    if (!vcs_blob_root(cp, sizeof(cp), root)) return false;
    zcl_hex_encode(root, sizeof(root), h->first_head);
    return db_build_worker_proof_pending_stage(&h->ndb, &first) &&
           build_fabric_proof_pending_publish(
               &h->ndb, h->store, bfh_worker_id, h->f.seed[PTF_A], 64, 8).ok;
}

/* B signs PASS for all three keys; C signs FAIL for k_conflict. */
static bool bfh_verifiers(struct bfh *h)
{
    uint8_t wire[VCS_PROOF_TICKET_WIRE_BYTES];
    uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
    const struct vcs_component_proof_key_v1 *keys[] = {
        &h->k_old, &h->k_new, &h->k_conflict};
    for (size_t i = 0; i < 3; i++)
        if (!ptf_emit(&h->f, PTF_B, keys[i], ptf_pass(), wire, NULL) ||
            !bfh_put(h->store, wire, sizeof(wire), NULL))
            return false;
    if (!vcs_proof_issuer_log_checkpoint(h->f.logs[PTF_B], 33, cp) ||
        !bfh_put(h->store, cp, sizeof(cp), NULL))
        return false;
    return ptf_emit(&h->f, PTF_C, &h->k_conflict, ptf_fail(), wire, NULL) &&
           bfh_put(h->store, wire, sizeof(wire), NULL) &&
           vcs_proof_issuer_log_checkpoint(h->f.logs[PTF_C], 34, cp) &&
           bfh_put(h->store, cp, sizeof(cp), NULL);
}

/* The second, not yet staged publication: A's k_new PASS. */
static bool bfh_second(struct bfh *h)
{
    uint8_t ticket[VCS_PROOF_TICKET_WIRE_BYTES];
    uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
    uint8_t root[32];
    if (!ptf_emit(&h->f, PTF_A, &h->k_new, ptf_pass(), ticket, NULL) ||
        !vcs_proof_issuer_log_checkpoint(h->f.logs[PTF_A], 35, cp) ||
        !vcs_blob_root(cp, sizeof(cp), root))
        return false;
    zcl_hex_encode(root, sizeof(root), h->second_head);
    bfh_pending(h, h->first_head, ticket, cp, &h->pending);
    return true;
}

static bool bfh_init(struct bfh *h, const char *tag)
{
    memset(h, 0, sizeof(*h));
    if (!ptf_init(&h->f)) return false;
    bfh_key(&h->f, "unit/old", &h->k_old);
    bfh_key(&h->f, "unit/new", &h->k_new);
    bfh_key(&h->f, "unit/conflict", &h->k_conflict);
    test_make_tmpdir(h->dir, sizeof(h->dir), "build_fabric", tag);
    (void)snprintf(h->path, sizeof(h->path), "%s/node.db", h->dir);
    return bfh_open(h) && bfh_save_worker(h) && bfh_first_head(h) &&
           bfh_verifiers(h) && bfh_second(h);
}

static bool bfh_decide(struct bfh *h, const struct vcs_proof_receiver *rx,
                       const struct vcs_component_proof_key_v1 *key,
                       struct vcs_proof_reuse_decision *d)
{
    struct vcs_proof_ticket_class cls[BFH_CAP];
    struct vcs_proof_reuse_request req = {
        .local = key, .action_class = VCS_PROOF_ACTION_CHECK,
        .domain = &h->f.domain, .policy = &h->f.policy,
        .artifacts = &h->f.source,
    };
    return vcs_proof_reuse_decide(rx, &req, cls, BFH_CAP, d);
}

static bool bfh_head_is(struct bfh *h, const char *head)
{
    struct db_build_worker worker;
    return db_build_worker_find_checked(&h->ndb, bfh_worker_id, &worker) == 1 &&
           strcmp(worker.proof_checkpoint_head_sha3, head) == 0;
}

static int bfh_pending_count(struct bfh *h)
{
    struct db_build_worker_proof_pending pending;
    return db_build_worker_proof_pending_find_checked(&h->ndb, bfh_worker_id,
                                                      &pending);
}

/* Rebuild a fresh receiver fenced by the worker's durable DB head. */
static struct vcs_proof_receiver *bfh_anchored(struct bfh *h, const char *head)
{
    struct vcs_proof_receiver_anchor anchor;
    memcpy(anchor.issuer_pubkey, h->f.pub[PTF_A], 32);
    struct vcs_proof_receiver *rx = vcs_proof_receiver_new();
    if (!rx) return NULL;
    size_t tickets = 0, cps = 0, skipped = 0;
    uint64_t generation = 0;
    if (!zcl_hex_decode_lower(head, anchor.checkpoint_blob_root, 32) ||
        !vcs_proof_receiver_rebuild_anchored_bounded(
            rx, h->store, &anchor, 1, BFH_REBUILD_ROWS, &tickets, &cps,
            &skipped, &generation)) {
        vcs_proof_receiver_free(rx);
        return NULL;
    }
    return rx;
}

static struct vcs_proof_receiver *bfh_rebuilt(struct bfh *h)
{
    struct vcs_proof_receiver *rx = vcs_proof_receiver_new();
    size_t tickets = 0, cps = 0, skipped = 0;
    if (rx && vcs_proof_receiver_rebuild_bounded(
                  rx, h->store, BFH_REBUILD_ROWS, &tickets, &cps, &skipped))
        return rx;
    vcs_proof_receiver_free(rx);
    return NULL;
}

/* After any restart: old evidence HIT, conflict REFUSE, never collapsed. */
static int bfh_expect_history(struct bfh *h, const struct vcs_proof_receiver *rx,
                              enum vcs_proof_reuse_outcome k_new_outcome)
{
    int failures = 0;
    TEST_CASE("build_fabric: restarted receiver keeps HIT/MISS/REFUSE distinct") {
        struct vcs_proof_reuse_decision d;
        ASSERT(bfh_decide(h, rx, &h->k_old, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_HIT_PASS);
        ASSERT_EQ(d.distinct_pass_signers, (uint32_t)2);
        ASSERT(bfh_decide(h, rx, &h->k_conflict, &d));
        ASSERT_EQ(d.outcome, VCS_PROOF_REUSE_REFUSE);
        ASSERT_STR_EQ(d.reason, VCS_PROOF_OBSERVATION_CONFLICT);
        ASSERT(bfh_decide(h, rx, &h->k_new, &d));
        ASSERT_EQ(d.outcome, k_new_outcome);
        if (k_new_outcome == VCS_PROOF_REUSE_MISS) {
            ASSERT_STR_EQ(d.reason, VCS_PROOF_REUSE_WHY_QUORUM);
            ASSERT_EQ(d.eligible_pass, (uint32_t)1);
        }
    } TEST_END
    return failures;
}

#if !defined(_WIN32)
enum bfh_crash_point {
    BFH_AFTER_STAGE = 0,
    BFH_AFTER_TICKET,
    BFH_BEFORE_FINALIZE,
    BFH_CRASH_POINTS,
};

static const char *const bfh_crash_names[BFH_CRASH_POINTS] = {
    "after the DB stage", "between ticket and checkpoint CAS writes",
    "after pinning, before the DB head commit",
};

static void bfh_die(void *context)
{
    (void)context;
    _exit(BFH_CRASHED);
}

/* The worker's publication, in a separate process that dies at `point`
 * without closing anything: the next open is a real crash recovery. */
[[noreturn]] static void bfh_child(const struct bfh *h,
                                   enum bfh_crash_point point)
{
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, h->path)) _exit(2);
    struct vcs_package_store *store = vcs_package_store_open(h->dir, BFH_QUOTA);
    if (!store) _exit(3);
    if (!db_build_worker_proof_pending_stage(&ndb, &h->pending)) _exit(4);
    if (point == BFH_AFTER_STAGE) _exit(BFH_CRASHED);
    if (!bfh_put(store, h->pending.ticket_wire,
                 sizeof(h->pending.ticket_wire), NULL))
        _exit(5);
    if (point == BFH_AFTER_TICKET) _exit(BFH_CRASHED);
    if (!bfh_put(store, h->pending.checkpoint_wire,
                 sizeof(h->pending.checkpoint_wire), NULL))
        _exit(6);
    build_fabric_proof_test_before_finalize(bfh_die, NULL);
    struct zcl_result published = build_fabric_proof_pending_publish(
        &ndb, store, bfh_worker_id, h->f.seed[PTF_A], BFH_REBUILD_ROWS, 8);
    _exit(published.ok ? 7 : 8);
}

static bool bfh_crash(struct bfh *h, enum bfh_crash_point point)
{
    bfh_close(h);
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) bfh_child(h, point);
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) return false;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != BFH_CRASHED) {
        printf("(child for %s ended with status %d) ",
               bfh_crash_names[point], status);
        return false;
    }
    return bfh_open(h);
}

static int bfh_case_crash(enum bfh_crash_point point)
{
    int failures = 0;
    struct bfh h;
    printf("build_fabric: crash %s... ", bfh_crash_names[point]);
    {
        ASSERT(bfh_init(&h, "proof_crash"));
        ASSERT(bfh_crash(&h, point));
        /* Nothing partial: the durable head is the first one, and the exact
         * staged intent survived the crash. */
        ASSERT(bfh_head_is(&h, h.first_head));
        ASSERT_EQ(bfh_pending_count(&h), 1);
        struct vcs_proof_receiver *fenced = bfh_anchored(&h, h.first_head);
        struct vcs_proof_receiver *open = bfh_rebuilt(&h);
        ASSERT(open != NULL);
        if (point == BFH_BEFORE_FINALIZE) {
            /* The CAS is ahead of the DB head: a head-fenced rebuild must
             * refuse rather than publish a view the head does not name. */
            ASSERT(fenced == NULL);
        } else {
            ASSERT(fenced != NULL);
            failures += bfh_expect_history(&h, fenced, VCS_PROOF_REUSE_MISS);
        }
        failures += bfh_expect_history(
            &h, open, point == BFH_BEFORE_FINALIZE ? VCS_PROOF_REUSE_HIT_PASS
                                                   : VCS_PROOF_REUSE_MISS);
        vcs_proof_receiver_free(fenced);
        vcs_proof_receiver_free(open);
        /* Worker-start recovery finishes exactly the staged head. */
        ASSERT(build_fabric_proof_pending_recover(
            &h.ndb, h.store, bfh_worker_id, h.f.seed[PTF_A]).ok);
        ASSERT(bfh_head_is(&h, h.second_head));
        ASSERT_EQ(bfh_pending_count(&h), 0);
        /* A second restart after recovery sees the same truth. */
        bfh_close(&h);
        ASSERT(bfh_open(&h));
        fenced = bfh_anchored(&h, h.second_head);
        ASSERT(fenced != NULL);
        failures += bfh_expect_history(&h, fenced, VCS_PROOF_REUSE_HIT_PASS);
        vcs_proof_receiver_free(fenced);
        ASSERT(bfh_anchored(&h, h.first_head) == NULL);
        bfh_free(&h);
        printf("OK\n");
    }
    if (0) {
_test_next:
        bfh_free(&h);
    }
    return failures;
}
#endif

/* ── Worker-start recovery over a moving or oversized catalog ─────────── */

/* Fixture rows: the production deferred-sync mode skips each put's own
 * fsync barrier (content addressing and temp+rename are unchanged). The
 * rows are filler the assertions only count, and no case crashes the
 * machine over them, so the per-row barrier proves nothing. */
static bool bfh_fill(struct vcs_package_store *store, uint32_t first,
                     uint32_t count)
{
    bool deferred = vcs_package_store_deferred_sync_enabled();
    vcs_package_store_set_deferred_sync(true);
    bool ok = true;
    for (uint32_t i = first; ok && i < first + count; i++) {
        uint8_t blob[8] = {'f', 'i', 'l', 'l', (uint8_t)i, (uint8_t)(i >> 8),
                           (uint8_t)(i >> 16), (uint8_t)(i >> 24)};
        uint8_t root[32];
        ok = vcs_proof_ticket_store_put(store, blob, sizeof(blob), root);
    }
    vcs_package_store_set_deferred_sync(deferred);
    return ok;
}

/* Stage the second publication with only its ticket transferred, as a crash
 * between CAS writes leaves it. Recovery must add the checkpoint itself. */
static bool bfh_stage_ticket_only(struct bfh *h)
{
    return db_build_worker_proof_pending_stage(&h->ndb, &h->pending) &&
           bfh_put(h->store, h->pending.ticket_wire,
                   sizeof(h->pending.ticket_wire), NULL);
}

struct bfh_mover {
    const char *dir;
    uint32_t next;
    unsigned fired;
    bool rearm;
    bool wrote;
};

/* A second store handle adds one unrelated package at the final commit
 * boundary, so the recovering handle's catalog generation goes stale. */
static void bfh_move_catalog(void *context)
{
    struct bfh_mover *m = context;
    m->fired++;
    struct vcs_package_store *writer = vcs_package_store_open(m->dir, BFH_QUOTA);
    m->wrote = writer && bfh_fill(writer, m->next++, 1);
    if (writer) vcs_package_store_close(writer);
    if (m->rearm) build_fabric_proof_test_before_finalize(bfh_move_catalog, m);
}

static int bfh_case_recover_moved_catalog(void)
{
    int failures = 0;
    struct bfh h;
    printf("build_fabric: recovery re-derives its budget after the catalog moves... ");
    {
        ASSERT(bfh_init(&h, "proof_recover_moved"));
        ASSERT(bfh_fill(h.store, 0, VCS_PACKAGE_STORE_PAGE_MAX + 4u));
        ASSERT(bfh_stage_ticket_only(&h));
        /* A fixed budget is any budget short of the catalog: replay itself
         * transfers the staged checkpoint, so the catalog as sized before
         * the call is one row short and the head can never publish. */
        size_t rows = 0;
        uint64_t generation = 0;
        ASSERT_EQ(vcs_package_store_catalog_rows(h.store, &rows, &generation),
                  VCS_PACKAGE_STORE_PAGE_OK);
        ASSERT(rows > VCS_PACKAGE_STORE_PAGE_MAX);
        ASSERT(!build_fabric_proof_pending_publish(
            &h.ndb, h.store, bfh_worker_id, h.f.seed[PTF_A], rows, 8).ok);
        ASSERT(bfh_head_is(&h, h.first_head));
        ASSERT_EQ(bfh_pending_count(&h), 1);
        struct bfh_mover mover = {.dir = h.dir, .next = 1000000u};
        build_fabric_proof_test_before_finalize(bfh_move_catalog, &mover);
        struct zcl_result recovered = build_fabric_proof_pending_recover(
            &h.ndb, h.store, bfh_worker_id, h.f.seed[PTF_A]);
        build_fabric_proof_test_before_finalize(NULL, NULL);
        ASSERT_EQ(mover.fired, 1u);
        ASSERT(mover.wrote);
        ASSERT(recovered.ok);
        ASSERT(bfh_head_is(&h, h.second_head));
        ASSERT_EQ(bfh_pending_count(&h), 0);
        struct vcs_proof_receiver *rx = bfh_anchored(&h, h.second_head);
        ASSERT(rx != NULL);
        failures += bfh_expect_history(&h, rx, VCS_PROOF_REUSE_HIT_PASS);
        vcs_proof_receiver_free(rx);
        bfh_free(&h);
        printf("OK\n");
    }
    if (0) {
_test_next:
        build_fabric_proof_test_before_finalize(NULL, NULL);
        bfh_free(&h);
    }
    return failures;
}

static int bfh_case_recover_restless_catalog(void)
{
    int failures = 0;
    struct bfh h;
    printf("build_fabric: a catalog that never holds still is a typed retry... ");
    {
        ASSERT(bfh_init(&h, "proof_recover_restless"));
        ASSERT(bfh_stage_ticket_only(&h));
        struct bfh_mover mover = {.dir = h.dir, .next = 2000000u,
                                  .rearm = true};
        build_fabric_proof_test_before_finalize(bfh_move_catalog, &mover);
        struct zcl_result recovered = build_fabric_proof_pending_recover(
            &h.ndb, h.store, bfh_worker_id, h.f.seed[PTF_A]);
        build_fabric_proof_test_before_finalize(NULL, NULL);
        ASSERT(!recovered.ok);
        ASSERT_EQ(recovered.code, BUILD_FABRIC_PROOF_ERR_CATALOG_CHANGED);
        ASSERT(mover.fired > 1u);
        ASSERT(mover.wrote);
        /* Refused, not forgotten: old head, exact pending intent, and the
         * old history still decides. */
        ASSERT(bfh_head_is(&h, h.first_head));
        ASSERT_EQ(bfh_pending_count(&h), 1);
        struct vcs_proof_receiver *rx = bfh_anchored(&h, h.first_head);
        ASSERT(rx == NULL); /* CAS already holds the staged checkpoint */
        rx = bfh_rebuilt(&h);
        ASSERT(rx != NULL);
        failures += bfh_expect_history(&h, rx, VCS_PROOF_REUSE_HIT_PASS);
        vcs_proof_receiver_free(rx);
        /* Once the catalog settles the same call publishes. */
        ASSERT(build_fabric_proof_pending_recover(
            &h.ndb, h.store, bfh_worker_id, h.f.seed[PTF_A]).ok);
        ASSERT(bfh_head_is(&h, h.second_head));
        ASSERT_EQ(bfh_pending_count(&h), 0);
        bfh_free(&h);
        printf("OK\n");
    }
    if (0) {
_test_next:
        build_fabric_proof_test_before_finalize(NULL, NULL);
        bfh_free(&h);
    }
    return failures;
}

void vcs_proof_receiver_test_before_recheck(void (*hook)(void *),
                                            void *context);

struct bfh_pinner {
    const char *dir;
    uint8_t root[32];
    bool pinned;
    unsigned fired;
    bool rearm;
    bool wrote;
};

/* A second handle flips one package's pin while recovery replays history:
 * the catalog generation moves, its row count does not. */
static void bfh_flip_pin(void *context)
{
    struct bfh_pinner *p = context;
    p->fired++;
    if (!p->rearm) vcs_proof_receiver_test_before_recheck(NULL, NULL);
    struct vcs_package_store *writer = vcs_package_store_open(p->dir, BFH_QUOTA);
    p->pinned = !p->pinned;
    p->wrote = writer &&
               vcs_package_store_pin(writer, p->root, p->pinned) ==
                   VCS_PACKAGE_STORE_OK;
    if (writer) vcs_package_store_close(writer);
}

static int bfh_case_recover_pinned_catalog(void)
{
    int failures = 0;
    struct bfh h;
    printf("build_fabric: a pin that moves the catalog mid-replay is a typed retry... ");
    {
        ASSERT(bfh_init(&h, "proof_recover_pinned"));
        uint8_t blob[8] = {'p', 'i', 'n', 'n', 'e', 'd', 0, 1};
        struct bfh_pinner pin = {.dir = h.dir, .rearm = true};
        ASSERT(vcs_proof_ticket_store_put(h.store, blob, sizeof(blob),
                                          pin.root));
        ASSERT(bfh_stage_ticket_only(&h));
        size_t rows = 0, rows_after = 0;
        uint64_t generation = 0, generation_after = 0;
        vcs_proof_receiver_test_before_recheck(bfh_flip_pin, &pin);
        struct zcl_result recovered = build_fabric_proof_pending_recover(
            &h.ndb, h.store, bfh_worker_id, h.f.seed[PTF_A]);
        vcs_proof_receiver_test_before_recheck(NULL, NULL);
        ASSERT(pin.wrote);
        ASSERT(!recovered.ok);
        ASSERT_EQ(recovered.code, BUILD_FABRIC_PROOF_ERR_CATALOG_CHANGED);
        ASSERT(pin.fired > 1u);
        ASSERT(bfh_head_is(&h, h.first_head));
        ASSERT_EQ(bfh_pending_count(&h), 1);
        /* One more pin: the row count holds while the generation moves. */
        ASSERT(vcs_package_store_refresh(h.store));
        ASSERT_EQ(vcs_package_store_catalog_rows(h.store, &rows, &generation),
                  VCS_PACKAGE_STORE_PAGE_OK);
        bfh_flip_pin(&pin);
        ASSERT(pin.wrote);
        ASSERT(vcs_package_store_refresh(h.store));
        ASSERT_EQ(vcs_package_store_catalog_rows(h.store, &rows_after,
                                                 &generation_after),
                  VCS_PACKAGE_STORE_PAGE_OK);
        ASSERT_EQ(rows_after, rows);
        ASSERT(generation_after != generation);
        /* A single pin inside the replay: the retry publishes. */
        pin.fired = 0;
        pin.rearm = false;
        vcs_proof_receiver_test_before_recheck(bfh_flip_pin, &pin);
        recovered = build_fabric_proof_pending_recover(
            &h.ndb, h.store, bfh_worker_id, h.f.seed[PTF_A]);
        vcs_proof_receiver_test_before_recheck(NULL, NULL);
        ASSERT_EQ(pin.fired, 1u);
        ASSERT(pin.wrote);
        ASSERT(recovered.ok);
        ASSERT(bfh_head_is(&h, h.second_head));
        ASSERT_EQ(bfh_pending_count(&h), 0);
        bfh_free(&h);
        printf("OK\n");
    }
    if (0) {
_test_next:
        vcs_proof_receiver_test_before_recheck(NULL, NULL);
        bfh_free(&h);
    }
    return failures;
}

/* Another handle changes a pin after the history walk listed the catalog:
 * the store refuses this handle's pin with an I/O refusal, not a stale
 * page. Recovery must still see a moved catalog and retry. */
static int bfh_case_recover_history_pin_refused(void)
{
    int failures = 0;
    struct bfh h;
    printf("build_fabric: a pin refused by a moved catalog is a typed retry... ");
    {
        ASSERT(bfh_init(&h, "proof_recover_pinrefused"));
        uint8_t blob[8] = {'p', 'i', 'n', 'n', 'e', 'd', 0, 2};
        struct bfh_pinner pin = {.dir = h.dir};
        ASSERT(vcs_proof_ticket_store_put(h.store, blob, sizeof(blob),
                                          pin.root));
        ASSERT(bfh_stage_ticket_only(&h));
        build_fabric_proof_test_before_history_pin(bfh_flip_pin, &pin);
        struct zcl_result recovered = build_fabric_proof_pending_recover(
            &h.ndb, h.store, bfh_worker_id, h.f.seed[PTF_A]);
        build_fabric_proof_test_before_history_pin(NULL, NULL);
        ASSERT_EQ(pin.fired, 1u);
        ASSERT(pin.wrote);
        ASSERT(recovered.ok);
        ASSERT(bfh_head_is(&h, h.second_head));
        ASSERT_EQ(bfh_pending_count(&h), 0);
        bfh_free(&h);
        printf("OK\n");
    }
    if (0) {
_test_next:
        build_fabric_proof_test_before_history_pin(NULL, NULL);
        bfh_free(&h);
    }
    return failures;
}

int bf_proof_history_cases(void);

int bf_proof_history_cases(void)
{
    int failures = 0;
#if !defined(_WIN32)
    for (int point = 0; point < BFH_CRASH_POINTS; point++)
        failures += bfh_case_crash((enum bfh_crash_point)point);
#endif
    failures += bfh_case_recover_moved_catalog();
    failures += bfh_case_recover_restless_catalog();
    failures += bfh_case_recover_pinned_catalog();
    failures += bfh_case_recover_history_pin_refused();
    return failures;
}
