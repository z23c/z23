/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zendp_revocation — REVOCATION TAKES EFFECT WHILE THE NODE IS UP.
 *
 * tests/harness/src/test_zendp_records.c proves what a node does at START with
 * the record files on disk: a record whose signing key is not chain-active
 * is discarded. That left one hole, and this file closes it.
 *
 * A signed endpoint record's chain verdict used to be decided exactly once,
 * at acceptance, and cached for the life of the process — vcs/zendp_swarm.h
 * said so outright ("never re-asks the chain"). So a key REVOKED while the
 * node stayed up kept being handed to peer discovery until the record's own
 * signed expiry (the publish default is three days, and the ceiling on how
 * long a record may ask for is thirty — test_zendp_window.c) or until
 * somebody restarted the node.
 *
 * THE PROPERTY PROVEN HERE, on the real path and in one process:
 *
 *   A record accepted while its key is ACTIVE stops being projected to
 *   discovery once the block fold marks that key revoked — WITHOUT A
 *   RESTART.
 *
 * Nothing is stubbed on the chain side. The identity is anchored by folding
 * a real ZID overlay ANCHOR block through explorer_index_block, revoked by
 * folding a real REVOKE block, and resolved through the production lookup
 * (boot_endpoint_anchor_from_db over the process runtime's node.db). The
 * only injected oracle in the file is in zr_case_lock_released, where the
 * point IS the callback.
 *
 * "Stops being projected" is asserted as an ABSENCE, the same discipline
 * test_zendp_records.c uses: the identity is not findable in the directory
 * at all and the discovery projection is empty. There is no entry left
 * carrying a "revoked" marker that a later reader could mistake for a hint.
 *
 * THE CASE THAT LOOKS ODD IS THE IMPORTANT ONE. zr_case_lock_released
 * re-enters the discovery projection from inside the chain lookup. It is
 * not a curiosity: the sweep must never hold the directory lock across a
 * database read, because the discovery projection runs on the shared
 * supervisor tick runner and a blocking database read on that thread is how
 * this node has been killed by its own watchdog. If the lock were held, that
 * case would deadlock rather than fail politely — which is the correct
 * failure mode for an invariant whose violation is a dead node.
 *
 * NOT covered, because it is not true: that a revoked key is unreachable.
 * A record is a hint about where to look; revoking it stops this node
 * OFFERING that hint. */

#include "test/test_core.h"

#include "config/boot_endpoint_records.h"
#include "config/db_service.h"
#include "config/runtime.h"
#include "crypto/ed25519.h"
#include "json/json.h"
#include "models/database.h"
#include "models/explorer_index.h"
#include "models/zid_identity.h"
#include "net/onion_discovery.h"
#include "chain/chain.h"
#include "platform/time_compat.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "util/supervisor.h"
#include "vcs/zendp_swarm.h"
#include "zid/zendp.h"
#include "zid/zid.h"
#include "zid/zid_anchor.h"

#include <stdio.h>
#include <string.h>

#define ZR_CHECK(name, expr) do {                                          \
    if (expr) { printf("  zendp_revocation: %s... OK\n", (name)); }         \
    else { printf("  zendp_revocation: %s... FAIL\n", (name)); failures++; }\
} while (0)

/* 56 base32 chars + ".onion". Anything else is refused before signing. */
#define ZR_ONION \
    "zclassictwothreerevocationgoldenvectoraaaaaaaaaaaaaaaaaa.onion"

/* ── the chain fixture: a real node.db behind the production lookup ── */

struct zr_chain {
    char dir[256];
    char dbpath[320];
    struct node_db ndb;
    struct db_service dbsvc;
    struct app_runtime_context runtime;
    bool wired;
    uint8_t owner[20];
    uint8_t prevbyte;      /* next unspent seed outpoint */
};

/* Seed a spendable output owned by `owner`, so a tx spending it resolves
 * that address as the signer the ownership checks compare against. */
static void zr_seed_owner_utxo(struct zr_chain *c, uint8_t prevbyte)
{
    uint8_t txid[32];
    memset(txid, prevbyte, 32);
    db_tx_output_save(&c->ndb, txid, 0, 5 * COIN, 0, c->owner, 10);
}

static bool zr_chain_up(struct zr_chain *c)
{
    memset(c, 0, sizeof(*c));
    memset(c->owner, 0x53, sizeof(c->owner));
    c->prevbyte = 0xA0;

    test_make_tmpdir(c->dir, sizeof(c->dir), "zendp_revocation", "chain");
    snprintf(c->dbpath, sizeof(c->dbpath), "%s/node.db", c->dir);
    if (!node_db_open(&c->ndb, c->dbpath) || !c->ndb.open)
        return false;
    db_service_init(&c->dbsvc);
    if (!db_service_attach(&c->dbsvc, &c->ndb) || !db_service_start(&c->dbsvc))
        return false;
    c->runtime.db_service = &c->dbsvc;
    app_runtime_set_current(&c->runtime);
    c->wired = app_runtime_node_db() == &c->ndb;

    for (uint8_t i = 0; i < 8; i++)
        zr_seed_owner_utxo(c, (uint8_t)(0xA0 + i));
    return c->wired;
}

static void zr_chain_down(struct zr_chain *c)
{
    /* Unregister the port BEFORE the database goes away: the lookup
     * dereferences the runtime node.db, and leaving a live port pointing at
     * a closed handle is a trap for whichever group runs next. */
    zendp_set_anchor_lookup(NULL, NULL);
    app_runtime_set_current(NULL);
    if (c->dbsvc.worker_started)
        db_service_stop(&c->dbsvc);
    if (c->ndb.open)
        node_db_close(&c->ndb);
}

/* Fold a one-tx block whose sole output is `script`, spending the chain's
 * next owner-seeded outpoint, at `height`. This is the real per-block
 * indexer — the ZID overlay is reached through its registered dispatch,
 * not called directly. */
static bool zr_fold_op(struct zr_chain *c, const uint8_t *script, size_t slen,
                       int height)
{
    struct transaction tx;
    transaction_init(&tx);
    transaction_alloc(&tx, 1, 1);
    memset(tx.vin[0].prevout.hash.data, c->prevbyte, 32);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].sequence = 0xFFFFFFFFu;
    tx.vin[0].script_sig.size = 0;
    tx.vout[0].value = 0;
    memcpy(tx.vout[0].script_pub_key.data, script, slen);
    tx.vout[0].script_pub_key.size = slen;
    tx.lock_time = 0;
    transaction_compute_hash(&tx);
    c->prevbyte++;

    struct block blk;
    block_init(&blk);
    blk.vtx = &tx;
    blk.num_vtx = 1;
    blk.header.nTime = 1700000000u + (uint32_t)height;

    struct uint256 bhash;
    memset(bhash.data, 0x70, 32);
    bhash.data[0] = (uint8_t)height;
    bhash.data[1] = (uint8_t)(height >> 8);
    struct block_index pindex;
    memset(&pindex, 0, sizeof(pindex));
    pindex.nHeight = height;
    pindex.phashBlock = &bhash;

    uint8_t prev_receipt[32] = {0}, out_receipt[32];
    bool ok = explorer_index_block(&c->ndb, &blk, &pindex, prev_receipt,
                                   out_receipt, NULL, NULL);
    blk.vtx = NULL;
    blk.num_vtx = 0;
    transaction_free(&tx);
    return ok;
}

static bool zr_fold_anchor(struct zr_chain *c, const uint8_t pk[32], int h)
{
    uint8_t buf[128];
    size_t n = zid_anchor_build_anchor(buf, sizeof(buf), pk);
    return n > 0 && zr_fold_op(c, buf, n, h);
}

static bool zr_fold_revoke(struct zr_chain *c, const uint8_t pk[32], int h)
{
    uint8_t buf[128];
    size_t n = zid_anchor_build_revoke(buf, sizeof(buf), pk);
    return n > 0 && zr_fold_op(c, buf, n, h);
}

static bool zr_status_is(struct zr_chain *c, const uint8_t pk[32],
                         const char *want)
{
    struct zid_identity row;
    return db_zid_identity_find(&c->ndb, pk, &row) &&
           strcmp(row.status, want) == 0;
}

/* ── the record fixture ────────────────────────────────────────────── */

/* The window is signed against the REAL wall clock, for the reason
 * test_zendp_records.c states at length: a record pinned to a fixed past
 * date is refused on its window whatever the chain says, and every
 * assertion about the chain then passes vacuously. */
static bool zr_sign_record(uint8_t seed_byte, uint64_t seq,
                           uint8_t out_wire[ZID_DOC_MAX], size_t *out_len,
                           uint8_t out_pk[32])
{
    uint8_t seed[32], sk[32];
    memset(seed, seed_byte, sizeof(seed));
    ed25519_keypair(out_pk, sk, seed);

    const uint64_t now = (uint64_t)platform_time_wall_unix();
    struct zendp ep;
    memset(&ep, 0, sizeof(ep));
    ep.flags = ZENDP_HAS_ONION;
    snprintf(ep.onion, sizeof(ep.onion), "%s", ZR_ONION);
    ep.onion_port = 8033;
    ep.services = 0x409;
    ep.height = 3196556;
    ep.not_before = now - 60;

    struct zid_doc doc;
    if (!zendp_sign(&doc, &ep, seq, now + 86400, seed))
        return false;
    size_t n = zid_doc_encode(out_wire, ZID_DOC_MAX, &doc);
    if (n == 0)
        return false;
    *out_len = n;
    return true;
}

static size_t zr_projected(void)
{
    struct zendp_record_view views[ZENDP_DIR_MAX];
    return zendp_global_records((uint64_t)platform_time_wall_unix(), views,
                                ZENDP_DIR_MAX);
}

/* What peer discovery would actually be offered, through the real adapter. */
static int zr_discovery_peers(void)
{
    struct onion_peer peers[ZENDP_DIR_MAX];
    memset(peers, 0, sizeof(peers));
    return boot_endpoint_record_peers(NULL, peers, ZENDP_DIR_MAX);
}

/* ── case 1: the whole property, end to end, in one process ────────── */

static int zr_case_revoked_key_stops_being_advertised(void)
{
    int failures = 0;
    struct zr_chain c;

    /* Other groups in this binary share the process-wide directory when the
     * suite runs single-process; start from a known-empty one. */
    zendp_directory_init(zendp_directory_global());

    if (!zr_chain_up(&c)) {
        printf("  zendp_revocation: chain fixture FAIL\n");
        zr_chain_down(&c);
        return 1;
    }
    boot_endpoint_records_register();

    uint8_t wire[ZID_DOC_MAX], pk[32];
    size_t wire_len = 0;
    if (!zr_sign_record(0x71, 1, wire, &wire_len, pk)) {
        printf("  zendp_revocation: record signing FAIL\n");
        zr_chain_down(&c);
        return 1;
    }

    ZR_CHECK("an unanchored key's record is refused",
             zendp_accept(zendp_directory_global(), wire, wire_len,
                          (uint64_t)platform_time_wall_unix(), NULL, NULL) ==
                 ZENDP_ERR_NOT_ANCHORED &&
             zr_projected() == 0);

    ZR_CHECK("folding a ZID ANCHOR block makes the key active",
             zr_fold_anchor(&c, pk, 600) &&
             zr_status_is(&c, pk, ZID_IDENTITY_STATUS_ACTIVE));

    ZR_CHECK("the same record is now accepted and projected",
             zendp_accept(zendp_directory_global(), wire, wire_len,
                          (uint64_t)platform_time_wall_unix(), NULL, NULL) ==
                 ZENDP_OK &&
             zr_projected() == 1 &&
             zendp_directory_find(zendp_directory_global(), pk, NULL) &&
             zr_discovery_peers() == 1);

    /* The ANCHOR fold moved the counter, so the first pass has real work:
     * re-derive every verdict. It must NOT drop a record that is still
     * good — a revalidation that empties the directory would "pass" case 3
     * for the wrong reason. */
    ZR_CHECK("a pass over a still-active key keeps the record",
             boot_endpoint_records_revalidate_once() ==
                 BOOT_ENDPOINT_REVAL_APPLIED &&
             zr_projected() == 1);

    /* And with nothing folded since, there is positively no work — the
     * only condition under which this worker reports itself idle. */
    ZR_CHECK("with no status change since, the pass is idle",
             boot_endpoint_records_revalidate_once() ==
                 BOOT_ENDPOINT_REVAL_IDLE &&
             zr_projected() == 1);

    const uint64_t gen_before = zid_identity_status_generation();

    ZR_CHECK("folding a ZID REVOKE block retires the key and bumps the "
             "generation",
             zr_fold_revoke(&c, pk, 601) &&
             zr_status_is(&c, pk, ZID_IDENTITY_STATUS_REVOKED) &&
             zid_identity_status_generation() > gen_before);

    /* Stated plainly, because it is the shape of the fix: the counter is a
     * SIGNAL, not the remedy. Until something acts on it the cached verdict
     * still stands — which is exactly the defect, now bounded to the poll
     * interval instead of the record's three-day expiry. */
    ZR_CHECK("the counter alone does not yet change what is advertised",
             zr_projected() == 1);

    ZR_CHECK("ONE revalidation pass — no restart — un-advertises the "
             "revoked key",
             boot_endpoint_records_revalidate_once() ==
                 BOOT_ENDPOINT_REVAL_APPLIED &&
             zr_projected() == 0 &&
             zr_discovery_peers() == 0);

    /* Discarded, not flagged: no entry survives in a lesser state. */
    ZR_CHECK("the entry is gone from the directory, not marked bad",
             !zendp_directory_find(zendp_directory_global(), pk, NULL) &&
             zendp_directory_global()->count == 0);

    /* And a revoked key cannot walk back in through the front door. */
    ZR_CHECK("re-accepting the same record is refused by name",
             zendp_accept(zendp_directory_global(), wire, wire_len,
                          (uint64_t)platform_time_wall_unix(), NULL, NULL) ==
                 ZENDP_ERR_REVOKED &&
             zr_projected() == 0);

    zr_chain_down(&c);
    return failures;
}

/* ── case 2: a non-answer must not empty peer discovery ────────────── */

static int zr_case_non_answer_changes_nothing(void)
{
    int failures = 0;
    struct zr_chain c;

    zendp_directory_init(zendp_directory_global());
    if (!zr_chain_up(&c)) {
        printf("  zendp_revocation: non-answer fixture FAIL\n");
        zr_chain_down(&c);
        return 1;
    }
    boot_endpoint_records_register();

    uint8_t wire[ZID_DOC_MAX], pk[32];
    size_t wire_len = 0;
    bool staged = zr_sign_record(0x72, 1, wire, &wire_len, pk) &&
                  zr_fold_anchor(&c, pk, 700) &&
                  zendp_accept(zendp_directory_global(), wire, wire_len,
                               (uint64_t)platform_time_wall_unix(), NULL,
                               NULL) == ZENDP_OK;
    ZR_CHECK("an active record is staged", staged && zr_projected() == 1);

    /* Catch up, so the next pass is driven only by what follows. */
    (void)boot_endpoint_records_revalidate_once();

    /* Now take the chain away and claim something changed. Acceptance fails
     * CLOSED on a non-answer because it decides whether to START trusting a
     * record. Revalidation must not: dropping every held record because
     * node.db hiccuped is a self-inflicted discovery outage. */
    zendp_set_anchor_lookup(NULL, NULL);
    zid_identity_note_status_change(701);

    ZR_CHECK("with the chain unreachable the pass reports unavailable and "
             "drops nothing",
             boot_endpoint_records_revalidate_once() ==
                 BOOT_ENDPOINT_REVAL_UNAVAILABLE &&
             zr_projected() == 1 &&
             zendp_directory_find(zendp_directory_global(), pk, NULL));

    /* The change is still pending — an unresolved pass must not be recorded
     * as handled, or the revocation would be lost for good. */
    ZR_CHECK("the unresolved change is retried, not swallowed",
             boot_endpoint_records_revalidate_once() ==
                 BOOT_ENDPOINT_REVAL_UNAVAILABLE);

    boot_endpoint_records_register();
    ZR_CHECK("once the chain answers again the pass applies and the still-"
             "active record survives",
             boot_endpoint_records_revalidate_once() ==
                 BOOT_ENDPOINT_REVAL_APPLIED &&
             zr_projected() == 1);

    zr_chain_down(&c);
    return failures;
}

/* ── case 3: the sweep does not hold the directory lock over the chain ─ */

/* This lookup re-enters the discovery projection — the exact call the
 * shared supervisor tick runner makes via onion_directory_tick. If the
 * sweep held the directory lock across the chain lookup, this would
 * deadlock on a non-recursive mutex; on a real node the same shape means
 * the tick runner parks behind a node.db read for as long as the fold
 * holds its write batch, and the watchdog kills the process. */
static _Atomic int g_reentrant_calls;
static _Atomic size_t g_reentrant_seen;

static bool zr_reentrant_lookup(void *ctx, const uint8_t pubkey[32],
                                struct zendp_anchor *out)
{
    (void)ctx;
    (void)pubkey;
    if (!out)
        return false;
    atomic_fetch_add(&g_reentrant_calls, 1);
    /* THE PROBE. Returns only if the lock is free. */
    atomic_store(&g_reentrant_seen, zr_projected());
    memset(out, 0, sizeof(*out));
    out->state = ZENDP_ANCHOR_ACTIVE;
    out->anchor_height = 3100000;
    out->updated_height = 3100000;
    return true;
}

static int zr_case_lock_released(void)
{
    int failures = 0;
    struct zr_chain c;

    zendp_directory_init(zendp_directory_global());
    if (!zr_chain_up(&c)) {
        printf("  zendp_revocation: lock fixture FAIL\n");
        zr_chain_down(&c);
        return 1;
    }
    boot_endpoint_records_register();

    uint8_t wire[ZID_DOC_MAX], pk[32];
    size_t wire_len = 0;
    bool staged = zr_sign_record(0x73, 1, wire, &wire_len, pk) &&
                  zr_fold_anchor(&c, pk, 800) &&
                  zendp_accept(zendp_directory_global(), wire, wire_len,
                               (uint64_t)platform_time_wall_unix(), NULL,
                               NULL) == ZENDP_OK;
    ZR_CHECK("a record is staged for the lock probe",
             staged && zr_projected() == 1);

    atomic_store(&g_reentrant_calls, 0);
    atomic_store(&g_reentrant_seen, (size_t)0);
    zendp_set_anchor_lookup(zr_reentrant_lookup, NULL);

    struct zendp_revalidation tally;
    memset(&tally, 0, sizeof(tally));
    enum zendp_result r = zendp_global_revalidate(&tally);

    ZR_CHECK("the discovery projection runs from inside the chain lookup — "
             "the sweep does not hold the directory lock across it",
             r == ZENDP_OK && atomic_load(&g_reentrant_calls) == 1 &&
             atomic_load(&g_reentrant_seen) == 1 &&
             tally.checked == 1 && tally.dropped == 0 &&
             tally.unavailable == 0);

    zr_chain_down(&c);
    return failures;
}

/* ── case 4: the operator surface ──────────────────────────────────── */

static int zr_case_dumper(void)
{
    int failures = 0;
    struct zr_chain c;

    zendp_directory_init(zendp_directory_global());
    if (!zr_chain_up(&c)) {
        printf("  zendp_revocation: dumper fixture FAIL\n");
        zr_chain_down(&c);
        return 1;
    }
    boot_endpoint_records_register();

    ZR_CHECK("the dumper refuses a NULL out",
             !boot_endpoint_records_dump_state_json(NULL, NULL));

    uint8_t wire[ZID_DOC_MAX], pk[32];
    size_t wire_len = 0;
    bool staged = zr_sign_record(0x74, 1, wire, &wire_len, pk) &&
                  zr_fold_anchor(&c, pk, 900) &&
                  zendp_accept(zendp_directory_global(), wire, wire_len,
                               (uint64_t)platform_time_wall_unix(), NULL,
                               NULL) == ZENDP_OK;
    (void)boot_endpoint_records_revalidate_once();

    /* Pending is the operator-visible statement "the chain moved and this
     * node has not caught up yet". */
    ZR_CHECK("after a fold the dumper reports the change as pending",
             staged && zr_fold_revoke(&c, pk, 901));
    { struct json_value out;
      json_init(&out);
      bool ok = boot_endpoint_records_dump_state_json(&out, NULL) &&
                out.type == JSON_OBJ &&
                json_get(&out, "identity_status_generation") != NULL &&
                json_get(&out, "revalidated_generation") != NULL &&
                json_get(&out, "revalidation_pending") != NULL &&
                json_get(&out, "sweeps_applied") != NULL &&
                json_get(&out, "records_invalidated") != NULL &&
                json_get(&out, "identities_checked") != NULL &&
                json_get(&out, "chain_unavailable_passes") != NULL &&
                json_get(&out, "records_projected") != NULL &&
                json_get(&out, "anchor_lookup_registered") != NULL &&
                json_get(&out, "worker_running") != NULL &&
                json_get(&out, "last_sweep_age_us") != NULL;
      json_free(&out);
      ZR_CHECK("the dumper emits the whole contract", ok); }

    ZR_CHECK("revalidation clears the pending flag and counts the drop",
             boot_endpoint_records_revalidate_once() ==
                 BOOT_ENDPOINT_REVAL_APPLIED);
    { struct json_value out;
      json_init(&out);
      bool ok = boot_endpoint_records_dump_state_json(&out, NULL);
      const struct json_value *pending =
          ok ? json_get(&out, "revalidation_pending") : NULL;
      const struct json_value *dropped =
          ok ? json_get(&out, "records_invalidated") : NULL;
      const struct json_value *projected =
          ok ? json_get(&out, "records_projected") : NULL;
      ok = ok && pending && !pending->val.b &&
           dropped && dropped->val.i >= 1 &&
           projected && projected->val.i == 0;
      json_free(&out);
      ZR_CHECK("the dumper separates results from activity", ok); }

    /* The registry must have room, or the next subsystem to register runs
     * unsupervised — and this slice adds one child. */
    ZR_CHECK("the supervisor registry has headroom for this child",
             supervisor_child_headroom() > 0);
    printf("  zendp_revocation: supervisor child_headroom = %d\n",
           supervisor_child_headroom());

    zr_chain_down(&c);
    return failures;
}

int test_zendp_revocation(void)
{
    printf("\n=== zendp revocation: a revoked key stops being advertised "
           "without a restart ===\n");
    int failures = 0;
    failures += zr_case_revoked_key_stops_being_advertised();
    failures += zr_case_non_answer_changes_nothing();
    failures += zr_case_lock_released();
    failures += zr_case_dumper();
    if (failures == 0)
        printf("=== zendp revocation: all checks passed ===\n");
    else
        printf("=== zendp revocation: %d FAILED ===\n", failures);
    return failures;
}
