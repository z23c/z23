/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for consensus_reject_index — the hash-keyed ring that
 * sits downstream of EV_CONSENSUS_REJECT_{TX,BLOCK} (wave 8 #4).
 *
 * Strategy
 * --------
 * Two layers:
 *
 *  1. Direct record() path. The index exposes a test seam that
 *     writes a struct cri_entry straight into the ring without
 *     going through the event system. We use this to exercise
 *     the ring mechanics in isolation — capacity rounding,
 *     eviction, lookup correctness, kind filtering, newest-match-
 *     wins ordering, count/total counters, clear() semantics.
 *
 *  2. Event path. We register the service with default capacity,
 *     then drive the real check_transaction / check_block_header
 *     wrappers on crafted-invalid inputs. This exercises (a) the
 *     payload parser against the exact printf'd format emitted
 *     by check_block.c / check_transaction.c and (b) the observer
 *     registration path. The index must be consistent with
 *     lookup() the instant check_transaction() returns.
 *
 * The event-path tests use tx hashes that are deterministic
 * (all-zeroes via uint256_set_null — check_transaction doesn't
 * compute tx->hash and the valid-path test sets the hash
 * manually via a helper).
 */

#include "test/test_core.h"
#include "json/json.h"
#include "services/consensus_reject_index.h"
#include "validation/check_transaction.h"
#include "validation/check_block.h"
#include "primitives/transaction.h"
#include "primitives/block.h"
#include "core/uint256.h"
#include "event/event.h"
#include "consensus/validation.h"
#include "chain/chainparams.h"
#include "script/script.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util/safe_alloc.h"
#include "test/setup_result.h"

#define CRI_CHECK(name, expr) do {         \
    printf("%s... ", (name));              \
    if ((expr)) printf("OK\n");            \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static struct uint256 make_hash(uint8_t seed)
{
    struct uint256 h;
    for (int i = 0; i < 32; i++) h.data[i] = (uint8_t)(seed + (uint8_t)i);
    return h;
}

/* Build a valid v1 tx mirroring cre_make_valid_tx — same helper
 * shape as test_consensus_reject_events.c so both tests agree on
 * what "valid" looks like. */
static struct transaction cri_valid_tx(void)
{
    struct transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = 1;
    tx.num_vin = 1;
    tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_vin");
    memset(tx.vin[0].prevout.hash.data, 0xAA, 32);
    tx.vin[0].sequence = 0xFFFFFFFF;
    uint8_t sig[] = {0x00, 0x00};
    script_set(&tx.vin[0].script_sig, sig, 2);
    tx.num_vout = 1;
    tx.vout = zcl_calloc(1, sizeof(struct tx_out), "test_vout");
    tx.vout[0].value = 50 * 100000000LL;
    uint8_t pk[] = {0x76, 0xa9, 0x14};
    script_set(&tx.vout[0].script_pub_key, pk, 3);
    return tx;
}

static void cri_free_tx(struct transaction *tx)
{
    free(tx->vin);
    free(tx->vout);
}

int test_consensus_reject_index(void)
{
    printf("\n=== consensus reject index ===\n");
    int failures = 0;

    /* ── 1. Start/stop lifecycle ───────────────────────────── */
    {
        CRI_CHECK("cri: not running before start",
                  !consensus_reject_index_running());
        CRI_CHECK("cri: start with default capacity",
                  consensus_reject_index_start(0).ok);
        CRI_CHECK("cri: running after start",
                  consensus_reject_index_running());
        CRI_CHECK("cri: default capacity is 256",
                  consensus_reject_index_capacity() == 256);
        CRI_CHECK("cri: start twice is idempotent",
                  consensus_reject_index_start(0).ok);
        consensus_reject_index_stop();
        CRI_CHECK("cri: stopped after stop",
                  !consensus_reject_index_running());
        CRI_CHECK("cri: stop twice is safe",
                  (consensus_reject_index_stop(), true));
    }

    /* ── 2. Capacity rounding + clamping ────────────────────── */
    {
        /* 50 → next pow2 = 64 */
        ZCL_TEST_SETUP(consensus_reject_index_start(50));
        CRI_CHECK("cri: capacity 50 rounds up to 64",
                  consensus_reject_index_capacity() == 64);
        consensus_reject_index_stop();

        /* 1 → clamped up to 8 */
        ZCL_TEST_SETUP(consensus_reject_index_start(1));
        CRI_CHECK("cri: capacity 1 clamped to 8",
                  consensus_reject_index_capacity() == 8);
        consensus_reject_index_stop();

        /* Beyond max → clamped to CRI_MAX_CAPACITY */
        ZCL_TEST_SETUP(consensus_reject_index_start(CRI_MAX_CAPACITY * 2));
        CRI_CHECK("cri: capacity above max clamped",
                  consensus_reject_index_capacity() == CRI_MAX_CAPACITY);
        consensus_reject_index_stop();
    }

    /* ── 3. Direct record() — basic insert + lookup ───────── */
    {
        ZCL_TEST_SETUP(consensus_reject_index_start(16));
        struct cri_entry e = {0};
        e.hash = make_hash(0x11);
        e.kind = CRI_KIND_TX;
        e.dos  = 100;
        snprintf(e.reason, sizeof(e.reason), "bad-txns-vin-empty");
        consensus_reject_index_record(&e);

        CRI_CHECK("cri: count=1 after one record",
                  consensus_reject_index_count() == 1);
        CRI_CHECK("cri: total=1 after one record",
                  consensus_reject_index_total() == 1);

        struct cri_entry got;
        struct uint256 h = make_hash(0x11);
        CRI_CHECK("cri: lookup finds recorded entry",
                  consensus_reject_index_lookup(&h, NULL, &got).ok);
        CRI_CHECK("cri: lookup returns correct reason",
                  strcmp(got.reason, "bad-txns-vin-empty") == 0);
        CRI_CHECK("cri: lookup returns correct dos",
                  got.dos == 100);
        CRI_CHECK("cri: lookup returns correct kind",
                  got.kind == CRI_KIND_TX);

        /* Wrong hash */
        struct uint256 h2 = make_hash(0x22);
        CRI_CHECK("cri: lookup of absent hash returns false",
                  !consensus_reject_index_lookup(&h2, NULL, &got).ok);

        consensus_reject_index_stop();
    }

    /* ── 4. Kind filter ─────────────────────────────────────── */
    {
        ZCL_TEST_SETUP(consensus_reject_index_start(16));
        struct cri_entry etx = {0};
        etx.hash = make_hash(0x33); etx.kind = CRI_KIND_TX; etx.dos = 10;
        snprintf(etx.reason, sizeof(etx.reason), "tx-reason");
        consensus_reject_index_record(&etx);

        /* Same hash but kind=BLOCK */
        struct cri_entry eb = {0};
        eb.hash = make_hash(0x33); eb.kind = CRI_KIND_BLOCK; eb.dos = 50;
        snprintf(eb.reason, sizeof(eb.reason), "block-reason");
        consensus_reject_index_record(&eb);

        struct cri_entry got;
        struct uint256 h = make_hash(0x33);
        enum cri_kind k_tx = CRI_KIND_TX, k_blk = CRI_KIND_BLOCK;

        CRI_CHECK("cri: kind=TX filter returns tx entry",
                  consensus_reject_index_lookup(&h, &k_tx, &got).ok &&
                  strcmp(got.reason, "tx-reason") == 0);
        CRI_CHECK("cri: kind=BLOCK filter returns block entry",
                  consensus_reject_index_lookup(&h, &k_blk, &got).ok &&
                  strcmp(got.reason, "block-reason") == 0);
        CRI_CHECK("cri: kind=NULL returns newest (block)",
                  consensus_reject_index_lookup(&h, NULL, &got).ok &&
                  strcmp(got.reason, "block-reason") == 0);
        consensus_reject_index_stop();
    }

    /* ── 5. Newest-match-wins when same hash recorded twice ─ */
    {
        ZCL_TEST_SETUP(consensus_reject_index_start(16));
        struct cri_entry e1 = {0};
        e1.hash = make_hash(0x44); e1.kind = CRI_KIND_TX; e1.dos = 100;
        snprintf(e1.reason, sizeof(e1.reason), "first");
        consensus_reject_index_record(&e1);
        struct cri_entry e2 = {0};
        e2.hash = make_hash(0x44); e2.kind = CRI_KIND_TX; e2.dos = 10;
        snprintf(e2.reason, sizeof(e2.reason), "second");
        consensus_reject_index_record(&e2);

        struct cri_entry got;
        struct uint256 h = make_hash(0x44);
        CRI_CHECK("cri: duplicate hash returns newest",
                  consensus_reject_index_lookup(&h, NULL, &got).ok &&
                  strcmp(got.reason, "second") == 0 && got.dos == 10);
        consensus_reject_index_stop();
    }

    /* ── 6. Ring eviction at capacity ───────────────────────── */
    {
        ZCL_TEST_SETUP(consensus_reject_index_start(8));  /* cap=8 */
        /* Record 12 — the first 4 should be evicted. */
        for (int i = 0; i < 12; i++) {
            struct cri_entry e = {0};
            e.hash = make_hash((uint8_t)i);
            e.kind = CRI_KIND_TX;
            e.dos  = i;
            snprintf(e.reason, sizeof(e.reason), "r%d", i);
            consensus_reject_index_record(&e);
        }
        CRI_CHECK("cri: count saturates at capacity",
                  consensus_reject_index_count() == 8);
        CRI_CHECK("cri: total keeps counting past capacity",
                  consensus_reject_index_total() == 12);

        struct cri_entry got;
        /* hash 0..3 should be evicted */
        for (int i = 0; i < 4; i++) {
            struct uint256 h = make_hash((uint8_t)i);
            if (consensus_reject_index_lookup(&h, NULL, &got).ok) {
                printf("cri: evicted entry %d still present... FAIL\n", i);
                failures++;
            }
        }
        /* hash 4..11 should be present */
        for (int i = 4; i < 12; i++) {
            struct uint256 h = make_hash((uint8_t)i);
            if (!consensus_reject_index_lookup(&h, NULL, &got).ok ||
                got.dos != i) {
                printf("cri: surviving entry %d missing/wrong... FAIL\n", i);
                failures++;
            }
        }
        CRI_CHECK("cri: eviction left exactly 8 survivors (implicit above)",
                  true);
        consensus_reject_index_stop();
    }

    /* ── 7. recent() returns newest-first ───────────────────── */
    {
        ZCL_TEST_SETUP(consensus_reject_index_start(8));
        for (int i = 0; i < 5; i++) {
            struct cri_entry e = {0};
            e.hash = make_hash((uint8_t)(0x80 + i));
            e.kind = CRI_KIND_TX;
            e.dos  = i;
            consensus_reject_index_record(&e);
        }
        struct cri_entry recent[8];
        size_t n = consensus_reject_index_recent(recent, 8);
        CRI_CHECK("cri: recent returns 5 entries", n == 5);
        CRI_CHECK("cri: recent[0] is newest",
                  n >= 1 && recent[0].dos == 4);
        CRI_CHECK("cri: recent[4] is oldest",
                  n >= 5 && recent[4].dos == 0);
        consensus_reject_index_stop();
    }

    /* ── 8. clear() drops entries, keeps service running ────── */
    {
        ZCL_TEST_SETUP(consensus_reject_index_start(16));
        struct cri_entry e = {0};
        e.hash = make_hash(0x55); e.kind = CRI_KIND_TX; e.dos = 1;
        consensus_reject_index_record(&e);
        CRI_CHECK("cri: count=1 before clear",
                  consensus_reject_index_count() == 1);
        consensus_reject_index_clear();
        CRI_CHECK("cri: count=0 after clear",
                  consensus_reject_index_count() == 0);
        CRI_CHECK("cri: total=0 after clear",
                  consensus_reject_index_total() == 0);
        CRI_CHECK("cri: still running after clear",
                  consensus_reject_index_running());
        consensus_reject_index_stop();
    }

    /* ── 9. Not running → writes are dropped, lookups empty ── */
    {
        /* Ensure stopped. */
        consensus_reject_index_stop();
        struct cri_entry e = {0};
        e.hash = make_hash(0x66); e.kind = CRI_KIND_TX; e.dos = 1;
        consensus_reject_index_record(&e);  /* must be safe no-op */
        struct cri_entry got;
        struct uint256 h = make_hash(0x66);
        CRI_CHECK("cri: lookup when stopped returns false",
                  !consensus_reject_index_lookup(&h, NULL, &got).ok);
        CRI_CHECK("cri: count when stopped is 0",
                  consensus_reject_index_count() == 0);
    }

    /* ── 10. Event path: real check_transaction rejection ───── */
    {
        ZCL_TEST_SETUP(consensus_reject_index_start(16));

        /* Invalid tx: num_vin = 0, num_vout = 0, no joinsplits */
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.version = 1;
        tx.num_vin = 0;
        tx.num_vout = 0;
        /* Give tx a deterministic non-null hash so lookup can find it. */
        memset(tx.hash.data, 0xCD, 32);

        struct validation_state vs;
        validation_state_init(&vs);
        bool ok = check_transaction(&tx, &vs);
        CRI_CHECK("cri: crafted-invalid tx returns false", !ok);

        struct uint256 expected;
        memset(expected.data, 0xCD, 32);
        struct cri_entry got;
        CRI_CHECK("cri: index has entry after check_transaction",
                  consensus_reject_index_lookup(&expected, NULL, &got).ok);
        CRI_CHECK("cri: event-path entry has correct kind",
                  got.kind == CRI_KIND_TX);
        CRI_CHECK("cri: event-path entry contains 'bad-txns-vin-empty'",
                  strcmp(got.reason, "bad-txns-vin-empty") == 0);
        CRI_CHECK("cri: event-path entry has dos>0",
                  got.dos > 0);

        consensus_reject_index_stop();
    }

    /* ── 11. Event path: check_block_header rejection ──────── */
    {
        ZCL_TEST_SETUP(consensus_reject_index_start(16));

        const struct chain_params *params = chain_params_get();
        struct block_header hdr;
        memset(&hdr, 0, sizeof(hdr));
        /* Recognisable prev-block so the header hash is distinctive. */
        memset(hdr.hashPrevBlock.data, 0xEF, 32);
        hdr.nVersion = 1;  /* below MIN_BLOCK_VERSION */

        struct validation_state vs;
        validation_state_init(&vs);
        bool ok = check_block_header(&hdr, &vs, params, /*check_pow=*/false);
        CRI_CHECK("cri: invalid header → check_block_header false", !ok);

        struct uint256 bh;
        block_header_get_hash(&hdr, &bh);
        struct cri_entry got;
        CRI_CHECK("cri: block hash looked up",
                  consensus_reject_index_lookup(&bh, NULL, &got).ok);
        CRI_CHECK("cri: entry kind = BLOCK",
                  got.kind == CRI_KIND_BLOCK);
        CRI_CHECK("cri: entry reason mentions version-too-low",
                  strcmp(got.reason, "version-too-low") == 0);

        consensus_reject_index_stop();
    }

    /* ── 12. Valid check_transaction → no entry ─────────────── */
    {
        ZCL_TEST_SETUP(consensus_reject_index_start(16));
        struct transaction tx = cri_valid_tx();
        memset(tx.hash.data, 0x77, 32);
        struct validation_state vs;
        validation_state_init(&vs);
        bool ok = check_transaction(&tx, &vs);
        cri_free_tx(&tx);
        CRI_CHECK("cri: valid tx → check_transaction true", ok);
        CRI_CHECK("cri: valid tx → count still 0",
                  consensus_reject_index_count() == 0);
        consensus_reject_index_stop();
    }

    /* ── 13. Restart between runs leaves clean state ────────── */
    {
        ZCL_TEST_SETUP(consensus_reject_index_start(16));
        struct cri_entry e = {0};
        e.hash = make_hash(0x88); e.kind = CRI_KIND_TX; e.dos = 7;
        consensus_reject_index_record(&e);
        CRI_CHECK("cri: recorded before stop",
                  consensus_reject_index_count() == 1);
        consensus_reject_index_stop();
        ZCL_TEST_SETUP(consensus_reject_index_start(16));
        CRI_CHECK("cri: fresh state after restart",
                  consensus_reject_index_count() == 0 &&
                  consensus_reject_index_total() == 0);
        consensus_reject_index_stop();
    }

    /* ── 13b. dump_state_json (`z23 dumpstate consensus_reject_index`):
     * running/total/count/capacity plus a `recent` array with the newest
     * entry's fields intact. ─────────────────────────────────────────── */
    {
        ZCL_TEST_SETUP(consensus_reject_index_start(16));
        struct cri_entry e = {0};
        e.hash = make_hash(0x99);
        e.kind = CRI_KIND_BLOCK;
        e.dos = 42;
        e.ts_us = 123456789;
        snprintf(e.reason, sizeof(e.reason), "test dump reason");
        consensus_reject_index_record(&e);

        struct json_value v = {0};
        json_set_object(&v);
        bool ok = consensus_reject_index_dump_state_json(&v, NULL);
        const struct json_value *running = json_get(&v, "running");
        const struct json_value *count = json_get(&v, "count");
        const struct json_value *recent = json_get(&v, "recent");
        const struct json_value *first = recent ? json_at(recent, 0) : NULL;
        bool shape_ok = ok && running && json_get_bool(running) == true &&
                        count && json_get_int(count) == 1 &&
                        recent && recent->type == JSON_ARR &&
                        json_size(recent) == 1 && first &&
                        strcmp(json_get_str(json_get(first, "kind")),
                              "block") == 0 &&
                        json_get_int(json_get(first, "dos")) == 42;
        json_free(&v);
        CRI_CHECK("cri: dump_state_json reports running/count/recent[0]",
                  shape_ok);
        consensus_reject_index_stop();
    }

    /* ── 14. Ensure test cleanup — leaks would break later tests */
    consensus_reject_index_stop();
    event_clear_observers(EV_CONSENSUS_REJECT_TX);
    event_clear_observers(EV_CONSENSUS_REJECT_BLOCK);

    printf("consensus reject index: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures + ZCL_TEST_SETUP_FAILURES();
}
