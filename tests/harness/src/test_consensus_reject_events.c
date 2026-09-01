/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for EV_CONSENSUS_REJECT_TX / EV_CONSENSUS_REJECT_BLOCK
 * emission — wave 7 new item "consensus metrics".
 *
 * Strategy
 * --------
 * Drive `check_transaction` and `check_block_header` through failure
 * paths using transactions/headers crafted specifically to hit a
 * chosen `REJECT_*` macro, then assert that:
 *
 *  1. `EV_CONSENSUS_REJECT_TX` fires exactly once per failing
 *     `check_transaction` call.
 *  2. Successful `check_transaction` emits nothing.
 *  3. `EV_CONSENSUS_REJECT_BLOCK` fires on a failing
 *     `check_block_header` call (and not on a successful one).
 *  4. The payload string contains the reject reason and the
 *     accumulated DoS score.
 *
 * The full `check_block` path (which internally recurses into
 * `check_transaction` and `check_block_header`) is covered by the
 * existing validation-path tests — here we only assert that the
 * event plumbing works, because the consumer
 * (`z23 core consensus report`,
 * AGENT3 wave 7) just needs the event stream to be reliable.
 */

#include "test/test_core.h"
#include "validation/check_transaction.h"
#include "validation/check_block.h"
#include "primitives/transaction.h"
#include "primitives/block.h"
#include "event/event.h"
#include "script/script.h"
#include "consensus/validation.h"
#include "chain/chainparams.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include "util/safe_alloc.h"

static _Atomic int g_rej_tx;
static _Atomic int g_rej_block;
static char g_last_tx_payload[256];
static char g_last_block_payload[256];

static void cre_observer(enum event_type type, uint32_t peer_id,
                          const void *payload, uint32_t payload_len,
                          void *ctx)
{
    (void)peer_id; (void)ctx;
    size_t n = payload_len < sizeof(g_last_tx_payload) - 1
                 ? payload_len : sizeof(g_last_tx_payload) - 1;
    if (type == EV_CONSENSUS_REJECT_TX) {
        atomic_fetch_add(&g_rej_tx, 1);
        memcpy(g_last_tx_payload, payload, n);
        g_last_tx_payload[n] = '\0';
    }
    if (type == EV_CONSENSUS_REJECT_BLOCK) {
        atomic_fetch_add(&g_rej_block, 1);
        memcpy(g_last_block_payload, payload, n);
        g_last_block_payload[n] = '\0';
    }
}

static void cre_reset(void)
{
    event_clear_observers(EV_CONSENSUS_REJECT_TX);
    event_clear_observers(EV_CONSENSUS_REJECT_BLOCK);
    atomic_store(&g_rej_tx, 0);
    atomic_store(&g_rej_block, 0);
    memset(g_last_tx_payload, 0, sizeof(g_last_tx_payload));
    memset(g_last_block_payload, 0, sizeof(g_last_block_payload));
    event_observe(EV_CONSENSUS_REJECT_TX, cre_observer, NULL);
    event_observe(EV_CONSENSUS_REJECT_BLOCK, cre_observer, NULL);
}

#define CRE_CHECK(name, expr) do { \
    printf("%s... ", (name));      \
    if ((expr)) printf("OK\n");    \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Build a minimal valid v1 transparent tx so check_transaction returns
 * true. Same shape the existing test_validation.c uses. */
static struct transaction cre_make_valid_tx(void)
{
    struct transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = 1;
    tx.overwintered = false;
    tx.num_vin = 1;
    tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_vin");
    memset(tx.vin[0].prevout.hash.data, 0xAA, 32);
    tx.vin[0].prevout.n = 0;
    uint8_t sig[] = {0x00, 0x00};
    script_set(&tx.vin[0].script_sig, sig, 2);
    tx.vin[0].sequence = 0xFFFFFFFF;
    tx.num_vout = 1;
    tx.vout = zcl_calloc(1, sizeof(struct tx_out), "test_vout");
    tx.vout[0].value = 50 * 100000000LL;
    uint8_t pk[] = {0x76, 0xa9, 0x14};
    script_set(&tx.vout[0].script_pub_key, pk, 3);
    return tx;
}

static void cre_free_tx(struct transaction *tx)
{
    /* script fields are inline — nothing to free on the script itself. */
    free(tx->vin);
    free(tx->vout);
}

int test_consensus_reject_events(void)
{
    printf("\n=== consensus reject events ===\n");
    int failures = 0;

    /* ── 1. Valid tx → no event ─────────────────────────────── */
    {
        cre_reset();
        struct transaction tx = cre_make_valid_tx();
        struct validation_state vs;
        validation_state_init(&vs);
        bool ok = check_transaction(&tx, &vs);
        cre_free_tx(&tx);
        CRE_CHECK("cre: valid tx → check_transaction returns true", ok);
        CRE_CHECK("cre: valid tx → no EV_CONSENSUS_REJECT_TX",
                  atomic_load(&g_rej_tx) == 0);
    }

    /* ── 2. Tx with empty vin/vout/joinsplit → event fires ─── */
    {
        cre_reset();
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.version = 1;
        tx.num_vin = 0;
        tx.num_vout = 1;
        tx.vout = zcl_calloc(1, sizeof(struct tx_out), "test_vout");
        tx.vout[0].value = 100;
        uint8_t pk[] = {0x00};
        script_set(&tx.vout[0].script_pub_key, pk, 1);

        struct validation_state vs;
        validation_state_init(&vs);
        bool ok = check_transaction(&tx, &vs);
        free(tx.vout);
        CRE_CHECK("cre: vin-empty → check_transaction returns false", !ok);
        CRE_CHECK("cre: vin-empty → EV_CONSENSUS_REJECT_TX fired once",
                  atomic_load(&g_rej_tx) == 1);
        CRE_CHECK("cre: vin-empty payload contains reason",
                  strstr(g_last_tx_payload, "reason=bad-txns-vin-empty") != NULL);
        CRE_CHECK("cre: vin-empty payload contains dos=",
                  strstr(g_last_tx_payload, "dos=") != NULL);
    }

    /* ── 3. Tx with negative output value → distinct reason ── */
    {
        cre_reset();
        struct transaction tx = cre_make_valid_tx();
        tx.vout[0].value = -1;
        struct validation_state vs;
        validation_state_init(&vs);
        bool ok = check_transaction(&tx, &vs);
        cre_free_tx(&tx);
        CRE_CHECK("cre: vout-negative → check_transaction returns false", !ok);
        CRE_CHECK("cre: vout-negative → event fired",
                  atomic_load(&g_rej_tx) == 1);
        CRE_CHECK("cre: vout-negative payload has correct reason",
                  strstr(g_last_tx_payload, "vout-negative") != NULL);
    }

    /* ── 4. Multiple failing calls → accumulate event count ── */
    {
        cre_reset();
        for (int i = 0; i < 5; i++) {
            struct transaction tx;
            memset(&tx, 0, sizeof(tx));
            tx.version = 1;
            tx.num_vin = 0;
            tx.num_vout = 0;
            struct validation_state vs;
            validation_state_init(&vs);
            (void)check_transaction(&tx, &vs);
        }
        CRE_CHECK("cre: 5 failing calls → 5 events",
                  atomic_load(&g_rej_tx) == 5);
    }

    /* ── 5. MODE_VALID state (no prior rejection) → no emit ── */
    {
        cre_reset();
        /* validation_state_init leaves mode=VALID, reject_reason[0]='\0'.
         * Directly call the wrapper on a valid tx and confirm no emit. */
        struct transaction tx = cre_make_valid_tx();
        struct validation_state vs;
        validation_state_init(&vs);
        (void)check_transaction(&tx, &vs);
        cre_free_tx(&tx);
        CRE_CHECK("cre: valid-path no event regression",
                  atomic_load(&g_rej_tx) == 0);
    }

    /* ── 6. check_block_header failing → REJECT_BLOCK fires ── */
    {
        cre_reset();
        const struct chain_params *params = chain_params_get();
        /* Version below MIN_BLOCK_VERSION → immediate REJECT_IF. */
        struct block_header hdr;
        memset(&hdr, 0, sizeof(hdr));
        hdr.nVersion = 1; /* MIN_BLOCK_VERSION is 4 for Sapling+ */
        struct validation_state vs;
        validation_state_init(&vs);
        bool ok = check_block_header(&hdr, &vs, params,
                                     /*check_pow=*/false);
        CRE_CHECK("cre: version-too-low → check_block_header false", !ok);
        CRE_CHECK("cre: REJECT_BLOCK event fired once",
                  atomic_load(&g_rej_block) == 1);
        CRE_CHECK("cre: REJECT_BLOCK payload contains reason",
                  strstr(g_last_block_payload, "version-too-low") != NULL);
        CRE_CHECK("cre: REJECT_BLOCK payload contains dos=",
                  strstr(g_last_block_payload, "dos=") != NULL);
    }

    /* ── 7. Successful check_block_header → no REJECT_BLOCK ── */
    {
        cre_reset();
        const struct chain_params *params = chain_params_get();
        struct block_header hdr;
        memset(&hdr, 0, sizeof(hdr));
        hdr.nVersion = 4; /* current MIN_BLOCK_VERSION */
        hdr.nTime = 1000; /* well in the past — won't trip time-too-new */
        struct validation_state vs;
        validation_state_init(&vs);
        bool ok = check_block_header(&hdr, &vs, params,
                                     /*check_pow=*/false);
        CRE_CHECK("cre: valid header → check_block_header true", ok);
        CRE_CHECK("cre: valid header → no REJECT_BLOCK event",
                  atomic_load(&g_rej_block) == 0);
    }

    /* ── 8. Observer is cleared between sections (sanity) ──── */
    {
        cre_reset();
        CRE_CHECK("cre: reset drops prior observer state",
                  atomic_load(&g_rej_tx) == 0 &&
                  atomic_load(&g_rej_block) == 0);
    }

    printf("consensus reject events: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}
