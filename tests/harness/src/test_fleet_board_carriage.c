/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The fleet board's per-peer carriage record: every reason the pull lane did
 * not pull a peer is named and recorded, a drained answer bumps the counters
 * and clears the reason, and `fleet board status` renders it under
 * carriage.peers and carriage.totals. The recording helpers are driven
 * directly; the gate reasons are also driven through the real
 * board_peer_due by pulling a store of pairing rows. The full tick with a
 * live peer session is not driven here: the board group's session fixture
 * covers the pull and drain themselves, and these cases do not repeat it. */
#include "test/test_core.h"
#include "config/boot_fleet_board.h"
#include "config/boot_internal.h"
#include "config/runtime.h"
#include "models/mesh_pairing.h"
#include "services/mesh_pairing_service.h"
#include "../../../engine/composition/src/boot_fleet_board_carriage_peers_internal.h"
#include "../../../engine/composition/src/boot_fleet_board_rpc_internal.h"

#include <stdio.h>
#include <string.h>

static void fbc_key(uint8_t fill, uint8_t out[32])
{
    memset(out, fill, 32);
}

/* The record for the peer keyed by `fill`, or false. */
static bool fbc_find(uint8_t fill, struct board_carriage_peer *out)
{
    struct board_carriage_peer rows[FLEET_BOARD_FLEET_PEERS_MAX];
    uint8_t key[32];
    fbc_key(fill, key);
    size_t n = board_carriage_snapshot(rows, FLEET_BOARD_FLEET_PEERS_MAX);
    for (size_t i = 0; i < n && i < FLEET_BOARD_FLEET_PEERS_MAX; i++)
        if (memcmp(rows[i].peer, key, 32) == 0) {
            *out = rows[i];
            return true;
        }
    return false;
}

/* "reason" or "reason:detail", as the status reply shows it. */
static bool fbc_reason_is(uint8_t fill, const char *want)
{
    struct board_carriage_peer p;
    char got[BOARD_CARRIAGE_DETAIL_MAX + 40];
    if (!fbc_find(fill, &p))
        return false;
    (void)snprintf(got, sizeof got, "%s%s%s",
                   board_carriage_reason_name(p.reason),
                   p.detail[0] ? ":" : "", p.detail);
    return strcmp(got, want) == 0;
}

static int fbc_record_case1(void)
{
    int failures = 0;
    uint8_t k1[32], k2[32];
    fbc_key(1, k1);
    fbc_key(2, k2);
    TEST("carriage: each silent decision is recorded under its own name") {
        board_carriage_test_reset();
        board_carriage_gate(k1, FLEET_BOARD_GATE_PAIRING, 100);
        ASSERT(fbc_reason_is(1, "pairing_window_closed"));
        board_carriage_gate(k1, FLEET_BOARD_GATE_DELEGATION_UNRESOLVED, 101);
        ASSERT(fbc_reason_is(1, "no_delegation"));
        board_carriage_gate(k1, FLEET_BOARD_GATE_DELEGATION_REFUSED, 102);
        ASSERT(fbc_reason_is(1, "delegation_refused"));
        board_carriage_gate(k1, FLEET_BOARD_GATE_ROSTER, 103);
        ASSERT(fbc_reason_is(1, "roster_gated"));
        board_carriage_skip(k1, BOARD_CARRIAGE_PULL_IN_FLIGHT, NULL, 104);
        ASSERT(fbc_reason_is(1, "pull_in_flight"));
        board_carriage_pull(k1, 105, false, true, "stream_peer_not_connected");
        ASSERT(fbc_reason_is(1, "peer_not_connected"));
        board_carriage_pull(k1, 106, false, false, "stream_cap");
        ASSERT(fbc_reason_is(1, "stream_open_failed:stream_cap"));
        board_carriage_refused(k1, "stream_peer_unpaired", 107);
        ASSERT(fbc_reason_is(1, "answer_refused:stream_peer_unpaired"));
        board_carriage_gate(k2, (enum boot_fleet_board_gate_reason)99, 108);
        ASSERT(!fbc_find(2, &(struct board_carriage_peer){0}));
        PASS();
    } _test_next:;
    return failures;
}

static int fbc_record_case2(void)
{
    int failures = 0;
    uint8_t k1[32], k2[32];
    fbc_key(1, k1);
    fbc_key(2, k2);
    TEST("carriage: a drained answer counts, stamps and clears the reason") {
        struct board_carriage_peer p;
        board_carriage_test_reset();
        board_carriage_pull(k1, 200, false, true, "x");
        board_carriage_refused(k1, "malformed", 201);
        ASSERT(fbc_find(1, &p));
        ASSERT_EQ(p.pulls, (uint64_t)1);
        ASSERT_EQ(p.refused, (uint64_t)1);
        ASSERT_EQ(p.answers, (uint64_t)0);
        ASSERT_EQ(p.last_pull_attempt_at, (int64_t)200);
        ASSERT_EQ(p.last_answer_at, (int64_t)0);
        board_carriage_answer(k1, 3, 202);
        board_carriage_answer(k1, 2, 203);
        ASSERT(fbc_find(1, &p));
        ASSERT_EQ(p.answers, (uint64_t)2);
        ASSERT_EQ(p.stored, (uint64_t)5);
        ASSERT_EQ(p.refused, (uint64_t)1);
        ASSERT_EQ(p.last_answer_at, (int64_t)203);
        ASSERT(p.reason == BOARD_CARRIAGE_NONE && p.detail[0] == '\0');
        PASS();
    } _test_next:;
    return failures;
}

static int fbc_record_case3(void)
{
    int failures = 0;
    uint8_t k1[32], k2[32];
    fbc_key(1, k1);
    fbc_key(2, k2);
    TEST("carriage: an opened stream ends a skip but not a refused answer") {
        board_carriage_test_reset();
        board_carriage_gate(k1, FLEET_BOARD_GATE_ROSTER, 300);
        board_carriage_gate(k2, FLEET_BOARD_GATE_ROSTER, 300);
        board_carriage_refused(k2, "malformed", 300);
        board_carriage_pull(k1, 301, true, false, "");
        board_carriage_pull(k2, 301, true, false, "");
        ASSERT(fbc_reason_is(1, ""));
        ASSERT(fbc_reason_is(2, "answer_refused:malformed"));
        PASS();
    } _test_next:;
    return failures;
}

static int fbc_record_case4(void)
{
    int failures = 0;
    uint8_t k1[32], k2[32];
    fbc_key(1, k1);
    fbc_key(2, k2);
    TEST("carriage: not_due_yet marks only peers with no reason on record") {
        board_carriage_test_reset();
        board_carriage_answer(k1, 0, 400);
        board_carriage_gate(k2, FLEET_BOARD_GATE_PAIRING, 400);
        board_carriage_not_due(401);
        ASSERT(fbc_reason_is(1, "not_due_yet"));
        ASSERT(fbc_reason_is(2, "pairing_window_closed"));
        board_carriage_pull(k1, 415, true, false, "");
        ASSERT(fbc_reason_is(1, ""));
        PASS();
    } _test_next:;
    return failures;
}

/* The status projection: one row per peer plus totals. */
static const struct json_value *fbc_row(const struct json_value *peers,
                                        const char *fingerprint)
{
    for (size_t i = 0; peers && i < peers->num_children; i++)
        if (!strncmp(json_get_str(json_get(&peers->children[i], "peer")),
                     fingerprint, 12))
            return &peers->children[i];
    return NULL;
}

static int fbc_status_cases(void)
{
    int failures = 0;
    uint8_t k1[32], k2[32];
    fbc_key(1, k1);
    fbc_key(2, k2);
    TEST("carriage: the status reply carries one row per peer and totals") {
        struct json_value result, *c, *peers, *t;
        board_carriage_test_reset();
        board_carriage_pull(k1, 500, false, true, "x");
        board_carriage_answer(k1, 4, 501);
        board_carriage_pull(k2, 502, false, false, "stream_cap");
        board_carriage_refused(k2, "malformed", 503);
        json_init(&result);
        json_set_object(&result);
        ASSERT(fb_render_carriage(&result));
        c = (struct json_value *)json_get(&result, "carriage");
        ASSERT(c != NULL);
        peers = (struct json_value *)json_get(c, "peers");
        t = (struct json_value *)json_get(c, "totals");
        ASSERT(peers && peers->type == JSON_ARR && t);
        ASSERT_EQ(peers->num_children, (size_t)2);
        ASSERT_EQ(json_get_int(json_get(t, "peers")), (int64_t)2);
        ASSERT_EQ(json_get_int(json_get(t, "pulls")), (int64_t)2);
        ASSERT_EQ(json_get_int(json_get(t, "answers")), (int64_t)1);
        ASSERT_EQ(json_get_int(json_get(t, "stored")), (int64_t)4);
        ASSERT_EQ(json_get_int(json_get(t, "refused")), (int64_t)1);
        const struct json_value *r = &peers->children[1];
        ASSERT_STR_EQ(json_get_str(json_get(r, "last_skip_reason")),
                      "answer_refused:malformed");
        ASSERT_EQ(json_get_int(json_get(r, "last_pull_attempt_at")),
                  (int64_t)502);
        r = &peers->children[0];
        ASSERT_STR_EQ(json_get_str(json_get(r, "last_skip_reason")), "");
        ASSERT_EQ(json_get_int(json_get(r, "last_answer_at")), (int64_t)501);
        ASSERT(strlen(json_get_str(json_get(r, "peer"))) == 12);
        ASSERT(fbc_row(peers, json_get_str(json_get(r, "peer"))) == r);
        json_free(&result);
        PASS();
    } _test_next:;
    return failures;
}

static bool fbc_pairing(struct node_db *db, uint8_t master, uint8_t noise,
                        int64_t expires)
{
    struct db_mesh_pairing row;
    memset(&row, 0, sizeof row);
    memset(row.network_genesis, 0x01, 32);
    memset(row.peer_master_pubkey, master, 32);
    memset(row.peer_noise_pubkey, noise, 32);
    row.capability_mask = MESH_PAIRING_CAP_STATUS_READ;
    row.delegation_sequence = 1;
    row.paired_at = 1000;
    row.expires_at = expires;
    return mesh_pairing_id_derive(row.network_genesis, row.peer_master_pubkey,
                                  row.peer_noise_pubkey, row.pairing_id) &&
           db_mesh_pairing_insert(db, &row);
}

/* The real board_peer_due over a store of pairing rows. */
static int fbc_driven_cases(void)
{
    int failures = 0;
    struct node_db db = {0};
    bool opened = node_db_open(&db, ":memory:");
    struct db_service service = {.node_db = &db, .started = true};
    struct app_runtime_context runtime = {.db_service = &service};
    TEST("carriage: the pull gate records why it did not pull, per peer") {
        struct board_carriage_peer p;
        struct vcs_zcode_dht_delegation other;
        uint8_t genesis[32];
        ASSERT(opened);
        ASSERT(fbc_pairing(&db, 0xA1, 0x11, 1500)); /* window closed at 2000 */
        ASSERT(fbc_pairing(&db, 0xA2, 0x12, 9000)); /* open, no delegation */
        memset(&other, 0, sizeof other);
        memset(other.noise_static_pubkey, 0xEE, 32);
        memset(genesis, 0x01, 32);
        board_carriage_test_reset();
        app_runtime_set_current(&runtime);
        boot_fleet_board_fleet_test_bind_authority(&other, genesis, 2000);
        boot_fleet_board_fleet_test_pull_paired(2000);
        boot_fleet_board_fleet_test_bind_authority(NULL, NULL, 0);
        app_runtime_set_current(NULL);
        ASSERT(fbc_reason_is(0xA1, "pairing_window_closed"));
        ASSERT(fbc_reason_is(0xA2, "no_delegation"));
        ASSERT(fbc_find(0xA1, &p));
        ASSERT_EQ(p.pulls, (uint64_t)0);
        PASS();
    } _test_next:;
    if (db.open)
        node_db_close(&db);
    return failures;
}

int test_fleet_board_carriage(void)
{
    int failures = fbc_record_case1() + fbc_record_case2() +
                  fbc_record_case3() + fbc_record_case4();
    failures += fbc_status_cases();
    failures += fbc_driven_cases();
    board_carriage_test_reset();
    return failures;
}
