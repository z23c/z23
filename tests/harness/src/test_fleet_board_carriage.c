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

#include "config/boot_fleet_roster.h"
#include "config/mesh_stream.h"
#include "fleet_enrol.h"
#include "base/hex.h"
#include "crypto/ed25519.h"
#include "util/fleet_roster_check.h"
#include "util/fleet_role_check.h"
#include "models/fleet_board_delivery.h"
#include "test/fleet_board_two_node_fixture.h"
#include "test/mesh_stream_loopback.h"
#include "../../../engine/composition/src/boot_fleet_board_roster_internal.h"
#include "../../../engine/composition/src/boot_fleet_board_push_internal.h"
#define FBC_TTL 3600u

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

#define FBR_ROOT 0x71          /* fleet root: a seed byte */
#define FBR_OTHER_ROOT 0x72    /* a different operator */
#define FBR_MEMBER 5           /* a member's board identity */
#define FBR_STRANGER 7         /* nobody's board identity */
#define FBR_PEER 9             /* stands for the paired peer's online key */
#define FBR_LINE_NOW INT64_C(1000000)

struct fbr_ctx {
    bool present;
    bool root_fail;
    bool manager;
    uint8_t root_pub[32];
    char lines[8][ZCL_FLEET_ROSTER_LINE_MAX];
    size_t n_lines;
    bool remap;
    uint8_t remap_from[32];
    uint8_t remap_to[32];
    struct zcl_fleet_head head; /* the test double's roster head */
};
static struct fbr_ctx g_fbr;

static void fbr_root_pub(uint8_t id, uint8_t seed[32], uint8_t pub[32])
{
    uint8_t secret[32];
    memset(seed, id, 32);
    ed25519_keypair(pub, secret, seed);
    memset(secret, 0, sizeof secret);
}

static bool fbr_root_cb(uint8_t root[32], bool *present, bool *manager,
                        void *ctx)
{
    (void)ctx;
    if (g_fbr.root_fail)
        return false;
    *present = g_fbr.present;
    *manager = g_fbr.manager;
    memcpy(root, g_fbr.root_pub, 32);
    return true;
}

static bool fbr_verify_cb(const char *line, const uint8_t root[32],
                          enum zcl_fleet_root_state state, bool require,
                          uint8_t signer[32], uint8_t box[32], bool *sealed,
                          const char **why,
                          void *ctx)
{
    (void)ctx;
    const struct zcl_fleet_roster_provider *real = zcl_fleet_roster_gate_provider();
    bool ok = real->verify(line, root, state, require, signer, box, sealed, why,
                           real->ctx);
    if (ok && g_fbr.remap && memcmp(signer, g_fbr.remap_from, 32) == 0)
        memcpy(signer, g_fbr.remap_to, 32);
    return ok;
}

static void fbr_head_cb(const uint8_t root[32], struct zcl_fleet_head *out,
                        void *ctx)
{
    (void)root;
    (void)ctx;
    *out = g_fbr.head;
}

static bool fbr_each_cb(void (*visit)(const char *line, void *user),
                        void *user, void *ctx)
{
    (void)ctx;
    for (size_t i = 0; i < g_fbr.n_lines; i++)
        visit(g_fbr.lines[i], user);
    return true;
}

static void fbr_install(uint8_t root_id, bool manager)
{
    uint8_t seed[32];
    static const struct zcl_fleet_roster_provider provider = {
        .root = fbr_root_cb, .verify = fbr_verify_cb, .head = fbr_head_cb,
        .each_line = fbr_each_cb, .ctx = NULL, .name = "fleet-board-test" };
    memset(&g_fbr, 0, sizeof g_fbr);
    g_fbr.present = true;
    g_fbr.manager = manager;
    fbr_root_pub(root_id, seed, g_fbr.root_pub);
    memset(seed, 0, sizeof seed);
    zcl_fleet_roster_provider_install(&provider);
    boot_fleet_roster_test_reset();
}

static void fbr_uninstall(void)
{
    zcl_fleet_roster_provider_install(NULL);
    memset(&g_fbr, 0, sizeof g_fbr);
    boot_fleet_roster_test_reset();
}

/* One sealed machine line: `root_id` seals a receipt for `name` whose board
 * signing key is test identity `signer_id`. */
static bool fbr_line(uint8_t root_id, const char *name, uint8_t signer_id,
                     char *out, size_t cap)
{
    uint8_t op_seed[32], op_pub[32], box_seed[32], box_pub[32];
    uint8_t invite_wire[FLEET_ENROL_INVITE_WIRE_MAX];
    uint8_t receipt_wire[FLEET_ENROL_RECEIPT_WIRE_MAX];
    char token[FLEET_ENROL_MACHINE_TEXT_MAX];
    char receipt[FLEET_ENROL_MACHINE_TEXT_MAX];
    struct fleet_invite invite;
    struct fleet_receipt parsed;
    struct fleet_box_facts facts;
    struct fleet_signing_key signer;
    size_t invite_len = 0, receipt_len = 0;
    const char *why = NULL;
    memset(&facts, 0, sizeof facts);
    (void)snprintf(facts.hostname, sizeof facts.hostname, "%s", name);
    fbr_root_pub(root_id, op_seed, op_pub);
    fbr_root_pub((uint8_t)(0x80 + signer_id), box_seed, box_pub);
    fb_test_identity(signer_id, signer.seed, signer.pubkey);
    return fleet_invite_mint(name, 24, "", op_seed, op_pub, FBR_LINE_NOW,
                             token, sizeof token, &invite, &why) &&
           fleet_invite_parse(token, &invite, invite_wire, sizeof invite_wire,
                              &invite_len, &why) &&
           fleet_receipt_mint(invite_wire, invite_len, "", &facts, "",
                              box_seed, box_pub, &signer, receipt,
                              sizeof receipt, &why) &&
           fleet_receipt_parse(receipt, &parsed, receipt_wire,
                               sizeof receipt_wire, &receipt_len, &why) &&
           fleet_machine_mint(receipt_wire, receipt_len, FBR_LINE_NOW,
                              FLEET_ENROL_PORT_FIRST, op_seed, op_pub, out,
                              cap, &why);
}

/* Store one roster-shaped row (a fleet-scope note) in `db` straight through
 * the store's own ingest, as if it had been accepted earlier, authored by
 * test identity `author` and living `ttl` seconds. `id` (optional) receives
 * the row id. This deliberately skips the roster screen: the screen is what
 * the ingress tests prove, and these rows are how they plant junk. */
static bool fbr_store_row_id(struct node_db *db, uint8_t author,
                             const char *line, int64_t now, uint32_t ttl,
                             uint8_t id[32])
{
    uint8_t seed[32], pk[32];
    struct fleet_board_post p;
    fb_test_identity(author, seed, pk);
    fb_test_compose(&p, FLEET_BOARD_KIND_NOTE, BOOT_FLEET_ROSTER_AGENT, line,
                    (uint64_t)now, ttl);
    fb_test_scope(&p, FLEET_BOARD_SCOPE_FLEET, "");
    bool ok = fleet_board_post_sign(&p, seed, pk) == FLEET_BOARD_OK &&
              db_fleet_board_post_ingest(db, &p, now, NULL) == FLEET_BOARD_OK;
    if (ok && id)
        memcpy(id, p.id, 32);
    boot_fleet_roster_invalidate();
    return ok;
}

static bool fbr_store_row(struct node_db *db, uint8_t author,
                          const char *line, int64_t now, uint32_t ttl)
{
    return fbr_store_row_id(db, author, line, now, ttl, NULL);
}
static void fbr_key(uint8_t id, uint8_t pub[32])
{
    uint8_t seed[32];
    fb_test_identity(id, seed, pub);
    memset(seed, 0, sizeof seed);
}
static void frc_sign_as(enum fleet_board_roster_side side, uint8_t id)
{
    uint8_t seed[32], pk[32];
    fb_test_identity(id, seed, pk);
    boot_fleet_board_fleet_test_roster_identity((int)side, seed, pk);
    memset(seed, 0, sizeof seed);
}

/* Each side signs as the box it stands in for. */
static void frc_boxes(uint8_t asking, uint8_t answering)
{
    frc_sign_as(FLEET_BOARD_ROSTER_SIDE_ASK, asking);
    frc_sign_as(FLEET_BOARD_ROSTER_SIDE_ANSWER, answering);
    /* The answering box is the one that pushes its own posts. */
    frc_sign_as(FLEET_BOARD_ROSTER_SIDE_PUSH, answering);
}

static void frc_ask_begin(struct fbw *w)
{
    mesh_loop_discard(w->asker, w->ask_q, w->f.res_term);
    mesh_loop_discard(w->answerer, w->answer_q, w->f.term_peer.ini);
    mesh_stream_test_reset();
}

/* The OPEN reaches the answering box, it answers, and the answer is committed
 * into `into`. */
static size_t frc_finish(struct fbw *w, struct node_db *into, size_t *frames)
{
    *frames = 0;
    if (mesh_loop_pump(w->asker, w->ask_q, w->f.res_term, &w->mp,
                       w->answerer) != 1)
        return SIZE_MAX;
    boot_fleet_board_fleet_test_serve(); /* the answer, when there is one */
    boot_fleet_board_fleet_test_serve(); /* nothing left: close */
    *frames = mesh_loop_pump(w->answerer, w->answer_q, w->f.term_peer.ini,
                             &w->mp, w->asker);
    return boot_fleet_board_fleet_test_drain_into(into);
}

/* One whole roster pull over the real encrypted stream path. */
static size_t frc_pull(struct fbw *w, struct node_db *into, size_t *frames)
{
    frc_ask_begin(w);
    if (!boot_fleet_board_fleet_test_pull_roster(&w->svc, w->f.resp_noise_pub))
        return SIZE_MAX;
    return frc_finish(w, into, frames);
}

static bool frc_plant(struct node_db *a, struct node_db *b, const char *name,
                      uint8_t signer, int64_t now)
{
    char line[FLEET_ENROL_MACHINE_TEXT_MAX];
    return fbr_line(FBR_ROOT, name, signer, line, sizeof line) &&
           fbr_store_row(a, 1, line, now, FBC_TTL) &&
           (!b || fbr_store_row(b, 1, line, now, FBC_TTL));
}

static void frc_revoke(uint8_t id)
{
    g_fbr.head.state = ZCL_FLEET_HEAD_OK;
    g_fbr.head.count = 1;
    fbr_key(id, g_fbr.head.revoked[0]);
    boot_fleet_roster_invalidate();
}

static void frc_unrevoke(void)
{
    memset(&g_fbr.head, 0, sizeof g_fbr.head);
    boot_fleet_roster_invalidate();
}
static size_t frc_to_asker(struct fbw *w)
{
    return mesh_loop_pump(w->answerer, w->answer_q, w->f.term_peer.ini, &w->mp,
                          w->asker);
}

static size_t frc_to_answerer(struct fbw *w)
{
    return mesh_loop_pump(w->asker, w->ask_q, w->f.res_term, &w->mp, w->answerer);
}

static size_t frc_offer(struct fbw *w, const char *text, int64_t at,
                        struct fleet_board_post *post, bool fanout)
{
    uint8_t own[32], target[32];
    char to[65];
    fbr_key(FBR_MEMBER, own);
    fbr_key(FBR_PEER, target);
    zcl_hex_encode(target, 32, to);
    if (!fbw_post(&w->a, FBR_MEMBER, FLEET_BOARD_SCOPE_FLEET, text, at,
                  FBC_TTL, at, post))
        return SIZE_MAX;
    enum fleet_board_push_hint hint = fanout
        ? boot_fleet_board_fleet_push_enqueue_all(post, own, to)
        : boot_fleet_board_fleet_push_enqueue_to(post, own, to);
    if (hint != FLEET_BOARD_PUSH_HINT_QUEUED)
        return SIZE_MAX;
    return boot_fleet_board_fleet_test_push_send_at(&w->svc, &w->a, at);
}

static int frc_addressed_cases(void)
{
    int failures = 0;
    static struct fbw w;
    struct fleet_board_post post, second;
    struct p2p_node *competing = NULL;
    struct send_segment *competing_q = NULL;
    struct p2p_node *nodes[3];
    struct zcl_fleet_role_checker checker = {
        .allow = fbw_role_check, .name = "fleet-board-addressed-test" };
    struct boot_fleet_board_fleet_counts before, after;
    size_t frames = 0;
    g_fbw_deny_read = false;
    zcl_fleet_role_checker_install(&checker);
    bool opened = fbw_open(&w);
    TEST("addressed roster push sends once, retries busy and records storage") {
        struct db_fleet_board_delivery delivered;
        ASSERT(opened);
        boot_fleet_board_fleet_test_bind_authority(&w.f.term_peer.delegation,
                                                   w.f.genesis, FBW_NOW);
        boot_fleet_board_fleet_test_bind(&w.a);
        fbr_install(FBR_ROOT, false);
        ASSERT(frc_plant(&w.a, &w.b, "answerbox", FBR_MEMBER, FBW_NOW));
        ASSERT(frc_plant(&w.a, &w.b, "askbox", FBR_PEER, FBW_NOW));
        fleet_board_roster_forget();
        frc_boxes(FBR_PEER, FBR_MEMBER);
        ASSERT(frc_pull(&w, &w.b, &frames) != SIZE_MAX);
        boot_fleet_board_fleet_counts(&before);
        ASSERT_EQ(frc_offer(&w, "addressed", 2501, &post, true), (size_t)0);
        ASSERT_EQ(frc_offer(&w, "busy", 2502, &second, false), (size_t)0);
        boot_fleet_board_fleet_counts(&after);
        ASSERT_EQ(after.push_fanout_no_session, before.push_fanout_no_session);
        ASSERT_EQ(frc_to_asker(&w), (size_t)1);
        ASSERT_EQ(boot_fleet_board_roster_push_test_commit(&w.b), (size_t)1);
        ASSERT(frc_to_answerer(&w) >= 1);
        ASSERT(board_delivery_flush(&w.a) >= 1);
        ASSERT_EQ(db_fleet_board_delivery_for_post(&w.a, post.id, &delivered, 1), 1);
        ASSERT_EQ(delivered.verdict, (int64_t)FLEET_BOARD_DELIVERY_STORED);
        (void)boot_fleet_board_fleet_test_push_send_at(&w.svc, &w.a, 2503);
        ASSERT_EQ(frc_to_asker(&w), (size_t)1);
        ASSERT_EQ(boot_fleet_board_roster_push_test_commit(&w.b), (size_t)1);
        ASSERT(db_fleet_board_have(&w.b, second.id));
        ASSERT(frc_to_answerer(&w) >= 1);
        PASS();
    }
    TEST("addressed roster push refuses a revoked recipient") {
        frc_revoke(FBR_PEER);
        ASSERT_EQ(frc_offer(&w, "revoked", 2504, &post, false), (size_t)0);
        ASSERT_EQ(frc_to_asker(&w), (size_t)0);
        ASSERT(!db_fleet_board_have(&w.b, post.id));
        frc_unrevoke();
        PASS();
    }
    TEST("addressed roster push refuses the wrong board key") {
        uint8_t own[32], wrong[32];
        char to[65];
        fbr_key(FBR_MEMBER, own);
        fbr_key(FBR_STRANGER, wrong);
        zcl_hex_encode(wrong, 32, to);
        ASSERT(fbw_post(&w.a, FBR_MEMBER, FLEET_BOARD_SCOPE_FLEET, "wrong key",
                        2505, FBC_TTL, 2505, &post));
        ASSERT_EQ(boot_fleet_board_fleet_push_enqueue_to(&post, own, to),
                  FLEET_BOARD_PUSH_HINT_QUEUED);
        (void)boot_fleet_board_fleet_test_push_send_at(&w.svc, &w.a, 2505);
        ASSERT_EQ(frc_to_asker(&w), (size_t)0);
        PASS();
    }
    TEST("addressed roster push refuses competing learned Noise identities") {
        struct net_address addr = {0};
        struct noise_transport_snapshot snap;
        uint8_t target[32], frame[MESH_LOOP_WIRE_MAX];
        bool more = false;
        addr.svc.port = 18035;
        competing = p2p_node_create(&w.nm, ZCL_INVALID_SOCKET, &addr,
                                    "competing", false);
        ASSERT(competing);
        competing->transport = w.f.res_status;
        competing->state = PEER_HANDSHAKE_COMPLETE;
        competing_q = mesh_loop_sentinel(competing);
        ASSERT(competing_q);
        ASSERT(noise_transport_snapshot(competing->transport, &snap));
        fbr_key(FBR_PEER, target);
        fleet_board_roster_learn(snap.remote_static, target, snap.transcript_hash,
                                 snap.connection_generation);
        nodes[0] = w.asker; nodes[1] = w.answerer; nodes[2] = competing;
        w.nm.nodes = nodes; w.nm.num_nodes = 3;
        boot_fleet_board_fleet_counts(&before);
        ASSERT_EQ(frc_offer(&w, "ambiguous", 2505, &post, false), (size_t)0);
        boot_fleet_board_fleet_counts(&after);
        ASSERT_EQ(after.push_skipped[FLEET_BOARD_PUSH_SKIP_AMBIGUOUS],
                  before.push_skipped[FLEET_BOARD_PUSH_SKIP_AMBIGUOUS] + 1);
        ASSERT_EQ(frc_to_asker(&w), (size_t)0);
        (void)mesh_loop_take(competing, competing_q, w.f.status_peer.ini,
                             frame, sizeof frame, &more);
        ASSERT(!more);
        w.nm.nodes = w.nodes; w.nm.num_nodes = 2;
        mesh_loop_free_queue(competing, competing_q);
        free(competing_q); competing_q = NULL;
        competing->transport = NULL; p2p_node_free(competing); competing = NULL;
        fleet_board_roster_forget();
        ASSERT(frc_pull(&w, &w.b, &frames) != SIZE_MAX);
        PASS();
    }
    TEST("addressed roster push refuses a recipient without read role") {
        g_fbw_deny_read = true;
        ASSERT_EQ(frc_offer(&w, "denied", 2505, &post, false), (size_t)0);
        ASSERT_EQ(frc_to_asker(&w), (size_t)0);
        g_fbw_deny_read = false;
        PASS();
    }
    TEST("addressed roster push leaves unsupported recipients to pull") {
        boot_fleet_board_roster_push_test_unknown(true);
        ASSERT_EQ(frc_offer(&w, "unsupported", 2506, &post, false), (size_t)0);
        ASSERT_EQ(frc_to_asker(&w), (size_t)1);
        ASSERT(frc_to_answerer(&w) >= 1);
        ASSERT_EQ(frc_offer(&w, "still unsupported", 2507, &second, false), (size_t)0);
        ASSERT_EQ(frc_to_asker(&w), (size_t)0);
        boot_fleet_board_roster_push_test_unknown(false);
        PASS();
    }
    _test_next:;
    w.nm.nodes = w.nodes; w.nm.num_nodes = 2;
    if (competing) {
        if (competing_q) mesh_loop_free_queue(competing, competing_q);
        free(competing_q);
        competing->transport = NULL; p2p_node_free(competing);
    }
    g_fbw_deny_read = false;
    boot_fleet_board_roster_push_test_unknown(false);
    boot_fleet_board_fleet_test_roster_identity(1, NULL, NULL);
    boot_fleet_board_fleet_test_roster_identity(2, NULL, NULL);
    boot_fleet_board_fleet_test_roster_identity((int)FLEET_BOARD_ROSTER_SIDE_PUSH, NULL, NULL);
    fbr_uninstall();
    fbw_close(&w);
    zcl_fleet_role_checker_install_permissive_for_testing();
    return failures;
}
int test_fleet_board_carriage(void)
{
    int failures = fbc_record_case1() + fbc_record_case2() +
                  fbc_record_case3() + fbc_record_case4();
    failures += fbc_status_cases();
    failures += fbc_driven_cases();
    failures += frc_addressed_cases();
    board_carriage_test_reset();
    return failures;
}
