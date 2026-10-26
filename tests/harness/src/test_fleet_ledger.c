/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The owner's private fleet ledger: what it stores, what it refuses, and
 * that a paired machine's rows arrive over the real stream wire.
 *
 * The refusals carry the weight here. A ledger that quietly accepted a
 * forged row would be a ledger nobody could quote, so every refusal is
 * checked BY NAME and the store is read back afterwards to prove that
 * nothing partial was written. The wire half runs the production service
 * callbacks over two real p2p nodes on the shared fixture's in-process
 * Noise pair — only the socket is elided — so the pull protocol is proven
 * as it ships rather than as the test wishes it were.
 */

#include "test/test_core.h"

#include "command/native_fleet.h"
#include "config/boot_fleet_ledger.h"
#include "config/boot_internal.h"
#include "config/mesh_stream.h"
#include "config/runtime.h"
#include "test/mesh_stream_fixture.h"
#include "test/mesh_stream_loopback.h"
#include "test/mesh_term_fixture.h"

#include "util/fleet_role_check.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "chainlog/chainlog.h"
#include "chain/chainparams.h"
#include "command/native_command.h"
#include "crypto/ed25519.h"
#include "controllers/agent_impact_rules.h"
#include "devloop.h"
#include "test/selection_build_needs.h"
#include "test_group_host_need.h"
#include "fleetledger/fleet_ledger.h"
#include "platform/private_file.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "models/mesh_pairing.h"
#include "models/zid_identity.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/noise_transport.h"
#include "net/protocol.h"
#include "platform/private_file.h"
#include "platform/time_compat.h"
#include "platform/clock.h"
#include "platform/os_proc.h"
#include "sha3/sha3.h"
#include "vcs/zcode_dht_identity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* A pairing window that brackets any clock this test could read: what is
 * graded is the lane's decision, never the hour the box thinks it is. */
#define FL_PAIRED_AT INT64_C(1)
#define FL_PAIRING_EXPIRES INT64_C(4102444800)
/* The clock the delegation authority is asked on. The accept callback is
 * handed no clock, so the seam names the hour once; the window above brackets
 * it, so the DELEGATION decides, never the hour. */
#define FL_AUTHORITY_NOW INT64_C(2500)

/* ── one box, made from nothing ──────────────────────────────────────── */

struct fl_box {
    char dir[320];
    uint8_t seed[32];
    uint8_t box_id[32]; /* stands in for the delegation's master key */
    uint8_t signer[32]; /* the online key it delegates, which signs rows */
    struct zcl_fleet_ledger *ledger;
};

/* box_id is deliberately NOT derived from the signing key: they are two
 * different keys in production, and a test that used one for both would
 * never catch a verifier checking the wrong one. */
static bool fl_box_open(struct fl_box *b, const char *root, const char *name,
                        uint8_t tag)
{
    memset(b, 0, sizeof(*b));
    if ((size_t)snprintf(b->dir, sizeof b->dir, "%s/%s", root, name) >=
        sizeof b->dir)
        return false;
    memset(b->seed, tag, sizeof b->seed);
    uint8_t sk[32];
    zcl_ed25519_keypair(b->signer, sk, b->seed);
    memset(b->box_id, (uint8_t)(tag ^ 0x5au), sizeof b->box_id);
    struct zcl_fleet_report report;
    b->ledger = zcl_fleet_ledger_open(b->dir, b->box_id, b->signer, &report);
    return b->ledger != NULL && report.status == ZCL_FLEET_OK;
}

static bool fl_wire_responder(struct mesh_term_fixture *f,
                               struct mesh_term_peer *peer,
                               struct fl_box *box, const char *root)
{
    uint8_t master_seed[32];
    memset(master_seed, 0x88, sizeof master_seed);
    memcpy(peer->noise_pub, f->resp_noise_pub, 32);
    if (vcs_zcode_dht_delegation_sign(
            &peer->delegation, f->genesis, f->resp_online_pub,
            f->resp_noise_pub, f->term_peer.delegation.beacon_height,
            f->term_peer.delegation.beacon_hash, 1000, 4000, 7,
            master_seed) != VCS_ZCODE_DHT_DELEGATION_OK)
        return false;
    memset(master_seed, 0, sizeof master_seed);
    struct zid_identity identity;
    if (!db_zid_identity_find(&f->ndb,
            f->term_peer.delegation.doc.master_pubkey, &identity))
        return false;
    memcpy(identity.master_pubkey, f->resp_master_pub, 32);
    if (!db_zid_identity_save(&f->ndb, &identity) ||
        !mesh_term_pair_row(f, peer, MESH_PAIRING_CAP_STATUS_READ,
                            FL_PAIRED_AT, FL_PAIRING_EXPIRES))
        return false;
    memset(box, 0, sizeof *box);
    if (snprintf(box->dir, sizeof box->dir, "%s/wire_a", root) >=
        (int)sizeof box->dir)
        return false;
    memcpy(box->seed, f->resp_online_seed, 32);
    memcpy(box->box_id, f->resp_master_pub, 32);
    memcpy(box->signer, f->resp_online_pub, 32);
    struct zcl_fleet_report report;
    box->ledger = zcl_fleet_ledger_open(box->dir, box->box_id, box->signer,
                                       &report);
    return box->ledger && report.status == ZCL_FLEET_OK;
}

static void fl_box_close(struct fl_box *b)
{
    zcl_fleet_ledger_close(b->ledger);
    b->ledger = NULL;
}

static enum zcl_fleet_status fl_add_usage(struct fl_box *b, uint16_t provider,
                                          int64_t in, int64_t out,
                                          const char *note)
{
    struct zcl_fleet_pair pairs[2];
    pairs[0].key = ZCL_FLEET_PAIR_TOKENS_IN;
    pairs[0].value = in;
    pairs[1].key = ZCL_FLEET_PAIR_TOKENS_OUT;
    pairs[1].value = out;
    return zcl_fleet_ledger_append(b->ledger, ZCL_FLEET_KIND_USAGE, provider,
                                   pairs, 2, note, NULL, b->seed, NULL);
}

static enum zcl_fleet_status fl_add_vital(struct fl_box *b, const char *id,
                                          int64_t value)
{
    uint16_t subject = 0;
    if (!zcl_fleet_subject_from_name(ZCL_FLEET_KIND_VITALS, id, &subject))
        return ZCL_FLEET_VITAL_UNKNOWN;
    struct zcl_fleet_pair pair = { ZCL_FLEET_PAIR_VALUE, value };
    return zcl_fleet_ledger_append(b->ledger, ZCL_FLEET_KIND_VITALS, subject,
                                   &pair, 1, NULL, NULL, b->seed, NULL);
}

static enum zcl_fleet_status fl_add_predict(struct fl_box *b, const char *id,
                                            uint8_t task_class, uint8_t harness,
                                            uint8_t model, uint8_t effort,
                                            int64_t tokens, int64_t wall_s)
{
    struct zcl_fleet_pair p[6];
    size_t n = 0;
    p[n].key = ZCL_FLEET_PAIR_TOKENS_IN;
    p[n++].value = tokens;
    p[n].key = ZCL_FLEET_PAIR_WALL_S;
    p[n++].value = wall_s;
    p[n].key = ZCL_FLEET_PAIR_TASK_CLASS;
    p[n++].value = task_class;
    p[n].key = ZCL_FLEET_PAIR_HARNESS;
    p[n++].value = harness;
    p[n].key = ZCL_FLEET_PAIR_MODEL;
    p[n++].value = model;
    p[n].key = ZCL_FLEET_PAIR_EFFORT;
    p[n++].value = effort;
    return zcl_fleet_ledger_append(b->ledger, ZCL_FLEET_KIND_EXPERIMENT,
                                   ZCL_FLEET_EXPERIMENT_PREDICT, p, n, id,
                                   NULL, b->seed, NULL);
}

/* Same as `fl_add_predict`, plus the two fields this lane adds: `story`
 * (free text) and `executor` (a closed-vocabulary pair, like model). Kept
 * as its own helper rather than growing every existing call site's
 * argument list. */
static enum zcl_fleet_status fl_add_predict_full(
    struct fl_box *b, const char *id, uint8_t task_class, uint8_t harness,
    uint8_t model, uint8_t effort, uint8_t executor, const char *story)
{
    struct zcl_fleet_pair p[5];
    size_t n = 0;
    p[n].key = ZCL_FLEET_PAIR_TASK_CLASS;
    p[n++].value = task_class;
    p[n].key = ZCL_FLEET_PAIR_HARNESS;
    p[n++].value = harness;
    p[n].key = ZCL_FLEET_PAIR_MODEL;
    p[n++].value = model;
    p[n].key = ZCL_FLEET_PAIR_EFFORT;
    p[n++].value = effort;
    p[n].key = ZCL_FLEET_PAIR_EXECUTOR;
    p[n++].value = executor;
    return zcl_fleet_ledger_append(b->ledger, ZCL_FLEET_KIND_EXPERIMENT,
                                   ZCL_FLEET_EXPERIMENT_PREDICT, p, n, id,
                                   story, b->seed, NULL);
}

static enum zcl_fleet_status fl_add_result(struct fl_box *b, const char *id,
                                           uint8_t task_class, uint8_t model,
                                           uint8_t outcome, int64_t tokens,
                                           int64_t wall_s)
{
    struct zcl_fleet_pair p[5];
    size_t n = 0;
    p[n].key = ZCL_FLEET_PAIR_TOKENS_IN;
    p[n++].value = tokens;
    p[n].key = ZCL_FLEET_PAIR_WALL_S;
    p[n++].value = wall_s;
    p[n].key = ZCL_FLEET_PAIR_TASK_CLASS;
    p[n++].value = task_class;
    p[n].key = ZCL_FLEET_PAIR_OUTCOME;
    p[n++].value = outcome;
    p[n].key = ZCL_FLEET_PAIR_MODEL;
    p[n++].value = model;
    return zcl_fleet_ledger_append(b->ledger, ZCL_FLEET_KIND_EXPERIMENT,
                                   ZCL_FLEET_EXPERIMENT_RESULT, p, n, id,
                                   NULL, b->seed, NULL);
}

/* Same as `fl_add_result`, plus `story`/`executor` — see
 * `fl_add_predict_full`. */
static enum zcl_fleet_status fl_add_result_full(
    struct fl_box *b, const char *id, uint8_t task_class, uint8_t model,
    uint8_t outcome, uint8_t executor, const char *story)
{
    struct zcl_fleet_pair p[4];
    size_t n = 0;
    p[n].key = ZCL_FLEET_PAIR_TASK_CLASS;
    p[n++].value = task_class;
    p[n].key = ZCL_FLEET_PAIR_OUTCOME;
    p[n++].value = outcome;
    p[n].key = ZCL_FLEET_PAIR_MODEL;
    p[n++].value = model;
    p[n].key = ZCL_FLEET_PAIR_EXECUTOR;
    p[n++].value = executor;
    return zcl_fleet_ledger_append(b->ledger, ZCL_FLEET_KIND_EXPERIMENT,
                                   ZCL_FLEET_EXPERIMENT_RESULT, p, n, id,
                                   story, b->seed, NULL);
}

static enum zcl_fleet_status fl_add_result_counters(
    struct fl_box *b, const char *id, uint8_t task_class, uint8_t model,
    uint8_t outcome, const struct zcl_fleet_pair *counters, size_t n_counters)
{
    struct zcl_fleet_pair p[7];
    if (n_counters > 4)
        return ZCL_FLEET_ARGUMENT;
    for (size_t i = 0; i < n_counters; i++)
        p[i] = counters[i];
    size_t n = n_counters;
    p[n].key = ZCL_FLEET_PAIR_TASK_CLASS;
    p[n++].value = task_class;
    p[n].key = ZCL_FLEET_PAIR_OUTCOME;
    p[n++].value = outcome;
    p[n].key = ZCL_FLEET_PAIR_MODEL;
    p[n++].value = model;
    return zcl_fleet_ledger_append(b->ledger, ZCL_FLEET_KIND_EXPERIMENT,
                                   ZCL_FLEET_EXPERIMENT_RESULT, p, n, id,
                                   NULL, b->seed, NULL);
}

#if !defined(_WIN32)
static int64_t fl_latest_wall_ms;

static int64_t fl_latest_wall(void *self)
{
    (void)self;
    return fl_latest_wall_ms;
}

static enum zcl_fleet_status fl_latest_at(struct fl_box *box,
                                         int64_t seconds, int64_t value)
{
    const clock_iface_t *saved = clock_default();
    const clock_iface_t fixed = { .now_wall_ms = fl_latest_wall };
    fl_latest_wall_ms = seconds * 1000;
    clock_set_default(&fixed);
    enum zcl_fleet_status status = fl_add_vital(box, "box.load1", value);
    clock_set_default(saved);
    return status;
}
#endif

/* The one usage bucket for a provider over today, or false. */
static bool fl_usage_bucket(struct zcl_fleet_ledger *ledger, uint16_t provider,
                            const uint8_t box_id[32],
                            struct zcl_fleet_bucket *out, uint64_t *index_us)
{
    struct zcl_fleet_query q;
    memset(&q, 0, sizeof q);
    q.kind = ZCL_FLEET_KIND_USAGE;
    q.have_subject = true;
    q.subject = provider;
    if (box_id) {
        q.have_box = true;
        memcpy(q.box_id, box_id, 32);
    }
    q.days = 1;
    q.now_unix = (int64_t)platform_time_wall_time_t();
    struct zcl_fleet_bucket buckets[8];
    size_t count = 0;
    if (zcl_fleet_ledger_query(ledger, &q, buckets, 8, &count, index_us) !=
            ZCL_FLEET_OK ||
        count != 1)
        return false;
    *out = buckets[0];
    return true;
}

/* Every row a box holds for itself, encoded as the wire carries them. */
static size_t fl_rows_of(struct fl_box *b, uint8_t *out, size_t cap)
{
    size_t len = 0;
    uint64_t last = 0;
    if (zcl_fleet_ledger_read_since(b->ledger, b->box_id, 0, out, cap, &len,
                                    &last) != ZCL_FLEET_OK)
        return 0;
    return len;
}

static bool fl_provision(const char *datadir, uint8_t box_id[32],
                         uint8_t signer[32])
{
    uint8_t seed[32], online[32], mseed[32], mpub[32], msk[32];
    uint8_t noise[32], beacon[32], genesis[32];
    char err[160];
    if (!vcs_zcode_dht_online_key_load_or_create(datadir, seed, online, err,
                                                 sizeof err))
        return false;
    memset(seed, 0, 32);
    memset(mseed, 0x22, 32);
    memset(noise, 0x33, 32);
    memset(beacon, 0x44, 32);
    memset(genesis, 0x55, 32);
    zcl_ed25519_keypair(mpub, msk, mseed);
    memset(msk, 0, 32);
    uint64_t now = (uint64_t)platform_time_wall_time_t();
    struct vcs_zcode_dht_delegation d;
    bool ok = vcs_zcode_dht_delegation_sign(
                  &d, genesis, online, noise, 1, beacon,
                  now > 10 ? now - 1 : 1, now + 3600, 1, mseed) ==
                  VCS_ZCODE_DHT_DELEGATION_OK &&
              vcs_zcode_dht_delegation_save(datadir, &d, err, sizeof err);
    memset(mseed, 0, 32);
    if (!ok)
        return false;
    memcpy(box_id, d.doc.master_pubkey, 32);
    memcpy(signer, online, 32);
    return true;
}

static int fl_host_uptime_test(const char *datadir)
{
    int failures = 0;
    TEST("fleet vitals snapshot: box uptime follows the machine clock") {
        /* Bracket the production snapshot rather than assuming how long the
         * machine or this collector has been running. Process age is a
         * different clock and cannot stand in for the boot-relative fact. */
        int64_t before = os_proc_system_uptime_seconds();
        int64_t values[ZCL_FLEET_HOST_N];
        bool present[ZCL_FLEET_HOST_N];
        zcl_fleet_host_snapshot(datadir, values, present);
        int64_t after = os_proc_system_uptime_seconds();
        if (before >= 0 && after >= 0) {
            ASSERT(present[7]);
            ASSERT(values[7] >= before);
            ASSERT(values[7] <= after);
        } else if (before < 0 && after < 0) {
            ASSERT(!present[7]);
        }
        PASS();
    } _test_next:;

    return failures;
}

static void fl_sample(struct json_value *input, struct zcl_command_reply *reply)
{
    struct zcl_command_request request = { .input = input };
    zcl_native_handle_fleet_vitals_sample(&request, reply);
}

/* Page-state predicates are shared by readonly and corruption witnesses. */
static bool fl_history_page_empty(const struct zcl_fleet_vitals_history *page)
{
    return !page->found && page->count == 0;
}

static bool fl_history_page_unpublished(const struct zcl_fleet_vitals_history *page)
{
    return fl_history_page_empty(page) && page->snapshot_head == 0;
}

#if !defined(_WIN32)
static int64_t fl_export_monotonic_ns(void *self)
{
    (void)self;
    return INT64_C(1000000000);
}

static int64_t fl_export_wall_ms(void *self)
{
    (void)self;
    return INT64_C(1700000000000);
}

static int fl_export_utf8_case(const char *sample, bool valid,
                                unsigned field, const char *escaped)
{
    int failures = 0;
    struct json_value input;
    struct zcl_command_reply reply = {0};
    json_init(&input);
    char dd[320] = {0};
    const clock_iface_t *saved_clock = clock_default();
    char saved_datadir[512];
    int saved_port = zcl_native_command_rpc_port();
    (void)snprintf(saved_datadir, sizeof saved_datadir, "%s",
                   zcl_native_command_datadir());
    static const clock_iface_t fixed_clock = {
        .now_monotonic_ns = fl_export_monotonic_ns,
        .now_wall_ms = fl_export_wall_ms,
    };
    clock_set_default(&fixed_clock);
    TEST("fleet export refuses malformed UTF-8 in either retained field") {
        char serialized[8192];
        ASSERT(test_mkdtemp(dd, sizeof dd, "fleet_export_utf8") != NULL);
        uint8_t box[32], signer[32];
        ASSERT(fl_provision(dd, box, signer));
        zcl_native_bridge_bind_rpc(dd, 0);
        json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "task_id", field ? sample : "t"));
        ASSERT(json_push_kv_str(&input, "story", field ? "s" : sample));
        ASSERT(json_push_kv_str(&input, "task_class", "read"));
        ASSERT(json_push_kv_str(&input, "harness", "manual"));
        ASSERT(json_push_kv_str(&input, "model", "grok"));
        ASSERT(json_push_kv_str(&input, "effort", "low"));
        struct zcl_command_request req = { .input = &input };
        zcl_native_handle_fleet_experiment_predict(&req, &reply);
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
        zcl_command_reply_free(&reply);
        json_free(&input);
        req.input = NULL;
        zcl_native_handle_fleet_experiment_export(&req, &reply);
        if (!valid) {
            ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_FAILED);
            ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
            ASSERT_STR_EQ(reply.error.code, "MALFORMED_TEXT");
            ASSERT(!reply.error.mutated);
            ASSERT(strstr(reply.error.message, "UTF-8") != NULL);
            ASSERT(json_get(&reply.data, "text") == NULL);
        } else {
            ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
            ASSERT_EQ(json_get_int(json_get(&reply.data, "rows")), INT64_C(1));
            const char *text = json_get_str(json_get(&reply.data, "text"));
            ASSERT(text != NULL && strstr(text, sample) != NULL);
            ASSERT(json_write(&reply.data, serialized, sizeof serialized) <
                   sizeof serialized);
            ASSERT(strstr(serialized, escaped) != NULL);
        }
        zcl_command_reply_free(&reply);
        ASSERT(test_rm_rf_recursive(dd) == 0);
        dd[0] = '\0';
        PASS();
    }

_test_next:
    zcl_command_reply_free(&reply);
    json_free(&input);
    zcl_native_bridge_bind_rpc(saved_datadir, saved_port);
    clock_set_default(saved_clock);
    if (dd[0]) {
        if (test_rm_rf_recursive(dd) != 0) {
            printf("FAIL cleanup: %s\n", dd);
            failures++;
        }
    }
    return failures;
}

static int fl_export_utf8_cases(void)
{
    static const char *const cases[] = {
        "\xff", "\xc3\x28", "\xe2\x82", "\xed\xa0\x80",
        "\xc0\xaf", "\xf4\x90\x80\x80", "a\"b\\c", "\xf0\x9f\x98\x80"
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        const char *escaped = i == 6 ? "a\\\"b\\\\c" : cases[i];
        for (unsigned field = 0; field < 2; field++)
            failures += fl_export_utf8_case(cases[i], i >= 6, field, escaped);
    }
    return failures;
}

static int fl_open_refusal_location(void)
{
    int failures = 0;
    char root[256], peer[320], path[416], hex[65];
    uint8_t id[32] = {0x42}, stream[32], zero[32] = {0};
    struct zcl_fleet_report report;
    struct zcl_chainlog_report lower;
    struct zcl_fleet_ledger *ledger = NULL;
    struct zcl_chainlog *log = NULL;
    struct platform_private_file file;
    platform_private_file_init(&file);
    test_make_tmpdir(root, sizeof root, "fleet_ledger", "refusal_location");
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)"zcl.fleet_ledger.chain.v1",
                   sizeof("zcl.fleet_ledger.chain.v1"));
    sha3_256_write(&ctx, id, sizeof id);
    sha3_256_finalize(&ctx, stream);
    zcl_hex_encode(id, sizeof id, hex);
    TEST("fleet ledger: peer open refusals name the chain and sequence") {
        ASSERT((size_t)snprintf(peer, sizeof peer, "%s/peer", root) < sizeof peer);
        ASSERT((size_t)snprintf(path, sizeof path, "%s/%s.chainlog", peer, hex) < sizeof path);
        ledger = zcl_fleet_ledger_open(root, NULL, NULL, &report);
        ASSERT(ledger && report.status == ZCL_FLEET_OK);
        zcl_fleet_ledger_close(ledger); ledger = NULL;
        log = zcl_chainlog_open(path, stream, &lower);
        ASSERT(log && lower.status == ZCL_CHAINLOG_OK);
        ASSERT(zcl_chainlog_append(log, 2, "x", 1, NULL, NULL) == ZCL_CHAINLOG_OK);
        zcl_chainlog_close(log); log = NULL;
        ASSERT(zcl_chainlog_verify(path, stream, &lower) == ZCL_CHAINLOG_OK);
        ASSERT(lower.records == 1);
        ledger = zcl_fleet_ledger_open(root, NULL, NULL, &report);
        ASSERT(!ledger && report.status == ZCL_FLEET_IO);
        ASSERT(memcmp(report.bad_box, id, sizeof id) == 0);
        ASSERT(report.first_bad_seq == 1);
        ASSERT(platform_private_file_open_locked_wait(path, &file));
        const uint8_t altered = 'y';
        ASSERT(platform_private_file_write_at(&file, &altered, 1,
            ZCL_CHAINLOG_HEADER_BYTES + ZCL_CHAINLOG_PREFIX_BYTES));
        ASSERT(platform_private_file_flush(&file));
        platform_private_file_close(&file);
        ASSERT(zcl_chainlog_verify(path, stream, &lower) == ZCL_CHAINLOG_BROKEN_CHAIN);
        ASSERT(lower.first_bad_seq == 1);
        ledger = zcl_fleet_ledger_open_readonly(root, NULL, NULL, &report);
        ASSERT(!ledger && report.status == ZCL_FLEET_CHAIN_BROKEN);
        ASSERT(memcmp(report.bad_box, id, sizeof id) == 0);
        ASSERT(report.first_bad_seq == lower.first_bad_seq);
        ASSERT(unlink(path) == 0);
        log = zcl_chainlog_open(path, zero, &lower);
        ASSERT(log && lower.status == ZCL_CHAINLOG_OK);
        zcl_chainlog_close(log); log = NULL;
        ASSERT(zcl_chainlog_verify(path, stream, &lower) == ZCL_CHAINLOG_STREAM_MISMATCH);
        ledger = zcl_fleet_ledger_open_readonly(root, NULL, NULL, &report);
        ASSERT(!ledger && report.status == ZCL_FLEET_IO);
        ASSERT(memcmp(report.bad_box, id, sizeof id) == 0);
        ASSERT(report.first_bad_seq == lower.first_bad_seq && report.first_bad_seq == 0);
        ASSERT(unlink(path) == 0);
        ledger = zcl_fleet_ledger_open_readonly(root, id, stream, &report);
        ASSERT(ledger && report.status == ZCL_FLEET_OK);
        ASSERT(report.rows == 0 && report.first_bad_seq == 0);
        ASSERT(memcmp(report.bad_box, zero, sizeof zero) == 0);
        ASSERT(access(path, F_OK) != 0);
        ASSERT((size_t)snprintf(path, sizeof path, "%s/self.chainlog", root) < sizeof path);
        ASSERT(access(path, F_OK) != 0);
        PASS();
    } _test_next:;
    platform_private_file_close(&file);
    zcl_chainlog_close(log);
    zcl_fleet_ledger_close(ledger);
    if (test_rm_rf_recursive(root) != 0) {
        printf("FAIL cleanup: %s\n", root);
        failures++;
    }
    return failures;
}

/* The admission regression is selected for a production-only edit even when
 * no dependency graph is available. Keep this check in its focused group. */
static bool fl_admission_routes(void)
{
    const char *path = "engine/modules/fleetledger/src/fleet_ledger.c";
    struct agent_impact_acc impact = {0};
    if (!agent_impact_apply_shared_rules(path, &impact) || impact.groups_lost)
        return false;
    bool admission = false, lint = false;
    for (size_t i = 0; i < impact.groups_len; i++) {
        admission |= strcmp(impact.groups[i], "fleet_ledger") == 0;
        lint |= strcmp(impact.groups[i], "make_lint_gates") == 0;
    }
    struct zcl_devloop_plan plan;
    if (!zcl_devloop_plan_files(&path, 1, &plan))
        return false;
    bool planned = false;
    for (size_t i = 0; i < plan.path_groups_len; i++)
        planned |= strcmp(plan.path_groups[i], "fleet_ledger") == 0;
    struct zcl_test_group_host_need needs[1];
    size_t count = 99;
    bool selected = zcl_test_selection_build_needs("test_fleet_ledger", true,
                                                  NULL, needs, 1, &count);
    return admission && lint && planned && selected && count == 0 &&
           plan.closure_groups_len == 0 &&
           plan.dims[ZCL_DEVLOOP_DIM_SEMANTIC].status ==
               ZCL_DEVLOOP_DIM_UNAVAILABLE &&
           plan.dims[ZCL_DEVLOOP_DIM_INCLUDE].status ==
               ZCL_DEVLOOP_DIM_UNAVAILABLE;
}

/* Exercise admission independently of the large wire fixture and wall time. */
static int fl_admission_regression(void)
{
    int failures = 0;
    char root[256];
    test_make_tmpdir(root, sizeof root, "fleet_ledger", "admission");
    struct zcl_fleet_report report;
    struct zcl_fleet_ledger *ledger = zcl_fleet_ledger_open(root, NULL, NULL,
                                                         &report);
    zcl_fleet_role_checker_install_permissive_for_testing();
    TEST("fleet ledger: rejected batches leave peer capacity available") {
        ASSERT(fl_admission_routes());
        ASSERT(ledger != NULL);
        ASSERT_EQ(report.status, ZCL_FLEET_OK);
        struct zcl_fleet_box_status boxes[ZCL_FLEET_BOXES_MAX];
        const uint8_t malformed[] = { 0xff };
        uint8_t peer[ZCL_FLEET_ID_BYTES];
        uint8_t seed[32] = { 0x11 }, signer[32], secret[32];
        zcl_ed25519_keypair(signer, secret, seed);
        size_t accepted = 99;
        for (size_t i = 0; i < ZCL_FLEET_BOXES_MAX; i++) {
            memset(peer, (int)(0x80u + i), sizeof peer);
            ASSERT_EQ(zcl_fleet_ledger_replicate(ledger, peer, signer,
                      malformed, sizeof malformed, &accepted),
                      ZCL_FLEET_MALFORMED);
            ASSERT_EQ(accepted, (size_t)0);
            ASSERT_EQ(zcl_fleet_ledger_boxes(ledger, boxes,
                      ZCL_FLEET_BOXES_MAX), (size_t)0);
        }
        /* An empty pull from an unknown peer consumes no capacity. */
        accepted = 99;
        ASSERT_EQ(zcl_fleet_ledger_replicate(ledger, peer, signer, NULL, 0,
                  &accepted), ZCL_FLEET_OK);
        ASSERT_EQ(accepted, (size_t)0);
        ASSERT_EQ(zcl_fleet_ledger_boxes(ledger, boxes, ZCL_FLEET_BOXES_MAX),
                  (size_t)0);
        struct zcl_fleet_row first = { 0 };
        first.version = ZCL_FLEET_ROW_VERSION;
        first.kind = ZCL_FLEET_KIND_USAGE;
        first.subject = ZCL_FLEET_PROVIDER_GROK;
        first.seq = 1;
        first.ts_unix = FL_AUTHORITY_NOW;
        memset(first.box_id, 0x21, sizeof first.box_id);
        memcpy(first.signer, signer, sizeof signer);
        ASSERT_EQ(zcl_fleet_row_sign(&first, seed), ZCL_FLEET_OK);
        uint8_t rows[ZCL_FLEET_ROW_MAX_BYTES];
        size_t len = zcl_fleet_row_encode(&first, rows, sizeof rows);
        ASSERT(len > 0);
        ASSERT_EQ(zcl_fleet_ledger_replicate(ledger, first.box_id, signer,
                  rows, len, &accepted), ZCL_FLEET_OK);
        ASSERT_EQ(accepted, (size_t)1);
        for (size_t i = 0; i < 2; i++) {
            /* Duplicate and empty pulls preserve the existing peer. */
            accepted = 99;
            ASSERT_EQ(zcl_fleet_ledger_replicate(ledger, first.box_id, signer,
                      rows, i == 0 ? len : 0, &accepted), ZCL_FLEET_OK);
            ASSERT_EQ(accepted, (size_t)0);
            ASSERT_EQ(zcl_fleet_ledger_boxes(ledger, boxes,
                      ZCL_FLEET_BOXES_MAX), (size_t)1);
            ASSERT(memcmp(boxes[0].box_id, first.box_id,
                          sizeof first.box_id) == 0);
            ASSERT_EQ(boxes[0].last_seq, UINT64_C(1));
            ASSERT_EQ(boxes[0].rows, UINT64_C(1));
            ASSERT_EQ(zcl_fleet_ledger_peer_seq(ledger, first.box_id),
                      UINT64_C(1));
        }
        PASS();
    }
_test_next:
    zcl_fleet_ledger_close(ledger);
    zcl_fleet_role_checker_install(NULL);
    test_rm_rf_recursive(root);
    return failures;
}

static int test_fleet_ledger_observation(void)
{
    int failures = fl_admission_regression();
    failures += fl_open_refusal_location();
    failures += fl_export_utf8_cases();
    char root[256], dir[320], peer[352], self[352];
    struct stat info;
    struct zcl_fleet_report report;
    struct zcl_fleet_ledger *ledger = NULL;
    uint8_t id[32] = {1}, signer[32] = {2}, seed[32] = {3};
    test_make_tmpdir(root, sizeof(root), "fleet_ledger", "readonly");
    (void)snprintf(dir, sizeof(dir), "%s/ledger", root);
    (void)snprintf(peer, sizeof(peer), "%s/peer", dir);
    (void)snprintf(self, sizeof(self), "%s/self.chainlog", dir);
    TEST("fleet ledger: readonly open preserves absence, modes and torn evidence") {
        struct zcl_fleet_vitals_history page;
        ASSERT_EQ(zcl_fleet_ledger_vitals_history_readonly(dir, id, signer,
            id, -1, 0, 1, &page, &report), ZCL_FLEET_IO);
        ASSERT(fl_history_page_empty(&page));
        ASSERT(lstat(dir, &info) != 0);
        ledger = zcl_fleet_ledger_open_readonly(dir, id, signer, &report);
        ASSERT(!ledger);
        ASSERT(lstat(dir, &info) != 0);
        ASSERT(mkdir(dir, 0700) == 0);
        ledger = zcl_fleet_ledger_open_readonly(dir, id, signer, &report);
        ASSERT(ledger);
        ASSERT(report.rows == 0);
        ASSERT(lstat(peer, &info) != 0 && lstat(self, &info) != 0);
        ASSERT(zcl_fleet_ledger_append(ledger, ZCL_FLEET_KIND_USAGE, 1,
            NULL, 0, NULL, NULL, seed, NULL) == ZCL_FLEET_ARGUMENT);
        size_t accepted = 0;
        ASSERT(zcl_fleet_ledger_replicate(ledger, id, signer, NULL, 0,
            &accepted) == ZCL_FLEET_ARGUMENT);
        zcl_fleet_ledger_close(ledger); ledger = NULL;
        ASSERT(chmod(dir, 0500) == 0);
        ledger = zcl_fleet_ledger_open_readonly(dir, id, signer, &report);
        ASSERT(!ledger && stat(dir, &info) == 0 && (info.st_mode & 0777) == 0500);
        ASSERT(chmod(dir, 0755) == 0);
        ledger = zcl_fleet_ledger_open_readonly(dir, id, signer, &report);
        ASSERT(!ledger && stat(dir, &info) == 0 && (info.st_mode & 0777) == 0755);
        ledger = zcl_fleet_ledger_open(dir, id, signer, &report);
        ASSERT(ledger && stat(dir, &info) == 0 && (info.st_mode & 0777) == 0700);
        zcl_fleet_ledger_close(ledger); ledger = NULL;
        struct platform_private_file held;
        platform_private_file_init(&held);
        ASSERT(platform_private_file_open_locked_wait(self, &held));
        ledger = zcl_fleet_ledger_open_readonly(dir, id, signer, &report);
        ASSERT(!ledger);
        ASSERT(report.status == ZCL_FLEET_IO);
        platform_private_file_close(&held);
        ASSERT(geteuid() != 0);
        ASSERT(chmod(self, 0400) == 0);
        ledger = zcl_fleet_ledger_open_readonly(dir, id, signer, &report);
        ASSERT(ledger);
        zcl_fleet_ledger_close(ledger); ledger = NULL;
        ASSERT(chmod(self, 0600) == 0);
        FILE *file = fopen(self, "ab");
        ASSERT(file != NULL);
        size_t written = fwrite("torn", 1, 4, file);
        int closed = fclose(file);
        ASSERT(written == 4 && closed == 0);
        ASSERT(stat(self, &info) == 0);
        struct stat before = info;
        ledger = zcl_fleet_ledger_open_readonly(dir, id, signer, &report);
        ASSERT(!ledger && report.status == ZCL_FLEET_IO);
        ASSERT_EQ(zcl_fleet_ledger_vitals_history_readonly(dir, id, signer,
            id, -1, 0, 1, &page, &report), ZCL_FLEET_IO);
        ASSERT(fl_history_page_empty(&page));
        ASSERT(stat(self, &info) == 0 && info.st_size == before.st_size &&
            info.st_mtime == before.st_mtime && info.st_mode == before.st_mode);
        ledger = zcl_fleet_ledger_open(dir, id, signer, &report);
        ASSERT(ledger && stat(self, &info) == 0 && info.st_size + 4 == before.st_size);
        PASS();
    } _test_next:;
    zcl_fleet_ledger_close(ledger);
    test_rm_rf_recursive(root);
    return failures;
}
#endif

static bool fl_replay_routes(void)
{
    static const char *const paths[] = {
        "engine/modules/fleetledger/src/fleet_ledger_replay.c",
        "engine/modules/fleetledger/src/fleet_ledger_replay.h"
    };
    for (size_t p = 0; p < sizeof paths / sizeof paths[0]; p++) {
        struct agent_impact_acc impact = {0};
        if (!agent_impact_apply_shared_rules(paths[p], &impact) || impact.groups_lost)
            return false;
        bool ledger = false, lint = false;
        for (size_t i = 0; i < impact.groups_len; i++) {
            ledger |= strcmp(impact.groups[i], "fleet_ledger") == 0;
            lint |= strcmp(impact.groups[i], "make_lint_gates") == 0;
        }
        if (!ledger || !lint) return false;
    }
    return true;
}

static int fl_history_cases(const char *root)
{
    int failures = 0;
    struct fl_box b = {0};
    TEST("fleet history pages scan gaps, distinguish absent/zero and retain head") {
        ASSERT(fl_replay_routes());
        ASSERT(fl_box_open(&b, root, "history", 0x73));
        uint16_t subject = 0;
        ASSERT(zcl_fleet_subject_from_name(ZCL_FLEET_KIND_VITALS,
                                           "box.load1", &subject));
        ASSERT_EQ(fl_add_vital(&b, "box.load1", 0), ZCL_FLEET_OK);
        ASSERT_EQ(zcl_fleet_ledger_append(b.ledger, ZCL_FLEET_KIND_VITALS,
            subject, NULL, 0, NULL, NULL, b.seed, NULL), ZCL_FLEET_OK);
        for (size_t i = 0; i < 65; i++)
            ASSERT_EQ(fl_add_vital(&b, "spend.tokens_in", 1), ZCL_FLEET_OK);
#if !defined(_WIN32)
        ASSERT_EQ(fl_latest_at(&b, 1700000000, 8), ZCL_FLEET_OK);
#else
        ASSERT_EQ(fl_add_vital(&b, "box.load1", 8), ZCL_FLEET_OK);
#endif
        struct zcl_fleet_report report;
        struct zcl_fleet_vitals_history page;
        ASSERT_EQ(zcl_fleet_ledger_vitals_history_readonly(b.dir, b.box_id,
            b.signer, b.box_id, subject, 0, 1, &page, &report), ZCL_FLEET_OK);
        ASSERT(page.found && page.more);
        ASSERT_EQ(page.count, (size_t)1);
        ASSERT_EQ(page.rows[0].pair[0].value, INT64_C(0));
        ASSERT_EQ(page.next_seq, UINT64_C(1));
        ASSERT_EQ(page.snapshot_head, UINT64_C(68));
        uint8_t head[32];
        memcpy(head, page.snapshot_hash, sizeof head);
        ASSERT_EQ(zcl_fleet_ledger_vitals_history_readonly(b.dir, b.box_id,
            b.signer, b.box_id, subject, 1, 64, &page, &report), ZCL_FLEET_OK);
        ASSERT_EQ(page.count, (size_t)1);
        ASSERT_EQ(page.rows[0].pair_count, 0);
        ASSERT_EQ(page.next_seq, UINT64_C(65));
        ASSERT(page.more);
        ASSERT_EQ(zcl_fleet_ledger_vitals_history_readonly(b.dir, b.box_id,
            b.signer, b.box_id, subject, 65, 64, &page, &report), ZCL_FLEET_OK);
        ASSERT_EQ(page.count, (size_t)1);
        ASSERT_EQ(page.rows[0].seq, UINT64_C(68));
#if !defined(_WIN32)
        ASSERT_EQ(page.rows[0].ts_unix, INT64_C(1700000000));
#endif
        ASSERT_EQ(page.next_seq, UINT64_C(68));
        ASSERT(!page.more);
        ASSERT(memcmp(head, page.snapshot_hash, sizeof head) == 0);
        PASS();
    }
    TEST("fleet history refuses overflowing cursors and preserves missing box") {
        struct zcl_fleet_report report;
        struct zcl_fleet_vitals_history page;
        uint8_t unknown[32] = {0x99};
        ASSERT_EQ(zcl_fleet_ledger_vitals_history_readonly(b.dir, b.box_id,
            b.signer, unknown, -1, 0, 64, &page, &report), ZCL_FLEET_OK);
        ASSERT(!page.found && !page.more && page.count == 0);
        ASSERT_EQ(zcl_fleet_ledger_vitals_history_readonly(b.dir, b.box_id,
            b.signer, b.box_id, -1, 100, 64, &page, &report), ZCL_FLEET_OK);
        ASSERT(page.found && !page.more && page.count == 0);
        ASSERT_EQ(page.next_seq, UINT64_C(100));
        ASSERT_EQ(page.snapshot_head, UINT64_C(68));
        ASSERT_EQ(zcl_fleet_ledger_vitals_history_readonly(b.dir, b.box_id,
            b.signer, b.box_id, -1, UINT64_MAX, 64, &page, &report),
            ZCL_FLEET_ARGUMENT);
        ASSERT(fl_history_page_empty(&page));
        PASS();
    }
_test_next:
    fl_box_close(&b);
    return failures;
}

static int fl_history_late_failure(const char *root)
{
    int failures = 0;
    struct fl_box b = {0};
    struct zcl_chainlog *log = NULL;
    TEST("fleet history publishes nothing when a later signed row refuses") {
        ASSERT(fl_box_open(&b, root, "history-late", 0x74));
        ASSERT_EQ(fl_add_vital(&b, "box.load1", 7), ZCL_FLEET_OK);
        struct zcl_fleet_report report;
        struct zcl_fleet_vitals_history page;
        ASSERT_EQ(zcl_fleet_ledger_vitals_history_readonly(b.dir, b.box_id,
            b.signer, b.box_id, -1, 0, 1, &page, &report), ZCL_FLEET_OK);
        struct zcl_fleet_row row = page.rows[0];
        row.seq = 2;
        memcpy(row.prev_hash, page.snapshot_hash, sizeof row.prev_hash);
        ASSERT_EQ(zcl_fleet_row_sign(&row, b.seed), ZCL_FLEET_OK);
        row.sig[0] ^= 1;
        uint8_t encoded[ZCL_FLEET_ROW_MAX_BYTES], stream[32];
        size_t n = zcl_fleet_row_encode(&row, encoded, sizeof encoded);
        ASSERT(n > 0);
        struct sha3_256_ctx ctx;
        sha3_256_init(&ctx);
        sha3_256_write(&ctx, (const unsigned char *)"zcl.fleet_ledger.chain.v1",
                       sizeof("zcl.fleet_ledger.chain.v1"));
        sha3_256_write(&ctx, b.box_id, sizeof b.box_id);
        sha3_256_finalize(&ctx, stream);
        char path[400];
        ASSERT((size_t)snprintf(path, sizeof path, "%s/self.chainlog", b.dir)
               < sizeof path);
        struct zcl_chainlog_report lower;
        log = zcl_chainlog_open(path, stream, &lower);
        ASSERT(log);
        ASSERT_EQ(zcl_chainlog_append(log, 1, encoded, n, NULL, NULL),
                  ZCL_CHAINLOG_OK);
        zcl_chainlog_close(log); log = NULL;
        ASSERT_EQ(zcl_fleet_ledger_vitals_history_readonly(b.dir, b.box_id,
            b.signer, b.box_id, -1, 0, 1, &page, &report), ZCL_FLEET_SIG_INVALID);
        ASSERT_EQ(report.first_bad_seq, UINT64_C(2));
        ASSERT(fl_history_page_unpublished(&page));
        PASS();
    }
_test_next:
    zcl_chainlog_close(log);
    fl_box_close(&b);
    return failures;
}

static int fl_latest_cases(const char *root)
{
    int failures = 0;
    struct fl_box lv = {0}, replica = {0};
    TEST("fleet latest vitals retain sequence, absence and row time across replay") {
        ASSERT(fl_box_open(&lv, root, "latest", 0x71));
        ASSERT(fl_box_open(&replica, root, "latest-replica", 0x72));
        uint16_t load = 0, sum = 0;
        ASSERT(zcl_fleet_subject_from_name(ZCL_FLEET_KIND_VITALS,
                                           "box.load1", &load));
        ASSERT(zcl_fleet_subject_from_name(ZCL_FLEET_KIND_VITALS,
                                           "spend.tokens_in", &sum));
        ASSERT_EQ(fl_add_vital(&lv, "box.load1", 9), ZCL_FLEET_OK);
        ASSERT_EQ(zcl_fleet_ledger_append(lv.ledger, ZCL_FLEET_KIND_VITALS,
                       load, NULL, 0, NULL, NULL, lv.seed, NULL), ZCL_FLEET_OK);
        struct zcl_fleet_vital_latest rows[4];
        size_t count = 99;
        ASSERT_EQ(zcl_fleet_ledger_vitals_latest(lv.ledger, lv.box_id, load,
                       rows, 4, &count), ZCL_FLEET_OK);
        ASSERT_EQ(count, (size_t)1);
        ASSERT_EQ(rows[0].seq, UINT64_C(2));
        ASSERT(!rows[0].present);
        ASSERT_EQ(fl_add_vital(&lv, "box.load1", 0), ZCL_FLEET_OK);
        ASSERT_EQ(fl_add_vital(&lv, "spend.tokens_in", 11), ZCL_FLEET_OK);
        ASSERT_EQ(fl_add_vital(&lv, "spend.tokens_in", 7), ZCL_FLEET_OK);
        ASSERT_EQ(zcl_fleet_ledger_vitals_latest(lv.ledger, NULL, -1,
                       rows, 1, &count), ZCL_FLEET_FULL);
        ASSERT_EQ(count, (size_t)1);
        ASSERT_EQ(zcl_fleet_ledger_vitals_latest(lv.ledger, NULL, -1,
                       NULL, 0, &count), ZCL_FLEET_FULL);
        ASSERT_EQ(count, (size_t)0);
        ASSERT_EQ(zcl_fleet_ledger_vitals_latest(lv.ledger, lv.box_id, load,
                       rows, 4, &count), ZCL_FLEET_OK);
        ASSERT(rows[0].present);
        ASSERT_EQ(rows[0].value, INT64_C(0));
        ASSERT_EQ(rows[0].seq, UINT64_C(3));
#if !defined(_WIN32)
        /* Chain order remains authoritative across a backwards UTC-day jump. */
        ASSERT_EQ(fl_latest_at(&lv, INT64_C(1700172800), 41), ZCL_FLEET_OK);
        ASSERT_EQ(fl_latest_at(&lv, INT64_C(1700000000), 42), ZCL_FLEET_OK);
        ASSERT_EQ(zcl_fleet_ledger_vitals_latest(lv.ledger, lv.box_id, load,
                       rows, 4, &count), ZCL_FLEET_OK);
        ASSERT_EQ(rows[0].seq, UINT64_C(7));
        ASSERT_EQ(rows[0].ts_unix, INT64_C(1700000000));
        ASSERT_EQ(rows[0].value, INT64_C(42));
        /* A later unknown sample must not inherit a preceding value or time. */
        ASSERT_EQ(zcl_fleet_ledger_append(lv.ledger, ZCL_FLEET_KIND_VITALS,
                       load, NULL, 0, NULL, NULL, lv.seed, NULL), ZCL_FLEET_OK);
        ASSERT_EQ(zcl_fleet_ledger_vitals_latest(lv.ledger, lv.box_id, load,
                       rows, 4, &count), ZCL_FLEET_OK);
        ASSERT_EQ(rows[0].seq, UINT64_C(8));
        ASSERT(!rows[0].present);
#endif
        struct zcl_fleet_vital_latest expected[4];
        ASSERT_EQ(zcl_fleet_ledger_vitals_latest(lv.ledger, NULL, -1,
                       expected, 4, &count), ZCL_FLEET_OK);
        ASSERT_EQ(count, (size_t)2);
        ASSERT_EQ(expected[1].subject, sum);
        ASSERT_EQ(expected[1].value, INT64_C(7));
        uint8_t wire[8192];
        size_t len = fl_rows_of(&lv, wire, sizeof wire), accepted = 0;
        ASSERT(len > 0);
        ASSERT_EQ(zcl_fleet_ledger_replicate(replica.ledger, lv.box_id,
                       lv.signer, wire, len, &accepted), ZCL_FLEET_OK);
        uint64_t expected_max_seq = expected[0].seq > expected[1].seq
            ? expected[0].seq : expected[1].seq;
        ASSERT_EQ(accepted, (size_t)expected_max_seq);
        fl_box_close(&lv);
        struct zcl_fleet_report report;
        lv.ledger = zcl_fleet_ledger_open_readonly(lv.dir, lv.box_id,
                                                  lv.signer, &report);
        ASSERT(lv.ledger);
        ASSERT_EQ(zcl_fleet_ledger_vitals_latest(lv.ledger, NULL, -1,
                       rows, 4, &count), ZCL_FLEET_OK);
        ASSERT_EQ(count, (size_t)2);
        for (size_t i = 0; i < count; i++) {
            ASSERT_EQ(rows[i].seq, expected[i].seq);
            ASSERT_EQ(rows[i].ts_unix, expected[i].ts_unix);
            ASSERT_EQ(rows[i].value, expected[i].value);
            ASSERT_EQ(rows[i].present, expected[i].present);
        }
        ASSERT_EQ(zcl_fleet_ledger_vitals_latest(replica.ledger, lv.box_id,
                       -1, rows, 4, &count), ZCL_FLEET_OK);
        ASSERT_EQ(count, (size_t)2);
        for (size_t i = 0; i < count; i++) {
            ASSERT_EQ(rows[i].seq, expected[i].seq);
            ASSERT_EQ(rows[i].ts_unix, expected[i].ts_unix);
            ASSERT_EQ(rows[i].value, expected[i].value);
            ASSERT_EQ(rows[i].present, expected[i].present);
        }
        ASSERT_EQ(zcl_fleet_ledger_vitals_latest(lv.ledger, NULL, -2,
                       rows, 4, &count), ZCL_FLEET_ARGUMENT);
        ASSERT_EQ(count, (size_t)0);
        ASSERT_EQ(zcl_fleet_ledger_vitals_latest(lv.ledger, NULL,
                       (int)zcl_fleet_vital_count(), rows, 4, &count),
                  ZCL_FLEET_VITAL_UNKNOWN);
        ASSERT_EQ(zcl_fleet_ledger_vitals_latest(lv.ledger, NULL, -1,
                       NULL, 1, &count), ZCL_FLEET_ARGUMENT);
        uint8_t unknown_box[32];
        memset(unknown_box, 0xee, sizeof unknown_box);
        ASSERT_EQ(zcl_fleet_ledger_vitals_latest(lv.ledger, unknown_box, -1,
                       rows, 4, &count), ZCL_FLEET_OK);
        ASSERT_EQ(count, (size_t)0);
        PASS();
    }

_test_next:
    fl_box_close(&lv);
    fl_box_close(&replica);
    return failures;
}

static int fl_vitals_sample_cases(char sample_dd[], uint8_t sample_box[],
                                  uint8_t sample_signer[])
{
    int failures = 0;
    TEST("fleet vitals sample: catalog ids measured-or-ABSENT; unknown id "
         "refuses by name; second sample appends a new seq") {
        struct zcl_command_reply reply;
        fl_sample(NULL, &reply);
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
        int64_t rows = json_get_int(json_get(&reply.data, "rows"));
        ASSERT(rows > 0);
        zcl_command_reply_free(&reply);
        char ldir[400];
        struct zcl_fleet_report report;
        ASSERT((size_t)snprintf(ldir, sizeof ldir, "%s/fleet_ledger",
                                sample_dd) < sizeof ldir);
        struct zcl_fleet_ledger *led =
            zcl_fleet_ledger_open(ldir, sample_box, sample_signer, &report);
        ASSERT(led);
        struct zcl_fleet_query q;
        memset(&q, 0, sizeof q);
        q.kind = ZCL_FLEET_KIND_VITALS;
        q.days = 1;
        q.now_unix = (int64_t)platform_time_wall_time_t();
        q.have_box = true;
        memcpy(q.box_id, sample_box, 32);
        struct zcl_fleet_bucket buckets[64];
        size_t count = 0;
        ASSERT_EQ(zcl_fleet_ledger_query(led, &q, buckets, 64, &count, NULL),
                  ZCL_FLEET_OK);
        ASSERT_EQ(count, (size_t)rows);
        for (size_t i = 0; i < count; i++) {
            ASSERT(zcl_fleet_vital_id(buckets[i].subject));
            uint8_t st = buckets[i].state[ZCL_FLEET_PAIR_VALUE];
            ASSERT(st == (uint8_t)ZCL_FLEET_FIELD_PRESENT ||
                   st == (uint8_t)ZCL_FLEET_FIELD_ABSENT);
            if (st == (uint8_t)ZCL_FLEET_FIELD_ABSENT)
                ASSERT_EQ(buckets[i].value[ZCL_FLEET_PAIR_VALUE], INT64_C(0));
        }
        uint64_t before = zcl_fleet_ledger_peer_seq(led, sample_box);
        zcl_fleet_ledger_close(led);

        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "id", "box.invented_metric"));
        fl_sample(&input, &reply);
        json_free(&input);
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "VITAL_UNKNOWN");
        ASSERT(strstr(reply.error.evidence, "box.invented_metric"));
        zcl_command_reply_free(&reply);

        fl_sample(NULL, &reply);
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get_int(json_get(&reply.data, "seq_first")) >
               (int64_t)before);
        zcl_command_reply_free(&reply);
        led = zcl_fleet_ledger_open(ldir, sample_box, sample_signer, &report);
        ASSERT(led);
        ASSERT(zcl_fleet_ledger_peer_seq(led, sample_box) > before);
        zcl_fleet_ledger_close(led);
        PASS();
    }

_test_next:
    return failures;
}

static int fl_experiment_cases(const char *root, struct fl_box *ex_out,
                               bool *ex_open_out)
{
    int failures = 0;
    struct fl_box ex = {0};
    bool ex_open = false;
    TEST("fleet ledger: predict then result then stats, and a result "
         "without a predict is unpredicted") {
        ASSERT(fl_box_open(&ex, root, "exp", 0x41));
        ex_open = true;
        uint8_t task_class = 0, task_verify = 0, harness = 0;
        uint8_t model = 0, model_codex = 0, effort = 0, outcome = 0;
        ASSERT(zcl_fleet_experiment_enum_from_name("task_class", "read",
                                                   &task_class) &&
               zcl_fleet_experiment_enum_stored("task_class", task_class));
        ASSERT(zcl_fleet_experiment_enum_from_name("harness", "manual",
                                                   &harness) &&
               zcl_fleet_experiment_enum_stored("harness", harness));
        ASSERT(zcl_fleet_experiment_enum_from_name("model", "grok", &model) &&
               zcl_fleet_experiment_enum_stored("model", model));
        ASSERT(zcl_fleet_experiment_enum_from_name("task_class", "verify",
                                                   &task_verify) &&
               zcl_fleet_experiment_enum_stored("task_class", task_verify));
        ASSERT(zcl_fleet_experiment_enum_from_name("model", "codex",
                                                   &model_codex) &&
               zcl_fleet_experiment_enum_stored("model", model_codex));
        ASSERT(zcl_fleet_experiment_enum_from_name("effort", "low", &effort) &&
               zcl_fleet_experiment_enum_stored("effort", effort));
        ASSERT(zcl_fleet_experiment_enum_from_name("outcome", "LAND",
                                                   &outcome) &&
               zcl_fleet_experiment_enum_stored("outcome", outcome));
        ASSERT_EQ(fl_add_predict(&ex, "t-exp-1", task_class, harness, model,
                                 effort, 100, 10),
                  ZCL_FLEET_OK);
        ASSERT_EQ(fl_add_result(&ex, "t-exp-1", task_class, model, outcome, 80,
                                12),
                  ZCL_FLEET_OK);
        struct zcl_fleet_experiment_group groups[8];
        size_t count = 0;
        uint64_t unpredicted = 0;
        ASSERT_EQ(zcl_fleet_ledger_experiment_stats(ex.ledger, groups, 8,
                                                    &count, &unpredicted, NULL),
                  ZCL_FLEET_OK);
        ASSERT_EQ(count, (size_t)1);
        ASSERT_EQ(groups[0].task_class, task_class);
        ASSERT_EQ(groups[0].model, model);
        ASSERT_EQ(groups[0].predicts, UINT64_C(1));
        ASSERT_EQ(groups[0].results, UINT64_C(1));
        ASSERT_EQ(groups[0].lands, UINT64_C(1));
        ASSERT_EQ(groups[0].unpredicted, UINT64_C(0));
        ASSERT_EQ(unpredicted, UINT64_C(0));
        ASSERT_EQ(groups[0].have_median_wall, (uint8_t)1);
        ASSERT_EQ(groups[0].median_wall_s, INT64_C(12));
        ASSERT_EQ(groups[0].have_median_tokens, (uint8_t)1);
        ASSERT_EQ(groups[0].median_tokens, INT64_C(80));
        ASSERT_EQ(groups[0].have_pred_actual, (uint8_t)1);
        ASSERT_EQ(groups[0].pred_actual_bp, INT64_C(12500));

        ASSERT_EQ(fl_add_result(&ex, "t-orphan", task_class, model, outcome, 50,
                                8),
                  ZCL_FLEET_OK);
        ASSERT_EQ(zcl_fleet_ledger_experiment_stats(ex.ledger, groups, 8,
                                                    &count, &unpredicted, NULL),
                  ZCL_FLEET_OK);
        ASSERT_EQ(count, (size_t)1);
        ASSERT_EQ(groups[0].predicts, UINT64_C(1));
        ASSERT_EQ(groups[0].results, UINT64_C(2));
        ASSERT_EQ(groups[0].unpredicted, UINT64_C(1));
        ASSERT_EQ(unpredicted, UINT64_C(1));

        /* A task ID is not enough to pair observations. Freeze collisions
         * differing only by model and only by task class before adding the
         * corresponding predictions. */
        ASSERT_EQ(fl_add_predict(&ex, "t-model-scope", task_class, harness,
                                 model, effort, 300, 9),
                  ZCL_FLEET_OK);
        ASSERT_EQ(fl_add_result(&ex, "t-model-scope", task_class, model_codex,
                                outcome, 100, 11),
                  ZCL_FLEET_OK);
        ASSERT_EQ(fl_add_predict(&ex, "t-class-scope", task_class, harness,
                                 model_codex, effort, 400, 13),
                  ZCL_FLEET_OK);
        ASSERT_EQ(fl_add_result(&ex, "t-class-scope", task_verify, model_codex,
                                outcome, 200, 15),
                  ZCL_FLEET_OK);
        ASSERT_EQ(zcl_fleet_ledger_experiment_stats(ex.ledger, groups, 8,
                                                    &count, &unpredicted, NULL),
                  ZCL_FLEET_OK);
        ASSERT_EQ(count, (size_t)3);
        ASSERT_EQ(groups[1].task_class, task_class);
        ASSERT_EQ(groups[1].model, model_codex);
        ASSERT_EQ(groups[1].unpredicted, UINT64_C(1));
        ASSERT_EQ(groups[1].have_pred_actual, (uint8_t)0);
        ASSERT_EQ(groups[2].task_class, task_verify);
        ASSERT_EQ(groups[2].model, model_codex);
        ASSERT_EQ(groups[2].unpredicted, UINT64_C(1));
        ASSERT_EQ(groups[2].have_pred_actual, (uint8_t)0);
        ASSERT_EQ(unpredicted, UINT64_C(3));

        /* The matching prediction follows a conflicting one in ledger order;
         * the ratio must use the prediction in the result's own group. */
        ASSERT_EQ(fl_add_predict(&ex, "t-model-scope", task_class, harness,
                                 model_codex, effort, 50, 10),
                  ZCL_FLEET_OK);
        ASSERT_EQ(fl_add_predict(&ex, "t-class-scope", task_verify, harness,
                                 model_codex, effort, 80, 14),
                  ZCL_FLEET_OK);
        ASSERT_EQ(zcl_fleet_ledger_experiment_stats(ex.ledger, groups, 8,
                                                    &count, &unpredicted, NULL),
                  ZCL_FLEET_OK);
        ASSERT_EQ(groups[1].unpredicted, UINT64_C(0));
        ASSERT_EQ(groups[1].have_pred_actual, (uint8_t)1);
        ASSERT_EQ(groups[1].pred_actual_bp, INT64_C(5000));
        ASSERT_EQ(groups[2].unpredicted, UINT64_C(0));
        ASSERT_EQ(groups[2].have_pred_actual, (uint8_t)1);
        ASSERT_EQ(groups[2].pred_actual_bp, INT64_C(4000));
        ASSERT_EQ(unpredicted, UINT64_C(1));

        uint8_t task_docs = 0, model_glm = 0;
        ASSERT(zcl_fleet_experiment_enum_from_name("task_class", "unit_docs",
                                                   &task_docs));
        ASSERT(zcl_fleet_experiment_enum_from_name("model", "glm",
                                                   &model_glm));
        const struct zcl_fleet_pair observed[] = {
            { ZCL_FLEET_PAIR_TOKENS_IN, INT64_C(13320) },
            { ZCL_FLEET_PAIR_TOKENS_OUT, INT64_C(1362) },
            { ZCL_FLEET_PAIR_TOKENS_CACHED, INT64_C(100) },
            { ZCL_FLEET_PAIR_TOKENS_REASONING, INT64_C(1199) },
        };
        const struct zcl_fleet_pair reasoning_only[] = {
            { ZCL_FLEET_PAIR_TOKENS_REASONING, INT64_C(1199) },
        };
        const struct zcl_fleet_pair measured_zero[] = {
            { ZCL_FLEET_PAIR_TOKENS_IN, INT64_C(0) },
            { ZCL_FLEET_PAIR_TOKENS_OUT, INT64_C(0) },
            { ZCL_FLEET_PAIR_TOKENS_CACHED, INT64_C(0) },
            { ZCL_FLEET_PAIR_TOKENS_REASONING, INT64_C(0) },
        };
        ASSERT_EQ(fl_add_result_counters(&ex, "t-token-subsets", task_docs,
                                         model, outcome, observed,
                                         sizeof observed / sizeof observed[0]),
                  ZCL_FLEET_OK);
        ASSERT_EQ(fl_add_result_counters(
                      &ex, "t-reasoning-only", task_docs, model_glm, outcome,
                      reasoning_only,
                      sizeof reasoning_only / sizeof reasoning_only[0]),
                  ZCL_FLEET_OK);
        ASSERT_EQ(fl_add_result_counters(
                      &ex, "t-measured-zero", task_docs, model_codex, outcome,
                      measured_zero,
                      sizeof measured_zero / sizeof measured_zero[0]),
                  ZCL_FLEET_OK);
        ASSERT_EQ(zcl_fleet_ledger_experiment_stats(ex.ledger, groups, 8,
                                                    &count, &unpredicted, NULL),
                  ZCL_FLEET_OK);
        ASSERT_EQ(count, (size_t)6);
        ASSERT_EQ(groups[3].task_class, task_docs);
        ASSERT_EQ(groups[3].model, model);
        ASSERT_EQ(groups[3].have_median_tokens, (uint8_t)1);
        ASSERT_EQ(groups[3].median_tokens, INT64_C(14682));
        ASSERT_EQ(groups[4].task_class, task_docs);
        ASSERT_EQ(groups[4].model, model_glm);
        ASSERT_EQ(groups[4].have_median_tokens, (uint8_t)0);
        ASSERT_EQ(groups[5].task_class, task_docs);
        ASSERT_EQ(groups[5].model, model_codex);
        ASSERT_EQ(groups[5].have_median_tokens, (uint8_t)1);
        ASSERT_EQ(groups[5].median_tokens, INT64_C(0));
        PASS();
    }

    TEST("fleet ledger: an experiment row's story and executor round-trip "
         "through zcl_fleet_ledger_experiment_rows, and its since/box "
         "filters narrow the walk") {
        /* A fresh, dedicated box: the since-floor check below turns on
         * "before every row this box holds" versus "before none of them",
         * and a box shared with an earlier TEST block could, at whole-
         * second clock resolution, hold a row stamped the very same
         * second as `before` — a real flake, not a bug in the filter. */
        struct fl_box rt;
        ASSERT(fl_box_open(&rt, root, "exp-rowtrip", 0x46));
        uint8_t task_class = 0, harness = 0, model = 0, effort = 0,
                outcome = 0, executor_grok = 0;
        ASSERT(zcl_fleet_experiment_enum_from_name("task_class", "read",
                                                   &task_class));
        ASSERT(zcl_fleet_experiment_enum_from_name("harness", "manual",
                                                   &harness));
        ASSERT(zcl_fleet_experiment_enum_from_name("model", "grok", &model));
        ASSERT(zcl_fleet_experiment_enum_from_name("effort", "low", &effort));
        ASSERT(zcl_fleet_experiment_enum_from_name("outcome", "LAND",
                                                   &outcome));
        ASSERT(zcl_fleet_experiment_enum_from_name("executor", "grok",
                                                   &executor_grok));

        int64_t before = (int64_t)platform_time_wall_time_t();
        ASSERT_EQ(fl_add_predict_full(&rt, "t-row-story", task_class, harness,
                                      model, effort, executor_grok,
                                      "alpha-story"),
                  ZCL_FLEET_OK);
        ASSERT_EQ(fl_add_result_full(&rt, "t-row-story", task_class, model,
                                     outcome, executor_grok, "alpha-story"),
                  ZCL_FLEET_OK);
        ASSERT_EQ(fl_add_predict(&rt, "t-row-plain", task_class, harness,
                                 model, effort, 10, 5),
                  ZCL_FLEET_OK);

        struct zcl_fleet_experiment_row rows[32];
        size_t count = 0;
        ASSERT_EQ(zcl_fleet_ledger_experiment_rows(rt.ledger, 0, NULL, false,
                                                   rows, 32, &count),
                  ZCL_FLEET_OK);
        ASSERT_EQ(count, (size_t)3);

        bool found_story = false, found_plain = false;
        for (size_t i = 0; i < count; i++) {
            if (strcmp(rows[i].task_id, "t-row-story") == 0 &&
                rows[i].phase == ZCL_FLEET_EXPERIMENT_PREDICT) {
                found_story = true;
                ASSERT_STR_EQ(rows[i].story, "alpha-story");
                ASSERT_EQ(rows[i].have_executor, (uint8_t)1);
                ASSERT_EQ(rows[i].executor, executor_grok);
            }
            if (strcmp(rows[i].task_id, "t-row-plain") == 0) {
                found_plain = true;
                ASSERT_STR_EQ(rows[i].story, "");
                ASSERT_EQ(rows[i].have_executor, (uint8_t)0);
            }
        }
        ASSERT(found_story);
        ASSERT(found_plain);

        /* since in the future excludes every row just written. */
        size_t future_count = 999;
        ASSERT_EQ(zcl_fleet_ledger_experiment_rows(rt.ledger, before + 3600,
                                                   NULL, false, rows, 32,
                                                   &future_count),
                  ZCL_FLEET_OK);
        ASSERT_EQ(future_count, (size_t)0);

        /* since at or before the first append keeps every row this fresh
         * box holds. */
        size_t since_count = 0;
        ASSERT_EQ(zcl_fleet_ledger_experiment_rows(rt.ledger, before, NULL,
                                                   false, rows, 32,
                                                   &since_count),
                  ZCL_FLEET_OK);
        ASSERT_EQ(since_count, (size_t)3);

        /* box filter: a box id that never wrote here keeps nothing; this
         * box's own id keeps every row. */
        uint8_t other_box[32];
        memset(other_box, 0xee, sizeof other_box);
        size_t other_count = 999;
        ASSERT_EQ(zcl_fleet_ledger_experiment_rows(rt.ledger, 0, other_box,
                                                   true, rows, 32,
                                                   &other_count),
                  ZCL_FLEET_OK);
        ASSERT_EQ(other_count, (size_t)0);

        size_t own_count = 0;
        ASSERT_EQ(zcl_fleet_ledger_experiment_rows(rt.ledger, 0, rt.box_id,
                                                   true, rows, 32,
                                                   &own_count),
                  ZCL_FLEET_OK);
        ASSERT_EQ(own_count, count);
        fl_box_close(&rt);
        PASS();
    }

    TEST("fleet ledger: a bad task_class and a bad harness refuse by "
         "name") {
        if (!ex_open) {
            ASSERT(fl_box_open(&ex, root, "exp-enum", 0x42));
            ex_open = true;
        }
        uint8_t value = 0;
        ASSERT(!zcl_fleet_experiment_enum_from_name("task_class",
                                                    "not_a_class", &value));
        ASSERT(!zcl_fleet_experiment_enum_from_name("harness", "not_a_harness",
                                                    &value));
        ASSERT(zcl_fleet_experiment_enum_from_name("task_class", "unknown",
                                                   &value));
        ASSERT(!zcl_fleet_experiment_enum_stored("task_class", value));
        ASSERT_STR_EQ(zcl_fleet_status_label(ZCL_FLEET_EXPERIMENT_ENUM),
                      "experiment_enum");

        uint8_t task_class = 0, harness = 0, model = 0, effort = 0;
        ASSERT(zcl_fleet_experiment_enum_from_name("task_class", "read",
                                                   &task_class));
        ASSERT(zcl_fleet_experiment_enum_from_name("harness", "manual",
                                                   &harness));
        ASSERT(zcl_fleet_experiment_enum_from_name("model", "grok", &model));
        ASSERT(zcl_fleet_experiment_enum_from_name("effort", "low", &effort));
        struct zcl_fleet_pair bad_class[4];
        size_t n = 0;
        bad_class[n].key = ZCL_FLEET_PAIR_TASK_CLASS;
        bad_class[n++].value = 99;
        bad_class[n].key = ZCL_FLEET_PAIR_HARNESS;
        bad_class[n++].value = harness;
        bad_class[n].key = ZCL_FLEET_PAIR_MODEL;
        bad_class[n++].value = model;
        bad_class[n].key = ZCL_FLEET_PAIR_EFFORT;
        bad_class[n++].value = effort;
        ASSERT_EQ(zcl_fleet_ledger_append(
                      ex.ledger, ZCL_FLEET_KIND_EXPERIMENT,
                      ZCL_FLEET_EXPERIMENT_PREDICT, bad_class, n, "t-bad-class",
                      NULL, ex.seed, NULL),
                  ZCL_FLEET_EXPERIMENT_ENUM);
        struct zcl_fleet_pair bad_harness[4];
        n = 0;
        bad_harness[n].key = ZCL_FLEET_PAIR_TASK_CLASS;
        bad_harness[n++].value = task_class;
        bad_harness[n].key = ZCL_FLEET_PAIR_HARNESS;
        bad_harness[n++].value = 99;
        bad_harness[n].key = ZCL_FLEET_PAIR_MODEL;
        bad_harness[n++].value = model;
        bad_harness[n].key = ZCL_FLEET_PAIR_EFFORT;
        bad_harness[n++].value = effort;
        ASSERT_EQ(zcl_fleet_ledger_append(
                      ex.ledger, ZCL_FLEET_KIND_EXPERIMENT,
                      ZCL_FLEET_EXPERIMENT_PREDICT, bad_harness, n,
                      "t-bad-harness", NULL, ex.seed, NULL),
                  ZCL_FLEET_EXPERIMENT_ENUM);
        PASS();
    }

_test_next:
    *ex_out = ex;
    *ex_open_out = ex_open;
    return failures;
}

static int fl_tamper_cases(const char *root, struct fl_box *ta_out,
                           bool *ta_open_out)
{
    int failures = 0;
    struct fl_box ta = {0};
    bool ta_open = false;
    TEST("fleet ledger: a tampered middle row refuses the whole chain, and "
         "the altered file is left as the evidence") {
        ASSERT(fl_box_open(&ta, root, "tamper", 0x61));
        ta_open = true;
        ASSERT_EQ(fl_add_usage(&ta, ZCL_FLEET_PROVIDER_MUSE, 1, 1, "aaa"),
                  ZCL_FLEET_OK);
        ASSERT_EQ(fl_add_usage(&ta, ZCL_FLEET_PROVIDER_MUSE, 2, 2, "bbb"),
                  ZCL_FLEET_OK);
        ASSERT_EQ(fl_add_usage(&ta, ZCL_FLEET_PROVIDER_MUSE, 3, 3, "ccc"),
                  ZCL_FLEET_OK);
        fl_box_close(&ta);
        ta_open = false;

        char path[400];
        ASSERT((size_t)snprintf(path, sizeof path, "%s/self.chainlog",
                                ta.dir) < sizeof path);
        struct platform_private_file file;
        platform_private_file_init(&file);
        ASSERT(platform_private_file_open_locked_wait(path, &file));
        uint64_t size = 0;
        ASSERT(platform_private_file_size(&file, &size));
        ASSERT(size > 0 && size < 65536);
        uint8_t *image = zcl_malloc((size_t)size, "fl_tamper_image");
        ASSERT(image != NULL);
        ASSERT(platform_private_file_read_at(&file, image, (size_t)size, 0));
        /* The middle row's own note, so the flipped byte is provably inside
         * a committed row's payload and not in a header or a sentinel. */
        uint64_t at = 0;
        bool found = false;
        for (uint64_t i = 0; i + 3 <= size && !found; i++)
            if (memcmp(image + i, "bbb", 3) == 0) {
                at = i;
                found = true;
            }
        free(image);
        ASSERT(found);
        uint8_t byte = 0;
        ASSERT(platform_private_file_read_at(&file, &byte, 1, at));
        byte ^= 0x40u;
        ASSERT(platform_private_file_write_at(&file, &byte, 1, at));
        ASSERT(platform_private_file_flush(&file));
        platform_private_file_close(&file);

        struct zcl_fleet_report report;
        memset(&report, 0, sizeof report);
        struct zcl_fleet_ledger *refused =
            zcl_fleet_ledger_open(ta.dir, ta.box_id, ta.signer, &report);
        /* Refused, named, and NOT repaired: an altered chain is evidence,
         * so it is neither skipped nor rewritten. */
        ASSERT(refused == NULL);
        struct zcl_fleet_vitals_history page;
        ASSERT(zcl_fleet_ledger_vitals_history_readonly(ta.dir, ta.box_id,
            ta.signer, ta.box_id, -1, 0, 1, &page, &report) != ZCL_FLEET_OK);
        ASSERT(fl_history_page_unpublished(&page));
        ASSERT(report.status == ZCL_FLEET_CHAIN_BROKEN ||
               report.status == ZCL_FLEET_SIG_INVALID ||
               report.status == ZCL_FLEET_MALFORMED);
        PASS();
    }

_test_next:
    *ta_out = ta;
    *ta_open_out = ta_open;
    return failures;
}

static void fl_box_close_if_open(struct fl_box *b, bool is_open)
{
    if (is_open)
        fl_box_close(b);
}

int test_fleet_ledger(void)
{
    int failures = 0;
#if !defined(_WIN32)
    failures += test_fleet_ledger_observation();
#endif
    char root[256];
    char wire_dir[256];
    /* Replication now asks whether the signing key holds a role here, and
     * every key in this group is one the group invented. The gate is held
     * open for the protocol proofs and closed again below; the gate itself
     * is proven in fleet_role_enforcement, which starts from an empty seam
     * and shows that it refuses. */
    zcl_fleet_role_checker_install_permissive_for_testing();
    test_make_tmpdir(root, sizeof(root), "fleet_ledger", "store");
    test_make_tmpdir(wire_dir, sizeof(wire_dir), "fleet_ledger", "wire");

    struct fl_box ma, mb, ta, wa, wb, ex;
    bool ma_open = false, mb_open = false, ta_open = false;
    bool wa_open = false, wb_open = false, ex_open = false;

    struct mesh_term_fixture f;
    struct mesh_term_peer responder = {0};
    bool fixture_open = false;
    bool registered = false;
    struct net_manager nm;
    struct msg_processor mp;
    struct p2p_node *asker = NULL;    /* dials: mints even stream ids */
    struct p2p_node *answerer = NULL; /* accepts: mints odd stream ids */
    struct p2p_node *nodes[2];
    struct send_segment *ask_queue = NULL, *answer_queue = NULL;
    struct boot_svc_ctx svc;
    struct db_service dbsvc;
    struct app_runtime_context runtime;
    memset(&nm, 0, sizeof(nm));
    memset(&mp, 0, sizeof(mp));
    memset(&svc, 0, sizeof(svc));
    memset(&dbsvc, 0, sizeof(dbsvc));
    memset(&runtime, 0, sizeof(runtime));

    TEST("fleet ledger: a signed row is stored, a counter key adds across "
         "rows, and a gauge does not") {
        ASSERT(fl_box_open(&ma, root, "a", 0x11));
        ma_open = true;
        struct zcl_fleet_pair first_pairs[2] = {
            { ZCL_FLEET_PAIR_TOKENS_IN, 100 },
            { ZCL_FLEET_PAIR_TOKENS_OUT, 10 }
        };
        uint64_t first_seq = 77;
        ASSERT_EQ(zcl_fleet_ledger_append(
                      ma.ledger, ZCL_FLEET_KIND_USAGE, ZCL_FLEET_PROVIDER_GROK,
                      first_pairs, 2, "t1", NULL, ma.seed, &first_seq),
                  ZCL_FLEET_OK);
        ASSERT_EQ(first_seq, UINT64_C(1));
        ASSERT_EQ(zcl_fleet_ledger_peer_seq(ma.ledger, ma.box_id), first_seq);
        ASSERT_EQ(fl_add_usage(&ma, ZCL_FLEET_PROVIDER_GROK, 200, 20, "t2"),
                  ZCL_FLEET_OK);
        struct zcl_fleet_bucket bucket;
        uint64_t index_us = 0;
        ASSERT(fl_usage_bucket(ma.ledger, ZCL_FLEET_PROVIDER_GROK, NULL,
                               &bucket, &index_us));
        ASSERT_EQ(bucket.rows, UINT64_C(2));
        /* tokens_in and tokens_out are COUNTER, so two statements add. */
        ASSERT_EQ(bucket.value[ZCL_FLEET_PAIR_TOKENS_IN], INT64_C(300));
        ASSERT_EQ(bucket.value[ZCL_FLEET_PAIR_TOKENS_OUT], INT64_C(30));
        /* A key no row carried is ABSENT, which is a different fact from a
         * measured zero and is stored and reported as one. */
        ASSERT_EQ(bucket.state[ZCL_FLEET_PAIR_TOKENS_IN],
                  (uint8_t)ZCL_FLEET_FIELD_PRESENT);
        ASSERT_EQ(bucket.state[ZCL_FLEET_PAIR_TOKENS_CACHED],
                  (uint8_t)ZCL_FLEET_FIELD_ABSENT);
        ASSERT_EQ(bucket.value[ZCL_FLEET_PAIR_TOKENS_CACHED], INT64_C(0));

        /* box.load1 is declared a gauge, so two samples do not add: the
         * later statement in chain order replaces the earlier one. */
        ASSERT_EQ(fl_add_vital(&ma, "box.load1", 3), ZCL_FLEET_OK);
        ASSERT_EQ(fl_add_vital(&ma, "box.load1", 5), ZCL_FLEET_OK);
        struct zcl_fleet_query q;
        memset(&q, 0, sizeof q);
        q.kind = ZCL_FLEET_KIND_VITALS;
        q.days = 1;
        q.now_unix = (int64_t)platform_time_wall_time_t();
        struct zcl_fleet_bucket gauges[8];
        size_t count = 0;
        ASSERT_EQ(
            zcl_fleet_ledger_query(ma.ledger, &q, gauges, 8, &count, NULL),
            ZCL_FLEET_OK);
        ASSERT_EQ(count, (size_t)1);
        ASSERT_EQ(gauges[0].value[ZCL_FLEET_PAIR_VALUE], INT64_C(5));
        /* And the class the index applied is the one the catalog declares,
         * not a second opinion held here. */
        uint16_t load1 = 0, spend_in = 0;
        ASSERT(zcl_fleet_subject_from_name(ZCL_FLEET_KIND_VITALS, "box.load1",
                                           &load1));
        ASSERT(zcl_fleet_subject_from_name(ZCL_FLEET_KIND_VITALS,
                                           "spend.tokens_in", &spend_in));
        ASSERT_EQ(zcl_fleet_pair_merge(ZCL_FLEET_KIND_VITALS, load1,
                                       ZCL_FLEET_PAIR_VALUE),
                  ZCL_FLEET_MERGE_LWW);
        ASSERT_EQ(zcl_fleet_pair_merge(ZCL_FLEET_KIND_VITALS, spend_in,
                                       ZCL_FLEET_PAIR_VALUE),
                  ZCL_FLEET_MERGE_COUNTER);
        ASSERT_EQ(zcl_fleet_pair_merge(ZCL_FLEET_KIND_USAGE,
                                       ZCL_FLEET_PROVIDER_GROK,
                                       ZCL_FLEET_PAIR_TOKENS_IN),
                  ZCL_FLEET_MERGE_COUNTER);
        PASS();
    }

    failures += fl_latest_cases(root);
    failures += fl_history_cases(root);
    failures += fl_history_late_failure(root);

    TEST("fleet ledger: refused appends clear the sequence output") {
        uint64_t seq = 77;
        ASSERT_EQ(zcl_fleet_ledger_append(NULL, 1, 0, NULL, 0, NULL, NULL,
                                          NULL, &seq), ZCL_FLEET_ARGUMENT);
        ASSERT_EQ(seq, UINT64_C(0));
        struct zcl_fleet_report report;
        struct zcl_fleet_ledger *readonly = zcl_fleet_ledger_open_readonly(
            ma.dir, ma.box_id, ma.signer, &report);
        ASSERT(readonly);
        seq = 77;
        enum zcl_fleet_status status = zcl_fleet_ledger_append(
            readonly, ZCL_FLEET_KIND_USAGE, ZCL_FLEET_PROVIDER_GROK,
            NULL, 0, NULL, NULL, ma.seed, &seq);
        zcl_fleet_ledger_close(readonly);
        ASSERT_EQ(status, ZCL_FLEET_ARGUMENT);
        ASSERT_EQ(seq, UINT64_C(0));
        seq = 77;
        struct zcl_fleet_pair pair = { ZCL_FLEET_PAIR_VALUE, 1 };
        ASSERT_EQ(zcl_fleet_ledger_append(ma.ledger, ZCL_FLEET_KIND_ATTEST, 0,
                                          &pair, 1, NULL, NULL, ma.seed, &seq),
                  ZCL_FLEET_KIND_NOT_WRITABLE);
        ASSERT_EQ(seq, UINT64_C(0));
        PASS();
    }

    TEST("fleet ledger: the closed vocabularies refuse what nobody "
         "declared") {
        uint16_t subject = 0;
        ASSERT(!zcl_fleet_subject_from_name(ZCL_FLEET_KIND_VITALS,
                                            "box.invented_metric", &subject));
        /* A reserved kind has a wire value and no writer in this lane. */
        ASSERT(zcl_fleet_kind_name(ZCL_FLEET_KIND_ATTEST) != NULL);
        ASSERT(!zcl_fleet_kind_writable(ZCL_FLEET_KIND_ATTEST));
        ASSERT(!zcl_fleet_kind_writable(ZCL_FLEET_KIND_REWARD));
        struct zcl_fleet_pair pair = { ZCL_FLEET_PAIR_VALUE, 1 };
        ASSERT_EQ(zcl_fleet_ledger_append(ma.ledger, ZCL_FLEET_KIND_ATTEST, 0,
                                          &pair, 1, NULL, NULL, ma.seed, NULL),
                  ZCL_FLEET_KIND_NOT_WRITABLE);
        /* A vitals subject past the end of the catalog is not a metric. */
        ASSERT_EQ(zcl_fleet_ledger_append(ma.ledger, ZCL_FLEET_KIND_VITALS,
                                          (uint16_t)zcl_fleet_vital_count(),
                                          &pair, 1, NULL, NULL, ma.seed, NULL),
                  ZCL_FLEET_VITAL_UNKNOWN);
        ASSERT_STR_EQ(zcl_fleet_status_label(ZCL_FLEET_VITAL_UNKNOWN),
                      "vital_unknown");
        ASSERT_STR_EQ(zcl_fleet_status_label(ZCL_FLEET_CHAIN_BROKEN),
                      "ledger_chain_broken");
        ASSERT_STR_EQ(zcl_fleet_status_label(ZCL_FLEET_SIG_INVALID),
                      "ledger_sig_invalid");
        ASSERT_STR_EQ(zcl_fleet_status_label(ZCL_FLEET_PEER_UNPAIRED),
                      "ledger_peer_unpaired");
        PASS();
    }

    TEST("fleet ledger: a query walks a table whose size is fixed at "
         "compile time, and refuses a window it does not hold") {
        struct zcl_fleet_bucket bucket;
        uint64_t index_us = 0;
        ASSERT(fl_usage_bucket(ma.ledger, ZCL_FLEET_PROVIDER_GROK, NULL,
                               &bucket, &index_us));
        /* The property that makes an answer instant is that the work is one
         * pass over a fixed table however long the chains grow — a constant,
         * not a duration. The measured microseconds are PRINTED and never
         * asserted on, so a loaded box cannot fail this. */
        ASSERT(ZCL_FLEET_INDEX_CELLS <= 8192u);
        ASSERT(ZCL_FLEET_INDEX_DAYS <= 64u);
        printf("\n      index walk over %u cells x %u days: %llu us\n",
               (unsigned)ZCL_FLEET_INDEX_CELLS,
               (unsigned)ZCL_FLEET_INDEX_DAYS, (unsigned long long)index_us);
        struct zcl_fleet_query q;
        memset(&q, 0, sizeof q);
        q.kind = ZCL_FLEET_KIND_USAGE;
        q.days = ZCL_FLEET_INDEX_DAYS + 1u;
        q.now_unix = (int64_t)platform_time_wall_time_t();
        struct zcl_fleet_bucket sink[2];
        size_t count = 0;
        ASSERT_EQ(zcl_fleet_ledger_query(ma.ledger, &q, sink, 2, &count, NULL),
                  ZCL_FLEET_WINDOW);
        PASS();
    }

    char sample_dd[320];
    ASSERT((size_t)snprintf(sample_dd, sizeof sample_dd, "%s/sample_dd", root) <
           sizeof sample_dd);
    ASSERT(mkdir(sample_dd, 0700) == 0);
    uint8_t sample_box[32], sample_signer[32];
    ASSERT(fl_provision(sample_dd, sample_box, sample_signer));
    zcl_native_bridge_bind_rpc(sample_dd, 0);

    failures += fl_host_uptime_test(sample_dd);

    failures += fl_vitals_sample_cases(sample_dd, sample_box, sample_signer);

    TEST("fleet experiment predict/result CLI leaves persist story and "
         "executor, and export prints exp.sh's 22-column TSV with its own "
         "empty-column placeholder for a field this row never carried") {
        struct json_value input;
        struct zcl_command_reply reply;

        json_init(&input);
        json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "task_id", "t-cli-story"));
        ASSERT(json_push_kv_str(&input, "task_class", "read"));
        ASSERT(json_push_kv_str(&input, "story", "cli-story"));
        ASSERT(json_push_kv_str(&input, "executor", "grok"));
        ASSERT(json_push_kv_str(&input, "harness", "manual"));
        ASSERT(json_push_kv_str(&input, "model", "grok"));
        ASSERT(json_push_kv_str(&input, "effort", "low"));
        struct zcl_command_request req_p1 = { .input = &input };
        zcl_native_handle_fleet_experiment_predict(&req_p1, &reply);
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input);
        json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "task_id", "t-cli-story"));
        ASSERT(json_push_kv_str(&input, "task_class", "read"));
        ASSERT(json_push_kv_str(&input, "story", "cli-story"));
        ASSERT(json_push_kv_str(&input, "executor", "grok"));
        ASSERT(json_push_kv_str(&input, "model", "grok"));
        ASSERT(json_push_kv_str(&input, "outcome", "LAND"));
        struct zcl_command_request req_r1 = { .input = &input };
        zcl_native_handle_fleet_experiment_result(&req_r1, &reply);
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
        zcl_command_reply_free(&reply);
        json_free(&input);

        /* No story, no executor at all: the export line for this row must
         * print the SAME empty-column placeholder exp.sh's own missing-text
         * convention uses, never a guess. */
        json_init(&input);
        json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "task_id", "t-cli-plain"));
        ASSERT(json_push_kv_str(&input, "task_class", "read"));
        ASSERT(json_push_kv_str(&input, "harness", "manual"));
        ASSERT(json_push_kv_str(&input, "model", "grok"));
        ASSERT(json_push_kv_str(&input, "effort", "low"));
        struct zcl_command_request req_p2 = { .input = &input };
        zcl_native_handle_fleet_experiment_predict(&req_p2, &reply);
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
        zcl_command_reply_free(&reply);
        json_free(&input);

        struct zcl_command_request req_all = { .input = NULL };
        zcl_native_handle_fleet_experiment_export(&req_all, &reply);
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
        const char *text = json_get_str(json_get(&reply.data, "text"));
        ASSERT(text != NULL);
        ASSERT(strstr(text,
                      "ts\tkind\tbox\ttask_id\ttask_class\tstory\texecutor\t"
                      "harness\tmodel\teffort\ttokens_in\ttokens_out\t"
                      "tokens_cache\ttokens_reasoning\ttool_uses\tturns\t"
                      "wall_s\toutcome\tlines_added\tlines_removed\t"
                      "defects\tnote\n") == text);
        {
            const char *nl = strchr(text, '\n');
            ASSERT(nl != NULL);
            size_t tabs = 0;
            for (const char *p = text; p < nl; p++)
                if (*p == '\t')
                    tabs++;
            /* 22 columns, 21 separators: the export's column COUNT. */
            ASSERT_EQ(tabs, (size_t)21);
        }
        ASSERT(strstr(text, "\tt-cli-story\tread\tcli-story\tgrok\t") != NULL);
        /* task_class then two empty columns (story, executor) then the
         * harness that follows them — the placeholder round trip. */
        ASSERT(strstr(text, "\tt-cli-plain\tread\t\t\tmanual\t") != NULL);
        zcl_command_reply_free(&reply);

        /* box filter: this machine's own box id keeps every row just
         * written; a box id that never wrote one keeps none. */
        json_init(&input);
        json_set_object(&input);
        char box_hex[65];
        zcl_hex_encode(sample_box, 32, box_hex);
        ASSERT(json_push_kv_str(&input, "box", box_hex));
        struct zcl_command_request req_box = { .input = &input };
        zcl_native_handle_fleet_experiment_export(&req_box, &reply);
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strstr(json_get_str(json_get(&reply.data, "text")),
                      "t-cli-story") != NULL);
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input);
        json_set_object(&input);
        uint8_t other_box[32];
        memset(other_box, 0x77, sizeof other_box);
        char other_hex[65];
        zcl_hex_encode(other_box, 32, other_hex);
        ASSERT(json_push_kv_str(&input, "box", other_hex));
        struct zcl_command_request req_other = { .input = &input };
        zcl_native_handle_fleet_experiment_export(&req_other, &reply);
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "rows")), INT64_C(0));
        zcl_command_reply_free(&reply);
        json_free(&input);

        /* since filter: a one-hour floor keeps the rows just written (the
         * exclusion side of this same filter is proven at the ledger level
         * below, where an arbitrary `since_unix` is reachable directly —
         * the CLI's own `since` is hours-back-from-now and so can never
         * name a floor in the future). */
        json_init(&input);
        json_set_object(&input);
        ASSERT(json_push_kv_int(&input, "since", 1));
        struct zcl_command_request req_since = { .input = &input };
        zcl_native_handle_fleet_experiment_export(&req_since, &reply);
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get_int(json_get(&reply.data, "rows")) >= INT64_C(3));
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    }

    failures += fl_experiment_cases(root, &ex, &ex_open);

    failures += fl_tamper_cases(root, &ta, &ta_open);

    TEST("fleet ledger: a peer's rows replicate, the same bytes again are a "
         "no-op, and a forged row refuses the batch whole") {
        ASSERT(fl_box_open(&ma, root, "a2", 0x21));
        ma_open = true;
        ASSERT(fl_box_open(&mb, root, "b2", 0x31));
        mb_open = true;
        ASSERT_EQ(
            fl_add_usage(&ma, ZCL_FLEET_PROVIDER_CLAUDE_OPUS, 7, 3, "u1"),
            ZCL_FLEET_OK);
        ASSERT_EQ(
            fl_add_usage(&ma, ZCL_FLEET_PROVIDER_CLAUDE_OPUS, 11, 5, "u2"),
            ZCL_FLEET_OK);

        uint8_t rows[8192];
        size_t len = fl_rows_of(&ma, rows, sizeof rows);
        ASSERT(len > 0);

        size_t accepted = 0;
        ASSERT_EQ(zcl_fleet_ledger_replicate(mb.ledger, ma.box_id, ma.signer,
                                             rows, len, &accepted),
                  ZCL_FLEET_OK);
        ASSERT_EQ(accepted, (size_t)2);
        ASSERT_EQ(zcl_fleet_ledger_peer_seq(mb.ledger, ma.box_id),
                  UINT64_C(2));

        /* The same bytes again: already held, so nothing is written and
         * nothing refuses. That is what makes a second pull free. */
        accepted = 99;
        ASSERT_EQ(zcl_fleet_ledger_replicate(mb.ledger, ma.box_id, ma.signer,
                                             rows, len, &accepted),
                  ZCL_FLEET_OK);
        ASSERT_EQ(accepted, (size_t)0);

        /* A row attributed to a machine that is not this link's peer. A
         * paired link carries that peer's own rows and nobody else's. */
        uint8_t stranger[32];
        memset(stranger, 0x77, sizeof stranger);
        ASSERT_EQ(zcl_fleet_ledger_replicate(mb.ledger, stranger, ma.signer,
                                             rows, len, NULL),
                  ZCL_FLEET_NOT_OWNER);
        /* A row signed by a key this peer's delegation does not delegate. */
        uint8_t other_signer[32];
        memset(other_signer, 0x66, sizeof other_signer);
        ASSERT_EQ(zcl_fleet_ledger_replicate(mb.ledger, ma.box_id,
                                             other_signer, rows, len, NULL),
                  ZCL_FLEET_PEER_UNPAIRED);

        /* A forged signature ANYWHERE in a batch refuses the whole batch,
         * including the rows ahead of it that were perfectly good. */
        ASSERT_EQ(
            fl_add_usage(&ma, ZCL_FLEET_PROVIDER_CLAUDE_OPUS, 13, 2, "u3"),
            ZCL_FLEET_OK);
        ASSERT_EQ(
            fl_add_usage(&ma, ZCL_FLEET_PROVIDER_CLAUDE_OPUS, 17, 4, "u4"),
            ZCL_FLEET_OK);
        uint8_t tail[8192];
        size_t tail_len = 0;
        uint64_t last = 0;
        ASSERT_EQ(zcl_fleet_ledger_read_since(ma.ledger, ma.box_id, 2, tail,
                                              sizeof tail, &tail_len, &last),
                  ZCL_FLEET_OK);
        ASSERT(tail_len > 0);
        ASSERT_EQ(last, UINT64_C(4));
        tail[tail_len - 1] ^= 0x01u; /* the LAST row's signature */
        ASSERT_EQ(zcl_fleet_ledger_replicate(mb.ledger, ma.box_id, ma.signer,
                                             tail, tail_len, NULL),
                  ZCL_FLEET_SIG_INVALID);
        /* Nothing partial: in memory and on disk, the replica is exactly
         * where it was before the forged batch arrived. */
        ASSERT_EQ(zcl_fleet_ledger_peer_seq(mb.ledger, ma.box_id),
                  UINT64_C(2));
        fl_box_close(&mb);
        mb_open = false;
        ASSERT(fl_box_open(&mb, root, "b2", 0x31));
        mb_open = true;
        ASSERT_EQ(zcl_fleet_ledger_peer_seq(mb.ledger, ma.box_id),
                  UINT64_C(2));
        PASS();
    }

    TEST("fleet ledger: the replica answers with the peer gone") {
        /* Box a is closed: nothing of it is reachable, and the question is
         * still answered, from the local replica alone. */
        fl_box_close(&ma);
        ma_open = false;
        struct zcl_fleet_bucket bucket;
        uint64_t index_us = 0;
        ASSERT(fl_usage_bucket(mb.ledger, ZCL_FLEET_PROVIDER_CLAUDE_OPUS,
                               ma.box_id, &bucket, &index_us));
        ASSERT_EQ(bucket.value[ZCL_FLEET_PAIR_TOKENS_IN], INT64_C(18));
        ASSERT_EQ(bucket.value[ZCL_FLEET_PAIR_TOKENS_OUT], INT64_C(8));
        /* Freshness travels with the answer, because instantly is not the
         * same as currently. */
        ASSERT(bucket.last_ts > 0);
        PASS();
    }

    TEST("fleet ledger: a pull over the real stream wire replicates a "
         "paired peer's rows, and an unpaired peer never reaches the "
         "service") {
        ASSERT(mesh_term_fixture_open(&f, wire_dir));
        fixture_open = true;
        ASSERT(fl_wire_responder(&f, &responder, &wa, root));

        wa_open = true;
        ASSERT(fl_box_open(&wb, root, "wire_b", 0x51));
        wb_open = true;
        for (int i = 0; i < 3; i++)
            ASSERT_EQ(
                fl_add_usage(&wa, ZCL_FLEET_PROVIDER_GLM, 10 + i, i, "w"),
                ZCL_FLEET_OK);

        zcl_mutex_init(&nm.cs_nodes);
        zcl_mutex_init(&nm.cs_last_node_id);
        struct net_address addr;
        memset(&addr, 0, sizeof(addr));
        addr.svc.port = 18034;
        asker = p2p_node_create(&nm, ZCL_INVALID_SOCKET, &addr, "ledger-ask",
                                false);
        answerer = p2p_node_create(&nm, ZCL_INVALID_SOCKET, &addr,
                                   "ledger-answer", true);
        ASSERT(asker && answerer);
        asker->transport = f.term_peer.ini;
        answerer->transport = f.res_term;
        asker->state = PEER_HANDSHAKE_COMPLETE;
        answerer->state = PEER_HANDSHAKE_COMPLETE;
        nodes[0] = asker;
        nodes[1] = answerer;
        nm.nodes = nodes;
        nm.num_nodes = 2;
        ask_queue = mesh_loop_sentinel(asker);
        answer_queue = mesh_loop_sentinel(answerer);
        ASSERT(ask_queue && answer_queue);
        mp.net_mgr = &nm;
        mp.params = chain_params_get();
        ASSERT(mp.params != NULL);
        svc.msg_processor = &mp;
        dbsvc.node_db = &f.ndb;
        dbsvc.started = true;
        runtime.db_service = &dbsvc;
        app_runtime_set_current(&runtime);
        mesh_stream_test_bind(&svc);
        mesh_stream_test_reset();
        ASSERT(boot_fleet_ledger_register_service());
        registered = true;
        /* The answering half serves box wa's own chain. */
        boot_fleet_ledger_test_bind(wa.ledger, wa.box_id, wa.signer);

        /* An OPEN from a peer this box holds no pairing for is refused by
         * name before the service is asked anything. These are the owner's
         * private rows: an unpaired stranger must not reach the service at
         * all, not merely be answered nothing. */
        uint8_t frame[MESH_LOOP_WIRE_MAX];
        uint8_t pull[FLEET_LEDGER_PULL_BYTES];
        pull[0] = (uint8_t)FLEET_LEDGER_MSG_PULL;
        pull[1] = 1u;
        memset(pull + 2, 0, 8);
        size_t frame_len = mesh_stream_test_open_frame(
            2, 4096u, FLEET_LEDGER_SERVICE_NAME, pull, sizeof pull, frame,
            sizeof frame);
        ASSERT(frame_len != 0);
        ASSERT(mesh_stream_frame(&mp, answerer, frame, frame_len, NULL));
        uint8_t answer[MESH_LOOP_WIRE_MAX];
        bool more = false;
        size_t answer_len =
            mesh_loop_take(answerer, answer_queue, f.term_peer.ini, answer,
                           sizeof answer, &more);
        ASSERT(more);
        uint8_t kind = 0;
        ASSERT(mesh_stream_test_read_header(answer, answer_len, &kind, NULL));
        ASSERT_EQ(kind, MESH_STREAM_KIND_CLOSE);
        ASSERT_EQ(answer[MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u],
                  MESH_STREAM_REFUSED_PEER_UNPAIRED);
        ASSERT_EQ(mesh_stream_test_live_count(FLEET_LEDGER_SERVICE_NAME),
                  (size_t)0);

        /* Paired, with the one grant the service asks for. */
        ASSERT(mesh_term_pair_row(&f, &f.term_peer,
                                  MESH_PAIRING_CAP_STATUS_READ, FL_PAIRED_AT,
                                  FL_PAIRING_EXPIRES));
        /* A pairing row is not enough on either half: the peer's
         * delegation has to still be current, and this group cannot host
         * the DHT service that holds it. The seam supplies that service's
         * answer and the genesis it is bound to — the authority itself
         * still runs against the fixture's real node.db. */
        boot_fleet_ledger_test_bind_authority(&f.term_peer.delegation,
                                              f.genesis, FL_AUTHORITY_NOW);

        boot_fleet_ledger_test_bind_authority(&responder.delegation,
                                              f.genesis, FL_AUTHORITY_NOW);

        /* Box wb asks box wa for everything after what it holds, which is
         * nothing, and commits what comes back. */
        ASSERT_EQ(zcl_fleet_ledger_peer_seq(wb.ledger, wa.box_id),
                  UINT64_C(0));
        ASSERT(boot_fleet_ledger_test_pull(
            f.resp_noise_pub, wa.box_id, wa.signer,
            zcl_fleet_ledger_peer_seq(wb.ledger, wa.box_id)));
        ASSERT_EQ(mesh_loop_pump(asker, ask_queue, f.res_term, &mp, answerer),
                  (size_t)1);
        boot_fleet_ledger_test_serve(); /* the answer */
        boot_fleet_ledger_test_serve(); /* nothing left to say: close */
        ASSERT(mesh_loop_pump(answerer, answer_queue, f.term_peer.ini, &mp,
                              asker) >= (size_t)2);
        boot_fleet_ledger_test_drain_into(wb.ledger);
        ASSERT_EQ(zcl_fleet_ledger_peer_seq(wb.ledger, wa.box_id),
                  UINT64_C(3));

        /* Asking again, now holding all three, moves no row: the answer is
         * empty and the stream closes without ever sending a DATA frame.
         * The finished exchange's own trailing frames are opened and thrown
         * away first — a Noise record must be opened in the order it was
         * sealed — so the count below is this pull's traffic and nothing
         * left over from the last one. */
        mesh_loop_discard(asker, ask_queue, f.res_term);
        mesh_loop_discard(answerer, answer_queue, f.term_peer.ini);
        mesh_stream_test_reset();
        ASSERT(boot_fleet_ledger_test_pull(
            f.resp_noise_pub, wa.box_id, wa.signer,
            zcl_fleet_ledger_peer_seq(wb.ledger, wa.box_id)));
        ASSERT_EQ(mesh_loop_pump(asker, ask_queue, f.res_term, &mp, answerer),
                  (size_t)1);
        boot_fleet_ledger_test_serve();
        ASSERT_EQ(mesh_loop_pump(answerer, answer_queue, f.term_peer.ini, &mp,
                                 asker),
                  (size_t)1); /* the CLOSE alone */
        boot_fleet_ledger_test_drain_into(wb.ledger);
        ASSERT_EQ(zcl_fleet_ledger_peer_seq(wb.ledger, wa.box_id),
                  UINT64_C(3));

        /* What replicated is usable, and it is wa's rows under wa's name. */
        struct zcl_fleet_bucket bucket;
        ASSERT(fl_usage_bucket(wb.ledger, ZCL_FLEET_PROVIDER_GLM, wa.box_id,
                               &bucket, NULL));
        ASSERT_EQ(bucket.rows, UINT64_C(3));
        ASSERT_EQ(bucket.value[ZCL_FLEET_PAIR_TOKENS_IN], INT64_C(33));
        PASS();
    }

    TEST("fleet ledger: a peer whose delegation is no longer current is "
         "refused on both halves and the replica does not move") {
        /* Nothing about the PAIRING changes in this case. The row keeps
         * its capability and its window, and only the master identity
         * behind it stops being current — the exact fact a pairing row
         * cannot express, and the reason the lane asks twice. */
        uint64_t refused = boot_fleet_ledger_delegation_refused_count();
        uint64_t seq_before = zcl_fleet_ledger_peer_seq(wb.ledger, wa.box_id);

        /* With the identity ACTIVE the REAL pull lane — pairing list,
         * delegation lookup, authority and all — opens both authorized peers'
         * streams and refuses nothing. */
        mesh_loop_discard(asker, ask_queue, f.res_term);
        mesh_loop_discard(answerer, answer_queue, f.term_peer.ini);
        mesh_stream_test_reset();
        boot_fleet_ledger_test_pull_paired(wb.ledger, FL_AUTHORITY_NOW);
        ASSERT_EQ(mesh_stream_test_live_count(FLEET_LEDGER_SERVICE_NAME),
                  (size_t)2);
        ASSERT_EQ(boot_fleet_ledger_delegation_refused_count(), refused);

        /* The peer's master identity is revoked on chain. */
        struct zid_identity identity;
        ASSERT(db_zid_identity_find(
            &f.ndb, f.term_peer.delegation.doc.master_pubkey, &identity));
        (void)snprintf(identity.status, sizeof identity.status, "%s",
                       ZID_IDENTITY_STATUS_REVOKED);
        ASSERT(db_zid_identity_save(&f.ndb, &identity));
        /* The pairing row itself is untouched: still granted, still
         * unrevoked, still inside its window. */
        struct db_mesh_pairing still;
        ASSERT(db_mesh_pairing_find(&f.ndb, f.term_peer.pairing.pairing_id,
                                    &still));
        ASSERT_EQ(still.revoked_at, INT64_C(0));
        ASSERT(mesh_pairing_allows(&still, MESH_PAIRING_CAP_STATUS_READ,
                                   FL_AUTHORITY_NOW));

        mesh_loop_discard(asker, ask_queue, f.res_term);
        mesh_loop_discard(answerer, answer_queue, f.term_peer.ini);
        mesh_stream_test_reset();

        /* PULL: the revoked peer is not asked; the responder still opens. The
         * refusal is counted under the name the catalog already carried. */
        boot_fleet_ledger_test_pull_paired(wb.ledger, FL_AUTHORITY_NOW);
        ASSERT_EQ(mesh_stream_test_live_count(FLEET_LEDGER_SERVICE_NAME),
                  (size_t)1);
        ASSERT_EQ(boot_fleet_ledger_delegation_refused_count(), refused + 1);
        ASSERT_EQ(zcl_fleet_ledger_peer_seq(wb.ledger, wa.box_id), seq_before);

        mesh_stream_test_reset();

        /* ACCEPT: the peer is not answered. The pairing row still grants
         * the capability, so the primitive admits the OPEN and it is THIS
         * lane that refuses it — before a byte of the ledger is read. */
        uint8_t frame[MESH_LOOP_WIRE_MAX];
        uint8_t pull[FLEET_LEDGER_PULL_BYTES];
        pull[0] = (uint8_t)FLEET_LEDGER_MSG_PULL;
        pull[1] = 1u;
        memset(pull + 2, 0, 8);
        size_t frame_len = mesh_stream_test_open_frame(
            6, 4096u, FLEET_LEDGER_SERVICE_NAME, pull, sizeof pull, frame,
            sizeof frame);
        ASSERT(frame_len != 0);
        ASSERT(mesh_stream_frame(&mp, answerer, frame, frame_len, NULL));
        uint8_t answer[MESH_LOOP_WIRE_MAX];
        bool more = false;
        size_t answer_len =
            mesh_loop_take(answerer, answer_queue, f.term_peer.ini, answer,
                           sizeof answer, &more);
        ASSERT(more);
        uint8_t kind = 0;
        ASSERT(mesh_stream_test_read_header(answer, answer_len, &kind, NULL));
        ASSERT_EQ(kind, MESH_STREAM_KIND_CLOSE);
        ASSERT_EQ(answer[MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u],
                  MESH_STREAM_REFUSED_PEER_UNPAIRED);
        ASSERT_EQ(mesh_stream_test_live_count(FLEET_LEDGER_SERVICE_NAME),
                  (size_t)0);
        ASSERT_EQ(boot_fleet_ledger_delegation_refused_count(), refused + 2);
        /* Nothing arrived and nothing was sent: no second frame follows
         * the refusal, and the replica is exactly where it was. */
        ASSERT_EQ(mesh_loop_take(answerer, answer_queue, f.term_peer.ini,
                                 answer, sizeof answer, &more),
                  (size_t)0);
        ASSERT(!more);
        ASSERT_EQ(zcl_fleet_ledger_peer_seq(wb.ledger, wa.box_id), seq_before);
        PASS();
    }

    TEST("fleet ledger: a batch with no free commit slot is counted, said "
         "out loud, and asked for again") {
        /* The identity is current again: what this case measures is the
         * inbox bound, not the delegation. */
        struct zid_identity identity;
        ASSERT(db_zid_identity_find(
            &f.ndb, f.term_peer.delegation.doc.master_pubkey, &identity));
        (void)snprintf(identity.status, sizeof identity.status, "%s",
                       ZID_IDENTITY_STATUS_ACTIVE);
        ASSERT(db_zid_identity_save(&f.ndb, &identity));
        uint64_t dropped = boot_fleet_ledger_inbox_full_count();

        /* One more answered pull than the inbox has slots, with nothing
         * committed in between. The last one has nowhere to go. */
        for (unsigned i = 0; i < FLEET_LEDGER_INBOX_MAX + 1u; i++) {
            mesh_loop_discard(asker, ask_queue, f.res_term);
            mesh_loop_discard(answerer, answer_queue, f.term_peer.ini);
            mesh_stream_test_reset();
            ASSERT(boot_fleet_ledger_test_pull(f.resp_noise_pub, wa.box_id,
                                               wa.signer, 0));
            ASSERT_EQ(mesh_loop_pump(asker, ask_queue, f.res_term, &mp,
                                     answerer),
                      (size_t)1);
            boot_fleet_ledger_test_serve(); /* the answer */
            boot_fleet_ledger_test_serve(); /* nothing left: close */
            ASSERT(mesh_loop_pump(answerer, answer_queue, f.term_peer.ini, &mp,
                           asker) >= (size_t)2);
        }
        ASSERT_EQ(boot_fleet_ledger_inbox_full_count(), dropped + 1);

        /* No row is lost: the batch that was dropped is the same range the
         * next pull asks for, and the eight that were kept commit to
         * exactly what this box already held. */
        boot_fleet_ledger_test_drain_into(wb.ledger);
        ASSERT_EQ(zcl_fleet_ledger_peer_seq(wb.ledger, wa.box_id),
                  UINT64_C(3));

        /* And an operator can see both counts, because `fleet ledger
         * status` prints them beside the chains it already reports. */
        struct fl_box sb;
        ASSERT(fl_box_open(&sb, wire_dir, "fleet_ledger", 0x71));
        fl_box_close(&sb);
        zcl_native_bridge_bind_rpc(wire_dir, 0);
        struct zcl_command_request request;
        struct zcl_command_reply reply;
        memset(&request, 0, sizeof request);
        zcl_native_handle_fleet_ledger_status(&request, &reply);
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
        const struct json_value *inbox_full =
            json_get(&reply.data, "inbox_full");
        const struct json_value *refused =
            json_get(&reply.data, "delegation_refused");
        ASSERT(inbox_full != NULL && refused != NULL);
        ASSERT_EQ(json_get_int(inbox_full),
                  (int64_t)boot_fleet_ledger_inbox_full_count());
        ASSERT_EQ(json_get_int(refused),
                  (int64_t)boot_fleet_ledger_delegation_refused_count());
        ASSERT(json_get_int(inbox_full) > 0);
        ASSERT(json_get_int(refused) > 0);
        zcl_command_reply_free(&reply);
        zcl_native_bridge_bind_rpc("", 0);
        PASS();
    }

    TEST("fleet ledger: expiry after OPEN sends no ledger DATA") {
        mesh_loop_discard(asker, ask_queue, f.res_term);
        mesh_loop_discard(answerer, answer_queue, f.term_peer.ini);
        mesh_stream_test_reset();
        ASSERT(boot_fleet_ledger_test_pull(f.resp_noise_pub, wa.box_id,
                                           wa.signer, 0));
        ASSERT_EQ(mesh_loop_pump(asker, ask_queue, f.res_term, &mp, answerer),
                  (size_t)1);
        boot_fleet_ledger_test_bind_authority(&f.term_peer.delegation,
                                              f.genesis, 4000);
        boot_fleet_ledger_test_serve();
        uint8_t wire[MESH_LOOP_WIRE_MAX], kind = 0;
        bool more = false;
        size_t len = mesh_loop_take(answerer, answer_queue, f.term_peer.ini,
                                    wire, sizeof wire, &more);
        ASSERT(more);
        ASSERT(mesh_stream_test_read_header(wire, len, &kind, NULL));
        ASSERT_EQ(kind, MESH_STREAM_KIND_CLOSE);
        ASSERT_EQ(wire[MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u],
                  MESH_STREAM_REFUSED_PEER_UNPAIRED);
        ASSERT_EQ(mesh_loop_take(answerer, answer_queue, f.term_peer.ini,
                                 wire, sizeof wire, &more), (size_t)0);
        boot_fleet_ledger_test_bind_authority(&f.term_peer.delegation,
                                              f.genesis, FL_AUTHORITY_NOW);
        PASS();
    }

    TEST("fleet ledger: expiry after receipt prevents replica commit") {
        ASSERT_EQ(fl_add_usage(&wa, ZCL_FLEET_PROVIDER_GLM, 81, 1, "expiry"),
                  ZCL_FLEET_OK);
        uint64_t before = zcl_fleet_ledger_peer_seq(wb.ledger, wa.box_id);
        mesh_loop_discard(asker, ask_queue, f.res_term);
        mesh_loop_discard(answerer, answer_queue, f.term_peer.ini);
        mesh_stream_test_reset();
        ASSERT(boot_fleet_ledger_test_pull(f.resp_noise_pub, wa.box_id,
                                           wa.signer, before));
        ASSERT_EQ(mesh_loop_pump(asker, ask_queue, f.res_term, &mp, answerer),
                  (size_t)1);
        boot_fleet_ledger_test_serve();
        boot_fleet_ledger_test_serve();
        ASSERT(mesh_loop_pump(answerer, answer_queue, f.term_peer.ini, &mp,
                              asker) >= (size_t)2);
        boot_fleet_ledger_test_bind_authority(&responder.delegation,
                                              f.genesis, 4000);
        boot_fleet_ledger_test_drain_into(wb.ledger);
        ASSERT_EQ(zcl_fleet_ledger_peer_seq(wb.ledger, wa.box_id), before);
        boot_fleet_ledger_test_bind_authority(&responder.delegation,
                                              f.genesis, FL_AUTHORITY_NOW);
        PASS();
    }

    TEST("fleet ledger: revocation after receipt prevents replica commit") {
        ASSERT_EQ(fl_add_usage(&wa, ZCL_FLEET_PROVIDER_GLM, 91, 1, "new"),
                  ZCL_FLEET_OK);
        uint64_t before = zcl_fleet_ledger_peer_seq(wb.ledger, wa.box_id);
        mesh_loop_discard(asker, ask_queue, f.res_term);
        mesh_loop_discard(answerer, answer_queue, f.term_peer.ini);
        mesh_stream_test_reset();
        ASSERT(boot_fleet_ledger_test_pull(f.resp_noise_pub, wa.box_id,
                                           wa.signer, before));
        ASSERT_EQ(mesh_loop_pump(asker, ask_queue, f.res_term, &mp, answerer),
                  (size_t)1);
        boot_fleet_ledger_test_serve();
        boot_fleet_ledger_test_serve();
        ASSERT(mesh_loop_pump(answerer, answer_queue, f.term_peer.ini, &mp,
                              asker) >= (size_t)2);
        ASSERT(db_mesh_pairing_revoke(&f.ndb, responder.pairing.pairing_id,
                                      FL_AUTHORITY_NOW));
        boot_fleet_ledger_test_drain_into(wb.ledger);
        ASSERT_EQ(zcl_fleet_ledger_peer_seq(wb.ledger, wa.box_id), before);
        PASS();
    }

    TEST("fleet ledger: revocation after OPEN sends no ledger DATA") {
        mesh_loop_discard(asker, ask_queue, f.res_term);
        mesh_loop_discard(answerer, answer_queue, f.term_peer.ini);
        mesh_stream_test_reset();
        uint8_t frame[MESH_LOOP_WIRE_MAX], pull[FLEET_LEDGER_PULL_BYTES] = {0};
        pull[0] = FLEET_LEDGER_MSG_PULL;
        pull[1] = 1;
        size_t len = mesh_stream_test_open_frame(10, 4096,
            FLEET_LEDGER_SERVICE_NAME, pull, sizeof pull, frame, sizeof frame);
        ASSERT(len > 0);
        ASSERT(mesh_stream_frame(&mp, answerer, frame, len, NULL));
        ASSERT_EQ(mesh_stream_test_live_count(FLEET_LEDGER_SERVICE_NAME),
                  (size_t)1);
        ASSERT(db_mesh_pairing_revoke(&f.ndb, f.term_peer.pairing.pairing_id,
                                      FL_AUTHORITY_NOW));
        boot_fleet_ledger_test_serve();
        bool more = false;
        uint8_t kind = 0;
        len = mesh_loop_take(answerer, answer_queue, f.term_peer.ini,
                             frame, sizeof frame, &more);
        ASSERT(more);
        ASSERT(mesh_stream_test_read_header(frame, len, &kind, NULL));
        ASSERT_EQ(kind, MESH_STREAM_KIND_CLOSE);
        ASSERT_EQ(frame[MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u],
                  MESH_STREAM_REFUSED_PEER_UNPAIRED);
        ASSERT_EQ(mesh_loop_take(answerer, answer_queue, f.term_peer.ini,
                                 frame, sizeof frame, &more), (size_t)0);
        PASS();
    }

_test_next:
    boot_fleet_ledger_test_bind_authority(NULL, NULL, 0);
    zcl_native_bridge_bind_rpc("", 0);
    if (registered) {
        mesh_stream_test_reset();
        boot_fleet_ledger_test_bind(NULL, NULL, NULL);
        mesh_stream_service_unregister(FLEET_LEDGER_SERVICE_NAME);
    }
    mesh_stream_test_bind(NULL);
    app_runtime_set_current(NULL);
    mesh_loop_free_queue(asker, ask_queue);
    mesh_loop_free_queue(answerer, answer_queue);
    if (asker)
        p2p_node_free(asker);
    if (answerer)
        p2p_node_free(answerer);
    free(ask_queue);
    free(answer_queue);
    if (nm.nodes) {
        zcl_mutex_destroy(&nm.cs_nodes);
        zcl_mutex_destroy(&nm.cs_last_node_id);
    }
    if (fixture_open)
        mesh_term_fixture_close(&f);
    fl_box_close_if_open(&wb, wb_open);
    fl_box_close_if_open(&wa, wa_open);
    fl_box_close_if_open(&ta, ta_open);
    fl_box_close_if_open(&mb, mb_open);
    fl_box_close_if_open(&ex, ex_open);
    fl_box_close_if_open(&ma, ma_open);
    test_rm_rf_recursive(wire_dir);
    test_rm_rf_recursive(root);
    zcl_fleet_role_checker_install(NULL);
    return failures;
}
