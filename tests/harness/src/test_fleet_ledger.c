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

#include "base/safe_alloc.h"
#include "chain/chainparams.h"
#include "command/native_command.h"
#include "crypto/ed25519.h"
#include "fleetledger/fleet_ledger.h"
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
/* The clock the delegation authority is asked on. The fixture's
 * delegations are signed for a fixed window, and the accept callback is
 * handed no clock, so the authority seam names the hour once. The pairing
 * row's window above brackets both this and any real clock, which is the
 * point: what decides below is the DELEGATION, never the hour. */
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
                                   pairs, 2, note, b->seed, NULL);
}

static enum zcl_fleet_status fl_add_vital(struct fl_box *b, const char *id,
                                          int64_t value)
{
    uint16_t subject = 0;
    if (!zcl_fleet_subject_from_name(ZCL_FLEET_KIND_VITALS, id, &subject))
        return ZCL_FLEET_VITAL_UNKNOWN;
    struct zcl_fleet_pair pair = { ZCL_FLEET_PAIR_VALUE, value };
    return zcl_fleet_ledger_append(b->ledger, ZCL_FLEET_KIND_VITALS, subject,
                                   &pair, 1, NULL, b->seed, NULL);
}

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

static void fl_sample(struct json_value *input, struct zcl_command_reply *reply)
{
    struct zcl_command_request request = { .input = input };
    zcl_native_handle_fleet_vitals_sample(&request, reply);
}

static void fl_drain_queue(struct p2p_node *node, struct send_segment *sentinel)
{
    if (!node || !sentinel)
        return;
    while (sentinel->next) {
        struct send_segment *seg = sentinel->next;
        sentinel->next = seg->next;
        send_segment_free(seg);
    }
    node->send_head = NULL;
    node->send_tail = NULL;
    node->transport = NULL; /* owned by the fixture */
}

int test_fleet_ledger(void)
{
    int failures = 0;
    char root[256];
    char wire_dir[256];
    test_make_tmpdir(root, sizeof(root), "fleet_ledger", "store");
    test_make_tmpdir(wire_dir, sizeof(wire_dir), "fleet_ledger", "wire");

    struct fl_box ma, mb, ta, wa, wb;
    bool ma_open = false, mb_open = false, ta_open = false;
    bool wa_open = false, wb_open = false;

    struct mesh_term_fixture f;
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
        ASSERT_EQ(fl_add_usage(&ma, ZCL_FLEET_PROVIDER_GROK, 100, 10, "t1"),
                  ZCL_FLEET_OK);
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
                                          &pair, 1, NULL, ma.seed, NULL),
                  ZCL_FLEET_KIND_NOT_WRITABLE);
        /* A vitals subject past the end of the catalog is not a metric. */
        ASSERT_EQ(zcl_fleet_ledger_append(ma.ledger, ZCL_FLEET_KIND_VITALS,
                                          (uint16_t)zcl_fleet_vital_count(),
                                          &pair, 1, NULL, ma.seed, NULL),
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
        ASSERT(report.status == ZCL_FLEET_CHAIN_BROKEN ||
               report.status == ZCL_FLEET_SIG_INVALID ||
               report.status == ZCL_FLEET_MALFORMED);
        PASS();
    }

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
        ASSERT(fl_box_open(&wa, root, "wire_a", 0x41));
        wa_open = true;
        ASSERT(fl_box_open(&wb, root, "wire_b", 0x51));
        wb_open = true;
        for (int i = 0; i < 3; i++)
            ASSERT_EQ(
                fl_add_usage(&wa, ZCL_FLEET_PROVIDER_GLM, 10 + i, i, "w"),
                ZCL_FLEET_OK);

        ASSERT(mesh_term_fixture_open(&f, wire_dir));
        fixture_open = true;
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
         * delegation lookup, authority and all — opens exactly one stream
         * toward this peer, and refuses nothing. */
        mesh_loop_discard(asker, ask_queue, f.res_term);
        mesh_loop_discard(answerer, answer_queue, f.term_peer.ini);
        mesh_stream_test_reset();
        boot_fleet_ledger_test_pull_paired(wb.ledger, FL_AUTHORITY_NOW);
        ASSERT_EQ(mesh_stream_test_live_count(FLEET_LEDGER_SERVICE_NAME),
                  (size_t)1);
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

        /* PULL: the peer is not asked. No stream is opened at all, and the
         * refusal is counted under the name the catalog already carried. */
        boot_fleet_ledger_test_pull_paired(wb.ledger, FL_AUTHORITY_NOW);
        ASSERT_EQ(mesh_stream_test_live_count(FLEET_LEDGER_SERVICE_NAME),
                  (size_t)0);
        ASSERT_EQ(boot_fleet_ledger_delegation_refused_count(), refused + 1);
        ASSERT_EQ(zcl_fleet_ledger_peer_seq(wb.ledger, wa.box_id), seq_before);

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
    if (wb_open)
        fl_box_close(&wb);
    if (wa_open)
        fl_box_close(&wa);
    if (ta_open)
        fl_box_close(&ta);
    if (mb_open)
        fl_box_close(&mb);
    if (ma_open)
        fl_box_close(&ma);
    test_rm_rf_recursive(wire_dir);
    test_rm_rf_recursive(root);
    return failures;
}
