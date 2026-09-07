/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fleet ROLE ENFORCEMENT: the two places another machine's signed bytes
 * enter this node, and what each does when the signing key holds no role.
 *
 * The neighbouring fleet_roles group proves the catalog and the signed
 * store in isolation. This group proves the WIRING: that
 * zcl_fleet_ledger_replicate() and db_fleet_board_post_ingest() actually
 * ask, that a grant and a revoke are felt on the very next batch and the
 * very next post, and — the one that matters most — that a process with
 * NOTHING installed to answer refuses rather than permits. A gate that is
 * only closed when somebody remembered to close it is not a gate.
 *
 * No clock here is ever read from the wall. Every post carries a
 * created_at the test chose, every ledger row is written against the
 * store's own sequence, and the one delegation this group files is signed
 * for a fixed window that brackets any hour a box could think it is.
 */

#include "test/test_core.h"

#include "util/fleet_role_check.h"
#include "config/boot_fleet_board.h"
#include "config/boot_fleet_ledger.h"
#include "crypto/ed25519.h"
#include "dev/fleet_roles.h"
#include "fleet_enrol.h"
#include "fleetledger/fleet_ledger.h"
#include "models/database.h"
#include "models/fleet_board_post.h"
#include "session/fleet_board_proto.h"
#include "vcs/zcode_dht_delegation.h"
#include "vcs/zcode_dht_identity.h"

#include <stdio.h>
#include <string.h>

/* A fixed delegation window, not one derived from a clock. It is the
 * longest a delegation may claim (ZENDP_MAX_WINDOW_SECONDS) starting at
 * second one, and it is deliberately in the past: filing an operator
 * identity is a key question, not a freshness question, and the bootstrap
 * this group grades reads the key and never the hour. */
#define RE_NOT_BEFORE UINT64_C(1)
#define RE_EXPIRY     UINT64_C(2592001)
#define RE_POST_NOW   INT64_C(100000)
#define RE_ROW_NOW    INT64_C(1000)

/* ── keys ────────────────────────────────────────────────────────────── */

/* Both halves, kept apart on purpose: the role store signs a grant row from
 * the SEED, and a board post is signed with the expanded secret key. A test
 * that handed one where the other was meant would fail for a reason that
 * has nothing to do with roles. */
static void re_key(uint8_t tag, uint8_t pub[32], uint8_t seed[32],
                   uint8_t sk[32])
{
    memset(seed, 0, 32);
    seed[0] = tag;
    seed[31] = (uint8_t)(0xc0 + tag);
    zcl_ed25519_keypair(pub, sk, seed);
}

/* ── the checker under test ──────────────────────────────────────────── */

/* The same shape production installs (tools/dev/fleet_roles_gate.c's
 * gate_allow), against a store this group opened rather than one it had to
 * find: a test that reimplemented the decision would prove only itself. */
static bool re_allow(const uint8_t key[32], const char *leaf, const char *kind,
                     char *why, size_t why_cap, void *ctx)
{
    uint8_t fp[ZCL_ROLE_FP_BYTES];
    zcl_role_fingerprint(key, fp);
    return zcl_role_check((const struct zcl_role_store *)ctx, fp, false, leaf,
                          kind, why, why_cap);
}

static void re_install(struct zcl_role_store *store)
{
    struct zcl_fleet_role_checker c = { .allow = re_allow,
                                        .ctx = store,
                                        .name = "test-role-store" };
    zcl_fleet_role_checker_install(&c);
}


/* ── the production checker's other half ─────────────────────────────── */

/* The grandfathering path mints INTO the store, and a chainlog holds an
 * exclusive lock, so this mirror of gate_allow opens per check exactly as
 * tools/dev/fleet_roles_gate.c does rather than holding a handle open. */
static char g_re_gate_dir[256];

static bool re_gate_allow(const uint8_t key[32], const char *leaf,
                          const char *kind, char *why, size_t why_cap,
                          void *ctx)
{
    (void)ctx;
    uint8_t fp[ZCL_ROLE_FP_BYTES];
    struct zcl_role_report report;
    zcl_role_fingerprint(key, fp);
    struct zcl_role_store *s = zcl_role_store_open(g_re_gate_dir, &report);
    if (!s)
        return false;
    bool ok = zcl_role_check(s, fp, false, leaf, kind, why, why_cap);
    zcl_role_store_close(s);
    return ok;
}

/* The clock is the test's constant, never the wall: what is being graded is
 * which key gets a grant, not what hour it was granted in. */
static bool re_gate_grandfather(const uint8_t key[32], const char *origin,
                                void *ctx)
{
    (void)origin;
    (void)ctx;
    return zcl_fleet_roles_grant_worker(g_re_gate_dir, key, RE_ROW_NOW, NULL);
}

static void re_gate_install(const char *datadir)
{
    (void)snprintf(g_re_gate_dir, sizeof g_re_gate_dir, "%s", datadir);
    struct zcl_fleet_role_checker c = { .allow = re_gate_allow,
                                        .grandfather = re_gate_grandfather,
                                        .ctx = NULL,
                                        .name = "test-role-gate" };
    zcl_fleet_role_checker_install(&c);
}

/* How many rows the signed grant store holds. Idempotence is a claim about
 * ROWS, not about a return value: a bootstrap that re-granted every key
 * would still report the same count. */
static uint64_t re_store_rows(const char *datadir)
{
    struct zcl_role_report report;
    memset(&report, 0, sizeof report);
    struct zcl_role_store *s = zcl_role_store_open(datadir, &report);
    if (!s)
        return 0;
    zcl_role_store_close(s);
    return report.rows;
}

/* ── one ledger box ──────────────────────────────────────────────────── */

struct re_box {
    char dir[320];
    uint8_t seed[32];
    uint8_t box_id[32]; /* the delegation's master key in production */
    uint8_t signer[32]; /* the online key that signs rows */
    struct zcl_fleet_ledger *ledger;
};

static bool re_box_open(struct re_box *b, const char *root, const char *name,
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


/* Reopen one box directory under a DIFFERENT online key, the way a box that
 * rotated its signing key looks to the replica following it. The machine
 * (box_id) does not change; only the key its next rows carry. */
static bool re_box_rotate(struct re_box *b, uint8_t tag)
{
    uint8_t sk[32];
    struct zcl_fleet_report report;
    zcl_fleet_ledger_close(b->ledger);
    memset(b->seed, tag, sizeof b->seed);
    zcl_ed25519_keypair(b->signer, sk, b->seed);
    b->ledger = zcl_fleet_ledger_open(b->dir, b->box_id, b->signer, &report);
    return b->ledger != NULL && report.status == ZCL_FLEET_OK;
}

static void re_box_close(struct re_box *b)
{
    zcl_fleet_ledger_close(b->ledger);
    b->ledger = NULL;
}

static enum zcl_fleet_status re_add_usage(struct re_box *b, int64_t in)
{
    struct zcl_fleet_pair pair = { ZCL_FLEET_PAIR_TOKENS_IN, in };
    return zcl_fleet_ledger_append(b->ledger, ZCL_FLEET_KIND_USAGE,
                                   ZCL_FLEET_PROVIDER_CLAUDE_OPUS, &pair, 1,
                                   NULL, NULL, b->seed, NULL);
}

static size_t re_rows_of(struct re_box *b, uint8_t *out, size_t cap)
{
    size_t len = 0;
    uint64_t last = 0;
    if (zcl_fleet_ledger_read_since(b->ledger, b->box_id, 0, out, cap, &len,
                                    &last) != ZCL_FLEET_OK)
        return 0;
    return len;
}

/* ── one board post ──────────────────────────────────────────────────── */

static enum fleet_board_result re_post(struct node_db *db, const uint8_t seed[32],
                                       const uint8_t pub[32], uint8_t kind,
                                       const char *text)
{
    struct fleet_board_post post;
    memset(&post, 0, sizeof post);
    post.kind = kind;
    post.created_at = (uint64_t)RE_POST_NOW;
    post.ttl = 3600;
    (void)snprintf(post.agent, sizeof post.agent, "%s", "role-lane");
    size_t n = strlen(text);
    memcpy(post.text, text, n);
    post.text[n] = '\0';
    post.text_len = (uint32_t)n;
    enum fleet_board_result r = fleet_board_post_sign(&post, seed, pub);
    if (r != FLEET_BOARD_OK)
        return r;
    return db_fleet_board_post_ingest(db, &post, RE_POST_NOW, NULL);
}

/* ── an operator identity on disk ────────────────────────────────────── */

/* File the delegation and online key `zcl_fleet_roles_bootstrap_keys` needs
 * to sign a grant with, in a datadir this group owns. The window is fixed,
 * not read from a clock. */
static bool re_file_identity(const char *datadir)
{
    uint8_t seed[32], online[32], master_seed[32];
    uint8_t noise[32], beacon[32], genesis[32];
    char err[160];
    if (!vcs_zcode_dht_online_key_load_or_create(datadir, seed, online, err,
                                                 sizeof err))
        return false;
    memset(seed, 0, sizeof seed);
    memset(master_seed, 0x24, sizeof master_seed);
    memset(noise, 0x35, sizeof noise);
    memset(beacon, 0x46, sizeof beacon);
    memset(genesis, 0x57, sizeof genesis);
    struct vcs_zcode_dht_delegation d;
    bool ok = vcs_zcode_dht_delegation_sign(&d, genesis, online, noise, 1,
                                            beacon, RE_NOT_BEFORE, RE_EXPIRY,
                                            1, master_seed) ==
                  VCS_ZCODE_DHT_DELEGATION_OK &&
              vcs_zcode_dht_delegation_save(datadir, &d, err, sizeof err);
    memset(master_seed, 0, sizeof master_seed);
    return ok;
}

int test_fleet_role_enforcement(void)
{
    int failures = 0;
    char root[256];
    char store_dir[256];
    char boot_dir[256];
    test_make_tmpdir(root, sizeof(root), "fleet_role_enforcement", "ledger");
    test_make_tmpdir(store_dir, sizeof(store_dir), "fleet_role_enforcement",
                     "roles");
    test_make_tmpdir(boot_dir, sizeof(boot_dir), "fleet_role_enforcement",
                     "boot");

    uint8_t op_pub[32], op_seed[32], op_sk[32];
    uint8_t stranger_pub[32], stranger_seed[32], stranger_sk[32];
    re_key(0x11, op_pub, op_seed, op_sk);
    re_key(0x12, stranger_pub, stranger_seed, stranger_sk);

    struct zcl_role_store *store = NULL;
    struct re_box a, b, c;
    bool a_open = false, b_open = false, c_open = false;
    uint8_t rows[8192];
    size_t rows_len = 0;

    /* Nothing is installed until a test installs it. Whatever ran before
     * this group in the same binary does not decide what this one proves. */
    zcl_fleet_role_checker_install(NULL);

    TEST("fleet roles: with no checker installed a peer's rows and a peer's "
         "post are both refused, not accepted") {
        ASSERT(!zcl_fleet_role_checker_installed());
        ASSERT(re_box_open(&a, root, "a", 0x21));
        a_open = true;
        ASSERT(re_box_open(&b, root, "b", 0x31));
        b_open = true;
        ASSERT_EQ(re_add_usage(&a, 7), ZCL_FLEET_OK);
        ASSERT_EQ(re_add_usage(&a, 11), ZCL_FLEET_OK);
        rows_len = re_rows_of(&a, rows, sizeof rows);
        ASSERT(rows_len > 0);

        size_t accepted = 99;
        ASSERT_EQ(zcl_fleet_ledger_replicate(b.ledger, a.box_id, a.signer,
                                             rows, rows_len, &accepted),
                  ZCL_FLEET_ROLE_REFUSED);
        ASSERT_EQ(accepted, (size_t)0);
        /* Not one row of a refused batch reached the replica. */
        ASSERT_EQ(zcl_fleet_ledger_peer_seq(b.ledger, a.box_id),
                  UINT64_C(0));

        struct node_db db;
        memset(&db, 0, sizeof db);
        ASSERT(node_db_open(&db, ":memory:"));
        ASSERT_EQ(re_post(&db, op_sk, op_pub, FLEET_BOARD_KIND_NOTE,
                          "nothing installed to ask"),
                  FLEET_BOARD_ERR_ROLE);
        node_db_close(&db);

        /* And the refusal says exactly why, so an operator reading a log
         * learns the gate is unwired rather than that a key is untrusted. */
        char why[ZCL_FLEET_ROLE_WHY_MAX];
        ASSERT(!zcl_fleet_role_allows(op_pub, ZCL_FLEET_LEAF_BOARD_POST,
                                      "note", why, sizeof why));
        ASSERT(strstr(why, "no role checker installed") != NULL);
        PASS();
    }

    TEST("fleet roles: a key holding worker replicates its rows and posts a "
         "note; a key holding nothing is refused at both doors") {
        struct zcl_role_report report;
        store = zcl_role_store_open(store_dir, &report);
        ASSERT(store != NULL);
        re_install(store);
        ASSERT(zcl_fleet_role_checker_installed());

        /* Box a's signing key holds worker; the board key does too. */
        uint8_t signer_fp[ZCL_ROLE_FP_BYTES], op_fp[ZCL_ROLE_FP_BYTES];
        zcl_role_fingerprint(a.signer, signer_fp);
        zcl_role_fingerprint(op_pub, op_fp);
        ASSERT_EQ((int)zcl_role_store_grant(store, signer_fp, ZCL_ROLE_worker,
                                            op_pub, op_seed, RE_ROW_NOW, NULL),
                  (int)ZCL_ROLE_OK);
        ASSERT_EQ((int)zcl_role_store_grant(store, op_fp, ZCL_ROLE_worker,
                                            op_pub, op_seed, RE_ROW_NOW, NULL),
                  (int)ZCL_ROLE_OK);

        size_t accepted = 0;
        ASSERT_EQ(zcl_fleet_ledger_replicate(b.ledger, a.box_id, a.signer,
                                             rows, rows_len, &accepted),
                  ZCL_FLEET_OK);
        ASSERT_EQ(accepted, (size_t)2);
        ASSERT_EQ(zcl_fleet_ledger_peer_seq(b.ledger, a.box_id),
                  UINT64_C(2));

        struct node_db db;
        memset(&db, 0, sizeof db);
        ASSERT(node_db_open(&db, ":memory:"));
        ASSERT_EQ(re_post(&db, op_sk, op_pub, FLEET_BOARD_KIND_NOTE,
                          "a granted key may write here"),
                  FLEET_BOARD_OK);
        /* worker's declared kinds do not include `offer`, so the SAME
         * granted key is refused one: a grant is per kind, not per key. */
        ASSERT_EQ(re_post(&db, op_sk, op_pub, FLEET_BOARD_KIND_OFFER,
                          "a kind this role was never granted"),
                  FLEET_BOARD_ERR_ROLE);
        /* A key with no grant at all is refused. */
        ASSERT_EQ(re_post(&db, stranger_sk, stranger_pub,
                          FLEET_BOARD_KIND_NOTE, "no grant anywhere"),
                  FLEET_BOARD_ERR_ROLE);
        node_db_close(&db);
        PASS();
    }

    TEST("fleet roles: an ungranted signer refuses the WHOLE batch, "
         "including the rows ahead of the one that failed") {
        ASSERT_EQ(re_add_usage(&a, 13), ZCL_FLEET_OK);
        ASSERT_EQ(re_add_usage(&a, 17), ZCL_FLEET_OK);
        uint8_t tail[8192];
        size_t tail_len = 0;
        uint64_t last = 0;
        ASSERT_EQ(zcl_fleet_ledger_read_since(a.ledger, a.box_id, 2, tail,
                                              sizeof tail, &tail_len, &last),
                  ZCL_FLEET_OK);
        ASSERT(tail_len > 0);
        ASSERT_EQ(last, UINT64_C(4));

        /* Box c's key signed nothing this box ever granted. Its batch is
         * well formed, well signed and internally consistent, and it is
         * still refused: a signature is not a permission. */
        ASSERT(re_box_open(&c, root, "c", 0x41));
        c_open = true;
        ASSERT_EQ(re_add_usage(&c, 3), ZCL_FLEET_OK);
        uint8_t c_rows[8192];
        size_t c_len = re_rows_of(&c, c_rows, sizeof c_rows);
        ASSERT(c_len > 0);
        size_t accepted = 99;
        ASSERT_EQ(zcl_fleet_ledger_replicate(b.ledger, c.box_id, c.signer,
                                             c_rows, c_len, &accepted),
                  ZCL_FLEET_ROLE_REFUSED);
        ASSERT_EQ(accepted, (size_t)0);
        ASSERT_EQ(zcl_fleet_ledger_peer_seq(b.ledger, c.box_id),
                  UINT64_C(0));
        re_box_close(&c);
        c_open = false;

        /* The granted box's own tail still lands, so the refusal above was
         * about the key and not about the batch. */
        ASSERT_EQ(zcl_fleet_ledger_replicate(b.ledger, a.box_id, a.signer,
                                             tail, tail_len, &accepted),
                  ZCL_FLEET_OK);
        ASSERT_EQ(accepted, (size_t)2);
        PASS();
    }

    TEST("fleet roles: a revoke is felt on the very next batch and the very "
         "next post") {
        uint8_t signer_fp[ZCL_ROLE_FP_BYTES], op_fp[ZCL_ROLE_FP_BYTES];
        zcl_role_fingerprint(a.signer, signer_fp);
        zcl_role_fingerprint(op_pub, op_fp);
        ASSERT_EQ((int)zcl_role_store_revoke(store, signer_fp, ZCL_ROLE_worker,
                                             op_pub, op_seed, RE_ROW_NOW + 1,
                                             NULL),
                  (int)ZCL_ROLE_OK);
        ASSERT_EQ((int)zcl_role_store_revoke(store, op_fp, ZCL_ROLE_worker,
                                             op_pub, op_seed, RE_ROW_NOW + 1,
                                             NULL),
                  (int)ZCL_ROLE_OK);

        ASSERT_EQ(re_add_usage(&a, 19), ZCL_FLEET_OK);
        uint8_t tail[8192];
        size_t tail_len = 0;
        uint64_t last = 0;
        ASSERT_EQ(zcl_fleet_ledger_read_since(a.ledger, a.box_id, 4, tail,
                                              sizeof tail, &tail_len, &last),
                  ZCL_FLEET_OK);
        ASSERT(tail_len > 0);
        ASSERT_EQ(zcl_fleet_ledger_replicate(b.ledger, a.box_id, a.signer,
                                             tail, tail_len, NULL),
                  ZCL_FLEET_ROLE_REFUSED);
        ASSERT_EQ(zcl_fleet_ledger_peer_seq(b.ledger, a.box_id),
                  UINT64_C(4));

        struct node_db db;
        memset(&db, 0, sizeof db);
        ASSERT(node_db_open(&db, ":memory:"));
        ASSERT_EQ(re_post(&db, op_sk, op_pub, FLEET_BOARD_KIND_NOTE,
                          "revoked between one post and the next"),
                  FLEET_BOARD_ERR_ROLE);
        node_db_close(&db);
        PASS();
    }

    TEST("fleet roles: the enrolment bootstrap grants worker once per key "
         "and mints nothing the second time") {
        const char *why = NULL;
        uint8_t keys[2][32];
        memcpy(keys[0], stranger_pub, 32);
        memcpy(keys[1], op_pub, 32);

        /* A box with no filed delegation mints nothing and says why: it
         * holds no key that could sign a grant. Enforcement still stands —
         * this is the state in which every foreign key is refused. */
        ASSERT_EQ(zcl_fleet_roles_bootstrap_keys(boot_dir, keys, 2, RE_ROW_NOW,
                                                 &why),
                  (size_t)0);
        ASSERT(why != NULL);

        ASSERT(re_file_identity(boot_dir));
        why = NULL;
        ASSERT_EQ(zcl_fleet_roles_bootstrap_keys(boot_dir, keys, 2, RE_ROW_NOW,
                                                 &why),
                  (size_t)2);
        /* Idempotent: running it at every boot writes no second row. */
        ASSERT_EQ(zcl_fleet_roles_bootstrap_keys(boot_dir, keys, 2,
                                                 RE_ROW_NOW + 1, &why),
                  (size_t)0);

        /* And what it minted is a real grant a check can see. */
        struct zcl_role_report report;
        struct zcl_role_store *booted = zcl_role_store_open(boot_dir, &report);
        ASSERT(booted != NULL);
        uint8_t fp[ZCL_ROLE_FP_BYTES];
        zcl_role_fingerprint(stranger_pub, fp);
        ASSERT(zcl_role_store_has_role(booted, fp, ZCL_ROLE_worker));
        ASSERT(zcl_role_check(booted, fp, false, ZCL_FLEET_LEAF_BOARD_POST,
                              "note", NULL, 0));
        ASSERT(zcl_role_check(booted, fp, false,
                              ZCL_FLEET_LEAF_LEDGER_REPLICATE, "usage", NULL,
                              0));
        zcl_role_store_close(booted);
        PASS();
    }

    TEST("fleet roles: admitting a machine grants it worker, and admitting "
         "it again writes no second row") {
        const char *why = NULL;
        uint8_t admitted_pub[32], admitted_seed[32], admitted_sk[32];
        re_key(0x13, admitted_pub, admitted_seed, admitted_sk);
        ASSERT(zcl_fleet_roles_grant_worker(boot_dir, admitted_pub, RE_ROW_NOW,
                                            &why));
        ASSERT(zcl_fleet_roles_grant_worker(boot_dir, admitted_pub,
                                            RE_ROW_NOW + 1, &why));
        struct zcl_role_report report;
        struct zcl_role_store *booted = zcl_role_store_open(boot_dir, &report);
        ASSERT(booted != NULL);
        /* Three keys granted, three rows written: the two the bootstrap
         * minted and this one. A second admit added none. */
        ASSERT_EQ((int)report.rows, 3);
        struct zcl_role_entry entries[8];
        ASSERT_EQ((int)zcl_role_store_list(booted, entries, 8), 3);
        zcl_role_store_close(booted);
        PASS();
    }

    TEST("fleet roles: the keys whose rows this node already holds keep the "
         "standing that storing them implied") {
        char gf_root[256], gf_dir[256];
        test_make_tmpdir(gf_root, sizeof(gf_root), "fleet_role_enforcement",
                         "gf_ledger");
        test_make_tmpdir(gf_dir, sizeof(gf_dir), "fleet_role_enforcement",
                         "gf_boot");
        ASSERT(re_file_identity(gf_dir));

        struct re_box g1, g2, recv;
        ASSERT(re_box_open(&g1, gf_root, "g1", 0x41));
        ASSERT(re_box_open(&g2, gf_root, "g2", 0x42));
        ASSERT(re_box_open(&recv, gf_root, "recv", 0x43));
        ASSERT_EQ(re_add_usage(&g1, 5), ZCL_FLEET_OK);
        ASSERT_EQ(re_add_usage(&g2, 6), ZCL_FLEET_OK);

        /* Yesterday: nothing asked, so both batches were simply accepted.
         * This is the fleet the upgrade lands on. */
        zcl_fleet_role_checker_install_permissive_for_testing();
        uint8_t buf[8192];
        size_t n = re_rows_of(&g1, buf, sizeof buf);
        ASSERT(n > 0);
        ASSERT_EQ(zcl_fleet_ledger_replicate(recv.ledger, g1.box_id, g1.signer,
                                             buf, n, NULL),
                  ZCL_FLEET_OK);
        n = re_rows_of(&g2, buf, sizeof buf);
        ASSERT_EQ(zcl_fleet_ledger_replicate(recv.ledger, g2.box_id, g2.signer,
                                             buf, n, NULL),
                  ZCL_FLEET_OK);

        /* Today: the gate exists, and nothing in the store names either
         * key. Without grandfathering this fleet stops here. */
        re_gate_install(gf_dir);
        ASSERT_EQ(re_add_usage(&g1, 7), ZCL_FLEET_OK);
        uint8_t tail[8192];
        size_t tail_len = 0;
        uint64_t last = 0;
        ASSERT_EQ(zcl_fleet_ledger_read_since(g1.ledger, g1.box_id, 1, tail,
                                              sizeof tail, &tail_len, &last),
                  ZCL_FLEET_OK);
        ASSERT_EQ(zcl_fleet_ledger_replicate(recv.ledger, g1.box_id, g1.signer,
                                             tail, tail_len, NULL),
                  ZCL_FLEET_ROLE_REFUSED);

        /* The boot walk, on the evidence this node already holds. */
        ASSERT_EQ(boot_fleet_ledger_grandfather(recv.ledger), (size_t)2);
        uint64_t rows_after_first = re_store_rows(gf_dir);
        ASSERT_EQ((int)rows_after_first, 2);

        /* The same batch that was refused a moment ago now lands. */
        ASSERT_EQ(zcl_fleet_ledger_replicate(recv.ledger, g1.box_id, g1.signer,
                                             tail, tail_len, NULL),
                  ZCL_FLEET_OK);

        /* A key that never had a row here is still refused: this grants the
         * decision this node already made, and nothing wider. */
        char why[ZCL_FLEET_ROLE_WHY_MAX];
        ASSERT(!zcl_fleet_role_allows(stranger_pub,
                                      ZCL_FLEET_LEAF_LEDGER_REPLICATE, "usage",
                                      why, sizeof why));

        /* Every boot runs it, so running it again must write nothing. */
        ASSERT_EQ(boot_fleet_ledger_grandfather(recv.ledger), (size_t)2);
        ASSERT_EQ((int)re_store_rows(gf_dir), (int)rows_after_first);

        re_box_close(&recv);
        re_box_close(&g2);
        re_box_close(&g1);
        test_rm_rf_recursive(gf_dir);
        test_rm_rf_recursive(gf_root);
        PASS();
    }

    TEST("fleet roles: the keys this node already stores posts from keep "
         "posting, and a key that never posted still cannot") {
        char gb_dir[256];
        test_make_tmpdir(gb_dir, sizeof(gb_dir), "fleet_role_enforcement",
                         "gf_board");
        ASSERT(re_file_identity(gb_dir));

        uint8_t h1_pub[32], h1_seed[32], h1_sk[32];
        uint8_t h2_pub[32], h2_seed[32], h2_sk[32];
        uint8_t h3_pub[32], h3_seed[32], h3_sk[32];
        re_key(0x61, h1_pub, h1_seed, h1_sk);
        re_key(0x62, h2_pub, h2_seed, h2_sk);
        re_key(0x63, h3_pub, h3_seed, h3_sk);

        struct node_db db;
        memset(&db, 0, sizeof db);
        ASSERT(node_db_open(&db, ":memory:"));

        zcl_fleet_role_checker_install_permissive_for_testing();
        ASSERT_EQ(re_post(&db, h1_sk, h1_pub, FLEET_BOARD_KIND_NOTE,
                          "stored the day before enforcement"),
                  FLEET_BOARD_OK);
        ASSERT_EQ(re_post(&db, h2_sk, h2_pub, FLEET_BOARD_KIND_RESULT,
                          "also stored the day before"),
                  FLEET_BOARD_OK);

        re_gate_install(gb_dir);
        ASSERT_EQ(re_post(&db, h1_sk, h1_pub, FLEET_BOARD_KIND_NOTE,
                          "and the morning after"),
                  FLEET_BOARD_ERR_ROLE);

        ASSERT_EQ(boot_fleet_board_grandfather(&db), (size_t)2);
        uint64_t rows_after_first = re_store_rows(gb_dir);
        ASSERT_EQ((int)rows_after_first, 2);
        ASSERT_EQ(re_post(&db, h1_sk, h1_pub, FLEET_BOARD_KIND_NOTE,
                          "and the morning after"),
                  FLEET_BOARD_OK);

        /* The third key posted nothing here, so nothing was decided about
         * it and the door stays shut. */
        ASSERT_EQ(re_post(&db, h3_sk, h3_pub, FLEET_BOARD_KIND_NOTE,
                          "a machine nobody admitted"),
                  FLEET_BOARD_ERR_ROLE);

        ASSERT_EQ(boot_fleet_board_grandfather(&db), (size_t)2);
        ASSERT_EQ((int)re_store_rows(gb_dir), (int)rows_after_first);

        node_db_close(&db);
        test_rm_rf_recursive(gb_dir);
        PASS();
    }

    TEST("fleet roles: an enrolment receipt names the key its box signs "
         "with, and that key is the one admitting grants") {
        char en_dir[256];
        test_make_tmpdir(en_dir, sizeof(en_dir), "fleet_role_enforcement",
                         "enrol");
        ASSERT(re_file_identity(en_dir));

        uint8_t mgr_pub[32], mgr_seed[32], mgr_sk[32];
        uint8_t box_pub[32], box_seed[32], box_sk[32];
        uint8_t sign_pub[32], sign_seed[32], sign_sk[32];
        re_key(0x71, mgr_pub, mgr_seed, mgr_sk);
        re_key(0x72, box_pub, box_seed, box_sk);
        re_key(0x73, sign_pub, sign_seed, sign_sk);

        uint8_t invite_wire[FLEET_ENROL_INVITE_WIRE_MAX];
        char token[FLEET_ENROL_MACHINE_TEXT_MAX];
        char receipt[FLEET_ENROL_MACHINE_TEXT_MAX];
        struct fleet_invite invite;
        struct fleet_box_facts facts;
        struct fleet_receipt parsed;
        struct fleet_signing_key signing;
        size_t invite_len = 0;
        const char *why = NULL;
        memset(&facts, 0, sizeof facts);
        (void)snprintf(facts.hostname, sizeof facts.hostname, "%s", "g1");
        memcpy(signing.pubkey, sign_pub, 32);
        memcpy(signing.seed, sign_seed, 32);

        ASSERT(fleet_invite_mint("studio", 24, "", mgr_seed, mgr_pub,
                                 RE_ROW_NOW, token, sizeof token, &invite,
                                 &why));
        ASSERT(fleet_invite_parse(token, &invite, invite_wire,
                                  sizeof invite_wire, &invite_len, &why));
        ASSERT(fleet_receipt_mint(invite_wire, invite_len, "", &facts, "",
                                  box_seed, box_pub, &signing, receipt,
                                  sizeof receipt, &why));
        ASSERT(fleet_receipt_parse(receipt, &parsed, NULL, 0, NULL, &why));
        /* The signing key travelled, and it is not the box key. */
        ASSERT(memcmp(parsed.signer_pubkey, sign_pub, 32) == 0);
        ASSERT(memcmp(parsed.signer_pubkey, parsed.box_pubkey, 32) != 0);

        /* What admit does with it: grant the key that will actually sign. */
        ASSERT(zcl_fleet_roles_grant_worker(en_dir, parsed.signer_pubkey,
                                            RE_ROW_NOW, &why));
        re_gate_install(en_dir);
        struct node_db db;
        memset(&db, 0, sizeof db);
        ASSERT(node_db_open(&db, ":memory:"));
        ASSERT_EQ(re_post(&db, sign_sk, sign_pub, FLEET_BOARD_KIND_NOTE,
                          "the key the receipt named"),
                  FLEET_BOARD_OK);
        node_db_close(&db);

        /* And a receipt that NAMES a key it cannot prove it holds is
         * refused whole: the operator would have granted a role on it. */
        memcpy(signing.pubkey, sign_pub, 32);
        memcpy(signing.seed, box_seed, 32); /* somebody else's key claimed */
        ASSERT(fleet_receipt_mint(invite_wire, invite_len, "", &facts, "",
                                  box_seed, box_pub, &signing, receipt,
                                  sizeof receipt, &why));
        why = NULL;
        ASSERT(!fleet_receipt_parse(receipt, &parsed, NULL, 0, NULL, &why));
        ASSERT_STR_EQ(why, FLEET_ENROL_WHY_SIGNER_SIGNATURE);
        memset(&signing, 0, sizeof signing);

        test_rm_rf_recursive(en_dir);
        PASS();
    }

    TEST("fleet roles: a ledger with more signers than the walk can carry "
         "says so instead of grandfathering a prefix in silence") {
        char tr_root[256], tr_dir[256];
        test_make_tmpdir(tr_root, sizeof(tr_root), "fleet_role_enforcement",
                         "trunc_ledger");
        test_make_tmpdir(tr_dir, sizeof(tr_dir), "fleet_role_enforcement",
                         "trunc_boot");
        ASSERT(re_file_identity(tr_dir));

        struct re_box sender, recv;
        ASSERT(re_box_open(&sender, tr_root, "rotator", 0x81));
        ASSERT(re_box_open(&recv, tr_root, "recv2", 0x82));

        /* One machine that rotated its online key 65 times, which is one
         * more distinct signer than the walk's key set holds. Everything
         * lands the way it did before roles existed. */
        zcl_fleet_role_checker_install_permissive_for_testing();
        uint8_t buf[8192];
        for (unsigned i = 0; i < 65u; i++) {
            ASSERT(re_box_rotate(&sender, (uint8_t)(0x90u + i)));
            ASSERT_EQ(re_add_usage(&sender, (int64_t)(i + 1u)), ZCL_FLEET_OK);
            size_t len = 0;
            uint64_t last = 0;
            ASSERT_EQ(zcl_fleet_ledger_read_since(sender.ledger,
                                                  sender.box_id, i, buf,
                                                  sizeof buf, &len, &last),
                      ZCL_FLEET_OK);
            ASSERT(len > 0);
            ASSERT_EQ(zcl_fleet_ledger_replicate(recv.ledger, sender.box_id,
                                                 sender.signer, buf, len,
                                                 NULL),
                      ZCL_FLEET_OK);
        }

        re_gate_install(tr_dir);
        uint64_t before = boot_fleet_ledger_grandfather_truncated_count();
        /* 64 of the 65 are granted, and the 65th is not quietly dropped:
         * the counter is bumped in the same branch as the WARN that names
         * the count and the bound. */
        ASSERT_EQ(boot_fleet_ledger_grandfather(recv.ledger), (size_t)64);
        ASSERT_EQ((int)(boot_fleet_ledger_grandfather_truncated_count() -
                        before),
                  1);

        re_box_close(&recv);
        re_box_close(&sender);
        test_rm_rf_recursive(tr_dir);
        test_rm_rf_recursive(tr_root);
        PASS();
    }

    TEST("fleet roles: a board with more posting keys than the host scan "
         "can carry says so instead of granting a prefix in silence") {
        char tb_dir[256];
        test_make_tmpdir(tb_dir, sizeof(tb_dir), "fleet_role_enforcement",
                         "trunc_board");
        ASSERT(re_file_identity(tb_dir));

        struct node_db db;
        memset(&db, 0, sizeof db);
        ASSERT(node_db_open(&db, ":memory:"));

        /* 65 distinct machines posted here before roles existed: one more
         * than FLEET_BOARD_HOST_LIST_MAX. */
        zcl_fleet_role_checker_install_permissive_for_testing();
        for (unsigned i = 0; i < 65u; i++) {
            uint8_t pub[32], seed[32], sk[32];
            char text[64];
            re_key((uint8_t)(0x90u + i), pub, seed, sk);
            (void)snprintf(text, sizeof text, "post from machine %u", i);
            ASSERT_EQ(re_post(&db, sk, pub, FLEET_BOARD_KIND_NOTE, text),
                      FLEET_BOARD_OK);
        }

        re_gate_install(tb_dir);
        uint64_t before = boot_fleet_board_grandfather_truncated_count();
        ASSERT_EQ(boot_fleet_board_grandfather(&db), (size_t)64);
        ASSERT_EQ((int)(boot_fleet_board_grandfather_truncated_count() -
                        before),
                  1);

        node_db_close(&db);
        test_rm_rf_recursive(tb_dir);
        PASS();
    }

_test_next:
    if (c_open)
        re_box_close(&c);
    if (b_open)
        re_box_close(&b);
    if (a_open)
        re_box_close(&a);
    if (store)
        zcl_role_store_close(store);
    zcl_fleet_role_checker_install(NULL);
    test_rm_rf_recursive(boot_dir);
    test_rm_rf_recursive(store_dir);
    test_rm_rf_recursive(root);
    return failures;
}
