/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_epoch — the `core epoch` command layer
 * (tools/command/native_epoch_command.c).
 *
 * The libraries under these handlers (zanc codec, the op_return catalog
 * cursor) are covered by test_zanc / test_op_return_index. This group
 * covers the WIRING, which is where the bugs have actually been: the
 * live anchor path once sent a bare JSON object where the RPC dispatcher
 * expects a params array, so it could never have worked, and nothing
 * caught it.
 *
 * Coverage:
 *   1. datadir resolution — explicit, absent (no --datadir default), and
 *      a datadir with no node.db.
 *   2. the two blocking paths — CATALOG_CURSOR_UNREADABLE (a refused
 *      persisted record) and CATALOG_EMPTY (nothing folded yet).
 *   3. base_height / base_digest / partial_coverage round-trip through
 *      status, anchor and verify — an epoch anchor is a commitment over a
 *      DECLARED range, so every surface that publishes the digest must
 *      publish the range with it.
 *   4. verify --height against the local checkpoint: genuine match,
 *      genuine mismatch, and the no-checkpoint case naming its reason.
 *   5. the paging path — an epoch anchor buried under more than 100
 *      newer unrelated anchors is still found. This was a SILENT WRONG
 *      ANSWER ("anchored: false" for an anchor that is on-chain).
 *   6. cross-operator agreement — two agreeing anchors, two disagreeing
 *      anchors (non-zero exit, report intact), and a local base above the
 *      height reported incomparable rather than disagreeing.
 *   7. the offline path's op_return_hex round-trips through zanc_parse,
 *      enters a simnet block, and rebuilds the exact ZANC projection.
 *   8. epoch arithmetic (cursor/1000) matches dumpstate zepoch exactly.
 *
 * Hermetic: per-pid ./test-tmp datadirs, no network, no wallet, no live
 * node. node_rpc_call is stubbed for the whole group (see epoch_rpc_stub)
 * so the anchor handler can NEVER reach a running node — the offline
 * op_return_hex branch is the only branch these tests exercise. Its bytes
 * are mined only in the RAM-only simnet fixture; nothing is broadcast.
 */

#include "test/test_core.h"

#include "command/native_command.h"

#include "controllers/rpc_client.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "models/database.h"
#include "models/op_return_index.h"
#include "models/zanc.h"
#include "services/op_return_backfill_service.h"
#include "test/transaction_lab_simnet.h"
#include "zanc/zanc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── RPC containment ────────────────────────────────────────────────
 *
 * `core epoch anchor` prefers a live node. In a test process that must
 * be impossible, not merely unlikely: this stub answers every RPC with a
 * transport error, so the handler always takes the offline branch and
 * `anchor_publish` is never dispatched anywhere. Installed for the whole
 * group and cleared at the end. */
static int g_epoch_rpc_calls;

static char *epoch_rpc_stub(const char *method, const char *params_json)
{
    (void)params_json;
    g_epoch_rpc_calls++;
    char *out = malloc(256); // raw-alloc-ok:test-fixture
    if (!out)
        return NULL;
    snprintf(out, 256,
             "{\"error\":{\"code\":-1,\"message\":\"test stub refused %s\"}}",
             method ? method : "(null)");
    return out;
}

/* ── in-process command runner (test_zcode_publish.c shape) ────────── */

struct ep_cmd {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void ep_cmd_init(struct ep_cmd *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    zcl_command_reply_init(&c->reply, "zcl.core_epoch_test.v1");
}

static void ep_cmd_free(struct ep_cmd *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

/* ── reply readers (absent key never reads as a value) ─────────────── */

static const char *ep_str(const struct zcl_command_reply *r, const char *key)
{
    const struct json_value *v = json_get(&r->data, key);
    return (v && v->type == JSON_STR) ? json_get_str(v) : NULL;
}

static bool ep_has(const struct zcl_command_reply *r, const char *key)
{
    return json_get(&r->data, key) != NULL;
}

/* Missing/typed-wrong reads back as `absent`, so a test can never pass by
 * reading a default off a key the handler forgot to publish. */
static int64_t ep_int(const struct zcl_command_reply *r, const char *key,
                      int64_t absent)
{
    const struct json_value *v = json_get(&r->data, key);
    return (v && v->type == JSON_INT) ? json_get_int(v) : absent;
}

static int ep_bool(const struct zcl_command_reply *r, const char *key)
{
    const struct json_value *v = json_get(&r->data, key);
    if (!v || v->type != JSON_BOOL)
        return -1;
    return json_get_bool(v) ? 1 : 0;
}

static bool ep_str_is(const struct zcl_command_reply *r, const char *key,
                      const char *want)
{
    const char *got = ep_str(r, key);
    return got && strcmp(got, want) == 0;
}

static bool ep_failed_with(const struct zcl_command_reply *r,
                           enum zcl_command_status status,
                           enum zcl_command_exit exit_code, const char *code)
{
    return r->status == status && r->exit_code == exit_code &&
           strcmp(r->error.code, code) == 0;
}

/* ── fixture ───────────────────────────────────────────────────────── */

struct ep_fixture {
    char datadir[256];
    char dbpath[320];
    struct node_db ndb;
    bool open;
};

static bool ep_fixture_init(struct ep_fixture *f, const char *tag)
{
    memset(f, 0, sizeof(*f));
    snprintf(f->datadir, sizeof(f->datadir), "./test-tmp/%d_epoch_%s",
             (int)getpid(), tag);
    mkdir("./test-tmp", 0755);
    char rm[512];
    snprintf(rm, sizeof(rm), "rm -rf %s", f->datadir);
    (void)system(rm);
    if (mkdir(f->datadir, 0755) != 0)
        return false;
    snprintf(f->dbpath, sizeof(f->dbpath), "%s/node.db", f->datadir);
    if (!node_db_open(&f->ndb, f->dbpath))
        return false;
    f->open = true;
    return true;
}

/* The handlers open <datadir>/node.db READONLY on their own connection.
 * Close the writer first so what they read is exactly what was committed. */
static void ep_fixture_seal(struct ep_fixture *f)
{
    if (f->open) {
        node_db_close(&f->ndb);
        f->open = false;
    }
}

static bool ep_fixture_reopen(struct ep_fixture *f)
{
    if (f->open)
        return true;
    if (!node_db_open(&f->ndb, f->dbpath))
        return false;
    f->open = true;
    return true;
}

static void ep_fixture_free(struct ep_fixture *f)
{
    ep_fixture_seal(f);
    char rm[512];
    snprintf(rm, sizeof(rm), "rm -rf %s", f->datadir);
    (void)system(rm);
}

/* Plant a catalog cursor: the chain declares [base_height, height]. */
static bool ep_set_cursor(struct ep_fixture *f, int32_t base_height,
                          uint8_t base_fill, int32_t height, uint8_t fill)
{
    struct op_return_index_cursor cur;
    memset(&cur, 0, sizeof(cur));
    cur.base_height = base_height;
    memset(cur.base_digest, base_fill, 32);
    cur.height = height;
    memset(cur.digest, fill, 32);
    return op_return_index_set_cursor(&f->ndb, &cur);
}

/* Plant one anchor row. `seed` makes the txid unique. */
static bool ep_put_anchor(struct ep_fixture *f, uint32_t seed, int32_t height,
                          uint8_t digest_fill, const char *label)
{
    struct zanc_anchor a;
    memset(&a, 0, sizeof(a));
    memcpy(a.txid, &seed, sizeof(seed));
    a.txid[31] = 0xA5; /* never all-zero (the validator rejects that) */
    a.height = height;
    a.hash_type = ZANC_HASH_SHA3_256;
    memset(a.digest, digest_fill, 32);
    snprintf(a.label, sizeof(a.label), "%s", label);
    return db_zanc_save(&f->ndb, &a);
}

static void ep_hex32(uint8_t fill, char out[65])
{
    uint8_t buf[32];
    memset(buf, fill, 32);
    HexStr(buf, 32, false, out, 65);
}

/* ── 1. datadir resolution ─────────────────────────────────────────── */

static int test_epoch_datadir(void)
{
    int failures = 0;
    struct ep_fixture f;

    printf("epoch datadir: fixture datadir with a migrated node.db... ");
    if (ep_fixture_init(&f, "datadir")) printf("OK\n");
    else { printf("FAIL\n"); return 1; }

    ep_set_cursor(&f, 0, 0x00, 4321, 0x11);
    ep_fixture_seal(&f);

    printf("epoch datadir: explicit --datadir is used verbatim... ");
    {
        struct ep_cmd c;
        ep_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        zcl_native_handle_core_epoch_status(&c.request, &c.reply);
        bool ok = c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
                  ep_str_is(&c.reply, "datadir", f.datadir) &&
                  ep_int(&c.reply, "tip_height", -1) == 4321;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        ep_cmd_free(&c);
    }

    /* No input datadir and no CLI --datadir (the bridge global is empty in
     * a test process): the handler must REFUSE, never silently pick a
     * default datadir and answer about somebody else's node. */
    printf("epoch datadir: absent datadir refuses with MISSING_DATADIR "
           "instead of defaulting... ");
    {
        struct ep_cmd c;
        ep_cmd_init(&c);
        zcl_native_handle_core_epoch_status(&c.request, &c.reply);
        bool ok = ep_failed_with(&c.reply, ZCL_COMMAND_STATUS_FAILED,
                                 ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR");
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        ep_cmd_free(&c);
    }

    printf("epoch datadir: a datadir with no node.db BLOCKS, retryable, "
           "naming the path... ");
    {
        char missing[300];
        snprintf(missing, sizeof(missing), "%s/nope", f.datadir);
        struct ep_cmd c;
        ep_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", missing);
        zcl_native_handle_core_epoch_status(&c.request, &c.reply);
        bool ok = ep_failed_with(&c.reply, ZCL_COMMAND_STATUS_BLOCKED,
                                 ZCL_COMMAND_EXIT_BLOCKED,
                                 "NODE_DB_UNAVAILABLE") &&
                  c.reply.error.retryable &&
                  strstr(c.reply.error.evidence, "nope/node.db") != NULL;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        ep_cmd_free(&c);
    }

    /* All three leaves share ep_datadir — prove the refusal is uniform. */
    printf("epoch datadir: anchor and verify refuse an absent datadir too... ");
    {
        struct ep_cmd a, v;
        ep_cmd_init(&a);
        ep_cmd_init(&v);
        zcl_native_handle_core_epoch_anchor(&a.request, &a.reply);
        zcl_native_handle_core_epoch_verify(&v.request, &v.reply);
        bool ok = ep_failed_with(&a.reply, ZCL_COMMAND_STATUS_FAILED,
                                 ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR") &&
                  ep_failed_with(&v.reply, ZCL_COMMAND_STATUS_FAILED,
                                 ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR");
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        ep_cmd_free(&a);
        ep_cmd_free(&v);
    }

    ep_fixture_free(&f);
    return failures;
}

/* ── 2. blocking paths ─────────────────────────────────────────────── */

static int test_epoch_blockers(void)
{
    int failures = 0;
    struct ep_fixture f;

    printf("epoch blockers: fixture... ");
    if (ep_fixture_init(&f, "blockers")) printf("OK\n");
    else { printf("FAIL\n"); return 1; }

    /* A fresh catalog: the cursor record reads EMPTY (height -1). Nothing
     * has been folded, so there is no digest to anchor or verify. */
    ep_fixture_seal(&f);

    printf("epoch blockers: anchor on an unfolded catalog BLOCKS with "
           "CATALOG_EMPTY... ");
    {
        struct ep_cmd c;
        ep_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        zcl_native_handle_core_epoch_anchor(&c.request, &c.reply);
        bool ok = ep_failed_with(&c.reply, ZCL_COMMAND_STATUS_BLOCKED,
                                 ZCL_COMMAND_EXIT_BLOCKED, "CATALOG_EMPTY") &&
                  c.reply.error.retryable;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        ep_cmd_free(&c);
    }

    printf("epoch blockers: verify (tip) on an unfolded catalog BLOCKS with "
           "CATALOG_EMPTY... ");
    {
        struct ep_cmd c;
        ep_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        zcl_native_handle_core_epoch_verify(&c.request, &c.reply);
        bool ok = ep_failed_with(&c.reply, ZCL_COMMAND_STATUS_BLOCKED,
                                 ZCL_COMMAND_EXIT_BLOCKED, "CATALOG_EMPTY");
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        ep_cmd_free(&c);
    }

    /* A LEGACY v1 record is a REFUSAL, not "nothing folded yet": it is a
     * genesis-rooted digest with no declared base, and reading it as a
     * range commitment would publish a range the chain never agreed to.
     * op_return_index_get_cursor returns false, and status must surface
     * that as its own named blocker. */
    printf("epoch blockers: a refused (legacy v1) cursor record BLOCKS with "
           "CATALOG_CURSOR_UNREADABLE... ");
    {
        bool planted = false;
        if (ep_fixture_reopen(&f)) {
            uint8_t legacy_digest[32];
            memset(legacy_digest, 0x3C, 32);
            planted = node_db_state_set_int(&f.ndb,
                          "op_return_index_cursor_height", 4242) &&
                      node_db_state_set(&f.ndb, "op_return_index_digest",
                                        legacy_digest, 32) &&
                      op_return_index_state_version(&f.ndb) ==
                          OP_RETURN_INDEX_STATE_LEGACY_V1;
        }
        ep_fixture_seal(&f);
        struct ep_cmd c;
        ep_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        zcl_native_handle_core_epoch_status(&c.request, &c.reply);
        bool ok = planted &&
                  ep_failed_with(&c.reply, ZCL_COMMAND_STATUS_BLOCKED,
                                 ZCL_COMMAND_EXIT_BLOCKED,
                                 "CATALOG_CURSOR_UNREADABLE") &&
                  /* The blocker must NOT be dressed up as a real answer. */
                  !ep_has(&c.reply, "tip_height") &&
                  !ep_has(&c.reply, "catalog_digest");
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        ep_cmd_free(&c);
    }

    ep_fixture_free(&f);
    return failures;
}

/* ── 3. declared range round-trip ──────────────────────────────────── */

static int test_epoch_declared_range(void)
{
    int failures = 0;
    struct ep_fixture f;

    printf("epoch range: fixture... ");
    if (ep_fixture_init(&f, "range")) printf("OK\n");
    else { printf("FAIL\n"); return 1; }

    const int32_t base = 3056000, head = 3056999;
    char want_base_hex[65], want_digest_hex[65];
    ep_hex32(0xB1, want_base_hex);
    ep_hex32(0xD1, want_digest_hex);
    bool planted = ep_set_cursor(&f, base, 0xB1, head, 0xD1);
    ep_fixture_seal(&f);

    printf("epoch range: status publishes base_height/base_digest/"
           "partial_coverage next to the digest... ");
    {
        struct ep_cmd c;
        ep_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        zcl_native_handle_core_epoch_status(&c.request, &c.reply);
        bool ok = planted && c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
                  ep_int(&c.reply, "base_height", -1) == base &&
                  ep_str_is(&c.reply, "base_digest", want_base_hex) &&
                  ep_bool(&c.reply, "partial_coverage") == 1 &&
                  ep_int(&c.reply, "tip_height", -1) == head &&
                  ep_str_is(&c.reply, "catalog_digest", want_digest_hex);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        ep_cmd_free(&c);
    }

    printf("epoch range: anchor publishes the SAME declared range as "
           "status... ");
    {
        struct ep_cmd c;
        ep_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        zcl_native_handle_core_epoch_anchor(&c.request, &c.reply);
        bool ok = c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
                  ep_int(&c.reply, "base_height", -1) == base &&
                  ep_str_is(&c.reply, "base_digest", want_base_hex) &&
                  ep_bool(&c.reply, "partial_coverage") == 1 &&
                  ep_str_is(&c.reply, "digest", want_digest_hex);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        ep_cmd_free(&c);
    }

    printf("epoch range: verify publishes the SAME declared range as "
           "status... ");
    {
        struct ep_cmd c;
        ep_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        zcl_native_handle_core_epoch_verify(&c.request, &c.reply);
        bool ok = c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
                  ep_int(&c.reply, "base_height", -1) == base &&
                  ep_str_is(&c.reply, "base_digest", want_base_hex) &&
                  ep_bool(&c.reply, "partial_coverage") == 1;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        ep_cmd_free(&c);
    }

    /* base_height 0 is the genesis-rooted chain: full coverage, and the
     * flag must say so rather than being permanently true. */
    printf("epoch range: a genesis-rooted chain reports "
           "partial_coverage=false... ");
    {
        bool ok = ep_fixture_reopen(&f) && ep_set_cursor(&f, 0, 0x00, 999, 0xD2);
        ep_fixture_seal(&f);
        struct ep_cmd c;
        ep_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        zcl_native_handle_core_epoch_status(&c.request, &c.reply);
        ok = ok && ep_int(&c.reply, "base_height", -1) == 0 &&
             ep_bool(&c.reply, "partial_coverage") == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        ep_cmd_free(&c);
    }

    ep_fixture_free(&f);
    return failures;
}

/* ── 4. verify --height against the local checkpoint ───────────────── */

/* Build a fixture whose cursor sits at `cursor_h` over [base, cursor_h]
 * with digest fill `fill`, plus the anchors the caller plants. */
static int ep_verify_case(const char *tag, const char *what,
                          int32_t base, int32_t cursor_h, uint8_t local_fill,
                          int32_t want_h,
                          bool (*plant)(struct ep_fixture *),
                          bool (*check)(const struct zcl_command_reply *))
{
    struct ep_fixture f;
    if (!ep_fixture_init(&f, tag)) {
        printf("epoch verify: %s... FAIL (fixture)\n", what);
        return 1;
    }
    bool ok = ep_set_cursor(&f, base, 0xB0, cursor_h, local_fill) &&
              (!plant || plant(&f));
    ep_fixture_seal(&f);

    struct ep_cmd c;
    ep_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", f.datadir);
    (void)json_push_kv_int(&c.input, "height", want_h);
    zcl_native_handle_core_epoch_verify(&c.request, &c.reply);

    printf("epoch verify: %s... ", what);
    ok = ok && check(&c.reply);
    int failures;
    if (ok) { printf("OK\n"); failures = 0; }
    else { printf("FAIL\n"); failures = 1; }

    ep_cmd_free(&c);
    ep_fixture_free(&f);
    return failures;
}

#define EP_H 3056999

static bool ep_plant_matching(struct ep_fixture *f)
{
    return ep_put_anchor(f, 1, 3057100, 0xD1, "zepoch@3056999");
}

static bool ep_check_match(const struct zcl_command_reply *r)
{
    return r->status == ZCL_COMMAND_STATUS_PASSED &&
           r->exit_code == ZCL_COMMAND_EXIT_OK &&
           ep_bool(r, "anchored") == 1 &&
           ep_int(r, "anchor_count", -1) == 1 &&
           ep_bool(r, "local_digest_available") == 1 &&
           ep_str_is(r, "local_digest_reason", "local_checkpoint_at_height") &&
           ep_str_is(r, "comparison", "match") &&
           ep_int(r, "agree_count", -1) == 1 &&
           ep_int(r, "disagree_count", -1) == 0 &&
           ep_int(r, "distinct_roots", -1) == 1 &&
           ep_bool(r, "disagreement") == 0;
}

static bool ep_plant_conflicting(struct ep_fixture *f)
{
    /* Same height, different bytes than the local digest (0xD1). */
    return ep_put_anchor(f, 2, 3057100, 0xEE, "zepoch@3056999");
}

static bool ep_check_mismatch(const struct zcl_command_reply *r)
{
    /* A disagreement is BOTH a full report and a non-zero exit — the
     * data body must survive zcl_command_reply_fail. */
    return ep_failed_with(r, ZCL_COMMAND_STATUS_FAILED,
                          ZCL_COMMAND_EXIT_FAILED,
                          "EPOCH_DIGEST_DISAGREEMENT") &&
           ep_str_is(r, "comparison", "mismatch") &&
           ep_int(r, "disagree_count", -1) == 1 &&
           ep_int(r, "agree_count", -1) == 0 &&
           ep_bool(r, "disagreement") == 1 &&
           ep_bool(r, "local_digest_available") == 1 &&
           strstr(r->error.evidence, "height=3056999") != NULL;
}

static bool ep_check_no_checkpoint(const struct zcl_command_reply *r)
{
    /* Cursor is elsewhere: no local digest for this height. The reason is
     * NAMED and the comparison is never silently a match. */
    return r->status == ZCL_COMMAND_STATUS_PASSED &&
           ep_bool(r, "anchored") == 1 &&
           ep_bool(r, "local_digest_available") == 0 &&
           ep_str_is(r, "local_digest_reason",
                     "no_local_checkpoint_at_height") &&
           ep_str_is(r, "comparison", "no_local_checkpoint") &&
           ep_int(r, "unverifiable_count", -1) == 1 &&
           ep_int(r, "agree_count", -1) == 0 &&
           ep_int(r, "disagree_count", -1) == 0 &&
           ep_bool(r, "disagreement") == 0 &&
           !ep_has(r, "local_digest");
}

static bool ep_check_no_anchor(const struct zcl_command_reply *r)
{
    return r->status == ZCL_COMMAND_STATUS_PASSED &&
           ep_bool(r, "anchored") == 0 &&
           ep_int(r, "anchor_count", -1) == 0 &&
           ep_str_is(r, "comparison", "no_anchor") &&
           ep_bool(r, "disagreement") == 0;
}

static int test_epoch_verify_height(void)
{
    int failures = 0;

    failures += ep_verify_case(
        "vmatch", "a matching anchor at the cursor height is a genuine match",
        0, EP_H, 0xD1, EP_H, ep_plant_matching, ep_check_match);

    failures += ep_verify_case(
        "vmiss", "a conflicting anchor at the cursor height is a genuine "
        "mismatch with a non-zero exit AND the report intact",
        0, EP_H, 0xD1, EP_H, ep_plant_conflicting, ep_check_mismatch);

    failures += ep_verify_case(
        "vnockpt", "an anchor at a height the cursor never sat on reports a "
        "NAMED no-checkpoint reason, not a match",
        0, EP_H + 5000, 0xD1, EP_H, ep_plant_matching, ep_check_no_checkpoint);

    failures += ep_verify_case(
        "vnone", "no anchor at the height reports no_anchor, not a "
        "disagreement", 0, EP_H, 0xD1, EP_H, NULL, ep_check_no_anchor);

    return failures;
}

/* ── 5. paging: an anchor buried under >100 newer anchors ──────────── */

static int test_epoch_paging(void)
{
    int failures = 0;
    struct ep_fixture f;

    printf("epoch paging: fixture... ");
    if (ep_fixture_init(&f, "paging")) printf("OK\n");
    else { printf("FAIL\n"); return 1; }

    /* THE REGRESSION. The epoch anchor is at chain height 10. Above it sit
     * 150 unrelated anchors (ZSLP/ZNAM/zcode families — routine on a live
     * chain). The old code read the newest 100 anchors of ANY label, so
     * this anchor was invisible and both status and verify answered
     * "anchored: false" for an anchor that is on-chain. */
    const int32_t epoch_h = 7000;
    bool planted = ep_put_anchor(&f, 9001, 10, 0xD7, "zepoch@7000");
    for (uint32_t i = 0; i < 150 && planted; i++) {
        char label[64];
        snprintf(label, sizeof(label), "zslp@%u", i);
        planted = ep_put_anchor(&f, 20000 + i, 1000 + (int32_t)i, 0x40,
                                label);
    }
    planted = planted && ep_set_cursor(&f, 0, 0x00, epoch_h, 0xD7);
    ep_fixture_seal(&f);

    printf("epoch paging: 150 newer unrelated anchors do not hide the epoch "
           "anchor from verify --height... ");
    {
        struct ep_cmd c;
        ep_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        (void)json_push_kv_int(&c.input, "height", epoch_h);
        zcl_native_handle_core_epoch_verify(&c.request, &c.reply);
        bool ok = planted && ep_bool(&c.reply, "anchored") == 1 &&
                  ep_int(&c.reply, "anchor_count", -1) == 1 &&
                  ep_str_is(&c.reply, "comparison", "match") &&
                  /* The scan is label-filtered: it walks the epoch anchors,
                   * not all 151 rows. */
                  ep_int(&c.reply, "anchors_scanned", -1) == 1 &&
                  ep_bool(&c.reply, "truncated") == -1;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        ep_cmd_free(&c);
    }

    printf("epoch paging: status also still sees it... ");
    {
        struct ep_cmd c;
        ep_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        zcl_native_handle_core_epoch_status(&c.request, &c.reply);
        bool ok = ep_bool(&c.reply, "anchored") == 1 &&
                  ep_bool(&c.reply, "digest_match") == 1;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        ep_cmd_free(&c);
    }

    /* Now bury it under 150 newer ZEPOCH anchors too, so even the filtered
     * scan must page: one SQL page is 128 rows. */
    printf("epoch paging: the filtered scan pages past its own page size "
           "(151 epoch anchors, the oldest still found)... ");
    {
        bool ok = ep_fixture_reopen(&f);
        for (uint32_t i = 0; i < 150 && ok; i++) {
            char label[64];
            snprintf(label, sizeof(label), "zepoch@%u", 8000 + i);
            ok = ep_put_anchor(&f, 30000 + i, 2000 + (int32_t)i, 0x50, label);
        }
        ep_fixture_seal(&f);

        struct ep_cmd c;
        ep_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        (void)json_push_kv_int(&c.input, "height", epoch_h);
        zcl_native_handle_core_epoch_verify(&c.request, &c.reply);
        ok = ok && ep_bool(&c.reply, "anchored") == 1 &&
             ep_int(&c.reply, "anchor_count", -1) == 1 &&
             ep_int(&c.reply, "anchors_scanned", -1) == 151 &&
             ep_str_is(&c.reply, "comparison", "match");
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        ep_cmd_free(&c);
    }

    /* status picks the anchor with the greatest LABEL height in the epoch,
     * which is the one the paged scan had to walk the whole family to see:
     * its chain height (2149) is not the newest row, and its label height
     * (8149) is not in the current epoch unless the cursor is there. */
    printf("epoch paging: the latest-in-epoch anchor is chosen by LABEL "
           "height across every page... ");
    {
        bool ok = ep_fixture_reopen(&f) &&
                  ep_set_cursor(&f, 0, 0x00, 8149, 0x50);
        ep_fixture_seal(&f);
        struct ep_cmd c;
        ep_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        zcl_native_handle_core_epoch_status(&c.request, &c.reply);
        const struct json_value *a = json_get(&c.reply.data, "anchor");
        const struct json_value *lv = a ? json_get(a, "label") : NULL;
        const char *label = (lv && lv->type == JSON_STR) ? json_get_str(lv)
                                                         : NULL;
        ok = ok && ep_bool(&c.reply, "anchored") == 1 && label &&
             strcmp(label, "zepoch@8149") == 0 &&
             ep_int(&c.reply, "epoch", -1) == 8;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        ep_cmd_free(&c);
    }

    ep_fixture_free(&f);
    return failures;
}

/* ── 6. cross-operator agreement ───────────────────────────────────── */

static int test_epoch_agreement(void)
{
    int failures = 0;
    struct ep_fixture f;

    printf("epoch agree: fixture... ");
    if (ep_fixture_init(&f, "agree")) printf("OK\n");
    else { printf("FAIL\n"); return 1; }

    printf("epoch agree: two operators anchoring the SAME digest agree "
           "(one root, no finding)... ");
    {
        bool ok = ep_put_anchor(&f, 41, 9100, 0xC3, "zepoch@8999") &&
                  ep_put_anchor(&f, 42, 9200, 0xC3, "zepoch@8999") &&
                  ep_set_cursor(&f, 0, 0x00, 8999, 0xC3);
        ep_fixture_seal(&f);
        struct ep_cmd c;
        ep_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        (void)json_push_kv_int(&c.input, "height", 8999);
        zcl_native_handle_core_epoch_verify(&c.request, &c.reply);
        ok = ok && c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             ep_int(&c.reply, "anchor_count", -1) == 2 &&
             ep_int(&c.reply, "distinct_roots", -1) == 1 &&
             ep_int(&c.reply, "agree_count", -1) == 2 &&
             ep_bool(&c.reply, "disagreement") == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        ep_cmd_free(&c);
    }

    printf("epoch agree: two operators anchoring DIFFERENT digests is a "
           "finding with a non-zero exit... ");
    {
        bool ok = ep_fixture_reopen(&f) &&
                  ep_put_anchor(&f, 43, 9300, 0x77, "zepoch@8999");
        ep_fixture_seal(&f);
        struct ep_cmd c;
        ep_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        (void)json_push_kv_int(&c.input, "height", 8999);
        zcl_native_handle_core_epoch_verify(&c.request, &c.reply);
        ok = ok && ep_failed_with(&c.reply, ZCL_COMMAND_STATUS_FAILED,
                                  ZCL_COMMAND_EXIT_FAILED,
                                  "EPOCH_DIGEST_DISAGREEMENT") &&
             ep_int(&c.reply, "anchor_count", -1) == 3 &&
             ep_int(&c.reply, "distinct_roots", -1) == 2 &&
             ep_bool(&c.reply, "disagreement") == 1 &&
             /* The report survives the failure envelope. */
             ep_int(&c.reply, "agree_count", -1) == 2 &&
             ep_int(&c.reply, "disagree_count", -1) == 1;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        ep_cmd_free(&c);
    }

    ep_fixture_free(&f);

    /* THE case that must not be collapsed into "disagree": a bounded node
     * whose declared base is ABOVE the anchored height never folded that
     * height. base_height/base_digest are folded into every preimage, so
     * its digest and the anchor's digest are commitments over different
     * ranges — they are SUPPOSED to differ. Reporting that as disagreement
     * would cry wolf every time a bounded node met an archival one. */
    printf("epoch agree: a local base ABOVE the height is incomparable, not "
           "disagreeing... ");
    {
        struct ep_fixture g;
        bool ok = ep_fixture_init(&g, "incomp");
        ok = ok && ep_put_anchor(&g, 51, 9400, 0x11, "zepoch@5000") &&
             /* declared range [6000, 9999] — 5000 is below the base. */
             ep_set_cursor(&g, 6000, 0xB6, 9999, 0x22);
        ep_fixture_seal(&g);
        struct ep_cmd c;
        ep_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", g.datadir);
        (void)json_push_kv_int(&c.input, "height", 5000);
        zcl_native_handle_core_epoch_verify(&c.request, &c.reply);
        ok = ok && c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             c.reply.exit_code == ZCL_COMMAND_EXIT_OK &&
             ep_int(&c.reply, "anchor_count", -1) == 1 &&
             ep_str_is(&c.reply, "comparison", "incomparable") &&
             ep_str_is(&c.reply, "local_digest_reason",
                       "local_base_above_height") &&
             ep_int(&c.reply, "incomparable_count", -1) == 1 &&
             ep_int(&c.reply, "disagree_count", -1) == 0 &&
             ep_bool(&c.reply, "disagreement") == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        ep_cmd_free(&c);
        ep_fixture_free(&g);
    }

    /* ...but an operator-vs-operator conflict is still a finding even when
     * this node cannot take a side. */
    printf("epoch agree: conflicting anchors are a finding even when this "
           "node cannot adjudicate them... ");
    {
        struct ep_fixture g;
        bool ok = ep_fixture_init(&g, "incomp2");
        ok = ok && ep_put_anchor(&g, 61, 9400, 0x11, "zepoch@5000") &&
             ep_put_anchor(&g, 62, 9500, 0x99, "zepoch@5000") &&
             ep_set_cursor(&g, 6000, 0xB6, 9999, 0x22);
        ep_fixture_seal(&g);
        struct ep_cmd c;
        ep_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", g.datadir);
        (void)json_push_kv_int(&c.input, "height", 5000);
        zcl_native_handle_core_epoch_verify(&c.request, &c.reply);
        ok = ok && ep_failed_with(&c.reply, ZCL_COMMAND_STATUS_FAILED,
                                  ZCL_COMMAND_EXIT_FAILED,
                                  "EPOCH_DIGEST_DISAGREEMENT") &&
             ep_int(&c.reply, "distinct_roots", -1) == 2 &&
             ep_int(&c.reply, "incomparable_count", -1) == 2 &&
             ep_int(&c.reply, "disagree_count", -1) == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        ep_cmd_free(&c);
        ep_fixture_free(&g);
    }

    return failures;
}

/* ── 7. offline op_return_hex round-trip ───────────────────────────── */

static int test_epoch_offline_anchor(void)
{
    int failures = 0;
    struct ep_fixture f;

    printf("epoch offline: fixture... ");
    if (ep_fixture_init(&f, "offline")) printf("OK\n");
    else { printf("FAIL\n"); return 1; }

    const int32_t head = 1234567;
    char want_digest_hex[65];
    ep_hex32(0x5A, want_digest_hex);
    bool planted = ep_set_cursor(&f, 0, 0x00, head, 0x5A);
    ep_fixture_seal(&f);

    printf("epoch offline: with no live node, anchor returns an "
           "op_return_hex that zanc_parse round-trips... ");
    {
        int calls_before = g_epoch_rpc_calls;
        struct ep_cmd c;
        ep_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        zcl_native_handle_core_epoch_anchor(&c.request, &c.reply);

        const char *hex = ep_str(&c.reply, "op_return_hex");
        uint8_t script[256];
        size_t n = hex ? (size_t)ParseHex(hex, script, sizeof(script)) : 0;
        struct zanc_message msg;
        memset(&msg, 0, sizeof(msg));
        uint8_t want_digest[32];
        memset(want_digest, 0x5A, 32);

        bool command_ok = planted &&
                  c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
                  /* the live path WAS attempted, and refused */
                  g_epoch_rpc_calls == calls_before + 1 &&
                  ep_has(&c.reply, "node_rpc_error") &&
                  n > 0 && zanc_parse(script, n, &msg) &&
                  msg.hash_type == ZANC_HASH_SHA3_256 &&
                  memcmp(msg.digest, want_digest, 32) == 0 &&
                  strcmp(msg.label, "zepoch@1234567") == 0 &&
                  /* the reply's own fields must agree with the bytes */
                  ep_str_is(&c.reply, "digest", want_digest_hex) &&
                  ep_str_is(&c.reply, "label", "zepoch@1234567") &&
                  ep_str_is(&c.reply, "hash_type", "sha3") &&
                  ep_int(&c.reply, "catalog_height", -1) == head &&
                  ep_int(&c.reply, "op_return_size", -1) == (int64_t)n &&
                  ep_str_is(&c.reply, "status", "ready") &&
                  /* nothing was broadcast: no txid anywhere */
                  !ep_has(&c.reply, "txid");
        if (command_ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }

        struct transaction_lab_simnet_receipt mined;
        bool mined_ok = command_ok && transaction_lab_simnet_mine_op_return(
            script, n, &mined);
        printf("epoch offline: exact command bytes enter a block through "
               "connect_block... ");
        if (mined_ok && mined.transaction.num_vout == 2 &&
            mined.change_zat == 800000)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }

        struct node_db projection_db;
        memset(&projection_db, 0, sizeof(projection_db));
        bool projection_open = node_db_open(&projection_db, ":memory:");
        bool projected = projection_open && mined_ok &&
            transaction_lab_simnet_project(&projection_db, &mined);
        struct zanc_anchor anchor;
        memset(&anchor, 0, sizeof(anchor));
        bool found = projected && db_zanc_find_by_digest(
            &projection_db, ZANC_HASH_SHA3_256, want_digest, &anchor);
        printf("epoch offline: mined bytes rebuild the exact epoch ZANC "
               "projection... ");
        if (found && anchor.height == mined.mined_height &&
            memcmp(anchor.txid, mined.txid.data, sizeof(anchor.txid)) == 0 &&
            strcmp(anchor.label, "zepoch@1234567") == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        if (projection_open)
            node_db_close(&projection_db);
        if (mined_ok)
            transaction_lab_simnet_receipt_free(&mined);
        ep_cmd_free(&c);
    }

    ep_fixture_free(&f);
    return failures;
}

/* ── 8. epoch arithmetic agrees with dumpstate zepoch ──────────────── */

static int test_epoch_arithmetic(void)
{
    int failures = 0;
    struct ep_fixture f;

    printf("epoch arith: fixture... ");
    if (ep_fixture_init(&f, "arith")) printf("OK\n");
    else { printf("FAIL\n"); return 1; }

    /* Deliberately awkward heights: an exact boundary, one below it, and
     * one in the middle. epoch = cursor/1000 must hold at all three, and
     * the command and the dumper must never disagree. */
    static const int32_t heights[] = {999, 1000, 3056758};
    for (size_t i = 0; i < sizeof(heights) / sizeof(heights[0]); i++) {
        int32_t h = heights[i];
        printf("epoch arith: at cursor %d, `core epoch status` and "
               "`dumpstate zepoch` report the same epoch... ", (int)h);
        bool ok = ep_fixture_reopen(&f) && ep_set_cursor(&f, 0, 0x00, h, 0x33);
        ep_fixture_seal(&f);

        struct ep_cmd c;
        ep_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", f.datadir);
        zcl_native_handle_core_epoch_status(&c.request, &c.reply);

        /* Point the dumper at the same datadir's db. */
        struct node_db dump_ndb;
        struct json_value dump;
        json_init(&dump);
        bool dumped = false;
        if (node_db_open(&dump_ndb, f.dbpath)) {
            g_op_return_backfill_test_ndb = &dump_ndb;
            dumped = zepoch_status_dump_state_json(&dump, NULL);
            g_op_return_backfill_test_ndb = NULL;
            node_db_close(&dump_ndb);
        }
        const struct json_value *de = json_get(&dump, "epoch");
        const struct json_value *ds = json_get(&dump, "epoch_start");
        const struct json_value *dt = json_get(&dump, "tip_height");
        const struct json_value *dd = json_get(&dump, "catalog_digest");

        ok = ok && dumped && de && ds && dt && dd &&
             ep_int(&c.reply, "epoch", -1) == (int64_t)(h / 1000) &&
             ep_int(&c.reply, "epoch_start", -1) == (int64_t)(h / 1000) * 1000 &&
             ep_int(&c.reply, "blocks_into_epoch", -1) ==
                 (int64_t)h - (int64_t)(h / 1000) * 1000 &&
             json_get_int(de) == ep_int(&c.reply, "epoch", -1) &&
             json_get_int(ds) == ep_int(&c.reply, "epoch_start", -1) &&
             json_get_int(dt) == ep_int(&c.reply, "tip_height", -1) &&
             ep_str_is(&c.reply, "catalog_digest", json_get_str(dd));
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
        json_free(&dump);
        ep_cmd_free(&c);
    }

    ep_fixture_free(&f);
    return failures;
}

/* ── entry point ───────────────────────────────────────────────────── */

int test_epoch(void)
{
    int failures = 0;
    printf("\n=== Epoch command tests ===\n");

    /* Containment first: no test below may reach a running node. */
    g_epoch_rpc_calls = 0;
    node_rpc_client_set_test_hook(epoch_rpc_stub);

    failures += test_epoch_datadir();
    failures += test_epoch_blockers();
    failures += test_epoch_declared_range();
    failures += test_epoch_verify_height();
    failures += test_epoch_paging();
    failures += test_epoch_agreement();
    failures += test_epoch_offline_anchor();
    failures += test_epoch_arithmetic();

    node_rpc_client_set_test_hook(NULL);

    printf("=== EPOCH: %d failure(s) ===\n", failures);
    return failures;
}
