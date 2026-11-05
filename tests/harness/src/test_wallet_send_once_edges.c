/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Once-only keyed send, edge cases that the leaf-level cases in
 * test_wallet_send_once.c do not reach. Every case calls the real
 * wallet_send_once_dispatch directly with params it builds itself, so it can
 * read the dispatch return value and the exact state / txid / replayed /
 * message fields. Only the build behind z_sendmany is replaced by a local
 * stand-in; no funds, key or proving parameter is involved. Everything runs
 * against a node.db in an isolated temporary datadir, and the fixture is
 * zero-initialised so a teardown after an early return touches nothing unset. */

#include "test/test_core.h"

#include "base/serialize_le.h"
#include "controllers/wallet_helpers.h"
#include "controllers/wallet_send_once.h"
#include "core/uint256.h"
#include "core/utiltime.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "models/database.h"
#include "models/wallet_send_once.h"
#include "primitives/transaction.h"
#include "util/safe_alloc.h"
#include "wallet/wallet.h"

#include <pthread.h>
#include <stdatomic.h>
#include <time.h>

#define E_FROM "\"zs1EdgeFrom\""
#define E_RECIPS "[{\"address\":\"zs1EdgeTo\",\"amount\":1}]"
#define E_CAP_MSG "Too many keyed sends on record; send refused"
#define E_RELEASE_MSG "Send record cannot be released"
#define E_ACTIVE_MAX 64
#define E_DIGEST_LABEL "wso_digest_param"
#define E_NOMEM_MSG "Not enough memory to read the send request; send refused"

static int g_failures;

static void edge_chk(const char *name, bool ok)
{
    printf("  wallet_send_once_edges: %s... %s\n", name, ok ? "OK" : "FAIL");
    if (!ok)
        g_failures++;
}

struct efx {
    struct node_db ndb;
    struct wallet *wallet;
    char dir[256];
    char path[320];
};

static struct efx g_fx;

static void fx_down(void)
{
    if (!g_fx.dir[0])
        return;
    wallet_rpc_context_set_node_db(NULL);
    wallet_rpc_context_set_base(NULL, NULL, NULL, NULL, NULL, NULL);
    if (g_fx.ndb.open)
        node_db_close(&g_fx.ndb);
    if (g_fx.wallet) {
        wallet_free(g_fx.wallet);
        free(g_fx.wallet);
    }
    (void)test_rm_rf_recursive(g_fx.dir);
    memset(&g_fx, 0, sizeof(g_fx));
}

static bool fx_up(const char *tag)
{
    memset(&g_fx, 0, sizeof(g_fx));
    test_make_tmpdir(g_fx.dir, sizeof(g_fx.dir), "wallet_send_once_edges", tag);
    (void)snprintf(g_fx.path, sizeof(g_fx.path), "%s/node.db", g_fx.dir);
    g_fx.wallet = zcl_calloc(1, sizeof(*g_fx.wallet), "wso_edge_wallet");
    if (!g_fx.wallet || !node_db_open(&g_fx.ndb, g_fx.path)) {
        fx_down();
        return false;
    }
    wallet_init(g_fx.wallet);
    g_fx.wallet->default_fee = 250;
    wallet_rpc_context_set_base(g_fx.wallet, NULL, g_fx.dir, NULL, NULL, NULL);
    wallet_rpc_context_set_node_db(&g_fx.ndb);
    return true;
}

/* ── Stand-ins for the build behind z_sendmany ────────────────────────── */

static atomic_int g_runs;
static uint8_t g_fill = 0xB1;
static const char *g_why = "Insufficient funds";
static const char *g_raw = "";
static bool g_pass_ret;

static void txid_fill(struct uint256 *id, uint8_t fill)
{
    memset(id->data, fill, 32);
}

static void admit(const struct uint256 *id)
{
    struct wallet_tx held;
    memset(&held, 0, sizeof(held));
    memcpy(held.tx.hash.data, id->data, 32);
    (void)wallet_add_to_wallet(g_fx.wallet, &held);
}

static void answer_hex(struct json_value *result, const struct uint256 *id)
{
    char hex[65];
    uint256_get_hex(id, hex);
    json_set_str(result, hex);
}

/* Build, hand the txid to the pre-admission hook, admit, answer the txid. */
static bool plain_hook_ok(const struct json_value *params, bool help,
                          struct json_value *result)
{
    (void)params;
    (void)help;
    atomic_fetch_add(&g_runs, 1);
    struct uint256 id;
    txid_fill(&id, g_fill);
    struct zcl_result r = wallet_send_once_before_commit(&id);
    if (!r.ok) {
        json_set_str(result, r.message);
        return false;
    }
    admit(&id);
    wallet_send_once_after_commit(true);
    answer_hex(result, &id);
    return true;
}

static bool plain_fail(const struct json_value *params, bool help,
                       struct json_value *result)
{
    (void)params;
    (void)help;
    atomic_fetch_add(&g_runs, 1);
    json_set_str(result, g_why);
    return false;
}

static bool plain_pass(const struct json_value *params, bool help,
                       struct json_value *result)
{
    (void)params;
    (void)help;
    atomic_fetch_add(&g_runs, 1);
    json_set_str(result, "plain");
    return g_pass_ret;
}

/* Succeeds without ever calling the pre-admission hook. */
static bool plain_raw(const struct json_value *params, bool help,
                      struct json_value *result)
{
    (void)params;
    (void)help;
    atomic_fetch_add(&g_runs, 1);
    json_set_str(result, g_raw);
    return true;
}

/* Hook for txid g_fill, admitted, then answers a different txid. */
static bool plain_other_hex(const struct json_value *params, bool help,
                            struct json_value *result)
{
    if (!plain_hook_ok(params, help, result))
        return false;
    struct uint256 other;
    txid_fill(&other, 0xCC);
    answer_hex(result, &other);
    return true;
}

/* Admitted, then a later step fails. */
static bool plain_admit_then_fail(const struct json_value *params, bool help,
                                  struct json_value *result)
{
    if (!plain_hook_ok(params, help, result))
        return false;
    json_set_str(result, "Wallet flush failed after admission");
    return false;
}

/* ── Params and reply readers ─────────────────────────────────────────── */

static void mk_params(struct json_value *p, const char *from,
                      const char *recips, const char *fee, const char *key)
{
    char buf[512];
    if (key)
        (void)snprintf(buf, sizeof(buf), "[%s,%s,1,%s,\"%s\"]", from, recips,
                       fee, key);
    else
        (void)snprintf(buf, sizeof(buf), "[%s,%s,1,%s,null]", from, recips,
                       fee);
    json_init(p);
    if (!json_read(p, buf, strlen(buf)))
        json_set_null(p);
}

static bool go(const char *from, const char *recips, const char *fee,
               const char *key, wallet_send_once_fn fn,
               struct json_value *res)
{
    struct json_value p;
    mk_params(&p, from, recips, fee, key);
    json_init(res);
    bool rc = wallet_send_once_dispatch(&p, false, fn, res);
    json_free(&p);
    return rc;
}

static bool state_is(const struct json_value *r, const char *state)
{
    const char *s = json_get_str(json_get(r, "state"));
    return s && strcmp(s, state) == 0;
}

static bool replayed_is(const struct json_value *r, bool want)
{
    const struct json_value *v = json_get(r, "replayed");
    return v && json_get_bool(v) == want;
}

static bool msg_is(const struct json_value *r, const char *msg)
{
    const char *s = json_get_str(r);
    return s && strcmp(s, msg) == 0;
}

static bool txid_is(const struct json_value *r, uint8_t fill)
{
    struct uint256 id;
    char hex[65];
    txid_fill(&id, fill);
    uint256_get_hex(&id, hex);
    const char *t = json_get_str(json_get(r, "txid"));
    return t && strcmp(t, hex) == 0;
}

static bool no_txid(const struct json_value *r)
{
    return json_get(r, "txid") == NULL;
}

/* A committed answer for a send that ran: state, txid, not a replay. */
static bool is_fresh_commit(bool rc, const struct json_value *r, uint8_t fill)
{
    return rc && state_is(r, "committed") && txid_is(r, fill) &&
           replayed_is(r, false);
}

/* ── The record's on-disk identity, rebuilt here from the format ──────── */

static void kat_absorb(struct sha3_256_ctx *c, const char *s)
{
    uint8_t len[4];
    zcl_write_u32_le(len, (uint32_t)strlen(s));
    sha3_256_write(c, len, sizeof(len));
    sha3_256_write(c, (const uint8_t *)s, strlen(s));
}

static void kat_ids(const struct json_value *p, const char *key,
                    uint8_t kh[32], uint8_t dg[32])
{
    char from[1024], recips[16384], fee[64] = "";
    (void)json_write(json_at(p, 0), from, sizeof(from));
    (void)json_write(json_at(p, 1), recips, sizeof(recips));
    const struct json_value *f = json_at(p, WALLET_SEND_ONCE_FEE_PARAM);
    if (f && !json_is_null(f))
        (void)json_write(f, fee, sizeof(fee));
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    kat_absorb(&c, "z23/wallet-send-once/key/v1");
    kat_absorb(&c, key);
    sha3_256_finalize(&c, kh);
    sha3_256_init(&c);
    kat_absorb(&c, "z23/wallet-send-once/request/v1");
    kat_absorb(&c, key);
    kat_absorb(&c, from);
    kat_absorb(&c, recips);
    kat_absorb(&c, fee);
    sha3_256_finalize(&c, dg);
}

static bool row_find(const char *fee, const char *key,
                     struct wallet_send_once_row *out)
{
    struct json_value p;
    uint8_t kh[32], dg[32];
    mk_params(&p, E_FROM, E_RECIPS, fee, key);
    kat_ids(&p, key, kh, dg);
    json_free(&p);
    return db_wallet_send_once_find(&g_fx.ndb, kh, out);
}

static bool seed(const char *key, const char *fee,
                 enum wallet_send_once_state st, uint8_t fill)
{
    struct json_value p;
    struct wallet_send_once_row row;
    memset(&row, 0, sizeof(row));
    mk_params(&p, E_FROM, E_RECIPS, fee, key);
    kat_ids(&p, key, row.key_hash, row.digest);
    json_free(&p);
    row.state = st;
    row.has_txid = st != WALLET_SEND_ONCE_STARTED;
    if (row.has_txid)
        memset(row.txid, fill, 32);
    row.created_at = row.updated_at = GetTime();
    return db_wallet_send_once_insert(&g_fx.ndb, &row);
}

static void reset_runs(void)
{
    atomic_store(&g_runs, 0);
    g_fill = 0xB1;
    g_why = "Insufficient funds";
    g_raw = "";
    g_pass_ret = false;
}

/* ── Cases ────────────────────────────────────────────────────────────── */

/* The key shape check, at both ends of every bound. */
static void case_key_shape(void)
{
    char k128[130], k129[131];
    memset(k128, 'a', 128);
    k128[128] = '\0';
    memset(k129, 'a', 129);
    k129[129] = '\0';
    edge_chk("a one-character key is valid", wallet_send_once_key_valid("a"));
    edge_chk("a 128-character key is valid", wallet_send_once_key_valid(k128));
    edge_chk("a 129-character key is refused", !wallet_send_once_key_valid(k129));
    edge_chk("an empty key is refused", !wallet_send_once_key_valid(""));
    edge_chk("no key is refused", !wallet_send_once_key_valid(NULL));
    edge_chk("dot underscore colon dash are valid",
        wallet_send_once_key_valid("a.b_c:d-e") &&
        wallet_send_once_key_valid(".") && wallet_send_once_key_valid("-"));
    edge_chk("a bad first character is refused",
        !wallet_send_once_key_valid("!abc"));
    edge_chk("a bad last character is refused",
        !wallet_send_once_key_valid("abc!") &&
        !wallet_send_once_key_valid("ab cd"));
}

/* An unkeyed or help call goes straight to the send and keeps its verdict. */
static void case_unkeyed_passthrough(void)
{
    struct json_value res;
    reset_runs();
    g_pass_ret = false;
    bool rc = go(E_FROM, E_RECIPS, "null", NULL, plain_pass, &res);
    edge_chk("an unkeyed failure stays a failure", !rc && msg_is(&res, "plain"));
    json_free(&res);
    g_pass_ret = true;
    rc = go(E_FROM, E_RECIPS, "null", NULL, plain_pass, &res);
    edge_chk("an unkeyed success stays a success", rc);
    json_free(&res);
    struct json_value p;
    g_pass_ret = false;
    mk_params(&p, E_FROM, E_RECIPS, "null", "edge-help");
    json_init(&res);
    rc = wallet_send_once_dispatch(&p, true, plain_pass, &res);
    edge_chk("help is answered by the send, not recorded",
        !rc && atomic_load(&g_runs) == 3 &&
        db_wallet_send_once_count(&g_fx.ndb) == 0);
    json_free(&res);
    json_free(&p);
}

static bool refused(const char *key, const char *msg)
{
    struct json_value res;
    bool rc = go(E_FROM, E_RECIPS, "null", key, plain_pass, &res);
    bool ok = !rc && msg_is(&res, msg) && atomic_load(&g_runs) == 0;
    json_free(&res);
    return ok;
}

/* A malformed key or an unusable record refuses the send before it runs. */
static void case_refusals(void)
{
    static struct node_db closed;
    reset_runs();
    edge_chk("a malformed key is refused with its own message",
        refused("bad key!", "Invalid idempotency key"));
    wallet_rpc_context_set_node_db(NULL);
    edge_chk("no node.db refuses the send",
        refused("edge-key-1", "Send record unavailable; send refused"));
    wallet_rpc_context_set_node_db(&closed);
    edge_chk("a closed node.db refuses the send",
        refused("edge-key-1", "Send record unavailable; send refused"));
    wallet_rpc_context_set_node_db(&g_fx.ndb);
    wallet_rpc_context_set_base(NULL, NULL, g_fx.dir, NULL, NULL, NULL);
    edge_chk("no wallet refuses the send",
        refused("edge-key-1", "Send record unavailable; send refused"));
    wallet_rpc_context_set_base(g_fx.wallet, NULL, g_fx.dir, NULL, NULL, NULL);
    edge_chk("nothing was recorded by any refusal",
        db_wallet_send_once_count(&g_fx.ndb) == 0);
}

/* The digest binds the key and every field, each with its own boundary. */
static void case_key_conflict(void)
{
    struct json_value res;
    reset_runs();
    bool rc = go("1", "23", "null", "edge-split", plain_hook_ok, &res);
    edge_chk("a first send with a null fee commits", is_fresh_commit(rc, &res, 0xB1));
    json_free(&res);
    rc = go("12", "3", "null", "edge-split", plain_hook_ok, &res);
    edge_chk("a shifted field boundary is a different request",
        rc && state_is(&res, "key_conflict") && replayed_is(&res, true) &&
        no_txid(&res) && atomic_load(&g_runs) == 1);
    json_free(&res);
    rc = go("1", "23", "\"0.0000025\"", "edge-split", plain_hook_ok, &res);
    edge_chk("a fee where there was none is a different request",
        rc && state_is(&res, "key_conflict") && atomic_load(&g_runs) == 1);
    json_free(&res);
    rc = go("1", "23", "null", "edge-split", plain_hook_ok, &res);
    edge_chk("the identical repeat is a committed replay",
        rc && state_is(&res, "committed") && replayed_is(&res, true) &&
        txid_is(&res, 0xB1) && atomic_load(&g_runs) == 1);
    json_free(&res);
}

static void case_key_conflict_fields(void)
{
    struct json_value res;
    reset_runs();
    bool rc = go("\"A\"", "[1]", "null", "edge-fields", plain_hook_ok, &res);
    edge_chk("the first send commits", is_fresh_commit(rc, &res, 0xB1));
    json_free(&res);
    rc = go("\"B\"", "[1]", "null", "edge-fields", plain_hook_ok, &res);
    edge_chk("another source address is a different request",
        rc && state_is(&res, "key_conflict"));
    json_free(&res);
    rc = go("\"A\"", "[2]", "null", "edge-fields", plain_hook_ok, &res);
    edge_chk("other recipients are a different request",
        rc && state_is(&res, "key_conflict"));
    json_free(&res);
    rc = go("\"A\"", "[1]", "null", "edge-other", plain_hook_ok, &res);
    edge_chk("the same request under another key is a new send",
        is_fresh_commit(rc, &res, 0xB1) && atomic_load(&g_runs) == 2);
    json_free(&res);
}

/* The stored key hash and digest are a persistent format: pin them. */
static void case_record_format(void)
{
    struct json_value res;
    struct wallet_send_once_row row;
    uint8_t want[32];
    reset_runs();
    bool rc = go(E_FROM, E_RECIPS, "\"0.0000025\"", "edge-kat", plain_hook_ok,
                 &res);
    edge_chk("the keyed send commits", is_fresh_commit(rc, &res, 0xB1));
    json_free(&res);
    bool found = row_find("\"0.0000025\"", "edge-kat", &row);
    edge_chk("a row exists under the key hash of the documented format", found);
    struct json_value p;
    uint8_t kh[32];
    mk_params(&p, E_FROM, E_RECIPS, "\"0.0000025\"", "edge-kat");
    kat_ids(&p, "edge-kat", kh, want);
    json_free(&p);
    edge_chk("the row carries the documented request digest",
        found && memcmp(row.digest, want, 32) == 0);
    memset(want, 0xB1, 32);
    edge_chk("the row is committed with the txid and a timestamp",
        found && row.state == WALLET_SEND_ONCE_COMMITTED && row.has_txid &&
        memcmp(row.txid, want, 32) == 0 && row.created_at > 0 &&
        row.updated_at >= row.created_at);
}

/* A repeat is answered from the row the key already has. */
static void case_seeded_rows(void)
{
    struct json_value res;
    reset_runs();
    edge_chk("a built row is seeded",
        seed("edge-built", "null", WALLET_SEND_ONCE_BUILT, 0x55));
    bool rc = go(E_FROM, E_RECIPS, "null", "edge-built", plain_hook_ok, &res);
    edge_chk("a built row is outcome_unknown with its txid, as a replay",
        rc && state_is(&res, "outcome_unknown") && txid_is(&res, 0x55) &&
        replayed_is(&res, true) && atomic_load(&g_runs) == 0);
    json_free(&res);
    edge_chk("a committed row is seeded",
        seed("edge-lost", "null", WALLET_SEND_ONCE_COMMITTED, 0x66));
    rc = go(E_FROM, E_RECIPS, "null", "edge-lost", plain_hook_ok, &res);
    edge_chk("a committed row the wallet lost is outcome_unknown, as a replay",
        rc && state_is(&res, "outcome_unknown") && txid_is(&res, 0x66) &&
        replayed_is(&res, true) && atomic_load(&g_runs) == 0);
    json_free(&res);
}

/* A row that never got a txid is freed and the send runs, fee checked. */
static void case_started_row(void)
{
    struct json_value res;
    struct wallet_send_once_row row;
    reset_runs();
    edge_chk("a started row is seeded",
        seed("edge-started", "\"0.00001\"", WALLET_SEND_ONCE_STARTED, 0));
    bool rc = go(E_FROM, E_RECIPS, "\"0.00001\"", "edge-started",
                 plain_hook_ok, &res);
    edge_chk("a started row is answered by the fee check before any send",
        rc && state_is(&res, "fee_changed") && atomic_load(&g_runs) == 0);
    json_free(&res);
    edge_chk("the fee refusal freed the key",
        !row_find("\"0.00001\"", "edge-started", &row) &&
        db_wallet_send_once_count(&g_fx.ndb) == 0);
    edge_chk("the started row is seeded again",
        seed("edge-started", "null", WALLET_SEND_ONCE_STARTED, 0));
    rc = go(E_FROM, E_RECIPS, "null", "edge-started", plain_hook_ok, &res);
    edge_chk("a started row is freed and the send runs once",
        is_fresh_commit(rc, &res, 0xB1) && atomic_load(&g_runs) == 1);
    json_free(&res);
    edge_chk("the row is committed afterwards",
        row_find("null", "edge-started", &row) &&
        row.state == WALLET_SEND_ONCE_COMMITTED);
}

/* ── Nested calls: a repeat arrives while the first is still running ──── */

static bool g_inner_done;
static bool g_inner_rc;
static struct json_value g_inner;
static const char *g_inner_key;

static bool plain_repeat_inside(const struct json_value *params, bool help,
                                struct json_value *result)
{
    if (!g_inner_done) {
        g_inner_done = true;
        g_inner_rc = go(E_FROM, E_RECIPS, "null", g_inner_key, plain_fail,
                        &g_inner);
    }
    return plain_hook_ok(params, help, result);
}

static void case_in_progress(void)
{
    struct json_value res;
    reset_runs();
    g_inner_done = false;
    g_inner_key = "edge-busy";
    bool rc = go(E_FROM, E_RECIPS, "null", "edge-busy", plain_repeat_inside,
                 &res);
    edge_chk("a repeat during the run is in_progress, as a replay, no txid",
        g_inner_rc && state_is(&g_inner, "in_progress") &&
        replayed_is(&g_inner, true) && no_txid(&g_inner) &&
        atomic_load(&g_runs) == 1);
    edge_chk("the first run still commits", is_fresh_commit(rc, &res, 0xB1));
    json_free(&g_inner);
    json_free(&res);
    edge_chk("a started row is seeded", seed("edge-busy2", "null",
                                         WALLET_SEND_ONCE_STARTED, 0));
    g_inner_done = false;
    g_inner_key = "edge-busy2";
    rc = go(E_FROM, E_RECIPS, "null", "edge-busy2", plain_repeat_inside, &res);
    edge_chk("a retry over a started row is registered as running",
        g_inner_rc && state_is(&g_inner, "in_progress") &&
        is_fresh_commit(rc, &res, 0xB1));
    json_free(&g_inner);
    json_free(&res);
}

static int g_depth;
static int g_first_refused;
static bool g_refused_ok;

/* Each running send starts the next key, until the table of runners is full. */
static bool plain_chain(const struct json_value *params, bool help,
                        struct json_value *result)
{
    (void)params;
    (void)help;
    atomic_fetch_add(&g_runs, 1);
    int k = g_depth++;
    if (k < E_ACTIVE_MAX) {
        char key[32];
        struct json_value res;
        (void)snprintf(key, sizeof(key), "chain-%d", k + 1);
        bool rc = go(E_FROM, E_RECIPS, "null", key, plain_chain, &res);
        if (!rc && g_first_refused == 0) {
            g_first_refused = k + 1;
            g_refused_ok = msg_is(&res, E_CAP_MSG);
        }
        json_free(&res);
    }
    json_set_str(result, "chain ends");
    return false;
}

static void case_active_cap(void)
{
    struct json_value res;
    reset_runs();
    g_depth = 0;
    g_first_refused = 0;
    g_refused_ok = false;
    (void)go(E_FROM, E_RECIPS, "null", "chain-0", plain_chain, &res);
    json_free(&res);
    edge_chk("exactly 64 sends run at once", atomic_load(&g_runs) == E_ACTIVE_MAX);
    edge_chk("the 65th is refused, as an error, with the cap message",
        g_first_refused == E_ACTIVE_MAX && g_refused_ok);
    bool rc = go(E_FROM, E_RECIPS, "null", "chain-after", plain_hook_ok, &res);
    edge_chk("a send after they all finished runs again",
        is_fresh_commit(rc, &res, 0xB1));
    json_free(&res);
}

/* ── Runners finishing out of order ───────────────────────────────────── */

#define E_GATES 3
static atomic_int g_gate[E_GATES];
static atomic_int g_entered;
static atomic_int g_done[E_GATES];
static _Thread_local int t_slot;

static void nap(void)
{
    struct timespec ts = { 0, 1000000L };
    nanosleep(&ts, NULL);
}

static bool plain_gated(const struct json_value *params, bool help,
                        struct json_value *result)
{
    (void)params;
    (void)help;
    atomic_fetch_add(&g_runs, 1);
    atomic_fetch_add(&g_entered, 1);
    while (!atomic_load(&g_gate[t_slot]))
        nap();
    json_set_str(result, g_why);
    return false;
}

static void *gated_thread(void *arg)
{
    char key[32];
    struct json_value res;
    t_slot = (int)(intptr_t)arg;
    (void)snprintf(key, sizeof(key), "gate-%d", t_slot);
    (void)go(E_FROM, E_RECIPS, "null", key, plain_gated, &res);
    json_free(&res);
    atomic_store(&g_done[t_slot], 1);
    return NULL;
}

static bool in_progress_for(const char *key)
{
    struct json_value res;
    bool rc = go(E_FROM, E_RECIPS, "null", key, plain_fail, &res);
    bool ok = rc && state_is(&res, "in_progress") && replayed_is(&res, true);
    json_free(&res);
    return ok;
}

static void case_out_of_order(void)
{
    pthread_t t[E_GATES];
    reset_runs();
    atomic_store(&g_entered, 0);
    for (int i = 0; i < E_GATES; i++) {
        atomic_store(&g_gate[i], 0);
        atomic_store(&g_done[i], 0);
    }
    for (int i = 0; i < E_GATES; i++) {
        pthread_create(&t[i], NULL, gated_thread, (void *)(intptr_t)i);
        while (atomic_load(&g_entered) < i + 1)
            nap();
    }
    atomic_store(&g_gate[0], 1);
    while (!atomic_load(&g_done[0]))
        nap();
    edge_chk("the second runner is still running after the first left",
        in_progress_for("gate-1"));
    edge_chk("the third runner is still running after the first left",
        in_progress_for("gate-2"));
    for (int i = 1; i < E_GATES; i++)
        atomic_store(&g_gate[i], 1);
    for (int i = 0; i < E_GATES; i++)
        pthread_join(t[i], NULL);
    edge_chk("each runner ran once", atomic_load(&g_runs) == E_GATES);
}

/* ── Table cap ────────────────────────────────────────────────────────── */

static void case_row_cap(void)
{
    struct json_value res;
    reset_runs();
    edge_chk("the table is filled to one below the cap",
        node_db_exec(&g_fx.ndb,
            "WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c "
            "WHERE i<99999) INSERT INTO wallet_send_once(key_hash,digest,"
            "state,txid,created_at,updated_at) SELECT randomblob(32),"
            "zeroblob(32),3,zeroblob(32),CAST(strftime('%s','now') AS INTEGER),"
            "CAST(strftime('%s','now') AS INTEGER) FROM c") &&
        db_wallet_send_once_count(&g_fx.ndb) == WALLET_SEND_ONCE_MAX_ROWS - 1);
    bool rc = go(E_FROM, E_RECIPS, "null", "cap-last", plain_hook_ok, &res);
    edge_chk("the send that fills the table runs", is_fresh_commit(rc, &res, 0xB1));
    json_free(&res);
    rc = go(E_FROM, E_RECIPS, "null", "cap-over", plain_hook_ok, &res);
    edge_chk("a new key at the cap is refused as an error",
        !rc && msg_is(&res, E_CAP_MSG) && atomic_load(&g_runs) == 1);
    json_free(&res);
    rc = go(E_FROM, E_RECIPS, "null", "cap-last", plain_hook_ok, &res);
    edge_chk("a known key is still answered at the cap",
        rc && state_is(&res, "committed") && replayed_is(&res, true));
    json_free(&res);
}

/* ── Failing record writes ────────────────────────────────────────────── */

static void case_release_blocked(void)
{
    struct json_value res;
    reset_runs();
    edge_chk("deletes are blocked", node_db_exec(&g_fx.ndb,
        "CREATE TRIGGER wso_nodel BEFORE DELETE ON wallet_send_once "
        "BEGIN SELECT RAISE(ABORT,'blocked'); END"));
    bool rc = go(E_FROM, E_RECIPS, "\"0.00001\"", "edge-rel-fee", plain_pass,
                 &res);
    edge_chk("a fee refusal that cannot free its key is an error",
        !rc && msg_is(&res, E_RELEASE_MSG) && atomic_load(&g_runs) == 0);
    json_free(&res);
    edge_chk("a started row is seeded",
        seed("edge-rel-old", "null", WALLET_SEND_ONCE_STARTED, 0));
    rc = go(E_FROM, E_RECIPS, "null", "edge-rel-old", plain_pass, &res);
    edge_chk("a retry that cannot free the old row does not send",
        !rc && msg_is(&res, E_RELEASE_MSG) && atomic_load(&g_runs) == 0);
    json_free(&res);
    rc = go(E_FROM, E_RECIPS, "null", "edge-rel-run", plain_fail, &res);
    edge_chk("a failed send that cannot free its key reports the failure",
        !rc && msg_is(&res, "Insufficient funds") &&
        atomic_load(&g_runs) == 1);
    json_free(&res);
}

static void case_insert_blocked(void)
{
    struct json_value res;
    reset_runs();
    edge_chk("inserts are blocked", node_db_exec(&g_fx.ndb,
        "CREATE TRIGGER wso_noins BEFORE INSERT ON wallet_send_once "
        "BEGIN SELECT RAISE(ABORT,'blocked'); END"));
    bool rc = go(E_FROM, E_RECIPS, "null", "edge-noins", plain_pass, &res);
    edge_chk("a record that cannot be created refuses the send, as an error",
        !rc && atomic_load(&g_runs) == 0 &&
        msg_is(&res, "Send record unreadable; nothing was changed but the "
                     "outcome of an earlier send is unknown"));
    json_free(&res);
    edge_chk("nothing was recorded", db_wallet_send_once_count(&g_fx.ndb) == 0);
}

static void case_batch_flush_failure(void)
{
    struct json_value res;
    reset_runs();
    /* A batch is flagged open but no transaction is: the commit fails. */
    g_fx.ndb.sync_in_batch = true;
    bool rc = go(E_FROM, E_RECIPS, "null", "edge-flush", plain_pass, &res);
    edge_chk("a pending batch that cannot commit refuses the send",
        !rc && atomic_load(&g_runs) == 0 &&
        db_wallet_send_once_count(&g_fx.ndb) == 0);
    json_free(&res);
    g_fx.ndb.sync_in_batch = false;
}

/* The durable write of the built txid fails: nothing was sent. */
static void case_built_write_fails(void)
{
    struct json_value res;
    reset_runs();
    edge_chk("updates are blocked", node_db_exec(&g_fx.ndb,
        "CREATE TRIGGER wso_noupd BEFORE UPDATE ON wallet_send_once "
        "BEGIN SELECT RAISE(ABORT,'blocked'); END"));
    bool rc = go(E_FROM, E_RECIPS, "null", "edge-durable", plain_hook_ok, &res);
    edge_chk("the send is refused and its key released",
        rc && state_is(&res, "released") &&
        atomic_load(&g_runs) == 1 && db_wallet_send_once_count(&g_fx.ndb) == 0);
    json_free(&res);
    bool opened = node_db_begin_immediate(&g_fx.ndb);
    edge_chk("the failed write left no transaction open on the connection", opened);
    if (opened)
        (void)node_db_rollback(&g_fx.ndb);
}

/* A node.db that runs with synchronous=OFF still gets its record written. */
static void case_sync_off(void)
{
    struct json_value res;
    reset_runs();
    edge_chk("synchronous is turned off",
        node_db_exec(&g_fx.ndb, "PRAGMA synchronous=OFF") &&
        db_wallet_send_once_sync_level(&g_fx.ndb) == 0);
    bool rc = go(E_FROM, E_RECIPS, "null", "edge-off", plain_hook_ok, &res);
    edge_chk("the send commits under synchronous=OFF",
        is_fresh_commit(rc, &res, 0xB1));
    json_free(&res);
    edge_chk("the level found is the level restored",
        db_wallet_send_once_sync_level(&g_fx.ndb) == 0);
}

/* ── How a send ends ──────────────────────────────────────────────────── */

static void case_finish_hex(void)
{
    struct json_value res;
    struct wallet_send_once_row row;
    reset_runs();
    g_raw = "abababababababababababababababababababababababababababababababab";
    bool rc = go(E_FROM, E_RECIPS, "null", "edge-raw", plain_raw, &res);
    edge_chk("a send that answers a txid without the hook still commits it",
        is_fresh_commit(rc, &res, 0xAB));
    json_free(&res);
    edge_chk("and its row holds that txid",
        row_find("null", "edge-raw", &row) &&
        row.state == WALLET_SEND_ONCE_COMMITTED && row.txid[0] == 0xAB &&
        row.txid[31] == 0xAB);
    g_raw = "ababababababababababababababababababababababababababababababab";
    rc = go(E_FROM, E_RECIPS, "null", "edge-short", plain_raw, &res);
    edge_chk("a 62-character answer is outcome_unknown with no txid",
        rc && state_is(&res, "outcome_unknown") && no_txid(&res) &&
        replayed_is(&res, false));
    json_free(&res);
    g_raw = "ababababababababababababababababababababababababababababababababab";
    rc = go(E_FROM, E_RECIPS, "null", "edge-long", plain_raw, &res);
    edge_chk("a 66-character answer is outcome_unknown with no txid",
        rc && state_is(&res, "outcome_unknown") && no_txid(&res));
    json_free(&res);
}

static void case_finish_recorded_txid(void)
{
    struct json_value res;
    reset_runs();
    bool rc = go(E_FROM, E_RECIPS, "null", "edge-other", plain_other_hex, &res);
    edge_chk("the txid made durable wins over the txid the send answers",
        is_fresh_commit(rc, &res, 0xB1));
    json_free(&res);
    rc = go(E_FROM, E_RECIPS, "null", "edge-late", plain_admit_then_fail, &res);
    edge_chk("a failure after admission is outcome_unknown with the txid",
        rc && state_is(&res, "outcome_unknown") && txid_is(&res, 0xB1) &&
        replayed_is(&res, false));
    json_free(&res);
    rc = go(E_FROM, E_RECIPS, "null", "edge-late", plain_hook_ok, &res);
    edge_chk("and a repeat is outcome_unknown again, without a second send",
        rc && state_is(&res, "outcome_unknown") && txid_is(&res, 0xB1) &&
        replayed_is(&res, true) && atomic_load(&g_runs) == 2);
    json_free(&res);
}

/* ── One transaction per key ──────────────────────────────────────────── */

static bool g_uniq[5];
static int g_uniq_code;

static struct zcl_result before(uint8_t fill, uint8_t last)
{
    struct uint256 id;
    txid_fill(&id, fill);
    id.data[31] = last;
    return wallet_send_once_before_commit(&id);
}

static bool plain_uniq(const struct json_value *params, bool help,
                       struct json_value *result)
{
    (void)params;
    (void)help;
    g_uniq[0] = before(0x40, 0x40).ok;
    g_uniq[1] = before(0x40, 0x40).ok;
    struct zcl_result up = before(0x40, 0x41);
    struct zcl_result down = before(0x40, 0x3F);
    g_uniq[2] = up.ok;
    g_uniq[3] = down.ok;
    g_uniq_code = up.code;
    g_uniq[4] = before(0x41, 0x40).ok;
    wallet_send_once_after_commit(false);
    json_set_str(result, "uniq done");
    return false;
}

static void case_one_transaction(void)
{
    struct json_value res;
    reset_runs();
    (void)go(E_FROM, E_RECIPS, "null", "edge-uniq", plain_uniq, &res);
    json_free(&res);
    edge_chk("the transaction made durable is accepted again", g_uniq[0] && g_uniq[1]);
    edge_chk("one differing only in the last byte, either way, is refused",
        !g_uniq[2] && !g_uniq[3]);
    edge_chk("one differing in the first byte is refused", !g_uniq[4]);
    edge_chk("the refusal carries error code -1", g_uniq_code == -1);
}

/* ── Requests larger than the buffers the digest once wrote into ──────── */

struct big_spec {
    size_t from_len;
    const char *from_tail;
    size_t recips_len;
    const char *recips_tail;
    size_t fee_len;
    const char *fee_tail;
};

struct big_req {
    char *from;
    char *recips;
    char *fee;
};

/* Ordinary sizes in every field; a case raises the one it is about. */
static struct big_spec big_small(void)
{
    return (struct big_spec){ .from_len = 40, .from_tail = "",
                              .recips_len = 60, .recips_tail = "",
                              .fee_len = 20, .fee_tail = "" };
}

/* head, then fill characters, then tail and end: exactly total bytes. */
static char *big_text(const char *head, char fill, size_t total,
                      const char *tail, const char *end)
{
    size_t t = strlen(tail);
    size_t e = strlen(end);
    char *s = zcl_malloc(total + 1, "wso_edge_big_text");
    if (!s)
        return NULL;
    memset(s, fill, total);
    memcpy(s, head, strlen(head));
    memcpy(s + total - e - t, tail, t);
    memcpy(s + total - e, end, e);
    s[total] = '\0';
    return s;
}

static void big_free(struct big_req *b)
{
    free(b->from);
    free(b->recips);
    free(b->fee);
    memset(b, 0, sizeof(*b));
}

/* The fee stays a string that parses to the wallet's 250: parsing stops at
 * eight decimals, so only the digest sees what follows. */
static bool big_make(struct big_req *b, const struct big_spec *s)
{
    b->from = big_text("\"", 'a', s->from_len, s->from_tail, "\"");
    b->recips = big_text("[{\"address\":\"", 'a', s->recips_len, s->recips_tail,
                         "\",\"amount\":1}]");
    b->fee = big_text("\"0.00000250", '0', s->fee_len, s->fee_tail, "\"");
    if (b->from && b->recips && b->fee)
        return true;
    big_free(b);
    edge_chk("a large request can be built", false);
    return false;
}

static bool big_params(struct json_value *p, const struct big_req *b,
                       const char *key)
{
    size_t n = strlen(b->from) + strlen(b->recips) + strlen(b->fee) +
               strlen(key) + 16;
    char *buf = zcl_malloc(n, "wso_edge_big_params");
    json_init(p);
    if (!buf)
        return false;
    (void)snprintf(buf, n, "[%s,%s,1,%s,\"%s\"]", b->from, b->recips, b->fee,
                   key);
    bool parsed = json_read(p, buf, strlen(buf));
    free(buf);
    return parsed;
}

static bool go_big(const struct big_req *b, const char *key,
                   wallet_send_once_fn fn, struct json_value *res)
{
    struct json_value p;
    json_init(res);
    bool parsed = big_params(&p, b, key);
    if (!parsed)
        edge_chk("a large request parses", false);
    bool rc = parsed && wallet_send_once_dispatch(&p, false, fn, res);
    json_free(&p);
    return rc;
}

static void big_chk(const char *field, const char *what, bool ok)
{
    char name[120];
    (void)snprintf(name, sizeof(name), "%s: %s", field, what);
    edge_chk(name, ok);
}

/* A row the wallet still holds answers its own request, and nothing else. */
static void big_answers(const char *field, const char *key, uint8_t fill,
                        const struct big_req *one, const struct big_req *other)
{
    struct json_value res;
    bool rc = go_big(one, key, plain_hook_ok, &res);
    big_chk(field, "the first send commits and runs once",
        is_fresh_commit(rc, &res, fill) && atomic_load(&g_runs) == 1);
    json_free(&res);
    rc = go_big(one, key, plain_hook_ok, &res);
    big_chk(field, "the identical request replays the earlier txid",
        rc && state_is(&res, "committed") && txid_is(&res, fill) &&
        replayed_is(&res, true) && atomic_load(&g_runs) == 1);
    json_free(&res);
    rc = go_big(other, key, plain_hook_ok, &res);
    big_chk(field, "a different tail is a key conflict, not a replay",
        rc && state_is(&res, "key_conflict") && no_txid(&res) &&
        replayed_is(&res, true) && atomic_load(&g_runs) == 1);
    json_free(&res);
    rc = go_big(one, key, plain_hook_ok, &res);
    big_chk(field, "the conflict leaves the first request's answer in place",
        rc && state_is(&res, "committed") && txid_is(&res, fill) &&
        atomic_load(&g_runs) == 1);
    json_free(&res);
}

static void big_case(const char *field, const char *key, uint8_t fill,
                     const struct big_spec *one_spec,
                     const struct big_spec *other_spec)
{
    struct big_req one;
    struct big_req other;
    reset_runs();
    g_fill = fill;
    if (!big_make(&one, one_spec))
        return;
    if (big_make(&other, other_spec)) {
        big_answers(field, key, fill, &one, &other);
        big_free(&other);
    }
    big_free(&one);
}

static void case_oversize_recipients(void)
{
    struct big_spec one = big_small();
    struct big_spec other = big_small();
    one.recips_len = 17000;
    other.recips_len = 17000;
    other.recips_tail = "\",\"amount\":1},{\"address\":\"zs1Second";
    big_case("recipients over 16383 bytes", "edge-big-recips", 0xC1, &one,
             &other);
}

static void case_oversize_from(void)
{
    struct big_spec one = big_small();
    struct big_spec other = big_small();
    one.from_len = 1100;
    one.from_tail = "X";
    other.from_len = 1100;
    other.from_tail = "Y";
    big_case("from over 1023 bytes", "edge-big-from", 0xC2, &one, &other);
}

static void case_oversize_fee(void)
{
    struct big_spec one = big_small();
    struct big_spec other = big_small();
    one.fee_len = 100;
    one.fee_tail = "1";
    other.fee_len = 100;
    other.fee_tail = "2";
    big_case("fee over 63 bytes", "edge-big-fee", 0xC3, &one, &other);
}

/* A row written before the digest covered the whole value holds the digest of
 * a prefix. Its identical retry cannot match any more: it must conflict, with
 * no second send and no claim that this request was the one sent. */
static void case_oversize_old_row(void)
{
    struct big_spec spec = big_small();
    struct big_req b;
    struct json_value p;
    struct json_value res;
    struct wallet_send_once_row row;
    spec.recips_len = 17000;
    reset_runs();
    if (!big_make(&b, &spec))
        return;
    memset(&row, 0, sizeof(row));
    bool parsed = big_params(&p, &b, "edge-big-old");
    edge_chk("the old-format request parses", parsed);
    if (!parsed) {
        json_free(&p);
        big_free(&b);
        return;
    }
    kat_ids(&p, "edge-big-old", row.key_hash, row.digest);
    json_free(&p);
    row.state = WALLET_SEND_ONCE_COMMITTED;
    row.has_txid = true;
    memset(row.txid, 0xC4, 32);
    row.created_at = row.updated_at = GetTime();
    edge_chk("a row with a prefix digest is seeded",
        db_wallet_send_once_insert(&g_fx.ndb, &row));
    bool rc = go_big(&b, "edge-big-old", plain_hook_ok, &res);
    edge_chk("its retry conflicts and sends nothing",
        rc && state_is(&res, "key_conflict") && no_txid(&res) &&
        atomic_load(&g_runs) == 0);
    json_free(&res);
    big_free(&b);
}

/* ── The digest of any request that always fit, pinned to the byte ────── */

static uint8_t pin_nibble(char c)
{
    return (uint8_t)(c >= 'a' ? c - 'a' + 10 : c - '0');
}

/* A committed row as an earlier build wrote it: the digest is a known answer
 * computed with an outside SHA3-256 tool over the length-prefixed fields. */
static bool pin_seed(const char *key, const char *hex, uint8_t fill)
{
    struct wallet_send_once_row row;
    struct sha3_256_ctx c;
    struct uint256 id;
    memset(&row, 0, sizeof(row));
    sha3_256_init(&c);
    kat_absorb(&c, "z23/wallet-send-once/key/v1");
    kat_absorb(&c, key);
    sha3_256_finalize(&c, row.key_hash);
    for (size_t i = 0; i < 32; i++)
        row.digest[i] = (uint8_t)(pin_nibble(hex[2 * i]) << 4 |
                                  pin_nibble(hex[2 * i + 1]));
    row.state = WALLET_SEND_ONCE_COMMITTED;
    row.has_txid = true;
    memset(row.txid, fill, 32);
    row.created_at = row.updated_at = GetTime();
    txid_fill(&id, fill);
    admit(&id);
    return db_wallet_send_once_insert(&g_fx.ndb, &row);
}

static void pin_chk(const char *name, bool rc, const struct json_value *r,
                    uint8_t fill)
{
    edge_chk(name, rc && state_is(r, "committed") && txid_is(r, fill) &&
                   replayed_is(r, true) && atomic_load(&g_runs) == 0);
}

static void case_digest_pins(void)
{
    static const struct { const char *key, *fee, *hex, *name; } pins[] = {
        { "pin-small", "null",
          "5959f55f484390cee8ddb2a4b9a8006564915c462c419dacac9fb9e2e7c6395a",
          "the digest with no fee is unchanged across an upgrade" },
        { "pin-fee", "\"0.0000025\"",
          "7cc42dd8dd7041e9c6b35505970ded36290b20776e0f067cb66a0c33351ba808",
          "the digest with a string fee is unchanged across an upgrade" },
        { "pin-real", "0.0000025",
          "fd74e5ae164469ba5bc67bd85ab52fabf808aa16f7dc76bbdd7dcceb3274a552",
          "the digest with a number fee is unchanged across an upgrade" },
    };
    struct json_value res;
    reset_runs();
    for (size_t i = 0; i < sizeof(pins) / sizeof(pins[0]); i++) {
        edge_chk("a pinned row is seeded",
            pin_seed(pins[i].key, pins[i].hex, 0xD1));
        bool rc = go(E_FROM, E_RECIPS, pins[i].fee, pins[i].key, plain_hook_ok,
                     &res);
        pin_chk(pins[i].name, rc, &res, 0xD1);
        json_free(&res);
    }
}

/* 1023, 16383 and 63 bytes: the largest request the old buffers held whole. */
static void case_digest_pin_largest(void)
{
    struct big_spec spec = { .from_len = 1023, .from_tail = "",
                             .recips_len = 16383, .recips_tail = "",
                             .fee_len = 63, .fee_tail = "" };
    struct big_req b;
    struct json_value res;
    reset_runs();
    if (!big_make(&b, &spec))
        return;
    edge_chk("the largest pinned row is seeded",
        pin_seed("pin-edge",
                 "2836a02bf823dad730809a9f12428aaca8d99c59e01017a52bd820941dca9fbf",
                 0xD2));
    bool rc = go_big(&b, "pin-edge", plain_hook_ok, &res);
    pin_chk("the digest of the largest whole request is unchanged", rc, &res,
            0xD2);
    json_free(&res);
    big_free(&b);
}

/* ── Only a failed allocation refuses for the digest ──────────────────── */

static void digest_nomem_at(unsigned nth, const char *name)
{
    struct json_value res;
    reset_runs();
    zcl_alloc_fault_fail_nth(E_DIGEST_LABEL, nth);
    bool rc = go(E_FROM, E_RECIPS, "\"0.0000025\"", "edge-nomem", plain_hook_ok,
                 &res);
    zcl_alloc_fault_clear();
    const char *msg = json_get_str(&res);
    edge_chk(name, !rc && msg && strcmp(msg, E_NOMEM_MSG) == 0 &&
                   atomic_load(&g_runs) == 0 &&
                   db_wallet_send_once_count(&g_fx.ndb) == 0);
    json_free(&res);
}

static void case_digest_no_memory(void)
{
    struct json_value res;
    digest_nomem_at(1, "no memory for from refuses before any record or send");
    digest_nomem_at(2, "no memory for recipients refuses likewise");
    digest_nomem_at(3, "no memory for the fee refuses likewise");
    reset_runs();
    bool rc = go(E_FROM, E_RECIPS, "\"0.0000025\"", "edge-nomem", plain_hook_ok,
                 &res);
    edge_chk("the same key sends once memory is back",
        is_fresh_commit(rc, &res, 0xB1) && atomic_load(&g_runs) == 1);
    json_free(&res);
}

/* ── A send that reports success and no txid at all ───────────────────── */

static void case_no_txid_holds_key(void)
{
    struct json_value res;
    struct wallet_send_once_row row;
    reset_runs();
    g_raw = "not a transaction id";
    bool rc = go(E_FROM, E_RECIPS, "null", "edge-held", plain_raw, &res);
    edge_chk("success with no txid at all is outcome_unknown",
        rc && state_is(&res, "outcome_unknown") && no_txid(&res) &&
        replayed_is(&res, false) && atomic_load(&g_runs) == 1);
    json_free(&res);
    edge_chk("the key is held by a row past started",
        row_find("null", "edge-held", &row) &&
        row.state == WALLET_SEND_ONCE_BUILT);
    rc = go(E_FROM, E_RECIPS, "null", "edge-held", plain_raw, &res);
    edge_chk("a retry is outcome_unknown with no txid and never a second send",
        rc && state_is(&res, "outcome_unknown") && no_txid(&res) &&
        replayed_is(&res, true) && atomic_load(&g_runs) == 1);
    json_free(&res);
    rc = go(E_FROM, "[]", "null", "edge-held", plain_raw, &res);
    edge_chk("other parameters on the held key still conflict",
        rc && state_is(&res, "key_conflict") && atomic_load(&g_runs) == 1);
    json_free(&res);
}

int wallet_send_once_edge_tests(void);
int wallet_send_once_edge_tests(void)
{
    printf("\n=== wallet send-once edge cases ===\n");
    g_failures = 0;
    case_key_shape();
    void (*const cases[])(void) = {
        case_unkeyed_passthrough, case_refusals, case_key_conflict,
        case_key_conflict_fields, case_record_format, case_seeded_rows,
        case_started_row, case_in_progress, case_active_cap,
        case_out_of_order, case_row_cap, case_release_blocked,
        case_insert_blocked, case_batch_flush_failure,
        case_built_write_fails, case_sync_off, case_finish_hex,
        case_finish_recorded_txid, case_one_transaction,
        case_oversize_recipients, case_oversize_from, case_oversize_fee,
        case_oversize_old_row, case_digest_pins, case_digest_pin_largest,
        case_digest_no_memory, case_no_txid_holds_key,
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (!fx_up("case")) {
            edge_chk("fixture opens", false);
            break;
        }
        cases[i]();
        fx_down();
    }
    if (g_failures == 0)
        printf("wallet_send_once_edges: OK\n");
    else
        printf("=== wallet_send_once_edges: %d failure(s) ===\n", g_failures);
    return g_failures;
}
