/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: kill the mutants the sweep left alive in vault_intent_private.c.
 * Three oracles, none of which spends or exports anything:
 *   1. build_prepared on hand-framed VIP2 plaintext: every decoder refusal is
 *      PLAN_TAMPERED, every accepted frame reaches EXACT_BUILD_FAILED because
 *      the zeroed wallet context cannot build a transaction.
 *   2. vault_intent_private_plan refusals (parse stage), by error code.
 *   3. an idempotent replay against a seeded row whose request digest is
 *      SHA3-256 of independently hand-built VIP2 bytes: the replay only
 *      renders ok when the parser accepted and re-encoded the exact request. */

#include "test/test_core.h"
#include "test/vault_intent_private_cases.h"

#include "base/serialize_le.h"
#include "chain/chainparams.h"
#include "controllers/sovereignty_controller.h"
#include "controllers/vault_intent_controller.h"
#include "controllers/vault_intent_private.h"
#include "controllers/wallet_helpers.h"
#include "controllers/wallet_shielded_controller.h"
#include "coins/coins_view.h"
#include "core/amount.h"
#include "crypto/sha3.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "models/database.h"
#include "models/vault_intent.h"
#include "models/wallet_metadata_crypto.h"
#include "platform/time_compat.h"
#include "primitives/transaction.h"
#include "services/wallet_backup_service.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/safe_alloc.h"
#include "validation/accept_to_mempool.h"
#include "validation/main_state.h"
#include "wallet/wallet.h"
#include "wallet/wallet_canary.h"
#include "wallet/wallet_lock.h"
#include "wallet/wallet_sqlite.h"

#include "core/uint256.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VP_BUF 20000
#define VR_FEE 10000

/* ---- oracle 1: framed plaintext through vault_intent_private_build_prepared */

struct vp_eff {
    unsigned to_len;
    int64_t amount;
    unsigned mkind, mlen, mbytes;
};

struct vp_spec {
    bool bad_magic, bad_digest, bad_id;
    unsigned route, from_len, count, n_eff;
    struct vp_eff eff[2];     /* eff[0] first, eff[1] every later effect */
    int64_t fee, row_fee, wallet_fee;
    int row_route;            /* -1: same as the payload route */
    size_t trail, trunc;
};

enum vp_kind {
    VP_END = 0, VP_MAGIC, VP_ROUTE, VP_FROMLEN, VP_COUNT, VP_NEFF, VP_N,
    VP_TOLEN, VP_AMOUNT, VP_AMOUNT2, VP_MKIND, VP_MLEN, VP_FEE, VP_ROWFEE,
    VP_WFEE, VP_ROWROUTE, VP_TRAIL, VP_TRUNC, VP_BADDIGEST, VP_BADID
};

struct vp_op { enum vp_kind kind; int64_t val; };
struct vp_row { const char *label; struct vp_op ops[3]; const char *expect; };

static struct vp_spec vp_spec_base(void)
{
    struct vp_spec s;
    memset(&s, 0, sizeof(s));
    s.route = VAULT_INTENT_ROUTE_PRIVATE;
    s.from_len = 2;
    s.count = s.n_eff = 1;
    s.eff[0] = (struct vp_eff){ .to_len = 2, .amount = 1 };
    s.eff[1] = s.eff[0];
    s.row_route = -1;
    return s;
}

static bool vp_apply_header(struct vp_spec *s, struct vp_op op)
{
    switch (op.kind) {
    case VP_MAGIC: s->bad_magic = true; return true;
    case VP_ROUTE: s->route = (unsigned)op.val; return true;
    case VP_FROMLEN: s->from_len = (unsigned)op.val; return true;
    case VP_COUNT: s->count = (unsigned)op.val; return true;
    case VP_NEFF: s->n_eff = (unsigned)op.val; return true;
    case VP_N: s->count = s->n_eff = (unsigned)op.val; return true;
    case VP_FEE: s->fee = op.val; return true;
    case VP_ROWFEE: s->row_fee = op.val; return true;
    case VP_WFEE: s->wallet_fee = op.val; return true;
    default: return false;
    }
}

static bool vp_apply_effect(struct vp_spec *s, struct vp_op op)
{
    switch (op.kind) {
    case VP_TOLEN: s->eff[0].to_len = (unsigned)op.val; return true;
    case VP_AMOUNT: s->eff[0].amount = op.val; return true;
    case VP_AMOUNT2: s->eff[1].amount = op.val; return true;
    case VP_MKIND: s->eff[0].mkind = (unsigned)op.val; return true;
    case VP_MLEN:
        s->eff[0].mlen = s->eff[0].mbytes = (unsigned)op.val; return true;
    default: return false;
    }
}

static void vp_apply_frame(struct vp_spec *s, struct vp_op op)
{
    switch (op.kind) {
    case VP_ROWROUTE: s->row_route = (int)op.val; break;
    case VP_TRAIL: s->trail = (size_t)op.val; break;
    case VP_TRUNC: s->trunc = (size_t)op.val; break;
    case VP_BADDIGEST: s->bad_digest = true; break;
    case VP_BADID: s->bad_id = true; break;
    default: break;
    }
}

static struct vp_spec vp_spec_for(const struct vp_row *r)
{
    struct vp_spec s = vp_spec_base();
    for (size_t i = 0; i < 3 && r->ops[i].kind != VP_END; i++) {
        if (!vp_apply_header(&s, r->ops[i]) &&
            !vp_apply_effect(&s, r->ops[i]))
            vp_apply_frame(&s, r->ops[i]);
    }
    return s;
}

static size_t vp_put_eff(uint8_t *o, size_t n, const struct vp_eff *e)
{
    o[n++] = (uint8_t)e->to_len;
    memset(o + n, 't', e->to_len); n += e->to_len;
    zcl_write_i64_le(o + n, e->amount); n += 8;
    o[n++] = (uint8_t)e->mkind;
    o[n++] = (uint8_t)(e->mlen & 0xff);
    o[n++] = (uint8_t)(e->mlen >> 8);
    memset(o + n, 'm', e->mbytes);
    return n + e->mbytes;
}

static size_t vp_serialize(const struct vp_spec *s, uint8_t *o)
{
    size_t n = 0;
    memcpy(o, s->bad_magic ? "VIP1" : "VIP2", 4); n = 4;
    o[n++] = (uint8_t)s->route;
    o[n++] = (uint8_t)s->from_len;
    memset(o + n, 'f', s->from_len); n += s->from_len;
    o[n++] = (uint8_t)s->count;
    zcl_write_i64_le(o + n, s->fee); n += 8;
    for (unsigned i = 0; i < s->n_eff; i++)
        n = vp_put_eff(o, n, &s->eff[i ? 1 : 0]);
    memset(o + n, 0, s->trail);
    n += s->trail;
    return n - s->trunc;
}

/* Runs the authenticated build path; code receives the error code. */
static bool vp_run(struct node_db *ndb, const struct vp_spec *s,
                   char *code, size_t cap)
{
    uint8_t plain[VP_BUF];
    size_t n = vp_serialize(s, plain);
    struct vault_intent_row row;
    memset(&row, 0, sizeof(row));
    memset(row.plan_id, 0x61, 32);
    row.route = (enum vault_intent_route)(
        s->row_route < 0 ? (int)s->route : s->row_route);
    row.max_fee_zat = s->row_fee;
    if (!wallet_metadata_encrypt(ndb, row.plan_id, 32, plain, n,
            row.encrypted_payload, sizeof(row.encrypted_payload),
            &row.encrypted_payload_len))
        return false;
    vault_intent_digest_payload(plain, n, &row, row.digest);
    if (s->bad_digest) row.digest[0] ^= 1;
    if (s->bad_id) row.plan_id[0] ^= 1;

    struct wallet *w = zcl_calloc(1, sizeof(*w), "vip_cases.wallet");
    if (!w) return false;
    wallet_init(w);
    w->default_fee = s->wallet_fee;
    struct wallet_rpc_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.node_db = ndb;
    ctx.wallet = w;
    struct wallet_rpc_context saved = g_wallet_ctx;
    memset(&g_wallet_ctx, 0, sizeof(g_wallet_ctx));
    struct wallet_tx wtx;
    memset(&wtx, 0, sizeof(wtx));
    struct json_value result;
    json_init(&result);
    (void)vault_intent_private_build_prepared(&ctx, &row, &wtx, &result);
    g_wallet_ctx = saved;
    const char *got = json_get_str(json_get(&result, "code"));
    snprintf(code, cap, "%s", got ? got : "(none)");
    json_free(&result);
    wallet_free(w);
    free(w);
    return true;
}

#define OP(k, v) { VP_##k, (v) }
#define TAMP "PLAN_TAMPERED"
#define BUILD "EXACT_BUILD_FAILED"

static const struct vp_row k_vp_rows[] = {
    { "base frame is accepted", { }, BUILD },
    { "wrong magic", { OP(MAGIC, 0) }, TAMP },
    { "route 0", { OP(ROUTE, 0) }, TAMP },
    { "route transparent", { OP(ROUTE, VAULT_INTENT_ROUTE_TRANSPARENT) },
      TAMP },
    { "route above mixed", { OP(ROUTE, VAULT_INTENT_ROUTE_MIXED + 1) },
      TAMP },
    { "route shield", { OP(ROUTE, VAULT_INTENT_ROUTE_SHIELD) }, BUILD },
    { "route unshield", { OP(ROUTE, VAULT_INTENT_ROUTE_UNSHIELD) }, BUILD },
    { "route mixed", { OP(ROUTE, VAULT_INTENT_ROUTE_MIXED) }, BUILD },
    { "row route differs", { OP(ROWROUTE, VAULT_INTENT_ROUTE_SHIELD) },
      TAMP },
    { "from length 0", { OP(FROMLEN, 0) }, TAMP },
    { "from length 1", { OP(FROMLEN, 1) }, BUILD },
    { "to length 0", { OP(TOLEN, 0) }, TAMP },
    { "to length 1", { OP(TOLEN, 1) }, BUILD },
    { "no effects", { OP(N, 0) }, TAMP },
    { "50 effects", { OP(N, 50) }, BUILD },
    { "51 effects", { OP(N, 51) }, TAMP },
    { "declared count above frame", { OP(COUNT, 2) }, TAMP },
    { "frame above declared count", { OP(NEFF, 2) }, TAMP },
    { "amount 0", { OP(AMOUNT, 0) }, TAMP },
    { "amount -1", { OP(AMOUNT, -1) }, TAMP },
    { "amount MAX_MONEY", { OP(AMOUNT, MAX_MONEY) }, BUILD },
    { "amount above MAX_MONEY", { OP(AMOUNT, MAX_MONEY + 1) }, TAMP },
    { "second amount 0", { OP(N, 2), OP(AMOUNT2, 0) }, TAMP },
    { "second amount 5", { OP(N, 2), OP(AMOUNT2, 5) }, BUILD },
    { "memo kind 3", { OP(MKIND, 3) }, TAMP },
    { "memo none with bytes", { OP(MKIND, 0), OP(MLEN, 1) }, TAMP },
    { "memo text without bytes", { OP(MKIND, 1) }, TAMP },
    { "memo text 1 byte", { OP(MKIND, 1), OP(MLEN, 1) }, BUILD },
    { "memo hex 1024 bytes", { OP(MKIND, 2), OP(MLEN, 1024) }, BUILD },
    { "memo text 1025 bytes", { OP(MKIND, 1), OP(MLEN, 1025) }, TAMP },
    { "payload fee differs from row", { OP(FEE, 5) }, TAMP },
    { "row fee differs from payload", { OP(ROWFEE, 5) }, TAMP },
    { "wallet fee differs from plan", { OP(WFEE, 5) }, TAMP },
    { "fee agreed by all three", { OP(FEE, 5), OP(ROWFEE, 5), OP(WFEE, 5) },
      BUILD },
    { "fee -1 agreed by all three",
      { OP(FEE, -1), OP(ROWFEE, -1), OP(WFEE, -1) }, TAMP },
    { "one trailing byte", { OP(TRAIL, 1) }, TAMP },
    { "truncated by one byte", { OP(TRUNC, 1) }, TAMP },
    { "digest bit flipped", { OP(BADDIGEST, 0) }, TAMP },
    { "plan id bit flipped", { OP(BADID, 0) }, "PLAN_DECRYPT_FAILED" },
};

static int vp_decode_cases(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    TEST("private intent decoder and authenticator refuse every frame defect") {
        ASSERT(node_db_open(&ndb, ":memory:"));
        wallet_lock_reset_for_test();
        wallet_lock_note_encrypted_at_rest();
        ASSERT(wallet_lock_unlock(NULL, NULL, "vip-cases-pass").ok);
        for (size_t i = 0; i < sizeof(k_vp_rows) / sizeof(k_vp_rows[0]); i++) {
            struct vp_spec s = vp_spec_for(&k_vp_rows[i]);
            char code[64] = "";
            bool ran = vp_run(&ndb, &s, code, sizeof(code));
            bool ok = ran && strcmp(code, k_vp_rows[i].expect) == 0;
            if (!ok)
                printf("(frame '%s' gave '%s') ", k_vp_rows[i].label, code);
            ASSERT(ok);
        }
        PASS();
    }
_test_next:
    wallet_lock_reset_for_test();
    if (ndb.open) node_db_close(&ndb);
    return failures;
}

/* ---- fixture that passes vault_intent_context_ready, nothing real ------ */

static struct {
    char dir[256];
    bool progress, db_open, ws_open;
    struct node_db db;
    struct wallet_sqlite ws;
    struct wallet *wallet;
    struct tx_mempool mempool;
    struct coins_view_cache cache;
    struct main_state ms;
    struct wallet_rpc_context saved;
    bool bound;
    unsigned seq;
} g_fx;

static char g_z[160], g_y[160], g_t[160], g_u[160];

static bool vp_fx_sovereign(void)
{
    test_make_tmpdir(g_fx.dir, sizeof(g_fx.dir), "vip_cases", "main");
    if (!progress_store_open(g_fx.dir)) return false;
    g_fx.progress = true;
    sqlite3 *pdb = progress_store_db();
    if (!pdb || !coins_kv_ensure_schema(pdb)) return false;
    reducer_frontier_provable_tip_set(50);
    struct uint256 t1;
    uint256_set_null(&t1);
    t1.data[0] = 0x51;
    t1.data[31] = 0x77;
    unsigned char sc[4] = { 0xE0, 0xE0, 0xE0, 0xE0 };
    if (!coins_kv_add(pdb, t1.data, 0, 1234, 50, true, sc, sizeof(sc)))
        return false;
    char *err = NULL;
    if (sqlite3_exec(pdb, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK ||
        !coins_kv_set_applied_height_in_tx(pdb, 51) ||
        sqlite3_exec(pdb, "COMMIT", NULL, NULL, &err) != SQLITE_OK)
        return false;
    char why[96] = { 0 };
    return sovereignty_guard_allow("wallet_spend", why, sizeof(why));
}

static bool vp_fx_wallet(void)
{
    if (!node_db_open(&g_fx.db, ":memory:")) return false;
    g_fx.db_open = true;
    if (!wallet_sqlite_open_r(&g_fx.ws, g_fx.db.db).ok) return false;
    g_fx.ws_open = true;
    if (wallet_canary_run(g_fx.db.db, NULL) != WALLET_CANARY_OK) return false;
    wallet_lock_reset_for_test();
    wallet_lock_note_encrypted_at_rest();
    if (!wallet_lock_unlock(NULL, NULL, "vip-plan-cases-pass").ok)
        return false;
    g_fx.wallet = zcl_calloc(1, sizeof(*g_fx.wallet), "vip_cases.fixture");
    if (!g_fx.wallet) return false;
    wallet_init(g_fx.wallet);
    g_fx.wallet->default_fee = VR_FEE;
    return true;
}

static bool vp_fx_backup_and_bind(void)
{
    char path[320];
    snprintf(path, sizeof(path), "%s/wallet.enc", g_fx.dir);
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool wrote = fputs("enc", f) >= 0;
    if (fclose(f) != 0 || !wrote) return false;
    wallet_backup_seed_encrypted_authority_for_test(
        path, (int64_t)platform_time_wall_time_t(), 0);
    g_fx.saved = g_wallet_ctx;
    g_fx.bound = true;
    memset(&g_wallet_ctx, 0, sizeof(g_wallet_ctx));
    g_wallet_ctx.wallet = g_fx.wallet;
    g_wallet_ctx.wallet_db = &g_fx.ws;
    g_wallet_ctx.node_db = &g_fx.db;
    g_wallet_ctx.mempool = &g_fx.mempool;
    g_wallet_ctx.coins_tip = &g_fx.cache;
    g_wallet_ctx.main_state = &g_fx.ms;
    g_wallet_ctx.datadir = g_fx.dir;
    return true;
}

static bool vp_fx_addresses(void)
{
    const struct chain_params *cp = chain_params_get();
    const char *hrp = cp ? cp->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS] : NULL;
    if (!hrp || !hrp[0]) return false;
    snprintf(g_z, sizeof(g_z), "%s1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", hrp);
    snprintf(g_y, sizeof(g_y), "%s1ppppppppppppppppppppppppppppppp", hrp);
    snprintf(g_t, sizeof(g_t), "t1TestSenderAddressNotDecoded0000001");
    snprintf(g_u, sizeof(g_u), "t1TestOtherAddressNotDecoded00000002");
    return wallet_addr_is_sapling(g_z) && wallet_addr_is_sapling(g_y) &&
        !wallet_addr_is_sapling(g_t) && !wallet_addr_is_sapling(g_u);
}

static void vp_fx_teardown(void)
{
    if (g_fx.bound) g_wallet_ctx = g_fx.saved;
    wallet_lock_reset_for_test();
    if (g_fx.wallet) { wallet_free(g_fx.wallet); free(g_fx.wallet); }
    if (g_fx.ws_open) wallet_sqlite_close(&g_fx.ws);
    if (g_fx.db_open) node_db_close(&g_fx.db);
    reducer_frontier_provable_tip_reset();
    if (g_fx.progress) progress_store_close();
    if (g_fx.dir[0]) (void)test_rm_rf_recursive(g_fx.dir);
    memset(&g_fx, 0, sizeof(g_fx));
}

/* ---- request model shared by the accept, boundary and refusal cases ---- */

struct vr_eff {
    const char *to, *amount;
    int64_t zat;
    unsigned mkind;           /* 0 none, 1 text, 2 hex */
    const char *memo;         /* NULL: field absent; "" with mkind 0: empty */
};

struct vr_case {
    const char *label, *from, *route;
    unsigned actual;
    const struct vr_eff *eff;
    size_t n;
};

static size_t vr_json_eff(char *b, size_t cap, const struct vr_eff *e, size_t i)
{
    int n = snprintf(b, cap, "%s{\"asset\":\"ZCL\",\"to\":\"%s\",\"amount\":\"%s\"",
                     i ? "," : "", e->to, e->amount);
    if (e->memo)
        n += snprintf(b + n, cap - (size_t)n, ",\"%s\":\"%s\"",
                      e->mkind == 2 ? "memo_hex" : "memo", e->memo);
    n += snprintf(b + n, cap - (size_t)n, "}");
    return (size_t)n;
}

static void vr_json(char *b, size_t cap, const char *key, const char *from,
                    const char *route, const struct vr_eff *e, size_t n)
{
    size_t o = (size_t)snprintf(b, cap,
        "{\"wallet_scope\":\"test\",\"idempotency_key\":\"%s\",\"from\":\"%s\",",
        key, from);
    if (route) o += (size_t)snprintf(b + o, cap - o, "\"route\":\"%s\",", route);
    o += (size_t)snprintf(b + o, cap - o, "\"effects\":[");
    for (size_t i = 0; i < n; i++)
        o += vr_json_eff(b + o, cap - o, &e[i], i);
    (void)snprintf(b + o, cap - o, "]}");
}

static size_t vr_plain(uint8_t *o, const char *from, unsigned route,
                       const struct vr_eff *e, size_t n)
{
    size_t k = 0, len = strlen(from);
    memcpy(o, "VIP2", 4); k = 4;
    o[k++] = (uint8_t)route;
    o[k++] = (uint8_t)len;
    memcpy(o + k, from, len); k += len;
    o[k++] = (uint8_t)n;
    zcl_write_i64_le(o + k, VR_FEE); k += 8;
    for (size_t i = 0; i < n; i++) {
        size_t tl = strlen(e[i].to);
        size_t ml = e[i].mkind ? strlen(e[i].memo) : 0;
        o[k++] = (uint8_t)tl;
        memcpy(o + k, e[i].to, tl); k += tl;
        zcl_write_i64_le(o + k, e[i].zat); k += 8;
        o[k++] = (uint8_t)e[i].mkind;
        o[k++] = (uint8_t)(ml & 0xff);
        o[k++] = (uint8_t)(ml >> 8);
        if (ml) memcpy(o + k, e[i].memo, ml);
        k += ml;
    }
    return k;
}

static void vr_req_digest(const uint8_t *plain, size_t n, uint8_t out[32])
{
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, (const uint8_t *)"vault-multi-request-v1", 22);
    sha3_256_write(&c, (const uint8_t *)"test", 4);
    sha3_256_write(&c, plain, n);
    sha3_256_finalize(&c, out);
}

static int64_t vr_target(const struct vr_case *c)
{
    int64_t total = 0;
    for (size_t i = 0; i < c->n; i++) total += c->eff[i].zat;
    return total;
}

static bool vr_seed(const char *key, const uint8_t *plain, size_t n,
                    int64_t target, unsigned route)
{
    struct vault_intent_row row;
    memset(&row, 0, sizeof(row));
    uint8_t tag = (uint8_t)++g_fx.seq;
    memset(row.plan_id, tag, 32);
    memset(row.digest, 0x42, 32);
    memset(row.anchor_hash, 0x43, 32);
    memset(row.encrypted_payload, 0x44, 32);
    row.encrypted_payload_len = 32;
    row.state = VAULT_INTENT_PLANNED;
    row.route = (enum vault_intent_route)route;
    row.created_at = (int64_t)platform_time_wall_time_t();
    row.expires_at = row.created_at + 600;
    row.updated_at = row.created_at;
    row.anchor_height = 42;
    row.confirm_height = -1;
    snprintf(row.wallet_scope, sizeof(row.wallet_scope), "test");
    memset(row.wallet_instance_id, 'a', WALLET_INSTANCE_ID_HEX_LEN);
    memset(row.wallet_genesis, 'b', WALLET_GENESIS_HEX_LEN);
    row.has_snapshot_root = true;
    memset(row.snapshot_root, 0x45, 32);
    row.recipient_value_zat = target;
    row.max_fee_zat = VR_FEE;
    row.reserved_zat = target + VR_FEE;
    snprintf(row.application_kind, sizeof(row.application_kind), "vault_multi");
    snprintf(row.idempotency_key, sizeof(row.idempotency_key), "%s", key);
    vr_req_digest(plain, n, row.request_digest);
    row.has_request_digest = true;
    return vault_intent_save(&g_fx.db, &row);
}

static bool vp_plan_json(const char *text, struct json_value *result)
{
    struct json_value input;
    json_init(&input);
    bool parsed = json_read(&input, text, strlen(text));
    bool called = parsed && vault_intent_private_plan(&input, result);
    json_free(&input);
    return called;
}

static const char *vp_code(const struct json_value *r)
{
    const char *c = json_get_str(json_get(r, "code"));
    return c ? c : "(none)";
}

static const char *vp_str(const struct json_value *r, const char *key)
{
    const char *s = json_get_str(json_get(r, key));
    return s ? s : "(none)";
}

/* ---- oracle 3: accepted requests render from the replayed row ---------- */

static const char *vr_route_name(unsigned actual)
{
    switch (actual) {
    case VAULT_INTENT_ROUTE_PRIVATE: return "private";
    case VAULT_INTENT_ROUTE_SHIELD: return "shield";
    case VAULT_INTENT_ROUTE_UNSHIELD: return "unshield";
    default: return "mixed";
    }
}

static bool vr_effects_render_ok(const struct json_value *r,
                                 const struct vr_case *c)
{
    const struct json_value *arr = json_get(r, "effects");
    if (!arr || json_size(arr) != c->n) return false;
    for (size_t i = 0; i < c->n; i++) {
        const struct json_value *e = json_at(arr, i);
        char amount[40];
        snprintf(amount, sizeof(amount), "%lld.%08lld",
                 (long long)(c->eff[i].zat / COIN),
                 (long long)(c->eff[i].zat % COIN));
        bool attached = c->eff[i].mkind != 0;
        if (strcmp(vp_str(e, "asset"), "ZCL") != 0 ||
            strcmp(vp_str(e, "to"), c->eff[i].to) != 0 ||
            strcmp(vp_str(e, "amount"), amount) != 0 ||
            json_get_bool(json_get(e, "memo_attached")) != attached)
            return false;
    }
    return true;
}

/* The seeded row's digest is 32 bytes of 0x42; the plan reply must show it. */
#define VR_SEED_DIGEST_HEX \
    "4242424242424242424242424242424242424242424242424242424242424242"

static bool vr_render_ok(const struct json_value *r, const struct vr_case *c)
{
    const char *privacy = vp_str(r, "privacy");
    bool is_private = c->actual == VAULT_INTENT_ROUTE_PRIVATE;
    bool privacy_ok = strncmp(privacy, is_private ? "PRIVATE:" : "MIXED POOLS:",
                              is_private ? 8 : 12) == 0;
    return json_get_bool(json_get(r, "ok")) &&
        json_get_bool(json_get(r, "idempotent_plan")) &&
        strcmp(vp_str(r, "digest"), VR_SEED_DIGEST_HEX) == 0 &&
        strcmp(vp_str(r, "route"), vr_route_name(c->actual)) == 0 &&
        strcmp(vp_str(r, "from"), c->from) == 0 &&
        strcmp(vp_str(r, "fee"), "0.00010000") == 0 &&
        json_get_int(json_get(r, "confirmation_policy")) == 6 &&
        privacy_ok && vr_effects_render_ok(r, c);
}

static bool vr_accept(const struct vr_case *c)
{
    char key[40];
    snprintf(key, sizeof(key), "vp-acc-%u", g_fx.seq + 1);
    uint8_t plain[VP_BUF];
    size_t n = vr_plain(plain, c->from, c->actual, c->eff, c->n);
    char json[32768];
    vr_json(json, sizeof(json), key, c->from, c->route, c->eff, c->n);
    struct json_value r;
    json_init(&r);
    bool ok = vr_seed(key, plain, n, vr_target(c), c->actual) &&
        vp_plan_json(json, &r) && vr_render_ok(&r, c);
    if (!ok)
        printf("(accept '%s' gave code '%s') ", c->label, vp_code(&r));
    json_free(&r);
    return ok;
}

/* A seeded digest one byte off must be a conflict, never a replay. */
static bool vr_conflict(const struct vr_case *c)
{
    char key[40];
    snprintf(key, sizeof(key), "vp-con-%u", g_fx.seq + 1);
    uint8_t plain[VP_BUF];
    size_t n = vr_plain(plain, c->from, c->actual, c->eff, c->n);
    plain[n - 1] ^= 1;
    char json[32768];
    vr_json(json, sizeof(json), key, c->from, c->route, c->eff, c->n);
    struct json_value r;
    json_init(&r);
    bool ok = vr_seed(key, plain, n, vr_target(c), c->actual) &&
        vp_plan_json(json, &r) &&
        strcmp(vp_code(&r), "IDEMPOTENCY_CONFLICT") == 0;
    if (!ok)
        printf("(conflict '%s' gave code '%s') ", c->label, vp_code(&r));
    json_free(&r);
    return ok;
}

static bool vr_refused(const char *label, const char *from, const char *route,
                       const struct vr_eff *e, size_t n, const char *want)
{
    char json[32768];
    vr_json(json, sizeof(json), "vp-ref", from, route, e, n);
    struct json_value r;
    json_init(&r);
    bool ok = vp_plan_json(json, &r) && strcmp(vp_code(&r), want) == 0;
    if (!ok)
        printf("(refusal '%s' gave '%s', wanted '%s') ", label, vp_code(&r), want);
    json_free(&r);
    return ok;
}

static const struct vr_eff k_shield_effs[] = {
    { NULL, "1.5", 150000000, 1, "hello" },
    { NULL, "0.00000001", 1, 2, "00ff" },
};
static const struct vr_eff k_private_effs[] = {
    { NULL, "1234.5678", 123456780000LL, 0, NULL },
};
static const struct vr_eff k_unshield_effs[] = {
    { NULL, "0.1", 10000000, 0, "" },
};
static const struct vr_eff k_mixed_effs[] = {
    { NULL, "0.5", 50000000, 0, NULL },
    { NULL, "0.25", 25000000, 0, NULL },
    { NULL, "0.00000007", 7, 2, "ff" },
};
static const struct vr_eff k_zmixed_effs[] = {
    { NULL, "3", 300000000, 0, NULL },
    { NULL, "4", 400000000, 1, "m" },
};
static const struct vr_eff k_hexpriv_effs[] = {
    { NULL, "2", 200000000, 2, "ff" },
};

/* The recipient addresses are runtime strings (the HRP is chain-selected), so
 * the tables above are patched once the addresses exist. */
static struct vr_eff g_shield[2], g_private[1], g_unshield[1], g_mixed[3],
    g_zmixed[2], g_hexpriv[1];

static void vr_patch(struct vr_eff *dst, const struct vr_eff *src, size_t n,
                     const char *const *to)
{
    for (size_t i = 0; i < n; i++) {
        dst[i] = src[i];
        dst[i].to = to[i];
    }
}

static void vr_patch_all(void)
{
    const char *const shield_to[] = { g_z, g_y };
    const char *const private_to[] = { g_y };
    const char *const unshield_to[] = { g_t };
    const char *const mixed_to[] = { g_z, g_t, g_y };
    const char *const zmixed_to[] = { g_t, g_z };
    vr_patch(g_shield, k_shield_effs, 2, shield_to);
    vr_patch(g_private, k_private_effs, 1, private_to);
    vr_patch(g_unshield, k_unshield_effs, 1, unshield_to);
    vr_patch(g_mixed, k_mixed_effs, 3, mixed_to);
    vr_patch(g_zmixed, k_zmixed_effs, 2, zmixed_to);
    vr_patch(g_hexpriv, k_hexpriv_effs, 1, private_to);
}

static bool vp_accept_all(void)
{
    vr_patch_all();
    const struct vr_case cases[] = {
        { "shield with text and hex memos", g_t, "shield",
          VAULT_INTENT_ROUTE_SHIELD, g_shield, 2 },
        { "private without memo", g_z, "private",
          VAULT_INTENT_ROUTE_PRIVATE, g_private, 1 },
        { "unshield with empty memo", g_z, "unshield",
          VAULT_INTENT_ROUTE_UNSHIELD, g_unshield, 1 },
        { "mixed from transparent", g_t, "mixed",
          VAULT_INTENT_ROUTE_MIXED, g_mixed, 3 },
        { "mixed from sapling", g_z, "mixed",
          VAULT_INTENT_ROUTE_MIXED, g_zmixed, 2 },
        { "private with hex memo", g_z, "private",
          VAULT_INTENT_ROUTE_PRIVATE, g_hexpriv, 1 },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        if (!vr_accept(&cases[i]) || !vr_conflict(&cases[i])) return false;
    return true;
}

static int vp_accept_cases(void)
{
    int failures = 0;
    TEST("private intent replay renders exactly the parsed request") {
        ASSERT(vp_accept_all());
        PASS();
    }
_test_next:
    return failures;
}

/* ---- oracle 2: parse refusals by code ---------------------------------- */

#define VPRE "{\"wallet_scope\":\"test\",\"idempotency_key\":\"k1\","
#define VFROM(f) "\"from\":\"" f "\","
#define VROUTE(r) "\"route\":\"" r "\","
#define VEFF(...) "\"effects\":[" __VA_ARGS__ "]}"
#define VEFF2(a, b) "\"effects\":[" a "," b "]}"
#define VE(to, amt) "{\"asset\":\"ZCL\",\"to\":\"" to "\",\"amount\":\"" amt "\"}"
#define VEM(to, amt, field, val) \
    "{\"asset\":\"ZCL\",\"to\":\"" to "\",\"amount\":\"" amt "\",\"" field \
    "\":\"" val "\"}"
#define VSHIELD VPRE VFROM("@T@") VROUTE("shield")

struct vp_ref { const char *label, *json, *code; };

static const struct vp_ref k_refs[] = {
    { "from missing", VPRE VROUTE("shield") VEFF(VE("@Z@", "1")),
      "FROM_REQUIRED" },
    { "from empty", VPRE VFROM("") VROUTE("shield") VEFF(VE("@Z@", "1")),
      "FROM_REQUIRED" },
    { "route unknown", VPRE VFROM("@T@") VROUTE("bogus") VEFF(VE("@Z@", "1")),
      "UNSUPPORTED_ROUTE" },
    { "effects missing", VSHIELD "\"x\":1}", "INVALID_EFFECTS" },
    { "effects not an array", VSHIELD "\"effects\":\"abc\"}",
      "INVALID_EFFECTS" },
    { "effects empty", VSHIELD VEFF(), "INVALID_EFFECTS" },
    { "from is a number",
      VPRE "\"from\":5," VROUTE("shield") VEFF(VE("@Z@", "1")),
      "FROM_REQUIRED" },
    { "route missing", VPRE VFROM("@T@") VEFF(VE("@Z@", "1")),
      "UNSUPPORTED_ROUTE" },
    { "route in the wrong case",
      VPRE VFROM("@T@") VROUTE("Shield") VEFF(VE("@Z@", "1")),
      "UNSUPPORTED_ROUTE" },
    { "bad from is reported before a bad route and bad effects",
      VPRE VFROM("") VROUTE("bogus") "\"x\":1}", "FROM_REQUIRED" },
    { "bad route is reported before bad effects",
      VPRE VFROM("@T@") VROUTE("bogus") "\"x\":1}", "UNSUPPORTED_ROUTE" },
    { "bad scope is reported before a bad key",
      "{\"wallet_scope\":\"live\",\"idempotency_key\":\"\"," VFROM("@T@")
      VROUTE("shield") VEFF(VE("@Z@", "1")), "WALLET_SCOPE_REQUIRED" },
    { "scope missing",
      "{\"idempotency_key\":\"k1\"," VFROM("@T@") VROUTE("shield")
      VEFF(VE("@Z@", "1")), "WALLET_SCOPE_REQUIRED" },
    { "idempotency key missing",
      "{\"wallet_scope\":\"test\"," VFROM("@T@") VROUTE("shield")
      VEFF(VE("@Z@", "1")), "IDEMPOTENCY_KEY_REQUIRED" },
    { "asset in the wrong case", VSHIELD VEFF("{\"asset\":\"zcl\","
      "\"to\":\"@Z@\",\"amount\":\"1\"}"), "INVALID_EFFECT" },
    { "scope not dev prod test",
      "{\"wallet_scope\":\"live\",\"idempotency_key\":\"k1\"," VFROM("@T@")
      VROUTE("shield") VEFF(VE("@Z@", "1")), "WALLET_SCOPE_REQUIRED" },
    { "idempotency key empty",
      "{\"wallet_scope\":\"test\",\"idempotency_key\":\"\"," VFROM("@T@")
      VROUTE("shield") VEFF(VE("@Z@", "1")), "IDEMPOTENCY_KEY_REQUIRED" },
    { "asset not ZCL", VSHIELD VEFF("{\"asset\":\"BTC\",\"to\":\"@Z@\","
      "\"amount\":\"1\"}"), "INVALID_EFFECT" },
    { "asset missing", VSHIELD VEFF("{\"to\":\"@Z@\",\"amount\":\"1\"}"),
      "INVALID_EFFECT" },
    { "to missing", VSHIELD VEFF("{\"asset\":\"ZCL\",\"amount\":\"1\"}"),
      "INVALID_EFFECT" },
    { "to empty", VSHIELD VEFF(VE("", "1")), "INVALID_EFFECT" },
    { "amount is a number", VSHIELD VEFF("{\"asset\":\"ZCL\",\"to\":\"@Z@\","
      "\"amount\":1}"), "INVALID_EFFECT" },
    { "amount missing", VSHIELD VEFF("{\"asset\":\"ZCL\",\"to\":\"@Z@\"}"),
      "INVALID_EFFECT" },
    { "amount zero", VSHIELD VEFF(VE("@Z@", "0")), "INVALID_EFFECT" },
    { "amount negative", VSHIELD VEFF(VE("@Z@", "-1")), "INVALID_EFFECT" },
    { "amount above supply", VSHIELD VEFF(VE("@Z@", "21000001")),
      "INVALID_EFFECT" },
    { "amount not a number", VSHIELD VEFF(VE("@Z@", "abc")),
      "INVALID_EFFECT" },
    { "amount past eight decimals", VSHIELD VEFF(VE("@Z@", "0.000000001")),
      "INVALID_EFFECT" },
    { "memo on transparent recipient",
      VSHIELD VEFF(VEM("@T@", "1", "memo", "hi")), "INVALID_EFFECT" },
    { "memo_hex on transparent recipient",
      VSHIELD VEFF(VEM("@T@", "1", "memo_hex", "00")), "INVALID_EFFECT" },
    { "memo_hex of odd length", VSHIELD VEFF(VEM("@Z@", "1", "memo_hex", "abc")),
      "INVALID_EFFECT" },
    { "memo_hex not hex", VSHIELD VEFF(VEM("@Z@", "1", "memo_hex", "zz")),
      "INVALID_EFFECT" },
    { "second effect invalid", VSHIELD VEFF2(VE("@Z@", "1"), VE("@Z@", "0")),
      "INVALID_EFFECT" },
    { "first effect invalid", VSHIELD VEFF2(VE("@Z@", "0"), VE("@Z@", "1")),
      "INVALID_EFFECT" },
    { "memo on the second, transparent effect",
      VPRE VFROM("@T@") VROUTE("mixed")
      VEFF2(VE("@Z@", "1"), VEM("@U@", "1", "memo", "x")), "INVALID_EFFECT" },
    { "empty memo on transparent recipient is no memo",
      VSHIELD VEFF(VEM("@U@", "1", "memo", "")), "ROUTE_MISMATCH" },
    { "empty memo_hex on transparent recipient is no memo",
      VSHIELD VEFF(VEM("@U@", "1", "memo_hex", "")), "ROUTE_MISMATCH" },
    { "memo and memo_hex both set on a Sapling recipient",
      VSHIELD VEFF("{\"asset\":\"ZCL\",\"to\":\"@Z@\",\"amount\":\"1\","
                   "\"memo\":\"hi\",\"memo_hex\":\"00\"}"), "INVALID_EFFECT" },
    { "memo that is a number", VSHIELD VEFF("{\"asset\":\"ZCL\",\"to\":\"@Z@\","
                                            "\"amount\":\"1\",\"memo\":5}"),
      "INVALID_EFFECT" },
    { "memo_hex that is a number", VSHIELD VEFF("{\"asset\":\"ZCL\",\"to\":\"@Z@\","
                                                "\"amount\":\"1\",\"memo_hex\":5}"),
      "INVALID_EFFECT" },
    { "memo that is null", VSHIELD VEFF("{\"asset\":\"ZCL\",\"to\":\"@Z@\","
                                        "\"amount\":\"1\",\"memo\":null}"),
      "INVALID_EFFECT" },
    { "transparent to transparent needs another route",
      VSHIELD VEFF(VE("@U@", "1")), "ROUTE_MISMATCH" },
    { "t to z asked as private", VPRE VFROM("@T@") VROUTE("private")
      VEFF(VE("@Z@", "1")), "ROUTE_MISMATCH" },
    { "t to z asked as mixed", VPRE VFROM("@T@") VROUTE("mixed")
      VEFF(VE("@Z@", "1")), "ROUTE_MISMATCH" },
    { "t to z asked as unshield", VPRE VFROM("@T@") VROUTE("unshield")
      VEFF(VE("@Z@", "1")), "ROUTE_MISMATCH" },
    { "z to z asked as shield", VPRE VFROM("@Z@") VROUTE("shield")
      VEFF(VE("@Y@", "1")), "ROUTE_MISMATCH" },
    { "z to z asked as unshield", VPRE VFROM("@Z@") VROUTE("unshield")
      VEFF(VE("@Y@", "1")), "ROUTE_MISMATCH" },
    { "z to z asked as mixed", VPRE VFROM("@Z@") VROUTE("mixed")
      VEFF(VE("@Y@", "1")), "ROUTE_MISMATCH" },
    { "z to t asked as private", VPRE VFROM("@Z@") VROUTE("private")
      VEFF(VE("@T@", "1")), "ROUTE_MISMATCH" },
    { "z to t asked as mixed", VPRE VFROM("@Z@") VROUTE("mixed")
      VEFF(VE("@T@", "1")), "ROUTE_MISMATCH" },
    { "z to z and t asked as private", VPRE VFROM("@Z@") VROUTE("private")
      VEFF2(VE("@Y@", "1"), VE("@T@", "1")), "ROUTE_MISMATCH" },
    { "t to z and t asked as shield", VSHIELD
      VEFF2(VE("@Z@", "1"), VE("@T@", "1")), "ROUTE_MISMATCH" },
};

static void vp_expand(const char *tpl, char *out, size_t cap)
{
    static const char *const toks[] = { "@Z@", "@Y@", "@T@", "@U@" };
    const char *vals[] = { g_z, g_y, g_t, g_u };
    size_t o = 0;
    for (const char *p = tpl; *p && o + 1 < cap; ) {
        bool hit = false;
        for (size_t i = 0; i < 4 && !hit; i++) {
            if (strncmp(p, toks[i], 3) != 0) continue;
            o += (size_t)snprintf(out + o, cap - o, "%s", vals[i]);
            p += 3;
            hit = true;
        }
        if (!hit) out[o++] = *p++;
    }
    out[o < cap ? o : cap - 1] = '\0';
}

static bool vp_refs_ok(void)
{
    for (size_t i = 0; i < sizeof(k_refs) / sizeof(k_refs[0]); i++) {
        char json[2048];
        vp_expand(k_refs[i].json, json, sizeof(json));
        struct json_value r;
        json_init(&r);
        bool ok = vp_plan_json(json, &r) &&
            strcmp(vp_code(&r), k_refs[i].code) == 0;
        if (!ok)
            printf("(refusal '%s' gave '%s') ", k_refs[i].label, vp_code(&r));
        json_free(&r);
        if (!ok) return false;
    }
    return true;
}

static bool vp_transparent_only_message(void)
{
    char json[1024];
    vp_expand(VSHIELD VEFF(VE("@U@", "1")), json, sizeof(json));
    struct json_value r;
    json_init(&r);
    bool ok = vp_plan_json(json, &r) &&
        strstr(vp_str(&r, "message"), "no route here") != NULL &&
        strstr(vp_str(&r, "message"), "route=transparent") == NULL;
    json_free(&r);
    return ok;
}

static int vp_refusal_cases(void)
{
    int failures = 0;
    TEST("private intent plan refuses every malformed field before money") {
        ASSERT(vp_refs_ok());
        ASSERT(vp_transparent_only_message());
        PASS();
    }
_test_next:
    return failures;
}

/* ---- boundaries: lengths accepted at the limit, refused one past ------- */

static void vp_fill(char *dst, size_t len, const char *prefix, char pad)
{
    size_t p = strlen(prefix);
    memcpy(dst, prefix, p);
    memset(dst + p, pad, len - p);
    dst[len] = '\0';
}

static bool vp_long_addresses(void)
{
    char from127[128], from128[129], to127[128], to128[129];
    vp_fill(from127, 127, "t", 'a');
    vp_fill(from128, 128, "t", 'a');
    char zprefix[16];
    snprintf(zprefix, sizeof(zprefix), "%.*s1", (int)(strchr(g_z, '1') - g_z), g_z);
    vp_fill(to127, 127, zprefix, 'q');
    vp_fill(to128, 128, zprefix, 'q');
    const struct vr_eff to_z = { to127, "1", 100000000, 0, NULL };
    const struct vr_eff to_zz = { to128, "1", 100000000, 0, NULL };
    const struct vr_eff plain_z = { g_z, "1", 100000000, 0, NULL };
    const struct vr_case a = { "from of 127 bytes", from127, "shield",
        VAULT_INTENT_ROUTE_SHIELD, &plain_z, 1 };
    const struct vr_case b = { "to of 127 bytes", g_t, "shield",
        VAULT_INTENT_ROUTE_SHIELD, &to_z, 1 };
    return vr_accept(&a) && vr_accept(&b) &&
        vr_refused("from of 128 bytes", from128, "shield", &plain_z, 1,
                   "FROM_REQUIRED") &&
        vr_refused("to of 128 bytes", g_t, "shield", &to_zz, 1,
                   "INVALID_EFFECT");
}

static bool vp_memo_bounds(void)
{
    static char text1024[1025], text1025[1026], hex1024[1025], hex1026[1027],
        hexbad[1025];
    vp_fill(text1024, 1024, "", 'm');
    vp_fill(text1025, 1025, "", 'm');
    vp_fill(hex1024, 1024, "", 'a');
    vp_fill(hex1026, 1026, "", 'a');
    vp_fill(hexbad, 1024, "", 'a');
    hexbad[1023] = 'g';
    const struct vr_eff t_ok = { g_z, "1", 100000000, 1, text1024 };
    const struct vr_eff t_no = { g_z, "1", 100000000, 1, text1025 };
    const struct vr_eff h_ok = { g_z, "1", 100000000, 2, hex1024 };
    const struct vr_eff h_no = { g_z, "1", 100000000, 2, hex1026 };
    const struct vr_eff h_bad = { g_z, "1", 100000000, 2, hexbad };
    const struct vr_case a = { "text memo of 1024 bytes", g_t, "shield",
        VAULT_INTENT_ROUTE_SHIELD, &t_ok, 1 };
    const struct vr_case b = { "hex memo of 1024 digits", g_t, "shield",
        VAULT_INTENT_ROUTE_SHIELD, &h_ok, 1 };
    return vr_accept(&a) && vr_accept(&b) &&
        vr_refused("text memo of 1025 bytes", g_t, "shield", &t_no, 1,
                   "INVALID_EFFECT") &&
        vr_refused("hex memo of 1026 digits", g_t, "shield", &h_no, 1,
                   "INVALID_EFFECT") &&
        vr_refused("hex memo with a non-hex digit", g_t, "shield", &h_bad, 1,
                   "INVALID_EFFECT");
}

static bool vp_count_bounds(void)
{
    static struct vr_eff effs[51];
    static char amounts[51][16];
    for (size_t i = 0; i < 51; i++) {
        snprintf(amounts[i], sizeof(amounts[i]), "0.%08zu", i + 1);
        effs[i] = (struct vr_eff){ g_z, amounts[i], (int64_t)(i + 1), 0, NULL };
    }
    const struct vr_case fifty = { "fifty effects", g_t, "shield",
        VAULT_INTENT_ROUTE_SHIELD, effs, 50 };
    return vr_accept(&fifty) &&
        vr_refused("fifty-one effects", g_t, "shield", effs, 51,
                   "INVALID_EFFECTS");
}

static int vp_boundary_cases(void)
{
    int failures = 0;
    TEST("private intent plan accepts the limits and refuses one past them") {
        ASSERT(vp_long_addresses());
        ASSERT(vp_memo_bounds());
        ASSERT(vp_count_bounds());
        PASS();
    }
_test_next:
    return failures;
}

/* ---- fresh requests: refused before any reservation is written --------- */

static const char *const k_money_codes[] = {
    "MONEY_STATE_NOT_CURRENT", "INSUFFICIENT_CONFIRMED_FUNDS",
    "DEVELOPMENT_RESERVE_OR_LAB_CAP",
};

static bool vp_is_money_code(const char *code)
{
    for (size_t i = 0; i < sizeof(k_money_codes) / sizeof(k_money_codes[0]); i++)
        if (strcmp(code, k_money_codes[i]) == 0) return true;
    return false;
}

static bool vp_row_absent(const char *scope, const char *key)
{
    struct vault_intent_row row;
    memset(&row, 0, sizeof(row));
    return !vault_intent_find_application_idempotency(
        &g_fx.db, scope, "vault_multi", key, &row);
}

/* One fresh shield request (no seeded row). Returns true when the plan call
 * ran; *accepted is whether the reply claimed success. */
static bool vp_fresh(const char *scope, const char *key, const char *session,
                     const char *amount, char *code, size_t cap,
                     bool *accepted)
{
    char json[1024], sess[160] = "";
    if (session)
        snprintf(sess, sizeof(sess), "\"_agent_session\":\"%s\",", session);
    snprintf(json, sizeof(json),
        "{\"wallet_scope\":\"%s\",\"idempotency_key\":\"%s\",%s"
        "\"from\":\"%s\",\"route\":\"shield\",\"effects\":[{\"asset\":\"ZCL\","
        "\"to\":\"%s\",\"amount\":\"%s\"}]}",
        scope, key, sess, g_t, g_z, amount);
    struct json_value r;
    json_init(&r);
    bool ran = vp_plan_json(json, &r);
    snprintf(code, cap, "%s", vp_code(&r));
    *accepted = json_get_bool(json_get(&r, "ok"));
    json_free(&r);
    return ran;
}

/* An unfunded wallet must never get a plan: every scope refuses on money and
 * leaves no row behind. An "ok" here would be a custody finding. */
static bool vp_fresh_refused_in(const char *scope, const char *key)
{
    char code[64] = "";
    bool accepted = true;
    bool ran = vp_fresh(scope, key, NULL, "1", code, sizeof(code), &accepted);
    bool ok = ran && !accepted && vp_is_money_code(code) &&
        vp_row_absent(scope, key);
    if (!ok) printf("(fresh plan in '%s' gave '%s') ", scope, code);
    return ok;
}

static bool vp_fresh_bogus_session(void)
{
    char code[64] = "";
    bool accepted = true;
    bool ran = vp_fresh("test", "vp-sess", "no-such-session", "1", code,
                        sizeof(code), &accepted);
    bool refused = ran && !accepted && code[0] != '\0' &&
        !vp_is_money_code(code);
    if (!refused)
        printf("(bogus session gave '%s') ", code);
    return refused && vp_row_absent("test", "vp-sess");
}

static int vp_fresh_cases(void)
{
    int failures = 0;
    TEST("private intent plan on an unfunded wallet reserves nothing") {
        ASSERT(vp_fresh_refused_in("test", "vp-fresh-test"));
        ASSERT(vp_fresh_refused_in("prod", "vp-fresh-prod"));
        ASSERT(vp_fresh_refused_in("dev", "vp-fresh-dev"));
        ASSERT(vp_fresh_bogus_session());
        PASS();
    }
_test_next:
    return failures;
}

/* ---- fee and size limits ------------------------------------------------ */

static bool vp_fee_refused(const char *label, int64_t fee, const char *amount)
{
    const struct vr_eff e = { g_z, amount, 100000000, 0, NULL };
    g_fx.wallet->default_fee = fee;
    bool ok = vr_refused(label, g_t, "shield", &e, 1, "FEE_INVALID");
    g_fx.wallet->default_fee = VR_FEE;
    return ok;
}

/* A request whose value plus the fee is exactly the supply is not a fee
 * error; it falls through to the money check. */
static bool vp_fee_edge_passes(void)
{
    char code[64] = "";
    bool accepted = true;
    bool ran = vp_fresh("test", "vp-edge", NULL, "20999999.9999", code,
                        sizeof(code), &accepted);
    if (!vp_is_money_code(code)) printf("(supply-edge request gave '%s') ", code);
    return ran && !accepted && vp_is_money_code(code);
}

static int vp_fee_cases(void)
{
    int failures = 0;
    TEST("private intent plan refuses a fee or total outside the money range") {
        ASSERT(vp_fee_refused("fee negative", -1, "1"));
        ASSERT(vp_fee_refused("fee above supply", MAX_MONEY + 1, "1"));
        ASSERT(vp_fee_refused("total above supply", VR_FEE, "21000000"));
        ASSERT(vp_fee_edge_passes());
        PASS();
    }
_test_next:
    g_fx.wallet->default_fee = VR_FEE;
    return failures;
}

/* A seeded row is replayed only when its request digest matches this
 * request under this fee. */
static bool vp_replay_is(const struct vr_case *c, const char *key,
                         const char *want)
{
    uint8_t plain[VP_BUF];
    size_t n = vr_plain(plain, c->from, c->actual, c->eff, c->n);
    char json[32768];
    vr_json(json, sizeof(json), key, c->from, c->route, c->eff, c->n);
    struct json_value r;
    json_init(&r);
    bool ok = vr_seed(key, plain, n, vr_target(c), c->actual) &&
        vp_plan_json(json, &r) && strcmp(vp_code(&r), want) == 0;
    if (!ok)
        printf("(replay '%s' gave '%s', wanted '%s') ", key, vp_code(&r), want);
    json_free(&r);
    return ok;
}

static int vp_replay_guard_cases(void)
{
    int failures = 0;
    const struct vr_eff e = { g_z, "1", 100000000, 0, NULL };
    const struct vr_case c = { "replay guard", g_t, "shield",
        VAULT_INTENT_ROUTE_SHIELD, &e, 1 };
    TEST("private intent replay is refused when the wallet fee has changed") {
        ASSERT(vp_replay_is(&c, "vp-rp-ok", ""));
        g_fx.wallet->default_fee = 2 * VR_FEE;
        bool drift = vp_replay_is(&c, "vp-rp-fee", "IDEMPOTENCY_CONFLICT");
        g_fx.wallet->default_fee = VR_FEE;
        ASSERT(drift);
        PASS();
    }
_test_next:
    g_fx.wallet->default_fee = VR_FEE;
    return failures;
}

/* The encrypted plan holds at most WALLET_METADATA_PLAINTEXT_MAX bytes: the
 * frame that fills it exactly is planned, one byte more is refused. */
static bool vp_size_edge(void)
{
    static char full[1025], last[1026];
    static struct vr_eff effs[16];
    size_t fixed = 4 + 1 + 1 + strlen(g_t) + 1 + 8;
    size_t per = 1 + strlen(g_z) + 8 + 1 + 2;
    size_t room = WALLET_METADATA_PLAINTEXT_MAX - fixed - 16 * per;
    if (room < 15 * 1024 + 1 || room > 16 * 1024) return false;
    size_t tail = room - 15 * 1024;
    vp_fill(full, 1024, "", 'm');
    vp_fill(last, tail, "", 'm');
    for (size_t i = 0; i < 16; i++)
        effs[i] = (struct vr_eff){ g_z, "1", 100000000, 1,
                                   i < 15 ? full : last };
    const struct vr_case fits = { "plan filling the budget", g_t, "shield",
        VAULT_INTENT_ROUTE_SHIELD, effs, 16 };
    if (!vr_accept(&fits)) return false;
    vp_fill(last, tail + 1, "", 'm');
    return vr_refused("plan one byte over the budget", g_t, "shield", effs, 16,
                      "PLAN_TOO_LARGE");
}

static bool vp_mismatch_message(void)
{
    char json[1024];
    vp_expand(VPRE VFROM("@Z@") VROUTE("shield") VEFF(VE("@Y@", "1")), json,
              sizeof(json));
    struct json_value r;
    json_init(&r);
    bool ok = vp_plan_json(json, &r) &&
        strcmp(vp_code(&r), "ROUTE_MISMATCH") == 0 &&
        strstr(vp_str(&r, "message"), "does not match") != NULL &&
        strstr(vp_str(&r, "message"), "no route here") == NULL;
    json_free(&r);
    return ok;
}

static int vp_size_cases(void)
{
    int failures = 0;
    TEST("private intent plan holds the plaintext budget and words a mismatch") {
        ASSERT(vp_size_edge());
        ASSERT(vp_mismatch_message());
        PASS();
    }
_test_next:
    return failures;
}

static int vp_plan_cases(void)
{
    int failures = 0;
    TEST("private intent plan fixture passes the readiness gate") {
        ASSERT(vp_fx_sovereign());
        ASSERT(vp_fx_wallet());
        ASSERT(vp_fx_backup_and_bind());
        ASSERT(vp_fx_addresses());
        struct json_value out;
        json_init(&out);
        bool ready = vault_intent_context_ready(&g_wallet_ctx, &out);
        if (!ready)
            printf("(not ready: %s) ", vp_code(&out));
        json_free(&out);
        ASSERT(ready);
        PASS();
    }
    if (failures) goto _test_next;
    failures += vp_refusal_cases();
    failures += vp_accept_cases();
    failures += vp_boundary_cases();
    failures += vp_fresh_cases();
    failures += vp_fee_cases();
    failures += vp_replay_guard_cases();
    failures += vp_size_cases();
_test_next:
    vp_fx_teardown();
    return failures;
}

/* ---- requirements preflight: missing context and the passing verdict ---- */

static bool vp_requirements_unavailable(struct wallet_rpc_context *ctx,
                                        const struct transaction *tx)
{
    struct json_value out;
    json_init(&out);
    bool refused = !vault_intent_private_requirements_current(ctx, tx, &out) &&
        strcmp(vp_code(&out), "SHIELDED_AUTHORITY_UNAVAILABLE") == 0;
    json_free(&out);
    return refused;
}

static int vp_requirements_cases(void)
{
    int failures = 0;
    struct transaction tx;
    transaction_init(&tx);
    TEST("private intent requirement preflight needs a full context") {
        static struct coins_view_cache cache;
        struct wallet_rpc_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        ASSERT(vp_requirements_unavailable(NULL, &tx));
        ASSERT(vp_requirements_unavailable(&ctx, &tx));
        ctx.coins_tip = &cache;
        ASSERT(vp_requirements_unavailable(&ctx, NULL));
        struct json_value out;
        json_init(&out);
        /* A transaction with no shielded spends has no anchor to check. */
        bool ok = vault_intent_private_requirements_current(&ctx, &tx, &out);
        json_free(&out);
        ASSERT(ok);
        PASS();
    }
_test_next:
    transaction_free(&tx);
    return failures;
}

int vault_intent_private_cases(void)
{
    int failures = vp_requirements_cases();
    if (failures) return failures;
    failures = vp_decode_cases();
    if (failures) return failures;
    return vp_plan_cases();
}
