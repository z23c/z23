/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCL Names (ZNAM) HTML site controller — names as the identity layer for
 * the sites this node hosts over onion + HTTPS.
 *
 * Wired into BOTH transport dispatch chains (lib/net/src/onion_service.c and
 * lib/net/src/https_server.c) via a `/n/` and `/names` path prefix, the same
 * way the store is wired. It resolves a registered name to its hosted site
 * and serves the browse / profile / register surfaces:
 *
 *   GET  /n/<name>          resolve → gateway page (opt-in) / 302 / profile
 *   GET  /names             browse index
 *   GET  /names/register    on-chain register form (CSRF + PoW puzzle)
 *   POST /names/register    CSRF + PoW gate → compose REGISTER tx → result
 *   GET  /names/<name>      profile (show)
 *
 * Reads are pure projection reads through the shared boot-wired node.db
 * handle (site_ndb()); the request path never triggers a chain
 * scan. The register POST mutates nothing locally — it composes and
 * broadcasts an OP_RETURN tx through the SAME wallet path the JSON-RPC
 * name_register uses (name_controller_compose_register), gated by CSRF (stops
 * a tricked browser) plus a name-bound hashcash puzzle (stops a direct
 * flood from spending wallet fees for free), mirroring store_controller_pow.c.
 */

#include "controllers/name_site_controller.h"
#include "controllers/web_form.h"
#include "controllers/name_controller.h"
#include "controllers/name_resolver.h"
#include "controllers/name_gateway_controller.h"
#include "models/znam.h"
#include "models/database.h"
#include "views/name_view.h"
#include "views/name_gateway_view.h"
#include "json/json.h"

#include "wallet/wallet.h"
#include "chain/chainparams.h"
#include "validation/txmempool.h"
#include "services/zslp_command_service.h"
#include "encoding/utilstrencodings.h"

#include "crypto/hmac_sha256.h"
#include "crypto/sha3.h"
#include "net/fast_sync.h"
#include "core/random.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "base/safe_alloc.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Snapshot the boot-wired node.db handle (read path). */
static struct node_db *site_ndb(void)
{
    struct name_controller_ctx c;
    name_controller_get_ctx(&c);
    return c.ndb;
}

/* ── shared REGISTER tx-compose (declared in name_controller.h) ──────
 * THE single REGISTER compose path, shared by the JSON-RPC name_register
 * handler (name_controller.c) and the HTML register POST below, so there is
 * exactly one tx-compose routine. Lives here (not name_controller.c) purely
 * for the file-size ceiling. On success returns true, writes the broadcast
 * txid (hex, >=65-byte buffer) and, when fee_out is non-NULL, the fee paid.
 * On failure returns false with a human-readable reason in err. Refuses with
 * "wallet not loaded" when no wallet is wired. Callers validate the name and
 * check availability first — this only builds and broadcasts. */
bool name_controller_compose_register(const char *name, uint8_t target_type,
                                      const char *value, char *txid_hex,
                                      size_t txid_cap, int64_t *fee_out,
                                      char *err, size_t err_cap)
{
    if (err && err_cap) err[0] = '\0';
    if (fee_out) *fee_out = 0;
    if (!name || !value || !txid_hex || txid_cap < 65) {
        if (err) snprintf(err, err_cap, "invalid arguments");
        return false;
    }

    struct name_controller_ctx c;
    name_controller_get_ctx(&c);
    if (!c.wallet || !c.mempool) {
        if (err) snprintf(err, err_cap, "wallet not loaded");
        return false;
    }

    uint8_t script[512];
    size_t script_len = znam_build_register(script, sizeof(script),
                                            name, target_type, value);
    if (script_len == 0) {
        if (err) snprintf(err, err_cap, "failed to build OP_RETURN script");
        return false;
    }

    struct wallet_tx wtx;
    memset(&wtx, 0, sizeof(wtx));
    int64_t fee_paid = 0;
    const char *tx_error = NULL;
    if (!zslp_command_build_genesis_base_tx(c.wallet, &wtx,
                                            &fee_paid, &tx_error).ok) {
        if (err) snprintf(err, err_cap, "%s",
                          tx_error ? tx_error : "failed to build transaction");
        return false;
    }

    struct wallet_tx_admission admission = {
        .mempool = c.mempool,
        .coins_tip = c.coins_tip,
        .main_state = c.main_state,
        .params = chain_params_get(),
    };
    struct zcl_result commit = zslp_command_commit_with_op_return(
        c.wallet, &wtx, &admission, script, script_len);
    if (!commit.ok) {
        if (err) snprintf(err, err_cap, "%s", commit.message);
        transaction_free(&wtx.tx);
        return false;
    }

    uint256_get_hex(&wtx.tx.hash, txid_hex);
    if (fee_out) *fee_out = fee_paid;
    return true;
}

/* ── name_records RPC (declared in name_controller.h) ────────────────
 * List a name's resolver records — the `name has_many name_records`
 * relationship, read through the model helpers (db_znam_text_list /
 * db_znam_addr_list), never controller SQL. Read-only, no wallet. */
#define NAME_RECORDS_RPC_LIMIT 64
bool rpc_name_records(const struct json_value *params, bool help,
                      struct json_value *result)
{
    if (help || !params || json_size(params) < 1) {
        json_set_str(result,
            "name_records \"name\"\n"
            "\nList a registered ZCL Name's resolver records (text +\n"
            "multi-coin address records — the name's has_many relationship).\n"
            "\nArguments:\n"
            "1. name (string, required) The name whose records to list\n"
            "\nResult: { name, found, text_records:[{key,value}],"
            " address_records:[{type,value}] }\n");
        return true;
    }

    const struct json_value *arg0 = json_at(params, 0);
    const char *name = arg0 ? json_get_str(arg0) : NULL;
    if (!name) {
        json_set_str(result, "name required");
        return false;
    }
    if (!znam_validate_name(name)) {
        json_set_str(result, "Invalid name (1-63 chars, lowercase alphanumeric + hyphens)");
        return false;
    }

    struct node_db *ndb = site_ndb();
    struct znam_entry entry;
    bool found = ndb && db_znam_find(ndb, name, &entry);

    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.names.records.v1");
    json_push_kv_str(result, "name", name);
    json_push_kv_bool(result, "found", found);

    struct json_value texts = {0};
    json_set_array(&texts);
    struct json_value addrs = {0};
    json_set_array(&addrs);

    if (found) {
        struct znam_text_record trecs[NAME_RECORDS_RPC_LIMIT];
        int tn = db_znam_text_list(ndb, name, trecs, NAME_RECORDS_RPC_LIMIT);
        for (int i = 0; i < tn; i++) {
            struct json_value t = {0};
            json_set_object(&t);
            json_push_kv_str(&t, "key", trecs[i].key);
            json_push_kv_str(&t, "value", trecs[i].value);
            json_push_back(&texts, &t);
            json_free(&t);
        }
        struct znam_addr_record arecs[NAME_RECORDS_RPC_LIMIT];
        int an = db_znam_addr_list(ndb, name, arecs, NAME_RECORDS_RPC_LIMIT);
        for (int i = 0; i < an; i++) {
            struct json_value a = {0};
            json_set_object(&a);
            json_push_kv_int(&a, "coin_type", arecs[i].coin_type);
            json_push_kv_str(&a, "type", znam_type_name(arecs[i].coin_type));
            json_push_kv_str(&a, "value", arecs[i].address);
            json_push_back(&addrs, &a);
            json_free(&a);
        }
    }

    json_push_kv(result, "text_records", &texts);
    json_push_kv(result, "address_records", &addrs);
    json_free(&texts);
    json_free(&addrs);
    return true;
}

#define NAME_LIST_LIMIT     100
#define NAME_RECORDS_LIMIT  64

/* ── small HTTP helpers ─────────────────────────────────────────── */

static bool path_eq(const char *path, const char *want)
{
    return path && strcmp(path, want) == 0;
}

/* 302 redirect. `location` is owner-controlled (a name's onion/url record),
 * so any CR/LF (and everything after) is dropped to prevent header
 * injection. */
static size_t name_redirect(uint8_t *resp, size_t max, const char *location)
{
    char safe[600];
    size_t j = 0;
    for (size_t i = 0; location[i] && j < sizeof(safe) - 1; i++) {
        char c = location[i];
        if (c == '\r' || c == '\n') break;
        safe[j++] = c;
    }
    safe[j] = '\0';
    return (size_t)snprintf((char *)resp, max,
        "HTTP/1.1 302 Found\r\n"
        "Location: %s\r\n"
        "Connection: close\r\n\r\n", safe);
}

/* ── CSRF (mirrors store_controller.c) ──────────────────────────── */

static unsigned char s_csrf_key[32];
static bool s_csrf_ready = false;
static pthread_mutex_t s_csrf_lock = PTHREAD_MUTEX_INITIALIZER;

static void name_csrf_init(void)
{
    pthread_mutex_lock(&s_csrf_lock);
    if (!s_csrf_ready) {
        GetRandBytes(s_csrf_key, sizeof(s_csrf_key));
        s_csrf_ready = true;
    }
    pthread_mutex_unlock(&s_csrf_lock);
}

/* The register form is generic (name is a free-text field), so the CSRF
 * token binds to the register action, not a specific name — the name-bound
 * axis lives in the PoW gate below. */
#define NAME_CSRF_CONTEXT "znam:register"

static void name_csrf_token(const char *context, char out[33])
{
    name_csrf_init();
    struct hmac_sha256_ctx ctx;
    unsigned char mac[HMAC_SHA256_OUTPUT_SIZE];
    hmac_sha256_init(&ctx, s_csrf_key, sizeof(s_csrf_key));
    hmac_sha256_write(&ctx, (const unsigned char *)context, strlen(context));
    hmac_sha256_finalize(&ctx, mac);
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 16; i++) {
        out[i * 2]     = hex[(mac[i] >> 4) & 0x0f];
        out[i * 2 + 1] = hex[mac[i] & 0x0f];
    }
    out[32] = '\0';
}

/* Live register-action CSRF token (public — form issuance + tests). */
void name_site_csrf_token(char out[33])
{
    name_csrf_token(NAME_CSRF_CONTEXT, out);
}

static bool name_csrf_verify(const char *context, const char *provided)
{
    if (!context || !provided) return false;
    if (strlen(provided) != 32) return false;
    char expected[33];
    name_csrf_token(context, expected);
    unsigned char diff = 0;
    for (size_t i = 0; i < 32; i++)
        diff |= (unsigned char)(expected[i] ^ provided[i]);
    return diff == 0;
}

/* ── name-bound proof-of-work gate (mirrors store_controller_pow.c) ── */

/* peer_id = SHA3-256("znam:register:pow:" || name) — binds a solved puzzle
 * to the exact name being registered, so it cannot be replayed for another. */
static void name_pow_bind(const char *name, uint8_t out[32])
{
    char ctx[128];
    int n = snprintf(ctx, sizeof(ctx), "znam:register:pow:%s", name ? name : "");
    if (n < 0) n = 0;
    sha3_256((const unsigned char *)ctx, (size_t)n < sizeof(ctx) ? (size_t)n
                                                                  : sizeof(ctx) - 1,
             out);
}

#define NAME_POW_USED_RING 4096
#define NAME_POW_USED_TTL_SECS 400
static uint8_t s_pow_used_key[NAME_POW_USED_RING][32];
static int64_t s_pow_used_at[NAME_POW_USED_RING];
static size_t  s_pow_used_next = 0;
static pthread_mutex_t s_pow_used_lock = PTHREAD_MUTEX_INITIALIZER;

static bool name_pow_claim_once(const struct fast_sync_pow *pow)
{
    uint8_t key[32];
    sha3_256((const unsigned char *)pow, sizeof(*pow), key);
    int64_t now = (int64_t)platform_time_wall_time_t();
    bool replay = false;

    pthread_mutex_lock(&s_pow_used_lock);
    for (size_t i = 0; i < NAME_POW_USED_RING; i++) {
        if (now - s_pow_used_at[i] < NAME_POW_USED_TTL_SECS &&
            memcmp(s_pow_used_key[i], key, 32) == 0) {
            replay = true;
            break;
        }
    }
    if (!replay) {
        memcpy(s_pow_used_key[s_pow_used_next], key, 32);
        s_pow_used_at[s_pow_used_next] = now;
        s_pow_used_next = (s_pow_used_next + 1) % NAME_POW_USED_RING;
    }
    pthread_mutex_unlock(&s_pow_used_lock);
    return !replay;
}

/* Verify + single-use-claim a name-bound puzzle solution. Exposed (non-static)
 * so tests can exercise the gate directly. */
bool name_pow_verify_and_claim(const char *name, const char *pow_ts_str,
                               const char *pow_nonce_str)
{
    struct fast_sync_pow pow;
    char *end = NULL;
    long long ts;
    unsigned long long nonce;

    if (!name || !name[0]) return false;
    if (!pow_ts_str || !pow_ts_str[0] || !pow_nonce_str || !pow_nonce_str[0])
        return false;

    ts = strtoll(pow_ts_str, &end, 10);
    if (!end || *end != '\0') return false;
    end = NULL;
    nonce = strtoull(pow_nonce_str, &end, 10);
    if (!end || *end != '\0') return false;

    memset(&pow, 0, sizeof(pow));
    name_pow_bind(name, pow.peer_id);
    pow.timestamp = (int64_t)ts;
    pow.nonce = (uint64_t)nonce;

    if (!fast_sync_verify_pow(&pow)) return false;
    return name_pow_claim_once(&pow);
}

/* ── profile render (shared by /n/<name> fallback and /names/<name>) ── */

static size_t name_render_profile(struct node_db *ndb,
                                  const struct znam_entry *e,
                                  uint8_t *resp, size_t max)
{
    struct znam_text_record texts[NAME_RECORDS_LIMIT];
    struct znam_addr_record addrs[NAME_RECORDS_LIMIT];
    struct name_history hist;
    int nt = db_znam_text_list(ndb, e->name, texts, NAME_RECORDS_LIMIT);
    int na = db_znam_addr_list(ndb, e->name, addrs, NAME_RECORDS_LIMIT);
    name_history_load(ndb, e, &hist);
    return name_view_profile(e, texts, nt, addrs, na, &hist, resp, max);
}

/* ── the onion gateway leg ──────────────────────────────────────── */

/* An .onion target, with the gateway turned on: fetch it and serve it.
 * With the gateway OFF (the default) this is never reached — the caller
 * redirects exactly as it always has. Every failure still produces a real
 * page carrying the direct link, so turning the gateway on can degrade a
 * visit but can never break one. */
static size_t name_serve_gateway(const char *name, const char *target,
                                 uint8_t *resp, size_t max)
{
    struct name_gateway_result *g;
    enum name_gateway_status st;
    size_t out;

    /* ~24 KiB of relayed body plus bookkeeping — heap, never the serving
     * thread's stack. */
    g = zcl_malloc(sizeof(*g), "name_gateway_result");
    if (!g) {
        LOG_WARN("name.gateway", "result alloc failed for '%s'", name);
        return name_gateway_view_unavailable(name, target,
            "GATEWAY_NO_MEMORY",
            "This node could not allocate a relay buffer for that page.",
            "503 Service Unavailable", resp, max);
    }

    st = name_gateway_fetch(target, g);
    if (st != NAME_GATEWAY_OK) {
        out = name_gateway_view_unavailable(name, target,
                  name_gateway_status_code(st),
                  name_gateway_status_message(st),
                  st == NAME_GATEWAY_BAD_HOST ? "400 Bad Request"
                                              : "502 Bad Gateway",
                  resp, max);
        free(g);
        return out;
    }

    out = name_gateway_view_page(name, g->host, g->body, g->body_len,
                                 g->http_status, g->truncated,
                                 g->upstream_bytes, resp, max);
    free(g);
    /* A relayed page that would not fit the caller's response buffer is
     * still a resolved name: fall back to the notice page rather than
     * writing a truncated, length-lying response. */
    if (out == 0)
        return name_gateway_view_unavailable(name, target, "GATEWAY_TOO_LARGE",
            "The relayed page did not fit this node's response buffer.",
            "502 Bad Gateway", resp, max);
    return out;
}

/* ── resolution (precedence: onion > url > content/profile) ─────── */

/* Resolve `name` (optionally constrained to `want_type_str`) and write the
 * response. An onion target either goes through the gateway (operator
 * opt-in) or 302s as before; a "url" text record 302s; anything else
 * renders the profile page as the name's default hosted site. Every
 * non-resolution comes back as its own named verdict, never a shared
 * "not found". */
static size_t name_resolve_site(struct node_db *ndb, const char *name,
                                const char *want_type_str,
                                uint8_t *resp, size_t max)
{
    struct name_resolution res;
    enum name_resolve_status st;
    enum name_route_kind route;
    uint8_t want = 0;
    char target[300];
    char loc[320];

    if (want_type_str && want_type_str[0]) {
        want = znam_type_from_name(want_type_str);
        if (want == 0)
            return name_view_resolve_error(name, NAME_RESOLVE_TYPE_UNKNOWN,
                                           want_type_str, NULL, resp, max);
    }

    st = name_resolve(ndb, name, want, &res);
    if (st != NAME_RESOLVE_OK)
        return name_view_resolve_error(name, st, want_type_str,
                                       res.have_entry ? &res.entry : NULL,
                                       resp, max);

    /* An explicit ?type= is a request for THAT record, not for the site:
     * hand back the profile so the visitor sees the value in context. */
    if (want != 0)
        return name_render_profile(ndb, &res.entry, resp, max);

    route = name_resolve_route(ndb, &res.entry, target, sizeof(target));
    if (route == NAME_ROUTE_ONION) {
        if (name_gateway_enabled())
            return name_serve_gateway(name, target, resp, max);
        if (strstr(target, "://")) snprintf(loc, sizeof(loc), "%s", target);
        else snprintf(loc, sizeof(loc), "http://%s/", target);
        return name_redirect(resp, max, loc);
    }
    if (route == NAME_ROUTE_URL) {
        if (strstr(target, "://")) snprintf(loc, sizeof(loc), "%s", target);
        else snprintf(loc, sizeof(loc), "http://%s", target);
        return name_redirect(resp, max, loc);
    }
    return name_render_profile(ndb, &res.entry, resp, max);
}

/* ── register POST ──────────────────────────────────────────────── */

static size_t name_handle_register_post(const uint8_t *body, size_t body_len,
                                        uint8_t *resp, size_t max)
{
    /* The register POST composes AND broadcasts a REGISTER tx from the
     * NODE's wallet — the operator pays the fee for an anonymous onion
     * visitor. CSRF + name-bound PoW bound the flood rate but each
     * accepted request still spends real ZCL, so public registration is
     * an explicit operator opt-in. RPC/CLI registration (name_register)
     * is unaffected — this gates only the anonymous HTML surface. */
    const char *pub = getenv("ZCL_NAMES_PUBLIC_REGISTER");
    if (!pub || strcmp(pub, "1") != 0)
        return name_view_register_result("", "", "",
            "Public registration is disabled on this node (the operator "
            "wallet funds each registration). Node operator: set "
            "ZCL_NAMES_PUBLIC_REGISTER=1 to enable, or use the "
            "name_register RPC / CLI.",
            resp, max);

    char name[128] = "", type_s[32] = "", value[256] = "";
    char csrf[64] = "", pow_ts[32] = "", pow_nonce[32] = "";
    if (body && body_len > 0) {
        web_form_field((const char *)body, body_len, "name", name, sizeof(name));
        web_form_field((const char *)body, body_len, "type", type_s, sizeof(type_s));
        web_form_field((const char *)body, body_len, "value", value, sizeof(value));
        web_form_field((const char *)body, body_len, "csrf_token", csrf, sizeof(csrf));
        web_form_field((const char *)body, body_len, "pow_ts", pow_ts, sizeof(pow_ts));
        web_form_field((const char *)body, body_len, "pow_nonce", pow_nonce, sizeof(pow_nonce));
    }

    /* CSRF first (cheapest, stops tricked-browser submissions). */
    if (!name_csrf_verify(NAME_CSRF_CONTEXT, csrf))
        return name_view_register_result(name, value, "",
            "CSRF token missing or invalid — reload the register page.",
            resp, max);

    if (!znam_validate_name(name))
        return name_view_register_result(name, value, "",
            "Invalid name (1-63 chars, lowercase letters, digits, hyphens).",
            resp, max);

    uint8_t type = znam_type_from_name(type_s);
    if (type == 0)
        return name_view_register_result(name, value, "",
            "Invalid target type.", resp, max);

    if (!value[0])
        return name_view_register_result(name, value, "",
            "Target value is required.", resp, max);

    /* Name-bound PoW — refused BEFORE spending any wallet fee. */
    if (!name_pow_verify_and_claim(name, pow_ts, pow_nonce))
        return name_view_register_result(name, value, "",
            "Proof-of-work missing, stale, or already used — reload and retry.",
            resp, max);

    struct node_db *ndb = site_ndb();
    struct znam_entry existing;
    if (ndb && db_znam_find(ndb, name, &existing))
        return name_view_register_result(name, value, "",
            "Name already registered (first-come-first-served).", resp, max);

    char txid[65] = "";
    char err[256] = "";
    if (!name_controller_compose_register(name, type, value, txid, sizeof(txid),
                                          NULL, err, sizeof(err)))
        return name_view_register_result(name, value, "",
            err[0] ? err : "Failed to compose registration transaction.",
            resp, max);

    return name_view_register_result(name, value, txid, "", resp, max);
}

/* ── router ─────────────────────────────────────────────────────── */

/* Handle any /n/ or /names request. Returns bytes written (a complete raw
 * HTTP/1.1 response), or 0 if `path`/`resp` are missing. */
size_t name_site_handle_request(const char *method, const char *path,
                                const uint8_t *body, size_t body_len,
                                uint8_t *response, size_t response_max)
{
    if (!path || !response) return 0;
    struct node_db *ndb = site_ndb();

    /* /n/<name>[?type=<t>] — resolve to the hosted site. The optional
     * ?type= is what makes "registered, but not for that" reachable over
     * HTTP as its own verdict rather than folding into "not found". */
    if (strncmp(path, "/n/", 3) == 0) {
        char name[128], type_q[32] = "";
        const char *q = strchr(path, '?');
        snprintf(name, sizeof(name), "%s", path + 3);
        char *cut = strpbrk(name, "/?");
        if (cut) *cut = '\0';
        if (q)
            web_form_field(q + 1, strlen(q + 1), "type",
                             type_q, sizeof(type_q));
        return name_resolve_site(ndb, name, type_q, response, response_max);
    }

    /* /names/register (GET form, POST create). */
    if (path_eq(path, "/names/register") || path_eq(path, "/names/register/")) {
        if (method && strcmp(method, "POST") == 0)
            return name_handle_register_post(body, body_len,
                                             response, response_max);
        char csrf[33];
        name_csrf_token(NAME_CSRF_CONTEXT, csrf);
        int64_t ts = (int64_t)platform_time_wall_time_t();
        return name_view_register_form(csrf, ts, response, response_max);
    }

    /* /names, /names/ — browse index. */
    if (path_eq(path, "/names") || path_eq(path, "/names/")) {
        struct znam_entry entries[NAME_LIST_LIMIT];
        int count = ndb ? db_znam_list(ndb, entries, NAME_LIST_LIMIT) : 0;
        return name_view_index(entries, count, response, response_max);
    }

    /* /names/<name> — profile (show), same taxonomy on failure. */
    if (strncmp(path, "/names/", 7) == 0) {
        char name[128];
        struct name_resolution res;
        enum name_resolve_status st;
        snprintf(name, sizeof(name), "%s", path + 7);
        char *cut = strpbrk(name, "/?");
        if (cut) *cut = '\0';
        st = name_resolve(ndb, name, 0, &res);
        if (st != NAME_RESOLVE_OK)
            return name_view_resolve_error(name, st, NULL,
                                           res.have_entry ? &res.entry : NULL,
                                           response, response_max);
        return name_render_profile(ndb, &res.entry, response, response_max);
    }

    /* Bare /names index fallback for any other /names… path. */
    {
        struct znam_entry entries[NAME_LIST_LIMIT];
        int count = ndb ? db_znam_list(ndb, entries, NAME_LIST_LIMIT) : 0;
        return name_view_index(entries, count, response, response_max);
    }
}
