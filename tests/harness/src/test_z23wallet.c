/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: z23wallet group. Amounts, option parsing, node location (Z23 and
 * legacy zclassicd: first-wins conf, cookie paths, reasons), the HTTP/RPC
 * client against the fixture mock node (401 rules, the read-only allowlist,
 * the getwalletsummary latch, balances, the total deadline), the connection
 * model and sync verdict, the beta13 Home shell geometry and the screen
 * goldens rendered headless from fixture replies. Isolated temp directories
 * only; no real node, key, address or balance is touched. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "../../../apps/z23wallet/src/zw.h"
#include "z23wallet_mock_node.h"

/* From ui_layout.c (not in ui.h). */
int32_t gui_ui_fit_px(const struct gui_ui *ui, const struct gui_node *n, const char *s, size_t len,
                      int32_t avail);
int32_t gui_ui_run_width(enum gui_font f, int32_t px, const char *s, size_t len);

static int g_fail;
#define CHECK(name, cond) \
    do { \
        bool ok_ = (cond); \
        printf("  %s... %s\n", (name), ok_ ? "OK" : "FAIL"); \
        if (!ok_) g_fail++; \
    } while (0)

#define TMP "build/test-tmp/z23wallet"
#define FIX "tests/fixtures/z23wallet/rpc/"
#define COOKIE "__cookie__:fixturecookie0123456789"
#define NOW_S INT64_C(1700000016) /* fixture tiptime + 16 s */
#define ZA "zs1fixtureaddressa000000000000000000000000000000000000000000000000000000000000"
#define TA "t1fixtureaddressa000000000000000000"

static void mkdirs(const char *path)
{
    char p[512];
    snprintf(p, sizeof(p), "%s", path);
    for (char *c = p + 1; *c; c++)
        if (*c == '/') {
            *c = 0;
            mkdir(p
#if !defined(_WIN32)
                  , 0700
#endif
            );
            *c = '/';
        }
    mkdir(p
#if !defined(_WIN32)
          , 0700
#endif
    );
}

static void set_env(const char *k, const char *v)
{
#if defined(_WIN32)
    _putenv_s(k, v);
#else
    setenv(k, v, 1);
#endif
}

static void hermetic_env(void)
{
    mkdirs(TMP "/profile");
    set_env("HOME", TMP "/profile");
    set_env("USERPROFILE", TMP "/profile");
    set_env("LOCALAPPDATA", TMP "/profile/local");
    set_env("APPDATA", TMP "/profile/roaming");
}

static void write_file(const char *dir, const char *name, const char *text)
{
    char p[600];
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    FILE *f = fopen(p, "wb");
    if (f) { fputs(text, f); fclose(f); }
}

static bool starts(const char *s, const char *prefix) { return !strncmp(s, prefix, strlen(prefix)); }

static void remove_file(const char *dir, const char *name)
{
    char p[600];
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    remove(p);
}

/* ---- amounts, ages, versions, args ---- */

static void test_amount(void)
{
    int64_t z = -1;
    CHECK("0.00000001 is 1 zat", zw_amount_parse("0.00000001", 10, &z) && z == 1);
    CHECK("21000000 is MAX_MONEY", zw_amount_parse("21000000", 8, &z) && z == INT64_C(2100000000000000));
    CHECK("9 decimals rejected", !zw_amount_parse("0.123456789", 11, &z));
    CHECK("negative rejected", !zw_amount_parse("-1", 2, &z));
    CHECK("above MAX_MONEY rejected", !zw_amount_parse("21000000.00000001", 17, &z));
    CHECK("garbage rejected", !zw_amount_parse("1e5", 3, &z) && !zw_amount_parse(".", 1, &z));
    struct json_value v;
    json_init(&v);
    json_set_real(&v, 0.1);
    CHECK("real 0.1 is 10,000,000 zat", zw_amount_from_json(&v, &z) && z == 10000000);
    json_set_real(&v, 21000001.0);
    CHECK("real above bound rejected", !zw_amount_from_json(&v, &z));
    json_set_str(&v, "12.50000000");
    CHECK("FormatMoney string parses exactly", zw_amount_from_json(&v, &z) && z == 1250000000);
    json_free(&v);
    char b[64];
    zw_amount_format(125000000, b, sizeof(b), true);
    CHECK("[8] 125000000 zat is 1.25 ZCL", !strcmp(b, "1.25 ZCL"));
    zw_amount_format(INT64_C(123456789000), b, sizeof(b), true);
    CHECK("[8] 123456789000 zat is 1234.56789 ZCL (no grouping)", !strcmp(b, "1234.56789 ZCL"));
    zw_amount_format(0, b, sizeof(b), true);
    CHECK("[8] zero is 0 ZCL", !strcmp(b, "0 ZCL"));
    zw_amount_format_net(50000000, b, sizeof(b), true);
    CHECK("[8] testnet unit is ZCT", !strcmp(b, "0.5 ZCT"));
    zw_amount_format(1250000000, b, sizeof(b), false);
    CHECK("12.5 without unit", !strcmp(b, "12.5"));
    zw_fmt_int(3329857, b, sizeof(b));
    CHECK("heights keep comma grouping", !strcmp(b, "3,329,857"));
}

static void test_age_and_version(void)
{
    char b[48];
    zw_fmt_age(16, b, sizeof(b));
    bool s = !strcmp(b, "16 s");
    zw_fmt_age(89 * 60 + 40, b, sizeof(b));
    bool mi = !strcmp(b, "90 min") || !strcmp(b, "89 min");
    zw_fmt_age(5 * 3600 + 1700, b, sizeof(b));
    bool h = !strcmp(b, "5 h");
    zw_fmt_age(10 * 86400, b, sizeof(b));
    bool d = !strcmp(b, "10 days");
    CHECK("ages follow SyncState::formatAge", s && mi && h && d);
    zw_version_decode(2010212, b, sizeof(b));
    bool beta = !strcmp(b, "v2.1.2-beta13");
    zw_version_decode(2010350, b, sizeof(b));
    bool rel = !strcmp(b, "v2.1.3");
    zw_version_decode(2010325, b, sizeof(b));
    bool rc = !strcmp(b, "v2.1.3-rc1");
    zw_version_decode(2010351, b, sizeof(b));
    bool post = !strcmp(b, "v2.1.3-1");
    CHECK("zclassicd version decodes as beta13 does", beta && rel && rc && post);
}

static void test_args(void)
{
    struct zw_options o;
    char err[160];
    char *good[] = { "z23-wallet", "--datadir=/x", "--rpcport=1234", "--node=zclassicd",
                     "--backend=headless", "--size=900x600", "--exit-after-shot", "--shot=a.png" };
    CHECK("good arguments parse", zw_args_parse(8, good, &o, err, sizeof(err)) && o.rpcport == 1234 &&
          o.profile == ZW_PROFILE_ZCLASSICD && o.width == 900 && o.exit_after_shot);
    char *bad[] = { "z23-wallet", "--bogus=1" };
    CHECK("unknown option names itself", !zw_args_parse(2, bad, &o, err, sizeof(err)) && strstr(err, "--bogus"));
    char *bad2[] = { "z23-wallet", "--size=10x10" };
    CHECK("tiny size refused", !zw_args_parse(2, bad2, &o, err, sizeof(err)));
}

/* ---- locate ---- */

static bool has_reason(const struct zw_locate_report *r, const char *path_part, const char *reason)
{
    for (size_t i = 0; i < r->ntried; i++)
        if (strstr(r->tried[i].path, path_part) && !strcmp(r->tried[i].reason, reason)) return true;
    return false;
}

static void test_locate_z23(void)
{
    hermetic_env();
    mkdirs(TMP "/loc1");
    zw_mock_write_cookie(TMP "/loc1", COOKIE);
    write_file(TMP "/loc1", ".rpcport", "19999");
    struct zw_options o = { .datadir = TMP "/loc1" };
    struct zw_endpoint ep = {0};
    struct zw_locate_report rep = {0};
    CHECK("datadir with cookie and .rpcport is found", zw_locate(&o, &ep, &rep) && ep.port == 19999 &&
          ep.profile == ZW_PROFILE_Z23 && ep.cred_src == ZW_CRED_COOKIE && !strncmp(ep.auth, "Basic ", 6));
    o.rpcport = 7;
    CHECK("--rpcport wins over .rpcport", zw_locate(&o, &ep, &rep) && ep.port == 7);
    mkdirs(TMP "/emptydd");
    struct zw_options none = { .datadir = TMP "/emptydd", .profile = ZW_PROFILE_Z23 };
    CHECK("[22] every Z23 candidate is listed with a reason",
          !zw_locate(&none, &ep, &rep) && rep.ntried >= 2 && has_reason(&rep, "/emptydd", "no .cookie") &&
          has_reason(&rep, ".zclassic-c23", "not found"));
    zw_endpoint_wipe(&ep);
}

static void test_locate_conf(void)
{
    struct zw_endpoint ep = {0};
    struct zw_locate_report rep = {0};
    char conf[600], pass[201];
    memset(pass, 'p', 200);
    pass[200] = 0;
    mkdirs(TMP "/legacy");
    snprintf(conf, sizeof(conf), "# comment\nrpcuser=a\nrpcuser=b\nRPCUSER=x\nrpcpassword=%s\nrpcpassword=late\n", pass);
    write_file(TMP "/legacy", "zclassic.conf", conf);
    zw_mock_write_cookie(TMP "/legacy", "__cookie__:stalecookie");
    struct zw_options lo = { .datadir = TMP "/legacy", .profile = ZW_PROFILE_ZCLASSICD };
    char up[300], b64[400], want[420];
    snprintf(up, sizeof(up), "a:%s", pass);
    zw_base64((const unsigned char *)up, strlen(up), b64, sizeof(b64));
    snprintf(want, sizeof(want), "Basic %s", b64);
    CHECK("[23] conf: first value wins, keys are case-sensitive, a 200-byte password works",
          zw_locate(&lo, &ep, &rep) && !strcmp(ep.auth, want) && ep.cred_src == ZW_CRED_CONF && ep.port == 8023);
    CHECK("[24] conf credentials win over a stale .cookie", ep.cred_src == ZW_CRED_CONF &&
          strstr(ep.conf_path, "zclassic.conf"));
    write_file(TMP "/legacy", "zclassic.conf", "testnet=1\n");
    mkdirs(TMP "/legacy/testnet3");
    zw_mock_write_cookie(TMP "/legacy/testnet3", COOKIE);
    CHECK("[26] testnet=1 without rpcport: port 18023, cookie in testnet3/",
          zw_locate(&lo, &ep, &rep) && ep.port == 18023 && ep.testnet && ep.cred_src == ZW_CRED_COOKIE &&
          strstr(ep.cookie_dir, "testnet3"));
    write_file(TMP "/legacy", "zclassic.conf", "regtest=1\n");
    CHECK("[26] regtest=1 without a regtest/.cookie fails with a reason",
          !zw_locate(&lo, &ep, &rep) && has_reason(&rep, "/legacy", "no rpcpassword and no .cookie"));
    mkdirs(TMP "/legacy_other");
    zw_mock_write_cookie(TMP "/legacy_other", COOKIE);
    write_file(TMP "/legacy", "zclassic.conf", "datadir=" TMP "/legacy_other\n");
    remove_file(TMP "/legacy", ".cookie");
    CHECK("[26] datadir= in the conf moves the cookie lookup",
          zw_locate(&lo, &ep, &rep) && strstr(ep.cookie_dir, "legacy_other") && ep.cred_src == ZW_CRED_COOKIE);
    remove_file(TMP "/legacy", "zclassic.conf");
    CHECK("[22] a folder without conf or cookie says \"no zclassic.conf\"",
          !zw_locate(&lo, &ep, &rep) && has_reason(&rep, "/legacy", "no zclassic.conf"));
    zw_endpoint_wipe(&ep);
}

static void test_locate_reasons(void)
{
    hermetic_env();
    struct zw_endpoint ep = {0};
    struct zw_locate_report rep = {0};
    struct zw_options lo = { .profile = ZW_PROFILE_ZCLASSICD };
    CHECK("[22] the default legacy folder is listed as not found", !zw_locate(&lo, &ep, &rep) && rep.ntried == 1 &&
          !strcmp(rep.tried[0].reason, "not found"));
#if defined(_WIN32)
    set_env("APPDATA", "");
    CHECK("[22] an unset APPDATA is a tried entry, never an empty list",
          !zw_locate(&lo, &ep, &rep) && rep.ntried == 1 && !strcmp(rep.tried[0].reason, "APPDATA is not set"));
#else
    set_env("HOME", "");
    CHECK("[22] an unset HOME is a tried entry, never an empty list",
          !zw_locate(&lo, &ep, &rep) && rep.ntried == 1 && !strcmp(rep.tried[0].reason, "HOME is not set"));
#endif
    hermetic_env();
    zw_endpoint_wipe(&ep);
}

/* ---- rpc against the mock ---- */

struct node {
    struct zw_mock *mock;
    uint16_t port;
    char dir[128];
    struct zw_options opt;
    struct zw_rpc *rpc;
};

static bool node_start(struct node *n, const char *scenario, const char *tag)
{
    memset(n, 0, sizeof(*n));
    snprintf(n->dir, sizeof(n->dir), TMP "/dd_%s", tag);
    mkdirs(n->dir);
    zw_mock_write_cookie(n->dir, COOKIE);
    char sc[256];
    snprintf(sc, sizeof(sc), FIX "%s", scenario);
    n->mock = zw_mock_start(sc, n->dir, &n->port);
    if (!n->mock) return false;
    snprintf(n->opt.datadir, sizeof(n->opt.datadir), "%s", n->dir);
    n->opt.rpcport = n->port;
    n->rpc = calloc(1, sizeof(*n->rpc));
    if (n->rpc) n->rpc->opt = &n->opt;
    return n->rpc != NULL;
}

static void node_stop(struct node *n)
{
    zw_mock_stop(n->mock);
    if (n->rpc) zw_endpoint_wipe(&n->rpc->ep);
    free(n->rpc);
}

/* A legacy node: zclassic.conf in the datadir; the mock checks those creds. */
static bool legacy_start(struct node *n, const char *scenario, const char *tag, const char *conf, const char *userpass)
{
    if (!node_start(n, scenario, tag)) return false;
    write_file(n->dir, "zclassic.conf", conf);
    zw_mock_set_auth(n->mock, userpass);
    n->opt.profile = ZW_PROFILE_ZCLASSICD;
    return true;
}

static void test_rpc_basic(struct node *n)
{
    struct json_value r;
    struct zw_rpc_error e;
    json_init(&r);
    CHECK("getblockchaininfo answers", zw_rpc_call(n->rpc, "getblockchaininfo", "[]", &r, &e) == ZW_OK &&
          json_get_int(json_get(&r, "blocks")) == 1234567);
    json_free(&r);
    json_init(&r);
    zw_mock_write_cookie(n->dir, "__cookie__:rotatedcookie9876543210");
    CHECK("[25] a rotated cookie is re-read after one 401", zw_rpc_call(n->rpc, "getnetworkinfo", "[]", &r, &e) == ZW_OK);
    json_free(&r);
    json_init(&r);
    enum zw_err ee = zw_rpc_call(n->rpc, "nosuchmethod", "[]", &r, &e);
    CHECK("unknown method is an RPC error -32601", ee == ZW_ERR_RPC && e.code == -32601);
    json_free(&r);
    struct zw_result res;
    memset(&res, 0, sizeof(res));
    CHECK("walletsummary parses to integer zatoshi",
          zw_query_run(n->rpc, ZW_Q_WALLET, &res) == ZW_OK && res.wallet.spendable == 1250000000 &&
          res.wallet.send_allowed && res.wallet.current && res.profile == ZW_PROFILE_Z23);
}

/* The log was opened before the mock session, so it holds every line the session
 * wrote (cookie rotation, 401 retry), not one hand-made probe. */
static void test_log_redaction(void)
{
    zw_log("probe line with %s inside", "rotatedcookie9876543210");
    zw_log("probe line with %s inside", "fixturecookie0123456789");
    char longpass[201];
    memset(longpass, 'q', 200);
    longpass[200] = 0;
    zw_log_secret(longpass); /* a 200-byte conf password is accepted, so it must be held */
    zw_log("probe line with %s inside", longpass);
    zw_log("probe line without a secret");
    zw_log_close();
    FILE *f = fopen(TMP "/session.log", "rb");
    char log[4096] = "";
    size_t got = f ? fread(log, 1, sizeof(log) - 1, f) : 0;
    if (f) fclose(f);
    log[got] = 0;
    CHECK("the session log holds the real session lines", strstr(log, "re-reading the cookie") != NULL &&
          strstr(log, "without a secret") != NULL);
    CHECK("the session log never holds either cookie or an auth header", got > 0 &&
          !strstr(log, "rotatedcookie") && !strstr(log, "fixturecookie") && !strstr(log, "Basic ") &&
          !strstr(log, "qqqqqqqqqqqqqqqq") && strstr(log, "line withheld") != NULL);
}

static void test_rpc_legacy_latch(void)
{
    struct node n;
    struct zw_result res;
    CHECK("legacy node starts", node_start(&n, "home_legacy", "legacy"));
    memset(&res, 0, sizeof(res));
    CHECK("walletsummary -32601 falls back through getwalletsummary to z_gettotalbalance",
          zw_query_run(n.rpc, ZW_Q_WALLET, &res) == ZW_OK && res.wallet.legacy && res.wallet.spendable == 1250000000 &&
          res.wallet.publicf == 340000000 && res.profile == ZW_PROFILE_ZCLASSICD);
    unsigned before = zw_mock_request_count(n.mock);
    memset(&res, 0, sizeof(res));
    zw_query_run(n.rpc, ZW_Q_WALLET, &res);
    CHECK("[27] -32601 latches z_gettotalbalance for the session", n.rpc->missing_walletsummary &&
          n.rpc->missing_getwalletsummary && zw_mock_request_count(n.mock) == before + 1);
    node_stop(&n);
}

static void test_rpc_conf(void)
{
    struct node n;
    struct zw_result res;
    struct json_value r;
    struct zw_rpc_error e;
    CHECK("legacy conf node starts", legacy_start(&n, "legacy_conf_stale_cookie", "lconf", "rpcuser=a\nrpcpassword=pw\n", "a:pw"));
    zw_mock_write_cookie(n.dir, "__cookie__:stalecookie");
    memset(&res, 0, sizeof(res));
    CHECK("[27] getwalletsummary [0] is asked first and parsed", zw_query_run(n.rpc, ZW_Q_WALLET, &res) == ZW_OK &&
          res.wallet.spendable == 1250000000 && res.wallet.total == 1590000000 && zw_mock_saw(n.mock, "\"getwalletsummary\",\"params\":[0]"));
    json_init(&r);
    unsigned before = zw_mock_request_count(n.mock);
    enum zw_err refused = zw_rpc_call(n.rpc, "z_sendmany", "[]", &r, &e);
    CHECK("[28] zclassicd: z_sendmany is refused client-side and no bytes are sent", refused == ZW_ERR_RPC &&
          strstr(e.message, "is not allowed against zclassicd") && zw_mock_request_count(n.mock) == before &&
          !zw_mock_saw(n.mock, "z_sendmany"));
    json_free(&r);
    zw_mock_set_auth(n.mock, "a:other");
    json_init(&r);
    before = zw_mock_request_count(n.mock);
    enum zw_err auth = zw_rpc_call(n.rpc, "getblockchaininfo", "[]", &r, &e);
    CHECK("[24] a 401 with conf credentials is AUTH; the cookie is not tried", auth == ZW_ERR_AUTH &&
          zw_mock_request_count(n.mock) == before + 1);
    json_free(&r);
    memset(&res, 0, sizeof(res));
    zw_query_run(n.rpc, ZW_Q_CHAIN, &res);
    struct zw_model m;
    zw_model_init(&m, ZW_PROFILE_ZCLASSICD);
    zw_model_apply(&m, &res);
    char t[600];
    zw_connect_text(&m, t, sizeof(t));
    CHECK("[24] the AUTH text names zclassic.conf", m.conn == ZW_CONN_AUTH && strstr(t, "refused the login in") &&
          strstr(t, "zclassic.conf"));
    zw_model_free(&m);
    node_stop(&n);
}

static void test_rpc_cookie_legacy(void)
{
    struct node n;
    struct zw_result res;
    CHECK("legacy cookie node starts", legacy_start(&n, "legacy_cookie", "lcookie", "server=1\n", NULL));
    memset(&res, 0, sizeof(res));
    CHECK("[25] conf without rpcpassword uses the .cookie", zw_query_run(n.rpc, ZW_Q_CHAIN, &res) == ZW_OK &&
          n.rpc->ep.cred_src == ZW_CRED_COOKIE && res.profile == ZW_PROFILE_ZCLASSICD);
    zw_mock_write_cookie(n.dir, "__cookie__:rotated");
    memset(&res, 0, sizeof(res));
    CHECK("[25] a rotated legacy cookie is re-read after one 401", zw_query_run(n.rpc, ZW_Q_CHAIN, &res) == ZW_OK);
    node_stop(&n);
}

static void test_rpc_balances_sum(void)
{
    struct node n;
    struct zw_result res;
    CHECK("balances node starts", node_start(&n, "home_public_funds", "bal"));
    memset(&res, 0, sizeof(res));
    bool ok = zw_query_run(n.rpc, ZW_Q_BALANCES, &res) == ZW_OK && res.bal && res.bal->n == 4;
    const struct zw_bal_row *r = ok ? res.bal->rows : NULL;
    CHECK("[12] per-address sums of listunspent [0] + z_listunspent [0], ascending",
          ok && strcmp(r[0].addr, r[1].addr) < 0 && !strcmp(r[0].addr, TA) && r[0].zat == 340000000 &&
          r[0].kind == ZW_ADDR_PUBLIC);
    CHECK("[12] Sapling, Sprout and transparent are classified", ok && r[1].kind == ZW_ADDR_SPROUT &&
          r[2].kind == ZW_ADDR_SAPLING);
    zw_result_release(&res);
    node_stop(&n);
}

static void test_rpc_balances_partial(void)
{
    struct node n;
    struct zw_result res;
    CHECK("partial-fail node starts", node_start(&n, "home_partial_fail", "pfail"));
    memset(&res, 0, sizeof(res));
    enum zw_err e = zw_query_run(n.rpc, ZW_Q_BALANCES, &res);
    struct zw_model m;
    zw_model_init(&m, ZW_PROFILE_AUTO);
    m.bal = calloc(1, sizeof(*m.bal));
    if (m.bal) { m.bal->n = 1; snprintf(m.bal->rows[0].addr, sizeof(m.bal->rows[0].addr), "%s", ZA); }
    zw_model_apply(&m, &res);
    CHECK("[13] one list failing publishes nothing; the previous rows stay", e == ZW_ERR_RPC && !res.bal &&
          m.bal && m.bal->n == 1 && !strcmp(m.bal->rows[0].addr, ZA));
    zw_model_free(&m);
    node_stop(&n);
    CHECK("unconfirmed node starts", node_start(&n, "home_unconfirmed", "unconf"));
    memset(&res, 0, sizeof(res));
    bool ok = zw_query_run(n.rpc, ZW_Q_BALANCES, &res) == ZW_OK && res.bal;
    CHECK("[14] a 0-conf UTXO marks its address and the wallet", ok && res.bal->any_unconfirmed &&
          res.bal->rows[0].unconfirmed && res.bal->rows[0].kind == ZW_ADDR_PUBLIC && !res.bal->rows[1].unconfirmed);
    zw_result_release(&res);
    node_stop(&n);
}

static void test_rpc_stalled(void)
{
    struct node n;
    struct zw_result res;
    CHECK("stalled node starts", node_start(&n, "stalled_recv", "stall"));
    n.rpc->deadline_ms = 400;
    memset(&res, 0, sizeof(res));
    uint64_t t0 = gui_now_ns();
    enum zw_err e = zw_query_run(n.rpc, ZW_Q_CHAIN, &res);
    uint64_t ms = (gui_now_ns() - t0) / 1000000u;
    int phase_after = atomic_load(&n.rpc->phase);
    CHECK("[29] accept-and-never-reply ends at the total deadline as TIMEOUT", e == ZW_ERR_TIMEOUT && ms < 1500);
    char line[160];
    zw_watchdog_line(ZW_PHASE_RECV, 8023, line, sizeof(line));
    CHECK("[29] the watchdog line names the phase and endpoint",
          !strcmp(line, "worker: no reply after 6 s (phase=recv, 127.0.0.1:8023)") && phase_after == ZW_PHASE_IDLE);
    struct zw_model m;
    zw_model_init(&m, ZW_PROFILE_AUTO);
    zw_model_apply(&m, &res);
    char t[300];
    zw_connect_text(&m, t, sizeof(t));
    CHECK("[29] the UI shows the refused text naming host:port", m.conn == ZW_CONN_REFUSED &&
          strstr(t, "isn't answering") && strstr(t, "127.0.0.1:"));
    n.rpc->deadline_ms = 5000;
    memset(&res, 0, sizeof(res));
    CHECK("[29] the next poll succeeds once the node answers", zw_query_run(n.rpc, ZW_Q_CHAIN, &res) == ZW_OK);
    zw_model_free(&m);
    node_stop(&n);
}

static void test_rpc_auto_prefers_z23(void)
{
    struct node z, l;
    hermetic_env();
    CHECK("both nodes start", node_start(&z, "home_synced", "auto_z23") &&
          legacy_start(&l, "legacy_conf", "auto_legacy", "rpcuser=u\nrpcpassword=p\n", "u:p"));
    struct zw_options o = { .profile = ZW_PROFILE_AUTO };
    snprintf(o.datadir, sizeof(o.datadir), "%s", z.dir);
    char port[16];
    snprintf(port, sizeof(port), "%u", (unsigned)z.port);
    write_file(z.dir, ".rpcport", port);
    struct zw_rpc *r = calloc(1, sizeof(*r));
    struct zw_result res;
    memset(&res, 0, sizeof(res));
    if (r) r->opt = &o;
    CHECK("[30] auto picks Z23 when both run", r && zw_query_run(r, ZW_Q_CHAIN, &res) == ZW_OK &&
          res.profile == ZW_PROFILE_Z23 && res.port == z.port);
    struct zw_model m;
    zw_model_init(&m, ZW_PROFILE_AUTO);
    zw_model_apply(&m, &res);
    char line[200];
    zw_node_line(&m, line, sizeof(line));
    CHECK("[30] the node line names the kind and port", starts(line, "Node: Z23 at 127.0.0.1:"));
    if (r) zw_endpoint_wipe(&r->ep);
    free(r);
    zw_model_free(&m);
    node_stop(&z);
    node_stop(&l);
}

static void test_rpc(void)
{
    hermetic_env();
    remove(TMP "/session.log");
    zw_log_open(TMP "/session.log");
    struct node n;
    CHECK("mock node starts", node_start(&n, "home_synced", "rpc"));
    test_rpc_basic(&n);
    test_log_redaction();
    node_stop(&n);
    test_rpc_legacy_latch();
    test_rpc_conf();
    test_rpc_cookie_legacy();
    test_rpc_balances_sum();
    test_rpc_balances_partial();
    test_rpc_stalled();
    test_rpc_auto_prefers_z23();
}

/* A peer that accepts and closes without a byte, and one that sends half a header,
 * must be an error, never a crash: parse_reply used to strstr a NULL buffer. */
static void test_hostile_peers(void)
{
    static const struct { const char *scenario, *what; } cases[] = {
        { "peer_closes", "a peer that closes without a byte" },
        { "peer_truncated", "a peer that sends half a header" },
    };
    hermetic_env();
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct node n;
        char label[128];
        snprintf(label, sizeof(label), "%s starts", cases[i].what);
        CHECK(label, node_start(&n, cases[i].scenario, cases[i].scenario));
        struct json_value r;
        struct zw_rpc_error e;
        json_init(&r);
        enum zw_err err = zw_rpc_call(n.rpc, "getblockchaininfo", "[]", &r, &e);
        snprintf(label, sizeof(label), "%s is a BAD_REPLY, not a crash", cases[i].what);
        CHECK(label, err == ZW_ERR_BAD_REPLY && zw_mock_request_count(n.mock) >= 1);
        json_free(&r);
        struct zw_result res;
        memset(&res, 0, sizeof(res));
        struct zw_model m;
        zw_model_init(&m, ZW_PROFILE_AUTO);
        zw_query_run(n.rpc, ZW_Q_CHAIN, &res);
        zw_model_apply(&m, &res);
        snprintf(label, sizeof(label), "%s shows as a bad reply on Connect", cases[i].what);
        CHECK(label, m.conn == ZW_CONN_BAD_REPLY);
        zw_model_free(&m);
        node_stop(&n);
    }
}

/* Wall-clock milliseconds: gui_now_ns is the virtual clock once a headless window exists. */
static uint64_t real_ms(void)
{
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* Shutdown while the node never answers: stop must shut the socket down and join
 * well inside the 5 s receive timeout, and only then may the window be freed. */
static void test_worker_shutdown(void)
{
    struct node n;
    hermetic_env();
    CHECK("silent node starts", node_start(&n, "peer_silent", "silent"));
    struct gui_window_desc d = { .title_utf8 = "w", .width = 100, .height = 100, .surface = GUI_SURFACE_CPU,
                                 .backend = GUI_BACKEND_HEADLESS };
    struct gui_window *win = NULL;
    char err[64];
    gui_window_open(&d, &win, err, sizeof(err));
    struct zw_worker *w = zw_worker_start(win, &n.opt);
    zw_worker_enqueue(w, ZW_Q_CHAIN, 0);
    for (int i = 0; i < 400 && zw_mock_request_count(n.mock) == 0; i++) {
        struct timespec ts = { 0, 5000000 };
        nanosleep(&ts, NULL); /* real-clock: polls a real loopback socket and worker thread, there is no fake-clock seam */
    }
    CHECK("the worker is blocked on a node that never answers", zw_mock_request_count(n.mock) >= 1 &&
          zw_worker_busy(w));
    struct timespec hold = { 0, 300000000L };
    nanosleep(&hold, NULL);
    CHECK("it is still blocked 300 ms later", zw_worker_busy(w));
    uint64_t t0 = real_ms();
    zw_worker_stop(w);
    uint64_t ms = real_ms() - t0;
    printf("    worker stop took %llu ms\n", (unsigned long long)ms);
    CHECK("stop returns within 1 s (the receive timeout is 5 s)", ms < 1000);
    gui_window_close(win); /* nothing may wake or read this window any more (run under ASan) */
    node_stop(&n);
}

/* Coalescing, deterministically: the worker is held in a 400 ms getnetworkinfo, so
 * the first CHAIN enqueue is queued and the second finds it still pending. */
static void test_worker_coalescing(void)
{
    struct node n;
    hermetic_env();
    CHECK("slow node starts", node_start(&n, "slow_net", "slow"));
    struct gui_window_desc d = { .title_utf8 = "w", .width = 100, .height = 100, .surface = GUI_SURFACE_CPU,
                                 .backend = GUI_BACKEND_HEADLESS };
    struct gui_window *win = NULL;
    char err[64];
    gui_window_open(&d, &win, err, sizeof(err));
    struct zw_worker *w = zw_worker_start(win, &n.opt);
    zw_worker_enqueue(w, ZW_Q_NET, 0);
    for (int i = 0; i < 400 && zw_mock_request_count(n.mock) == 0; i++) {
        struct timespec ts = { 0, 5000000 };
        nanosleep(&ts, NULL); /* real-clock: polls a real loopback socket and worker thread, there is no fake-clock seam */
    }
    bool first = zw_worker_enqueue(w, ZW_Q_CHAIN, 0);
    bool again = zw_worker_enqueue(w, ZW_Q_CHAIN, 0);
    CHECK("the second enqueue of a pending kind is coalesced", first && !again);
    struct zw_result out[8];
    size_t got = 0;
    int chains = 0, nets = 0;
    for (int i = 0; i < 600 && (chains + nets < 2 || zw_worker_busy(w)); i++) {
        struct timespec ts = { 0, 5000000 };
        nanosleep(&ts, NULL); /* real-clock: polls a real loopback socket and worker thread, there is no fake-clock seam */
        size_t k = zw_worker_drain(w, out, 8);
        for (size_t j = 0; j < k; j++) {
            chains += out[j].kind == ZW_Q_CHAIN;
            nets += out[j].kind == ZW_Q_NET;
        }
        got += k;
    }
    CHECK("one result per kind, no duplicate CHAIN", got == 2 && chains == 1 && nets == 1);
    zw_worker_stop(w);
    gui_window_close(win);
    node_stop(&n);
}

/* Numbers from the node are untrusted: a double outside int64 and INT64_MIN must
 * neither be cast (undefined) nor negated (undefined). Run under UBSan too. */
static void test_hostile_numbers(void)
{
    struct node n;
    hermetic_env();
    CHECK("hostile-number node starts", node_start(&n, "hostile_numbers", "numbers"));
    struct zw_result res;
    memset(&res, 0, sizeof(res));
    enum zw_err e = zw_query_run(n.rpc, ZW_Q_CHAIN, &res);
    CHECK("1e300 block heights fall back to the default instead of being cast",
          e == ZW_OK && res.chain.blocks == 0 && res.chain.headers == 0);
    memset(&res, 0, sizeof(res));
    e = zw_query_run(n.rpc, ZW_Q_NET, &res);
    CHECK("1e300 connection counts fall back too", e == ZW_OK && res.net.connections == 0 && res.net.version == 0);
    node_stop(&n);
    char buf[40];
    zw_fmt_int(INT64_MIN, buf, sizeof(buf));
    CHECK("INT64_MIN formats without negating it", !strcmp(buf, "-9,223,372,036,854,775,808"));
}

/* ---- model ---- */

static void test_model(void)
{
    uint32_t seq[7] = { zw_backoff_s(0), zw_backoff_s(1), zw_backoff_s(2), zw_backoff_s(3), zw_backoff_s(4),
                        zw_backoff_s(5), zw_backoff_s(50) };
    CHECK("backoff is 1,2,4,8,15 capped at 15", seq[0] == 1 && seq[1] == 1 && seq[2] == 2 && seq[3] == 4 &&
          seq[4] == 8 && seq[5] == 15 && seq[6] == 15);
    struct zw_model m;
    zw_model_init(&m, ZW_PROFILE_ZCLASSICD);
    char t[1600];
    zw_connect_text(&m, t, sizeof(t));
    CHECK("[21] before any result the screen says \"Looking for your node...\"", m.conn == ZW_CONN_STARTING &&
          !strcmp(t, "Looking for your node\xE2\x80\xA6") && !strstr(t, "Looked in"));
    struct zw_result r;
    memset(&r, 0, sizeof(r));
    r.generation = 7;
    CHECK("stale generation results are dropped", !zw_model_apply(&m, &r));
    memset(&r, 0, sizeof(r));
    r.err = ZW_ERR_SEARCHING;
    r.report.ntried = 1;
    snprintf(r.report.tried[0].path, sizeof(r.report.tried[0].path), "fixture-home/ZClassic");
    snprintf(r.report.tried[0].reason, sizeof(r.report.tried[0].reason), "no zclassic.conf");
    zw_model_apply(&m, &r);
    zw_connect_text(&m, t, sizeof(t));
    CHECK("[22] NOT_FOUND names the requested profile and lists path and reason", m.conn == ZW_CONN_NOT_FOUND &&
          starts(t, "Couldn't find a ZClassic node (zclassicd) on this computer.\n") &&
          strstr(t, "fixture-home/ZClassic \xE2\x80\x94 no zclassic.conf"));
    zw_model_init(&m, ZW_PROFILE_Z23);
    zw_model_apply(&m, &r);
    zw_connect_text(&m, t, sizeof(t));
    CHECK("[22] the Z23 profile says Z23 node", starts(t, "Couldn't find a Z23 node on this computer.\n"));
    zw_model_free(&m);
}

static void sync_case(struct zw_model *m, int64_t blocks, int64_t headers, int64_t tip, bool ibd, int64_t peers,
                      int polls)
{
    zw_model_init(m, ZW_PROFILE_AUTO);
    m->conn = ZW_CONN_ONLINE;
    m->have_chain = m->have_net = true;
    m->chain = (struct zw_chain){ .blocks = blocks, .headers = headers, .tiptime = tip, .ibd = ibd };
    snprintf(m->chain.chain, sizeof(m->chain.chain), "main");
    m->net.connections = peers;
    m->peerless_polls = polls;
    m->ever_synced = true;
}

static bool banner_is(struct gui_ui *ui, const struct zw_model *m, const char *want)
{
    zw_home_publish(m, ui, NOW_S);
    bool ok = !strcmp(gui_ui_get(ui, "home.banner"), want);
    if (!ok) printf("    banner: %s\n", gui_ui_get(ui, "home.banner"));
    return ok;
}

static void test_sync_texts(void)
{
    struct gui_tree *t = gui_tree_new();
    struct gui_ui *ui = gui_ui_new(t);
    struct zw_model m;
    sync_case(&m, 1234567, 1234567, NOW_S - 16, false, 8, 0);
    zw_home_publish(&m, ui, NOW_S);
    CHECK("[6] quiet pill: dot, Synced, block, last block age, two spaces around each dot",
          zw_sync_classify(&m, NOW_S) == ZW_SYNC_SYNCED &&
          !strcmp(gui_ui_get(ui, "home.pill"), "\xE2\x97\x8F\xC2\xA0\xC2\xA0Synced  \xC2\xB7  block 1,234,567  \xC2\xB7  last block 16 s ago"));
    m.conn = ZW_CONN_REFUSED;
    CHECK("[20] connecting", banner_is(ui, &m, "Connecting to your ZClassic node\xE2\x80\xA6"));
    sync_case(&m, 1100000, 1234567, NOW_S - 30 * 86400, true, 8, 0);
    CHECK("[20] syncing with a height", banner_is(ui, &m, "Syncing blockchain\nValidated block 1,100,000 \xC2\xB7 30 days behind"));
    sync_case(&m, 0, 0, 0, true, 8, 0);
    CHECK("[20] syncing with no height", banner_is(ui, &m, "Syncing blockchain \xE2\x80\x94 finding the latest blocks\xE2\x80\xA6"));
    sync_case(&m, 1234567, 1234567, NOW_S - 3 * 3600, false, 8, 0);
    CHECK("[20] stale tip", banner_is(ui, &m, "Waiting for new blocks\nLast block 3 h ago \xE2\x80\x94 if this stays, check your computer's date and time"));
    sync_case(&m, 1234567, 1234567, NOW_S - 600, false, 0, 3);
    CHECK("[20] peerless", banner_is(ui, &m, "Connecting to the ZClassic network\xE2\x80\xA6 no peers yet\nYour wallet is at block 1,234,567 (newest block 10 min old)."));
    m.peerless_polls = 36;
    CHECK("[20] peerless after 36 polls", banner_is(ui, &m, "Still no connection to the ZClassic network \xE2\x80\x94 please check your internet connection and firewall.\nYour wallet is at block 1,234,567 (newest block 10 min old)."));
    sync_case(&m, 1234567, 1234567, NOW_S + 5 * 3600, false, 8, 0);
    CHECK("[20] clock skew", banner_is(ui, &m, "Your computer's date or time looks wrong\nWallet is up to date at block 1,234,567, but block times look off. Please correct the clock in your system settings."));
    gui_ui_free(ui);
    gui_tree_free(t);
}

static void test_worker(void)
{
    struct node n;
    hermetic_env();
    CHECK("worker node starts", node_start(&n, "home_synced", "worker"));
    struct gui_window_desc d = { .title_utf8 = "w", .width = 100, .height = 100, .surface = GUI_SURFACE_CPU,
                                 .backend = GUI_BACKEND_HEADLESS };
    struct gui_window *win = NULL;
    char err[64];
    gui_window_open(&d, &win, err, sizeof(err));
    struct zw_worker *w = zw_worker_start(win, &n.opt);
    bool first = zw_worker_enqueue(w, ZW_Q_CHAIN, 0);
    zw_worker_enqueue(w, ZW_Q_BALANCES, 0);
    struct zw_result *out = calloc(8, sizeof(*out));
    size_t got = 0;
    for (int i = 0; out && i < 400 && got < 2; i++) {
        struct gui_event ev;
        gui_window_wait(win, 0, &ev);
        struct timespec ts = { 0, 5000000 };
        nanosleep(&ts, NULL); /* real-clock: polls a real loopback socket and worker thread, there is no fake-clock seam */
        got += zw_worker_drain(w, out + got, 8 - got);
    }
    CHECK("the worker answers queued jobs", got >= 2 && out[0].err == ZW_OK);
    CHECK("an idle worker accepts a queued job", first);
    for (size_t i = 0; i < got; i++) zw_result_release(&out[i]);
    free(out);
    zw_worker_stop(w);
    gui_window_close(win);
    node_stop(&n);
}

/* ---- screens: build from fixture replies, lay out headless ---- */

struct scene {
    struct zw_model m;
    struct gui_window *win;
    struct gui_tree *t;
    struct gui_ui *ui;
    bool built;
};

static void model_from(struct zw_model *m, const char *scenario, const char *tag, enum zw_profile p)
{
    struct node n;
    zw_model_init(m, p);
    if (!scenario) {
        struct zw_options none = { .datadir = TMP "/missing_datadir", .profile = p };
        struct zw_rpc *r = calloc(1, sizeof(*r));
        struct zw_result res;
        memset(&res, 0, sizeof(res));
        if (r) { r->opt = &none; zw_query_run(r, ZW_Q_CHAIN, &res); zw_model_apply(m, &res); free(r); }
        return;
    }
    if (!node_start(&n, scenario, tag)) return;
    for (enum zw_query q = 0; q < ZW_Q_COUNT; q++) {
        struct zw_result res;
        memset(&res, 0, sizeof(res));
        zw_query_run(n.rpc, q, &res);
        zw_model_apply(m, &res);
    }
    node_stop(&n);
    m->port = 18232; /* the mock binds a random port; goldens must not show it */
    m->last_update_s = NOW_S;
}

static void scene_render(struct scene *s, size_t screen, int32_t w, int32_t h, float scale)
{
    if (!s->win) {
        struct gui_window_desc d = { .title_utf8 = "t", .width = w, .height = h, .surface = GUI_SURFACE_CPU,
                                     .backend = GUI_BACKEND_HEADLESS };
        char err[64];
        gui_window_open(&d, &s->win, err, sizeof(err));
        s->t = gui_tree_new();
        s->ui = gui_ui_new(s->t);
        gui_ui_set_window(s->ui, s->win);
        zw_home_sources(s->ui, &s->m);
    }
    gui_headless_set_size(s->win, (int32_t)((float)w * scale), (int32_t)((float)h * scale), scale);
    gui_ui_set_scale(s->ui, scale);
    s->m.now_s = NOW_S;
    s->m.narrow = w - 168 - 24 < 820;
    zw_shell_build(s->t, &s->m, screen);
    char terr[96] = "";
    s->built = gui_tree_end(s->t, terr, sizeof(terr));
    if (!s->built) printf("    tree: %s\n", terr);
    gui_ui_rebind(s->ui);
    zw_model_publish(&s->m, s->ui, NOW_S);
    int32_t pw, ph;
    gui_window_size(s->win, &pw, &ph, NULL);
    gui_ui_layout(s->ui, pw, ph);
    struct gui_cpu_frame f;
    gui_cpu_acquire(s->win, &f);
    struct gui_surface surf = gui_surface_from_frame(&f);
    gui_ui_paint(s->ui, &surf, NULL, 0);
}

static void scene_free(struct scene *s)
{
    gui_ui_free(s->ui);
    gui_tree_free(s->t);
    gui_window_close(s->win);
    zw_model_free(&s->m);
}

static const struct gui_node *node_of(const struct scene *s, const char *id)
{
    int at = gui_tree_find(s->t, id);
    return at < 0 ? NULL : &s->t->nodes[at];
}

static bool frame_is(const struct scene *s, const char *id, int32_t x, int32_t y, int32_t w, int32_t h)
{
    const struct gui_node *n = node_of(s, id);
    bool ok = n && (x < 0 || n->frame.x == x) && (y < 0 || n->frame.y == y) && (w < 0 || n->frame.w == w) &&
              (h < 0 || n->frame.h == h);
    if (!ok && n) printf("    %s frame %d %d %d %d\n", id, n->frame.x, n->frame.y, n->frame.w, n->frame.h);
    return ok;
}

static bool style_is(const struct scene *s, const char *id, enum gui_style st)
{
    const struct gui_node *n = node_of(s, id);
    return n && n->style == st;
}

static bool menubar_ok(const struct scene *s)
{
    const struct gui_node *f = node_of(s, "menu_file"), *e = node_of(s, "menu_edit"), *h = node_of(s, "menu_help");
    if (!f || !e || !h) return false;
    return !strcmp(gui_tree_text(s->t, f), "File") && !strcmp(gui_tree_text(s->t, e), "Edit") &&
           !strcmp(gui_tree_text(s->t, h), "Help");
}

static int checked_items(const struct scene *s)
{
    int active = 0;
    for (size_t i = 0; i < ZW_SCREEN_COUNT; i++) {
        char id[32];
        snprintf(id, sizeof(id), "nav_%s", zw_screens[i].name);
        const struct gui_node *n = node_of(s, id);
        if (n) active += n->style == GS_NAV_ITEM_ACTIVE || n->style == GS_NAV_ADV_ACTIVE;
    }
    return active;
}

static void test_shell_rail(const struct scene *s)
{
    const struct gui_node *rail = node_of(s, "rail");
    CHECK("[2] rail 168 wide, #0c0e12 with a #2a2d35 border", rail && rail->frame.w == 168 &&
          gui_theme(GS_RAIL)->bg == 0x0c0e12 && gui_theme(GS_RAIL)->border == 0x2a2d35);
    int32_t top = rail ? rail->frame.y : 0, bottom = rail ? rail->frame.y + rail->frame.h : 0;
    CHECK("[2] items 152x48 at pitch 54, the first 16 below the rail top",
          frame_is(s, "nav_home", 8, top + 16, 152, 48) && frame_is(s, "nav_send", 8, top + 70, 152, 48) &&
          frame_is(s, "nav_receive", 8, top + 124, 152, 48) && frame_is(s, "nav_activity", 8, top + 178, 152, 48));
    CHECK("[2] Advanced is 42 high, 16 above the rail bottom", frame_is(s, "nav_advanced", 8, bottom - 16 - 42, 152, 42));
    CHECK("[3] exactly one rail item is checked (Home)", checked_items(s) == 1 &&
          style_is(s, "nav_home", GS_NAV_ITEM_ACTIVE) && gui_theme(GS_NAV_ITEM_ACTIVE)->bg == 0x0f2214 &&
          gui_theme(GS_NAV_ITEM_ACTIVE)->border == 0x1f7a1f);
}

static void test_shell(void)
{
    struct scene s = {0};
    model_from(&s.m, "home_synced", "shell", ZW_PROFILE_AUTO);
    scene_render(&s, ZW_SCREEN_HOME, 1100, 720, 1.0f);
    CHECK("[1] menu bar: File, Edit, Help, 31 high, #0f1115", s.built && frame_is(&s, "menubar", 0, 0, 1100, 31) &&
          menubar_ok(&s) && gui_theme(GS_MENUBAR)->bg == 0x0f1115);
    test_shell_rail(&s);
    const struct gui_node *icon = node_of(&s, "status_icon");
    CHECK("[4] status bar 30 high with \"Connected (1,234,567)\" and a 16x16 tick",
          frame_is(&s, "statusbar", 0, 690, 1100, 30) && !strcmp(gui_ui_get(s.ui, "status.label"), "Connected (1,234,567)") &&
          icon && icon->style == GS_ICON_OK && icon->frame.w == 16 && icon->frame.h == 16);
    scene_render(&s, ZW_SCREEN_SEND, 1100, 720, 1.0f);
    CHECK("[3] the check follows the page; Send is a Coming soon stub", style_is(&s, "nav_send", GS_NAV_ITEM_ACTIVE) &&
          style_is(&s, "nav_home", GS_NAV_ITEM) && node_of(&s, "s_soon"));
    scene_free(&s);
}

static bool hero_ok(const struct scene *s)
{
    const struct gui_node *title = node_of(s, "h_summary_title"), *cap = node_of(s, "h_hero_caption");
    if (!title || !cap) return false;
    return !strcmp(gui_tree_text(s->t, title), "Summary") && !strcmp(gui_tree_text(s->t, cap), "PRIVATE BALANCE") &&
           style_is(s, "h_hero", GS_HERO_CARD) && style_is(s, "h_hero_amount", GS_HERO_AMOUNT_OK) &&
           gui_theme(GS_HERO_AMOUNT_OK)->fg == 0x34c759 && gui_theme(GS_HERO_CARD)->radius == 12;
}

static bool actions_ok(const struct scene *s)
{
    const struct gui_node *send = node_of(s, "h_send"), *recv = node_of(s, "h_receive"), *hero = node_of(s, "h_hero");
    if (!send || !recv || !hero) return false;
    return send->style == GS_BUTTON_PRIMARY && recv->style == GS_BUTTON_SECONDARY && send->frame.h == 50 &&
           recv->frame.h == 50 && recv->frame.x - (send->frame.x + send->frame.w) == 8 &&
           abs(send->frame.w - recv->frame.w) <= 1 && send->frame.y - (hero->frame.y + hero->frame.h) == 6;
}

static bool table_ok(const struct scene *s)
{
    const struct gui_node *tbl = node_of(s, "h_balances");
    const struct gui_table_source *src = gui_ui_source(s->ui, "home.balances");
    char c0[256], c1[64];
    enum gui_style s0 = GS_BODY, s1 = GS_BODY;
    if (!tbl || !src || tbl->ncols != 2 || src->rows(src->ctx) != 2) return false;
    if (!src->cell(src->ctx, 0, 0, c0, sizeof(c0), &s0) || !src->cell(src->ctx, 0, 1, c1, sizeof(c1), &s1)) return false;
    return !strcmp(tbl->cols[0].label, "Address") && !tbl->cols[0].right && !strcmp(tbl->cols[1].label, "Amount") &&
           tbl->cols[1].right && !strcmp(c0, "Private\t" ZA) && s0 == GS_PILL_PRIVATE && !strcmp(c1, "10 ZCL") &&
           s1 == GS_AMOUNT_MONO;
}

static void test_home_synced(void)
{
    struct scene s = {0};
    model_from(&s.m, "home_synced", "hsync", ZW_PROFILE_AUTO);
    scene_render(&s, ZW_SCREEN_HOME, 1100, 720, 1.0f);
    CHECK("[7] Summary group; hero caption, green amount and Total line", hero_ok(&s) &&
          !strcmp(gui_ui_get(s.ui, "home.private"), "12.5 ZCL") && !strcmp(gui_ui_get(s.ui, "home.total"), "Total: 12.5 ZCL"));
    CHECK("[10] Send primary, Receive secondary, 50 high, gap 8, equal widths, 6 below the hero", actions_ok(&s));
    CHECK("[12] Address Balances: Address centred / Amount right, pill + address, mono amount", table_ok(&s));
    CHECK("[11] no fix-it card without public funds", !node_of(&s, "h_fixit"));
    scene_free(&s);
}

static void test_home_states(void)
{
    struct scene s = {0};
    model_from(&s.m, "home_public_funds", "hpub", ZW_PROFILE_AUTO);
    scene_render(&s, ZW_SCREEN_HOME, 1100, 720, 1.0f);
    const struct gui_node *sh = node_of(&s, "h_shield");
    CHECK("[11] the amber card text and \"Shield my funds\"", node_of(&s, "h_fixit") && sh &&
          !strcmp(gui_tree_text(s.t, sh), "Shield my funds") &&
          !strcmp(gui_ui_get(s.ui, "home.fixit"), "3.4 ZCL is PUBLIC and visible to everyone."));
    scene_free(&s);
    memset(&s, 0, sizeof(s));
    model_from(&s.m, "home_empty", "hempty", ZW_PROFILE_AUTO);
    scene_render(&s, ZW_SCREEN_HOME, 1100, 720, 1.0f);
    const struct gui_node *helper = node_of(&s, "h_hero_helper");
    CHECK("[10] total 0: Receive is primary and the helper shows", style_is(&s, "h_receive", GS_BUTTON_PRIMARY) &&
          style_is(&s, "h_send", GS_BUTTON_SECONDARY) && helper &&
          !strcmp(gui_tree_text(s.t, helper), "Your private balance \xE2\x80\x94 receive ZCL to get started."));
    scene_free(&s);
    memset(&s, 0, sizeof(s));
    model_from(&s.m, "home_warming", "hwarm", ZW_PROFILE_AUTO);
    scene_render(&s, ZW_SCREEN_HOME, 1100, 720, 1.0f);
    CHECK("[15] syncing: grey hero and \"Updating... not final yet\"", style_is(&s, "h_hero_amount", GS_HERO_AMOUNT_WARM) &&
          !strcmp(gui_ui_get(s.ui, "home.qualifier"), "Updating\xE2\x80\xA6 not final yet") && node_of(&s, "h_banner"));
    scene_free(&s);
    memset(&s, 0, sizeof(s));
    model_from(&s.m, "home_unconfirmed", "hunc", ZW_PROFILE_AUTO);
    scene_render(&s, ZW_SCREEN_HOME, 1100, 720, 1.0f);
    const struct gui_table_source *src = gui_ui_source(s.ui, "home.balances");
    char cell[128];
    enum gui_style cs = GS_BODY;
    CHECK("[14] unconfirmed warning, the address amount tinted", node_of(&s, "h_unconfirmed") && src &&
          src->cell(src->ctx, 0, 1, cell, sizeof(cell), &cs) && cs == GS_WARN_TEXT && gui_theme(GS_WARN_TEXT)->fg == 0xe06b5e);
    scene_free(&s);
}

static void test_home_no_node(void)
{
    struct scene s = {0};
    hermetic_env();
    model_from(&s.m, NULL, "nonode", ZW_PROFILE_ZCLASSICD);
    scene_render(&s, ZW_SCREEN_HOME, 1100, 720, 1.0f);
    const char *text = gui_ui_get(s.ui, "connect.text");
    CHECK("[16] no node: hero \"--\", unavailable total, funds-not-affected qualifier, never 0 ZCL",
          !strcmp(gui_ui_get(s.ui, "home.private"), "\xE2\x80\x94") &&
          !strcmp(gui_ui_get(s.ui, "home.total"), "Balance unavailable until the node is connected") &&
          strstr(gui_ui_get(s.ui, "home.qualifier"), "Your funds are not affected.") &&
          !strstr(gui_ui_get(s.ui, "home.private"), "0 ZCL"));
    CHECK("[22] the Connect card lists the searched folder with its reason", node_of(&s, "c_retry") &&
          strstr(text, "Couldn't find a ZClassic node (zclassicd)") && strstr(text, "missing_datadir \xE2\x80\x94 not found"));
    const struct gui_node *icon = node_of(&s, "status_icon");
    CHECK("[4] no node: critical icon and \"No Connection\"", icon && icon->style == GS_ICON_CRIT &&
          !strcmp(gui_ui_get(s.ui, "status.label"), "No Connection"));
    scene_free(&s);
}

static void test_home_layout(void)
{
    struct scene s = {0};
    model_from(&s.m, "home_synced", "hlay", ZW_PROFILE_AUTO);
    scene_render(&s, ZW_SCREEN_HOME, 1100, 720, 1.0f);
    const struct gui_node *a = node_of(&s, "h_summary"), *b = node_of(&s, "h_addrs");
    CHECK("[17] wide: the groups sit side by side with equal widths", a && b && a->frame.y == b->frame.y &&
          abs(a->frame.w - b->frame.w) <= 1 && b->frame.x - (a->frame.x + a->frame.w) == 7);
    scene_render(&s, ZW_SCREEN_HOME, 640, 720, 1.0f);
    a = node_of(&s, "h_summary");
    b = node_of(&s, "h_addrs");
    CHECK("[17] under 820 px of content the groups stack, Summary first", a && b && a->frame.x == b->frame.x &&
          b->frame.y > a->frame.y);
    s.m.wallet.spendable = INT64_C(2099999999999999);
    s.m.wallet.total = s.m.wallet.spendable;
    scene_render(&s, ZW_SCREEN_HOME, 640, 720, 1.0f);
    const struct gui_node *amt = node_of(&s, "h_hero_amount");
    const char *txt = gui_ui_get(s.ui, "home.private");
    int32_t px = amt ? gui_ui_fit_px(s.ui, amt, txt, strlen(txt), amt->frame.w) : 0;
    CHECK("[9] the hero auto-fits: every digit at width 640, font at least 19 px", amt && px >= 19 &&
          gui_ui_run_width(GUI_FONT_STRONG, px, txt, strlen(txt)) <= amt->frame.w &&
          !strcmp(txt, "20999999.99999999 ZCL"));
    scene_free(&s);
}

static void test_home_row_menu(void)
{
    struct scene s = {0};
    model_from(&s.m, "home_synced", "hmenu", ZW_PROFILE_AUTO);
    scene_render(&s, ZW_SCREEN_HOME, 1100, 720, 1.0f);
    const struct gui_node *tbl = node_of(&s, "h_balances");
    struct gui_action act;
    struct gui_event ev = { .type = GUI_EV_MOUSE_BUTTON };
    ev.button.x = tbl ? tbl->frame.x + 40 : 0;
    ev.button.y = tbl ? tbl->frame.y + 47 + 10 : 0;
    ev.button.button = 2;
    ev.button.down = true;
    ev.button.clicks = 1;
    bool fired = gui_ui_event(s.ui, &ev, &act);
    CHECK("[18] right-click on a row asks for its menu", fired && !strcmp(act.name, "home.balances.menu") && act.row == 0);
    s.m.menu = ZW_MENU_ROW;
    s.m.menu_row = 0;
    scene_render(&s, ZW_SCREEN_HOME, 1100, 720, 1.0f);
    const struct gui_node *copy = node_of(&s, "mr_copy"), *send = node_of(&s, "mr_send");
    char want[80];
    snprintf(want, sizeof(want), "Send from %.40s...", ZA);
    CHECK("[18] the menu offers Copy address and Send from <40>...", copy && send &&
          !strcmp(gui_tree_text(s.t, copy), "Copy address") && !strcmp(gui_tree_text(s.t, send), want));
    ev.button.button = 1;
    ev.button.clicks = 2;
    ev.button.x = 3;
    ev.button.y = 300;
    bool closed = gui_ui_event(s.ui, &ev, &act);
    CHECK("[18] a click outside closes the menu", closed && !strcmp(act.name, "menu.close"));
    s.m.menu = ZW_MENU_NONE;
    scene_render(&s, ZW_SCREEN_HOME, 1100, 720, 1.0f);
    ev.button.x = tbl ? tbl->frame.x + 40 : 0;
    ev.button.y = tbl ? tbl->frame.y + 47 + 10 : 0;
    fired = gui_ui_event(s.ui, &ev, &act);
    CHECK("[19] double-click on a row opens it", fired && !strcmp(act.name, "home.balances.open") && act.row == 0);
    scene_free(&s);
}

/* ---- goldens ---- */

static bool golden_ok(const char *name, const struct gui_cpu_frame *f)
{
    uint8_t h[32];
    gui_frame_sha3(f, h);
    char hex[65];
    for (int i = 0; i < 32; i++) snprintf(hex + 2 * i, 3, "%02x", h[i]);
    mkdirs("build/test-artifacts/z23wallet");
    char png[256];
    snprintf(png, sizeof(png), "build/test-artifacts/z23wallet/%s.png", name);
    gui_frame_write_png(f, png);
    FILE *g = fopen("tests/fixtures/z23wallet/golden.tsv", "r");
    char line[256], want[65] = "";
    while (g && fgets(line, sizeof(line), g)) {
        char nm[64], hx[80];
        int w, hh;
        if (sscanf(line, "%63[^\t]\t%d\t%d\t%79s", nm, &w, &hh, hx) == 4 && !strcmp(nm, name) &&
            w == f->width && hh == f->height) snprintf(want, sizeof(want), "%.64s", hx);
    }
    if (g) fclose(g);
    if (strcmp(want, hex)) printf("    golden %s: got %s want %s\n", name, hex, want[0] ? want : "(none)");
    return !strcmp(want, hex);
}

struct shot_case { const char *name, *scenario; size_t screen; float scale; enum zw_profile profile; };

static void run_golden(const struct shot_case *c)
{
    struct scene s = {0};
    hermetic_env();
    model_from(&s.m, c->scenario, c->name, c->profile);
    scene_render(&s, c->screen, 1100, 720, c->scale);
    struct gui_cpu_frame f;
    gui_cpu_acquire(s.win, &f);
    char label[96];
    snprintf(label, sizeof(label), "%s golden", c->name);
#if defined(_WIN32)
    /* Searched paths differ on Windows, so the not-found frame is Linux-only. */
    CHECK(label, s.built && (!c->scenario || golden_ok(c->name, &f)));
#else
    CHECK(label, s.built && golden_ok(c->name, &f));
#endif
    scene_free(&s);
}

static void test_goldens(void)
{
    static const struct shot_case cases[] = {
        { "home_synced", "home_synced", ZW_SCREEN_HOME, 1.0f, ZW_PROFILE_AUTO },
        { "home_synced_175", "home_synced", ZW_SCREEN_HOME, 1.75f, ZW_PROFILE_AUTO },
        { "home_public_funds", "home_public_funds", ZW_SCREEN_HOME, 1.0f, ZW_PROFILE_AUTO },
        { "home_public_funds_175", "home_public_funds", ZW_SCREEN_HOME, 1.75f, ZW_PROFILE_AUTO },
        { "home_empty", "home_empty", ZW_SCREEN_HOME, 1.0f, ZW_PROFILE_AUTO },
        { "home_empty_175", "home_empty", ZW_SCREEN_HOME, 1.75f, ZW_PROFILE_AUTO },
        { "home_warming", "home_warming", ZW_SCREEN_HOME, 1.0f, ZW_PROFILE_AUTO },
        { "home_warming_175", "home_warming", ZW_SCREEN_HOME, 1.75f, ZW_PROFILE_AUTO },
        { "home_legacy", "home_legacy", ZW_SCREEN_HOME, 1.0f, ZW_PROFILE_AUTO },
        { "advanced_synced", "home_synced", ZW_SCREEN_ADVANCED, 1.0f, ZW_PROFILE_AUTO },
        { "advanced_syncing", "node_syncing", ZW_SCREEN_ADVANCED, 1.0f, ZW_PROFILE_AUTO },
        { "advanced_no_peers", "node_no_peers", ZW_SCREEN_ADVANCED, 1.0f, ZW_PROFILE_AUTO },
        { "home_catching_up", "home_catching_up", ZW_SCREEN_HOME, 1.0f, ZW_PROFILE_AUTO },
        { "connect_not_found", NULL, ZW_SCREEN_HOME, 1.0f, ZW_PROFILE_ZCLASSICD },
        { "connect_not_found_175", NULL, ZW_SCREEN_HOME, 1.75f, ZW_PROFILE_ZCLASSICD },
        { "connect_warming", "connect_warming", ZW_SCREEN_HOME, 1.0f, ZW_PROFILE_AUTO },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) run_golden(&cases[i]);
}

int test_z23wallet(void)
{
    printf("\n=== z23wallet ===\n");
    g_fail = 0;
    test_amount();
    test_age_and_version();
    test_args();
    test_locate_z23();
    test_locate_conf();
    test_locate_reasons();
    test_rpc();
    test_hostile_peers();
    test_worker_shutdown();
    test_worker_coalescing();
    test_hostile_numbers();
    test_model();
    test_sync_texts();
    test_worker();
    test_shell();
    test_home_synced();
    test_home_states();
    test_home_no_node();
    test_home_layout();
    test_home_row_menu();
    test_goldens();
    return g_fail;
}
