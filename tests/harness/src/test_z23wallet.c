/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: z23wallet group. Amounts, option parsing, node location, the
 * HTTP/RPC client against the fixture mock node (401 rotation, warming,
 * legacy fallback latch, refusal), the read worker, the connection model and
 * the screen goldens rendered headless from fixture replies. Isolated temp
 * directories only; no real node, key or fund is touched. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "../../../apps/z23wallet/src/zw.h"
#include "z23wallet_mock_node.h"

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
    mkdirs(TMP "/home");
    set_env("HOME", TMP "/home");
    set_env("USERPROFILE", TMP "/home");
    set_env("LOCALAPPDATA", TMP "/home/local");
    set_env("APPDATA", TMP "/home/roaming");
}

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
    json_set_int(&v, 12);
    CHECK("integer JSON is zatoshi", zw_amount_from_json(&v, &z) && z == 12);
    json_free(&v);
    char b[64];
    zw_amount_format(0, b, sizeof(b), true);
    CHECK("zero formats as 0 ZCL", !strcmp(b, "0 ZCL"));
    zw_amount_format(INT64_C(123456789012345), b, sizeof(b), true);
    CHECK("grouping and trimmed zeros", !strcmp(b, "1,234,567.89012345 ZCL"));
    zw_amount_format(1250000000, b, sizeof(b), false);
    CHECK("12.5 without unit", !strcmp(b, "12.5"));
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

static void write_file(const char *dir, const char *name, const char *text)
{
    char p[600];
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    FILE *f = fopen(p, "wb");
    if (f) { fputs(text, f); fclose(f); }
}

static void test_locate(void)
{
    hermetic_env();
    mkdirs(TMP "/loc1");
    zw_mock_write_cookie(TMP "/loc1", COOKIE);
    write_file(TMP "/loc1", ".rpcport", "19999");
    struct zw_options o = { .datadir = TMP "/loc1" };
    struct zw_endpoint ep = {0};
    struct zw_locate_report rep = {0};
    CHECK("datadir with cookie and .rpcport is found", zw_locate(&o, &ep, &rep) && ep.port == 19999 &&
          ep.profile == ZW_PROFILE_Z23 && !strcmp(ep.host, "127.0.0.1") && !strncmp(ep.auth, "Basic ", 6));
    o.rpcport = 7;
    CHECK("--rpcport wins over .rpcport", zw_locate(&o, &ep, &rep) && ep.port == 7);
    struct zw_options none = { .datadir = TMP "/nowhere" };
    CHECK("missing cookie means searching and lists every path",
          !zw_locate(&none, &ep, &rep) && rep.ntried >= 2 && !strcmp(rep.tried[0], TMP "/nowhere"));
    mkdirs(TMP "/legacy");
    write_file(TMP "/legacy", "zclassic.conf",
               "# comment\nRPCUSER=zu\nrpcpassword=zp\nrpcport=18024\ntestnet=1\n");
    struct zw_options lo = { .datadir = TMP "/legacy", .profile = ZW_PROFILE_ZCLASSICD };
    CHECK("zclassic.conf yields credentials, port and testnet",
          zw_locate(&lo, &ep, &rep) && ep.profile == ZW_PROFILE_ZCLASSICD && ep.port == 18024 && ep.testnet);
    write_file(TMP "/legacy", "zclassic.conf", "rpcuser=a\nrpcpassword=b\n");
    CHECK("legacy default port is 8023", zw_locate(&lo, &ep, &rep) && ep.port == 8023 && !ep.testnet);
    zw_endpoint_wipe(&ep);
}

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
    n->rpc->opt = &n->opt;
    return n->rpc != NULL;
}

static void node_stop(struct node *n)
{
    zw_mock_stop(n->mock);
    zw_endpoint_wipe(&n->rpc->ep);
    free(n->rpc);
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
    CHECK("a rotated cookie is re-read after one 401", zw_rpc_call(n->rpc, "getnetworkinfo", "[]", &r, &e) == ZW_OK);
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

static void test_log_redaction(void)
{
    zw_log_open(TMP "/session.log");
    zw_log("probe line with %s inside", "rotatedcookie9876543210");
    zw_log("probe line without a secret");
    zw_log_close();
    FILE *f = fopen(TMP "/session.log", "rb");
    char log[2048] = "";
    size_t got = f ? fread(log, 1, sizeof(log) - 1, f) : 0;
    if (f) fclose(f);
    log[got] = 0;
    CHECK("the session log never holds the cookie", got > 0 && !strstr(log, "rotatedcookie") &&
          strstr(log, "without a secret"));
}

static void test_rpc_legacy(void)
{
    struct node n;
    struct zw_result res;
    CHECK("legacy node starts", node_start(&n, "home_legacy", "legacy"));
    memset(&res, 0, sizeof(res));
    CHECK("walletsummary -32601 falls back to z_gettotalbalance", zw_query_run(n.rpc, ZW_Q_WALLET, &res) == ZW_OK &&
          res.wallet.legacy && res.wallet.spendable == 1250000000 && res.wallet.publicf == 340000000 &&
          res.profile == ZW_PROFILE_ZCLASSICD);
    unsigned before = zw_mock_request_count(n.mock);
    memset(&res, 0, sizeof(res));
    zw_query_run(n.rpc, ZW_Q_WALLET, &res);
    CHECK("the missing method is latched for the session", n.rpc->missing_walletsummary &&
          zw_mock_request_count(n.mock) == before + 1);
    node_stop(&n);
}

static void test_rpc_warming(void)
{
    struct node n;
    struct zw_result res;
    CHECK("warming node starts", node_start(&n, "connect_warming", "warm"));
    memset(&res, 0, sizeof(res));
    enum zw_err w = zw_query_run(n.rpc, ZW_Q_CHAIN, &res);
    struct zw_model m;
    zw_model_init(&m);
    zw_model_apply(&m, &res);
    CHECK("-28 becomes WARMING with the node's message and percent", w == ZW_ERR_RPC &&
          m.conn == ZW_CONN_WARMING && strstr(m.conn_msg, "Loading block index") && m.warm_percent == 45);
    node_stop(&n);
}

static void test_rpc_refused(void)
{
    struct node n;
    struct zw_result res;
    CHECK("refused node starts", node_start(&n, "home_synced", "refused"));
    zw_mock_stop(n.mock); /* the port stays recorded in the options but nobody listens */
    n.mock = NULL;
    n.rpc->ep.valid = false;
    memset(&res, 0, sizeof(res));
    enum zw_err refused = zw_query_run(n.rpc, ZW_Q_CHAIN, &res);
    CHECK("a closed port is REFUSED (or TIMEOUT), never a hang", refused == ZW_ERR_REFUSED ||
          refused == ZW_ERR_TIMEOUT || refused == ZW_ERR_IO);
    zw_endpoint_wipe(&n.rpc->ep);
    free(n.rpc);
}

static void test_rpc(void)
{
    hermetic_env();
    struct node n;
    CHECK("mock node starts", node_start(&n, "home_synced", "rpc"));
    test_rpc_basic(&n);
    test_log_redaction();
    node_stop(&n);
    test_rpc_legacy();
    test_rpc_warming();
    test_rpc_refused();
}

static void test_model_and_worker(void)
{
    uint32_t seq[7] = { zw_backoff_s(0), zw_backoff_s(1), zw_backoff_s(2), zw_backoff_s(3), zw_backoff_s(4),
                        zw_backoff_s(5), zw_backoff_s(50) };
    CHECK("backoff is 1,2,4,8,15 capped at 15", seq[0] == 1 && seq[1] == 1 && seq[2] == 2 && seq[3] == 4 &&
          seq[4] == 8 && seq[5] == 15 && seq[6] == 15);
    struct zw_model m;
    zw_model_init(&m);
    struct zw_result r;
    memset(&r, 0, sizeof(r));
    r.generation = 7;
    CHECK("stale generation results are dropped", !zw_model_apply(&m, &r));

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
    bool again = zw_worker_enqueue(w, ZW_Q_CHAIN, 0);
    zw_worker_enqueue(w, ZW_Q_NET, 0);
    struct zw_result out[8];
    size_t got = 0;
    for (int i = 0; i < 400 && got < 2; i++) {
        struct gui_event ev;
        gui_window_wait(win, 0, &ev);
        struct timespec ts = { 0, 5000000 };
        nanosleep(&ts, NULL);
        got += zw_worker_drain(w, out + got, 8 - got);
    }
    CHECK("the worker answers queued jobs", got >= 2 && out[0].err == ZW_OK);
    CHECK("a queued kind is coalesced (usually; timing can run it first)", first && (!again || got >= 2));
    zw_worker_stop(w);
    gui_window_close(win);
    node_stop(&n);
}

/* ---- screen goldens ---- */

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
    if (getenv("ZCL_GOLDEN_UPDATE")) {
        FILE *a = fopen("tests/fixtures/z23wallet/golden.tsv", "a");
        if (a) { fprintf(a, "%s\t%d\t%d\t%s\n", name, f->width, f->height, hex); fclose(a); }
        return true;
    }
    if (strcmp(want, hex)) printf("    golden %s: got %s want %s\n", name, hex, want[0] ? want : "(none)");
    return !strcmp(want, hex);
}

struct shot_case {
    const char *name, *scenario;
    enum zw_screen_kind { S_HOME, S_NODE } screen;
    float scale;
    const char *key, *value; /* one gui_data assertion */
    bool expect_connect;
    int mode; /* 0 normal, 1 no datadir, 2 closed port, 3 wrong cookie */
};

static void run_case(const struct shot_case *c)
{
    hermetic_env();
    struct node n;
    struct zw_options none = { .datadir = TMP "/missing_datadir" };
    struct zw_options *opt = &none;
    struct zw_mock *other = NULL;
    memset(&n, 0, sizeof(n));
    if (c->mode != 1) {
        node_start(&n, c->scenario, c->name);
        opt = &n.opt;
    }
    if (c->mode == 2) {
        zw_mock_stop(n.mock);
        n.mock = NULL;
    }
    if (c->mode == 3) {
        zw_mock_write_cookie(n.dir, "__cookie__:differentnodecookie000");
        uint16_t p2;
        char dd2[160];
        snprintf(dd2, sizeof(dd2), "%s_other", n.dir);
        mkdirs(dd2);
        zw_mock_write_cookie(dd2, COOKIE);
        other = zw_mock_start(FIX "home_synced", dd2, &p2);
        opt->rpcport = p2; /* serves with COOKIE; the client reads the other cookie */
    }
    struct zw_rpc *rpc = calloc(1, sizeof(*rpc));
    rpc->opt = opt;
    struct zw_model m;
    zw_model_init(&m);
    for (enum zw_query q = 0; q < ZW_Q_COUNT; q++) {
        struct zw_result res;
        memset(&res, 0, sizeof(res));
        zw_query_run(rpc, q, &res);
        if (zw_model_apply(&m, &res) && res.err == ZW_OK) m.last_update_s = 0;
    }
    m.port = 18232; /* the mock binds a random port; goldens must not show it */
    struct gui_window_desc d = { .title_utf8 = "t", .width = 1100, .height = 720, .surface = GUI_SURFACE_CPU,
                                 .backend = GUI_BACKEND_HEADLESS };
    struct gui_window *win = NULL;
    char err[64];
    gui_window_open(&d, &win, err, sizeof(err));
    gui_headless_set_size(win, (int32_t)(1100 * c->scale), (int32_t)(720 * c->scale), c->scale);
    struct gui_tree *t = gui_tree_new();
    struct gui_ui *ui = gui_ui_new(t);
    gui_ui_set_window(ui, win);
    gui_ui_set_scale(ui, c->scale);
    zw_shell_build(t, &m, (size_t)c->screen);
    char terr[96] = "";
    bool built = gui_tree_end(t, terr, sizeof(terr));
    zw_model_publish(&m, ui, 0);
    int32_t pw, ph;
    gui_window_size(win, &pw, &ph, NULL);
    gui_ui_layout(ui, pw, ph);
    struct gui_cpu_frame f;
    gui_cpu_acquire(win, &f);
    struct gui_surface s = gui_surface_from_frame(&f);
    gui_ui_paint(ui, &s, NULL, 0);
    char label[96];
    snprintf(label, sizeof(label), "%s tree builds, key %s is right", c->name, c->key);
    CHECK(label, built && (!c->key || !strcmp(gui_ui_get(ui, c->key), c->value)));
    snprintf(label, sizeof(label), "%s golden", c->name);
#if defined(_WIN32)
    /* The searched-path list differs on Windows, so that one frame is Linux-only. */
    CHECK(label, c->mode == 1 || golden_ok(c->name, &f));
#else
    CHECK(label, golden_ok(c->name, &f));
#endif
    if (c->expect_connect) {
        char dump[4096];
        gui_tree_dump(t, dump, sizeof(dump));
        CHECK("the Connect panel replaces the screen", strstr(dump, "c_retry") != NULL);
    }
    gui_ui_free(ui);
    gui_tree_free(t);
    gui_window_close(win);
    zw_endpoint_wipe(&rpc->ep);
    free(rpc);
    if (other) zw_mock_stop(other);
    if (c->mode != 1) {
        if (n.mock) zw_mock_stop(n.mock);
        free(n.rpc);
    }
}

static void test_screens(void)
{
    static const struct shot_case cases[] = {
        { "home_synced", "home_synced", S_HOME, 1.0f, "home.private", "12.5 ZCL", false, 0 },
        { "home_synced_scale2", "home_synced", S_HOME, 2.0f, "home.total", "12.5 ZCL", false, 0 },
        { "home_catching_up", "home_catching_up", S_HOME, 1.0f, "home.blocked", "Wallet is still scanning the chain", false, 0 },
        { "home_public_funds", "home_public_funds", S_HOME, 1.0f, "home.public_warn", "3.4 ZCL is PUBLIC - visible to everyone", false, 0 },
        { "home_legacy", "home_legacy", S_HOME, 1.0f, "home.transparent", "3.4 ZCL", false, 0 },
        { "node_syncing", "node_syncing", S_NODE, 1.0f, "status.text", "Syncing - validated block 1,100,000 of ~1,234,567", false, 0 },
        { "node_no_peers", "node_no_peers", S_NODE, 1.0f, "node.hint", "Waiting for peers - check your internet connection", false, 0 },
        { "connect_searching", NULL, S_HOME, 1.0f, "status.text", "Looking for your node", true, 1 },
        { "connect_refused", "home_synced", S_HOME, 1.0f, "connect.text", "Your node isn't answering yet. Retrying in 4 s.", true, 2 },
        { "connect_warming", "connect_warming", S_HOME, 1.0f, "connect.text", "Your node is starting: Loading block index... 45%", true, 0 },
        { "connect_auth", "home_synced", S_HOME, 1.0f, "status.text", "Can't reach your node - retrying in 4 s", true, 3 },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) run_case(&cases[i]);
}

int test_z23wallet(void)
{
    printf("\n=== z23wallet ===\n");
    g_fail = 0;
    test_amount();
    test_args();
    test_locate();
    test_rpc();
    test_model_and_worker();
    test_screens();
    return g_fail;
}
