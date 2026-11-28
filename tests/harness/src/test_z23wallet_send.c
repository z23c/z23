/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: z23wallet_send group, the Send page (beta13 sendtab.cpp parity).
 * Address checksums and types, the amount validator, the four privacy
 * categories, every doSendTxValidations message in order with the
 * integer-zatoshi funds guard, memo encoding and its 512-byte limit, the
 * z_sendmany parameters byte for byte, the send-flow verdicts, the runner
 * against the fixture mock node (success, insufficient funds, operation
 * failed, still executing, connection lost mid-send, warming, a node without
 * the send key, malformed replies, a Z23 node) and the page's state machine
 * (syncing gate default No, confirm default Cancel, no double send, the
 * de-shield acknowledgement, memo, discard). Only the mock node and
 * synthetic addresses (repeated-byte payloads) are used; nothing here can
 * reach a real wallet. Set ZW_SEND_SHOTS to a folder to also write a PNG of
 * every page state. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "../../../apps/z23wallet/src/zw_send.h"
#include "platform/time_compat.h"
#include "z23wallet_mock_node.h"

static int g_fail;
#define CHECK(name, cond) \
    do { \
        bool ok_ = (cond); \
        printf("  %s... %s\n", (name), ok_ ? "OK" : "FAIL"); \
        if (!ok_) g_fail++; \
    } while (0)

#define TMP "build/test-tmp/z23wallet_send"
#define FIX "tests/fixtures/z23wallet/rpc/"
#define COOKIE "__cookie__:fixturecookie0123456789"
#define NOW_S INT64_C(1700000016)
/* Synthetic, checksum-valid addresses: payloads are one repeated byte. */
#define T1 "t1KRqwQhktLV4BjbNLiuH6pb3AMoszZKcQB"
#define T2 "t1Lz5sUzNoMBWmq8qk1zS4q5A54RgF5e4Ua"
#define Z0 "zs1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpq6d8g"
#define Z1 "zs1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zx3shhc"
#define ZC "zcCh611B2bV6yLqJsRz88ZhaJrixJogPqNyEp3xV8TcTwSKsHgmHQRAJnZbKHiWmZV9XPKHApqT6nDvah7HFpyv9hLHr7yH"
#define ZR "zregtestsapling1xvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxe0df5j"
#define TX "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e"
#define OPID "opid-11111111-2222-3333-4444-555555555555"

static void mkdirs(const char *path)
{
    char p[512];
    snprintf(p, sizeof(p), "%s", path);
    for (char *c = p + 1;; c++) {
        bool end = !*c;
        if (*c == '/' || end) {
            *c = 0;
#if defined(_WIN32)
            mkdir(p);
#else
            mkdir(p, 0700);
#endif
            if (end) break;
            *c = '/';
        }
    }
}

static void write_file(const char *dir, const char *name, const char *text)
{
    char p[600];
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    FILE *f = fopen(p, "wb");
    if (f) { fputs(text, f); fclose(f); }
}

static void plan1(struct zw_send_plan *p, const char *from, const char *to, const char *amount, const char *memo)
{
    memset(p, 0, sizeof(*p));
    snprintf(p->from, sizeof(p->from), "%s", from);
    p->n = 1;
    p->fee = ZW_DEFAULT_FEE;
    snprintf(p->to[0].addr, sizeof(p->to[0].addr), "%s", to);
    snprintf(p->to[0].amount, sizeof(p->to[0].amount), "%s", amount);
    snprintf(p->to[0].memo, sizeof(p->to[0].memo), "%s", memo ? memo : "");
}

/* ---- pure plan ---- */

static void sv_addresses(void)
{
    char bad[128];
    CHECK("Sapling zs, Sprout zc, transparent t1 and regtest Sapling are valid with their types",
          zw_addr_check(Z0) == ZW_AT_SAPLING && zw_addr_check(Z1) == ZW_AT_SAPLING &&
          zw_addr_check(ZC) == ZW_AT_SPROUT && zw_addr_check(T1) == ZW_AT_TRANSPARENT &&
          zw_addr_check(ZR) == ZW_AT_SAPLING);
    snprintf(bad, sizeof(bad), "%s", T1);
    bad[10] = bad[10] == 'a' ? 'b' : 'a';
    CHECK("one changed character in a t-address fails its base58check", zw_addr_check(bad) == ZW_AT_INVALID);
    snprintf(bad, sizeof(bad), "%s", Z1);
    bad[20] = bad[20] == 'q' ? 'p' : 'q';
    CHECK("one changed character in a Sapling address fails its bech32 checksum", zw_addr_check(bad) == ZW_AT_INVALID);
    snprintf(bad, sizeof(bad), "%s", Z1);
    bad[5] = (char)(bad[5] - 32);
    CHECK("mixed-case bech32 is refused", zw_addr_check(bad) == ZW_AT_INVALID);
}

static void sv_address_rules(void)
{
    CHECK("wrong lengths, empty and non-alphanumeric text are invalid",
          zw_addr_check("t1KRqwQhktLV4BjbNLiuH6pb3AMoszZKcQ") == ZW_AT_INVALID && zw_addr_check("") == ZW_AT_INVALID &&
          zw_addr_check("t1KRqwQhktLV4BjbNLiuH6pb3AMoszZKc-B") == ZW_AT_INVALID);
    CHECK("isZAddress / isTAddress", zw_addr_is_z(Z0) && zw_addr_is_z(ZC) && !zw_addr_is_z(T1) && zw_addr_is_t(T1));
    uint8_t h[32];
    zw_sha256((const uint8_t *)"abc", 3, h);
    CHECK("SHA-256 of \"abc\" (FIPS 180-4 vector)", h[0] == 0xba && h[1] == 0x78 && h[31] == 0xad);
    CHECK("look-alike: same first and last 5, different middle; never the same address",
          zw_addr_lookalike("t1KRqXXXXXXXXXXXXXXXXXXXXXXXXXZKcQB", T1) && !zw_addr_lookalike(T1, T1) &&
          !zw_addr_lookalike(T2, T1));
}

static void sv_amounts(void)
{
    int64_t z = -1;
    CHECK("amount text: empty, zero, \".\", valid, 8 decimals",
          zw_amount_text("", &z) == ZW_AMT_EMPTY && zw_amount_text("0", &z) == ZW_AMT_ZERO &&
          zw_amount_text(".", &z) == ZW_AMT_ZERO && zw_amount_text("1.5", &z) == ZW_AMT_OK && z == 150000000 &&
          zw_amount_text("0.00000001", &z) == ZW_AMT_OK && z == 1 && zw_amount_text(" 2 ", &z) == ZW_AMT_OK);
    CHECK("amount text: 9 decimals, 9 integer digits, letters and above MAX_MONEY are refused",
          zw_amount_text("0.000000001", &z) == ZW_AMT_BAD && zw_amount_text("123456789", &z) == ZW_AMT_BAD &&
          zw_amount_text("1e3", &z) == ZW_AMT_BAD && zw_amount_text("21000001", &z) == ZW_AMT_BAD);
    char d[40];
    zw_decimal(11990000, d, sizeof(d));
    bool a = !strcmp(d, "0.1199");
    zw_decimal(150000000, d, sizeof(d));
    bool b = !strcmp(d, "1.5");
    zw_decimal(0, d, sizeof(d));
    CHECK("getDecimalString: 0.1199, 1.5, 0", a && b && !strcmp(d, "0"));
    const char *t;
    size_t n = zw_trimmed("\xC2\xA0 x y\t\xE3\x80\x80", &t);
    CHECK("QString::trimmed also trims U+00A0 and U+3000", n == 3 && !strncmp(t, "x y", 3));
}

static void sv_categories(void)
{
    struct zw_send_plan p;
    plan1(&p, Z0, Z1, "1", NULL);
    bool zz = zw_send_category(&p) == ZW_CAT_PRIVATE;
    plan1(&p, T1, Z0, "1", NULL);
    bool tz = zw_send_category(&p) == ZW_CAT_SHIELDING;
    plan1(&p, Z0, T1, "1", NULL);
    bool zt = zw_send_category(&p) == ZW_CAT_DESHIELD;
    plan1(&p, T1, T2, "1", NULL);
    bool tt = zw_send_category(&p) == ZW_CAT_PUBLIC;
    CHECK("four categories: z->z private, t->z shielding, z->t de-shield, t->t public", zz && tz && zt && tt);
    plan1(&p, Z0, "zs1notarealaddress", "1", NULL);
    CHECK("an unrecognised recipient counts as public (fail safe: de-shield from z)",
          zw_send_category(&p) == ZW_CAT_DESHIELD);
    CHECK("four confirm titles", !strcmp(zw_send_confirm_title(ZW_CAT_PRIVATE), "Confirm private transaction") &&
          !strcmp(zw_send_confirm_title(ZW_CAT_SHIELDING), "Confirm shielding transaction") &&
          !strcmp(zw_send_confirm_title(ZW_CAT_PUBLIC), "Confirm public transaction") &&
          !strcmp(zw_send_confirm_title(ZW_CAT_DESHIELD), "Confirm DE-SHIELD (public) transaction"));
    enum gui_style st;
    plan1(&p, Z0, "", "", NULL);
    bool rest = !strcmp(zw_send_badge(&p, &st), "Set who you are paying to see if this send is private");
    plan1(&p, Z0, T1, "", NULL);
    const char *b = zw_send_badge(&p, &st);
    CHECK("badge: resting text, then the de-shield verdict in red", rest && st == GS_BADGE_DANGER &&
          strstr(b, "De-shield \xE2\x80\x94 this leaves your private balance and becomes public forever"));
}

static bool validates_to(const struct zw_send_plan *p, const struct zw_funds *f, bool syncing, const char *want)
{
    char err[400];
    bool ok = zw_send_validate(p, f, syncing, false, err, sizeof(err));
    if (want) return !ok && !strcmp(err, want);
    return ok;
}

static void sv_validation(void)
{
    struct zw_send_plan p;
    struct zw_funds f = { true, 1625000000, 1600000000 };
    plan1(&p, "", T1, "1", NULL);
    CHECK("1. From Address is Invalid", validates_to(&p, &f, false, "From Address is Invalid"));
    plan1(&p, Z0, "", "1", NULL);
    CHECK("2a. Recipient Address is Invalid (empty)", validates_to(&p, &f, false, "Recipient Address is Invalid"));
    plan1(&p, Z0, "t1nope", "1", NULL);
    CHECK("2b. Recipient Address %1 is Invalid", validates_to(&p, &f, false, "Recipient Address t1nope is Invalid"));
    plan1(&p, Z0, T1, "99.123456789", NULL);
    CHECK("3. Amount '%1' is invalid!", validates_to(&p, &f, false, "Amount '99.123456789' is invalid!"));
    plan1(&p, Z0, T1, "", NULL);
    CHECK("4. Enter an amount greater than 0", validates_to(&p, &f, false,
          "Enter an amount greater than 0 for each recipient."));
    plan1(&p, Z0, T1, "16.1", NULL);
    CHECK("5a. still confirming", validates_to(&p, &f, false, "0.1001 ZCL of these funds is still confirming (about a "
          "few minutes). You can shield or send it as soon as it confirms."));
    plan1(&p, Z0, T1, "20", NULL);
    CHECK("5b. Not enough funds", validates_to(&p, &f, false, "Not enough funds. You're trying to send 20.0001 ZCL "
          "(including the fee), but this address only holds 16.25 ZCL."));
    CHECK("5c. no funds check while syncing", validates_to(&p, &f, true, NULL));
    struct zw_funds tight = { true, 12000000, 12000000 };
    plan1(&p, Z0, T1, "0.1199", NULL);
    CHECK("integer-zatoshi guard: 0.1199 + 0.0001 against 0.12 passes", validates_to(&p, &tight, false, NULL));
    plan1(&p, Z0, T1, "0.11990001", NULL);
    CHECK("one zatoshi more does not", !validates_to(&p, &tight, false, NULL));
    struct zw_funds unknown = { false, 0, 0 };
    plan1(&p, Z0, T1, "5", NULL);
    CHECK("an address with no balance row is left to the node", validates_to(&p, &unknown, false, NULL));
}

static void sv_params(void)
{
    struct zw_send_plan p;
    char out[4096], memo[2 * ZW_MEMO_MAX + 2];
    plan1(&p, Z0, " " T1 " ", "1.50", "ignored for t");
    bool keyed = zw_send_params(&p, "zq-KEY", out, sizeof(out)) &&
                 !strcmp(out, "[\"" Z0 "\",[{\"address\":\"" T1 "\",\"amount\":\"1.5\"}],1,0.0001,\"zq-KEY\"]");
    bool plain = zw_send_params(&p, NULL, out, sizeof(out)) &&
                 !strcmp(out, "[\"" Z0 "\",[{\"address\":\"" T1 "\",\"amount\":\"1.5\"}]]");
    CHECK("z_sendmany params byte-exact, keyed and unkeyed; no memo to a t-address", keyed && plain);
    plan1(&p, Z0, Z1, "0.001", "  hi \xC3\xA9\n");
    CHECK("memo: the trimmed UTF-8 as lowercase hex", zw_send_params(&p, NULL, out, sizeof(out)) &&
          !strcmp(out, "[\"" Z0 "\",[{\"address\":\"" Z1 "\",\"amount\":\"0.001\",\"memo\":\"686920c3a9\"}]]"));
    char big[ZW_MEMO_MAX + 2];
    memset(big, 'm', ZW_MEMO_MAX);
    big[ZW_MEMO_MAX] = 0;
    plan1(&p, Z0, Z1, "1", big);
    bool at_limit = zw_memo_hex(&p.to[0], memo, sizeof(memo)) && strlen(memo) == 2 * ZW_MEMO_MAX;
    CHECK("a 512-byte memo is encoded whole", at_limit);
    plan1(&p, "t1\"quote", T1, "1", NULL);
    CHECK("a from-address that needs escaping is refused, not escaped", !zw_send_params(&p, NULL, out, sizeof(out)));
    char totals[160];
    plan1(&p, Z0, T1, "1.5", NULL);
    zw_send_totals(&p, false, totals, sizeof(totals));
    CHECK("totals line", !strcmp(totals, "You'll send 1.5 ZCL + 0.0001 ZCL fee = 1.5001 ZCL"));
}

static void sv_flow(void)
{
    struct zw_rpc_error e = { -28, ZW_ERR_RPC, "Loading wallet..." };
    char msg[256];
    CHECK("warming answer to a keyed call is ambiguous (ask again with the key)",
          zw_flow_classify(ZW_ERR_RPC, &e, true, true, msg, sizeof(msg)) == ZW_CALL_AMBIGUOUS);
    struct zw_rpc_error old = { -1, ZW_ERR_RPC, "z_sendmany fromaddress amounts ( minconf ) ( fee )" };
    CHECK("usage text without idempotency_key: the node does not take the key",
          zw_flow_classify(ZW_ERR_RPC, &old, true, true, msg, sizeof(msg)) == ZW_CALL_KEY_UNSUPPORTED);
    CHECK("no connection on the first call is definitive; later it is ambiguous",
          zw_flow_classify(ZW_ERR_REFUSED, &e, true, true, msg, sizeof(msg)) == ZW_CALL_DEFINITIVE &&
          zw_flow_classify(ZW_ERR_REFUSED, &e, true, false, msg, sizeof(msg)) == ZW_CALL_AMBIGUOUS &&
          zw_flow_classify(ZW_ERR_TIMEOUT, &e, true, true, msg, sizeof(msg)) == ZW_CALL_AMBIGUOUS);
    struct zw_queue_entry q = { .present = true };
    struct zw_journal_entry j = { .present = true };
    struct zw_verdict v;
    snprintf(q.status, sizeof(q.status), "failed");
    snprintf(j.state, sizeof(j.state), "outcome_unknown");
    zw_flow_resolve(true, &q, true, &j, &v);
    CHECK("a keyed send whose queue says failed but journal says outcome_unknown is never 'failed'",
          v.state == ZW_FLOW_UNKNOWN && !strcmp(v.text, ZW_TXT_UNKNOWN));
    struct zw_queue_entry gone = { .present = false };
    zw_flow_resolve(false, &gone, false, &j, &v);
    CHECK("an unkeyed send the node forgot is 'lost', with a next step", v.state == ZW_FLOW_LOST &&
          strstr(v.text, "Check your transactions before sending again"));
    CHECK("humane errors: insufficient, locked, coinbase", strstr(zw_flow_humane("Insufficient funds"), "enough "
          "confirmed ZCL") && strstr(zw_flow_humane("Error: Please enter the wallet passphrase with "
          "walletpassphrase first."), "locked") && strstr(zw_flow_humane("Coinbase funds can only be sent to a zaddr"),
          "Mined (coinbase)"));
    char k1[ZW_SEND_KEY_MAX], k2[ZW_SEND_KEY_MAX];
    bool keys = zw_flow_new_key(k1) && zw_flow_new_key(k2);
    CHECK("keys: zq- plus 32 base62, never repeated", keys && strlen(k1) == 35 && !strncmp(k1, "zq-", 3) &&
          strcmp(k1, k2));
    CHECK("retry pace 1, 2, 4, 8, then 15 s", zw_flow_retry_delay_ms(1, 1000) == 1000 &&
          zw_flow_retry_delay_ms(4, 1000) == 8000 && zw_flow_retry_delay_ms(9, 1000) == 15000);
}

/* ---- the runner against the mock node ---- */

struct node {
    struct zw_mock *mock;
    uint16_t port;
    char dir[128];
    struct zw_options opt;
    struct zw_model m;
};

static bool node_up(struct node *n, const char *scenario, const char *tag, bool legacy)
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
    n->opt.profile = legacy ? ZW_PROFILE_ZCLASSICD : ZW_PROFILE_Z23;
    if (legacy) {
        write_file(n->dir, "zclassic.conf", "rpcuser=u\nrpcpassword=p\n");
        zw_mock_set_auth(n->mock, "u:p");
    }
    zw_model_init(&n->m, n->opt.profile);
    struct zw_rpc *r = calloc(1, sizeof(*r));
    if (!r) return false;
    r->opt = &n->opt;
    for (enum zw_query q = 0; q < ZW_Q_COUNT; q++) {
        struct zw_result res;
        memset(&res, 0, sizeof(res));
        zw_query_run(r, q, &res);
        zw_model_apply(&n->m, &res);
    }
    zw_endpoint_wipe(&r->ep);
    free(r);
    n->m.port = n->port;
    n->m.last_update_s = NOW_S;
    n->m.now_s = NOW_S;
    return true;
}

static void node_down(struct node *n)
{
    zw_mock_stop(n->mock);
    zw_model_free(&n->m);
}

static struct gui_window *headless(void)
{
    struct gui_window_desc d = { .title_utf8 = "t", .width = 1100, .height = 720, .surface = GUI_SURFACE_CPU,
                                 .backend = GUI_BACKEND_HEADLESS };
    struct gui_window *w = NULL;
    char err[64];
    gui_window_open(&d, &w, err, sizeof(err));
    return w;
}

static bool run_to_end(struct zw_sender *s, struct zw_send_status *st, uint32_t limit_ms)
{
    for (uint32_t t = 0; t < limit_ms && s; t += 10) {
        zw_sender_poll(s, st);
        if (zw_sender_finished(s)) { zw_sender_poll(s, st); return true; }
        platform_sleep_ms(10); /* real-clock: the runner waits on the mock node */
    }
    return false;
}

static bool runner_case(const char *scenario, bool legacy, const char *to, struct zw_send_status *st,
                        unsigned *requests, char *seen_probe, size_t cap)
{
    struct node n;
    struct gui_window *w = headless();
    bool ok = w && node_up(&n, scenario, scenario, legacy);
    if (!ok) { if (w) gui_window_close(w); return false; }
    struct zw_send_plan p;
    plan1(&p, Z0, to, "1.5", NULL);
    char keyed[2048], plain[2048];
    ok = zw_send_params(&p, "zq-TESTKEY0000000000000000000000000", keyed, sizeof(keyed)) &&
         zw_send_params(&p, NULL, plain, sizeof(plain));
    struct zw_sender *s = ok ? zw_sender_start(w, &n.opt, &n.m, keyed, plain) : NULL;
    ok = run_to_end(s, st, 8000);
    zw_sender_free(s);
    *requests = zw_mock_request_count(n.mock);
    if (seen_probe) snprintf(seen_probe, cap, "%d", zw_mock_saw(n.mock, "\"params\":[\"" Z0 "\",[{\"address\":\"" T1
                             "\",\"amount\":\"1.5\"}],1,0.0001,\"zq-TESTKEY0000000000000000000000000\"]") ? 1 : 0);
    node_down(&n);
    gui_window_close(w);
    return ok;
}

static void sv_runner_sent(void)
{
    struct zw_send_status st;
    unsigned req;
    char exact[8];
    bool done = runner_case("send_success", true, T1, &st, &req, exact, sizeof(exact));
    CHECK("legacy: keyed z_sendmany byte-exact, then status polled to the txid",
          done && st.phase == ZW_SP_SENT && !strcmp(st.txid, TX) && !strcmp(st.opid, OPID) && exact[0] == '1');
    done = runner_case("send_conn_lost", true, T1, &st, &req, exact, sizeof(exact));
    CHECK("connection lost mid-send: the same key again, sent once", done && st.phase == ZW_SP_SENT && exact[0] == '1');
    done = runner_case("send_warming", true, T1, &st, &req, NULL, 0);
    CHECK("warming (-28) on a keyed call: asked again, then sent", done && st.phase == ZW_SP_SENT);
    done = runner_case("send_key_unsupported", true, T1, &st, &req, NULL, 0);
    CHECK("a node without the send key: sent once without it", done && st.phase == ZW_SP_SENT);
    done = runner_case("send_z23", false, T1, &st, &req, NULL, 0);
    CHECK("Z23 node: the keyed send answers committed with the txid", done && st.phase == ZW_SP_SENT &&
          !strcmp(st.txid, TX));
}

static void sv_runner_failed(void)
{
    struct zw_send_status st;
    unsigned req;
    bool done = runner_case("send_insufficient", true, T1, &st, &req, NULL, 0);
    CHECK("insufficient funds: the node's text, nothing repeated", done && st.phase == ZW_SP_FAILED &&
          strstr(st.raw, "Insufficient shielded funds") && strstr(zw_flow_humane(st.text), "enough confirmed ZCL"));
    done = runner_case("send_op_failed", true, T1, &st, &req, NULL, 0);
    CHECK("operation failed: the queue error after the journal is read", done && st.phase == ZW_SP_FAILED &&
          strstr(st.text, "Insufficient shielded funds") && !strcmp(st.opid, OPID));
    done = runner_case("send_malformed", true, T1, &st, &req, NULL, 0);
    CHECK("malformed replies: a broken body is asked again, a non-string answer is refused", done &&
          st.phase == ZW_SP_FAILED && !strcmp(st.text, "The node's answer to the send was not understood."));
}

static void sv_runner_executing(void)
{
    struct zw_send_status st;
    struct node n;
    struct gui_window *w = headless();
    if (w && node_up(&n, "send_executing", "send_executing", true)) {
        struct zw_send_plan p;
        char keyed[2048];
        plan1(&p, Z0, T1, "1.5", NULL);
        zw_send_params(&p, "zq-K", keyed, sizeof(keyed));
        unsigned before = zw_mock_request_count(n.mock);
        struct zw_sender *s = zw_sender_start(w, &n.opt, &n.m, keyed, keyed);
        /* Outcome, not time: wait until the send and three status polls reached the mock. */
        for (int i = 0; s && i < 1000 && zw_mock_request_count(n.mock) < before + 4; i++)
            platform_sleep_ms(10); /* real-clock: the runner polls the mock node over loopback */
        zw_sender_poll(s, &st);
        bool polled = s && zw_mock_request_count(n.mock) >= before + 4 && st.phase == ZW_SP_PROGRESS &&
                      !zw_sender_finished(s);
        zw_sender_free(s);
        CHECK("still executing: progress text, not finished, polling", polled && !strcmp(st.text, ZW_TXT_SENDING));
        node_down(&n);
    }
    if (w) gui_window_close(w);
}

static void sv_allowlist(void)
{
    struct node n;
    if (!node_up(&n, "send_success", "allow", true)) { CHECK("mock up", false); return; }
    struct zw_rpc *r = calloc(1, sizeof(*r));
    if (!r) return;
    r->opt = &n.opt;
    struct json_value v;
    struct zw_rpc_error e;
    json_init(&v);
    unsigned before = zw_mock_request_count(n.mock);
    enum zw_err a = zw_rpc_call(r, "z_sendmany", "[]", &v, &e);
    enum zw_err b = zw_rpc_call(r, "sendtoaddress", "[]", &v, &e);
    CHECK("a read client cannot send z_sendmany, and sendtoaddress stays off the zclassicd allowlist; no bytes sent",
          a == ZW_ERR_RPC && b == ZW_ERR_RPC && zw_mock_request_count(n.mock) == before);
    CHECK("the allowlist gained exactly the Send calls", zw_rpc_legacy_allowed("z_sendmany") &&
          zw_rpc_legacy_allowed("z_getoperationstatus") && zw_rpc_legacy_allowed("z_listsendjournal") &&
          !zw_rpc_legacy_allowed("sendtoaddress") && !zw_rpc_legacy_allowed("z_getnewaddress") &&
          !zw_rpc_legacy_allowed("z_getoperationresult"));
    json_free(&v);
    zw_endpoint_wipe(&r->ep);
    free(r);
    node_down(&n);
}

/* ---- the page ---- */

struct page {
    struct node n;
    struct gui_window *win;
    struct gui_tree *t;
    struct gui_ui *ui;
    struct zw_send *s;
    struct zw_send_env env;
    int shots;
};

static void page_frame(struct page *p, const char *shot)
{
    zw_send_sync(p->s, &p->env);
    zw_shell_build(p->t, &p->n.m, ZW_SCREEN_SEND);
    char err[96];
    if (!gui_tree_end(p->t, err, sizeof(err))) printf("    tree: %s\n", err);
    gui_ui_rebind(p->ui);
    zw_model_publish(&p->n.m, p->ui, NOW_S);
    int32_t w, h;
    gui_window_size(p->win, &w, &h, NULL);
    gui_ui_layout(p->ui, w, h);
    struct gui_cpu_frame f;
    gui_cpu_acquire(p->win, &f);
    struct gui_surface surf = gui_surface_from_frame(&f);
    gui_ui_paint(p->ui, &surf, NULL, 0);
    const char *dir = getenv("ZW_SEND_SHOTS");
    if (dir && dir[0] && shot) {
        char path[600];
        snprintf(path, sizeof(path), "%s/%02d_%s.png", dir, ++p->shots, shot);
        gui_frame_write_png(&f, path);
    }
}

static bool page_up(struct page *p, const char *scenario, bool legacy, float scale)
{
    memset(p, 0, sizeof(*p));
    p->win = headless();
    if (!p->win || !node_up(&p->n, scenario, scenario, legacy)) return false;
    gui_headless_set_size(p->win, (int32_t)(1100 * scale), (int32_t)(720 * scale), scale);
    p->t = gui_tree_new();
    p->ui = gui_ui_new(p->t);
    p->s = zw_send_new();
    if (!p->t || !p->ui || !p->s) return false;
    gui_ui_set_window(p->ui, p->win);
    gui_ui_set_scale(p->ui, scale);
    zw_home_sources(p->ui, &p->n.m);
    p->n.m.send = p->s;
    p->env = (struct zw_send_env){ p->win, p->ui, &p->n.m, &p->n.opt, NOW_S };
    page_frame(p, NULL);
    return true;
}

static void page_down(struct page *p)
{
    zw_send_free(p->s);
    p->n.m.send = NULL;
    gui_ui_free(p->ui);
    gui_tree_free(p->t);
    if (p->n.mock) node_down(&p->n);
    if (p->win) gui_window_close(p->win);
    memset(p, 0, sizeof(*p));
}

static void act(struct page *p, const char *name, const char *shot)
{
    struct zw_send_out out;
    zw_send_action(p->s, &p->env, name, &out);
    page_frame(p, shot);
}

static void type(struct page *p, const char *id, const char *text)
{
    gui_ui_input_set(p->ui, id, text);
    page_frame(p, NULL);
}

static bool press_enter(struct page *p)
{
    struct gui_event ev = { .type = GUI_EV_KEY, .key = { GUI_KEY_ENTER, 0, true, false } };
    struct gui_action a;
    if (!gui_ui_event(p->ui, &ev, &a)) return false;
    act(p, a.name, NULL);
    return true;
}

static bool has_node(const struct page *p, const char *id) { return gui_tree_find(p->t, id) >= 0; }

static bool node_disabled(const struct page *p, const char *id)
{
    int at = gui_tree_find(p->t, id);
    return at >= 0 && (p->t->nodes[at].flags & GUI_F_DISABLED);
}

static bool node_style(const struct page *p, const char *id, enum gui_style s)
{
    int at = gui_tree_find(p->t, id);
    return at >= 0 && p->t->nodes[at].style == s;
}

static const char *node_label(const struct page *p, const char *id)
{
    int at = gui_tree_find(p->t, id);
    return at < 0 ? "" : gui_tree_text(p->t, &p->t->nodes[at]);
}

/* Empty page, the first validation, then a filled de-shield form. */
static void page_review(struct page *p)
{
    page_frame(p, "send_empty");
    CHECK("default pay-from is the z-address with the most", !strcmp(zw_send_form(p->s)->from, Z0));
    CHECK("available to send: confirmed, with the confirming part",
          strstr(p->s->view.avail, "12.5 ZCL (+0.25 ZCL confirming)") != NULL);
    act(p, "send.review", "send_error_recipient");
    CHECK("review with no recipient: Transaction Error, Recipient Address is Invalid",
          !strcmp(zw_send_dialog_title(p->s), "Transaction Error") &&
          strstr(p->s->dlg_body, "Recipient Address is Invalid") && has_node(p, "s_err"));
    act(p, "send.close", NULL);
    type(p, "s_addr1", T1);
    type(p, "s_amt1", "1.5");
    CHECK("valid address border; memo button off for a t-address; de-shield badge",
          node_style(p, "s_addr1", GS_INPUT_VALID) && node_disabled(p, "s_memo1") &&
          p->s->view.badge_style == GS_BADGE_DANGER);
    page_frame(p, "send_filled_deshield");
}

/* The confirm dialog: Cancel is the default and has focus. */
static void page_confirm(struct page *p)
{
    act(p, "send.review", "send_confirm_deshield");
    int at = gui_tree_find(p->t, "sc_send");
    CHECK("confirm dialog: de-shield title, Cancel focused, the send button names the amount and is not default",
          has_node(p, "s_conf") && !strcmp(zw_send_dialog_title(p->s), "Confirm DE-SHIELD (public) transaction") &&
          !strcmp(p->ui->focus, "sc_cancel") && strstr(node_label(p, "sc_send"), "Send 1.5 ZCL") && at >= 0 &&
          !(p->t->nodes[at].flags & GUI_F_DEFAULT));
    CHECK("the From address is shown whole", strstr(node_label(p, "sc_from_addr"), "qpq6d8g") != NULL);
    CHECK("Enter in the confirm dialog cancels; nothing is sent",
          press_enter(p) && p->s->dlg == ZW_DLG_NONE && !p->s->runner);
}

/* De-shield acknowledgement, one send however often it is confirmed, the card. */
static void page_send(struct page *p)
{
    act(p, "send.review", NULL);
    act(p, "send.confirm.go", "send_deshield_ack");
    CHECK("de-shield needs the extra acknowledgement, default No",
          !strcmp(zw_send_dialog_title(p->s), "De-shield to a public address?") && !strcmp(p->ui->focus, "sd_no") &&
          !p->s->runner);
    act(p, "send.deshield.yes", "send_sending");
    act(p, "send.deshield.yes", NULL);
    act(p, "send.confirm.go", NULL);
    CHECK("confirmed once: the runner started, the form cleared, repeats do nothing",
          p->s->runner && !zw_send_form(p->s)->to[0].addr[0] && p->s->dlg == ZW_DLG_NONE);
    struct zw_send_out out = { .dirty = false };
    for (int i = 0; i < 400 && !p->s->card; i++) {
        platform_sleep_ms(10); /* real-clock: the runner talks to the mock node */
        zw_send_wake(p->s, &p->env, &out);
    }
    page_frame(p, "send_sent_card");
    CHECK("sent: the card and the txid status message", p->s->card && has_node(p, "s_card") &&
          strstr(out.msg, "Tx submitted (right click to copy) txid: " TX) != NULL);
}

static void sv_page_flow(void)
{
    struct page p;
    if (!page_up(&p, "send_success", true, 1.0f)) { CHECK("page up", false); page_down(&p); return; }
    struct zw_chain original = p.n.m.chain;
    snprintf(p.n.m.chain.chain, sizeof(p.n.m.chain.chain), "test");
    page_frame(&p, NULL);
    CHECK("reported testnet updates recipient, fee and available funds on an ordinary endpoint",
          !p.n.m.testnet && !strcmp(node_label(&p, "s_r1_unit"), "ZCT") &&
          !strcmp(node_label(&p, "s_fee_unit"), "ZCT") && strstr(p.s->view.avail, "12.5 ZCT"));
    p.n.m.testnet = true;
    snprintf(p.n.m.chain.chain, sizeof(p.n.m.chain.chain), "regtest");
    page_frame(&p, NULL);
    CHECK("reported regtest uses ZCL for recipient, fee and available funds on a test endpoint",
          !strcmp(node_label(&p, "s_r1_unit"), "ZCL") && !strcmp(node_label(&p, "s_fee_unit"), "ZCL") &&
          strstr(p.s->view.avail, "12.5 ZCL"));
    p.n.m.testnet = false;
    p.n.m.chain = original;
    page_review(&p);
    page_confirm(&p);
    page_send(&p);
    page_down(&p);
}

static void page_review_handover(void)
{
    struct page p;
    if (!page_up(&p, "send_success", true, 1.0f)) { CHECK("handover page fixture", false); return; }
    type(&p, "s_addr1", T1);
    type(&p, "s_amt1", "1.5");
    act(&p, "send.review", NULL);
    CHECK("review is bound before a node handover", p.s->dlg == ZW_DLG_CONFIRM && p.s->review_bound);
    struct node replacement;
    if (!node_up(&replacement, "send_z23", "send_replacement", false)) {
        CHECK("replacement node starts", false);
        page_down(&p);
        return;
    }
    unsigned old_calls = zw_mock_request_count(p.n.mock);
    unsigned replacement_calls = zw_mock_request_count(replacement.mock);
    p.n.m.profile = replacement.m.profile;
    p.n.m.port = replacement.port;
    snprintf(p.n.m.datadir, sizeof(p.n.m.datadir), "%s", replacement.m.datadir);
    ++p.n.m.generation;
    p.env.o = &replacement.opt;
    act(&p, "send.confirm.go", NULL);
    CHECK("handover closes and invalidates the old confirmation", p.s->dlg == ZW_DLG_NONE && !p.s->review_bound);
    CHECK("handover clears the pending plan without starting a runner", !p.s->pending.n && !p.s->runner);
    CHECK("no commit reaches either the old or replacement node",
          zw_mock_request_count(p.n.mock) == old_calls && zw_mock_request_count(replacement.mock) == replacement_calls);
    node_down(&replacement);
    page_down(&p);
}

/* Syncing: the gate, a memo, a second recipient, Discard, a look-alike. */
static void page_syncing(struct page *p)
{
    type(p, "s_addr1", Z1);
    type(p, "s_amt1", "1");
    act(p, "send.review", "send_sync_gate");
    CHECK("syncing: the gate 'Wallet still syncing', default No",
          !strcmp(zw_send_dialog_title(p->s), "Wallet still syncing") && !strcmp(p->ui->focus, "sg_no") &&
          strstr(p->s->dlg_body, "Send anyway?"));
    CHECK("Enter on the gate answers No; nothing is sent",
          press_enter(p) && p->s->dlg == ZW_DLG_NONE && !p->s->runner);
    act(p, "send.memo.1", "send_memo");
    type(p, "s_memo_edit", "thanks for lunch");
    act(p, "send.memo.ok", "send_memo_preview");
    CHECK("memo for a z-address: kept and previewed",
          !strcmp(zw_send_form(p->s)->to[0].memo, "thanks for lunch") && has_node(p, "s_r1_memo"));
    act(p, "send.add", NULL);
    CHECK("Add Recipient adds a second box", has_node(p, "s_addr2") && p->s->view.nrcpt == 2);
    act(p, "send.cancel", "send_discard");
    CHECK("Cancel with typed input asks 'Discard this payment?' (default No)",
          !strcmp(zw_send_dialog_title(p->s), "Discard this payment?") && !strcmp(p->ui->focus, "sx_no"));
    act(p, "send.discard.yes", NULL);
    CHECK("Discard clears the form", !zw_send_form(p->s)->to[0].addr[0] && p->s->view.nrcpt == 1);
    type(p, "s_addr1", "t1KRqXXXXXXXXXXXXXXXXXXXXXXXXXZKcQB");
    page_frame(p, "send_lookalike");
    CHECK("look-alike warning under the field", p->s->view.look[0][0] && has_node(p, "s_r1_look"));
}

/* At 175%: the pay-from list, Send all, the not-connected box. */
static void page_from_and_max(struct page *p)
{
    act(p, "send.from", "send_from_popup_175");
    CHECK("pay-from list lists every funded address", has_node(p, "s_from_pop") && p->s->view.nfrom == 2);
    for (size_t i = 0; i < ZW_FROM_ITEMS; i++) {
        if (strcmp(p->s->from_addr[i], T1)) continue;
        char name[32];
        snprintf(name, sizeof(name), "send.from.%zu", i + 1);
        act(p, name, NULL);
    }
    type(p, "s_amt1", "0");
    CHECK("choosing the t-address; zero amount gets the invalid border",
          !strcmp(zw_send_form(p->s)->from, T1) && node_style(p, "s_amt1", GS_INPUT_INVALID));
    act(p, "send.max", "send_max_175");
    CHECK("Send all: spendable minus the fee, read-only",
          !strcmp(zw_send_form(p->s)->to[0].amount, "3.3999") && node_disabled(p, "s_amt1"));
    p->n.m.conn = ZW_CONN_REFUSED;
    act(p, "send.review", "send_not_connected_175");
    CHECK("not connected: 'Not connected yet'", !strcmp(zw_send_dialog_title(p->s), "Not connected yet"));
}

static void sv_page_states(void)
{
    struct page p;
    if (page_up(&p, "send_syncing", true, 1.0f)) page_syncing(&p);
    page_down(&p);
    if (page_up(&p, "send_success", true, 1.75f)) page_from_and_max(&p);
    page_down(&p);
}

static bool home_shield_discovery(struct page *p)
{
    struct zw_model *m = &p->n.m;
    free(m->rcv.list);
    m->rcv.list = NULL;
    if (!m->bal) { CHECK("Home balances supplied", false); return false; }
    size_t funded_rows = m->bal->n;
    m->bal->n = 0;
    unsigned rpc_before = zw_mock_request_count(p->n.mock);
    CHECK("fresh empty balances need no address query", !zw_shield_source(m->bal) &&
          zw_send_home_shield(p->s, &p->env, NULL) == ZW_SHIELD_EMPTY &&
          zw_mock_request_count(p->n.mock) == rpc_before);
    m->bal->n = funded_rows;
    CHECK("funded Home asks for a read-only address list", zw_send_home_shield(p->s, &p->env, NULL) == ZW_SHIELD_READ &&
          zw_mock_request_count(p->n.mock) == rpc_before);
    ++m->generation;
    CHECK("Home discovery after identity reset cannot create or spend",
          zw_send_home_shield(p->s, &p->env, NULL) == ZW_SHIELD_READ && !m->rcv.creating &&
          zw_mock_request_count(p->n.mock) == rpc_before);
    m->rcv.list = calloc(1, sizeof(*m->rcv.list));
    if (!m->rcv.list || !m->bal) {
        CHECK("shield balances allocated", false);
        free(m->rcv.list);
        m->rcv.list = NULL;
        return false;
    }
    return true;
}

static void home_shield_form(struct page *p)
{
    struct zw_model *m = &p->n.m;
    m->bal->n = 2;
    m->bal->rows[0] = (struct zw_bal_row){.addr = T1, .kind = ZW_ADDR_PUBLIC, .zat = 900000000};
    m->bal->rows[1] = (struct zw_bal_row){.addr = T2, .kind = ZW_ADDR_PUBLIC, .zat = 200000000,
                                           .confirmed_zat = 200000000};
    m->rcv.list->rows[0] = (struct zw_bal_row){.addr = ZC, .kind = ZW_ADDR_SPROUT};
    m->rcv.list->n = 1;
    CHECK("Sprout-only wallet requests Sapling provisioning", zw_send_home_shield(p->s, &p->env, NULL) == ZW_SHIELD_CREATE);
    m->rcv.list->rows[1] = (struct zw_bal_row){.addr = Z0, .kind = ZW_ADDR_SAPLING};
    m->rcv.list->n = 2;
    CHECK("shield selects largest confirmed and first Sapling", zw_send_home_shield(p->s, &p->env, NULL) == ZW_SHIELD_READY &&
          !strcmp(p->s->form.from,T2) && !strcmp(p->s->form.to[0].addr,Z0) && p->s->max_on);
    page_frame(p, NULL);
    char expected[40];
    zw_decimal(200000000 - ZW_DEFAULT_FEE, expected, sizeof(expected));
    CHECK("shield Max deducts ordinary fee and waits for user review", !strcmp(p->s->form.to[0].amount,expected) &&
          p->s->dlg == ZW_DLG_NONE && !p->s->pend.active && !p->s->runner);
    zw_send_cancel_review(p->s, p->ui);
    CHECK("leaving Send immediately clears shield recipient and Max", !p->s->form.to[0].addr[0] && !p->s->max_on);
    page_frame(p, NULL);
    CHECK("handover removes prior shield recipient and Max", !p->s->form.to[0].addr[0] && !p->s->max_on);
    CHECK("immediate repeated Shield is not busy", zw_send_home_shield(p->s,&p->env,Z0) == ZW_SHIELD_READY);
    zw_send_cancel_review(p->s, p->ui);
    zw_send_prefill_from(p->s, T1);
    page_frame(p, NULL);
    CHECK("explicit Home source survives the next sync", !strcmp(p->s->form.from,T1));
    m->bal->rows[1].confirmed_zat = 0;
    CHECK("with only unconfirmed public funds choose largest displayed", zw_send_home_shield(p->s,&p->env,Z1) == ZW_SHIELD_READY &&
          !strcmp(p->s->form.from,T1) && !strcmp(p->s->form.to[0].addr,Z1));
    zw_send_clear_form(p->s,p->ui);
    m->bal->rows[0].zat = m->bal->rows[1].zat = 10;
    CHECK("dust opens Send without preparing a doomed payment", zw_send_home_shield(p->s,&p->env,NULL) == ZW_SHIELD_EMPTY);
    p->s->pend.active = true;
    CHECK("shield never replaces an unresolved payment", zw_send_home_shield(p->s,&p->env,NULL) == ZW_SHIELD_BUSY && !p->s->runner);
    p->s->pend.active = false;
}

static void home_shield_draft(void)
{
    struct page p;
    if (!page_up(&p, "send_success", true, 1.0f)) { CHECK("shield preview fixture", false); return; }
    if (!home_shield_discovery(&p)) { page_down(&p); return; }
    home_shield_form(&p);
    struct zw_model *m = &p.n.m;
    free(m->rcv.list);
    m->rcv.list = NULL;
    page_down(&p);
}

int test_z23wallet_send(void)
{
    printf("\n=== z23wallet_send ===\n");
    g_fail = 0;
    mkdirs(TMP);
    sv_addresses();
    sv_address_rules();
    sv_amounts();
    sv_categories();
    sv_validation();
    sv_params();
    sv_flow();
    sv_allowlist();
    struct zw_sender_timing fast = { 10, 20, 3000, 3000, 4000 };
    zw_sender_set_timing(&fast);
    sv_runner_sent();
    sv_runner_failed();
    sv_runner_executing();
    sv_page_flow();
    page_review_handover();
    sv_page_states();
    home_shield_draft();
    return g_fail;
}
