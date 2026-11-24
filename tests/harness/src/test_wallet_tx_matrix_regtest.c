/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * wallet_tx_matrix_regtest: every kind of wallet transaction, end to end,
 * through the node calls a wallet front end makes, on one isolated regtest
 * node holding no real funds.
 *
 * The node and its command runner are tests/harness/include/test/
 * regtest_node_fixture.h. Funding is mined, never spent from anywhere: five
 * blocks to the wallet's own transparent address, then a hundred to a foreign
 * address so the five coinbases are mature and every later block leaves the
 * wallet's balance alone. Every amount below is integer zatoshi.
 *
 *   t->t      core.wallet.transaction.send plan and commit; pending (0
 *             confirmations) then 1 then 3 confirmations
 *   t->z      core.wallet.shielded.send from a transparent address, text memo
 *   z->z      text memo (UTF-8, multi-byte); a memo that is not UTF-8, sent
 *             as memo_hex; the same commit repeated on its idempotency key
 *   z->t      de-shielding
 *   multi     legacy z_sendmany with transparent and shielded recipients
 *   max       amount = balance - fee from a shielded and a transparent address
 *   refusals  insufficient funds, invalid address, memo to a transparent
 *             recipient, zero amount: each must fail and change no balance
 *   legacy    the legacy-compatible methods of the node's RPC table that a
 *             legacy front end uses, with the refusal for each one missing
 *   lock      a send committed with the wallet locked is refused
 *
 * Every call's request and reply are checked against the sanitized reply the
 * regtest node gave, kept under tests/fixtures/z23wallet/regtest_shapes/: the
 * reply's field names and value types must match. ZCL_REGTEST_SHAPES_RECORD=1
 * rewrites those files from the live replies instead (a reviewed change).
 *
 * Absent proving parameters or an absent binary are reported UNOBSERVED, the
 * way wallet_e2e_regtest reports them.
 *
 * make t-fast ONLY=wallet_tx_matrix_regtest */

#include "test/regtest_node_fixture.h"
#include "sapling/params_init.h"
#include "sapling/sapling_prover.h"

#define WTM_SHAPES "tests/fixtures/z23wallet/regtest_shapes"
#define WTM_FEE 100LL
#define WTM_COIN 100000000LL
#define WTM_FUND_BLOCKS 5
#define WTM_MATURE_BLOCKS 100
#define WTM_SPENDABLE_CONFS 10
#define WTM_MINE_CHUNK 20
#define WTM_DOC (512 * 1024)
/* Valid regtest addresses whose keys exist in no wallet of this test: the
 * foreign miner and the foreign recipients. */
#define WTM_FOREIGN_T "tmJ3riuRtngp6NzgJoFHG5Sz328zZWjLXRj"
#define WTM_FOREIGN_Z "zregtestsapling192cj4j4ezaat2n623rgt0c4cnxxx8mt58njyl6g6cqf5el37fdkx695efj4rxc3gqrdpjmp4jdy"

struct wtm {
    struct rnf n;
    char t1[128], t2[128], za[256], zb[256];
    bool record;
    long shapes_checked;
};

struct reply {
    int rc;
    bool parsed;      /* the output is one JSON document */
    bool ok;          /* exit 0 and no error member or error text */
    struct json_value doc;
    char raw[RNF_RAW];
};

static struct reply wtm_r; /* the one live reply; valid until the next call */

/* ── reply shapes: field names and value types, never values ──────── */

struct sb {
    char *p;
    size_t cap, len;
};

static void sb_add(struct sb *s, const char *t)
{
    for (; *t && s->len + 1 < s->cap; t++) s->p[s->len++] = *t;
    s->p[s->len] = '\0';
}

static void shape_of(const struct json_value *v, struct sb *s)
{
    static const char *const scalar[] = { [JSON_NULL] = "null",
        [JSON_BOOL] = "bool", [JSON_INT] = "number", [JSON_REAL] = "number",
        [JSON_STR] = "string" };
    if (v->type != JSON_ARR && v->type != JSON_OBJ) {
        sb_add(s, scalar[v->type]);
        return;
    }
    bool obj = v->type == JSON_OBJ;
    sb_add(s, obj ? "{" : "[");
    for (size_t i = 0; i < v->num_children && (obj || i == 0); i++) {
        if (obj) {
            sb_add(s, v->keys[i]);
            sb_add(s, ":");
        }
        shape_of(&v->children[i], s);
        if (obj) sb_add(s, ",");
    }
    sb_add(s, obj ? "}" : "]");
}

static void reply_shape(const struct reply *r, char *out, size_t cap)
{
    struct sb s = { out, cap, 0 };
    out[0] = '\0';
    if (r->parsed) shape_of(&r->doc, &s);
    else sb_add(&s, "text");
}

/* ── one node call, recorded or checked against its fixture ───────── */

static bool wtm_text_error(const char *raw)
{
    return strncmp(raw, "Error", 5) == 0 || strncmp(raw, "error=", 6) == 0;
}

/* The output is one JSON document when it starts like one, or is a bare JSON
 * scalar (a decimal balance); an `Error: ...` line is text. */
static bool reply_parse(struct reply *r, const char *p)
{
    size_t n = strlen(p);
    json_init(&r->doc);
    if (*p == '{' || *p == '[') return json_read(&r->doc, p, n);
    return *p && *p != 'E' && json_valid(p, n) && json_read(&r->doc, p, n);
}

static void reply_load(struct reply *r)
{
    const char *p = r->raw;
    while (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t') p++;
    r->parsed = reply_parse(r, p);
    const struct json_value *flag = r->parsed && r->doc.type == JSON_OBJ
                                        ? json_get(&r->doc, "ok") : NULL;
    r->ok = r->rc == 0 && !wtm_text_error(p) &&
            !(flag && !json_get_bool(flag));
}

static void reply_free(struct reply *r)
{
    json_free(&r->doc);
    json_init(&r->doc);
    r->parsed = false;
}

/* Replace every occurrence of `from` in buf with `to`. */
static void wtm_replace(char *buf, size_t cap, const char *from, const char *to)
{
    size_t fl = strlen(from), tl = strlen(to), len = strlen(buf);
    for (char *at = strstr(buf, from); at; at = strstr(at + tl, from)) {
        if (len - fl + tl + 1 > cap) return;
        memmove(at + tl, at + fl, strlen(at + fl) + 1);
        memcpy(at, to, tl);
        len = len - fl + tl;
    }
}

static bool wtm_fixture_path(char *path, size_t cap, const char *tag)
{
    int n = snprintf(path, cap, "%s/%s.json", WTM_SHAPES, tag);
    return n > 0 && (size_t)n < cap;
}

/* The fixture document: the request words, the exit status and the reply. */
static bool wtm_fixture_compose(const struct wtm *w, const char *tag,
                                const char *const *words,
                                const struct reply *r, char *out, size_t cap)
{
    struct json_value doc, req, body;
    json_init(&doc);
    json_init(&req);
    json_init(&body);
    json_set_object(&doc);
    json_set_array(&req);
    for (size_t i = 0; words[i]; i++) {
        struct json_value s;
        json_init(&s);
        json_set_str(&s, words[i]);
        json_push_back(&req, &s);
        json_free(&s);
    }
    if (r->parsed) json_copy(&body, &r->doc);
    else {
        size_t n = strcspn(r->raw, "\r\n");
        char line[512];
        snprintf(line, sizeof(line), "%.*s", (int)(n < 500 ? n : 500), r->raw);
        json_set_str(&body, line);
    }
    bool ok = json_push_kv_str(&doc, "case", tag) &&
              json_push_kv(&doc, "request", &req) &&
              json_push_kv_int(&doc, "exit", r->rc) &&
              json_push_kv(&doc, "reply", &body);
    size_t len = ok ? json_write(&doc, out, cap) : 0;
    json_free(&doc);
    json_free(&req);
    json_free(&body);
    if (len == 0 || len + 2 >= cap) return false;
    wtm_replace(out, cap, w->n.work, "<regtest-datadir>");
    return true;
}

static bool wtm_fixture_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (!f) return false;
    bool ok = fputs(text, f) >= 0 && fputc('\n', f) != EOF;
    return fclose(f) == 0 && ok;
}

/* The fixture's reply must have the live reply's field names and types, and
 * the same exit class. */
static bool wtm_fixture_match(const char *path, const struct reply *live)
{
    static char text[WTM_DOC];
    FILE *f = fopen(path, "r");
    if (!f) {
        printf("\n  no fixture %s (record with ZCL_REGTEST_SHAPES_RECORD=1)", path);
        return false;
    }
    size_t n = fread(text, 1, sizeof(text) - 1, f);
    fclose(f);
    text[n] = '\0';
    struct json_value fx;
    json_init(&fx);
    bool ok = json_read(&fx, text, n);
    struct reply want = { 0 };
    char a[8192], b[8192];
    if (ok) {
        const struct json_value *body = json_get(&fx, "reply");
        want.parsed = body && body->type != JSON_STR;
        if (want.parsed) json_copy(&want.doc, body);
        reply_shape(&want, a, sizeof(a));
        reply_shape(live, b, sizeof(b));
        ok = (json_get_int(json_get(&fx, "exit")) == 0) == (live->rc == 0) &&
             strcmp(a, b) == 0;
        if (!ok)
            printf("\n  shape differs from %s\n    fixture: %.600s\n    live:    %.600s",
                   path, a, b);
        if (want.parsed) json_free(&want.doc);
    }
    json_free(&fx);
    return ok;
}

static bool wtm_shape(struct wtm *w, const char *tag, const char *const *words,
                      const struct reply *r)
{
    static char out[WTM_DOC];
    char path[256];
    if (!tag) return true;
    if (!wtm_fixture_path(path, sizeof(path), tag)) return false;
    w->shapes_checked++;
    if (w->record)
        return wtm_fixture_compose(w, tag, words, r, out, sizeof(out)) &&
               wtm_fixture_write(path, out);
    return wtm_fixture_match(path, r);
}

/* Run a node command and return the live reply (valid until the next call).
 * A NULL tag records nothing. A reply whose shape differs from its fixture
 * fails the call. */
static struct reply *wtm_call_in(struct wtm *w, const char *tag,
                                 const char *const *words, const char *input)
{
    reply_free(&wtm_r);
    wtm_r.raw[0] = '\0';
    wtm_r.rc = input ? rnf_exec_stdin(&w->n, words, input, wtm_r.raw,
                                      sizeof(wtm_r.raw))
                     : rnf_exec(&w->n, words, wtm_r.raw, sizeof(wtm_r.raw));
    reply_load(&wtm_r);
    test_note("wtm %s exit=%d", tag ? tag : words[0], wtm_r.rc);
    test_note_bytes("wtm reply", wtm_r.raw, strnlen(wtm_r.raw, 4000));
    if (!wtm_shape(w, tag, words, &wtm_r)) {
        printf("\n  call %s: reply does not match its recorded shape", tag);
        wtm_r.ok = false;
        wtm_r.rc = wtm_r.rc ? wtm_r.rc : 1000;
    }
    return &wtm_r;
}

static struct reply *wtm_call(struct wtm *w, const char *tag,
                              const char *const *words)
{
    return wtm_call_in(w, tag, words, NULL);
}

#define WTM_CALL(w, tag, ...) \
    wtm_call((w), (tag), (const char *const[]){ __VA_ARGS__, NULL })

/* ── chain and wallet observations ────────────────────────────────── */

static bool wtm_mine(struct wtm *w, int blocks)
{
    for (int left = blocks; left > 0;) {
        int n = left < WTM_MINE_CHUNK ? left : WTM_MINE_CHUNK;
        if (!rnf_mine_to(&w->n, WTM_FOREIGN_T, n)) return false;
        left -= n;
    }
    return true;
}

/* The wallet's two totals, in zats, through the legacy z_gettotalbalance a
 * legacy front end shows; the transparent one must equal getbalance. */
struct totals {
    int64_t t, z;
};

static bool wtm_totals(struct wtm *w, const char *tag, struct totals *out)
{
    struct reply *r = WTM_CALL(w, tag, "z_gettotalbalance");
    bool ok = r->ok && r->parsed;
    if (ok) {
        out->t = rnf_zats(rnf_str(&r->doc, "transparent"));
        out->z = rnf_zats(rnf_str(&r->doc, "private"));
        ok = out->t >= 0 && out->z >= 0;
    }
    r = WTM_CALL(w, tag ? "getbalance" : NULL, "getbalance");
    return ok && r->ok && rnf_zats(r->raw) == out->t;
}

struct note {
    int count;        /* notes of the txid at the address */
    int64_t zat;      /* that note's amount */
    int confs;
    char memo[600];
    char memo_hex[600];  /* set instead of memo when the memo is not UTF-8 */
    int64_t held;     /* all notes at the address */
    int held_count;
};

static struct note wtm_notes(struct wtm *w, const char *tag, const char *addr,
                             const char *txid)
{
    struct note out = { 0 };
    struct reply *r = WTM_CALL(w, tag, "core", "wallet", "shielded", "notes");
    const struct json_value *l = r->ok ? rnf_at(&r->doc, "data.notes") : NULL;
    for (size_t i = 0; l && i < l->num_children; i++) {
        const struct json_value *n = &l->children[i];
        if (strcmp(rnf_str(n, "address"), addr) != 0) continue;
        out.held += rnf_zats(rnf_str(n, "amount"));
        out.held_count++;
        if (!txid || strcmp(rnf_str(n, "txid"), txid) != 0) continue;
        out.count++;
        out.zat = rnf_zats(rnf_str(n, "amount"));
        out.confs = (int)json_get_int(json_get(n, "confirmations"));
        snprintf(out.memo, sizeof(out.memo), "%s", rnf_str(n, "memo"));
        snprintf(out.memo_hex, sizeof(out.memo_hex), "%s", rnf_str(n, "memo_hex"));
    }
    return out;
}

struct hist {
    bool found;
    char status[16], direction[16], kind[16];
    int confs;
    int64_t amount, fee, net;
    bool memo_present;
};

/* One transaction's wallet history entry (core.wallet.history txid filter). */
static struct hist wtm_hist(struct wtm *w, const char *tag, const char *txid)
{
    struct hist h = { 0 };
    char input[160];
    snprintf(input, sizeof(input), "--input={\"txid\":\"%s\"}", txid);
    struct reply *r = WTM_CALL(w, tag, "core", "wallet", "history", input);
    const struct json_value *e = r->ok ? rnf_at(&r->doc, "data.entry") : NULL;
    if (!e || strcmp(rnf_str(e, "txid"), txid) != 0) return h;
    h.found = true;
    snprintf(h.status, sizeof(h.status), "%s", rnf_str(e, "status"));
    snprintf(h.direction, sizeof(h.direction), "%s", rnf_str(e, "direction"));
    snprintf(h.kind, sizeof(h.kind), "%s", rnf_str(e, "kind"));
    h.confs = (int)json_get_int(json_get(e, "confirmations"));
    h.amount = json_get_int(json_get(e, "amount_zat"));
    h.fee = json_get_int(json_get(e, "fee_zat"));
    h.net = json_get_int(json_get(e, "net_zat"));
    h.memo_present = json_get_bool(json_get(e, "memo_present"));
    return h;
}

/* The newest history entry's txid: a refused send must not change it. */
static bool wtm_newest(struct wtm *w, char *txid, size_t cap)
{
    struct reply *r = WTM_CALL(w, NULL, "core", "wallet", "history",
                               "--input={\"limit\":1}");
    const struct json_value *e = r->ok ? rnf_at(&r->doc, "data.entries") : NULL;
    if (!e || e->num_children == 0) return false;
    snprintf(txid, cap, "%s", rnf_str(&e->children[0], "txid"));
    return true;
}

/* Zats at one address through z_getbalance (minconf 1); -1 on failure. */
static int64_t wtm_addr_bal(struct wtm *w, const char *tag, const char *addr)
{
    struct reply *r = WTM_CALL(w, tag, "z_getbalance", addr);
    return r->ok ? rnf_zats(r->raw) : -1;
}

/* ── one send: plan, then commit with the plan's own commit_input ─── */

struct send {
    const char *from, *to, *amount;
    const char *memo, *memo_hex;  /* NULL for none */
    const char *key;
    char txid[80];
    int64_t fee_zat;
    bool replayed;
    char code[64], message[256];  /* a refusal's error code and message */
};

static void send_input(const struct send *s, char *out, size_t cap)
{
    char memo[640] = "", hex[640] = "";
    if (s->memo) snprintf(memo, sizeof(memo), ",\"memo\":\"%s\"", s->memo);
    if (s->memo_hex)
        snprintf(hex, sizeof(hex), ",\"memo_hex\":\"%s\"", s->memo_hex);
    snprintf(out, cap,
             "--input={\"wallet_scope\":\"dev\",\"from\":\"%s\",\"to\":\"%s\","
             "\"amount\":\"%s\",\"idempotency_key\":\"%s\"%s%s}",
             s->from, s->to, s->amount, s->key, memo, hex);
}

static bool send_plan(struct wtm *w, const char *tag, const struct send *s,
                      char *commit, size_t cap)
{
    char input[2048];
    send_input(s, input, sizeof(input));
    struct reply *r = WTM_CALL(w, tag, "core", "wallet", "shielded", "send",
                               input);
    const char *ci = rnf_str(&r->doc, "data.commit_input");
    bool ok = r->ok && strcmp(rnf_str(&r->doc, "data.stage"), "plan") == 0 &&
              ci[0] && strlen(ci) + 9 < cap &&
              json_get_int(rnf_at(&r->doc, "data.fee_zat")) == WTM_FEE;
    if (ok) snprintf(commit, cap, "--input=%s", ci);
    return ok;
}

static void send_note_refusal(const struct reply *r, struct send *s)
{
    snprintf(s->code, sizeof(s->code), "%s", rnf_str(&r->doc, "error.code"));
    snprintf(s->message, sizeof(s->message), "%s",
             rnf_str(&r->doc, "error.message"));
}

/* Plan and commit one shielded-send. Fills txid and fee on success. */
static bool send_run(struct wtm *w, const char *tag, struct send *s)
{
    char commit[2300], ptag[96], ctag[96];
    snprintf(ptag, sizeof(ptag), "%s.plan", tag);
    snprintf(ctag, sizeof(ctag), "%s.commit", tag);
    if (!send_plan(w, ptag, s, commit, sizeof(commit))) return false;
    struct reply *r = WTM_CALL(w, ctag, "core", "wallet", "shielded", "send",
                               commit);
    bool ok = r->ok && strcmp(rnf_str(&r->doc, "data.stage"), "committed") == 0 &&
              strlen(rnf_str(&r->doc, "data.txid")) == 64;
    snprintf(s->txid, sizeof(s->txid), "%s", rnf_str(&r->doc, "data.txid"));
    s->fee_zat = json_get_int(rnf_at(&r->doc, "data.fee_zat"));
    s->replayed = json_get_bool(rnf_at(&r->doc, "data.replayed"));
    return ok;
}

/* The node's refusal of a send: true when the plan or the commit is refused
 * and nothing was sent (code and message in s). */
static bool send_refused(struct wtm *w, const char *tag, struct send *s)
{
    char commit[2300], ptag[96], ctag[96];
    snprintf(ptag, sizeof(ptag), "%s.plan", tag);
    snprintf(ctag, sizeof(ctag), "%s.commit", tag);
    char input[2048];
    send_input(s, input, sizeof(input));
    struct reply *r = WTM_CALL(w, ptag, "core", "wallet", "shielded", "send",
                               input);
    if (!r->ok) {
        send_note_refusal(r, s);
        return true;
    }
    const char *ci = rnf_str(&r->doc, "data.commit_input");
    if (!ci[0] || strlen(ci) + 9 >= sizeof(commit)) return false;
    snprintf(commit, sizeof(commit), "--input=%s", ci);
    r = WTM_CALL(w, ctag, "core", "wallet", "shielded", "send", commit);
    if (r->ok) return false;
    send_note_refusal(r, s);
    return true;
}

/* ── steps ────────────────────────────────────────────────────────── */

static bool wtm_new_address(struct wtm *w, const char *tag, bool shielded,
                            char *out, size_t cap)
{
    /* Key derivation can outlast the client's RPC deadline on a loaded host;
     * an extra derived address is harmless, so retry. */
    for (int i = 0; i < 3; i++) {
        struct reply *r = shielded
            ? WTM_CALL(w, tag, "core", "wallet", "shielded", "address")
            : WTM_CALL(w, tag, "core", "wallet", "address", "new");
        if (r->ok) snprintf(out, cap, "%s", rnf_str(&r->doc, "data.address"));
        if (r->ok && out[0]) return true;
    }
    return false;
}

static int step_boot_fund(struct wtm *w)
{
    int failures = 0;
    TEST("wallet_tx_matrix_regtest: node boots as regtest; wallet funded with mature coinbase") {
        ASSERT(rnf_wait_up(&w->n));
        struct reply *r = WTM_CALL(w, "boot.getblockchaininfo", "getblockchaininfo");
        ASSERT(r->ok);
        ASSERT_STR_EQ(rnf_str(&r->doc, "chain"), "regtest");
        ASSERT_EQ(json_get_int(json_get(&r->doc, "blocks")), 0);
        ASSERT(wtm_new_address(w, "fund.address_new", false, w->t1, sizeof(w->t1)));
        ASSERT(wtm_new_address(w, NULL, false, w->t2, sizeof(w->t2)));
        ASSERT(wtm_new_address(w, "fund.shielded_address", true, w->za, sizeof(w->za)));
        ASSERT(wtm_new_address(w, NULL, true, w->zb, sizeof(w->zb)));
        ASSERT(strcmp(w->za, w->zb) != 0);
        ASSERT(rnf_mine_to(&w->n, w->t1, WTM_FUND_BLOCKS));
        ASSERT(wtm_mine(w, WTM_MATURE_BLOCKS));
        struct totals t;
        ASSERT(wtm_totals(w, "fund.totals", &t));
        ASSERT_EQ(t.t, WTM_FUND_BLOCKS * 1250000000LL);
        ASSERT_EQ(t.z, 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Transparent to transparent: pending, then the confirmation counts. */
static int step_t_to_t(struct wtm *w)
{
    int failures = 0;
    TEST("wallet_tx_matrix_regtest: t -> t (transaction.send): pending, then 1 and 3 confirmations") {
        struct totals before, after;
        ASSERT(wtm_totals(w, NULL, &before));
        char plan[600], commit[700], amt[32];
        snprintf(amt, sizeof(amt), "%lld.00000000", 1LL);
        snprintf(plan, sizeof(plan),
                 "--input={\"wallet_scope\":\"dev\",\"address\":\"%s\","
                 "\"amount\":%s,\"idempotency_key\":\"matrix-tt\"}",
                 WTM_FOREIGN_T, amt);
        struct reply *r = WTM_CALL(w, "t2t.plan", "core", "wallet",
                                   "transaction", "send", plan);
        ASSERT(r->ok);
        ASSERT_STR_EQ(rnf_str(&r->doc, "data.stage"), "plan");
        snprintf(commit, sizeof(commit), "--input=%s",
                 rnf_str(&r->doc, "data.commit_input"));
        r = WTM_CALL(w, "t2t.commit", "core", "wallet", "transaction", "send",
                     commit);
        ASSERT(r->ok);
        ASSERT_STR_EQ(rnf_str(&r->doc, "data.stage"), "committed");
        char txid[80];
        snprintf(txid, sizeof(txid), "%s", rnf_str(&r->doc, "data.txid"));
        ASSERT_EQ((int64_t)strlen(txid), 64);
        struct hist h = wtm_hist(w, "t2t.history_pending", txid);
        ASSERT(h.found);
        ASSERT_STR_EQ(h.status, "pending");
        ASSERT_EQ(h.confs, 0);
        ASSERT_EQ(h.fee, WTM_FEE);
        ASSERT_EQ(h.amount, WTM_COIN);
        struct reply *lt = WTM_CALL(w, "t2t.listtransactions_pending",
                                    "listtransactions");
        ASSERT(lt->ok && lt->parsed);
        ASSERT_STR_EQ(rnf_str(json_at(&lt->doc, 0), "txid"), txid);
        ASSERT_EQ(json_get_int(json_get(json_at(&lt->doc, 0), "confirmations")), 0);
        ASSERT(wtm_mine(w, 1));
        h = wtm_hist(w, "t2t.history_confirmed", txid);
        ASSERT_STR_EQ(h.status, "confirmed");
        ASSERT_EQ(h.confs, 1);
        ASSERT(wtm_mine(w, 2));
        h = wtm_hist(w, NULL, txid);
        ASSERT_EQ(h.confs, 3);
        ASSERT(wtm_totals(w, "t2t.totals", &after));
        ASSERT_EQ(after.t, before.t - WTM_COIN - WTM_FEE);
        ASSERT_EQ(after.z, before.z);
        /* The same commit again: transaction.send records the key only to
         * correlate plan and commit, so a repeat is a second payment. */
        r = WTM_CALL(w, "t2t.commit_repeat", "core", "wallet", "transaction",
                     "send", commit);
        printf("\n  [evidence] t->t commit repeated on its key: ok=%d second txid %s the first ",
               r->ok, strcmp(rnf_str(&r->doc, "data.txid"), txid) == 0 ? "equals" : "differs from");
        ASSERT(wtm_mine(w, 1));
        PASS();
    } _test_next:;
    return failures;
}

static int step_shield(struct wtm *w, struct send *s)
{
    int failures = 0;
    TEST("wallet_tx_matrix_regtest: t -> z (shielding) with a text memo: note, memo, history") {
        struct totals before, after;
        ASSERT(wtm_totals(w, NULL, &before));
        *s = (struct send){ .from = w->t1, .to = w->za, .amount = "5.00000000",
                            .memo = "hello shield", .key = "matrix-shield" };
        ASSERT(send_run(w, "shield", s));
        ASSERT_EQ(s->fee_zat, WTM_FEE);
        ASSERT(!s->replayed);
        struct hist h = wtm_hist(w, "shield.history_pending", s->txid);
        ASSERT_STR_EQ(h.status, "pending");
        ASSERT_EQ(h.confs, 0);
        ASSERT(wtm_mine(w, 1));
        struct note n = wtm_notes(w, "shield.notes", w->za, s->txid);
        ASSERT_EQ(n.count, 1);
        ASSERT_EQ(n.zat, 5 * WTM_COIN);
        ASSERT_EQ(n.confs, 1);
        ASSERT_STR_EQ(n.memo, "hello shield");
        h = wtm_hist(w, "shield.history_confirmed", s->txid);
        ASSERT_STR_EQ(h.status, "confirmed");
        ASSERT_EQ(h.confs, 1);
        ASSERT(h.memo_present);
        ASSERT(wtm_totals(w, "shield.totals", &after));
        ASSERT_EQ(after.t, before.t - 5 * WTM_COIN - WTM_FEE);
        ASSERT_EQ(after.z, before.z + 5 * WTM_COIN);
        PASS();
    } _test_next:;
    return failures;
}

/* z->z with a multi-byte UTF-8 memo; the same commit repeated on its key. */
static int step_z_to_z_text(struct wtm *w, struct send *s)
{
    int failures = 0;
    TEST("wallet_tx_matrix_regtest: z -> z with a UTF-8 memo; repeated commit on one key sends once") {
        struct totals before, after;
        ASSERT(wtm_mine(w, WTM_SPENDABLE_CONFS));
        ASSERT(wtm_totals(w, NULL, &before));
        *s = (struct send){ .from = w->za, .to = w->zb, .amount = "2.00000000",
                            .memo = "caf\xc3\xa9 \xe2\x98\x95 \xe6\x97\xa5\xe6\x9c\xac",
                            .key = "matrix-zz-text" };
        char commit[2300];
        ASSERT(send_plan(w, "zz_text.plan", s, commit, sizeof(commit)));
        struct reply *r = WTM_CALL(w, "zz_text.commit", "core", "wallet",
                                   "shielded", "send", commit);
        ASSERT(r->ok);
        snprintf(s->txid, sizeof(s->txid), "%s", rnf_str(&r->doc, "data.txid"));
        ASSERT_EQ((int64_t)strlen(s->txid), 64);
        ASSERT(!json_get_bool(rnf_at(&r->doc, "data.replayed")));
        r = WTM_CALL(w, "zz_text.commit_repeat", "core", "wallet", "shielded",
                     "send", commit);
        ASSERT(r->ok);
        ASSERT_STR_EQ(rnf_str(&r->doc, "data.txid"), s->txid);
        ASSERT(json_get_bool(rnf_at(&r->doc, "data.replayed")));
        ASSERT(wtm_mine(w, 1));
        struct note to_b = wtm_notes(w, "zz_text.notes", w->zb, s->txid);
        struct note change = wtm_notes(w, NULL, w->za, s->txid);
        ASSERT_EQ(to_b.count, 1);
        ASSERT_EQ(to_b.zat, 2 * WTM_COIN);
        ASSERT_STR_EQ(to_b.memo, s->memo);
        ASSERT_EQ(change.count, 1);
        ASSERT_EQ(change.zat, 3 * WTM_COIN - WTM_FEE);
        char newest[80];
        ASSERT(wtm_newest(w, newest, sizeof(newest)));
        ASSERT_STR_EQ(newest, s->txid);
        ASSERT(wtm_totals(w, "zz_text.totals", &after));
        ASSERT_EQ(after.z, before.z - WTM_FEE);
        ASSERT_EQ(after.t, before.t);
        /* the same key with other parameters is refused and sends nothing */
        struct send other = *s;
        other.amount = "1.00000000";
        ASSERT(send_refused(w, "zz_text.key_reuse", &other));
        printf("\n  [evidence] key reused for other parameters: %s: %s ",
               other.code, other.message);
        ASSERT(wtm_totals(w, NULL, &before));
        ASSERT_EQ(before.z, after.z);
        PASS();
    } _test_next:;
    return failures;
}

/* z->z with a memo that is not valid UTF-8, given as memo_hex. */
static int step_z_to_z_binary(struct wtm *w, struct send *s)
{
    int failures = 0;
    TEST("wallet_tx_matrix_regtest: z -> z with a memo that is not UTF-8 (memo_hex): hex fallback") {
        struct totals before, after;
        ASSERT(wtm_mine(w, WTM_SPENDABLE_CONFS));
        ASSERT(wtm_totals(w, NULL, &before));
        *s = (struct send){ .from = w->za, .to = w->zb, .amount = "1.00000000",
                            .memo_hex = "fffe00ff41", .key = "matrix-zz-bin" };
        ASSERT(send_run(w, "zz_bin", s));
        ASSERT(wtm_mine(w, 1));
        struct note n = wtm_notes(w, "zz_bin.notes", w->zb, s->txid);
        ASSERT_EQ(n.count, 1);
        ASSERT_EQ(n.zat, WTM_COIN);
        printf("\n  [evidence] non-UTF-8 memo read back as: %s ", n.memo);
        ASSERT_STR_EQ(n.memo_hex, "fffe00ff41");
        ASSERT_STR_EQ(n.memo, "");
        struct hist h = wtm_hist(w, "zz_bin.history", s->txid);
        ASSERT(h.found && h.memo_present);
        ASSERT(wtm_totals(w, "zz_bin.totals", &after));
        ASSERT_EQ(after.z, before.z - WTM_FEE);
        PASS();
    } _test_next:;
    return failures;
}

static int step_z_to_t(struct wtm *w, struct send *s)
{
    int failures = 0;
    TEST("wallet_tx_matrix_regtest: z -> t (de-shielding) to a wallet address: balances move exactly") {
        struct totals before, after;
        ASSERT(wtm_mine(w, WTM_SPENDABLE_CONFS));
        ASSERT(wtm_totals(w, NULL, &before));
        *s = (struct send){ .from = w->zb, .to = w->t2, .amount = "1.50000000",
                            .key = "matrix-z-to-t" };
        ASSERT(send_run(w, "deshield", s));
        ASSERT(wtm_mine(w, 1));
        struct hist h = wtm_hist(w, "deshield.history", s->txid);
        ASSERT(h.found);
        ASSERT_STR_EQ(h.kind, "public");
        ASSERT(wtm_totals(w, "deshield.totals", &after));
        ASSERT_EQ(after.t, before.t + 3 * WTM_COIN / 2);
        ASSERT_EQ(after.z, before.z - 3 * WTM_COIN / 2 - WTM_FEE);
        ASSERT_EQ(wtm_addr_bal(w, "deshield.z_getbalance", w->t2),
                  3 * WTM_COIN / 2);
        PASS();
    } _test_next:;
    return failures;
}

/* One legacy z_sendmany with a shielded recipient (with memo), two
 * transparent ones (one the wallet's own) and a foreign shielded one. */
static int step_multi(struct wtm *w)
{
    int failures = 0;
    TEST("wallet_tx_matrix_regtest: one transaction, four recipients, mixed private and public (z_sendmany)") {
        struct totals before, after;
        ASSERT(wtm_mine(w, WTM_SPENDABLE_CONFS));
        ASSERT(wtm_totals(w, NULL, &before));
        char recips[1400];
        snprintf(recips, sizeof(recips),
                 "[{\"address\":\"%s\",\"amount\":0.25,\"memo_hex\":\"6d756c7469\"},"
                 "{\"address\":\"%s\",\"amount\":0.10},"
                 "{\"address\":\"%s\",\"amount\":0.05},"
                 "{\"address\":\"%s\",\"amount\":0.05}]",
                 w->zb, w->t2, WTM_FOREIGN_T, WTM_FOREIGN_Z);
        struct reply *r = WTM_CALL(w, "multi.z_sendmany", "z_sendmany", w->za,
                                   recips);
        ASSERT(r->ok);
        char txid[80];
        snprintf(txid, sizeof(txid), "%.64s", r->raw);
        ASSERT_EQ((int64_t)strlen(txid), 64);
        ASSERT(wtm_mine(w, 1));
        struct note n = wtm_notes(w, "multi.notes", w->zb, txid);
        ASSERT_EQ(n.count, 1);
        ASSERT_EQ(n.zat, 25000000);
        ASSERT_STR_EQ(n.memo, "multi");
        ASSERT(wtm_totals(w, "multi.totals", &after));
        ASSERT_EQ(after.t, before.t + 10000000);
        ASSERT_EQ(after.z, before.z - 10000000 - 5000000 - 5000000 - WTM_FEE);
        /* A legacy front end passes the memo as hex under "memo" (zclassicd's
         * z_sendmany). This node reads "memo" as text and hex only under
         * "memo_hex": print what the recipient is given. */
        ASSERT(wtm_mine(w, WTM_SPENDABLE_CONFS)); /* the change note is spendable */
        char one[400];
        snprintf(one, sizeof(one),
                 "[{\"address\":\"%s\",\"amount\":0.01,\"memo\":\"6c6567\"}]",
                 w->zb);
        r = WTM_CALL(w, "multi.z_sendmany_legacy_memo_key", "z_sendmany", w->za,
                     one);
        ASSERT(r->ok);
        snprintf(txid, sizeof(txid), "%.64s", r->raw);
        ASSERT(wtm_mine(w, 1));
        n = wtm_notes(w, NULL, w->zb, txid);
        ASSERT_EQ(n.count, 1);
        ASSERT_EQ(n.zat, 1000000);
        printf("\n  [evidence] z_sendmany memo \"6c6567\" under the legacy \"memo\" key is stored as memo=\"%s\" (legacy zclassicd: hex, i.e. \"leg\") ",
               n.memo);
        PASS();
    } _test_next:;
    return failures;
}

/* amount = balance - fee, from a shielded address and a transparent one:
 * nothing is left at the source. */
static int step_max(struct wtm *w)
{
    int failures = 0;
    TEST("wallet_tx_matrix_regtest: exact-balance send (amount = balance - fee) leaves nothing, shielded and transparent") {
        struct totals before, after;
        ASSERT(wtm_mine(w, WTM_SPENDABLE_CONFS));
        ASSERT(wtm_totals(w, NULL, &before));
        struct note held = wtm_notes(w, NULL, w->za, NULL);
        ASSERT(held.held_count >= 1 && held.held > WTM_FEE);
        char amt[40];
        int64_t zmax = held.held - WTM_FEE;
        snprintf(amt, sizeof(amt), "%lld.%08lld", (long long)(zmax / WTM_COIN),
                 (long long)(zmax % WTM_COIN));
        struct send s = { .from = w->za, .to = WTM_FOREIGN_T, .amount = amt,
                          .key = "matrix-max-z" };
        ASSERT(send_run(w, "max_z", &s));
        ASSERT(wtm_mine(w, 1));
        held = wtm_notes(w, "max_z.notes", w->za, NULL);
        ASSERT_EQ(held.held_count, 0);
        ASSERT_EQ(wtm_addr_bal(w, "max_z.z_getbalance", w->za), 0);
        ASSERT(wtm_totals(w, NULL, &after));
        ASSERT_EQ(after.z, before.z - zmax - WTM_FEE);
        /* transparent: every coin at t1 */
        int64_t tmax = wtm_addr_bal(w, NULL, w->t1) - WTM_FEE;
        ASSERT(tmax > 0);
        snprintf(amt, sizeof(amt), "%lld.%08lld", (long long)(tmax / WTM_COIN),
                 (long long)(tmax % WTM_COIN));
        struct send t = { .from = w->t1, .to = WTM_FOREIGN_T, .amount = amt,
                          .key = "matrix-max-t" };
        ASSERT(send_run(w, "max_t", &t));
        ASSERT(wtm_mine(w, 1));
        ASSERT_EQ(wtm_addr_bal(w, "max_t.z_getbalance", w->t1), 0);
        struct totals last;
        ASSERT(wtm_totals(w, NULL, &last));
        ASSERT_EQ(last.t, after.t - tmax - WTM_FEE);
        PASS();
    } _test_next:;
    return failures;
}

/* ── refusals: each must fail and change no balance ───────────────── */

struct refusal {
    const char *name, *tag, *from, *to, *amount, *memo;
    bool may_accept;  /* a node that accepts it is reported, not failed */
};

static int step_refusal_one(struct wtm *w, const struct refusal *c)
{
    int failures = 0;
    TEST(c->name) {
        struct totals before, after;
        char newest_before[80], newest_after[80], tag[64];
        ASSERT(wtm_totals(w, NULL, &before));
        ASSERT(wtm_newest(w, newest_before, sizeof(newest_before)));
        struct send s = { .from = c->from, .to = c->to, .amount = c->amount,
                          .memo = c->memo, .key = "matrix-refusal" };
        char key[64];
        snprintf(key, sizeof(key), "matrix-refusal-%s", c->tag);
        s.key = key;
        snprintf(tag, sizeof(tag), "refuse.%s", c->tag);
        bool refused = send_refused(w, tag, &s);
        if (!refused && c->may_accept) {
            printf("\n  [evidence] GAP: the node accepted and sent this "
                   "request (legacy zclassicd refuses it) ");
            ASSERT(wtm_mine(w, 1));
            PASS();
            break;
        }
        ASSERT(refused);
        printf("\n  [evidence] refused (%s): %.150s ", s.code, s.message);
        ASSERT(s.code[0]);
        ASSERT(wtm_mine(w, 1));
        ASSERT(wtm_totals(w, NULL, &after));
        ASSERT_EQ(after.t, before.t);
        ASSERT_EQ(after.z, before.z);
        ASSERT(wtm_newest(w, newest_after, sizeof(newest_after)));
        ASSERT_STR_EQ(newest_after, newest_before);
        PASS();
    } _test_next:;
    return failures;
}

static int step_refusals(struct wtm *w)
{
    int failures = 0;
    if (!wtm_mine(w, WTM_SPENDABLE_CONFS)) return 1;
    const struct refusal cases[] = {
        { "wallet_tx_matrix_regtest: refused: shielded insufficient funds", "shielded_insufficient",
          w->zb, w->za, "900.00000000", NULL, false },
        { "wallet_tx_matrix_regtest: refused: transparent insufficient funds", "transparent_insufficient",
          w->t2, WTM_FOREIGN_T, "900.00000000", NULL, false },
        { "wallet_tx_matrix_regtest: refused: invalid address (to)", "invalid_address",
          w->zb, "notanaddress", "0.10000000", NULL, false },
        { "wallet_tx_matrix_regtest: refused: memo to a transparent recipient", "memo_to_transparent",
          w->zb, WTM_FOREIGN_T, "0.10000000", "this cannot be delivered", true },
        { "wallet_tx_matrix_regtest: refused: amount of zero", "zero_amount",
          w->zb, w->za, "0.00000000", NULL, false },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]) && !failures; i++)
        failures += step_refusal_one(w, &cases[i]);
    return failures;
}

/* ── the legacy-compatible methods a legacy front end calls ───────── */


static int step_legacy(struct wtm *w)
{
    int failures = 0;
    TEST("wallet_tx_matrix_regtest: legacy-compatible reads answer with the shapes a legacy front end parses") {
        struct reply *r = WTM_CALL(w, "legacy.z_listaddresses", "z_listaddresses");
        ASSERT(r->ok && r->parsed && r->doc.type == JSON_ARR);
        ASSERT(r->doc.num_children >= 2);
        r = WTM_CALL(w, "legacy.listunspent", "listunspent");
        ASSERT(r->ok && r->parsed && r->doc.type == JSON_ARR);
        r = WTM_CALL(w, "legacy.listtransactions", "listtransactions");
        ASSERT(r->ok && r->parsed && r->doc.type == JSON_ARR);
        r = WTM_CALL(w, "legacy.z_listreceivedbyaddress_minconf1",
                     "z_listreceivedbyaddress", w->zb);
        ASSERT(r->ok && r->parsed && r->doc.type == JSON_ARR);
        printf("\n  [evidence] z_listreceivedbyaddress(zb) default minconf: %zu entries ",
               r->doc.num_children);
        r = WTM_CALL(w, "legacy.z_listreceivedbyaddress_minconf0",
                     "z_listreceivedbyaddress", w->zb, "0");
        ASSERT(r->ok && r->parsed && r->doc.type == JSON_ARR);
        ASSERT(r->doc.num_children >= 1);
        r = WTM_CALL(w, "legacy.validateaddress_valid", "validateaddress", w->t2);
        ASSERT(r->ok && json_get_bool(json_get(&r->doc, "isvalid")));
        ASSERT(json_get_bool(json_get(&r->doc, "ismine")));
        r = WTM_CALL(w, "legacy.validateaddress_invalid", "validateaddress", "notanaddress");
        ASSERT(r->ok && !json_get_bool(json_get(&r->doc, "isvalid")));
        r = WTM_CALL(w, "legacy.getnewaddress", "getnewaddress");
        ASSERT(r->ok && strlen(r->raw) > 20);
        r = WTM_CALL(w, "legacy.z_getnewaddress", "z_getnewaddress");
        ASSERT(r->ok && strncmp(r->raw, "zregtestsapling", 15) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* The legacy methods the node's RPC table does not have: each is refused by
 * name. A gap a legacy front end must cover (operations are polled there). */
static int step_legacy_unsupported(struct wtm *w)
{
    int failures = 0;
    TEST("wallet_tx_matrix_regtest: legacy methods this node lacks (z_validateaddress, z_getoperationstatus, z_getoperationresult) are refused by name") {
        struct reply *r = WTM_CALL(w, NULL, "z_validateaddress", w->zb);
        ASSERT(!r->ok && strstr(r->raw, "UNKNOWN_") != NULL);
        printf("\n  [evidence] UNSUPPORTED z_validateaddress: %.120s ", r->raw);
        r = WTM_CALL(w, NULL, "z_getoperationstatus");
        ASSERT(!r->ok && strstr(r->raw, "UNKNOWN_") != NULL);
        printf("\n  [evidence] UNSUPPORTED z_getoperationstatus: %.120s ", r->raw);
        r = WTM_CALL(w, NULL, "z_getoperationresult");
        ASSERT(!r->ok && strstr(r->raw, "UNKNOWN_") != NULL);
        printf("\n  [evidence] UNSUPPORTED z_getoperationresult: %.120s ", r->raw);
        PASS();
    } _test_next:;
    return failures;
}

/* A send committed with the wallet locked is refused and sends nothing; after
 * unlock the same commit goes through. The wallet is encrypted first: a
 * dev-lane wallet is plaintext, where a lock changes nothing. The passphrase
 * is a throwaway regtest value and reaches the node on stdin only. */
#define WTM_PASS_ENCRYPT "{\"passphrase\":\"regtest-matrix-passphrase\"}"
#define WTM_PASS_UNLOCK \
    "{\"passphrase\":\"regtest-matrix-passphrase\",\"timeout_seconds\":600}"

static bool wtm_wallet_locked(struct wtm *w, const char *tag, bool want)
{
    struct reply *r = WTM_CALL(w, tag, "core", "wallet", "security", "status");
    return r->ok && json_get_bool(rnf_at(&r->doc, "data.locked")) == want &&
           json_get_bool(rnf_at(&r->doc, "data.encrypted_at_rest"));
}

static int step_lock(struct wtm *w)
{
    int failures = 0;
    TEST("wallet_tx_matrix_regtest: a send committed with the wallet locked is refused; after unlock it goes through") {
        struct totals before, after;
        ASSERT(wtm_mine(w, WTM_SPENDABLE_CONFS));
        ASSERT(wtm_totals(w, NULL, &before));
        char commit[2300];
        struct send plan = { .from = w->zb, .to = WTM_FOREIGN_Z,
                             .amount = "0.10000000", .key = "matrix-locked" };
        ASSERT(send_plan(w, "lock.plan", &plan, commit, sizeof(commit)));
        struct reply *r = wtm_call_in(w, "lock.security_encrypt",
            (const char *const[]){ "core", "wallet", "security", "encrypt", "--input=-", NULL },
            WTM_PASS_ENCRYPT);
        ASSERT(r->ok);
        ASSERT(wtm_wallet_locked(w, "lock.security_status_locked", true));
        r = WTM_CALL(w, "lock.commit", "core", "wallet", "shielded", "send",
                     commit);
        ASSERT(!r->ok);
        printf("\n  [evidence] locked commit refused (%s): %.150s ",
               rnf_str(&r->doc, "error.code"), rnf_str(&r->doc, "error.message"));
        ASSERT(strstr(rnf_str(&r->doc, "error.message"), "ock") != NULL);
        r = wtm_call_in(w, "lock.security_unlock",
            (const char *const[]){ "core", "wallet", "security", "unlock", "--input=-", NULL },
            WTM_PASS_UNLOCK);
        ASSERT(r->ok);
        ASSERT(wtm_wallet_locked(w, "lock.security_status_unlocked", false));
        ASSERT(wtm_mine(w, 1));
        /* the wallet's shielded view is reloaded just after an unlock */
        after = (struct totals){ -1, -1 };
        for (int i = 0; i < 40 && (after.t != before.t || after.z != before.z); i++) {
            if (i > 0) rnf_sleep_ms(500);
            if (!wtm_totals(w, NULL, &after)) after = (struct totals){ -1, -1 };
        }
        ASSERT_EQ(after.t, before.t);
        ASSERT_EQ(after.z, before.z);
        r = WTM_CALL(w, "lock.commit_after_unlock", "core", "wallet", "shielded",
                     "send", commit);
        printf("\n  [evidence] the same commit after unlock: ok=%d %s ", r->ok,
               r->ok ? "committed" : rnf_str(&r->doc, "error.code"));
        PASS();
    } _test_next:;
    return failures;
}

static int wtm_run_steps(struct wtm *w)
{
    struct send a, b, c;
    int failures = step_boot_fund(w);
    if (!failures) failures += step_t_to_t(w);
    if (!failures) failures += step_shield(w, &a);
    if (!failures) failures += step_z_to_z_text(w, &b);
    if (!failures) failures += step_z_to_z_binary(w, &c);
    if (!failures) failures += step_z_to_t(w, &a);
    if (!failures) failures += step_multi(w);
    if (!failures) failures += step_refusals(w);
    if (!failures) failures += step_legacy(w);
    if (!failures) failures += step_legacy_unsupported(w);
    if (!failures) failures += step_max(w);
    if (!failures) failures += step_lock(w);
    return failures;
}

/* The same gate wallet_e2e_regtest uses for proving parameters. */
static bool wtm_params_available(void)
{
    const char *home = getenv("HOME");
    char params_dir[512];
    snprintf(params_dir, sizeof(params_dir), "%s/.zcash-params",
             (home && *home) ? home : ".");
    if (sapling_init_params(params_dir) && zclassic_sapling_prover_is_ready())
        return true;
    printf("  UNOBSERVED (wallet_tx_matrix_regtest proving parameters) - %s "
           "(status=%s)\n", zclassic_sapling_prover_backend(),
           zclassic_sapling_prover_status());
    return false;
}

int test_wallet_tx_matrix_regtest(void);
int test_wallet_tx_matrix_regtest(void)
{
    printf("\n=== wallet tx matrix: every transaction kind through a real regtest node ===\n");
    if (access(RNF_BIN, X_OK) != 0) {
        printf("  UNOBSERVED (%s absent - build it with make z23)\n", RNF_BIN);
        return 0;
    }
    if (!wtm_params_available()) return 0;
    static struct wtm w;
    int failures = 0;
    const char *rec = getenv("ZCL_REGTEST_SHAPES_RECORD");
    w.record = rec && rec[0] == '1';
    rnf_live = &w.n;
    atexit(rnf_atexit_reap);
    TEST("wallet_tx_matrix_regtest: isolated fixture and node start") {
        ASSERT(rnf_setup(&w.n, "wallet_tx_matrix"));
        ASSERT(rnf_node_start(&w.n));
        PASS();
    } _test_next:;
    if (!failures) failures = wtm_run_steps(&w);
    printf("  [evidence] %ld call shapes %s\n", w.shapes_checked,
           w.record ? "recorded" : "checked");
    if (failures && w.n.work[0]) rnf_log_tail(&w.n);
    reply_free(&wtm_r);
    rnf_cleanup(&w.n);
    rnf_live = NULL;
    return failures;
}
