/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "residue.h"
#include "wallet_screens.h"
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CHECK(cond)                                                                              \
    do {                                                                                         \
        if (!(cond)) {                                                                           \
            fprintf(stderr, "wallet_screens_test: %s:%d: failed: %s\n", __FILE__, __LINE__, #cond); \
            exit(1);                                                                             \
        }                                                                                        \
    } while (0)

/* Fixtures hold no key material: only the length and charset of each address form are real. */
#define Q10 "qqqqqqqqqq"
#define Q70 Q10 Q10 Q10 Q10 Q10 Q10 Q10
#define ADDR(n) "zs1" Q70 "qqqq" #n
#define A1 "zs1" Q70 "qqqqp"
#define A2 "zs1" Q70 "qqqqz"
#define PUBLIC_ADDR "t1" "aaaaaaaaaa" "aaaaaaaaaa" "aaaaaaaaaa" "aaa"
_Static_assert(sizeof(A1) == 79 && sizeof(A2) == 79 && sizeof(PUBLIC_ADDR) == 36, "address fixtures have real lengths");
#define H8(c) c c c c c c c c
#define TXID(c) H8(c) H8(c) H8(c) H8(c) H8(c) H8(c) H8(c) H8(c)
#define TX_A TXID("a")
#define TX_B TXID("b")
#define TX_C TXID("c")
#define TX_D TXID("d")
#define CURSOR_1 "3000000:" TXID("e")

#define SUMMARY_SEND_EL(enc, locked, spendable_zat, spendable, pending_zat, pending, public_zat, public, allowed, why)  \
    "{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_summary.v1\",\"spendable_zat\":" spendable_zat ","  \
    "\"spendable\":\"" spendable "\",\"pending_zat\":" pending_zat ",\"pending\":\"" pending "\","      \
    "\"pending_notes\":2,\"pending_min_confirmations_needed\":7,\"sending_zat\":0,\"sending\":\"0.00000000\"," \
    "\"public_zat\":" public_zat ",\"public\":\"" public "\",\"immature_zat\":0,"                       \
    "\"immature\":\"0.00000000\",\"tip_height\":3000000,\"header_height\":3000000,"                     \
    "\"scanned_through_height\":3000000,\"blocks_behind\":0,\"current\":true,\"locked\":" locked ","    \
    "\"encrypted\":" enc ",\"shielded_keys\":1,\"send_allowed\":" allowed ",\"send_blocked_reason\":\"" why "\"}}"
#define SUMMARY_SEND_E(enc, ...) SUMMARY_SEND_EL(enc, "false", __VA_ARGS__)
#define SUMMARY_SEND(...) SUMMARY_SEND_E("true", __VA_ARGS__)
#define SUMMARY(spendable_zat, spendable, pending_zat, pending, public_zat, public) \
    SUMMARY_SEND(spendable_zat, spendable, pending_zat, pending, public_zat, public, "true", "")
/* Summaries with one thing changed: a wallet that has scanned up to a height, immature coins, a node that is not current. */
#define SUMMARY_SCAN(scanned)                                                                           \
    "{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_summary.v1\",\"spendable_zat\":123456789,"          \
    "\"spendable\":\"1.23456789\",\"pending_zat\":0,\"pending\":\"0.00000000\",\"pending_notes\":0,"     \
    "\"pending_min_confirmations_needed\":0,\"sending_zat\":0,\"sending\":\"0.00000000\","               \
    "\"public_zat\":0,\"public\":\"0.00000000\",\"immature_zat\":0,\"immature\":\"0.00000000\","         \
    "\"tip_height\":3000000,\"header_height\":3000000,\"scanned_through_height\":" scanned ","           \
    "\"blocks_behind\":0,\"current\":true,\"locked\":false,\"encrypted\":true,\"shielded_keys\":1,"      \
    "\"send_allowed\":true,\"send_blocked_reason\":\"\"}}"
#define SUMMARY_IMMATURE(zat, text)                                                                     \
    "{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_summary.v1\",\"spendable_zat\":2500000000,"         \
    "\"spendable\":\"25.00000000\",\"pending_zat\":0,\"pending\":\"0.00000000\",\"pending_notes\":0,"    \
    "\"pending_min_confirmations_needed\":0,\"sending_zat\":0,\"sending\":\"0.00000000\","               \
    "\"public_zat\":0,\"public\":\"0.00000000\",\"immature_zat\":" zat ",\"immature\":\"" text "\","      \
    "\"tip_height\":3000000,\"header_height\":3000000,\"scanned_through_height\":3000000,"              \
    "\"blocks_behind\":0,\"current\":true,\"locked\":false,\"encrypted\":true,\"shielded_keys\":1,"      \
    "\"send_allowed\":true,\"send_blocked_reason\":\"\"}}"
#define SUMMARY_OFFLINE                                                                                 \
    "{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_summary.v1\",\"spendable_zat\":123456789,"          \
    "\"spendable\":\"1.23456789\",\"pending_zat\":0,\"pending\":\"0.00000000\",\"pending_notes\":0,"     \
    "\"pending_min_confirmations_needed\":0,\"sending_zat\":0,\"sending\":\"0.00000000\","               \
    "\"public_zat\":0,\"public\":\"0.00000000\",\"immature_zat\":0,\"immature\":\"0.00000000\","         \
    "\"tip_height\":3000000,\"header_height\":3000000,\"scanned_through_height\":3000000,"              \
    "\"blocks_behind\":0,\"current\":false,\"locked\":false,\"encrypted\":true,\"shielded_keys\":1,"     \
    "\"send_allowed\":true,\"send_blocked_reason\":\"\"}}"
#define RT_ADDR "zregtestsapling1" Q70 "qqqqq"
/* Spendable 2, 0.5 pending in two payments with 7 confirmations to the first, 0.1 public, 20 maturing. */
#define SUMMARY_ALL                                                                                     \
    "{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_summary.v1\",\"spendable_zat\":200000000,"          \
    "\"spendable\":\"2.00000000\",\"pending_zat\":50000000,\"pending\":\"0.50000000\",\"pending_notes\":2," \
    "\"pending_min_confirmations_needed\":7,\"sending_zat\":0,\"sending\":\"0.00000000\","               \
    "\"public_zat\":10000000,\"public\":\"0.10000000\",\"immature_zat\":2000000000,"                     \
    "\"immature\":\"20.00000000\",\"tip_height\":3000000,\"header_height\":3000000,"                     \
    "\"scanned_through_height\":3000000,\"blocks_behind\":0,\"current\":true,\"locked\":false,"          \
    "\"encrypted\":true,\"shielded_keys\":1,\"send_allowed\":true,\"send_blocked_reason\":\"\"}}"
/* Summaries that carry the node's word on private amounts. */
#define PRIVATE_OK(spendable_zat, spendable, extra)                                                      \
    "\"spendable_zat\":" spendable_zat ",\"spendable\":\"" spendable "\",\"pending_zat\":0,\"pending\":\"0.00000000\"," \
    "\"pending_notes\":0,\"pending_min_confirmations_needed\":0," extra
#define PRIVATE_HIDDEN                                                                                   \
    "\"spendable_zat\":null,\"spendable\":null,\"pending_zat\":null,\"pending\":null,\"pending_notes\":null," \
    "\"pending_min_confirmations_needed\":null,\"unready_zat\":null,\"unready\":null,"
#define SUMMARY_STATE_L(state, locked, private_part, public_zat, public)                                  \
    "{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_summary.v1\",\"shielded_state\":\"" state "\"," private_part \
    "\"public_zat\":" public_zat ",\"public\":\"" public "\",\"immature_zat\":0,\"immature\":\"0.00000000\"," \
    "\"tip_height\":3000000,\"header_height\":3000000,\"scanned_through_height\":3000000,\"blocks_behind\":0," \
    "\"current\":true,\"locked\":" locked ",\"encrypted\":true,\"shielded_keys\":1,\"send_allowed\":true,\"send_blocked_reason\":\"\"}}"
#define SUMMARY_STATE(state, private_part, public_zat, public) SUMMARY_STATE_L(state, "false", private_part, public_zat, public)
#define GOOD_SUMMARY SUMMARY("123456789", "1.23456789", "50000000", "0.50000000", "10000000", "0.10000000")
/* The same wallet without encryption: it never locks, so its amounts are always shown. */
#define GOOD_SUMMARY_PLAIN \
    SUMMARY_SEND_E("false", "123456789", "1.23456789", "50000000", "0.50000000", "10000000", "0.10000000", "true", "")
/* The same wallet encrypted and locked with its viewing key loaded, as the app's wallets are: its amounts show without the
 * screen lock, so they are kept. */
#define GOOD_SUMMARY_LOCKED \
    SUMMARY_SEND_EL("true", "true", "123456789", "1.23456789", "50000000", "0.50000000", "10000000", "0.10000000", "true", "")
/* A locked wallet whose node hides the private amounts. */
#define LOCKED_SUMMARY SUMMARY_STATE_L("keys_unavailable", "true", PRIVATE_HIDDEN, "10000000", "0.10000000")
#define UNKNOWN_COMMAND_ERROR "{\"ok\":false,\"error\":{\"code\":\"UNKNOWN_COMMAND\"}}"
#define NODE_UNAVAILABLE_ERROR "{\"ok\":false,\"error\":{\"code\":\"NODE_UNAVAILABLE\"}}"
#define OTHER_ERROR "{\"ok\":false,\"error\":{\"code\":\"WALLET_LOCKED\"}}"

/* The fleet status worker's frame, with its machines. */
#define FLEET_R(member, verdict, refuses, total, connected, machines)                                  \
    "{\"ok\":true,\"data\":{\"schema\":\"zcl.fleet_status.v1\",\"member\":" member ",\"verdict\":\"" verdict "\"," \
    "\"refuses_send\":" refuses ",\"machines_total\":" total ",\"machines_connected\":" connected ",\"local_tip\":3000000," \
    "\"machines\":[" machines "]}}"
#define FLEET(member, verdict, total, connected, machines) FLEET_R(member, verdict, "false", total, connected, machines)
#define MACHINE(name, up, how) "{\"name\":\"" name "\",\"connected\":" up ",\"agreement\":\"" how "\"}"

#define ROW(direction, kind, status, amount, time, txid, memo)                                          \
    "{\"txid\":\"" txid "\",\"status\":\"" status "\",\"height\":2999990,\"confirmations\":11,\"time\":" time "," \
    "\"direction\":\"" direction "\",\"kind\":\"" kind "\",\"amount_zat\":" amount ",\"amount\":null," \
    "\"fee_zat\":null,\"fee\":null,\"net_zat\":0,\"memo_present\":" memo "}"
/* A row with one more member, for fields the node may add. */
#define ROWX(direction, kind, status, amount, time, txid, memo, extra)                                  \
    "{\"txid\":\"" txid "\",\"status\":\"" status "\",\"height\":2999990,\"confirmations\":11,\"time\":" time "," \
    "\"direction\":\"" direction "\",\"kind\":\"" kind "\",\"amount_zat\":" amount ",\"amount\":null," \
    "\"fee_zat\":null,\"fee\":null,\"net_zat\":0,\"memo_present\":" memo "," extra "}"
/* A history page with the node's word on private payments: state is "\"shielded_state\":\"ok\"," or similar, or "". */
#define PAGE_STATE(state, rows, count, next)                                                             \
    "{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_history.v1\"," state "\"entries\":[" rows "],\"count\":" count "," \
    "\"next_cursor\":" next "}}"
#define STATE_OK "\"shielded_state\":\"ok\","
#define STATE_HIDDEN "\"shielded_state\":\"keys_unavailable\","
#define PAGE(rows, count, next) PAGE_STATE(STATE_OK, rows, count, next)
#define ROW_SENT ROW("sent", "private", "confirmed", "150000000", "1700000000", TX_A, "true")
#define ROW_RECEIVED ROW("received", "public", "pending", "null", "1700003600", TX_B, "false")
#define ROW_INTERNAL ROW("internal", "private", "bogus", "1", "null", TX_C, "false")
#define HISTORY_PAGE0 PAGE(ROW_SENT "," ROW_RECEIVED "," ROW_INTERNAL, "3", "\"" CURSOR_1 "\"")
#define HISTORY_PAGE1 PAGE(ROW("received", "private", "confirmed", "2100000000000000", "1700086400", TX_D, "false"), "1", "null")
#define DETAIL(memo_member) "{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_history.v1\",\"entry\":{\"txid\":\"" TX_A "\"," memo_member "}}}"

struct fake {
    bool secure_ok, secure_on, block, async, always_ok, node_up, copy_ok;
    int copy_calls, dismissed;
    enum wallet_reveal reveal, reveal_after_start; /* the state the environment reports; the state a tap on Show private balance moves it to */
    int reveal_started, reveal_ended;
    bool reveal_refused; /* reveal_start returns false and changes nothing */
    const char *progress;
    char copied[128];
    int secure_on_calls, secure_off_calls, changed, active, active_max, op_active[8];
    char ops[1024][16];
    char args[1024][WALLET_CURSOR_MAX];
    int op_count, counts[8];
    const char *summary, *fleet, *latest, *receive, *detail, *refusal;
    const char *history[3]; /* by page: the first, the one after CURSOR_1 */
    void (*during)(const char *op, const char *arg);
    uint64_t now;
    pthread_mutex_t lock;
    pthread_cond_t cond;
};
static struct fake fake;

static bool fake_secure(void *ctx, bool on)
{
    (void)ctx;
    if (on) ++fake.secure_on_calls; else ++fake.secure_off_calls;
    if (fake.secure_ok) fake.secure_on = on;
    return fake.secure_ok;
}
static const char *fake_refusal(void *ctx) { (void)ctx; return fake.refusal; }
static bool reply(const char *text, char *out, size_t cap)
{
    bool ok = text && (fake.always_ok || strncmp(text, "{\"ok\":false", 11) != 0);
    snprintf(out, cap, "%s", text ? text : UNKNOWN_COMMAND_ERROR);
    return ok;
}
static const char *answer(const char *op, const char *arg)
{
    if (!strcmp(op, "summary")) return fake.summary;
    if (!strcmp(op, "fleet")) return fake.fleet;
    if (!strcmp(op, "latest")) return fake.latest;
    if (!strcmp(op, "receive")) return fake.receive;
    if (!strcmp(op, "detail")) { CHECK(!strcmp(arg, TX_A)); return fake.detail; }
    CHECK(!strcmp(op, "history"));
    return !arg[0] ? fake.history[0] : !strcmp(arg, CURSOR_1) ? fake.history[1] : NULL;
}
static int op_slot(const char *op)
{
    static const char *const names[] = {"summary", "fleet", "latest", "receive", "history", "detail"};
    for (int i = 0; i < 6; ++i) if (!strcmp(op, names[i])) return i;
    CHECK(false);
    return 0;
}
static bool fake_run(void *ctx, const char *op, const char *arg, char *out, size_t cap)
{
    (void)ctx;
    int slot = op_slot(op);
    pthread_mutex_lock(&fake.lock);
    if (fake.op_count < 1024) {
        snprintf(fake.ops[fake.op_count], sizeof(fake.ops[0]), "%s", op);
        snprintf(fake.args[fake.op_count], sizeof(fake.args[0]), "%s", arg);
    }
    ++fake.op_count;
    ++fake.counts[slot];
    ++fake.op_active[slot];
    if (++fake.active > fake.active_max) fake.active_max = fake.active;
    CHECK(!fake.async || fake.op_active[slot] == 1);
    while (fake.block) pthread_cond_wait(&fake.cond, &fake.lock);
    pthread_mutex_unlock(&fake.lock);
    if (fake.during) fake.during(op, arg);
    bool ok = reply(answer(op, arg), out, cap);
    pthread_mutex_lock(&fake.lock);
    --fake.op_active[slot];
    --fake.active;
    pthread_mutex_unlock(&fake.lock);
    return ok;
}
static void fake_changed(void *ctx) { (void)ctx; pthread_mutex_lock(&fake.lock); ++fake.changed; pthread_mutex_unlock(&fake.lock); }
static uint64_t fake_now(void *ctx) { (void)ctx; return fake.now; }
static bool fake_node_running(void *ctx) { (void)ctx; return fake.node_up; }
static char cache_dir[PATH_MAX];  /* the files directory of the wallet under test; empty keeps no balance */
static int64_t wall = 1700000000;
static int64_t fake_wall(void *ctx) { (void)ctx; return wall; }
static bool fake_progress(void *ctx, char *line, size_t cap)
{
    (void)ctx;
    if (!fake.progress) return false;
    snprintf(line, cap, "%s", fake.progress);
    return true;
}
static void fake_dismiss(void *ctx) { (void)ctx; ++fake.dismissed; fake.progress = NULL; }
static bool fake_reveal_start(void *ctx)
{
    (void)ctx;
    ++fake.reveal_started;
    if (fake.reveal_refused) return false;
    fake.reveal = fake.reveal_after_start;
    return true;
}
static enum wallet_reveal fake_reveal_state(void *ctx) { (void)ctx; return fake.reveal; }
static void fake_reveal_end(void *ctx) { (void)ctx; ++fake.reveal_ended; fake.reveal = WALLET_REVEAL_NONE; }
/* Whether the environment offers Show private balance at all. */
static bool with_reveal = true;
static bool fake_copy_address(void *ctx, const char *address)
{
    (void)ctx;
    ++fake.copy_calls;
    snprintf(fake.copied, sizeof(fake.copied), "%s", address);
    return fake.copy_ok;
}
/* The balance key in memory: XOR with a stream drawn from the nonce, and a tag over the bound data, the nonce and the sealed bytes,
 * so a changed byte or other bound data does not open. refuse stands for a key that is gone or a phone that is locked. */
static struct { bool refuse; int seals, unseals; uint8_t counter; } keystore;
static bool with_seal = true;
static uint64_t mix(uint64_t hash, const uint8_t *bytes, size_t len)
{
    for (size_t i = 0; i < len; ++i) { hash ^= bytes[i]; hash *= 1099511628211ull; }
    return hash;
}
static void fake_tag(const uint8_t *aad, size_t aad_len, const uint8_t iv[WALLET_SEAL_IV], const uint8_t *sealed, size_t len,
                     uint8_t tag[WALLET_SEAL_TAG])
{
    uint64_t hash = mix(mix(mix(1469598103934665603ull, aad, aad_len), iv, WALLET_SEAL_IV), sealed, len);
    for (unsigned i = 0; i < WALLET_SEAL_TAG; ++i) { hash = hash * 6364136223846793005ull + 1442695040888963407ull; tag[i] = (uint8_t)(hash >> 56); }
}
static uint8_t stream(const uint8_t iv[WALLET_SEAL_IV], size_t i) { return (uint8_t)(0x5a ^ iv[i % WALLET_SEAL_IV] ^ (i * 31u)); }
static bool fake_seal(void *ctx, const uint8_t *aad, size_t aad_len, const uint8_t *plain, size_t len, uint8_t iv[WALLET_SEAL_IV],
                      uint8_t *out)
{
    (void)ctx;
    ++keystore.seals;
    if (keystore.refuse) return false;
    ++keystore.counter;
    for (unsigned i = 0; i < WALLET_SEAL_IV; ++i) iv[i] = (uint8_t)(keystore.counter * 13u + i);
    for (size_t i = 0; i < len; ++i) out[i] = plain[i] ^ stream(iv, i);
    fake_tag(aad, aad_len, iv, out, len, out + len);
    return true;
}
static bool fake_unseal(void *ctx, const uint8_t *aad, size_t aad_len, const uint8_t iv[WALLET_SEAL_IV], const uint8_t *sealed,
                        size_t len, uint8_t *plain)
{
    uint8_t tag[WALLET_SEAL_TAG];
    (void)ctx;
    ++keystore.unseals;
    if (keystore.refuse || len < WALLET_SEAL_TAG) return false;
    fake_tag(aad, aad_len, iv, sealed, len - WALLET_SEAL_TAG, tag);
    if (memcmp(tag, sealed + len - WALLET_SEAL_TAG, WALLET_SEAL_TAG)) return false;
    for (size_t i = 0; i + WALLET_SEAL_TAG < len; ++i) plain[i] = sealed[i] ^ stream(iv, i);
    return true;
}

static void start(bool async)
{
    struct wallet_env env = {NULL, fake_secure, fake_run, fake_changed, fake_now, async, fake_refusal, fake_node_running, fake_copy_address,
                             cache_dir[0] ? cache_dir : NULL, fake_wall, fake_progress, fake_dismiss,
                             with_reveal ? fake_reveal_start : NULL, with_reveal ? fake_reveal_state : NULL,
                             with_reveal ? fake_reveal_end : NULL, with_seal ? fake_seal : NULL, with_seal ? fake_unseal : NULL};
    wallet_screens_shutdown();
    memset(&fake, 0, sizeof(fake));
    memset(&keystore, 0, sizeof(keystore));
    pthread_mutex_init(&fake.lock, NULL);
    pthread_cond_init(&fake.cond, NULL);
    fake.secure_ok = true;
    fake.async = async;
    fake.now = 1000000;
    fake.node_up = true;
    fake.copy_ok = true;
    fake.summary = cache_dir[0] ? GOOD_SUMMARY_LOCKED : GOOD_SUMMARY;   /* a balance is kept from what shows without the screen lock */
    fake.reveal_after_start = WALLET_REVEAL_ASKING;
    fake.latest = "{\"ok\":true,\"data\":{\"address\":\"" A1 "\"}}";
    fake.receive = "{\"ok\":true,\"data\":{\"address\":\"" A2 "\"}}";
    fake.history[0] = HISTORY_PAGE0;
    fake.history[1] = HISTORY_PAGE1;
    CHECK(wallet_screens_init(&env));
}

static struct wallet_screen screen;
static struct wallet_screen *snap(void) { (void)wallet_screens_snapshot(&screen); return &screen; }
static long find(const struct wallet_screen *s, enum wallet_item_kind kind, enum wallet_action action)
{
    for (size_t i = 0; i < s->count; ++i) if (s->items[i].kind == kind && s->items[i].action == action) return (long)i;
    return -1;
}
static long find_text(const struct wallet_screen *s, const char *text)
{
    for (size_t i = 0; i < s->count; ++i) if (strstr(s->items[i].text, text)) return (long)i;
    return -1;
}
static const char *text_at(const struct wallet_screen *s, long i) { CHECK(i >= 0 && (size_t)i < s->count); return s->items[i].text; }
static int count_ops(const char *op) { return fake.counts[op_slot(op)]; }
static void tap(enum wallet_action action, unsigned arg, enum wallet_outcome want) { CHECK(wallet_screens_activate(action, arg) == want); }
static bool has(const char *text) { return find_text(snap(), text) >= 0; }
static void wait_for(bool (*done)(void))
{
    for (int i = 0; i < 1000 && !done(); ++i) usleep(5000);
    CHECK(done());
}
static bool settled(void)
{
    pthread_mutex_lock(&fake.lock);
    bool idle = fake.active == 0;
    pthread_mutex_unlock(&fake.lock);
    return idle;
}
static void set_block(void)
{
    pthread_mutex_lock(&fake.lock);
    fake.block = true;
    pthread_mutex_unlock(&fake.lock);
}
/* Whether the commands of a freshly opened Funds screen have all run and none is running. */
static bool funds_commands_done(void)
{
    pthread_mutex_lock(&fake.lock);
    bool done = fake.counts[0] >= 1 && fake.counts[1] >= 1 && fake.active == 0;
    pthread_mutex_unlock(&fake.lock);
    return done;
}
static void release_block(void)
{
    pthread_mutex_lock(&fake.lock);
    fake.block = false;
    pthread_cond_broadcast(&fake.cond);
    pthread_mutex_unlock(&fake.lock);
}

/* ---- Funds ---- */

static void test_funds(void)
{
    start(false);
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS) && fake.secure_on);
    struct wallet_screen *s = snap();
    long amount = find(s, WALLET_ITEM_AMOUNT, WALLET_ACT_NONE), pending = find_text(s, "pending"), pub = find_text(s, "public");
    CHECK(amount >= 0 && !strcmp(text_at(s, amount), "1.23456789 ZCL"));
    CHECK(pending > amount && !strcmp(text_at(s, pending), "0.5 ZCL pending in 2 payments. The next arrives in 7 confirmations."));
    CHECK(pub > pending && !strcmp(text_at(s, pub), "0.1 ZCL public: visible to everyone, not part of the spendable amount"));
    CHECK(find_text(s, "Up to date at block 3000000") > pub);
    CHECK(find_text(s, WALLET_FLEET_UNCHECKED) > 0);     /* the fake node has no fleet command */
    CHECK(strcmp(text_at(s, amount), text_at(s, pending)) && !strstr(text_at(s, amount), "0.5"));
    CHECK(find(s, WALLET_ITEM_BUTTON, WALLET_ACT_RECEIVE) >= 0 && find(s, WALLET_ITEM_BUTTON, WALLET_ACT_SEND) >= 0);
    CHECK(find(s, WALLET_ITEM_BUTTON, WALLET_ACT_HISTORY) >= 0 && find(s, WALLET_ITEM_BUTTON, WALLET_ACT_BACK) >= 0);
    CHECK(count_ops("summary") == 1 && count_ops("fleet") == 1 && fake.changed == 2);
    wallet_screens_close();
}

static void funds_no_extra_lines(void)
{
    fake.summary = SUMMARY("5", "0.00000005", "0", "0.00000000", "0", "0.00000000");   /* nothing arriving and no public funds: no such lines */
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    CHECK(!has("arriving") && !has("public") && has("0.00000005 ZCL"));
}
static void funds_node_silent(void)
{
    fake.summary = NODE_UNAVAILABLE_ERROR;    /* a stopped node that does not answer: one line and Start node, never a zero that was not read */
    fake.node_up = false;
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    CHECK(has("Node stopped. Start it to see your funds.") && !has("unknown") && !has("ZCL") && !has("could not be read"));
    CHECK(find(snap(), WALLET_ITEM_AMOUNT, WALLET_ACT_NONE) < 0 && find(snap(), WALLET_ITEM_BUTTON, WALLET_ACT_START_NODE) >= 0);
    int silent_ops = fake.op_count;
    tap(WALLET_ACT_START_NODE, 0, WALLET_START_NODE);              /* the shell hands the start to the controller; nothing else runs */
    CHECK(fake.op_count == silent_ops);

    fake.summary = "{\"ok\":false}\nThe command timed out.";                       /* so does one that takes too long */
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    CHECK(has("Node stopped. Start it to see your funds.") && find(snap(), WALLET_ITEM_BUTTON, WALLET_ACT_START_NODE) >= 0);
    fake.node_up = true;
}
/* A node that gave no answer is "stopped", with Start node, only when its process is known not to run. A running process is
 * starting or busy: the owner is told to wait and Start is not offered, because the controller would refuse it. */
static void funds_node_stopped_or_starting(void)
{
    fake.summary = NODE_UNAVAILABLE_ERROR;
    fake.node_up = false;
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    CHECK(has("Node stopped. Start it to see your funds.") && !has("Waiting for your node") && find(snap(), WALLET_ITEM_BUTTON, WALLET_ACT_START_NODE) >= 0);
    fake.node_up = true;
    fake.copy_ok = true;
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    CHECK(has("Waiting for your node. It is running") && !has("Node stopped") && !has("Start it") && !has("ZCL"));
    CHECK(find(snap(), WALLET_ITEM_BUTTON, WALLET_ACT_START_NODE) < 0 && find(snap(), WALLET_ITEM_AMOUNT, WALLET_ACT_NONE) < 0);
}
static void funds_node_answers(void)
{
    static const char *const answering[] = {                       /* a node that answers, even with an error, is running: Start would only say so */
        OTHER_ERROR, UNKNOWN_COMMAND_ERROR, "{\"ok\":false,\"error\":{\"code\":\"WALLET_DB_UNREADABLE\",\"message\":\"Wallet database unreadable\"}}",
    };
    for (size_t i = 0; i < sizeof(answering) / sizeof(answering[0]); ++i) {
        fake.summary = answering[i];
        CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
        CHECK(has("Balance unknown") && !has("not answering") && !has("0 ZCL") && find(snap(), WALLET_ITEM_BUTTON, WALLET_ACT_START_NODE) < 0);
    }
    fake.summary = "{\"ok\":true,\"data\":{\"x\":1}}";             /* a node that answers with something else: unknown, never zero */
    fake.always_ok = true;
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    CHECK(has("Balance unknown") && !has("0 ZCL") && has("could not be read") && !has("not answering"));
    CHECK(find(snap(), WALLET_ITEM_BUTTON, WALLET_ACT_START_NODE) < 0);
    fake.always_ok = false;

    /* A reply that says ok:false is no reply, whatever data it carries. */
    fake.summary = "{\"ok\":false,\"data\":\"x\"}";
    fake.always_ok = true;
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS) && has("Balance unknown"));
    fake.always_ok = false;
    fake.summary = GOOD_SUMMARY;

}
static void test_funds_replies(void)
{
    start(false);
    funds_no_extra_lines();
    funds_node_silent();
    funds_node_stopped_or_starting();
    funds_node_answers();
    int before = fake.op_count;               /* Send opens the Send screen and starts nothing */
    tap(WALLET_ACT_SEND, 0, WALLET_SEND);
    CHECK(fake.op_count == before && snap()->page == WALLET_PAGE_FUNDS);
    tap(WALLET_ACT_BACK, 0, WALLET_LEAVE);
    wallet_screens_close();
    CHECK(!fake.secure_on && !wallet_screens_active() && snap()->count == 0);
}

static void fleet_line(const char *reply_text, const char *want)
{
    start(false);
    fake.fleet = reply_text;
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    CHECK(has(want));
    CHECK(strcmp(want, WALLET_FLEET_UNCHECKED) == 0 || !has(WALLET_FLEET_UNCHECKED));
    if (strcmp(want, WALLET_FLEET_UNCHECKED)) CHECK(has("fleet machine"));
    wallet_screens_close();
}
static void test_fleet(void)
{
    fleet_line(FLEET("true", "agree", "2", "2", MACHINE("r1", "true", "agrees") "," MACHINE("r2", "true", "agrees")), "2 fleet machines agree");
    fleet_line(FLEET("true", "agree", "2", "1", MACHINE("r1", "true", "agrees") "," MACHINE("mac", "false", "unknown")), "1 fleet machine agrees");
    fleet_line(FLEET_R("true", "disagree", "true", "3", "3", MACHINE("a", "true", "agrees") "," MACHINE("b", "true", "disagree") "," MACHINE("c", "true", "agrees")),
               "1 of 3 fleet machines disagree: sending waits");
    fleet_line(FLEET_R("true", "disagree", "true", "2", "2", MACHINE("a", "true", "disagree") "," MACHINE("b", "true", "disagree")),
               "2 of 2 fleet machines disagree: sending waits");
    /* A machine on a fork far below the tip is reported, but the node does not hold sending back for it. */
    fleet_line(FLEET_R("true", "disagree", "false", "2", "2", MACHINE("a", "true", "agrees") "," MACHINE("b", "true", "disagree")),
               "1 of 2 fleet machines last reported another chain at a lower height: sending is not held back");
    fleet_line(FLEET("true", "agree", "3", "3", MACHINE("a", "true", "agrees") "," MACHINE("b", "true", "phone_behind") "," MACHINE("c", "true", "machine_behind")),
               "2 fleet machines agree");
    /* One block behind on this chain still agrees with it, so a one-machine fleet reads so after every block. */
    fleet_line(FLEET("true", "agree", "1", "1", MACHINE("a", "true", "machine_behind")), "1 fleet machine agrees");
    fleet_line(FLEET("true", "none_connected", "1", "0", MACHINE("a", "false", "unknown")), WALLET_FLEET_UNCHECKED);
    fleet_line(FLEET("false", "not_member", "0", "0", ""), WALLET_FLEET_UNCHECKED);
    /* Anything but the exact frame reads as not checked. */
    static const char *const bad[] = {
        "{\"ok\":true,\"data\":{\"connected\":2}}",
        "{\"ok\":true,\"data\":{\"connected\":2,\"disagree\":0}}",
        "{\"ok\":true,\"data\":{\"connected\":2,\"disagree\":\"1\"}}",
        "{\"ok\":true,\"data\":{\"connected\":3,\"disagree\":1}}",
        "{\"ok\":false,\"data\":" FLEET("true", "agree", "1", "1", MACHINE("a", "true", "agrees")) "}",
        "{\"ok\":true,\"data\":[]}", "[]", "1", "{}", "",
        FLEET("true", "agree", "1", "1", MACHINE("a", "true", "agrees")) "x",
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.fleet_status.v2\",\"member\":true,\"verdict\":\"agree\",\"machines_total\":1,"
        "\"refuses_send\":false,\"machines_connected\":1,\"local_tip\":1,\"machines\":[" MACHINE("a", "true", "agrees") "]}}",
        /* the earlier frame: no refuses_send, and local_best_header for local_tip */
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.fleet_status.v1\",\"member\":true,\"verdict\":\"agree\",\"machines_total\":1,\"machines_connected\":1,"
        "\"local_best_header\":3000000,\"machines\":[" MACHINE("a", "true", "agrees") "]}}",
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.fleet_status.v1\",\"member\":true,\"verdict\":\"agree\",\"refuses_send\":\"false\",\"machines_total\":1,"
        "\"machines_connected\":1,\"local_tip\":3000000,\"machines\":[" MACHINE("a", "true", "agrees") "]}}",
        FLEET_R("true", "disagree", "true", "1", "1", MACHINE("a", "true", "agrees")),                      /* a refusal with nobody apart */
        FLEET_R("true", "agree", "true", "1", "1", MACHINE("a", "true", "agrees")),                         /* agree that refuses sending */
        FLEET("true", "agree", "1", "1", MACHINE("a", "true", "phone_behind")),                            /* agree with no machine agreeing */
        FLEET("true", "unchecked", "1", "1", MACHINE("a", "true", "phone_behind")),
        FLEET_R("true", "disagree", "true", "2", "1", MACHINE("a", "true", "disagree") "," MACHINE("b", "false", "disagree")),   /* a machine that is down cannot disagree */
        FLEET("true", "agree", "1", "1", MACHINE("a", "true", "ahead")),                                    /* names of the earlier frame */
        FLEET("true", "agree", "1", "1", MACHINE("a", "true", "behind")),
        FLEET("true", "agree", "1", "2", MACHINE("a", "true", "agrees")),                                  /* connected count disagrees with the list */
        FLEET("true", "agree", "2", "1", MACHINE("a", "true", "agrees")),                                  /* total disagrees with the list */
        FLEET("true", "agree", "2", "2", MACHINE("a", "true", "agrees") "," MACHINE("b", "true", "disagree")), /* agree beside a disagreeing machine */
        FLEET("true", "agree", "1", "0", MACHINE("a", "false", "unknown")),                                /* agree with nobody connected */
        FLEET("false", "agree", "1", "1", MACHINE("a", "true", "agrees")),                                 /* agree from a non-member */
        FLEET("true", "disagree", "1", "1", MACHINE("a", "true", "agrees")),                               /* disagree with nobody apart */
        FLEET("true", "agree", "1", "1", MACHINE("a", "true", "maybe")),
        FLEET("true", "agree", "1", "1", MACHINE("a", "false", "agrees")),                                 /* a machine that is down cannot agree */
        FLEET("true", "agree", "1", "1", "\"x\""),
        FLEET("true", "agree", "1", "1", "{\"name\":\"a\",\"connected\":1,\"agreement\":\"agrees\"}"),
        FLEET("\"true\"", "agree", "1", "1", MACHINE("a", "true", "agrees")),
        FLEET("true", "yes", "1", "1", MACHINE("a", "true", "agrees")),
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        start(false);
        fake.fleet = bad[i];
        fake.always_ok = true;
        CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
        CHECK(has(WALLET_FLEET_UNCHECKED) && !has("agree") && !has("disagree"));
        wallet_screens_close();
    }
}

static void test_refresh_and_stale(void)
{
    start(false);                                  /* a stopped node: the next refresh fails, so nothing confident stays */
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS) && has("Up to date at block 3000000"));
    fake.now += WALLET_REFRESH_MS - 1;
    wallet_screens_tick();
    CHECK(count_ops("summary") == 1);
    fake.now += 1;
    fake.summary = NODE_UNAVAILABLE_ERROR;         /* the node stops answering */
    wallet_screens_tick();
    CHECK(count_ops("summary") == 2 && has("Waiting for your node") && !has("Up to date"));
    fake.summary = GOOD_SUMMARY;
    fake.now += WALLET_REFRESH_MS;
    wallet_screens_tick();
    CHECK(count_ops("summary") == 3 && has("Up to date at block 3000000"));
    tap(WALLET_ACT_HISTORY, 0, WALLET_STAY);       /* no refresh off Funds */
    int before = fake.op_count;
    fake.now += WALLET_REFRESH_MS * 3;
    wallet_screens_tick();
    CHECK(fake.op_count == before);
    wallet_screens_close();

    start(true);                                   /* a node that never answers: the old lines are withdrawn */
    fake.fleet = FLEET("true", "agree", "1", "1", MACHINE("fleetbox", "true", "agrees"));
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    wait_for(funds_commands_done);                 /* both opening commands have finished before the node is stopped */
    for (int i = 0; i < 400 && !(has("Up to date") && has("1 fleet machine agrees")); ++i) usleep(5000);
    CHECK(has("Up to date at block 3000000") && has("1 fleet machine agrees"));
    set_block();
    fake.now += WALLET_REFRESH_MS;
    wallet_screens_tick();
    fake.now += WALLET_STALE_MS;
    wallet_screens_tick();
    CHECK(has("Last read more than 30 seconds ago") && !has("Up to date") && has(WALLET_FLEET_UNCHECKED) && !has("agree"));
    unsigned before_version = wallet_screens_snapshot(&screen);
    fake.now += 1000;
    wallet_screens_tick();
    CHECK(wallet_screens_snapshot(&screen) == before_version);   /* the notice appears once, not on every tick */
    release_block();
    for (int i = 0; i < 1000 && !has("Up to date"); ++i) usleep(5000);
    CHECK(has("Up to date at block 3000000") && !has("Last read more than"));
    wallet_screens_close();
    wait_for(settled);
}

/* ---- the payment in flight ---- */

#define SENDING_LINE "Sending 1.5 ZCL to zs1abcde…uvwxyz: building the payment (about 2 min)"

/* A line from the send flow sits right under the balance, follows the flow on every refresh, and a finished one can be dismissed. */
static void test_send_line(void)
{
    start(false);
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    CHECK(find_text(snap(), "Sending") < 0 && find_text(snap(), "Sent") < 0 && find(snap(), WALLET_ITEM_BUTTON, WALLET_ACT_DISMISS_SEND) < 0);
    fake.progress = SENDING_LINE;                       /* a payment starts while Funds is in front: the next tick draws it */
    wallet_screens_tick();
    struct wallet_screen *s = snap();
    long amount = find(s, WALLET_ITEM_AMOUNT, WALLET_ACT_NONE), line = find_text(s, "Sending 1.5 ZCL");
    CHECK(amount >= 0 && line == amount + 1 && !strcmp(text_at(s, line), SENDING_LINE));
    CHECK(find(s, WALLET_ITEM_BUTTON, WALLET_ACT_DISMISS_SEND) < 0);          /* nothing to dismiss while it runs */
    tap(WALLET_ACT_DISMISS_SEND, 0, WALLET_STAY);
    CHECK(fake.dismissed == 0 && has("Sending 1.5 ZCL"));

    fake.progress = "Sent 1.5 ZCL";                     /* a refresh on resume, without waiting for a tick */
    wallet_screens_refresh_send();
    s = snap();
    long done = find_text(s, "Sent 1.5 ZCL"), dismiss = find(s, WALLET_ITEM_BUTTON, WALLET_ACT_DISMISS_SEND);
    CHECK(done == amount + 1 && dismiss == done + 1 && !strcmp(text_at(s, dismiss), "Dismiss") && find_text(s, "Sending") < 0);
    tap(WALLET_ACT_DISMISS_SEND, 0, WALLET_STAY);
    CHECK(fake.dismissed == 1 && find_text(snap(), "Sent 1.5") < 0 && find(snap(), WALLET_ITEM_BUTTON, WALLET_ACT_DISMISS_SEND) < 0);
    wallet_screens_tick();
    CHECK(find_text(snap(), "Sent 1.5") < 0);          /* the flow forgot it, so it stays gone */

    static const char *const ended[] = {"Already sent 2 ZCL", "Payment not sent: the node refused it. Your coins were not spent.",
                                        "Payment status unknown: the node did not answer. It may have been sent."};
    for (size_t i = 0; i < 3; ++i) {
        fake.progress = ended[i];
        wallet_screens_tick();
        CHECK(find_text(snap(), ended[i]) >= 0 && find(snap(), WALLET_ITEM_BUTTON, WALLET_ACT_DISMISS_SEND) >= 0);
        tap(WALLET_ACT_DISMISS_SEND, 0, WALLET_STAY);
        CHECK(fake.dismissed == (int)i + 2 && find_text(snap(), ended[i]) < 0);
    }
    fake.progress = SENDING_LINE;
    wallet_screens_close();
    CHECK(!wallet_screens_residue("building the payment", 20));   /* leaving wipes it */
}

/* The line shows before the node has answered, with or without a last known balance, and when the node is silent. */
static void test_send_line_before_answer(void)
{
    start(true);
    set_block();
    fake.progress = SENDING_LINE;
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    long loading = find_text(snap(), "Loading"), line = find_text(snap(), "Sending 1.5 ZCL");
    CHECK(loading >= 0 && line == loading + 1);
    release_block();
    wait_for(settled);
    wallet_screens_close();

    start(false);
    fake.summary = NODE_UNAVAILABLE_ERROR;
    fake.progress = "Sent 1.5 ZCL";
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    CHECK(has("Sent 1.5 ZCL") && has("Waiting for your node") && find(snap(), WALLET_ITEM_BUTTON, WALLET_ACT_DISMISS_SEND) >= 0);
    wallet_screens_close();
}

/* ---- last known balance ---- */

#define CACHE "wallet_balance_sealed"
#define PLAIN_CACHE "wallet_balance_cache"
#define SEALED_TAG "z23-balance-sealed-v1\n"
#define SEALED_TAG_LEN (sizeof(SEALED_TAG) - 1u)
#define SEALED_HEAD (SEALED_TAG_LEN + WALLET_SEAL_IV)

static void put_bytes(const char *name, const void *bytes, size_t len)
{
    char path[PATH_MAX + 32];
    snprintf(path, sizeof(path), "%s/%s", cache_dir, name);
    FILE *f = fopen(path, "wb");
    CHECK(f && fwrite(bytes, 1, len, f) == len);
    if (f) fclose(f);
}
static void put_file(const char *name, const char *text) { put_bytes(name, text, strlen(text)); }
static size_t get_bytes(const char *name, uint8_t *out, size_t cap)
{
    char path[PATH_MAX + 32];
    snprintf(path, sizeof(path), "%s/%s", cache_dir, name);
    FILE *f = fopen(path, "rb");
    size_t n = f ? fread(out, 1, cap, f) : 0;
    if (f) fclose(f);
    return n;
}
static bool bytes_hold(const uint8_t *bytes, size_t n, const char *text)
{
    size_t len = strlen(text);
    for (size_t i = 0; i + len <= n; ++i) if (!memcmp(bytes + i, text, len)) return true;
    return false;
}
static bool file_exists(const char *name)
{
    char path[PATH_MAX + 32];
    struct stat info;
    snprintf(path, sizeof(path), "%s/%s", cache_dir, name);
    return lstat(path, &info) == 0;
}
static bool item_is(const char *text)
{
    const struct wallet_screen *s = snap();
    for (size_t i = 0; i < s->count; ++i) if (!strcmp(s->items[i].text, text)) return true;
    return false;
}
static void remove_dir(void)
{
    static const char *const names[] = {"wallet_key.blob", CACHE, CACHE ".tmp", PLAIN_CACHE, "elsewhere"};
    char path[PATH_MAX + 32];
    for (int attempt = 0; attempt < 400; ++attempt) {      /* a write the last reply started may still be finishing */
        for (size_t i = 0; i < 5; ++i) { snprintf(path, sizeof(path), "%s/%s", cache_dir, names[i]); (void)unlink(path); }
        if (rmdir(cache_dir) == 0) { cache_dir[0] = '\0'; return; }
        usleep(5000);
    }
    CHECK(false);
}
static bool live_shown(void) { return find_text(snap(), "Up to date") >= 0; }
static bool node_waited(void) { return find_text(snap(), "Waiting for your node") >= 0; }
static bool cache_present(void) { return file_exists(CACHE); }
/* A fresh files directory under TMPDIR, which the Makefile points at the build directory so no test writes to /tmp. */
static void make_dir(void)
{
    const char *base = getenv("TMPDIR");
    CHECK(base && base[0]);
    snprintf(cache_dir, sizeof(cache_dir), "%s/z23-balance-XXXXXX", base && base[0] ? base : ".");
    CHECK(mkdtemp(cache_dir) != NULL);
}
/* A wallet directory holding key file "one", whose first live summary, of an encrypted wallet that is locked and shows its
 * amounts, leaves the sealed balance file. */
static void wallet_with_balance(void)
{
    make_dir();
    put_file("wallet_key.blob", "key file one");
    wall = 1700000000;
    start(false);
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS) && has("1.23456789 ZCL"));
    wallet_screens_close();
}
/* Opens Funds while the node has not answered and returns with the first screen. */
static struct wallet_screen *open_waiting(void)
{
    start(true);
    set_block();
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    return snap();
}
static void finish_waiting(void)
{
    release_block();
    wait_for(live_shown);
    wallet_screens_close();
}
/* The kept balance as Funds draws it: its heading, the amount and under it the age line. */
static bool cached_shown(const struct wallet_screen *s, const char *amount, const char *age)
{
    long at = find(s, WALLET_ITEM_AMOUNT, WALLET_ACT_NONE);
    return at >= 1 && (size_t)at + 1 < s->count && !strcmp(text_at(s, at), amount) &&
           !strcmp(text_at(s, at - 1), "Last known balance") && !strcmp(text_at(s, at + 1), age);
}

static void test_cache_roundtrip(void)
{
    wallet_with_balance();
    uint8_t bytes[1024];
    char path[PATH_MAX + 32];
    struct stat info;
    snprintf(path, sizeof(path), "%s/" CACHE, cache_dir);
    CHECK(stat(path, &info) == 0 && (info.st_mode & 0777) == 0600 && !file_exists(CACHE ".tmp") && !file_exists(PLAIN_CACHE));
    size_t n = get_bytes(CACHE, bytes, sizeof(bytes));
    size_t body = strlen("z23-balance-cache-v1\n") + 17 + strlen("1700000000\n1.23456789 ZCL\n") +
                  strlen("0.5 ZCL pending in 2 payments. The next arrives in 7 confirmations.\n") +
                  strlen("0.1 ZCL public: visible to everyone, not part of the spendable amount\n");
    CHECK(n == SEALED_HEAD + body + WALLET_SEAL_TAG && !memcmp(bytes, SEALED_TAG, SEALED_TAG_LEN) && keystore.seals == 1);
    CHECK(!bytes_hold(bytes, n, "ZCL") && !bytes_hold(bytes, n, "1.23456789") && !bytes_hold(bytes, n, "1700000000"));
    wall += 300;                                                   /* five minutes later, before the node answers */
    struct wallet_screen *s = open_waiting();
    CHECK(find_text(s, "Loading") < 0 && !item_is("Balance") && keystore.unseals == 1);
    CHECK(cached_shown(s, "1.23456789 ZCL", "As of 5 min ago, updating"));
    long amount = find(s, WALLET_ITEM_AMOUNT, WALLET_ACT_NONE);
    CHECK(find_text(s, "0.5 ZCL pending") > amount && find_text(s, "0.1 ZCL public") > amount);
    CHECK(find_text(s, "Up to date") < 0 && find(s, WALLET_ITEM_BUTTON, WALLET_ACT_SEND) >= 0);
    wall += 600;                                                   /* the age line follows the clock */
    wallet_screens_tick();
    CHECK(cached_shown(snap(), "1.23456789 ZCL", "As of 15 min ago, updating"));
    release_block();                                               /* the node answers: live data replaces it */
    wait_for(live_shown);
    CHECK(!has("Last known") && !has("As of") && item_is("Balance") && has("Up to date at block 3000000"));
    wallet_screens_close();
    remove_dir();

    make_dir();                                                    /* a wallet without encryption is kept the same way */
    put_file("wallet_key.blob", "key file one");
    start(false);
    fake.summary = GOOD_SUMMARY_PLAIN;
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS) && has("1.23456789 ZCL"));
    wallet_screens_close();
    n = get_bytes(CACHE, bytes, sizeof(bytes));
    CHECK(n > SEALED_HEAD && !memcmp(bytes, SEALED_TAG, SEALED_TAG_LEN) && !bytes_hold(bytes, n, "ZCL"));
    remove_dir();
}

static void test_cache_other_wallet(void)
{
    wallet_with_balance();
    put_file("wallet_key.blob", "key file two");                  /* the first wallet was set aside and another made */
    struct wallet_screen *s = open_waiting();
    CHECK(find_text(s, "Last known") < 0 && find_text(s, "1.23456789") < 0 && find_text(s, "Loading") >= 0);
    CHECK(!file_exists(CACHE));                                     /* the other wallet's balance is deleted, not kept */
    finish_waiting();
    wait_for(cache_present);                                        /* the live summary starts the new wallet's own */
    remove_dir();

    wallet_with_balance();
    char path[PATH_MAX + 32];
    snprintf(path, sizeof(path), "%s/wallet_key.blob", cache_dir);
    CHECK(unlink(path) == 0);                                       /* no key file: no wallet to show a balance for */
    s = open_waiting();
    CHECK(find_text(s, "Last known") < 0 && !file_exists(CACHE));
    finish_waiting();
    remove_dir();
}

/* 16 hex digits of the FNV-1a hash of a key file, as the screens name a wallet. */
static void identity_of(const char *key_file, char out[17])
{
    uint64_t hash = 1469598103934665603ull;
    for (const char *p = key_file; *p; ++p) { hash ^= (unsigned char)*p; hash *= 1099511628211ull; }
    snprintf(out, 17, "%016llx", (unsigned long long)hash);
}
/* A file sealed for the wallet of key file "one" whose body is text, as a writer that is not the screens could leave it. */
static void put_sealed(const char *text)
{
    uint8_t aad[64], out[1024];
    char wallet[17];
    identity_of("key file one", wallet);
    memcpy(aad, SEALED_TAG, SEALED_TAG_LEN);
    memcpy(aad + SEALED_TAG_LEN, wallet, 16);
    memcpy(out, SEALED_TAG, SEALED_TAG_LEN);
    size_t len = strlen(text);
    CHECK(fake_seal(NULL, aad, SEALED_TAG_LEN + 16, (const uint8_t *)text, len, out + SEALED_TAG_LEN, out + SEALED_HEAD));
    put_bytes(CACHE, out, SEALED_HEAD + len + WALLET_SEAL_TAG);
}

/* Every file that is not the sealed balance of this wallet, exactly, is deleted and shows nothing. */
static void test_cache_not_trusted(void)
{
    static const char *const bad[] = {"garbage\n", "", SEALED_TAG, "z23-balance-sealed-v2\n" "0123456789ab" "z23-balance-cache-v1\n"};
    for (size_t i = 0; i < 8; ++i) {
        wallet_with_balance();
        uint8_t bytes[1024];
        size_t n = get_bytes(CACHE, bytes, sizeof(bytes));
        if (i < 4) put_file(CACHE, bad[i]);
        else if (i == 4) { bytes[SEALED_HEAD + 3] ^= 1; put_bytes(CACHE, bytes, n); }        /* a changed byte */
        else if (i == 5) { bytes[SEALED_TAG_LEN - 2] = '9'; put_bytes(CACHE, bytes, n); }    /* a version this build does not know */
        else if (i == 6) put_bytes(CACHE, bytes, n - 1);                                     /* cut short */
        else put_sealed("z23-balance-cache-v1\nffffffffffffffff\n1700000000\n42 ZCL\n\n\n");   /* names another wallet inside */
        struct wallet_screen *s = open_waiting();
        CHECK(find_text(s, "Last known") < 0 && find_text(s, "ZCL") < 0 && find_text(s, "Loading") >= 0 && !file_exists(CACHE));
        finish_waiting();
        remove_dir();
    }
    wallet_with_balance();                                          /* the key is gone or the phone is locked: nothing opens */
    start(true);
    keystore.refuse = true;
    set_block();
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS) && find_text(snap(), "Last known") < 0 && !file_exists(CACHE));
    finish_waiting();
    CHECK(!file_exists(CACHE) && !file_exists(CACHE ".tmp"));       /* a seal that fails writes nothing */
    remove_dir();

    wallet_with_balance();                                          /* the plain text file of an earlier build is removed */
    put_file(PLAIN_CACHE, "z23-balance-cache-v1\nffffffffffffffff\n1700000000\n42 ZCL\n\n\n");
    struct wallet_screen *s = open_waiting();
    CHECK(!file_exists(PLAIN_CACHE) && find_text(s, "42 ZCL") < 0 && cached_shown(s, "1.23456789 ZCL", "As of less than a minute ago, updating"));
    finish_waiting();
    remove_dir();

    wallet_with_balance();                                          /* a link in the file's place is never followed */
    char path[PATH_MAX + 32];
    snprintf(path, sizeof(path), "%s/" CACHE, cache_dir);
    char kept[PATH_MAX + 32];
    snprintf(kept, sizeof(kept), "%s/elsewhere", cache_dir);
    CHECK(rename(path, kept) == 0 && symlink(kept, path) == 0);
    s = open_waiting();
    CHECK(find_text(s, "Last known") < 0);
    finish_waiting();
    (void)unlink(kept);
    remove_dir();
}

/* Only a real summary is kept: an unreadable reply, a stopped node, a locked wallet that hides its amounts, a wallet unlocked for
 * the owner, and an environment without the key leave nothing. */
static void test_cache_only_real_summaries(void)
{
    static const char *const replies[] = {NODE_UNAVAILABLE_ERROR, "{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_summary.v1\"}}",
                                          SUMMARY_STATE("keys_unavailable", PRIVATE_HIDDEN, "10000000", "0.10000000"),
                                          LOCKED_SUMMARY, GOOD_SUMMARY, GOOD_SUMMARY_LOCKED};
    for (size_t i = 0; i < 6; ++i) {
        make_dir();
        put_file("wallet_key.blob", "key file one");
        with_seal = i < 5;
        start(false);
        fake.summary = replies[i];
        CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
        CHECK(!file_exists(CACHE) && keystore.seals == 0);
        wallet_screens_close();
        remove_dir();
    }
    with_seal = true;
}

/* A balance file dated ahead of this clock was not written by it: nothing is shown and the file is deleted. A small lead is clock slack. */
static void test_cache_from_the_future(void)
{
    make_dir();
    put_file("wallet_key.blob", "key file one");
    wall = 1700007200;                                             /* written when the clock said two hours later */
    start(false);
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS) && has("1.23456789 ZCL"));
    wallet_screens_close();
    CHECK(file_exists(CACHE));
    wall = 1700000000;
    struct wallet_screen *s = open_waiting();
    CHECK(find_text(s, "Last known") < 0 && find_text(s, "Loading") >= 0 && !file_exists(CACHE));
    finish_waiting();
    remove_dir();

    make_dir();
    put_file("wallet_key.blob", "key file one");
    wall = 1700000100;                                             /* 100 s ahead: within the slack */
    start(false);
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    wallet_screens_close();
    wall = 1700000000;
    s = open_waiting();
    CHECK(cached_shown(s, "1.23456789 ZCL", "As of less than a minute ago, updating"));
    finish_waiting();
    remove_dir();
}

/* A node that stops answering after it did answer shows the last balance with its age, beside the notice that it is waiting. Once
 * its process has stopped, the age line no longer says it is updating. */
static void test_cache_silent_node(void)
{
    wallet_with_balance();
    wall += 120;
    start(false);
    fake.summary = NODE_UNAVAILABLE_ERROR;
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    CHECK(cached_shown(snap(), "1.23456789 ZCL", "As of 2 min ago, updating") && has("Waiting for your node"));
    wallet_screens_close();
    start(false);
    fake.summary = NODE_UNAVAILABLE_ERROR;
    fake.node_up = false;
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    CHECK(cached_shown(snap(), "1.23456789 ZCL", "As of 2 min ago") && has("Node stopped. Start it to see your funds."));
    wallet_screens_close();
    remove_dir();
}

/* Setup has just made a wallet: Funds shows 0 ZCL at once while the node restarts, never as the live balance, until the node
 * answers. Without the call, as after a restore, Funds waits for the node. */
static void test_new_wallet_zero(void)
{
    make_dir();
    put_file("wallet_key.blob", "key file one");
    wall = 1700000000;
    struct wallet_screen *s = open_waiting();                       /* no call: nothing is known before the node answers */
    CHECK(find_text(s, "Loading") >= 0 && find(s, WALLET_ITEM_AMOUNT, WALLET_ACT_NONE) < 0);
    finish_waiting();
    remove_dir();

    make_dir();
    put_file("wallet_key.blob", "key file one");
    start(true);
    wallet_screens_new_wallet();
    uint8_t bytes[1024];
    size_t n = get_bytes(CACHE, bytes, sizeof(bytes));
    CHECK(n > SEALED_HEAD && !memcmp(bytes, SEALED_TAG, SEALED_TAG_LEN) && !bytes_hold(bytes, n, "ZCL") && keystore.seals == 1);
    wall += 70;                                                     /* the owner opens Funds while the node restarts */
    set_block();
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    s = snap();
    CHECK(cached_shown(s, "0 ZCL", "As of 1 min ago, updating") && find_text(s, "Loading") < 0 && !item_is("Balance"));
    CHECK(find_text(s, "Up to date") < 0 && find_text(s, "Updating your wallet") < 0);
    fake.summary = NODE_UNAVAILABLE_ERROR;                          /* the node is still starting */
    release_block();
    wait_for(node_waited);
    CHECK(cached_shown(snap(), "0 ZCL", "As of 1 min ago, updating"));
    fake.summary = GOOD_SUMMARY_LOCKED;                             /* it answers: the live summary replaces the kept zero */
    fake.now += WALLET_REFRESH_MS;
    wallet_screens_tick();
    wait_for(live_shown);
    CHECK(!has("Last known") && !has("As of") && item_is("Balance") && item_is("1.23456789 ZCL"));
    wallet_screens_close();
    remove_dir();

    make_dir();                                                     /* no key file, or no seal: nothing is kept */
    start(false);
    wallet_screens_new_wallet();
    CHECK(!file_exists(CACHE));
    put_file("wallet_key.blob", "key file one");
    with_seal = false;
    start(false);
    wallet_screens_new_wallet();
    CHECK(!file_exists(CACHE));
    with_seal = true;
    remove_dir();
}

/* ---- Make private ---- */

static long make_private_button(void) { return find(snap(), WALLET_ITEM_BUTTON, WALLET_ACT_MAKE_PRIVATE); }

/* Funds draws Make private under the public line when the public balance is above the fee and sending is allowed, and a tap
 * hands the shell the move; it never runs a command itself. */
static void test_make_private_offer(void)
{
    start(false);
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    long at = make_private_button(), pub = find_text(snap(), "0.1 ZCL public");
    CHECK(at >= 0 && pub >= 0 && at == pub + 1 && !strcmp(text_at(snap(), at), "Make private"));
    int ops = fake.op_count;
    tap(WALLET_ACT_MAKE_PRIVATE, 0, WALLET_MAKE_PRIVATE);
    CHECK(fake.op_count == ops && fake.reveal_started == 0);       /* the node is asked when the owner reviews, not by this tap */
    wallet_screens_close();

    /* A locked wallet that hides its private balance still shows its public one, and the move asks for the screen lock itself. */
    start(false);
    fake.summary = LOCKED_SUMMARY;
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS) && make_private_button() >= 0 && has("Show private balance"));
    wallet_screens_close();
}
/* The button is not drawn, and a tap that still arrives moves nothing, without a public amount above the fee, while sending
 * is paused, and while the node is silent. */
static void test_make_private_hidden(void)
{
    static const char *const none[] = {
        SUMMARY("123456789", "1.23456789", "0", "0.00000000", "0", "0.00000000"),                  /* no public amount */
        SUMMARY("123456789", "1.23456789", "0", "0.00000000", "10000", "0.00010000"),              /* exactly the fee */
        SUMMARY_SEND("123456789", "1.23456789", "0", "0.00000000", "10000000", "0.10000000", "false", "progress_store_unavailable"),
        NODE_UNAVAILABLE_ERROR, "{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_summary.v1\"}}",
    };
    for (size_t i = 0; i < sizeof(none) / sizeof(none[0]); ++i) {
        start(false);
        fake.summary = none[i];
        CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
        CHECK(make_private_button() < 0);
        tap(WALLET_ACT_MAKE_PRIVATE, 0, WALLET_STAY);
        wallet_screens_close();
    }
    start(false);
    fake.summary = SUMMARY("123456789", "1.23456789", "0", "0.00000000", "10001", "0.00010001");   /* one zatoshi above the fee */
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS) && make_private_button() >= 0);
    wallet_screens_close();
    tap(WALLET_ACT_MAKE_PRIVATE, 0, WALLET_STAY);                    /* no screen is open */
}

/* ---- Show private balance ---- */

static long reveal_button(void) { return find(snap(), WALLET_ITEM_BUTTON, WALLET_ACT_SHOW_PRIVATE); }
#define HIDDEN_LINE "Your private balance is hidden because the wallet is locked"

/* The button is drawn only for a wallet that is encrypted, locked, and hides its private amounts, and only where the app
 * can unlock it. */
static void test_reveal_offer(void)
{
    start(false);
    fake.summary = LOCKED_SUMMARY;
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    long at = reveal_button();
    CHECK(at >= 0 && !strcmp(text_at(snap(), at), "Show private balance") && has(HIDDEN_LINE));
    CHECK(fake.reveal_started == 0);                                  /* drawing it asks for nothing */
    wallet_screens_close();

    static const char *const none[] = {
        GOOD_SUMMARY,                                                 /* encrypted and unlocked: the amounts are shown */
        GOOD_SUMMARY_PLAIN,                                           /* not encrypted: nothing to unlock */
        SUMMARY_STATE_L("ok", "true", PRIVATE_OK("100000000", "1.00000000", "\"unready_zat\":0,\"unready\":\"0.00000000\","), "0", "0.00000000"),
        SUMMARY_STATE("keys_unavailable", PRIVATE_HIDDEN, "10000000", "0.10000000"),   /* hidden but not reported locked */
        NODE_UNAVAILABLE_ERROR, "{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_summary.v1\"}}",
    };
    for (size_t i = 0; i < sizeof(none) / sizeof(none[0]); ++i) {
        start(false);
        fake.summary = none[i];
        fake.node_up = true;
        CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
        CHECK(reveal_button() < 0);
        wallet_screens_close();
    }
    with_reveal = false;                                              /* an environment that cannot unlock draws no button */
    start(false);
    fake.summary = LOCKED_SUMMARY;
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS) && has(HIDDEN_LINE) && reveal_button() < 0);
    tap(WALLET_ACT_SHOW_PRIVATE, 0, WALLET_STAY);
    CHECK(fake.reveal_started == 0);
    wallet_screens_close();
    with_reveal = true;
}

/* The tap asks the environment once; the lines appear when the wallet opens and hide again when it locks. */
static void test_reveal_window(void)
{
    start(false);
    fake.summary = LOCKED_SUMMARY;
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS) && count_ops("summary") == 1);
    tap(WALLET_ACT_SHOW_PRIVATE, 0, WALLET_STAY);
    CHECK(fake.reveal_started == 1 && has("Confirm with your screen lock to show your private balance."));
    CHECK(reveal_button() < 0 && has(HIDDEN_LINE));                   /* no second tap while the prompt is up */
    tap(WALLET_ACT_SHOW_PRIVATE, 0, WALLET_STAY);
    CHECK(fake.reveal_started == 1);

    fake.summary = GOOD_SUMMARY;                                      /* the owner confirmed: the node is unlocked */
    fake.reveal = WALLET_REVEAL_OPEN;
    wallet_screens_refresh_send();                                    /* what the next draw does */
    CHECK(count_ops("summary") == 2);
    CHECK(has("1.23456789 ZCL") && !has(HIDDEN_LINE) && reveal_button() < 0 && !has("Confirm with your screen lock"));
    CHECK(has("hides again"));

    fake.summary = LOCKED_SUMMARY;                                    /* the window ended and the wallet was locked */
    fake.reveal = WALLET_REVEAL_NONE;
    wallet_screens_tick();
    CHECK(count_ops("summary") == 3);
    CHECK(has(HIDDEN_LINE) && !has("1.23456789") && reveal_button() >= 0 && !has("hides again"));
    CHECK(fake.reveal_ended == 0);
    wallet_screens_close();
    CHECK(fake.reveal_ended == 1);
}

/* A cancelled or refused prompt changes nothing on the wallet and says so; the button asks again. */
static void test_reveal_cancelled(void)
{
    static const struct { enum wallet_reveal state; const char *words; } cases[] = {
        {WALLET_REVEAL_CANCELLED, "Cancelled. Your private balance is still hidden."},
        {WALLET_REVEAL_NO_SCREEN_LOCK, "Set a screen lock on this phone to show your private balance."},
        {WALLET_REVEAL_KEY_GONE, "The wallet key on this phone is gone. Restore the wallet from its recovery phrase."},
        {WALLET_REVEAL_FAILED, "Could not unlock the wallet. Your private balance is still hidden. Try again."},
        {WALLET_REVEAL_SENDING, "A payment is in progress. Try again when it ends."},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        start(false);
        fake.summary = LOCKED_SUMMARY;
        CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
        fake.reveal_after_start = cases[i].state;
        tap(WALLET_ACT_SHOW_PRIVATE, 0, WALLET_STAY);
        CHECK(has(cases[i].words) && has(HIDDEN_LINE) && reveal_button() >= 0);
        CHECK(count_ops("summary") == 1);                             /* nothing opened: no reason to read it again */
        fake.reveal_after_start = WALLET_REVEAL_ASKING;
        tap(WALLET_ACT_SHOW_PRIVATE, 0, WALLET_STAY);
        CHECK(fake.reveal_started == 2 && has("Confirm with your screen lock") && !has(cases[i].words));
        wallet_screens_close();
    }
    start(false);                                                     /* an environment that refuses the tap changes nothing */
    fake.summary = LOCKED_SUMMARY;
    fake.reveal_refused = true;
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    tap(WALLET_ACT_SHOW_PRIVATE, 0, WALLET_STAY);
    CHECK(fake.reveal_started == 1 && has(HIDDEN_LINE) && reveal_button() >= 0 && !has("Confirm with"));
    wallet_screens_close();
}

/* Hiding the app, leaving the wallet screens and shutting down each ask the environment to lock the wallet again. */
static void test_reveal_ends_on_leaving(void)
{
    start(false);
    fake.summary = LOCKED_SUMMARY;
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    tap(WALLET_ACT_SHOW_PRIVATE, 0, WALLET_STAY);
    wallet_screens_pause();                                           /* the app goes out of view */
    CHECK(fake.reveal_ended == 1 && !wallet_screens_active());
    wallet_screens_close();
    CHECK(fake.reveal_ended == 2);
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    wallet_screens_close();                                           /* leaving Funds for Home */
    CHECK(fake.reveal_ended == 3);
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    wallet_screens_shutdown();
    CHECK(fake.reveal_ended == 4);
    start(false);
}

/* The page stays open between Funds, Receive and History: the window follows the owner there. */
static void test_reveal_across_pages(void)
{
    start(false);
    fake.summary = LOCKED_SUMMARY;
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    tap(WALLET_ACT_SHOW_PRIVATE, 0, WALLET_STAY);
    fake.summary = GOOD_SUMMARY;
    fake.reveal = WALLET_REVEAL_OPEN;
    wallet_screens_refresh_send();
    tap(WALLET_ACT_RECEIVE, 0, WALLET_STAY);
    CHECK(fake.reveal_ended == 0);
    CHECK(wallet_screens_back() && has("1.23456789 ZCL"));            /* Funds is read again and the wallet is still open */
    wallet_screens_refresh_send();
    CHECK(has("hides again") && fake.reveal_ended == 0);
    wallet_screens_close();
}

/* A private amount read from a wallet unlocked for the owner never reaches the balance file, and a reply that hides the private
 * amounts removes a kept one, so no kept amount is shown for a wallet that hides it now. */
static void test_reveal_amount_not_kept(void)
{
    wallet_with_balance();                                            /* kept from a locked read that showed the amounts */
    CHECK(file_exists(CACHE));
    start(false);                                                     /* the same wallet, now locked with its amounts hidden */
    fake.summary = LOCKED_SUMMARY;
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    CHECK(!file_exists(CACHE));                                       /* the kept balance is removed */
    tap(WALLET_ACT_SHOW_PRIVATE, 0, WALLET_STAY);
    fake.summary = GOOD_SUMMARY;                                      /* encrypted, unlocked, 1.23456789 ZCL */
    fake.reveal = WALLET_REVEAL_OPEN;
    wallet_screens_refresh_send();
    CHECK(has("1.23456789 ZCL"));
    wallet_screens_close();
    CHECK(!file_exists(CACHE) && !file_exists(CACHE ".tmp") && keystore.seals == 0);
    remove_dir();
}

/* ---- Receive ---- */

static void test_receive(void)
{
    start(false);
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    tap(WALLET_ACT_RECEIVE, 0, WALLET_STAY);
    struct wallet_screen *s = snap();
    CHECK(s->page == WALLET_PAGE_RECEIVE && count_ops("latest") == 1);
    CHECK(count_ops("receive") == 0);          /* opening Receive makes no key */
    long qr = find(s, WALLET_ITEM_QR, WALLET_ACT_NONE), address = find(s, WALLET_ITEM_ADDRESS, WALLET_ACT_NONE);
    CHECK(qr >= 0 && !strcmp(text_at(s, qr), A1) && address >= 0);
    CHECK(!strncmp(text_at(s, address), "zs1 qqqq qqqq", 13) && find_text(s, "diversified") < 0);
    CHECK(find(s, WALLET_ITEM_INPUT, WALLET_ACT_NONE) >= 0 && find(s, WALLET_ITEM_BUTTON, WALLET_ACT_NEW_ADDRESS) >= 0);
    CHECK(!has("may have been shown") && !has("shown before"));            /* the reply cannot say the address was used, so no note claims it */

    wallet_screens_close();
}

static void test_receive_amount(void)
{
    start(false);
    CHECK(wallet_screens_open(WALLET_PAGE_RECEIVE));
    CHECK(wallet_screens_set_amount("1.5"));
    struct wallet_screen *s = snap();
    CHECK(!strcmp(text_at(s, find(s, WALLET_ITEM_QR, WALLET_ACT_NONE)), "zclassic:" A1 "?amount=1.5") && find_text(s, "Asking for 1.5 ZCL") >= 0);
    CHECK(!wallet_screens_set_amount("1.123456789") && has("Enter an amount"));
    CHECK(!wallet_screens_set_amount("0") && !wallet_screens_set_amount("-1") && !wallet_screens_set_amount("22000000"));
    CHECK(!wallet_screens_set_amount("21000000.00000001"));                  /* one zatoshi over the supply */
    s = snap();
    CHECK(!strcmp(text_at(s, find(s, WALLET_ITEM_QR, WALLET_ACT_NONE)), "zclassic:" A1 "?amount=1.5"));
    CHECK(wallet_screens_set_amount("21000000"));                            /* the supply itself is the limit */
    CHECK(wallet_screens_set_amount("  ") && !strcmp(text_at(snap(), find(snap(), WALLET_ITEM_QR, WALLET_ACT_NONE)), A1));
    CHECK(wallet_screens_set_amount("0.00000001"));
    wallet_screens_close();
}

static void test_receive_new_address(void)
{
    start(false);
    CHECK(wallet_screens_open(WALLET_PAGE_RECEIVE));
    CHECK(wallet_screens_set_amount("0.00000001"));
    struct wallet_screen *s;
    tap(WALLET_ACT_NEW_ADDRESS, 0, WALLET_STAY);                    /* only this makes an address, and the amount stays */
    s = snap();
    CHECK(count_ops("receive") == 1 && count_ops("latest") == 1);
    CHECK(!has("may have been shown") && !has("shown before"));
    CHECK(!strcmp(text_at(s, find(s, WALLET_ITEM_QR, WALLET_ACT_NONE)), "zclassic:" A2 "?amount=0.00000001") && find_text(s, A1) < 0);

    CHECK(wallet_screens_back() && snap()->page == WALLET_PAGE_FUNDS);   /* leaving wipes the address from the screens */
    for (size_t i = 0; i < snap()->count; ++i) CHECK(!strstr(snap()->items[i].text, "zs1"));
    fake.latest = "{\"ok\":true,\"data\":{\"address\":\"" A2 "\"}}";    /* the node now reports the new address as the latest */
    tap(WALLET_ACT_RECEIVE, 0, WALLET_STAY);
    s = snap();
    CHECK(count_ops("receive") == 1 && !strcmp(text_at(s, find(s, WALLET_ITEM_QR, WALLET_ACT_NONE)), A2));
    wallet_screens_close();
}

static void test_receive_never_makes_keys(void)
{
    start(false);
    for (int i = 0; i < 300; ++i) {                  /* 300 visits make 300 reads and no key */
        CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
        tap(WALLET_ACT_RECEIVE, 0, WALLET_STAY);
        CHECK(wallet_screens_back());
    }
    CHECK(count_ops("latest") == 300 && count_ops("receive") == 0);
    for (int i = 0; i < 300; ++i) CHECK(wallet_screens_open(WALLET_PAGE_RECEIVE));
    CHECK(count_ops("receive") == 0);
    wallet_screens_close();
}

static void test_receive_replies(void)
{
    start(false);                                     /* a node without the read command: Receive says so, makes nothing */
    fake.latest = NULL;
    CHECK(wallet_screens_open(WALLET_PAGE_RECEIVE));
    struct wallet_screen *s = snap();
    CHECK(find(s, WALLET_ITEM_QR, WALLET_ACT_NONE) < 0 && has("cannot report its latest address yet") && count_ops("receive") == 0);
    CHECK(find(s, WALLET_ITEM_BUTTON, WALLET_ACT_NEW_ADDRESS) >= 0);

    fake.latest = "{\"ok\":true,\"data\":{\"address\":null}}";
    CHECK(wallet_screens_open(WALLET_PAGE_RECEIVE) && has("no receive address yet"));
    fake.latest = OTHER_ERROR;
    CHECK(wallet_screens_open(WALLET_PAGE_RECEIVE) && has("could not be read") && !has("WALLET_LOCKED"));
    fake.latest = "{\"ok\":false,\"data\":{\"address\":\"" A1 "\"}}";    /* ok:false is no reply, even when the command exited cleanly */
    fake.always_ok = true;
    CHECK(wallet_screens_open(WALLET_PAGE_RECEIVE) && find(snap(), WALLET_ITEM_QR, WALLET_ACT_NONE) < 0);
    fake.always_ok = false;
    fake.latest = "{\"ok\":true,\"data\":{\"address\":\"" PUBLIC_ADDR "\"}}";   /* a public address is never shown */
    CHECK(wallet_screens_open(WALLET_PAGE_RECEIVE));
    CHECK(find(snap(), WALLET_ITEM_QR, WALLET_ACT_NONE) < 0 && !has("aaaa") && has("not private"));

    wallet_screens_close();
}

static void test_receive_without_new_address(void)
{
    struct wallet_screen *s;
    start(false);                                     /* a node without the receive command: one sentence, nothing offered, no key made */
    fake.receive = NULL;
    CHECK(wallet_screens_open(WALLET_PAGE_RECEIVE));
    CHECK(count_ops("receive") == 0 && find(snap(), WALLET_ITEM_BUTTON, WALLET_ACT_NEW_ADDRESS) >= 0);
    tap(WALLET_ACT_NEW_ADDRESS, 0, WALLET_STAY);
    s = snap();
    CHECK(count_ops("receive") == 1);
    CHECK(find(s, WALLET_ITEM_QR, WALLET_ACT_NONE) < 0 && find_text(s, "zs1") < 0);
    CHECK(has("This build cannot make a new address.") && !has("Tap New address") && !has("256") && !has("spending key"));
    CHECK(find(s, WALLET_ITEM_BUTTON, WALLET_ACT_NEW_ADDRESS) < 0 && find(s, WALLET_ITEM_BUTTON, WALLET_ACT_BACK) >= 0);
    int before = fake.op_count;                       /* a tap that nothing offers does nothing */
    tap(WALLET_ACT_NEW_ADDRESS, 0, WALLET_STAY);
    CHECK(fake.op_count == before && count_ops("receive") == 1);
    start(false);                                     /* a failure that is not a missing command keeps the button */
    fake.receive = OTHER_ERROR;
    CHECK(wallet_screens_open(WALLET_PAGE_RECEIVE));
    tap(WALLET_ACT_NEW_ADDRESS, 0, WALLET_STAY);
    s = snap();
    CHECK(find(s, WALLET_ITEM_QR, WALLET_ACT_NONE) < 0 && has("No address was made") && !has("WALLET_LOCKED"));
    CHECK(!has("256") && !has("locked") && !has("which"));                      /* receive makes no key: no reason about keys or locks */
    CHECK(find(s, WALLET_ITEM_BUTTON, WALLET_ACT_NEW_ADDRESS) >= 0 && !has("cannot make a new address"));
    wallet_screens_close();
}

/* ---- History ---- */

static void test_history(void)
{
    start(false);
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    tap(WALLET_ACT_HISTORY, 0, WALLET_STAY);
    struct wallet_screen *s = snap();
    CHECK(s->page == WALLET_PAGE_HISTORY && count_ops("history") == 1 && !fake.args[fake.op_count - 1][0]);
    long row0 = find_text(s, "Sent ·");
    CHECK(row0 >= 0 && !strcmp(text_at(s, row0), "1.5 ZCL\nSent · Confirmed · Today 22:13"));
    CHECK(!strcmp(text_at(s, row0 + 1), "Amount unknown\nReceived · Pending · Today 23:13"));
    CHECK(!strcmp(text_at(s, row0 + 2), "0.00000001 ZCL\nMoved inside your wallet · State unknown · Date unknown"));
    CHECK(!has(TX_A) && !has("MEMO"));
    CHECK(find(s, WALLET_ITEM_BUTTON, WALLET_ACT_OLDER) >= 0 && find(s, WALLET_ITEM_BUTTON, WALLET_ACT_NEWER) < 0);
    wallet_screens_close();
}

static void test_history_detail(void)
{
    start(false);
    CHECK(wallet_screens_open(WALLET_PAGE_HISTORY));
    struct wallet_screen *s;
    fake.detail = DETAIL("\"memo\":\"MEMO-MARKER thanks\"");           /* details on request */
    tap(WALLET_ACT_DETAIL, 0, WALLET_STAY);
    s = snap();
    CHECK(s->page == WALLET_PAGE_DETAIL && count_ops("detail") == 1 && !strcmp(fake.args[fake.op_count - 1], TX_A));
    long memo = find(s, WALLET_ITEM_MEMO, WALLET_ACT_NONE);
    CHECK(has(TX_A) && memo >= 0 && !strcmp(text_at(s, memo), "MEMO-MARKER thanks") && find_text(s, "written by the sender") >= 0);
    CHECK(has("Today 22:13") && !has("Public"));
    CHECK(wallet_screens_back() && snap()->page == WALLET_PAGE_HISTORY && count_ops("history") == 1);
    CHECK(find_text(snap(), "MEMO-MARKER") < 0);                                    /* leaving a detail forgets its memo */
    CHECK(!wallet_screens_residue("MEMO-MARKER", 11));                              /* nor does the screen keep it */
    tap(WALLET_ACT_DETAIL, 1, WALLET_STAY);                                           /* a row without a memo asks for none */
    s = snap();
    CHECK(count_ops("detail") == 1 && has("The node does not say whether every part of this payment was private.") && !has("Public") && has("Amount unknown"));
    CHECK(find(s, WALLET_ITEM_MEMO, WALLET_ACT_NONE) < 0 && !has("Memo"));
    CHECK(wallet_screens_back());
    tap(WALLET_ACT_DETAIL, 9, WALLET_STAY);                                           /* a row that is not there changes nothing */
    CHECK(snap()->page == WALLET_PAGE_HISTORY);
    wallet_screens_close();
}

static void test_history_pages(void)
{
    start(false);
    CHECK(wallet_screens_open(WALLET_PAGE_HISTORY));
    tap(WALLET_ACT_OLDER, 0, WALLET_STAY);
    struct wallet_screen *s = snap();
    CHECK(count_ops("history") == 2 && !strcmp(fake.args[fake.op_count - 1], CURSOR_1));
    CHECK(has("21000000 ZCL\nReceived · Confirmed · 15 Nov 22:13"));
    CHECK(find(s, WALLET_ITEM_BUTTON, WALLET_ACT_OLDER) < 0 && find(s, WALLET_ITEM_BUTTON, WALLET_ACT_NEWER) >= 0);
    tap(WALLET_ACT_NEWER, 0, WALLET_STAY);
    CHECK(count_ops("history") == 3 && !fake.args[fake.op_count - 1][0] && has("Sent ·"));
    fake.history[1] = PAGE("", "0", "null");                                            /* an older page with nothing on it */
    tap(WALLET_ACT_OLDER, 0, WALLET_STAY);
    CHECK(has("No older transactions.") && !has("No transactions yet.") && !has("None found"));
    wallet_screens_close();
}

static void history_error(const char *reply_text)
{
    start(false);
    fake.always_ok = true;
    fake.history[0] = reply_text;
    CHECK(wallet_screens_open(WALLET_PAGE_HISTORY));
    CHECK(has("could not be read") && !has("No transactions") && !has("WALLET_LOCKED") && find(snap(), WALLET_ITEM_BUTTON, WALLET_ACT_DETAIL) < 0);
    wallet_screens_close();
}
static void test_history_replies(void)
{
    start(false);
    fake.history[0] = PAGE("", "0", "null");
    CHECK(wallet_screens_open(WALLET_PAGE_HISTORY) && has("No transactions yet.") && !has("could not be read"));
    history_error(OTHER_ERROR);
    history_error("{\"ok\":true,\"data\":{\"entries\":[]}}");                       /* no frame: an error, not an empty wallet */
    history_error("{\"ok\":true,\"data\":{\"known\":true,\"has_more\":false,\"entries\":[]}}");   /* the old, absent shape */
    history_error("{\"ok\":true,\"data\":{\"entries\":[1,2,3]}}");
    history_error("{\"ok\":true,\"data\":[1,2,3]}");
    history_error("[1,2,3]");
    history_error("{\"ok\":false,\"data\":" PAGE("", "0", "null") "}");
    history_error("{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_history.v1\",\"entries\":[1,2],\"count\":2,\"next_cursor\":null}}");
    history_error("{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_history.v1\",\"entries\":[],\"count\":1,\"next_cursor\":null}}");
    history_error("{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_history.v1\",\"entries\":[],\"next_cursor\":null}}");
    history_error("{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_history.v1\",\"entries\":[],\"count\":0}}");
    history_error("{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_history.v2\",\"entries\":[],\"count\":0,\"next_cursor\":null}}");
    history_error("{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_history.v1\",\"entries\":[],\"count\":0,\"next_cursor\":\"not a cursor\"}}");
    history_error("{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_history.v1\",\"entries\":[],\"count\":0,\"next_cursor\":7}}");
    history_error(PAGE(ROW_SENT "," ROW_SENT "," ROW_SENT "," ROW_SENT "," ROW_SENT "," ROW_SENT "," ROW_SENT "," ROW_SENT "," ROW_SENT "," ROW_SENT "," ROW_SENT, "11", "null"));

    start(false);                                     /* fields of the wrong type or value read as unknown, never a guess */
    fake.history[0] = PAGE("{\"direction\":\"sideways\",\"kind\":7,\"amount_zat\":-5,\"status\":3,\"time\":-1,\"txid\":\"x\\ny\",\"memo_present\":\"yes\"},"
                           "{\"direction\":1,\"kind\":\"private\",\"amount_zat\":2100000000000001,\"time\":253402300800,\"txid\":\"" TX_A "\"},"
                           "{\"amount_zat\":1.5,\"time\":\"1700000000\"},{}", "4", "null");
    CHECK(wallet_screens_open(WALLET_PAGE_HISTORY));
    struct wallet_screen *s = snap();
    long row0 = find(s, WALLET_ITEM_BUTTON, WALLET_ACT_DETAIL);
    CHECK(row0 >= 0);
    CHECK(!strcmp(text_at(s, row0), "Amount unknown\nDirection unknown · State unknown · Date unknown"));
    CHECK(!strcmp(text_at(s, row0 + 1), "Amount unknown\nDirection unknown · State unknown · Date unknown"));
    CHECK(!strcmp(text_at(s, row0 + 2), text_at(s, row0)) && !strcmp(text_at(s, row0 + 3), text_at(s, row0)));
    tap(WALLET_ACT_DETAIL, 0, WALLET_STAY);
    CHECK(has("unknown") && !has("x\ny"));                                /* a txid that is not one is not shown */
    wallet_screens_close();

    start(false);                                     /* the supply is the limit of an amount */
    fake.history[0] = PAGE(ROW("received", "private", "confirmed", "2100000000000000", "1700000000", TX_A, "false") ","
                           ROW("received", "private", "confirmed", "2100000000000001", "1700000000", TX_B, "false"), "2", "null");
    CHECK(wallet_screens_open(WALLET_PAGE_HISTORY) && has("21000000 ZCL") && has("Amount unknown\nReceived · Confirmed") && !has("Private"));
    wallet_screens_close();
}

static void test_memo_text(void)
{
    start(false);
    fake.history[0] = PAGE(ROW_SENT, "1", "null");
    CHECK(wallet_screens_open(WALLET_PAGE_HISTORY));
    fake.detail = DETAIL("\"memo\":\"Failed\"");      /* a memo that reads like a state line is drawn as a memo */
    tap(WALLET_ACT_DETAIL, 0, WALLET_STAY);
    struct wallet_screen *s = snap();
    long memo = find(s, WALLET_ITEM_MEMO, WALLET_ACT_NONE);
    CHECK(memo >= 0 && !strcmp(text_at(s, memo), "Failed"));
    for (size_t i = 0; i < s->count; ++i) CHECK(s->items[i].kind == WALLET_ITEM_MEMO || strcmp(s->items[i].text, "Failed"));
    wallet_screens_back();

    /* Controls, separators, bidi and zero-width characters, and invalid bytes are shown as what they are. */
    fake.detail = DETAIL("\"memo\":\"a\\u2028b\\u202ec\\u0085d\\u200be\\u0001f\\n\\u2066g\\ufeffh\"");
    tap(WALLET_ACT_DETAIL, 0, WALLET_STAY);
    s = snap();
    CHECK(!strcmp(text_at(s, find(s, WALLET_ITEM_MEMO, WALLET_ACT_NONE)),
                  "a<U+2028>b<U+202E>c<U+0085>d<U+200B>e<U+0001>f<U+000A><U+2066>g<U+FEFF>h"));
    wallet_screens_back();
    fake.detail = DETAIL("\"memo\":\"ok \xff\xfe \xc3\x28 \xed\xa0\x80 \xe2\x80 end\"");
    tap(WALLET_ACT_DETAIL, 0, WALLET_STAY);
    s = snap();
    long bad = find(s, WALLET_ITEM_MEMO, WALLET_ACT_NONE);
    CHECK(bad >= 0 && !strcmp(text_at(s, bad), "ok <xFF><xFE> <xC3>( <xED><xA0><x80> <xE2><x80> end"));    /* every invalid byte is shown, and the memo is not refused */
    wallet_screens_back();

    fake.detail = DETAIL("\"memo_hex\":\"00ff10\"");  /* a memo that is not text is shown as hexadecimal */
    tap(WALLET_ACT_DETAIL, 0, WALLET_STAY);
    s = snap();
    CHECK(!strcmp(text_at(s, find(s, WALLET_ITEM_MEMO, WALLET_ACT_NONE)), "00ff10") && has("shown as hexadecimal"));
    wallet_screens_back();
    fake.detail = DETAIL("\"memo_hex\":\"0g\"");
    tap(WALLET_ACT_DETAIL, 0, WALLET_STAY);
    CHECK(has("could not be read"));
    wallet_screens_back();
    fake.detail = DETAIL("\"x\":1");
    tap(WALLET_ACT_DETAIL, 0, WALLET_STAY);
    CHECK(has("reports a memo but gave none"));
    wallet_screens_back();
    fake.detail = "{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_history.v1\",\"entry\":{\"txid\":\"" TX_B "\",\"memo\":\"other\"}}}";
    tap(WALLET_ACT_DETAIL, 0, WALLET_STAY);                      /* a reply for another transaction is no reply */
    CHECK(has("could not be read") && !has("other"));
    wallet_screens_close();
}

static char long_memo_reply[4400];
static size_t memo_items_total(const struct wallet_screen *s)
{
    size_t total = 0;
    for (size_t i = 0; i < s->count; ++i) if (s->items[i].kind == WALLET_ITEM_MEMO) total += strlen(s->items[i].text);
    return total;
}
static const struct wallet_screen *long_memo(const char *member, size_t count, const char *piece)
{
    char body[4000] = "";
    size_t used = 0, length = strlen(piece);
    for (size_t i = 0; i < count && used + length < sizeof(body); ++i, used += length) memcpy(body + used, piece, length);
    body[used] = '\0';
    snprintf(long_memo_reply, sizeof(long_memo_reply), "{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_history.v1\",\"entry\":{\"txid\":\"" TX_A "\",\"%s\":\"%s\"}}}", member, body);
    fake.detail = long_memo_reply;
    tap(WALLET_ACT_DETAIL, 0, WALLET_STAY);
    return snap();
}
static void test_memo_length(void)
{
    start(false);
    fake.history[0] = PAGE(ROW_SENT, "1", "null");
    CHECK(wallet_screens_open(WALLET_PAGE_HISTORY));
    const struct wallet_screen *s = long_memo("memo", 512, "m");          /* the longest memo shows whole, with no cut */
    CHECK(memo_items_total(s) == 512 && !has("so it is cut") && !has("longer than this screen"));
    wallet_screens_back();
    s = long_memo("memo", 513, "m");                                       /* over what the wallet keeps: cut, and said so */
    CHECK(memo_items_total(s) == 512 && has("so it is cut"));
    wallet_screens_back();
    s = long_memo("memo", 512, "\\u0001");                                 /* expansion beyond the room: cut at the room, and said so */
    CHECK(memo_items_total(s) < 512 * 8 && has("longer than this screen shows") && find_text(s, "<U+0001>") >= 0);
    wallet_screens_back();
    s = long_memo("memo_hex", 512, "ab");
    CHECK(memo_items_total(s) == 1024 && !has("longer"));
    for (size_t i = 0; i < s->count; ++i) CHECK(strlen(s->items[i].text) < WALLET_TEXT_MAX);
    memset(long_memo_reply, 0, sizeof(long_memo_reply));
    wallet_screens_close();
}

/* ---- protection ---- */

static void test_dropped_taps(void)
{
    start(false);
    wallet_screens_dropped(1);                                  /* before a wallet screen is in front: nothing to explain */
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS) && !has("drawing over this screen"));
    unsigned version = wallet_screens_snapshot(&screen);
    wallet_screens_dropped(0);
    CHECK(!has("drawing over this screen") && wallet_screens_snapshot(&screen) == version);
    wallet_screens_dropped(2);                                  /* an overlay cut two gestures: the screen says why */
    CHECK(wallet_screens_snapshot(&screen) != version);        /* the drawn screen is replaced, or the notice never shows */
    struct wallet_screen *s = snap();
    CHECK(has("Another app is drawing over this screen") && s->items[1].kind == WALLET_ITEM_NOTE && s->items[0].kind == WALLET_ITEM_TITLE);
    CHECK(find(s, WALLET_ITEM_BUTTON, WALLET_ACT_RECEIVE) >= 0 && find(s, WALLET_ITEM_BUTTON, WALLET_ACT_HISTORY) >= 0);
    version = wallet_screens_snapshot(&screen);
    tap(WALLET_ACT_SEND, 0, WALLET_SEND);                       /* a tap that reaches the screen ends the notice, whatever it does */
    CHECK(snap()->page == WALLET_PAGE_FUNDS && !has("drawing over this screen") && wallet_screens_snapshot(&screen) != version);
    wallet_screens_dropped(1);
    CHECK(has("drawing over this screen"));
    tap(WALLET_ACT_RECEIVE, 0, WALLET_STAY);
    CHECK(snap()->page == WALLET_PAGE_RECEIVE && !has("drawing over this screen"));
    wallet_screens_dropped(1);
    CHECK(has("drawing over this screen"));
    version = wallet_screens_snapshot(&screen);
    CHECK(wallet_screens_set_amount("1"));                      /* so does the amount field */
    CHECK(!has("drawing over this screen") && wallet_screens_snapshot(&screen) != version);
    wallet_screens_dropped(UINT_MAX);                           /* the count never wraps back to nothing */
    wallet_screens_dropped(1);
    CHECK(has("drawing over this screen"));
    wallet_screens_close();                                     /* leaving forgets it */
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS) && !has("drawing over this screen"));
    wallet_screens_close();
}

static void test_secure(void)
{
    static const enum wallet_page pages[] = {WALLET_PAGE_FUNDS, WALLET_PAGE_RECEIVE, WALLET_PAGE_HISTORY};
    for (size_t i = 0; i < sizeof(pages) / sizeof(pages[0]); ++i) {      /* every page is protected before it shows anything */
        start(false);
        CHECK(wallet_screens_open(pages[i]) && fake.secure_on && fake.secure_on_calls == 1);
        CHECK(wallet_screens_active() && snap()->count > 1);
        wallet_screens_close();
        CHECK(!fake.secure_on && fake.secure_off_calls == 1 && snap()->count == 0);
    }
    start(false);                                                         /* one protection for a whole visit */
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    tap(WALLET_ACT_HISTORY, 0, WALLET_STAY);
    tap(WALLET_ACT_DETAIL, 0, WALLET_STAY);
    CHECK(fake.secure_on && fake.secure_on_calls == 1 && fake.secure_off_calls == 0);
    wallet_screens_shutdown();
    CHECK(!fake.secure_on);

    start(false);                                                         /* no protection, no wallet content, no command, and the words name what failed */
    fake.secure_ok = false;
    fake.refusal = "stop other apps from drawing over the screen";
    CHECK(!wallet_screens_open(WALLET_PAGE_FUNDS));
    CHECK(has("would not let the app stop other apps from drawing over the screen.") && !has("screenshots") && fake.op_count == 0);
    wallet_screens_close();
    start(false);
    fake.secure_ok = false;
    CHECK(!wallet_screens_open(WALLET_PAGE_FUNDS));
    struct wallet_screen *s = snap();
    CHECK(fake.op_count == 0 && find_text(s, "would not let the app protect the screen") >= 0);    /* no callback: the general words */
    CHECK(find(s, WALLET_ITEM_AMOUNT, WALLET_ACT_NONE) < 0 && find(s, WALLET_ITEM_BUTTON, WALLET_ACT_RECEIVE) < 0);
    tap(WALLET_ACT_RECEIVE, 0, WALLET_STAY);
    tap(WALLET_ACT_HISTORY, 0, WALLET_STAY);
    wallet_screens_tick();
    CHECK(fake.op_count == 0 && !wallet_screens_set_amount("1"));
    tap(WALLET_ACT_BACK, 0, WALLET_LEAVE);
    wallet_screens_close();
}

static void pause_during(const char *op, const char *arg)
{
    (void)op; (void)arg;
    wallet_screens_pause();
}
/* The app goes out of view with a wallet screen in front: what the screens hold goes at once, and the window
 * protection stays in force until the caller has drawn a screen without wallet data and closes. */
static void pause_on_each_page(void)
{
    static const enum wallet_page pages[] = {WALLET_PAGE_FUNDS, WALLET_PAGE_RECEIVE, WALLET_PAGE_HISTORY};
    for (size_t i = 0; i < sizeof(pages) / sizeof(pages[0]); ++i) {
        start(false);
        CHECK(wallet_screens_open(pages[i]) && fake.secure_on && fake.secure_on_calls == 1);
        CHECK(wallet_screens_residue("1.23456789", 10) || wallet_screens_residue(A1, sizeof(A1) - 1) || wallet_screens_residue(TX_A, 64));
        wallet_screens_pause();
        CHECK(fake.secure_on && fake.secure_off_calls == 0);                  /* still blank in Recents */
        CHECK(!wallet_screens_active() && snap()->count == 0);
        CHECK(!wallet_screens_residue("1.23456789", 10) && !wallet_screens_residue(A1, sizeof(A1) - 1) && !wallet_screens_residue(TX_A, 64));
        wallet_screens_tick();                                               /* nothing runs for a screen that is gone */
        CHECK(fake.secure_on && fake.secure_off_calls == 0);
        wallet_screens_close();                                              /* the caller drew a screen without wallet data */
        CHECK(!fake.secure_on && fake.secure_off_calls == 1 && fake.secure_on_calls == 1);
    }
}
static void pause_then_return(void)
{
    start(false);                                                            /* back into the wallet before the release */
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    wallet_screens_pause();
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS) && has("1.23456789 ZCL"));
    CHECK(fake.secure_on && fake.secure_on_calls == 1 && fake.secure_off_calls == 0);
    wallet_screens_pause();
    wallet_screens_shutdown();                                               /* the app is destroyed while held */
    CHECK(!fake.secure_on && fake.secure_off_calls == 1);
}
static void test_pause(void)
{
    pause_on_each_page();
    pause_then_return();
    start(false);                                                            /* a reply that lands after the pause is dropped */
    fake.during = pause_during;
    CHECK(wallet_screens_open(WALLET_PAGE_RECEIVE));
    fake.during = NULL;
    CHECK(count_ops("latest") == 1 && fake.changed == 0);                    /* the command ran and its reply was not applied */
    CHECK(snap()->count == 0 && !wallet_screens_residue(A1, sizeof(A1) - 1) && fake.secure_on);
    wallet_screens_close();
}

/* After a pause the shell calls settle on a tick once Home is drawn: only then does the protection go. */
static void test_settle(void)
{
    start(false);
    wallet_screens_settle();                                                 /* nothing was paused: nothing to release */
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    wallet_screens_settle();                                                 /* a screen in front keeps its protection */
    CHECK(fake.secure_on && fake.secure_off_calls == 0);
    wallet_screens_pause();
    CHECK(fake.secure_on && fake.secure_off_calls == 0);
    wallet_screens_settle();                                                 /* the pause tick is too early: Funds may still be on screen */
    CHECK(fake.secure_on && fake.secure_off_calls == 0);
    fake.now += 249;
    wallet_screens_settle();
    CHECK(fake.secure_on && fake.secure_off_calls == 0);
    fake.now += 1;
    wallet_screens_settle();
    CHECK(!fake.secure_on && fake.secure_off_calls == 1);
    wallet_screens_settle();                                                 /* once only */
    CHECK(fake.secure_off_calls == 1);

    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));                           /* back in before the first tick: protection stays */
    wallet_screens_pause();
    CHECK(wallet_screens_open(WALLET_PAGE_RECEIVE));
    wallet_screens_settle();
    CHECK(fake.secure_on && fake.secure_off_calls == 1 && wallet_screens_active());
    wallet_screens_close();

    start(false);                                                            /* a pause without protection (it was refused) holds nothing */
    fake.secure_ok = false;
    CHECK(!wallet_screens_open(WALLET_PAGE_FUNDS));
    wallet_screens_pause();
    wallet_screens_settle();
    CHECK(!fake.secure_on);

    start(false);                                                            /* a stalled thread: time passes but only one tick ran */
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    wallet_screens_pause();
    fake.now += 5000;
    wallet_screens_settle();
    CHECK(fake.secure_on && fake.secure_off_calls == 0);
    wallet_screens_settle();
    CHECK(!fake.secure_on && fake.secure_off_calls == 1);
}

/* Only the node's fully_shielded says whether a transaction was private: true is Private and false is Public, in every
 * direction; null, a missing field and the old kind alone make no claim. */
static void test_privacy_claims(void)
{
    static const char *const unclaimed = "The node does not say whether every part of this payment was private.";
    start(false);
    fake.history[0] = PAGE(ROW("sent", "private", "confirmed", "100000000", "1700000000", TX_A, "false") ","
                           ROWX("sent", "private", "confirmed", "200000000", "1700000000", TX_B, "false", "\"fully_shielded\":true") ","
                           ROWX("sent", "private", "confirmed", "300000000", "1700000000", TX_C, "false", "\"fully_shielded\":false") ","
                           ROWX("received", "private", "confirmed", "500000000", "1700000000", TX_A, "false", "\"fully_shielded\":null") ","
                           ROW("received", "private", "confirmed", "600000000", "1700000000", TX_B, "false") ","
                           ROWX("received", "public", "confirmed", "700000000", "1700000000", TX_C, "false", "\"fully_shielded\":true") ","
                           ROWX("internal", "private", "confirmed", "800000000", "1700000000", TX_D, "false", "\"fully_shielded\":false") ","
                           ROWX("internal", "public", "confirmed", "900000000", "1700000000", TX_A, "false", "\"fully_shielded\":true"),
                           "8", "null");
    CHECK(wallet_screens_open(WALLET_PAGE_HISTORY));
    struct wallet_screen *s = snap();
    CHECK(find_text(s, "1 ZCL\nSent · Confirmed") >= 0);                             /* a private-looking kind alone is no claim */
    CHECK(find_text(s, "2 ZCL\nSent · Private · Confirmed") >= 0);                    /* the node said so */
    CHECK(find_text(s, "3 ZCL\nSent · Public · Confirmed") >= 0);                     /* a z-to-t payment */
    CHECK(find_text(s, "5 ZCL\nReceived · Confirmed") >= 0);                         /* null: the wallet cannot tell */
    CHECK(find_text(s, "6 ZCL\nReceived · Confirmed") >= 0);                         /* a t-to-z payment is not private either */
    CHECK(find_text(s, "7 ZCL\nReceived · Private · Confirmed") >= 0);               /* the field decides, not the old kind */
    CHECK(find_text(s, "8 ZCL\nMoved inside your wallet · Public · Confirmed") >= 0);  /* a z-to-own-t move */
    CHECK(find_text(s, "9 ZCL\nMoved inside your wallet · Private · Confirmed") >= 0);
    tap(WALLET_ACT_DETAIL, 0, WALLET_STAY);
    CHECK(has(unclaimed) && !has("Private") && !has("Public"));
    CHECK(wallet_screens_back());
    tap(WALLET_ACT_DETAIL, 1, WALLET_STAY);
    CHECK(has("Private") && !has(unclaimed));
    CHECK(wallet_screens_back());
    tap(WALLET_ACT_DETAIL, 2, WALLET_STAY);
    CHECK(has("Public: at least one amount or address in this payment is visible to everyone.") && !has(unclaimed));
    wallet_screens_close();
}

/* A wallet that is still scanning does not call an empty list its whole history. */
static void test_history_while_scanning(void)
{
    start(false);
    fake.history[0] = PAGE("", "0", "null");
    CHECK(wallet_screens_open(WALLET_PAGE_HISTORY));
    CHECK(has("No transactions yet.") && !has("None found"));                    /* a wallet that has scanned everything */
    fake.summary = SUMMARY_SCAN("2999000");
    CHECK(wallet_screens_open(WALLET_PAGE_HISTORY));
    CHECK(has("None found so far. The wallet is still scanning the chain.") && !has("No transactions yet."));
    fake.summary = OTHER_ERROR;                                                  /* no summary: nothing says the scan is done */
    CHECK(wallet_screens_open(WALLET_PAGE_HISTORY));
    CHECK(has("None found so far.") && !has("No transactions yet.") && !has("still scanning") && !has("not up to date"));
    fake.summary = SUMMARY_OFFLINE;                                              /* a node that is not at the tip has not seen everything */
    CHECK(wallet_screens_open(WALLET_PAGE_HISTORY));
    CHECK(has("None found so far. The node is not up to date.") && !has("No transactions yet.") && !has("still scanning"));
    wallet_screens_close();
}

/* Funds: immature coins in one line, a node that is not current, amounts without trailing zeros. */
static void test_funds_lines(void)
{
    start(false);
    fake.summary = SUMMARY_IMMATURE("2000000000", "20.00000000");
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    CHECK(has("20 ZCL of mined coins maturing, not yet spendable") && has("25 ZCL") && !has("25.0"));
    start(false);
    fake.summary = SUMMARY_OFFLINE;
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    CHECK(has("1.23456789 ZCL") && !has("Up to date") && !has("maturing"));
    wallet_screens_close();
}

/* Copy address hands the bare address to the clipboard and says what happened, and only that. */
static void test_receive_copy(void)
{
    start(false);
    CHECK(wallet_screens_open(WALLET_PAGE_RECEIVE));
    struct wallet_screen *s = snap();
    long address = find(s, WALLET_ITEM_ADDRESS, WALLET_ACT_NONE), copy = find(s, WALLET_ITEM_BUTTON, WALLET_ACT_COPY_ADDRESS);
    CHECK(address >= 0 && copy == address + 1 && !strcmp(text_at(s, copy), "Copy address"));
    CHECK(!has("Address copied") && !has("Could not copy") && fake.copy_calls == 0);
    tap(WALLET_ACT_COPY_ADDRESS, 0, WALLET_STAY);
    CHECK(fake.copy_calls == 1 && !strcmp(fake.copied, A1));                      /* the bare address, not the groups of four */
    s = snap();
    CHECK(!strcmp(text_at(s, find_text(s, "Address copied")), "Address copied. It clears after a minute."));
    CHECK(find_text(s, "Could not copy") < 0);
    fake.copy_ok = false;
    tap(WALLET_ACT_COPY_ADDRESS, 0, WALLET_STAY);
    s = snap();
    CHECK(fake.copy_calls == 2 && !strcmp(text_at(s, find_text(s, "Could not copy")), "Could not copy the address."));
    CHECK(find_text(s, "Address copied") < 0);
    tap(WALLET_ACT_NEW_ADDRESS, 0, WALLET_STAY);                                  /* a new address starts without the old word */
    CHECK(!has("Could not copy") && !has("Address copied"));
    wallet_screens_close();
}

/* No address on the screen: nothing is copied, whatever is tapped. */
static void test_receive_copy_without_address(void)
{
    start(false);
    fake.latest = "{\"ok\":true,\"data\":{\"address\":null}}";
    CHECK(wallet_screens_open(WALLET_PAGE_RECEIVE));
    CHECK(find(snap(), WALLET_ITEM_BUTTON, WALLET_ACT_COPY_ADDRESS) < 0);
    tap(WALLET_ACT_COPY_ADDRESS, 0, WALLET_STAY);
    CHECK(fake.copy_calls == 0 && !has("Address copied") && !has("Could not copy"));
    wallet_screens_back();
    tap(WALLET_ACT_COPY_ADDRESS, 0, WALLET_STAY);                                 /* off the Receive page it does nothing */
    CHECK(fake.copy_calls == 0);
    wallet_screens_close();
}

/* Receive puts the code, the address and New address on the first screen; the notes come after. */
static void test_receive_order(void)
{
    start(false);
    CHECK(wallet_screens_open(WALLET_PAGE_RECEIVE));
    struct wallet_screen *s = snap();
    long qr = find(s, WALLET_ITEM_QR, WALLET_ACT_NONE), address = find(s, WALLET_ITEM_ADDRESS, WALLET_ACT_NONE);
    long button = find(s, WALLET_ITEM_BUTTON, WALLET_ACT_NEW_ADDRESS);
    long input = find(s, WALLET_ITEM_INPUT, WALLET_ACT_NONE);
    CHECK(qr >= 0 && address > qr && button > address && input > button && find_text(s, "shown before") < 0);
    wallet_screens_close();
}

/* Funds says why the node holds sending back, and says nothing when it does not. */
static void send_note(const char *summary, const char *want)
{
    start(false);
    fake.summary = summary;
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    struct wallet_screen *s = snap();
    CHECK(find_text(s, "1.23456789 ZCL") >= 0);
    if (want) CHECK(find(s, WALLET_ITEM_NOTE, WALLET_ACT_NONE) >= 0 && !strcmp(text_at(s, find_text(s, "Sending is")), want));
    else CHECK(find_text(s, "Sending is") < 0);
    CHECK(find(s, WALLET_ITEM_BUTTON, WALLET_ACT_SEND) >= 0);
    wallet_screens_close();
}
static void test_funds_send_paused(void)
{
    send_note(SUMMARY_SEND("123456789", "1.23456789", "0", "0.00000000", "0", "0.00000000", "false", "progress_store_unavailable"),
              "Sending is paused because the wallet cannot save its progress right now.");
    send_note(SUMMARY_SEND("123456789", "1.23456789", "0", "0.00000000", "0", "0.00000000", "false", "release_assisted: tip"),
              "Sending is paused until your phone has checked the latest blocks on its own.");
    send_note(SUMMARY_SEND("123456789", "1.23456789", "0", "0.00000000", "0", "0.00000000", "false", "something_new"),
              "Sending is paused for a reason this app does not recognize.");
    send_note(SUMMARY("123456789", "1.23456789", "0", "0.00000000", "0", "0.00000000"), NULL);
}

/* ---- replies that arrive late ---- */

static void leave_during(const char *op, const char *arg)
{
    (void)arg;
    if (!strcmp(op, "summary")) { CHECK(wallet_screens_activate(WALLET_ACT_RECEIVE, 0) == WALLET_STAY); }
}
static void older_then_newer(const char *op, const char *arg)
{
    if (!strcmp(op, "history") && !strcmp(arg, CURSOR_1)) tap(WALLET_ACT_NEWER, 0, WALLET_STAY);
}
static void back_during(const char *op, const char *arg)
{
    (void)arg;
    if (!strcmp(op, "history") || !strcmp(op, "detail")) wallet_screens_back();
}
static void close_during(const char *op, const char *arg)
{
    (void)op; (void)arg;
    wallet_screens_close();
}
static void test_late_replies(void)
{
    start(false);                                     /* a summary that arrives on a later screen is dropped */
    fake.during = leave_during;
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    fake.during = NULL;
    CHECK(snap()->page == WALLET_PAGE_RECEIVE && !wallet_screens_residue("1.23456789", 10) && !wallet_screens_residue("Up to date", 10));
    wallet_screens_close();

    start(false);                                     /* a page that arrives after the owner paged back is dropped */
    CHECK(wallet_screens_open(WALLET_PAGE_HISTORY));
    fake.during = older_then_newer;
    tap(WALLET_ACT_OLDER, 0, WALLET_STAY);
    fake.during = NULL;
    CHECK(snap()->page == WALLET_PAGE_HISTORY && has("Sent ·") && !has("21000000 ZCL") && !wallet_screens_residue(TX_D, 64));
    wallet_screens_close();

    start(false);                                     /* a history page that arrives on Funds is dropped */
    fake.during = back_during;
    CHECK(wallet_screens_open(WALLET_PAGE_HISTORY));
    fake.during = NULL;
    CHECK(snap()->page == WALLET_PAGE_FUNDS && !wallet_screens_residue(TX_A, 64) && !has("Sent ·"));
    wallet_screens_close();

    start(false);                                     /* a memo that arrives after the owner left the detail is dropped */
    CHECK(wallet_screens_open(WALLET_PAGE_HISTORY));
    fake.detail = DETAIL("\"memo\":\"MEMO-MARKER late\"");
    fake.during = back_during;
    tap(WALLET_ACT_DETAIL, 0, WALLET_STAY);
    fake.during = NULL;
    CHECK(snap()->page == WALLET_PAGE_HISTORY && !wallet_screens_residue("MEMO-MARKER", 11));
    wallet_screens_close();

    start(false);                                     /* anything that arrives after the wallet was closed is dropped */
    fake.during = close_during;
    CHECK(wallet_screens_open(WALLET_PAGE_HISTORY));
    fake.during = NULL;
    CHECK(fake.changed == 0 && snap()->page == WALLET_PAGE_NONE && snap()->count == 0 && !wallet_screens_residue(TX_A, 64));
}

/* Nothing of what a screen showed stays in the state of the screens, in the heap or in program data once the owner leaves. */
static void test_nothing_left_behind(void)
{
    static const char *const markers[] = {"MEMO-MARKER", TX_A, "1.23456789", "0.5 ZCL", A1, "Sent ·"};
    start(false);
    fake.fleet = FLEET("true", "agree", "1", "1", MACHINE("fleetbox", "true", "agrees"));
    fake.detail = DETAIL("\"memo\":\"padding past the allocator header MEMO-MARKER and then more words, enough to outgrow the first block a JSON string gets\"");
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    tap(WALLET_ACT_RECEIVE, 0, WALLET_STAY);
    CHECK(wallet_screens_back());
    tap(WALLET_ACT_HISTORY, 0, WALLET_STAY);
    tap(WALLET_ACT_DETAIL, 0, WALLET_STAY);
    CHECK(has("MEMO-MARKER"));
    CHECK(process_holds("MEMO-MARKER") && wallet_screens_residue("MEMO-MARKER", 11));   /* the check can see data that is there */
    memset(&screen, 0, sizeof(screen));
    wallet_screens_close();
    CHECK(snap()->count == 0);
    memset(&screen, 0, sizeof(screen));
    memset(fake.args, 0, sizeof(fake.args));
    for (size_t i = 0; i < sizeof(markers) / sizeof(markers[0]); ++i) {
        if (wallet_screens_residue(markers[i], strlen(markers[i])) || process_holds(markers[i])) {
            fprintf(stderr, "wallet_screens_test: left behind after close: %s\n", markers[i]);
            exit(1);
        }
    }
    CHECK(!process_holds("fleetbox"));
    wallet_screens_shutdown();
}

/* ---- threads ---- */

static void test_single_flight(void)
{
    start(true);
    set_block();
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    for (int i = 0; i < 500; ++i) { fake.now += WALLET_REFRESH_MS; wallet_screens_tick(); }   /* a refresh due on every tick */
    for (int i = 0; i < 400; ++i) { tap(WALLET_ACT_RECEIVE, 0, WALLET_STAY); wallet_screens_back(); }
    tap(WALLET_ACT_RECEIVE, 0, WALLET_STAY);
    for (int i = 0; i < 1000; ++i) usleep(1000);
    CHECK(fake.active_max <= 6);
    for (int i = 0; i < 201; ++i) tap(WALLET_ACT_NEW_ADDRESS, 0, WALLET_STAY);   /* 201 fast taps */
    release_block();
    wait_for(settled);
    for (int i = 0; i < 100; ++i) usleep(2000);
    wait_for(settled);
    CHECK(count_ops("receive") == 1);               /* one address, not 201 */
    CHECK(fake.active_max <= 6 && count_ops("summary") <= 3 && count_ops("fleet") <= 3 && count_ops("latest") <= 3);

    start(true);                                        /* the same taps, one after the other, each make an address */
    CHECK(wallet_screens_open(WALLET_PAGE_RECEIVE));
    wait_for(settled);
    tap(WALLET_ACT_NEW_ADDRESS, 0, WALLET_STAY);
    for (int i = 0; i < 400 && !has(A2); ++i) usleep(5000);
    CHECK(has(A2) || find_text(snap(), "qqqq") >= 0);
    for (int i = 0; i < 400 && count_ops("receive") < 2; ++i) { tap(WALLET_ACT_NEW_ADDRESS, 0, WALLET_STAY); usleep(5000); }
    CHECK(count_ops("receive") >= 2);
    wallet_screens_close();
    wait_for(settled);
    usleep(50000);
}

static bool funds_shown(void) { return find_text(snap(), "1.23456789 ZCL") >= 0; }
static void test_async(void)
{
    start(true);
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    wait_for(funds_shown);
    wallet_screens_close();
    wait_for(settled);
    usleep(50000);
    wallet_screens_shutdown();
    CHECK(!wallet_screens_open(WALLET_PAGE_FUNDS) && snap()->count == 0);
}

/* With "stale" or "async" as the argument only that test runs, so a thread sanitizer can cover it in reasonable time. */
/* Funds says in plain words what can be spent now, what is arriving, what is maturing and what is public, and
 * shows no number the node did not report. */
static void test_funds_plain_words(void)
{
    start(false);
    fake.summary = SUMMARY_ALL;
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    struct wallet_screen *s = snap();
    long label = find_text(s, "Balance"), amount = find(s, WALLET_ITEM_AMOUNT, WALLET_ACT_NONE);
    CHECK(label >= 0 && amount == label + 1 && !strcmp(text_at(s, amount), "2 ZCL"));
    CHECK(has("0.5 ZCL pending in 2 payments. The next arrives in 7 confirmations."));
    CHECK(has("20 ZCL of mined coins maturing, not yet spendable"));
    CHECK(has("0.1 ZCL public: visible to everyone, not part of the spendable amount"));
    fake.summary = "{\"ok\":true,\"data\":{\"x\":1}}";
    fake.always_ok = true;
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    CHECK(has("Balance unknown") && has("Pending amount unknown") && has("Public amount unknown") && has("Maturing amount unknown"));
    CHECK(!has(" 0 ZCL") && !has("0.0") && !has("Up to date"));
    wallet_screens_close();
}

/* A scan begun at Send that ends without a payment to review leaves the owner on Funds with the words and a way to try again. */
static void test_scan_notice(void)
{
    start(false);
    wallet_screens_scan_notice("This payment code was refused. Nothing was done.");   /* nothing open: ignored */
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    CHECK(!has("refused") && !strcmp(text_at(snap(), find(snap(), WALLET_ITEM_BUTTON, WALLET_ACT_SEND)), "Send"));
    wallet_screens_scan_notice("This payment code was refused. Nothing was done.");
    struct wallet_screen *s = snap();
    long send = find(s, WALLET_ITEM_BUTTON, WALLET_ACT_SEND);
    CHECK(s->page == WALLET_PAGE_FUNDS && has("This payment code was refused. Nothing was done.") && has("1.23456789 ZCL"));
    CHECK(send >= 0 && !strcmp(text_at(s, send), "Scan again") && find(s, WALLET_ITEM_NOTE, WALLET_ACT_NONE) >= 0);
    fake.now += 100000;                                                      /* a refresh keeps the words */
    wallet_screens_tick();
    CHECK(has("This payment code was refused."));
    tap(WALLET_ACT_SEND, 0, WALLET_SEND);
    tap(WALLET_ACT_RECEIVE, 0, WALLET_STAY);
    wallet_screens_scan_notice("not on Funds");                              /* only Funds shows it */
    CHECK(!has("not on Funds") && !has("refused"));
    CHECK(wallet_screens_back() && !has("refused") && !strcmp(text_at(snap(), find(snap(), WALLET_ITEM_BUTTON, WALLET_ACT_SEND)), "Send"));
    wallet_screens_close();
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS) && !has("refused"));
    wallet_screens_close();
}

/* The whole address is shown on every network, its prefix kept in one piece, so no group starts inside the prefix. */
static void test_receive_address_whole(void)
{
    static const char *const addresses[] = {A1, RT_ADDR};
    static const char *const prefixes[] = {"zs1", "zregtestsapling1"};
    for (size_t i = 0; i < 2; ++i) {
        char reply_text[256], flat[256] = "";
        snprintf(reply_text, sizeof(reply_text), "{\"ok\":true,\"data\":{\"address\":\"%s\"}}", addresses[i]);
        start(false);
        fake.latest = reply_text;
        CHECK(wallet_screens_open(WALLET_PAGE_RECEIVE));
        struct wallet_screen *s = snap();
        const char *shown = text_at(s, find(s, WALLET_ITEM_ADDRESS, WALLET_ACT_NONE));
        size_t prefix = strlen(prefixes[i]), used = 0;
        CHECK(!strncmp(shown, prefixes[i], prefix) && shown[prefix] == ' ');
        for (const char *c = shown; *c; ++c) if (*c != ' ') flat[used++] = *c;
        CHECK(!strcmp(flat, addresses[i]));
        for (const char *c = shown + prefix + 1, *start_of = c; *c; ++c)
            if (*c == ' ') { CHECK(c - start_of == 4); start_of = c + 1; }
        wallet_screens_close();
    }
}

/* Confirmed funds a send would refuse for now are said in one plain line, never added to what is spendable; a
 * total that one send cannot reach is said too; unreadable or hidden private amounts are never shown as zero. */
static void test_funds_unready(void)
{
    start(false);
    fake.summary = SUMMARY_STATE("ok", PRIVATE_OK("0", "0.00000000", "\"unready_zat\":5000000000,\"unready\":\"50.00000000\",\"unready_notes\":2,"), "0", "0.00000000");
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    CHECK(has("50 ZCL received, not spendable yet") && has("0 ZCL"));
    CHECK(!strcmp(text_at(snap(), find(snap(), WALLET_ITEM_AMOUNT, WALLET_ACT_NONE)), "0 ZCL"));
    fake.summary = SUMMARY_STATE("ok", PRIVATE_OK("100000000", "1.00000000", "\"unready_zat\":0,\"unready\":\"0.00000000\",\"spendable_total_zat\":900000000,\"spendable_total\":\"9.00000000\","), "0", "0.00000000");
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    CHECK(has("You can send up to 1 ZCL at once, fee included") && !has("catches up"));
    CHECK(!strcmp(text_at(snap(), find(snap(), WALLET_ITEM_AMOUNT, WALLET_ACT_NONE)), "9 ZCL"));
    fake.summary = SUMMARY_STATE("ok", PRIVATE_OK("100000000", "1.00000000", "\"unready_zat\":0,\"unready\":\"0.00000000\",\"spendable_total_zat\":100000000,\"spendable_total\":\"1.00000000\","), "0", "0.00000000");
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    CHECK(!has("in one payment") && !has("catches up"));
    fake.summary = SUMMARY_STATE("ok", PRIVATE_OK("100000000", "1.00000000", "\"unready_zat\":null,\"unready\":null,"), "0", "0.00000000");
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    CHECK(has("Funds received but not spendable yet: amount unknown") && has("1 ZCL") && !has("catches up"));
    fake.summary = SUMMARY_STATE("ok", PRIVATE_OK("100000000", "1.00000000", "\"unready_zat\":5,\"unready\":\"0.5\","), "0", "0.00000000");   /* a malformed amount is no reply */
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    CHECK(has("Balance unknown") && !has("catches up"));
    fake.summary = SUMMARY_STATE("keys_unavailable", PRIVATE_HIDDEN, "10000000", "0.10000000");
    CHECK(wallet_screens_open(WALLET_PAGE_FUNDS));
    CHECK(has("Your private balance is hidden because the wallet is locked") && has("Up to date at block 3000000") && !has("Catching up") && has("0.1 ZCL public") && !has("catches up") && !has("0 ZCL") && !has("unknown"));
    wallet_screens_close();
}

/* A row whose kind and fully_shielded are null is neither Private nor Public. */
#define NULL_PRIVACY_ROW                                                                                 \
    "{\"txid\":\"" TX_A "\",\"status\":\"confirmed\",\"height\":2999990,\"confirmations\":11,\"time\":1700000000," \
    "\"direction\":\"received\",\"kind\":null,\"amount_zat\":100,\"amount\":null,\"fee_zat\":null,\"fee\":null,\"net_zat\":0," \
    "\"memo_present\":false,\"fully_shielded\":null}"
static void test_null_privacy(void)
{
    start(false);
    fake.history[0] = PAGE(NULL_PRIVACY_ROW, "1", "null");
    CHECK(wallet_screens_open(WALLET_PAGE_HISTORY));
    long at = find_text(snap(), "Received ·");
    CHECK(at >= 0 && !strstr(text_at(snap(), at), "Private") && !strstr(text_at(snap(), at), "Public"));
    tap(WALLET_ACT_DETAIL, 0, WALLET_STAY);
    CHECK(has("The node does not say whether every part of this payment was private.") && !has("Private"));
    wallet_screens_close();
}

/* A history page that does not say "ok" for private payments is not the whole history: its rows show with one plain line,
 * and an empty one is never called empty. */
static void test_history_incomplete(void)
{
    start(false);
    fake.history[0] = PAGE_STATE(STATE_HIDDEN, ROW_RECEIVED, "1", "null");
    CHECK(wallet_screens_open(WALLET_PAGE_HISTORY));
    CHECK(has("Private payments are hidden while the wallet is locked") && has("Received") && !has("No transactions yet") && !has("None found"));
    fake.history[0] = PAGE_STATE(STATE_HIDDEN, "", "0", "null");
    CHECK(wallet_screens_open(WALLET_PAGE_HISTORY));
    CHECK(has("Private payments are hidden while the wallet is locked") && !has("No transactions yet") && !has("None found") && !has("No older"));
    fake.history[0] = PAGE_STATE("", "", "0", "null");                       /* a node that says nothing about it */
    CHECK(wallet_screens_open(WALLET_PAGE_HISTORY));
    CHECK(has("did not say whether this list is complete") && !has("No transactions yet") && !has("None found"));
    fake.history[0] = PAGE_STATE("\"shielded_state\":\"bogus\",", ROW_RECEIVED, "1", "null");
    CHECK(wallet_screens_open(WALLET_PAGE_HISTORY));
    CHECK(has("did not say whether this list is complete") && has("Received"));
    fake.history[0] = PAGE_STATE(STATE_OK, "", "0", "null");                 /* complete and empty */
    CHECK(wallet_screens_open(WALLET_PAGE_HISTORY));
    CHECK(has("No transactions yet.") && !has("hidden") && !has("did not say"));
    wallet_screens_close();
}

static int64_t at_utc(int year, int month, int day, int hour, int minute)
{
    struct tm t = {.tm_year = year - 1900, .tm_mon = month - 1, .tm_mday = day, .tm_hour = hour, .tm_min = minute};
    return (int64_t)timegm(&t);
}
static void label(int64_t now, int64_t when, int64_t offset, const char *want)
{
    char text[48];
    wallet_time_label(now, when, offset, text, sizeof(text));
    if (strcmp(text, want)) fprintf(stderr, "label: got \"%s\", want \"%s\"\n", text, want);
    CHECK(!strcmp(text, want));
}
static void test_time_labels(void)
{
    int64_t now = at_utc(2026, 11, 2, 12, 0);
    label(now, at_utc(2026, 11, 2, 14, 5), 0, "Today 14:05");
    label(now, at_utc(2026, 11, 2, 0, 0), 0, "Today 00:00");
    label(now, at_utc(2026, 11, 1, 9, 12), 0, "Yesterday 09:12");
    label(now, at_utc(2026, 10, 31, 23, 59), 0, "31 Oct 23:59");
    label(now, at_utc(2026, 11, 3, 0, 0), 0, "3 Nov 00:00");                 /* a time ahead of the clock */
    label(now, at_utc(2025, 11, 2, 8, 30), 0, "2 Nov 2025 08:30");           /* the year is shown when it is not this year */
    now = at_utc(2027, 1, 1, 0, 30);
    label(now, at_utc(2026, 12, 31, 23, 10), 0, "Yesterday 23:10");         /* across the year boundary */
    label(now, at_utc(2026, 12, 30, 8, 0), 0, "30 Dec 2026 08:00");
    now = at_utc(2028, 3, 1, 10, 0);
    label(now, at_utc(2028, 2, 29, 10, 0), 0, "Yesterday 10:00");           /* a leap day */
    label(now, at_utc(2028, 2, 28, 10, 0), 0, "28 Feb 10:00");
    label(now, at_utc(2027, 2, 28, 10, 0), 0, "28 Feb 2027 10:00");
    now = at_utc(2026, 11, 2, 3, 0);
    label(now, at_utc(2026, 11, 2, 2, 0), -5 * 3600, "Today 21:00");        /* the phone is five hours behind UTC */
    now = at_utc(2026, 11, 2, 12, 0);
    label(now, at_utc(2026, 11, 2, 11, 30), 14 * 3600, "Today 01:30");      /* the phone is fourteen hours ahead */
    label(now, at_utc(2026, 11, 2, 9, 0), 5 * 3600 + 1800, "Today 14:30");  /* a half-hour zone */
}
static void test_receive_redraw(void)
{
    struct wallet_screen before, after;
    start(false);
    CHECK(wallet_screens_open(WALLET_PAGE_RECEIVE));
    unsigned v0 = wallet_screens_snapshot(&before);
    CHECK(wallet_screens_set_amount("  "));                          /* nothing new on the screen: the version changes, the items do not */
    unsigned v1 = wallet_screens_snapshot(&after);
    CHECK(v1 != v0 && wallet_screen_same(&before, &after));
    CHECK(wallet_screens_set_amount("1.5"));
    (void)wallet_screens_snapshot(&before);
    CHECK(!wallet_screen_same(&before, &after));
    CHECK(wallet_screens_set_amount("2.5"));                           /* the same count of items, another code */
    (void)wallet_screens_snapshot(&after);
    CHECK(after.count == before.count && !wallet_screen_same(&before, &after));
    CHECK(!wallet_screens_set_amount("2.5x"));                         /* refused: a note appears, the code stays */
    (void)wallet_screens_snapshot(&before);
    CHECK(find_text(&before, "Enter an amount") >= 0 && !wallet_screen_same(&before, &after));
    long qr = find(&before, WALLET_ITEM_QR, WALLET_ACT_NONE);
    CHECK(qr >= 0 && !strcmp(text_at(&before, qr), "zclassic:" A1 "?amount=2.5"));
    wallet_screens_close();
}

int main(int argc, char **argv)
{
    setenv("TZ", "UTC", 1);
    tzset();
    if (argc > 1 && !strcmp(argv[1], "stale")) test_refresh_and_stale();
    else if (argc > 1 && !strcmp(argv[1], "async")) test_async();
    if (argc > 1) { puts("wallet_screens_test: ok"); return 0; }
    test_funds();
    test_funds_replies();
    test_fleet();
    test_refresh_and_stale();
    test_send_line();
    test_send_line_before_answer();
    test_cache_roundtrip();
    test_cache_other_wallet();
    test_cache_not_trusted();
    test_cache_from_the_future();
    test_cache_only_real_summaries();
    test_cache_silent_node();
    test_new_wallet_zero();
    test_make_private_offer();
    test_make_private_hidden();
    test_reveal_offer();
    test_reveal_window();
    test_reveal_cancelled();
    test_reveal_ends_on_leaving();
    test_reveal_across_pages();
    test_reveal_amount_not_kept();
    test_receive();
    test_receive_amount();
    test_receive_new_address();
    test_receive_copy();
    test_receive_copy_without_address();
    test_receive_never_makes_keys();
    test_receive_replies();
    test_receive_without_new_address();
    test_history();
    test_history_detail();
    test_history_pages();
    test_history_replies();
    test_memo_text();
    test_memo_length();
    test_secure();
    test_pause();
    test_settle();
    test_privacy_claims();
    test_history_while_scanning();
    test_funds_lines();
    test_funds_plain_words();
    test_funds_unready();
    test_history_incomplete();
    test_null_privacy();
    test_scan_notice();
    test_receive_address_whole();
    test_receive_order();
    test_funds_send_paused();
    test_dropped_taps();
    test_late_replies();
    test_nothing_left_behind();
    test_single_flight();
    test_async();
    test_time_labels();
    test_receive_redraw();
    puts("wallet_screens_test: ok");
    return 0;
}
