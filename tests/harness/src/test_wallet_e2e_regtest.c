/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * wallet_e2e_regtest: the real shielded send path, end to end, through a real
 * node process and only its command interface.
 *
 * One isolated regtest node (private datadir, distinct ports,
 * -regtest -regtestshielded -operator-lane=dev) is driven by the built `z23`
 * binary exactly as an operator or a phone drives it:
 *
 *   boot  the chain is regtest before any mutation
 *   fund  one transparent and two Sapling addresses, 101 mined blocks
 *   t->z  plan, commit, mine; note amount, memo, confirmation, block
 *   rule  before z->z and z->t the send is refused at every depth at which
 *         the node's summary reports the note pending (threshold 3 or 10
 *         confirmations), then the note is mined to the first spendable depth
 *   z->z  plan, commit, mine; recipient and change notes, exact fee, memo,
 *         block inclusion read without the wallet, tip hash validated
 *   z->t  plan, commit, mine; block inclusion and exact balance arithmetic
 *   sweep 110 blocks mined to a fresh transparent address; core.wallet.
 *         shielded.shield plans the node's ten mature coins, commits one
 *         transaction (ten inputs, no transparent output, one Sapling
 *         output, value_balance) and replays on the same key before and
 *         after a block; a coin maturing after the plan gives
 *         PLAN_TOKEN_MISMATCH and sends nothing; a locked wallet refuses
 *
 * Each proving send prints its elapsed milliseconds; no time limit is
 * asserted.
 *
 * Seams for later lanes. Every node command is a row of e2e_cmds[]. A send
 * is one struct e2e_send run by e2e_send_run(): plan, then commit with the
 * plan's own commit_input. `key` is the idempotency key; `extra` adds input
 * members (a broadcast mode) and `commit_count` repeats the commit, so replay and
 * private-relay lanes extend a step instead of rewriting it. e2e_notes()
 * is the one note reader a whole-account step reuses.
 *
 * Guarantees. The node runs on 127.0.0.1 only: -private-listeners starts no
 * file-service, HTTPS or RPC-TLS listener (they ignore -bind), and the p2p and
 * RPC listeners are checked against the kernel socket tables. The node never
 * outlives the test process: the child sets PR_SET_PDEATHSIG(SIGKILL) before
 * exec, so even SIGKILL of the test kills it (Linux). On normal and failed
 * returns, and on exit(), the node is stopped and the fixture removed. On
 * SIGINT, SIGTERM or SIGKILL of the test the node is killed and the fixture
 * remains under the runner's test temporary root; the signal handler never
 * removes it.
 *
 * Absent proving parameters or an absent binary are reported UNOBSERVED, the
 * way simnet_sapling_shielded_send reports them.
 *
 * make t-fast ONLY=wallet_e2e_regtest */

#include "test/test_core.h"
#include "json/json.h"
#include "sapling/params_init.h"
#include "sapling/sapling_prover.h"
#include "util/spawn.h"
#include "platform/socket_compat.h"

#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

#define E2E_BIN "build/bin/z23"
#define E2E_FUND_BLOCKS 101
#define E2E_MINE_CHUNK 1
#define E2E_CONF_CHANGE 3    /* WALLET_CONF_CHANGE: a note a wallet spend created */
#define E2E_CONF_RECEIVED 10 /* WALLET_CONF_RECEIVED: any other note */
#define E2E_FEE_ZAT 100
#define E2E_AMT_TZ "0.00400000"
#define E2E_AMT_ZZ "0.00200000"
#define E2E_AMT_ZT "0.00100000"
#define E2E_ZAT_TZ 400000
#define E2E_ZAT_ZZ 200000
#define E2E_ZAT_ZT 100000
#define E2E_MEMO_TZ "e2e t to z memo"
#define E2E_MEMO_ZZ "e2e z to z memo"
#define E2E_CMD_MS 900000
#define E2E_RAW (256 * 1024)
#define E2E_RECONCILE_MS 120000

/* Every node command the test issues: the words after the binary. */
enum e2e_cmd_id {
    E2E_TIP, E2E_CHAININFO, E2E_BALANCE, E2E_ADDR_NEW, E2E_Z_ADDR, E2E_MINE,
    E2E_SEND, E2E_NOTES, E2E_BLOCK_GET, E2E_TX_GET, E2E_SUMMARY,
    E2E_SHIELD, E2E_UNSPENT, E2E_RAWTX, E2E_LOCK,
    E2E_CMD_COUNT
};
static const struct { const char *w[5]; } e2e_cmds[E2E_CMD_COUNT] = {
    [E2E_TIP] = { { "core", "chain", "tip" } },
    [E2E_CHAININFO] = { { "getblockchaininfo" } },
    [E2E_BALANCE] = { { "core", "wallet", "shielded", "balance" } },
    [E2E_ADDR_NEW] = { { "core", "wallet", "address", "new" } },
    [E2E_Z_ADDR] = { { "core", "wallet", "shielded", "address" } },
    [E2E_MINE] = { { "core", "mining", "regtest-mine" } },
    [E2E_SEND] = { { "core", "wallet", "shielded", "send" } },
    [E2E_NOTES] = { { "core", "wallet", "shielded", "notes" } },
    [E2E_BLOCK_GET] = { { "core", "chain", "block", "get" } },
    [E2E_TX_GET] = { { "core", "wallet", "transaction", "get" } },
    [E2E_SUMMARY] = { { "core", "wallet", "summary" } },
    [E2E_SHIELD] = { { "core", "wallet", "shielded", "shield" } },
    [E2E_UNSPENT] = { { "listunspent" } },
    [E2E_RAWTX] = { { "getrawtransaction" } },
    [E2E_LOCK] = { { "core", "wallet", "security", "lock" } },
};

struct e2e {
    char work[PATH_MAX];
    char cred[PATH_MAX + 16];
    char dd_flag[PATH_MAX + 16];
    char rpc_flag[32];
    uint16_t port[2]; /* p2p, rpc */
    pid_t node;
    int tip;
    char tip_hash[80];
    char taddr[128], za[256], zb[256], tdest[128];
};

static struct e2e *e2e_live; /* reaped by atexit if a path forgets */
static volatile pid_t e2e_node_pid; /* read by the signal handler */
static struct sigaction e2e_old_int, e2e_old_term;
static bool e2e_signals_armed;

static long e2e_now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;  // platform-ok:elapsed-evidence-printed-never-asserted
    return (long)ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static void e2e_sleep_ms(long ms)
{
    struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static uint16_t e2e_reserve_port(void)
{
    platform_socket_t fd = platform_socket_open(AF_INET, SOCK_STREAM, 0,
                                                true, false);
    if (fd == PLATFORM_SOCKET_INVALID) return 0;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    uint16_t port = 0;
    if (platform_socket_bind(fd, (struct sockaddr *)&a, sizeof(a)) == 0) {
        size_t len = sizeof(a);
        if (platform_socket_local_address(fd, (struct sockaddr *)&a,
                                          &len) == 0)
            port = ntohs(a.sin_port);
    }
    platform_socket_close(fd);
    return port;
}

/* ── node process ─────────────────────────────────────────────────── */

static void e2e_node_stop(struct e2e *e)
{
    if (e->node <= 0) return;
    kill(-e->node, SIGTERM);
    int status = 0;
    for (int i = 0; i < 600; i++) {
        if (waitpid(e->node, &status, WNOHANG) == e->node) {
            e->node = 0;
            return;
        }
        e2e_sleep_ms(100);
    }
    kill(-e->node, SIGKILL);
    (void)waitpid(e->node, &status, 0);
    e->node = 0;
}

static void e2e_signals_disarm(void);

/* Stop the node and remove the fixture; safe to call twice. */
static void e2e_cleanup(struct e2e *e)
{
    e2e_node_stop(e);
    e2e_signals_disarm();
    if (e->work[0]) test_rm_rf(e->work);
    e->work[0] = '\0';
}

static void e2e_atexit_reap(void)
{
    if (e2e_live) e2e_cleanup(e2e_live);
}

/* The last bytes of the node log, printed before a failed run's fixture is
 * removed. */
static void e2e_log_tail(const struct e2e *e)
{
    char path[PATH_MAX + 16], buf[2049];
    snprintf(path, sizeof(path), "%s/node.log", e->work);
    FILE *f = fopen(path, "r");
    if (!f) return;
    if (fseek(f, -2048L, SEEK_END) != 0) rewind(f);
    size_t n = fread(buf, 1, 2048, f);
    buf[n] = '\0';
    fclose(f);
    printf("  node.log tail:\n%s\n", buf);
}


/* SIGINT or SIGTERM to the test: kill the node's process group, then take the
 * default action. Only async-signal-safe calls. */
static void e2e_on_signal(int sig)
{
    pid_t p = e2e_node_pid;
    if (p > 0) kill(-p, SIGKILL);
    signal(sig, SIG_DFL);
    raise(sig);
}

static void e2e_signals_arm(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = e2e_on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, &e2e_old_int);
    sigaction(SIGTERM, &sa, &e2e_old_term);
    e2e_signals_armed = true;
}

static void e2e_signals_disarm(void)
{
    e2e_node_pid = 0;
    if (!e2e_signals_armed) return;
    e2e_signals_armed = false;
    sigaction(SIGINT, &e2e_old_int, NULL);
    sigaction(SIGTERM, &e2e_old_term, NULL);
}

/* In the node child before exec: die with the test process, however it dies
 * (SIGKILL included). getppid() against the saved parent closes the race where
 * the parent exited before the request took effect. */
static bool e2e_child_die_with_parent(pid_t parent)
{
#ifdef __linux__
    return prctl(PR_SET_PDEATHSIG, SIGKILL) == 0 && getppid() == parent;
#else
    (void)parent;
    return true;
#endif
}

static bool e2e_node_start(struct e2e *e)
{
    char p2p[32], log[PATH_MAX + 16];
    snprintf(p2p, sizeof(p2p), "-port=%u", e->port[0]);
    snprintf(log, sizeof(log), "%s/node.log", e->work);
    pid_t parent = getpid();
    e2e_signals_arm();
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        if (!e2e_child_die_with_parent(parent)) _exit(127);
        setpgid(0, 0);
        int fd = open(log, O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (fd >= 0) {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
        setenv("CREDENTIALS_DIRECTORY", e->cred, 1);
        execl(E2E_BIN, E2E_BIN, e->dd_flag, e->rpc_flag, "-regtest",
              "-regtestshielded", "-operator-lane=dev",
              "-private-listeners", "-bind=127.0.0.1", p2p,
              "-connect=127.0.0.1:1", "-packagehost=0",
              "-wallet-no-phrase-backup", "-nobgvalidation",
              "-nolegacyimport", "-showmetrics=0", (char *)NULL);
        _exit(127);
    }
    setpgid(pid, pid);
    e->node = pid;
    e2e_node_pid = pid;
    return true;
}

/* ── command runner ───────────────────────────────────────────────── */

/* Run one node command with optional arguments (NULL-terminated). Captures
 * stdout into raw; returns the exit status, -1 on spawn failure or timeout. */
static int e2e_exec(const struct e2e *e, enum e2e_cmd_id id,
                    const char *const *args, char *raw, size_t cap)
{
    const char *argv[16];
    size_t n = 0;
    argv[n++] = E2E_BIN;
    argv[n++] = e->dd_flag;
    argv[n++] = e->rpc_flag;
    for (size_t i = 0; i < 5 && e2e_cmds[id].w[i]; i++)
        argv[n++] = e2e_cmds[id].w[i];
    for (size_t i = 0; args && args[i] && n < 15; i++) argv[n++] = args[i];
    argv[n] = NULL;
    bool timed_out = false;
    int rc = zcl_spawn_capture_observed(argv, raw, cap, E2E_CMD_MS,
                                        &timed_out);
    return timed_out ? -1 : rc;
}

/* Run a command and parse its JSON output into *out (caller json_free()s).
 * Returns true when it exited 0 and printed one JSON document whose "ok"
 * member, if present, is true. A failure prints the literal output. */
static bool e2e_json(const struct e2e *e, enum e2e_cmd_id id,
                     const char *const *args, struct json_value *out)
{
    static char raw[E2E_RAW];
    json_init(out);
    int rc = e2e_exec(e, id, args, raw, sizeof(raw));
    test_note("e2e %s exit=%d", e2e_cmds[id].w[0], rc);
    test_note_bytes("e2e reply", raw, strnlen(raw, sizeof(raw)));
    const char *start = strchr(raw, '{');
    bool parsed = start && json_read(out, start, strlen(start));
    bool ok = rc == 0 && parsed;
    const struct json_value *flag = ok ? json_get(out, "ok") : NULL;
    if (ok && flag && !json_get_bool(flag)) ok = false;
    if (!ok) {
        const struct json_value *err = parsed ? json_get(out, "error") : NULL;
        const char *msg = err ? json_get_str(json_get(err, "message")) : NULL;
        printf("\n  command %s failed (exit %d): %s\n  raw: %.1200s\n",
               e2e_cmds[id].w[0], rc, msg ? msg : "", raw);
    }
    return ok;
}

/* Run a command whose refusal is the expected outcome: parse its JSON reply
 * whatever the exit status. True when a document was parsed; *accepted is its
 * "ok" member. Nothing is printed. */
static bool e2e_call(const struct e2e *e, enum e2e_cmd_id id,
                     const char *const *args, struct json_value *out,
                     bool *accepted)
{
    static char raw[E2E_RAW];
    json_init(out);
    int rc = e2e_exec(e, id, args, raw, sizeof(raw));
    test_note("e2e %s exit=%d", e2e_cmds[id].w[0], rc);
    test_note_bytes("e2e reply", raw, strnlen(raw, sizeof(raw)));
    const char *start = strchr(raw, '{');
    bool parsed = rc >= 0 && start && json_read(out, start, strlen(start));
    const struct json_value *flag = parsed ? json_get(out, "ok") : NULL;
    *accepted = rc == 0 && flag && json_get_bool(flag);
    return parsed;
}

/* Dotted-path accessor over a parsed document: "data.txid". */
static const struct json_value *e2e_at(const struct json_value *v,
                                       const char *path)
{
    char buf[128];
    snprintf(buf, sizeof(buf), "%s", path);
    char *save = NULL;
    for (char *tok = strtok_r(buf, ".", &save); tok && v;
         tok = strtok_r(NULL, ".", &save))
        v = json_get(v, tok);
    return v;
}

static const char *e2e_str(const struct json_value *v, const char *path)
{
    const char *s = json_get_str(e2e_at(v, path));
    return s ? s : "";
}

/* Decimal ZCL string "0.00400000" -> zats; -1 when malformed. */
static int64_t e2e_zats(const char *s)
{
    int64_t whole = 0, frac = 0;
    int digits = 0;
    if (!*s) return -1;
    for (; *s >= '0' && *s <= '9'; s++) whole = whole * 10 + (*s - '0');
    if (*s == '.')
        for (s++; *s >= '0' && *s <= '9' && digits < 8; s++, digits++)
            frac = frac * 10 + (*s - '0');
    if (*s && *s != '\n') return -1;
    while (digits++ < 8) frac *= 10;
    return whole * 100000000LL + frac;
}

/* ── chain observations ───────────────────────────────────────────── */

/* The node's view of its own chain: height and best hash. */
static bool e2e_chain_now(const struct e2e *e, int *height, char *hash,
                          size_t cap)
{
    struct json_value r;
    bool ok = e2e_json(e, E2E_CHAININFO, NULL, &r);
    if (ok) {
        *height = (int)json_get_int(json_get(&r, "blocks"));
        snprintf(hash, cap, "%s", e2e_str(&r, "bestblockhash"));
    }
    json_free(&r);
    return ok;
}

/* A mining call whose reply was lost (the client's RPC deadline passed on a
 * loaded host) has an unknown outcome. Inspect the chain and never retry:
 * poll until the height reaches exactly the requested blocks, fail if it
 * passes them or the deadline expires. */
static bool e2e_mine_reconcile(struct e2e *e, int blocks)
{
    int want = e->tip + blocks, height = -1;
    char hash[80] = "";
    long deadline = e2e_now_ms() + E2E_RECONCILE_MS;
    while (e2e_now_ms() < deadline) {
        if (!e2e_chain_now(e, &height, hash, sizeof(hash)) || height > want) {
            test_note("e2e mine reconcile: height=%d want=%d (gave up)",
                      height, want);
            return false;
        }
        if (height == want) {
            e->tip = height;
            snprintf(e->tip_hash, sizeof(e->tip_hash), "%s", hash);
            return true;
        }
        e2e_sleep_ms(500);
    }
    return false;
}

static bool e2e_mine_chunk(struct e2e *e, int blocks, const char *address)
{
    char input[512];
    snprintf(input, sizeof(input),
             "--input={\"address\":\"%s\",\"blocks\":%d,\"confirm\":true}",
             address, blocks);
    const char *args[] = { input, NULL };
    struct json_value r;
    bool ok = e2e_json(e, E2E_MINE, args, &r);
    const struct json_value *h = ok ? e2e_at(&r, "data.block_hashes") : NULL;
    ok = ok && h && h->num_children == (size_t)blocks;
    if (ok) {
        snprintf(e->tip_hash, sizeof(e->tip_hash), "%s",
                 json_get_str(&h->children[h->num_children - 1]));
        e->tip += blocks;
    }
    json_free(&r);
    return ok || e2e_mine_reconcile(e, blocks);
}

static bool e2e_mine(struct e2e *e, int blocks)
{
    for (int left = blocks; left > 0;) {
        int n = left < E2E_MINE_CHUNK ? left : E2E_MINE_CHUNK;
        if (!e2e_mine_chunk(e, n, e->taddr)) return false;
        left -= n;
        if (blocks > 10 && (blocks - left) % 20 == 0)
            printf("\n  mined %d/%d blocks", blocks - left, blocks);
    }
    return true;
}

/* The node's own validation: its best block is the last block this test
 * mined, at the height this test counted. */
static bool e2e_tip_validated(const struct e2e *e)
{
    struct json_value r;
    bool ok = e2e_json(e, E2E_CHAININFO, NULL, &r) &&
              strcmp(e2e_str(&r, "chain"), "regtest") == 0 &&
              json_get_int(json_get(&r, "blocks")) == e->tip &&
              strcmp(e2e_str(&r, "bestblockhash"), e->tip_hash) == 0;
    json_free(&r);
    return ok;
}

/* Does the block at `height` list `txid`? Read through the chain, not the
 * wallet. */
static bool e2e_block_has_tx(const struct e2e *e, int height, const char *txid)
{
    char arg[32];
    snprintf(arg, sizeof(arg), "--height=%d", height);
    const char *args[] = { arg, NULL };
    struct json_value b;
    bool found = false;
    if (e2e_json(e, E2E_BLOCK_GET, args, &b)) {
        const struct json_value *tx = e2e_at(&b, "data.tx");
        for (size_t i = 0; tx && i < tx->num_children; i++)
            if (strcmp(json_get_str(&tx->children[i]) ?
                       json_get_str(&tx->children[i]) : "", txid) == 0)
                found = true;
    }
    json_free(&b);
    return found;
}

struct e2e_note {
    int count;          /* notes at `addr` created by `txid` */
    int64_t zat;
    int confs;
    char memo[600];
};

/* The note(s) of `txid` at `addr`; the one note reader every step uses. */
static struct e2e_note e2e_notes(const struct e2e *e, const char *addr,
                                 const char *txid)
{
    struct e2e_note out = { 0 };
    struct json_value r;
    if (e2e_json(e, E2E_NOTES, NULL, &r)) {
        const struct json_value *l = e2e_at(&r, "data.notes");
        for (size_t i = 0; l && i < l->num_children; i++) {
            const struct json_value *n = &l->children[i];
            if (strcmp(e2e_str(n, "address"), addr) != 0 ||
                strcmp(e2e_str(n, "txid"), txid) != 0)
                continue;
            out.count++;
            out.zat = e2e_zats(e2e_str(n, "amount"));
            out.confs = (int)json_get_int(json_get(n, "confirmations"));
            snprintf(out.memo, sizeof(out.memo), "%s", e2e_str(n, "memo"));
        }
    }
    json_free(&r);
    return out;
}

/* Notes at `addr` that were created by any other txid than `except`. */
static int e2e_notes_other(const struct e2e *e, const char *addr,
                           const char *except)
{
    int count = 0;
    struct json_value r;
    if (e2e_json(e, E2E_NOTES, NULL, &r)) {
        const struct json_value *l = e2e_at(&r, "data.notes");
        for (size_t i = 0; l && i < l->num_children; i++)
            if (strcmp(e2e_str(&l->children[i], "address"), addr) == 0 &&
                strcmp(e2e_str(&l->children[i], "txid"), except) != 0)
                count++;
    }
    json_free(&r);
    return count;
}

/* Zats held at a transparent address with at least one confirmation. */
static int64_t e2e_received(const struct e2e *e, const char *addr)
{
    char arg[300];
    snprintf(arg, sizeof(arg), "--address=%s", addr);
    const char *args[] = { arg, NULL };
    struct json_value r;
    int64_t zat = -1;
    if (e2e_json(e, E2E_BALANCE, args, &r))
        zat = e2e_zats(e2e_str(&r, "data.balance"));
    json_free(&r);
    return zat;
}

/* ── one send: plan, then commit with the plan's own commit_input ─── */

struct e2e_send {
    const char *from, *to, *amount;
    const char *memo;       /* NULL for none */
    const char *key;        /* idempotency_key, required by the shielded send */
    const char *extra;      /* extra input members, e.g. "\"broadcast\":\"private\"" */
    int commit_count;       /* commit attempts; 0 means one */
    char txid[80];
    int64_t plan_fee_zat, fee_zat;
    long elapsed_ms;
};

static void e2e_send_input(const struct e2e_send *s, char *input, size_t cap)
{
    snprintf(input, cap,
             "--input={\"wallet_scope\":\"dev\",\"from\":\"%s\",\"to\":\"%s\","
             "\"amount\":\"%s\",\"idempotency_key\":\"%s\"%s%s%s%s%s}",
             s->from, s->to, s->amount, s->key, s->memo ? ",\"memo\":\"" : "",
             s->memo ? s->memo : "", s->memo ? "\"" : "",
             s->extra ? "," : "", s->extra ? s->extra : "");
}

static bool e2e_send_plan(struct e2e *e, struct e2e_send *s, char *commit,
                          size_t cap)
{
    char input[2048];
    e2e_send_input(s, input, sizeof(input));
    const char *args[] = { input, NULL };
    struct json_value plan;
    bool ok = e2e_json(e, E2E_SEND, args, &plan) &&
              strcmp(e2e_str(&plan, "data.stage"), "plan") == 0;
    const char *ci = e2e_str(&plan, "data.commit_input");
    ok = ok && ci[0] && strlen(ci) + 9 < cap;
    if (ok) {
        snprintf(commit, cap, "--input=%s", ci);
        s->plan_fee_zat = json_get_int(e2e_at(&plan, "data.fee_zat"));
    }
    json_free(&plan);
    return ok;
}

static bool e2e_send_run(struct e2e *e, struct e2e_send *s)
{
    char commit[2200];
    if (!e2e_send_plan(e, s, commit, sizeof(commit))) return false;
    const char *args[] = { commit, NULL };
    int attempts = s->commit_count > 0 ? s->commit_count : 1;
    struct json_value done = { 0 };
    long t0 = e2e_now_ms();
    for (int i = 0; i < attempts; i++) {
        if (i > 0) json_free(&done);
        if (!e2e_json(e, E2E_SEND, args, &done)) {
            json_free(&done);
            return false;
        }
    }
    s->elapsed_ms = e2e_now_ms() - t0;
    test_note("e2e send: stage=%s txid_len=%zu attempts=%d elapsed_ms=%ld",
              e2e_str(&done, "data.stage"), strlen(e2e_str(&done, "data.txid")),
              attempts, s->elapsed_ms);
    bool ok = strcmp(e2e_str(&done, "data.stage"), "committed") == 0 &&
         strlen(e2e_str(&done, "data.txid")) == 64;
    snprintf(s->txid, sizeof(s->txid), "%s", e2e_str(&done, "data.txid"));
    s->fee_zat = json_get_int(e2e_at(&done, "data.fee_zat"));
    json_free(&done);
    return ok;
}

/* ── steps ────────────────────────────────────────────────────────── */

static bool e2e_new_address(const struct e2e *e, enum e2e_cmd_id id, char *out,
                            size_t cap)
{
    /* Key derivation can outlast the client's RPC deadline on a loaded host;
     * an extra derived address is harmless, so retry a few times. */
    for (int attempt = 0; attempt < 3; attempt++) {
        struct json_value r;
        bool ok = e2e_json(e, id, NULL, &r);
        if (ok) snprintf(out, cap, "%s", e2e_str(&r, "data.address"));
        json_free(&r);
        if (ok && out[0]) return true;
    }
    return false;
}

/* Listening sockets of this node: every TCP listener on one of its two ports
 * must be bound to 127.0.0.1 (or ::1). Returns the number of listeners found
 * on the ports, negative when one is bound elsewhere. Reads the kernel's socket
 * tables; no process listing. */
static int e2e_listeners(const struct e2e *e, const char *table, bool v6)
{
    FILE *f = fopen(table, "r");
    if (!f) return 0;
    char line[512], addr[40];
    int found = 0;
    const char *lo = v6 ? "00000000000000000000000001000000" : "0100007F";
    while (fgets(line, sizeof(line), f)) {
        unsigned port, st;
        if (sscanf(line, " %*d: %39[0-9A-Fa-f]:%x %*s %x", addr, &port,
                   &st) != 3 || st != 0x0A)
            continue;
        for (int i = 0; i < 2; i++) {
            if (port != e->port[i]) continue;
            found++;
            if (strcmp(addr, lo) != 0) {
                printf("\n  listener %s %s port %u bound to %s, not loopback", table,
                       (const char *[]){ "p2p", "rpc" }[i], port, addr);
                found = -1000;
            }
        }
    }
    fclose(f);
    return found;
}

static bool e2e_loopback_only(const struct e2e *e)
{
    int v4 = e2e_listeners(e, "/proc/net/tcp", false);
    int v6 = e2e_listeners(e, "/proc/net/tcp6", true);
    if (access("/proc/net/tcp", R_OK) != 0) return true; /* not Linux */
    if (v4 == 0) printf("\n  no IPv4 listener on the node ports");
    return v4 >= 1 && v6 >= 0;
}

static int e2e_step_boot(struct e2e *e)
{
    int failures = 0;
    TEST("wallet_e2e_regtest: node boots; chain is regtest before any mutation") {
        struct json_value r;
        bool up = false;
        for (int i = 0; i < 240 && !up; i++) {
            int st = 0;
            if (waitpid(e->node, &st, WNOHANG) == e->node) {
                e->node = 0;
                break;
            }
            static char raw[E2E_RAW];
            up = e2e_exec(e, E2E_TIP, NULL, raw, sizeof(raw)) == 0 &&
                 strstr(raw, "\"ok\":true") != NULL;
            if (!up) e2e_sleep_ms(500);
        }
        ASSERT(up);
        ASSERT(e2e_json(e, E2E_CHAININFO, NULL, &r));
        ASSERT_STR_EQ(e2e_str(&r, "chain"), "regtest");
        e->tip = (int)json_get_int(json_get(&r, "blocks"));
        snprintf(e->tip_hash, sizeof(e->tip_hash), "%s",
                 e2e_str(&r, "bestblockhash"));
        json_free(&r);
        ASSERT_EQ(e->tip, 0);
        ASSERT(e2e_loopback_only(e));
        PASS();
    } _test_next:;
    return failures;
}

static int e2e_step_fund(struct e2e *e)
{
    int failures = 0;
    TEST("wallet_e2e_regtest: addresses created; 101 blocks mined to the transparent address") {
        ASSERT(e2e_new_address(e, E2E_ADDR_NEW, e->taddr, sizeof(e->taddr)));
        ASSERT(e2e_new_address(e, E2E_Z_ADDR, e->za, sizeof(e->za)));
        ASSERT(e2e_new_address(e, E2E_Z_ADDR, e->zb, sizeof(e->zb)));
        ASSERT(e2e_new_address(e, E2E_ADDR_NEW, e->tdest, sizeof(e->tdest)));
        ASSERT(strcmp(e->za, e->zb) != 0);
        ASSERT(e2e_mine(e, E2E_FUND_BLOCKS));
        ASSERT_EQ(e->tip, E2E_FUND_BLOCKS);
        ASSERT(e2e_tip_validated(e));
        ASSERT(e2e_loopback_only(e));
        PASS();
    } _test_next:;
    return failures;
}

/* ── the wallet spend rule ────────────────────────────────────────── */

struct e2e_summary {
    int64_t spendable;      /* zats one send can spend now */
    int pending_notes;      /* confirmed notes still below their threshold */
    int pending_need;       /* fewest confirmations any pending note lacks */
};

static bool e2e_summary(const struct e2e *e, struct e2e_summary *s)
{
    struct json_value r;
    bool ok = e2e_json(e, E2E_SUMMARY, NULL, &r);
    if (ok) {
        s->spendable = json_get_int(e2e_at(&r, "data.spendable_zat"));
        s->pending_notes = (int)json_get_int(e2e_at(&r, "data.pending_notes"));
        s->pending_need = (int)json_get_int(
            e2e_at(&r, "data.pending_min_confirmations_needed"));
    }
    json_free(&r);
    return ok;
}

/* Plan, then commit once. True when the node refuses the send, with the
 * refusal's code and message; a send that goes through returns false. */
static bool e2e_send_refused(const struct e2e *e, const struct e2e_send *s,
                             char *code, char *msg, size_t cap)
{
    char input[2048], commit[2200];
    e2e_send_input(s, input, sizeof(input));
    const char *plan_args[] = { input, NULL };
    struct json_value r;
    bool accepted = false;
    bool parsed = e2e_call(e, E2E_SEND, plan_args, &r, &accepted);
    const char *ci = e2e_str(&r, "data.commit_input");
    if (parsed && accepted && ci[0] && strlen(ci) + 9 < sizeof(commit)) {
        snprintf(commit, sizeof(commit), "--input=%s", ci);
        json_free(&r);
        const char *commit_args[] = { commit, NULL };
        parsed = e2e_call(e, E2E_SEND, commit_args, &r, &accepted);
    }
    bool refused = parsed && !accepted;
    if (refused) {
        snprintf(code, 64, "%s", e2e_str(&r, "error.code"));
        snprintf(msg, cap, "%s", e2e_str(&r, "error.message"));
    }
    json_free(&r);
    return refused;
}

/* The send, tried with a fresh idempotency key at `confs` confirmations, is
 * refused for want of spendable funds, and the node's own summary says why:
 * nothing spendable and a note pending whose threshold, confs plus the
 * confirmations it lacks, is one of the wallet's two rule values. */
static bool e2e_gate_refused(const struct e2e *e, const struct e2e_send *send,
                             int confs, const struct e2e_summary *sum)
{
    struct e2e_send probe = *send;
    char key[96], code[64] = "", msg[512] = "";
    snprintf(key, sizeof(key), "%s-at-%d", send->key, confs);
    probe.key = key;
    bool refused = e2e_send_refused(e, &probe, code, msg, sizeof(msg));
    int need = confs + sum->pending_need;
    printf("\n  [evidence] %d confirmations: refused (%s): %s; spendable "
           "%lld, %d pending, %d short of %d ", confs, code, msg,
           (long long)sum->spendable, sum->pending_notes, sum->pending_need,
           need);
    return refused && strcmp(code, "SEND_REFUSED_KEY_RELEASED") == 0 &&
           strstr(msg, "Insufficient shielded funds") != NULL &&
           sum->pending_notes >= 1 && sum->pending_need >= 1 &&
           (need == E2E_CONF_CHANGE || need == E2E_CONF_RECEIVED);
}

/* The note of `txid` at `addr` starts at one confirmation. While the node's
 * summary reports nothing spendable the send is refused, at every depth; mine
 * one block at a time until the summary shows the note spendable. That must
 * happen no earlier than WALLET_CONF_CHANGE and no later than
 * WALLET_CONF_RECEIVED confirmations. The rule is followed, never bypassed:
 * no minconf override is passed. */
static bool e2e_confirm_gate(struct e2e *e, const char *addr, const char *txid,
                             const struct e2e_send *send)
{
    for (int confs = 1; confs <= E2E_CONF_RECEIVED; confs++) {
        struct e2e_note n = e2e_notes(e, addr, txid);
        struct e2e_summary sum = { 0 };
        if (n.count != 1 || n.confs != confs || !e2e_summary(e, &sum)) {
            printf("\n  note has %d confirmations, expected %d ", n.confs,
                   confs);
            return false;
        }
        if (sum.spendable > 0)
            return confs >= E2E_CONF_CHANGE && sum.spendable >= n.zat;
        if (!e2e_gate_refused(e, send, confs, &sum)) return false;
        if (!e2e_mine(e, 1)) return false;
    }
    return false;
}

static int e2e_step_t_to_z(struct e2e *e, struct e2e_send *s)
{
    int failures = 0;
    TEST("wallet_e2e_regtest: t -> zA with memo: note, memo, confirmation, block") {
        *s = (struct e2e_send){ .from = e->taddr, .to = e->za,
                                .amount = E2E_AMT_TZ, .memo = E2E_MEMO_TZ,
                                .key = "e2e-t-to-z" };
        ASSERT(e2e_send_run(e, s));
        printf("\n  [evidence] t->z proving send: %ld ms ", s->elapsed_ms);
        ASSERT_EQ(s->plan_fee_zat, E2E_FEE_ZAT);
        ASSERT_EQ(s->fee_zat, E2E_FEE_ZAT);
        ASSERT(e2e_mine(e, 1));
        struct e2e_note n = e2e_notes(e, e->za, s->txid);
        ASSERT_EQ(n.count, 1);
        ASSERT_EQ(n.zat, E2E_ZAT_TZ);
        ASSERT_EQ(n.confs, 1);
        ASSERT_STR_EQ(n.memo, E2E_MEMO_TZ);
        ASSERT(e2e_block_has_tx(e, e->tip, s->txid));
        ASSERT(e2e_tip_validated(e));
        PASS();
    } _test_next:;
    return failures;
}

static int e2e_step_z_to_z(struct e2e *e, const struct e2e_send *prev,
                           struct e2e_send *s)
{
    int failures = 0;
    TEST("wallet_e2e_regtest: zA -> zB with memo: recipient, change, exact fee, block, validation") {
        *s = (struct e2e_send){ .from = e->za, .to = e->zb,
                                .amount = E2E_AMT_ZZ, .memo = E2E_MEMO_ZZ,
                                .key = "e2e-z-to-z" };
        ASSERT(e2e_confirm_gate(e, e->za, prev->txid, s));
        ASSERT(e2e_send_run(e, s));
        printf("\n  [evidence] z->z proving send: %ld ms ", s->elapsed_ms);
        ASSERT_EQ(s->plan_fee_zat, E2E_FEE_ZAT);
        ASSERT_EQ(s->fee_zat, E2E_FEE_ZAT);
        ASSERT(e2e_mine(e, 1));
        struct e2e_note to_b = e2e_notes(e, e->zb, s->txid);
        struct e2e_note change = e2e_notes(e, e->za, s->txid);
        ASSERT_EQ(to_b.count, 1);
        ASSERT_EQ(to_b.zat, E2E_ZAT_ZZ);
        ASSERT_EQ(to_b.confs, 1);
        ASSERT_STR_EQ(to_b.memo, E2E_MEMO_ZZ);
        ASSERT_EQ(change.count, 1);
        ASSERT_EQ(change.zat, E2E_ZAT_TZ - E2E_ZAT_ZZ - E2E_FEE_ZAT);
        ASSERT_EQ(e2e_notes_other(e, e->za, s->txid), 0);
        ASSERT(e2e_block_has_tx(e, e->tip, s->txid));
        ASSERT(e2e_tip_validated(e));
        PASS();
    } _test_next:;
    return failures;
}

static int e2e_step_z_to_t(struct e2e *e, const struct e2e_send *prev,
                           struct e2e_send *s)
{
    int failures = 0;
    TEST("wallet_e2e_regtest: zB -> t: block inclusion and exact balances") {
        *s = (struct e2e_send){ .from = e->zb, .to = e->tdest,
                                .amount = E2E_AMT_ZT,
                                .key = "e2e-z-to-t" };
        ASSERT(e2e_confirm_gate(e, e->zb, prev->txid, s));
        ASSERT(e2e_send_run(e, s));
        printf("\n  [evidence] z->t proving send: %ld ms ", s->elapsed_ms);
        ASSERT_EQ(s->fee_zat, E2E_FEE_ZAT);
        ASSERT(e2e_mine(e, 1));
        ASSERT(e2e_block_has_tx(e, e->tip, s->txid));
        ASSERT_EQ(e2e_received(e, e->tdest), E2E_ZAT_ZT);
        struct e2e_note change = e2e_notes(e, e->zb, s->txid);
        ASSERT_EQ(change.count, 1);
        ASSERT_EQ(change.zat, E2E_ZAT_ZZ - E2E_ZAT_ZT - E2E_FEE_ZAT);
        ASSERT_EQ(e2e_notes_other(e, e->zb, s->txid), 0);
        /* Conservation: what the t->z send shielded is now the two change
         * notes, the transparent payout and the two shielded-send fees. */
        struct e2e_note a_change = e2e_notes(e, e->za, prev->txid);
        ASSERT_EQ(a_change.count, 1);
        ASSERT_EQ(a_change.zat + change.zat + E2E_ZAT_ZT + 2 * E2E_FEE_ZAT,
                  E2E_ZAT_TZ);
        ASSERT(e2e_tip_validated(e));
        PASS();
    } _test_next:;
    return failures;
}

/* ── the public-address sweep: core.wallet.shielded.shield ────────── */

#define E2E_SWEEP_BLOCKS 110
#define E2E_COINBASE_CONFS 101 /* a coinbase output spends at tip - height >= 100 */
#define E2E_SWEEP_FEE_ZAT E2E_FEE_ZAT
#define E2E_SAPLING_SPEND_BYTES 384
#define E2E_SAPLING_OUTPUT_BYTES 948

/* Mature coins of one transparent address as the node lists them. */
struct e2e_coins {
    int count;
    int64_t total;
};

/* The node's own listunspent at the coinbase depth: a bare JSON array, so it
 * is read from the first '['. */
static bool e2e_coins_of(const struct e2e *e, const char *addr,
                         struct e2e_coins *c)
{
    static char raw[E2E_RAW];
    char minconf[16];
    snprintf(minconf, sizeof(minconf), "%d", E2E_COINBASE_CONFS);
    const char *args[] = { minconf, NULL };
    c->count = 0;
    c->total = 0;
    int rc = e2e_exec(e, E2E_UNSPENT, args, raw, sizeof(raw));
    const char *start = strchr(raw, '[');
    struct json_value l;
    json_init(&l);
    if (rc != 0 || !start || !json_read(&l, start, strlen(start)) ||
        l.type != JSON_ARR) {
        printf("\n  listunspent failed (exit %d): %.300s\n", rc, raw);
        json_free(&l);
        return false;
    }
    for (size_t i = 0; i < l.num_children; i++) {
        const struct json_value *u = &l.children[i];
        const struct json_value *a = json_get(u, "amount");
        if (strcmp(e2e_str(u, "address"), addr) != 0) continue;
        c->count++;
        c->total += (int64_t)((a && a->type == JSON_REAL ? a->val.d : 0) *
                                  1e8 + 0.5);
    }
    json_free(&l);
    return true;
}

/* The wire form of a transaction, read back from the node. */
struct e2e_rawtx {
    size_t vin, vout, spends, outputs;
    int64_t value_balance;
};

static bool e2e_cs(const uint8_t *b, size_t len, size_t *pos, uint64_t *v)
{
    if (*pos >= len) return false;
    uint8_t first = b[(*pos)++];
    size_t extra = first < 253 ? 0 : first == 253 ? 2 : first == 254 ? 4 : 8;
    if (extra == 0) { *v = first; return true; }
    if (*pos + extra > len) return false;
    *v = 0;
    for (size_t i = 0; i < extra; i++) *v |= (uint64_t)b[*pos + i] << (8 * i);
    *pos += extra;
    return true;
}

static bool e2e_skip_scripts(const uint8_t *b, size_t len, size_t *pos,
                             uint64_t count, size_t fixed)
{
    for (uint64_t i = 0; i < count; i++) {
        uint64_t sl;
        if (*pos + fixed > len) return false;
        *pos += fixed;
        if (!e2e_cs(b, len, pos, &sl) || sl > len - *pos) return false;
        *pos += (size_t)sl;
        if (fixed == 36) { /* an input: the sequence follows the script */
            if (*pos + 4 > len) return false;
            *pos += 4;
        }
    }
    return true;
}

/* Sapling v4 layout: header, group id, inputs, outputs, lock time, expiry,
 * value balance, spend descriptions, output descriptions. */
static bool e2e_decode(const char *hex, struct e2e_rawtx *t)
{
    static uint8_t b[64 * 1024];
    size_t n = strlen(hex) / 2, pos = 8;
    uint64_t v;
    if (n == 0 || n > sizeof(b)) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned x;
        if (sscanf(hex + 2 * i, "%2x", &x) != 1) return false;
        b[i] = (uint8_t)x;
    }
    memset(t, 0, sizeof(*t));
    if (!e2e_cs(b, n, &pos, &v) || !e2e_skip_scripts(b, n, &pos, v, 36))
        return false;
    t->vin = (size_t)v;
    if (!e2e_cs(b, n, &pos, &v) || !e2e_skip_scripts(b, n, &pos, v, 8))
        return false;
    t->vout = (size_t)v;
    pos += 8; /* lock time, expiry height */
    if (pos + 8 > n) return false;
    for (int i = 7; i >= 0; i--)
        t->value_balance = (int64_t)(((uint64_t)t->value_balance << 8) |
                                     b[pos + (size_t)i]);
    pos += 8;
    if (!e2e_cs(b, n, &pos, &v)) return false;
    t->spends = (size_t)v;
    if (v > (n - pos) / E2E_SAPLING_SPEND_BYTES) return false;
    pos += (size_t)v * E2E_SAPLING_SPEND_BYTES;
    if (!e2e_cs(b, n, &pos, &v)) return false;
    t->outputs = (size_t)v;
    return v <= (n - pos) / E2E_SAPLING_OUTPUT_BYTES;
}

static bool e2e_rawtx_of(const struct e2e *e, const char *txid,
                         struct e2e_rawtx *t)
{
    const char *args[] = { txid, "1", NULL };
    struct json_value r;
    bool ok = e2e_json(e, E2E_RAWTX, args, &r) &&
              e2e_decode(e2e_str(&r, "hex"), t);
    json_free(&r);
    return ok;
}

struct e2e_sweep {
    char addr[128], to[256], commit[2200], txid[80];
    struct e2e_coins coins;
    int64_t total, fee, amount;
    int64_t notes_before;
};

static void e2e_sweep_input(const struct e2e_sweep *w, const char *key,
                            char *input, size_t cap)
{
    snprintf(input, cap,
             "--input={\"wallet_scope\":\"dev\",\"from\":\"%s\","
             "\"idempotency_key\":\"%s\"}", w->addr, key);
}

/* Plan the sweep. On success w->commit is the plan's own commit input and the
 * quoted figures are in w. */
static bool e2e_sweep_plan(const struct e2e *e, struct e2e_sweep *w,
                           const char *key, int64_t *count_out)
{
    char input[512];
    e2e_sweep_input(w, key, input, sizeof(input));
    const char *args[] = { input, NULL };
    struct json_value r;
    bool ok = e2e_json(e, E2E_SHIELD, args, &r) &&
              strcmp(e2e_str(&r, "data.stage"), "plan") == 0;
    const char *ci = e2e_str(&r, "data.commit_input");
    ok = ok && ci[0] && strlen(ci) + 9 < sizeof(w->commit);
    if (ok) {
        snprintf(w->commit, sizeof(w->commit), "--input=%s", ci);
        snprintf(w->to, sizeof(w->to), "%s", e2e_str(&r, "data.to"));
        w->total = json_get_int(e2e_at(&r, "data.total_zat"));
        w->fee = json_get_int(e2e_at(&r, "data.fee_zat"));
        w->amount = json_get_int(e2e_at(&r, "data.amount_zat"));
        *count_out = json_get_int(e2e_at(&r, "data.input_count"));
        ok = json_get_int(e2e_at(&r, "data.coinbase_input_count")) ==
                 *count_out &&
             json_get_int(e2e_at(&r, "data.remaining_inputs")) == 0;
    }
    json_free(&r);
    return ok;
}

/* Commit with the stored commit input. True when the node accepted it;
 * *replayed and txid are its answer. */
static bool e2e_sweep_commit(const struct e2e *e, const struct e2e_sweep *w,
                             bool *replayed, char *txid, size_t cap)
{
    const char *args[] = { w->commit, NULL };
    struct json_value r;
    bool ok = e2e_json(e, E2E_SHIELD, args, &r) &&
              strcmp(e2e_str(&r, "data.stage"), "committed") == 0 &&
              strlen(e2e_str(&r, "data.txid")) == 64;
    if (ok) {
        *replayed = json_get_bool(e2e_at(&r, "data.replayed"));
        snprintf(txid, cap, "%s", e2e_str(&r, "data.txid"));
    }
    json_free(&r);
    return ok;
}

/* The commit is refused; *code is the node's answer. */
static bool e2e_sweep_refused(const struct e2e *e, const struct e2e_sweep *w,
                              char *code, char *msg, size_t cap)
{
    const char *args[] = { w->commit, NULL };
    struct json_value r;
    bool accepted = false;
    bool parsed = e2e_call(e, E2E_SHIELD, args, &r, &accepted);
    if (parsed && !accepted) {
        snprintf(code, 64, "%s", e2e_str(&r, "error.code"));
        snprintf(msg, cap, "%s", e2e_str(&r, "error.message"));
    }
    json_free(&r);
    return parsed && !accepted;
}

/* Every note the wallet holds at `addr`, in zats. */
static int64_t e2e_notes_value(const struct e2e *e, const char *addr)
{
    int64_t sum = 0;
    struct json_value r;
    if (e2e_json(e, E2E_NOTES, NULL, &r)) {
        const struct json_value *l = e2e_at(&r, "data.notes");
        for (size_t i = 0; l && i < l->num_children; i++)
            if (strcmp(e2e_str(&l->children[i], "address"), addr) == 0)
                sum += e2e_zats(e2e_str(&l->children[i], "amount"));
    }
    json_free(&r);
    return sum;
}

static int e2e_step_sweep_plan(struct e2e *e, struct e2e_sweep *w)
{
    int failures = 0;
    TEST("wallet_e2e_regtest: sweep plan quotes the node's own mature coins") {
        ASSERT(e2e_new_address(e, E2E_ADDR_NEW, w->addr, sizeof(w->addr)));
        for (int i = 0; i < E2E_SWEEP_BLOCKS; i++) {
            ASSERT(e2e_mine_chunk(e, 1, w->addr));
            if ((i + 1) % 20 == 0) printf("\n  mined %d/%d sweep blocks",
                                          i + 1, E2E_SWEEP_BLOCKS);
        }
        ASSERT(e2e_tip_validated(e));
        ASSERT(e2e_coins_of(e, w->addr, &w->coins));
        int64_t count = 0;
        ASSERT(e2e_sweep_plan(e, w, "e2e-shield-1", &count));
        printf("\n  [evidence] node lists %d mature coins, %lld zat; plan "
               "quotes %lld inputs, total %lld, fee %lld, to %s ",
               w->coins.count, (long long)w->coins.total, (long long)count,
               (long long)w->total, (long long)w->fee, w->to);
        ASSERT_EQ(w->coins.count, E2E_SWEEP_BLOCKS - 100);
        ASSERT_EQ(count, w->coins.count);
        ASSERT_EQ(w->total, w->coins.total);
        ASSERT_EQ(w->fee, E2E_SWEEP_FEE_ZAT);
        ASSERT_EQ(w->amount, w->coins.total - w->fee);
        ASSERT(strcmp(w->to, e->za) == 0 || strcmp(w->to, e->zb) == 0);
        w->notes_before = e2e_notes_value(e, w->to);
        PASS();
    } _test_next:;
    return failures;
}

static int e2e_step_sweep_commit(struct e2e *e, struct e2e_sweep *w)
{
    int failures = 0;
    TEST("wallet_e2e_regtest: sweep commit: one shielded output, no transparent output") {
        bool replayed = true;
        ASSERT(e2e_sweep_commit(e, w, &replayed, w->txid, sizeof(w->txid)));
        ASSERT(!replayed);
        /* The same commit input before any block is mined: the coins are
         * already spent, and the key replays the first result. */
        char again[80] = "";
        ASSERT(e2e_sweep_commit(e, w, &replayed, again, sizeof(again)));
        ASSERT(replayed);
        ASSERT_STR_EQ(again, w->txid);
        ASSERT(e2e_mine(e, 1));
        ASSERT(e2e_block_has_tx(e, e->tip, w->txid));
        struct e2e_rawtx t;
        ASSERT(e2e_rawtx_of(e, w->txid, &t));
        printf("\n  [evidence] sweep tx: %zu inputs, %zu transparent outputs, "
               "%zu spends, %zu shielded outputs, value_balance %lld ",
               t.vin, t.vout, t.spends, t.outputs, (long long)t.value_balance);
        ASSERT_EQ((int64_t)t.vin, w->coins.count);
        ASSERT_EQ((int64_t)t.vout, 0);
        ASSERT_EQ((int64_t)t.spends, 0);
        ASSERT_EQ((int64_t)t.outputs, 1);
        ASSERT_EQ(t.value_balance, -(w->coins.total - w->fee));
        struct e2e_note n = e2e_notes(e, w->to, w->txid);
        ASSERT_EQ(n.count, 1);
        ASSERT_EQ(n.zat, w->coins.total - E2E_SWEEP_FEE_ZAT);
        ASSERT_EQ(n.confs, 1);
        ASSERT_EQ(e2e_notes_value(e, w->to), w->notes_before + n.zat);
        ASSERT(e2e_tip_validated(e));
        PASS();
    } _test_next:;
    return failures;
}

static int e2e_step_sweep_replay(struct e2e *e, struct e2e_sweep *w)
{
    int failures = 0;
    TEST("wallet_e2e_regtest: sweep retried after a block and a new mature coin replays") {
        struct e2e_coins now;
        ASSERT(e2e_coins_of(e, w->addr, &now));
        printf("\n  [evidence] %d mature coin(s) now at the swept address ",
               now.count);
        ASSERT(now.count >= 1);
        bool replayed = false;
        char again[80] = "";
        ASSERT(e2e_sweep_commit(e, w, &replayed, again, sizeof(again)));
        ASSERT(replayed);
        ASSERT_STR_EQ(again, w->txid);
        ASSERT_EQ(e2e_notes(e, w->to, w->txid).count, 1);
        ASSERT_EQ(e2e_notes_value(e, w->to),
                  w->notes_before + w->coins.total - E2E_SWEEP_FEE_ZAT);
        struct e2e_coins after;
        ASSERT(e2e_coins_of(e, w->addr, &after));
        ASSERT_EQ(after.count, now.count);
        ASSERT_EQ(after.total, now.total);
        PASS();
    } _test_next:;
    return failures;
}

static int e2e_step_sweep_drift(struct e2e *e, struct e2e_sweep *w)
{
    int failures = 0;
    TEST("wallet_e2e_regtest: a coin that matures after the plan: PLAN_TOKEN_MISMATCH, nothing sent") {
        struct e2e_coins before, after;
        int64_t count = 0;
        ASSERT(e2e_coins_of(e, w->addr, &before));
        ASSERT(e2e_sweep_plan(e, w, "e2e-shield-2", &count));
        ASSERT_EQ(count, before.count);
        ASSERT(e2e_mine(e, 1));
        int64_t notes = e2e_notes_value(e, w->to);
        char code[64] = "", msg[512] = "";
        ASSERT(e2e_sweep_refused(e, w, code, msg, sizeof(msg)));
        printf("\n  [evidence] drift refused (%s): %s ", code, msg);
        ASSERT_STR_EQ(code, "PLAN_TOKEN_MISMATCH");
        ASSERT(e2e_coins_of(e, w->addr, &after));
        ASSERT_EQ(after.count, before.count + 1);
        ASSERT_EQ(e2e_notes_value(e, w->to), notes);
        PASS();
    } _test_next:;
    return failures;
}

static int e2e_step_sweep_lock(struct e2e *e, struct e2e_sweep *w)
{
    int failures = 0;
    TEST("wallet_e2e_regtest: a sweep committed with the wallet locked is refused") {
        struct e2e_coins before, after;
        int64_t count = 0;
        struct json_value r;
        ASSERT(e2e_coins_of(e, w->addr, &before));
        ASSERT(e2e_sweep_plan(e, w, "e2e-shield-3", &count));
        ASSERT(e2e_json(e, E2E_LOCK, NULL, &r));
        json_free(&r);
        int64_t notes = e2e_notes_value(e, w->to);
        char code[64] = "", msg[512] = "";
        ASSERT(e2e_sweep_refused(e, w, code, msg, sizeof(msg)));
        printf("\n  [evidence] locked commit refused (%s): %s ", code, msg);
        ASSERT(strstr(msg, "locked") != NULL);
        ASSERT(e2e_mine(e, 1));
        ASSERT(e2e_coins_of(e, w->addr, &after));
        ASSERT(after.count >= before.count);
        ASSERT_EQ(e2e_notes_value(e, w->to), notes);
        PASS();
    } _test_next:;
    return failures;
}

static int e2e_step_sweep(struct e2e *e)
{
    struct e2e_sweep w;
    memset(&w, 0, sizeof(w));
    int failures = e2e_step_sweep_plan(e, &w);
    if (!failures) failures += e2e_step_sweep_commit(e, &w);
    if (!failures) failures += e2e_step_sweep_replay(e, &w);
    if (!failures) failures += e2e_step_sweep_drift(e, &w);
    if (!failures) failures += e2e_step_sweep_lock(e, &w);
    return failures;
}

static bool e2e_setup(struct e2e *e)
{
    memset(e, 0, sizeof(*e));
    if (!test_mkdtemp(e->work, sizeof(e->work), "wallet_e2e")) return false;
    char dd[PATH_MAX + 16];
    snprintf(dd, sizeof(dd), "%s/datadir", e->work);
    snprintf(e->cred, sizeof(e->cred), "%s/cred", e->work);
    if (mkdir(dd, 0700) != 0 || mkdir(e->cred, 0700) != 0) return false;
    char pass[PATH_MAX + 32];
    snprintf(pass, sizeof(pass), "%s/wallet-passphrase", e->cred);
    int fd = open(pass, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return false;
    bool wrote = write(fd, "e2e-regtest-passphrase\n", 23) == 23;
    close(fd);
    for (int i = 0; i < 2; i++) e->port[i] = e2e_reserve_port();
    for (int i = 0; i < 2; i++)
        for (int j = 0; j < i; j++)
            if (e->port[i] == 0 || e->port[i] == e->port[j]) return false;
    snprintf(e->dd_flag, sizeof(e->dd_flag), "-datadir=%s", dd);
    snprintf(e->rpc_flag, sizeof(e->rpc_flag), "-rpcport=%u", e->port[1]);
    return wrote;
}

/* The same gate simnet_sapling_shielded_send uses for proving parameters. */
static bool e2e_params_available(void)
{
    const char *home = getenv("HOME");
    char params_dir[512];
    snprintf(params_dir, sizeof(params_dir), "%s/.zcash-params",
             (home && *home) ? home : ".");
    if (sapling_init_params(params_dir) && zclassic_sapling_prover_is_ready())
        return true;
    if (zclassic_sapling_prover_is_ready())
        printf("  ~/.zcash-params absent - SKIPPING the real send path\n");
    else
        printf("  UNOBSERVED (wallet_e2e_regtest proving parameters) - %s "
               "(status=%s)\n", zclassic_sapling_prover_backend(),
               zclassic_sapling_prover_status());
    return false;
}

static int e2e_run_steps(struct e2e *e)
{
    struct e2e_send tz, zz, zt;
    int failures = e2e_step_boot(e);
    if (!failures) failures += e2e_step_fund(e);
    if (!failures) failures += e2e_step_t_to_z(e, &tz);
    if (!failures) failures += e2e_step_z_to_z(e, &tz, &zz);
    if (!failures) failures += e2e_step_z_to_t(e, &zz, &zt);
    if (!failures) failures += e2e_step_sweep(e);
    return failures;
}

int test_wallet_e2e_regtest(void);
int test_wallet_e2e_regtest(void)
{
    printf("\n=== wallet e2e: t->z, z->z, z->t through a real regtest node ===\n");
    int failures = 0;
    if (access(E2E_BIN, X_OK) != 0) {
        printf("  UNOBSERVED (%s absent - build it with make z23)\n", E2E_BIN);
        return 0;
    }
    if (!e2e_params_available()) return 0;

    /* The fixture is removed and the node stopped on every path out: the
     * normal return below, and the atexit reaper for an abnormal exit. */
    struct e2e e = { 0 };
    e2e_live = &e;
    atexit(e2e_atexit_reap);
    TEST("wallet_e2e_regtest: isolated fixture and node start") {
        ASSERT(e2e_setup(&e));
        ASSERT(e2e_node_start(&e));
        PASS();
    } _test_next:;
    if (!failures) failures = e2e_run_steps(&e);
    if (failures && e.work[0]) e2e_log_tail(&e);
    e2e_cleanup(&e);
    e2e_live = NULL;
    return failures;
}
