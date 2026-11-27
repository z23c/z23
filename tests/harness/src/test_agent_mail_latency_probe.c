/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Acceptance tests for dev.agent.mail.probe
 * (tools/command/native_devagent_mailprobe.c): the latency probe that turns
 * "under one second across real hosts" into a measurement.
 *
 * Two boxes, one process: two isolated state roots (XDG_STATE_HOME switched per
 * step), each with its own mail dir. A courier copies rows between the
 * outbox of one root and an inbox stream of the other, standing in for the
 * transport, and the leaf's pump seam runs the peer's echo role between the
 * sender's post and its wait. A scripted wall clock stands behind every
 * t1..t4 timestamp: each box reads its own offset, and a read advances true
 * time one millisecond, so the arithmetic is exact and repeatable. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_devagent_mailprobe.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/private_directory.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

#if defined(_WIN32)
int test_agent_mail_latency_probe(void);
int test_agent_mail_latency_probe(void)
{
    printf("test_agent_mail_latency_probe: skipped on Windows\n");
    return 0;
}
#else

#define PMT_PATH "dev.agent.mail.probe"
#define PMT_SIDE_A 0
#define PMT_SIDE_B 1
#define PMT_TOKEN 4096

struct pmt_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

/* ── the scripted world ────────────────────────────────────────────────── */

struct pmt_world {
    char state[2][1024];
    char mail[2][1400];
    int64_t true_ms;
    int64_t offset[2];
    int64_t peer_clock_step;
    int side;
    bool with_board;
    int board_shape;        /* 0 well-formed, 1 short post, 2 upper-case post,
                             * 3 no signer */
    const char *alias_from; /* rewrite the echo row's from to this name */
    bool dup_plain;         /* also carry the echo again without board fields */
    bool back_to_outbox;    /* land the echo row in the sender's own outbox */
    bool use_since;
    int drop_index;
    int invalid_index;
    int delivered;
    long carried_a, carried_b;
    char since[PMT_TOKEN];
};

static struct pmt_world g_w;
static char g_saved[4096];
static bool g_had;

static int64_t pmt_clock(void *ctx)
{
    struct pmt_world *w = ctx;
    int64_t v = w->true_ms + w->offset[w->side];
    w->true_ms += w->side == PMT_SIDE_B && w->peer_clock_step ? w->peer_clock_step : 1;
    return v;
}

static void pmt_use(int side)
{
    g_w.side = side;
    if (setenv("XDG_STATE_HOME", g_w.state[side], 1) != 0)
        abort();
}

static void pmt_begin(struct pmt_call *c, const char *path, const char *schema)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    zcl_command_reply_init(&c->reply, schema);
}

static void pmt_end(struct pmt_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool pmt_ok(const struct pmt_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static void pmt_isolate_begin(void)
{
    const char *old = getenv("XDG_STATE_HOME");
    g_had = old != NULL;
    if (old)
        (void)snprintf(g_saved, sizeof(g_saved), "%s", old);
}

static void pmt_isolate_end(void)
{
    zcl_devagent_mailprobe_test_set_clock(NULL, NULL);
    zcl_devagent_mailprobe_test_set_pump(NULL, NULL);
    if (g_had)
        (void)setenv("XDG_STATE_HOME", g_saved, 1);
    else
        (void)unsetenv("XDG_STATE_HOME");
}

/* Fresh pair of roots, offsets and counters; clocks installed. */
static void pmt_world(const char *tag, int64_t offset_b, bool with_board,
                      bool use_since, int drop_index)
{
    char base[512];
    memset(&g_w, 0, sizeof(g_w));
    test_make_tmpdir(base, sizeof(base), "agent_mail_latency_probe", tag);
    for (int s = 0; s < 2; s++) {
        (void)snprintf(g_w.state[s], sizeof(g_w.state[s]), "%s/state%d", base,
                       s);
        char root[1300];
        if (!platform_private_directory_ensure(g_w.state[s]) ||
            setenv("XDG_STATE_HOME", g_w.state[s], 1) != 0 ||
            !platform_state_root(root, sizeof(root)) ||
            snprintf(g_w.mail[s], sizeof(g_w.mail[s]), "%s/mail", root) >=
                (int)sizeof(g_w.mail[s]) ||
            !platform_private_directory_ensure(g_w.mail[s])) {
            fprintf(stderr, "latency probe fixture: cannot isolate\n");
            abort();
        }
    }
    g_w.true_ms = 1700000000000LL;
    g_w.offset[PMT_SIDE_B] = offset_b;
    g_w.with_board = with_board;
    g_w.use_since = use_since;
    g_w.drop_index = drop_index;
    g_w.invalid_index = -1;
    zcl_devagent_mailprobe_test_set_clock(pmt_clock, &g_w);
    pmt_use(PMT_SIDE_A);
}

/* ── the courier: one row at a time, outbox -> inbox stream ────────────── */

static void pmt_stamp_line(char *line, size_t cap, const char *raw, size_t n)
{
    static const char lower[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static const char upper[] =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    static const char signer[] =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    char tail[256];
    const char *post = g_w.board_shape == 1   ? "abc"
                       : g_w.board_shape == 2 ? upper
                                              : lower;
    int w = snprintf(tail, sizeof(tail), ",\"board_post\":\"%s\"", post);
    if (g_w.board_shape != 3)
        w += snprintf(tail + w, sizeof(tail) - (size_t)w,
                      ",\"board_signer\":\"%s\"", signer);
    w += snprintf(tail + w, sizeof(tail) - (size_t)w, "}\n");
    /* raw ends with "}\n": drop both, add the board evidence. */
    if (n < 2 || n + (size_t)w + 1 >= cap)
        abort();
    memcpy(line, raw, n - 2);
    memcpy(line + n - 2, tail, (size_t)w + 1);
}

/* A courier that names the wrong sender on the echo row. */
static void pmt_alias(char *raw)
{
    char *at = g_w.alias_from ? strstr(raw, "\"from\":\"node-b\"") : NULL;
    if (at)
        memcpy(at + 8, g_w.alias_from, strlen("node-b"));
}

/* Copy complete outbox lines addressed to `to` into `dest`'s inbox stream. */
static void pmt_carry(int from_side, int to_side, const char *to,
                      const char *stream, long *consumed, int drop)
{
    char path[1500], dest[1600], needle[160], dropat[32];
    char raw[8192], line[8192];
    FILE *in, *out;
    long pos;
    (void)snprintf(path, sizeof(path), "%s/outbox.jsonl", g_w.mail[from_side]);
    (void)snprintf(dest, sizeof(dest), "%s/%s", g_w.mail[to_side], stream);
    (void)snprintf(needle, sizeof(needle), "\"to\":\"%s\"", to);
    (void)snprintf(dropat, sizeof(dropat), ".%d\"", drop);
    in = fopen(path, "rb");
    if (!in)
        return;
    (void)fseek(in, *consumed, SEEK_SET);
    out = fopen(dest, "ab");
    if (!out)
        abort();
    while (fgets(raw, sizeof(raw), in)) {
        size_t n = strlen(raw);
        if (n == 0 || raw[n - 1] != '\n')
            break;
        pos = ftell(in);
        *consumed = pos;
        if (!strstr(raw, needle) || (drop >= 0 && strstr(raw, dropat)))
            continue;
        pmt_alias(raw);
        if (g_w.with_board) {
            pmt_stamp_line(line, sizeof(line), raw, n);
            (void)fputs(line, out);
            if (g_w.dup_plain)
                (void)fputs(raw, out);
        } else {
            (void)fputs(raw, out);
        }
    }
    (void)fclose(out);
    (void)fclose(in);
}

/* ── in-process leaf calls ─────────────────────────────────────────────── */

static void pmt_probe(struct pmt_call *c, const char *action, const char *to,
                      const char *from, int64_t probes, int64_t interval_ms,
                      int64_t timeout_ms, const char *since)
{
    pmt_begin(c, PMT_PATH, "zcl.agent_mail_probe.v1");
    (void)json_push_kv_str(&c->input, "action", action);
    if (to)
        (void)json_push_kv_str(&c->input, "to", to);
    (void)json_push_kv_str(&c->input, "from", from);
    if (probes >= 0)
        (void)json_push_kv_int(&c->input, "probes", probes);
    if (interval_ms >= 0)
        (void)json_push_kv_int(&c->input, "interval_ms", interval_ms);
    if (timeout_ms > 0)
        (void)json_push_kv_int(&c->input, "timeout_ms", timeout_ms);
    if (since && since[0])
        (void)json_push_kv_str(&c->input, "since", since);
    zcl_native_handle_dev_agent_mail_probe(&c->request, &c->reply);
}

/* The peer's echo role, run on side B. */
static void pmt_echo_once(struct pmt_call *c, bool with_since, int64_t timeout_ms)
{
    int saved = g_w.side;
    pmt_use(PMT_SIDE_B);
    pmt_probe(c, "echo", NULL, "node-b", 5, -1, timeout_ms,
              with_since ? g_w.since : NULL);
    pmt_use(saved);
}

static void pmt_keep_cursor(const struct pmt_call *c)
{
    const struct json_value *v = json_get(&c->reply.data, "next_since");
    if (v && v->type == JSON_STR && json_get_str(v))
        (void)snprintf(g_w.since, sizeof(g_w.since), "%s", json_get_str(v));
}

/* After each probe post: carry it, run the peer's echo, carry the echo back. */
static void pmt_pump(void *ctx)
{
    struct pmt_call c;
    int idx = g_w.delivered++;
    (void)ctx;
    g_w.true_ms += 10 + idx; /* A -> B */
    pmt_carry(PMT_SIDE_A, PMT_SIDE_B, "node-b", "inbox.node-a.jsonl",
              &g_w.carried_a, -1);
    pmt_echo_once(&c, g_w.use_since, 1);
    if (g_w.use_since)
        pmt_keep_cursor(&c);
    pmt_end(&c);
    g_w.true_ms += 20; /* B -> A */
    const char *saved_alias = g_w.alias_from;
    if (idx == g_w.invalid_index) g_w.alias_from = "wrongx";
    pmt_carry(PMT_SIDE_B, PMT_SIDE_A, "node-a",
              g_w.back_to_outbox ? "outbox.jsonl" : "inbox.node-b.jsonl",
              &g_w.carried_b, g_w.drop_index);
    g_w.alias_from = saved_alias;
}

/* One box playing both roles: the "echo" runs on the sending root, under the
 * peer's name, and answers the sender's own outbox rows. Nothing is carried. */
static void pmt_pump_loopback(void *ctx)
{
    struct pmt_call c;
    (void)ctx;
    g_w.true_ms += 10;
    pmt_probe(&c, "echo", NULL, "node-b", 5, -1, 1, g_w.since);
    pmt_keep_cursor(&c);
    pmt_end(&c);
    g_w.true_ms += 20;
}

/* The echo run that must exist before the sender starts. */
static void pmt_prime_echo(void)
{
    struct pmt_call c;
    pmt_echo_once(&c, false, 1);
    pmt_keep_cursor(&c);
    pmt_end(&c);
}

static void pmt_send(struct pmt_call *c, int64_t probes, int64_t interval_ms,
                     int64_t timeout_ms)
{
    zcl_devagent_mailprobe_test_set_pump(pmt_pump, &g_w);
    pmt_probe(c, "send", "node-b", "node-a", probes, interval_ms, timeout_ms,
              NULL);
    zcl_devagent_mailprobe_test_set_pump(NULL, NULL);
}

/* ── reading results ───────────────────────────────────────────────────── */

static const struct json_value *pmt_field(const struct pmt_call *c,
                                          const char *key)
{
    return json_get(&c->reply.data, key);
}

static int64_t pmt_int(const struct pmt_call *c, const char *key)
{
    const struct json_value *v = pmt_field(c, key);
    return v && v->type == JSON_INT ? json_get_int(v) : -999999;
}

static const char *pmt_str(const struct pmt_call *c, const char *key)
{
    const struct json_value *v = pmt_field(c, key);
    return v && v->type == JSON_STR ? json_get_str(v) : "";
}

static const struct json_value *pmt_sample(const struct pmt_call *c, size_t i)
{
    const struct json_value *a = pmt_field(c, "samples");
    return a && a->type == JSON_ARR && i < json_size(a) ? json_at(a, i) : NULL;
}

static int64_t pmt_sample_int(const struct pmt_call *c, size_t i,
                              const char *key)
{
    const struct json_value *s = pmt_sample(c, i);
    const struct json_value *v = s ? json_get(s, key) : NULL;
    return v && v->type == JSON_INT ? json_get_int(v) : -999999;
}

static const char *pmt_sample_str(const struct pmt_call *c, size_t i,
                                  const char *key)
{
    const struct json_value *s = pmt_sample(c, i);
    const struct json_value *v = s ? json_get(s, key) : NULL;
    return v && v->type == JSON_STR ? json_get_str(v) : "";
}

static const char *pmt_pct_status(const struct pmt_call *c, const char *name)
{
    const struct json_value *p = pmt_field(c, "percentiles");
    const struct json_value *e = p ? json_get(p, name) : NULL;
    const struct json_value *s = e ? json_get(e, "status") : NULL;
    return s && s->type == JSON_STR ? json_get_str(s) : "";
}

static int64_t pmt_pct_network(const struct pmt_call *c, const char *name)
{
    const struct json_value *p = pmt_field(c, "percentiles");
    const struct json_value *e = p ? json_get(p, name) : NULL;
    const struct json_value *v = e ? json_get(e, "network_ms") : NULL;
    return v && v->type == JSON_INT ? json_get_int(v) : -999999;
}

static const char *pmt_pct_overall(const struct pmt_call *c)
{
    const struct json_value *p = pmt_field(c, "percentiles");
    const struct json_value *s = p ? json_get(p, "status") : NULL;
    return s && s->type == JSON_STR ? json_get_str(s) : "";
}

static const char *pmt_pct_reason(const struct pmt_call *c)
{
    const struct json_value *p = pmt_field(c, "percentiles");
    const struct json_value *s = p ? json_get(p, "reason") : NULL;
    return s && s->type == JSON_STR ? json_get_str(s) : "";
}

/* Rows of one side's mail dir: count, and whether every row passes `check`. */
struct pmt_scan {
    int rows;
    int bad;
    const char *prefix;
    size_t body_max;
};

static void pmt_scan_rows(int side, const char *from, struct pmt_scan *scan)
{
    struct pmt_call c;
    int saved = g_w.side;
    const struct json_value *rows;
    pmt_use(side);
    pmt_begin(&c, "dev.agent.mail", "zcl.agent_mail.v1");
    (void)json_push_kv_str(&c.input, "action", "pull");
    (void)json_push_kv_str(&c.input, "from", from);
    zcl_native_handle_dev_agent_mail(&c.request, &c.reply);
    rows = json_get(&c.reply.data, "rows");
    scan->rows = 0;
    scan->bad = 0;
    for (size_t i = 0; rows && rows->type == JSON_ARR && i < json_size(rows);
         i++) {
        const struct json_value *r = json_at(rows, i);
        const char *kind = json_get_str(json_get(r, "kind"));
        const char *body = json_get_str(json_get(r, "body"));
        const char *ref = json_get_str(json_get(r, "ref"));
        scan->rows++;
        if (!kind || strcmp(kind, "note") != 0 || !body ||
            strncmp(body, scan->prefix, strlen(scan->prefix)) != 0 ||
            strlen(body) > scan->body_max || !ref ||
            strncmp(ref, "probe.", 6) != 0)
            scan->bad++;
    }
    pmt_end(&c);
    pmt_use(saved);
}

/* Post one raw mail row, as another process would. */
static void pmt_mail_post(const char *from, const char *to, const char *body)
{
    struct pmt_call c;
    pmt_begin(&c, "dev.agent.mail", "zcl.agent_mail.v1");
    (void)json_push_kv_str(&c.input, "action", "post");
    (void)json_push_kv_str(&c.input, "from", from);
    (void)json_push_kv_str(&c.input, "to", to);
    (void)json_push_kv_str(&c.input, "kind", "note");
    (void)json_push_kv_str(&c.input, "body", body);
    zcl_native_handle_dev_agent_mail(&c.request, &c.reply);
    if (!pmt_ok(&c))
        abort();
    pmt_end(&c);
}

/* A hostile or malformed row dropped into a side's inbox stream. */
static void pmt_inject(int side, const char *stream, const char *kind,
                       const char *to, const char *body, const char *ref)
{
    char path[1600], ts[40];
    time_t now = time(NULL);
    struct tm tm_utc;
    FILE *f;
    (void)snprintf(path, sizeof(path), "%s/%s", g_w.mail[side], stream);
    if (!gmtime_r(&now, &tm_utc) ||
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_utc) == 0)
        abort();
    f = fopen(path, "ab");
    if (!f)
        abort();
    (void)fprintf(f,
                  "{\"seq\":1,\"ts\":\"%s\",\"from\":\"node-x\",\"to\":\"%s\","
                  "\"kind\":\"%s\",\"body\":\"%s\",\"ref\":\"%s\"}\n",
                  ts, to, kind, body, ref);
    (void)fclose(f);
}

/* Exercise the real envelope serializer and input typing. */
static bool pmt_registry(const struct json_value *input, struct json_value *out,
                         enum zcl_command_exit *exit_code)
{
    const struct zcl_command_registry *registry = zcl_command_catalog();
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(registry, PMT_PATH, NULL);
    struct zcl_command_context context = {
        .registry = registry,
        .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
    };
    char serialized[8192];
    struct zcl_command_spec executable;
    size_t n;
    if (!spec)
        return false;
    executable = *spec;
    executable.handler = zcl_native_handle_dev_agent_mail_probe;
    n = zcl_command_registry_execute_json(
        registry, &executable, &context, input, false, PMT_PATH, "normal", 0,
        0, NULL, serialized, sizeof(serialized), exit_code);
    return n > 0 && json_read(out, serialized, n);
}

/* ── scenarios (return the sender's reply) ─────────────────────────────── */

static int pmt_test_sender_observation(void)
{
    int failures = 0;
    struct pmt_call a;
    TEST("probe: inferred sender warns only for a held receiver mismatch") {
        pmt_world("sender-source", 0, true, true, -1);
        char root[1300], dir[1400], path[1500];
        ASSERT(platform_state_root(root, sizeof(root)));
        ASSERT(snprintf(dir, sizeof(dir), "%s/receive", root) > 0);
        ASSERT(platform_private_directory_ensure(dir));
        ASSERT(snprintf(path, sizeof(path), "%s/resident.state", dir) > 0);
        FILE *f = fopen(path, "w");
        ASSERT(f && fputs("receiver=r2-devfleet\nworkspace=\n", f) >= 0 && fclose(f) == 0);
        ASSERT(snprintf(path, sizeof(path), "%s/receive.lock", dir) > 0);
        int fd = open(path, O_CREAT | O_RDWR, 0600);
        ASSERT(fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) == 0);
        const char *old = getenv("BOARD_AGENT");
        char saved[128] = "";
        if (old) (void)snprintf(saved, sizeof(saved), "%s", old);
        bool had = old != NULL;
        ASSERT(setenv("BOARD_AGENT", "r2", 1) == 0);
        pmt_begin(&a, PMT_PATH, "zcl.agent_mail_probe.v1");
        ASSERT(json_push_kv_str(&a.input, "action", "echo"));
        ASSERT(json_push_kv_int(&a.input, "timeout_ms", 1));
        zcl_native_handle_dev_agent_mail_probe(&a.request, &a.reply);
        bool warned = pmt_ok(&a) && !strcmp(pmt_str(&a, "from"), "r2") &&
            !strcmp(pmt_str(&a, "from_source"), "BOARD_AGENT") &&
            strstr(pmt_str(&a, "sender_warning"), "recorded receiver") != NULL;
        pmt_end(&a);
        (void)flock(fd, LOCK_UN);
        close(fd);
        if (had) (void)setenv("BOARD_AGENT", saved, 1); else (void)unsetenv("BOARD_AGENT");
        ASSERT(warned);
        PASS();
    }

_test_next:;
    return failures;
}

static void pmt_run_full(struct pmt_call *c, const char *tag, int64_t offset_b,
                         bool with_board, bool use_since, int drop,
                         int64_t probes, int64_t timeout_ms)
{
    pmt_world(tag, offset_b, with_board, use_since, drop);
    if (use_since)
        pmt_prime_echo();
    pmt_send(c, probes, 0, timeout_ms);
}

int test_agent_mail_latency_probe(void);
int test_agent_mail_latency_probe(void)
{
    int failures = 0;
    struct pmt_call a, b;
    struct json_value envelope = {0};
    enum zcl_command_exit exit_code;

    pmt_isolate_begin();
    failures += pmt_test_sender_observation();

    TEST("probe: registered with its typed keys and a distinct group") {
        const struct zcl_command_spec *spec = zcl_command_registry_find(
            zcl_command_catalog(), PMT_PATH, NULL);
        ASSERT(spec != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "probes"));
        ASSERT(spec->input_keys && strstr(spec->input_keys, "interval_ms"));
        ASSERT(spec->input_keys && strstr(spec->input_keys, "since"));
        ASSERT(spec->input_keys && !strstr(spec->input_keys, "kind"));
        ASSERT(spec->input_keys && !strstr(spec->input_keys, "body"));
        PASS();
    }

    TEST("probe: the one-way estimate is the same under a 5 s clock offset") {
        int64_t n_zero[20];
        pmt_run_full(&a, "zero", 0, true, true, -1, 20, 2000);
        ASSERT(pmt_ok(&a));
        ASSERT_EQ(pmt_int(&a, "sent"), (int64_t)20);
        ASSERT_EQ(pmt_int(&a, "valid"), (int64_t)20);
        ASSERT_EQ(pmt_int(&a, "missing"), (int64_t)0);
        for (int i = 0; i < 20; i++) {
            n_zero[i] = pmt_sample_int(&a, (size_t)i, "network_ms");
            ASSERT(n_zero[i] >= 30 + i && n_zero[i] <= 36 + i);
        }
        pmt_end(&a);
        pmt_run_full(&b, "skew", 5000, true, true, -1, 20, 2000);
        ASSERT(pmt_ok(&b));
        ASSERT_EQ(pmt_int(&b, "valid"), (int64_t)20);
        for (int i = 0; i < 20; i++) {
            int64_t t1 = pmt_sample_int(&b, (size_t)i, "t1");
            int64_t t2 = pmt_sample_int(&b, (size_t)i, "t2");
            int64_t t3 = pmt_sample_int(&b, (size_t)i, "t3");
            int64_t t4 = pmt_sample_int(&b, (size_t)i, "t4");
            int64_t net = pmt_sample_int(&b, (size_t)i, "network_ms");
            /* Offset cancels: identical to the run with no offset. */
            ASSERT_EQ(net, n_zero[i]);
            ASSERT_EQ(net, (t4 - t1) - (t3 - t2));
            /* The naive one-way reading t2 - t1 is wrong by the offset. */
            ASSERT(t2 - t1 > 4000);
            ASSERT_EQ(pmt_sample_int(&b, (size_t)i, "round_trip_ms"), t4 - t1);
        }
        pmt_end(&b);
        PASS();
    }

    TEST("probe: percentiles are nearest-rank over the sent probes") {
        pmt_run_full(&a, "pct", 5000, true, true, -1, 20, 2000);
        ASSERT(pmt_ok(&a));
        ASSERT_STR_EQ(pmt_pct_overall(&a), "ok");
        ASSERT_STR_EQ(pmt_pct_status(&a, "p50"), "ok");
        /* n[i] grows with i, so the sorted order is the index order. */
        ASSERT_EQ(pmt_pct_network(&a, "p50"),
                  pmt_sample_int(&a, 9, "network_ms"));
        ASSERT_EQ(pmt_pct_network(&a, "p90"),
                  pmt_sample_int(&a, 17, "network_ms"));
        ASSERT_EQ(pmt_pct_network(&a, "p95"),
                  pmt_sample_int(&a, 18, "network_ms"));
        const struct json_value *p95 = json_get(pmt_field(&a, "percentiles"), "p95");
        const struct json_value *estimate = json_get(p95, "one_way_ms");
        ASSERT(estimate && estimate->type == JSON_REAL);
        ASSERT(json_get_real(estimate) == (double)pmt_pct_network(&a, "p95") / 2.0);
        ASSERT(pmt_sample_int(&a, 18, "round_trip_ms") >
               pmt_sample_int(&a, 18, "network_ms"));
        ASSERT_EQ(pmt_pct_network(&a, "p99"),
                  pmt_sample_int(&a, 19, "network_ms"));
        ASSERT_EQ(pmt_pct_network(&a, "max"),
                  pmt_sample_int(&a, 19, "network_ms"));
        pmt_end(&a);
        PASS();
    }

    TEST("probe: a missing echo is counted and reported, never dropped") {
        pmt_run_full(&a, "miss", 5000, true, true, 3, 20, 300);
        ASSERT(pmt_ok(&a));
        ASSERT_EQ(pmt_int(&a, "sent"), (int64_t)20);
        ASSERT_EQ(pmt_int(&a, "echoed"), (int64_t)19);
        ASSERT_EQ(pmt_int(&a, "missing"), (int64_t)1);
        ASSERT_EQ(pmt_int(&a, "valid"), (int64_t)19);
        ASSERT_STR_EQ(pmt_sample_str(&a, 3, "state"), "missing");
        ASSERT_STR_EQ(pmt_sample_str(&a, 4, "state"), "valid");
        /* One of 20 missing is 5%: p50 and p90 hold, p99 and max do not. */
        ASSERT_STR_EQ(pmt_pct_status(&a, "p50"), "ok");
        ASSERT_STR_EQ(pmt_pct_status(&a, "p90"), "ok");
        ASSERT_STR_EQ(pmt_pct_status(&a, "p95"), "ok");
        ASSERT_STR_EQ(pmt_pct_status(&a, "p99"), "missing");
        ASSERT_STR_EQ(pmt_pct_status(&a, "max"), "missing");
        pmt_end(&a);
        PASS();
    }

    TEST("probe: p95 counts both invalid and missing samples") {
        pmt_world("p95-invalid", 5000, true, true, 3);
        pmt_prime_echo();
        g_w.invalid_index = 7;
        pmt_send(&a, 20, 0, 300);
        ASSERT(pmt_ok(&a));
        ASSERT_EQ(pmt_int(&a, "sent"), (int64_t)20);
        ASSERT_EQ(pmt_int(&a, "missing"), (int64_t)1);
        ASSERT_EQ(pmt_int(&a, "invalid"), (int64_t)1);
        ASSERT_EQ(pmt_int(&a, "valid"), (int64_t)18);
        ASSERT_STR_EQ(pmt_pct_status(&a, "p90"), "ok");
        ASSERT_STR_EQ(pmt_pct_status(&a, "p95"), "missing");
        ASSERT_STR_EQ(pmt_pct_status(&a, "p95_round_trip"), "missing");
        pmt_end(&a);
        PASS();
    }

    TEST("probe: p95 full round trip includes peer processing") {
        pmt_world("p95-rtt", 0, true, true, -1);
        pmt_prime_echo();
        g_w.peer_clock_step = 6000;
        pmt_send(&a, 20, 0, 2000);
        ASSERT(pmt_ok(&a));
        ASSERT_EQ(pmt_int(&a, "valid"), (int64_t)20);
        ASSERT_STR_EQ(pmt_pct_status(&a, "p95"), "ok");
        ASSERT_STR_EQ(pmt_pct_status(&a, "p95_round_trip"), "ok");
        const struct json_value *p = json_get(pmt_field(&a, "percentiles"),
                                              "p95_round_trip");
        const struct json_value *v = json_get(p, "round_trip_ms");
        ASSERT(v && v->type == JSON_INT);
        ASSERT(json_get_int(v) > 5000);
        ASSERT(pmt_pct_network(&a, "p95") < 10000);
        pmt_end(&a);
        PASS();
    }

    TEST("probe: below the minimum sample count no percentile is reported") {
        pmt_run_full(&a, "few", 0, true, true, -1, 5, 2000);
        ASSERT(pmt_ok(&a));
        ASSERT_EQ(pmt_int(&a, "sent"), (int64_t)5);
        ASSERT_EQ(pmt_int(&a, "valid"), (int64_t)5);
        ASSERT_STR_EQ(pmt_pct_overall(&a), "refused");
        ASSERT_STR_EQ(pmt_pct_status(&a, "p50"), "");
        ASSERT_STR_EQ(pmt_pct_status(&a, "p95"), "");
        ASSERT(json_size(pmt_field(&a, "samples")) == 5);
        ASSERT(strstr(pmt_pct_reason(&a), "fewer than 10 probes") != NULL);
        pmt_end(&a);
        /* Exactly ten sent and valid is enough. */
        pmt_run_full(&a, "ten", 0, true, true, -1, 10, 2000);
        ASSERT(pmt_ok(&a));
        ASSERT_EQ(pmt_int(&a, "valid"), (int64_t)10);
        ASSERT_STR_EQ(pmt_pct_overall(&a), "ok");
        pmt_end(&a);
        PASS();
    }

    TEST("probe: an echo that cannot vouch for t2 is invalid, not a sample") {
        pmt_run_full(&a, "scan", 0, true, false, -1, 12, 2000);
        ASSERT(pmt_ok(&a));
        ASSERT_EQ(pmt_int(&a, "echoed"), (int64_t)12);
        ASSERT_EQ(pmt_int(&a, "valid"), (int64_t)0);
        ASSERT_EQ(pmt_int(&a, "invalid"), (int64_t)12);
        ASSERT_STR_EQ(pmt_sample_str(&a, 0, "state"), "invalid");
        ASSERT_STR_EQ(pmt_sample_str(&a, 0, "reason"), "t2_unmeasured_scan");
        ASSERT_STR_EQ(pmt_pct_overall(&a), "refused");
        ASSERT(strstr(pmt_pct_reason(&a), "fewer than 10 samples are valid"));
        pmt_end(&a);
        PASS();
    }

    TEST("probe: transport is read from the rows' board_post evidence") {
        pmt_run_full(&a, "board", 0, true, true, -1, 10, 2000);
        ASSERT(pmt_ok(&a));
        ASSERT_STR_EQ(pmt_str(&a, "transport"), "board");
        ASSERT_STR_EQ(pmt_sample_str(&a, 0, "echo_leg"), "board");
        ASSERT_STR_EQ(pmt_sample_str(&a, 0, "probe_leg"), "board");
        pmt_end(&a);
        pmt_run_full(&a, "other", 0, false, true, -1, 10, 2000);
        ASSERT(pmt_ok(&a));
        ASSERT_STR_EQ(pmt_str(&a, "transport"), "other");
        ASSERT_STR_EQ(pmt_sample_str(&a, 0, "echo_leg"), "other");
        ASSERT_STR_EQ(pmt_sample_str(&a, 0, "probe_leg"), "other");
        pmt_end(&a);
        /* Every echo dropped: nothing to claim a carrier from. */
        pmt_world("none", 0, true, true, 0);
        pmt_prime_echo();
        pmt_send(&a, 1, 0, 100);
        ASSERT(pmt_ok(&a));
        ASSERT_STR_EQ(pmt_str(&a, "transport"), "none");
        ASSERT_EQ(pmt_int(&a, "missing"), (int64_t)1);
        pmt_end(&a);
        PASS();
    }

    TEST("probe: a count, interval or rate past the bound is refused by name") {
        pmt_world("bounds", 0, true, true, -1);
        pmt_probe(&a, "send", "node-b", "node-a", 65, 0, 0, NULL);
        ASSERT(!pmt_ok(&a));
        ASSERT_STR_EQ(a.reply.error.code, "PROBE_COUNT_OUT_OF_RANGE");
        pmt_end(&a);
        pmt_probe(&a, "send", "node-b", "node-a", 0, 0, 0, NULL);
        ASSERT_STR_EQ(a.reply.error.code, "PROBE_COUNT_OUT_OF_RANGE");
        pmt_end(&a);
        pmt_probe(&a, "send", "node-b", "node-a", 20, 600001, 0, NULL);
        ASSERT_STR_EQ(a.reply.error.code, "PROBE_INTERVAL_OUT_OF_RANGE");
        pmt_end(&a);
        /* 64 at once, or 41 at 15 s, would put over 40 posts in 10 minutes. */
        pmt_probe(&a, "send", "node-b", "node-a", 64, 0, 0, NULL);
        ASSERT_STR_EQ(a.reply.error.code, "PROBE_RATE_OVER_BUDGET");
        pmt_end(&a);
        pmt_probe(&a, "send", "node-b", "node-a", 41, 15000, 0, NULL);
        ASSERT_STR_EQ(a.reply.error.code, "PROBE_RATE_OVER_BUDGET");
        pmt_end(&a);
        pmt_probe(&a, "send", "node-b", "node-a", 64, 100000, 0, NULL);
        ASSERT_STR_EQ(a.reply.error.code, "PROBE_RUN_TOO_LONG");
        pmt_end(&a);
        pmt_probe(&a, "send", "node-b", "node-a", 20, 0, 300001, NULL);
        ASSERT_STR_EQ(a.reply.error.code, "PROBE_RUN_TOO_LONG");
        pmt_end(&a);
        pmt_probe(&a, "send", "*", "node-a", 20, 0, 0, NULL);
        ASSERT_STR_EQ(a.reply.error.code, "PROBE_TO_NOT_A_BOX");
        pmt_end(&a);
        pmt_probe(&a, "send", "node-a", "node-a", 20, 0, 0, NULL);
        ASSERT_STR_EQ(a.reply.error.code, "PROBE_TO_IS_SELF");
        pmt_end(&a);
        pmt_probe(&a, "scatter", "node-b", "node-a", 20, 0, 0, NULL);
        ASSERT_STR_EQ(a.reply.error.code, "PROBE_ACTION_UNKNOWN");
        pmt_end(&a);
        /* Nothing above posted a row. */
        {
            struct pmt_scan scan = {.prefix = "z23-probe v1 ", .body_max = 96};
            pmt_scan_rows(PMT_SIDE_A, "node-a", &scan);
            ASSERT_EQ(scan.rows, 0);
        }
        PASS();
    }

    TEST("probe: recent probe rows count against the post budget") {
        pmt_world("recent", 0, true, true, -1);
        for (int i = 0; i < 30; i++)
            pmt_mail_post("node-a", "node-b", "z23-probe v1 t1=1 i=0");
        pmt_probe(&a, "send", "node-b", "node-a", 20, 0, 0, NULL);
        ASSERT(!pmt_ok(&a));
        ASSERT_STR_EQ(a.reply.error.code, "PROBE_QUOTA_RECENT");
        pmt_end(&a);
        {
            struct pmt_scan scan = {.prefix = "z23-probe v1 ", .body_max = 96};
            pmt_scan_rows(PMT_SIDE_A, "node-a", &scan);
            ASSERT_EQ(scan.rows, 30);
        }
        PASS();
    }

    TEST("probe: kind, body and ref cannot be chosen; every row is a small note") {
        struct pmt_scan scan;
        pmt_world("fixed", 0, true, true, -1);
        pmt_begin(&a, PMT_PATH, "zcl.agent_mail_probe.v1");
        (void)json_push_kv_str(&a.input, "action", "send");
        (void)json_push_kv_str(&a.input, "to", "node-b");
        (void)json_push_kv_str(&a.input, "from", "node-a");
        (void)json_push_kv_str(&a.input, "kind", "directive");
        zcl_native_handle_dev_agent_mail_probe(&a.request, &a.reply);
        ASSERT(!pmt_ok(&a));
        ASSERT_STR_EQ(a.reply.error.code, "PROBE_FIELD_FIXED");
        pmt_end(&a);
        pmt_begin(&a, PMT_PATH, "zcl.agent_mail_probe.v1");
        (void)json_push_kv_str(&a.input, "action", "send");
        (void)json_push_kv_str(&a.input, "to", "node-b");
        (void)json_push_kv_str(&a.input, "from", "node-a");
        (void)json_push_kv_str(&a.input, "body", "rm everything");
        zcl_native_handle_dev_agent_mail_probe(&a.request, &a.reply);
        ASSERT_STR_EQ(a.reply.error.code, "PROBE_FIELD_FIXED");
        pmt_end(&a);
        /* The registry refuses the undeclared key before the leaf runs. */
        {
            struct json_value in;
            json_init(&in);
            json_set_object(&in);
            (void)json_push_kv_str(&in, "action", "send");
            (void)json_push_kv_str(&in, "to", "node-b");
            (void)json_push_kv_str(&in, "kind", "directive");
            ASSERT(pmt_registry(&in, &envelope, &exit_code));
            ASSERT(exit_code != ZCL_COMMAND_EXIT_OK);
            json_free(&envelope);
            json_free(&in);
        }
        /* A full run leaves only notes with the fixed prefix and cap. */
        pmt_prime_echo();
        pmt_send(&a, 10, 0, 2000);
        ASSERT(pmt_ok(&a));
        pmt_end(&a);
        scan = (struct pmt_scan){.prefix = "z23-probe v1 ", .body_max = 96};
        pmt_scan_rows(PMT_SIDE_A, "node-a", &scan);
        ASSERT_EQ(scan.rows, 10);
        ASSERT_EQ(scan.bad, 0);
        scan = (struct pmt_scan){.prefix = "z23-probe-echo v1 ", .body_max = 160};
        pmt_scan_rows(PMT_SIDE_B, "node-b", &scan);
        ASSERT_EQ(scan.rows, 10);
        ASSERT_EQ(scan.bad, 0);
        PASS();
    }

    TEST("probe: the echo ignores directives, oversize probes and answered ones") {
        struct pmt_scan scan = {.prefix = "z23-probe-echo v1 ", .body_max = 160};
        char big[220];
        pmt_world("echo", 0, true, true, -1);
        memset(big, 'x', sizeof(big) - 1);
        big[sizeof(big) - 1] = '\0';
        memcpy(big, "z23-probe v1 t1=1 ", 18);
        pmt_inject(PMT_SIDE_B, "inbox.evil.jsonl", "directive", "node-b",
                   "z23-probe v1 t1=1 i=0", "probe.aaaaaaaaaaaa.0");
        pmt_inject(PMT_SIDE_B, "inbox.evil.jsonl", "note", "node-b", big,
                   "probe.aaaaaaaaaaaa.1");
        pmt_inject(PMT_SIDE_B, "inbox.evil.jsonl", "note", "node-b",
                   "not a probe", "probe.aaaaaaaaaaaa.2");
        pmt_inject(PMT_SIDE_B, "inbox.evil.jsonl", "note", "node-b",
                   "z23-probe v1 t1=1 i=3", "probe.aaaaaaaaaaaa.3");
        pmt_echo_once(&a, false, 1);
        ASSERT(pmt_ok(&a));
        ASSERT_EQ(pmt_int(&a, "answered"), (int64_t)1);
        ASSERT_EQ(pmt_int(&a, "skipped_oversize"), (int64_t)1);
        ASSERT_EQ(pmt_int(&a, "skipped_other"), (int64_t)1);
        pmt_end(&a);
        /* A second run finds its own echo and answers nothing. */
        pmt_echo_once(&a, false, 1);
        ASSERT(pmt_ok(&a));
        ASSERT_EQ(pmt_int(&a, "answered"), (int64_t)0);
        pmt_end(&a);
        pmt_scan_rows(PMT_SIDE_B, "node-b", &scan);
        ASSERT_EQ(scan.rows, 1);
        ASSERT_EQ(scan.bad, 0);
        PASS();
    }

    TEST("probe: a same-box loopback delivers nothing and measures nothing") {
        pmt_world("loop", 0, false, true, -1);
        pmt_probe(&b, "echo", NULL, "node-b", 5, -1, 1, NULL);
        pmt_keep_cursor(&b);
        pmt_end(&b);
        zcl_devagent_mailprobe_test_set_pump(pmt_pump_loopback, &g_w);
        pmt_probe(&a, "send", "node-b", "node-a", 10, 0, 300, NULL);
        zcl_devagent_mailprobe_test_set_pump(NULL, NULL);
        ASSERT(pmt_ok(&a));
        ASSERT_EQ(pmt_int(&a, "sent"), (int64_t)10);
        ASSERT_EQ(pmt_int(&a, "valid"), (int64_t)0);
        ASSERT_STR_EQ(pmt_pct_overall(&a), "refused");
        ASSERT_STR_EQ(pmt_pct_status(&a, "p50"), "");
        ASSERT_STR_EQ(pmt_pct_status(&a, "p99"), "");
        pmt_end(&a);
        PASS();
    }

    TEST("probe: an echo read from the sender's own outbox is invalid") {
        pmt_world("outbox", 0, true, true, -1);
        g_w.back_to_outbox = true;
        pmt_prime_echo();
        pmt_send(&a, 10, 0, 300);
        ASSERT(pmt_ok(&a));
        ASSERT_EQ(pmt_int(&a, "echoed"), (int64_t)10);
        ASSERT_EQ(pmt_int(&a, "valid"), (int64_t)0);
        ASSERT_EQ(pmt_int(&a, "invalid"), (int64_t)10);
        ASSERT_EQ(pmt_int(&a, "echo_wrong_stream"), (int64_t)10);
        ASSERT_STR_EQ(pmt_sample_str(&a, 0, "state"), "invalid");
        ASSERT_STR_EQ(pmt_sample_str(&a, 0, "reason"),
                      "echo_not_from_peer_inbox");
        ASSERT_STR_EQ(pmt_pct_overall(&a), "refused");
        ASSERT_STR_EQ(pmt_pct_status(&a, "p50"), "");
        pmt_end(&a);
        PASS();
    }

    TEST("probe: an echo from a box other than the peer is invalid") {
        pmt_world("alias", 0, true, true, -1);
        g_w.alias_from = "node-c";
        pmt_prime_echo();
        pmt_send(&a, 10, 0, 300);
        ASSERT(pmt_ok(&a));
        ASSERT_EQ(pmt_int(&a, "echoed"), (int64_t)10);
        ASSERT_EQ(pmt_int(&a, "valid"), (int64_t)0);
        ASSERT_EQ(pmt_int(&a, "echo_from_not_peer"), (int64_t)10);
        ASSERT_STR_EQ(pmt_sample_str(&a, 0, "state"), "invalid");
        ASSERT_STR_EQ(pmt_sample_str(&a, 0, "reason"), "echo_from_not_peer");
        ASSERT_STR_EQ(pmt_pct_overall(&a), "refused");
        pmt_end(&a);
        PASS();
    }

    TEST("probe: malformed board fields do not earn the board label") {
        for (int shape = 1; shape <= 3; shape++) {
            pmt_world("shape", 0, true, true, -1);
            g_w.board_shape = shape;
            pmt_prime_echo();
            pmt_send(&a, 10, 0, 2000);
            ASSERT(pmt_ok(&a));
            ASSERT_EQ(pmt_int(&a, "valid"), (int64_t)10);
            ASSERT_STR_EQ(pmt_str(&a, "transport"), "unattributed");
            ASSERT_STR_EQ(pmt_sample_str(&a, 0, "echo_leg"), "unattributed");
            ASSERT_STR_EQ(pmt_sample_str(&a, 0, "probe_leg"), "unattributed");
            ASSERT(strstr(pmt_str(&a, "transport_note"),
                          "not verified against the node") != NULL);
            pmt_end(&a);
        }
        PASS();
    }

    TEST("probe: the same echo by two carriers marks the sample mixed") {
        pmt_world("mixed", 0, true, true, -1);
        g_w.dup_plain = true;
        pmt_prime_echo();
        pmt_send(&a, 10, 0, 2000);
        ASSERT(pmt_ok(&a));
        ASSERT_EQ(pmt_int(&a, "valid"), (int64_t)10);
        ASSERT_STR_EQ(pmt_sample_str(&a, 0, "echo_leg"), "mixed");
        ASSERT_STR_EQ(pmt_str(&a, "transport"), "mixed");
        pmt_end(&a);
        PASS();
    }

    TEST("probe: typed integers reach the leaf, which refuses by name") {
        struct json_value in;
        pmt_world("typed", 0, true, true, -1);
        json_init(&in);
        json_set_object(&in);
        (void)json_push_kv_str(&in, "action", "send");
        (void)json_push_kv_str(&in, "to", "node-b");
        (void)json_push_kv_str(&in, "from", "node-a");
        (void)json_push_kv_int(&in, "probes", 65);
        ASSERT(pmt_registry(&in, &envelope, &exit_code));
        ASSERT_STR_EQ(json_get_str(json_get(json_get(&envelope, "error"),
                                            "code")),
                      "PROBE_COUNT_OUT_OF_RANGE");
        json_free(&envelope);
        json_free(&in);
        PASS();
    }

_test_next:;
    json_free(&envelope);
    pmt_isolate_end();
    if (failures == 0)
        printf("test_agent_mail_latency_probe: all passed\n");
    else
        printf("test_agent_mail_latency_probe: %d FAILED\n", failures);
    return failures;
}
#endif
