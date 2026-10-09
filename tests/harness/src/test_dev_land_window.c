/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Acceptance tests for dev.land.window (tools/command/native_dev_land_window.c)
 * against an isolated state root. Inbox rows are written straight into the
 * fixture mail dir; announce posts through the real dev.agent.mail post. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_dev_land_window.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/private_directory.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#endif

#define DLW_PATH "dev.land.window"
#define DLW_T1000 1791540000LL /* 2026-10-09T10:00:00Z */
#define DLW_T2355 1791590100LL /* 2026-10-09T23:55:00Z */
#define DLW_REF "\"ref\":\"astra-board-runs\""
#define DLW_C "aaaaaaaaaa"
#define DLW_B "bbbbbbbbbb"

struct dlw_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void dlw_begin(struct dlw_call *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), DLW_PATH, NULL);
    zcl_command_reply_init(&c->reply, "zcl.land_window.v1");
}

static void dlw_end(struct dlw_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static void dlw_open(struct dlw_call *c, const char *host, long long now)
{
    dlw_begin(c);
    (void)json_push_kv_str(&c->input, "action", "open");
    (void)json_push_kv_str(&c->input, "host", host);
    (void)json_push_kv_int(&c->input, "now", now);
    zcl_native_handle_dev_land_window(&c->request, &c->reply);
}

static void dlw_announce_pair(struct dlw_call *c, const char *cand,
                               const char *base, const char *expected)
{
    dlw_begin(c);
    (void)json_push_kv_str(&c->input, "action", "announce");
    (void)json_push_kv_str(&c->input, "host", "hosta");
    (void)json_push_kv_int(&c->input, "seq", 7);
    (void)json_push_kv_str(&c->input, "candidate", cand);
    (void)json_push_kv_str(&c->input, "base", base);
    (void)json_push_kv_str(&c->input, "expected_done", expected);
    zcl_native_handle_dev_land_window(&c->request, &c->reply);
}

static void dlw_announce(struct dlw_call *c, const char *cand,
                         const char *expected)
{
    dlw_announce_pair(c, cand, "0123456789abcdef0123456789abcdef01234567",
                      expected);
}


static bool dlw_ok(const struct dlw_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static int64_t dlw_int(const struct dlw_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_INT ? json_get_int(v) : -1;
}

static size_t dlw_windows(const struct dlw_call *c)
{
    const struct json_value *v = json_get(&c->reply.data, "open_windows");
    return v && v->type == JSON_ARR ? json_size(v) : 99;
}

static bool dlw_bool(const struct dlw_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

static char g_dlw_mail[4096];

/* Replace the fixture inbox with the given raw lines. */
static void dlw_rows(const char *const *lines, size_t n)
{
    char path[4200];
    FILE *f;
    (void)snprintf(path, sizeof(path), "%s/inbox.peer.jsonl", g_dlw_mail);
    f = fopen(path, "w");
    if (!f)
        abort();
    for (size_t i = 0; i < n; i++)
        (void)fprintf(f, "%s\n", lines[i]);
    (void)fclose(f);
}

#define WROW(seq, ts, from, hh, host, done)                                   \
    "{\"seq\":" #seq ",\"ts\":\"" ts "\",\"from\":\"" from                    \
    "\",\"to\":\"*\",\"kind\":\"note\",\"body\":\"LAND-WINDOW " host          \
    ", candidate " DLW_C " on base " DLW_B ", proving now, expected done "    \
    done ".\"," DLW_REF "}"
#define CROW(seq, ts, from, text)                                             \
    "{\"seq\":" #seq ",\"ts\":\"" ts "\",\"from\":\"" from                    \
    "\",\"to\":\"*\",\"kind\":\"note\",\"body\":\"" text "\"," DLW_REF "}"

static char g_dlw_saved[4096];
static bool g_dlw_had;

static void dlw_isolate(void)
{
    char base[512], state[1024];
    const char *old = getenv("XDG_STATE_HOME");
    g_dlw_had = old != NULL;
    if (old)
        (void)snprintf(g_dlw_saved, sizeof(g_dlw_saved), "%s", old);
    test_make_tmpdir(base, sizeof(base), "dev_land_window", "rig");
    (void)snprintf(state, sizeof(state), "%s/state", base);
    if (!platform_private_directory_ensure(state) ||
        setenv("XDG_STATE_HOME", state, 1) != 0)
        abort();
    if (!platform_state_root(state, sizeof(state)))
        abort();
    (void)snprintf(g_dlw_mail, sizeof(g_dlw_mail), "%s/mail", state);
    if (!platform_private_directory_ensure(g_dlw_mail))
        abort();
}

static void dlw_restore(void)
{
    if (g_dlw_had)
        (void)setenv("XDG_STATE_HOME", g_dlw_saved, 1);
    else
        (void)unsetenv("XDG_STATE_HOME");
}

static size_t dlw_outbox_lines(void)
{
    char path[4200], buf[8192];
    size_t n = 0;
    FILE *f;
    (void)snprintf(path, sizeof(path), "%s/outbox.jsonl", g_dlw_mail);
    f = fopen(path, "r");
    if (!f)
        return 0;
    while (fgets(buf, sizeof(buf), f))
        n++;
    (void)fclose(f);
    return n;
}

/* ── lander side: estimate, foreign windows, own window lifecycle ─────── */

#if !defined(_WIN32)
static bool dlw_mkdirs(const char *path)
{
    char buf[4096];
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof(buf))
        return false;
    memcpy(buf, path, n + 1);
    for (size_t i = 1; i <= n; i++) {
        if (buf[i] != '/' && buf[i] != '\0')
            continue;
        char keep = buf[i];
        buf[i] = '\0';
        if (mkdir(buf, 0700) != 0) {
            struct stat st;
            if (stat(buf, &st) != 0 || !S_ISDIR(st.st_mode))
                return false;
        }
        buf[i] = keep;
    }
    return true;
}

static bool dlw_put(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return false;
    bool ok = fputs(text, f) >= 0;
    return fclose(f) == 0 && ok;
}

/* One proof attempt dir: request with its start epoch, phases.txt last
 * written at start + wall, a step=test row only for a real proof, and the
 * test-selection note when `shape` is given. */
static bool dlw_attempt(const char *root, unsigned n, int64_t start,
                        int64_t wall, const char *shape, bool real)
{
    char local[41], dir[4096], path[4400], text[512], pair[96];
    struct timespec ts[2];
    (void)snprintf(local, sizeof(local), "%040x", n);
    (void)snprintf(pair, sizeof(pair), "%s-%s", local,
                   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    (void)snprintf(dir, sizeof(dir),
                   "%s/.cache/zcl-dev-proof/attempts/%s.Ab%04u", root, pair,
                   n);
    (void)snprintf(path, sizeof(path), "%s/logs", dir);
    if (!dlw_mkdirs(path))
        return false;
    (void)snprintf(path, sizeof(path), "%s/request", dir);
    (void)snprintf(text, sizeof(text),
                   "zcl.dev_proof_request.v1\n%s\n%s\n%lld\n0\n", local,
                   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                   (long long)start);
    if (!dlw_put(path, text))
        return false;
    if (shape) {
        (void)snprintf(path, sizeof(path), "%s/logs/%s.test-selection.log",
                       dir, pair);
        (void)snprintf(text, sizeof(text),
                       "test_selection=%s reason=impact-plan "
                       "groups_selected=3\nhost_gated=-\n", shape);
        if (!dlw_put(path, text))
            return false;
    }
    (void)snprintf(path, sizeof(path), "%s/phases.txt", dir);
    (void)snprintf(text, sizeof(text),
                   "queue_wait_ms=10\n%s",
                   real ? "step=test budget_ms=3600000 elapsed_ms=1000 "
                          "last_progress_age_ms=0 cause=none exit=0\n"
                        : "");
    if (!dlw_put(path, text))
        return false;
    ts[0].tv_sec = (time_t)(start + wall);
    ts[0].tv_nsec = 0;
    ts[1] = ts[0];
    return utimensat(AT_FDCWD, path, ts, 0) == 0;
}

static void dlw_proof_root(char *out, size_t cap, const char *tag)
{
    test_make_tmpdir(out, cap, "dev_land_window", tag);
}

/* Universal 20..34 min (8), exact 7..10 min (4), one long refusal without a
 * step=test row, and the attempts dir's `superseded` entry. */
static bool dlw_history(const char *root)
{
    static const int uni[8] = {20, 22, 24, 26, 28, 30, 32, 34};
    static const int exact[4] = {7, 8, 9, 10};
    char path[4400];
    unsigned n = 1;
    for (int i = 0; i < 8; i++, n++)
        if (!dlw_attempt(root, n, DLW_T1000 - (int64_t)n * 3600,
                         (int64_t)uni[i] * 60, "universal", true))
            return false;
    for (int i = 0; i < 4; i++, n++)
        if (!dlw_attempt(root, n, DLW_T1000 - (int64_t)n * 3600,
                         (int64_t)exact[i] * 60, "exact", true))
            return false;
    if (!dlw_attempt(root, 99, DLW_T1000 - 1800, 300 * 60, "exact", false))
        return false;
    (void)snprintf(path, sizeof(path),
                   "%s/.cache/zcl-dev-proof/attempts/superseded", root);
    return dlw_mkdirs(path);
}

static int dlw_estimate_cases(void)
{
    int failures = 0;
    struct zcl_land_window_estimate e;
    char root[512];

    TEST("land.window: estimate is p75 of real proof walls, by shape") {
        dlw_proof_root(root, sizeof(root), "estimate");
        ASSERT(dlw_history(root));
        zcl_land_window_estimate(root, NULL, &e);
        ASSERT(e.measured);
        ASSERT_EQ(e.samples, 12);
        ASSERT_EQ(e.p75_s, (int64_t)28 * 60);
        ASSERT_EQ(e.seconds, (int64_t)28 * 60);
        ASSERT_EQ(e.max_s, (int64_t)34 * 60);
        ASSERT_STR_EQ(e.shape, "any");
        zcl_land_window_estimate(root, "exact", &e);
        ASSERT_EQ(e.samples, 4);
        ASSERT_EQ(e.seconds, (int64_t)9 * 60);
        ASSERT_STR_EQ(e.shape, "exact");
        zcl_land_window_estimate(root, "universal", &e);
        ASSERT_EQ(e.samples, 8);
        ASSERT_EQ(e.seconds, (int64_t)30 * 60);
        ASSERT_EQ(e.p90_s, (int64_t)34 * 60);
        PASS();
    }

    TEST("land.window: estimate keeps the newest 20 and falls back without history") {
        dlw_proof_root(root, sizeof(root), "estimate_cap");
        for (unsigned n = 1; n <= 25; n++)
            ASSERT(dlw_attempt(root, n, DLW_T1000 - (int64_t)n * 3600,
                               n > 20 ? 120 * 60 : 10 * 60, "exact", true));
        zcl_land_window_estimate(root, NULL, &e);
        ASSERT_EQ(e.samples, 20);
        ASSERT_EQ(e.max_s, (int64_t)600);
        ASSERT_EQ(e.seconds, (int64_t)600);
        dlw_proof_root(root, sizeof(root), "estimate_empty");
        zcl_land_window_estimate(root, NULL, &e);
        ASSERT(!e.measured);
        ASSERT_EQ(e.seconds, (int64_t)ZCL_LAND_WINDOW_FALLBACK_S);
        PASS();
    }

    TEST("land.window: the newest attempt of a pair names its shape") {
        char shape[12] = "";
        char local[41];
        dlw_proof_root(root, sizeof(root), "shape");
        ASSERT(dlw_attempt(root, 5, DLW_T1000 - 7200, 600, "exact", true));
        ASSERT(dlw_attempt(root, 6, DLW_T1000 - 600, 60, "universal", false));
        (void)snprintf(local, sizeof(local), "%040x", 6u);
        ASSERT(zcl_land_window_attempt_shape(
            root, local, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", shape));
        ASSERT_STR_EQ(shape, "universal");
        (void)snprintf(local, sizeof(local), "%040x", 7u);
        ASSERT(!zcl_land_window_attempt_shape(
            root, local, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", shape));
        PASS();
    }

_test_next:;
    return failures;
}
#endif

static int dlw_foreign_cases(void)
{
    int failures = 0;
    struct zcl_land_window_hit hit;

    TEST("land.window: a foreign window on the base counts until expected+grace") {
        const char *rows[] = {
            WROW(1, "2026-10-09T09:50:00Z", "agent-b", 0, "hostb", "10:30Z"),
        };
        dlw_rows(rows, 1);
        ASSERT(zcl_land_window_foreign("hosta", DLW_B, DLW_T1000, 600, &hit));
        ASSERT(hit.open);
        ASSERT_STR_EQ(hit.host, "hostb");
        ASSERT_STR_EQ(hit.candidate, DLW_C);
        ASSERT_EQ(hit.seconds_left, (int64_t)1800);
        /* five minutes past expected-done: still inside the grace */
        ASSERT(zcl_land_window_foreign("hosta", DLW_B, DLW_T1000 + 2100, 600,
                                       &hit));
        ASSERT(hit.open);
        ASSERT_EQ(hit.seconds_left, (int64_t)-300);
        /* eleven minutes past: stale, ignored, counted */
        ASSERT(zcl_land_window_foreign("hosta", DLW_B, DLW_T1000 + 2460, 600,
                                       &hit));
        ASSERT(!hit.open);
        ASSERT_EQ(hit.stale, (int64_t)1);
        PASS();
    }

    TEST("land.window: other base, own host and closed windows do not count") {
        const char *rows[] = {
            WROW(1, "2026-10-09T09:50:00Z", "agent-b", 0, "hostb", "10:30Z"),
            WROW(2, "2026-10-09T09:51:00Z", "agent-a", 0, "hosta", "10:30Z"),
        };
        dlw_rows(rows, 2);
        ASSERT(zcl_land_window_foreign("hosta", "cccccccccc", DLW_T1000, 600,
                                       &hit));
        ASSERT(!hit.open);
        ASSERT(zcl_land_window_foreign("hostb", DLW_B, DLW_T1000, 600, &hit));
        ASSERT(hit.open);
        ASSERT_STR_EQ(hit.host, "hosta");
        const char *closed[] = {
            WROW(1, "2026-10-09T09:50:00Z", "agent-b", 0, "hostb", "10:30Z"),
            CROW(3, "2026-10-09T09:59:00Z", "agent-b",
                 "RELEASED hostb, candidate " DLW_C " on base " DLW_B "."),
        };
        dlw_rows(closed, 2);
        ASSERT(zcl_land_window_foreign("hosta", DLW_B, DLW_T1000, 600, &hit));
        ASSERT(!hit.open);
        ASSERT_EQ(hit.stale, (int64_t)0);
        PASS();
    }

    TEST("land.window: open with grace_s keeps an overrun window") {
        struct dlw_call c;
        const char *rows[] = {
            WROW(1, "2026-10-09T09:30:00Z", "agent-b", 0, "hostb", "09:55Z"),
        };
        dlw_rows(rows, 1);
        dlw_begin(&c);
        (void)json_push_kv_str(&c.input, "action", "open");
        (void)json_push_kv_str(&c.input, "host", "hosta");
        (void)json_push_kv_int(&c.input, "now", DLW_T1000);
        (void)json_push_kv_int(&c.input, "grace_s", 600);
        zcl_native_handle_dev_land_window(&c.request, &c.reply);
        ASSERT(dlw_ok(&c));
        ASSERT_EQ((int)dlw_windows(&c), 1);
        ASSERT_EQ(json_get_int(json_get(json_at(json_get(&c.reply.data,
                      "open_windows"), 0), "seconds_left")), (int64_t)-300);
        dlw_end(&c);
        PASS();
    }

_test_next:;
    return failures;
}

/* Last outbox line into out ("" when none). */
static void dlw_outbox_last(char *out, size_t cap)
{
    char path[4200], buf[8192];
    FILE *f;
    out[0] = '\0';
    (void)snprintf(path, sizeof(path), "%s/outbox.jsonl", g_dlw_mail);
    f = fopen(path, "r");
    if (!f)
        return;
    while (fgets(buf, sizeof(buf), f))
        (void)snprintf(out, cap, "%s", buf);
    (void)fclose(f);
}

/* The body of a window row expected done at `done` (rounded up). */
static void dlw_window_body(char *out, size_t cap, const char *cand10,
                            const char *base10, int64_t done)
{
    int64_t m = (done + 59) / 60;
    (void)snprintf(out, cap,
                   "LAND-WINDOW hosta, candidate %s on base %s, proving now, "
                   "expected done %02d:%02dZ.",
                   cand10, base10, (int)((m / 60) % 24), (int)(m % 60));
}

static size_t dlw_open_on(const char *host, const char *base)
{
    struct dlw_call c;
    size_t n;
    dlw_begin(&c);
    (void)json_push_kv_str(&c.input, "action", "open");
    (void)json_push_kv_str(&c.input, "host", host);
    (void)json_push_kv_str(&c.input, "base", base);
    zcl_native_handle_dev_land_window(&c.request, &c.reply);
    n = dlw_ok(&c) ? dlw_windows(&c) : 99;
    dlw_end(&c);
    return n;
}

#define DLW_C40 "1234567890abcdef1234567890abcdef12345678"
#define DLW_B40 "9876543210fedcba9876543210fedcba98765432"
#define DLW_P40 "abcdefabcdefabcdefabcdefabcdefabcdefabcd"

static int dlw_lifecycle_cases(void)
{
    int failures = 0;
    char side[600], root[512], last[8192], want[256], note[256];
    struct zcl_land_window_self self = { side, "hosta", "dev.land" };
    struct zcl_land_window_estimate est = { .seconds = 1200 };
    int64_t now = platform_time_wall_unix();
    size_t lines;

    test_make_tmpdir(root, sizeof(root), "dev_land_window", "self");
    (void)snprintf(side, sizeof(side), "%s/window.state", root);
    dlw_rows(NULL, 0);

    TEST("land.window: begin announces once per (candidate, base)") {
        lines = dlw_outbox_lines();
        ASSERT_EQ((int)zcl_land_window_begin(&self, DLW_C40, DLW_B40, now,
                                             &est, note, sizeof(note)),
                  (int)ZCL_LAND_WINDOW_ANNOUNCED);
        ASSERT_EQ((int)dlw_outbox_lines(), (int)lines + 1);
        dlw_outbox_last(last, sizeof(last));
        dlw_window_body(want, sizeof(want), "1234567890", "9876543210",
                        now + 1200);
        ASSERT(strstr(last, want) != NULL);
        ASSERT(strstr(last, "\"from\":\"dev.land\"") != NULL);
        ASSERT_EQ((int)zcl_land_window_begin(&self, DLW_C40, DLW_B40, now,
                                             &est, note, sizeof(note)),
                  (int)ZCL_LAND_WINDOW_NONE);
        ASSERT_EQ((int)dlw_outbox_lines(), (int)lines + 1);
        ASSERT_EQ((int)dlw_open_on("hostb", "9876543210"), 1);
        PASS();
    }

    TEST("land.window: an overrun proof re-announces with a fresh estimate") {
        int64_t t1 = now + 1200 + 120, t2;
        lines = dlw_outbox_lines();
        ASSERT_EQ((int)zcl_land_window_tick(&self, root, now + 600, note,
                                            sizeof(note)),
                  (int)ZCL_LAND_WINDOW_NONE);
        /* no history under root: fallback 30 min is still ahead of t1 */
        ASSERT_EQ((int)zcl_land_window_tick(&self, root, t1, note,
                                            sizeof(note)),
                  (int)ZCL_LAND_WINDOW_REANNOUNCED);
        ASSERT_EQ((int)dlw_outbox_lines(), (int)lines + 1);
        dlw_outbox_last(last, sizeof(last));
        dlw_window_body(want, sizeof(want), "1234567890", "9876543210",
                        now + ZCL_LAND_WINDOW_FALLBACK_S);
        ASSERT(strstr(last, want) != NULL);
        ASSERT_EQ((int)zcl_land_window_tick(&self, root, t1 + 60, note,
                                            sizeof(note)),
                  (int)ZCL_LAND_WINDOW_NONE);
        /* past every quantile: now + 2 * REANNOUNCE_S */
        t2 = now + ZCL_LAND_WINDOW_FALLBACK_S + 120;
        ASSERT_EQ((int)zcl_land_window_tick(&self, root, t2, note,
                                            sizeof(note)),
                  (int)ZCL_LAND_WINDOW_REANNOUNCED);
        dlw_outbox_last(last, sizeof(last));
        dlw_window_body(want, sizeof(want), "1234567890", "9876543210",
                        t2 + 2 * ZCL_LAND_WINDOW_REANNOUNCE_S);
        ASSERT(strstr(last, want) != NULL);
        ASSERT_EQ((int)dlw_outbox_lines(), (int)lines + 2);
        PASS();
    }

    TEST("land.window: close posts LANDED for the landed candidate") {
        lines = dlw_outbox_lines();
        ASSERT_EQ((int)zcl_land_window_close(&self, DLW_C40, DLW_B40, NULL,
                                             note, sizeof(note)),
                  (int)ZCL_LAND_WINDOW_NONE);
        ASSERT_EQ((int)zcl_land_window_close(&self, NULL, NULL, DLW_C40,
                                             note, sizeof(note)),
                  (int)ZCL_LAND_WINDOW_CLOSED);
        dlw_outbox_last(last, sizeof(last));
        ASSERT(strstr(last, "\"body\":\"LANDED hosta, candidate 1234567890 "
                            "on base 9876543210.\"") != NULL);
        ASSERT_EQ((int)dlw_open_on("hostb", "9876543210"), 0);
        ASSERT_EQ((int)zcl_land_window_close(&self, NULL, NULL, DLW_C40,
                                             note, sizeof(note)),
                  (int)ZCL_LAND_WINDOW_NONE);
        ASSERT_EQ((int)dlw_outbox_lines(), (int)lines + 1);
        PASS();
    }

    TEST("land.window: a new pair releases the old window first") {
        lines = dlw_outbox_lines();
        ASSERT_EQ((int)zcl_land_window_begin(&self, DLW_P40, DLW_B40, now,
                                             &est, note, sizeof(note)),
                  (int)ZCL_LAND_WINDOW_ANNOUNCED);
        ASSERT_EQ((int)zcl_land_window_begin(&self, DLW_C40, DLW_P40, now,
                                             &est, note, sizeof(note)),
                  (int)ZCL_LAND_WINDOW_ANNOUNCED);
        ASSERT_EQ((int)dlw_outbox_lines(), (int)lines + 3);
        ASSERT_EQ((int)dlw_open_on("hostb", "9876543210"), 0);
        ASSERT_EQ((int)dlw_open_on("hostb", "abcdefabcd"), 1);
        ASSERT_EQ((int)zcl_land_window_close(&self, NULL, NULL, DLW_P40,
                                             note, sizeof(note)),
                  (int)ZCL_LAND_WINDOW_CLOSED);
        dlw_outbox_last(last, sizeof(last));
        ASSERT(strstr(last, "\"body\":\"RELEASED hosta, candidate 1234567890 "
                            "on base abcdefabcd.\"") != NULL);
        ASSERT_EQ((int)dlw_open_on("hostb", "abcdefabcd"), 0);
        PASS();
    }

_test_next:;
    return failures;
}

int test_dev_land_window(void);
int test_dev_land_window(void)
{
    int failures = 0;
    struct dlw_call c;
    dlw_isolate();

    TEST("land.window: another host's open window is reported") {
        const char *rows[] = {
            WROW(1, "2026-10-09T09:50:00Z", "agent-b", 0, "hostb", "10:30Z"),
            CROW(5, "2026-10-09T09:55:00Z", "agent-c",
                 "LANDED " DLW_C " on main"),
        };
        dlw_rows(rows, 2);
        dlw_open(&c, "hosta", DLW_T1000);
        ASSERT(dlw_ok(&c));
        ASSERT_EQ((int)dlw_windows(&c), 1);
        ASSERT_EQ(dlw_int(&c, "max_seconds_left"), (int64_t)1800);
        ASSERT_EQ(json_get_int(json_get(json_at(json_get(&c.reply.data,
                      "open_windows"), 0), "seconds_left")), (int64_t)1800);
        ASSERT_STR_EQ(json_get_str(json_get(json_at(json_get(&c.reply.data,
                      "open_windows"), 0), "host")), "hostb");
        dlw_end(&c);
        PASS();
    }

    TEST("land.window: a later LANDED from the same sender closes it") {
        const char *rows[] = {
            WROW(1, "2026-10-09T09:50:00Z", "agent-b", 0, "hostb", "10:30Z"),
            CROW(2, "2026-10-09T09:58:00Z", "agent-b",
                 "LANDED " DLW_C " on main"),
        };
        dlw_rows(rows, 2);
        dlw_open(&c, "hosta", DLW_T1000);
        ASSERT(dlw_ok(&c));
        ASSERT_EQ((int)dlw_windows(&c), 0);
        ASSERT_EQ(dlw_int(&c, "max_seconds_left"), (int64_t)0);
        dlw_end(&c);
        PASS();
    }

    TEST("land.window: a later RELEASED from the same sender closes it") {
        const char *rows[] = {
            WROW(1, "2026-10-09T09:50:00Z", "agent-b", 0, "hostb", "10:30Z"),
            CROW(2, "2026-10-09T09:58:00Z", "agent-b",
                 "RELEASED " DLW_C " without landing"),
        };
        dlw_rows(rows, 2);
        dlw_open(&c, "hosta", DLW_T1000);
        ASSERT(dlw_ok(&c));
        ASSERT_EQ((int)dlw_windows(&c), 0);
        dlw_end(&c);
        PASS();
    }

    TEST("land.window: an expired window is not open") {
        const char *rows[] = {
            WROW(1, "2026-10-09T09:30:00Z", "agent-b", 0, "hostb", "09:55Z"),
        };
        dlw_rows(rows, 1);
        dlw_open(&c, "hosta", DLW_T1000);
        ASSERT(dlw_ok(&c));
        ASSERT_EQ((int)dlw_windows(&c), 0);
        dlw_end(&c);
        PASS();
    }

    TEST("land.window: the asking host's own window is ignored") {
        const char *rows[] = {
            WROW(1, "2026-10-09T09:50:00Z", "agent-a", 0, "hosta", "10:30Z"),
        };
        dlw_rows(rows, 1);
        dlw_open(&c, "hosta", DLW_T1000);
        ASSERT(dlw_ok(&c));
        ASSERT_EQ((int)dlw_windows(&c), 0);
        dlw_end(&c);
        PASS();
    }

    TEST("land.window: expected-done earlier than the row rolls to next day") {
        const char *rows[] = {
            WROW(1, "2026-10-09T23:50:00Z", "agent-b", 0, "hostb", "00:20Z"),
        };
        dlw_rows(rows, 1);
        dlw_open(&c, "hosta", DLW_T2355);
        ASSERT(dlw_ok(&c));
        ASSERT_EQ((int)dlw_windows(&c), 1);
        ASSERT_EQ(dlw_int(&c, "max_seconds_left"), (int64_t)1500);
        dlw_end(&c);
        PASS();
    }

    TEST("land.window: malformed rows are skipped and counted") {
        const char *rows[] = {
            "this is not json",
            CROW(1, "2026-10-09T09:50:00Z", "agent-b",
                 "LAND-WINDOW hostb, candidate zz on base " DLW_B
                 ", proving now, expected done 10:30Z."),
            WROW(3, "2026-10-09T09:50:00Z", "agent-b", 0, "hostb", "10:30Z"),
        };
        dlw_rows(rows, 3);
        dlw_open(&c, "hosta", DLW_T1000);
        ASSERT(dlw_ok(&c));
        ASSERT_EQ((int)dlw_windows(&c), 1);
        ASSERT(dlw_int(&c, "skipped") >= 2);
        dlw_end(&c);
        PASS();
    }

    TEST("land.window: announce posts once, then reports already_announced") {
        const char *cand = "fedcba9876543210fedcba9876543210fedcba98";
        dlw_announce(&c, cand, "10:30Z");
        ASSERT(dlw_ok(&c));
        ASSERT(!dlw_bool(&c, "already_announced"));
        dlw_end(&c);
        ASSERT_EQ((int)dlw_outbox_lines(), 1);
        dlw_announce(&c, cand, "10:30Z");
        ASSERT(dlw_ok(&c));
        ASSERT(dlw_bool(&c, "already_announced"));
        dlw_end(&c);
        ASSERT_EQ((int)dlw_outbox_lines(), 1);
        PASS();
    }

    TEST("land.window: announce refuses a malformed expected_done") {
        dlw_announce(&c, "fedcba9876", "25:00Z");
        ASSERT(!dlw_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "INVALID_INPUT");
        dlw_end(&c);
        dlw_announce(&c, "xyz", "10:30Z");
        ASSERT(!dlw_ok(&c));
        dlw_end(&c);
        ASSERT_EQ((int)dlw_outbox_lines(), 1);
        PASS();
    }

    TEST("land.window: same seq, new candidate/base pair announces again") {
        const char *cand2 = "543e52aa0a1111111111";
        const char *base2 = "d3297d65b2222222222222";
        dlw_announce_pair(&c, cand2, "25b88f1a51aaaaaaaaaa", "11:00Z");
        ASSERT(dlw_ok(&c));
        ASSERT(!dlw_bool(&c, "already_announced"));
        dlw_end(&c);
        ASSERT_EQ((int)dlw_outbox_lines(), 2);
        /* same candidate, base moved: a new proof attempt, a new row */
        dlw_announce_pair(&c, cand2, base2, "11:30Z");
        ASSERT(dlw_ok(&c));
        ASSERT(!dlw_bool(&c, "already_announced"));
        dlw_end(&c);
        ASSERT_EQ((int)dlw_outbox_lines(), 3);
        /* repeating either current pair stays idempotent */
        dlw_announce_pair(&c, cand2, base2, "11:30Z");
        ASSERT(dlw_ok(&c));
        ASSERT(dlw_bool(&c, "already_announced"));
        dlw_end(&c);
        ASSERT_EQ((int)dlw_outbox_lines(), 3);
        PASS();
    }

    TEST("land.window: open with base keeps only windows on that base") {
        const char *rows[] = {
            WROW(1, "2026-10-09T09:50:00Z", "agent-b", 0, "hostb", "10:30Z"),
            CROW(2, "2026-10-09T09:51:00Z", "agent-d",
                 "LAND-WINDOW hostd, candidate cccccccccc on base dddddddddd"
                 ", proving now, expected done 10:20Z."),
        };
        dlw_rows(rows, 2);
        dlw_begin(&c);
        (void)json_push_kv_str(&c.input, "action", "open");
        (void)json_push_kv_str(&c.input, "host", "hosta");
        (void)json_push_kv_int(&c.input, "now", DLW_T1000);
        (void)json_push_kv_str(&c.input, "base", "dddddddddd");
        zcl_native_handle_dev_land_window(&c.request, &c.reply);
        ASSERT(dlw_ok(&c));
        ASSERT_EQ((int)dlw_windows(&c), 1);
        ASSERT_EQ(dlw_int(&c, "max_seconds_left"), (int64_t)1200);
        dlw_end(&c);
        dlw_open(&c, "hosta", DLW_T1000);
        ASSERT_EQ((int)dlw_windows(&c), 2);
        dlw_end(&c);
        PASS();
    }

_test_next:;
#if !defined(_WIN32)
    failures += dlw_estimate_cases();
#endif
    failures += dlw_foreign_cases();
    failures += dlw_lifecycle_cases();
    dlw_restore();
    if (failures == 0)
        printf("test_dev_land_window: all passed\n");
    else
        printf("test_dev_land_window: %d FAILED\n", failures);
    return failures;
}
