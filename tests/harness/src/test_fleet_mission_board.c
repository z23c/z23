/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * fleet.mission.board (tools/command/native_fleet_mission_board.c): a kanban
 * projection of the dev agent queue, the dev land queue and the steer outbox.
 * Every case runs against an isolated XDG_STATE_HOME with fixture files, calls
 * the bound handler directly, and never asserts on wall time (row timestamps
 * are derived from the same platform clock the leaf reads). */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_fleet.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/time_compat.h"

#include <dirent.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MBX_PATH "fleet.mission.board"
#define MBX_TIP_A "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define MBX_TIP_B "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define MBX_TIP_C "cccccccccccccccccccccccccccccccccccccccc"

static char g_mbx_state[600];
static char g_mbx_saved_xdg[4096];
static bool g_mbx_had_xdg;

/* ── rig ───────────────────────────────────────────────────────────────── */

static bool mbx_mkdir(const char *path)
{
    return mkdir(path, 0700) == 0 || access(path, F_OK) == 0;
}

static void mbx_path(char *out, size_t cap, const char *sub, const char *file)
{
    (void)snprintf(out, cap, "%s/z23/dev/%s%s%s", g_mbx_state, sub,
                   file[0] ? "/" : "", file);
}

/* Owner-private z23/dev always; the three source dirs only when wanted. */
static bool mbx_isolate(const char *tag, bool sources)
{
    char base[400], p[800];
    test_make_tmpdir(base, sizeof(base), "fleet_mission_board", tag);
    (void)snprintf(g_mbx_state, sizeof(g_mbx_state), "%s/state", base);
    g_mbx_had_xdg = getenv("XDG_STATE_HOME") != NULL;
    if (g_mbx_had_xdg)
        (void)snprintf(g_mbx_saved_xdg, sizeof(g_mbx_saved_xdg), "%s",
                       getenv("XDG_STATE_HOME"));
    setenv("XDG_STATE_HOME", g_mbx_state, 1);
    if (!mbx_mkdir(g_mbx_state))
        return false;
    (void)snprintf(p, sizeof(p), "%s/z23", g_mbx_state);
    if (!mbx_mkdir(p))
        return false;
    (void)snprintf(p, sizeof(p), "%s/z23/dev", g_mbx_state);
    if (!mbx_mkdir(p))
        return false;
    if (!sources)
        return true;
    mbx_path(p, sizeof(p), "queue", "");
    if (!mbx_mkdir(p))
        return false;
    mbx_path(p, sizeof(p), "land", "");
    if (!mbx_mkdir(p))
        return false;
    mbx_path(p, sizeof(p), "mail", "");
    return mbx_mkdir(p);
}

static void mbx_restore(void)
{
    if (g_mbx_had_xdg)
        setenv("XDG_STATE_HOME", g_mbx_saved_xdg, 1);
    else
        unsetenv("XDG_STATE_HOME");
}

static bool mbx_write(const char *sub, const char *file, const char *text)
{
    char p[900];
    FILE *f;
    size_t len = strlen(text);
    bool ok;
    mbx_path(p, sizeof(p), sub, file);
    f = fopen(p, "wb");
    if (!f)
        return false;
    ok = fwrite(text, 1, len, f) == len;
    return fclose(f) == 0 && ok;
}

/* "YYYY-MM-DDTHH:MM:SSZ" for now minus secs, off the platform clock. */
static void mbx_ago(char out[32], long long secs)
{
    struct tm tm;
    time_t t = platform_time_wall_time_t() - (time_t)secs;
    out[0] = '\0';
    if (platform_time_utc_tm(t, &tm))
        (void)strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static void mbx_cat(char *dst, size_t cap, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void mbx_cat(char *dst, size_t cap, const char *fmt, ...)
{
    size_t used = strlen(dst);
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(dst + used, cap - used, fmt, ap);
    va_end(ap);
}

static void mbx_qrow(char *buf, size_t cap, int seq, const char *name,
                     const char *state)
{
    char ts[32];
    mbx_ago(ts, 7200);
    mbx_cat(buf, cap,
            "{\"seq\":%d,\"ts\":\"%s\",\"kind\":\"leaf\",\"name\":\"%s\","
            "\"engine\":\"codex\",\"attempt\":1,\"state\":\"%s\","
            "\"started\":0}\n",
            seq, ts, name, state);
}

static void mbx_lrow(char *buf, size_t cap, int seq, const char *tip,
                     const char *state, long long ago, const char *dim)
{
    char ts[32];
    mbx_ago(ts, ago);
    mbx_cat(buf, cap,
            "{\"seq\":%d,\"ts\":\"%s\",\"tip\":\"%s\",\"state\":\"%s\","
            "\"attempt\":1,\"dimension\":\"%s\"}\n",
            seq, ts, tip, state, dim);
}

static void mbx_mrow(char *buf, size_t cap, int seq, long long ago,
                     const char *from, const char *body, const char *ref)
{
    char ts[32];
    mbx_ago(ts, ago);
    mbx_cat(buf, cap,
            "{\"seq\":%d,\"ts\":\"%s\",\"from\":\"%s\",\"to\":\"lead\","
            "\"kind\":\"steer\",\"body\":\"%s\",\"ref\":\"%s\"}\n",
            seq, ts, from, body, ref);
}

/* ── one invocation ────────────────────────────────────────────────────── */

struct mbx_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static bool mbx_run(struct mbx_call *c, long long hours, long long limit)
{
    char why[256];
    json_init(&c->input);
    json_set_object(&c->input);
    if (hours >= 0)
        (void)json_push_kv_int(&c->input, "hours", hours);
    if (limit >= 0)
        (void)json_push_kv_int(&c->input, "limit", limit);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), MBX_PATH, NULL);
    zcl_command_reply_init(&c->reply, "zcl.fleet_mission_board.v1");
    if (c->request.spec &&
        !zcl_command_registry_input_validate(c->request.spec, &c->input, why,
                                             sizeof(why))) {
        printf("[input rejected: %s] ", why);
        return false;
    }
    zcl_native_handle_fleet_mission_board(&c->request, &c->reply);
    return true;
}

static void mbx_end(struct mbx_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool mbx_ok(const struct mbx_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static int64_t mbx_count(const struct mbx_call *c, const char *col)
{
    const struct json_value *counts = json_get(&c->reply.data, "counts");
    const struct json_value *v = counts ? json_get(counts, col) : NULL;
    return v && v->type == JSON_INT ? json_get_int(v) : -1;
}

static const struct json_value *mbx_col(const struct mbx_call *c, const char *name)
{
    const struct json_value *cols = json_get(&c->reply.data, "columns");
    for (size_t i = 0; cols && i < json_size(cols); i++) {
        const struct json_value *col = json_at(cols, i);
        const struct json_value *n = col ? json_get(col, "name") : NULL;
        if (n && n->type == JSON_STR && strcmp(json_get_str(n), name) == 0)
            return col;
    }
    return NULL;
}

static int64_t mbx_field(const struct mbx_call *c, const char *name,
                         const char *key)
{
    const struct json_value *col = mbx_col(c, name);
    const struct json_value *v = col ? json_get(col, key) : NULL;
    return v && v->type == JSON_INT ? json_get_int(v) : -1;
}

static bool mbx_has_card(const struct mbx_call *c, const char *name,
                         const char *needle)
{
    const struct json_value *col = mbx_col(c, name);
    const struct json_value *cards = col ? json_get(col, "cards") : NULL;
    for (size_t i = 0; cards && i < json_size(cards); i++) {
        const struct json_value *s = json_at(cards, i);
        if (s && s->type == JSON_STR && strstr(json_get_str(s), needle))
            return true;
    }
    return false;
}

static const char *mbx_screen(const struct mbx_call *c)
{
    const struct json_value *v = json_get(&c->reply.data, "screen");
    return v && v->type == JSON_STR ? json_get_str(v) : "";
}

/* Widest line of the screen in display columns (UTF-8 code points). */
static size_t mbx_widest(const char *screen)
{
    size_t best = 0, cur = 0;
    for (const unsigned char *p = (const unsigned char *)screen; *p; p++) {
        if (*p == '\n') {
            if (cur > best)
                best = cur;
            cur = 0;
        } else if ((*p & 0xC0) != 0x80) {
            cur++;
        }
    }
    return cur > best ? cur : best;
}

/* Every path under dir, depth first, into one string. */
static void mbx_tree(const char *dir, char *out, size_t cap)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    if (!d)
        return;
    while ((e = readdir(d)) != NULL) {
        char sub[1200];
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        (void)snprintf(sub, sizeof(sub), "%s/%s", dir, e->d_name);
        mbx_cat(out, cap, "%s\n", sub);
        mbx_tree(sub, out, cap);
    }
    (void)closedir(d);
}

static bool mbx_exists(const char *sub, const char *file)
{
    char p[900];
    mbx_path(p, sizeof(p), sub, file);
    return access(p, F_OK) == 0;
}

/* The standard three-source fixture the column cases share. */
static bool mbx_standard(void)
{
    static char q[8192], l[8192], o[8192], m[8192];
    q[0] = l[0] = o[0] = m[0] = '\0';
    mbx_qrow(q, sizeof(q), 1, "backlog-one", "queued");
    mbx_qrow(q, sizeof(q), 2, "backlog-two", "queued");
    mbx_qrow(q, sizeof(q), 3, "build-one", "running");
    mbx_lrow(l, sizeof(l), 5, MBX_TIP_A, "queued", 600, "");
    mbx_lrow(l, sizeof(l), 6, MBX_TIP_B, "inflight", 300, "");
    mbx_lrow(o, sizeof(o), 3, MBX_TIP_C, "landed", 3600, "");
    mbx_lrow(o, sizeof(o), 4, MBX_TIP_A, "failed", 1800, "cargo-test");
    mbx_mrow(m, sizeof(m), 1, 5400, "astra-mac", "CLAIM pipe unit", "r1");
    mbx_mrow(m, sizeof(m), 2, 3000, "astra-mac", "CLAIM pipe unit again", "r1");
    mbx_mrow(m, sizeof(m), 3, 1200, "bob", "READY to land", "");
    mbx_mrow(m, sizeof(m), 4, 900, "bob", "just chatting", "");
    return mbx_write("queue", "queue.jsonl", q) &&
           mbx_write("land", "queue.jsonl", l) &&
           mbx_write("land", "outcomes.jsonl", o) &&
           mbx_write("mail", "outbox.jsonl", m);
}

static int mbx_case_1(void)
{
    int failures = 0;

    TEST("mission board: every column fills from its source") {
        struct mbx_call c;
        const char *screen;
        ASSERT(mbx_isolate("columns", true) && mbx_standard());
        ASSERT(mbx_run(&c, -1, -1) && mbx_ok(&c));
        ASSERT_EQ(mbx_count(&c, "BACKLOG"), 2);
        ASSERT_EQ(mbx_count(&c, "CLAIMED"), 1); /* the repeat folds into r1 */
        ASSERT_EQ(mbx_count(&c, "BUILDING"), 1);
        ASSERT_EQ(mbx_count(&c, "REVIEW"), 1);
        ASSERT_EQ(mbx_count(&c, "PROVING"), 2);
        ASSERT_EQ(mbx_count(&c, "LANDED"), 1);
        ASSERT_EQ(mbx_count(&c, "FAILED"), 1);
        ASSERT(mbx_has_card(&c, "BACKLOG", "backlog-one"));
        ASSERT(mbx_has_card(&c, "BUILDING", "build-one codex a1"));
        ASSERT(mbx_has_card(&c, "CLAIMED", "astra-mac: CLAIM pipe unit"));
        ASSERT(mbx_has_card(&c, "REVIEW", "bob: READY to land"));
        ASSERT(mbx_has_card(&c, "PROVING", "#6 bbbbbbbb inflight"));
        ASSERT(mbx_has_card(&c, "LANDED", "#3 cccccccc landed 1h"));
        ASSERT(mbx_has_card(&c, "FAILED", "cargo-test"));
        screen = mbx_screen(&c);
        ASSERT(strstr(screen, "\xe2\x94\x8c") != NULL); /* top-left corner */
        ASSERT(strstr(screen, "\xe2\x94\x94") != NULL); /* bottom-left */
        ASSERT(strstr(screen, "FAILED 1") != NULL);
        ASSERT(mbx_widest(screen) <= 120);
        mbx_end(&c);
        mbx_restore();
        PASS();
    }

_test_next:;
    mbx_restore();
    return failures;
}

static int mbx_case_2(void)
{
    int failures = 0;

    TEST("mission board: a missing outbox shows the not-on-this-host card") {
        struct mbx_call c;
        char p[900];
        ASSERT(mbx_isolate("nosteer", true) && mbx_standard());
        mbx_path(p, sizeof(p), "mail", "outbox.jsonl");
        ASSERT(unlink(p) == 0);
        ASSERT(mbx_run(&c, -1, -1) && mbx_ok(&c));
        ASSERT_EQ(mbx_count(&c, "CLAIMED"), 0);
        ASSERT(mbx_has_card(&c, "CLAIMED", "steer bus not on this host"));
        ASSERT(mbx_has_card(&c, "REVIEW", "steer bus not on this host"));
        ASSERT_EQ(mbx_count(&c, "BACKLOG"), 2);
        ASSERT(strstr(mbx_screen(&c), "steer bus not on this host") != NULL);
        mbx_end(&c);
        mbx_restore();
        PASS();
    }

_test_next:;
    mbx_restore();
    return failures;
}

static int mbx_case_3(void)
{
    int failures = 0;

    TEST("mission board: the hours window excludes old rows") {
        static char o[4096], m[4096];
        struct mbx_call c;
        o[0] = m[0] = '\0';
        ASSERT(mbx_isolate("hours", true));
        mbx_lrow(o, sizeof(o), 1, MBX_TIP_A, "landed", 30 * 3600, "");
        mbx_lrow(o, sizeof(o), 2, MBX_TIP_B, "failed", 30 * 3600, "old-dim");
        mbx_lrow(o, sizeof(o), 3, MBX_TIP_C, "landed", 3600, "");
        mbx_mrow(m, sizeof(m), 1, 30 * 3600, "old", "CLAIM stale", "x");
        mbx_mrow(m, sizeof(m), 2, 3600, "new", "CLAIM fresh", "y");
        ASSERT(mbx_write("land", "outcomes.jsonl", o));
        ASSERT(mbx_write("mail", "outbox.jsonl", m));
        ASSERT(mbx_run(&c, 24, -1) && mbx_ok(&c));
        ASSERT_EQ(mbx_count(&c, "LANDED"), 1);
        ASSERT_EQ(mbx_count(&c, "FAILED"), 0);
        ASSERT_EQ(mbx_count(&c, "CLAIMED"), 1);
        ASSERT(mbx_has_card(&c, "CLAIMED", "new: CLAIM fresh"));
        mbx_end(&c);
        ASSERT(mbx_run(&c, 48, -1) && mbx_ok(&c));
        ASSERT_EQ(mbx_count(&c, "LANDED"), 2);
        ASSERT_EQ(mbx_count(&c, "FAILED"), 1);
        ASSERT_EQ(mbx_count(&c, "CLAIMED"), 2);
        mbx_end(&c);
        mbx_restore();
        PASS();
    }

_test_next:;
    mbx_restore();
    return failures;
}

static int mbx_case_4(void)
{
    int failures = 0;

    TEST("mission board: limit truncates and reports the overflow") {
        static char q[8192];
        struct mbx_call c;
        char name[16];
        q[0] = '\0';
        ASSERT(mbx_isolate("limit", true));
        for (int i = 1; i <= 5; i++) {
            (void)snprintf(name, sizeof(name), "job-%d", i);
            mbx_qrow(q, sizeof(q), i, name, "queued");
        }
        ASSERT(mbx_write("queue", "queue.jsonl", q));
        ASSERT(mbx_run(&c, -1, 2) && mbx_ok(&c));
        ASSERT_EQ(mbx_field(&c, "BACKLOG", "count"), 5);
        ASSERT_EQ(mbx_field(&c, "BACKLOG", "shown"), 2);
        ASSERT_EQ(mbx_field(&c, "BACKLOG", "overflow"), 3);
        ASSERT(strstr(mbx_screen(&c), "+3 more") != NULL);
        mbx_end(&c);
        mbx_restore();
        PASS();
    }

_test_next:;
    mbx_restore();
    return failures;
}

static int mbx_case_5(void)
{
    int failures = 0;

    TEST("mission board: it creates no file, directory or lock") {
        char before[8192] = "", after[8192] = "", root[700];
        struct mbx_call c;
        /* Source dirs absent: nothing may appear. */
        ASSERT(mbx_isolate("nowrite_bare", false));
        (void)snprintf(root, sizeof(root), "%s", g_mbx_state);
        mbx_tree(root, before, sizeof(before));
        ASSERT(mbx_run(&c, -1, -1) && mbx_ok(&c));
        ASSERT_EQ(mbx_count(&c, "BACKLOG"), 0);
        mbx_end(&c);
        mbx_tree(root, after, sizeof(after));
        ASSERT_STR_EQ(before, after);
        ASSERT(!mbx_exists("queue", "") && !mbx_exists("land", "") &&
               !mbx_exists("mail", ""));
        mbx_restore();
        /* Populated sources: same listing, and no lock file. */
        ASSERT(mbx_isolate("nowrite_full", true) && mbx_standard());
        before[0] = after[0] = '\0';
        (void)snprintf(root, sizeof(root), "%s", g_mbx_state);
        mbx_tree(root, before, sizeof(before));
        ASSERT(mbx_run(&c, -1, -1) && mbx_ok(&c));
        mbx_end(&c);
        mbx_tree(root, after, sizeof(after));
        ASSERT_STR_EQ(before, after);
        ASSERT(!mbx_exists("land", "step.lock"));
        ASSERT(!mbx_exists("land", "queue.lock"));
        ASSERT(!mbx_exists("queue", "queue.lock"));
        mbx_restore();
        PASS();
    }

_test_next:;
    mbx_restore();
    return failures;
}

static int mbx_case_6(void)
{
    int failures = 0;

    TEST("mission board: a malformed line is skipped and counted") {
        static char q[4096], l[4096], m[4096];
        struct mbx_call c;
        q[0] = l[0] = m[0] = '\0';
        ASSERT(mbx_isolate("malformed", true));
        mbx_cat(q, sizeof(q), "this is not json\n");
        mbx_qrow(q, sizeof(q), 1, "ok-job", "queued");
        mbx_cat(l, sizeof(l), "{\"seq\":\n");
        mbx_lrow(l, sizeof(l), 2, MBX_TIP_A, "queued", 60, "");
        mbx_cat(m, sizeof(m), "garbage\n");
        mbx_mrow(m, sizeof(m), 1, 60, "ann", "CLAIM good", "z");
        ASSERT(mbx_write("queue", "queue.jsonl", q));
        ASSERT(mbx_write("land", "queue.jsonl", l));
        ASSERT(mbx_write("mail", "outbox.jsonl", m));
        ASSERT(mbx_run(&c, -1, -1) && mbx_ok(&c));
        ASSERT_EQ(mbx_count(&c, "BACKLOG"), 1);
        ASSERT_EQ(mbx_count(&c, "PROVING"), 1);
        ASSERT_EQ(mbx_count(&c, "CLAIMED"), 1);
        {
            const struct json_value *s = json_get(&c.reply.data, "skipped");
            ASSERT(s && s->type == JSON_INT && json_get_int(s) == 3);
        }
        ASSERT(strstr(mbx_screen(&c), "3 malformed rows skipped") != NULL);
        mbx_end(&c);
        mbx_restore();
        PASS();
    }

_test_next:;
    mbx_restore();
    return failures;
}

static int mbx_case_7(void)
{
    int failures = 0;

    TEST("mission board: hours and limit are bounded") {
        static const long long bad_hours[] = {0, 169, 100000};
        static const long long bad_limit[] = {0, 33, 100000};
        struct mbx_call c;
        ASSERT(mbx_isolate("bounds", true));
        /* The registry refuses some values before the handler runs; the
         * handler refuses the rest (169 and 33 reach it). */
        for (size_t i = 0; i < 3; i++) {
            bool ran = mbx_run(&c, bad_hours[i], -1);
            ASSERT(i != 1 || ran);
            ASSERT(!ran || !mbx_ok(&c));
            mbx_end(&c);
            ran = mbx_run(&c, -1, bad_limit[i]);
            ASSERT(i != 1 || ran);
            ASSERT(!ran || !mbx_ok(&c));
            mbx_end(&c);
        }
        ASSERT(mbx_run(&c, 1, 1) && mbx_ok(&c));
        mbx_end(&c);
        ASSERT(mbx_run(&c, 168, 32) && mbx_ok(&c));
        mbx_end(&c);
        mbx_restore();
        PASS();
    }

_test_next:;
    mbx_restore();
    return failures;
}

static int mbx_landed_time(void)
{
    int failures = 0;
    TEST("mission board: landed age and window use landing time with legacy fallback") {
        static char outcomes[8192];
        struct mbx_call c;
        char old[32], recent[32], two_hours[32];
        long long now = (long long)platform_time_wall_time_t();
        outcomes[0] = '\0';
        ASSERT(mbx_isolate("landed-time", true));
        mbx_ago(old, 30 * 3600);
        mbx_ago(recent, 3600);
        mbx_ago(two_hours, 2 * 3600);
        ASSERT(now > 30 * 3600);
        mbx_cat(outcomes, sizeof(outcomes),
            "{\"seq\":1,\"ts\":\"%s\",\"tip\":\"%s\",\"state\":\"landed\",\"attempt\":1,\"landed_at\":%lld}\n",
            old, MBX_TIP_A, now - 120);
        mbx_cat(outcomes, sizeof(outcomes),
            "{\"seq\":2,\"ts\":\"%s\",\"tip\":\"%s\",\"state\":\"landed\",\"attempt\":1,\"landed_at\":%lld}\n",
            recent, MBX_TIP_B, now - 30 * 3600);
        mbx_lrow(outcomes, sizeof(outcomes), 3, MBX_TIP_C, "landed", 3600, "");
        mbx_cat(outcomes, sizeof(outcomes),
            "{\"seq\":4,\"ts\":\"%s\",\"tip\":\"%s\",\"state\":\"landed\",\"attempt\":1,\"landed_at\":0}\n",
            two_hours, MBX_TIP_B);
        mbx_cat(outcomes, sizeof(outcomes),
            "{\"seq\":5,\"ts\":\"%s\",\"tip\":\"%s\",\"state\":\"failed\",\"attempt\":1,\"dimension\":\"failed-recent\",\"landed_at\":%lld}\n",
            recent, MBX_TIP_A, now - 120);
        mbx_cat(outcomes, sizeof(outcomes),
            "{\"seq\":6,\"ts\":\"%s\",\"tip\":\"%s\",\"state\":\"failed\",\"attempt\":1,\"dimension\":\"failed-old\",\"landed_at\":%lld}\n",
            old, MBX_TIP_C, now - 120);
        ASSERT(mbx_write("land", "outcomes.jsonl", outcomes));
        ASSERT(mbx_run(&c, 24, -1) && mbx_ok(&c));
        ASSERT_EQ(mbx_count(&c, "LANDED"), 3);
        ASSERT(mbx_has_card(&c, "LANDED", "#1 aaaaaaaa landed 2m"));
        ASSERT(!mbx_has_card(&c, "LANDED", "#2 bbbbbbbb"));
        ASSERT(mbx_has_card(&c, "LANDED", "#3 cccccccc landed 1h"));
        ASSERT(mbx_has_card(&c, "LANDED", "#4 bbbbbbbb landed 2h"));
        ASSERT_EQ(mbx_count(&c, "FAILED"), 1);
        ASSERT(mbx_has_card(&c, "FAILED", "#5 aaaaaaaa failed-recent 1h"));
        ASSERT(!mbx_has_card(&c, "FAILED", "failed-old"));
        mbx_end(&c);
        mbx_restore();
        PASS();
    } _test_next:;
    mbx_restore();
    return failures;
}

static int mbx_bad_landed_time(void)
{
    int failures = 0;
    TEST("mission board: non-root or non-integer landing times use submission time") {
        static char outcomes[4096];
        struct mbx_call c;
        char ts[32];
        long long now = (long long)platform_time_wall_time_t();
        outcomes[0] = '\0';
        ASSERT(mbx_isolate("bad-landed-time", true));
        mbx_ago(ts, 3600);
        ASSERT(now > 120);
        mbx_cat(outcomes, sizeof(outcomes),
            "{\"seq\":11,\"ts\":\"%s\",\"tip\":\"%s\",\"state\":\"landed\",\"attempt\":1,\"landed_at\":%lld.5}\n",
            ts, MBX_TIP_A, now - 120);
        mbx_cat(outcomes, sizeof(outcomes),
            "{\"seq\":12,\"ts\":\"%s\",\"tip\":\"%s\",\"state\":\"landed\",\"attempt\":1,\"landed_at\":\"%lld\"}\n",
            ts, MBX_TIP_B, now - 120);
        mbx_cat(outcomes, sizeof(outcomes),
            "{\"seq\":13,\"ts\":\"%s\",\"tip\":\"%s\",\"state\":\"landed\",\"attempt\":1,\"failed_proof_root\":{\"landed_at\":%lld}}\n",
            ts, MBX_TIP_C, now - 120);
        ASSERT(mbx_write("land", "outcomes.jsonl", outcomes));
        ASSERT(mbx_run(&c, 24, -1) && mbx_ok(&c));
        ASSERT_EQ(mbx_count(&c, "LANDED"), 3);
        ASSERT(mbx_has_card(&c, "LANDED", "#11 aaaaaaaa landed 1h"));
        ASSERT(mbx_has_card(&c, "LANDED", "#12 bbbbbbbb landed 1h"));
        ASSERT(mbx_has_card(&c, "LANDED", "#13 cccccccc landed 1h"));
        mbx_end(&c);
        mbx_restore();
        PASS();
    } _test_next:;
    mbx_restore();
    return failures;
}

int test_fleet_mission_board(void);
int test_fleet_mission_board(void)
{
    int failures = 0;
    failures += mbx_case_1();
    failures += mbx_case_2();
    failures += mbx_case_3();
    failures += mbx_landed_time();
    failures += mbx_bad_landed_time();
    failures += mbx_case_4();
    failures += mbx_case_5();
    failures += mbx_case_6();
    failures += mbx_case_7();
    if (failures == 0)
        printf("test_fleet_mission_board: all passed\n");
    else
        printf("test_fleet_mission_board: %d FAILED\n", failures);
    return failures;
}
