/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.fleet.start (tools/command/native_dev_fleet_start.c).
 *
 * Written against fixtures built here — a throwaway Git repository with a bare
 * origin and three linked worktrees, and a throwaway board directory — never
 * against the checkout it runs in, so it proves BEHAVIOUR rather than the
 * state of this machine.
 *
 * It calls the bound handler DIRECTLY: dev.fleet.start is a dev-lane leaf and
 * an in-process call is exactly what the CLI does after input validation, so
 * the input keys are additionally validated through the real registry. That
 * matters more here than for most leaves: `include_units` is a bool, and the
 * transport's per-key type chain is the reason it is not named `units`.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_dev_fleet.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FSX_PATH "dev.fleet.start"

/* ── fixture helpers (deliberately local: this group owns its own rig) ──── */

/* Run one git command in `dir`. Never a shell: zcl_spawn_capture execs git
 * itself, which is the only process rail this tree allows. */
static bool fsx_git(const char *dir, const char *const args[])
{
    const char *argv[32];
    size_t n = 0;
    argv[n++] = "git";
    argv[n++] = "-C";
    argv[n++] = dir;
    for (size_t i = 0; args[i]; i++) {
        if (n + 1 >= sizeof(argv) / sizeof(argv[0]))
            return false;
        argv[n++] = args[i];
    }
    argv[n] = NULL;
    char out[16384];
    return zcl_spawn_capture(argv, out, sizeof(out), 60000) == 0;
}

static bool fsx_write(const char *dir, const char *rel, const char *text)
{
    char path[1024];
    if (snprintf(path, sizeof(path), "%s/%s", dir, rel) < 0)
        return false;
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    size_t len = strlen(text);
    bool wrote = fwrite(text, 1, len, f) == len;
    return fclose(f) == 0 && wrote;
}

static bool fsx_append(const char *dir, const char *rel, const char *text)
{
    char path[1024];
    if (snprintf(path, sizeof(path), "%s/%s", dir, rel) < 0)
        return false;
    FILE *f = fopen(path, "ab");
    if (!f)
        return false;
    size_t len = strlen(text);
    bool wrote = fwrite(text, 1, len, f) == len;
    return fclose(f) == 0 && wrote;
}

/* Committing needs an identity and no signing: the runner's own Git config
 * must not decide whether this group passes. */
#define FSX_ID                                                               \
    "-c", "user.name=Z23 Test", "-c", "user.email=z23-test@example.invalid", \
        "-c", "commit.gpgsign=false"

static bool fsx_commit(const char *dir, const char *message)
{
    const char *add[] = {"add", "-A", NULL};
    const char *commit[] = {FSX_ID, "commit", "-q", "-m", message, NULL};
    return fsx_git(dir, add) && fsx_git(dir, commit);
}

/* ── one in-process invocation ─────────────────────────────────────────── */

struct fsx_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void fsx_begin(struct fsx_call *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), FSX_PATH, NULL);
    zcl_command_reply_init(&c->reply, "zcl.fleet_start.v1");
}

/* Validate through the REAL registry first, so a key the .def never declared
 * — or one the transport's type chain refuses — is caught here rather than
 * passing in-process and failing from a shell. */
static bool fsx_run(struct fsx_call *c)
{
    char why[192];
    if (c->request.spec &&
        !zcl_command_registry_input_validate(c->request.spec, &c->input, why,
                                             sizeof(why))) {
        printf("[input rejected: %s] ", why);
        return false;
    }
    zcl_native_handle_dev_fleet_start(&c->request, &c->reply);
    return true;
}

static void fsx_end(struct fsx_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool fsx_ok(const struct fsx_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static const char *fsx_code(const struct fsx_call *c)
{
    return c->reply.error.code;
}

static const struct json_value *fsx_sec(const struct fsx_call *c,
                                        const char *section)
{
    const struct json_value *v = json_get(&c->reply.data, section);
    return v && v->type == JSON_OBJ ? v : NULL;
}

static const char *fsx_sec_str(const struct fsx_call *c, const char *section,
                               const char *key)
{
    const struct json_value *o = fsx_sec(c, section);
    const struct json_value *v = o ? json_get(o, key) : NULL;
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}

static int64_t fsx_sec_int(const struct fsx_call *c, const char *section,
                           const char *key)
{
    const struct json_value *o = fsx_sec(c, section);
    const struct json_value *v = o ? json_get(o, key) : NULL;
    return v && v->type == JSON_INT ? json_get_int(v) : -424242;
}

static bool fsx_sec_bool(const struct fsx_call *c, const char *section,
                         const char *key)
{
    const struct json_value *o = fsx_sec(c, section);
    const struct json_value *v = o ? json_get(o, key) : NULL;
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

static const struct json_value *fsx_rows(const struct fsx_call *c,
                                         const char *section)
{
    const struct json_value *o = fsx_sec(c, section);
    const struct json_value *v = o ? json_get(o, "rows") : NULL;
    return v && v->type == JSON_ARR ? v : NULL;
}

static const char *fsx_row_str(const struct json_value *rows, size_t i,
                               const char *key)
{
    const struct json_value *row = rows ? json_at(rows, i) : NULL;
    const struct json_value *v = row ? json_get(row, key) : NULL;
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}

static int64_t fsx_row_int(const struct json_value *rows, size_t i,
                           const char *key)
{
    const struct json_value *row = rows ? json_at(rows, i) : NULL;
    const struct json_value *v = row ? json_get(row, key) : NULL;
    return v && v->type == JSON_INT ? json_get_int(v) : -424242;
}

/* Find the worktrees row whose `name` ends with `suffix`, or SIZE_MAX. */
static size_t fsx_row_by_name(const struct json_value *rows,
                              const char *suffix)
{
    if (!rows)
        return (size_t)-1;
    for (size_t i = 0; i < rows->num_children; i++) {
        const char *name = fsx_row_str(rows, i, "name");
        size_t nl = strlen(name), sl = strlen(suffix);
        if (nl >= sl && strcmp(name + nl - sl, suffix) == 0)
            return i;
    }
    return (size_t)-1;
}

/* The whole reply data as one string, for the "no operator path" check. */
static size_t fsx_serialize(const struct fsx_call *c, char *buf, size_t cap)
{
    return json_write(&c->reply.data, buf, cap);
}

/* ── the fixtures ───────────────────────────────────────────────────────── */

/* A bare origin, a main clone, and three linked worktrees: one clean at
 * origin/main, one two commits ahead, one dirty. This is the shape the leaf
 * exists to summarize, at three rows instead of 276. */
static bool fsx_repo_fixture(const char *root, char *main_dir, size_t cap)
{
    char origin[1024], clean[1024], ahead[1024], dirty[1024];
    (void)snprintf(origin, sizeof(origin), "%s/origin.git", root);
    (void)snprintf(main_dir, cap, "%s/main", root);
    (void)snprintf(clean, sizeof(clean), "%s/wt-clean", root);
    (void)snprintf(ahead, sizeof(ahead), "%s/wt-ahead", root);
    (void)snprintf(dirty, sizeof(dirty), "%s/wt-dirty", root);

    {
        const char *init[] = {"-c", "init.defaultBranch=main", "init", "-q",
                              "--bare", origin, NULL};
        const char *argv[] = {"git", init[0], init[1], init[2], init[3],
                              init[4], init[5], NULL};
        char out[4096];
        if (zcl_spawn_capture(argv, out, sizeof(out), 60000) != 0)
            return false;
    }
    {
        const char *argv[] = {"git",   "-c", "init.defaultBranch=main",
                              "clone", "-q", origin,
                              main_dir, NULL};
        char out[4096];
        if (zcl_spawn_capture(argv, out, sizeof(out), 60000) != 0)
            return false;
    }
    {
        const char *checkout[] = {"checkout", "-q", "-b", "main", NULL};
        const char *push[] = {"push", "-q", "-u", "origin", "main", NULL};
        if (!fsx_git(main_dir, checkout) ||
            !fsx_write(main_dir, "a.c", "int a(void){return 1;}\n") ||
            !fsx_commit(main_dir, "base") || !fsx_git(main_dir, push))
            return false;
    }
    {
        const char *add_clean[] = {"worktree", "add", "-q", "--detach", clean,
                                   "origin/main", NULL};
        const char *add_ahead[] = {"worktree", "add", "-q", "-b", "lane/ahead",
                                   ahead, "origin/main", NULL};
        const char *add_dirty[] = {"worktree", "add", "-q", "-b", "lane/dirty",
                                   dirty, "origin/main", NULL};
        if (!fsx_git(main_dir, add_clean) || !fsx_git(main_dir, add_ahead) ||
            !fsx_git(main_dir, add_dirty))
            return false;
    }
    /* Two commits ahead of origin/main, and nothing else. */
    if (!fsx_write(ahead, "b.c", "int b(void){return 2;}\n") ||
        !fsx_commit(ahead, "ahead one") ||
        !fsx_write(ahead, "c.c", "int c(void){return 3;}\n") ||
        !fsx_commit(ahead, "ahead two"))
        return false;
    /* One tracked edit and one untracked file: two porcelain rows. */
    if (!fsx_write(dirty, "a.c", "int a(void){return 99;}\n") ||
        !fsx_write(dirty, "untracked.c", "int u(void){return 0;}\n"))
        return false;
    return true;
}

#define FSX_ROW(ts_, id_, host_, agent_, kind_, ref_, text_)                 \
    "{\"ts\":\"" ts_ "\",\"id\":\"" id_ "\",\"host\":\"" host_              \
    "\",\"agent\":\"" agent_ "\",\"kind\":\"" kind_ "\",\"ref\":\"" ref_    \
    "\",\"text\":\"" text_ "\"}\n"

/* Two host files. alpha carries an unanswered need, an answered need and an
 * automated offer; beta carries a problem and a post by the OTHER automated
 * agent. Unanswered must be exactly two. */
static bool fsx_board_fixture(const char *dir)
{
    if (mkdir(dir, 0700) != 0)
        return false;
    if (!fsx_write(dir, "alpha.jsonl",
                   FSX_ROW("2026-09-05T01:00:00Z", "20260905T010000-alpha-1",
                           "alpha", "lane-one", "need", "",
                           "alpha needs a reviewer for the sync lane")
                   FSX_ROW("2026-09-05T01:10:00Z", "20260905T011000-alpha-2",
                           "alpha", "lane-two", "need", "",
                           "alpha needs a proof slot")
                   FSX_ROW("2026-09-05T01:20:00Z", "20260905T012000-alpha-3",
                           "alpha", "lane-three", "result",
                           "20260905T011000-alpha-2", "took the proof slot")
                   FSX_ROW("2026-09-05T01:30:00Z", "20260905T013000-alpha-4",
                           "alpha", "board-cpu", "offer", "",
                           "cpu: alpha load 1.00 of 8 cores, ~7 free")))
        return false;
    if (!fsx_write(dir, "beta.jsonl",
                   FSX_ROW("2026-09-05T02:00:00Z", "20260905T020000-beta-1",
                           "beta", "lane-four", "problem", "",
                           "beta cannot link Tor")
                   FSX_ROW("2026-09-05T02:10:00Z", "20260905T021000-beta-2",
                           "beta", "z23 front page", "need", "",
                           "an automated need nobody should be asked to answer")
                   FSX_ROW("2026-09-05T02:20:00Z", "20260905T022000-beta-3",
                           "beta", "board-cpu", "offer", "",
                           "cpu: beta load 4.00 of 32 cores, ~28 free")))
        return false;
    return true;
}

int test_dev_fleet_start(void);
int test_dev_fleet_start(void)
{
    int failures = 0;
    char root[512], main_dir[1024], board[1024], cursor[256] = "";
    test_make_tmpdir(root, sizeof(root), "dev_fleet_start", "fixture");
    (void)snprintf(board, sizeof(board), "%s/board", root);

    TEST("start: the leaf is registered under a dev.fleet MENU with truth") {
        const struct zcl_command_registry *reg = zcl_command_catalog();
        const struct zcl_command_spec *start =
            zcl_command_registry_find(reg, FSX_PATH, NULL);
        const struct zcl_command_spec *truth =
            zcl_command_registry_find(reg, "dev.fleet.truth", NULL);
        ASSERT(start != NULL);
        ASSERT(start->handler != NULL);
        /* The old surface must still be reachable: turning dev.fleet into a
         * branch is only safe because `truth` inherits its behaviour. */
        ASSERT(truth != NULL);
        ASSERT(truth->handler != NULL);
        ASSERT(start->input_keys &&
               strstr(start->input_keys, "since") != NULL);
        ASSERT(start->input_keys &&
               strstr(start->input_keys, "budget_bytes") != NULL);
        ASSERT(start->input_keys &&
               strstr(start->input_keys, "board_dir") != NULL);
        ASSERT(start->input_keys &&
               strstr(start->input_keys, "include_units") != NULL);
        PASS();
    }

    ASSERT(fsx_repo_fixture(root, main_dir, sizeof(main_dir)));
    ASSERT(fsx_board_fixture(board));
    ASSERT(chdir(main_dir) == 0);

    /* (a) three worktrees, their ahead and dirty counts, and stale */
    TEST("start: the three worktrees arrive with their ahead and dirty counts") {
        struct fsx_call c;
        fsx_begin(&c);
        (void)json_push_kv_str(&c.input, "board_dir", board);
        (void)json_push_kv_bool(&c.input, "include_units", false);
        ASSERT(fsx_run(&c));
        ASSERT(fsx_ok(&c));
        const struct json_value *rows = fsx_rows(&c, "worktrees");
        ASSERT(rows != NULL);
        /* main plus the three linked worktrees. */
        ASSERT_EQ(fsx_sec_int(&c, "worktrees", "total"), 4);
        size_t clean = fsx_row_by_name(rows, "wt-clean");
        size_t ahead = fsx_row_by_name(rows, "wt-ahead");
        size_t dirty = fsx_row_by_name(rows, "wt-dirty");
        ASSERT(clean != (size_t)-1);
        ASSERT(ahead != (size_t)-1);
        ASSERT(dirty != (size_t)-1);
        ASSERT_EQ(fsx_row_int(rows, clean, "ahead"), 0);
        ASSERT_EQ(fsx_row_int(rows, clean, "dirty"), 0);
        ASSERT_EQ(fsx_row_int(rows, ahead, "ahead"), 2);
        ASSERT_EQ(fsx_row_int(rows, ahead, "behind"), 0);
        ASSERT_EQ(fsx_row_int(rows, dirty, "dirty"), 2);
        ASSERT_EQ(fsx_row_int(rows, dirty, "ahead"), 0);
        /* Nothing has moved on origin/main, so this checkout is current. */
        ASSERT(!fsx_sec_bool(&c, "checkout", "stale"));
        ASSERT_EQ(fsx_sec_int(&c, "checkout", "behind"), 0);
        fsx_end(&c);
        PASS();
    }

    /* (b) the board: unanswered rows and host offers */
    TEST("start: an answered need is not unanswered, and bots are excluded") {
        struct fsx_call c;
        fsx_begin(&c);
        (void)json_push_kv_str(&c.input, "board_dir", board);
        (void)json_push_kv_bool(&c.input, "include_units", false);
        ASSERT(fsx_run(&c));
        ASSERT(fsx_ok(&c));
        /* alpha-1 (need, never referenced) and beta-1 (problem). alpha-2 was
         * answered by a later result; the two automated agents' rows never
         * count however they are shaped. */
        ASSERT_EQ(fsx_sec_int(&c, "board", "unanswered"), 2);
        const struct json_value *rows = fsx_rows(&c, "board");
        ASSERT(rows != NULL);
        ASSERT_EQ((long long)rows->num_children, 2);
        /* Newest first. */
        ASSERT_STR_EQ(fsx_row_str(rows, 0, "id"), "20260905T020000-beta-1");
        ASSERT_STR_EQ(fsx_row_str(rows, 1, "id"), "20260905T010000-alpha-1");
        for (size_t i = 0; i < rows->num_children; i++) {
            ASSERT(strcmp(fsx_row_str(rows, i, "agent"), "board-cpu") != 0);
            ASSERT(strcmp(fsx_row_str(rows, i, "agent"),
                          "z23 front page") != 0);
        }
        /* Hosts: one row per file, each carrying its last posted offer. */
        const struct json_value *hosts = fsx_rows(&c, "hosts");
        ASSERT(hosts != NULL);
        ASSERT_EQ((long long)hosts->num_children, 2);
        size_t alpha = strcmp(fsx_row_str(hosts, 0, "host"), "alpha") == 0
                           ? 0 : 1;
        ASSERT(strstr(fsx_row_str(hosts, alpha, "offer"),
                      "load 1.00 of 8 cores") != NULL);
        ASSERT_STR_EQ(fsx_row_str(hosts, alpha, "offer_ts"),
                      "2026-09-05T01:30:00Z");
        /* The last post by a NON-automated agent, which is not the offer. */
        ASSERT_STR_EQ(fsx_row_str(hosts, alpha, "last_agent_ts"),
                      "2026-09-05T01:20:00Z");
        /* The cursor is opaque to a caller, but it must at least be a
         * non-empty tagged string this leaf will take back. */
        (void)snprintf(cursor, sizeof(cursor), "%s",
                       json_get_str(json_get(&c.reply.data, "cursor")));
        ASSERT(strncmp(cursor, "z23fs1.", 7) == 0);
        ASSERT(strstr(cursor, "20260905T022000-beta-3") != NULL);
        fsx_end(&c);
        PASS();
    }

    /* (f) no operator path is anywhere in the serialized packet */
    TEST("start: no absolute home path survives into the packet") {
        struct fsx_call c;
        static char buf[262144];
        fsx_begin(&c);
        (void)json_push_kv_str(&c.input, "board_dir", board);
        (void)json_push_kv_bool(&c.input, "include_units", false);
        ASSERT(fsx_run(&c));
        ASSERT(fsx_ok(&c));
        size_t n = fsx_serialize(&c, buf, sizeof(buf));
        ASSERT(n > 0);
        /* The fixture lives under the runner's home, so every path this
         * packet quotes had to be rendered through the ~ form. A packet an
         * agent pastes into a commit or a document is exactly how an
         * operator path reaches a tracked file. */
        ASSERT(strstr(buf, "/home/") == NULL);
        ASSERT(strstr(buf, "/Users/") == NULL);
        ASSERT(strstr(buf, "~/") != NULL);
        fsx_end(&c);
        PASS();
    }

    /* (g) the declared latency budget holds */
    TEST("start: the declared latency budget holds on the fixture") {
        struct fsx_call c;
        fsx_begin(&c);
        (void)json_push_kv_str(&c.input, "board_dir", board);
        (void)json_push_kv_bool(&c.input, "include_units", false);
        ASSERT(fsx_run(&c));
        ASSERT(fsx_ok(&c));
        const struct json_value *v =
            json_get(&c.reply.data, "budget_exceeded");
        ASSERT(v && v->type == JSON_BOOL && !json_get_bool(v));
        /* The declared class, reported so a caller can judge a slow answer
         * without reading the .def. */
        const struct json_value *b =
            json_get(&c.reply.data, "latency_budget_ms");
        ASSERT(b && b->type == JSON_INT && json_get_int(b) > 0);
        fsx_end(&c);
        PASS();
    }

    /* (e) a missing board dir is unavailable with a reason, not a failure */
    TEST("start: a board directory that is not there is unavailable, not fatal") {
        struct fsx_call c;
        char missing[1024];
        (void)snprintf(missing, sizeof(missing), "%s/no-such-board", root);
        fsx_begin(&c);
        (void)json_push_kv_str(&c.input, "board_dir", missing);
        (void)json_push_kv_bool(&c.input, "include_units", false);
        ASSERT(fsx_run(&c));
        /* The command still SUCCEEDS: an orchestrator without a board still
         * needs its checkout, its worktrees and its next action. */
        ASSERT(fsx_ok(&c));
        ASSERT_STR_EQ(fsx_sec_str(&c, "board", "state"), "unavailable");
        ASSERT(fsx_sec_str(&c, "board", "reason")[0] != '\0');
        ASSERT_STR_EQ(fsx_sec_str(&c, "hosts", "state"), "unavailable");
        ASSERT_STR_EQ(fsx_sec_str(&c, "worktrees", "state"), "observed");
        /* include_units=false is unobserved, and says which of the two
         * reasons it was. */
        ASSERT_STR_EQ(fsx_sec_str(&c, "units", "state"), "unobserved");
        ASSERT_STR_EQ(fsx_sec_str(&c, "units", "reason"),
                      "include_units=false");
        fsx_end(&c);
        PASS();
    }

    /* (d) budget */
    TEST("start: a 1024-byte packet stays inside 1024 bytes and says what it cut") {
        struct fsx_call c;
        fsx_begin(&c);
        (void)json_push_kv_str(&c.input, "board_dir", board);
        (void)json_push_kv_bool(&c.input, "include_units", false);
        (void)json_push_kv_int(&c.input, "budget_bytes", 1024);
        ASSERT(fsx_run(&c));
        ASSERT(fsx_ok(&c));
        const struct json_value *bytes = json_get(&c.reply.data, "bytes");
        ASSERT(bytes && bytes->type == JSON_INT);
        ASSERT(json_get_int(bytes) <= 1024);
        /* At least one section says it was cut, and names how many rows it
         * had — a dropped row that says nothing is the failure this whole
         * budget mechanism exists to prevent. */
        static const char *const sections[] = {
            "checkout", "mission", "worktrees", "units",
            "hosts",    "board",   "main",      "next", NULL};
        bool saw_truncated = false;
        for (size_t i = 0; sections[i]; i++) {
            if (!fsx_sec(&c, sections[i]))
                continue;
            if (!fsx_sec_bool(&c, sections[i], "truncated"))
                continue;
            saw_truncated = true;
            ASSERT(fsx_sec_int(&c, sections[i], "total") >=
                   fsx_sec_int(&c, sections[i], "count"));
        }
        ASSERT(saw_truncated);
        fsx_end(&c);
        PASS();
    }

    TEST("start: a budget outside the declared range is refused by name") {
        struct fsx_call c;
        fsx_begin(&c);
        (void)json_push_kv_int(&c.input, "budget_bytes", 64);
        ASSERT(fsx_run(&c));
        ASSERT(!fsx_ok(&c));
        ASSERT_STR_EQ(fsx_code(&c), "budget_out_of_range");
        fsx_end(&c);

        fsx_begin(&c);
        (void)json_push_kv_int(&c.input, "budget_bytes", 1000000);
        ASSERT(fsx_run(&c));
        ASSERT(!fsx_ok(&c));
        ASSERT_STR_EQ(fsx_code(&c), "budget_out_of_range");
        fsx_end(&c);
        PASS();
    }

    /* (c) cursor */
    TEST("start: a cursor this leaf never issued is refused by name") {
        struct fsx_call c;
        fsx_begin(&c);
        (void)json_push_kv_str(&c.input, "since", "not-a-cursor");
        ASSERT(fsx_run(&c));
        ASSERT(!fsx_ok(&c));
        ASSERT_STR_EQ(fsx_code(&c), "cursor_invalid");
        fsx_end(&c);

        /* Right tag, wrong shape: three fields instead of four. */
        fsx_begin(&c);
        (void)json_push_kv_str(&c.input, "since", "z23fs1.abc.def");
        ASSERT(fsx_run(&c));
        ASSERT(!fsx_ok(&c));
        ASSERT_STR_EQ(fsx_code(&c), "cursor_invalid");
        fsx_end(&c);

        /* Right shape, non-numeric time. */
        fsx_begin(&c);
        (void)json_push_kv_str(&c.input, "since", "z23fs1.a.b.later");
        ASSERT(fsx_run(&c));
        ASSERT(!fsx_ok(&c));
        ASSERT_STR_EQ(fsx_code(&c), "cursor_invalid");
        fsx_end(&c);
        PASS();
    }

    TEST("start: with a cursor, only what changed since it comes back") {
        /* A worktree's change signal is a file mtime, and a file mtime has
         * one-second granularity — so this fixture must put the fixture's
         * own writes, the cursor, and the change it wants to see in THREE
         * different seconds. That is what the two waits buy, and it is the
         * only place in this group where wall time is load-bearing. */
        struct fsx_call c;
        char fresh[256];
        sleep(1);
        fsx_begin(&c);
        (void)json_push_kv_str(&c.input, "board_dir", board);
        (void)json_push_kv_bool(&c.input, "include_units", false);
        ASSERT(fsx_run(&c));
        ASSERT(fsx_ok(&c));
        (void)snprintf(fresh, sizeof(fresh), "%s",
                       json_get_str(json_get(&c.reply.data, "cursor")));
        ASSERT(fresh[0] != '\0');
        fsx_end(&c);
        sleep(1);

        /* One newer board row, and one worktree touched after the cursor. */
        ASSERT(fsx_append(board, "beta.jsonl",
                          FSX_ROW("2026-09-06T03:00:00Z",
                                  "20260906T030000-beta-9", "beta",
                                  "lane-five", "problem", "",
                                  "beta lost its onion identity again")));
        char ahead_dir[1024];
        (void)snprintf(ahead_dir, sizeof(ahead_dir), "%s/wt-ahead", root);
        ASSERT(fsx_write(ahead_dir, "d.c", "int d(void){return 4;}\n"));
        ASSERT(fsx_commit(ahead_dir, "ahead three"));

        fsx_begin(&c);
        (void)json_push_kv_str(&c.input, "board_dir", board);
        (void)json_push_kv_bool(&c.input, "include_units", false);
        (void)json_push_kv_str(&c.input, "since", fresh);
        ASSERT(fsx_run(&c));
        ASSERT(fsx_ok(&c));

        /* Exactly the one new problem — the two older unanswered rows are
         * the caller's already. */
        ASSERT_EQ(fsx_sec_int(&c, "board", "unanswered"), 1);
        const struct json_value *rows = fsx_rows(&c, "board");
        ASSERT(rows != NULL);
        ASSERT_EQ((long long)rows->num_children, 1);
        ASSERT_STR_EQ(fsx_row_str(rows, 0, "id"), "20260906T030000-beta-9");

        /* Only the worktree that moved. */
        const struct json_value *wts = fsx_rows(&c, "worktrees");
        ASSERT(wts != NULL);
        ASSERT_EQ((long long)wts->num_children, 1);
        ASSERT(fsx_row_by_name(wts, "wt-ahead") == 0);
        ASSERT_EQ(fsx_row_int(wts, 0, "ahead"), 3);
        fsx_end(&c);
        PASS();
    }

    /* (a, second half) origin/main moves and the checkout goes stale */
    TEST("start: when origin/main moves ahead, the checkout says it is stale") {
        char ahead_dir[1024];
        const char *push[] = {"push", "-q", "origin", "HEAD:main", NULL};
        const char *fetch[] = {"fetch", "-q", "origin", NULL};
        (void)snprintf(ahead_dir, sizeof(ahead_dir), "%s/wt-ahead", root);
        /* Publish exactly one commit past the base, then let the main
         * worktree SEE it: the leaf never fetches, so the fixture must. */
        {
            const char *reset[] = {"push", "-q", "origin",
                                   "lane/ahead~2:main", NULL};
            ASSERT(fsx_git(ahead_dir, reset));
        }
        (void)push;
        ASSERT(fsx_git(main_dir, fetch));

        struct fsx_call c;
        fsx_begin(&c);
        (void)json_push_kv_str(&c.input, "board_dir", board);
        (void)json_push_kv_bool(&c.input, "include_units", false);
        ASSERT(fsx_run(&c));
        ASSERT(fsx_ok(&c));
        ASSERT(fsx_sec_bool(&c, "checkout", "stale"));
        ASSERT_EQ(fsx_sec_int(&c, "checkout", "behind"), 1);
        /* A stale checkout is the FIRST thing to do, and the packet says so
         * with a command, not an adjective. */
        const struct json_value *next = fsx_rows(&c, "next");
        ASSERT(next != NULL);
        ASSERT(next->num_children >= 1);
        ASSERT(strstr(fsx_row_str(next, 0, "command"), "rebase") != NULL);
        fsx_end(&c);
        PASS();
    }

_test_next:;
    (void)test_rm_rf_recursive(root);
    if (failures == 0) printf("test_dev_fleet_start: all passed\n");
    else printf("test_dev_fleet_start: %d FAILED\n", failures);
    return failures;
}
