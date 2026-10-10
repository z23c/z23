/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Acceptance tests for dev.agent.mail (tools/command/native_devagent_mail.c),
 * run against an isolated platform state root, never the real state dir.
 *
 * It calls the bound handler DIRECTLY: dev.agent.mail is a dev-lane leaf and
 * an in-process call is exactly what the CLI does after input validation, so
 * the input keys are additionally validated through the real registry. No
 * case here touches the network, sleeps, or polls: post returns the row,
 * pull returns what is already on disk, ack records the cursor.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_devagent.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "zutf8/zutf8.h"
#include "kernel/command_registry.h"
#include "platform/private_directory.h"
#include "platform/state_root.h"

#include <limits.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <dirent.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#define DVX_PATH "dev.agent.mail"

/* ── isolated state root (this group owns its own rig) ─────────────────── */

static char g_dvx_state[1024];
static bool g_dvx_had_root;
static bool g_dvx_isolated;
static unsigned g_dvx_after_probe_calls;
#if defined(_WIN32)
static wchar_t g_dvx_saved_root[32768];
#else
static char g_dvx_saved_root[4096];
#endif

static void dvx_fixture_fail(const char *context)
{
    fprintf(stderr, "devagent_mail fixture: %s\n", context);
    abort();
}

/* Save the ambient state-root environment variable and point it at the
 * isolated fixture directory, per platform. Split out of dvx_isolate() so
 * that function's own complexity does not fold both platforms' branches
 * together. */
#if defined(_WIN32)
static void dvx_isolate_env(const char *state)
{
    wchar_t root[1024];
    g_dvx_saved_root[0] = L'\0';
    SetLastError(ERROR_SUCCESS);
    DWORD length = GetEnvironmentVariableW(L"ZCL_STATE_ROOT", g_dvx_saved_root,
                                           32768);
    DWORD error = GetLastError();
    if (length >= 32768 || (length == 0 && error != ERROR_SUCCESS &&
                            error != ERROR_ENVVAR_NOT_FOUND))
        dvx_fixture_fail("could not preserve ZCL_STATE_ROOT");
    g_dvx_had_root = length > 0 || error == ERROR_SUCCESS;
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, state, -1,
                            root, 1024) <= 0 ||
        !SetEnvironmentVariableW(L"ZCL_STATE_ROOT", root))
        dvx_fixture_fail("could not isolate ZCL_STATE_ROOT");
}
#else
static void dvx_isolate_env(const char *state)
{
    const char *original = getenv("XDG_STATE_HOME");
    g_dvx_had_root = original != NULL;
    if (original) {
        int n = snprintf(g_dvx_saved_root, sizeof(g_dvx_saved_root), "%s",
                         original);
        if (n < 0 || (size_t)n >= sizeof(g_dvx_saved_root))
            dvx_fixture_fail("could not preserve XDG_STATE_HOME");
    }
    if (setenv("XDG_STATE_HOME", state, 1) != 0)
        dvx_fixture_fail("could not isolate XDG_STATE_HOME");
}
#endif

static void dvx_isolate(const char *tag)
{
    char base[512];
    if (g_dvx_isolated)
        dvx_fixture_fail("previous state root has not been restored");
    test_make_tmpdir(base, sizeof(base), "devagent_mail", tag);
    int n = snprintf(g_dvx_state, sizeof(g_dvx_state), "%s/state", base);
    if (n <= 0 || (size_t)n >= sizeof(g_dvx_state) ||
        !platform_private_directory_ensure(g_dvx_state))
        dvx_fixture_fail("could not create isolated state parent");
    dvx_isolate_env(g_dvx_state);
    g_dvx_isolated = true;
}

static void dvx_restore(void)
{
    if (!g_dvx_isolated) return;
#if defined(_WIN32)
    if (!SetEnvironmentVariableW(L"ZCL_STATE_ROOT",
                                 g_dvx_had_root ? g_dvx_saved_root : NULL))
        dvx_fixture_fail("could not restore ZCL_STATE_ROOT");
#else
    int rc = g_dvx_had_root ? setenv("XDG_STATE_HOME", g_dvx_saved_root, 1)
                            : unsetenv("XDG_STATE_HOME");
    if (rc != 0)
        dvx_fixture_fail("could not restore XDG_STATE_HOME");
#endif
    g_dvx_isolated = false;
}

static void dvx_maildir(char *out, size_t cap)
{
    (void)snprintf(out, cap, "%s/z23/dev/mail", g_dvx_state);
}

/* ── one in-process invocation ─────────────────────────────────────────── */

struct dvx_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void dvx_begin(struct dvx_call *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), DVX_PATH, NULL);
    zcl_command_reply_init(&c->reply, "zcl.agent_mail.v1");
}

/* Validate through the REAL registry first, so a key the .def never declared
 * is caught here rather than passing in-process and failing from a shell. */
static bool dvx_run_mode(struct dvx_call *c, bool brief_drain)
{
    char why[256];
    if (c->request.spec &&
        !zcl_command_registry_input_validate(c->request.spec, &c->input, why,
                                             sizeof(why))) {
        printf("[input rejected: %s] ", why);
        return false;
    }
    if (brief_drain)
        zcl_native_handle_dev_agent_mail_brief_drain(&c->request, &c->reply);
    else
        zcl_native_handle_dev_agent_mail(&c->request, &c->reply);
    return true;
}

static bool dvx_run(struct dvx_call *c)
{
    return dvx_run_mode(c, false);
}

static void dvx_end(struct dvx_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool dvx_ok(const struct dvx_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static const char *dvx_str(const struct dvx_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}

static int64_t dvx_int(const struct dvx_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_INT ? json_get_int(v) : -1;
}

static const struct json_value *dvx_arr(const struct dvx_call *c,
                                        const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_ARR ? v : NULL;
}

static void dvx_post(struct dvx_call *c, const char *from, const char *to,
                     const char *kind, const char *body)
{
    dvx_begin(c);
    (void)json_push_kv_str(&c->input, "action", "post");
    if (from)
        (void)json_push_kv_str(&c->input, "from", from);
    if (to)
        (void)json_push_kv_str(&c->input, "to", to);
    if (kind)
        (void)json_push_kv_str(&c->input, "kind", kind);
    if (body)
        (void)json_push_kv_str(&c->input, "body", body);
}

static void dvx_pull(struct dvx_call *c, long long since, const char *from,
                     const char *kind)
{
    dvx_begin(c);
    (void)json_push_kv_str(&c->input, "action", "pull");
    (void)json_push_kv_int(&c->input, "since", since);
    if (from)
        (void)json_push_kv_str(&c->input, "from", from);
    if (kind)
        (void)json_push_kv_str(&c->input, "kind", kind);
}

static void dvx_ack(struct dvx_call *c, const char *agent, long long cursor)
{
    dvx_begin(c);
    (void)json_push_kv_str(&c->input, "action", "ack");
    if (agent)
        (void)json_push_kv_str(&c->input, "agent", agent);
    (void)json_push_kv_int(&c->input, "cursor", cursor);
}

/* Refused rows must never reach the outbox: a clean pull returns nothing. */
static bool dvx_outbox_empty(void)
{
    struct dvx_call p;
    const struct json_value *rows;
    bool empty;
    dvx_pull(&p, 0, NULL, NULL);
    if (!dvx_run(&p) || !dvx_ok(&p)) {
        dvx_end(&p);
        return false;
    }
    rows = dvx_arr(&p, "rows");
    empty = rows != NULL && rows->num_children == 0;
    dvx_end(&p);
    return empty;
}

static bool dvx_fresh_pull_unchanged(const char *maildir)
{
    struct dvx_call c;
    struct stat info;
    char root[4096];
    dvx_pull(&c, 0, NULL, NULL);
    bool refused = dvx_run(&c) && !dvx_ok(&c) &&
                   strcmp(c.reply.error.code, "STATE_DIR_FAILED") == 0;
    dvx_end(&c);
    if (!refused || !platform_state_root(root, sizeof(root))) return false;
    dvx_pull(&c, 0, NULL, NULL);
    bool empty = dvx_run(&c) && dvx_ok(&c) && dvx_int(&c, "count") == 0;
    dvx_end(&c);
    return empty && stat(maildir, &info) != 0 && errno == ENOENT;
}

static void dvx_import_stream(const char *name, const char *row)
{
    char maildir[1024], path[1200];
    if (!platform_state_root(path, sizeof(path)))
        dvx_fixture_fail("cannot initialize imported stream root");
    dvx_maildir(maildir, sizeof(maildir));
    if (!platform_private_directory_ensure(maildir))
        dvx_fixture_fail("cannot initialize imported stream directory");
    int n = snprintf(path, sizeof(path), "%s/%s.jsonl", maildir, name);
    if (n <= 0 || (size_t)n >= sizeof(path))
        dvx_fixture_fail("import path exceeds bound");
    FILE *f = fopen(path, "w");
    if (!f) dvx_fixture_fail("cannot create imported stream");
    bool wrote = fputs(row, f) >= 0;
    if (fclose(f) != 0 || !wrote)
        dvx_fixture_fail("cannot finish imported stream");
}

#if !defined(_WIN32)
/* ── admission must not depend on where the process runs ──────────────────
 * One body, several directories, one verdict. Each directory is BOTH chdir()-ed
 * into and passed as the leaf's `cwd` input, because the contract is that
 * neither can move the answer — a mail body crosses hosts, so the bytes
 * alone decide. The refusal must not resolve a checkout root
 * from the process cwd. */

/* Every directory this group judges the same body from: the real checkout,
 * this run's isolated state dir, $HOME, and the filesystem root. Derived at
 * runtime — no operator path is written down here. */
#define DVX_CWDS 4u

static size_t dvx_cwd_table(char table[DVX_CWDS][PATH_MAX])
{
    const char *home = getenv("HOME");
    size_t n = 0;
    char root[PATH_MAX];
    if (zcl_devagent_checkout_root(NULL, root, sizeof(root)))
        (void)snprintf(table[n++], PATH_MAX, "%s", root);
    (void)snprintf(table[n++], PATH_MAX, "%s", g_dvx_state);
    if (home && home[0])
        (void)snprintf(table[n++], PATH_MAX, "%s", home);
    (void)snprintf(table[n++], PATH_MAX, "%s", "/");
    return n;
}

/* One admission verdict: the MAIL_REFUSED_* code, or "" when admitted.
 * Returns false only when the rig could not enter the directory. */
static bool dvx_verdict(const char *body, const char *cwd, char *out,
                        size_t cap)
{
    struct dvx_call c;
    if (chdir(cwd) != 0)
        return false;
    dvx_post(&c, "alice", "probe-sink", "directive", body);
    (void)json_push_kv_str(&c.input, "cwd", cwd);
    if (!dvx_run(&c)) {
        dvx_end(&c);
        return false;
    }
    (void)snprintf(out, cap, "%s",
                   c.reply.error.code[0] ? c.reply.error.code : "");
    dvx_end(&c);
    return true;
}

/* Judge one body from every directory in the table and hand back the single
 * verdict. Fails the caller's assertion if any two disagree. */
static bool dvx_one_verdict(const char *body, char *out, size_t cap)
{
    char table[DVX_CWDS][PATH_MAX];
    char here[PATH_MAX];
    char other[128];
    size_t n = dvx_cwd_table(table), i;
    bool same = true;
    if (!getcwd(here, sizeof(here)))
        return false;
    if (!dvx_verdict(body, table[0], out, cap)) {
         TEST_DISCARD(chdir(here));
        return false;
    }
    for (i = 1; i < n; i++) {
        if (!dvx_verdict(body, table[i], other, sizeof(other))) {
            same = false;
            break;
        }
        if (strcmp(out, other) != 0) {
            printf("[verdict moved: %s gave '%s', %s gave '%s'] ", table[0],
                   out[0] ? out : "<admitted>", table[i],
                   other[0] ? other : "<admitted>");
            same = false;
            break;
        }
    }
    return chdir(here) == 0 && same;
}
#endif /* !defined(_WIN32) */

static bool dvx_cursor_refusal_serializes(const struct dvx_call *call)
{
    if (!call->request.spec) return false;
    struct zcl_command_spec spec = *call->request.spec;
    spec.handler = zcl_native_handle_dev_agent_mail;
    char wire[8192];
    enum zcl_command_exit code;
    size_t len = zcl_command_registry_execute_json(zcl_command_catalog(),
        &spec, NULL, &call->input, false, DVX_PATH, NULL, 0, 0, NULL,
        wire, sizeof(wire), &code);
    struct json_value doc;
    json_init(&doc);
    bool ok = len > 0 && code == ZCL_COMMAND_EXIT_FAILED &&
        json_read(&doc, wire, len);
    const struct json_value *error = json_get(&doc, "error");
    const char *error_code = json_get_str(json_get(error, "code"));
    const char *action = json_get_str(json_get(error, "next_action"));
    ok = ok && error_code && strcmp(error_code, "MAIL_CURSOR_AMBIGUOUS") == 0 &&
        action && strcmp(action, "z23-dev dev agent mail pull --since=0") == 0;
    json_free(&doc);
    return ok;
}

/* ── paging: a long history never fails a pull wholesale ─────────────────
 * The live defect: an append-only history of ~130 directive rows made one
 * `pull --since=0` exceed the leaf's response budget, so the CLI answered
 * RESPONSE_BUDGET_EXCEEDED and returned nothing at all. A pull is now one
 * bounded page plus a resume token, and draining the token returns every
 * row exactly once. */

#define DVX_PAGE_ROWS 202u

static void dvx_pull_token(struct dvx_call *c, const char *token,
                           const char *kind)
{
    dvx_begin(c);
    (void)json_push_kv_str(&c->input, "action", "pull");
    (void)json_push_kv_str(&c->input, "since", token);
    if (kind)
        (void)json_push_kv_str(&c->input, "kind", kind);
}

/* Serialize this exact pull through the real registry under the leaf's
 * own declared response budget: the CLI shape that failed before. */
static bool dvx_pull_fits_budget(const struct dvx_call *call)
{
    if (!call->request.spec)
        return false;
    struct zcl_command_spec spec = *call->request.spec;
    spec.handler = zcl_native_handle_dev_agent_mail;
    size_t cap = 65536;
    char *wire = malloc(cap);
    enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
    if (!wire)
        return false;
    size_t len = zcl_command_registry_execute_json(zcl_command_catalog(),
        &spec, NULL, &call->input, false, DVX_PATH, NULL, 0, 0, NULL,
        wire, cap, &code);
    bool ok = len > 0 && code == ZCL_COMMAND_EXIT_OK &&
              strstr(wire, "RESPONSE_BUDGET_EXCEEDED") == NULL &&
              strstr(wire, "\"truncated\":true") != NULL;
    free(wire);
    return ok;
}

/* Mark each row's "row-NNN" body index; false on a duplicate or a body
 * this rig never wrote. */
static bool dvx_mark_rows(const struct json_value *rows, unsigned char *seen,
                          size_t *total, unsigned *order,
                          size_t order_cap, size_t *order_n)
{
    for (size_t i = 0; rows && i < rows->num_children; i++) {
        const char *body = json_get_str(json_get(&rows->children[i], "body"));
        long idx;
        if (!body || strncmp(body, "row-", 4) != 0)
            return false;
        idx = strtol(body + 4, NULL, 10);
        if (idx < 0 || (size_t)idx >= DVX_PAGE_ROWS + 1u || seen[idx])
            return false;
        if (order && (!order_n || *order_n >= order_cap))
            return false;
        seen[idx] = 1;
        (*total)++;
        if (order)
            order[(*order_n)++] = (unsigned)idx;
    }
    return true;
}

/* Post n directive rows, each ~1.5 KiB, so the history is several times
 * one response budget. */
static bool dvx_post_history(size_t n)
{
    char body[1600];
    for (size_t i = 0; i < n; i++) {
        struct dvx_call c;
        int w = snprintf(body, sizeof(body), "row-%03zu ", i);
        memset(body + w, 'x', 1500);
        body[w + 1500] = '\0';
        dvx_post(&c, "alice", "*", "directive", body);
        bool ok = dvx_run(&c) && dvx_ok(&c);
        dvx_end(&c);
        if (!ok)
            return false;
    }
    return true;
}

/* Follow next_since from `token` until a page is the last one. Returns the
 * number of pages, or 0 when a page failed or repeated a row. */
static size_t dvx_drain_mode(char *token, size_t cap, unsigned char *seen,
                             size_t *total, bool brief_drain,
                             long long *cursor, long long *skipped,
                             unsigned *order, size_t order_cap,
                             size_t *order_n)
{
    size_t pages = 0;
    bool more = true;
    while (more && pages < 1000) {
        struct dvx_call p;
        const struct json_value *tr;
        dvx_pull_token(&p, token, "directive");
        if (!dvx_run_mode(&p, brief_drain) || !dvx_ok(&p) ||
            !dvx_mark_rows(dvx_arr(&p, "rows"), seen, total, order,
                           order_cap, order_n)) {
            dvx_end(&p);
            return 0;
        }
        tr = json_get(&p.reply.data, "truncated");
        more = tr && tr->type == JSON_BOOL && json_get_bool(tr);
        if (cursor)
            *cursor = dvx_int(&p, "cursor");
        if (skipped)
            *skipped += dvx_int(&p, "skipped");
        (void)snprintf(token, cap, "%s", dvx_str(&p, "next_since"));
        dvx_end(&p);
        pages++;
    }
    return more ? 0 : pages;
}

static size_t dvx_drain(char *token, size_t cap, unsigned char *seen,
                        size_t *total)
{
    return dvx_drain_mode(token, cap, seen, total, false, NULL, NULL, NULL,
                          0, NULL);
}

static void dvx_import_append(const char *name, const char *row)
{
    char maildir[1024], path[1200];
    dvx_maildir(maildir, sizeof(maildir));
    (void)snprintf(path, sizeof(path), "%s/%s.jsonl", maildir, name);
    FILE *f = fopen(path, "a");
    if (!f || fputs(row, f) < 0 || fclose(f) != 0)
        dvx_fixture_fail("cannot append to imported stream");
}

static void dvx_append_after_brief_probe(void)
{
    g_dvx_after_probe_calls++;
    dvx_import_append("outbox",
        "{\"seq\":1001,\"ts\":\"2019-01-01T00:00:00Z\","
        "\"from\":\"alice\",\"to\":\"*\",\"kind\":\"directive\","
        "\"body\":\"late row\",\"ref\":\"\"}\n");
}

static bool dvx_public_replay_matches(const char *brief_wire)
{
    struct dvx_call p;
    char public_wire[8192];
    dvx_pull_token(&p, "0|", "directive");
    bool matches = dvx_run(&p) && dvx_ok(&p) &&
        json_write(&p.reply.data, public_wire, sizeof(public_wire)) > 0 &&
        strcmp(public_wire, brief_wire) == 0;
    dvx_end(&p);
    return matches;
}

static bool dvx_brief_stage_append_safe(void)
{
    struct dvx_call p, b, scalar;
    char brief_wire[8192];
    bool matches;
    dvx_isolate("brief_stage_append");
    dvx_post(&p, "alice", "*", "directive", "initial row");
    if (!dvx_run(&p) || !dvx_ok(&p)) {
        dvx_end(&p);
        dvx_restore();
        return false;
    }
    dvx_end(&p);
    g_dvx_after_probe_calls = 0;
    (void)zcl_devagent_mail_test_max_seq_scans(true);
    zcl_devagent_mail_test_set_after_brief_probe(
        dvx_append_after_brief_probe);
    dvx_pull_token(&b, "0|", "directive");
    bool ran = dvx_run_mode(&b, true);
    zcl_devagent_mail_test_set_after_brief_probe(NULL);
    if (!ran || !dvx_ok(&b) || g_dvx_after_probe_calls != 1 ||
        zcl_devagent_mail_test_max_seq_scans(false) != 1 ||
        dvx_int(&b, "cursor") != 1001 || dvx_int(&b, "count") != 2 ||
        json_write(&b.reply.data, brief_wire, sizeof(brief_wire)) == 0) {
        dvx_end(&b);
        dvx_restore();
        return false;
    }
    dvx_end(&b);
    matches = dvx_public_replay_matches(brief_wire);
    dvx_pull(&scalar, 1001, NULL, "directive");
    matches = matches && dvx_run(&scalar) && dvx_ok(&scalar) &&
              dvx_int(&scalar, "count") == 0;
    dvx_end(&scalar);
    dvx_restore();
    return matches;
}

static int test_mail_paging(void)
{
    int failures = 0;
    TEST("mail: a pull over a large history pages with a token, every row once") {
        static unsigned char seen[DVX_PAGE_ROWS + 1u];
        char token[4096];
        size_t total = 0, pages;
        struct dvx_call p;
        memset(seen, 0, sizeof(seen));
        dvx_isolate("paging");
        ASSERT(dvx_post_history(200));
        /* A second stream whose rows sort BEFORE the whole outbox. */
        dvx_import_stream("inbox.peer",
            "{\"seq\":1,\"ts\":\"2020-01-01T00:00:00Z\",\"from\":\"bob\","
            "\"to\":\"*\",\"kind\":\"directive\",\"body\":\"row-200\","
            "\"ref\":\"\"}\n"
            "{\"seq\":2,\"ts\":\"2020-01-01T00:00:01Z\",\"from\":\"bob\","
            "\"to\":\"*\",\"kind\":\"directive\",\"body\":\"row-201\","
            "\"ref\":\"\"}\n");
        /* The first page is bounded, truncated, resumable, and serializes
         * inside the budget where the whole history could not. */
        dvx_pull(&p, 0, NULL, "directive");
        ASSERT(dvx_run(&p) && dvx_ok(&p));
        ASSERT(json_get_bool(json_get(&p.reply.data, "truncated")));
        ASSERT(dvx_int(&p, "count") > 0 && dvx_int(&p, "count") < 202);
        ASSERT(strchr(dvx_str(&p, "next_since"), '|') != NULL);
        ASSERT(dvx_pull_fits_budget(&p));
        dvx_end(&p);
        /* Draining the token from the start yields every row once. */
        (void)snprintf(token, sizeof(token), "%s", "0|");
        pages = dvx_drain(token, sizeof(token), seen, &total);
        ASSERT(pages > 1);
        ASSERT_EQ(total, (size_t)202);
        /* A row a transport appends later, with a ts OLDER than every row
         * already drained, is still returned: streams resume by offset. */
        dvx_import_append("inbox.peer",
            "{\"seq\":3,\"ts\":\"2019-01-01T00:00:00Z\",\"from\":\"bob\","
            "\"to\":\"*\",\"kind\":\"directive\",\"body\":\"row-202\","
            "\"ref\":\"\"}\n");
        ASSERT_EQ(dvx_drain(token, sizeof(token), seen, &total), (size_t)1);
        ASSERT_EQ(total, (size_t)203);
        /* A stream replaced under the token is refused, never guessed. */
        dvx_import_stream("inbox.peer", "\n");
        dvx_pull_token(&p, token, "directive");
        ASSERT(dvx_run(&p) && !dvx_ok(&p));
        ASSERT_STR_EQ(p.reply.error.code, "MAIL_CURSOR_STALE");
        dvx_end(&p);
        dvx_restore();
        PASS();
    }
_test_next:;
    return failures;
}

static bool dvx_brief_drain_equivalent(char *public_token,
                                      char *brief_token)
{
    unsigned char public_seen[DVX_PAGE_ROWS + 1u] = {0};
    unsigned char brief_seen[DVX_PAGE_ROWS + 1u] = {0};
    unsigned public_order[DVX_PAGE_ROWS + 1u] = {0};
    unsigned brief_order[DVX_PAGE_ROWS + 1u] = {0};
    size_t public_order_n = 0, brief_order_n = 0;
    size_t public_total = 0, brief_total = 0;
    size_t public_pages, brief_pages;
    size_t public_scans, brief_scans;
    long long public_cursor = -1, brief_cursor = -1;
    long long public_skipped = 0, brief_skipped = 0;
    (void)snprintf(public_token, 4096, "%s", "0|");
    (void)snprintf(brief_token, 4096, "%s", "0|");
    (void)zcl_devagent_mail_test_max_seq_scans(true);
    public_pages = dvx_drain_mode(public_token, 4096, public_seen,
                                  &public_total, false, &public_cursor,
                                  &public_skipped, public_order,
                                  sizeof(public_order) / sizeof(public_order[0]),
                                  &public_order_n);
    public_scans = zcl_devagent_mail_test_max_seq_scans(true);
    brief_pages = dvx_drain_mode(brief_token, 4096, brief_seen, &brief_total,
                                 true, &brief_cursor, &brief_skipped,
                                 brief_order,
                                 sizeof(brief_order) / sizeof(brief_order[0]),
                                 &brief_order_n);
    brief_scans = zcl_devagent_mail_test_max_seq_scans(false);
    return public_pages > 1 && brief_pages == public_pages &&
           public_scans == public_pages * 2 && brief_scans == 2 &&
           brief_total == public_total &&
           memcmp(brief_seen, public_seen, sizeof(brief_seen)) == 0 &&
           brief_order_n == public_order_n &&
           memcmp(brief_order, public_order,
                  brief_order_n * sizeof(brief_order[0])) == 0 &&
           brief_cursor == public_cursor && brief_cursor == 1000 &&
           brief_skipped == public_skipped && brief_skipped == 1 &&
           strcmp(brief_token, public_token) == 0;
}

static bool dvx_brief_append_equivalent(char *public_token,
                                        char *brief_token)
{
    struct dvx_call p, b;
    char public_wire[8192], brief_wire[8192];
    bool same;
    dvx_import_append("inbox.peer",
        "{\"seq\":1001,\"ts\":\"2019-01-01T00:00:00Z\","
        "\"from\":\"bob\",\"to\":\"*\",\"kind\":\"directive\","
        "\"body\":\"row-202\",\"ref\":\"\"}\n");
    dvx_pull_token(&p, public_token, "directive");
    if (!dvx_run(&p) || !dvx_ok(&p) || dvx_int(&p, "cursor") != 1001 ||
        dvx_int(&p, "count") != 1 ||
        json_write(&p.reply.data, public_wire, sizeof(public_wire)) == 0) {
        dvx_end(&p);
        return false;
    }
    (void)snprintf(public_token, 4096, "%s", dvx_str(&p, "next_since"));
    dvx_end(&p);
    dvx_pull_token(&b, brief_token, "directive");
    if (!dvx_run_mode(&b, true) || !dvx_ok(&b) ||
        dvx_int(&b, "cursor") != 1001 || dvx_int(&b, "count") != 1 ||
        json_write(&b.reply.data, brief_wire, sizeof(brief_wire)) == 0) {
        dvx_end(&b);
        return false;
    }
    (void)snprintf(brief_token, 4096, "%s", dvx_str(&b, "next_since"));
    same = strcmp(brief_wire, public_wire) == 0 &&
           strcmp(brief_token, public_token) == 0;
    dvx_end(&b);
    return same;
}

static bool dvx_brief_stale_refusal_matches(const char *public_token,
                                           const char *brief_token)
{
    struct dvx_call p, b;
    bool public_stale, brief_stale;
    dvx_import_stream("inbox.peer", "\n");
    dvx_pull_token(&p, public_token, "directive");
    public_stale = dvx_run(&p) && !dvx_ok(&p) &&
                   strcmp(p.reply.error.code, "MAIL_CURSOR_STALE") == 0 &&
                   !p.reply.error.mutated;
    dvx_end(&p);
    dvx_pull_token(&b, brief_token, "directive");
    brief_stale = dvx_run_mode(&b, true) && !dvx_ok(&b) &&
                  strcmp(b.reply.error.code, "MAIL_CURSOR_STALE") == 0 &&
                  !b.reply.error.mutated;
    dvx_end(&b);
    return public_stale && brief_stale;
}

static bool dvx_brief_drain_fixture(void)
{
    char public_token[4096], brief_token[4096];
    bool ok = false;
    dvx_isolate("brief_drain");
    if (!dvx_post_history(200))
        goto done;
    dvx_import_stream("inbox.peer",
        "malformed row\n"
        "{\"seq\":999,\"ts\":\"2020-01-01T00:00:00Z\","
        "\"from\":\"bob\",\"to\":\"*\",\"kind\":\"directive\","
        "\"body\":\"row-200\",\"ref\":\"\"}\n"
        "{\"seq\":1000,\"ts\":\"2020-01-01T00:00:01Z\","
        "\"from\":\"bob\",\"to\":\"*\",\"kind\":\"directive\","
        "\"body\":\"row-201\",\"ref\":\"\"}\n");
    if (!dvx_brief_drain_equivalent(public_token, brief_token) ||
        !dvx_brief_append_equivalent(public_token, brief_token) ||
        !dvx_brief_stale_refusal_matches(public_token, brief_token))
        goto done;
    ok = true;
done:
    dvx_restore();
    return ok;
}

static int test_mail_brief_drain(void)
{
    int failures = 0;
    TEST("mail: brief drain defers only the intermediate global cursor") {
        ASSERT(dvx_brief_drain_fixture());
        PASS();
    }
    TEST("mail: append after final-page probe remains in the cursor result") {
        ASSERT(dvx_brief_stage_append_safe());
        PASS();
    }
_test_next:;
    return failures;
}

/* One conversation is one page, and a reader keeps its place across
 * restarts: ref/to filters, an acked next_since token resumed by `agent`,
 * late arrivals, re-reads before ack, and per-source completeness. */
static bool dvx_post_ref(const char *from, const char *to, const char *ref,
                         const char *body)
{
    struct dvx_call c;
    bool ok;
    dvx_post(&c, from, to, "note", body);
    (void)json_push_kv_str(&c.input, "ref", ref);
    ok = dvx_run(&c) && dvx_ok(&c);
    dvx_end(&c);
    return ok;
}

static void dvx_pull_agent(struct dvx_call *c, const char *agent,
                           const char *ref)
{
    dvx_begin(c);
    (void)json_push_kv_str(&c->input, "action", "pull");
    (void)json_push_kv_str(&c->input, "agent", agent);
    if (ref)
        (void)json_push_kv_str(&c->input, "ref", ref);
}

static bool dvx_ack_token(const char *agent, const char *token)
{
    struct dvx_call c;
    bool ok;
    dvx_begin(&c);
    (void)json_push_kv_str(&c.input, "action", "ack");
    (void)json_push_kv_str(&c.input, "agent", agent);
    (void)json_push_kv_str(&c.input, "cursor", token);
    ok = dvx_run(&c) && dvx_ok(&c);
    dvx_end(&c);
    return ok;
}

static bool dvx_sources_complete(const struct dvx_call *c, size_t want)
{
    const struct json_value *src = dvx_arr(c, "sources");
    if (!src || src->num_children != want)
        return false;
    for (size_t i = 0; i < src->num_children; i++)
        if (!json_get_bool(json_get(&src->children[i], "complete")))
            return false;
    return true;
}

static bool dvx_stored_cursor(const char *bytes, size_t n, bool accepted)
{
    char dir[1100], path[1200];
    struct dvx_call p;
    dvx_maildir(dir, sizeof(dir));
    (void)snprintf(path, sizeof(path), "%s/cursor.alice", dir);
    FILE *f = fopen(path, "wb");
    if (!f) dvx_fixture_fail("could not open stored cursor");
    bool written = fwrite(bytes, 1, n, f) == n;
    if (fclose(f) != 0 || !written)
        dvx_fixture_fail("could not write stored cursor");
    dvx_pull_agent(&p, "alice", NULL);
    bool ok = dvx_run(&p) && dvx_ok(&p) == accepted;
    if (!accepted)
        ok = ok && strcmp(p.reply.error.code, "MAIL_CURSOR_STALE") == 0;
    else
        ok = ok && strcmp(dvx_str(&p, "resumed_from"), "agent") == 0;
    dvx_end(&p);
    return ok;
}

static int test_mail_cursor_row(const char *name, const char *bytes, size_t n,
                                bool accepted)
{
    int failures = 0;
    TEST(name) {
        dvx_isolate("stored_cursor");
        ASSERT(dvx_ack_token("alice", "7"));
        ASSERT(dvx_stored_cursor(bytes, n, accepted));
        PASS();
    }
_test_next:;
    dvx_restore();
    return failures;
}

static int test_mail_stored_cursor(void)
{
    char oversized[4096];
    int failures = 0;
    memset(oversized, '0', sizeof(oversized));
    oversized[sizeof(oversized) - 1] = 'x';
    failures += test_mail_cursor_row("mail: stored NUL suffix refuses",
                                     "7\0junk", 6, false);
    failures += test_mail_cursor_row("mail: stored scalar suffix refuses",
                                     "7junk", 5, false);
    failures += test_mail_cursor_row("mail: stored oversized suffix refuses",
                                     oversized, sizeof(oversized), false);
    failures += test_mail_cursor_row("mail: stored scalar overflow refuses",
                                     "9223372036854775808", 19, false);
    failures += test_mail_cursor_row("mail: stored repeated newline refuses",
                                     "7\n\n", 3, false);
    failures += test_mail_cursor_row("mail: stored bare CR refuses",
                                     "7\r", 2, false);
    failures += test_mail_cursor_row("mail: stored scalar without newline",
                                     "7", 1, true);
    failures += test_mail_cursor_row("mail: stored scalar with LF",
                                     "7\n", 2, true);
    failures += test_mail_cursor_row("mail: stored scalar with CRLF",
                                     "7\r\n", 3, true);
    failures += test_mail_cursor_row("mail: stored token without newline",
                                     "0|", 2, true);
    failures += test_mail_cursor_row("mail: stored token with CRLF",
                                     "0|\r\n", 4, true);
    return failures;
}

static int test_mail_ref_filter_and_agent_resume(void)
{
    int failures = 0;
    TEST("mail: ref/to filters page one thread; agent resumes an acked token") {
        char token[4096];
        char maildir[1024], path[1200];
        struct dvx_call p;
        dvx_isolate("ref_resume");
        ASSERT(dvx_post_ref("B", "oauth", "thread-1", "one"));
        ASSERT(dvx_post_ref("A", "B", "thread-2", "other"));
        ASSERT(dvx_post_ref("B", "A", "thread-1", "two"));
        dvx_import_stream("inbox.peer",
            "{\"seq\":1,\"ts\":\"2020-01-01T00:00:00Z\",\"from\":\"C\","
            "\"to\":\"oauth\",\"kind\":\"note\",\"body\":\"three\","
            "\"ref\":\"thread-1\"}\n");
        /* ref: only the thread, across both streams; to: only that peer. */
        dvx_pull_agent(&p, "reader", "thread-1");
        ASSERT(dvx_run(&p) && dvx_ok(&p));
        ASSERT_EQ(dvx_int(&p, "count"), 3);
        ASSERT_STR_EQ(dvx_str(&p, "resumed_from"), "start");
        ASSERT(dvx_sources_complete(&p, 2));
        (void)snprintf(token, sizeof(token), "%s", dvx_str(&p, "next_since"));
        dvx_end(&p);
        dvx_pull(&p, 0, NULL, NULL);
        (void)json_push_kv_str(&p.input, "to", "oauth");
        ASSERT(dvx_run(&p) && dvx_ok(&p));
        ASSERT_EQ(dvx_int(&p, "count"), 2);
        dvx_end(&p);
        /* Ack the token; a fresh process (same agent, no since) sees nothing
         * new, then exactly the late row, and re-sees it until it acks. */
        ASSERT(dvx_ack_token("reader", token));
        dvx_pull_agent(&p, "reader", "thread-1");
        ASSERT(dvx_run(&p) && dvx_ok(&p));
        ASSERT_EQ(dvx_int(&p, "count"), 0);
        ASSERT_STR_EQ(dvx_str(&p, "resumed_from"), "agent");
        dvx_end(&p);
        dvx_import_append("inbox.peer",
            "{\"seq\":2,\"ts\":\"2019-01-01T00:00:00Z\",\"from\":\"C\","
            "\"to\":\"oauth\",\"kind\":\"note\",\"body\":\"late\","
            "\"ref\":\"thread-1\"}\n");
        for (int pass = 0; pass < 2; pass++) {
            dvx_pull_agent(&p, "reader", "thread-1");
            ASSERT(dvx_run(&p) && dvx_ok(&p));
            ASSERT_EQ(dvx_int(&p, "count"), 1);
            dvx_end(&p);
        }
        /* A stored cursor that is not one is refused by name, never
         * silently read as "from the start". A path in a token is bad. */
        dvx_maildir(maildir, sizeof(maildir));
        (void)snprintf(path, sizeof(path), "%s/cursor.reader", maildir);
        {
            FILE *f = fopen(path, "w");
            ASSERT(f && fputs("garbage\n", f) >= 0 && fclose(f) == 0);
        }
        dvx_pull_agent(&p, "reader", NULL);
        ASSERT(dvx_run(&p) && !dvx_ok(&p));
        ASSERT_STR_EQ(p.reply.error.code, "MAIL_CURSOR_STALE");
        dvx_end(&p);
        ASSERT(!dvx_ack_token("reader", "0|../outbox:1"));
        dvx_restore();
        PASS();
    }
_test_next:;
    return failures;
}

#if !defined(_WIN32)
static int test_mail_ack_sync(int mode);
#endif
static int test_mail_independent_cursor(void)
{
    int failures = 0;
    TEST("mail: scalar resume refuses a later independently sequenced stream") {
        struct dvx_call p;
        dvx_isolate("independent_cursor");
        dvx_import_stream("inbox-a",
            "{\"seq\":20,\"ts\":\"2026-09-09T00:00:00Z\",\"from\":\"alice\","
            "\"to\":\"bob\",\"kind\":\"note\",\"body\":\"first\",\"ref\":\"\"}\n");
        dvx_pull(&p, 0, NULL, NULL);
        ASSERT(dvx_run(&p) && dvx_ok(&p));
        ASSERT_EQ(dvx_int(&p, "count"), 1);
        ASSERT_EQ(dvx_int(&p, "cursor"), 20);
        dvx_end(&p);
        dvx_import_stream("inbox-c",
            "{\"seq\":1,\"ts\":\"2026-09-09T00:00:01Z\",\"from\":\"carol\","
            "\"to\":\"bob\",\"kind\":\"note\",\"body\":\"later\",\"ref\":\"\"}\n");
        dvx_pull(&p, 20, "carol", "note");
        ASSERT(dvx_run(&p));
        ASSERT(!dvx_ok(&p));
        ASSERT_STR_EQ(p.reply.error.code, "MAIL_CURSOR_AMBIGUOUS");
        ASSERT(!p.reply.error.mutated);
        ASSERT(dvx_arr(&p, "rows") == NULL);
        ASSERT(dvx_cursor_refusal_serializes(&p));
        dvx_end(&p);
        dvx_pull(&p, 0, NULL, NULL);
        ASSERT(dvx_run(&p) && dvx_ok(&p));
        ASSERT_EQ(dvx_int(&p, "count"), 2);
        dvx_end(&p);
        dvx_restore();
        PASS();
    }
_test_next:;
    dvx_restore();
#if !defined(_WIN32)
    failures += test_mail_ack_sync(1);
    failures += test_mail_ack_sync(2);
#endif
    return failures;
}

#if !defined(_WIN32)
/* Admission is a function of the body alone. Its own group function so
 * that adding a directory or a vector never pushes the main one over the
 * complexity cap. POSIX-only, because it chdir()s. */
static int test_mail_cwd_invariance(void)
{
    int failures = 0;
    /* ── B's durable regression, ported into this group ───────────────────
     * Same authenticated directive bytes plus same receiver state must give
     * the same admission verdict, wherever the process happens to be
     * running. */

    TEST("mail: one directive body gets one verdict from every directory") {
        char body[PATH_MAX + 256];
        char verdict[128];
        dvx_isolate("cwd_invariance");
        /* The pre-final cross-box directive: an absolute workspace, a
         * relative scope, a gate, a prompt. The absolute path is written
         * from this run's own state dir, so no operator path is spelled
         * out here and the body is still the shape that moved. */
        (void)snprintf(body, sizeof(body),
                       "muse-workspace: %s/trains/muse-accept-tree\n"
                       "muse-scope: tests/harness/src/test_hex_codec.c\n"
                       "muse-gate: hex_codec\n\n"
                       "Add one harmless explanatory comment.",
                       g_dvx_state);
        ASSERT(dvx_one_verdict(body, verdict, sizeof(verdict)));
        /* And the one verdict is the refusal: an absolute path in a body
         * that crosses hosts carries no authority anywhere. */
        ASSERT_STR_EQ(verdict, "MAIL_REFUSED_PATH");
        dvx_restore();
        PASS();
    }

    TEST("mail: a relative directive is admitted from every directory") {
        char verdict[128];
        dvx_isolate("cwd_relative");
        ASSERT(dvx_one_verdict("muse-scope: src/x.c", verdict,
                               sizeof(verdict)));
        ASSERT_STR_EQ(verdict, "");
        ASSERT(dvx_one_verdict("muse-gate: hex_codec\n"
                               "muse-scope: tests/harness/src/a.c",
                               verdict, sizeof(verdict)));
        ASSERT_STR_EQ(verdict, "");
        ASSERT(dvx_one_verdict("nothing here but plain words", verdict,
                               sizeof(verdict)));
        ASSERT_STR_EQ(verdict, "");
        dvx_restore();
        PASS();
    }

    TEST("mail: public web references are admitted from every directory") {
        static const char *const references[] = {
            "reference https://example.org/reference",
            "reference http://example.org/reference",
            "reference HTTPS://example.org/reference",
            "reference hTtP://example.org/reference",
        };
        char verdict[128];
        dvx_isolate("cwd_web_reference");
        for (size_t i = 0; i < sizeof(references) / sizeof(references[0]); i++) {
            ASSERT(dvx_one_verdict(references[i], verdict, sizeof(verdict)));
            ASSERT_STR_EQ(verdict, "");
        }
        dvx_restore();
        PASS();
    }

    TEST("mail: a foreign path is refused from every directory") {
        static const char *const hostile[] = {
            /* B's four fail-closed vectors. */
            "please read /etc/shadow",
            "key at ~/.ssh/id_rsa",
            "see /var/log/auth.log",
            "climb out: tests/../../../etc/passwd",
            /* The same climb toward a target NO marker matches, so only the
             * ".." SEGMENT rule can refuse it: delete that rule and this
             * line is admitted. B's climbing vector above refuses either
             * way, because the substring it climbs toward is on the marker
             * list. */
            "climb out: tests/../../../secrets/x",
            "a/../../b names the same place",
            /* A Windows drive path, both spellings. B's oracle claims this
             * vector in prose and has no case for it, so nothing there
             * would notice dvm_has_drive_path() breaking.
             *
             * KEEP THESE OFF THE TWO HOME PREFIXES, the Linux one and the
             * macOS one. check-no-operator-paths derives its
             * operator-identity tokens FROM the tree: a home-prefixed
             * absolute path in any tracked file mints the account segment
             * after that prefix as an identity, then hunts that word
             * through every file. Windows/Temp trips nothing. */
            "copied to C:\\Windows\\Temp\\notes.txt",
            "fetched C:/Windows/Temp/notes.txt",
            "reference https://example.org/C:/Windows/Temp/notes.txt",
            "reference https://example.org/../../secrets/x",
            "reference https://example.org then C:/Windows/Temp/notes.txt",
        };
        char verdict[128];
        size_t i;
        dvx_isolate("cwd_hostile");
        for (i = 0; i < sizeof(hostile) / sizeof(hostile[0]); i++) {
            ASSERT(dvx_one_verdict(hostile[i], verdict, sizeof(verdict)));
            ASSERT_STR_EQ(verdict, "MAIL_REFUSED_PATH");
        }
        ASSERT(dvx_outbox_empty());
        dvx_restore();
        PASS();
    }
_test_next:;
    return failures;
}
#endif /* !defined(_WIN32) */

/* A board-carrying transport appends board_post and board_signer to the
 * row it imported. Pull hands both back verbatim for the receiver to
 * verify; a row without them reads "", and a value too long to be a post
 * id or a host key reads "" too, never a truncated prefix. Post has no
 * input for either: only a transport writes them. */
static int test_mail_utf8_ref(void);
static int test_mail_board_fields(void)
{
    int failures = 0;
    failures += test_mail_utf8_ref();
    TEST("mail: pull returns board_post and board_signer a transport appended") {
        static const char id[] =
            "1111111111111111111111111111111111111111111111111111111111111111";
        static const char host[] =
            "2222222222222222222222222222222222222222222222222222222222222222";
        char line[1024];
        struct dvx_call p;
        const struct json_value *rows;
        dvx_isolate("board_fields");
        (void)snprintf(line, sizeof(line),
            "{\"seq\":1,\"ts\":\"2020-01-01T00:00:00Z\",\"from\":\"chatgpt\","
            "\"to\":\"node-b\",\"kind\":\"directive\",\"body\":\"go\","
            "\"ref\":\"job-1\",\"board_post\":\"%s\",\"board_signer\":\"%s\"}\n"
            "{\"seq\":2,\"ts\":\"2020-01-01T00:00:01Z\",\"from\":\"chatgpt\","
            "\"to\":\"node-b\",\"kind\":\"directive\",\"body\":\"go\","
            "\"ref\":\"job-2\",\"board_post\":\"%s0\"}\n"
            "{\"seq\":3,\"ts\":\"2020-01-01T00:00:02Z\",\"from\":\"chatgpt\","
            "\"to\":\"node-b\",\"kind\":\"directive\",\"body\":\"go\","
            "\"ref\":\"job-3\"}\n",
            id, host, id);
        dvx_import_stream("inbox.node-a", line);
        dvx_pull(&p, 0, NULL, NULL);
        ASSERT(dvx_run(&p) && dvx_ok(&p));
        ASSERT_EQ(dvx_int(&p, "count"), 3);
        rows = dvx_arr(&p, "rows");
        ASSERT(rows != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(json_at(rows, 0), "board_post")), id);
        ASSERT_STR_EQ(json_get_str(json_get(json_at(rows, 0), "board_signer")),
                      host);
        /* 65 hex digits is not a post id: empty, never the first 64. */
        ASSERT_STR_EQ(json_get_str(json_get(json_at(rows, 1), "board_post")), "");
        ASSERT_STR_EQ(json_get_str(json_get(json_at(rows, 2), "board_post")), "");
        ASSERT_STR_EQ(json_get_str(json_get(json_at(rows, 2), "board_signer")),
                      "");
        dvx_end(&p);
        /* Post takes no board field: the registry refuses the key. */
        dvx_begin(&p);
        (void)json_push_kv_str(&p.input, "action", "post");
        (void)json_push_kv_str(&p.input, "to", "node-b");
        (void)json_push_kv_str(&p.input, "kind", "directive");
        (void)json_push_kv_str(&p.input, "body", "forge");
        (void)json_push_kv_str(&p.input, "board_post", id);
        ASSERT(!dvx_run(&p));
        dvx_end(&p);
        dvx_restore();
        PASS();
    }
_test_next:;
    return failures;
}

static int test_mail_utf8_ref(void)
{
    int failures = 0;
    TEST("mail: invalid UTF-8 ref refuses before append; Unicode is exact") {
        struct dvx_call c;
        char maildir[1100], path[1200], line[8192];
        const char *text = "caf\xc3\xa9\n\"\\";
        const char *binding = "0123456789abcdef0123456789abcdef";
        FILE *f;
        struct json_value row;
        dvx_isolate("utf8-ref");
        dvx_post(&c, "alice", "bob", "note", "hello");
        ASSERT(json_push_kv_str(&c.input, "ref", "a\xff" "b"));
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "BAD_INPUT");
        dvx_end(&c);
        ASSERT(dvx_outbox_empty());
        dvx_post(&c, "alice", "bob", "note", "a\xff" "b");
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "BAD_INPUT");
        dvx_end(&c);
        ASSERT(dvx_outbox_empty());
        dvx_post(&c, "alice", "bob", "note", text);
        ASSERT(json_push_kv_str(&c.input, "ref", text));
        ASSERT(json_push_kv_str(&c.input, "sender_binding", binding));
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        dvx_end(&c);
        dvx_maildir(maildir, sizeof(maildir));
        ASSERT(snprintf(path, sizeof(path), "%s/outbox.jsonl", maildir) < (int)sizeof(path));
        f = fopen(path, "r");
        ASSERT(f != NULL);
        bool read = fgets(line, sizeof(line), f) != NULL;
        ASSERT_EQ(fclose(f), 0);
        ASSERT(read);
        ASSERT(zutf8_validate_n(line, strlen(line)));
        ASSERT(json_valid(line, strlen(line)));
        json_init(&row);
        ASSERT(json_read(&row, line, strlen(line)));
        ASSERT_STR_EQ(json_get_str(json_get(&row, "ref")), text);
        ASSERT_STR_EQ(json_get_str(json_get(&row, "body")), text);
        ASSERT_STR_EQ(json_get_str(json_get(&row, "sender_binding")), binding);
        json_free(&row);
        PASS();
    }
_test_next:;
    dvx_restore();
    return failures;
}

#if !defined(_WIN32)
static int dvx_sync_mode;
static bool dvx_overlap_exact;
static char dvx_cursor_path[1200];

static bool dvx_cursor_exact(const char *want)
{
    char text[64] = {0};
    FILE *f = fopen(dvx_cursor_path, "r");
    if (!f) return false;
    size_t n = fread(text, 1, sizeof(text) - 1, f);
    return fclose(f) == 0 && n == strlen(want) && strcmp(text, want) == 0;
}

static bool dvx_ack_ok(long long cursor)
{
    struct dvx_call a;
    dvx_ack(&a, "alice", cursor);
    bool ok = dvx_run(&a) && dvx_ok(&a);
    dvx_end(&a);
    return ok;
}

int zcl_devagent_mail_test_sync(int fd);
int zcl_devagent_mail_test_sync(int fd)
{
    if (dvx_sync_mode == 1) { errno = EIO; return -1; }
    if (dvx_sync_mode == 2) {
        struct dvx_call a;
        dvx_sync_mode = 0;
        dvx_ack(&a, "alice", 7);
        bool installed = dvx_run(&a) && dvx_ok(&a);
        dvx_end(&a);
        dvx_overlap_exact = installed && pwrite(fd, "12\n", 3, 0) == 3 &&
            dvx_cursor_exact("7\n");
    }
    return fsync(fd);
}

static int test_mail_ack_sync(int mode)
{
    int failures = 0;
    TEST("mail: ack flush refusal preserves OLD; overlap keeps installs whole") {
        struct dvx_call a;
        dvx_isolate("acksync");
        (void)snprintf(dvx_cursor_path, sizeof(dvx_cursor_path),
                       "%s/z23/dev/mail/cursor.alice", g_dvx_state);
        ASSERT(dvx_ack_ok(7));
        dvx_sync_mode = mode;
        dvx_overlap_exact = false;
        dvx_ack(&a, "alice", 12);
        ASSERT(dvx_run(&a));
        ASSERT(dvx_ok(&a) == (mode == 2));
        ASSERT(dvx_cursor_exact(mode == 1 ? "7\n" : "12\n"));
        ASSERT(mode == 1 || dvx_overlap_exact);
        dvx_end(&a);
        dvx_sync_mode = 0;
        ASSERT(dvx_ack_ok(12));
        ASSERT(dvx_cursor_exact("12\n"));
        PASS();
    }
_test_next:;
    dvx_sync_mode = 0;
    dvx_restore();
    return failures;
}
#endif

int test_devagent_mail(void);
int test_devagent_mail(void)
{
    int failures = 0;
    long long cursor = 0;

    failures += test_mail_independent_cursor();
    failures += test_mail_paging();
    failures += test_mail_brief_drain();
    failures += test_mail_ref_filter_and_agent_resume();
    failures += test_mail_stored_cursor();
    failures += test_mail_board_fields();
#if !defined(_WIN32)
    failures += test_mail_cwd_invariance();
#endif

    TEST("mail: the leaf is registered with its post/pull/ack keys") {
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(), DVX_PATH, NULL);
        ASSERT(spec != NULL);
        /* A DEV_COMMAND leaf binds its handler only in a dev build (the
         * test binary calls zcl_native_handle_dev_agent_mail directly,
         * exactly as the CLI does after input validation), so only the
         * declared keys are pinned here. */
        ASSERT(spec->input_keys && strstr(spec->input_keys, "action") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "to") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "kind") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "body") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "since") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "from") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "cursor") != NULL);
        PASS();
    }

    TEST("mail: a missing state dir is created by the first post") {
        char maildir[1100], outbox[1200];
        struct dvx_call c;
        FILE *f;
        dvx_isolate("fresh");
        dvx_maildir(maildir, sizeof(maildir));
        (void)test_rm_rf_recursive(maildir);
        ASSERT(dvx_fresh_pull_unchanged(maildir));
        dvx_post(&c, "alice", "*", "note", "first hello");
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT_STR_EQ(dvx_str(&c, "leaf"), DVX_PATH);
        ASSERT(dvx_int(&c, "seq") >= 1);
        (void)snprintf(outbox, sizeof(outbox), "%s/outbox.jsonl", maildir);
        f = fopen(outbox, "r");
        ASSERT(f != NULL);
        if (f)
            (void)fclose(f);
        cursor = dvx_int(&c, "cursor");
        dvx_end(&c);
        dvx_restore();
        PASS();
    }

    TEST("mail: post then pull returns the row") {
        struct dvx_call c, p;
        const struct json_value *rows;
        const struct json_value *row;
        dvx_isolate("roundtrip");
        dvx_post(&c, "alice", "bob", "need", "please review the lane");
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT_STR_EQ(dvx_str(&c, "from"), "alice");
        ASSERT_STR_EQ(dvx_str(&c, "to"), "bob");
        ASSERT_STR_EQ(dvx_str(&c, "kind"), "need");
        ASSERT_STR_EQ(dvx_str(&c, "body"), "please review the lane");
        cursor = dvx_int(&c, "seq");
        ASSERT(cursor >= 1);
        dvx_end(&c);

        dvx_pull(&p, 0, NULL, NULL);
        ASSERT(dvx_run(&p));
        ASSERT(dvx_ok(&p));
        rows = dvx_arr(&p, "rows");
        ASSERT(rows != NULL);
        ASSERT_EQ((long long)rows->num_children, 1);
        row = &rows->children[0];
        ASSERT_STR_EQ(json_get_str(json_get(row, "from")), "alice");
        ASSERT_STR_EQ(json_get_str(json_get(row, "body")),
                      "please review the lane");
        ASSERT(dvx_int(&p, "cursor") >= cursor);
        cursor = dvx_int(&p, "cursor");
        dvx_end(&p);
        dvx_restore();
        PASS();
    }

    TEST("mail: pull with the returned cursor returns nothing") {
        struct dvx_call c, p;
        const struct json_value *rows;
        dvx_isolate("empty");
        dvx_post(&c, "alice", "*", "note", "one row");
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        cursor = dvx_int(&c, "cursor");
        dvx_end(&c);
        dvx_pull(&p, cursor, NULL, NULL);
        ASSERT(dvx_run(&p));
        ASSERT(dvx_ok(&p));
        rows = dvx_arr(&p, "rows");
        ASSERT(rows != NULL);
        ASSERT_EQ((long long)rows->num_children, 0);
        dvx_end(&p);
        dvx_restore();
        PASS();
    }

    TEST("mail: ack persists the caller cursor") {
        struct dvx_call c, a;
        char path[1200];
        FILE *f;
        char body[64];
        dvx_isolate("ack");
        dvx_post(&c, "alice", "*", "note", "ack me");
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        cursor = dvx_int(&c, "cursor");
        dvx_end(&c);
        dvx_ack(&a, "alice", cursor);
        ASSERT(dvx_run(&a));
        ASSERT(dvx_ok(&a));
        ASSERT_STR_EQ(dvx_str(&a, "agent"), "alice");
        ASSERT_EQ(dvx_int(&a, "cursor"), cursor);
        dvx_end(&a);
        (void)snprintf(path, sizeof(path), "%s/z23/dev/mail/cursor.alice",
                       g_dvx_state);
        f = fopen(path, "r");
        ASSERT(f != NULL);
        if (f) {
            ASSERT(fgets(body, sizeof(body), f) != NULL);
            ASSERT(atoll(body) == cursor);
            (void)fclose(f);
        }
        dvx_restore();
        PASS();
    }

    TEST("mail: a body containing an onion address is refused, not stored") {
        struct dvx_call c, p;
        const struct json_value *rows;
        dvx_isolate("onion");
        dvx_post(&c, "alice", "*",
                 "note", "meet at abcdef1234567890.onion right now");
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT(strstr(c.reply.error.code, "REFUSED") != NULL);
        ASSERT(strstr(c.reply.error.code, "ONION") != NULL);
        dvx_end(&c);
        dvx_pull(&p, 0, NULL, NULL);
        ASSERT(dvx_run(&p));
        ASSERT(dvx_ok(&p));
        rows = dvx_arr(&p, "rows");
        ASSERT(rows != NULL);
        ASSERT_EQ((long long)rows->num_children, 0);
        dvx_end(&p);
        dvx_restore();
        PASS();
    }

    TEST("mail: a traversal path starting with the real root is refused") {
        struct dvx_call c;
        char root[PATH_MAX];
        char body[PATH_MAX + 64];
        /* Reproduces the actual defect: a plain prefix strncmp against the
         * checkout root, with no canonicalization, let a body naming
         * <root>/../../../etc/shadow through as "under root" because the
         * bytes of `root` do prefix it. Use the REAL resolved root (not a
         * stand-in path) and a tail word that trips no other refusal rule,
         * so this test only passes when the ".." climb itself is caught. */
        ASSERT(zcl_devagent_checkout_root(NULL, root, sizeof(root)));
        (void)snprintf(body, sizeof(body), "read %s/../../../secret please",
                       root);
        dvx_isolate("dotdot");
        dvx_post(&c, "alice", "*", "note", body);
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT(strstr(c.reply.error.code, "REFUSED") != NULL);
        ASSERT(strstr(c.reply.error.code, "PATH") != NULL);
        dvx_end(&c);
        ASSERT(dvx_outbox_empty());
        dvx_restore();
        PASS();
    }

    TEST("mail: a bare .. and a mid-token /../ are both refused") {
        struct dvx_call c1, c2;
        char root[PATH_MAX];
        char body1[PATH_MAX + 64];
        char body2[PATH_MAX + 64];
        ASSERT(zcl_devagent_checkout_root(NULL, root, sizeof(root)));
        /* Token equal to the root plus a trailing "/.." (ends in "/.."). */
        (void)snprintf(body1, sizeof(body1), "see %s/.. please", root);
        /* ".." in the middle of the token, not just at the end. */
        (void)snprintf(body2, sizeof(body2), "see %s/../secret/x please",
                       root);
        dvx_isolate("dotdot2");
        dvx_post(&c1, "alice", "*", "note", body1);
        ASSERT(dvx_run(&c1));
        ASSERT(!dvx_ok(&c1));
        ASSERT(strstr(c1.reply.error.code, "REFUSED") != NULL);
        ASSERT(strstr(c1.reply.error.code, "PATH") != NULL);
        dvx_end(&c1);
        ASSERT(dvx_outbox_empty());
        dvx_restore();
        dvx_isolate("dotdot3");
        dvx_post(&c2, "alice", "*", "note", body2);
        ASSERT(dvx_run(&c2));
        ASSERT(!dvx_ok(&c2));
        ASSERT(strstr(c2.reply.error.code, "REFUSED") != NULL);
        ASSERT(strstr(c2.reply.error.code, "PATH") != NULL);
        dvx_end(&c2);
        ASSERT(dvx_outbox_empty());
        dvx_restore();
        PASS();
    }

    TEST("mail: a Z.ai-shaped key token in the body is refused") {
        struct dvx_call c;
        dvx_isolate("apikey");
        /* 32 hex chars, a dot, 16 alnum: the Z.ai key shape, bare. */
        dvx_post(&c, "alice", "*", "note",
                 "token 0123456789abcdef0123456789abcdef.ABCDEFGHIJKLMNOP " /* api-key-example-ok */
                 "leaked");
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT(strstr(c.reply.error.code, "REFUSED") != NULL);
        ASSERT(strstr(c.reply.error.code, "KEY") != NULL);
        dvx_end(&c);
        ASSERT(dvx_outbox_empty());
        dvx_restore();
        PASS();
    }

    TEST("mail: a bare IPv4 address in the body is refused") {
        struct dvx_call c;
        dvx_isolate("ipv4");
        dvx_post(&c, "alice", "*", "note",
                 "gateway at 192.168.1.7 is down again");
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT(strstr(c.reply.error.code, "REFUSED") != NULL);
        ASSERT(strstr(c.reply.error.code, "IP") != NULL);
        dvx_end(&c);
        ASSERT(dvx_outbox_empty());
        dvx_restore();
        PASS();
    }

    TEST("mail: an absolute path outside the root is refused") {
        struct dvx_call c;
        dvx_isolate("outside");
        dvx_post(&c, "alice", "*", "note",
                 "config broke, see /etc/shadow.conf for details");
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT(strstr(c.reply.error.code, "REFUSED") != NULL);
        ASSERT(strstr(c.reply.error.code, "PATH") != NULL);
        dvx_end(&c);
        ASSERT(dvx_outbox_empty());
        dvx_restore();
        PASS();
    }

    /* A body naming only REPO-RELATIVE paths is accepted: the detector must
     * not require an absolute in-root token, or a cross-box directive naming
     * a workspace logically and a scope relatively could never pass. Every
     * absolute refusal below is unchanged. */
    TEST("mail: a body naming only relative paths is accepted") {
        struct dvx_call c, p;
        const struct json_value *rows;
        dvx_isolate("relative");
        dvx_post(&c, "alice", "*", "note",
                 "see docs/experiments/x.md for detail");
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        dvx_end(&c);
        dvx_pull(&p, 0, NULL, NULL);
        ASSERT(dvx_run(&p));
        ASSERT(dvx_ok(&p));
        rows = dvx_arr(&p, "rows");
        ASSERT(rows != NULL);
        ASSERT_EQ((long long)rows->num_children, 1);
        dvx_end(&p);
        dvx_restore();
        dvx_isolate("relative2");
        dvx_post(&c, "alice", "*", "note", "a/b/c relative only");
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        dvx_end(&c);
        dvx_restore();
        PASS();
    }

    TEST("mail: one real muse direction with a selector posts as itself") {
        struct dvx_call c;
        dvx_isolate("direction");
        /* Exactly the shape a cross-box directive now has: a logical
         * workspace, a relative scope, and a prompt naming relative paths.
         * No absolute token anywhere, which is the entire point. */
        dvx_post(&c, "alice", "box-a", "directive",
                 "muse-workspace: receiver\nmuse-scope: docs/experiments/\n"
                 "muse-gate: hex_codec\n\n"
                 "Write docs/experiments/plan.md from tools/dev/README.md.\n");
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        dvx_end(&c);
        dvx_restore();
        PASS();
    }

    TEST("mail: an absolute token after a delimiter is still refused") {
        struct dvx_call c;
        dvx_isolate("afterequals");
        /* '=' delimits a token, so this slash still STARTS one. */
        dvx_post(&c, "alice", "*", "note", "path=/etc/passwd is readable");
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT(strstr(c.reply.error.code, "PATH") != NULL);
        dvx_end(&c);
        ASSERT(dvx_outbox_empty());
        dvx_restore();
        dvx_isolate("afterequals2");
        dvx_post(&c, "alice", "*", "note", "/srv/data/x is mounted");
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT(strstr(c.reply.error.code, "PATH") != NULL);
        dvx_end(&c);
        ASSERT(dvx_outbox_empty());
        dvx_restore();
        PASS();
    }

    TEST("mail: an absolute path under our own checkout is refused too") {
        struct dvx_call c;
        char root[PATH_MAX];
        char body[PATH_MAX + 64];
        /* The old rule allowed this one, by resolving a checkout root from
         * the process cwd and letting anything under it pass. A mail body
         * crosses hosts: this box's build path names something else, or
         * nothing, on the receiver, and the allowance is what made the
         * verdict on fixed bytes move with the sending process's
         * directory. Every absolute path is refused now. */
        ASSERT(zcl_devagent_checkout_root(NULL, root, sizeof(root)));
        (void)snprintf(body, sizeof(body), "built %s/build/bin/z23 already",
                       root);
        dvx_isolate("inroot");
        dvx_post(&c, "alice", "*", "note", body);
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT(strstr(c.reply.error.code, "PATH") != NULL);
        dvx_end(&c);
        ASSERT(dvx_outbox_empty());
        dvx_restore();
        PASS();
    }

    TEST("mail: a purely relative token that climbs out is refused") {
        struct dvx_call c;
        dvx_isolate("reldotdot");
        /* No leading slash and no marker word: the only thing wrong with
         * this token is the ".." segment, which climbs to exactly what an
         * absolute path would have named. */
        dvx_post(&c, "alice", "*", "note", "read tests/../../secret/x now");
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT(strstr(c.reply.error.code, "PATH") != NULL);
        dvx_end(&c);
        ASSERT(dvx_outbox_empty());
        dvx_restore();
        dvx_isolate("reldotdot2");
        dvx_post(&c, "alice", "*", "note", "read /srv/../secret/x please");
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT(strstr(c.reply.error.code, "PATH") != NULL);
        dvx_end(&c);
        ASSERT(dvx_outbox_empty());
        dvx_restore();
        PASS();
    }


    TEST("mail: a dotted filename is not a climb and stays accepted") {
        struct dvx_call c;
        dvx_isolate("dottedname");
        /* "a..b" is one segment, not a "..", and "./x" climbs nowhere. */
        dvx_post(&c, "alice", "*", "note",
                 "diff docs/a..b.md against ./docs/x.md");
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        dvx_end(&c);
        dvx_restore();
        PASS();
    }

    TEST("mail: a Windows drive path is still refused") {
        struct dvx_call c;
        dvx_isolate("drive");
        dvx_post(&c, "alice", "*", "note", "copied to C:\\Windows\\Temp\\x");
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT(strstr(c.reply.error.code, "PATH") != NULL);
        dvx_end(&c);
        ASSERT(dvx_outbox_empty());
        dvx_restore();
        PASS();
    }

#if !defined(_WIN32)
    TEST("mail: ack leaves the cursor exact and no temp file behind") {
        struct dvx_call c, a;
        char maildir[1100], path[1200], buf[64];
        FILE *f;
        DIR *d;
        struct dirent *ent;
        bool stray_tmp = false;
        dvx_isolate("acktmp");
        dvx_post(&c, "alice", "*", "note", "cursor me atomically");
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        cursor = dvx_int(&c, "cursor");
        dvx_end(&c);
        dvx_ack(&a, "alice", cursor);
        ASSERT(dvx_run(&a));
        ASSERT(dvx_ok(&a));
        dvx_end(&a);
        dvx_maildir(maildir, sizeof(maildir));
        (void)snprintf(path, sizeof(path), "%s/cursor.alice", maildir);
        f = fopen(path, "r");
        ASSERT(f != NULL);
        if (f) {
            size_t got;
            ASSERT((got = fread(buf, 1, sizeof(buf) - 1, f)) > 0);
            buf[got] = '\0';
            /* EXACTLY the cursor: decimal, newline, nothing else. */
            ASSERT(got == strlen(buf));
            ASSERT_EQ((long long)atoll(buf), cursor);
            {
                char want[64];
                (void)snprintf(want, sizeof(want), "%lld\n", cursor);
                ASSERT(strcmp(buf, want) == 0);
            }
            (void)fclose(f);
        }
        d = opendir(maildir);
        ASSERT(d != NULL);
        if (d) {
            while ((ent = readdir(d)) != NULL) {
                if (strstr(ent->d_name, ".tmp") != NULL)
                    stray_tmp = true;
            }
            (void)closedir(d);
        }
        ASSERT(!stray_tmp);
        dvx_restore();
        PASS();
    }
#endif

#if !defined(_WIN32)
    TEST("mail: two processes posting at once never interleave bytes") {
        char maildir[1100], outbox[1200];
        pid_t a, b;
        int sa = 0, sb = 0;
        struct dvx_call p;
        const struct json_value *rows;
        int found_a = 0, found_b = 0;
        FILE *f;
        char line[8192];
        int nlines = 0;
        dvx_isolate("fork");
        a = fork();
        ASSERT(a >= 0);
        if (a == 0) {
            struct dvx_call c;
            dvx_post(&c, "proc-a", "*", "note",
                     "fork body alpha 0123456789 abcdefghij");
            (void)dvx_run(&c);
            /* _exit with the handler's verdict: a failure here must fail
             * the parent even though output is captured per process. */
            _exit(dvx_ok(&c) ? 0 : 1);
        }
        b = fork();
        ASSERT(b >= 0);
        if (b == 0) {
            struct dvx_call c;
            dvx_post(&c, "proc-b", "*", "note",
                     "fork body beta 9876543210 jihgfedcba");
            (void)dvx_run(&c);
            _exit(dvx_ok(&c) ? 0 : 1);
        }
        while (waitpid(a, &sa, 0) < 0)
            ;
        while (waitpid(b, &sb, 0) < 0)
            ;
        ASSERT(WIFEXITED(sa) && WEXITSTATUS(sa) == 0);
        ASSERT(WIFEXITED(sb) && WEXITSTATUS(sb) == 0);
        /* Byte-level proof: every line of the outbox is one complete,
         * parseable row. An interleaved write would leave a line that
         * fails to parse or a body split across lines. */
        dvx_maildir(maildir, sizeof(maildir));
        (void)snprintf(outbox, sizeof(outbox), "%s/outbox.jsonl", maildir);
        f = fopen(outbox, "r");
        ASSERT(f != NULL);
        if (f) {
            while (fgets(line, sizeof(line), f)) {
                struct json_value v;
                size_t len = strlen(line);
                while (len > 0 &&
                       (line[len - 1] == '\n' || line[len - 1] == '\r'))
                    line[--len] = '\0';
                if (len == 0)
                    continue;
                nlines++;
                json_init(&v);
                ASSERT(json_read(&v, line, len) && v.type == JSON_OBJ);
                json_free(&v);
            }
            (void)fclose(f);
        }
        ASSERT_EQ((long long)nlines, 2);
        dvx_pull(&p, 0, NULL, NULL);
        ASSERT(dvx_run(&p));
        ASSERT(dvx_ok(&p));
        rows = dvx_arr(&p, "rows");
        ASSERT(rows != NULL);
        ASSERT_EQ((long long)rows->num_children, 2);
        for (size_t i = 0; i < rows->num_children; i++) {
            const char *body =
                json_get_str(json_get(&rows->children[i], "body"));
            if (body && strstr(body, "alpha"))
                found_a = 1;
            if (body && strstr(body, "beta"))
                found_b = 1;
        }
        ASSERT(found_a && found_b);
        dvx_end(&p);
        dvx_restore();
        PASS();
    }
#endif

_test_next:;
    dvx_restore();
    if (failures == 0)
        printf("test_devagent_mail: all passed\n");
    else
        printf("test_devagent_mail: %d FAILED\n", failures);
    return failures;
}
