/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for fleet.objectives.brief
 * (tools/command/native_fleet_objectives_brief.c).
 *
 * The leaf is driven over fixture inputs only: a status-brief file, a
 * lintc directory, a cyclomatic baseline and paths that do not exist, so no
 * case reads the live land state, a datadir or a node. The measured rows come
 * from fleet.objectives itself, so the pick is compared against its `next`.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_fleet_objectives.h"
#include "command/work_card.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define FOB_PATH "fleet.objectives.brief"
#define FOB_NOWHERE "/nonexistent/z23-fob"

/* The work rows, pasted from the same def the leaf compiles in. */
struct fob_work {
    const char *id;
    int runner_ok;
    const char *owned;
};

static const struct fob_work k_fob_work[] = {
#define Z23_OBJECTIVE_WORK(id_, runner_ok_, owned_, acceptance_, stop_if_) \
    {id_, runner_ok_, owned_},
#include "../../../engine/composition/objective_work.def"
#undef Z23_OBJECTIVE_WORK
};
#define FOB_WORK_COUNT (sizeof(k_fob_work) / sizeof(k_fob_work[0]))

static bool fob_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    size_t len = strlen(text);
    bool wrote;
    if (!f)
        return false;
    wrote = fwrite(text, 1, len, f) == len;
    return fclose(f) == 0 && wrote;
}

static bool fob_write_n_lines(const char *path, int n)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    for (int i = 0; i < n; i++)
        if (fputs("x\n", f) < 0) {
            (void)fclose(f);
            return false;
        }
    return fclose(f) == 0;
}

struct fob_paths {
    char brief[600];
    char lintc[600];
    char baseline[600];
    char repo[600];
    char exclude[300];
};

/* Writes repo/<rel> with `lines` lines, making the parent directories. */
static bool fob_repo_file(const struct fob_paths *p, const char *rel, int lines)
{
    char path[1300], dir[1300];
    char *slash;
    (void)snprintf(path, sizeof(path), "%s/%s", p->repo, rel);
    (void)snprintf(dir, sizeof(dir), "%s", path);
    slash = strrchr(dir, '/');
    if (!slash)
        return false;
    for (char *c = dir + strlen(p->repo) + 1; c <= slash; c++) {
        char keep = *c;
        if (*c != '/' && c != slash)
            continue;
        *c = '\0';
        if (mkdir(dir, 0700) != 0 && errno != EEXIST)
            return false;
        *c = keep;
    }
    return fob_write_n_lines(path, lines);
}

/* A node at 2200 MB (a product row over its 1024 target), one oversized lint
 * file, and three cyclomatic pin rows in three small repo files. Everything
 * else is unmeasured. */
static bool fob_fixture(const char *root, struct fob_paths *p)
{
    char file[700];
    (void)snprintf(p->brief, sizeof(p->brief), "%s/brief.json", root);
    (void)snprintf(p->lintc, sizeof(p->lintc), "%s/lintc", root);
    (void)snprintf(p->baseline, sizeof(p->baseline), "%s/baseline.txt", root);
    (void)snprintf(p->repo, sizeof(p->repo), "%s/repo", root);
    p->exclude[0] = '\0';
    (void)snprintf(file, sizeof(file), "%s/big.c", p->lintc);
    return mkdir(p->lintc, 0700) == 0 && mkdir(p->repo, 0700) == 0 &&
           fob_write(p->brief, "{\"hstar\":1000,\"gap\":0,\"rss_mb\":2200,"
                               "\"serving\":true}") &&
           fob_write_n_lines(file, 1600) &&
           fob_repo_file(p, "apps/x.c", 10) &&
           fob_repo_file(p, "apps/y.c", 10) &&
           fob_repo_file(p, "apps/z.c", 10) &&
           fob_write(p->baseline,
                     "apps/x.c:f:16\napps/y.c:g:17\napps/z.c:h:18\n");
}

struct fob_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void fob_begin(struct fob_call *c, const char *path,
                      const struct fob_paths *p, const char *id,
                      bool runner_only)
{
    json_init(&c->input);
    json_set_object(&c->input);
    (void)json_push_kv_str(&c->input, "brief", p->brief);
    (void)json_push_kv_str(&c->input, "lintc_dir", p->lintc);
    (void)json_push_kv_str(&c->input, "baseline", p->baseline);
    (void)json_push_kv_str(&c->input, "outcomes", FOB_NOWHERE "/o.jsonl");
    (void)json_push_kv_str(&c->input, "attempts_dir", FOB_NOWHERE "/a");
    (void)json_push_kv_str(&c->input, "repo", p->repo);
    if (p->exclude[0])
        (void)json_push_kv_str(&c->input, "exclude", p->exclude);
    if (id)
        (void)json_push_kv_str(&c->input, "id", id);
    if (runner_only)
        (void)json_push_kv_bool(&c->input, "runner_ok_only", true);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    zcl_command_reply_init(&c->reply, "zcl.test.v1");
}

static void fob_end(struct fob_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool fob_brief(struct fob_call *c, const struct fob_paths *p,
                      const char *id, bool runner_only)
{
    char why[192];
    fob_begin(c, FOB_PATH, p, id, runner_only);
    if (c->request.spec &&
        !zcl_command_registry_input_validate(c->request.spec, &c->input, why,
                                             sizeof(why))) {
        printf("[input rejected: %s] ", why);
        return false;
    }
    zcl_native_handle_fleet_objectives_brief(&c->request, &c->reply);
    return true;
}

static const char *fob_objective_id(const struct fob_call *c)
{
    return json_get_str(json_get(json_get(&c->reply.data, "objective"), "id"));
}

static bool fob_has_str(const struct json_value *arr, const char *want)
{
    for (size_t i = 0; arr && i < json_size(arr); i++)
        if (strcmp(json_get_str(json_at(arr, i)), want) == 0)
            return true;
    return false;
}

/* What a runner_ok row must never own, as literal path prefixes: the
 * consensus core, the reducer, the wallet, consensus storage and the land
 * driver (objective_work.def's runner_ok_ rule). */
static const char *const k_fob_runner_forbidden[] = {
    "core/", "engine/reducer/", "contexts/wallet/", "engine/modules/storage/",
    "tools/command/native_dev_land", "tools/dev/",
};

/* True when one glob of the comma list `csv` reaches a forbidden prefix:
 * its literal part (up to the first '*') either sits inside the prefix or is
 * an ancestor of it, as "tools/" is of "tools/command/native_dev_land". */
static bool fob_owned_reaches_forbidden(const char *csv, char *hit,
                                        size_t hit_size)
{
    const char *at = csv;
    while (*at) {
        size_t len = strcspn(at, ",");
        size_t lit = strcspn(at, ",*");
        for (size_t i = 0; i < sizeof(k_fob_runner_forbidden) /
                                   sizeof(k_fob_runner_forbidden[0]);
             i++) {
            const char *f = k_fob_runner_forbidden[i];
            size_t flen = strlen(f);
            size_t n = lit < flen ? lit : flen;
            if (strncmp(at, f, n) == 0) {
                (void)snprintf(hit, hit_size, "%.*s reaches %s", (int)len, at,
                               f);
                return true;
            }
        }
        at += len;
        if (*at)
            at++;
    }
    return false;
}

static int fob_case_runner_paths(void)
{
    int failures = 0;
    char hit[256];
    TEST("brief: no runner_ok row owns a path under core/, the reducer, the "
         "wallet, consensus storage or the land driver") {
        for (size_t j = 0; j < FOB_WORK_COUNT; j++) {
            hit[0] = '\0';
            if (k_fob_work[j].runner_ok &&
                fob_owned_reaches_forbidden(k_fob_work[j].owned, hit,
                                            sizeof(hit)))
                printf("  %s: %s\n", k_fob_work[j].id, hit);
            ASSERT(hit[0] == '\0');
        }
        ASSERT(fob_owned_reaches_forbidden("apps/**,tools/**", hit,
                                           sizeof(hit)));
        ASSERT(fob_owned_reaches_forbidden("engine/reducer/src/x.c", hit,
                                           sizeof(hit)));
        ASSERT(!fob_owned_reaches_forbidden("tools/lint/lintc/**", hit,
                                            sizeof(hit)));
        PASS();
    }
    TEST("brief: the registry types runner_ok_only as a boolean") {
        struct zcl_command_input_descriptor d;
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(), FOB_PATH, NULL);
        ASSERT(spec != NULL);
        ASSERT(zcl_command_registry_input_descriptor(spec, "runner_ok_only",
                                                     &d));
        ASSERT_EQ(d.type, JSON_BOOL);
        PASS();
    }
_test_next:;
    return failures;
}

static int fob_case_rows(void)
{
    int failures = 0;
    const struct zcl_objective_row *catalog;
    size_t n = zcl_objectives_catalog(&catalog);
    TEST("brief: every catalog objective has exactly one work row and no "
         "work row is an orphan") {
        ASSERT_EQ(n, (size_t)FOB_WORK_COUNT);
        for (size_t i = 0; i < n; i++) {
            int hits = 0;
            for (size_t j = 0; j < FOB_WORK_COUNT; j++)
                hits += strcmp(catalog[i].id, k_fob_work[j].id) == 0;
            ASSERT_EQ(hits, 1);
        }
        for (size_t j = 0; j < FOB_WORK_COUNT; j++) {
            int hits = 0;
            for (size_t i = 0; i < n; i++)
                hits += strcmp(catalog[i].id, k_fob_work[j].id) == 0;
            ASSERT_EQ(hits, 1);
            if (strncmp(k_fob_work[j].id, "node_", 5) == 0)
                ASSERT_EQ(k_fob_work[j].runner_ok, 0);
        }
        PASS();
    }
_test_next:;
    return failures;
}

static int fob_case_pick(const struct fob_paths *p)
{
    int failures = 0;
    struct fob_call c, next;
    TEST("brief: the plain brief picks the id fleet.objectives names as next") {
        ASSERT(fob_brief(&c, p, NULL, false));
        fob_begin(&next, "fleet.objectives", p, NULL, false);
        zcl_native_handle_fleet_objectives(&next.request, &next.reply);
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(fob_objective_id(&c),
                      json_get_str(json_get(json_get(&next.reply.data, "next"),
                                            "id")));
        ASSERT_STR_EQ(fob_objective_id(&c), "node_rss_mb");
        ASSERT(!json_get_bool(json_get(json_get(&c.reply.data, "objective"),
                                       "runner_ok")));
        fob_end(&next);
        fob_end(&c);
        PASS();
    }
    TEST("brief: runner_ok_only skips node rows and picks a runner_ok row") {
        ASSERT(fob_brief(&c, p, NULL, true));
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strncmp(fob_objective_id(&c), "node_", 5) != 0);
        ASSERT_STR_EQ(fob_objective_id(&c), "functions_over_complexity_cap");
        ASSERT(json_get_bool(json_get(json_get(&c.reply.data, "objective"),
                                      "runner_ok")));
        fob_end(&c);
        PASS();
    }
    TEST("brief: the validator refuses a text runner_ok_only, and a direct "
         "caller's text \"true\" narrows the pick the same way") {
        char why[192];
        fob_begin(&c, FOB_PATH, p, NULL, false);
        ASSERT(json_push_kv_str(&c.input, "runner_ok_only", "true"));
        ASSERT(c.request.spec != NULL);
        ASSERT(!zcl_command_registry_input_validate(c.request.spec, &c.input,
                                                    why, sizeof(why)));
        zcl_native_handle_fleet_objectives_brief(&c.request, &c.reply);
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(fob_objective_id(&c), "functions_over_complexity_cap");
        fob_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int fob_case_card(const struct fob_paths *p)
{
    int failures = 0;
    struct fob_call c;
    struct json_value card;
    char wire[4096];
    struct work_card parsed;
    json_init(&card);
    TEST("brief: the card carries owned and acceptance and validates as a "
         "work card once it has a base") {
        size_t len;
        ASSERT(fob_brief(&c, p, NULL, true));
        ASSERT(json_size(json_get(&c.reply.data, "owned")) > 0);
        ASSERT(fob_has_str(json_get(&c.reply.data, "forbidden"), "core/"));
        ASSERT(json_get_str(json_get(&c.reply.data, "acceptance"))[0] != '\0');
        ASSERT(json_size(json_get(&c.reply.data, "stop_if")) > 0);
        ASSERT(json_get(json_get(&c.reply.data, "objective"), "gap") != NULL);
        ASSERT(json_get(&c.reply.data, "base") == NULL);
        ASSERT(json_copy_checked(&card, &c.reply.data));
        ASSERT(json_push_kv_str(&card, "base",
                                "41451675f0000000000000000000000000000000"));
        len = json_write(&card, wire, sizeof(wire));
        ASSERT(len < sizeof(wire));
        ASSERT_EQ(work_card_validate(wire, len, &parsed), WORK_CARD_OK);
        fob_end(&c);
        PASS();
    }
_test_next:;
    json_free(&card);
    return failures;
}

static int fob_case_refusals(const struct fob_paths *p)
{
    int failures = 0;
    struct fob_call c;
    TEST("brief: an unknown id is refused with an explanatory body") {
        ASSERT(fob_brief(&c, p, "no_such_objective", false));
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(c.reply.error.code, "UNKNOWN_OBJECTIVE");
        ASSERT(strstr(c.reply.error.message, "no_such_objective") != NULL);
        ASSERT(strstr(c.reply.error.message, "catalog") != NULL);
        fob_end(&c);
        PASS();
    }
    TEST("brief: an explicit id briefs that row, and a node row is refused "
         "under runner_ok_only") {
        ASSERT(fob_brief(&c, p, "lint_families_over_ceiling", false));
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(fob_objective_id(&c), "lint_families_over_ceiling");
        fob_end(&c);
        ASSERT(fob_brief(&c, p, "node_rss_mb", true));
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(c.reply.error.code, "OBJECTIVE_NOT_ACTIONABLE");
        ASSERT(strstr(c.reply.error.message, "runner_ok") != NULL);
        fob_end(&c);
        ASSERT(fob_brief(&c, p, "node_tip_lag_blocks", false));
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT(strstr(c.reply.error.message, "node_tip_lag_blocks") != NULL);
        fob_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

/* What grades the runner or pins Commons: literal prefixes (a path ending in
 * '/' is a tree) every card must forbid and no runner_ok row may own inside. */
static const char *const k_fob_protected[] = {
    "tools/command/native_fleet_objectives",
    "engine/composition/objective_work.def",
    "engine/composition/objectives.def",
    "engine/composition/commands/fleet.def",
    "tools/lint/lintc/",
    "platform/deploy/",
#define ZCODE_PACKAGE(name_, dir_, ...) dir_ "/",
#include "../../../engine/composition/zcode_package_registry.def"
#undef ZCODE_PACKAGE
};
#define FOB_PROTECTED_COUNT \
    (sizeof(k_fob_protected) / sizeof(k_fob_protected[0]))

/* True when a token of the comma list `csv` starts inside a protected path. */
static bool fob_owned_inside_protected(const char *csv)
{
    const char *at = csv;
    while (*at) {
        size_t len = strcspn(at, ",");
        for (size_t i = 0; i < FOB_PROTECTED_COUNT; i++)
            if (strncmp(at, k_fob_protected[i],
                        strlen(k_fob_protected[i])) == 0)
                return true;
        at += len;
        if (*at)
            at++;
    }
    return false;
}

/* True when a forbidden-list token is a prefix of `path` (a trailing '*'
 * ends the literal part). */
static bool fob_card_refuses(const struct json_value *forbidden,
                             const char *path)
{
    for (size_t i = 0; forbidden && i < json_size(forbidden); i++) {
        const char *tok = json_get_str(json_at(forbidden, i));
        if (strncmp(path, tok, strcspn(tok, "*")) == 0)
            return true;
    }
    return false;
}

static int fob_case_protected(const struct fob_paths *p)
{
    int failures = 0;
    struct fob_call c;
    char path[300];
    TEST("brief: the card forbids every runner-grading path and every path "
         "under a pinned Commons root") {
        ASSERT(fob_brief(&c, p, NULL, true));
        for (size_t i = 0; i < FOB_PROTECTED_COUNT; i++) {
            const char *pre = k_fob_protected[i];
            bool tree = pre[strlen(pre) - 1] == '/';
            bool leaf = strstr(pre, ".def") != NULL;
            (void)snprintf(path, sizeof(path), "%s%s", pre,
                           leaf ? "" : (tree ? "src/x.c" : "_x.c"));
            if (!fob_card_refuses(json_get(&c.reply.data, "forbidden"), path))
                printf("  not forbidden: %s\n", path);
            ASSERT(fob_card_refuses(json_get(&c.reply.data, "forbidden"),
                                    path));
        }
        ASSERT(fob_card_refuses(json_get(&c.reply.data, "forbidden"),
                                "platform/modules/base/src/x.c"));
        ASSERT(fob_card_refuses(json_get(&c.reply.data, "forbidden"),
                                "contexts/commons/modules/vcs/src/x.c"));
        ASSERT(!fob_card_refuses(json_get(&c.reply.data, "forbidden"),
                                 "apps/x.c"));
        fob_end(&c);
        PASS();
    }
    TEST("brief: no runner_ok row owns a path inside a protected path") {
        for (size_t j = 0; j < FOB_WORK_COUNT; j++)
            if (k_fob_work[j].runner_ok)
                ASSERT(!fob_owned_inside_protected(k_fob_work[j].owned));
        ASSERT(fob_owned_inside_protected("tools/lint/lintc/**"));
        ASSERT(fob_owned_inside_protected(
            "tools/command/native_fleet_objectives*.c"));
        PASS();
    }
_test_next:;
    return failures;
}

/* A repo of pinned files for the narrowing: a pinned-root file, a test file,
 * an over-1300-line file, an excluded-by-name file, and eligible apps files
 * a (2 pins), c and d (4 pins each, max M 17). */
static bool fob_narrow_fixture(const char *root, struct fob_paths *p)
{
    (void)snprintf(p->baseline, sizeof(p->baseline), "%s/narrow.txt", root);
    p->exclude[0] = '\0';
    return fob_repo_file(p, "platform/modules/base/src/p.c", 10) &&
           fob_repo_file(p, "tests/harness/src/t.c", 10) &&
           fob_repo_file(p, "apps/big.c", 1400) &&
           fob_repo_file(p, "apps/ex.c", 10) &&
           fob_repo_file(p, "apps/a.c", 10) &&
           fob_repo_file(p, "apps/c.c", 10) &&
           fob_repo_file(p, "apps/d.c", 10) &&
           fob_write(p->baseline,
                     "platform/modules/base/src/p.c:f:16\n"
                     "platform/modules/base/src/p.c:g:16\n"
                     "platform/modules/base/src/p.c:h:16\n"
                     "tests/harness/src/t.c:f:16\n"
                     "apps/big.c:f:16\napps/big.c:g:16\napps/big.c:h:16\n"
                     "apps/ex.c:f:16\napps/ex.c:g:16\napps/ex.c:h:16\n"
                     "apps/gone.c:f:16\napps/gone.c:g:16\napps/gone.c:h:16\n"
                     "apps/a.c:f:16\napps/a.c:g:16\n"
                     "apps/c.c:f:17\napps/c.c:g:16\napps/c.c:h:16\n"
                     "apps/c.c:i#2:16\n"
                     "apps/d.c:f:17\napps/d.c:g:16\napps/d.c:h:16\n"
                     "apps/d.c:i:16\n");
}

/* Briefs the complexity card with `exclude` and checks the chosen file. */
static bool fob_narrow_picks(struct fob_paths *p, const char *exclude,
                             const char *want_file)
{
    struct fob_call c;
    bool ok;
    (void)snprintf(p->exclude, sizeof(p->exclude), "apps/ex.c%s%s",
                   exclude[0] ? "," : "", exclude);
    ok = fob_brief(&c, p, NULL, true) &&
         c.reply.status == ZCL_COMMAND_STATUS_PASSED;
    if (ok && want_file) {
        const struct json_value *owned = json_get(&c.reply.data, "owned");
        ok = strcmp(json_get_str(json_get(&c.reply.data, "target_file")),
                    want_file) == 0 &&
             json_size(owned) == 2 &&
             strcmp(json_get_str(json_at(owned, 0)), want_file) == 0 &&
             strcmp(json_get_str(json_at(owned, 1)),
                    "tools/lint/cyclomatic_complexity_baseline.txt") == 0;
    } else if (ok) {
        ok = json_get(&c.reply.data, "owned") == NULL &&
             strcmp(json_get_str(json_get(&c.reply.data, "reason")),
                    "NO_ELIGIBLE_FILE") == 0;
    }
    fob_end(&c);
    return ok;
}

static int fob_case_narrow(const char *root, struct fob_paths *p)
{
    int failures = 0;
    struct fob_call c;
    TEST("brief: the complexity card narrows to the one file with 3-6 pins, "
         "the lowest max M, then path order") {
        ASSERT(fob_narrow_fixture(root, p));
        ASSERT(fob_narrow_picks(p, "", "apps/c.c"));
        ASSERT(fob_brief(&c, p, NULL, true));
        ASSERT(json_get(&c.reply.data, "pins") != NULL);
        ASSERT_EQ(json_size(json_get(&c.reply.data, "pins")), (size_t)4);
        ASSERT_STR_EQ(json_get_str(json_get(json_at(json_get(&c.reply.data,
                                                             "pins"), 0),
                                            "function")), "f");
        ASSERT_EQ(json_get_int(json_get(json_at(json_get(&c.reply.data,
                                                         "pins"), 0), "m")), 17);
        ASSERT(strstr(json_get_str(json_get(&c.reply.data, "outcome")),
                      "Bring 4 functions in apps/c.c to cyclomatic "
                      "complexity <= 15 by behaviour-preserving "
                      "extraction.") != NULL);
        fob_end(&c);
        PASS();
    }
    TEST("brief: exclude skips files in flight, and a file-less answer is a "
         "typed no-card") {
        p->exclude[0] = '\0';
        ASSERT(fob_brief(&c, p, NULL, true));
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "target_file")),
                      "apps/ex.c");
        fob_end(&c);
        ASSERT(fob_narrow_picks(p, "apps/c.c", "apps/d.c"));
        ASSERT(fob_narrow_picks(p, "apps/zzz.c,apps/c.c", "apps/d.c"));
        ASSERT(fob_narrow_picks(p, "apps/c.c,apps/d.c", "apps/a.c"));
        ASSERT(fob_narrow_picks(p, "apps/c.c,apps/d.c,apps/a.c", NULL));
        PASS();
    }
    TEST("brief: other objectives' cards are not narrowed") {
        p->exclude[0] = '\0';
        ASSERT(fob_brief(&c, p, "node_rss_mb", false));
        ASSERT(json_get(&c.reply.data, "target_file") == NULL);
        ASSERT(json_get(&c.reply.data, "pins") == NULL);
        fob_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

#define FOB_HARD_ID "baseline_hardening_banned_str"
#define FOB_HARD_PATH "tools/lint/hardening_ratchet_baseline.txt"

/* A hardening baseline under p->repo: a comment, another rule's row, a row in
 * a forbidden tree, a row under a tests/ directory, and two eligible rows
 * listed out of path order. Every named file exists and is small. */
static bool fob_hard_fixture(const struct fob_paths *p)
{
    char file[700];
    (void)snprintf(file, sizeof(file), "%s/%s", p->repo, FOB_HARD_PATH);
    return fob_repo_file(p, FOB_HARD_PATH, 1) &&
           fob_repo_file(p, "core/m.c", 10) &&
           fob_repo_file(p, "apps/q/tests/t.c", 10) &&
           fob_repo_file(p, "apps/aa.c", 10) &&
           fob_repo_file(p, "apps/zz.c", 10) &&
           fob_write(file,
                     "# header\n"
                     "banned-str core/m.c 3\n"
                     "banned-str apps/q/tests/t.c 5\n"
                     "banned-str apps/zz.c 2\n"
                     "banned-str apps/aa.c 1\n"
                     "local-reader apps/aa.c 7\n");
}

static bool fob_hard_card_ok(const struct fob_call *c)
{
    const struct json_value *d = &c->reply.data;
    const struct json_value *owned = json_get(d, "owned");
    return strcmp(json_get_str(json_get(d, "kind")), "baseline_row") == 0 &&
           strcmp(json_get_str(json_get(d, "level")), "haiku") == 0 &&
           strcmp(json_get_str(json_get(d, "target_file")), "apps/aa.c") == 0 &&
           strcmp(json_get_str(json_get(d, "baseline")), FOB_HARD_PATH) == 0 &&
           strcmp(json_get_str(json_get(d, "row")),
                  "banned-str apps/aa.c 1") == 0 &&
           strcmp(json_get_str(json_get(d, "verify")),
                  "build/bin/z23-lint check-hardening-ratchet") == 0 &&
           strcmp(json_get_str(json_get(d, "acceptance")),
                  json_get_str(json_get(d, "verify"))) == 0 &&
           strstr(json_get_str(json_get(d, "recipe")), "snprintf") != NULL &&
           json_get_str(json_get(d, "review_focus"))[0] != '\0' &&
           json_size(owned) == 2 &&
           strcmp(json_get_str(json_at(owned, 0)), "apps/aa.c") == 0 &&
           strcmp(json_get_str(json_at(owned, 1)), FOB_HARD_PATH) == 0 &&
           json_get(d, "pins") == NULL;
}

static int fob_case_baseline_row(struct fob_paths *p)
{
    int failures = 0;
    struct fob_call c;
    char file[700];
    struct zcl_objectives_options o = {0};
    struct zcl_objective_value v;
    (void)snprintf(file, sizeof(file), "%s/%s", p->repo, FOB_HARD_PATH);
    o.repo = p->repo;
    TEST("brief: a baseline objective picks the first eligible row by path "
         "order and emits every card field") {
        ASSERT(fob_hard_fixture(p));
        p->exclude[0] = '\0';
        ASSERT(fob_brief(&c, p, FOB_HARD_ID, true));
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(fob_objective_id(&c), FOB_HARD_ID);
        ASSERT(fob_hard_card_ok(&c));
        fob_end(&c);
        PASS();
    }
    TEST("brief: exclude skips the baseline row, and no eligible row is a "
         "typed no-card") {
        (void)snprintf(p->exclude, sizeof(p->exclude), "apps/aa.c");
        ASSERT(fob_brief(&c, p, FOB_HARD_ID, true));
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "target_file")),
                      "apps/zz.c");
        fob_end(&c);
        (void)snprintf(p->exclude, sizeof(p->exclude), "apps/aa.c,apps/zz.c");
        ASSERT(fob_brief(&c, p, FOB_HARD_ID, true));
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get(&c.reply.data, "target_file") == NULL);
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "reason")),
                      "NO_ELIGIBLE_ROW");
        p->exclude[0] = '\0';
        fob_end(&c);
        PASS();
    }
    TEST("objectives: the banned-str producer sums the COUNT of banned-str "
         "rows only, and refuses a malformed row") {
        v = zcl_objectives_measure(&o, FOB_HARD_ID);
        ASSERT(v.measured);
        ASSERT_EQ(v.value, 11);
        ASSERT(fob_write(file, "banned-str apps/a.c 2\nbanned-str apps/b.c x\n"));
        v = zcl_objectives_measure(&o, FOB_HARD_ID);
        ASSERT(!v.measured);
        ASSERT(strstr(v.reason, "malformed") != NULL);
        ASSERT_EQ(remove(file), 0);
        v = zcl_objectives_measure(&o, FOB_HARD_ID);
        ASSERT(!v.measured);
        PASS();
    }
_test_next:;
    return failures;
}

int test_fleet_objectives_brief(void);
int test_fleet_objectives_brief(void)
{
    int failures = 0;
    char root[512];
    struct fob_paths paths;
    test_make_tmpdir(root, sizeof(root), "fleet_objectives_brief", "root");
    (void)setenv("ZCL_LAND_OBJECTIVES_DATADIR", FOB_NOWHERE "/datadir", 1);
    failures += fob_case_rows();
    failures += fob_case_runner_paths();
    if (!fob_fixture(root, &paths)) {
        printf("fleet_objectives_brief: cannot build the fixture tree\n");
        failures++;
    } else {
        failures += fob_case_pick(&paths);
        failures += fob_case_card(&paths);
        failures += fob_case_refusals(&paths);
        failures += fob_case_protected(&paths);
        failures += fob_case_narrow(root, &paths);
        failures += fob_case_baseline_row(&paths);
    }
    (void)unsetenv("ZCL_LAND_OBJECTIVES_DATADIR");
    (void)test_rm_rf_recursive(root);
    if (failures == 0)
        printf("test_fleet_objectives_brief: all passed\n");
    else
        printf("test_fleet_objectives_brief: %d FAILED\n", failures);
    return failures;
}
