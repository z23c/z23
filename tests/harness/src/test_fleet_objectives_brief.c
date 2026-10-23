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
};

/* A node at 2200 MB (a product row over its 1024 target), one oversized lint
 * file, and three cyclomatic pin rows. Everything else is unmeasured. */
static bool fob_fixture(const char *root, struct fob_paths *p)
{
    char file[700];
    (void)snprintf(p->brief, sizeof(p->brief), "%s/brief.json", root);
    (void)snprintf(p->lintc, sizeof(p->lintc), "%s/lintc", root);
    (void)snprintf(p->baseline, sizeof(p->baseline), "%s/baseline.txt", root);
    (void)snprintf(file, sizeof(file), "%s/big.c", p->lintc);
    return mkdir(p->lintc, 0700) == 0 &&
           fob_write(p->brief, "{\"hstar\":1000,\"gap\":0,\"rss_mb\":2200,"
                               "\"serving\":true}") &&
           fob_write_n_lines(file, 1600) &&
           fob_write(p->baseline, "a/x.c:f:16\na/y.c:g:17\na/z.c:h:18\n");
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
    (void)json_push_kv_str(&c->input, "repo", FOB_NOWHERE "/repo");
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
    }
    (void)unsetenv("ZCL_LAND_OBJECTIVES_DATADIR");
    (void)test_rm_rf_recursive(root);
    if (failures == 0)
        printf("test_fleet_objectives_brief: all passed\n");
    else
        printf("test_fleet_objectives_brief: %d FAILED\n", failures);
    return failures;
}
