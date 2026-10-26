/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: live-derived Z23 C23 ecosystem snapshot and text-form tests. */

#include "test/test_core.h"

#include "codeindex/codeindex.h"
#include "command/native_command.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/directory_compat.h"
#include "science/code_growth.h"
#include "science/ecosystem.h"
#include "util/spawn.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define ECO_CHECK(name_, expression_) do {                              \
    bool eco_ok_ = (expression_);                                       \
    printf("ecosystem: %s... %s\n", (name_),                            \
           eco_ok_ ? "OK" : "FAIL");                                    \
    if (!eco_ok_) failures++;                                           \
} while (0)

static bool spill(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    const size_t n = strlen(text);
    const bool ok = fwrite(text, 1, n, f) == n;
    return fclose(f) == 0 && ok;
}

static bool ecosystem_mtime_equal(const struct stat *left,
                                  const struct stat *right)
{
#if defined(_WIN32)
    /* UCRT exposes only the second-resolution compatibility member. */
    return left->st_mtime == right->st_mtime;
#elif defined(__APPLE__)
    return left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec &&
           left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec;
#else
    return left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
           left->st_mtim.tv_nsec == right->st_mtim.tv_nsec;
#endif
}

static bool mkdir_p(const char *dir, const char *rel)
{
    char path[1024];
    int n = snprintf(path, sizeof path, "%s/", dir);
    if (n <= 0 || (size_t)n >= sizeof path)
        return false;
    size_t at = (size_t)n;
    for (const char *p = rel;; p++) {
        if (*p == '/' || *p == '\0') {
            if (at >= sizeof path)
                return false;
            path[at] = '\0';
            if (!platform_directory_ensure(path, 0755))
                return false;
            if (*p == '\0')
                return true;
        }
        if (at + 1 >= sizeof path)
            return false;
        path[at++] = *p;
    }
}

static bool write_pkg(const char *dir, const char *pkg, const char *name)
{
    char rel[256];
    char path[1024];
    (void)snprintf(rel, sizeof(rel), "contexts/commons/packages/%s", pkg);
    if (!mkdir_p(dir, rel))
        return false;
    (void)snprintf(path, sizeof(path), "%s/%s/zcode-package.json", dir, rel);
    char body[256];
    (void)snprintf(body, sizeof(body),
                   "{\"schema\":1,\"name\":\"%s\",\"language\":\"c23\"}\n",
                   name);
    return spill(path, body);
}

/* All three fragments are present; an absent inventory must say which
 * command produces it, not only that its numbers are unavailable. */
static bool eco_has_all3(const char *text, const char *a, const char *b,
                         const char *c)
{
    return strstr(text, a) && strstr(text, b) && strstr(text, c);
}

static bool build_fixture(const char *dir, bool with_inventory)
{
    if (!mkdir_p(dir, "engine/src") ||
        !mkdir_p(dir, "contexts/wallet/src") ||
        !mkdir_p(dir, "contexts/explorer") ||
        !mkdir_p(dir, "tests/harness/src") ||
        !mkdir_p(dir, "docs") || !mkdir_p(dir, "build/gen"))
        return false;
    char path[1024];
    (void)snprintf(path, sizeof(path), "%s/engine/src/node.c", dir);
    if (!spill(path, "a\nb\nc\n"))
        return false;
    (void)snprintf(path, sizeof(path), "%s/contexts/wallet/src/w.c", dir);
    if (!spill(path, "x\n"))
        return false;
    (void)snprintf(path, sizeof(path), "%s/tests/harness/src/test_demo.c", dir);
    if (!spill(path, "one\ntwo\n"))
        return false;
    if (!write_pkg(dir, "alpha", "alpha/alpha") ||
        !write_pkg(dir, "beta", "beta/beta"))
        return false;
    if (!with_inventory)
        return true;
    (void)snprintf(path, sizeof(path), "%s/build/gen/CAPABILITY_INVENTORY.jsonl",
                   dir);
    return spill(path,
                 "{\"record\":\"inventory\",\"files_scanned\":3,"
                 "\"production_files\":2,\"test_files\":1}\n"
                 "{\"record\":\"capability\",\"symbols\":["
                 "{\"test_evidence\":\"registered_test_reachable\"},"
                 "{\"test_evidence\":\"none_UNPROVEN\"}]}\n"
                 "{\"record\":\"duplicate\",\"symbol_a\":\"x\"}\n"
                 "{\"record\":\"untested_invariant\",\"symbol\":\"z\"}\n");
}

static bool eco_json_str_is(const struct json_value *obj, const char *key,
                            const char *value)
{
    const struct json_value *field = json_get(obj, key);
    return field && field->type == JSON_STR && json_get_str(field) &&
           strcmp(json_get_str(field), value) == 0;
}

static bool eco_git(const char *dir, const char *const extra[], size_t extra_n)
{
    if (extra_n > 8u)
        return false;
    const char *argv[12];
    argv[0] = "git";
    argv[1] = "-C";
    argv[2] = dir;
    for (size_t i = 0; i < extra_n; i++)
        argv[3u + i] = extra[i];
    argv[3u + extra_n] = NULL;
    char out[512];
    return zcl_spawn_capture(argv, out, sizeof(out), 60000) == 0;
}

static bool build_growth_repo(const char *dir)
{
    static const char *const init[] = {"init", "-q"};
    static const char *const add[] = {"add", "-A"};
    static const char *const commit[] = {
        "-c", "user.name=z23 fixture", "-c", "user.email=fixture@z23.invalid",
        "commit", "-m", "growth fixture",
    };
    char src[1024], test[1024];
    (void)snprintf(src, sizeof(src), "%s/engine/src/a.c", dir);
    (void)snprintf(test, sizeof(test), "%s/tests/harness/src/t.c", dir);
    if (!mkdir_p(dir, "engine/src") || !mkdir_p(dir, "tests/harness/src") ||
        !mkdir_p(dir, "docs") || !mkdir_p(dir, "build/gen"))
        return false;
    return spill(src, "a\nb\n") && spill(test, "x\ny\n") &&
        eco_git(dir, init,
                sizeof(init) / sizeof(init[0])) &&
        eco_git(dir, add, sizeof(add) / sizeof(add[0])) &&
        eco_git(dir, commit, sizeof(commit) / sizeof(commit[0]));
}

/* Stop at the first needle that misses `want_present`, in array order. */
static bool eco_text_needles_match(const char *text,
                                   const char *const *needles, size_t n,
                                   bool want_present)
{
    bool ok = true;
    for (size_t i = 0; i < n && ok; i++) {
        bool present = strstr(text, needles[i]) != NULL;
        ok = present == want_present;
    }
    return ok;
}

static bool eco_format_matches_needles(
    const struct science_ecosystem_snapshot *snap,
    char *text, size_t text_cap, size_t *text_len,
    const char *const *have, size_t have_n,
    const char *const *lack, size_t lack_n)
{
    bool formatted =
        science_ecosystem_format_text(snap, text, text_cap, text_len);
    bool haves = formatted &&
                 eco_text_needles_match(text, have, have_n, true);
    bool lacks = haves && (lack_n == 0 ||
                           eco_text_needles_match(text, lack, lack_n, false));
    return lacks;
}

struct eco_json_str_row {
    const char *key;
    const char *value;
};

static bool eco_json_rows_match(const struct json_value *obj,
                                const struct eco_json_str_row *rows, size_t n)
{
    bool ok = true;
    for (size_t i = 0; i < n && ok; i++)
        ok = eco_json_str_is(obj, rows[i].key, rows[i].value);
    return ok;
}

static int eco_check_fixture_corpus(char *dir, size_t dir_cap,
                                    struct science_ecosystem_snapshot *snap)
{
    int failures = 0;
    char error[160];
    test_make_tmpdir(dir, dir_cap, "ecosystem", "snap");
    ECO_CHECK("the fixture tree builds", build_fixture(dir, true));

    ECO_CHECK("collect derives the live snapshot",
              science_ecosystem_collect(dir, NULL, snap, error,
                                        sizeof(error)));

    ECO_CHECK("package count comes from manifests, not a constant",
              snap->package_count == 2u && snap->package_listed == 2u);

    bool saw_alpha = false, saw_beta = false;
    for (uint32_t i = 0; i < snap->package_listed; i++) {
        saw_alpha |= strcmp(snap->packages[i].name, "alpha/alpha") == 0;
        saw_beta |= strcmp(snap->packages[i].name, "beta/beta") == 0;
    }
    ECO_CHECK("package names are read from zcode-package.json",
              saw_alpha && saw_beta);

    ECO_CHECK("production and test C23 lines stay separate",
              snap->corpus.non_test_lines == 4u &&
                  snap->corpus.test_lines == 2u &&
                  snap->corpus.files_walked == 3u);

    ECO_CHECK("architectural contexts are the contexts/ feature rooms",
              snap->context_count == 3u);
    bool saw_commons = false, saw_wallet = false, saw_explorer = false;
    for (uint32_t i = 0; i < snap->context_listed; i++) {
        saw_commons |= strcmp(snap->contexts[i].name, "commons") == 0;
        saw_wallet |= strcmp(snap->contexts[i].name, "wallet") == 0;
        saw_explorer |= strcmp(snap->contexts[i].name, "explorer") == 0;
    }
    ECO_CHECK("context names are the live feature rooms",
              saw_commons && saw_wallet && saw_explorer);
    return failures;
}

static int eco_check_inventory_and_text(
    const struct science_ecosystem_snapshot *snap)
{
    int failures = 0;
    ECO_CHECK("capability, reuse, and test evidence come from the inventory",
              snap->corpus.inventory_present &&
                  snap->corpus.capabilities == 1u &&
                  snap->corpus.symbols_exposed == 2u &&
                  snap->corpus.symbols_test_reached == 1u &&
                  snap->corpus.duplicates == 1u &&
                  snap->corpus.untested_invariants == 1u &&
                  snap->corpus.scope_agrees);

    ECO_CHECK("index facts stay unnamed until bound",
              !snap->index_present && !snap->source_root_sha3_present);
    ECO_CHECK("growth stays unnamed unless collected",
              !snap->growth_present);

    char text[SCIENCE_ECOSYSTEM_TEXT_MAX];
    size_t text_len = 0;
    static const char *const have[] = {
        "source_root: ",
        "packages: 2",
        "package[",
        "production_c23_lines: 4",
        "test_c23_lines: 2",
        "architectural_contexts: 3",
        "capabilities: 1",
        "duplicates: 1",
        "symbols_test_reached: 1",
        "indexed_c23_files: unavailable",
        "include_edges: unavailable",
        "growth: unavailable",
        "authority: display-only",
    };
    ECO_CHECK("text form includes every fact family",
              eco_format_matches_needles(snap, text, sizeof(text), &text_len,
                                         have, sizeof(have) / sizeof(have[0]),
                                         NULL, 0));
    return failures;
}

static int eco_check_bound_index_and_growth(
    struct science_ecosystem_snapshot *snap)
{
    int failures = 0;
    char text[SCIENCE_ECOSYSTEM_TEXT_MAX];
    size_t text_len = 0;
    char error[160];
    uint8_t sha3[32];
    memset(sha3, 0xa5, sizeof(sha3));
    struct science_ecosystem_named_count roots[1];
    memset(roots, 0, sizeof(roots));
    (void)snprintf(roots[0].name, sizeof(roots[0].name), "engine");
    (void)snprintf(roots[0].detail, sizeof(roots[0].detail), "runtime");
    roots[0].count = 2;
    science_ecosystem_bind_index(snap, true, sha3, 9u, 1u, true, 0, roots, 1u);
    text_len = 0;
    static const char *const zero_have[] = {
        "include_edges: unanswered",
        "indexed_c23_files: 9",
        "source_root_sha3: ",
    };
    static const char *const zero_lack[] = {
        "source_root_sha3: unavailable",
    };
    ECO_CHECK("zero include edges are unanswered, not a measured zero",
              eco_format_matches_needles(
                  snap, text, sizeof(text), &text_len, zero_have,
                  sizeof(zero_have) / sizeof(zero_have[0]), zero_lack,
                  sizeof(zero_lack) / sizeof(zero_lack[0])));

    science_ecosystem_bind_index(snap, true, sha3, 9u, 1u, true, 12, roots,
                                  1u);
    text_len = 0;
    static const char *const edge_have[] = {
        "include_edges: 12",
    };
    ECO_CHECK("dependency totals are the live include-edge count",
              eco_format_matches_needles(
                  snap, text, sizeof(text), &text_len, edge_have,
                  sizeof(edge_have) / sizeof(edge_have[0]), NULL, 0));

    struct science_ecosystem_named_count
        many[SCIENCE_ECOSYSTEM_ROOTS_MAX + 4u];
    memset(many, 0, sizeof(many));
    for (uint32_t i = 0; i < SCIENCE_ECOSYSTEM_ROOTS_MAX + 4u; i++) {
        (void)snprintf(many[i].name, sizeof(many[i].name), "root%" PRIu32, i);
        many[i].count = 1u;
    }
    science_ecosystem_bind_index(snap, true, sha3, 9u, 1u, true, 5, many,
                                 SCIENCE_ECOSYSTEM_ROOTS_MAX + 4u);
    text_len = 0;
    static const char *const trunc_have[] = {
        "indexed_source_roots: 20",
        "truncated: true",
    };
    ECO_CHECK("more live roots than the cap are counted and named truncated",
              snap->indexed_root_count == SCIENCE_ECOSYSTEM_ROOTS_MAX + 4u &&
                  snap->indexed_root_listed == SCIENCE_ECOSYSTEM_ROOTS_MAX &&
                  snap->indexed_roots_truncated &&
                  eco_format_matches_needles(
                      snap, text, sizeof(text), &text_len, trunc_have,
                      sizeof(trunc_have) / sizeof(trunc_have[0]), NULL, 0));

    static const char stream[] =
        "@@0000000000000000000000000000000000000001\t0\n"
        "5\t0\tlib/demo/src/a.c\n"
        "2\t0\tlib/test/src/test_a.c\n"
        "@@0000000000000000000000000000000000000002\t86400\n"
        "3\t1\tlib/demo/src/a.c\n";
    struct science_code_growth_history history;
    ECO_CHECK("growth fixture parses",
              science_code_growth_parse(stream, sizeof(stream) - 1u, &history,
                                        error, sizeof(error)));
    science_ecosystem_bind_growth(snap, &history);
    text_len = 0;
    static const char *const growth_have[] = {
        "growth: present",
        "growth_days: 2",
        "growth_latest_date: 1970-01-02",
        "growth_non_test_lines: 7",
    };
    ECO_CHECK("growth facts bind the latest UTC day and running totals",
              eco_format_matches_needles(
                  snap, text, sizeof(text), &text_len, growth_have,
                  sizeof(growth_have) / sizeof(growth_have[0]), NULL, 0));
    return failures;
}

static int eco_check_other_trees(const struct science_ecosystem_snapshot *snap,
                                 char *dir_one, size_t dir_one_cap,
                                 char *dir_bare, size_t dir_bare_cap)
{
    int failures = 0;
    char error[160];
    test_make_tmpdir(dir_one, dir_one_cap, "ecosystem", "onepkg");
    ECO_CHECK("a one-package tree builds",
              mkdir_p(dir_one, "docs") &&
                  write_pkg(dir_one, "only", "only/only"));
    struct science_ecosystem_snapshot one;
    ECO_CHECK("a different tree produces a different package count",
              science_ecosystem_collect(dir_one, NULL, &one, error,
                                        sizeof(error)) &&
                  one.package_count == 1u &&
                  snap->package_count != one.package_count);

    test_make_tmpdir(dir_bare, dir_bare_cap, "ecosystem", "bare");
    char bare_src[1024];
    (void)snprintf(bare_src, sizeof(bare_src), "%s/engine/src/a.c", dir_bare);
    ECO_CHECK("a tree without an inventory still walks",
              mkdir_p(dir_bare, "docs") && mkdir_p(dir_bare, "engine/src") &&
                  spill(bare_src, "int x;\n"));
    struct science_ecosystem_snapshot bare;
    char text[SCIENCE_ECOSYSTEM_TEXT_MAX];
    size_t text_len = 0;
    static const char *const absent[] = {
        "capabilities: 0",
        "duplicates: 0",
    };
    ECO_CHECK("missing inventory is named, never printed as zero evidence",
              science_ecosystem_collect(dir_bare, NULL, &bare, error,
                                        sizeof(error)) &&
                  !bare.corpus.inventory_present &&
                  science_ecosystem_format_text(&bare, text, sizeof(text),
                                                &text_len) &&
                  eco_has_all3(text, "capabilities: unavailable",
                               "duplicates: unavailable",
                               "make docs-capability-inventory") &&
                  eco_text_needles_match(text, absent,
                                         sizeof(absent) / sizeof(absent[0]),
                                         false));
    return failures;
}

static int eco_check_growth_repo(char *dir_repo, size_t dir_repo_cap)
{
    int failures = 0;
    char error[160];
    test_make_tmpdir(dir_repo, dir_repo_cap, "ecosystem", "growrepo");
    ECO_CHECK("an isolated real Git repo builds",
              build_growth_repo(dir_repo));
    struct science_ecosystem_collect_options with_growth = {
        .collect_growth = true,
    };
    struct science_ecosystem_snapshot repo;
    ECO_CHECK("growth collects from a real Git toplevel",
              science_ecosystem_collect(dir_repo, &with_growth, &repo, error,
                                        sizeof(error)) &&
                  repo.growth_present &&
                  repo.growth.day_count == 1u &&
                  repo.growth.non_test_lines == 2u &&
                  repo.growth.test_lines == 2u);
    char nested[640];
    (void)snprintf(nested, sizeof(nested), "%s/nested", dir_repo);
    struct science_code_growth_history refused;
    ECO_CHECK("a nested root exists for the refusal check",
              mkdir_p(dir_repo, "nested/docs"));
    ECO_CHECK("growth from a non-toplevel root refuses without walking Git",
              !science_code_growth_collect(nested, &refused, error,
                                           sizeof(error)) &&
                  strstr(error, "toplevel") != NULL);
    return failures;
}

static int eco_check_text_headless(const struct zcl_command_reply *reply,
                                   const char *dir)
{
    int failures = 0;
    const char *plain =
        json_get_str(json_get(&reply->data, "plain_text"));
    const char *const plain_need[] = {
        "packages: 2",
        dir,
        "authority: display-only",
    };
    ECO_CHECK("output=text is headless, display-only, and binds the fixture",
              reply->status == ZCL_COMMAND_STATUS_PASSED &&
                  !json_get_bool(json_get(&reply->data, "launched")) &&
                  strcmp(json_get_str(json_get(&reply->data, "authority")),
                         "display-only") == 0 &&
                  json_get_int(json_get(&reply->data, "packages")) == 2 &&
                  json_get_int(json_get(&reply->data,
                                        "production_c23_lines")) == 4 &&
                  json_get_int(json_get(&reply->data, "test_c23_lines")) == 2 &&
                  json_get_int(json_get(&reply->data,
                                        "architectural_contexts")) == 3 &&
                  plain && eco_text_needles_match(
                               plain, plain_need,
                               sizeof(plain_need) / sizeof(plain_need[0]),
                               true));
    return failures;
}

static int eco_check_text_reply_gaps(const struct zcl_command_reply *reply)
{
    int failures = 0;
    {
        const char *growth_error =
            json_get_str(json_get(&reply->data, "growth_error"));
        ECO_CHECK("growth from a nested root is named unavailable",
                  !json_get_bool(json_get(&reply->data, "growth_present")) &&
                      eco_json_str_is(&reply->data, "growth", "unavailable") &&
                      growth_error && strstr(growth_error, "toplevel"));
    }
    static const struct eco_json_str_row index_rows[] = {
        { "indexed_c23_files", "unavailable" },
        { "indexed_registry_nodes", "unavailable" },
        { "indexed_source_roots", "unavailable" },
        { "indexed_root_list", "unavailable" },
        { "include_edges", "unavailable" },
    };
    ECO_CHECK("missing index facts are unavailable JSON strings, not zeros",
              !json_get_bool(json_get(&reply->data, "index_present")) &&
                  eco_json_rows_match(&reply->data, index_rows,
                                      sizeof(index_rows) /
                                          sizeof(index_rows[0])));
    return failures;
}

static int eco_check_bare_inventory_json(struct json_value *input,
                                         const char *dir_bare)
{
    int failures = 0;
    struct zcl_command_context ctx_bare = { .source_root = dir_bare };
    struct zcl_command_request request_bare = {
        .input = input,
        .context = &ctx_bare,
    };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.app_presentation_ecosystem.v1");
    zcl_native_handle_presentation_ecosystem(&request_bare, &reply);
    static const struct eco_json_str_row rows[] = {
        { "capabilities", "unavailable" },
        { "symbols_exposed", "unavailable" },
        { "symbols_test_reached", "unavailable" },
        { "duplicates", "unavailable" },
        { "untested_invariants", "unavailable" },
        { "scope_agrees", "n/a" },
    };
    ECO_CHECK("missing inventory facts are unavailable JSON strings, not zeros",
              reply.status == ZCL_COMMAND_STATUS_PASSED &&
                  !json_get_bool(json_get(&reply.data,
                                          "inventory_present")) &&
                  eco_json_rows_match(&reply.data, rows,
                                      sizeof(rows) / sizeof(rows[0])));
    zcl_command_reply_free(&reply);
    return failures;
}

static int eco_check_stale_index_store(struct json_value *input,
                                       char *dir_idx, size_t dir_idx_cap)
{
    int failures = 0;
    test_make_tmpdir(dir_idx, dir_idx_cap, "ecosystem", "idx");
    ECO_CHECK("an index-fixture tree builds", build_fixture(dir_idx, false));
    struct codeindex *built = codeindex_open(dir_idx);
    ECO_CHECK("the test itself builds a real index store", built != NULL);
    if (built)
        codeindex_close(built);
    char store_path[1024];
    (void)snprintf(store_path, sizeof(store_path), "%s/.codeindex/index.kv",
                   dir_idx);
    struct stat store_before;
    memset(&store_before, 0, sizeof(store_before));
    ECO_CHECK("the built index store exists on disk",
              stat(store_path, &store_before) == 0);
    char node_path[1024];
    (void)snprintf(node_path, sizeof(node_path), "%s/engine/src/node.c",
                   dir_idx);
    ECO_CHECK("a source edit makes the store stale",
              spill(node_path, "a\nb\nc\nint stale_marker;\n"));
    struct zcl_command_context ctx_idx = { .source_root = dir_idx };
    struct zcl_command_request request_idx = {
        .input = input,
        .context = &ctx_idx,
    };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.app_presentation_ecosystem.v1");
    zcl_native_handle_presentation_ecosystem(&request_idx, &reply);
    struct stat store_after;
    memset(&store_after, 0, sizeof(store_after));
    ECO_CHECK("the display leaf reads a stale store instead of rebuilding",
              reply.status == ZCL_COMMAND_STATUS_PASSED &&
                  json_get_bool(json_get(&reply.data, "index_present")) &&
                  json_get_int(json_get(&reply.data, "indexed_c23_files")) >=
                      1 &&
                  stat(store_path, &store_after) == 0 &&
                  ecosystem_mtime_equal(&store_after, &store_before));
    zcl_command_reply_free(&reply);
    return failures;
}

int test_ecosystem(void)
{
    int failures = 0;
    char dir[512];
    struct science_ecosystem_snapshot snap;
    failures += eco_check_fixture_corpus(dir, sizeof(dir), &snap);
    failures += eco_check_inventory_and_text(&snap);
    failures += eco_check_bound_index_and_growth(&snap);

    char dir_one[512];
    char dir_bare[512];
    failures += eco_check_other_trees(&snap, dir_one, sizeof(dir_one),
                                      dir_bare, sizeof(dir_bare));

    char dir_repo[512];
    failures += eco_check_growth_repo(dir_repo, sizeof(dir_repo));

    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    json_push_kv_str(&input, "output", "text");
    struct zcl_command_context ctx = {
        .source_root = dir,
    };
    struct zcl_command_request request = {
        .input = &input,
        .context = &ctx,
    };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.app_presentation_ecosystem.v1");
    zcl_native_handle_presentation_ecosystem(&request, &reply);
    failures += eco_check_text_headless(&reply, dir);
    failures += eco_check_text_reply_gaps(&reply);
    zcl_command_reply_free(&reply);

    failures += eco_check_bare_inventory_json(&input, dir_bare);

    char dir_idx[512];
    failures += eco_check_stale_index_store(&input, dir_idx, sizeof(dir_idx));

    json_free(&input);
    json_init(&input);
    json_set_object(&input);
    json_push_kv_str(&input, "output", "json");
    zcl_command_reply_init(&reply, "zcl.app_presentation_ecosystem.v1");
    zcl_native_handle_presentation_ecosystem(&request, &reply);
    ECO_CHECK("output must be native or text",
              reply.status == ZCL_COMMAND_STATUS_FAILED);
    zcl_command_reply_free(&reply);
    json_free(&input);

    (void)test_rm_rf_recursive(dir);
    (void)test_rm_rf_recursive(dir_one);
    (void)test_rm_rf_recursive(dir_bare);
    (void)test_rm_rf_recursive(dir_repo);
    (void)test_rm_rf_recursive(dir_idx);
    return failures;
}
