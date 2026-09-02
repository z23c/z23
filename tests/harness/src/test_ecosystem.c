/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: live-derived Z23 C23 ecosystem snapshot and text-form tests. */

#include "test/test_core.h"

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

static bool build_fixture(const char *dir, bool with_inventory)
{
    if (!mkdir_p(dir, "engine/src") ||
        !mkdir_p(dir, "contexts/wallet/src") ||
        !mkdir_p(dir, "contexts/explorer") ||
        !mkdir_p(dir, "tests/harness/src") ||
        !mkdir_p(dir, "docs"))
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
    (void)snprintf(path, sizeof(path), "%s/docs/CAPABILITY_INVENTORY.jsonl",
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
        !mkdir_p(dir, "docs"))
        return false;
    return spill(src, "a\nb\n") && spill(test, "x\ny\n") &&
        eco_git(dir, init,
                sizeof(init) / sizeof(init[0])) &&
        eco_git(dir, add, sizeof(add) / sizeof(add[0])) &&
        eco_git(dir, commit, sizeof(commit) / sizeof(commit[0]));
}

int test_ecosystem(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof(dir), "ecosystem", "snap");
    ECO_CHECK("the fixture tree builds", build_fixture(dir, true));

    struct science_ecosystem_snapshot snap;
    char error[160];
    ECO_CHECK("collect derives the live snapshot",
              science_ecosystem_collect(dir, NULL, &snap, error,
                                        sizeof(error)));

    ECO_CHECK("package count comes from manifests, not a constant",
              snap.package_count == 2u && snap.package_listed == 2u);
    bool saw_alpha = false, saw_beta = false;
    for (uint32_t i = 0; i < snap.package_listed; i++) {
        saw_alpha |= strcmp(snap.packages[i].name, "alpha/alpha") == 0;
        saw_beta |= strcmp(snap.packages[i].name, "beta/beta") == 0;
    }
    ECO_CHECK("package names are read from zcode-package.json",
              saw_alpha && saw_beta);

    ECO_CHECK("production and test C23 lines stay separate",
              snap.corpus.non_test_lines == 4u &&
                  snap.corpus.test_lines == 2u &&
                  snap.corpus.files_walked == 3u);

    ECO_CHECK("architectural contexts are the contexts/ feature rooms",
              snap.context_count == 3u);
    bool saw_commons = false, saw_wallet = false, saw_explorer = false;
    for (uint32_t i = 0; i < snap.context_listed; i++) {
        saw_commons |= strcmp(snap.contexts[i].name, "commons") == 0;
        saw_wallet |= strcmp(snap.contexts[i].name, "wallet") == 0;
        saw_explorer |= strcmp(snap.contexts[i].name, "explorer") == 0;
    }
    ECO_CHECK("context names are the live feature rooms",
              saw_commons && saw_wallet && saw_explorer);

    ECO_CHECK("capability, reuse, and test evidence come from the inventory",
              snap.corpus.inventory_present &&
                  snap.corpus.capabilities == 1u &&
                  snap.corpus.symbols_exposed == 2u &&
                  snap.corpus.symbols_test_reached == 1u &&
                  snap.corpus.duplicates == 1u &&
                  snap.corpus.untested_invariants == 1u &&
                  snap.corpus.scope_agrees);

    ECO_CHECK("index facts stay unnamed until bound",
              !snap.index_present && !snap.source_root_sha3_present);
    ECO_CHECK("growth stays unnamed unless collected",
              !snap.growth_present);

    char text[SCIENCE_ECOSYSTEM_TEXT_MAX];
    size_t text_len = 0;
    ECO_CHECK("text form includes every fact family",
              science_ecosystem_format_text(&snap, text, sizeof(text),
                                            &text_len) &&
                  strstr(text, "source_root: ") &&
                  strstr(text, "packages: 2") &&
                  strstr(text, "package[") &&
                  strstr(text, "production_c23_lines: 4") &&
                  strstr(text, "test_c23_lines: 2") &&
                  strstr(text, "architectural_contexts: 3") &&
                  strstr(text, "capabilities: 1") &&
                  strstr(text, "duplicates: 1") &&
                  strstr(text, "symbols_test_reached: 1") &&
                  strstr(text, "indexed_c23_files: unavailable") &&
                  strstr(text, "include_edges: unavailable") &&
                  strstr(text, "growth: unavailable") &&
                  strstr(text, "authority: display-only"));

    uint8_t sha3[32];
    memset(sha3, 0xa5, sizeof(sha3));
    struct science_ecosystem_named_count roots[1];
    memset(roots, 0, sizeof(roots));
    (void)snprintf(roots[0].name, sizeof(roots[0].name), "engine");
    (void)snprintf(roots[0].detail, sizeof(roots[0].detail), "runtime");
    roots[0].count = 2;
    science_ecosystem_bind_index(&snap, true, sha3, 9u, 1u, true, 0, roots, 1u);
    text_len = 0;
    ECO_CHECK("zero include edges are unanswered, not a measured zero",
              science_ecosystem_format_text(&snap, text, sizeof(text),
                                            &text_len) &&
                  strstr(text, "include_edges: unanswered") &&
                  strstr(text, "indexed_c23_files: 9") &&
                  strstr(text, "source_root_sha3: ") &&
                  !strstr(text, "source_root_sha3: unavailable"));

    science_ecosystem_bind_index(&snap, true, sha3, 9u, 1u, true, 12, roots,
                                 1u);
    text_len = 0;
    ECO_CHECK("dependency totals are the live include-edge count",
              science_ecosystem_format_text(&snap, text, sizeof(text),
                                            &text_len) &&
                  strstr(text, "include_edges: 12"));

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
    science_ecosystem_bind_growth(&snap, &history);
    text_len = 0;
    ECO_CHECK("growth facts bind the latest UTC day and running totals",
              science_ecosystem_format_text(&snap, text, sizeof(text),
                                            &text_len) &&
                  strstr(text, "growth: present") &&
                  strstr(text, "growth_days: 2") &&
                  strstr(text, "growth_latest_date: 1970-01-02") &&
                  strstr(text, "growth_non_test_lines: 7"));

    char dir_one[512];
    test_make_tmpdir(dir_one, sizeof(dir_one), "ecosystem", "onepkg");
    ECO_CHECK("a one-package tree builds",
              mkdir_p(dir_one, "docs") &&
                  write_pkg(dir_one, "only", "only/only"));
    struct science_ecosystem_snapshot one;
    ECO_CHECK("a different tree produces a different package count",
              science_ecosystem_collect(dir_one, NULL, &one, error,
                                        sizeof(error)) &&
                  one.package_count == 1u &&
                  snap.package_count != one.package_count);

    char dir_bare[512];
    test_make_tmpdir(dir_bare, sizeof(dir_bare), "ecosystem", "bare");
    char bare_src[1024];
    (void)snprintf(bare_src, sizeof(bare_src), "%s/engine/src/a.c", dir_bare);
    ECO_CHECK("a tree without an inventory still walks",
              mkdir_p(dir_bare, "docs") && mkdir_p(dir_bare, "engine/src") &&
                  spill(bare_src, "int x;\n"));
    struct science_ecosystem_snapshot bare;
    ECO_CHECK("missing inventory is named, never printed as zero evidence",
              science_ecosystem_collect(dir_bare, NULL, &bare, error,
                                        sizeof(error)) &&
                  !bare.corpus.inventory_present &&
                  science_ecosystem_format_text(&bare, text, sizeof(text),
                                                &text_len) &&
                  strstr(text, "capabilities: unavailable") &&
                  strstr(text, "duplicates: unavailable") &&
                  !strstr(text, "capabilities: 0") &&
                  !strstr(text, "duplicates: 0"));

    char dir_repo[512];
    test_make_tmpdir(dir_repo, sizeof(dir_repo), "ecosystem", "growrepo");
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
    const char *plain =
        json_get_str(json_get(&reply.data, "plain_text"));
    ECO_CHECK("output=text is headless, display-only, and binds the fixture",
              reply.status == ZCL_COMMAND_STATUS_PASSED &&
                  !json_get_bool(json_get(&reply.data, "launched")) &&
                  strcmp(json_get_str(json_get(&reply.data, "authority")),
                         "display-only") == 0 &&
                  json_get_int(json_get(&reply.data, "packages")) == 2 &&
                  json_get_int(json_get(&reply.data,
                                        "production_c23_lines")) == 4 &&
                  json_get_int(json_get(&reply.data, "test_c23_lines")) == 2 &&
                  json_get_int(json_get(&reply.data,
                                        "architectural_contexts")) == 3 &&
                  plain && strstr(plain, "packages: 2") &&
                  strstr(plain, dir) &&
                  strstr(plain, "authority: display-only"));
    {
        const char *growth_error =
            json_get_str(json_get(&reply.data, "growth_error"));
        ECO_CHECK("growth from a nested root is named unavailable",
                  !json_get_bool(json_get(&reply.data, "growth_present")) &&
                      eco_json_str_is(&reply.data, "growth", "unavailable") &&
                      growth_error && strstr(growth_error, "toplevel"));
    }
    zcl_command_reply_free(&reply);

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
    return failures;
}
