/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_command_input_bounds: the per-key length rule in
 * zcl_command_registry_input_validate() and the per-leaf read frame
 * (zcl_command_registry_input_budget_bytes()).
 *
 * Unlisted keys are strings of at most 4096 characters; hex payload keys are
 * bounded by their wire constants. Both edges are held for:
 *
 *   manifest_hex  2 * VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES  (2 MiB chars)
 *   recipe_hex    2 * VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES    (512 KiB chars)
 *   release_hex   2 * VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES
 *   everything else                     4096 chars
 *
 * and the read frame each leaf gets, since a validator accepting 2 MiB in
 * front of a reader that stops at 16 KiB is not a fix. */

#include "test/test_core.h"

#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "command/native_evidence_judge.h"
#include "command/native_app_receive_flow.h"
#include "command/native_app_receive_job.h"
#include "session/fleet_board_proto.h"

#include "fleetledger/fleet_ledger.h"
#include "vcs/package_manifest.h"
#include "vcs/package_recipe.h"
#include "vcs/package_release.h"
#include "vcs/zcode_c23_corpus.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CIB_CHECK(name, expr) do {                                         \
    if (expr) { printf("  command_input_bounds: %s... OK\n", (name)); }     \
    else { printf("  command_input_bounds: %s... FAIL\n", (name));          \
           failures++; }                                                    \
} while (0)

/* A malloc'd run of `len` 'a' characters. */
static char *cib_fill(size_t len)
{
    char *s = malloc(len + 1);
    if (!s)
        return NULL;
    memset(s, 'a', len);
    s[len] = 0;
    return s;
}

/* Validate `{key: <len chars>}` against `path`. `why` receives the refusal. */
static bool cib_accepts(const char *path, const char *key, size_t len,
                        char *why, size_t why_size)
{
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    if (!spec)
        return false;
    char *value = cib_fill(len);
    if (!value)
        return false;
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, key, value);
    if (why && why_size)
        why[0] = 0;
    bool ok = zcl_command_registry_input_validate(spec, &input, why, why_size);
    json_free(&input);
    free(value);
    return ok;
}

static bool cib_accepts_int(const char *path, const char *key, int64_t value)
{
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    if (!spec) return false;
    struct json_value input;
    json_init(&input); json_set_object(&input);
    bool built = json_push_kv_int(&input, key, value);
    bool ok = built && zcl_command_registry_input_validate(
        spec, &input, NULL, 0);
    json_free(&input);
    return ok;
}

enum cib_fleet_type { CIB_FLEET_INT, CIB_FLEET_STRING, CIB_FLEET_BOOL,
                      CIB_FLEET_REAL };

static bool cib_fleet_value(const struct zcl_command_spec *spec,
                            const char *kind, const char *subject,
                            const char *key, enum cib_fleet_type type,
                            int64_t value, bool duplicate, bool *built_out)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    bool built = json_push_kv_str(&input, "kind", kind) &&
                 json_push_kv_str(&input, "subject", subject);
    if (built && type == CIB_FLEET_INT)
        built = json_push_kv_int(&input, key, value);
    else if (built && type == CIB_FLEET_STRING)
        built = json_push_kv_str(&input, key, "1");
    else if (built && type == CIB_FLEET_BOOL)
        built = json_push_kv_bool(&input, key, true);
    else if (built)
        built = json_push_kv_real(&input, key, 1.5);
    if (built && duplicate)
        built = json_push_kv_int(&input, key, value);
    bool accepted = built &&
        zcl_command_registry_input_validate(spec, &input, NULL, 0);
    json_free(&input);
    *built_out = built;
    return accepted;
}

/* Checks one usage counter key: integer and wrong-type input shapes. */
static int cib_fleet_counter_checks(const struct zcl_command_spec *spec,
                                    const char *key)
{
    int failures = 0;
    char name[128];
    bool made = false;
    bool accepted = cib_fleet_value(spec, "usage", "grok", key,
                                    CIB_FLEET_INT, 0, false, &made);
    snprintf(name, sizeof name, "%s measured zero constructs", key);
    CIB_CHECK(name, made);
    snprintf(name, sizeof name, "%s accepts measured zero", key);
    CIB_CHECK(name, made && accepted);
    accepted = cib_fleet_value(spec, "usage", "grok", key,
                               CIB_FLEET_INT, INT64_C(4294967296), false,
                               &made);
    snprintf(name, sizeof name, "%s wide integer constructs", key);
    CIB_CHECK(name, made);
    snprintf(name, sizeof name, "%s accepts a wide integer", key);
    CIB_CHECK(name, made && accepted);

    if (strcmp(key, "value") != 0) {
        accepted = cib_fleet_value(spec, "usage", "grok", key,
                                   CIB_FLEET_INT, -1, false, &made);
        snprintf(name, sizeof name, "%s negative counter constructs",
                 key);
        CIB_CHECK(name, made);
        snprintf(name, sizeof name, "%s refuses a negative counter",
                 key);
        CIB_CHECK(name, made && !accepted);
    }
    const enum cib_fleet_type wrong[] = {
        CIB_FLEET_STRING, CIB_FLEET_BOOL, CIB_FLEET_REAL,
    };
    const char *const labels[] = { "string", "boolean", "real" };
    for (size_t j = 0; j < sizeof wrong / sizeof wrong[0]; j++) {
        accepted = cib_fleet_value(spec, "usage", "grok", key,
                                   wrong[j], 0, false, &made);
        snprintf(name, sizeof name, "%s %s constructs", key,
                 labels[j]);
        CIB_CHECK(name, made);
        snprintf(name, sizeof name, "%s refuses a %s", key,
                 labels[j]);
        CIB_CHECK(name, made && !accepted);
    }
    return failures;
}

static int t_fleet_ledger_numeric_keys(void)
{
    int failures = 0;
    const char *const keys[] = {
        "tokens_in", "tokens_out", "tokens_cached", "tokens_reasoning",
        "wall_ms", "turns", "tool_uses", "cost_micro_usd", "value",
        "count", "bytes", "limit",
    };
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(zcl_command_catalog(), "fleet.ledger.add",
                                  NULL);
    CIB_CHECK("fleet.ledger.add resolves", spec != NULL);
    if (!spec)
        return failures;

    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    bool built = json_push_kv_str(&input, "kind", "usage") &&
                 json_push_kv_str(&input, "subject", "grok");
    CIB_CHECK("fleet usage without counters constructs", built);
    if (built)
        CIB_CHECK("fleet usage permits every counter to be absent",
                  zcl_command_registry_input_validate(spec, &input, NULL, 0));
    json_free(&input);

    for (size_t i = 0; i < sizeof keys / sizeof keys[0]; i++) {
        failures += cib_fleet_counter_checks(spec, keys[i]);
    }

    bool accepted = cib_fleet_value(spec, "vitals", "box.load1", "value",
                                    CIB_FLEET_INT, -1, false, &built);
    CIB_CHECK("negative gauge input constructs", built);
    CIB_CHECK("a negative gauge value is valid", built && accepted);
    accepted = cib_fleet_value(spec, "usage", "grok", "tokens_in",
                               CIB_FLEET_INT, 1, true, &built);
    CIB_CHECK("duplicate counter input constructs", built);
    CIB_CHECK("duplicate counter keys are refused", built && !accepted);

    const struct zcl_command_spec *query = zcl_command_registry_find(
        zcl_command_catalog(), "core.storage.query", NULL);
    CIB_CHECK("core.storage.query resolves for collateral limit checks",
              query != NULL);
    const int64_t limits[] = { 1, 0, INT64_C(4294967296) };
    const bool limit_ok[] = { true, false, false };
    for (size_t i = 0; query && i < sizeof limits / sizeof limits[0]; i++) {
        json_init(&input);
        json_set_object(&input);
        built = json_push_kv_str(&input, "sql", "SELECT 1") &&
                json_push_kv_int(&input, "limit", limits[i]);
        CIB_CHECK("complete core storage query input constructs", built);
        if (built) {
            bool valid = zcl_command_registry_input_validate(
                query, &input, NULL, 0);
            CIB_CHECK(limit_ok[i] ? "core storage query accepts limit one"
                                  : "core storage query refuses bad limit",
                      valid == limit_ok[i]);
        }
        json_free(&input);
    }
    return failures;
}

/* ── 1. Both edges of three differently-limited keys ─────────────────── */

static int t_key_edges(void)
{
    int failures = 0;
    const char *plan = "zcode.package.publish.plan";
    char why[192];

    struct {
        const char *key;
        size_t max;
        const char *label;
    } cases[] = {
        { "manifest_hex", 2u * (size_t)VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES,
          "manifest_hex" },
        { "recipe_hex", 2u * (size_t)VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES,
          "recipe_hex" },
        { "release_hex", 2u * (size_t)VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES,
          "release_hex" },
        /* `dir` is on the same leaf and takes the unchanged default — proof
         * that the raise is per key, not a global loosening. */
        { "dir", 4096u, "dir (default bound)" },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char name[128];

        snprintf(name, sizeof(name), "%s: the stated maximum is exactly the "
                 "advertised bound", cases[i].label);
        CIB_CHECK(name,
                  zcl_command_registry_input_str_max(cases[i].key) ==
                      cases[i].max);

        snprintf(name, sizeof(name), "%s: a value AT the bound is accepted",
                 cases[i].label);
        bool at = cib_accepts(plan, cases[i].key, cases[i].max, why,
                              sizeof(why));
        CIB_CHECK(name, at);
        if (!at)
            printf("    refused at the bound: %s\n", why);

        snprintf(name, sizeof(name), "%s: one character OVER is refused",
                 cases[i].label);
        bool over = cib_accepts(plan, cases[i].key, cases[i].max + 1, why,
                                sizeof(why));
        CIB_CHECK(name, !over);

        /* The refusal must name the length rule. An over-long string is
         * perfectly well-typed, so "invalid type or range" sends the
         * operator hunting the wrong problem. */
        snprintf(name, sizeof(name), "%s: the refusal names length, not type",
                 cases[i].label);
        CIB_CHECK(name, !over && strstr(why, cases[i].key) != NULL &&
                            strstr(why, "characters") != NULL &&
                            strstr(why, "limit") != NULL);
    }

    /* The default is a property of not knowing the key, so a key nobody has
     * ruled on must still get 4096 — never the largest per-key bound. */
    CIB_CHECK("an unruled key keeps the 4096 default",
              zcl_command_registry_input_str_max("no_such_key_at_all") == 4096u);
    CIB_CHECK("a NULL key is answered, not dereferenced",
              zcl_command_registry_input_str_max(NULL) == 4096u);
    CIB_CHECK("zcode work CPU floor is typed and reachable",
              cib_accepts_int("zcode.work.start", "max_cpu_seconds", 1));
    CIB_CHECK("zcode work CPU ceiling is typed and reachable",
              cib_accepts_int("zcode.work.start", "max_cpu_seconds", 600));
    CIB_CHECK("zcode work CPU zero is refused at transport",
              !cib_accepts_int("zcode.work.start", "max_cpu_seconds", 0));
    CIB_CHECK("zcode work CPU overflow is refused at transport",
              !cib_accepts_int("zcode.work.start", "max_cpu_seconds", 601));

    /* The package bounds must stay DERIVED. If someone edits a wire's own
     * maximum, the input bound has to move with it in the same build; a
     * hand-copied number would fail this the moment the two disagree. */
    CIB_CHECK("manifest bound tracks VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES",
              zcl_command_registry_input_str_max("manifest_hex") ==
                  2u * (size_t)VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES);
    CIB_CHECK("recipe bound tracks VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES",
              zcl_command_registry_input_str_max("recipe_hex") ==
                  2u * (size_t)VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES);

    const char *verify = "zcode.commons.corpus.verify";
    size_t checkpoint_hex_max = ZCL_COMMAND_MAX_INPUT;
    CIB_CHECK("checkpoint bound carries the 54-shard inline wire",
              zcl_command_registry_input_str_max("checkpoint") ==
                  checkpoint_hex_max &&
              (checkpoint_hex_max / 2u -
               VCS_ZCODE_C23_CHECKPOINT_HEADER_WIRE_BYTES) /
                  VCS_ZCODE_C23_CHECKPOINT_BINDING_WIRE_BYTES == 54u);
    CIB_CHECK("checkpoint at its canonical inline bound is deliverable",
              cib_accepts(verify, "checkpoint", checkpoint_hex_max, why,
                          sizeof(why)));
    CIB_CHECK("checkpoint one character over its bound is refused",
              !cib_accepts(verify, "checkpoint", checkpoint_hex_max + 1u,
                           why, sizeof(why)) &&
              strstr(why, "checkpoint") != NULL &&
              strstr(why, "limit") != NULL);
    const char *shard_verify = "zcode.commons.corpus.shard.verify";
    size_t shard_hex_max = ZCL_COMMAND_MAX_INPUT;
    CIB_CHECK("shard bound carries 28 whole inline entries",
              zcl_command_registry_input_str_max("shard") == shard_hex_max &&
              (shard_hex_max / 2u - VCS_ZCODE_C23_SHARD_HEADER_WIRE_BYTES) /
                  VCS_ZCODE_C23_SHARD_ENTRY_WIRE_BYTES == 28u);
    CIB_CHECK("shard at its canonical inline bound is deliverable",
              cib_accepts(shard_verify, "shard", shard_hex_max, why,
                          sizeof(why)));
    CIB_CHECK("shard one character over its bound is refused",
              !cib_accepts(shard_verify, "shard", shard_hex_max + 1u,
                           why, sizeof(why)) &&
              strstr(why, "shard") != NULL &&
              strstr(why, "limit") != NULL);
    return failures;
}

/* ── 2. The read frame follows the per-key bounds ────────────────────── */

static bool cib_wiki_escaped_frame(const struct zcl_command_spec *spec)
{
    size_t cap = zcl_command_registry_input_budget_bytes(spec);
    char *text = cib_fill(FLEET_BOARD_WIKI_TEXT_MAX);
    char *wire = malloc(cap);
    struct json_value input, decoded;
    json_init(&input);
    json_init(&decoded);
    json_set_object(&input);
    bool ok = text && wire;
    if (ok) {
        memset(text, 1, FLEET_BOARD_WIKI_TEXT_MAX);
        ok = json_push_kv_str(&input, "text", text) &&
             json_push_kv_str(&input, "slug", "bounded-page") &&
             json_push_kv_str(&input, "title", "Bounded page");
    }
    size_t n = ok ? json_write(&input, wire, cap) : 0;
    ok = n >= 6u * FLEET_BOARD_WIKI_TEXT_MAX && n < cap &&
         json_read(&decoded, wire, n) &&
         zcl_command_registry_input_validate(spec, &decoded, NULL, 0);
    json_free(&decoded);
    json_free(&input);
    free(wire);
    free(text);
    return ok;
}

static int t_wiki_text_bounds(void)
{
    int failures = 0;
    const char *paths[] = {"fleet.wiki.write", "fleet.steer.wiki-write"};
    const size_t accepted[] = {4097, 7765, FLEET_BOARD_WIKI_TEXT_MAX};
    char why[256];
    for (size_t p = 0; p < sizeof(paths) / sizeof(paths[0]); p++) {
        const struct zcl_command_spec *spec = zcl_command_registry_find(
            zcl_command_catalog(), paths[p], NULL);
        CIB_CHECK("wiki write leaf resolves", spec != NULL);
        if (!spec) continue;
        for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); i++)
            CIB_CHECK("wiki text within signed body limit is accepted",
                cib_accepts(paths[p], "text", accepted[i], why, sizeof(why)));
        CIB_CHECK("wiki text above signed body limit is refused",
            !cib_accepts(paths[p], "text", FLEET_BOARD_WIKI_TEXT_MAX + 1u,
                         why, sizeof(why)));
        CIB_CHECK("wiki text refusal reports the signed body limit",
            strstr(why, "16384") != NULL);
        CIB_CHECK("empty wiki text is refused",
            !cib_accepts(paths[p], "text", 0, why, sizeof(why)));
        CIB_CHECK("integer wiki text is refused",
            !cib_accepts_int(paths[p], "text", 1));
        CIB_CHECK("maximum escaped wiki body fits and validates in input frame",
            cib_wiki_escaped_frame(spec));
    }
    CIB_CHECK("unrelated text accepts the default bound",
        cib_accepts("code.have", "text", 4096, why, sizeof(why)));
    CIB_CHECK("unrelated text retains the default bound",
        !cib_accepts("code.have", "text", 4097, why, sizeof(why)));
    return failures;
}

/* Counts the catalog's input keys and those no frame can deliver. */
static void cib_count_input_keys(const struct zcl_command_registry *reg,
                                 size_t *checked, size_t *undeliverable)
{
    for (size_t i = 0; i < reg->count; i++) {
        const struct zcl_command_spec *spec = &reg->commands[i];
        if (!spec->input_keys || !spec->input_keys[0])
            continue;
        size_t budget = zcl_command_registry_input_budget_bytes(spec);
        const char *at = spec->input_keys;
        char token[128];
        while (*at) {
            const char *end = strchr(at, ',');
            size_t len = end ? (size_t)(end - at) : strlen(at);
            if (len > 0 && len < sizeof(token)) {
                memcpy(token, at, len);
                token[len] = 0;
                (*checked)++;
                if (zcl_command_registry_input_str_max(token) >= budget)
                    (*undeliverable)++;
            }
            if (!end)
                break;
            at = end + 1;
        }
    }
}

static int t_frame_budget(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *plan =
        zcl_command_registry_find(reg, "zcode.package.publish.plan", NULL);
    const struct zcl_command_spec *query =
        zcl_command_registry_find(reg, "core.storage.query", NULL);
    const struct zcl_command_spec *verify =
        zcl_command_registry_find(reg, "zcode.commons.corpus.verify", NULL);
    const struct zcl_command_spec *shard_verify = zcl_command_registry_find(
        reg, "zcode.commons.corpus.shard.verify", NULL);
    const struct zcl_command_spec *shard_page = zcl_command_registry_find(
        reg, "zcode.commons.corpus.shard.page", NULL);

    CIB_CHECK("all fixture leaves resolve",
              plan && query && verify && shard_verify && shard_page);
    if (!plan || !query || !verify || !shard_verify || !shard_page)
        return failures;

    size_t plan_budget = zcl_command_registry_input_budget_bytes(plan);
    size_t query_budget = zcl_command_registry_input_budget_bytes(query);
    size_t verify_budget = zcl_command_registry_input_budget_bytes(verify);
    size_t shard_verify_budget =
        zcl_command_registry_input_budget_bytes(shard_verify);

    /* A reader that stopped before the validator's ceiling would truncate a
     * legal document — the exact second wall this change had to clear. */
    size_t declared = 2u * (size_t)VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES +
                      2u * (size_t)VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES +
                      2u * (size_t)VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES;
    CIB_CHECK("the publish frame holds every declared key at its bound",
              plan_budget > declared);

    /* ...and a leaf that declares only default-bounded keys keeps the frame
     * it always had. Widening is per leaf, not global. */
    CIB_CHECK("a small leaf keeps the ZCL_COMMAND_MAX_INPUT floor",
              query_budget == ZCL_COMMAND_MAX_INPUT);
    CIB_CHECK("the floor is a floor, never a ceiling",
              plan_budget > ZCL_COMMAND_MAX_INPUT);
    CIB_CHECK("the checkpoint read frame includes JSON overhead above its wire hex",
              verify_budget >
                  zcl_command_registry_input_str_max("checkpoint"));
    CIB_CHECK("the shard read frame includes JSON overhead above its wire hex",
              shard_verify_budget >
                  zcl_command_registry_input_str_max("shard"));

    /* NULL is answered with the floor rather than a crash or a zero frame
     * (a zero frame would refuse every input on an unresolved leaf). */
    CIB_CHECK("a NULL spec yields the floor",
              zcl_command_registry_input_budget_bytes(NULL) ==
                  ZCL_COMMAND_MAX_INPUT);

    /* Every leaf in the live catalog must get a frame at least as large as
     * its own largest single key, or that key is undeliverable by any
     * transport — the failure mode this whole group exists to prevent. */
    size_t checked = 0, undeliverable = 0;
    cib_count_input_keys(reg, &checked, &undeliverable);
    CIB_CHECK("the catalog declares input keys to walk", checked > 0);
    CIB_CHECK("no catalog key is larger than its own leaf's frame",
              undeliverable == 0);
    return failures;
}

/* ── 3. The raise did not loosen anything else ───────────────────────── */

static int t_no_collateral_loosening(void)
{
    int failures = 0;
    const struct zcl_command_spec *query =
        zcl_command_registry_find(zcl_command_catalog(), "core.storage.query",
                                  NULL);
    CIB_CHECK("core.storage.query resolves", query != NULL);
    if (!query)
        return failures;

    char why[192];
    /* `sql` is arbitrary operator SQL — it must keep the default bound even
     * though it sits one catalog row away from the raised keys. */
    CIB_CHECK("sql at 4096 is accepted",
              cib_accepts("core.storage.query", "sql", 4096, why,
                          sizeof(why)));
    CIB_CHECK("sql at 4097 is refused",
              !cib_accepts("core.storage.query", "sql", 4097, why,
                           sizeof(why)));
    CIB_CHECK("the sql refusal names the 4096 limit",
              strstr(why, "4096") != NULL);

    /* An empty string is still not a value, at any bound. */
    CIB_CHECK("an empty string is still refused",
              !cib_accepts("zcode.package.publish.plan", "manifest_hex", 0,
                           why, sizeof(why)));

    /* A key nothing declares is still unknown, however long or short. */
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "manifest_hex", "aa");
    why[0] = 0;
    bool leaked = zcl_command_registry_input_validate(query, &input, why,
                                                      sizeof(why));
    json_free(&input);
    CIB_CHECK("a raised key is still unknown on a leaf that never declared it",
              !leaked && strstr(why, "unknown input key") != NULL);

    const struct zcl_command_spec *policy = zcl_command_registry_find(
        zcl_command_catalog(), "zcode.network.policy.mutate", NULL);
    CIB_CHECK("the sovereignty policy mutation leaf resolves", policy != NULL);
    if (policy) {
        json_init(&input);
        json_set_object(&input);
        (void)json_push_kv_str(&input, "mode", "plan");
        (void)json_push_kv_str(&input, "operation", "add");
        (void)json_push_kv_int(&input, "action_mask", 127);
        CIB_CHECK("the seven-action policy mask reaches its handler",
                  zcl_command_registry_input_validate(policy, &input, why,
                                                      sizeof(why)));
        json_free(&input);

        json_init(&input);
        json_set_object(&input);
        (void)json_push_kv_str(&input, "mode", "plan");
        (void)json_push_kv_str(&input, "operation", "advisory");
        (void)json_push_kv_bool(&input, "enabled", true);
        CIB_CHECK("the advisory opt-in boolean reaches its handler",
                  zcl_command_registry_input_validate(policy, &input, why,
                                                      sizeof(why)));
        json_free(&input);
    }

    const struct zcl_command_spec *work_status = zcl_command_registry_find(
        zcl_command_catalog(), "zcode.work.status", NULL);
    CIB_CHECK("zcode work status resolves", work_status != NULL);
    if (work_status) {
        json_init(&input);
        json_set_object(&input);
        (void)json_push_kv_bool(&input, "details", true);
        CIB_CHECK("work proof details opt-in reaches its handler",
                  zcl_command_registry_input_validate(
                      work_status, &input, why, sizeof(why)));
        json_free(&input);

        json_init(&input);
        json_set_object(&input);
        (void)json_push_kv_str(&input, "details", "true");
        CIB_CHECK("work proof details refuses a string lookalike",
                  !zcl_command_registry_input_validate(
                      work_status, &input, why, sizeof(why)));
        json_free(&input);
    }
    return failures;
}

/* ── 4. Structured vault effects reach their owning handler ──────────── */

static int t_vault_effects_array(void)
{
    int failures = 0;
    const struct zcl_command_spec *plan = zcl_command_registry_find(
        zcl_command_catalog(), "vault.intent.plan", NULL);
    CIB_CHECK("vault.intent.plan resolves", plan != NULL);
    if (!plan)
        return failures;

    struct json_value input, effects, effect;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "wallet_scope", "dev");
    (void)json_push_kv_str(&input, "route", "transparent");
    (void)json_push_kv_str(&input, "idempotency_key", "payment-001");
    json_init(&effects);
    json_set_array(&effects);
    json_init(&effect);
    json_set_object(&effect);
    (void)json_push_kv_str(&effect, "asset", "ZCL");
    (void)json_push_kv_str(&effect, "to",
                           "t1Recipient000000000000000000000000");
    (void)json_push_kv_str(&effect, "amount", "0.01000000");
    (void)json_push_back(&effects, &effect);
    (void)json_push_kv(&input, "effects", &effects);
    json_free(&effect);
    json_free(&effects);

    char why[192] = {0};
    CIB_CHECK("a documented structured effect passes transport validation",
              zcl_command_registry_input_validate(plan, &input, why,
                                                  sizeof(why)));
    json_free(&input);

    json_init(&input);
    json_set_object(&input);
    json_init(&effects);
    json_set_array(&effects);
    (void)json_push_kv(&input, "effects", &effects);
    json_free(&effects);
    CIB_CHECK("an empty effects array fails closed",
              !zcl_command_registry_input_validate(plan, &input, why,
                                                   sizeof(why)));
    json_free(&input);

    json_init(&input);
    json_set_object(&input);
    json_init(&effects);
    json_set_array(&effects);
    for (size_t i = 0; i < 51; i++) {
        json_init(&effect);
        json_set_object(&effect);
        (void)json_push_back(&effects, &effect);
        json_free(&effect);
    }
    (void)json_push_kv(&input, "effects", &effects);
    json_free(&effects);
    CIB_CHECK("more than 50 effects fails closed",
              !zcl_command_registry_input_validate(plan, &input, why,
                                                   sizeof(why)));
    json_free(&input);

    CIB_CHECK("the vault plan frame budgets a structured effects document",
              zcl_command_registry_input_budget_bytes(plan) >
                  ZCL_COMMAND_MAX_INPUT);
    return failures;
}

/* ── 5. Liquidity planner's numeric contract reaches its handler ─────── */

static int t_liquidity_numeric_input(void)
{
    int failures = 0;
    const struct zcl_command_spec *spec = zcl_command_registry_find(
        zcl_command_catalog(), "metaverse.agent.liquidity", NULL);
    CIB_CHECK("metaverse.agent.liquidity resolves", spec != NULL);
    if (!spec)
        return failures;

    struct json_value input;
    char why[192] = {0};
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "dir", "/private/broker");
    (void)json_push_kv_str(&input, "wallet_scope", "dev");
    (void)json_push_kv_int(&input, "recipient_value_zat", 1000);
    (void)json_push_kv_int(&input, "maximum_fee_zat", 10000);
    (void)json_push_kv_int(&input, "concurrency", 10);
    CIB_CHECK("documented liquidity request passes transport validation",
              zcl_command_registry_input_validate(spec, &input, why,
                                                  sizeof(why)));
    json_free(&input);

    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_int(&input, "concurrency", 51);
    CIB_CHECK("liquidity concurrency above 50 fails closed",
              !zcl_command_registry_input_validate(spec, &input, why,
                                                   sizeof(why)));
    json_free(&input);

    spec = zcl_command_registry_find(
        zcl_command_catalog(), "vault.intent.fanout-plan", NULL);
    CIB_CHECK("vault.intent.fanout-plan resolves", spec != NULL);
    if (!spec)
        return failures;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "wallet_scope", "dev");
    (void)json_push_kv_int(&input, "recipient_value_zat", 1000);
    (void)json_push_kv_int(&input, "maximum_fee_zat", 10000);
    (void)json_push_kv_int(&input, "concurrency", 10);
    (void)json_push_kv_str(&input, "idempotency_key", "parallel-lab-001");
    CIB_CHECK("documented fanout request passes transport validation",
              zcl_command_registry_input_validate(spec, &input, why,
                                                  sizeof(why)));
    json_free(&input);
    return failures;
}

/* ── 6. Package preparation's documented sequence reaches its handler ── */

static int t_package_prepare_sequence(void)
{
    int failures = 0;
    const struct zcl_command_spec *spec = zcl_command_registry_find(
        zcl_command_catalog(), "zcode.package.dev.prepare", NULL);
    CIB_CHECK("zcode.package.dev.prepare resolves", spec != NULL);
    if (!spec)
        return failures;

    struct json_value input;
    char why[192] = {0};
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "dir", "platform/modules/sha3");
    (void)json_push_kv_str(
        &input, "publisher_pubkey",
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    (void)json_push_kv_int(&input, "publisher_sequence", 1);
    CIB_CHECK("documented package publisher sequence passes transport validation",
              zcl_command_registry_input_validate(spec, &input, why,
                                                  sizeof(why)));
    json_free(&input);
    return failures;
}

static int t_lab_include_source(void)
{
    int failures = 0;
    const struct zcl_command_spec *spec = zcl_command_registry_find(
        zcl_command_catalog(), "lab.promote", NULL);
    CIB_CHECK("lab include-source leaf resolves", spec != NULL);
    if (!spec)
        return failures;
    const char *wires[] = { "{\"include-source\":true}",
                            "{\"include-source\":false}",
                            "{\"include-source\":\"true\"}",
                            "{\"include-source\":1}" };
    for (size_t i = 0; i < sizeof(wires) / sizeof(wires[0]); i++) {
        struct json_value input;
        char why[192] = {0};
        json_init(&input);
        bool parsed = json_read(&input, wires[i], strlen(wires[i]));
        bool accepted = parsed && zcl_command_registry_input_validate(
            spec, &input, why, sizeof(why));
        CIB_CHECK("lab include-source admits only boolean shape",
                  parsed && accepted == (i < 2));
        if (i == 0) {
            struct zcl_command_spec unrelated = *spec;
            unrelated.path = "lab.run";
            CIB_CHECK("lab include-source rule does not widen another leaf",
                      !zcl_command_registry_input_validate(&unrelated, &input,
                                                           why, sizeof(why)));
        }
        json_free(&input);
    }
    return failures;
}

/* ── 7. Shared key names keep command-specific numeric bounds ──────────── */

static int t_package_fetch_maximum_bytes(void)
{
    int failures = 0;
    const struct zcl_command_spec *fetch = zcl_command_registry_find(
        zcl_command_catalog(), "zcode.package.fetch", NULL);
    const struct zcl_command_spec *scout = zcl_command_registry_find(
        zcl_command_catalog(), "metaverse.space.scout.plan", NULL);
    CIB_CHECK("package fetch and space scout resolve", fetch && scout);
    if (!fetch || !scout)
        return failures;

    struct json_value input;
    char why[192] = {0};
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_int(&input, "maximum_bytes", 256 * 1024 * 1024);
    CIB_CHECK("package fetch admits one full 256 MiB source carrier",
              zcl_command_registry_input_validate(fetch, &input, why,
                                                  sizeof(why)));
    json_free(&input);

    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_int(&input, "maximum_bytes",
                           256 * 1024 * 1024 + 1);
    CIB_CHECK("package fetch refuses more than its 256 MiB carrier bound",
              !zcl_command_registry_input_validate(fetch, &input, why,
                                                   sizeof(why)));
    json_free(&input);

    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_int(&input, "maximum_bytes", 8 * 1024 * 1024);
    CIB_CHECK("space scout retains its independent 8 MiB traversal bound",
              zcl_command_registry_input_validate(scout, &input, why,
                                                  sizeof(why)));
    json_free(&input);

    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_int(&input, "maximum_bytes", 8 * 1024 * 1024 + 1);
    CIB_CHECK("package fetch widening does not widen space scout",
              !zcl_command_registry_input_validate(scout, &input, why,
                                                   sizeof(why)));
    json_free(&input);
    return failures;
}

static int t_fleet_usage_days(void)
{
    int failures = 0;
    const struct zcl_command_spec *usage = zcl_command_registry_find(
        zcl_command_catalog(), "fleet.usage", NULL);
    CIB_CHECK("fleet.usage resolves", usage != NULL);
    if (!usage)
        return failures;

    CIB_CHECK("fleet usage admits day one",
              cib_accepts_int("fleet.usage", "days", 1));
    CIB_CHECK("fleet usage admits its default seven-day window",
              cib_accepts_int("fleet.usage", "days", 7));
    CIB_CHECK("fleet usage transport admits the index window",
              cib_accepts_int("fleet.usage", "days", ZCL_FLEET_INDEX_DAYS));

    static const char *const refused[] = {
        "{\"days\":0}", "{\"days\":-1}", "{\"days\":\"7\"}",
        "{\"days\":true}", "{\"days\":7.0}", "{\"days\":null}",
    };
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
        struct json_value input;
        json_init(&input);
        const bool built = json_read(&input, refused[i], strlen(refused[i]));
        const bool accepted = built && zcl_command_registry_input_validate(
            usage, &input, NULL, 0);
        CIB_CHECK("fleet usage refuses a non-positive or non-integer day",
                  built && !accepted);
        json_free(&input);
    }

    struct zcl_command_spec other = *usage;
    other.path = "fixture.fleet-usage-shape";
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    const bool string_built = json_push_kv_str(&input, "days", "7");
    CIB_CHECK("days remains an ordinary string outside fleet.usage",
              string_built && zcl_command_registry_input_validate(
                  &other, &input, NULL, 0));
    json_free(&input);
    json_init(&input);
    json_set_object(&input);
    const bool int_built = json_push_kv_int(&input, "days", 7);
    CIB_CHECK("the integer exception is scoped to fleet.usage",
              int_built && !zcl_command_registry_input_validate(
                  &other, &input, NULL, 0));
    json_free(&input);
    return failures;
}

/* ── 10. The rules that moved into command_registry_input_types.c ──────
 *
 * The dual-shape keys, the chunk and line integer bounds, and the
 * discovery required-key rule left command_registry.c in the complexity
 * split. A moved rule with no owning case is a rule that can be deleted
 * without a red test, so each one is pinned here at BOTH of its edges: an
 * accept at the bound and a reject one step outside it, on each side. A
 * pair of assertions that both sit at the same edge would leave the other
 * edge free to move, which is how a shared rule quietly loses the half of
 * itself that differs between its keys. */

/* Validate `{key: <value>}` as an integer against `path`, keeping the
 * refusal text so the exact `why` can be asserted. */
static bool cib_accepts_int_why(const char *path, const char *key,
                                int64_t value, char *why, size_t why_size)
{
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    if (!spec)
        return false;
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    bool built = json_push_kv_int(&input, key, value);
    if (why && why_size)
        why[0] = 0;
    bool ok = built && zcl_command_registry_input_validate(spec, &input, why,
                                                           why_size);
    json_free(&input);
    return ok;
}

/* The refusal every one of these bounds produces: the value is the wrong
 * type or out of range, named by key. */
static bool cib_type_refusal(const char *why, const char *key)
{
    char expect[192];
    (void)snprintf(expect, sizeof(expect),
                   "invalid type or range for input key '%s'", key);
    return strcmp(why, expect) == 0;
}

/* cr_match_dual: `since` is a non-negative integer OR a non-empty string,
 * and nothing else. Both shapes are live wire shapes for code.recent
 * (`--since=5` and `--since=HEAD~5`), so dropping either half breaks a
 * documented call. */
static int t_moved_dual_shape_since(void)
{
    int failures = 0;
    char why[192];

    CIB_CHECK("code.recent admits `since` as a non-negative integer",
              cib_accepts_int("code.recent", "since", 0));
    CIB_CHECK("code.recent admits `since` as a non-empty string",
              cib_accepts("code.recent", "since", 7, why, sizeof(why)));
    CIB_CHECK("code.recent refuses a negative `since`",
              !cib_accepts_int_why("code.recent", "since", -1, why,
                                   sizeof(why)) &&
              cib_type_refusal(why, "since"));
    CIB_CHECK("code.recent refuses an empty `since` string",
              !cib_accepts("code.recent", "since", 0, why, sizeof(why)) &&
              cib_type_refusal(why, "since"));
    return failures;
}

/* fleet.board `ttl`: a post/proposal lifetime in seconds, bounded by
 * FLEET_BOARD_TTL_MAX (1..2592000, cognition .../fleet_board_proto.h) and
 * typed integer-only from the k_bounds table. Before the entry, `ttl` fell
 * through to the default string rule, so every numeric ttl was refused at
 * normalize and the vitals heartbeat's explicit --ttl=86400 (the documented
 * default value, stated for its quota comment) failed INVALID_INPUT on every
 * 5-minute run. */
static int t_moved_ttl_bounds(void)
{
    int failures = 0;
    char why[192];
    const char *path = "fleet.board.post";

    CIB_CHECK("fleet.board.post admits ttl=86400 (the documented default)",
              cib_accepts_int(path, "ttl", 86400));
    CIB_CHECK("fleet.board.post admits ttl=1 (low edge)",
              cib_accepts_int(path, "ttl", 1));
    CIB_CHECK("fleet.board.post admits ttl=2592000 (FLEET_BOARD_TTL_MAX)",
              cib_accepts_int(path, "ttl", 2592000));
    CIB_CHECK("fleet.board.post refuses ttl=0",
              !cib_accepts_int_why(path, "ttl", 0, why, sizeof(why)) &&
              cib_type_refusal(why, "ttl"));
    CIB_CHECK("fleet.board.post refuses ttl past FLEET_BOARD_TTL_MAX",
              !cib_accepts_int_why(path, "ttl", 2592001, why, sizeof(why)) &&
              cib_type_refusal(why, "ttl"));
    CIB_CHECK("fleet.board.post refuses ttl typed as a string",
              !cib_accepts(path, "ttl", 5, why, sizeof(why)) &&
              cib_type_refusal(why, "ttl"));
    return failures;
}

/* core.mining.regtest-mine `blocks` is the JSON integer the handler reads
 * (1..101). Without its k_bounds entry the key fell to the string default and
 * the normalize stage refused every numeric count, so the command could not
 * be invoked from the CLI at all. */
static int t_regtest_mine_blocks(void)
{
    int failures = 0;
    char why[192];
    const char *path = "core.mining.regtest-mine";

    CIB_CHECK("regtest-mine admits blocks=1 (low edge)",
              cib_accepts_int(path, "blocks", 1));
    CIB_CHECK("regtest-mine admits blocks=101 (high edge)",
              cib_accepts_int(path, "blocks", 101));
    CIB_CHECK("regtest-mine refuses blocks=0",
              !cib_accepts_int_why(path, "blocks", 0, why, sizeof(why)) &&
              cib_type_refusal(why, "blocks"));
    CIB_CHECK("regtest-mine refuses blocks=102",
              !cib_accepts_int_why(path, "blocks", 102, why, sizeof(why)) &&
              cib_type_refusal(why, "blocks"));
    CIB_CHECK("regtest-mine refuses blocks typed as a string",
              !cib_accepts(path, "blocks", 3, why, sizeof(why)) &&
              cib_type_refusal(why, "blocks"));
    CIB_CHECK("regtest-mine response budget fits 101 block hashes (67 bytes each)",
              zcl_command_registry_find(zcl_command_catalog(), path, NULL) &&
              (size_t)zcl_command_registry_find(zcl_command_catalog(), path,
                                                NULL)->budget_bytes >=
                  101U * 67U + 1024U);
    return failures;
}

/* core.wallet.security.unlock `timeout_seconds` is the integer the handler
 * reads (default 300) and wallet_lock_arm_timeout bounds to 1..3600. Before
 * the leaf rule it fell to the string default and every numeric timeout was
 * refused at normalize on a locked wallet. */
static int t_wallet_unlock_timeout(void)
{
    int failures = 0;
    char why[192];
    const char *path = "core.wallet.security.unlock";

    CIB_CHECK("wallet unlock admits timeout_seconds=60",
              cib_accepts_int(path, "timeout_seconds", 60));
    CIB_CHECK("wallet unlock admits timeout_seconds=1",
              cib_accepts_int(path, "timeout_seconds", 1));
    CIB_CHECK("wallet unlock admits timeout_seconds=3600",
              cib_accepts_int(path, "timeout_seconds", 3600));
    CIB_CHECK("wallet unlock refuses timeout_seconds=0",
              !cib_accepts_int_why(path, "timeout_seconds", 0, why,
                                   sizeof(why)) &&
              cib_type_refusal(why, "timeout_seconds"));
    CIB_CHECK("wallet unlock refuses timeout_seconds=3601",
              !cib_accepts_int_why(path, "timeout_seconds", 3601, why,
                                   sizeof(why)) &&
              cib_type_refusal(why, "timeout_seconds"));
    return failures;
}

/* cr_match_chunks_and_lines, first key: a PAID chunk count starts at one —
 * zero paid chunks is not a purchase — and stops at the 32-bit chunk index
 * space. Both edges, both sides. */
static int t_moved_chunks_paid_bounds(void)
{
    int failures = 0;
    char why[192];
    const char *path = "app.market.purchase.plan";

    CIB_CHECK("purchase plan admits one paid chunk (low edge)",
              cib_accepts_int(path, "chunks_paid", 1));
    CIB_CHECK("purchase plan refuses zero paid chunks (below the low edge)",
              !cib_accepts_int_why(path, "chunks_paid", 0, why,
                                   sizeof(why)) &&
              cib_type_refusal(why, "chunks_paid"));
    CIB_CHECK("purchase plan admits the last 32-bit chunk count (high edge)",
              cib_accepts_int(path, "chunks_paid", 4294967295LL));
    CIB_CHECK("purchase plan refuses one chunk past 32 bits",
              !cib_accepts_int_why(path, "chunks_paid", 4294967296LL, why,
                                   sizeof(why)) &&
              cib_type_refusal(why, "chunks_paid"));
    return failures;
}

/* cr_match_chunks_and_lines, second key: the two keys share one rule but
 * carry DIFFERENT low bounds — a chunk OFFSET starts at zero. Pinning only
 * the shared high edge would let the two low bounds collapse into one. */
static int t_moved_chunk_start_bounds(void)
{
    int failures = 0;
    char why[192];
    const char *path = "app.market.purchase.plan";

    CIB_CHECK("purchase plan admits chunk zero as a start offset (low edge)",
              cib_accepts_int(path, "chunk_start", 0));
    CIB_CHECK("purchase plan refuses a negative chunk start",
              !cib_accepts_int_why(path, "chunk_start", -1, why,
                                   sizeof(why)) &&
              cib_type_refusal(why, "chunk_start"));
    CIB_CHECK("purchase plan admits the last 32-bit chunk offset (high edge)",
              cib_accepts_int(path, "chunk_start", 4294967295LL));
    CIB_CHECK("purchase plan refuses one offset past 32 bits",
              !cib_accepts_int_why(path, "chunk_start", 4294967296LL, why,
                                   sizeof(why)) &&
              cib_type_refusal(why, "chunk_start"));
    return failures;
}

/* cr_match_chunks_and_lines, third key: `line` is a source line number —
 * one-based, reaching a million. */
static int t_moved_line_bounds(void)
{
    int failures = 0;
    char why[192];

    CIB_CHECK("agent mutate admits the first source line (low edge)",
              cib_accepts_int("dev.agent.mutate", "line", 1));
    CIB_CHECK("agent mutate refuses line zero",
              !cib_accepts_int_why("dev.agent.mutate", "line", 0, why,
                                   sizeof(why)) &&
              cib_type_refusal(why, "line"));
    CIB_CHECK("agent mutate admits the millionth source line (high edge)",
              cib_accepts_int("dev.agent.mutate", "line", 1000000));
    CIB_CHECK("agent mutate refuses one line past its ceiling",
              !cib_accepts_int_why("dev.agent.mutate", "line", 1000001, why,
                                   sizeof(why)) &&
              cib_type_refusal(why, "line"));
    return failures;
}

/* `line` names two unrelated inputs: dev.agent.mutate's integer source line
 * and fleet.import's whole base64url roster line. The name-keyed type table
 * needs a per-leaf exception; both meanings are pinned in both directions. */
static int t_line_key_is_per_leaf(void)
{
    int failures = 0;
    char why[192];

    /* The roster line an owner pastes is about 320 characters; the wire
     * ceiling is FLEET_ENROL_MACHINE_TEXT_MAX (2333). Both are inside the
     * 4096-character default string bound, and the bound's own edges are
     * held so a later "line is special, drop its length rule" is caught. */
    CIB_CHECK("fleet import accepts a pasted roster line",
              cib_accepts("fleet.import", "line", 320, why, sizeof(why)));
    CIB_CHECK("fleet import accepts a roster line at the wire ceiling",
              cib_accepts("fleet.import", "line", 2333, why, sizeof(why)));
    CIB_CHECK("fleet import accepts a roster line at the string bound",
              cib_accepts("fleet.import", "line", 4096, why, sizeof(why)));
    /* An over-long line is well-typed, so the refusal names the length rule. */
    CIB_CHECK("fleet import refuses one character past the string bound",
              !cib_accepts("fleet.import", "line", 4097, why, sizeof(why)) &&
              strstr(why, "line") != NULL &&
              strstr(why, "characters") != NULL &&
              strstr(why, "limit") != NULL);
    CIB_CHECK("fleet import refuses an empty roster line",
              !cib_accepts("fleet.import", "line", 0, why, sizeof(why)) &&
              cib_type_refusal(why, "line"));
    /* A number is not a roster line, and a string is not a source line.
     * Neither leaf inherits the other's meaning in either direction. */
    CIB_CHECK("fleet import refuses a NUMBER for its roster line",
              !cib_accepts_int_why("fleet.import", "line", 42, why,
                                   sizeof(why)) &&
              cib_type_refusal(why, "line"));
    CIB_CHECK("agent mutate still refuses a STRING for its source line",
              !cib_accepts("dev.agent.mutate", "line", 3, why, sizeof(why)) &&
              cib_type_refusal(why, "line"));
    return failures;
}

/* `out` is a measured token count on fleet.experiment.result and an output
 * path on fleet.bundle.fetch. A global integer rule refused every
 * `--out=/abs/path`, so a bundle could not be fetched from a shell. */
static int t_out_key_is_per_leaf(void)
{
    int failures = 0;
    char why[192];

    CIB_CHECK("bundle fetch accepts a STRING output path",
              cib_accepts("fleet.bundle.fetch", "out", 40, why, sizeof(why)));
    CIB_CHECK("bundle fetch refuses a NUMBER for its output path",
              !cib_accepts_int_why("fleet.bundle.fetch", "out", 7, why,
                                   sizeof(why)) &&
              cib_type_refusal(why, "out"));
    CIB_CHECK("experiment result still accepts a count for out",
              cib_accepts_int("fleet.experiment.result", "out", 1200));
    CIB_CHECK("experiment result still refuses a STRING for out",
              !cib_accepts("fleet.experiment.result", "out", 4, why,
                           sizeof(why)) &&
              cib_type_refusal(why, "out"));
    CIB_CHECK("experiment result still refuses a negative out",
              !cib_accepts_int("fleet.experiment.result", "out", -1));
    CIB_CHECK("experiment predict still types tokens as a count",
              cib_accepts_int("fleet.experiment.predict", "tokens", 1200) &&
              !cib_accepts("fleet.experiment.predict", "tokens", 4, why,
                           sizeof(why)));
    CIB_CHECK("receipt append still accepts a count for wall_s",
              cib_accepts_int("fleet.receipt.append", "wall_s", 30));
    return failures;
}

/* cr_match_chunks_and_lines, fourth key: `max_lines` is a tail size — it
 * shares `line`'s low bound but stops a thousand times earlier, so its own
 * high edge has to be held down separately. */
static int t_moved_max_lines_bounds(void)
{
    int failures = 0;
    char why[192];

    CIB_CHECK("ops logs admits a one-line tail (low edge)",
              cib_accepts_int("ops.logs", "max_lines", 1));
    CIB_CHECK("ops logs refuses a zero-line tail",
              !cib_accepts_int_why("ops.logs", "max_lines", 0, why,
                                   sizeof(why)) &&
              cib_type_refusal(why, "max_lines"));
    CIB_CHECK("ops logs admits a thousand lines (high edge)",
              cib_accepts_int("ops.logs", "max_lines", 1000));
    CIB_CHECK("ops logs refuses one line past its own ceiling",
              !cib_accepts_int_why("ops.logs", "max_lines", 1001, why,
                                   sizeof(why)) &&
              cib_type_refusal(why, "max_lines"));
    return failures;
}

/* command_registry_input_required_discovery: discover.search without a
 * query is refused by NAME, not by type — the only rule in the moved set
 * that reads the whole document rather than one value. */
static int t_moved_required_discovery(void)
{
    int failures = 0;
    char why[192];

    CIB_CHECK("discover search admits a query",
              cib_accepts("discover.search", "query", 5, why, sizeof(why)));

    const struct zcl_command_spec *search =
        zcl_command_registry_find(zcl_command_catalog(), "discover.search",
                                  NULL);
    CIB_CHECK("discover.search resolves", search != NULL);
    if (!search)
        return failures;

    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    why[0] = 0;
    CIB_CHECK("discover search refuses a request with no query",
              !zcl_command_registry_input_validate(search, &input, why,
                                                   sizeof(why)) &&
              strcmp(why, "missing required input key 'query'") == 0);
    json_free(&input);
    return failures;
}

/* Shape admission is separate from the handler's exact execution grant.
 * A string "true" must never substitute for JSON boolean true. */
static int t_resident_execution_grant(void)
{
    int failures = 0;
    const struct zcl_command_spec *spec = zcl_command_registry_find(
        zcl_command_catalog(), "app.invoke.package", NULL);
    CIB_CHECK("resident package leaf resolves", spec != NULL);
    if (!spec) return failures;
    const char *wires[] = {"{\"accept_execution\":true}",
                          "{\"accept_execution\":false}",
                          "{\"accept_execution\":\"true\"}",
                          "{\"accept_execution\":1}"};
    for (size_t i = 0; i < sizeof(wires) / sizeof(wires[0]); ++i) {
        struct json_value input;
        json_init(&input);
        char why[192] = {0};
        bool parsed = json_read(&input, wires[i], strlen(wires[i]));
        bool admitted = parsed && zcl_command_registry_input_validate(
            spec, &input, why, sizeof(why));
        CIB_CHECK("resident execution grant admits only boolean shape",
                  parsed && admitted == (i < 2));
        if (i < 2 && parsed) {
            struct zcl_command_spec unrelated = *spec;
            unrelated.path = "app.invoke.unrelated";
            CIB_CHECK("resident boolean rule does not widen another leaf",
                      !zcl_command_registry_input_validate(
                          &unrelated, &input, why, sizeof(why)));
        }
        json_free(&input);
    }
    return failures;
}
static bool cib_consent_shape(const struct zcl_command_spec *spec,
    const char *wire, bool expected)
{
    struct json_value input; json_init(&input);
    char why[192];
    bool ok = json_read(&input, wire, strlen(wire)) &&
        zcl_command_registry_input_validate(spec, &input, why, sizeof(why)) == expected;
    json_free(&input); return ok;
}
static int cib_consent_leaf(const char *path)
{
    int failures = 0;
    const struct zcl_command_spec *spec = zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    printf("  command_input_bounds: execution consent leaf=%s\n", path);
    CIB_CHECK("declared execution consent leaf resolves", spec != NULL);
    if (!spec) return failures;
    struct zcl_command_input_descriptor d;
    CIB_CHECK("execution consent discovery remains boolean",
        zcl_command_registry_input_descriptor(spec, "accept_execution", &d) && d.type == JSON_BOOL);
    CIB_CHECK("execution consent CLI remains boolean",
        zcl_command_registry_input_key_is_boolean(spec, "accept_execution"));
    const char *wires[] = {"{\"accept_execution\":true}", "{\"accept_execution\":false}",
        "{\"accept_execution\":\"true\"}", "{\"accept_execution\":1}",
        "{\"accept_execution\":null}", "{\"accept_execution\":[]}", "{\"accept_execution\":{}}"};
    for (size_t i = 0; i < sizeof(wires) / sizeof(wires[0]); ++i)
        CIB_CHECK("execution consent admits only true/false shape",
            cib_consent_shape(spec, wires[i], i < 2));
    return failures;
}
static int t_execution_consent_scopes(void)
{
    int failures = 0;
    const char *paths[] = {"app.open", "app.keep", "app.invoke.package",
        "app.run.confined", "app.run.copy", "ops.mesh.device.host.package.run"};
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i)
        failures += cib_consent_leaf(paths[i]);
    const struct zcl_command_spec *spec = zcl_command_registry_find(zcl_command_catalog(), "app.invoke.package", NULL);
    if (!spec) return failures + 1;
    struct zcl_command_spec unrelated = *spec; unrelated.path = "app.invoke.unrelated";
    struct zcl_command_input_descriptor d;
    CIB_CHECK("unrelated execution consent has no boolean discovery descriptor",
        !zcl_command_registry_input_descriptor(&unrelated, "accept_execution", &d));
    CIB_CHECK("unrelated execution consent is not a CLI boolean",
        !zcl_command_registry_input_key_is_boolean(&unrelated, "accept_execution"));
    CIB_CHECK("unrelated consent key retains prior ordinary-string interpretation",
        cib_consent_shape(&unrelated, "{\"accept_execution\":\"true\"}", true));
    return failures;
}

static int t_local_acceptance_boolean(void)
{
    int failures = 0;
    const struct zcl_command_spec *spec = zcl_command_registry_find(
        zcl_command_catalog(), "zcode.package.add.plan", NULL);
    CIB_CHECK("local plan leaf resolves", spec != NULL);
    if (!spec) return failures;
    const char *wires[] = {"{\"local_only\":true}", "{\"local_only\":false}",
                          "{\"local_only\":\"true\"}", "{\"local_only\":1}"};
    for (size_t i = 0; i < sizeof(wires) / sizeof(wires[0]); ++i) {
        struct json_value input;
        json_init(&input);
        bool parsed = json_read(&input, wires[i], strlen(wires[i])) &&
            json_push_kv_str(&input, "name_or_root", "ztasks/ztasks");
        bool admitted = parsed && zcl_command_registry_input_validate(spec, &input, NULL, 0);
        CIB_CHECK("local-only uses one boolean contract", parsed && admitted == (i < 2));
        json_free(&input);
    }
    return failures;
}

static int t_resident_binding_types(void)
{
    int failures = 0;
    const char *path = "app.invoke.package";
    CIB_CHECK("resident generation zero is a typed precondition",
        cib_accepts_int(path, "generation", 0));
    CIB_CHECK("resident negative generation refuses",
        !cib_accepts_int(path, "generation", -1));
    CIB_CHECK("resident positive start token is an integer",
        cib_accepts_int(path, "start_token", INT64_MAX));
    CIB_CHECK("resident zero start token refuses",
        !cib_accepts_int(path, "start_token", 0));
    CIB_CHECK("resident start token string refuses",
        !cib_accepts(path, "start_token", 1, NULL, 0));
    CIB_CHECK("resident generation string refuses",
        !cib_accepts(path, "generation", 1, NULL, 0));
    return failures;
}

static int t_policy_fact_types(void)
{
    int failures = 0;
    const char *path = "zcode.package.policy.limits";
    const char *keys[] = {
        "earned_score", "uploaded_bytes", "downloaded_bytes"
    };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        CIB_CHECK("policy fact accepts zero", cib_accepts_int(path, keys[i], 0));
        CIB_CHECK("policy fact accepts the largest JSON integer",
                  cib_accepts_int(path, keys[i], INT64_MAX));
        CIB_CHECK("policy fact refuses negative input",
                  !cib_accepts_int(path, keys[i], -1));
        CIB_CHECK("policy fact refuses string input",
                  !cib_accepts(path, keys[i], 3, NULL, 0));
    }
    return failures;
}

static int g_cib_handler_calls;

static void cib_counting_handler(const struct zcl_command_request *request,
                                 struct zcl_command_reply *reply)
{
    (void)request;
    (void)reply;
    g_cib_handler_calls++;
}

static bool cib_execute_int(const struct zcl_command_spec *spec,
                            const char *key, int64_t value, char *out,
                            size_t out_size, enum zcl_command_exit *code)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    struct zcl_command_context ctx = {
        .registry = reg,
        .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
    };
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    bool built = json_push_kv_int(&input, key, value);
    *code = ZCL_COMMAND_EXIT_OK;
    size_t n = built ? zcl_command_registry_execute_json(
                           reg, spec, &ctx, &input, false, spec->path,
                           "normal", 0, 0, NULL, out, out_size, code)
                     : 0;
    json_free(&input);
    return n > 0;
}

static int t_execute_json_valid_call(void)
{
    int failures = 0;
    static char out[65536];
    enum zcl_command_exit code;
    const struct zcl_command_spec *ok_spec = zcl_command_registry_find(
        zcl_command_catalog(), "ops.statecatalog", NULL);
    struct json_value empty;
    json_init(&empty);
    json_set_object(&empty);
    struct zcl_command_context ctx = {
        .registry = zcl_command_catalog(),
        .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
    };
    code = ZCL_COMMAND_EXIT_INTERNAL;
    size_t n = ok_spec ? zcl_command_registry_execute_json(
                             zcl_command_catalog(), ok_spec, &ctx, &empty,
                             false, ok_spec->path, "normal", 0, 0, NULL, out,
                             sizeof(out), &code)
                       : 0;
    json_free(&empty);
    CIB_CHECK("a valid existing call still succeeds",
              n > 0 && code == ZCL_COMMAND_EXIT_OK);
    return failures;
}

static int t_execute_json_validates_input(void)
{
    int failures = 0;
    static char out[65536];
    enum zcl_command_exit code;
    const struct zcl_command_spec *real = zcl_command_registry_find(
        zcl_command_catalog(), "core.node.bootwait", NULL);
    CIB_CHECK("execute_json fixture leaf exists", real != NULL);
    if (!real)
        return failures + 1;
    /* Counting stub over the real bootwait contract: same keys and ranges. */
    struct zcl_command_spec stub = *real;
    stub.handler = cib_counting_handler;

    g_cib_handler_calls = 0;
    bool got = cib_execute_int(real, "timeout_ms", 999999999, out,
                               sizeof(out), &code);
    struct json_value env;
    bool parsed = got && json_read(&env, out, strlen(out));
    const struct json_value *err = parsed ? json_get(&env, "error") : NULL;
    CIB_CHECK("execute_json refuses out-of-range bootwait input",
              parsed && !json_get_bool(json_get(&env, "ok")) && err &&
                  code == ZCL_COMMAND_EXIT_INVALID &&
                  strcmp(json_get_str(json_get(err, "code")),
                         "INVALID_INPUT") == 0 &&
                  strcmp(json_get_str(json_get(err, "phase")),
                         "normalize") == 0 &&
                  !json_get_bool(json_get(err, "mutated")));
    if (parsed)
        json_free(&env);

    got = cib_execute_int(&stub, "timeout_ms", 999999999, out, sizeof(out),
                          &code);
    CIB_CHECK("invalid input never reaches the handler",
              got && code == ZCL_COMMAND_EXIT_INVALID &&
                  g_cib_handler_calls == 0);
    got = cib_execute_int(&stub, "timeout_ms", 1000, out, sizeof(out), &code);
    CIB_CHECK("valid input reaches the handler once",
              got && code == ZCL_COMMAND_EXIT_OK && g_cib_handler_calls == 1);

    return failures + t_execute_json_valid_call();
}

/* Real catalog/type normalization only; never executes the boot handler. */
static bool cib_machine_shape(const char *key,const char *value)
{
    const struct zcl_command_spec *spec=zcl_command_registry_find(
        zcl_command_catalog(),"dev.app.machine.boot",NULL);
    char raw[2048];
    int n=snprintf(raw,sizeof raw,"{\"%s\":%s}",key,value);
    if(!spec||n<0||(size_t)n>=sizeof raw)return false;
    struct json_value input;json_init(&input);
    bool parsed=json_read(&input,raw,(size_t)n);
    bool accepted=parsed&&zcl_command_registry_input_validate(spec,&input,NULL,0);
    json_free(&input);return accepted;
}
static int t_machine_protected_object_types(void)
{
    int failures=0;
    CIB_CHECK("protected_kernel object reaches nested handler validation",
        cib_machine_shape("protected_kernel","{}"));
    CIB_CHECK("protected_unlock object reaches nested handler validation",
        cib_machine_shape("protected_unlock","{}"));
    static const char selector[]=
        "{\"datadir\":\"test-tmp/protected-capture/cas\","
        "\"observation_root\":\"625184de81e80c9fa1a86120de9024ffff5f0cc818aa236a282bca403b935108\","
        "\"max_artifact_bytes\":43412608,\"max_verification_bytes\":50000000}";
    static const char unlock[]=
        "{\"policy\":\"protected_host\",\"purpose\":\"protected_geli_keyfile\","
        "\"receiver_revision\":1,"
        "\"authorized_kernel_sha256\":\"a5080bb076351c5b5e058a81e5bf6ad3a0f748e97423d2214af5602a5f90097c\","
        "\"credential_mode\":\"create_new_host\",\"mode\":\"initial\","
        "\"volume\":\"test-tmp/protected/volume\",\"record\":\"test-tmp/protected/record\","
        "\"credential\":\"test-tmp/protected/credential\",\"extension\":\"test-tmp/protected/extension\","
        "\"reserve_stage\":\"test-tmp/protected/reserve\",\"ready_stage\":\"test-tmp/protected/ready\"}";
    CIB_CHECK("full protected capture selector passes typed normalizer",
        cib_machine_shape("protected_kernel",selector));
    CIB_CHECK("full twelve-field protected unlock passes typed normalizer",
        cib_machine_shape("protected_unlock",unlock));
    static const char *const old[]={"accepted_kernel","public_kernel","public_unlock"};
    for(size_t i=0;i<sizeof old/sizeof old[0];i++)
        CIB_CHECK("existing machine object type remains accepted",cib_machine_shape(old[i],"{}"));
    return failures;
}
static int t_machine_protected_wrong_types(void)
{
    int failures=0;
    static const char *const keys[]={"protected_kernel","protected_unlock"};
    static const char *const wrong[]={"\"wrong\"","[]","null","0","true"};
    for(size_t i=0;i<sizeof keys/sizeof keys[0];i++)
        for(size_t j=0;j<sizeof wrong/sizeof wrong[0];j++)
            CIB_CHECK("protected machine key refuses non-object",
                !cib_machine_shape(keys[i],wrong[j]));
    CIB_CHECK("unlisted machine object key still refused",
        !cib_machine_shape("protected_kernel_extra","{}"));
    return failures;
}

static int t_offline_compare_limit_bounds(void)
{
    int failures = 0;
    const char *path = "core.consensus.utxo.compare.offline";
    CIB_CHECK("offline comparison admits zero examples",
        cib_accepts_int(path, "example_limit", 0));
    CIB_CHECK("offline comparison admits 32 examples",
        cib_accepts_int(path, "example_limit", 32));
    CIB_CHECK("offline comparison refuses negative example limit",
        !cib_accepts_int(path, "example_limit", -1));
    CIB_CHECK("offline comparison refuses example limit 33",
        !cib_accepts_int(path, "example_limit", 33));
    CIB_CHECK("offline comparison refuses a string example limit",
        !cib_accepts(path, "example_limit", 1, NULL, 0));
    return failures;
}
static int t_offline_compare_limit_descriptor(void)
{
    int failures = 0;
    const struct zcl_command_spec *spec = zcl_command_registry_find(
        zcl_command_catalog(), "core.consensus.utxo.compare.offline", NULL);
    struct zcl_command_input_descriptor descriptor;
    CIB_CHECK("offline example limit descriptor states integer range zero through 32",
        spec && zcl_command_registry_input_descriptor(spec, "example_limit", &descriptor) &&
        descriptor.type == JSON_INT && descriptor.minimum == 0 && descriptor.maximum == 32);
    return failures;
}
static int t_offline_compare_limit_isolation(void)
{
    int failures = 0;
    const struct zcl_command_spec *spec = zcl_command_registry_find(
        zcl_command_catalog(), "core.consensus.utxo.compare.offline", NULL);
    CIB_CHECK("offline comparison leaf resolves for isolation fixture", spec != NULL);
    if (!spec) return failures;
    struct zcl_command_spec neighbor = *spec;
    neighbor.path = "core.consensus.utxo.audit";
    struct json_value input = {0}; json_set_object(&input);
    bool built = json_push_kv_str(&input, "example_limit", "1");
    CIB_CHECK("example limit remains an ordinary string on a neighboring leaf",
        built && zcl_command_registry_input_validate(&neighbor, &input, NULL, 0));
    json_free(&input); json_set_object(&input);
    built = json_push_kv_int(&input, "example_limit", 1);
    CIB_CHECK("integer example limit exception is confined to offline comparison",
        built && !zcl_command_registry_input_validate(&neighbor, &input, NULL, 0));
    json_free(&input);
    return failures;
}

static bool cib_json_shape(const char *path, const char *text)
{
    const struct zcl_command_spec *spec = zcl_command_registry_find(
        zcl_command_catalog(), path, NULL);
    struct json_value input;
    json_init(&input);
    bool ok = spec && json_read(&input, text, strlen(text)) &&
              zcl_command_registry_input_validate(spec, &input, NULL, 0);
    json_free(&input);
    return ok;
}

static int t_discovery_transport_shapes(void)
{
    int failures = 0;
    struct zcl_command_input_descriptor d;
    const struct zcl_command_spec *claim = zcl_command_registry_find(
        zcl_command_catalog(), "dev.agent.claim", NULL);
    const struct zcl_command_spec *drive = zcl_command_registry_find(
        zcl_command_catalog(), "dev.land.drive", NULL);
    CIB_CHECK("claim files descriptor comes from array validator",
        zcl_command_registry_input_descriptor(claim, "files", &d) && d.type == JSON_ARR);
    CIB_CHECK("claim release descriptor comes from boolean validator",
        zcl_command_registry_input_descriptor(claim, "release", &d) && d.type == JSON_BOOL);
    CIB_CHECK("drive seq descriptor preserves transport bounds",
        zcl_command_registry_input_descriptor(drive, "seq", &d) &&
        d.type == JSON_INT && d.minimum == 1 && d.maximum == 1000000000);
    CIB_CHECK("drive max_rows descriptor states transport not handler range",
        zcl_command_registry_input_descriptor(drive, "max_rows", &d) &&
        d.type == JSON_INT && d.minimum == 1 && d.maximum == 1000000);
    CIB_CHECK("claim array and boolean accepted without dispatch",
        cib_json_shape("dev.agent.claim", "{\"files\":[\"a.c\"],\"release\":false}"));
    CIB_CHECK("claim comma string rejected without dispatch",
        !cib_json_shape("dev.agent.claim", "{\"files\":\"a.c,b.c\"}"));
    CIB_CHECK("claim wrong array item rejected without dispatch",
        !cib_json_shape("dev.agent.claim", "{\"files\":[3]}"));
    CIB_CHECK("claim string boolean rejected without dispatch",
        !cib_json_shape("dev.agent.claim", "{\"release\":\"false\"}"));
    CIB_CHECK("status undeclared seq remains rejected",
        !cib_json_shape("dev.land.status", "{\"seq\":704}"));
    CIB_CHECK("drive handler constraints remain outside transport",
        cib_json_shape("dev.land.drive", "{\"seq\":704,\"prove\":true}") &&
        cib_json_shape("dev.land.drive", "{\"max_rows\":17}"));
    return failures;
}

static bool cib_files_shape(size_t count, size_t bytes)
{
    char *text = cib_fill(bytes);
    struct json_value input, array, item;
    json_init(&input);
    json_init(&array);
    json_init(&item);
    json_set_object(&input);
    json_set_array(&array);
    if (text)
        json_set_str(&item, text);
    bool built = text != NULL;
    for (size_t i = 0; built && i < count; i++)
        built = json_push_back(&array, &item);
    const struct zcl_command_spec *spec = zcl_command_registry_find(
        zcl_command_catalog(), "dev.agent.claim", NULL);
    bool ok = built && spec && json_push_kv(&input, "files", &array) &&
        zcl_command_registry_input_validate(spec, &input, NULL, 0);
    json_free(&item);
    json_free(&array);
    json_free(&input);
    free(text);
    return ok;
}

static bool cib_paths_descriptor(const struct zcl_command_spec *guide)
{
    struct zcl_command_input_descriptor d;
    return zcl_command_registry_input_descriptor(guide, "paths", &d) &&
           d.type == JSON_ARR && d.allows_string && d.max_items == 256 &&
           d.item_max_bytes == 1024 && d.max_bytes == 4096;
}

static int t_discovery_descriptor_contract(void)
{
    int failures = 0;
    struct zcl_command_input_descriptor d;
    const unsigned char zero[sizeof(d)] = {0};
    const struct zcl_command_spec *guide = zcl_command_registry_find(
        zcl_command_catalog(), "code.guide", NULL);
    const struct zcl_command_spec *schema = zcl_command_registry_find(
        zcl_command_catalog(), "discover.schema", NULL);
    CIB_CHECK("paths dual-shape descriptor preserves both limits",
        cib_paths_descriptor(guide));
    CIB_CHECK("paths string form remains admitted",
        cib_json_shape("code.guide", "{\"paths\":\"tools/zcc.c\"}"));
    CIB_CHECK("paths array form remains admitted",
        cib_json_shape("code.guide", "{\"paths\":[\"tools/zcc.c\"]}"));
    CIB_CHECK("side enum shares validator values",
        zcl_command_registry_input_descriptor(schema, "side", &d) &&
        d.enum_values && strcmp(d.enum_values, "input,output") == 0 &&
        !cib_json_shape("discover.schema", "{\"path\":\"code.guide\",\"side\":\"other\"}"));
    CIB_CHECK("discovery path is required by transport",
        zcl_command_registry_input_descriptor(schema, "path", &d) && d.required);
    memset(&d, 127, sizeof(d));
    CIB_CHECK("undeclared field resets complete descriptor",
        !zcl_command_registry_input_descriptor(schema, "not_declared", &d) &&
        memcmp(&d, zero, sizeof(d)) == 0);
    memset(&d, 127, sizeof(d));
    CIB_CHECK("null spec resets complete descriptor",
        !zcl_command_registry_input_descriptor(NULL, "path", &d) &&
        memcmp(&d, zero, sizeof(d)) == 0);
    CIB_CHECK("null output is rejected",
        !zcl_command_registry_input_descriptor(schema, "path", NULL));
    return failures;
}

static int t_discovery_transport_edges(void)
{
    int failures = 0;
    CIB_CHECK("files empty array stays transport-valid", cib_files_shape(0, 1));
    CIB_CHECK("files maximum count and bytes accepted", cib_files_shape(256, 1024));
    CIB_CHECK("files excessive count rejected", !cib_files_shape(257, 1));
    CIB_CHECK("files excessive bytes rejected", !cib_files_shape(1, 1025));
    CIB_CHECK("files empty item rejected", !cib_files_shape(1, 0));
    CIB_CHECK("seq lower endpoint accepted", cib_accepts_int("dev.land.drive", "seq", 1));
    CIB_CHECK("seq upper endpoint accepted", cib_accepts_int("dev.land.drive", "seq", 1000000000));
    CIB_CHECK("seq outside endpoint rejected", !cib_accepts_int("dev.land.drive", "seq", 1000000001));
    CIB_CHECK("max_rows transport upper endpoint accepted", cib_accepts_int("dev.land.drive", "max_rows", 1000000));
    CIB_CHECK("max_rows outside transport endpoint rejected", !cib_accepts_int("dev.land.drive", "max_rows", 1000001));
    CIB_CHECK("drive wrong scalar types rejected",
        !cib_json_shape("dev.land.drive", "{\"seq\":\"704\"}") &&
        !cib_json_shape("dev.land.drive", "{\"prove\":\"true\"}"));
    return failures;
}

static int t_ops_state_explain_boolean(void)
{
    int failures = 0;
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(zcl_command_catalog(), "ops.state", NULL);
    struct zcl_command_input_descriptor d = {0};
    CIB_CHECK("ops.state explain descriptor is boolean",
        spec && zcl_command_registry_input_descriptor(spec, "explain", &d) &&
        d.type == JSON_BOOL);
    static const struct { const char *input; bool accepted; } cases[] = {
        { "{\"subsystem\":\"connman\",\"explain\":true}", true },
        { "{\"subsystem\":\"connman\",\"explain\":false}", true },
        { "{\"subsystem\":\"connman\",\"explain\":\"true\"}", false },
        { "{\"subsystem\":\"connman\",\"explain\":1}", false },
        { "{\"subsystem\":\"connman\",\"explain\":1.0}", false },
        { "{\"subsystem\":\"connman\",\"explain\":null}", false },
        { "{\"subsystem\":\"connman\",\"explain\":[]}", false },
        { "{\"subsystem\":\"connman\",\"explain\":{}}", false },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        CIB_CHECK(cases[i].input,
            cib_json_shape("ops.state", cases[i].input) == cases[i].accepted);
    return failures;
}

static bool cib_soak_fixture(const char *file)
{
    FILE *f = fopen(file, "w");
    if (!f) return false;
    bool ok = true;
    for (int ts = -3600; ts <= 0; ts += 3600)
        if (fprintf(f, "{\"ts\":%d,\"soak_height\":1,\"zd_height\":1,\"gap\":0,"
            "\"nrestarts\":0,\"active_enter_ts\":0,\"rss_kb\":1,"
            "\"binary_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
            "\"security_review_required\":false,\"security_posture_ok\":true,"
            "\"window_eligible\":true,\"ok\":true}\n", ts) < 0) ok = false;
    if (fclose(f) != 0) ok = false;
    return ok;
}

static int t_soak_input_contract(void)
{
    int failures = 0;
    const char *leaf = "ops.host.slo.soak";
    CIB_CHECK("soak typed allow_stale accepted", cib_json_shape(leaf, "{\"allow_stale\":true}"));
    CIB_CHECK("soak string allow_stale refused", !cib_json_shape(leaf, "{\"allow_stale\":\"true\"}"));
    CIB_CHECK("soak zero-hour legacy window accepted", cib_accepts_int(leaf, "window_hours", 0));
    CIB_CHECK("soak longer legacy window accepted", cib_accepts_int(leaf, "window_hours", 169));
    CIB_CHECK("soak overflowing seconds refused",
        !cib_accepts_int(leaf, "window_hours", INT64_MAX / 3600 + 1));
    CIB_CHECK("neighbor window bound unchanged",
        !cib_accepts_int("ops.host.slo.judge", "window_hours", 169));
    CIB_CHECK("soak largest whole-second window accepted",
        cib_accepts_int(leaf, "window_hours", INT64_MAX / 3600));
    return failures;
}

static int cib_soak_command_zero(const char *root)
{
    int failures = 0;
    struct json_value input;
    json_init(&input); json_set_object(&input);
    bool built = json_push_kv_str(&input, "dir", root) &&
        json_push_kv_int(&input, "window_hours", 1) && json_push_kv_int(&input, "now", 0);
    struct zcl_command_request request = {.input = &input};
    struct zcl_command_reply reply;
    zcl_native_handle_ops_soak_judge(&request, &reply);
    const char *text = json_get_str(json_get(&reply.data, "text"));
    CIB_CHECK("soak supplied command zero is literal epoch",
        built && text && strstr(text, "last_sample_age_sec=0 "));
    zcl_command_reply_free(&reply); json_free(&input);
    return failures;
}

static int cib_soak_environment_time(const char *root, const char *file)
{
    int failures = 0;
    const char *old = getenv("ZCL_SOAK_NOW");
    char *saved = old ? strdup(old) : NULL;
    if (old && !saved) return 1;
    char path[512], err[160];
    struct zcl_soak_judge_opts opts;
    struct zcl_judge_result result;
    bool defaults = setenv("ZCL_SOAK_NOW", "0", 1) == 0 &&
        zcl_soak_judge_defaults(&opts, path, sizeof(path), err, sizeof(err));
    opts.file = file; opts.window_hours = 1;
    CIB_CHECK("soak supplied environment zero is literal epoch",
        defaults && zcl_soak_judge(&opts, &result) &&
        strstr(result.text, "last_sample_age_sec=0 ") != NULL);
    defaults = unsetenv("ZCL_SOAK_NOW") == 0 &&
        zcl_soak_judge_defaults(&opts, path, sizeof(path), err, sizeof(err));
    opts.file = file; opts.window_hours = 1;
    CIB_CHECK("soak absent environment retains wall-clock default",
        defaults && zcl_soak_judge(&opts, &result) &&
        strstr(result.text, "last_sample_age_sec=0 ") == NULL);
    struct zcl_soak_judge_opts legacy = {.file = file, .window_hours = 1, .now_unix = 0};
    CIB_CHECK("soak legacy C caller zero retains sentinel",
        zcl_soak_judge(&legacy, &result) &&
        strstr(result.text, "last_sample_age_sec=0 ") == NULL);
    failures += cib_soak_command_zero(root);
    if (saved) { if (setenv("ZCL_SOAK_NOW", saved, 1) != 0) failures++; }
    else if (unsetenv("ZCL_SOAK_NOW") != 0) failures++;
    free(saved);
    return failures;
}

static int t_soak_time_contract(void)
{
    int failures = 0;
    char root[512], file[600];
    test_make_tmpdir(root, sizeof(root), "soak_time", "contract");
    (void)snprintf(file, sizeof(file), "%s/evidence.jsonl", root);
    bool ready = cib_soak_fixture(file);
    CIB_CHECK("soak time isolated fixture", ready);
    if (ready) failures += cib_soak_environment_time(root, file);
    test_cleanup_tmpdir(root);
    return failures;
}

/* Synthetic boundary inputs, real continuation summary/finish and registry
 * serializer. This tests encoded receipts, not Receive/preview authorization. */
static bool rfw_receipt_base(struct json_value *data)
{
    static const char *const pins[] = {"release_id", "package_root", "version"};
    char pin[65]; memset(pin, 'a', 64); pin[64] = 0;
    char publisher[67]; memset(publisher, 'b', 66); publisher[66] = 0;
    for (size_t i = 0; i < sizeof(pins) / sizeof(pins[0]); ++i)
        if (!json_push_kv_str(data, pins[i], pin)) return false;
    return json_push_kv_str(data, "stage", "commit") &&
        json_push_kv_str(data, "publisher_fingerprint", publisher) &&
        json_push_kv_str(data, "name", "fixture/receive-wire") &&
        json_push_kv_str(data, "trust_record", "/private/fixture/trust") &&
        json_push_kv_bool(data, "verified", true) &&
        json_push_kv_bool(data, "executed", false) &&
        json_push_kv_str(data, "destination", "");
}
static bool rfw_receipt(struct json_value *data)
{
    if (!rfw_receipt_base(data)) return false;
    size_t n = json_write(data, NULL, 0);
    if (n >= 8192) return false;
    /* Force actual JSON escaping, not a decoded-length estimate. */
    size_t left = 8192 - n, used = 0;
    char path[8193];
    while (left >= 6) { path[used++] = 1; left -= 6; }
    while (left >= 2) { path[used++] = '"'; left -= 2; }
    if (left) path[used++] = 'x';
    path[used] = 0;
    struct json_value *destination = &data->children[data->num_children - 1];
    json_set_str(destination, path);
    return destination->type == JSON_STR && json_write(data, NULL, 0) == 8192;
}
static bool rfw_private_body(struct json_value *data)
{
    char *body = malloc(60001);
    if (!body) return false;
    memset(body, 'x', 60000); body[60000] = 0;
    static const char marker[] = "MUST_NOT_COPY_WORKER_BODY";
    memcpy(body, marker, sizeof(marker) - 1);
    bool ok = json_push_kv_str(data, "private_input", body);
    free(body);
    return ok;
}
static bool rfw_worker_data(struct json_value *data)
{
    static const char *const keys[] = {"stage", "version", "package_root", "plan_id",
        "record_id", "image_sha3", "name", "ready_basis", "start_token", "mapped_proof"};
    char text[65];
    memset(text, 'a', 64); text[64] = 0;
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i)
        if (!json_push_kv_str(data, keys[i], text)) return false;
    return json_push_kv_bool(data, "ready", true) &&
        json_push_kv_bool(data, "executed", true) &&
        json_push_kv_int(data, "pid", INT64_MAX) &&
        json_push_kv_int(data, "selection_revision", INT64_MAX) &&
        rfw_private_body(data);
}
static bool rfw_worker(struct json_value *wire, bool failed)
{
    struct json_value data, error;
    json_init(&data); json_set_object(&data); json_init(&error); json_set_object(&error);
    char diagnostic[513];
    /* Quotes require two encoded bytes each in the retained 160-byte excerpt. */
    memset(diagnostic, '"', 512); diagnostic[512] = 0;
    bool ok = rfw_worker_data(&data) &&
        json_push_kv_str(wire, "status", failed ? "failed" : "passed");
    if (failed)
        ok = ok && json_push_kv(&error, "facts", &data) &&
            json_push_kv_str(&error, "message", diagnostic) && json_push_kv(wire, "error", &error);
    else ok = ok && json_push_kv(wire, "data", &data);
    ok = ok && json_write(wire, NULL, 0) <= APP_RECEIVE_JOB_OUTPUT_MAX;
    json_free(&error); json_free(&data);
    return ok;
}
static void rfw_evidence(struct app_receive_job_result result[3], bool failed)
{
    memset(result, 0, 3 * sizeof(*result));
    for (size_t i = 0; i < 3; ++i) {
        result[i].evidence.exit_observed = true;
        result[i].evidence.stdout_complete = true;
        result[i].evidence.stderr_complete = true;
        result[i].evidence.stderr_len = sizeof(result[i].evidence.stderr_tail);
        result[i].evidence.stderr_observed = INT64_MAX;
        memset(result[i].evidence.stderr_tail, 0xff, sizeof(result[i].evidence.stderr_tail));
        /* Retention must select the tail, not the initial discarded bytes. */
        memset(result[i].evidence.stderr_tail + result[i].evidence.stderr_len - 128, 0xab, 128);
    }
    if (failed) {
        result[2].capture_status = -1;
        result[2].evidence.exit_observed = false;
        result[2].evidence.exit_code = -1;
        result[2].evidence.timed_out = true;
    }
}
static bool rfw_original(const struct json_value *original, const struct json_value *actual)
{
    char before[8193], after[8193];
    for (size_t i = 0; i < original->num_children; ++i) {
        const struct json_value *v = json_get(actual, original->keys[i]);
        if (!v) return false;
        size_t a = json_write(&original->children[i], before, sizeof(before));
        size_t b = json_write(v, after, sizeof(after));
        if (!a || a >= sizeof(before) || a != b || memcmp(before, after, a)) return false;
    }
    return true;
}
static bool rfw_pins(const struct json_value *summary)
{
    static const char *const keys[] = {"stage", "version", "package_root", "plan_id",
        "record_id", "image_sha3", "name", "ready_basis", "start_token", "mapped_proof"};
    char expected[65]; memset(expected, 'a', 64); expected[64] = 0;
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        const char *value = json_get_str(json_get(summary, keys[i]));
        if (!value || strcmp(value, expected)) return false;
    }
    return json_get_int(json_get(summary, "pid")) == INT64_MAX &&
        json_get_int(json_get(summary, "selection_revision")) == INT64_MAX;
}
static bool rfw_operation_matches(const struct json_value *op,
    const char *tail, const char *expected_stage)
{
    const char *hex = json_get_str(json_get(op, "stderr_tail_hex"));
    const char *stage = json_get_str(json_get(op, "operation"));
    return hex && !strcmp(hex, tail) &&
        json_get_int(json_get(op, "stderr_bytes_omitted")) == INT64_MAX - 128 &&
        json_get_bool(json_get(op, "result_is_summary")) && !json_get(op, "private_input") &&
        rfw_pins(op) && stage && !strcmp(stage, expected_stage);
}
static bool rfw_diagnostics(const struct json_value *data, bool failed)
{
    static const char *const stages[] = {"build-plan", "build-confirm", "open"};
    const struct json_value *ops = json_get(data, "operations");
    if (!ops || ops->type != JSON_ARR || json_size(ops) != 3) return false;
    char tail[257];
    for (size_t i = 0; i < 128; ++i) { tail[2*i] = 'a'; tail[2*i+1] = 'b'; }
    tail[256] = 0;
    for (size_t i = 0; i < 3; ++i) {
        if (!rfw_operation_matches(json_at(ops, i), tail, stages[i])) return false;
    }
    const struct json_value *last = json_at(ops, 2);
    return json_get_bool(json_get(last, "exit_observed")) == !failed &&
        json_get_int(json_get(last, "exit_code")) == (failed ? -1 : 0);
}
static bool rfw_bool(const struct json_value *object, const char *key, bool expected)
{
    const struct json_value *value = json_get(object, key);
    return value && value->type == JSON_BOOL && json_get_bool(value) == expected;
}
static bool rfw_failed(const struct json_value *data, const struct json_value *execution)
{
    const struct json_value *error = json_get(data, "continuation_error");
    const char *message = json_get_str(json_get(error, "message_excerpt"));
    const char *code = json_get_str(json_get(error, "code"));
    const char *worker_message = json_get_str(json_get(json_at(json_get(data, "operations"), 2), "error_excerpt"));
    char expected[161]; memset(expected, '"', 160); expected[160] = 0;
    return execution->type == JSON_NULL && message && !strcmp(message, expected) &&
        code && !strcmp(code, "PREVIEW_TIMEOUT") && worker_message && !strcmp(worker_message, expected) &&
        rfw_bool(error, "received_copy_retained", true) &&
        rfw_bool(error, "automatic_retry", false) && !json_get(data, "kept");
}
static bool rfw_outcome(const struct json_value *envelope, bool failed)
{
    const struct json_value *data = json_get(envelope, "data");
    const struct json_value *execution = json_get(data, "continuation_executed");
    const char *status = json_get_str(json_get(envelope, "status"));
    const char *continuation = json_get_str(json_get(data, "continuation"));
    if (!json_get_bool(json_get(envelope, "ok")) || !status || strcmp(status, "passed") ||
        !continuation || strcmp(continuation, failed ? "failed" : "kept") || !execution) return false;
    if (!failed) return execution->type == JSON_BOOL && json_get_bool(execution) &&
        rfw_pins(json_get(data, "kept")) && !json_get(data, "continuation_error");
    return rfw_failed(data, execution);
}
static bool rfw_edge(const struct zcl_command_spec *spec, struct zcl_command_reply *reply,
    struct zcl_command_budget_fixture fixture, size_t measured)
{
    char wire[16385]; size_t usable = 0, n = 0;
    fixture.budget_bytes = measured;
    bool ok = zcl_command_registry_test_success_budget(spec, reply, &fixture,
        &usable, wire, sizeof(wire), &n) && n == measured;
    fixture.budget_bytes = measured - 1;
    return ok && zcl_command_registry_test_success_budget(spec, reply, &fixture,
        &usable, wire, sizeof(wire), &n) && n == 0 && wire[0] == 0;
}
static bool rfw_report(struct zcl_command_reply *reply, bool failed)
{
    struct json_value success, failure;
    json_init(&success); json_set_object(&success);
    json_init(&failure); json_set_object(&failure);
    struct app_receive_job_result results[3]; rfw_evidence(results, failed);
    const struct json_value *wires[] = {&success, &success, failed ? &failure : &success};
    bool ok = rfw_worker(&success, false) && rfw_worker(&failure, true) &&
        app_receive_flow_test_report(reply, results, wires, failed);
    json_free(&failure); json_free(&success);
    return ok;
}
/* Synchronous fixture dispatch adds the engine's post-handler contract check,
 * which the bounded-serializer API intentionally does not perform. */
static bool rfw_inject_stale_error;
static void rfw_handler(const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    reply->error.mutated = true; /* Synthetic already-committed Receive. */
    if (!rfw_receipt(&reply->data) || !rfw_report(reply, true)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "FIXTURE_FAILED", "fixture", false, false, "Cannot prepare wire fixture", "receive-wire");
        return;
    }
    if (rfw_inject_stale_error)
        (void)snprintf(reply->error.code, sizeof(reply->error.code), "STALE_FIXTURE_ERROR");
}
static bool rfw_dispatch(const struct zcl_command_spec *base, bool stale)
{
    struct zcl_command_spec spec = *base;
    spec.path = "fixture.receive-wire";
    spec.input_schema = NULL; spec.input_keys = NULL; spec.handler = rfw_handler;
    struct zcl_command_registry registry = {.commands = &spec, .count = 1};
    struct zcl_command_context context = {.registry = zcl_command_catalog(),
        .granted_capabilities = ~(uint64_t)0, .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
    struct json_value input, envelope;
    json_init(&input); json_set_object(&input); json_init(&envelope);
    char wire[16385]; enum zcl_command_exit exit_code;
    rfw_inject_stale_error = stale;
    size_t n = zcl_command_registry_execute_json(&registry, &spec, &context, &input,
        false, spec.path, "normal", 0, 0, NULL, wire, sizeof(wire), &exit_code);
    rfw_inject_stale_error = false;
    bool ok = n > 0 && n <= 16384 && json_read(&envelope, wire, n);
    if (stale) {
        const char *code = json_get_str(json_get(json_get(&envelope, "error"), "code"));
        ok = ok && exit_code == ZCL_COMMAND_EXIT_INTERNAL && code && !strcmp(code, "INTERNAL_CONTRACT");
    } else ok = ok && exit_code == ZCL_COMMAND_EXIT_OK && rfw_outcome(&envelope, true);
    json_free(&envelope); json_free(&input);
    return ok;
}
static int rfw_case(const struct zcl_command_spec *spec, bool failed)
{
    int failures = 0;
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, spec->output_schema);
    reply.error.mutated = true;
    struct json_value original, envelope;
    json_init(&original); json_init(&envelope);
    bool ready = rfw_receipt(&reply.data) && json_copy_checked(&original, &reply.data);
    CIB_CHECK("receive wire: full 8192-byte escaped committed receipt and worker inputs", ready);
    bool produced = ready && rfw_report(&reply, failed);
    CIB_CHECK("receive wire: actual compact producer and finish retain successful receive", produced &&
        reply.status == ZCL_COMMAND_STATUS_PASSED && reply.exit_code == 0 && !reply.error.code[0]);
    CIB_CHECK("receive wire: committed mutation truth retained", reply.error.mutated);
    struct zcl_command_budget_fixture fixture = {.authority_evidence = "fixture:\"\\\n",
        .debited_zat = INT64_MAX, .remaining_zat = INT64_MAX, .elapsed_us = INT64_MAX,
        .presented = true, .alias = true};
    size_t n = 0, usable = 0;
    char wire[16385];
    bool serialized = produced && zcl_command_registry_test_success_budget(spec, &reply,
        &fixture, &usable, wire, sizeof(wire), &n);
    bool decoded = serialized && n > 8192 && n <= 16384 && json_read(&envelope, wire, n);
    CIB_CHECK("receive wire: actual full envelope fits 16KiB without serialize-zero", decoded);
    if (decoded) {
        CIB_CHECK("receive wire: every original receipt value preserved", rfw_original(&original, json_get(&envelope, "data")));
        CIB_CHECK("receive wire: exact tail/omission count and observed or unknown exit", rfw_diagnostics(json_get(&envelope, "data"), failed));
        CIB_CHECK("receive wire: failure never erases receipt or claims execution false", rfw_outcome(&envelope, failed));
        CIB_CHECK("receive wire: arbitrary worker body excluded", !strstr(wire, "MUST_NOT_COPY_WORKER_BODY"));
        CIB_CHECK("receive wire: encoded-size exact edge passes, one byte less refuses", rfw_edge(spec, &reply, fixture, n));
    }
    printf("  receive wire: failed=%d encoded_bytes=%zu usable_data=%zu\n", failed, n, usable);
    json_free(&envelope); json_free(&original);
    zcl_command_reply_free(&reply);
    return failures;
}
static int t_receive_continuation_wire(void)
{
    int failures = 0;
    const struct zcl_command_spec *spec = zcl_command_registry_find(zcl_command_catalog(), "app.receive", NULL);
    bool ready = spec && spec->budget_bytes == 16384;
    CIB_CHECK("receive wire: real catalog contract is 16KiB", ready);
    if (ready) {
        failures += rfw_case(spec, false); failures += rfw_case(spec, true);
        CIB_CHECK("receive wire: real executor accepts nested failure after committed receipt", rfw_dispatch(spec, false));
        CIB_CHECK("receive wire: executor still rejects PASSED with stale outer error", rfw_dispatch(spec, true));
    }
    return failures;
}

int test_command_input_bounds(void)
{
    printf("\n=== command_input_bounds: per-key input length rules ===\n");
    int failures = 0;
    failures += t_receive_continuation_wire();
    failures += t_ops_state_explain_boolean();
    failures += t_discovery_transport_shapes();
    failures += t_discovery_transport_edges();
    failures += t_discovery_descriptor_contract();
    failures += t_soak_input_contract();
    failures += t_soak_time_contract();
    failures += t_key_edges();
    failures += t_machine_protected_object_types();
    failures += t_machine_protected_wrong_types();
    failures += t_frame_budget();
    failures += t_wiki_text_bounds();
    failures += t_no_collateral_loosening();
    failures += t_vault_effects_array();
    failures += t_liquidity_numeric_input();
    failures += t_fleet_ledger_numeric_keys();
    failures += t_package_prepare_sequence();
    failures += t_lab_include_source();
    failures += t_package_fetch_maximum_bytes();
    failures += t_fleet_usage_days();
    failures += t_moved_dual_shape_since();
    failures += t_moved_ttl_bounds();
    failures += t_regtest_mine_blocks();
    failures += t_wallet_unlock_timeout();
    failures += t_moved_chunks_paid_bounds();
    failures += t_moved_chunk_start_bounds();
    failures += t_moved_line_bounds();
    failures += t_line_key_is_per_leaf();
    failures += t_out_key_is_per_leaf();
    failures += t_moved_max_lines_bounds();
    failures += t_moved_required_discovery();
    failures += t_resident_execution_grant();
    failures += t_execution_consent_scopes();
    failures += t_local_acceptance_boolean();
    failures += t_resident_binding_types();
    failures += t_policy_fact_types();
    failures += t_offline_compare_limit_bounds();
    failures += t_offline_compare_limit_descriptor();
    failures += t_offline_compare_limit_isolation();
    failures += t_execute_json_validates_input();
    printf("=== command_input_bounds complete: %d failure(s) ===\n", failures);
    return failures;
}
