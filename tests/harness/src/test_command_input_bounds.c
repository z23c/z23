/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_command_input_bounds — the per-key length rule in
 * zcl_command_registry_input_validate() and the per-leaf read frame it
 * implies (zcl_command_registry_input_budget_bytes()).
 *
 * THE BUG THIS PINS (2026-07-29): the validator's default branch typed every
 * unlisted key as a string of at most 4096 characters. The zcode publish
 * leaves carry their payloads as HEX, so that capped a package manifest wire
 * at 2 KB — about three files — while VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES is
 * 1 MiB. Publishing worked for toy packages only, and the refusal read
 * "invalid type or range", which points at the type, not at the length.
 *
 * The fix is a per-key bound derived from each wire's own constant, with the
 * bound living where the type lives. These cases hold BOTH edges of three
 * differently-limited keys, so a future "just raise the default" or "just
 * drop the bound" is caught:
 *
 *   manifest_hex  2 * VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES  (2 MiB chars)
 *   recipe_hex    2 * VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES    (512 KiB chars)
 *   release_hex   2 * VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES
 *   everything else                     4096 chars, unchanged
 *
 * and the read frame each leaf gets, because a validator that accepts 2 MiB
 * in front of a reader that stops at 16 KiB is not a fix. */

#include "test/test_core.h"

#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"

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
                checked++;
                if (zcl_command_registry_input_str_max(token) >= budget)
                    undeliverable++;
            }
            if (!end)
                break;
            at = end + 1;
        }
    }
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

int test_command_input_bounds(void)
{
    printf("\n=== command_input_bounds: per-key input length rules ===\n");
    int failures = 0;
    failures += t_key_edges();
    failures += t_frame_budget();
    failures += t_no_collateral_loosening();
    failures += t_vault_effects_array();
    failures += t_liquidity_numeric_input();
    failures += t_package_prepare_sequence();
    failures += t_package_fetch_maximum_bytes();
    printf("=== command_input_bounds complete: %d failure(s) ===\n", failures);
    return failures;
}
