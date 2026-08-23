/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * check_describe_budget — every leaf's `discover describe` document must fit
 * the byte budget the renderer writes into.
 *
 * Why this gate exists. `discover describe <path>` is the ONLY surface that
 * renders a leaf's long-form `semantics` contract at all: docs/API_REFERENCE.md
 * carries summaries, and `discover help` carries a five-field child row. When a
 * leaf's describe document outgrows ZCL_COMMAND_SPEC_BUDGET,
 * zcl_command_registry_describe_json() returns 0 and the CLI reports the path
 * as missing — so the leaf keeps dispatching, keeps being listed by help and
 * search, and its written contract silently becomes unreadable. That happened
 * to core.wallet.recovery.restore with a money-safety warning inside the text
 * nobody could read, and to zcode.endpoint.publish before it. Neither was
 * caught by any gate, because nothing rendered a describe document for every
 * leaf.
 *
 * Mechanism. This tool is a SECOND consumer of the same X-macro grammar
 * config/src/command_catalog.c uses (the same trick tools/gen_api_reference.c
 * plays): it defines every ZCL_COMMAND_* macro to emit one real
 * `struct zcl_command_spec` initializer, #includes the same eleven .def files
 * in the same order, and then calls the REAL
 * zcl_command_registry_describe_json() on every leaf. There is no second
 * renderer and no size model to drift — the bytes measured here are the bytes
 * the binary emits. If a row macro's arity ever changes, this file fails to
 * compile, which is a loud failure, not a silent skip.
 *
 * The handler column is the one field this tool does NOT bind: resolving 180
 * handler symbols would drag the whole node into a lint gate, and describe
 * never calls a handler. Every row lands `.handler = NULL`, which is exactly
 * what a COMPAT/PLANNED row carries in the shipped catalog anyway.
 *
 * Availability view: rendered as the RELEASE catalog sees it (no
 * ZCL_DEV_BUILD), because a release row carries a non-empty
 * `availability_reason` and a dev row does not — so the release view is the
 * LARGER document. Measuring the larger one is the fail-closed direction.
 *
 * Baseline: tools/lint/describe_budget_baseline.txt lists the leaves that
 * already overflowed when this gate was written, one `path  reason` per line.
 * It may only SHRINK. A new overflow fails; a baselined leaf that now fits
 * also fails, so a fix cannot leave a stale exemption behind.
 *
 * Usage:
 *   check_describe_budget <baseline.txt>     # gate
 *   check_describe_budget <baseline.txt> -v  # gate + per-leaf byte sizes
 */

#include "kernel/command_registry.h"

#include "services/agent_spend_policy.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* lib/kernel/src/command_registry.c calls the agent spend policy from
 * zcl_command_registry_invoke() — the dispatch path — and nowhere else. This
 * gate only renders describe documents, so neither of these can be reached.
 * Defining them here keeps the gate a seven-file link instead of dragging
 * app/services and its RPC client in behind it; both abort rather than
 * returning a made-up decision, so if a future refactor ever does route
 * describe through the policy, this gate dies loudly instead of measuring the
 * wrong document. */
void agent_spend_policy_evaluate(const char *session_id,
                                 const struct zcl_command_spec *spec,
                                 const struct json_value *input,
                                 bool committing,
                                 struct agent_spend_policy_decision *out)
{
    (void)session_id; (void)spec; (void)input; (void)committing; (void)out;
    fputs("check-describe-budget: agent spend policy reached from a describe "
          "render — this gate's link is no longer honest\n", stderr);
    abort();
}

void agent_spend_policy_release(const char *session_id,
                                const struct agent_spend_policy_decision *d)
{
    (void)session_id; (void)d;
    fputs("check-describe-budget: agent spend policy reached from a describe "
          "render — this gate's link is no longer honest\n", stderr);
    abort();
}

/* ── Row macros: one real struct zcl_command_spec per .def entry ──────── */

#define ZCL_COMMAND_BRANCH(path_, parent_, summary_, layer_)                   \
    { .path = (path_), .parent = (parent_), .aliases = "",                     \
      .summary = (summary_), .semantics = "", .tags = "", .input_schema = "",  \
      .output_schema = "", .input_keys = "", .positional_keys = "",            \
      .example = "", .availability_reason = "", .compat_target = "",           \
      .budget_bytes = 0,                                                       \
      .layer = (layer_), .effect = ZCL_COMMAND_EFFECT_READ,                    \
      .risk = ZCL_COMMAND_RISK_READ, .scope = ZCL_COMMAND_SCOPE_LOCAL,         \
      .authority = ZCL_COMMAND_AUTH_PUBLIC,                                    \
      .availability = ZCL_COMMAND_READY, .mode = ZCL_COMMAND_MODE_BRANCH,      \
      .latency = ZCL_COMMAND_LATENCY_INSTANT, .cost = ZCL_COMMAND_COST_TINY,   \
      .confirmation = ZCL_COMMAND_CONFIRM_NONE,                                \
      .allowed_lanes = ZCL_COMMAND_LANE_LOCAL | ZCL_COMMAND_LANE_ALL_NODE,     \
      .required_capabilities = ZCL_COMMAND_CAP_NONE,                           \
      .traits = ZCL_COMMAND_TRAIT_NONE,                                        \
      .transports = ZCL_COMMAND_TRANSPORT_NATIVE, .handler = NULL },

#define ZCL_COMMAND_READY_READ(path_, parent_, aliases_, summary_, semantics_, \
                               budget_, tags_,                                 \
                               in_, out_, in_keys_, pos_keys_, example_,       \
                               layer_, scope_, authority_, latency_, cost_,    \
                               lanes_, caps_, traits_, transports_, handler_)  \
    { .path = (path_), .parent = (parent_), .aliases = (aliases_),             \
      .summary = (summary_), .semantics = (semantics_), .tags = (tags_),       \
      .input_schema = (in_),                                                   \
      .output_schema = (out_), .input_keys = (in_keys_),                       \
      .positional_keys = (pos_keys_), .example = (example_),                   \
      .availability_reason = "", .compat_target = "",                          \
      .budget_bytes = (budget_), .layer = (layer_),                            \
      .effect = ZCL_COMMAND_EFFECT_READ, .risk = ZCL_COMMAND_RISK_READ,        \
      .scope = (scope_), .authority = (authority_),                            \
      .availability = ZCL_COMMAND_READY, .mode = ZCL_COMMAND_MODE_SYNC,        \
      .latency = (latency_), .cost = (cost_),                                  \
      .confirmation = ZCL_COMMAND_CONFIRM_NONE, .allowed_lanes = (lanes_),     \
      .required_capabilities = (caps_), .traits = (traits_),                   \
      .transports = (transports_), .handler = NULL },

#define ZCL_COMMAND_COMPAT_READ(path_, parent_, aliases_, summary_, semantics_,\
                                budget_, tags_,                                \
                                in_, out_, in_keys_, pos_keys_, example_,      \
                                layer_, scope_, authority_, latency_, cost_,   \
                                lanes_, caps_, transports_, compat_)           \
    { .path = (path_), .parent = (parent_), .aliases = (aliases_),             \
      .summary = (summary_), .semantics = (semantics_), .tags = (tags_),       \
      .input_schema = (in_),                                                   \
      .output_schema = (out_), .input_keys = (in_keys_),                       \
      .positional_keys = (pos_keys_), .example = (example_),                   \
      .availability_reason =                                                   \
          "native adapter is not executable yet; use the compatibility "       \
          "target",                                                            \
      .compat_target = (compat_), .budget_bytes = (budget_),                   \
      .layer = (layer_),                                                       \
      .effect = ZCL_COMMAND_EFFECT_READ, .risk = ZCL_COMMAND_RISK_READ,        \
      .scope = (scope_), .authority = (authority_),                            \
      .availability = ZCL_COMMAND_COMPAT, .mode = ZCL_COMMAND_MODE_SYNC,       \
      .latency = (latency_), .cost = (cost_),                                  \
      .confirmation = ZCL_COMMAND_CONFIRM_NONE, .allowed_lanes = (lanes_),     \
      .required_capabilities = (caps_), .traits = ZCL_COMMAND_TRAIT_NONE,      \
      .transports = (transports_), .handler = NULL },

#define ZCL_COMMAND_PLANNED_READ(path_, parent_, aliases_, summary_,           \
                                 semantics_, budget_, tags_,                   \
                                 in_, out_, in_keys_, pos_keys_, example_,     \
                                 layer_, scope_, authority_, latency_, cost_,  \
                                 lanes_, caps_, reason_)                       \
    { .path = (path_), .parent = (parent_), .aliases = (aliases_),             \
      .summary = (summary_), .semantics = (semantics_), .tags = (tags_),       \
      .input_schema = (in_),                                                   \
      .output_schema = (out_), .input_keys = (in_keys_),                       \
      .positional_keys = (pos_keys_), .example = (example_),                   \
      .availability_reason = (reason_), .compat_target = "",                   \
      .budget_bytes = (budget_),                                               \
      .layer = (layer_), .effect = ZCL_COMMAND_EFFECT_READ,                    \
      .risk = ZCL_COMMAND_RISK_READ, .scope = (scope_),                        \
      .authority = (authority_), .availability = ZCL_COMMAND_PLANNED,          \
      .mode = ZCL_COMMAND_MODE_SYNC, .latency = (latency_), .cost = (cost_),   \
      .confirmation = ZCL_COMMAND_CONFIRM_NONE, .allowed_lanes = (lanes_),     \
      .required_capabilities = (caps_), .traits = ZCL_COMMAND_TRAIT_NONE,      \
      .transports = ZCL_COMMAND_TRANSPORT_NATIVE, .handler = NULL },

#define ZCL_COMMAND_PLANNED_COMMAND(path_, parent_, aliases_, summary_,        \
                                    semantics_, budget_, tags_,                \
                                    in_, out_, in_keys_, pos_keys_, example_,  \
                                    layer_, effect_, risk_, scope_,            \
                                    authority_, mode_, latency_, cost_,        \
                                    confirmation_, lanes_, caps_, traits_,     \
                                    reason_)                                   \
    { .path = (path_), .parent = (parent_), .aliases = (aliases_),             \
      .summary = (summary_), .semantics = (semantics_), .tags = (tags_),       \
      .input_schema = (in_),                                                   \
      .output_schema = (out_), .input_keys = (in_keys_),                       \
      .positional_keys = (pos_keys_), .example = (example_),                   \
      .availability_reason = (reason_), .compat_target = "",                   \
      .budget_bytes = (budget_),                                               \
      .layer = (layer_), .effect = (effect_), .risk = (risk_),                 \
      .scope = (scope_), .authority = (authority_),                            \
      .availability = ZCL_COMMAND_PLANNED, .mode = (mode_),                    \
      .latency = (latency_), .cost = (cost_), .confirmation = (confirmation_), \
      .allowed_lanes = (lanes_), .required_capabilities = (caps_),             \
      .traits = (traits_), .transports = ZCL_COMMAND_TRANSPORT_NATIVE,         \
      .handler = NULL },

#define ZCL_COMMAND_COMPAT_COMMAND(path_, parent_, aliases_, summary_,         \
                                   semantics_, budget_, tags_,                 \
                                   in_, out_, in_keys_, pos_keys_, example_,   \
                                   layer_, effect_, risk_, scope_,             \
                                   authority_, mode_, latency_, cost_,         \
                                   confirmation_, lanes_, caps_, traits_,      \
                                   reason_, compat_)                           \
    { .path = (path_), .parent = (parent_), .aliases = (aliases_),             \
      .summary = (summary_), .semantics = (semantics_), .tags = (tags_),       \
      .input_schema = (in_),                                                   \
      .output_schema = (out_), .input_keys = (in_keys_),                       \
      .positional_keys = (pos_keys_), .example = (example_),                   \
      .availability_reason = (reason_), .compat_target = (compat_),            \
      .budget_bytes = (budget_),                                               \
      .layer = (layer_), .effect = (effect_), .risk = (risk_),                 \
      .scope = (scope_), .authority = (authority_),                            \
      .availability = ZCL_COMMAND_COMPAT, .mode = (mode_),                     \
      .latency = (latency_), .cost = (cost_), .confirmation = (confirmation_), \
      .allowed_lanes = (lanes_), .required_capabilities = (caps_),             \
      .traits = (traits_), .transports = ZCL_COMMAND_TRANSPORT_NATIVE,         \
      .handler = NULL },

#define ZCL_COMMAND_READY_COMMAND(path_, parent_, aliases_, summary_,          \
                                  semantics_, budget_, tags_,                  \
                                  in_, out_, in_keys_, pos_keys_, example_,    \
                                  layer_, effect_, risk_, scope_,              \
                                  authority_, mode_, latency_, cost_,          \
                                  confirmation_, lanes_, caps_, traits_,       \
                                  handler_)                                    \
    { .path = (path_), .parent = (parent_), .aliases = (aliases_),             \
      .summary = (summary_), .semantics = (semantics_), .tags = (tags_),       \
      .input_schema = (in_),                                                   \
      .output_schema = (out_), .input_keys = (in_keys_),                       \
      .positional_keys = (pos_keys_), .example = (example_),                   \
      .availability_reason = "", .compat_target = "",                          \
      .budget_bytes = (budget_),                                               \
      .layer = (layer_), .effect = (effect_), .risk = (risk_),                 \
      .scope = (scope_), .authority = (authority_),                            \
      .availability = ZCL_COMMAND_READY, .mode = (mode_),                      \
      .latency = (latency_), .cost = (cost_), .confirmation = (confirmation_), \
      .allowed_lanes = (lanes_), .required_capabilities = (caps_),             \
      .traits = (traits_), .transports = ZCL_COMMAND_TRANSPORT_NATIVE,         \
      .handler = NULL },

/* Release view of a dev leaf: honest COMPAT metadata with the reason string
 * present. See the availability note in the file header. */
#define ZCL_DEV_AVAILABILITY ZCL_COMMAND_COMPAT
#define ZCL_DEV_REASON(reason_) (reason_)
#define ZCL_DEV_COMPAT(target_) (target_)

#define ZCL_COMMAND_DEV_READ(path_, parent_, aliases_, summary_, semantics_,   \
                             budget_, tags_,                                   \
                             in_, out_, in_keys_, pos_keys_, example_,         \
                             scope_, authority_, latency_, cost_, lanes_,      \
                             caps_, traits_, handler_, release_reason_,        \
                             compat_)                                          \
    { .path = (path_), .parent = (parent_), .aliases = (aliases_),             \
      .summary = (summary_), .semantics = (semantics_), .tags = (tags_),       \
      .input_schema = (in_),                                                   \
      .output_schema = (out_), .input_keys = (in_keys_),                       \
      .positional_keys = (pos_keys_), .example = (example_),                   \
      .availability_reason = ZCL_DEV_REASON(release_reason_),                  \
      .compat_target = ZCL_DEV_COMPAT(compat_),                                \
      .budget_bytes = (budget_),                                               \
      .layer = ZCL_COMMAND_LAYER_DEV, .effect = ZCL_COMMAND_EFFECT_READ,       \
      .risk = ZCL_COMMAND_RISK_READ, .scope = (scope_),                        \
      .authority = (authority_), .availability = ZCL_DEV_AVAILABILITY,         \
      .mode = ZCL_COMMAND_MODE_SYNC, .latency = (latency_), .cost = (cost_),   \
      .confirmation = ZCL_COMMAND_CONFIRM_NONE, .allowed_lanes = (lanes_),     \
      .required_capabilities = (caps_), .traits = (traits_),                   \
      .transports = ZCL_COMMAND_TRANSPORT_NATIVE, .handler = NULL },

#define ZCL_COMMAND_DEV_COMMAND(path_, parent_, aliases_, summary_,            \
                                semantics_, budget_, tags_,                    \
                                in_, out_, in_keys_, pos_keys_, example_,      \
                                effect_, risk_, scope_, authority_, mode_,     \
                                latency_, cost_, confirmation_, lanes_, caps_, \
                                traits_, handler_, release_reason_, compat_)   \
    { .path = (path_), .parent = (parent_), .aliases = (aliases_),             \
      .summary = (summary_), .semantics = (semantics_), .tags = (tags_),       \
      .input_schema = (in_),                                                   \
      .output_schema = (out_), .input_keys = (in_keys_),                       \
      .positional_keys = (pos_keys_), .example = (example_),                   \
      .availability_reason = ZCL_DEV_REASON(release_reason_),                  \
      .compat_target = ZCL_DEV_COMPAT(compat_),                                \
      .budget_bytes = (budget_),                                               \
      .layer = ZCL_COMMAND_LAYER_DEV, .effect = (effect_), .risk = (risk_),    \
      .scope = (scope_), .authority = (authority_),                            \
      .availability = ZCL_DEV_AVAILABILITY, .mode = (mode_),                   \
      .latency = (latency_), .cost = (cost_),                                  \
      .confirmation = (confirmation_), .allowed_lanes = (lanes_),              \
      .required_capabilities = (caps_), .traits = (traits_),                   \
      .transports = ZCL_COMMAND_TRANSPORT_NATIVE, .handler = NULL },

/* The catalogs are reached through the include PATH (`-Iconfig`), not a
 * relative path, so the gate's --selftest can compile this same file against a
 * padded copy of config/commands by putting that copy's parent first on -I. */
static struct zcl_command_spec g_specs[] = {
#include "commands/root.def"
#include "commands/core.def"
#include "commands/apps.def"
#include "commands/app_features.def"
#include "commands/store.def"
#include "commands/ops.def"
#include "commands/dev.def"
#include "commands/code.def"
#include "commands/accounts.def"
#include "commands/vault.def"
#include "commands/zcode.def"
#include "commands/metaverse.def"
#include "commands/zses.def"
};

#define SPEC_COUNT (sizeof(g_specs) / sizeof(g_specs[0]))

/* ── Baseline ─────────────────────────────────────────────────────────── */

#define MAX_BASELINE 64

struct baseline_entry {
    char path[ZCL_COMMAND_MAX_PATH];
    bool seen_overflowing;
};

static struct baseline_entry g_baseline[MAX_BASELINE];
static size_t g_baseline_count;

static void trim(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ' ||
                     s[n - 1] == '\t'))
        s[--n] = '\0';
}

/* One `path<whitespace>reason` per line; `#` comments and blanks ignored.
 * A line with no reason is rejected: an exemption without a written reason is
 * how a permanent hole gets normalised. */
static bool load_baseline(const char *file)
{
    FILE *f = fopen(file, "re");
    if (!f) {
        fprintf(stderr, "check-describe-budget: cannot open baseline %s\n",
                file);
        return false;
    }
    char line[1024];
    bool ok = true;
    while (fgets(line, sizeof(line), f)) {
        trim(line);
        if (line[0] == '\0' || line[0] == '#')
            continue;
        char *sep = strpbrk(line, " \t");
        if (!sep) {
            fprintf(stderr, "check-describe-budget: baseline line has no "
                            "reason: '%s'\n", line);
            ok = false;
            continue;
        }
        *sep = '\0';
        while (*++sep == ' ' || *sep == '\t')
            ;
        if (*sep == '\0') {
            fprintf(stderr, "check-describe-budget: baseline line has no "
                            "reason: '%s'\n", line);
            ok = false;
            continue;
        }
        if (g_baseline_count >= MAX_BASELINE) {
            fprintf(stderr, "check-describe-budget: baseline too large\n");
            ok = false;
            break;
        }
        size_t path_len = strlen(line);
        if (path_len >= ZCL_COMMAND_MAX_PATH) {
            fprintf(stderr, "check-describe-budget: baseline path too long: "
                            "'%s'\n", line);
            ok = false;
            continue;
        }
        memcpy(g_baseline[g_baseline_count].path, line, path_len + 1);
        g_baseline[g_baseline_count].seen_overflowing = false;
        g_baseline_count++;
    }
    fclose(f);
    return ok;
}

static struct baseline_entry *baseline_find(const char *path)
{
    for (size_t i = 0; i < g_baseline_count; i++)
        if (strcmp(g_baseline[i].path, path) == 0)
            return &g_baseline[i];
    return NULL;
}

/* ── Measurement ──────────────────────────────────────────────────────── */

/* How many bytes the describe document needs, when it needs more than the
 * budget allows. describe_json returns 0 on overflow and never the needed
 * size, so this measures it from the same renderer instead of modelling it:
 * render a COPY of the catalog whose `semantics` for this one leaf is a single
 * character, which always fits, then add back what the real prose costs once
 * JSON-escaped. Returns 0 if even the one-character form does not fit (a leaf
 * whose FIXED fields alone are over budget — different bug, reported as such).
 *
 * `registry_digest` is 71 characters for any registry content, so mutating the
 * copy changes the digest's value and not the document's length. */
static size_t describe_needed_bytes(size_t idx)
{
    static struct zcl_command_spec probe[SPEC_COUNT];
    memcpy(probe, g_specs, sizeof(g_specs));
    const char *real = probe[idx].semantics;
    probe[idx].semantics = "x";
    struct zcl_command_registry reg = { .commands = probe,
                                        .count = SPEC_COUNT };
    char out[ZCL_COMMAND_LIST_BUDGET + 1];
    size_t base = zcl_command_registry_describe_json(&reg, probe[idx].path, out,
                                                     sizeof(out));
    if (base == 0)
        return 0;
    size_t escaped = 0;
    for (const char *p = real ? real : ""; *p; p++)
        escaped += (*p == '"' || *p == '\\' || (unsigned char)*p < 0x20) ? 2 : 1;
    return base - 1 /* the placeholder 'x' */ + escaped;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <baseline.txt> [-v]\n", argv[0]);
        return 2;
    }
    const bool verbose = argc > 2 && strcmp(argv[2], "-v") == 0;
    if (!load_baseline(argv[1]))
        return 1;

    const struct zcl_command_registry reg = { .commands = g_specs,
                                              .count = SPEC_COUNT };
    char out[ZCL_COMMAND_LIST_BUDGET + 1];
    size_t leaves = 0, largest = 0, new_overflow = 0, fixed_overflow = 0;
    const char *largest_path = "";

    for (size_t i = 0; i < SPEC_COUNT; i++) {
        const struct zcl_command_spec *spec = &g_specs[i];
        if (spec->mode == ZCL_COMMAND_MODE_BRANCH)
            continue;   /* branches render a menu, gated by MENU_BUDGET */
        leaves++;
        size_t n = zcl_command_registry_describe_json(&reg, spec->path, out,
                                                      sizeof(out));
        if (n > 0) {
            if (n > largest) {
                largest = n;
                largest_path = spec->path;
            }
            if (verbose)
                printf("  %5zu  %s\n", n, spec->path);
            struct baseline_entry *b = baseline_find(spec->path);
            if (b)
                fprintf(stderr,
                    "STALE BASELINE: %s now fits (%zu bytes) — delete its line "
                    "from %s. This baseline may only shrink.\n",
                    spec->path, n, argv[1]);
            continue;
        }

        size_t need = describe_needed_bytes(i);
        struct baseline_entry *b = baseline_find(spec->path);
        if (b) {
            b->seen_overflowing = true;
            if (verbose)
                printf("  BASELINED  %s (needs %zu of %u)\n", spec->path, need,
                       ZCL_COMMAND_SPEC_BUDGET);
            continue;
        }
        if (need == 0) {
            fixed_overflow++;
            fprintf(stderr,
                "OVER BUDGET: %s — its describe document does not fit "
                "ZCL_COMMAND_SPEC_BUDGET (%u bytes) even with an empty "
                "`semantics`. Shorten the fixed fields (summary, example, "
                "input_keys, schema ids).\n",
                spec->path, ZCL_COMMAND_SPEC_BUDGET);
            continue;
        }
        new_overflow++;
        fprintf(stderr,
            "OVER BUDGET: %s — its describe document needs %zu bytes and "
            "ZCL_COMMAND_SPEC_BUDGET is %u. `discover describe %s` cannot be "
            "read at all: the renderer reports DESCRIBE_BUDGET and the leaf's "
            "written contract is invisible. Trim its `semantics` in "
            "config/commands/*.def by at least %zu bytes. Do NOT raise the "
            "budget.\n",
            spec->path, need, ZCL_COMMAND_SPEC_BUDGET, spec->path,
            need - ZCL_COMMAND_SPEC_BUDGET);
    }

    size_t stale = 0;
    for (size_t i = 0; i < g_baseline_count; i++)
        if (!g_baseline[i].seen_overflowing)
            stale++;

    if (new_overflow || fixed_overflow || stale) {
        fprintf(stderr,
            "\nFAIL: %zu leaf/leaves over the describe budget"
            "%s. Baseline: %s (%zu entr%s, may only shrink).\n",
            new_overflow + fixed_overflow,
            stale ? ", plus a stale baseline entry" : "", argv[1],
            g_baseline_count, g_baseline_count == 1 ? "y" : "ies");
        return 1;
    }
    printf("check-describe-budget: %zu leaves render; largest %zu/%u bytes "
           "(%s); %zu baselined pre-existing.\n",
           leaves, largest, ZCL_COMMAND_SPEC_BUDGET, largest_path,
           g_baseline_count);
    return 0;
}
