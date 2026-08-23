/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Generates docs/API_REFERENCE.md from the declarative command catalogs under
 * the config/commands .def catalogs, so the operator-facing command reference
 * can never drift from the table the binary actually compiles.
 *
 * Mechanism: this tool is a SECOND consumer of the same X-macro grammar
 * config/src/command_catalog.c uses. It defines every ZCL_COMMAND_* macro to
 * emit one `struct row` initializer, #includes the same ten .def files in the
 * same order, and renders Markdown from the resulting table. The C
 * preprocessor does the parsing, so multi-line invocations, adjacent
 * string-literal concatenation, and `A | B` flag expressions are handled by
 * construction — there is no hand-rolled .def parser to truncate an entry.
 *
 * Editorial prose is NOT generated: it lives in the template passed as argv[1]
 * (docs/API_REFERENCE.md.in) and is copied through verbatim. Only lines whose
 * trimmed content is a `<!-- ZCL-GEN:<block> -->` marker are replaced with
 * generated content. An unknown marker is a hard error, never a silent pass.
 *
 * Availability note: dev-gated leaves (ZCL_COMMAND_DEV_READ/_COMMAND) are
 * rendered as the RELEASE catalog sees them — `compat` with the declared
 * fallback — regardless of how this tool itself was compiled, so the output is
 * a pure function of the .def files.
 *
 * Usage: gen_api_reference <template.md.in> <out.md>
 */

#include "kernel/command_registry.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct row {
    const char *path;
    const char *parent;
    const char *aliases;
    const char *summary;
    const char *semantics;
    const char *tags;
    const char *input_schema;
    const char *output_schema;
    const char *input_keys;
    const char *positional_keys;
    const char *example;
    const char *availability_reason;
    const char *compat_target;
    const char *handler_name;
    const char *def_file;
    unsigned long budget_bytes;
    int layer;
    int effect;
    int risk;
    int scope;
    int authority;
    int availability;
    int mode;
    int latency;
    int cost;
    int confirmation;
    unsigned long lanes;
    unsigned long long caps;
    unsigned long traits;
    unsigned long transports;
    bool dev_gated;
    bool is_branch;
};

/* ── X-macro expansions (one row per catalog leaf) ──────────────────────── */

#define ZCL_COMMAND_BRANCH(path_, parent_, summary_, layer_)                   \
    { .path = (path_), .parent = (parent_), .aliases = "",                     \
      .summary = (summary_), .semantics = "", .tags = "", .input_schema = "",  \
      .output_schema = "", .input_keys = "", .positional_keys = "",            \
      .example = "", .availability_reason = "", .compat_target = "",           \
      .handler_name = "", .def_file = ZCL_DEF_FILE, .budget_bytes = 0,         \
      .layer = (layer_), .effect = ZCL_COMMAND_EFFECT_READ,                    \
      .risk = ZCL_COMMAND_RISK_READ, .scope = ZCL_COMMAND_SCOPE_LOCAL,         \
      .authority = ZCL_COMMAND_AUTH_PUBLIC,                                    \
      .availability = ZCL_COMMAND_READY, .mode = ZCL_COMMAND_MODE_BRANCH,      \
      .latency = ZCL_COMMAND_LATENCY_INSTANT, .cost = ZCL_COMMAND_COST_TINY,   \
      .confirmation = ZCL_COMMAND_CONFIRM_NONE,                                \
      .lanes = ZCL_COMMAND_LANE_LOCAL | ZCL_COMMAND_LANE_ALL_NODE,             \
      .caps = ZCL_COMMAND_CAP_NONE, .traits = ZCL_COMMAND_TRAIT_NONE,          \
      .transports = ZCL_COMMAND_TRANSPORT_NATIVE, .dev_gated = false,          \
      .is_branch = true },

#define ZCL_COMMAND_READY_READ(path_, parent_, aliases_, summary_, semantics_, \
                               budget_, tags_,                                 \
                               in_, out_, in_keys_, pos_keys_, example_,       \
                               layer_, scope_, authority_, latency_, cost_,    \
                               lanes_, caps_, traits_, transports_, handler_)  \
    { .path = (path_), .parent = (parent_), .aliases = (aliases_),             \
      .summary = (summary_), .semantics = (semantics_), .tags = (tags_),       \
      .input_schema = (in_), .output_schema = (out_),                          \
      .input_keys = (in_keys_), .positional_keys = (pos_keys_),                \
      .example = (example_), .availability_reason = "", .compat_target = "",   \
      .handler_name = #handler_, .def_file = ZCL_DEF_FILE,                     \
      .budget_bytes = (budget_), .layer = (layer_),                            \
      .effect = ZCL_COMMAND_EFFECT_READ, .risk = ZCL_COMMAND_RISK_READ,        \
      .scope = (scope_), .authority = (authority_),                            \
      .availability = ZCL_COMMAND_READY, .mode = ZCL_COMMAND_MODE_SYNC,        \
      .latency = (latency_), .cost = (cost_),                                  \
      .confirmation = ZCL_COMMAND_CONFIRM_NONE, .lanes = (lanes_),             \
      .caps = (caps_), .traits = (traits_), .transports = (transports_),       \
      .dev_gated = false, .is_branch = false },

#define ZCL_COMMAND_COMPAT_READ(path_, parent_, aliases_, summary_, semantics_,\
                                budget_, tags_,                                \
                                in_, out_, in_keys_, pos_keys_, example_,      \
                                layer_, scope_, authority_, latency_, cost_,   \
                                lanes_, caps_, transports_, compat_)           \
    { .path = (path_), .parent = (parent_), .aliases = (aliases_),             \
      .summary = (summary_), .semantics = (semantics_), .tags = (tags_),       \
      .input_schema = (in_), .output_schema = (out_),                          \
      .input_keys = (in_keys_), .positional_keys = (pos_keys_),                \
      .example = (example_),                                                   \
      .availability_reason =                                                   \
          "native adapter is not executable yet; use the compatibility "       \
          "target",                                                            \
      .compat_target = (compat_), .handler_name = "",                          \
      .def_file = ZCL_DEF_FILE, .budget_bytes = (budget_),                     \
      .layer = (layer_), .effect = ZCL_COMMAND_EFFECT_READ,                    \
      .risk = ZCL_COMMAND_RISK_READ, .scope = (scope_),                        \
      .authority = (authority_), .availability = ZCL_COMMAND_COMPAT,           \
      .mode = ZCL_COMMAND_MODE_SYNC, .latency = (latency_), .cost = (cost_),   \
      .confirmation = ZCL_COMMAND_CONFIRM_NONE, .lanes = (lanes_),             \
      .caps = (caps_), .traits = ZCL_COMMAND_TRAIT_NONE,                       \
      .transports = (transports_), .dev_gated = false, .is_branch = false },

#define ZCL_COMMAND_PLANNED_READ(path_, parent_, aliases_, summary_,           \
                                 semantics_, budget_, tags_,                   \
                                 in_, out_, in_keys_, pos_keys_, example_,     \
                                 layer_, scope_, authority_, latency_, cost_,  \
                                 lanes_, caps_, reason_)                       \
    { .path = (path_), .parent = (parent_), .aliases = (aliases_),             \
      .summary = (summary_), .semantics = (semantics_), .tags = (tags_),       \
      .input_schema = (in_), .output_schema = (out_),                          \
      .input_keys = (in_keys_), .positional_keys = (pos_keys_),                \
      .example = (example_), .availability_reason = (reason_),                 \
      .compat_target = "", .handler_name = "", .def_file = ZCL_DEF_FILE,       \
      .budget_bytes = (budget_), .layer = (layer_),                            \
      .effect = ZCL_COMMAND_EFFECT_READ, .risk = ZCL_COMMAND_RISK_READ,        \
      .scope = (scope_), .authority = (authority_),                            \
      .availability = ZCL_COMMAND_PLANNED, .mode = ZCL_COMMAND_MODE_SYNC,      \
      .latency = (latency_), .cost = (cost_),                                  \
      .confirmation = ZCL_COMMAND_CONFIRM_NONE, .lanes = (lanes_),             \
      .caps = (caps_), .traits = ZCL_COMMAND_TRAIT_NONE,                       \
      .transports = ZCL_COMMAND_TRANSPORT_NATIVE, .dev_gated = false,          \
      .is_branch = false },

#define ZCL_COMMAND_PLANNED_COMMAND(path_, parent_, aliases_, summary_,        \
                                    semantics_, budget_, tags_,                \
                                    in_, out_, in_keys_, pos_keys_, example_,  \
                                    layer_, effect_, risk_, scope_,            \
                                    authority_, mode_, latency_, cost_,        \
                                    confirmation_, lanes_, caps_, traits_,     \
                                    reason_)                                   \
    { .path = (path_), .parent = (parent_), .aliases = (aliases_),             \
      .summary = (summary_), .semantics = (semantics_), .tags = (tags_),       \
      .input_schema = (in_), .output_schema = (out_),                          \
      .input_keys = (in_keys_), .positional_keys = (pos_keys_),                \
      .example = (example_), .availability_reason = (reason_),                 \
      .compat_target = "", .handler_name = "", .def_file = ZCL_DEF_FILE,       \
      .budget_bytes = (budget_), .layer = (layer_), .effect = (effect_),       \
      .risk = (risk_), .scope = (scope_), .authority = (authority_),           \
      .availability = ZCL_COMMAND_PLANNED, .mode = (mode_),                    \
      .latency = (latency_), .cost = (cost_), .confirmation = (confirmation_), \
      .lanes = (lanes_), .caps = (caps_), .traits = (traits_),                 \
      .transports = ZCL_COMMAND_TRANSPORT_NATIVE, .dev_gated = false,          \
      .is_branch = false },

#define ZCL_COMMAND_COMPAT_COMMAND(path_, parent_, aliases_, summary_,         \
                                   semantics_, budget_, tags_,                 \
                                   in_, out_, in_keys_, pos_keys_, example_,   \
                                   layer_, effect_, risk_, scope_,             \
                                   authority_, mode_, latency_, cost_,         \
                                   confirmation_, lanes_, caps_, traits_,      \
                                   reason_, compat_)                           \
    { .path = (path_), .parent = (parent_), .aliases = (aliases_),             \
      .summary = (summary_), .semantics = (semantics_), .tags = (tags_),       \
      .input_schema = (in_), .output_schema = (out_),                          \
      .input_keys = (in_keys_), .positional_keys = (pos_keys_),                \
      .example = (example_), .availability_reason = (reason_),                 \
      .compat_target = (compat_), .handler_name = "",                          \
      .def_file = ZCL_DEF_FILE, .budget_bytes = (budget_),                     \
      .layer = (layer_), .effect = (effect_), .risk = (risk_),                 \
      .scope = (scope_), .authority = (authority_),                            \
      .availability = ZCL_COMMAND_COMPAT, .mode = (mode_),                     \
      .latency = (latency_), .cost = (cost_), .confirmation = (confirmation_), \
      .lanes = (lanes_), .caps = (caps_), .traits = (traits_),                 \
      .transports = ZCL_COMMAND_TRANSPORT_NATIVE, .dev_gated = false,          \
      .is_branch = false },

#define ZCL_COMMAND_READY_COMMAND(path_, parent_, aliases_, summary_,          \
                                  semantics_, budget_, tags_,                  \
                                  in_, out_, in_keys_, pos_keys_, example_,    \
                                  layer_, effect_, risk_, scope_,              \
                                  authority_, mode_, latency_, cost_,          \
                                  confirmation_, lanes_, caps_, traits_,       \
                                  handler_)                                    \
    { .path = (path_), .parent = (parent_), .aliases = (aliases_),             \
      .summary = (summary_), .semantics = (semantics_), .tags = (tags_),       \
      .input_schema = (in_), .output_schema = (out_),                          \
      .input_keys = (in_keys_), .positional_keys = (pos_keys_),                \
      .example = (example_), .availability_reason = "", .compat_target = "",   \
      .handler_name = #handler_, .def_file = ZCL_DEF_FILE,                     \
      .budget_bytes = (budget_), .layer = (layer_), .effect = (effect_),       \
      .risk = (risk_), .scope = (scope_), .authority = (authority_),           \
      .availability = ZCL_COMMAND_READY, .mode = (mode_),                      \
      .latency = (latency_), .cost = (cost_), .confirmation = (confirmation_), \
      .lanes = (lanes_), .caps = (caps_), .traits = (traits_),                 \
      .transports = ZCL_COMMAND_TRANSPORT_NATIVE, .dev_gated = false,          \
      .is_branch = false },

/* Dev leaves: rendered as a RELEASE binary carries them (compat + fallback),
 * independent of how this generator was compiled. */
#define ZCL_COMMAND_DEV_READ(path_, parent_, aliases_, summary_, semantics_,   \
                             budget_, tags_,                                   \
                             in_, out_, in_keys_, pos_keys_, example_,         \
                             scope_, authority_, latency_, cost_, lanes_,      \
                             caps_, traits_, handler_, release_reason_,        \
                             compat_)                                          \
    { .path = (path_), .parent = (parent_), .aliases = (aliases_),             \
      .summary = (summary_), .semantics = (semantics_), .tags = (tags_),       \
      .input_schema = (in_), .output_schema = (out_),                          \
      .input_keys = (in_keys_), .positional_keys = (pos_keys_),                \
      .example = (example_), .availability_reason = (release_reason_),         \
      .compat_target = (compat_), .handler_name = #handler_,                   \
      .def_file = ZCL_DEF_FILE, .budget_bytes = (budget_),                     \
      .layer = ZCL_COMMAND_LAYER_DEV, .effect = ZCL_COMMAND_EFFECT_READ,       \
      .risk = ZCL_COMMAND_RISK_READ, .scope = (scope_),                        \
      .authority = (authority_), .availability = ZCL_COMMAND_COMPAT,           \
      .mode = ZCL_COMMAND_MODE_SYNC, .latency = (latency_), .cost = (cost_),   \
      .confirmation = ZCL_COMMAND_CONFIRM_NONE, .lanes = (lanes_),             \
      .caps = (caps_), .traits = (traits_),                                    \
      .transports = ZCL_COMMAND_TRANSPORT_NATIVE, .dev_gated = true,           \
      .is_branch = false },

#define ZCL_COMMAND_DEV_COMMAND(path_, parent_, aliases_, summary_,            \
                                semantics_, budget_, tags_,                    \
                                in_, out_, in_keys_, pos_keys_, example_,      \
                                effect_, risk_, scope_, authority_, mode_,     \
                                latency_, cost_, confirmation_, lanes_, caps_, \
                                traits_, handler_, release_reason_, compat_)   \
    { .path = (path_), .parent = (parent_), .aliases = (aliases_),             \
      .summary = (summary_), .semantics = (semantics_), .tags = (tags_),       \
      .input_schema = (in_), .output_schema = (out_),                          \
      .input_keys = (in_keys_), .positional_keys = (pos_keys_),                \
      .example = (example_), .availability_reason = (release_reason_),         \
      .compat_target = (compat_), .handler_name = #handler_,                   \
      .def_file = ZCL_DEF_FILE, .budget_bytes = (budget_),                     \
      .layer = ZCL_COMMAND_LAYER_DEV, .effect = (effect_), .risk = (risk_),    \
      .scope = (scope_), .authority = (authority_),                            \
      .availability = ZCL_COMMAND_COMPAT, .mode = (mode_),                     \
      .latency = (latency_), .cost = (cost_), .confirmation = (confirmation_), \
      .lanes = (lanes_), .caps = (caps_), .traits = (traits_),                 \
      .transports = ZCL_COMMAND_TRANSPORT_NATIVE, .dev_gated = true,           \
      .is_branch = false },

static const struct row g_rows[] = {
#define ZCL_DEF_FILE "config/commands/root.def"
#include "../config/commands/root.def"
#undef ZCL_DEF_FILE
#define ZCL_DEF_FILE "config/commands/core.def"
#include "../config/commands/core.def"
#undef ZCL_DEF_FILE
#define ZCL_DEF_FILE "config/commands/apps.def"
#include "../config/commands/apps.def"
#undef ZCL_DEF_FILE
#define ZCL_DEF_FILE "config/commands/app_features.def"
#include "../config/commands/app_features.def"
#undef ZCL_DEF_FILE
#define ZCL_DEF_FILE "config/commands/store.def"
#include "../config/commands/store.def"
#undef ZCL_DEF_FILE
#define ZCL_DEF_FILE "config/commands/ops.def"
#include "../config/commands/ops.def"
#undef ZCL_DEF_FILE
#define ZCL_DEF_FILE "config/commands/dev.def"
#include "../config/commands/dev.def"
#undef ZCL_DEF_FILE
#define ZCL_DEF_FILE "config/commands/code.def"
#include "../config/commands/code.def"
#undef ZCL_DEF_FILE
#define ZCL_DEF_FILE "config/commands/accounts.def"
#include "../config/commands/accounts.def"
#undef ZCL_DEF_FILE
#define ZCL_DEF_FILE "config/commands/vault.def"
#include "../config/commands/vault.def"
#undef ZCL_DEF_FILE
#define ZCL_DEF_FILE "config/commands/zcode.def"
#include "../config/commands/zcode.def"
#undef ZCL_DEF_FILE
#define ZCL_DEF_FILE "config/commands/zcode_science.def"
#include "../config/commands/zcode_science.def"
#undef ZCL_DEF_FILE
#define ZCL_DEF_FILE "config/commands/metaverse.def"
#include "../config/commands/metaverse.def"
#undef ZCL_DEF_FILE
#define ZCL_DEF_FILE "config/commands/yardsale.def"
#include "../config/commands/yardsale.def"
#undef ZCL_DEF_FILE
#define ZCL_DEF_FILE "config/commands/zses.def"
#include "../config/commands/zses.def"
#undef ZCL_DEF_FILE
#define ZCL_DEF_FILE "config/commands/telemetry/root.def"
#include "../config/commands/telemetry/root.def"
#undef ZCL_DEF_FILE

#define ZCL_DEF_FILE "config/commands/telemetry/watch.def"
#include "../config/commands/telemetry/watch.def"
#undef ZCL_DEF_FILE
#define ZCL_DEF_FILE "config/commands/telemetry/runtime.def"
#include "../config/commands/telemetry/runtime.def"
#undef ZCL_DEF_FILE
#define ZCL_DEF_FILE "config/commands/telemetry/sync.def"
#include "../config/commands/telemetry/sync.def"
#undef ZCL_DEF_FILE
#define ZCL_DEF_FILE "config/commands/telemetry/network.def"
#include "../config/commands/telemetry/network.def"
#undef ZCL_DEF_FILE
#define ZCL_DEF_FILE "config/commands/telemetry/storage.def"
#include "../config/commands/telemetry/storage.def"
#undef ZCL_DEF_FILE
#define ZCL_DEF_FILE "config/commands/telemetry/wallet.def"
#include "../config/commands/telemetry/wallet.def"
#undef ZCL_DEF_FILE
#define ZCL_DEF_FILE "config/commands/telemetry/agents.def"
#include "../config/commands/telemetry/agents.def"
#undef ZCL_DEF_FILE
#define ZCL_DEF_FILE "config/commands/telemetry/zcode.def"
#include "../config/commands/telemetry/zcode.def"
#undef ZCL_DEF_FILE
#define ZCL_DEF_FILE "config/commands/telemetry/metaverse.def"
#include "../config/commands/telemetry/metaverse.def"
#undef ZCL_DEF_FILE
};

#define ROW_COUNT (sizeof(g_rows) / sizeof(g_rows[0]))

/* ── enum rendering ─────────────────────────────────────────────────────── */

static const char *effect_name(int v)
{
    switch (v) {
    case ZCL_COMMAND_EFFECT_READ: return "read";
    case ZCL_COMMAND_EFFECT_MUTATE: return "mutate";
    case ZCL_COMMAND_EFFECT_DESTRUCTIVE: return "destructive";
    default: return "unknown";
    }
}

static const char *risk_name(int v)
{
    switch (v) {
    case ZCL_COMMAND_RISK_READ: return "read";
    case ZCL_COMMAND_RISK_APP_WRITE: return "app-write";
    case ZCL_COMMAND_RISK_WALLET: return "wallet";
    case ZCL_COMMAND_RISK_CORE_RECOVERY: return "core-recovery";
    case ZCL_COMMAND_RISK_DESTRUCTIVE: return "destructive";
    case ZCL_COMMAND_RISK_DEV_MUTATION: return "dev-mutation";
    default: return "unknown";
    }
}

static const char *authority_name(int v)
{
    switch (v) {
    case ZCL_COMMAND_AUTH_PUBLIC: return "public";
    case ZCL_COMMAND_AUTH_OPERATOR: return "operator";
    case ZCL_COMMAND_AUTH_OWNER: return "owner";
    default: return "unknown";
    }
}

static const char *availability_name(int v)
{
    switch (v) {
    case ZCL_COMMAND_READY: return "ready";
    case ZCL_COMMAND_COMPAT: return "compat";
    case ZCL_COMMAND_PLANNED: return "planned";
    default: return "unknown";
    }
}

static const char *mode_name(int v)
{
    switch (v) {
    case ZCL_COMMAND_MODE_BRANCH: return "branch";
    case ZCL_COMMAND_MODE_SYNC: return "sync";
    case ZCL_COMMAND_MODE_JOB: return "job";
    case ZCL_COMMAND_MODE_STREAM: return "stream";
    default: return "unknown";
    }
}

static const char *latency_name(int v)
{
    switch (v) {
    case ZCL_COMMAND_LATENCY_INSTANT: return "instant";
    case ZCL_COMMAND_LATENCY_FAST: return "fast";
    case ZCL_COMMAND_LATENCY_FOREGROUND: return "foreground";
    case ZCL_COMMAND_LATENCY_BACKGROUND: return "background";
    case ZCL_COMMAND_LATENCY_PERSISTENT: return "persistent";
    default: return "unknown";
    }
}

static const char *cost_name(int v)
{
    switch (v) {
    case ZCL_COMMAND_COST_TINY: return "tiny";
    case ZCL_COMMAND_COST_LOW: return "low";
    case ZCL_COMMAND_COST_MODERATE: return "moderate";
    case ZCL_COMMAND_COST_HIGH: return "high";
    case ZCL_COMMAND_COST_STREAM: return "stream";
    default: return "unknown";
    }
}

static const char *confirmation_name(int v)
{
    switch (v) {
    case ZCL_COMMAND_CONFIRM_NONE: return "none";
    case ZCL_COMMAND_CONFIRM_IDEMPOTENCY: return "idempotency";
    case ZCL_COMMAND_CONFIRM_PLAN_COMMIT: return "plan-commit";
    default: return "unknown";
    }
}

/* ── Markdown emitters ──────────────────────────────────────────────────── */

/* A table cell must never contain a raw `|` (it would split the row) or a
 * newline. Escape both, and collapse the runs of whitespace that adjacent
 * string-literal concatenation leaves behind. */
static void emit_cell_text(FILE *f, const char *s)
{
    bool pending_space = false;
    bool wrote = false;
    for (const char *p = s; *p != '\0'; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            if (wrote) {
                pending_space = true;
            }
            continue;
        }
        if (pending_space) {
            fputc(' ', f);
            pending_space = false;
        }
        if (c == '|') {
            fputs("\\|", f);
        } else {
            fputc((int)c, f);
        }
        wrote = true;
    }
}

static void emit_code(FILE *f, const char *s)
{
    if (s == NULL || s[0] == '\0') {
        fputs("—", f);
        return;
    }
    fputc('`', f);
    emit_cell_text(f, s);
    fputc('`', f);
}

/* `core.chain.block.get` -> `core chain block get` */
static void emit_cli(FILE *f, const char *path)
{
    fputc('`', f);
    for (const char *p = path; *p != '\0'; p++) {
        fputc(*p == '.' ? ' ' : *p, f);
    }
    fputc('`', f);
}

static bool list_has(const char *list, const char *item, size_t len)
{
    const char *p = list;
    while (*p != '\0') {
        const char *comma = strchr(p, ',');
        size_t seg = comma != NULL ? (size_t)(comma - p) : strlen(p);
        if (seg == len && strncmp(p, item, len) == 0) {
            return true;
        }
        if (comma == NULL) {
            break;
        }
        p = comma + 1;
    }
    return false;
}

static void emit_key(FILE *f, const char *key, size_t len, bool required,
                     bool *first)
{
    if (len == 0) {
        return;
    }
    if (!*first) {
        fputs(", ", f);
    }
    *first = false;
    if (required) {
        fputs("**", f);
    }
    fputc('`', f);
    fwrite(key, 1, len, f);
    fputc('`', f);
    if (required) {
        fputs("**", f);
    }
}

/* Allowed input keys, bold where the key is positional (handler-required). */
static void emit_input_keys(FILE *f, const struct row *r)
{
    bool first = true;
    const char *p = r->input_keys;
    while (*p != '\0') {
        const char *comma = strchr(p, ',');
        size_t seg = comma != NULL ? (size_t)(comma - p) : strlen(p);
        emit_key(f, p, seg, list_has(r->positional_keys, p, seg), &first);
        if (comma == NULL) {
            break;
        }
        p = comma + 1;
    }
    /* A positional key that is not also listed as allowed would otherwise be
     * invisible; render it rather than silently drop it. */
    p = r->positional_keys;
    while (*p != '\0') {
        const char *comma = strchr(p, ',');
        size_t seg = comma != NULL ? (size_t)(comma - p) : strlen(p);
        if (!list_has(r->input_keys, p, seg)) {
            emit_key(f, p, seg, true, &first);
        }
        if (comma == NULL) {
            break;
        }
        p = comma + 1;
    }
    if (first) {
        fputs("none", f);
    }
}

static void emit_aliases(FILE *f, const char *aliases)
{
    bool first = true;
    const char *p = aliases;
    while (*p != '\0') {
        const char *comma = strchr(p, ',');
        size_t seg = comma != NULL ? (size_t)(comma - p) : strlen(p);
        if (seg > 0) {
            if (first) {
                fputs(" (aliases: ", f);
            } else {
                fputs(", ", f);
            }
            first = false;
            fputc('`', f);
            fwrite(p, 1, seg, f);
            fputc('`', f);
        }
        if (comma == NULL) {
            break;
        }
        p = comma + 1;
    }
    if (!first) {
        fputc(')', f);
    }
}

static void emit_availability(FILE *f, const struct row *r)
{
    fputs(availability_name(r->availability), f);
    if (r->dev_gated) {
        fputs(" 🔧", f);
    }
    if (r->compat_target[0] != '\0') {
        fputs(" → ", f);
        emit_code(f, r->compat_target);
    }
}

static void emit_policy(FILE *f, const struct row *r)
{
    fputs(effect_name(r->effect), f);
    fputs(" / ", f);
    fputs(risk_name(r->risk), f);
    fputs(" / ", f);
    if (r->authority == ZCL_COMMAND_AUTH_OWNER) {
        fputs("**owner**", f);
    } else {
        fputs(authority_name(r->authority), f);
    }
    if (r->mode != ZCL_COMMAND_MODE_SYNC) {
        fputs(", ", f);
        fputs(mode_name(r->mode), f);
    }
    if (r->confirmation != ZCL_COMMAND_CONFIRM_NONE) {
        fputs(", ", f);
        fputs(confirmation_name(r->confirmation), f);
    }
    if ((r->traits & ZCL_COMMAND_TRAIT_DISPLAY_ONLY) != 0)
        fputs(", display-only", f);
    fputs(" · ", f);
    fputs(latency_name(r->latency), f);
    fputc('/', f);
    fputs(cost_name(r->cost), f);
}

static void emit_summary(FILE *f, const struct row *r)
{
    emit_cell_text(f, r->summary);
    if (r->availability != ZCL_COMMAND_READY &&
        r->availability_reason[0] != '\0') {
        fputs(" — *", f);
        emit_cell_text(f, r->availability_reason);
        fputc('*', f);
    }
}

/* ── tree helpers ───────────────────────────────────────────────────────── */

static bool is_descendant(const char *path, const char *root)
{
    size_t n = strlen(root);
    return strncmp(path, root, n) == 0 && path[n] == '.';
}

static size_t direct_leaf_count(const char *parent)
{
    size_t n = 0;
    for (size_t i = 0; i < ROW_COUNT; i++) {
        if (!g_rows[i].is_branch && strcmp(g_rows[i].parent, parent) == 0) {
            n++;
        }
    }
    return n;
}

static const char LEAF_HEADER[] =
    "| Command | Avail | Policy | Input keys "
    "(**required**) | Output schema | Example | Summary |\n"
    "|---|---|---|---|---|---|---|\n";

static void emit_leaf_row(FILE *f, const struct row *r)
{
    fputs("| ", f);
    emit_cli(f, r->path);
    emit_aliases(f, r->aliases);
    fputs(" | ", f);
    emit_availability(f, r);
    fputs(" | ", f);
    emit_policy(f, r);
    fputs(" | ", f);
    emit_input_keys(f, r);
    fputs(" | ", f);
    emit_code(f, r->output_schema);
    fputs(" | ", f);
    emit_code(f, r->example);
    fputs(" | ", f);
    emit_summary(f, r);
    fputs(" |\n", f);
}

static void emit_leaf_table(FILE *f, const char *parent)
{
    if (direct_leaf_count(parent) == 0) {
        return;
    }
    fputs(LEAF_HEADER, f);
    for (size_t i = 0; i < ROW_COUNT; i++) {
        if (!g_rows[i].is_branch && strcmp(g_rows[i].parent, parent) == 0) {
            emit_leaf_row(f, &g_rows[i]);
        }
    }
    fputc('\n', f);
}

/* ── generated blocks ───────────────────────────────────────────────────── */

static void block_counts(FILE *f)
{
    size_t branches = 0, leaves = 0, roots = 0;
    size_t ready = 0, compat = 0, planned = 0, dev_gated = 0;
    size_t mutating = 0, destructive = 0, owner = 0;

    for (size_t i = 0; i < ROW_COUNT; i++) {
        const struct row *r = &g_rows[i];
        if (r->parent[0] == '\0') {
            roots++;
        }
        if (r->is_branch) {
            branches++;
            continue;
        }
        leaves++;
        if (r->dev_gated) {
            dev_gated++;
        }
        switch (r->availability) {
        case ZCL_COMMAND_READY: ready++; break;
        case ZCL_COMMAND_COMPAT: compat++; break;
        default: planned++; break;
        }
        if (r->effect == ZCL_COMMAND_EFFECT_MUTATE) {
            mutating++;
        }
        if (r->effect == ZCL_COMMAND_EFFECT_DESTRUCTIVE) {
            destructive++;
        }
        if (r->authority == ZCL_COMMAND_AUTH_OWNER) {
            owner++;
        }
    }

    fprintf(f, "| Catalog fact | Count |\n|---|---|\n");
    fprintf(f, "| Registry entries (branches + leaves) | %zu |\n", ROW_COUNT);
    fprintf(f, "| Top-level roots | %zu |\n", roots);
    fprintf(f, "| Branches | %zu |\n", branches);
    fprintf(f, "| Leaves (dispatchable command paths) | %zu |\n", leaves);
    fprintf(f, "| … `ready` (live handler in this build) | %zu |\n", ready);
    fprintf(f, "| … `compat` (metadata only, names a fallback) | %zu |\n",
            compat);
    fprintf(f, "| … `planned` (fail-closed BLOCKED, exit 3) | %zu |\n",
            planned);
    fprintf(f, "| … dev-gated 🔧 (`ready` only in `z23-dev`) | %zu |\n",
            dev_gated);
    fprintf(f, "| Leaves with `effect=mutate` | %zu |\n", mutating);
    fprintf(f, "| Leaves with `effect=destructive` | %zu |\n", destructive);
    fprintf(f, "| Leaves requiring **owner** authority | %zu |\n", owner);
    fputc('\n', f);

    fputs("Per source file:\n\n", f);
    fputs("| `.def` file | Entries | Branches | Leaves |\n|---|---|---|---|\n",
          f);
    for (size_t i = 0; i < ROW_COUNT; i++) {
        bool seen = false;
        for (size_t j = 0; j < i; j++) {
            if (strcmp(g_rows[j].def_file, g_rows[i].def_file) == 0) {
                seen = true;
                break;
            }
        }
        if (seen) {
            continue;
        }
        size_t n = 0, b = 0, l = 0;
        for (size_t j = 0; j < ROW_COUNT; j++) {
            if (strcmp(g_rows[j].def_file, g_rows[i].def_file) != 0) {
                continue;
            }
            n++;
            if (g_rows[j].is_branch) {
                b++;
            } else {
                l++;
            }
        }
        fprintf(f, "| `%s` | %zu | %zu | %zu |\n", g_rows[i].def_file, n, b, l);
    }
    fputc('\n', f);
}

static void block_roots(FILE *f)
{
    fputs("| Root | CLI | Kind | Avail | Summary |\n|---|---|---|---|---|\n", f);
    for (size_t i = 0; i < ROW_COUNT; i++) {
        const struct row *r = &g_rows[i];
        if (r->parent[0] != '\0') {
            continue;
        }
        fputs("| ", f);
        emit_code(f, r->path);
        fputs(" | ", f);
        emit_cli(f, r->path);
        fputs(" | ", f);
        fputs(r->is_branch ? "branch" : "leaf", f);
        fputs(" | ", f);
        emit_availability(f, r);
        fputs(" | ", f);
        emit_summary(f, r);
        fputs(" |\n", f);
    }
    fputc('\n', f);
}

static void block_tree(FILE *f)
{
    for (size_t i = 0; i < ROW_COUNT; i++) {
        const struct row *root = &g_rows[i];
        if (root->parent[0] != '\0') {
            continue;
        }
        fputs("### ", f);
        emit_code(f, root->path);
        fputs(" — ", f);
        emit_cell_text(f, root->summary);
        fputs("\n\n", f);

        if (!root->is_branch) {
            fputs(LEAF_HEADER, f);
            emit_leaf_row(f, root);
            fputc('\n', f);
            continue;
        }

        emit_leaf_table(f, root->path);

        for (size_t j = 0; j < ROW_COUNT; j++) {
            const struct row *b = &g_rows[j];
            if (!b->is_branch || !is_descendant(b->path, root->path)) {
                continue;
            }
            if (direct_leaf_count(b->path) == 0) {
                continue;
            }
            fputs("#### ", f);
            emit_code(f, b->path);
            fputs(" — ", f);
            emit_cell_text(f, b->summary);
            fputs("\n\n", f);
            emit_leaf_table(f, b->path);
        }
    }
}

static void block_aliases(FILE *f)
{
    size_t emitted = 0;
    fputs("| Alias | Resolves to |\n|---|---|\n", f);
    for (size_t i = 0; i < ROW_COUNT; i++) {
        const struct row *r = &g_rows[i];
        const char *p = r->aliases;
        while (*p != '\0') {
            const char *comma = strchr(p, ',');
            size_t seg = comma != NULL ? (size_t)(comma - p) : strlen(p);
            if (seg > 0) {
                fputs("| `", f);
                fwrite(p, 1, seg, f);
                fputs("` | ", f);
                emit_code(f, r->path);
                fputs(" |\n", f);
                emitted++;
            }
            if (comma == NULL) {
                break;
            }
            p = comma + 1;
        }
    }
    if (emitted == 0) {
        fputs("| — | — |\n", f);
    }
    fputc('\n', f);
}

static void block_schemas(FILE *f)
{
    fputs("| Output schema | Leaves |\n|---|---|\n", f);
    for (size_t i = 0; i < ROW_COUNT; i++) {
        if (g_rows[i].is_branch || g_rows[i].output_schema[0] == '\0') {
            continue;
        }
        bool seen = false;
        for (size_t j = 0; j < i; j++) {
            if (!g_rows[j].is_branch &&
                strcmp(g_rows[j].output_schema, g_rows[i].output_schema) == 0) {
                seen = true;
                break;
            }
        }
        if (seen) {
            continue;
        }
        size_t n = 0;
        for (size_t j = 0; j < ROW_COUNT; j++) {
            if (!g_rows[j].is_branch &&
                strcmp(g_rows[j].output_schema, g_rows[i].output_schema) == 0) {
                n++;
            }
        }
        if (n < 2) {
            continue; /* only the shared schemas are interesting here */
        }
        fputs("| ", f);
        emit_code(f, g_rows[i].output_schema);
        fputs(" | ", f);
        bool first = true;
        for (size_t j = 0; j < ROW_COUNT; j++) {
            if (g_rows[j].is_branch ||
                strcmp(g_rows[j].output_schema, g_rows[i].output_schema) != 0) {
                continue;
            }
            if (!first) {
                fputs(", ", f);
            }
            first = false;
            emit_code(f, g_rows[j].path);
        }
        fputs(" |\n", f);
    }
    fputc('\n', f);
}

/* ── template expansion ─────────────────────────────────────────────────── */

struct block {
    const char *name;
    void (*emit)(FILE *);
};

static const struct block g_blocks[] = {
    { "counts", block_counts },   { "roots", block_roots },
    { "tree", block_tree },       { "aliases", block_aliases },
    { "schemas", block_schemas },
};

static const char MARKER_OPEN[] = "<!-- ZCL-GEN:";
static const char MARKER_CLOSE[] = "-->";

/* Returns the marker name in `out` (NUL-terminated) when `line` is a lone
 * generation marker, else false. */
static bool marker_name(const char *line, char *out, size_t out_len)
{
    const char *p = line;
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    size_t open_len = sizeof(MARKER_OPEN) - 1;
    if (strncmp(p, MARKER_OPEN, open_len) != 0) {
        return false;
    }
    p += open_len;
    const char *end = strstr(p, MARKER_CLOSE);
    if (end == NULL) {
        return false;
    }
    const char *name_end = end;
    while (name_end > p && (name_end[-1] == ' ' || name_end[-1] == '\t')) {
        name_end--;
    }
    size_t len = (size_t)(name_end - p);
    if (len == 0 || len + 1 > out_len) {
        return false;
    }
    memcpy(out, p, len);
    out[len] = '\0';
    return true;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr,
                "usage: %s <template.md.in> <out.md>\n"
                "  Generates the native command reference from "
                "config/commands/*.def\n",
                argv[0]);
        return 2;
    }

    FILE *tpl = fopen(argv[1], "r");
    if (tpl == NULL) {
        fprintf(stderr, "gen_api_reference: cannot open template '%s'\n",
                argv[1]);
        return 1;
    }
    FILE *out = fopen(argv[2], "w");
    if (out == NULL) {
        fprintf(stderr, "gen_api_reference: cannot write '%s'\n", argv[2]);
        fclose(tpl);
        return 1;
    }

    fputs("<!-- GENERATED FILE — DO NOT EDIT BY HAND.\n"
          "     Source of truth: config/commands/*.def\n"
          "     Template (editorial prose): docs/API_REFERENCE.md.in\n"
          "     Generator: tools/gen_api_reference.c\n"
          "     Regenerate: make docs-api-reference\n"
          "     Gate: tools/lint/check_api_reference_generated.sh "
          "(check-api-reference-generated) -->\n",
          out);

    char line[8192];
    char name[128];
    size_t expanded = 0;
    int rc = 0;
    while (fgets(line, (int)sizeof(line), tpl) != NULL) {
        if (!marker_name(line, name, sizeof(name))) {
            fputs(line, out);
            continue;
        }
        const struct block *hit = NULL;
        for (size_t i = 0; i < sizeof(g_blocks) / sizeof(g_blocks[0]); i++) {
            if (strcmp(g_blocks[i].name, name) == 0) {
                hit = &g_blocks[i];
                break;
            }
        }
        if (hit == NULL) {
            fprintf(stderr,
                    "gen_api_reference: unknown generation marker '%s' in %s\n",
                    name, argv[1]);
            rc = 1;
            break;
        }
        hit->emit(out);
        expanded++;
    }

    fclose(tpl);
    if (fclose(out) != 0) {
        fprintf(stderr, "gen_api_reference: write failed for '%s'\n", argv[2]);
        rc = 1;
    }
    if (rc != 0) {
        return rc;
    }
    if (expanded != sizeof(g_blocks) / sizeof(g_blocks[0])) {
        fprintf(stderr,
                "gen_api_reference: template expanded %zu of %zu generated "
                "blocks — a marker is missing from %s\n",
                expanded, sizeof(g_blocks) / sizeof(g_blocks[0]), argv[1]);
        return 1;
    }
    fprintf(stderr, "gen_api_reference: %zu catalog entries -> %s\n",
            (size_t)ROW_COUNT, argv[2]);
    return 0;
}
