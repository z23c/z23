/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Composition root for the native command registry (contract §12).
 *
 * This file expands the declarative X-macro files under config/commands into
 * one immutable metadata table and binds the native handler pointers for this
 * build. Metadata is transport-neutral; the handler column is the single
 * explicitly injected native binding per leaf.
 *
 * Read-only checkout inspection handlers are release-safe.  Process execution,
 * watcher ownership, and generation inspection bind only in ZCL_DEV_BUILD;
 * the same entries remain honest COMPAT metadata with NULL handlers in a
 * release catalog.  This keeps one grammar without linking dev mutation code
 * into the release binary.
 */

#include "config/command_catalog.h"
#include "config/command_handler_index.h"

#include "command/native_command.h"
#include "kernel/command_registry.h"

#include <stddef.h>

/* Each macro expands to one designated-initializer struct literal. Designated
 * initializers keep the expansion order-independent and let a leaf omit the
 * fields its shape never sets. */

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
      .transports = (transports_), .handler = (handler_) },

#define ZCL_COMMAND_COMPAT_READ(path_, parent_, aliases_, summary_, semantics_,\
                                budget_, tags_,                               \
                                in_, out_, in_keys_, pos_keys_, example_,      \
                                layer_, scope_, authority_, latency_, cost_,   \
                                lanes_, caps_, transports_, compat_)           \
    { .path = (path_), .parent = (parent_), .aliases = (aliases_),             \
      .summary = (summary_), .semantics = (semantics_), .tags = (tags_),       \
      .input_schema = (in_),                                                   \
      .output_schema = (out_), .input_keys = (in_keys_),                       \
      .positional_keys = (pos_keys_), .example = (example_),                   \
      .availability_reason =                                                   \
          "native adapter is not executable yet; use the compatibility "      \
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
                                    semantics_, budget_, tags_,               \
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

/* A mutating leaf whose canonical native adapter is not executable yet: it is
 * COMPAT (NULL handler, points at a compatibility target) but carries the full
 * effect/risk/mode policy of the mutation it will one day own. Used by dev.def
 * for `dev.change.apply` (the cycle still shells out to Make targets). */
#define ZCL_COMMAND_COMPAT_COMMAND(path_, parent_, aliases_, summary_,         \
                                   semantics_, budget_, tags_,                \
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

/* A READY mutating leaf: availability=READY with a non-NULL native handler —
 * the first executable mutating native leaves (account.add/role/suspend/...).
 * Mirrors ZCL_COMMAND_PLANNED_COMMAND's full effect/risk/mode policy grammar
 * but binds an executable handler instead of failing BLOCKED. */
#define ZCL_COMMAND_READY_COMMAND(path_, parent_, aliases_, summary_,          \
                                  semantics_, budget_, tags_,                 \
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
      .handler = (handler_) },

/* One declarative dev leaf, two build-specific bindings.  A dev binary owns
 * the executable handler; a release binary exposes only an honest COMPAT
 * description pointing at the dev binary. */
#ifdef ZCL_DEV_BUILD
#define ZCL_DEV_AVAILABILITY ZCL_COMMAND_READY
#define ZCL_DEV_REASON(reason_) ""
#define ZCL_DEV_COMPAT(target_) ""
#define ZCL_DEV_HANDLER(handler_) (handler_)
#else
#define ZCL_DEV_AVAILABILITY ZCL_COMMAND_COMPAT
#define ZCL_DEV_REASON(reason_) (reason_)
#define ZCL_DEV_COMPAT(target_) (target_)
#define ZCL_DEV_HANDLER(handler_) NULL
#endif

#define ZCL_COMMAND_DEV_READ(path_, parent_, aliases_, summary_, semantics_,  \
                             budget_, tags_,                                  \
                             in_, out_, in_keys_, pos_keys_, example_,        \
                             scope_, authority_, latency_, cost_, lanes_,     \
                             caps_, traits_, handler_, release_reason_,       \
                             compat_)                                         \
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
      .transports = ZCL_COMMAND_TRANSPORT_NATIVE,                              \
      .handler = ZCL_DEV_HANDLER(handler_) },

#define ZCL_COMMAND_DEV_COMMAND(path_, parent_, aliases_, summary_,           \
                                semantics_, budget_, tags_,                   \
                                in_, out_, in_keys_, pos_keys_, example_,     \
                                effect_, risk_, scope_, authority_, mode_,    \
                                latency_, cost_, confirmation_, lanes_, caps_,\
                                traits_, handler_, release_reason_, compat_)  \
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
      .transports = ZCL_COMMAND_TRANSPORT_NATIVE,                              \
      .handler = ZCL_DEV_HANDLER(handler_) },

static const struct zcl_command_spec g_catalog_commands[] = {
#include "../commands/root.def"
#include "../commands/core.def"
#include "../commands/apps.def"
#include "../commands/app_features.def"
#include "../commands/store.def"
#include "../commands/ops.def"
#include "../commands/dev.def"
#include "../commands/code.def"
#include "../commands/accounts.def"
#include "../commands/vault.def"
#include "../commands/zcode.def"
#include "../commands/zcode_science.def"
#include "../commands/metaverse.def"
#include "../commands/yardsale.def"
#include "../commands/zses.def"
#include "../commands/telemetry/root.def"
#include "../commands/telemetry/watch.def"
#include "../commands/telemetry/runtime.def"
#include "../commands/telemetry/sync.def"
#include "../commands/telemetry/network.def"
#include "../commands/telemetry/storage.def"
#include "../commands/telemetry/wallet.def"
#include "../commands/telemetry/agents.def"
#include "../commands/telemetry/zcode.def"
#include "../commands/telemetry/metaverse.def"
};

#undef ZCL_COMMAND_BRANCH
#undef ZCL_COMMAND_READY_READ
#undef ZCL_COMMAND_COMPAT_READ
#undef ZCL_COMMAND_PLANNED_READ
#undef ZCL_COMMAND_PLANNED_COMMAND
#undef ZCL_COMMAND_READY_COMMAND
#undef ZCL_COMMAND_COMPAT_COMMAND
#undef ZCL_COMMAND_DEV_READ
#undef ZCL_COMMAND_DEV_COMMAND
#undef ZCL_DEV_AVAILABILITY
#undef ZCL_DEV_REASON
#undef ZCL_DEV_COMPAT
#undef ZCL_DEV_HANDLER

static const struct zcl_command_registry g_catalog_registry = {
    .commands = g_catalog_commands,
    .count = sizeof(g_catalog_commands) / sizeof(g_catalog_commands[0]),
};

/* OS-B2 size guard: the kernel's per-leaf latency-ring side-table
 * (g_latency_rings[ZCL_COMMAND_LATENCY_TABLE_MAX]) must be at least as large as
 * the compiled catalog, since it is keyed by catalog offset. `lib/kernel` may
 * not include config headers, so this check lives here, on the config side,
 * which already includes kernel/command_registry.h. */
_Static_assert(sizeof(g_catalog_commands) / sizeof(g_catalog_commands[0]) <=
                   ZCL_COMMAND_LATENCY_TABLE_MAX,
               "catalog leaf count exceeds the kernel latency-ring table — "
               "raise ZCL_COMMAND_LATENCY_TABLE_MAX in command_registry.h");

const struct zcl_command_registry *zcl_command_catalog(void)
{
    return &g_catalog_registry;
}

/* WF4 code-capsule dispatch join — see config/command_handler_index.h.
 *
 * A SECOND, parallel stringizing expansion of the exact same command .def
 * catalogs used to build g_catalog_commands above. Each macro here mirrors
 * the arity of its g_catalog_commands counterpart exactly (so the same .def
 * line compiles against either expansion) but emits only a
 * {path, handler_name} pair, and ONLY for leaves that actually bind a
 * non-NULL native handler — branch/compat/planned leaves never bind one and
 * expand to nothing here. This never touches the g_catalog_commands
 * expansion above; it is purely additive. */

#define ZCL_COMMAND_BRANCH(path_, parent_, summary_, layer_) /* no handler */

#define ZCL_COMMAND_READY_READ(path_, parent_, aliases_, summary_,           \
                               semantics_, budget_, tags_,                   \
                               in_, out_, in_keys_, pos_keys_, example_,      \
                               layer_, scope_, authority_, latency_, cost_,   \
                               lanes_, caps_, traits_, transports_, handler_) \
    { .path = (path_), .handler_name = #handler_ },

#define ZCL_COMMAND_COMPAT_READ(path_, parent_, aliases_, summary_,          \
                                semantics_, budget_, tags_,                  \
                                in_, out_, in_keys_, pos_keys_, example_,     \
                                layer_, scope_, authority_, latency_, cost_,  \
                                lanes_, caps_, transports_, compat_) /* NULL */

#define ZCL_COMMAND_PLANNED_READ(path_, parent_, aliases_, summary_,         \
                                 semantics_, budget_, tags_,                 \
                                 in_, out_, in_keys_, pos_keys_, example_,    \
                                 layer_, scope_, authority_, latency_, cost_, \
                                 lanes_, caps_, reason_) /* NULL handler */

#define ZCL_COMMAND_PLANNED_COMMAND(path_, parent_, aliases_, summary_,      \
                                    semantics_, budget_, tags_,              \
                                    in_, out_, in_keys_, pos_keys_, example_,\
                                    layer_, effect_, risk_, scope_,           \
                                    authority_, mode_, latency_, cost_,       \
                                    confirmation_, lanes_, caps_, traits_,    \
                                    reason_) /* NULL handler */

#define ZCL_COMMAND_COMPAT_COMMAND(path_, parent_, aliases_, summary_,       \
                                   semantics_, budget_, tags_,               \
                                   in_, out_, in_keys_, pos_keys_, example_,  \
                                   layer_, effect_, risk_, scope_,            \
                                   authority_, mode_, latency_, cost_,        \
                                   confirmation_, lanes_, caps_, traits_,     \
                                   reason_, compat_) /* NULL handler */

#define ZCL_COMMAND_READY_COMMAND(path_, parent_, aliases_, summary_,        \
                                  semantics_, budget_, tags_,                \
                                  in_, out_, in_keys_, pos_keys_, example_,   \
                                  layer_, effect_, risk_, scope_,             \
                                  authority_, mode_, latency_, cost_,         \
                                  confirmation_, lanes_, caps_, traits_,      \
                                  handler_)                                   \
    { .path = (path_), .handler_name = #handler_ },

/* Dev leaves bind a real handler only in a dev build (ZCL_DEV_HANDLER above
 * mirrors this same condition for g_catalog_commands); a release catalog
 * leaves the leaf on the COMPAT path with a NULL handler, so the index must
 * not claim one either. */
#ifdef ZCL_DEV_BUILD
#define ZCL_INDEX_DEV_ENTRY(path_, handler_) \
    { .path = (path_), .handler_name = #handler_ },
#else
#define ZCL_INDEX_DEV_ENTRY(path_, handler_) /* release: handler not bound */
#endif

#define ZCL_COMMAND_DEV_READ(path_, parent_, aliases_, summary_, semantics_, \
                             budget_, tags_,                                 \
                             in_, out_, in_keys_, pos_keys_, example_,       \
                             scope_, authority_, latency_, cost_, lanes_,    \
                             caps_, traits_, handler_, release_reason_,      \
                             compat_)                                        \
    ZCL_INDEX_DEV_ENTRY(path_, handler_)

#define ZCL_COMMAND_DEV_COMMAND(path_, parent_, aliases_, summary_,          \
                                semantics_, budget_, tags_,                  \
                                in_, out_, in_keys_, pos_keys_, example_,    \
                                effect_, risk_, scope_, authority_, mode_,    \
                                latency_, cost_, confirmation_, lanes_,       \
                                caps_, traits_, handler_, release_reason_,    \
                                compat_)                                      \
    ZCL_INDEX_DEV_ENTRY(path_, handler_)

static const struct zcl_command_handler_entry g_handler_index_entries[] = {
#include "../commands/root.def"
#include "../commands/core.def"
#include "../commands/apps.def"
#include "../commands/app_features.def"
#include "../commands/store.def"
#include "../commands/ops.def"
#include "../commands/dev.def"
#include "../commands/code.def"
#include "../commands/accounts.def"
#include "../commands/vault.def"
#include "../commands/zcode.def"
#include "../commands/zcode_science.def"
#include "../commands/metaverse.def"
#include "../commands/yardsale.def"
#include "../commands/zses.def"
#include "../commands/telemetry/root.def"
#include "../commands/telemetry/watch.def"
#include "../commands/telemetry/runtime.def"
#include "../commands/telemetry/sync.def"
#include "../commands/telemetry/network.def"
#include "../commands/telemetry/storage.def"
#include "../commands/telemetry/wallet.def"
#include "../commands/telemetry/agents.def"
#include "../commands/telemetry/zcode.def"
#include "../commands/telemetry/metaverse.def"
};

#undef ZCL_COMMAND_BRANCH
#undef ZCL_COMMAND_READY_READ
#undef ZCL_COMMAND_COMPAT_READ
#undef ZCL_COMMAND_PLANNED_READ
#undef ZCL_COMMAND_PLANNED_COMMAND
#undef ZCL_COMMAND_READY_COMMAND
#undef ZCL_COMMAND_COMPAT_COMMAND
#undef ZCL_COMMAND_DEV_READ
#undef ZCL_COMMAND_DEV_COMMAND
#undef ZCL_INDEX_DEV_ENTRY

static const struct zcl_command_handler_index g_handler_index = {
    .entries = g_handler_index_entries,
    .count = sizeof(g_handler_index_entries) /
             sizeof(g_handler_index_entries[0]),
};

/* Count guard mirroring the kernel latency-ring guard above (:278-281): the
 * handler index can never hold more entries than the catalog it indexes,
 * since every indexed leaf is itself one catalog row. */
_Static_assert(sizeof(g_handler_index_entries) /
                       sizeof(g_handler_index_entries[0]) <=
                   sizeof(g_catalog_commands) / sizeof(g_catalog_commands[0]),
               "handler index cannot exceed the catalog it indexes");

const struct zcl_command_handler_index *zcl_command_handler_index(void)
{
    return &g_handler_index;
}
