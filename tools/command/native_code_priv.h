/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Private interface shared by the `code` command family's sibling
 * translation units (native_code_command.c, native_code_capsule.c,
 * native_code_render.c, native_code_structure.c). Nothing here is part of
 * the public command surface — every symbol declared below is defined in
 * exactly one of those four files and consumed by at least one other. Do
 * not include this header outside that family.
 */

#ifndef ZCL_TOOLS_COMMAND_NATIVE_CODE_PRIV_H
#define ZCL_TOOLS_COMMAND_NATIVE_CODE_PRIV_H

#include "command/native_command.h"

#include "codeindex/codeindex.h"
#include "controllers/agent_impact_rules.h"
#include "territory/territory.h"

#include <stddef.h>

/* Conservative per-list caps. The whole reply envelope must fit in
 * ZCL_COMMAND_RESULT_BUDGET (4096 bytes), so lists stay small and each rendered
 * string is truncated. Overflow beyond a cap is reported, never silently cut. */
enum {
    CODE_SUBGROUP_CAP = 40,
    CODE_FILE_CAP     = 16,
    CODE_SYM_CAP      = 20,
    CODE_INC_CAP      = 16,
    CODE_REFS_DEFAULT = 5,
    CODE_REFS_MAX     = 20,
    CODE_FIND_DEFAULT = 5,
    CODE_FIND_MAX     = 12,
    CODE_OTHER_DEF_CAP = 5,
    CODE_TESTS_CAP     = 12,   /* max test_groups emitted by code.tests/code.file */
    CODE_MAP_ROOT_CAP  = 16,   /* max root groups rendered by code.map */
    CODE_MAP_SHAPE_CAP = 16,   /* max app/ shapes rendered by code.map */
    CODE_COMMAND_CAP    = 12,  /* max command paths per file (code.room/code.capsule) */
    CODE_CAPSULE_CALLER_CAP = 10,
    CODE_CAPSULE_CALLEE_CAP = 10,
    CODE_CAPSULE_INC_CAP    = 10,
    CODE_IMPACT_CAP     = 120, /* max impacted_files rendered by code.impact
                                * (list budget; the engine's own cap+truncated
                                * contract, not a second layer of paging) */
    CODE_IMPACT_INC_CAP = 32,  /* direct_includes fan-out cap */
    /* include_dependents is a DISPLAY cap over a larger true answer, which is
     * the opposite of CODE_IMPACT_CAP above and is why the two are separate
     * constants. The reverse-include query still runs at CODE_IMPACT_CAP, so
     * `include_dependent_count` and `include_dimension` describe the whole
     * answer; only the rendered array is abridged, because a hub header has
     * hundreds of readers and this leaf's declared reply budget is 8 KB. A
     * consumer that needs the full set asks the store, not the summary. */
    CODE_IMPACT_INCDEP_LIST_CAP = 20,
    CODE_IMPACT_SYM_CAP = 64,  /* symbols-in-file cap when summing direct_callers */
    CODE_IMPACT_REF_CAP = 256, /* per-symbol callers cap when summing direct_callers */
    CODE_MERKLE_CHILD_CAP = 40, /* direct subtree roots rendered by code.merkle
                                 * (list budget); `children_total` always
                                 * reports the true count */
    CODE_METRICS_GROUP_CAP = 40,
};

/* Territory scorecard caps, shared by code.territory (native_code_structure.c,
 * which owns the enum's canonical definition) and `general` (native_code_render.c,
 * which renders the same scorecard shape for its brief). */
enum {
    CODE_TERRITORY_LIST_CAP    = 96, /* territories rendered by the no-arg form */
    CODE_TERRITORY_GROUP_CAP   = 6,
    CODE_TERRITORY_DEP_CAP     = 6,
    CODE_TERRITORY_WEAK_CAP    = 10,
    CODE_TERRITORY_UNKNOWN_CAP = 4,
    CODE_TERRITORY_FILE_CAP    = 4,
};

/* ── shared helpers (defined in native_code_command.c) ────────────────────── */

/* Bounded copy of at most `max` visible chars of `src` into dst[cap]; appends
 * "…"-as-"..." when truncated. Always NUL-terminates. */
void code_trunc(char *dst, size_t cap, const char *src, size_t max);

/* The checkout root the index scans: an explicit context source_root wins, then
 * ZCL_DEV_SOURCE_ROOT, else the current directory. */
const char *code_source_root(const struct zcl_command_request *request);

/* Open the index or fail the reply with a bounded internal error. */
struct codeindex *code_open(const struct zcl_command_request *request,
                            struct zcl_command_reply *reply);

/* code.group and code.map consume only source-derived file/group rows.
 * Compiler depfile epochs affect include edges, not these answers, so do not
 * put their post-build writeback on either command's warm latency path. */
struct codeindex *code_open_source_view(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);

/* Positional/typed string input for `key` (NULL when absent/empty). */
const char *code_str(const struct zcl_command_request *request,
                     const char *key);

/* Push one string onto a JSON array. */
void code_push_line(struct json_value *arr, const char *s);

/* Push a completed object onto an array (copies, then frees the local). */
void code_push_obj(struct json_value *arr, struct json_value *obj);

/* MIRROR of tools/dev/devloop_plan.c's consensus-risk detection: the whole
 * sealed core/ tree plus the non-core consensus/validation prefixes. Kept in
 * lockstep by the route-parity invariant in test_codeindex.c. */
bool code_path_is_consensus_risk(const char *path);

/* Emit the routing block for a changed source `path` into reply->data:
 * test_groups[] (the matched shared-rule groups, capped), the routed group,
 * whether it is a consensus surface, and whether any rule matched. Shared by
 * code.tests, code.file, code.room, code.capsule and code.impact. Returns
 * the routed group and, via `consensus_risk`, whether it is a consensus
 * surface — so the caller can render a summary without recomputing. */
const char *code_emit_route(
    struct zcl_command_reply *reply, const char *path, bool *consensus_risk,
    char route_storage[static ZCL_AGENT_IMPACT_GROUP_MAX]);

/* WF4 4C dispatch-index join (config/command_handler_index.h) against the
 * code index's own symbol table for one FILE: which commands does this file
 * back. Deterministic: dispatch-index declaration order (catalog order),
 * first match wins per entry. Returns the count. */
int code_commands_for_file(struct codeindex *ci, const char *def_path,
                           const char **out, int cap);

/* Exact function-pointer/.def join for one handler symbol. */
int code_commands_for_symbol(const char *symbol_name,
                             const char **out, int cap);

/* ── territory router port (defined in native_code_structure.c) ──────────── */

/* The territory_proof_source `at` callback: the SAME test-group catalog
 * code.territory and `general` both score against. */
const char *code_territory_entry_at(size_t index, void *user);

/* The territory_router `route` callback: the SAME shared-rule resolver
 * behind `code tests`, used by both code.territory and `general`. */
size_t code_territory_route(const char *path,
                            char (*out)[TERRITORY_GROUP_MAX],
                            size_t cap, void *user);

#endif /* ZCL_TOOLS_COMMAND_NATIVE_CODE_PRIV_H */
