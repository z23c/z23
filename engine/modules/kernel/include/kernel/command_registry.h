/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Canonical command registry shared by native, REST, and RPC adapters. The
 * registry owns command identity and policy; transport
 * adapters only normalize input and render the bounded result.
 */

#ifndef ZCL_KERNEL_COMMAND_REGISTRY_H
#define ZCL_KERNEL_COMMAND_REGISTRY_H

#include "json/json.h"

#include <stdbool.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Raised 1200 -> 1536: the root menu lists every root as the same fixed
 * 5-field child summary the branch menus use, so it grows ~130 bytes per root.
 * The `vault` root (what this node owns, and the custody paths that may act on
 * it) took the eight roots to 1237 bytes — legitimate growth with an already
 * minimal summary, not bloat. 1536 clears that with ~300 bytes (two more roots)
 * of headroom, so adding a root is a deliberate act rather than a surprise
 * budget failure in an unrelated test.
 * Raised 1536 -> 1792: the `zcode` and `metaverse` roots consumed that
 * headroom, and the `yardsale` root (for-sale-by-owner signed ads) pushed
 * the eleven-root menu past 1536 — same fixed 5-field summary, legitimate
 * growth. 1792 left roughly one root of headroom.
 * Raised 1792 -> 2048: the thirteenth root is StoryGraph, the bounded causal
 * view over canonical ZCODE development evidence. The root document still
 * emits the same fixed child rows; 2048 preserves one bounded growth slot. */
#define ZCL_COMMAND_ROOT_BUDGET 2048U
/* Raised 1600 -> 2048: each branch menu lists its immediate children as a
 * fixed 5-field summary (path, summary, risk, latency, availability), so a
 * branch's size grows one summary per leaf. The `code` navigator branch reached
 * 9 leaves (group/map/tests/room/file/sym/capsule/refs/find) rendering to 1643
 * bytes — legitimate growth with already-minimal per-child summaries, not
 * bloat. 3072 leaves bounded headroom for the larger typed ZCODE development
 * catalog while keeping accidental branch-document growth fail-closed. */
#define ZCL_COMMAND_BRANCH_BUDGET 3072U
/* Raised from 2400 to absorb the per-leaf `semantics` contract and effective
 * `budget_bytes` the describe document now emits. */
#define ZCL_COMMAND_SPEC_BUDGET 2816U
#define ZCL_COMMAND_STATUS_BUDGET 2048U
#define ZCL_COMMAND_ERROR_BUDGET 3072U
#define ZCL_COMMAND_RESULT_BUDGET 4096U
#define ZCL_COMMAND_LIST_BUDGET 8192U
/* Complete, unpaged catalogs whose bounded row count legitimately exceeds the
 * ordinary list ceiling. Prefer ZCL_COMMAND_LIST_BUDGET for paged lists. */
#define ZCL_COMMAND_EXTENDED_LIST_BUDGET 16384U
#define ZCL_COMMAND_SEARCH_LIMIT 5U
#define ZCL_COMMAND_MAX_NEXT 3U
#define ZCL_COMMAND_MAX_PATH 128U
/* FLOOR on the bytes a single `--input` document may occupy, not the ceiling.
 * The real per-leaf ceiling is zcl_command_registry_input_budget_bytes(),
 * which sums the declared keys' own value bounds; this constant only keeps a
 * leaf whose keys are all small from being handed a frame so tight that a
 * previously-accepted document would start being refused. Never compare an
 * input length against this directly — ask the budget function. */
#define ZCL_COMMAND_MAX_INPUT 16384U

enum zcl_command_layer {
    ZCL_COMMAND_LAYER_ROOT = 0,
    ZCL_COMMAND_LAYER_CORE,
    ZCL_COMMAND_LAYER_APP,
    ZCL_COMMAND_LAYER_DEV,
    ZCL_COMMAND_LAYER_OPS,
    ZCL_COMMAND_LAYER_DISCOVER,
    ZCL_COMMAND_LAYER_CODE,
};

enum zcl_command_effect {
    ZCL_COMMAND_EFFECT_READ = 0,
    ZCL_COMMAND_EFFECT_MUTATE,
    ZCL_COMMAND_EFFECT_DESTRUCTIVE,
};

enum zcl_command_risk {
    ZCL_COMMAND_RISK_READ = 0,
    ZCL_COMMAND_RISK_APP_WRITE,
    ZCL_COMMAND_RISK_WALLET,
    ZCL_COMMAND_RISK_CORE_RECOVERY,
    ZCL_COMMAND_RISK_DESTRUCTIVE,
    ZCL_COMMAND_RISK_DEV_MUTATION,
};

enum zcl_command_scope {
    ZCL_COMMAND_SCOPE_LOCAL = 0,
    ZCL_COMMAND_SCOPE_NODE,
    ZCL_COMMAND_SCOPE_DEV_LANE,
    ZCL_COMMAND_SCOPE_OFFLINE_COPY,
};

enum zcl_command_authority {
    ZCL_COMMAND_AUTH_PUBLIC = 0,
    ZCL_COMMAND_AUTH_OPERATOR,
    ZCL_COMMAND_AUTH_OWNER,
};

enum zcl_command_availability {
    ZCL_COMMAND_READY = 0,
    ZCL_COMMAND_COMPAT,
    ZCL_COMMAND_PLANNED,
};

enum zcl_command_mode {
    ZCL_COMMAND_MODE_BRANCH = 0,
    ZCL_COMMAND_MODE_SYNC,
    ZCL_COMMAND_MODE_JOB,
    ZCL_COMMAND_MODE_STREAM,
};

enum zcl_command_latency {
    ZCL_COMMAND_LATENCY_INSTANT = 0,
    ZCL_COMMAND_LATENCY_FAST,
    ZCL_COMMAND_LATENCY_FOREGROUND,
    ZCL_COMMAND_LATENCY_BACKGROUND,
    ZCL_COMMAND_LATENCY_PERSISTENT,
};

/* Per-latency-bucket dispatch budget in milliseconds. This kernel-owned
 * contract gives every native leaf an explicit dispatch ceiling. */
#define ZCL_COMMAND_LATENCY_BUDGET_INSTANT_MS    50
#define ZCL_COMMAND_LATENCY_BUDGET_FAST_MS       250
#define ZCL_COMMAND_LATENCY_BUDGET_FOREGROUND_MS 750
#define ZCL_COMMAND_LATENCY_BUDGET_BACKGROUND_MS 900
#define ZCL_COMMAND_LATENCY_BUDGET_PERSISTENT_MS 900

/* >= the compiled catalog's leaf count; sized with headroom for the per-leaf
 * latency-sample ring (OS-B2 §2). engine/composition/src/command_catalog.c asserts against
 * this at compile time (size guard). */
/* Sized above the declarative catalog with deliberate growth room. The config
 * catalog has a compile-time assertion against this fixed side table. */
#define ZCL_COMMAND_LATENCY_TABLE_MAX 1024U

/* Maps a leaf's declared `latency` enum to its dispatch budget in ms. Pure,
 * total: an out-of-range value falls back to the PERSISTENT/900ms ceiling,
 * never 0 or undefined behavior. */
int64_t zcl_command_latency_budget_ms(enum zcl_command_latency latency);

enum zcl_command_cost {
    ZCL_COMMAND_COST_TINY = 0,
    ZCL_COMMAND_COST_LOW,
    ZCL_COMMAND_COST_MODERATE,
    ZCL_COMMAND_COST_HIGH,
    ZCL_COMMAND_COST_STREAM,
};

enum zcl_command_confirmation {
    ZCL_COMMAND_CONFIRM_NONE = 0,
    ZCL_COMMAND_CONFIRM_IDEMPOTENCY,
    ZCL_COMMAND_CONFIRM_PLAN_COMMIT,
};

enum zcl_command_status {
    ZCL_COMMAND_STATUS_PASSED = 0,
    ZCL_COMMAND_STATUS_ACCEPTED,
    ZCL_COMMAND_STATUS_BLOCKED,
    ZCL_COMMAND_STATUS_FAILED,
};

enum zcl_command_exit {
    ZCL_COMMAND_EXIT_OK = 0,
    ZCL_COMMAND_EXIT_FAILED = 1,
    ZCL_COMMAND_EXIT_INVALID = 2,
    ZCL_COMMAND_EXIT_BLOCKED = 3,
    ZCL_COMMAND_EXIT_DENIED = 4,
    ZCL_COMMAND_EXIT_TRANSIENT = 5,
    ZCL_COMMAND_EXIT_INTERNAL = 6,
};

enum zcl_command_lane {
    ZCL_COMMAND_LANE_LOCAL = 1U << 0,
    ZCL_COMMAND_LANE_DEV = 1U << 1,
    ZCL_COMMAND_LANE_CANONICAL = 1U << 2,
    ZCL_COMMAND_LANE_SOAK = 1U << 3,
    ZCL_COMMAND_LANE_OFFLINE_COPY = 1U << 4,
    ZCL_COMMAND_LANE_ALL_NODE = ZCL_COMMAND_LANE_DEV |
                                ZCL_COMMAND_LANE_CANONICAL |
                                ZCL_COMMAND_LANE_SOAK,
};

enum zcl_command_capability {
    ZCL_COMMAND_CAP_NONE = 0,
    ZCL_COMMAND_CAP_CHAIN_READ = UINT64_C(1) << 0,
    ZCL_COMMAND_CAP_APP_MANIFEST_READ = UINT64_C(1) << 1,
    ZCL_COMMAND_CAP_APP_SIMULATE = UINT64_C(1) << 2,
    ZCL_COMMAND_CAP_CHECKOUT_READ = UINT64_C(1) << 3,
    ZCL_COMMAND_CAP_CHECKOUT_WRITE = UINT64_C(1) << 4,
    ZCL_COMMAND_CAP_DEV_STATE_READ = UINT64_C(1) << 5,
    ZCL_COMMAND_CAP_DEV_STATE_WRITE = UINT64_C(1) << 6,
    ZCL_COMMAND_CAP_PROCESS_EXEC = UINT64_C(1) << 7,
    ZCL_COMMAND_CAP_TEST_RUN = UINT64_C(1) << 8,
    ZCL_COMMAND_CAP_COMPILER = UINT64_C(1) << 9,
    ZCL_COMMAND_CAP_HOTSWAP = UINT64_C(1) << 10,
    ZCL_COMMAND_CAP_DEV_ACTIVATE = UINT64_C(1) << 11,
    ZCL_COMMAND_CAP_WALLET_REQUEST = UINT64_C(1) << 12,
    ZCL_COMMAND_CAP_ZNAM = UINT64_C(1) << 13,
    ZCL_COMMAND_CAP_WEB = UINT64_C(1) << 14,
    ZCL_COMMAND_CAP_ONION = UINT64_C(1) << 15,
    ZCL_COMMAND_CAP_P2P_TOPIC = UINT64_C(1) << 16,
};

enum zcl_command_trait {
    ZCL_COMMAND_TRAIT_NONE = 0,
    ZCL_COMMAND_TRAIT_DETERMINISTIC = 1U << 0,
    ZCL_COMMAND_TRAIT_REVERSIBLE = 1U << 1,
    ZCL_COMMAND_TRAIT_IDEMPOTENT = 1U << 2,
    ZCL_COMMAND_TRAIT_DRY_RUN = 1U << 3,
    ZCL_COMMAND_TRAIT_DEV_ONLY = 1U << 4,
    /* May create only a bounded native window/process and return bounded
     * display input. It carries no domain write or software authority. */
    ZCL_COMMAND_TRAIT_DISPLAY_ONLY = 1U << 5,
};

enum zcl_command_transport {
    ZCL_COMMAND_TRANSPORT_NONE = 0,
    ZCL_COMMAND_TRANSPORT_NATIVE = 1U << 0,
    ZCL_COMMAND_TRANSPORT_REST = 1U << 1,
    /* Bits 2 and 3 are retired; keep RPC at bit 4 for persisted catalogs. */
    ZCL_COMMAND_TRANSPORT_RPC = 1U << 4,
};

struct zcl_command_spec;
struct zcl_command_registry;

struct zcl_command_context {
    const struct zcl_command_registry *registry;
    const char *source_root;
    const char *operator_lane;
    uint64_t granted_capabilities;
    /* The highest command authority this session may exercise. Dispatch fails
     * closed with AUTHORITY_DENIED when spec->authority exceeds it. A
     * zero-initialized context therefore defaults to ZCL_COMMAND_AUTH_PUBLIC
     * (the least-privilege floor); real sessions raise it from their role via
     * authz_ceiling_for_role(). A NULL context bypasses the check entirely. */
    enum zcl_command_authority authority_ceiling;
    /* Agent spend-policy session id (agent_sessions.session_id), presented
     * per-invocation by a bounded agent. Dispatch consults
     * agent_spend_policy_check() before running a spend-shaped handler and
     * fails closed with the policy's why token on refusal. NULL (the
     * zero-initialized default) is the local operator and is explicitly
     * exempt — a zero-init context is unaffected. */
    const char *agent_session;
    bool dev_build;
};

struct zcl_command_request {
    const struct zcl_command_spec *spec;
    const struct zcl_command_context *context;
    const struct json_value *input;
    const char *view;         /* "summary" | "normal" | "full" (default) */
    size_t budget_bytes;      /* 0 = contract default (never raises the cap) */
    size_t max_items;         /* 0 = unbounded; bounds a --view=full page */
    const char *cursor;       /* opaque page cursor for --view=full, or NULL */
    bool invoked_by_alias;
    const char *invoked_name;
    /* True once the agent spend policy has already ruled on THIS invocation
     * (set by zcl_command_registry_execute_json after its gate allows). A
     * handler that dispatches onward in-process — vault_dispatch is the only
     * one — must not re-run the gate: the amount it would present is the same
     * amount already authorized and debited, so a second run charges the
     * window twice and can refuse a spend the caller is entitled to. It
     * re-checks nothing and records nothing; the kernel gate is the single
     * accounting point per invocation. */
    bool agent_policy_settled;
};

struct zcl_command_next {
    char command[ZCL_COMMAND_MAX_PATH];
    char input_json[512];
    char reason[160];
};

struct zcl_command_error {
    char code[64];
    char message[192];
    char phase[64];
    char current_state[64];
    char next_action[256];
    char evidence[256];
    char failure_id[96];
    bool retryable;
    bool human_action_required;
    bool mutated;
};

struct zcl_command_reply {
    enum zcl_command_status status;
    enum zcl_command_exit exit_code;
    const char *data_schema;
    struct json_value data;
    struct zcl_command_error error;
    struct zcl_command_next next[ZCL_COMMAND_MAX_NEXT];
    size_t next_count;
};

typedef void (*zcl_command_handler_fn)(const struct zcl_command_request *request,
                                       struct zcl_command_reply *reply);

struct zcl_command_spec {
    const char *path;
    const char *parent;
    const char *aliases;
    const char *summary;
    /* One-line OUTPUT-interpretation contract: the source, freshness, units,
     * and completeness of `data` — not a restatement of `summary`. Required
     * and distinct from summary on every READY leaf; empty on branches. */
    const char *semantics;
    const char *tags;
    const char *input_schema;
    const char *output_schema;
    const char *input_keys;
    const char *positional_keys;
    const char *example;
    const char *availability_reason;
    const char *compat_target;
    /* Per-leaf response byte budget: 0 selects the kind default (RESULT/ERROR),
     * else clamps the success envelope to this cap. Validated to 0 or
     * [256, 65536]. Set only where the default is obviously wrong (list-shaped
     * leaves that legitimately need the larger LIST budget). */
    int budget_bytes;
    enum zcl_command_layer layer;
    enum zcl_command_effect effect;
    enum zcl_command_risk risk;
    enum zcl_command_scope scope;
    enum zcl_command_authority authority;
    enum zcl_command_availability availability;
    enum zcl_command_mode mode;
    enum zcl_command_latency latency;
    enum zcl_command_cost cost;
    enum zcl_command_confirmation confirmation;
    uint32_t allowed_lanes;
    uint64_t required_capabilities;
    uint32_t traits;
    uint32_t transports;
    zcl_command_handler_fn handler;
};

struct zcl_command_registry {
    const struct zcl_command_spec *commands;
    size_t count;
};

void zcl_command_reply_init(struct zcl_command_reply *reply,
                            const char *data_schema);
void zcl_command_reply_free(struct zcl_command_reply *reply);
void zcl_command_reply_fail(struct zcl_command_reply *reply,
                            enum zcl_command_status status,
                            enum zcl_command_exit exit_code,
                            const char *code, const char *phase,
                            bool retryable, bool mutated,
                            const char *message, const char *evidence);
bool zcl_command_reply_add_next(struct zcl_command_reply *reply,
                                const char *command, const char *input_json,
                                const char *reason);

bool zcl_command_registry_validate(const struct zcl_command_registry *registry,
                                   char *why, size_t why_size);
const struct zcl_command_spec *zcl_command_registry_find(
    const struct zcl_command_registry *registry, const char *path_or_alias,
    bool *was_alias);
const struct zcl_command_spec *zcl_command_registry_resolve_words(
    const struct zcl_command_registry *registry,
    const char *const *words, size_t word_count, size_t *consumed,
    bool *was_alias, char *invoked, size_t invoked_size);
bool zcl_command_registry_input_validate(const struct zcl_command_spec *spec,
                                         const struct json_value *input,
                                         char *why, size_t why_size);
/* Turn a rejection from the call above into a message that NAMES the keys the
 * leaf accepts: "<why>; accepted input keys: <a,b,c>", or "…; this command
 * accepts no input keys" for an empty-input leaf.
 *
 * This exists because "unknown input key 'name'" plus a pointer to a second
 * command is a round trip the caller usually does not spend. An agent that
 * guessed `name` for `code find` read the rejection, read "inspect the input
 * schema", and went back to grep — the right key (`text`) was already sitting
 * in the spec at the moment of the refusal. Every transport that rejects input
 * should render THIS, so no caller has to learn the answer twice.
 *
 * Writes a NUL-terminated string into `out` and returns its length.
 *
 * Header-only, for the same reason base/text_fit.h is: it reads one field of a
 * spec the caller already holds and formats a string, so it needs no link edge
 * and cannot grow command_registry.c, a legacy file whose recorded size may
 * only shrink. */
static inline size_t zcl_command_registry_input_reject_detail(
    const struct zcl_command_spec *spec, const char *why,
    char *out, size_t cap)
{
    if (!out || cap == 0) return 0;
    const char *keys = spec && spec->input_keys ? spec->input_keys : "";
    int n;
    if (keys[0])
        n = snprintf(out, cap, "%s; accepted input keys: %s",
                     why ? why : "invalid input", keys);
    else
        n = snprintf(out, cap, "%s; this command accepts no input keys",
                     why ? why : "invalid input");
    if (n < 0) { out[0] = '\0'; return 0; }
    return (size_t)n < cap ? (size_t)n : cap - 1;
}
/* Maximum characters a STRING value for `key` may carry. This is the same
 * answer zcl_command_registry_input_validate() enforces — it calls this
 * function — so a caller sizing a buffer or a frame can never disagree with
 * the validator. Unknown/NULL keys get the conservative default. */
size_t zcl_command_registry_input_str_max(const char *key);
/* Largest `--input` document `spec` can legally carry, in bytes: the sum of
 * its declared keys' own value bounds plus JSON punctuation, floored at
 * ZCL_COMMAND_MAX_INPUT. This is the read/parse bound for every transport;
 * it exists so a reader can never truncate a document the validator would
 * have accepted, and can never buffer one the validator would refuse. */
size_t zcl_command_registry_input_budget_bytes(
    const struct zcl_command_spec *spec);
void zcl_command_registry_digest(const struct zcl_command_registry *registry,
                                 char out[72]);

size_t zcl_command_registry_menu_json(const struct zcl_command_registry *registry,
                                      const char *path, char *out,
                                      size_t out_size);
size_t zcl_command_registry_describe_json(
    const struct zcl_command_registry *registry, const char *path,
    char *out, size_t out_size);
size_t zcl_command_registry_search_json(
    const struct zcl_command_registry *registry, const char *query,
    char *out, size_t out_size);
size_t zcl_command_registry_execute_json(
    const struct zcl_command_registry *registry,
    const struct zcl_command_spec *spec,
    const struct zcl_command_context *context,
    const struct json_value *input,
    bool invoked_by_alias, const char *invoked_name,
    const char *view, size_t budget_bytes,
    size_t max_items, const char *cursor,
    char *out, size_t out_size, enum zcl_command_exit *exit_code);

/* ── Hot-swap leaf-handler override layer ─────────────────────────────
 *
 * A lock-free, all-or-nothing snapshot layer that re-points a bounded set of
 * READY read-only leaf handlers at runtime. Dispatch
 * (zcl_command_registry_execute_json) consults the active override snapshot
 * for the resolved leaf path before falling back to the immutable catalog
 * handler column; with no snapshot published the cost is a single atomic load
 * + NULL check. Published snapshots are NEVER freed — an in-flight dispatch
 * that acquired an older snapshot must be allowed to finish without a UAF
 * race.
 */
#define ZCL_COMMAND_HANDLER_OVERRIDE_MAX 64U

struct zcl_command_handler_override {
    const char *path;                 /* canonical READY read-only leaf path */
    zcl_command_handler_fn handler;   /* replacement handler (must be non-NULL) */
};

/* Bind the canonical registry used to validate override paths. Idempotent;
 * pass NULL to unbind. Must be set before zcl_command_registry_replace_batch
 * can succeed. */
void zcl_command_registry_set_active(const struct zcl_command_registry *registry);

/* Atomically replace a batch of leaf handlers. All-or-nothing: every override
 * path must resolve to an existing READY, read-only leaf in the bound registry
 * (destructive/mutating leaves and aliases are rejected) BEFORE anything is
 * cloned or published. On any failure the active snapshot is untouched and
 * `why` (when non-NULL, size why_sz) carries a one-line reason. `generation`
 * must be strictly greater than the active generation, or 0 to auto-increment.
 * In-flight readers observe the entire old or entire new override set, never a
 * torn one. Returns true on publish.
 *
 * `out_generation` (nullable) receives the generation THIS call published,
 * written under the same write lock that assigns it. Use it instead of a
 * follow-up zcl_command_registry_active_generation() call: a concurrent
 * publisher can bump the active generation between the two, so a read-after-
 * write attributes another publisher's generation to this batch. On a REFUSED
 * publish `out_generation` is left untouched. */
bool zcl_command_registry_replace_batch(
    uint32_t generation,
    const struct zcl_command_handler_override *overrides,
    size_t count, char *why, size_t why_sz, uint32_t *out_generation);

/* Active override-snapshot generation (0 = none published). */
uint32_t zcl_command_registry_active_generation(void);

/* True iff every RETIRED override snapshot (published but no longer active) has
 * drained to a zero in-flight dispatch refcount — no dispatch can still be
 * executing a superseded handler. A hot-swap loader polls this before it
 * dlcloses a superseded module .so (epoch/refcount quiesce; see
 * hotswap_activate). Lock-free; the publish list is append-only, never freed. */
bool zcl_command_registry_all_retired_quiesced(void);

/* Effective handler for `spec`: the active override for spec->path when one is
 * published, else spec->handler. NULL when neither exists. */
zcl_command_handler_fn zcl_command_registry_effective_handler(
    const struct zcl_command_spec *spec);

/* Drop all overrides (revert to the immutable catalog). Reset hook; publishes
 * an empty (NULL) snapshot. The previous snapshot is retired per the
 * never-free discipline. */
void zcl_command_registry_reset_overrides(void);

const char *zcl_command_layer_name(enum zcl_command_layer value);
const char *zcl_command_effect_name(enum zcl_command_effect value);
const char *zcl_command_risk_name(enum zcl_command_risk value);
const char *zcl_command_scope_name(enum zcl_command_scope value);
const char *zcl_command_authority_name(enum zcl_command_authority value);
const char *zcl_command_availability_name(enum zcl_command_availability value);
const char *zcl_command_mode_name(enum zcl_command_mode value);
const char *zcl_command_latency_name(enum zcl_command_latency value);
const char *zcl_command_cost_name(enum zcl_command_cost value);
const char *zcl_command_confirmation_name(enum zcl_command_confirmation value);
const char *zcl_command_status_name(enum zcl_command_status value);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_KERNEL_COMMAND_REGISTRY_H */
