/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `zcl.service_binding.v1` — the declared way to add a SERVICE.
 *
 * WHY a binding and not a second service catalog: the process-isolation
 * charter already exists. `zcl.service_manifest.v1`
 * (kernel/service_manifest.h + engine/composition/services/catalog.def) declares the six
 * node roles, their trust classes, descriptor grants, resource budgets, and
 * restart policy. It answers "what may this process touch". It deliberately
 * does NOT answer "what commands does this unit register, what state does it
 * own, and who is allowed to call it" — and its per-manifest SHA3 identity is
 * pinned by a golden vector, so growing that struct would rewrite an existing
 * identity. A binding therefore COMPOSES with a manifest rather than copying
 * it: every binding names a `host_service_id` that must be a real catalog
 * entry with trust class APP_BROKER (appd), and it inherits that manifest's
 * descriptor grants unchanged. A service can never widen them.
 *
 * A binding declares exactly four things a manifest cannot:
 *   1. command_prefix     — the native command namespace it owns. It must sit
 *                           under "app.service." so a service can never shadow
 *                           the core, dev, or ops roots, and the leaves are
 *                           still declared in a engine/composition/commands .def, so
 *                           `discover` and the generated API reference pick
 *                           them up for free.
 *   2. state_table_prefix — the node.db table namespace it owns. Reserved
 *                           consensus/kernel prefixes are refused by the
 *                           validator, not by convention.
 *   3. gate               — access derived from a ZSLP token balance at a
 *                           stated snapshot height, read from `zslp_ledger`
 *                           (the debit-correct per-(token,outpoint) ledger).
 *                           NOT `zslp_balances`, which is a credit-only
 *                           merchant ledger keyed on ticker strings.
 *   4. isolation          — the boundary, as a required flag set the
 *                           validator refuses to let a declaration drop.
 *
 * Nothing here launches, binds, or authorizes anything: validation and
 * hashing are pure. A binding is data; the runtime still has to honour it.
 *
 * ISOLATION (enforced, not advised). Every binding must carry the complete
 * ZCL_SERVICE_ISOLATION_REQUIRED_V1 set; a manifest that omits one bit or
 * invents a new one fails zcl_service_binding_validate_v1, which fails the
 * catalog, which fails test_service_binding. The five bits mean:
 *   - NO_BLOCK_VALIDITY: a service is never consulted by any consensus
 *     predicate. Consensus predicates live under core/, which is byte-sealed.
 *   - NO_CONSENSUS_WRITE: a service never writes chain/kernel state — no
 *     coins, headers, anchors, nullifiers, stage cursors.
 *   - NO_BLOCKING_PROGRESS_LOCK: a service never blocks on the reducer
 *     progress lock; observers use the trylock path or they do without.
 *   - CATALOG_DECLARED_AUTH: every entry point is a command-catalog leaf, so
 *     its auth/effect/risk are the catalog's declaration, not the service's.
 *   - OWNED_STATE_ONLY: writes are confined to state_table_prefix tables.
 */

#ifndef ZCL_KERNEL_SERVICE_BINDING_H
#define ZCL_KERNEL_SERVICE_BINDING_H

#include "kernel/service_manifest.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_SERVICE_BINDING_V1 1u
#define ZCL_SERVICE_BINDING_SCHEMA_NAME "zcl.service_binding.v1"
#define ZCL_SERVICE_BINDING_CATALOG_SCHEMA_NAME "zcl.service_binding_catalog.v1"

#define ZCL_SERVICE_BINDING_NAME_MAX 31u
#define ZCL_SERVICE_BINDING_DISPLAY_MAX 63u
#define ZCL_SERVICE_BINDING_VERSION_MAX 15u
#define ZCL_SERVICE_BINDING_COMMAND_PREFIX_MAX 47u
#define ZCL_SERVICE_BINDING_TABLE_PREFIX_MAX 31u
#define ZCL_SERVICE_BINDING_STATE_SCHEMA_MAX 63u
#define ZCL_SERVICE_BINDING_CATALOG_MAX 32u

/* Every service command leaf lives under this root. Enforced by the
 * validator so a binding can never claim `core.` or `dev.`. */
#define ZCL_SERVICE_BINDING_COMMAND_ROOT "app.service."

/* Snapshot depth ceiling: a gate that reaches further back than this is a
 * declaration error, not a policy. */
#define ZCL_SERVICE_GATE_DEPTH_MAX 100000

/* Reserved sentinel token id (32 × 0xFF): "this binding names a token that
 * has not been minted yet". It VALIDATES — so a contract can be declared and
 * reviewed before the token exists — but it never GRANTS: the evaluator
 * returns a denied verdict with reason `token_unminted`, and a service whose
 * gate carries it cannot leave STARTING. That is the honest shape: a
 * placeholder that fails closed rather than a fabricated txid that looks
 * real. Replace it with the real GENESIS txid to arm the binding. */
#define ZCL_SERVICE_GATE_TOKEN_UNMINTED_BYTE 0xFFu
bool zcl_service_gate_token_unminted_v1(const uint8_t token_genesis_txid[32]);

enum zcl_service_isolation_v1 {
    ZCL_SERVICE_ISOLATION_NO_BLOCK_VALIDITY = UINT64_C(1) << 0,
    ZCL_SERVICE_ISOLATION_NO_CONSENSUS_WRITE = UINT64_C(1) << 1,
    ZCL_SERVICE_ISOLATION_NO_BLOCKING_PROGRESS_LOCK = UINT64_C(1) << 2,
    ZCL_SERVICE_ISOLATION_CATALOG_DECLARED_AUTH = UINT64_C(1) << 3,
    ZCL_SERVICE_ISOLATION_OWNED_STATE_ONLY = UINT64_C(1) << 4,
};

/* The complete boundary. A binding declares exactly this — no subset, no
 * superset. There is deliberately no way to spell "this service may write
 * consensus state". */
#define ZCL_SERVICE_ISOLATION_REQUIRED_V1                        \
    (ZCL_SERVICE_ISOLATION_NO_BLOCK_VALIDITY |                   \
     ZCL_SERVICE_ISOLATION_NO_CONSENSUS_WRITE |                  \
     ZCL_SERVICE_ISOLATION_NO_BLOCKING_PROGRESS_LOCK |           \
     ZCL_SERVICE_ISOLATION_CATALOG_DECLARED_AUTH |               \
     ZCL_SERVICE_ISOLATION_OWNED_STATE_ONLY)

/* Which height the balance is read at. Both forms are reproducible: the same
 * ledger and the same tip yield the same snapshot height, and the same ledger
 * and the same snapshot height yield the same balance. */
enum zcl_service_gate_snapshot_v1 {
    ZCL_SERVICE_GATE_SNAPSHOT_INVALID = 0,
    /* snapshot_param = confirmation depth; height = tip - depth. */
    ZCL_SERVICE_GATE_SNAPSHOT_CONFIRMED_DEPTH = 1,
    /* snapshot_param = an absolute height; the verdict never moves again. */
    ZCL_SERVICE_GATE_SNAPSHOT_FIXED_HEIGHT = 2,
};

/* Whose balance is measured. */
enum zcl_service_gate_holder_v1 {
    ZCL_SERVICE_GATE_HOLDER_INVALID = 0,
    /* Folded over every address this node's wallet owns. */
    ZCL_SERVICE_GATE_HOLDER_WALLET = 1,
    /* One explicit 20-byte hash160 supplied by the caller. */
    ZCL_SERVICE_GATE_HOLDER_ADDRESS = 2,
};

/* token_genesis_txid is the ZSLP GENESIS txid in internal (node) byte order —
 * the same order zslp_ledger stores as token_id. All-zero is refused: an
 * unnamed token is not a binding. */
struct zcl_service_token_gate_v1 {
    uint8_t token_genesis_txid[32];
    uint64_t min_balance;      /* base units, strictly positive */
    uint32_t snapshot_kind;    /* enum zcl_service_gate_snapshot_v1 */
    uint32_t holder_kind;      /* enum zcl_service_gate_holder_v1 */
    int32_t snapshot_param;    /* depth (>=1) or absolute height (>=0) */
};

/* Pointer-free, so a parsed binding is self-contained and safe to copy. */
struct zcl_service_binding_v1 {
    uint32_t struct_size;
    uint32_t schema_version;
    uint32_t binding_id;                 /* unique, strictly ascending */
    char name[ZCL_SERVICE_BINDING_NAME_MAX + 1u];
    char display_name[ZCL_SERVICE_BINDING_DISPLAY_MAX + 1u];
    char version[ZCL_SERVICE_BINDING_VERSION_MAX + 1u];

    uint32_t host_service_id;            /* must be an APP_BROKER manifest */
    char command_prefix[ZCL_SERVICE_BINDING_COMMAND_PREFIX_MAX + 1u];
    char state_table_prefix[ZCL_SERVICE_BINDING_TABLE_PREFIX_MAX + 1u];
    char state_schema[ZCL_SERVICE_BINDING_STATE_SCHEMA_MAX + 1u];
    uint32_t state_schema_version;       /* >= 1 */

    struct zcl_service_token_gate_v1 gate;
    uint64_t isolation;                  /* == ZCL_SERVICE_ISOLATION_REQUIRED_V1 */
    uint32_t restart_policy;             /* enum zcl_service_restart_policy_v1 */
    uint64_t health_deadline_ms;         /* 1 ms .. 600 s */
};

enum zcl_service_binding_result {
    ZCL_SERVICE_BINDING_OK = 0,
    ZCL_SERVICE_BINDING_NULL,
    ZCL_SERVICE_BINDING_SCHEMA,
    ZCL_SERVICE_BINDING_IDENTITY,
    ZCL_SERVICE_BINDING_HOST,
    ZCL_SERVICE_BINDING_COMMAND_PREFIX,
    ZCL_SERVICE_BINDING_STATE_PREFIX,
    ZCL_SERVICE_BINDING_STATE_SCHEMA,
    ZCL_SERVICE_BINDING_TOKEN_GATE,
    ZCL_SERVICE_BINDING_ISOLATION,
    ZCL_SERVICE_BINDING_RESTART,
    ZCL_SERVICE_BINDING_HEALTH,
    ZCL_SERVICE_BINDING_CATALOG_ORDER,
    ZCL_SERVICE_BINDING_CATALOG_COLLISION,
};

/* Human-readable, stable, lowercase_snake. Never NULL. */
const char *zcl_service_binding_result_name_v1(
    enum zcl_service_binding_result result);

/* Pure. Grants nothing; a valid binding is still just a declaration. */
enum zcl_service_binding_result zcl_service_binding_validate_v1(
    const struct zcl_service_binding_v1 *binding);

/* Catalog rules on top of per-binding validity: binding_id strictly
 * ascending, and no two bindings sharing a name, a command prefix, or a state
 * table prefix — including the case where one prefix is a prefix of another,
 * which would silently let one service write another's tables. */
enum zcl_service_binding_result zcl_service_binding_catalog_validate_v1(
    const struct zcl_service_binding_v1 *bindings,
    size_t count,
    size_t *bad_index);

/* The host manifest must exist and must be an APP_BROKER. Split out so the
 * composition root can cross-check against the real service catalog without
 * this module depending on config/. */
enum zcl_service_binding_result zcl_service_binding_host_check_v1(
    const struct zcl_service_binding_v1 *binding,
    const struct zcl_service_manifest_v1 *manifests,
    size_t manifest_count);

/* Canonical fixed-width little-endian SHA3-256 over the declared fields.
 * Invalid input fails closed and zeros `out`. */
bool zcl_service_binding_digest_v1(
    const struct zcl_service_binding_v1 *binding, uint8_t out[32]);

bool zcl_service_binding_catalog_digest_v1(
    const struct zcl_service_binding_v1 *bindings,
    size_t count,
    uint8_t out[32]);

/* ── the reproducible half of the token binding ──────────────────────
 *
 * Resolve the snapshot height a gate is evaluated at. Pure: no ledger, no
 * clock, no node. CONFIRMED_DEPTH needs a tip at least `depth` high; a
 * shallower chain fails closed rather than clamping to genesis, because a
 * clamped verdict would silently change meaning as the chain grows. */
bool zcl_service_gate_snapshot_height_v1(
    const struct zcl_service_token_gate_v1 *gate,
    int32_t tip_height,
    int32_t *out_height);

/* True when `table` is inside the binding's owned state namespace. The
 * comparison is exact-prefix on a fully lowercase table name; anything else
 * is outside and must be refused by the writer. */
bool zcl_service_binding_owns_table_v1(
    const struct zcl_service_binding_v1 *binding, const char *table);

/* True when `path` is the binding's command prefix or a leaf beneath it.
 * "app.service.vaulted" is NOT beneath "app.service.vault". */
bool zcl_service_binding_owns_command_v1(
    const struct zcl_service_binding_v1 *binding, const char *path);

/* ── lifecycle ───────────────────────────────────────────────────────
 *
 * States are `enum zcl_service_lifecycle_v1` from the manifest contract —
 * reused verbatim so a service and a node role are read on one scale.
 * DECLARED is both the pre-register state and the post-remove state: a
 * compiled-in declaration cannot be un-declared, only unregistered. */
enum zcl_service_lifecycle_event_v1 {
    ZCL_SERVICE_EVENT_INVALID = 0,
    ZCL_SERVICE_EVENT_REGISTER = 1,  /* DECLARED  -> STARTING */
    ZCL_SERVICE_EVENT_START = 2,     /* STARTING  -> READY (gate must pass) */
    ZCL_SERVICE_EVENT_DEGRADE = 3,   /* READY     -> DEGRADED */
    ZCL_SERVICE_EVENT_RECOVER = 4,   /* DEGRADED  -> READY */
    ZCL_SERVICE_EVENT_FAULT = 5,     /* any live  -> BLOCKED (named reason) */
    ZCL_SERVICE_EVENT_STOP = 6,      /* live|BLOCKED -> STOPPING */
    ZCL_SERVICE_EVENT_EXIT = 7,      /* STOPPING  -> EXITED */
    ZCL_SERVICE_EVENT_REMOVE = 8,    /* EXITED    -> DECLARED */
};

/* Pure transition table. Returns false (and leaves *out_state untouched) for
 * every transition the machine does not allow — including every escape from
 * BLOCKED except an explicit STOP, so a failed service stays named until an
 * operator acts on it. */
bool zcl_service_lifecycle_next_v1(uint32_t state, uint32_t event,
                                   uint32_t *out_state);

/* Stable lowercase_snake names for the reused lifecycle states. */
const char *zcl_service_lifecycle_name_v1(uint32_t state);

#endif /* ZCL_KERNEL_SERVICE_BINDING_H */
