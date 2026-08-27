/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tier-1 hot-swap — the REAL (activatable) MULTI-LEAF module ABI.
 *
 * This is the multi-leaf successor to the native-leaf generation loader in
 * hotswap.h. Where that loader re-points a whole controller's leaf table via a
 * host vtable and NEVER dlcloses (a deliberate permanent leak), this module ABI
 * is:
 *
 *   - per-FILE, multi-leaf: one shape-leaf translation unit per .so, carrying
 *     up to ZCL_HOTSWAP_MODULE_MAX_LEAVES {leaf path, function} pairs. Every
 *     leaf is admitted through the identical gauntlet, then ALL of them are
 *     published in ONE all-or-nothing command-registry batch. A partial admit
 *     publishes ZERO leaves;
 *   - self-describing under ONE known symbol (`zcl_hotswap_module`), version
 *     stamped (`abi_version`) — an ABI mismatch or a missing symbol is refused
 *     LOUDLY (logged + typed error), no handler is ever called;
 *   - probed BEFORE publish: the file's declared probe leaf
 *     (config/hotswap_eligible.def) is dispatched against the registry's public
 *     spec/request/reply contract with a bounded empty input and validated
 *     against the leaf's DECLARED output schema. A mismatch publishes nothing.
 *     This replaces module self-certification as the last gate;
 *   - reclaimable: an activation commits into the kernel command-registry
 *     override layer and the superseded .so is dlclose'd AFTER in-flight
 *     dispatch drains (epoch/refcount quiesce in lib/kernel/command_registry.c).
 *
 * Widening the leaf count widens BATCH SIZE, not authority: every leaf still
 * has to be a READY read-only leaf of an allowlisted shape-leaf TU, activation
 * is still dev-datadir-only behind -hotswap-activate + ZCL_HOTSWAP_ACTIVATE=1,
 * and the registry batch commit still independently re-checks READY +
 * EFFECT_READ + non-alias for every path.
 *
 * Dynamic loading is DEV-ONLY: every dlopen/dlsym/dlclose lives behind
 * `#ifdef ZCL_DEV_BUILD` in hotswap_activate.c; a release build links only a
 * refusal stub. Activation is gated OFF by default — see
 * hotswap_activation_authorized(): it requires BOTH the `-hotswap-activate`
 * flag AND `ZCL_HOTSWAP_ACTIVATE=1`, and REFUSES the canonical datadir.
 * Without authorization every call is verify-only (labeled as such).
 */

#ifndef ZCL_HOTSWAP_MODULE_H
#define ZCL_HOTSWAP_MODULE_H

/* Supplies ZCL_CORE_SEAL_ROOT — the consensus pin both halves compare. */
#include "hotswap/core_seal_root.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward decls only — lib/hotswap never pulls kernel/app headers. The concrete
 * request/reply structs are complete only in the swappable controller TU. */
struct zcl_command_request;
struct zcl_command_reply;
struct json_value;

typedef void (*zcl_hotswap_handler_fn)(const struct zcl_command_request *request,
                                       struct zcl_command_reply *reply);

/* ABI v1 was the single-handler {handler_name, fn} layout. It is RETIRED: a
 * module still stamped v1 has an incompatible struct layout and is refused at
 * stage=abi before any field but abi_version is read. */
#define ZCL_HOTSWAP_MODULE_ABI_V1 1u
/* Bump only on an incompatible layout change to struct zcl_hotswap_module. A
 * loaded .so whose abi_version != this is refused before any handler runs. */
#define ZCL_HOTSWAP_MODULE_ABI_V2 2u

/* Hard ceiling on leaves per module. Matches the command registry's
 * ZCL_COMMAND_HANDLER_OVERRIDE_MAX so one module can never exceed what a
 * single all-or-nothing batch replace can carry. */
#define ZCL_HOTSWAP_MODULE_MAX_LEAVES 64U

/* The descriptor symbol every swappable module .so must export. */
#define ZCL_HOTSWAP_MODULE_SYMBOL "zcl_hotswap_module"

/* The consensus pin. A module .so ALSO exports this string: the ZCL_CORE_SEAL_ROOT
 * its compile saw. The resident compares it to its own before any leaf is
 * admitted, so a module built against a different sealed consensus core is
 * refused before leaf publication instead of dispatching a private, stale copy
 * of the inline consensus arithmetic it compiled in. dlopen may already have
 * run ELF constructors; this pin is not an execution sandbox. See
 * hotswap/core_seal_root.h for why the
 * pin is the seal ROOT and not a whole-tree build id — a controller edit must
 * not invalidate a module, a consensus edit must.
 *
 * A module missing this symbol is refused too: absence is what a pre-pin
 * artifact looks like, and those are exactly the ones whose consensus vintage
 * is unknown. */
#define ZCL_HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL "zcl_hotswap_module_core_seal_root"

/* One re-pointed command leaf. */
struct zcl_hotswap_leaf {
    const char *name;            /* canonical READY read-only leaf path */
    zcl_hotswap_handler_fn fn;   /* replacement handler (non-NULL) */
};

/* Exported (verbatim symbol name ZCL_HOTSWAP_MODULE_SYMBOL) by each swappable
 * .so. Resolved and fully validated before any `fn` is called. */
struct zcl_hotswap_module {
    uint32_t abi_version;                     /* == ZCL_HOTSWAP_MODULE_ABI_V2 */
    const char *source_tu;                    /* row in hotswap_swappable.def */
    uint32_t leaf_count;                      /* 1..MAX_LEAVES */
    const struct zcl_hotswap_leaf *leaves;    /* leaf_count entries */
    bool (*self_test)(char *err, size_t cap); /* structural health hook */
};

/* ── Module emitter (invoke ONCE at file scope in a swappable TU) ──────────
 *
 * Under a module build (-DZCL_HOTSWAP_MODULE_GEN) this emits the exported
 * `zcl_hotswap_module` bound to the TU's freshly-compiled leaf table +
 * self-test. In ordinary node and release builds it expands to nothing, so the
 * symbol only ever exists inside a module .so, never in the shipped binary.
 *
 * The build recipe passes -DZCL_HOTSWAP_MODULE_SOURCE_TU="<repo-relative .c>"
 * so a module cannot mislabel which allowlist row it belongs to; __FILE__ is
 * the fallback (make/hotswap-module-fast compile the source by its
 * repo-relative path, so the two agree).
 *
 *     static const struct zcl_hotswap_leaf k_module_leaves[] = {
 *         { "core.status",       module_tramp_status },
 *         { "core.status.brief", module_tramp_status_brief },
 *     };
 *     ZCL_HOTSWAP_MODULE_LEAVES(k_module_leaves, module_selftest_status)
 */
#ifndef ZCL_HOTSWAP_MODULE_SOURCE_TU
#define ZCL_HOTSWAP_MODULE_SOURCE_TU __FILE__
#endif

#ifdef ZCL_HOTSWAP_MODULE_GEN
#define ZCL_HOTSWAP_MODULE_LEAVES(leaves_, self_test_)                       \
    const char zcl_hotswap_module_core_seal_root[] = ZCL_CORE_SEAL_ROOT;     \
    const struct zcl_hotswap_module zcl_hotswap_module = {                   \
        .abi_version = ZCL_HOTSWAP_MODULE_ABI_V2,                            \
        .source_tu = ZCL_HOTSWAP_MODULE_SOURCE_TU,                           \
        .leaf_count = (uint32_t)(sizeof(leaves_) / sizeof((leaves_)[0])),    \
        .leaves = (leaves_),                                                 \
        .self_test = (self_test_),                                           \
    };
#else
#define ZCL_HOTSWAP_MODULE_LEAVES(leaves_, self_test_) /* node/release: omitted */
#endif

/* Compatibility alias for the original single-handler emitter. Expands to a
 * one-entry ZCL_HOTSWAP_MODULE_LEAVES table — the same v2 struct, so a TU that
 * has not yet grown a multi-leaf table keeps building and swapping unchanged:
 *
 *     ZCL_HOTSWAP_MODULE("core.status", tramp_status, selftest_status)
 */
#ifdef ZCL_HOTSWAP_MODULE_GEN
#define ZCL_HOTSWAP_MODULE(handler_name_, fn_, self_test_)                   \
    static const struct zcl_hotswap_leaf zcl_hotswap_compat_leaves_[] = {    \
        { (handler_name_), (fn_) },                                          \
    };                                                                       \
    ZCL_HOTSWAP_MODULE_LEAVES(zcl_hotswap_compat_leaves_, (self_test_))
#else
#define ZCL_HOTSWAP_MODULE(handler_name_, fn_, self_test_) /* node/release: omitted */
#endif

/* Result of hotswap_activate(). Always fully populated (even on failure). */
struct hotswap_activate_report {
    bool ok;              /* verify passed; and activated iff request+authorized */
    bool verify_only;     /* activation was not requested OR not authorized */
    bool activated;       /* the live registry slots were actually re-pointed */
    bool rolled_back;     /* a failure left every previous handler in place */
    bool probed;          /* the declared probe leaf was dispatched + validated */
    uint32_t generation;  /* registry override generation after commit (else 0) */
    uint32_t leaf_count;  /* leaves admitted (and, when activated, published) */
    char source_tu[256];  /* the module's allowlist row */
    char probe_leaf[128]; /* the file's declared probe leaf */
    char handler_name[128]; /* first leaf — the pre-multi-leaf report field */
    char leaves[512];     /* comma-joined admitted leaf paths (may be clipped) */
    char artifact_sha256[65];
    /* SHA3-256 over the SAME descriptor the loader maps. A second,
     * structurally different hash family over identical bytes: a collision
     * engineered against SHA-256 is not a collision against Keccak. Integrity
     * only, never authorization — see hotswap/hotswap_artifact_digest.h for
     * exactly what the fd pin does and does not guarantee.
     *
     * hotswap_activate() fills this AND artifact_sha256 above from one fd.
     * hotswap_verify_module_so() (the standalone build-time verifier) fills
     * only this one and leaves artifact_sha256 empty — it links neither
     * lib/crypto nor its dispatch table. Either field is "" on any path that
     * failed before reaching the artifact's bytes; test both before use. */
    char artifact_sha3_256[65];
    /* precheck|authorize|dlopen|abi|fields|capacity|allowlist|duplicate|
     * probe|self_test|commit|verified|activated|release */
    char stage[64];
    char error[256];      /* "" on ok */
};

/* Publish the module's ENTIRE leaf set into the resident command registry as
 * ONE all-or-nothing batch. Supplied by the resident (tools/command) layer /
 * test harness so lib/hotswap stays free of kernel headers. Returns true on
 * publish, filling *out_gen with the new override generation; false leaves
 * every active handler untouched and fills `why`. */
typedef bool (*hotswap_commit_batch_cb)(void *ctx,
                                        const struct zcl_hotswap_leaf *leaves,
                                        size_t leaf_count,
                                        uint32_t *out_gen,
                                        char *why, size_t why_sz);

/* PROBE-BEFORE-PUBLISH. Dispatch `fn` for the canonical leaf `leaf` against the
 * command registry's public contract — the registry-resolved spec, its input
 * validation with a bounded EMPTY request, and its reply envelope — then
 * validate the reply against that leaf's DECLARED output schema and response
 * budget. Return false (with `why`) on any mismatch; the loader then publishes
 * NOTHING. Supplied by the resident layer for the same reason as the commit
 * callback: lib/hotswap must not link the kernel registry. */
typedef bool (*hotswap_probe_leaf_cb)(void *ctx, const char *leaf,
                                      zcl_hotswap_handler_fn fn,
                                      char *why, size_t why_sz);

/* Compiled into the resident host. A candidate supplies only its immutable
 * source identity; it cannot select or weaken these qualification inputs. */
struct zcl_hotswap_probe_case {
    const char *case_id;
    const char *kind;
    const char *operation;
    const char *canonical_input_json;
    const char *expected_schema;
    size_t byte_budget;
};

/* Return true iff every RETIRED override snapshot has drained — i.e. no
 * in-flight dispatch can still enter a superseded handler, so the previous
 * module .so is safe to dlclose. Polled with a bounded backoff after commit. */
typedef bool (*hotswap_quiesced_cb)(void *ctx);

/* The resident hooks a publish needs. `ctx` is passed to each callback.
 *   commit    REQUIRED to activate (ignored for verify-only).
 *   probe     REQUIRED to activate. On verify-only it is run when present and
 *             skipped when NULL (report->probed says which).
 *   quiesced  optional; NULL keeps the superseded .so mapped forever (safe). */
struct hotswap_publish_hooks {
    hotswap_commit_batch_cb commit;
    hotswap_probe_leaf_cb probe;
    hotswap_quiesced_cb quiesced;
    void *ctx;
};

/* Load a multi-leaf module .so and, when authorized, activate it live.
 *
 *   so_path           absolute path to the module .so (hotswap_path_is_acceptable)
 *   resolved_datadir  must resolve to the exact worker path ~/.zclassic-c23-dev
 *   request_activate  false => verify-only (default). true => attempt a live
 *                     swap, which still requires hotswap_activation_authorized().
 *   hooks             commit/probe/quiesce callbacks (see above); may be NULL
 *                     for a pure verify-only load.
 *   report            out — always populated; on any failure every previous
 *                     handler is untouched (rolled_back=true) and error is set.
 *
 * Verify-only (or unauthorized activate): dlopen + admit the whole leaf set +
 * optional probe, NEVER commits, dlcloses the candidate, reports
 * verify_only=true. Authorized activate: admit -> probe -> ONE batch commit
 * into the command registry override layer (generation bumped), then dlclose
 * the superseded .so once quiesced reports drain (else keep it mapped, the
 * pilot's never-close fallback — always safe).
 *
 * DEV-ONLY: without ZCL_DEV_BUILD this refuses ("unavailable") and never
 * dlopens. Returns report->ok. */
bool hotswap_activate(const char *so_path,
                      const char *resolved_datadir,
                      bool request_activate,
                      const struct hotswap_publish_hooks *hooks,
                      struct hotswap_activate_report *report);

/* Process-local variant for the operator's own one-shot CLI process: always
 * commits (never verify-only) but SKIPS the resident activation gate
 * (-hotswap-activate + ZCL_HOTSWAP_ACTIVATE=1) — a throwaway CLI holds
 * probe-class authority (identical to dev.hotswap.probe), and the overrides it
 * installs die with the process. The dev-datadir requirement, path
 * confinement, the full admit gauntlet, and probe-before-publish all still
 * apply; the registry commit itself re-checks READY + EFFECT_READ. This is the
 * observable dev loop: ZCL_HOTSWAP_PRELOAD=<module.so> zclassic23-dev <leaf>
 * renders from the freshly compiled body with no resident restart.
 * DEV-ONLY: no release caller exists; the implementation lives inside the
 * ZCL_DEV_BUILD region like hotswap_activate. */
bool hotswap_activate_local(const char *so_path,
                            const char *resolved_datadir,
                            const struct hotswap_publish_hooks *hooks,
                            struct hotswap_activate_report *report);

/* BUILD-TIME LOAD VERIFICATION. dlopen `so_path`, resolve
 * ZCL_HOTSWAP_MODULE_SYMBOL, and run the full hotswap_module_admit() gauntlet
 * against the REAL, compiler-emitted module struct. Needs no node, no datadir
 * and no registry: it never commits, never probes a live leaf, and never calls
 * a trampoline.
 *
 * This exists because every hot-swap test in the tree drives
 * hotswap_module_admit() with a struct FABRICATED in the test's own TU, which
 * proves the gauntlet's logic and nothing about any real artifact. A row in
 * config/hotswap_swappable.def whose TU never emits `zcl_hotswap_module` at
 * all passed every gate in the repo and failed at stage=symbol the first time
 * a human tried it. An allowlist entry that has never been loaded is a claim,
 * not an admission; this is what turns one into the other.
 *
 * `expect_tu` (optional) is compared against the module's stamped source_tu.
 * `report` is always populated: stage is one of precheck|dlopen|symbol|
 * source_tu|<any hotswap_module_admit stage>|verified.
 * DEV-ONLY: the release build links a refusal stub. Returns report->ok. */
bool hotswap_verify_module_so(const char *so_path, const char *expect_tu,
                              struct hotswap_activate_report *report);

/* Pure admission check for a resolved module: ABI version, required fields,
 * the leaf-count ceiling, the swappable file+leaf allowlist, intra-module leaf
 * uniqueness, the presence of the file's declared probe leaf, and the module's
 * own self_test — the exact gauntlet hotswap_activate applies after dlsym,
 * factored out so it is unit-testable with a fabricated struct in ANY build (no
 * dlopen). On failure fills `stage` (one of "abi"|"fields"|"capacity"|
 * "allowlist"|"duplicate"|"probe"|"self_test") and `why`.
 * Returns true iff the module is admissible. */
bool hotswap_module_admit(const struct zcl_hotswap_module *module,
                          char *stage, size_t stage_cap,
                          char *why, size_t why_cap);

/* The ENTIRE post-dlsym publish sequence, factored out of hotswap_activate so
 * it is drivable with a fabricated module in ANY build (no dlopen, no dev
 * build): admit every leaf -> probe the declared probe leaf -> ONE all-or-
 * nothing batch commit. `report` is fully populated either way and is NOT
 * memset here (the caller owns artifact_sha256 and the earlier stages).
 *
 * request_activate=false stops after admit+probe and reports verify_only. Any
 * failure at any stage publishes ZERO leaves and returns false with
 * report->rolled_back set. Returns report->ok. */
bool hotswap_module_publish(const struct zcl_hotswap_module *module,
                            bool request_activate,
                            const struct hotswap_publish_hooks *hooks,
                            struct hotswap_activate_report *report);

/* Record the -hotswap-activate flag (argv parse, resident node process). */
void hotswap_set_activate_flag(bool enabled);
bool hotswap_activate_flag(void);

/* Activation gate. True ONLY when: the -hotswap-activate flag was set AND
 * env ZCL_HOTSWAP_ACTIVATE=1 AND resolved_datadir is the exact dev lane
 * (~/.zclassic-c23-dev). The canonical datadir (~/.zclassic-c23) is refused
 * with a loud, typed reason in `why`. */
bool hotswap_activation_authorized(const char *resolved_datadir,
                                   char *why, size_t why_sz);

/* Runtime mirror of the check-hotswap-swappable-shape lint gate: true iff
 * `leaf` is on the compiled swappable allowlist (config/hotswap_swappable.def)
 * under some source file — a shape-leaf handler (controllers/views/
 * conditions), never a reducer/consensus/storage/supervisor path. */
bool hotswap_handler_is_swappable(const char *leaf);

/* The repo-relative source TU that owns `leaf` per config/hotswap_swappable.def,
 * or NULL when the leaf is not swappable. A leaf is owned by exactly one file,
 * which is what makes a duplicate leaf across two modules unrepresentable. */
const char *hotswap_swappable_source_for_leaf(const char *leaf);

/* True iff source_tu is an exact row in config/hotswap_swappable.def. This is
 * the resident build authority's source-side confinement check; it avoids
 * reparsing the manifest from disk on every edit. */
bool hotswap_source_is_swappable(const char *source_tu);

/* Resolve either an owning swappable TU or one of its stateless island-member
 * TUs to the owning module source. Members come from
 * config/hotswap_islands.def and are compiled into the same -Bsymbolic .so. */
const char *hotswap_island_owner_for_path(const char *path);
const char *hotswap_island_members_for_source(const char *source_tu);

/* The probe leaf config/hotswap_eligible.def declares for `source_tu`, or NULL
 * when that file declares none. The module does NOT choose its own probe. */
const char *hotswap_module_probe_leaf(const char *source_tu);
const struct zcl_hotswap_probe_case *hotswap_module_probe_case(
    const char *source_tu);
const struct zcl_hotswap_probe_case *hotswap_probe_case_for_operation(
    const char *operation);

/* Append the activation subsystem's telemetry into an already-open object.
 * Called by hotswap_dump_state_json() so `z23 dumpstate hotswap` shows
 * both the generation loader and activation
 * slots/epochs/containment in one document. */
void hotswap_activate_dump_json(struct json_value *out);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_HOTSWAP_MODULE_H */
