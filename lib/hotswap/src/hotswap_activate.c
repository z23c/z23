/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tier-1 hot-swap — the REAL (activatable) MULTI-LEAF module loader.
 *
 * See hotswap/hotswap_module.h for the ABI. The pure surface (swappable
 * allowlist, probe map, activation flag, the activation GATE, admission, and
 * telemetry) compiles in every build; only the dlopen/dlsym/dlclose activation
 * core is DEV-ONLY. A release build links the refusal stub at the bottom.
 *
 * Publish order is fixed and all-or-nothing:
 *   dlopen -> dlsym -> admit EVERY leaf -> probe the file's DECLARED probe leaf
 *   against the registry's public contract -> ONE batch replace.
 * Any failure before the batch replace publishes ZERO leaves and leaves every
 * resident handler untouched.
 *
 * Safety of the reclamation: a superseded module .so is released ONLY after
 * BOTH gates clear — the resident quiesced callback confirms every retired
 * command registry override snapshot has drained (no in-flight dispatch can
 * still enter an old handler), AND the live-leaf ownership table proves the
 * ACTIVE snapshot can no longer reach it. Either gate unproven keeps the .so
 * mapped forever, which is always memory-safe; releasing it is best-effort
 * reclamation, never a correctness dependency. The second gate is not
 * decoration: without it a commit that lost the registry race, or a module
 * that dropped a leaf, unmaps code the live snapshot still dispatches into.
 * The whole argument, and the interleaving that motivated it, is in
 * hotswap/hotswap_shelf.h.
 */

#define _GNU_SOURCE
#include "hotswap/hotswap_module.h"
#include "hotswap/hotfork_capsule.h"
#include "hotswap/hotswap.h"
#include "hotswap/hotswap_retire_blocker.h"
#include "hotswap/hotswap_shelf.h"

#include "json/json.h"
#include "platform/fd_path.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ── swappable allowlist, compiled from config/hotswap_swappable.def ───────
 * ONE row per source TU; `leaves` is the space-separated set of canonical
 * leaf paths that TU's module may re-point. */
static const struct {
    const char *source;
    const char *leaves;
} g_swappable[] = {
#define HOTSWAP_SWAPPABLE(source_, leaves_) { .source = source_, .leaves = leaves_ },
#include "../../../config/hotswap_swappable.def"
#undef HOTSWAP_SWAPPABLE
};

/* ── probe map, compiled from config/hotswap_eligible.def ─────────────────
 * The declared param-free probe leaf per eligible TU. A module never chooses
 * its own probe: the loader looks it up here by source_tu. */
static const struct {
    const char *source;
    const char *probe;
} g_probes[] = {
#define HOTSWAP_ELIGIBLE(path_) { .source = path_,
#define HOTSWAP_PROBE(tool_) .probe = tool_ },
#include "../../../config/hotswap_eligible.def"
#undef HOTSWAP_ELIGIBLE
#undef HOTSWAP_PROBE
};

static const struct zcl_hotswap_probe_case g_probe_cases[] = {
#define HOTSWAP_PROBE_CASE(case_id_, kind_, operation_, input_, schema_, budget_) \
    { (case_id_), (kind_), (operation_), (input_), (schema_), (budget_) },
#include "../../../config/hotswap_probe_cases.def"
#undef HOTSWAP_PROBE_CASE
};

#define SWAPPABLE_COUNT (sizeof(g_swappable) / sizeof(g_swappable[0]))
#define PROBE_COUNT (sizeof(g_probes) / sizeof(g_probes[0]))

/* Space/tab-separated membership test over a `leaves` column. No allocation. */
static bool leaf_list_contains(const char *list, const char *leaf)
{
    if (!list || !leaf || !leaf[0])
        return false;
    size_t want = strlen(leaf);
    const char *p = list;
    while (*p) {
        while (*p == ' ' || *p == '\t')
            p++;
        const char *start = p;
        while (*p && *p != ' ' && *p != '\t')
            p++;
        size_t len = (size_t)(p - start);
        if (len == want && strncmp(start, leaf, want) == 0)
            return true;
    }
    return false;
}

const char *hotswap_swappable_source_for_leaf(const char *leaf)
{
    if (!leaf || !leaf[0])
        return NULL;
    for (size_t i = 0; i < SWAPPABLE_COUNT; i++) {
        if (leaf_list_contains(g_swappable[i].leaves, leaf))
            return g_swappable[i].source;
    }
    return NULL;
}

bool hotswap_handler_is_swappable(const char *leaf)
{
    return hotswap_swappable_source_for_leaf(leaf) != NULL;
}

static const char *swappable_leaves_for_source(const char *source_tu)
{
    if (!source_tu || !source_tu[0])
        return NULL;
    for (size_t i = 0; i < SWAPPABLE_COUNT; i++) {
        if (strcmp(source_tu, g_swappable[i].source) == 0)
            return g_swappable[i].leaves;
    }
    return NULL;
}

const struct zcl_hotswap_probe_case *hotswap_probe_case_for_operation(
    const char *operation)
{
    if (!operation || !operation[0])
        return NULL;
    for (size_t i = 0; i < sizeof(g_probe_cases) /
                            sizeof(g_probe_cases[0]); i++)
        if (strcmp(operation, g_probe_cases[i].operation) == 0)
            return &g_probe_cases[i];
    return NULL;
}

const struct zcl_hotswap_probe_case *hotswap_module_probe_case(
    const char *source_tu)
{
    if (!source_tu || !source_tu[0])
        return NULL;
    for (size_t i = 0; i < PROBE_COUNT; i++) {
        if (strcmp(source_tu, g_probes[i].source) == 0)
            return hotswap_probe_case_for_operation(g_probes[i].probe);
    }
    return NULL;
}

const char *hotswap_module_probe_leaf(const char *source_tu)
{
    const struct zcl_hotswap_probe_case *probe =
        hotswap_module_probe_case(source_tu);
    return probe ? probe->operation : NULL;
}

/* ── the resident's sealed-core SECTION table ──────────────────────────────
 * Compiled from hotswap/core_seal_sections.h, which is generated from the
 * SECTION/TREE lines of core/MANIFEST.sha3 by `make core-seal-sections`. The
 * SAME X-macro expansion builds the module-side table in
 * ZCL_HOTSWAP_MODULE_LEAVES, so the two halves cannot disagree in shape — only
 * in CONTENT, which is exactly the disagreement admission is here to catch. */
static const struct zcl_hotswap_core_section g_core_sections[] = {
    ZCL_CORE_SEAL_SECTION_ROWS
};
#define CORE_SECTION_COUNT (sizeof(g_core_sections) / sizeof(g_core_sections[0]))

static const struct zcl_hotswap_core_sections g_core_sections_self = {
    .tree = ZCL_CORE_SEAL_TREE,
    .count = (uint32_t)CORE_SECTION_COUNT,
    .sections = g_core_sections,
};

const struct zcl_hotswap_core_sections *hotswap_core_sections_self(void)
{
    return &g_core_sections_self;
}

const char *hotswap_core_section_digest(const char *path)
{
    if (!path || !path[0])
        return NULL;
    for (size_t i = 0; i < CORE_SECTION_COUNT; i++)
        if (strcmp(path, g_core_sections[i].path) == 0)
            return g_core_sections[i].digest;
    return NULL;
}

const char *hotswap_core_seal_tree(void)
{
    return ZCL_CORE_SEAL_TREE;
}

static void act_copy(char *dst, size_t cap, const char *src)
{
    if (!dst || cap == 0)
        return;
    snprintf(dst, cap, "%s", src ? src : "");
}

/* Exact 64-char lowercase-hex, no shorter and no longer. A digest that is not
 * this shape never gets compared — it is refused outright. */
static bool is_seal_digest(const char *hex)
{
    if (!hex)
        return false;
    size_t n = 0;
    for (; hex[n]; n++) {
        if (n >= 64)
            return false;
        char c = hex[n];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return n == 64;
}

/* ── THE SECTION DECLARATION CHECK (purely ADDITIVE to the ROOT pin) ───────
 *
 * The ROOT pin (module_consensus_pin_ok, dlsym path) and the pre-map ELF probe
 * both still compare ZCL_CORE_SEAL_ROOT and are UNCHANGED. This adds, for a
 * module that has been dlsym'd into a struct:
 *
 *   - TREE must equal the resident's ZCL_CORE_SEAL_TREE (the same 70 sealed
 *     files, folded in lib/codeindex's source-Merkle dialect instead of the
 *     flat ROOT fold — a second opinion in a different hash structure);
 *   - every SECTION the module declares must be a section this resident HAS,
 *     and its digest must equal the resident's for that path. A section the
 *     resident does not have is refused, never ignored;
 *   - a section declared twice is refused (a duplicate row could otherwise
 *     hide a mismatched second entry behind a matching first one).
 *
 * Nothing here can admit a module the old code refused: every module still has
 * to clear ROOT first, and this only adds ways to be refused. */
static bool module_sections_ok(const struct zcl_hotswap_module *module,
                               char *stage, size_t stage_cap,
                               char *why, size_t why_cap)
{
    const struct zcl_hotswap_core_sections *cs = module->core_sections;
    act_copy(stage, stage_cap, "sections");
    if (!cs || !cs->sections || cs->count == 0) {
        act_copy(why, why_cap,
                 "module declares no sealed-core sections — built before the "
                 "section declaration existed; rebuild it with "
                 "'make hotswap-module-so'");
        return false;
    }
    if (cs->count > ZCL_HOTSWAP_MODULE_MAX_SECTIONS) {
        if (why && why_cap)
            snprintf(why, why_cap,
                     "module declares %u sealed-core sections, ceiling is %u",
                     cs->count, ZCL_HOTSWAP_MODULE_MAX_SECTIONS);
        return false;
    }
    if (!is_seal_digest(cs->tree)) {
        act_copy(why, why_cap,
                 "module's sealed-core TREE is not 64 lowercase hex");
        return false;
    }
    if (strcmp(cs->tree, ZCL_CORE_SEAL_TREE) != 0) {
        if (why && why_cap)
            snprintf(why, why_cap,
                     "sealed-core TREE mismatch: artifact=%.64s resident=%s "
                     "(the module was compiled against a different sealed core;"
                     " rebuild it)",
                     cs->tree, ZCL_CORE_SEAL_TREE);
        return false;
    }
    for (uint32_t i = 0; i < cs->count; i++) {
        const char *path = cs->sections[i].path;
        const char *digest = cs->sections[i].digest;
        if (!path || !path[0] || !is_seal_digest(digest)) {
            if (why && why_cap)
                snprintf(why, why_cap,
                         "declared section %u has an empty path or a malformed "
                         "digest", i);
            return false;
        }
        for (uint32_t j = 0; j < i; j++) {
            if (cs->sections[j].path && strcmp(path, cs->sections[j].path) == 0) {
                if (why && why_cap)
                    snprintf(why, why_cap,
                             "sealed-core section '%s' is declared twice", path);
                return false;
            }
        }
        const char *host = hotswap_core_section_digest(path);
        if (!host) {
            if (why && why_cap)
                snprintf(why, why_cap,
                         "module declares sealed-core section '%s', which this "
                         "resident's sealed core does not have", path);
            return false;
        }
        if (strcmp(digest, host) != 0) {
            if (why && why_cap)
                snprintf(why, why_cap,
                         "sealed-core section '%s' mismatch: artifact=%.64s "
                         "resident=%s (rebuild the module)",
                         path, digest, host);
            return false;
        }
    }
    if (stage && stage_cap) stage[0] = '\0';
    return true;
}

bool hotswap_module_admit(const struct zcl_hotswap_module *module,
                          char *stage, size_t stage_cap,
                          char *why, size_t why_cap)
{
    if (stage && stage_cap) stage[0] = '\0';
    if (why && why_cap) why[0] = '\0';
    if (!module) {
        act_copy(stage, stage_cap, "abi");
        act_copy(why, why_cap, "null module");
        return false;
    }
    if (module->abi_version != ZCL_HOTSWAP_MODULE_ABI_V3) {
        act_copy(stage, stage_cap, "abi");
        if (why && why_cap)
            snprintf(why, why_cap,
                     "module abi_version %u != required %u (rebuild the module "
                     "against the current hotswap_module.h)",
                     module->abi_version, ZCL_HOTSWAP_MODULE_ABI_V3);
        return false;
    }
    /* The sealed-core SECTION + TREE declaration, verified immediately after
     * the version stamp and BEFORE any other property of the module is
     * considered. A v2 struct is shorter than v3, so `core_sections` is only
     * safe to read once abi_version has proven the layout — which is why this
     * block sits here and not earlier. */
    if (!module_sections_ok(module, stage, stage_cap, why, why_cap))
        return false;
    if (!module->source_tu || !module->source_tu[0] || !module->leaves ||
        !module->self_test || module->leaf_count == 0) {
        act_copy(stage, stage_cap, "fields");
        act_copy(why, why_cap,
                 "module fields incomplete (source_tu/leaves/leaf_count/self_test)");
        return false;
    }
    if (module->leaf_count > ZCL_HOTSWAP_MODULE_MAX_LEAVES) {
        act_copy(stage, stage_cap, "capacity");
        if (why && why_cap)
            snprintf(why, why_cap,
                     "module declares %u leaves, ceiling is %u (one batch "
                     "replace must carry them all)",
                     module->leaf_count, ZCL_HOTSWAP_MODULE_MAX_LEAVES);
        return false;
    }
    for (uint32_t i = 0; i < module->leaf_count; i++) {
        if (!module->leaves[i].name || !module->leaves[i].name[0] ||
            !module->leaves[i].fn) {
            act_copy(stage, stage_cap, "fields");
            if (why && why_cap)
                snprintf(why, why_cap,
                         "leaf %u has an empty name or NULL handler", i);
            return false;
        }
    }

    const char *allowed = swappable_leaves_for_source(module->source_tu);
    if (!allowed) {
        act_copy(stage, stage_cap, "allowlist");
        if (why && why_cap)
            snprintf(why, why_cap,
                     "source '%s' is not on the swappable shape-leaf allowlist",
                     module->source_tu);
        return false;
    }

    for (uint32_t i = 0; i < module->leaf_count; i++) {
        const char *leaf = module->leaves[i].name;
        if (!leaf_list_contains(allowed, leaf)) {
            act_copy(stage, stage_cap, "allowlist");
            if (why && why_cap)
                snprintf(why, why_cap,
                         "leaf '%s' is not on the swappable allowlist for '%s'",
                         leaf, module->source_tu);
            return false;
        }
        for (uint32_t j = 0; j < i; j++) {
            if (strcmp(leaf, module->leaves[j].name) == 0) {
                act_copy(stage, stage_cap, "duplicate");
                if (why && why_cap)
                    snprintf(why, why_cap,
                             "leaf '%s' is declared twice in one module", leaf);
                return false;
            }
        }
    }

    /* The declared probe leaf must exist for this file AND be one of the
     * leaves this module actually re-points; otherwise probe-before-publish
     * would validate code the module never installs. */
    const char *probe = hotswap_module_probe_leaf(module->source_tu);
    if (!probe || !probe[0]) {
        act_copy(stage, stage_cap, "probe");
        if (why && why_cap)
            snprintf(why, why_cap,
                     "source '%s' declares no probe leaf in "
                     "config/hotswap_eligible.def", module->source_tu);
        return false;
    }
    bool probe_exported = false;
    for (uint32_t i = 0; i < module->leaf_count && !probe_exported; i++)
        probe_exported = strcmp(module->leaves[i].name, probe) == 0;
    if (!probe_exported) {
        act_copy(stage, stage_cap, "probe");
        if (why && why_cap)
            snprintf(why, why_cap,
                     "module does not export its declared probe leaf '%s'",
                     probe);
        return false;
    }

    char st_err[192] = {0};
    if (!module->self_test(st_err, sizeof(st_err))) {
        act_copy(stage, stage_cap, "self_test");
        act_copy(why, why_cap,
                 st_err[0] ? st_err : "module self_test returned false");
        return false;
    }
    return true;
}

/* ── activation flag + gate (pure; compiled in every build) ─────────────── */
static _Atomic bool g_activate_flag = false;

void hotswap_set_activate_flag(bool enabled)
{
    atomic_store_explicit(&g_activate_flag, enabled, memory_order_release);
}

bool hotswap_activate_flag(void)
{
    return atomic_load_explicit(&g_activate_flag, memory_order_acquire);
}

static bool env_opt_in(void)
{
    const char *v = getenv("ZCL_HOTSWAP_ACTIVATE");
    return v && strcmp(v, "1") == 0;
}

static bool dir_equals(const char *a, const char *b)
{
    if (!a || !a[0] || !b || !b[0])
        return false;
#if defined(_WIN32)
    /* Native activation is refused below before this comparison can grant
     * authority. Do not approximate canonical identity with string folding. */
    return false;
#else
    char ra[PATH_MAX], rb[PATH_MAX];
    const char *pa = realpath(a, ra) ? ra : a;
    const char *pb = realpath(b, rb) ? rb : b;
    size_t la = strlen(pa), lb = strlen(pb);
    if (la && pa[la - 1] == '/') la--;
    if (lb && pb[lb - 1] == '/') lb--;
    return la == lb && strncmp(pa, pb, la) == 0;
#endif
}

static bool datadir_is_canonical(const char *datadir)
{
    if (!datadir || !datadir[0])
        return false;
    const char *home = getenv("HOME");
    if (!home || home[0] != '/')
        return false;
    char canonical[PATH_MAX];
    snprintf(canonical, sizeof(canonical), "%s/.zclassic-c23", home);
    return dir_equals(datadir, canonical);
}

bool hotswap_activation_authorized(const char *resolved_datadir,
                                   char *why, size_t why_sz)
{
    if (why && why_sz)
        why[0] = '\0';
#if defined(_WIN32)
    (void)resolved_datadir;
    if (why && why_sz)
        snprintf(why, why_sz,
                 "activation refused: native Windows module loading awaits "
                 "PE import validation and immutable directory staging");
    return false;
#endif
    if (!hotswap_activate_flag()) {
        if (why) snprintf(why, why_sz,
            "activation refused: -hotswap-activate flag is not set");
        return false;
    }
    if (!env_opt_in()) {
        if (why) snprintf(why, why_sz,
            "activation refused: ZCL_HOTSWAP_ACTIVATE=1 is not set");
        return false;
    }
    if (datadir_is_canonical(resolved_datadir)) {
        if (why) snprintf(why, why_sz,
            "activation refused on the canonical datadir ~/.zclassic-c23 "
            "(canonical activation stays behind the owner's Phase-3 ritual)");
        return false;
    }
    if (!hotswap_datadir_is_dev(resolved_datadir)) {
        if (why) snprintf(why, why_sz,
            "activation requires the exact dev datadir ~/.zclassic-c23-dev, got '%s'",
            resolved_datadir ? resolved_datadir : "");
        return false;
    }
    return true;
}

/* ── activation telemetry state (written only on the dev activate path) ──── */
#define HOTSWAP_ACT_MAX_SLOTS 32

/* The datadir a slot's live image was admitted under, kept so a rollback can
 * re-run the SAME authorization the forward swap ran instead of inventing a
 * looser one. A resident node has exactly one datadir for its whole life, so
 * this is a record, not a policy input. Sized well past
 * `$HOME/.zclassic-c23-dev`; a path that does not fit is stored truncated and
 * then FAILS the dev-datadir re-check at rollback time, which is the safe
 * direction. */
#define HOTSWAP_ACT_DATADIR_MAX 512

/* Longest canonical leaf path in config/hotswap_swappable.def is well under
 * half of this; a name that does not fit is refused as untrackable, and an
 * untrackable leaf pins its image mapped forever (the safe direction). */
#define HOTSWAP_LEAF_NAME_MAX 64

/* The leaf paths ONE image published, captured at its commit. This is what the
 * reference proof is evaluated against when that image becomes a retirement
 * candidate — never re-read from the module struct, which lives inside the
 * mapping we are deciding whether to unmap. */
struct hotswap_leafset {
    uint32_t count;
    bool trackable;          /* false => a name did not fit; never unmap */
    char name[ZCL_HOTSWAP_MODULE_MAX_LEAVES][HOTSWAP_LEAF_NAME_MAX];
};

struct hotswap_act_slot {
    char source[256];        /* one slot per swappable source TU */
    void *handle;            /* currently-live module .so for this source */
    int artifact_fd;
    char artifact_sha256[65];
    uint32_t generation;
    uint32_t leaf_count;
    time_t activated_at;
    uint64_t swaps;
    bool in_use;
    char datadir[HOTSWAP_ACT_DATADIR_MAX];
    /* The leaves the CURRENTLY LIVE image published, and the generation the
     * registry gave that publish. `generation` above is that same number; it
     * is the ordering authority for every later commit on this source. */
    struct hotswap_leafset leaves;

    /* ── shelf: the depth-1 retained PREDECESSOR IMAGE for this source ────
     * `shelf_fd` is a dup() of the sealed memfd that was live before the
     * current one, taken at commit BEFORE the original descriptor goes to the
     * retire path. Independent descriptor, same sealed inode: the two close()
     * calls never race, and F_SEAL_WRITE guarantees the retained bytes are
     * still the bytes that were admitted. Rollback re-dlopens it, so the shelf
     * costs one descriptor and NOT a retained mapping.
     * `shelf_generation`/`shelf_sha256` describe that image as it was WHEN
     * LIVE, not what is running now. See hotswap/hotswap_shelf.h. */
    int shelf_fd;
    char shelf_sha256[65];
    uint32_t shelf_generation;
    time_t shelf_retired_at;
    bool shelf_present;
    /* A rollback of this source is between its shelf claim and its commit.
     * A plain flag, not a lock: it is only ever read and written under
     * g_act_lock, so it adds no lock-ordering edge at all. */
    bool rollback_in_flight;
};

/* ── LIVE-LEAF OWNERSHIP — the reference proof's only input ────────────────
 *
 * owner_gen is the HIGHEST registry generation that ever published this leaf.
 * That is exactly the merge rule zcl_command_registry_replace_batch() applies
 * when it builds the next snapshot (overwrite the slot with the same path,
 * else append), so an entry answers "whose code does the live snapshot run for
 * this leaf" without depending on the order the loader's own threads arrive
 * in — a MAX is order-independent, which is the whole point.
 *
 * A leaf may appear under exactly ONE source_tu (config/hotswap_swappable.def
 * says so and check-hotswap-swappable-shape enforces it), so leaves partition
 * across sources and only a later publish for the SAME source can displace
 * one.
 *
 * Guarded by g_act_lock. On overflow the table stops being an authority and
 * NOTHING may ever be unmapped again — a permanent latch, because a partial
 * ownership map cannot prove absence. */
#define HOTSWAP_LIVE_LEAF_MAX 256
struct hotswap_live_leaf {
    char name[HOTSWAP_LEAF_NAME_MAX];
    uint32_t owner_gen;
};

struct hotswap_act_event {
    bool present;
    time_t at;
    char source[256];
    char leaves[512];
    uint32_t leaf_count;
    char stage[64];
    char error[256];
    bool activated;
    bool ok;
};

static pthread_mutex_t g_act_lock = PTHREAD_MUTEX_INITIALIZER;
static struct hotswap_act_slot g_slots[HOTSWAP_ACT_MAX_SLOTS];
static size_t g_slot_count;
static struct hotswap_act_event g_last_activation;
static struct hotswap_act_event g_last_rejection;
static _Atomic uint64_t g_activation_count;
static _Atomic uint64_t g_rollback_count;
static _Atomic uint64_t g_verify_count;
static _Atomic uint64_t g_probe_reject_count;
static _Atomic uint64_t g_leaves_published;
static _Atomic uint64_t g_dlclose_count;
static _Atomic uint64_t g_retained_mapped_count;
/* DELIBERATELY NOT g_rollback_count. That counter means "an activation was
 * refused and unwound" and is bumped by every act_reject(); this one means "a
 * shelved predecessor image was successfully put back". Folding the two would
 * make an existing telemetry number silently ambiguous. */
static _Atomic uint64_t g_shelf_rollback_count;
static _Atomic uint64_t g_shelf_dup_fail_count;
/* A commit whose registry generation was NOT newer than the one already
 * recorded for its source: the publish order and the loader's arrival order
 * disagreed. See hotswap/hotswap_shelf.h. */
static _Atomic uint64_t g_stale_commit_count;
/* Retirement candidates kept mapped because a leaf they published is still
 * owned by their own generation. Each one is a use-after-free that did not
 * happen. */
static _Atomic uint64_t g_reference_hold_count;

static struct hotswap_live_leaf g_live_leaf[HOTSWAP_LIVE_LEAF_MAX];
static size_t g_live_leaf_count;      /* guarded by g_act_lock */
static bool g_live_leaf_overflow;     /* latched; guarded by g_act_lock */

uint64_t hotswap_stale_commit_count(void)
{
    return atomic_load_explicit(&g_stale_commit_count, memory_order_relaxed);
}

uint64_t hotswap_reference_hold_count(void)
{
    return atomic_load_explicit(&g_reference_hold_count, memory_order_relaxed);
}

static void event_json(struct json_value *obj, const struct hotswap_act_event *ev)
{
    json_set_object(obj);
    json_push_kv_bool(obj, "present", ev->present);
    if (!ev->present)
        return;
    json_push_kv_int(obj, "at", (int64_t)ev->at);
    json_push_kv_str(obj, "source", ev->source);
    json_push_kv_str(obj, "leaves", ev->leaves);
    json_push_kv_int(obj, "leaf_count", (int64_t)ev->leaf_count);
    json_push_kv_str(obj, "stage", ev->stage);
    if (ev->error[0])
        json_push_kv_str(obj, "error", ev->error);
    json_push_kv_bool(obj, "activated", ev->activated);
    json_push_kv_bool(obj, "ok", ev->ok);
}

void hotswap_activate_dump_json(struct json_value *out)
{
    if (!out)
        return;
    struct json_value act = {0};
    json_set_object(&act);
    json_push_kv_str(&act, "abi", "zcl.hotswap_module.v3");
    json_push_kv_int(&act, "abi_version", (int64_t)ZCL_HOTSWAP_MODULE_ABI_V3);
    json_push_kv_int(&act, "max_leaves_per_module",
                     (int64_t)ZCL_HOTSWAP_MODULE_MAX_LEAVES);
    /* What a module has to agree with. Reported so an operator can compare an
     * artifact's stamp to the resident's without loading it. */
    json_push_kv_str(&act, "core_seal_root", ZCL_CORE_SEAL_ROOT);
    json_push_kv_str(&act, "core_seal_tree", ZCL_CORE_SEAL_TREE);
    json_push_kv_int(&act, "core_seal_sections", (int64_t)CORE_SECTION_COUNT);
    json_push_kv_bool(&act, "available",
                      hotswap_native_activation_available());
    if (!hotswap_native_activation_available())
        json_push_kv_str(&act, "note", hotswap_native_unavailable_reason());
    bool flag = hotswap_activate_flag();
    bool env = env_opt_in();
    json_push_kv_bool(&act, "activate_flag", flag);
    json_push_kv_bool(&act, "env_opt_in", env);
    /* Containment state: only "armed" once BOTH gates are on; the datadir/
     * canonical check is still applied per-activation. */
    json_push_kv_str(&act, "containment",
                     (flag && env) ? "armed_dev_lane_only" : "verify_only");
    json_push_kv_int(&act, "activation_count",
                     (int64_t)atomic_load(&g_activation_count));
    json_push_kv_int(&act, "verify_only_count",
                     (int64_t)atomic_load(&g_verify_count));
    json_push_kv_int(&act, "rollback_count",
                     (int64_t)atomic_load(&g_rollback_count));
    json_push_kv_int(&act, "probe_reject_count",
                     (int64_t)atomic_load(&g_probe_reject_count));
    json_push_kv_int(&act, "leaves_published",
                     (int64_t)atomic_load(&g_leaves_published));
    json_push_kv_int(&act, "dlclose_count",
                     (int64_t)atomic_load(&g_dlclose_count));
    json_push_kv_int(&act, "retained_mapped_count",
                     (int64_t)atomic_load(&g_retained_mapped_count));
    /* Shelf + retirement-proof visibility. `rollback_count` above is the
     * failed-activation unwind count and keeps its old meaning. */
    json_push_kv_int(&act, "shelf_depth", (int64_t)ZCL_HOTSWAP_SHELF_DEPTH);
    json_push_kv_int(&act, "shelf_rollback_count",
                     (int64_t)atomic_load(&g_shelf_rollback_count));
    json_push_kv_int(&act, "shelf_dup_fail_count",
                     (int64_t)atomic_load(&g_shelf_dup_fail_count));
    json_push_kv_int(&act, "stale_commit_count",
                     (int64_t)atomic_load(&g_stale_commit_count));
    json_push_kv_int(&act, "reference_hold_count",
                     (int64_t)atomic_load(&g_reference_hold_count));

    struct json_value allow = {0};
    json_set_array(&allow);
    for (size_t i = 0; i < SWAPPABLE_COUNT; i++) {
        struct json_value row = {0};
        json_set_object(&row);
        json_push_kv_str(&row, "source", g_swappable[i].source);
        json_push_kv_str(&row, "leaves", g_swappable[i].leaves);
        const char *probe = hotswap_module_probe_leaf(g_swappable[i].source);
        json_push_kv_str(&row, "probe_leaf", probe ? probe : "");
        json_push_back(&allow, &row);
        json_free(&row);
    }
    json_push_kv(&act, "swappable_allowlist", &allow);
    json_free(&allow);

    pthread_mutex_lock(&g_act_lock);
    struct json_value slots = {0};
    json_set_array(&slots);
    size_t shelved = 0;
    for (size_t i = 0; i < g_slot_count; i++) {
        if (!g_slots[i].in_use)
            continue;
        if (g_slots[i].shelf_present)
            shelved++;
        struct json_value s = {0};
        json_set_object(&s);
        json_push_kv_str(&s, "source", g_slots[i].source);
        json_push_kv_int(&s, "generation", (int64_t)g_slots[i].generation);
        json_push_kv_int(&s, "leaf_count", (int64_t)g_slots[i].leaf_count);
        json_push_kv_str(&s, "artifact_sha256", g_slots[i].artifact_sha256);
        json_push_kv_int(&s, "activated_at", (int64_t)g_slots[i].activated_at);
        json_push_kv_int(&s, "swaps", (int64_t)g_slots[i].swaps);
        /* The shelved PREDECESSOR of this slot, if any: what a rollback of
         * this source would put back. Absent fields when nothing is shelved,
         * so "shelf_present": false is never accompanied by a stale digest. */
        json_push_kv_bool(&s, "shelf_present", g_slots[i].shelf_present);
        if (g_slots[i].shelf_present) {
            json_push_kv_str(&s, "shelf_artifact_sha256",
                             g_slots[i].shelf_sha256);
            json_push_kv_int(&s, "shelf_generation",
                             (int64_t)g_slots[i].shelf_generation);
            json_push_kv_int(&s, "shelf_retired_at",
                             (int64_t)g_slots[i].shelf_retired_at);
        }
        json_push_back(&slots, &s);
        json_free(&s);
    }
    json_push_kv(&act, "active_slots", &slots);
    json_free(&slots);
    json_push_kv_int(&act, "shelf_entries", (int64_t)shelved);

    struct json_value last_a = {0}, last_r = {0};
    event_json(&last_a, &g_last_activation);
    event_json(&last_r, &g_last_rejection);
    pthread_mutex_unlock(&g_act_lock);
    json_push_kv(&act, "last_activation", &last_a);
    json_push_kv(&act, "last_rejection", &last_r);
    json_free(&last_a);
    json_free(&last_r);

    json_push_kv(out, "activation", &act);
    json_free(&act);
}

static void record_event(struct hotswap_act_event *ev,
                         const struct hotswap_activate_report *report,
                         const char *stage, const char *error,
                         bool activated, bool ok)
{
    pthread_mutex_lock(&g_act_lock);
    memset(ev, 0, sizeof(*ev));
    ev->present = true;
    ev->at = platform_time_wall_time_t();
    act_copy(ev->source, sizeof(ev->source), report->source_tu);
    act_copy(ev->leaves, sizeof(ev->leaves), report->leaves);
    ev->leaf_count = report->leaf_count;
    act_copy(ev->stage, sizeof(ev->stage), stage);
    act_copy(ev->error, sizeof(ev->error), error);
    ev->activated = activated;
    ev->ok = ok;
    pthread_mutex_unlock(&g_act_lock);
}

/* Populate the report, log, record the rejection, count it, and return false.
 * Any dlopen/fd cleanup is the caller's, done BEFORE calling this. */
static bool act_reject(struct hotswap_activate_report *report,
                       const char *stage, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(report->error, sizeof(report->error), fmt, ap);
    va_end(ap);
    act_copy(report->stage, sizeof(report->stage), stage);
    report->ok = false;
    report->rolled_back = true;
    atomic_fetch_add_explicit(&g_rollback_count, 1, memory_order_relaxed);
    record_event(&g_last_rejection, report, stage, report->error, false, false);
    LOG_WARN("hotswap.activate", "reject stage=%s: %s", stage, report->error);
    return false;
}

/* Fill report->leaves / leaf_count / handler_name from an admitted module. */
static void report_describe_leaves(struct hotswap_activate_report *report,
                                   const struct zcl_hotswap_module *mod)
{
    report->leaf_count = mod->leaf_count;
    act_copy(report->handler_name, sizeof(report->handler_name),
             mod->leaves[0].name);
    size_t used = 0;
    report->leaves[0] = '\0';
    for (uint32_t i = 0; i < mod->leaf_count; i++) {
        int n = snprintf(report->leaves + used, sizeof(report->leaves) - used,
                         "%s%s", i ? "," : "", mod->leaves[i].name);
        if (n < 0 || (size_t)n >= sizeof(report->leaves) - used)
            break;              /* clipped; report->leaf_count stays exact */
        used += (size_t)n;
    }
}

bool hotswap_module_publish(const struct zcl_hotswap_module *module,
                            bool request_activate,
                            const struct hotswap_publish_hooks *hooks,
                            struct hotswap_activate_report *report)
{
    if (!report)
        return false;
    report->ok = false;
    report->activated = false;
    report->probed = false;
    report->verify_only = !request_activate;
    if (module && module->abi_version == ZCL_HOTSWAP_MODULE_ABI_V3 &&
        module->source_tu)
        act_copy(report->source_tu, sizeof(report->source_tu),
                 module->source_tu);

    hotswap_commit_batch_cb commit_cb = hooks ? hooks->commit : NULL;
    hotswap_probe_leaf_cb probe_cb = hooks ? hooks->probe : NULL;
    void *cb_ctx = hooks ? hooks->ctx : NULL;

    /* ABI version + required fields + leaf ceiling + the swappable file/leaf
     * allowlist + intra-module leaf uniqueness + the declared probe leaf +
     * module self_test, all in one pure gauntlet. Any failure => refuse
     * LOUDLY, ZERO leaves published, every resident handler untouched. */
    char stage[64] = {0}, why[256] = {0};
    if (!hotswap_module_admit(module, stage, sizeof(stage), why, sizeof(why)))
        return act_reject(report, stage[0] ? stage : "abi", "%s", why);
    report_describe_leaves(report, module);

    const char *probe_leaf = hotswap_module_probe_leaf(module->source_tu);
    act_copy(report->probe_leaf, sizeof(report->probe_leaf), probe_leaf);
    zcl_hotswap_handler_fn probe_fn = NULL;
    for (uint32_t i = 0; i < module->leaf_count && !probe_fn; i++) {
        if (strcmp(module->leaves[i].name, probe_leaf) == 0)
            probe_fn = module->leaves[i].fn;
    }

    /* PROBE BEFORE PUBLISH. A module asserting its own health is
     * self-certification; this dispatches the DECLARED probe leaf against the
     * registry's public spec/input-validation/reply contract and checks the
     * reply against that leaf's declared output schema. Publishing without it
     * is refused outright. */
    if (probe_cb) {
        why[0] = '\0';
        if (!probe_cb(cb_ctx, probe_leaf, probe_fn, why, sizeof(why))) {
            atomic_fetch_add_explicit(&g_probe_reject_count, 1,
                                      memory_order_relaxed);
            return act_reject(report, "probe", "probe leaf '%s' failed: %s",
                              probe_leaf,
                              why[0] ? why
                                     : "reply did not match its declared schema");
        }
        report->probed = true;
    } else if (request_activate) {
        return act_reject(report, "probe",
                          "no probe callback supplied; publishing without a "
                          "probe-before-publish check is refused");
    }

    if (!request_activate) {
        report->ok = true;
        report->verify_only = true;
        act_copy(report->stage, sizeof(report->stage), "verified");
        atomic_fetch_add_explicit(&g_verify_count, 1, memory_order_relaxed);
        record_event(&g_last_activation, report, "verified", "", false, true);
        LOG_INFO("hotswap.activate",
                 "verify-only OK source=%s leaves=%u (not activated)",
                 report->source_tu, report->leaf_count);
        return true;
    }

    if (!commit_cb)
        return act_reject(report, "commit",
                          "no registry commit callback supplied");
    uint32_t gen = 0;
    why[0] = '\0';
    if (!commit_cb(cb_ctx, module->leaves, (size_t)module->leaf_count, &gen,
                   why, sizeof(why))) {
        /* Rollback: the registry never published, old handlers untouched. */
        return act_reject(report, "commit", "%s",
                          why[0] ? why : "registry commit failed");
    }

    report->ok = true;
    report->activated = true;
    report->verify_only = false;
    report->generation = gen;
    act_copy(report->stage, sizeof(report->stage), "activated");
    atomic_fetch_add_explicit(&g_activation_count, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&g_leaves_published, module->leaf_count,
                              memory_order_relaxed);
    record_event(&g_last_activation, report, "activated", "", true, true);
    LOG_INFO("hotswap.activate",
             "activated source=%s leaves=%u (%s) gen=%u",
             report->source_tu, report->leaf_count, report->leaves, gen);
    return true;
}

/* ── shelf readers ────────────────────────────────────────────────────────
 * Pure table reads, compiled in EVERY build. Only the dev activation core can
 * ever put an image on the shelf, so in a release binary these correctly and
 * quietly report an empty shelf rather than being absent.
 *
 * Both take g_act_lock. That is safe for a status/CLI caller by construction:
 * command dispatch resolves its handler from a lock-free snapshot pointer and
 * never touches this mutex, so nothing held here can add dispatch latency. */
static void shelf_entry_from_slot_locked(struct hotswap_shelf_entry *out,
                                         const struct hotswap_act_slot *slot)
{
    memset(out, 0, sizeof(*out));
    out->present = true;
    act_copy(out->source_tu, sizeof(out->source_tu), slot->source);
    act_copy(out->artifact_sha256, sizeof(out->artifact_sha256),
             slot->shelf_sha256);
    out->generation = slot->shelf_generation;
    out->retired_at = slot->shelf_retired_at;
}

size_t hotswap_shelf_list(struct hotswap_shelf_entry *out, size_t cap)
{
    size_t found = 0;
    pthread_mutex_lock(&g_act_lock);
    for (size_t i = 0; i < g_slot_count; i++) {
        if (!g_slots[i].in_use || !g_slots[i].shelf_present)
            continue;
        if (out && found < cap)
            shelf_entry_from_slot_locked(&out[found], &g_slots[i]);
        found++;        /* the RETURN is the true count, not what was written */
    }
    pthread_mutex_unlock(&g_act_lock);
    return found;
}

bool hotswap_shelf_peek(const char *source_tu, struct hotswap_shelf_entry *out)
{
    if (out)
        memset(out, 0, sizeof(*out));
    if (!source_tu || !source_tu[0])
        return false;
    bool found = false;
    pthread_mutex_lock(&g_act_lock);
    for (size_t i = 0; i < g_slot_count && !found; i++) {
        if (!g_slots[i].in_use || !g_slots[i].shelf_present ||
            strcmp(g_slots[i].source, source_tu) != 0)
            continue;
        if (out)
            shelf_entry_from_slot_locked(out, &g_slots[i]);
        found = true;
    }
    pthread_mutex_unlock(&g_act_lock);
    return found;
}

/* Find (or, if activating a not-yet-seen source, add) the per-source slot.
 * ASSUMES g_act_lock held. Returns NULL only when the fixed table is full.
 *
 * Slots exist ONLY on a real image commit, and that is deliberate.
 * hotswap_module_publish() — the pure, always-compiled admit/probe/commit
 * gauntlet, which any caller can drive with a fabricated struct — never
 * creates or touches a slot, so it can never put anything on the shelf. That
 * is what keeps the shelf from becoming a second, ungated way to publish live
 * handlers: everything on it is a sealed image that has to be re-admitted
 * from scratch. */
static struct hotswap_act_slot *slot_for_source_locked(const char *source)
{
    for (size_t i = 0; i < g_slot_count; i++) {
        if (g_slots[i].in_use && strcmp(g_slots[i].source, source) == 0)
            return &g_slots[i];
    }
    if (g_slot_count >= HOTSWAP_ACT_MAX_SLOTS)
        return NULL;
    struct hotswap_act_slot *slot = &g_slots[g_slot_count++];
    memset(slot, 0, sizeof(*slot));
    slot->artifact_fd = -1;
    slot->shelf_fd = -1;        /* shelf_present=false already says "empty" */
    act_copy(slot->source, sizeof(slot->source), source);
    slot->in_use = true;
    return slot;
}

/* ── leaf sets and the live-leaf ownership table ──────────────────────────
 *
 * A leafset is captured ONCE, at the image's own commit, from the module
 * struct while that struct is still mapped. It is never re-read later: the
 * whole question at retire time is whether that mapping may be released, and
 * reading the answer's inputs out of the thing being released is exactly the
 * mistake this file exists to avoid. */
static void leafset_capture(struct hotswap_leafset *out,
                            const struct zcl_hotswap_leaf *leaves,
                            uint32_t leaf_count)
{
    memset(out, 0, sizeof(*out));
    out->trackable = true;
    if (!leaves || leaf_count == 0 ||
        leaf_count > ZCL_HOTSWAP_MODULE_MAX_LEAVES) {
        out->trackable = false;
        return;
    }
    for (uint32_t i = 0; i < leaf_count; i++) {
        const char *nm = leaves[i].name;
        if (!nm || !nm[0] || strlen(nm) >= HOTSWAP_LEAF_NAME_MAX) {
            out->trackable = false;
            return;
        }
        act_copy(out->name[out->count], HOTSWAP_LEAF_NAME_MAX, nm);
        out->count++;
    }
}

/* ASSUMES g_act_lock held. Records that `gen` published every leaf in `ls`.
 * owner_gen is a MAX, so the result does not depend on the order concurrent
 * committers reach this function — only on the generations the registry
 * handed out, which is the order that actually decides whose code runs. */
static void live_leaf_publish_locked(const struct hotswap_leafset *ls,
                                     uint32_t gen)
{
    if (!ls->trackable || gen == 0) {
        g_live_leaf_overflow = true;   /* latched: nothing may be unmapped */
        return;
    }
    for (uint32_t i = 0; i < ls->count; i++) {
        size_t k = 0;
        bool found = false;
        for (; k < g_live_leaf_count; k++) {
            if (strcmp(g_live_leaf[k].name, ls->name[i]) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            if (g_live_leaf_count >= HOTSWAP_LIVE_LEAF_MAX) {
                g_live_leaf_overflow = true;
                return;
            }
            k = g_live_leaf_count++;
            act_copy(g_live_leaf[k].name, HOTSWAP_LEAF_NAME_MAX, ls->name[i]);
            g_live_leaf[k].owner_gen = 0;
        }
        if (gen > g_live_leaf[k].owner_gen)
            g_live_leaf[k].owner_gen = gen;
    }
}

/* THE REFERENCE PROOF. ASSUMES g_act_lock held.
 *
 * True when the live override snapshot may STILL dispatch into this image, so
 * its mapping must not be released. Answers "yes" for anything it cannot
 * prove — an untracked leaf, a generation it never saw, an overflowed table —
 * because a partial ownership map cannot establish absence.
 *
 * Monotone: owner_gen only ever rises, so an image proved unreferenced can
 * never become referenced again. That is what lets the unmap happen outside
 * the lock. */
static bool image_referenced_locked(const struct hotswap_leafset *ls,
                                    uint32_t gen)
{
    if (g_live_leaf_overflow || !ls->trackable || gen == 0)
        return true;
    for (uint32_t i = 0; i < ls->count; i++) {
        bool found = false;
        for (size_t k = 0; k < g_live_leaf_count; k++) {
            if (strcmp(g_live_leaf[k].name, ls->name[i]) != 0)
                continue;
            found = true;
            if (g_live_leaf[k].owner_gen <= gen)
                return true;     /* still ours (or unorderable): keep mapped */
            break;
        }
        if (!found)
            return true;         /* we published it and lost the record */
    }
    return false;
}

/* ── retirement ──────────────────────────────────────────────────────────
 *
 * One candidate: a mapping plus the descriptor and leafset that belong to it.
 * `unmap` is the caller's release function — the loader passes the dynamic
 * loader's, a test passes its own observer — so this whole path compiles in
 * every build and carries no dynamic-loading dependency. */
struct hotswap_retire_candidate {
    void *handle;
    int fd;
    uint32_t generation;
    struct hotswap_leafset leaves;
    hotswap_unmap_fn unmap;
    hotswap_quiesced_cb quiesced_cb;
    void *ctx;
};

/* Pending-retire table: mappings kept because a gate could not be cleared.
 * This exists so the retention is RECLAIMABLE (the escape retries it) instead
 * of being an unbounded silent leak. Bounded: past the cap we still never
 * release an unproven mapping — we just stop tracking it for retry, and the
 * blocker keeps saying so. */
#define HOTSWAP_PENDING_RETIRE_MAX 32
static struct hotswap_retire_candidate g_pending[HOTSWAP_PENDING_RETIRE_MAX];
static size_t g_pending_count;  /* guarded by g_act_lock */

/* Reclaim seam invoked from the blocker escape (outside the registry lock).
 * Returns true only when NOTHING is left retained — the escape refuses to
 * clear the blocker on a partial reclaim.
 *
 * BOTH gates are re-run here, not just the drain one: a mapping retained
 * because the live snapshot still dispatched into it becomes releasable only
 * when a later generation has taken over every one of its leaves. */
static bool hotswap_reclaim_pending(void *unused)
{
    (void)unused;
    /* Only what the release itself needs, so this frame stays a few hundred
     * bytes: a whole candidate is ~4 KB and 32 of them would be a 130 KB stack
     * frame on whatever thread the blocker sweep happens to run on. */
    struct { void *handle; int fd; hotswap_unmap_fn unmap; }
        release[HOTSWAP_PENDING_RETIRE_MAX];
    size_t release_count = 0;

    pthread_mutex_lock(&g_act_lock);
    size_t kept = 0;
    for (size_t i = 0; i < g_pending_count; i++) {
        struct hotswap_retire_candidate *p = &g_pending[i];
        bool drained = p->quiesced_cb ? p->quiesced_cb(p->ctx) : false;
        bool referenced = image_referenced_locked(&p->leaves, p->generation);
        if (drained && !referenced) {
            release[release_count].handle = p->handle;
            release[release_count].fd = p->fd;
            release[release_count].unmap = p->unmap;
            release_count++;
            continue;
        }
        if (kept != i)
            g_pending[kept] = *p;
        kept++;
    }
    g_pending_count = kept;
    bool all_clear = (kept == 0);
    pthread_mutex_unlock(&g_act_lock);

    /* Outside the lock: the release callback is the caller's code, and an
     * unreferenced image can never become referenced again (owner_gen only
     * rises), so nothing can invalidate the decision in between. */
    for (size_t i = 0; i < release_count; i++) {
        if (release[i].unmap)
            release[i].unmap(release[i].handle);
        if (release[i].fd >= 0)
            close(release[i].fd);
        atomic_fetch_add_explicit(&g_dlclose_count, 1, memory_order_relaxed);
        atomic_fetch_sub_explicit(&g_retained_mapped_count, 1,
                                  memory_order_relaxed);
        hotswap_retire_blocker_note_reclaimed();
    }
    return all_clear;
}

bool hotswap_reclaim_retained_now(void)
{
    return hotswap_reclaim_pending(NULL);
}

/* Release a superseded image, but ONLY once both gates are cleared:
 *
 *   DRAIN      no in-flight dispatch is still inside a retired snapshot;
 *   REFERENCE  no leaf this image published is still owned by this image's
 *              own generation, i.e. the live snapshot cannot reach it.
 *
 * On doubt the mapping is KEPT — always memory-safe — but NAMED, and queued
 * for a reclaim retry. The old behaviour kept it mapped behind one LOG_WARN,
 * which at a high swap rate is a mapping + fd leaked per swap with no operator
 * signal; and it ran only the drain gate, which is why a retirement that
 * raced a concurrent publish could release the mapping the live snapshot was
 * still dispatching into. See hotswap/hotswap_shelf.h. */
static void retire_candidate(struct hotswap_retire_candidate *cand)
{
    if (!cand->handle) {
        if (cand->fd >= 0)
            close(cand->fd);
        return;
    }

    bool drained = false;
    if (cand->quiesced_cb) {
        /* ~2 s worst case: cheap sched_yield spin, escalating to a 1 ms sleep. */
        for (int i = 0; i < 20000; i++) {
            if (cand->quiesced_cb(cand->ctx)) { drained = true; break; }
            if (i % 1000 == 999) {
                struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
                nanosleep(&ts, NULL);
            } else {
                sched_yield();
            }
        }
    }

    pthread_mutex_lock(&g_act_lock);
    bool referenced = image_referenced_locked(&cand->leaves, cand->generation);
    bool queued = false;
    if (!(drained && !referenced)) {
        if (g_pending_count < HOTSWAP_PENDING_RETIRE_MAX) {
            g_pending[g_pending_count++] = *cand;
            queued = true;
        }
    }
    pthread_mutex_unlock(&g_act_lock);

    if (drained && !referenced) {
        if (cand->unmap)
            cand->unmap(cand->handle);
        if (cand->fd >= 0)
            close(cand->fd);
        atomic_fetch_add_explicit(&g_dlclose_count, 1, memory_order_relaxed);
        LOG_INFO("hotswap.activate",
                 "retired superseded module image gen=%u after drain and "
                 "reference proof (unmapped)", cand->generation);
        return;
    }

    if (referenced)
        atomic_fetch_add_explicit(&g_reference_hold_count, 1,
                                  memory_order_relaxed);
    atomic_fetch_add_explicit(&g_retained_mapped_count, 1,
                              memory_order_relaxed);
    hotswap_retire_blocker_set_reclaimer(hotswap_reclaim_pending, NULL);
    /* Raise unconditionally, queued or not: an untracked retention is a
     * WORSE fault than a tracked one, so it must not be the quiet case. */
    hotswap_retire_blocker_raise();
    LOG_WARN("hotswap.activate",
             "keeping superseded module image gen=%u mapped (safe leak): "
             "drain=%s live-reference=%s — blocker %s raised, reclaim retry %s",
             cand->generation, drained ? "confirmed" : "UNCONFIRMED",
             referenced ? "STILL PRESENT" : "none",
             HOTSWAP_RETIRE_UNDRAINED_BLOCKER_ID,
             queued ? "queued" : "NOT queued (pending table full)");
}

/* ── THE COMMIT STEP ─────────────────────────────────────────────────────
 * See hotswap/hotswap_shelf.h for the full argument. In short: the registry
 * generation, not this function's arrival order, decides which image is live,
 * and nothing is unmapped without the reference proof above. */
bool hotswap_commit_image(const struct hotswap_commit_image *req)
{
    if (!req || !req->source_tu || !req->source_tu[0]) {
        if (req && req->fd >= 0)
            close(req->fd);
        return false;
    }

    struct hotswap_leafset mine;
    leafset_capture(&mine, req->leaves, req->leaf_count);

    struct hotswap_retire_candidate cand;
    memset(&cand, 0, sizeof(cand));
    cand.fd = -1;
    cand.unmap = req->unmap;
    cand.quiesced_cb = req->hooks ? req->hooks->quiesced : NULL;
    cand.ctx = req->hooks ? req->hooks->ctx : NULL;

    int evicted_shelf_fd = -1;
    bool shelf_dup_failed = false;
    int dup_errno = 0;
    bool stale = false;

    pthread_mutex_lock(&g_act_lock);
    struct hotswap_act_slot *slot = slot_for_source_locked(req->source_tu);
    if (!slot) {
        pthread_mutex_unlock(&g_act_lock);
        /* Committed but untrackable (table full): the caller keeps its own
         * mapping and nothing is retired. */
        atomic_fetch_add_explicit(&g_retained_mapped_count, 1,
                                  memory_order_relaxed);
        LOG_WARN("hotswap.activate",
                 "activation slot table full; keeping module image mapped");
        return false;
    }

    /* Record leaf ownership FIRST and unconditionally. A stale committer's
     * leaves were genuinely published at its generation, and owner_gen is a
     * MAX, so recording it can only ever make a LATER image look referenced —
     * never make an earlier one look free. */
    live_leaf_publish_locked(&mine, req->generation);

    if (req->generation > slot->generation) {
        /* We won the registry race for this source: we are the live image and
         * the slot's previous image is the retirement candidate. */
        cand.handle = slot->handle;
        cand.fd = slot->artifact_fd;
        cand.generation = slot->generation;
        cand.leaves = slot->leaves;

        /* ── SHELVE THE SUPERSEDED IMAGE (depth 1) ─────────────────────────
         * dup() BEFORE the outgoing descriptor becomes the retire candidate's,
         * so the shelf and the retire path own one descriptor each and neither
         * can close the other's. dup() is an fd-table operation with no I/O;
         * nothing on the dispatch path takes g_act_lock, so doing it here
         * cannot add dispatch latency.
         *
         * A dup() failure (EMFILE) must NEVER fail the activation: the swap
         * the operator asked for has already committed. The shelf entry is
         * simply absent — and any entry already there is dropped rather than
         * left describing something that is no longer the immediately previous
         * image, so an entry is never reported present without a descriptor
         * behind it. */
        if (cand.fd >= 0) {
            int dup_fd = dup(cand.fd);
            evicted_shelf_fd = slot->shelf_fd;
            if (dup_fd < 0) {
                dup_errno = errno;
                shelf_dup_failed = true;
                slot->shelf_fd = -1;
                slot->shelf_present = false;
            } else {
                slot->shelf_fd = dup_fd;
                slot->shelf_present = true;
                slot->shelf_generation = slot->generation;
                slot->shelf_retired_at = platform_time_wall_time_t();
                act_copy(slot->shelf_sha256, sizeof(slot->shelf_sha256),
                         slot->artifact_sha256);
            }
        }

        slot->handle = req->handle;
        slot->artifact_fd = req->fd;
        slot->generation = req->generation;
        slot->leaf_count = req->leaf_count;
        slot->leaves = mine;
        slot->activated_at = platform_time_wall_time_t();
        slot->swaps++;
        act_copy(slot->artifact_sha256, sizeof(slot->artifact_sha256),
                 req->artifact_sha256);
        /* Recorded so a rollback re-runs the SAME authorization, never a
         * looser one invented at rollback time. */
        act_copy(slot->datadir, sizeof(slot->datadir), req->resolved_datadir);
    } else {
        /* A NEWER generation for this source is already recorded: the registry
         * superseded US between our publish and this line. Touch neither the
         * slot nor the shelf — both describe the image the registry considers
         * live — and offer OURSELVES as the retirement candidate. */
        stale = true;
        cand.handle = req->handle;
        cand.fd = req->fd;
        cand.generation = req->generation;
        cand.leaves = mine;
    }
    uint32_t slot_generation = slot->generation;   /* read under the lock */
    pthread_mutex_unlock(&g_act_lock);

    /* Depth is 1: the image this shelving displaced is closed, outside the
     * lock. It was reachable only through the entry we just overwrote, and a
     * rollback holding a dup() of it is unaffected. */
    if (evicted_shelf_fd >= 0)
        close(evicted_shelf_fd);
    if (shelf_dup_failed) {
        atomic_fetch_add_explicit(&g_shelf_dup_fail_count, 1,
                                  memory_order_relaxed);
        LOG_WARN("hotswap.activate",
                 "could not shelve the superseded image for %s: dup failed "
                 "errno=%d; the swap stands, but rollback for this source is "
                 "unavailable until the next swap shelves one",
                 req->source_tu, dup_errno);
    }
    if (stale) {
        atomic_fetch_add_explicit(&g_stale_commit_count, 1,
                                  memory_order_relaxed);
        LOG_WARN("hotswap.activate",
                 "commit for %s arrived at generation %u after generation %u "
                 "was already live: the registry superseded this image, so it "
                 "is retired instead of installed",
                 req->source_tu, req->generation, slot_generation);
    }

    retire_candidate(&cand);
    return !stale;
}

void hotswap_activation_reset_for_testing(void)
{
    int close_fds[HOTSWAP_ACT_MAX_SLOTS * 2 + HOTSWAP_PENDING_RETIRE_MAX];
    size_t close_count = 0;

    pthread_mutex_lock(&g_act_lock);
    for (size_t i = 0; i < g_slot_count; i++) {
        if (g_slots[i].artifact_fd >= 0)
            close_fds[close_count++] = g_slots[i].artifact_fd;
        if (g_slots[i].shelf_fd >= 0)
            close_fds[close_count++] = g_slots[i].shelf_fd;
    }
    for (size_t i = 0; i < g_pending_count; i++) {
        if (g_pending[i].fd >= 0)
            close_fds[close_count++] = g_pending[i].fd;
    }
    memset(g_slots, 0, sizeof(g_slots));
    g_slot_count = 0;
    memset(g_pending, 0, sizeof(g_pending));
    g_pending_count = 0;
    memset(g_live_leaf, 0, sizeof(g_live_leaf));
    g_live_leaf_count = 0;
    g_live_leaf_overflow = false;
    pthread_mutex_unlock(&g_act_lock);

    for (size_t i = 0; i < close_count; i++)
        close(close_fds[i]);

    atomic_store(&g_stale_commit_count, 0);
    atomic_store(&g_reference_hold_count, 0);
    atomic_store(&g_shelf_rollback_count, 0);
    atomic_store(&g_shelf_dup_fail_count, 0);
    atomic_store(&g_retained_mapped_count, 0);
    atomic_store(&g_dlclose_count, 0);
}

#ifdef ZCL_DEV_BUILD
#if defined(__linux__) && !defined(_WIN32)

#include <dlfcn.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "crypto/sha256.h"
#include "hotswap/hotswap_artifact_digest.h"
#include "hotswap/hotswap_elf_probe.h"
#include "hotswap/hotswap_sealed_image.h"

static bool artifact_sha256_fd(int fd, char hex_out[65])
{
    if (fd < 0 || !hex_out || lseek(fd, 0, SEEK_SET) < 0)
        return false;
    hex_out[0] = '\0';
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    unsigned char buf[64 * 1024];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) { sha256_write(&ctx, buf, (size_t)n); continue; }
        if (n == 0) break;
        if (errno == EINTR) continue;
        return false;
    }
    if (lseek(fd, 0, SEEK_SET) < 0)
        return false;
    unsigned char digest[SHA256_OUTPUT_SIZE];
    sha256_finalize(&ctx, digest);
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < SHA256_OUTPUT_SIZE; i++) {
        hex_out[i * 2] = hex[digest[i] >> 4];
        hex_out[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    hex_out[64] = '\0';
    return true;
}

bool zcl_hotswap_hotfork_visit_so(
    const char *so_path, const char *expected_sha256,
    zcl_hotfork_capsule_visit_fn visit, void *ctx,
    char actual_sha256[65])
{
    if (!so_path || !expected_sha256 || strlen(expected_sha256) != 64 ||
        !visit || !actual_sha256)
        return false;
    actual_sha256[0] = '\0';
    int fd = open(so_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        !artifact_sha256_fd(fd, actual_sha256) ||
        strcmp(actual_sha256, expected_sha256) != 0) {
        if (fd >= 0) (void)close(fd);
        return false;
    }
    char pinned[PATH_MAX];
    if (!platform_fd_path(pinned, sizeof(pinned), fd, NULL)) {
        (void)close(fd);
        return false;
    }
#if defined(__APPLE__)
    /* On this host the pinned name is a /dev/fd path rather than an inode
     * pin. Refuse unless it still resolves to the exact inode whose bytes
     * were just hash-verified — the same identity discipline as
     * execve-by-fd. The remaining window between resolve and dlopen is
     * inherent to any name-based dlopen and is one reason pinned hosts run
     * the Linux semantics only. */
    struct stat current;
    if (stat(pinned, &current) != 0 ||
        current.st_dev != st.st_dev || current.st_ino != st.st_ino) {
        (void)close(fd);
        return false;
    }
#endif
    void *handle = dlopen(pinned, RTLD_LAZY | RTLD_LOCAL);
    if (!handle) {
        (void)close(fd);
        return false;
    }
    dlerror();
    const struct zcl_hotfork_capsule_v1 *capsule =
        dlsym(handle, ZCL_HOTFORK_CAPSULE_SYMBOL);
    const char *sym_error = dlerror();
    bool ok = !sym_error && capsule && visit(capsule, ctx);
    (void)dlclose(handle);
    (void)close(fd);
    return ok;
}

/* ── the consensus pin ─────────────────────────────────────────────────────
 *
 * A module .so is compiled from ONE shape-leaf TU; the resident supplies every
 * other body it calls. The admit gauntlet below checks abi_version, fields,
 * capacity, the allowlist row, duplicates and the probe leaf — six stages, none
 * of which is about the consensus layer the two halves share. Nothing was.
 *
 * That matters because the sealed core ships `static inline` bodies, consensus
 * arithmetic among them (consensus_last_founders_reward_height(),
 * consensus_subsidy_slow_start_shift(), the compact-size sizing in
 * core/serialize.h). A controller that includes one of those headers compiles a
 * PRIVATE COPY into its .so. Re-cut the seal, rebuild the node, and a module
 * built before the change still mounted, still passed all six stages, and still
 * ran its stale copy — a cloned ledger reached through a dlopen.
 *
 * So the artifact carries the ZCL_CORE_SEAL_ROOT its compile saw, and the
 * resident compares it to its own before admitting anything. dlopen may have
 * run ELF constructors already, so this prevents stale leaf publication, not
 * arbitrary module execution. The pin is the
 * SEAL ROOT, deliberately, not a whole-tree build id: editing a controller must
 * not invalidate a module — that is the fast loop — while editing consensus
 * must invalidate every one of them.
 *
 * A missing symbol is a rejection, not a pass. Absence is exactly what an
 * artifact built before the pin existed looks like, and those are the ones
 * whose consensus vintage cannot be established. */
static bool module_consensus_pin_ok(void *handle, char *stage, size_t stage_cap,
                                    char *err, size_t err_cap)
{
    const char *host = ZCL_CORE_SEAL_ROOT;
    if (strlen(host) != 64) {
        act_copy(stage, stage_cap, "consensus");
        (void)snprintf(err, err_cap,
                       "resident has no sealed-core ROOT to pin against "
                       "(run 'make core-seal')");
        return false;
    }
    (void)dlerror();
    const char *mod =
        (const char *)dlsym(handle, ZCL_HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL);
    const char *sym_err = dlerror();
    if (!mod || sym_err) {
        act_copy(stage, stage_cap, "consensus");
        (void)snprintf(err, err_cap,
                       "artifact exports no %s — built before the consensus "
                       "pin existed; rebuild it",
                       ZCL_HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL);
        return false;
    }
    if (strncmp(mod, host, 65) != 0) {
        act_copy(stage, stage_cap, "consensus");
        (void)snprintf(err, err_cap,
                       "sealed-core ROOT mismatch: artifact=%.64s resident=%s "
                       "(the module was compiled against a different consensus "
                       "core; rebuild it)",
                       mod, host);
        return false;
    }
    return true;
}

/* How a module mapping is released. The commit/retire core is compiled in
 * every build and never names the dynamic loader; this is the one place that
 * does, and it exists only here in the dev region. */
static void dev_unmap_module(void *handle)
{
    if (handle)
        dlclose(handle);
}

/* THE ADMISSION GAUNTLET, entered from two doors and no others. Defined just
 * below; activate_run() (the path entrance) and hotswap_rollback() (the shelf
 * entrance) both call it, and neither gets a stage the other skips. */
static bool activate_from_sealed_fd(int fd,
                                    const char *origin_label,
                                    const char *resolved_datadir,
                                    bool request_activate,
                                    bool require_authorization,
                                    const struct hotswap_publish_hooks *hooks,
                                    struct hotswap_activate_report *report);

/* The dlopen half: confinement, authorization, pin+hash, dlopen/dlsym. The
 * admit -> probe -> ONE batch commit half is hotswap_module_publish(), which
 * compiles in every build and is unit-tested directly with fabricated modules
 * (lib/test/src/test_hotswap_module_v2.c).
 *
 * PATH ENTRANCE. This function is everything that is specific to "the bytes
 * arrived as a file at so_path": path confinement, the datadir/authorization
 * gate, opening the inode, and copying it into a sealed image. From the sealed
 * image onward there is nothing path-shaped left to check, and the rest is
 * activate_from_sealed_fd() — the SAME code the shelf rollback re-enters. */
static bool activate_run(const char *so_path, const char *resolved_datadir,
                         bool request_activate, bool require_authorization,
                         const struct hotswap_publish_hooks *hooks,
                         struct hotswap_activate_report *report)
{
    if (!report)
        return false;
    memset(report, 0, sizeof(*report));
    report->verify_only = !request_activate;

    char why[256] = {0};
    if (!hotswap_path_is_acceptable(so_path, why, sizeof(why)))
        return act_reject(report, "precheck", "rejected so_path: %s", why);
    if (!hotswap_datadir_is_dev(resolved_datadir))
        return act_reject(report, "precheck",
            "hot-swap requires the exact dev datadir ~/.zclassic-c23-dev, got '%s'",
            resolved_datadir ? resolved_datadir : "");

    if (require_authorization && request_activate &&
        !hotswap_activation_authorized(resolved_datadir, why, sizeof(why)))
        return act_reject(report, "authorize", "%s", why);

    /* ── LOAD ORDER IS THE SECURITY PROPERTY ───────────────────────────────
     * seal -> probe -> hash -> map, and every step after the seal reads the
     * SAME immutable image.
     *
     * Sealing first is what makes the rest meaningful. The previous order
     * (open, hash the fd, dlopen /proc/self/fd/N) is redirect-proof but not
     * tamper-proof: dlopen re-reads the inode, so a writer overwriting that
     * inode in place between the hash and the map makes the node hash bytes A
     * and run bytes B. Measured, not theorised. A sealed memfd cannot change
     * after F_SEAL_WRITE, so "the bytes I checked" and "the bytes I ran" stop
     * being two different questions.
     *
     * Probing before mapping fixes a second ordering defect. Every identity
     * fact used to come from dlsym -- which means the module was already
     * mapped and its ELF constructors had ALREADY RUN before a single
     * admission stage was consulted. We lint our own sources for
     * __attribute__((constructor)), but a packaged artifact built elsewhere
     * never passed our lint. Reading the file's own claims first turns "run
     * it, then check it" into "check it, then run it".
     *
     * This is still not an isolation boundary: admitted leaf handlers execute
     * inside this process after publication. It does ensure an artifact
     * rejected before publication has no DT_INIT/init-array opportunity to run
     * first. */
    int src_fd = open(so_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (src_fd < 0 || fstat(src_fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        if (src_fd >= 0) close(src_fd);
        return act_reject(report, "dlopen",
                          "could not pin a regular module artifact");
    }

    char seal_err[200];
    int fd = hotswap_sealed_image_from_fd(src_fd, seal_err, sizeof(seal_err));
    close(src_fd);              /* the on-disk inode is no longer load-bearing */
    if (fd < 0)
        return act_reject(report, "seal", "%s", seal_err);

    /* Sealed. Everything from here is entrance-independent — hand the image
     * to the one gauntlet, which TAKES OWNERSHIP of `fd` on every path. */
    return activate_from_sealed_fd(fd, so_path, resolved_datadir,
                                   request_activate, require_authorization,
                                   hooks, report);
}

/* ── THE ONE ADMISSION GAUNTLET ───────────────────────────────────────────
 *
 * probe -> hash -> map -> symbol -> consensus pin -> admit -> probe-before-
 * publish -> ONE batch commit -> image commit, over a SEALED image. This is
 * the tail of the "LOAD ORDER IS THE SECURITY PROPERTY" sequence documented at
 * its seal step in activate_run() above; the order is the property, so it
 * lives in exactly one function and both entrances run all of it.
 *
 * Two entrances, no shortcut between them:
 *   - activate_run(): the bytes arrived as a file, were path-confined, and
 *     were copied into a sealed image.
 *   - hotswap_rollback(): the bytes are a dup() of an image that was live for
 *     this same source until a later swap superseded it.
 * The shelf entrance deliberately does NOT get a "we already admitted this
 * one" fast path. A second door into module activation that skips stages is a
 * second implementation of activation, and a stage that was true an hour ago
 * (the sealed-core pin above all — `make core-seal` may have moved since) is
 * not a stage that is true now.
 *
 * THE ONE STAGE THE SHELF ENTRANCE CANNOT RUN is
 * hotswap_path_is_acceptable(): a shelved image has no path to confine. That
 * check answers "where did these bytes come from", and these bytes answered it
 * before they were ever mapped — it is skipped knowingly, and skipped nowhere
 * else. Everything the check could still be protecting (that the bytes are
 * what was admitted) is carried by F_SEAL_WRITE on the retained image.
 *
 * DESCRIPTOR DISCIPLINE: this function TAKES OWNERSHIP of `fd` and closes it
 * on every single return path, EXCEPT a successful activation, where it is
 * handed to hotswap_commit_image() which owns it from there.
 *
 * `origin_label` names where the image came from, for diagnostics only; it is
 * never an input to any admission decision.
 *
 * `resolved_datadir` + `require_authorization` re-run the resident gate HERE
 * rather than trusting that the caller ran it. For activate_run() that is a
 * second evaluation of the same pure predicates on the same inputs, which
 * costs two realpath() calls and can only ever change its mind if the operator
 * flipped the gate mid-call — in which case refusing is the correct answer. */
static bool activate_from_sealed_fd(int fd,
                                    const char *origin_label,
                                    const char *resolved_datadir,
                                    bool request_activate,
                                    bool require_authorization,
                                    const struct hotswap_publish_hooks *hooks,
                                    struct hotswap_activate_report *report)
{
    (void)origin_label;
    if (!report) {
        if (fd >= 0) close(fd);
        return false;
    }
    if (fd < 0)
        return act_reject(report, "seal", "no sealed module image to admit");

    char why[256] = {0};
    if (!hotswap_datadir_is_dev(resolved_datadir)) {
        close(fd);
        return act_reject(report, "precheck",
            "hot-swap requires the exact dev datadir ~/.zclassic-c23-dev, got '%s'",
            resolved_datadir ? resolved_datadir : "");
    }
    if (require_authorization && request_activate &&
        !hotswap_activation_authorized(resolved_datadir, why, sizeof(why))) {
        close(fd);
        return act_reject(report, "authorize", "%s", why);
    }

    /* Pre-map shape check, against the sealed image. */
    {
        struct hotswap_elf_facts facts;
        char probe_err[200];
        if (!hotswap_elf_probe_fd(fd, &facts, probe_err, sizeof(probe_err))) {
            close(fd);
            return act_reject(report, "shape", "%s", probe_err);
        }
        if (!hotswap_elf_pre_map_admit(
                &facts, ZCL_CORE_SEAL_ROOT,
                ZCL_HOTSWAP_MODULE_ABI_V3, probe_err, sizeof(probe_err))) {
            close(fd);
            return act_reject(report, "shape", "%s", probe_err);
        }
    }

    if (!artifact_sha256_fd(fd, report->artifact_sha256) ||
        !hotswap_artifact_sha3_fd(fd, report->artifact_sha3_256)) {
        close(fd);
        return act_reject(report, "dlopen",
                          "could not hash the sealed module image");
    }
    char pinned[64];
    (void)snprintf(pinned, sizeof(pinned), "/proc/self/fd/%d", fd);
    void *handle = dlopen(pinned, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        const char *dl = dlerror();
        char msg[200];
        snprintf(msg, sizeof(msg), "dlopen failed: %s", dl ? dl : "(unknown)");
        close(fd);
        return act_reject(report, "dlopen", "%s", msg);
    }

    dlerror();
    const struct zcl_hotswap_module *mod = dlsym(handle, ZCL_HOTSWAP_MODULE_SYMBOL);
    const char *sym_err = dlerror();
    if (!mod || sym_err) {
        char msg[200];
        snprintf(msg, sizeof(msg), "missing %s symbol: %s",
                 ZCL_HOTSWAP_MODULE_SYMBOL, sym_err ? sym_err : "not found");
        dlclose(handle);
        close(fd);
        return act_reject(report, "abi", "%s", msg);
    }

    /* Consensus pin BEFORE admit: a module compiled against a different sealed
     * core never reaches a stage that could publish a leaf. */
    {
        char pin_stage[32], pin_err[256];
        if (!module_consensus_pin_ok(handle, pin_stage, sizeof(pin_stage),
                                     pin_err, sizeof(pin_err))) {
            dlclose(handle);
            close(fd);
            return act_reject(report, pin_stage, "%s", pin_err);
        }
    }

    /* admit -> probe -> ONE all-or-nothing batch replace. ZERO leaves publish
     * on any failure, and the resident handlers are untouched. */
    if (!hotswap_module_publish(mod, request_activate, hooks, report)) {
        dlclose(handle);
        close(fd);
        return false;
    }
    if (!report->activated) {
        /* Verify-only: nothing referenced the candidate, drop it now. */
        dlclose(handle);
        close(fd);
        LOG_INFO("hotswap.activate", "verify-only OK sha=%s (not activated)",
                 report->artifact_sha256);
        return true;
    }

    /* Record the image against its source and decide what may be released.
     * hotswap_commit_image() TAKES OWNERSHIP of `fd` on every path, and it —
     * not this function's arrival order — decides which image the registry
     * considers live. See hotswap/hotswap_shelf.h. */
    struct hotswap_commit_image commit = {
        .source_tu = mod->source_tu,
        .handle = handle,
        .fd = fd,
        .leaves = mod->leaves,
        .leaf_count = mod->leaf_count,
        .generation = report->generation,
        .artifact_sha256 = report->artifact_sha256,
        .resolved_datadir = resolved_datadir,
        .unmap = dev_unmap_module,
        .hooks = hooks,
    };
    if (!hotswap_commit_image(&commit)) {
        /* The registry publish succeeded, but a newer publish for this source
         * won before image ownership was recorded. The commit path owns and
         * safely retires this stale mapping; it is not the live activation
         * this caller requested and must not be reported as success. */
        report->activated = false;
        return act_reject(report, "superseded",
                          "registry generation %u was superseded before the "
                          "image ownership commit",
                          report->generation);
    }
    return true;
}

bool hotswap_activate(const char *so_path, const char *resolved_datadir,
                      bool request_activate,
                      const struct hotswap_publish_hooks *hooks,
                      struct hotswap_activate_report *report)
{
    return activate_run(so_path, resolved_datadir, request_activate,
                        /*require_authorization=*/true, hooks, report);
}

bool hotswap_activate_local(const char *so_path, const char *resolved_datadir,
                            const struct hotswap_publish_hooks *hooks,
                            struct hotswap_activate_report *report)
{
    /* Process-local commit in the operator's own one-shot CLI: probe-class
     * authority, so the resident gate (-hotswap-activate +
     * ZCL_HOTSWAP_ACTIVATE=1) does not apply. The overrides die with the
     * process. Path confinement, the dev-datadir check, the admit gauntlet,
     * probe-before-publish, and the registry's READY/EFFECT_READ re-check all
     * still apply. */
    struct hotswap_publish_hooks local = {0};
    if (hooks)
        local = *hooks;
    local.quiesced = NULL;      /* nothing to reclaim in a one-shot process */
    return activate_run(so_path, resolved_datadir, /*request_activate=*/true,
                        /*require_authorization=*/false, &local, report);
}

/* ── SHELF ROLLBACK — the second entrance to the ONE gauntlet ─────────────
 *
 * See hotswap/hotswap_shelf.h for what this does and does not mean (it
 * republishes the PREVIOUS MODULE, not a compiled-in baseline — the registry
 * has no per-leaf revert), and for why it must stay operator-initiated.
 *
 * ONE DOOR. The shelved image goes back through activate_from_sealed_fd() —
 * dev-datadir confinement, the -hotswap-activate + ZCL_HOTSWAP_ACTIVATE=1
 * gate, ELF shape probe, hash, dlopen, symbol, consensus pin, admit,
 * probe-before-publish, ONE batch commit, image commit. Not one stage is
 * skipped, and there is deliberately no cheaper variant for "an image we
 * admitted before".
 *
 * The toggle is not special-cased either: the rollback's own commit shelves
 * the image it supersedes exactly like any other swap, so a second rollback
 * lands back where you started. A REFUSED rollback never reaches that commit,
 * so the shelf is not consumed and the live handlers are untouched.
 *
 * CONCURRENCY. Three collisions, and none of them can reach an unmap:
 *   - Two rollbacks of the SAME source: the claim below runs under g_act_lock
 *     and sets `rollback_in_flight`, so the second is refused at stage
 *     "shelf" instead of racing. Cleared on every exit path.
 *   - Two rollbacks of DIFFERENT sources: independent slots; they share only
 *     the microseconds each spends inside the claim.
 *   - A rollback racing a FORWARD activation of the same source: both publish
 *     outside any loader lock, so they can reach hotswap_commit_image() in the
 *     opposite order to the one the registry gave them. That is the retirement
 *     race, and it is handled where it belongs — the commit orders itself by
 *     the registry generation and unmaps nothing it cannot prove unreachable.
 *     The claim also holds a dup() of the sealed inode, so a forward swap
 *     replacing (and closing) the shelf entry mid-rollback cannot pull the
 *     bytes out from under it.
 * No new lock means no new lock-ordering edge: g_act_lock stays a leaf, and
 * this function never holds it across a hook callback, dlopen, or any other
 * blocking call. */
bool hotswap_rollback(const char *source_tu,
                      const struct hotswap_publish_hooks *hooks,
                      struct hotswap_activate_report *report)
{
    if (!report)
        return false;
    memset(report, 0, sizeof(*report));
    report->verify_only = false;
    if (!source_tu || !source_tu[0])
        return act_reject(report, "precheck", "rollback needs a source_tu");
    act_copy(report->source_tu, sizeof(report->source_tu), source_tu);

    enum claim { CLAIM_NO_SLOT, CLAIM_EMPTY, CLAIM_BUSY, CLAIM_DUP, CLAIM_OK };
    enum claim outcome = CLAIM_NO_SLOT;
    char datadir[HOTSWAP_ACT_DATADIR_MAX] = {0};
    char shelf_sha[65] = {0};
    size_t idx = 0;
    bool claimed = false;
    int fd = -1;
    int dup_errno = 0;

    pthread_mutex_lock(&g_act_lock);
    for (size_t i = 0; i < g_slot_count; i++) {
        if (!g_slots[i].in_use || strcmp(g_slots[i].source, source_tu) != 0)
            continue;
        idx = i;
        if (!g_slots[i].shelf_present || g_slots[i].shelf_fd < 0) {
            outcome = CLAIM_EMPTY;
        } else if (g_slots[i].rollback_in_flight) {
            outcome = CLAIM_BUSY;
        } else {
            fd = dup(g_slots[i].shelf_fd);
            if (fd < 0) {
                dup_errno = errno;
                outcome = CLAIM_DUP;
            } else {
                g_slots[i].rollback_in_flight = true;
                claimed = true;
                act_copy(datadir, sizeof(datadir), g_slots[i].datadir);
                act_copy(shelf_sha, sizeof(shelf_sha), g_slots[i].shelf_sha256);
                outcome = CLAIM_OK;
            }
        }
        break;
    }
    pthread_mutex_unlock(&g_act_lock);

    switch (outcome) {
    case CLAIM_NO_SLOT:
        return act_reject(report, "shelf",
            "source '%s' has never been activated in this process, so nothing "
            "is shelved for it", source_tu);
    case CLAIM_EMPTY:
        return act_reject(report, "shelf",
            "source '%s' has nothing shelved: its current module is the first "
            "one activated, and there is no per-leaf revert to a compiled-in "
            "baseline", source_tu);
    case CLAIM_BUSY:
        return act_reject(report, "shelf",
            "a rollback of source '%s' is already in flight", source_tu);
    case CLAIM_DUP:
        return act_reject(report, "shelf",
            "could not duplicate the shelved image for '%s' (errno=%d)",
            source_tu, dup_errno);
    case CLAIM_OK:
        break;
    }

    /* From here `fd` belongs to the gauntlet, which closes it on every path
     * except a successful commit (where the image commit takes it over). */
    char origin[320];
    (void)snprintf(origin, sizeof(origin), "shelf:%s@%.16s", source_tu,
                   shelf_sha[0] ? shelf_sha : "(unhashed)");
    bool ok = activate_from_sealed_fd(fd, origin, datadir,
                                      /*request_activate=*/true,
                                      /*require_authorization=*/true,
                                      hooks, report);

    if (claimed) {
        pthread_mutex_lock(&g_act_lock);
        if (idx < g_slot_count)
            g_slots[idx].rollback_in_flight = false;
        pthread_mutex_unlock(&g_act_lock);
    }

    if (ok) {
        atomic_fetch_add_explicit(&g_shelf_rollback_count, 1,
                                  memory_order_relaxed);
        LOG_INFO("hotswap.activate",
                 "rolled back source=%s to the shelved image sha=%.16s gen=%u "
                 "(what was live is now the shelf entry)",
                 source_tu, shelf_sha, report->generation);
    }
    return ok;
}

bool hotswap_verify_module_so(const char *so_path, const char *expect_tu,
                              struct hotswap_activate_report *report)
{
    if (!report)
        return false;
    memset(report, 0, sizeof(*report));
    report->verify_only = true;
    report->rolled_back = true;

    if (!so_path || !so_path[0]) {
        act_copy(report->stage, sizeof(report->stage), "precheck");
        act_copy(report->error, sizeof(report->error), "empty so_path");
        return false;
    }

    /* Same fd discipline as activate_run(): open ONCE, hash that descriptor,
     * and dlopen the identical descriptor through /proc/self/fd/N, so the
     * digest describes the inode that is actually mapped rather than whatever
     * the path resolves to a moment later. The descriptor is closed as soon as
     * dlopen has mapped it — the mapping outlives the fd, and unlike the
     * resident path there is no later retire step here that needs it.
     *
     * SHA3-256 ONLY on this path, deliberately. report->artifact_sha256 stays
     * empty here: this verifier is linked standalone by tools/dev/
     * hotswap-verify.sh and tools/dev/hotswap-package.sh from a handful of
     * sources plus --gc-sections, and pulling in lib/crypto's SHA-256 (with
     * its CPU-dispatch table and logging macros) to fill a field nothing in
     * the verification or packaging lane reads would buy nothing for a real
     * dependency cost. The RESIDENT loader still computes BOTH over its own
     * fd — see activate_run(). */
    /* Same seal -> probe -> hash -> map order as activate_run(); see the long
     * comment there for why the order IS the property. The offline verifier
     * matters here as much as the resident does: it is the tool a human runs
     * to decide whether a packaged artifact is worth mounting, so it must not
     * form that opinion by running the artifact's constructors first. */
    int vsrc_fd = open(so_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat vst;
    if (vsrc_fd < 0 || fstat(vsrc_fd, &vst) != 0 || !S_ISREG(vst.st_mode)) {
        if (vsrc_fd >= 0)
            (void)close(vsrc_fd);
        act_copy(report->stage, sizeof(report->stage), "dlopen");
        act_copy(report->error, sizeof(report->error),
                 "not a regular readable module artifact");
        return false;
    }

    char vseal_err[200];
    int fd = hotswap_sealed_image_from_fd(vsrc_fd, vseal_err, sizeof(vseal_err));
    (void)close(vsrc_fd);
    if (fd < 0) {
        act_copy(report->stage, sizeof(report->stage), "seal");
        act_copy(report->error, sizeof(report->error), vseal_err);
        return false;
    }

    {
        struct hotswap_elf_facts vfacts;
        char vprobe_err[200];
        if (!hotswap_elf_probe_fd(fd, &vfacts, vprobe_err, sizeof(vprobe_err))) {
            (void)close(fd);
            act_copy(report->stage, sizeof(report->stage), "shape");
            act_copy(report->error, sizeof(report->error), vprobe_err);
            return false;
        }
        if (!hotswap_elf_pre_map_admit(
                &vfacts, ZCL_CORE_SEAL_ROOT,
                ZCL_HOTSWAP_MODULE_ABI_V3, vprobe_err,
                sizeof(vprobe_err))) {
            (void)close(fd);
            act_copy(report->stage, sizeof(report->stage), "shape");
            act_copy(report->error, sizeof(report->error), vprobe_err);
            return false;
        }
    }

    if (!hotswap_artifact_sha3_fd(fd, report->artifact_sha3_256)) {
        (void)close(fd);
        act_copy(report->stage, sizeof(report->stage), "dlopen");
        act_copy(report->error, sizeof(report->error),
                 "could not SHA3-hash the sealed module image");
        return false;
    }
    char vpinned[64];
    (void)snprintf(vpinned, sizeof(vpinned), "/proc/self/fd/%d", fd);

    /* RTLD_LOCAL so the candidate's symbols never join the global scope and
     * interpose on anything the verifying process later resolves. The shared
     * pre-map policy has proved that no artifact callback runs at load time.
     * RTLD_LAZY defers function imports the resident node would satisfy, which is exactly
     * what lets a build-time verifier open an artifact with no node running.
     * Data and address-taken relocations still resolve eagerly, so a module
     * that references a body defined in a TU outside its own island still
     * fails here — correctly, since re-pointing such a leaf would dispatch
     * into resident code and the swap would silently do nothing for it. */
    void *handle = dlopen(vpinned, RTLD_LAZY | RTLD_LOCAL);
    (void)close(fd);
    if (!handle) {
        const char *e = dlerror();
        act_copy(report->stage, sizeof(report->stage), "dlopen");
        act_copy(report->error, sizeof(report->error), e ? e : "dlopen failed");
        return false;
    }

    (void)dlerror();
    const struct zcl_hotswap_module *module =
        (const struct zcl_hotswap_module *)dlsym(handle,
                                                 ZCL_HOTSWAP_MODULE_SYMBOL);
    const char *sym_err = dlerror();
    if (!module || sym_err) {
        act_copy(report->stage, sizeof(report->stage), "symbol");
        snprintf(report->error, sizeof(report->error),
                 "'%s' not exported (%s)", ZCL_HOTSWAP_MODULE_SYMBOL,
                 sym_err ? sym_err : "resolved to NULL");
        dlclose(handle);
        return false;
    }

    act_copy(report->source_tu, sizeof(report->source_tu),
             module->source_tu ? module->source_tu : "");
    report->leaf_count = module->leaf_count;
    if (module->leaves) {
        size_t used = 0;
        for (uint32_t i = 0; i < module->leaf_count &&
                             i < ZCL_HOTSWAP_MODULE_MAX_LEAVES; i++) {
            const char *nm = module->leaves[i].name;
            if (!nm)
                continue;
            int w = snprintf(report->leaves + used,
                             sizeof(report->leaves) - used, "%s%s",
                             used ? "," : "", nm);
            if (w < 0 || (size_t)w >= sizeof(report->leaves) - used)
                break;
            used += (size_t)w;
        }
    }
    const char *probe = hotswap_module_probe_leaf(
        module->source_tu ? module->source_tu : "");
    act_copy(report->probe_leaf, sizeof(report->probe_leaf),
             probe ? probe : "");

    /* A module cannot mislabel its allowlist row: the build recipe stamps
     * -DZCL_HOTSWAP_MODULE_SOURCE_TU, so a mismatch means the artifact and the
     * file the caller believes it built have diverged. */
    if (expect_tu && expect_tu[0] &&
        strcmp(expect_tu, module->source_tu ? module->source_tu : "") != 0) {
        act_copy(report->stage, sizeof(report->stage), "source_tu");
        snprintf(report->error, sizeof(report->error),
                 "artifact declares '%s', expected '%s'",
                 module->source_tu ? module->source_tu : "(null)", expect_tu);
        dlclose(handle);
        return false;
    }

    /* The same consensus pin the resident enforces. Verification must not be
     * looser than the mount it stands in for — the -z lazy re-link this path
     * dlopens already costs it the unresolved-symbol check (hotswap-symbols.sh
     * covers that separately); it does not get to skip this one too. */
    if (!module_consensus_pin_ok(handle, report->stage, sizeof(report->stage),
                                 report->error, sizeof(report->error))) {
        dlclose(handle);
        return false;
    }

    /* The REAL gauntlet the resident loader runs — not a copy of it. */
    if (!hotswap_module_admit(module, report->stage, sizeof(report->stage),
                              report->error, sizeof(report->error))) {
        dlclose(handle);
        return false;
    }

    act_copy(report->stage, sizeof(report->stage), "verified");
    report->ok = true;
    report->rolled_back = false;
    dlclose(handle);
    return true;
}

#else
#define ZCL_HOTSWAP_ACTIVATE_UNAVAILABLE 1
#endif /* Linux */
#else
#define ZCL_HOTSWAP_ACTIVATE_UNAVAILABLE 1
#endif /* ZCL_DEV_BUILD */

#ifdef ZCL_HOTSWAP_ACTIVATE_UNAVAILABLE
/* Unsupported platform or release build: no dynamic activation surface. */

bool hotswap_verify_module_so(const char *so_path, const char *expect_tu,
                              struct hotswap_activate_report *report)
{
    (void)so_path;
    (void)expect_tu;
    if (!report)
        return false;
    memset(report, 0, sizeof(*report));
    report->verify_only = true;
    report->rolled_back = true;
    act_copy(report->stage, sizeof(report->stage),
             hotswap_native_unavailable_stage());
    act_copy(report->error, sizeof(report->error),
             hotswap_native_unavailable_reason());
    return false;
}

bool zcl_hotswap_hotfork_visit_so(
    const char *so_path, const char *expected_sha256,
    zcl_hotfork_capsule_visit_fn visit, void *ctx,
    char actual_sha256[65])
{
    (void)so_path;
    (void)expected_sha256;
    (void)visit;
    (void)ctx;
    if (actual_sha256)
        actual_sha256[0] = '\0';
    return false;
}

bool hotswap_activate(const char *so_path, const char *resolved_datadir,
                      bool request_activate,
                      const struct hotswap_publish_hooks *hooks,
                      struct hotswap_activate_report *report)
{
    (void)so_path;
    (void)resolved_datadir;
    (void)request_activate;
    (void)hooks;
    if (!report)
        return false;
    memset(report, 0, sizeof(*report));
    report->verify_only = true;
    report->rolled_back = true;
    act_copy(report->stage, sizeof(report->stage), HOTSWAP_UNAVAILABLE_STAGE);
    act_copy(report->error, sizeof(report->error), HOTSWAP_UNAVAILABLE_REASON);
    return false;
}

bool hotswap_activate_local(const char *so_path, const char *resolved_datadir,
                            const struct hotswap_publish_hooks *hooks,
                            struct hotswap_activate_report *report)
{
    (void)so_path;
    (void)resolved_datadir;
    (void)hooks;
    if (!report)
        return false;
    memset(report, 0, sizeof(*report));
    report->verify_only = true;
    report->rolled_back = true;
    act_copy(report->stage, sizeof(report->stage), HOTSWAP_UNAVAILABLE_STAGE);
    act_copy(report->error, sizeof(report->error), HOTSWAP_UNAVAILABLE_REASON);
    return false;
}

/* Nothing can shelve an image in a release build (only the dev activation
 * core commits one), so hotswap_shelf_list/peek already report an empty shelf
 * correctly and need no stub. Rollback still needs one: it publishes live
 * code, and a release binary refuses to do that. */
bool hotswap_rollback(const char *source_tu,
                      const struct hotswap_publish_hooks *hooks,
                      struct hotswap_activate_report *report)
{
    (void)source_tu;
    (void)hooks;
    if (!report)
        return false;
    memset(report, 0, sizeof(*report));
    report->verify_only = true;
    report->rolled_back = true;
    act_copy(report->stage, sizeof(report->stage), HOTSWAP_UNAVAILABLE_STAGE);
    act_copy(report->error, sizeof(report->error), HOTSWAP_UNAVAILABLE_REASON);
    return false;
}

#undef HOTSWAP_UNAVAILABLE_STAGE
#undef HOTSWAP_UNAVAILABLE_REASON

#endif /* ZCL_HOTSWAP_ACTIVATE_UNAVAILABLE */
#undef ZCL_HOTSWAP_ACTIVATE_UNAVAILABLE
