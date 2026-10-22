/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the MULTI-LEAF (ABI v3) Tier-1 hot-swap module: one shared library,
 * many leaves, ONE atomic commit — plus probe-before-publish.
 *
 * The whole post-dlsym sequence lives in hotswap_module_publish() (admit ->
 * probe -> ONE all-or-nothing batch commit), which compiles in EVERY build, so
 * these tests drive it directly with fabricated modules and fabricated hooks —
 * no dlopen, no ZCL_DEV_BUILD. The commit hook publishes into the real kernel
 * command-registry override layer, so "publishes ZERO leaves" is asserted
 * against the registry's actual active generation, not a mock.
 *
 * Covered (the properties that make batch-widening safe):
 *   - a partial admit publishes ZERO leaves (all-or-nothing);
 *   - a duplicate leaf across two modules is refused;
 *   - an old-ABI (v1) module is refused LOUDLY at stage=abi;
 *   - a module exceeding the 64-leaf cap is refused at stage=capacity;
 *   - generation numbers stay monotonic across repeated publishes;
 *   - a probe schema mismatch publishes NOTHING;
 *   - the compile-time consensus pin is a well-formed, CURRENT sealed-core ROOT
 *     (a stale one silently admits modules built against a consensus core the
 *     node no longer runs).
 */

#include "test/test_helpers.h"

#include "hotswap/hotswap.h"
#include "hotswap/hotswap_elf_probe.h"
#include "hotswap/hotswap_module.h"
#include "hotswap/hotswap_sealed_image.h"
#include "hotswap/hotfork_capsule.h"
#include "kernel/command_registry.h"
#include "json/json.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#if !defined(_WIN32)
#include "hotswap/hotswap_macho_probe.h"
#include "base/serialize_le.h"

struct macho_magic_row {
    uint32_t offset, size;
    size_t length;
    const char *reason;
};

/* Existing fat32 + arm64 MH_BUNDLE bytes. No Apple SDK or artifact execution
 * is needed to drive the descriptor-reading and selection stage. */
static void t_macho_magic_image(unsigned char image[88],
                                 const struct macho_magic_row *row, bool swap)
{
    uint32_t fat[2] = {UINT32_C(0xcafebabe), 1};
    uint32_t arch[5] = {UINT32_C(0x0100000c), 0, row->offset, row->size, 0};
    uint32_t thin[8] = {UINT32_C(0xfeedfacf), UINT32_C(0x0100000c), 0, 8,
                        1, 24, 0, 0};
    uint32_t symbols[6] = {2, 24, 88, 0, 88, 0};
    memset(image, 0, 88);
    if (swap) {
        fat[0] = zcl_bswap32(fat[0]);
        fat[1] = zcl_bswap32(fat[1]);
        for (size_t i = 0; i < sizeof(arch) / sizeof(arch[0]); i++)
            arch[i] = zcl_bswap32(arch[i]);
    }
    memcpy(image, fat, sizeof(fat));
    memcpy(image + sizeof(fat), arch, sizeof(arch));
    memcpy(image + 32, thin, sizeof(thin));
    memcpy(image + 64, symbols, sizeof(symbols));
}

static int t_macho_magic_result(int fd, const struct macho_magic_row *row)
{
    int failures = 0;
    static struct hotswap_macho_facts facts;
    static const struct hotswap_macho_facts zero;
    char err[256] = {0};
    memset(&facts, 0xa5, sizeof(facts));
    bool ok = hotswap_macho_probe_fd(fd, &facts, err, sizeof(err));
    if (row->reason) {
        ASSERT(!ok);
        ASSERT_STR_EQ(err, row->reason);
        ASSERT(memcmp(&facts, &zero, sizeof(facts)) == 0);
    } else {
#if defined(__APPLE__)
        ASSERT(ok);
        ASSERT(facts.file_size == row->length);
        ASSERT(err[0] == '\0');
#else
        ASSERT(!ok);
        ASSERT_STR_EQ(err, "macho probe: full probe requires macOS");
        ASSERT(memcmp(&facts, &zero, sizeof(facts)) == 0);
#endif
        ASSERT(lseek(fd, 0, SEEK_CUR) == 0);
    }
_test_next:;
    return failures;
}

static int t_macho_magic_row(int fd, const struct macho_magic_row *row, bool swap)
{
    int failures = 0;
    unsigned char image[88];
    t_macho_magic_image(image, row, swap);
    ASSERT(row->length <= sizeof(image));
    ASSERT(ftruncate(fd, 0) == 0);
    ASSERT(lseek(fd, 0, SEEK_SET) == 0);
    ASSERT(write(fd, image, row->length) == (ssize_t)row->length);
    failures += t_macho_magic_result(fd, row);
_test_next:;
    return failures;
}

static int t_macho_fat_magic_bounds(void)
{
    int failures = 0;
    int fd = -1;
    bool linked = false;
    char path[PATH_MAX] = {0};
    const struct macho_magic_row rows[] = {
        {32, 0, 88, "macho probe: fat arch extends past file"},
        {32, 1, 88, "macho probe: fat arch extends past file"},
        {32, 2, 88, "macho probe: fat arch extends past file"},
        {32, 3, 88, "macho probe: fat arch extends past file"},
        {27, 1, 28, "macho probe: fat arch extends past file"},
        {28, 0, 28, "macho probe: fat arch extends past file"},
        {28, 1, 28, "macho probe: fat arch extends past file"},
        {89, 4, 88, "macho probe: fat arch extends past file"},
        {32, 57, 88, "macho probe: fat arch extends past file"},
        {32, 56, 88, NULL}
    };
    TEST("Mach-O fat selection bounds magic before reading it") {
        fd = test_mkstemp(path, sizeof(path), "hotswap_macho_magic");
        ASSERT(fd >= 0);
        linked = true;
        ASSERT(unlink(path) == 0);
        linked = false;
        for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
            failures += t_macho_magic_row(fd, &rows[i], false);
            failures += t_macho_magic_row(fd, &rows[i], true);
        }
        if (failures == 0)
            PASS();
    } _test_next:;
    if (fd >= 0) {
        int closed = close(fd);
        fd = -1;
        ASSERT(closed == 0);
    }
    if (linked) {
        linked = false;
        ASSERT(unlink(path) == 0);
    }
    return failures;
}
#endif

/* The status controller row of engine/composition/hotswap_swappable.def; its declared probe
 * leaf in engine/composition/hotswap_eligible.def is core.status. */
#define V2_TU_STATUS "engine/controllers/src/status_native_handlers.c"
#define V2_TU_META   "engine/controllers/src/meta_native_handlers.c"
#define V2_TU_METAVERSE "contexts/commons/controllers/src/metaverse_controller.c"
#define V2_TU_DIAGNOSTICS \
    "engine/controllers/src/diagnostics_native_handlers.c"
#define V2_TU_OPS "engine/controllers/src/ops_native_handlers.c"

static void v2_handler(const struct zcl_command_request *request,
                       struct zcl_command_reply *reply)
{
    (void)request;
    (void)json_push_kv_str(&reply->data, "who", "module_v2");
}

static bool v2_selftest_true(char *err, size_t cap)
{
    (void)err;
    (void)cap;
    return true;
}

/* ── Fabricated publish hooks ─────────────────────────────────────────────
 * commit publishes into the REAL registry override layer; probe is switchable
 * so a schema mismatch can be simulated exactly where the resident probe would
 * report one. */

static _Bool g_probe_ok = 1;
static int g_probe_calls = 0;
static int g_commit_calls = 0;
static char g_last_probe_leaf[128];

static bool v2_commit(void *ctx, const struct zcl_hotswap_leaf *leaves,
                      size_t leaf_count, uint32_t *out_gen, char *why,
                      size_t why_sz)
{
    (void)ctx;
    g_commit_calls++;
    if (!leaves || leaf_count == 0 ||
        leaf_count > ZCL_COMMAND_HANDLER_OVERRIDE_MAX) {
        if (why && why_sz) snprintf(why, why_sz, "bad batch size %zu", leaf_count);
        return false;
    }
    struct zcl_command_handler_override ovr[ZCL_COMMAND_HANDLER_OVERRIDE_MAX];
    for (size_t i = 0; i < leaf_count; i++) {
        ovr[i].path = leaves[i].name;
        ovr[i].handler = leaves[i].fn;
    }
    /* Take the generation from the publish itself. Re-reading the active
     * generation here would race a concurrent publisher and could hand the
     * loader a generation that belongs to somebody else's batch. */
    if (!zcl_command_registry_replace_batch(0, ovr, leaf_count, why, why_sz,
                                            out_gen))
        return false;
    return true;
}

static bool v2_probe(void *ctx, const char *leaf, zcl_hotswap_handler_fn fn,
                     char *why, size_t why_sz)
{
    (void)ctx;
    g_probe_calls++;
    snprintf(g_last_probe_leaf, sizeof(g_last_probe_leaf), "%s",
             leaf ? leaf : "");
    if (!fn) {
        if (why && why_sz) snprintf(why, why_sz, "probe handler is NULL");
        return false;
    }
    if (!g_probe_ok) {
        if (why && why_sz)
            snprintf(why, why_sz,
                     "reply data_schema 'zcl.wrong.v0' != declared output "
                     "schema 'zcl.core_status.v2'");
        return false;
    }
    return true;
}

static void v2_hooks(struct hotswap_publish_hooks *h)
{
    memset(h, 0, sizeof(*h));
    h->commit = v2_commit;
    h->probe = v2_probe;
}

/* ── A registry the override layer can validate against ───────────────────
 * The override commit re-checks READY + read-only + resolvable, so the bound
 * registry must carry the real leaf paths under test. */
static const struct zcl_command_spec g_v2_specs[] = {
    { .path = "core.status", .summary = "swappable read leaf",
      .layer = ZCL_COMMAND_LAYER_CORE, .effect = ZCL_COMMAND_EFFECT_READ,
      .availability = ZCL_COMMAND_READY, .mode = ZCL_COMMAND_MODE_SYNC,
      .allowed_lanes = ZCL_COMMAND_LANE_LOCAL, .handler = v2_handler },
    { .path = "ops.metrics", .summary = "swappable read leaf",
      .layer = ZCL_COMMAND_LAYER_OPS, .effect = ZCL_COMMAND_EFFECT_READ,
      .availability = ZCL_COMMAND_READY, .mode = ZCL_COMMAND_MODE_SYNC,
      .allowed_lanes = ZCL_COMMAND_LANE_LOCAL, .handler = v2_handler },
};
static const struct zcl_command_registry g_v2_reg = {
    .commands = g_v2_specs,
    .count = sizeof(g_v2_specs) / sizeof(g_v2_specs[0]),
};

static void v2_reset(void)
{
    zcl_command_registry_reset_overrides();
    zcl_command_registry_set_active(&g_v2_reg);
    g_probe_ok = 1;
    g_probe_calls = 0;
    g_commit_calls = 0;
    g_last_probe_leaf[0] = '\0';
}

/* ── 1. A partial admit publishes ZERO leaves ─────────────────────────── */

static const struct zcl_hotswap_leaf k_partial_leaves[] = {
    { "core.status", v2_handler },                 /* admissible */
    { "core.consensus.pow.verify", v2_handler },   /* NOT owned by this TU */
};

static int t_partial_admit_publishes_nothing(void)
{
    int failures = 0;
    TEST("a partial admit publishes ZERO leaves (all-or-nothing)") {
        v2_reset();
        uint32_t before = zcl_command_registry_active_generation();

        struct zcl_hotswap_module m = {
            .abi_version = ZCL_HOTSWAP_MODULE_ABI_V3,
            .core_sections = hotswap_core_sections_self(),
            .source_tu = V2_TU_STATUS,
            .leaf_count = 2,
            .leaves = k_partial_leaves,
            .self_test = v2_selftest_true,
        };
        struct hotswap_publish_hooks hooks;
        v2_hooks(&hooks);
        struct hotswap_activate_report report;
        memset(&report, 0, sizeof(report));

        ASSERT(!hotswap_module_publish(&m, /*request_activate=*/true, &hooks,
                                       &report));
        ASSERT(!report.ok);
        ASSERT(!report.activated);
        ASSERT(report.rolled_back);
        ASSERT_EQ(strcmp(report.stage, "allowlist"), 0);
        /* The admissible sibling leaf must NOT have slipped through: no probe,
         * no commit, and the registry generation is untouched. */
        ASSERT_EQ(g_probe_calls, 0);
        ASSERT_EQ(g_commit_calls, 0);
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(),
                  (unsigned)before);

        zcl_command_registry_reset_overrides();
        zcl_command_registry_set_active(NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 2. A duplicate leaf across two modules is refused ─────────────────── */

static const struct zcl_hotswap_leaf k_status_only[] = {
    { "core.status", v2_handler },
};
/* The meta TU trying to claim core.status — a leaf it does not own. Leaf
 * ownership in engine/composition/hotswap_swappable.def is exclusive, which is what makes
 * two modules publishing the same leaf unrepresentable. */
static const struct zcl_hotswap_leaf k_meta_claims_status[] = {
    { "ops.metrics", v2_handler },
    { "core.status", v2_handler },
};
/* The same leaf twice INSIDE one module. */
static const struct zcl_hotswap_leaf k_status_twice[] = {
    { "core.status", v2_handler },
    { "core.status", v2_handler },
};

static int t_duplicate_leaf_refused(void)
{
    int failures = 0;
    TEST("a duplicate leaf across two modules (and within one) is refused") {
        v2_reset();
        struct hotswap_publish_hooks hooks;
        v2_hooks(&hooks);
        struct hotswap_activate_report report;
        char stage[64] = {0}, why[192] = {0};

        /* Module A (the owner) admits cleanly. */
        struct zcl_hotswap_module a = {
            .abi_version = ZCL_HOTSWAP_MODULE_ABI_V3,
            .core_sections = hotswap_core_sections_self(),
            .source_tu = V2_TU_STATUS, .leaf_count = 1,
            .leaves = k_status_only, .self_test = v2_selftest_true,
        };
        ASSERT(hotswap_module_admit(&a, stage, sizeof(stage), why, sizeof(why)));

        /* Module B, a DIFFERENT source file, claiming the same leaf: refused,
         * because core.status belongs to exactly one row. */
        struct zcl_hotswap_module b = {
            .abi_version = ZCL_HOTSWAP_MODULE_ABI_V3,
            .core_sections = hotswap_core_sections_self(),
            .source_tu = V2_TU_META, .leaf_count = 2,
            .leaves = k_meta_claims_status, .self_test = v2_selftest_true,
        };
        memset(&report, 0, sizeof(report));
        ASSERT(!hotswap_module_publish(&b, true, &hooks, &report));
        ASSERT_EQ(strcmp(report.stage, "allowlist"), 0);
        ASSERT(strstr(report.error, "core.status") != NULL);
        ASSERT_EQ(g_commit_calls, 0);

        /* And the same leaf twice inside ONE module is refused too. */
        struct zcl_hotswap_module c = {
            .abi_version = ZCL_HOTSWAP_MODULE_ABI_V3,
            .core_sections = hotswap_core_sections_self(),
            .source_tu = V2_TU_STATUS, .leaf_count = 2,
            .leaves = k_status_twice, .self_test = v2_selftest_true,
        };
        memset(&report, 0, sizeof(report));
        ASSERT(!hotswap_module_publish(&c, true, &hooks, &report));
        ASSERT_EQ(strcmp(report.stage, "duplicate"), 0);
        ASSERT_EQ(g_commit_calls, 0);

        zcl_command_registry_reset_overrides();
        zcl_command_registry_set_active(NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 3. An old-ABI module is refused LOUDLY ────────────────────────────── */

static int t_old_abi_refused(void)
{
    int failures = 0;
    TEST("an ABI v1 module is refused loudly at stage=abi, nothing published") {
        v2_reset();
        uint32_t before = zcl_command_registry_active_generation();

        struct zcl_hotswap_module m = {
            .abi_version = ZCL_HOTSWAP_MODULE_ABI_V1,   /* retired layout */
            .source_tu = V2_TU_STATUS, .leaf_count = 1,
            .leaves = k_status_only, .self_test = v2_selftest_true,
        };
        struct hotswap_publish_hooks hooks;
        v2_hooks(&hooks);
        struct hotswap_activate_report report;
        memset(&report, 0, sizeof(report));

        ASSERT(!hotswap_module_publish(&m, true, &hooks, &report));
        ASSERT_EQ(strcmp(report.stage, "abi"), 0);
        /* Loud: the reason names the version it saw and the one it needs. */
        ASSERT(strstr(report.error, "abi_version") != NULL);
        ASSERT(strstr(report.error, "rebuild") != NULL);
        ASSERT_EQ(g_probe_calls, 0);
        ASSERT_EQ(g_commit_calls, 0);
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(),
                  (unsigned)before);

        zcl_command_registry_reset_overrides();
        zcl_command_registry_set_active(NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4. A module exceeding the 64-leaf cap is refused ──────────────────── */

static int t_leaf_cap_refused(void)
{
    int failures = 0;
    TEST("a module over the 64-leaf cap is refused at stage=capacity") {
        v2_reset();
        /* The cap must never exceed what ONE registry batch can carry. */
        ASSERT_EQ((unsigned)ZCL_HOTSWAP_MODULE_MAX_LEAVES,
                  (unsigned)ZCL_COMMAND_HANDLER_OVERRIDE_MAX);

        static struct zcl_hotswap_leaf oversize[ZCL_HOTSWAP_MODULE_MAX_LEAVES + 1];
        for (size_t i = 0; i < sizeof(oversize) / sizeof(oversize[0]); i++) {
            oversize[i].name = "core.status";
            oversize[i].fn = v2_handler;
        }
        struct zcl_hotswap_module m = {
            .abi_version = ZCL_HOTSWAP_MODULE_ABI_V3,
            .core_sections = hotswap_core_sections_self(),
            .source_tu = V2_TU_STATUS,
            .leaf_count = ZCL_HOTSWAP_MODULE_MAX_LEAVES + 1u,
            .leaves = oversize, .self_test = v2_selftest_true,
        };
        struct hotswap_publish_hooks hooks;
        v2_hooks(&hooks);
        struct hotswap_activate_report report;
        memset(&report, 0, sizeof(report));

        ASSERT(!hotswap_module_publish(&m, true, &hooks, &report));
        ASSERT_EQ(strcmp(report.stage, "capacity"), 0);
        ASSERT(strstr(report.error, "ceiling") != NULL);
        ASSERT_EQ(g_commit_calls, 0);

        zcl_command_registry_reset_overrides();
        zcl_command_registry_set_active(NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 5. Generation numbers stay monotonic ──────────────────────────────── */

static int t_generation_monotonic(void)
{
    int failures = 0;
    TEST("repeated multi-leaf publishes keep the generation strictly rising") {
        v2_reset();
        struct zcl_hotswap_module m = {
            .abi_version = ZCL_HOTSWAP_MODULE_ABI_V3,
            .core_sections = hotswap_core_sections_self(),
            .source_tu = V2_TU_STATUS, .leaf_count = 1,
            .leaves = k_status_only, .self_test = v2_selftest_true,
        };
        struct hotswap_publish_hooks hooks;
        v2_hooks(&hooks);

        uint32_t prev = zcl_command_registry_active_generation();
        for (int i = 0; i < 8; i++) {
            struct hotswap_activate_report report;
            memset(&report, 0, sizeof(report));
            ASSERT(hotswap_module_publish(&m, true, &hooks, &report));
            ASSERT(report.ok);
            ASSERT(report.activated);
            ASSERT(report.probed);
            ASSERT_EQ((int)report.leaf_count, 1);
            ASSERT(report.generation > prev);
            ASSERT_EQ((unsigned)report.generation,
                      (unsigned)zcl_command_registry_active_generation());
            prev = report.generation;
        }
        /* The probe ran once per publish, on the file's DECLARED probe leaf. */
        ASSERT_EQ(g_probe_calls, 8);
        ASSERT_EQ(strcmp(g_last_probe_leaf, "core.status"), 0);

        zcl_command_registry_reset_overrides();
        zcl_command_registry_set_active(NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 6. A probe schema mismatch publishes NOTHING ──────────────────────── */

static int t_probe_mismatch_publishes_nothing(void)
{
    int failures = 0;
    TEST("a probe schema mismatch publishes nothing (no commit, no generation)") {
        v2_reset();
        struct zcl_hotswap_module m = {
            .abi_version = ZCL_HOTSWAP_MODULE_ABI_V3,
            .core_sections = hotswap_core_sections_self(),
            .source_tu = V2_TU_STATUS, .leaf_count = 1,
            .leaves = k_status_only, .self_test = v2_selftest_true,
        };
        struct hotswap_publish_hooks hooks;
        v2_hooks(&hooks);

        /* One good publish so there IS a live generation to protect. */
        struct hotswap_activate_report good;
        memset(&good, 0, sizeof(good));
        ASSERT(hotswap_module_publish(&m, true, &hooks, &good));
        uint32_t held = zcl_command_registry_active_generation();
        ASSERT(held > 0);

        /* Now the candidate's reply does not match its declared output
         * schema. The module's own self_test still returns true — that is the
         * self-certification this gate replaces. */
        g_probe_ok = 0;
        struct hotswap_activate_report bad;
        memset(&bad, 0, sizeof(bad));
        ASSERT(!hotswap_module_publish(&m, true, &hooks, &bad));
        ASSERT(!bad.ok);
        ASSERT(!bad.activated);
        ASSERT(!bad.probed);
        ASSERT(bad.rolled_back);
        ASSERT_EQ(strcmp(bad.stage, "probe"), 0);
        ASSERT(strstr(bad.error, "data_schema") != NULL);
        /* Nothing published: the generation held by the good publish stands. */
        ASSERT_EQ(g_commit_calls, 1);
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(),
                  (unsigned)held);

        /* Activating with NO probe hook at all is refused for the same reason:
         * self-certification is not a publish credential. */
        struct hotswap_publish_hooks commit_only;
        memset(&commit_only, 0, sizeof(commit_only));
        commit_only.commit = v2_commit;
        struct hotswap_activate_report unprobed;
        memset(&unprobed, 0, sizeof(unprobed));
        ASSERT(!hotswap_module_publish(&m, true, &commit_only, &unprobed));
        ASSERT_EQ(strcmp(unprobed.stage, "probe"), 0);
        ASSERT_EQ(g_commit_calls, 1);
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(),
                  (unsigned)held);

        zcl_command_registry_reset_overrides();
        zcl_command_registry_set_active(NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ── The def-derived surface the whole batch rests on ──────────────────── */

/* The consensus pin the resident compares against a module's stamped copy.
 *
 * The comparison itself lives in module_consensus_pin_ok(), reachable only with
 * a dlopen handle, so what a fabricated-struct test CAN prove is the property
 * the comparison depends on: that the compile-time constant is a well-formed
 * seal ROOT and that it still names the seal actually in the tree. Both failure
 * modes are silent and severe. A malformed constant makes the resident refuse
 * EVERY module (the pin rejects a host root that is not 64 hex), and a stale
 * one makes it accept modules compiled against a consensus core the node no
 * longer runs — the exact hazard the pin exists to close.
 *
 * This re-derives the ROOT from core/MANIFEST.sha3 in C, independently of
 * tools/lint/lintc/gate_landing_proof.c's shell parse, so the two would
 * have to be wrong the same way to agree wrongly. */
static int t_consensus_pin_matches_the_seal(void)
{
    int failures = 0;
    TEST("hot-swap consensus pin is a well-formed, current sealed-core ROOT") {
        const char *pin = ZCL_CORE_SEAL_ROOT;
        ASSERT_EQ(strlen(pin), (size_t)64);
        for (size_t i = 0; i < 64; i++) {
            char c = pin[i];
            ASSERT((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
        }

        FILE *manifest = fopen("core/MANIFEST.sha3", "r");
        ASSERT(manifest != NULL);
        char line[512];
        char root[65];
        root[0] = '\0';
        while (fgets(line, sizeof(line), manifest)) {
            if (strncmp(line, "ROOT", 4) != 0)
                continue;
            const char *p = line + 4;
            while (*p == ' ' || *p == '\t') p++;
            size_t n = strspn(p, "0123456789abcdef");
            if (n == 64) {
                memcpy(root, p, 64);
                root[64] = '\0';
            }
            break;
        }
        fclose(manifest);

        /* No ROOT line at all would make the assertion below vacuous. */
        ASSERT_EQ(strlen(root), (size_t)64);
        ASSERT_STR_EQ(pin, root);
    } _test_next:;
    return failures;
}

static int t_allowlist_is_per_file(void)
{
    int failures = 0;
    TEST("engine/composition/hotswap_swappable.def resolves leaves to their owning file") {
        ASSERT(hotswap_handler_is_swappable("core.status"));
        ASSERT(hotswap_handler_is_swappable("ops.metrics"));
        ASSERT(hotswap_handler_is_swappable("ops.health"));
        ASSERT(!hotswap_handler_is_swappable("core.consensus.pow.verify"));
        ASSERT(!hotswap_handler_is_swappable(""));
        ASSERT(!hotswap_handler_is_swappable(NULL));

        const char *owner = hotswap_swappable_source_for_leaf("core.status");
        ASSERT(owner != NULL);
        ASSERT_EQ(strcmp(owner, V2_TU_STATUS), 0);
        ASSERT_EQ(strcmp(hotswap_swappable_source_for_leaf("ops.metrics"),
                         V2_TU_META), 0);
        ASSERT_STR_EQ(hotswap_swappable_source_for_leaf("ops.health"),
                      V2_TU_OPS);
        ASSERT(hotswap_swappable_source_for_leaf("core.consensus.pow.verify")
               == NULL);

        ASSERT(hotswap_source_is_swappable(V2_TU_STATUS));
        ASSERT(!hotswap_source_is_swappable(
            "engine/controllers/src/status_native_helpers.c"));
        ASSERT_STR_EQ(hotswap_island_owner_for_path(V2_TU_STATUS),
                      V2_TU_STATUS);
        ASSERT_STR_EQ(hotswap_island_owner_for_path(
                          "engine/controllers/src/status_native_helpers.c"),
                      V2_TU_STATUS);
        ASSERT_STR_EQ(hotswap_island_owner_for_path(
                          "contexts/wallet/controllers/src/wallet_native_read_bodies.c"),
                      "contexts/wallet/controllers/src/wallet_native_handlers.c");
        ASSERT_STR_EQ(hotswap_island_owner_for_path(
                          "engine/services/src/property_catalog_service.c"),
                      V2_TU_METAVERSE);
        const char *agent_owner = hotswap_island_owner_for_path(
            "cognition/services/src/metaverse_agent_service.c");
        ASSERT(agent_owner != NULL);
        ASSERT_STR_EQ(agent_owner, V2_TU_METAVERSE);
        ASSERT_STR_EQ(hotswap_island_owner_for_path(
                          "contexts/commons/modules/metaverse/src/property_view.c"),
                      V2_TU_METAVERSE);
        ASSERT(hotswap_source_is_swappable(V2_TU_METAVERSE));
        ASSERT(hotswap_handler_is_swappable("metaverse.property.list"));
        ASSERT(hotswap_handler_is_swappable("metaverse.agent.status"));
        ASSERT(hotswap_handler_is_swappable("metaverse.agent.money"));
        ASSERT(hotswap_handler_is_swappable("metaverse.agent.liquidity"));
        ASSERT(hotswap_handler_is_swappable("metaverse.agent.audit"));
        ASSERT(hotswap_island_owner_for_path("engine/modules/storage/src/storage.c") ==
               NULL);
        ASSERT(strstr(hotswap_island_members_for_source(V2_TU_STATUS),
                      "status_native_helpers.c") != NULL);

        /* The probe leaf comes from engine/composition/hotswap_eligible.def, keyed by the
         * source file — a module never chooses its own probe. */
        const char *probe = hotswap_module_probe_leaf(V2_TU_STATUS);
        ASSERT(probe != NULL);
        ASSERT_EQ(strcmp(probe, "core.status"), 0);
        ASSERT(hotswap_module_probe_leaf("lib/consensus/src/pow.c") == NULL);
        ASSERT(hotswap_module_probe_leaf(NULL) == NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int t_parameterized_probe_catalog_is_host_owned(void)
{
    int failures = 0;
    TEST("host-owned probe catalog binds diagnostics input/schema/budget") {
        const struct zcl_hotswap_probe_case *probe =
            hotswap_module_probe_case(V2_TU_DIAGNOSTICS);
        ASSERT(probe != NULL);
        ASSERT_STR_EQ(probe->case_id, "command.ops.logs.bounded.v1");
        ASSERT_STR_EQ(probe->operation, "ops.logs");
        ASSERT_STR_EQ(probe->canonical_input_json,
                      "{\"level\":\"all\",\"max_lines\":1,"
                      "\"pattern\":\"hotswap\",\"since_secs\":1}");
        ASSERT_STR_EQ(probe->expected_schema, "zcl.ops_logs.v1");
        ASSERT_EQ((unsigned)probe->byte_budget, 2048u);
        ASSERT_STR_EQ(hotswap_module_probe_leaf(V2_TU_DIAGNOSTICS),
                      "ops.logs");
        probe = hotswap_probe_case_for_operation(
            "zcode.commons.corpus.show");
        ASSERT(probe != NULL);
        ASSERT_STR_EQ(probe->case_id, "service.corpus.show.rules.v1");
        ASSERT_STR_EQ(probe->kind, "service");
        ASSERT_STR_EQ(probe->expected_schema,
                      "zcl.zcode_commons_corpus_show.v1");
        ASSERT(strstr(probe->canonical_input_json,
                      "ae0c059c8c925464a7d9376b17687b207027833f5337dc49944bcd1b55d3be23")
               != NULL);
        ASSERT_EQ((unsigned)probe->byte_budget, 2048u);
        PASS();
    } _test_next:;
    return failures;
}

static void elf_put16(unsigned char *p, uint16_t v)
{
    p[0] = (unsigned char)v;
    p[1] = (unsigned char)(v >> 8);
}

static void elf_put32(unsigned char *p, uint32_t v)
{
    for (unsigned i = 0; i < 4; i++)
        p[i] = (unsigned char)(v >> (i * 8));
}

static void elf_put64(unsigned char *p, uint64_t v)
{
    for (unsigned i = 0; i < 8; i++)
        p[i] = (unsigned char)(v >> (i * 8));
}

static void elf_dyn(unsigned char *image, size_t slot,
                    uint64_t tag, uint64_t value)
{
    const size_t off = 512u + slot * 16u;
    elf_put64(image + off, tag);
    elf_put64(image + off + 8u, value);
}

/* A minimal parser fixture. It is structural evidence, not executable code:
 * one PT_LOAD covers the image, PT_DYNAMIC names bounded string/symbol/hash
 * tables, and section headers independently describe the init array. */
static void elf_fixture(unsigned char image[4096], bool with_init,
                        bool duplicate_seal)
{
    enum {
        ELF_BASE = 0x10000, STR_OFF = 1024, SYM_OFF = 1280,
        HASH_OFF = 1536, INIT_OFF = 1664, ROOT_OFF = 1728,
        ABI_OFF = 1800, SHSTR_OFF = 1984, SH_OFF = 2048
    };
    const char seal_name[] = ZCL_HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL;
    const char abi_name[] = ZCL_HOTSWAP_MODULE_SYMBOL;
    const char sh_names[] = "\0.shstrtab\0.init_array\0";
    const uint32_t seal_idx = 1;
    const uint32_t abi_idx = seal_idx + (uint32_t)sizeof(seal_name);
    const uint32_t sym_count = duplicate_seal ? 4u : 3u;

    memset(image, 0, 4096);
    memcpy(image, "\177ELF", 4);
    image[4] = 2; image[5] = 1; image[6] = 1;
    elf_put16(image + 16, 3);            /* ET_DYN */
    elf_put16(image + 18, 62);           /* EM_X86_64 */
    elf_put32(image + 20, 1);
    elf_put64(image + 32, 64);
    elf_put64(image + 40, SH_OFF);
    elf_put16(image + 52, 64);
    elf_put16(image + 54, 56);
    elf_put16(image + 56, 2);
    elf_put16(image + 58, 64);
    elf_put16(image + 60, with_init ? 3 : 2);
    elf_put16(image + 62, 1);

    elf_put32(image + 64, 1);            /* PT_LOAD */
    elf_put64(image + 64 + 16, ELF_BASE);
    elf_put64(image + 64 + 32, 4096);
    elf_put64(image + 64 + 40, 4096);
    elf_put32(image + 120, 2);           /* PT_DYNAMIC */
    elf_put64(image + 120 + 8, 512);
    elf_put64(image + 120 + 16, ELF_BASE + 512);
    elf_put64(image + 120 + 32, 9 * 16);
    elf_put64(image + 120 + 40, 9 * 16);

    size_t d = 0;
    elf_dyn(image, d++, 5, ELF_BASE + STR_OFF);
    elf_dyn(image, d++, 10, sizeof(seal_name) + sizeof(abi_name) + 1u);
    elf_dyn(image, d++, 6, ELF_BASE + SYM_OFF);
    elf_dyn(image, d++, 11, 24);
    elf_dyn(image, d++, 4, ELF_BASE + HASH_OFF);
    if (with_init) {
        elf_dyn(image, d++, 25, ELF_BASE + INIT_OFF);
        elf_dyn(image, d++, 27, 8);
    }
    elf_dyn(image, d, 0, 0);

    image[STR_OFF] = '\0';
    memcpy(image + STR_OFF + seal_idx, seal_name, sizeof(seal_name));
    memcpy(image + STR_OFF + abi_idx, abi_name, sizeof(abi_name));
    elf_put32(image + HASH_OFF, 1);
    elf_put32(image + HASH_OFF + 4, sym_count);

    unsigned char *seal_sym = image + SYM_OFF + 24;
    elf_put32(seal_sym, seal_idx);
    elf_put16(seal_sym + 6, 1);
    elf_put64(seal_sym + 8, ELF_BASE + ROOT_OFF);
    elf_put64(seal_sym + 16, 65);
    unsigned char *abi_sym = image + SYM_OFF + 48;
    elf_put32(abi_sym, abi_idx);
    elf_put16(abi_sym + 6, 1);
    elf_put64(abi_sym + 8, ELF_BASE + ABI_OFF);
    elf_put64(abi_sym + 16, 4);
    if (duplicate_seal)
        memcpy(image + SYM_OFF + 72, seal_sym, 24);
    memcpy(image + ROOT_OFF, ZCL_CORE_SEAL_ROOT, 65);
    elf_put32(image + ABI_OFF, ZCL_HOTSWAP_MODULE_ABI_V3);

    memcpy(image + SHSTR_OFF, sh_names, sizeof(sh_names));
    unsigned char *shstr = image + SH_OFF + 64;
    elf_put32(shstr, 1);
    elf_put32(shstr + 4, 3);              /* SHT_STRTAB */
    elf_put64(shstr + 16, ELF_BASE + SHSTR_OFF);
    elf_put64(shstr + 24, SHSTR_OFF);
    elf_put64(shstr + 32, sizeof(sh_names));
    if (with_init) {
        unsigned char *init = image + SH_OFF + 128;
        elf_put32(init, 11);
        elf_put32(init + 4, 14);          /* SHT_INIT_ARRAY */
        elf_put64(init + 16, ELF_BASE + INIT_OFF);
        elf_put64(init + 24, INIT_OFF);
        elf_put64(init + 32, 8);
    }
}

static int fixture_fd(const unsigned char image[4096], char path[64])
{
    snprintf(path, 64, "/tmp/z23-hotswap-elf-XXXXXX");
    int fd = mkstemp(path);
    if (fd < 0)
        return -1;
    size_t off = 0;
    while (off < 4096) {
        ssize_t n = write(fd, image + off, 4096 - off);
        if (n <= 0) {
            close(fd);
            unlink(path);
            return -1;
        }
        off += (size_t)n;
    }
    (void)lseek(fd, 0, SEEK_SET);
    return fd;
}

static int t_pre_map_policy_is_zero_execution(void)
{
    int failures = 0;
    TEST("pre-map policy requires exact identity and zero callbacks") {
        struct hotswap_elf_facts facts = {0};
        char err[256];
        memcpy(facts.core_seal_root, ZCL_CORE_SEAL_ROOT, 65);
        facts.core_seal_root_present = true;
        facts.abi_version = ZCL_HOTSWAP_MODULE_ABI_V3;
        facts.abi_version_present = true;
        ASSERT(hotswap_elf_pre_map_admit(
            &facts, ZCL_CORE_SEAL_ROOT, ZCL_HOTSWAP_MODULE_ABI_V3,
            err, sizeof(err)));
        facts.has_dt_init = true;
        ASSERT(!hotswap_elf_pre_map_admit(
            &facts, ZCL_CORE_SEAL_ROOT, ZCL_HOTSWAP_MODULE_ABI_V3,
            err, sizeof(err)));
        ASSERT(strstr(err, "DT_INIT") != NULL);
        facts.has_dt_init = false;
        facts.init_array_entries = 1;
        ASSERT(!hotswap_elf_pre_map_admit(
            &facts, ZCL_CORE_SEAL_ROOT, ZCL_HOTSWAP_MODULE_ABI_V3,
            err, sizeof(err)));
        facts.init_array_entries = 0;
        facts.core_seal_root_present = false;
        ASSERT(!hotswap_elf_pre_map_admit(
            &facts, ZCL_CORE_SEAL_ROOT, ZCL_HOTSWAP_MODULE_ABI_V3,
            err, sizeof(err)));
        facts.core_seal_root_present = true;
        facts.abi_version_present = false;
        ASSERT(!hotswap_elf_pre_map_admit(
            &facts, ZCL_CORE_SEAL_ROOT, ZCL_HOTSWAP_MODULE_ABI_V3,
            err, sizeof(err)));
        facts.abi_version_present = true;
        facts.undefined_symbol_count = 1;
        snprintf(facts.undefined_symbols[0],
                 sizeof(facts.undefined_symbols[0]),
                 "zcl_forbidden_runtime_import");
        ASSERT(!hotswap_elf_pre_map_admit(
            &facts, ZCL_CORE_SEAL_ROOT, ZCL_HOTSWAP_MODULE_ABI_V3,
            err, sizeof(err)));
        ASSERT(strstr(err, "undeclared") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int t_elf_probe_rejects_deception(void)
{
    int failures = 0;
    TEST("ELF probe rejects pointer deception and duplicate identity") {
        unsigned char image[4096];
        char path[64], err[256];
        struct hotswap_elf_facts facts;
        elf_fixture(image, false, false);
        int fd = fixture_fd(image, path);
        ASSERT(fd >= 0);
        ASSERT(hotswap_elf_probe_fd(fd, &facts, err, sizeof(err)));
        ASSERT(hotswap_elf_pre_map_admit(
            &facts, ZCL_CORE_SEAL_ROOT, ZCL_HOTSWAP_MODULE_ABI_V3,
            err, sizeof(err)));
        close(fd); unlink(path);

        /* A defined GNU IFUNC symbol is a pre-dlsym execution path even
         * when the artifact has no DT_INIT or initializer arrays. */
        elf_fixture(image, false, false);
        elf_put32(image + 1536 + 4, 4); /* DT_HASH nchain: one extra symbol */
        image[1280 + 72 + 4] = 0x1a;    /* STB_GLOBAL | STT_GNU_IFUNC */
        elf_put16(image + 1280 + 72 + 6, 1);
        fd = fixture_fd(image, path);
        ASSERT(fd >= 0);
        ASSERT(hotswap_elf_probe_fd(fd, &facts, err, sizeof(err)));
        ASSERT(facts.ifunc_symbol_count == 1);
        ASSERT(!hotswap_elf_pre_map_admit(
            &facts, ZCL_CORE_SEAL_ROOT, ZCL_HOTSWAP_MODULE_ABI_V3,
            err, sizeof(err)));
        ASSERT(strstr(err, "IFUNC") != NULL);
        close(fd); unlink(path);

        /* IRELATIVE can call a local resolver without an IFUNC dynsym entry. */
        elf_fixture(image, false, false);
        elf_dyn(image, 5, 7, 0x10000 + 1900); /* DT_RELA */
        elf_dyn(image, 6, 8, 24);             /* DT_RELASZ */
        elf_dyn(image, 7, 9, 24);             /* DT_RELAENT */
        elf_dyn(image, 8, 0, 0);
        elf_put64(image + 1900 + 8, 37);     /* R_X86_64_IRELATIVE */
        fd = fixture_fd(image, path);
        ASSERT(fd >= 0);
        ASSERT(hotswap_elf_probe_fd(fd, &facts, err, sizeof(err)));
        ASSERT(facts.has_irelative_relocation);
        ASSERT(!hotswap_elf_pre_map_admit(
            &facts, ZCL_CORE_SEAL_ROOT, ZCL_HOTSWAP_MODULE_ABI_V3,
            err, sizeof(err)));
        ASSERT(strstr(err, "IRELATIVE") != NULL);
        close(fd); unlink(path);

        /* The dynamic hash's symbol count must cover every relocation's
         * symbol index; otherwise an IFUNC could hide past the audited walk. */
        elf_put64(image + 1900 + 8, (UINT64_C(3) << 32) | 1u);
        fd = fixture_fd(image, path);
        ASSERT(fd >= 0);
        ASSERT(!hotswap_elf_probe_fd(fd, &facts, err, sizeof(err)));
        ASSERT(strstr(err, "relocation") != NULL);
        close(fd); unlink(path);

        elf_fixture(image, true, false);
        elf_put64(image + 2048 + 128 + 16, 0x10000 + 1664 + 8);
        fd = fixture_fd(image, path);
        ASSERT(fd >= 0);
        ASSERT(!hotswap_elf_probe_fd(fd, &facts, err, sizeof(err)));
        ASSERT(strstr(err, "disagrees") != NULL);
        close(fd); unlink(path);

        elf_fixture(image, false, true);
        fd = fixture_fd(image, path);
        ASSERT(fd >= 0);
        ASSERT(!hotswap_elf_probe_fd(fd, &facts, err, sizeof(err)));
        ASSERT(strstr(err, "duplicate") != NULL);
        close(fd); unlink(path);

        elf_fixture(image, false, false);
        elf_dyn(image, 5, 5, 0x10000 + 1024); /* duplicate DT_STRTAB */
        fd = fixture_fd(image, path);
        ASSERT(fd >= 0);
        ASSERT(!hotswap_elf_probe_fd(fd, &facts, err, sizeof(err)));
        ASSERT(strstr(err, "duplicate DT_STRTAB") != NULL);
        close(fd); unlink(path);
        PASS();
    } _test_next:;
    return failures;
}

static int t_sealed_image_is_bounded(void)
{
    int failures = 0;
    TEST("sealed image rejects oversize before copying") {
        char path[] = "/tmp/z23-hotswap-seal-XXXXXX";
        char err[256];
        int fd = mkstemp(path);
        ASSERT(fd >= 0);
        ASSERT(ftruncate(fd, (off_t)ZCL_HOTSWAP_SEALED_IMAGE_MAX_BYTES + 1) == 0);
        int sealed = hotswap_sealed_image_from_fd(fd, err, sizeof(err));
        ASSERT(sealed < 0);
        ASSERT(strstr(err, "over") != NULL);
        close(fd); unlink(path);
        PASS();
    } _test_next:;
    return failures;
}

#if defined(__linux__)
struct pure_test_image {
    unsigned char *bytes;
    size_t size;
    char directory[64];
    char source[96];
    char artifact[96];
};

static const char pure_test_source[] =
    "#include \"hotswap/hotfork_capsule.h\"\n"
    "static bool story(struct zcl_hotfork_observation_v1 *o) {"
    "o->magic=ZCL_HOTFORK_OBSERVATION_MAGIC; o->checks_run=1;"
    "o->checks_passed=1; return true;}\n"
    "__attribute__((visibility(\"default\"))) "
    "const struct zcl_hotfork_capsule_v1 zcl_hotfork_capsule_v1={"
    ".abi_version=ZCL_HOTFORK_CAPSULE_ABI_V1,"
    ".descriptor_size=sizeof(struct zcl_hotfork_capsule_v1),"
    ".owner_id=\"owner\",.source_tu=\"source\","
    ".candidate_object_root=\"object\",.story_id=\"story\","
    ".story_root=\"root\",.story_fixture_root=\"fixture\",.run_story=story};\n";

static void pure_test_release(struct pure_test_image *image)
{
    free(image->bytes);
    (void)unlink(image->artifact);
    (void)unlink(image->source);
    (void)rmdir(image->directory);
    memset(image, 0, sizeof(*image));
}

static bool pure_test_write_source(const char *path, const char *extra)
{
    FILE *source = fopen(path, "wb");
    if (!source) return false;
    bool wrote = fwrite(pure_test_source, 1, sizeof(pure_test_source) - 1u, source) ==
                 sizeof(pure_test_source) - 1u;
    bool appended = fputs(extra, source) >= 0;
    return fclose(source) == 0 && wrote && appended;
}

static bool pure_test_read_artifact(struct pure_test_image *image)
{
    FILE *artifact = fopen(image->artifact, "rb");
    if (!artifact) return false;
    struct stat st;
    bool bounded = fstat(fileno(artifact), &st) == 0 && st.st_size > 0 &&
                   st.st_size <= 65536;
    image->size = bounded ? (size_t)st.st_size : 0;
    image->bytes = bounded ? malloc(image->size) : NULL;
    bool read = image->bytes && fread(image->bytes, 1, image->size, artifact) == image->size;
    return fclose(artifact) == 0 && read;
}

static bool pure_test_compile(struct pure_test_image *image, const char *extra)
{
    memset(image, 0, sizeof(*image));
    (void)snprintf(image->directory, sizeof(image->directory),
                   "test-tmp/hotfork-pure-XXXXXX");
    if (!mkdtemp(image->directory)) return false;
    (void)snprintf(image->source, sizeof(image->source), "%s/capsule.c", image->directory);
    (void)snprintf(image->artifact, sizeof(image->artifact), "%s/capsule.so", image->directory);
    if (!pure_test_write_source(image->source, extra)) return false;
    const char *compiler = getenv("ZCL_HOTFORK_PURE_FIXTURE_CC");
    if (!compiler) compiler = "cc";
    if (strcmp(compiler, "cc") != 0 && strcmp(compiler, "clang") != 0) return false;
    char command[512];
    int n = snprintf(command, sizeof(command),
        "%s -std=c23 -shared -nostdlib -fPIC -fvisibility=hidden "
        "-fcf-protection=none -fno-unwind-tables -fno-asynchronous-unwind-tables "
        "-Wl,-z,now,-z,relro,--no-undefined -Iengine/modules/hotswap/include "
        "%s -o %s", compiler, image->source, image->artifact);
    printf("[pure fixture compiler=%s] ", compiler);
    if (n < 0 || (size_t)n >= sizeof(command) || system(command) != 0) return false;
    return pure_test_read_artifact(image);
}

static int pure_test_seal(const struct pure_test_image *image, char err[256])
{
    int fd = open(image->artifact, O_RDWR | O_TRUNC | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < image->size) {
        ssize_t n = write(fd, image->bytes + off, image->size - off);
        if (n <= 0) { close(fd); return -1; }
        off += (size_t)n;
    }
    int sealed = hotswap_sealed_image_from_fd(fd, err, 256);
    close(fd);
    return sealed;
}

static int t_pure_hotfork_real_capsule(void)
{
    int failures = 0;
    struct pure_test_image image = {0};
    int fd = -1;
    TEST("pure HOT_FORK profile accepts existing ABI from actual compiler bytes") {
        ASSERT(pure_test_compile(&image, ""));
        char err[256];
        int unsealed = open(image.artifact, O_RDONLY | O_CLOEXEC);
        ASSERT(unsealed >= 0);
        struct hotswap_elf_hotfork_pure_facts facts;
        bool unsealed_accepted = hotswap_elf_hotfork_pure_fd(unsealed, &facts, err, sizeof(err));
        close(unsealed);
        ASSERT(!unsealed_accepted);
        ASSERT(strstr(err, "kernel-sealed") != NULL);
        fd = pure_test_seal(&image, err);
        ASSERT(fd >= 0);
        bool qualified = hotswap_elf_hotfork_pure_fd(fd, &facts, err, sizeof(err));
        printf("[qualified=%d reason=%s] ", qualified, err);
        ASSERT(qualified);
        ASSERT_EQ(facts.abi_version, ZCL_HOTFORK_CAPSULE_ABI_V1);
        ASSERT_EQ(facts.descriptor_size, sizeof(struct zcl_hotfork_capsule_v1));
        ASSERT_EQ(facts.exported_symbols, 1u);
        ASSERT_EQ(facts.relative_relocations, 7u);
        ASSERT(fcntl(fd, F_GETFD) >= 0);
        PASS();
    } _test_next:;
    if (fd >= 0) close(fd);
    pure_test_release(&image);
    return failures;
}

/* These helpers locate tables only in the compiler-produced positive fixture.
 * They are test mutation coordinates, never receiver parsing authority. */
static uint64_t pure_test_read(const unsigned char *p, size_t bytes)
{
    uint64_t value = 0;
    for (size_t i = 0; i < bytes; i++) value |= (uint64_t)p[i] << (8u * i);
    return value;
}

static size_t pure_test_section(const struct pure_test_image *image, uint32_t kind)
{
    size_t offset = (size_t)pure_test_read(image->bytes + 40, 8);
    size_t count = (size_t)pure_test_read(image->bytes + 60, 2);
    if (offset > image->size || count > (image->size - offset) / 64u) return 0;
    for (size_t i = 0; i < count; i++) {
        const unsigned char *s = image->bytes + offset + i * 64u;
        if (pure_test_read(s + 4, 4) == kind)
            return (size_t)pure_test_read(s + 24, 8);
    }
    return 0;
}

static bool pure_test_refused(struct pure_test_image *image, const char *label)
{
    char err[256];
    int fd = pure_test_seal(image, err);
    if (fd < 0) return false;
    struct hotswap_elf_hotfork_pure_facts facts;
    memset(&facts, 0xa5, sizeof(facts));
    bool accepted = hotswap_elf_hotfork_pure_fd(fd, &facts, err, sizeof(err));
    close(fd);
    static const struct hotswap_elf_hotfork_pure_facts zero;
    printf("[%s refused=%d reason=%s] ", label, !accepted, err);
    return !accepted && err[0] && memcmp(&facts, &zero, sizeof(facts)) == 0;
}

static size_t pure_test_dynamic_row(const struct pure_test_image *image, uint64_t tag)
{
    size_t offset = pure_test_section(image, 6);
    if (!offset) return 0;
    for (size_t i = 0; i < 32u && offset + (i + 1u) * 16u <= image->size; i++) {
        if (pure_test_read(image->bytes + offset + i * 16u, 8) == tag)
            return offset + i * 16u;
    }
    return 0;
}

static size_t pure_test_address(const struct pure_test_image *image, uint64_t address)
{
    size_t offset = (size_t)pure_test_read(image->bytes + 32, 8);
    size_t count = (size_t)pure_test_read(image->bytes + 56, 2);
    if (offset > image->size || count > (image->size - offset) / 56u) return 0;
    for (size_t i = 0; i < count; i++) {
        const unsigned char *p = image->bytes + offset + i * 56u;
        uint64_t base = pure_test_read(p + 16, 8), size = pure_test_read(p + 32, 8);
        if (pure_test_read(p, 4) == 1u && address >= base && address - base < size)
            return (size_t)(pure_test_read(p + 8, 8) + address - base);
    }
    return 0;
}

static size_t pure_test_program(const struct pure_test_image *image, uint32_t kind)
{
    size_t offset = (size_t)pure_test_read(image->bytes + 32, 8);
    size_t count = (size_t)pure_test_read(image->bytes + 56, 2);
    if (offset > image->size || count > (image->size - offset) / 56u) return 0;
    for (size_t i = 0; i < count; i++)
        if (pure_test_read(image->bytes + offset + i * 56u, 4) == kind)
            return offset + i * 56u;
    return 0;
}

struct pure_test_mutation {
    const char *label;
    size_t offset;
    size_t width;
    uint64_t value;
};

static bool pure_test_mutations(struct pure_test_image *image,
    const struct pure_test_mutation *rows, size_t count)
{
    unsigned char *gold = malloc(image->size);
    if (!gold) return false;
    memcpy(gold, image->bytes, image->size);
    bool passed = true;
    for (size_t i = 0; i < count; i++) {
        memcpy(image->bytes, gold, image->size);
        if (rows[i].offset > image->size ||
            rows[i].width > image->size - rows[i].offset) { passed = false; break; }
        for (size_t j = 0; j < rows[i].width; j++)
            image->bytes[rows[i].offset + j] = (unsigned char)(rows[i].value >> (8u * j));
        if (!pure_test_refused(image, rows[i].label)) { passed = false; break; }
    }
    memcpy(image->bytes, gold, image->size);
    free(gold);
    return passed;
}

static int t_pure_hotfork_mutations(void)
{
    int failures = 0;
    struct pure_test_image image = {0};
    TEST("pure HOT_FORK refuses compiler-image structural mutations") {
        ASSERT(pure_test_compile(&image, ""));
        size_t dynamic = pure_test_dynamic_row(&image, 30);
        size_t symbols = pure_test_section(&image, 11);
        size_t relocations = pure_test_section(&image, 4);
        size_t programs = (size_t)pure_test_read(image.bytes + 32, 8);
        ASSERT(dynamic && symbols && relocations && programs);
        uint64_t descriptor_address = pure_test_read(image.bytes + symbols + 24 + 8, 8);
        size_t descriptor = pure_test_address(&image, descriptor_address);
        ASSERT(descriptor);
        size_t stack = pure_test_program(&image, UINT32_C(0x6474e551));
        size_t sections = (size_t)pure_test_read(image.bytes + 40, 8);
        ASSERT(stack && sections + 128u <= image.size);
        const struct pure_test_mutation rows[] = {
            {"bad magic", 0, 1, 0}, {"wrong class", 4, 1, 1},
            {"wrong CPU", 18, 2, 183}, {"wrong ELF ABI", 7, 1, 9},
            {"entry point", 24, 8, 1},
            {"TLS program", stack, 4, 7},
            {"GNU_PROPERTY", stack, 4, UINT32_C(0x6474e553)},
            {"unknown program", stack, 4, 999},
            {"executable stack", stack + 4, 4, 7},
            {"W+X program", programs + 4, 4, 7},
            {"TLS section", sections + 64u + 8u, 8, UINT64_C(0x402)},
            {"W+X section", sections + 64u + 8u, 8, 7},
            {"init section", sections + 64u + 4u, 4, 14},
            {"fini section", sections + 64u + 4u, 4, 15},
            {"preinit section", sections + 64u + 4u, 4, 16},
            {"DT_NEEDED", dynamic, 8, 1},
            {"DT_INIT", dynamic, 8, 12}, {"DT_FINI", dynamic, 8, 13},
            {"RPATH", dynamic, 8, 15}, {"FILTER", dynamic, 8, UINT64_C(0x7fffffff)},
            {"AUXILIARY", dynamic, 8, UINT64_C(0x7ffffffd)},
            {"RELR", dynamic, 8, 36},
            {"undefined import", symbols + 24 + 6, 2, 0},
            {"IFUNC", symbols + 24 + 4, 1, 0x1a},
            {"TLS symbol", symbols + 24 + 4, 1, 0x16},
            {"wrong descriptor size", symbols + 24 + 16, 8, 8},
            {"wrong capsule ABI", descriptor, 4, 999},
            {"wrong capsule size", descriptor + 8, 8, 8},
            {"unbounded descriptor", symbols + 24 + 8, 8, UINT64_MAX},
            {"IRELATIVE", relocations + 8, 8, 37},
            {"unknown relocation", relocations + 8, 8, 999},
            {"symbol relocation", relocations + 8, 8, UINT64_C(0x100000008)},
            {"unbounded target", relocations, 8, UINT64_MAX - 7u},
            {"descriptor header target", relocations, 8, descriptor_address},
            {"writable string", relocations + 16, 8, descriptor_address},
            {"nonexecuting story", relocations + 6u * 24u + 16u, 8, descriptor_address},
            {"unbounded addend", relocations + 16, 8, UINT64_MAX},
            {"duplicate target", relocations + 24, 8, pure_test_read(image.bytes + relocations, 8)}
        };
        ASSERT(pure_test_mutations(&image, rows, sizeof(rows) / sizeof(rows[0])));
        PASS();
    } _test_next:;
    pure_test_release(&image);
    return failures;
}

static int t_pure_hotfork_duplicate_export(void)
{
    int failures = 0;
    struct pure_test_image image = {0};
    TEST("pure HOT_FORK refuses a real descriptor alias renamed to duplicate export") {
        ASSERT(pure_test_compile(&image,
            "extern const struct zcl_hotfork_capsule_v1 capsule_alias "
            "__attribute__((alias(\"zcl_hotfork_capsule_v1\"),visibility(\"default\")));\n"));
        size_t symbols = pure_test_section(&image, 11);
        ASSERT(symbols && symbols + 72 <= image.size);
        /* Both actual linker symbols alias the same descriptor. Renaming
         * their dynstr references must not turn two exports into one fact. */
        uint64_t name = pure_test_read(image.bytes + symbols + 24, 4);
        elf_put32(image.bytes + symbols + 48, (uint32_t)name);
        ASSERT(pure_test_refused(&image, "duplicate capsule alias"));
        PASS();
    } _test_next:;
    pure_test_release(&image);
    return failures;
}
#endif

static int t_pure_hotfork_refuses_generic_module(void)
{
    int failures = 0;
    TEST("pure HOT_FORK profile refuses a well-formed generic ABI module") {
        struct hotswap_elf_hotfork_pure_facts facts;
        char err[256];
#if defined(__linux__)
        unsigned char image[4096];
        char path[64];
        elf_fixture(image, false, false);
        int fd = fixture_fd(image, path);
        ASSERT(fd >= 0);
        int sealed = hotswap_sealed_image_from_fd(fd, err, sizeof(err));
        ASSERT(sealed >= 0);
        ASSERT(!hotswap_elf_hotfork_pure_fd(sealed, &facts, err, sizeof(err)));
        close(sealed); close(fd); unlink(path);
#else
        ASSERT(!hotswap_elf_hotfork_pure_fd(-1, &facts, err, sizeof(err)));
        ASSERT(strstr(err, "requires Linux") != NULL);
#endif
        PASS();
    } _test_next:;
    return failures;
}

int test_hotswap_module_v2(void);

int test_hotswap_module_v2(void)
{
    int failures = 0;
    failures += t_allowlist_is_per_file();
#if !defined(_WIN32)
    failures += t_macho_fat_magic_bounds();
#endif
    failures += t_parameterized_probe_catalog_is_host_owned();
    failures += t_partial_admit_publishes_nothing();
    failures += t_duplicate_leaf_refused();
    failures += t_old_abi_refused();
    failures += t_leaf_cap_refused();
    failures += t_generation_monotonic();
    failures += t_probe_mismatch_publishes_nothing();
    failures += t_consensus_pin_matches_the_seal();
    failures += t_pre_map_policy_is_zero_execution();
    failures += t_elf_probe_rejects_deception();
    failures += t_sealed_image_is_bounded();
    failures += t_pure_hotfork_refuses_generic_module();
#if defined(__linux__)
    failures += t_pure_hotfork_real_capsule();
    failures += t_pure_hotfork_mutations();
    failures += t_pure_hotfork_duplicate_export();
#endif
    zcl_command_registry_reset_overrides();
    zcl_command_registry_set_active(NULL);
    printf("=== hotswap_module_v2: %d failures ===\n", failures);
    return failures;
}
