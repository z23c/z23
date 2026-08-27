/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the depth-1 hot-swap ROLLBACK SHELF (hotswap/hotswap_shelf.h):
 * when a real, dlopen'd module image is superseded, its previously-live
 * sealed image (a dup() of the memfd) is retained — one slot per source file
 * — so hotswap_rollback() can put it back by re-entering the SAME admission
 * gauntlet the forward path uses (activate_from_sealed_fd(), with the dev
 * datadir and -hotswap-activate/ZCL_HOTSWAP_ACTIVATE=1 gate re-checked at
 * rollback time, not remembered from the original activation).
 *
 * WHY THIS FILE FABRICATES NOTHING SHELVED, UNLIKE test_hotswap_module_v2.c.
 * That file (and this one, for its own admit/publish assertions) drives the
 * pure, always-compiled hotswap_module_publish() with a struct FABRICATED in
 * the test TU — no dlopen, no real .so. An earlier version of this file
 * relied on a MODULE-backed shelf branch that let a bare
 * hotswap_module_publish() call populate a shelf slot directly. That branch
 * was deliberately REMOVED by the owning lane: it was reachable from
 * hotswap_module_publish(), which is compiled into every build (not just
 * dev), and it bypassed dev-datadir confinement, the activation gate, the
 * seal, the ELF shape probe, both digests, dlopen/dlsym, and the sealed-core
 * consensus pin. Verified directly against the current source
 * (lib/hotswap/src/hotswap_activate.c): slot_for_source_locked() is now
 * called only from the real loader's commit block inside the dev region, so
 * hotswap_module_publish() alone — no matter how many times, for any source —
 * creates no slot, and no slot means no shelf entry (t_pure_publish_never_
 * shelves proves exactly this against the resident's own accounting).
 *
 * FEASIBILITY OF THE IMAGE PATH FROM THIS GROUP: checked and NOT drivable
 * here.
 *   - Producing a shelved image needs a real, compiled, consensus-pinned,
 *     ELF-shape-clean module .so (`make hotswap-module-so` /
 *     tools/dev/hotswap-module-fast.sh / `make hotswap-test-so`), which is a
 *     separate build step outside this lane's owned files (no fixture .c, no
 *     Makefile rule).
 *   - The one mechanism that loads a real module .so INTO a test_parallel
 *     process (ZCL_HOTSWAP_TEST_MODULE / ZCL_HOTSWAP_TEST_AUTH, read once by
 *     hotswap_module_mode_begin() in lib/test/src/test_parallel.c) activates
 *     a SINGLE module for the WHOLE process before any group forks — it is
 *     a `make t-hotswap`-only, one-shot dev-loop mode, explicitly labeled
 *     "NOT a linked-binary run" whose own banner says to re-run
 *     `make t-fast ONLY=<group>` "before treating any verdict as a gate". It
 *     has no facility for activating a SECOND module afterward to produce a
 *     genuine supersede, so it cannot build a shelf/rollback/toggle
 *     narrative even in principle.
 *   - Even granting a shelved image, hotswap_rollback()'s CLAIM_OK path
 *     re-checks hotswap_activation_authorized() at rollback time: the exact
 *     dev datadir AND the -hotswap-activate flag AND ZCL_HOTSWAP_ACTIVATE=1.
 *     Nothing in a `test_parallel` invocation sets the flag.
 *   - This matches existing precedent: test_hotswap_module.c's own "real
 *     loader" tests (test_loader_refuses_unconfined_input,
 *     test_loader_refuses_non_dev_datadir) only ever drive a nonexistent/fake
 *     so_path to prove a PRECHECK refusal; nothing in the hermetic suite
 *     drives a real successful dlopen.
 *
 * CONSEQUENCE, reported plainly rather than papered over: peek/list
 * reporting a genuine superseded artifact_sha256 (computed from the sealed
 * descriptor); rollback actually restoring a DIFFERENT live handler and
 * dispatch proving it; rollback as a toggle; generation monotonicity across
 * a real rollback; depth-1 eviction across three real supersedes; and a
 * mid-gauntlet rollback refusal leaving a real live handler untouched are
 * UNVERIFIED by any test in this tree today — not just this file. Proving
 * them needs an image-mode harness that can activate two distinct real
 * modules in sequence with the activation gate satisfied, which does not
 * currently exist. That is a real coverage gap, not something this file can
 * relocate to an already-existing target.
 *
 * What IS proven here, against the real resident accounting (no mocks):
 *   - the shelf starts empty and stays empty for any source, including
 *     NULL/empty source_tu (peek false, list 0);
 *   - repeated pure-gauntlet publishes for the SAME source (exactly the
 *     forward path test_hotswap_module_v2.c exercises) shelve NOTHING;
 *   - hotswap_rollback() on such a source — allowlisted or not, touched by
 *     the pure gauntlet or not, empty/NULL — fails cleanly: report->ok is
 *     false, report->rolled_back is true, report->stage is "shelf" (CLAIM_
 *     NO_SLOT — "has never been activated in this process"), report->error
 *     is populated, and neither the live command-registry generation nor
 *     dispatch output changes;
 *   - hotswap_shelf_list's count-only mode (cap=0, out=NULL) works.
 *
 * "Unchanged" dispatch comparisons use the `who` marker via strstr, never
 * strcmp on the whole envelope: the reply carries a per-call request_id and
 * elapsed_us/elapsed_ms (lib/kernel/src/command_registry.c), so two
 * genuinely identical dispatches are never byte-identical JSON.
 */

#include "test/test_helpers.h"

#include "hotswap/hotswap.h"
#include "hotswap/hotswap_module.h"
#include "hotswap/hotswap_shelf.h"
#include "kernel/command_registry.h"
#include "json/json.h"

#include <string.h>

/* The status controller row of config/hotswap_swappable.def; its declared
 * probe leaf in config/hotswap_eligible.def is core.status (proven by
 * test_hotswap_module_v2.c's t_allowlist_is_per_file). Used only to drive the
 * PURE gauntlet (hotswap_module_publish) — never the real dlopen path. */
#define SHELF_TU "app/controllers/src/status_native_handlers.c"
/* A different allowlisted row, touched by nothing in this file. */
#define SHELF_TU_META "app/controllers/src/meta_native_handlers.c"
/* Never allowlisted at all (a consensus TU). */
#define SHELF_TU_UNKNOWN "lib/consensus/src/pow.c"

static void h_a(const struct zcl_command_request *request,
                struct zcl_command_reply *reply)
{
    (void)request;
    (void)json_push_kv_str(&reply->data, "who", "shelf_a");
}

static bool selftest_true(char *err, size_t cap)
{
    (void)err;
    (void)cap;
    return true;
}

static const struct zcl_hotswap_leaf k_leaves_a[] = { { "core.status", h_a } };
static const struct zcl_hotswap_module k_mod_a = {
    .abi_version = ZCL_HOTSWAP_MODULE_ABI_V2,
    .source_tu = SHELF_TU, .leaf_count = 1,
    .leaves = k_leaves_a, .self_test = selftest_true,
};

/* ── Fabricated publish hooks — same shape as test_hotswap_module_v2.c ── */

static bool shelf_commit(void *ctx, const struct zcl_hotswap_leaf *leaves,
                         size_t leaf_count, uint32_t *out_gen, char *why,
                         size_t why_sz)
{
    (void)ctx;
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
    if (!zcl_command_registry_replace_batch(0, ovr, leaf_count, why, why_sz))
        return false;
    if (out_gen)
        *out_gen = zcl_command_registry_active_generation();
    return true;
}

static bool shelf_probe(void *ctx, const char *leaf, zcl_hotswap_handler_fn fn,
                        char *why, size_t why_sz)
{
    (void)ctx;
    (void)leaf;
    if (!fn) {
        if (why && why_sz) snprintf(why, why_sz, "probe handler is NULL");
        return false;
    }
    return true;
}

static void shelf_hooks(struct hotswap_publish_hooks *h)
{
    memset(h, 0, sizeof(*h));
    h->commit = shelf_commit;
    h->probe = shelf_probe;
}

/* ── A registry the override layer can validate against ──────────────── */
static const struct zcl_command_spec g_shelf_specs[] = {
    { .path = "core.status", .summary = "swappable read leaf",
      .layer = ZCL_COMMAND_LAYER_CORE, .effect = ZCL_COMMAND_EFFECT_READ,
      .availability = ZCL_COMMAND_READY, .mode = ZCL_COMMAND_MODE_SYNC,
      .allowed_lanes = ZCL_COMMAND_LANE_LOCAL, .handler = h_a },
};
static const struct zcl_command_registry g_shelf_reg = {
    .commands = g_shelf_specs,
    .count = sizeof(g_shelf_specs) / sizeof(g_shelf_specs[0]),
};

static enum zcl_command_exit shelf_dispatch(char *out, size_t out_size)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    enum zcl_command_exit ec = ZCL_COMMAND_EXIT_INTERNAL;
    (void)zcl_command_registry_execute_json(&g_shelf_reg, &g_shelf_specs[0],
                                            NULL, &input, false,
                                            "core.status", "normal", 0, 0,
                                            NULL, out, out_size, &ec);
    json_free(&input);
    return ec;
}

static void shelf_reset(void)
{
    zcl_command_registry_reset_overrides();
    zcl_command_registry_set_active(&g_shelf_reg);
}

/* ── 1. Depth constant + nothing shelved anywhere, before anything runs ──── */

static int t_nothing_shelved_initially(void)
{
    int failures = 0;
    TEST("depth is 1, and nothing is shelved before any real activation ever happens") {
        ASSERT_EQ((unsigned)ZCL_HOTSWAP_SHELF_DEPTH, (unsigned)1);

        struct hotswap_shelf_entry e;
        memset(&e, 0, sizeof(e));
        ASSERT(!hotswap_shelf_peek(SHELF_TU, &e));
        ASSERT(!hotswap_shelf_peek(SHELF_TU_META, &e));
        ASSERT(!hotswap_shelf_peek(SHELF_TU_UNKNOWN, &e));
        ASSERT(!hotswap_shelf_peek("", &e));
        ASSERT(!hotswap_shelf_peek(NULL, &e));

        /* Count-only mode: cap=0/out=NULL must not crash and must report the
         * true (zero) count. */
        ASSERT_EQ(hotswap_shelf_list(NULL, 0), (size_t)0);
        struct hotswap_shelf_entry arr[4];
        ASSERT_EQ(hotswap_shelf_list(arr, 4), (size_t)0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 2. The pure admit/probe/commit gauntlet never touches the shelf ─────── */

static int t_pure_publish_never_shelves(void)
{
    int failures = 0;
    TEST("repeated pure hotswap_module_publish() calls shelve nothing (shelving "
         "is a property of the real dlopen activation path, not the gauntlet)") {
        shelf_reset();
        struct hotswap_publish_hooks hooks;
        shelf_hooks(&hooks);

        uint32_t prev_gen = 0;
        for (int i = 0; i < 3; i++) {
            struct hotswap_activate_report rep;
            memset(&rep, 0, sizeof(rep));
            /* The caller owns artifact_sha256 (hotswap_module_publish does not
             * memset or fill it) — stamp a fabricated digest so a shelf write,
             * if it happened, would be observable. */
            memset(rep.artifact_sha256, 'a' + i, 64);
            rep.artifact_sha256[64] = '\0';
            ASSERT(hotswap_module_publish(&k_mod_a, /*request_activate=*/true,
                                          &hooks, &rep));
            ASSERT(rep.ok);
            ASSERT(rep.activated);
            ASSERT(rep.generation > prev_gen);
            prev_gen = rep.generation;

            struct hotswap_shelf_entry e;
            memset(&e, 0, sizeof(e));
            ASSERT(!hotswap_shelf_peek(SHELF_TU, &e));
        }
        struct hotswap_shelf_entry arr[4];
        ASSERT_EQ(hotswap_shelf_list(arr, 4), (size_t)0);

        char out[4096];
        ASSERT_EQ((int)shelf_dispatch(out, sizeof(out)), (int)ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "\"who\":\"shelf_a\"") != NULL);

        zcl_command_registry_reset_overrides();
        zcl_command_registry_set_active(NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 3. Rollback of a source with no real activation fails cleanly ───────── */

static int t_rollback_never_activated_fails_cleanly(void)
{
    int failures = 0;
    TEST("rollback of a source never REALLY activated fails cleanly and changes nothing") {
        shelf_reset();
        uint32_t before_gen = zcl_command_registry_active_generation();

        struct hotswap_publish_hooks hooks;
        shelf_hooks(&hooks);

        /* (a) a source that was never touched by anything at all. */
        struct hotswap_activate_report rep_unknown;
        memset(&rep_unknown, 0, sizeof(rep_unknown));
        ASSERT(!hotswap_rollback(SHELF_TU_UNKNOWN, &hooks, &rep_unknown));
        ASSERT(!rep_unknown.ok);
        ASSERT(rep_unknown.rolled_back);
        ASSERT_EQ(strcmp(rep_unknown.stage, "shelf"), 0);
        ASSERT(rep_unknown.error[0] != '\0');

        /* (b) a different allowlisted source, also never touched here. */
        struct hotswap_activate_report rep_meta;
        memset(&rep_meta, 0, sizeof(rep_meta));
        ASSERT(!hotswap_rollback(SHELF_TU_META, &hooks, &rep_meta));
        ASSERT(!rep_meta.ok);
        ASSERT_EQ(strcmp(rep_meta.stage, "shelf"), 0);
        ASSERT(rep_meta.error[0] != '\0');

        /* (c) SHELF_TU itself, having only ever gone through the pure gauntlet
         * (never the real activation path) in this process — see test 2. No
         * slot was ever created for it, so this is still CLAIM_NO_SLOT, not
         * "nothing shelved for an activated source" (CLAIM_EMPTY). */
        struct hotswap_activate_report rep_pure;
        memset(&rep_pure, 0, sizeof(rep_pure));
        ASSERT(!hotswap_rollback(SHELF_TU, &hooks, &rep_pure));
        ASSERT(!rep_pure.ok);
        ASSERT_EQ(strcmp(rep_pure.stage, "shelf"), 0);
        ASSERT(strstr(rep_pure.error, "never been activated") != NULL);

        /* (d) empty/NULL source_tu is refused before any slot lookup. */
        struct hotswap_activate_report rep_empty;
        memset(&rep_empty, 0, sizeof(rep_empty));
        ASSERT(!hotswap_rollback("", &hooks, &rep_empty));
        ASSERT(!rep_empty.ok);
        struct hotswap_activate_report rep_null;
        memset(&rep_null, 0, sizeof(rep_null));
        ASSERT(!hotswap_rollback(NULL, &hooks, &rep_null));
        ASSERT(!rep_null.ok);

        /* Nothing published: the registry generation never moved, and the
         * shelf remains empty for the source the pure gauntlet touched. */
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(),
                  (unsigned)before_gen);
        struct hotswap_shelf_entry e;
        memset(&e, 0, sizeof(e));
        ASSERT(!hotswap_shelf_peek(SHELF_TU, &e));

        char out[4096];
        ASSERT_EQ((int)shelf_dispatch(out, sizeof(out)), (int)ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "\"who\":\"shelf_a\"") != NULL);

        zcl_command_registry_reset_overrides();
        zcl_command_registry_set_active(NULL);
        PASS();
    } _test_next:;
    return failures;
}

int test_hotswap_shelf(void);

int test_hotswap_shelf(void)
{
    int failures = 0;
    failures += t_nothing_shelved_initially();
    failures += t_pure_publish_never_shelves();
    failures += t_rollback_never_activated_fails_cleanly();
    zcl_command_registry_reset_overrides();
    zcl_command_registry_set_active(NULL);
    printf("=== hotswap_shelf: %d failures ===\n", failures);
    return failures;
}
