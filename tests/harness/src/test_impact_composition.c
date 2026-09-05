/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_impact_composition — adversarial proof that the two impact-planning
 * systems COMPOSE honestly.
 *
 * The two systems both stay. Neither is a cache of the other:
 *   A = cognition/controllers/include/controllers/agent_impact_rules.def, hand-
 *       authored judgement mapping a changed PATH to TEST GROUP NAMES. Not
 *       derivable from any graph; ~40% of the file is the rationale.
 *   B = cognition/modules/codeindex/, a scanned call graph plus the compiler's own depfiles,
 *       mapping a changed FILE to downstream FILES.
 *
 * What this group pins is the COMPOSITION, and specifically the four ways it
 * used to lie:
 *   T1  a bound firing threw the ENTIRE partial closure away, so five of twelve
 *       representative changes — every hub header, all consensus crypto, and
 *       sealed core — planned exactly as if the graph had never been consulted,
 *       while reporting a plan.
 *   T2  a `*.def` registry had no reverse closure at all, so editing the file
 *       CLAUDE.md instructs every agent to edit selected nothing.
 *   T3  the call graph is the only graph that was walked, so a macro-only
 *       header (no callable symbol, therefore no callers) had a blast radius
 *       of exactly itself.
 *   T4  and the plan that resulted was still handed to callers as if it were
 *       sufficient proof.
 * T5 and T6 pin the two properties that make the fix reviewable: every selected
 * group can say which dimension named it, and the union can never lose a group
 * system A alone would have named.
 *
 * Every fixture below is a self-contained tree under test-tmp/: real source
 * files, real compiler-style depfiles, a real index build. Nothing here reads
 * the live repository index or the live datadir. */

/* realpath() is declared by glibc only through the fortify inline unless a
 * feature-test macro asks for it; without this the file compiles today by
 * accident of -O2 and is a hard C23 error at -O0 or on another libc. Must
 * precede the first #include, which is where <features.h> is read. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_core.h"

#include <errno.h>
#include <fcntl.h>
#include <utime.h>

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "codeindex/codeindex.h"
#include "command/native_dev_proof_command.h"
#include "config/command_catalog.h"
#include "controllers/agent_impact_rules.h"
#include "dev_proof.h"
#include "dev_proof_budget.h"
#include "dev_proof_receipt.h"
#include "devloop.h"
#include "json/json.h"
#include "platform/disk_space.h"
#include "platform/ram_scratch.h"
#include "platform/time_compat.h"
#include "kernel/command_registry.h"
#include "test/testcache.h"
#include "test_group_catalog.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#include <unistd.h>
#endif

#define IC_FIX_ROOT   "test-tmp/impact_composition"
#define IC_FIX_TRUNC  IC_FIX_ROOT "/trunc"
#define IC_FIX_GROUP  IC_FIX_ROOT "/groupcap"
#define IC_FIX_DEF    IC_FIX_ROOT "/registry"
#define IC_FIX_MACRO  IC_FIX_ROOT "/macro"
#define IC_FIX_NODEPS IC_FIX_ROOT "/nodeps"
#define IC_FIX_SNAPSHOT IC_FIX_ROOT "/snapshot"

/* ── fixture helpers ──────────────────────────────────────────────────── */

static bool ic_write(const char *dir, const char *rel, const char *content)
{
    char full[4096];
    snprintf(full, sizeof(full), "%s/%s", dir, rel);
    for (char *p = full + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(full, 0755); *p = '/'; }
    }
    FILE *f = fopen(full, "wb");
    if (!f) return false;
    if (content && content[0]) fwrite(content, 1, strlen(content), f);
    fclose(f);
    return true;
}

static bool ic_group_in(const char (*groups)[ZCL_DEVLOOP_GROUP_MAX],
                        size_t len, const char *g)
{
    for (size_t i = 0; i < len; i++)
        if (strcmp(groups[i], g) == 0)
            return true;
    return false;
}

/* Union membership across BOTH group arrays — the composed plan. */
static bool ic_planned(const struct zcl_devloop_plan *p, const char *g)
{
    return ic_group_in(p->path_groups, p->path_groups_len, g) ||
           ic_group_in(p->closure_groups, p->closure_groups_len, g);
}

static const struct zcl_devloop_selection *ic_selection(
    const struct zcl_devloop_plan *p, const char *group)
{
    for (size_t i = 0; i < p->selections_len; i++)
        if (strcmp(p->selections[i].group, group) == 0)
            return &p->selections[i];
    return NULL;
}

/* The two leaves every fixture shares: a definition site and one caller of it
 * that carries its own distinct impact-rule group ("download"). */
static bool ic_write_call_pair(const char *root)
{
    return ic_write(root, "core/modules/net/src/tor_integration.c",
                    "/* tor fixture */\n"
                    "#include \"net/clp.h\"\n"
                    "int tor_leaf(int x) { return x + 1; }\n") &&
           ic_write(root, "core/modules/net/src/download.c",
                    "/* download fixture */\n"
                    "#include \"net/clp.h\"\n"
                    "int dl_top(int x) { return tor_leaf(x) * 2; }\n") &&
           ic_write(root, "core/modules/net/include/net/clp.h",
                    "#ifndef NET_CLP_H\n#define NET_CLP_H\n"
                    "int tor_leaf(int x);\nint dl_top(int x);\n#endif\n");
}

/* Compiler-style depfiles. Prerequisite lists are transitively flattened by
 * the real compiler, and these mirror that: the TU on the left, every byte it
 * read on the right. */
static bool ic_write_depfiles(const char *root)
{
    return ic_write(root, "build/obj/tor_integration.d",
                    "build/obj/tor_integration.o: "
                    "core/modules/net/src/tor_integration.c "
                    "core/modules/net/include/net/clp.h\n") &&
           ic_write(root, "build/obj/download.d",
                    "build/obj/download.o: core/modules/net/src/download.c "
                    "core/modules/net/include/net/clp.h\n");
}

/* ── T1: a truncated closure keeps what the partial walk found ────────── */

/* Two independent bounds discard evidence, and BOTH used to zero the group
 * set. This fixture fires the first: one symbol with more call sites than the
 * engine's per-query fan-out batch, so codeindex_impact_closure reports
 * truncated while still returning a real, useful impacted-file set. */
static bool ic_write_fanout_caller(const char *root)
{
    /* Sorts AFTER download.c so the bounded caller query still reaches it —
     * otherwise the fan-out file alone would fill the batch and the assertion
     * below would be testing nothing. */
    const size_t calls = 5000;
    size_t cap = calls * 16 + 256;
    char *body = malloc(cap);
    if (!body) return false;
    size_t pos = 0;
    pos += (size_t)snprintf(body + pos, cap - pos,
                            "/* fan-out fixture */\n"
                            "#include \"net/clp.h\"\n"
                            "int zbig(int x) { return x");
    for (size_t i = 0; i < calls && pos + 32 < cap; i++)
        pos += (size_t)snprintf(body + pos, cap - pos, "+tor_leaf(%d)", 1);
    (void)snprintf(body + pos, cap - pos, "; }\n");
    bool ok = ic_write(root, "core/modules/net/src/zbigfanout.c", body);
    free(body);
    return ok;
}

static int test_ic_truncated_closure_preserves_groups(void)
{
    int failures = 0;
    TEST("impact composition: a truncated closure KEEPS the groups it found") {
        system("rm -rf " IC_FIX_TRUNC);
        ASSERT(ic_write_call_pair(IC_FIX_TRUNC));
        ASSERT(ic_write_depfiles(IC_FIX_TRUNC));
        ASSERT(ic_write_fanout_caller(IC_FIX_TRUNC));

        const char *files[] = { "core/modules/net/src/tor_integration.c" };
        struct zcl_devloop_plan plan;
        ASSERT(zcl_devloop_plan_files(files, 1, &plan));
        ASSERT(ic_group_in(plan.path_groups, plan.path_groups_len,
                           "test_tor"));

        ASSERT(zcl_devloop_plan_add_closure(IC_FIX_TRUNC, files, 1, &plan));
        ASSERT(plan.closure_attempted);

        /* The bound really fired — otherwise this whole case proves nothing.
         * A capacity bound is answered by the universal closure, so the
         * dimension is COMPLETE and says which answer it gave. */
        ASSERT(plan.dims[ZCL_DEVLOOP_DIM_SEMANTIC].status ==
               ZCL_DEVLOOP_DIM_COMPLETE);
        ASSERT(strcmp(plan.dims[ZCL_DEVLOOP_DIM_SEMANTIC].reason,
                      "closure-universal") == 0);
        ASSERT(plan.closure_universal);
        ASSERT(!plan.closure_truncated);

        /* C1, the whole point: INCOMPLETE is not EMPTY. The partial walk
         * reached download.c, so "download" is planned. Before this change the
         * group set was zeroed the instant truncation was seen, and the plan
         * silently degraded to the path floor. */
        ASSERT(plan.closure_groups_len > 0);
        ASSERT(ic_planned(&plan, "download"));

        /* And the path floor is still whole. */
        ASSERT(ic_group_in(plan.path_groups, plan.path_groups_len,
                           "test_tor"));

        system("rm -rf " IC_FIX_TRUNC);
        PASS();
    } _test_next:;
    return failures;
}

static int test_ic_closure_capacity_follows_corpus(void)
{
    int failures = 0;
    TEST("impact composition: planner capacity follows the verified corpus") {
        ASSERT(zcl_devloop_test_closure_file_cap(2050, 1) == 2051);
        ASSERT(zcl_devloop_test_closure_file_cap(0, 0) == 1);
        ASSERT(zcl_devloop_test_closure_file_cap(
                   CI_IMPACT_CLOSURE_MAX_FILES, 1) ==
               CI_IMPACT_CLOSURE_MAX_FILES);
        ASSERT(zcl_devloop_test_closure_file_cap(-1, 1) == -1);
        PASS();
    } _test_next:;
    return failures;
}

/* A representative high-fanout graph plan must retain substantially more
 * groups than the direct path floor without becoming incomplete. */
static const char *const ic_many_group_files[] = {
    "tests/harness/src/test_simnet_wire_ibd.c",
    "tests/harness/src/test_importblockindex_roundtrip.c",
    "tests/harness/src/test_validate_script_hash_split_repair.c",
    "tests/harness/src/test_subsystem_snapshot.c",
    "tests/harness/src/test_stage_crash_sweep.c",
    "tests/harness/src/test_stage_anchor_frontier_cap.c",
    "tests/harness/src/test_sqlite.c",
    "tests/harness/src/test_simnet_wallet_reorg.c",
    "tests/harness/src/test_simnet_value_inflation.c",
    "tests/harness/src/test_simnet_mempool_adv.c",
    "tests/harness/src/test_simnet_input_value_range.c",
    "tests/harness/src/test_simnet_fee_range.c",
    "tests/harness/src/test_simnet_empty_vin_vout.c",
    "tests/harness/src/test_simnet_duplicate_input.c",
    "tests/harness/src/test_simnet_doublespend.c",
    "tests/harness/src/test_simnet_cluster_reorg.c",
    "tests/harness/src/test_simnet_cluster.c",
    "tests/harness/src/test_simnet_chained_tx.c",
    "tests/harness/src/test_simnet_block_sigops.c",
    "tests/harness/src/test_self_folded_anchor.c",
    "tests/harness/src/test_rom_manifest.c",
    "tests/harness/src/test_simnet_fuzz.c",
    "tests/harness/src/test_command_handler_snapshot.c",
    "tests/harness/src/test_pow_diffadj_precedence.c",
    "tests/harness/src/test_always_sync_lifecycle.c",
    "tests/harness/src/test_read_leaf_no_datadir_write.c",
    "tests/harness/src/test_crypto_registry.c",
    "tests/harness/src/test_sprout_groth16_kat.c",
    "tests/harness/src/test_transaction_wire_evidence.c",
    "tests/harness/src/test_net.c",
    "tests/harness/src/test_api_query_filters.c",
    "tests/harness/src/test_bip34_coinbase_height_parity.c",
    "tests/harness/src/test_canary_sentinel_watch.c",
    "tests/harness/src/test_block_locator_bounds.c",
    "tests/harness/src/test_mint_anchor_preflight.c",
    "tests/harness/src/test_contaminated_coin_above_anchor.c",
    "tests/harness/src/test_reducer_frontier_reconcile_light.c",
    "tests/harness/src/test_reducer_reconcile_witness.c",
    "tests/harness/src/test_refold_progress_floor.c",
    "tests/harness/src/test_refold_retro_validate.c",
    "tests/harness/src/test_reorg_residue_tipfin_replace.c",
    "tests/harness/src/test_kill9_recovery.c",
    "tests/harness/src/test_block_swarm_loopback.c",
    "tests/harness/src/test_test_zmsg_memo_codec.c",
    "tests/harness/src/test_mesh_private_object_grant_pipeline.c",
    "tests/harness/src/test_json.c",
    "tests/harness/src/test_rpc.c",
    "tests/harness/src/test_coinbase_subsidy_adversarial.c",
    "tests/harness/src/test_accept_to_mempool.c",
    "tests/harness/src/test_mempool.c",
    "tests/harness/src/test_merkle_tree.c",
    "tests/harness/src/test_parity_lockin_anchor_membership.c",
    "tests/harness/src/test_sync_service.c",
    "tests/harness/src/test_principal_authz.c",
    "tests/harness/src/test_auth_login.c",
    "tests/harness/src/test_command_authority.c",
    "tests/harness/src/test_importblockindex_roundtrip.c",
    "tests/harness/src/test_cli_auth_robust.c",
    "tests/harness/src/test_chain.c",
    "tests/harness/src/test_chain_evidence_controller.c",
    "tests/harness/src/test_fast_sync.c",
    "tests/harness/src/test_keystone_utxo_binding.c",
    "tests/harness/src/test_loader_owns_seed_gate.c",
    "tests/harness/src/test_mmb.c",
    "tests/harness/src/test_utxo_snapshot_loader.c",
    "tests/harness/src/test_code_capsule.c",
    "tests/harness/src/test_zcode_commons_projection.c",
    "tests/harness/src/test_zcode_family_admission.c",
    "tests/harness/src/test_zcode_swarm_net.c",
    "tests/harness/src/test_sprout_phgr13_kat.c",
    "tests/harness/src/test_store_buyer.c",
    "tests/harness/src/test_directory_watcher.c",
    "tests/harness/src/test_watcher_record.c",
    "tests/harness/src/test_read_mapping_positioned.c",
    "tests/harness/src/test_running_image_positioned.c",
    "tests/harness/src/test_socket_resolve.c",
    "tests/harness/src/test_private_link_no_clobber.c",
    "tests/harness/src/test_replay_receipt_root.c",
    "tests/harness/src/test_file_ops_copy.c",
    "tests/harness/src/test_boot_refusal_identity.c",
    "tests/harness/src/test_boot_shutdown_marker_persistence.c",
    "tests/harness/src/test_rom_fetch_onion.c",
    "tests/harness/src/test_zcode_sovereignty_policy.c",
    "tests/harness/src/test_script.c",
    "tests/harness/src/test_zendp.c",
    "tests/harness/src/test_node_character.c",
    "tests/harness/src/test_metaverse_vocabulary_bits.c",
    "tests/harness/src/test_code_have.c",
    "tests/harness/src/test_mutation_harness.c",
};

static int test_ic_large_plan_preserves_groups(void)
{
    int failures = 0;
    TEST("impact composition: a large graph plan keeps complete groups") {
        system("rm -rf " IC_FIX_GROUP);
        ASSERT(ic_write_call_pair(IC_FIX_GROUP));
        ASSERT(ic_write_depfiles(IC_FIX_GROUP));

        size_t n = sizeof(ic_many_group_files) /
                   sizeof(ic_many_group_files[0]);
        for (size_t i = 0; i < n; i++) {
            char body[256];
            (void)snprintf(body, sizeof(body),
                           "/* many-group fixture */\n"
                           "#include \"net/clp.h\"\n"
                           "int mg_%zu(int x) { return tor_leaf(x); }\n", i);
            ASSERT(ic_write(IC_FIX_GROUP, ic_many_group_files[i], body));
        }

        const char *files[] = { "core/modules/net/src/tor_integration.c" };
        struct zcl_devloop_plan plan;
        ASSERT(zcl_devloop_plan_files(files, 1, &plan));
        ASSERT(zcl_devloop_plan_add_closure(IC_FIX_GROUP, files, 1, &plan));

        ASSERT(plan.closure_groups_len > ZCL_AGENT_IMPACT_MAX_GROUPS);
        ASSERT(plan.dims[ZCL_DEVLOOP_DIM_SEMANTIC].status ==
               ZCL_DEVLOOP_DIM_COMPLETE);
        ASSERT(ic_planned(&plan, "download"));

        struct zcl_devloop_plan direct;
        ASSERT(zcl_devloop_plan_files(ic_many_group_files, n, &direct));
        ASSERT(direct.path_groups_len > ZCL_AGENT_IMPACT_MAX_GROUPS);
        ASSERT(direct.dims[ZCL_DEVLOOP_DIM_OPAQUE].status ==
               ZCL_DEVLOOP_DIM_COMPLETE);

        /* Regression: the exact execution list is droppable presentation,
         * while the closure and completeness verdict are mandatory evidence.
         * Rendering a high-fanout valid plan must abridge the former instead
         * of returning an empty document/INVALID_FILE_SET. */
        char body[ZCL_DEVLOOP_PLAN_WIRE_MAX + 1];
        size_t body_len = zcl_devloop_plan_json_closure(
            IC_FIX_GROUP, files, 1, body, sizeof(body));
        ASSERT(body_len > 0 && body_len <= ZCL_DEVLOOP_PLAN_WIRE_MAX);
        ASSERT(strstr(body, "\"closure_groups\":[") != NULL);
        ASSERT(strstr(body, "\"dimensions\":[") != NULL);
        ASSERT(strstr(body, "\"execution_groups_abridged\":") != NULL);

        /* Rendering the plan the caller already closed must produce the SAME
         * document byte for byte. It has to, because the only reason a proof
         * may render instead of re-closing is that the two are the same
         * answer -- and re-closing costs a second code-index open plus a
         * second walk of the whole reverse-caller graph. */
        char rendered[ZCL_DEVLOOP_PLAN_WIRE_MAX + 1];
        size_t rendered_len = zcl_devloop_plan_json_render(
            &plan, files, 1, rendered, sizeof(rendered));
        ASSERT(rendered_len == body_len);
        ASSERT(memcmp(rendered, body, body_len) == 0);

        system("rm -rf " IC_FIX_GROUP);
        PASS();
    } _test_next:;
    return failures;
}

static int test_ic_command_latency_scope_is_precise(void)
{
    int failures = 0;
    TEST("impact composition: command latency follows only latency owners") {
        const char *code_files[] = { "cognition/modules/codeindex/src/codeindex.c" };
        struct zcl_devloop_plan code_plan;
        ASSERT(zcl_devloop_plan_files(code_files, 1, &code_plan));
        ASSERT(ic_planned(&code_plan, "command_registry_catalog"));
        ASSERT(ic_planned(&code_plan, "command_registry_latency"));

        const char *zcode_files[] = {
            "tools/command/native_zcode_dev_command.c"
        };
        struct zcl_devloop_plan zcode_plan;
        ASSERT(zcl_devloop_plan_files(zcode_files, 1, &zcode_plan));
        ASSERT(ic_planned(&zcode_plan, "command_registry_catalog"));
        ASSERT(!ic_planned(&zcode_plan, "command_registry_latency"));
        PASS();
    } _test_next:;
    return failures;
}

/* ── T2: a .def registry's dependents ARE found ───────────────────────── */

static int test_ic_registry_def_has_dependents(void)
{
    int failures = 0;
    TEST("impact composition: a .def registry reaches its dependents") {
        system("rm -rf " IC_FIX_DEF);
        ASSERT(ic_write_call_pair(IC_FIX_DEF));
        /* A registry with the shape the tree actually uses: X-macro rows, no
         * C declarations, `#include`d by exactly one translation unit. */
        ASSERT(ic_write(IC_FIX_DEF,
                        "engine/controllers/include/controllers/ic_rows.def",
                        "/* registry fixture */\n"
                        "IC_ROW(alpha, 1)\n"
                        "IC_ROW(beta, 2)\n"));
        /* The compiler read the registry while building download.c. */
        ASSERT(ic_write(IC_FIX_DEF, "build/obj/tor_integration.d",
                        "build/obj/tor_integration.o: "
                        "core/modules/net/src/tor_integration.c "
                        "core/modules/net/include/net/clp.h\n"));
        ASSERT(ic_write(IC_FIX_DEF, "build/obj/download.d",
                        "build/obj/download.o: core/modules/net/src/download.c "
                        "core/modules/net/include/net/clp.h "
                        "engine/controllers/include/controllers/ic_rows.def\n"));

        struct codeindex *ci = codeindex_open(IC_FIX_DEF);
        ASSERT(ci != NULL);

        /* The call graph has nothing to say — a registry defines no callable
         * symbol, so its reverse-caller closure is exactly itself. That is a
         * correct answer to the wrong question, and used to be the ONLY
         * question asked. */
        char changed[1][256];
        (void)snprintf(changed[0], sizeof(changed[0]),
                       "engine/controllers/include/controllers/ic_rows.def");
        static char impacted[64][256];
        bool trunc = false;
        int nc = codeindex_impact_closure(ci, changed, 1, 0, impacted, 64,
                                          &trunc);
        ASSERT(nc == 1);

        /* The include dimension answers it. */
        static char deps[64][256];
        enum codeindex_include_dim dim = CODEINDEX_INCLUDE_DIM_UNAVAILABLE;
        int nd = codeindex_reverse_includes(
            ci, "engine/controllers/include/controllers/ic_rows.def", deps, 64,
            &dim);
        ASSERT(nd == 1);
        ASSERT(dim == CODEINDEX_INCLUDE_DIM_COMPLETE);
        ASSERT(strcmp(deps[0], "core/modules/net/src/download.c") == 0);
        codeindex_close(ci);

        /* And the composed plan selects download.c's group, through the
         * INCLUDE dimension, naming the file it came through. */
        const char *files[] = {
            "engine/controllers/include/controllers/ic_rows.def"
        };
        struct zcl_devloop_plan plan;
        ASSERT(zcl_devloop_plan_files(files, 1, &plan));
        ASSERT(zcl_devloop_plan_add_closure(IC_FIX_DEF, files, 1, &plan));
        ASSERT(ic_planned(&plan, "download"));
        const struct zcl_devloop_selection *sel = ic_selection(&plan,
                                                               "download");
        ASSERT(sel != NULL);
        ASSERT(sel->dim == ZCL_DEVLOOP_DIM_INCLUDE);
        ASSERT(strcmp(sel->via, "core/modules/net/src/download.c") == 0);

        system("rm -rf " IC_FIX_DEF);
        PASS();
    } _test_next:;
    return failures;
}

/* ── T3: a macro-only header's dependents ARE found ───────────────────── */

static int test_ic_macro_only_header_has_dependents(void)
{
    int failures = 0;
    TEST("impact composition: a macro-only header reaches its dependents") {
        system("rm -rf " IC_FIX_MACRO);
        ASSERT(ic_write_call_pair(IC_FIX_MACRO));
        /* No prototypes, no typedefs, no callable symbol of any kind: the call
         * graph cannot see this file, by construction. */
        ASSERT(ic_write(IC_FIX_MACRO, "core/modules/net/include/net/ic_macros.h",
                        "#ifndef NET_IC_MACROS_H\n#define NET_IC_MACROS_H\n"
                        "#define IC_WINDOW 4096\n"
                        "#define IC_DOUBLE(x) ((x) * 2)\n"
                        "#endif\n"));
        ASSERT(ic_write(IC_FIX_MACRO, "build/obj/tor_integration.d",
                        "build/obj/tor_integration.o: "
                        "core/modules/net/src/tor_integration.c "
                        "core/modules/net/include/net/clp.h\n"));
        ASSERT(ic_write(IC_FIX_MACRO, "build/obj/download.d",
                        "build/obj/download.o: core/modules/net/src/download.c "
                        "core/modules/net/include/net/clp.h "
                        "core/modules/net/include/net/ic_macros.h\n"));

        struct codeindex *ci = codeindex_open(IC_FIX_MACRO);
        ASSERT(ci != NULL);

        char changed[1][256];
        (void)snprintf(changed[0], sizeof(changed[0]),
                       "core/modules/net/include/net/ic_macros.h");
        static char impacted[64][256];
        bool trunc = false;
        int nc = codeindex_impact_closure(ci, changed, 1, 0, impacted, 64,
                                          &trunc);
        ASSERT(nc == 1);  /* call graph: the file and nothing else */

        static char deps[64][256];
        enum codeindex_include_dim dim = CODEINDEX_INCLUDE_DIM_UNAVAILABLE;
        int nd = codeindex_reverse_includes(ci,
                                            "core/modules/net/include/net/ic_macros.h",
                                            deps, 64, &dim);
        ASSERT(nd == 1);
        ASSERT(dim == CODEINDEX_INCLUDE_DIM_COMPLETE);
        ASSERT(strcmp(deps[0], "core/modules/net/src/download.c") == 0);
        codeindex_close(ci);

        const char *files[] = { "core/modules/net/include/net/ic_macros.h" };
        struct zcl_devloop_plan plan;
        ASSERT(zcl_devloop_plan_files(files, 1, &plan));
        ASSERT(zcl_devloop_plan_add_closure(IC_FIX_MACRO, files, 1, &plan));
        ASSERT(ic_planned(&plan, "download"));
        const struct zcl_devloop_selection *sel = ic_selection(&plan,
                                                               "download");
        ASSERT(sel != NULL);
        ASSERT(sel->dim == ZCL_DEVLOOP_DIM_INCLUDE);

        system("rm -rf " IC_FIX_MACRO);
        PASS();
    } _test_next:;
    return failures;
}

/* ── T4: an incomplete dimension makes the plan REFUSE to be proof ────── */

static int test_ic_incomplete_dimension_refuses_proof(void)
{
    int failures = 0;
    TEST("impact composition: an incomplete dimension refuses to be proof") {
        /* (a) a complete fixture is admissible — the positive control, so a
         * blanket "always refuse" cannot pass this case. */
        system("rm -rf " IC_FIX_MACRO);
        ASSERT(ic_write_call_pair(IC_FIX_MACRO));
        ASSERT(ic_write_depfiles(IC_FIX_MACRO));
        const char *files[] = { "core/modules/net/src/tor_integration.c" };
        struct zcl_devloop_plan good;
        ASSERT(zcl_devloop_plan_files(files, 1, &good));
        ASSERT(zcl_devloop_plan_add_closure(IC_FIX_MACRO, files, 1, &good));
        const char *why = "unset";
        ASSERT(zcl_devloop_plan_proof_admissible(&good, &why));
        ASSERT(strcmp(why, "") == 0);

        /* (b) a CAPACITY-bounded closure is a different fact from a missing
         * one: the index answered, and its answer was "more than this plan can
         * list". The universal closure is the sound reading of that, so the
         * plan stays admissible — and covers everything. */
        system("rm -rf " IC_FIX_TRUNC);
        ASSERT(ic_write_call_pair(IC_FIX_TRUNC));
        ASSERT(ic_write_depfiles(IC_FIX_TRUNC));
        ASSERT(ic_write_fanout_caller(IC_FIX_TRUNC));
        struct zcl_devloop_plan cut;
        ASSERT(zcl_devloop_plan_files(files, 1, &cut));
        ASSERT(zcl_devloop_plan_add_closure(IC_FIX_TRUNC, files, 1, &cut));
        why = "unset";
        ASSERT(zcl_devloop_plan_proof_admissible(&cut, &why));
        ASSERT(cut.closure_universal);
        /* Widening did NOT cost the evidence the partial walk found. */
        ASSERT(ic_planned(&cut, "download"));

        /* (c) the vocabulary the result cache uses for a truncated closure is
         * still the ONE word for that condition, and it is still spoken —
         * codeindex reports it to the planner, which is what triggers the
         * universal answer above. Pinned here so the two cannot drift. */
        ASSERT(strcmp("closure-truncated",
                      testcache_reason_label(TESTCACHE_R_TRUNCATED)) == 0);

        /* (d) no depfiles at all: the include dimension was never answerable,
         * which is a different fact from "nothing depends on this". Same
         * refusal, and again the same word the result cache uses. */
        system("rm -rf " IC_FIX_NODEPS);
        ASSERT(ic_write_call_pair(IC_FIX_NODEPS));
        const char *header_files[] = { "core/modules/net/include/net/net.h" };
        struct zcl_devloop_plan bare;
        ASSERT(zcl_devloop_plan_files(header_files, 1, &bare));
        ASSERT(zcl_devloop_plan_add_closure(IC_FIX_NODEPS, header_files, 1,
                                            &bare));
        why = "unset";
        ASSERT(!zcl_devloop_plan_proof_admissible(&bare, &why));
        ASSERT(strcmp(why, "no-include-graph") == 0);
        ASSERT(strcmp(why,
                      testcache_reason_label(TESTCACHE_R_NO_INCLUDE_GRAPH)) == 0);
        /* Still runs the tests the path floor named. */
        ASSERT(ic_group_in(bare.path_groups, bare.path_groups_len, "net"));

        /* (e) a plan that never consulted the graph at all must not read as
         * proof that it did. */
        struct zcl_devloop_plan unasked;
        ASSERT(zcl_devloop_plan_files(files, 1, &unasked));
        why = "unset";
        ASSERT(!zcl_devloop_plan_proof_admissible(&unasked, &why));
        ASSERT(strcmp(why, "closure-not-attempted") == 0);

        /* (f) the refusal reaches the wire: a consumer reading only the JSON
         * gets the same verdict. */
        char body[65536];
        size_t n = zcl_devloop_plan_json_closure(IC_FIX_NODEPS, header_files, 1,
                                                 body, sizeof(body));
        ASSERT(n > 0 && n < sizeof(body));
        ASSERT(strstr(body, "\"proof_admissible\":false") != NULL);
        ASSERT(strstr(body, "\"proof_refusal\":\"no-include-graph\"") != NULL);
        ASSERT(strstr(body, "\"live_eligible\":false") != NULL);
        ASSERT(strstr(body, "\"closure_universal\":false") != NULL);

        /* (g) and so does the capacity answer, which is NOT a refusal. */
        n = zcl_devloop_plan_json_closure(IC_FIX_TRUNC, files, 1, body,
                                          sizeof(body));
        ASSERT(n > 0 && n < sizeof(body));
        ASSERT(strstr(body, "\"proof_admissible\":true") != NULL);
        ASSERT(strstr(body, "\"closure_universal\":true") != NULL);
        ASSERT(strstr(body, "\"closure_truncated\":false") != NULL);
        ASSERT(strstr(body, "\"execution_selector\":\"universal\"") != NULL);
        ASSERT(strstr(body, "\"live_eligible\":false") != NULL);
        ASSERT(strstr(body,
                      "\"why_not_live\":\"consensus_or_chain_state_is_never_swappable\"")
               != NULL);
        ASSERT(strstr(body,
                      "\"why_not_live_path\":\"core/modules/net/src/tor_integration.c\"")
               != NULL);
        ASSERT(strstr(body,
                      "\"agent_next_action\":\"z23-dev dev begin\"")
               != NULL);

        system("rm -rf " IC_FIX_TRUNC);
        system("rm -rf " IC_FIX_MACRO);
        system("rm -rf " IC_FIX_NODEPS);
        PASS();
    } _test_next:;
    return failures;
}

/* ── T4b: CAPACITY is answered by the universal closure ────────────────
 *
 * Two bounds mean "this change reaches more than the plan can enumerate":
 * the reverse-caller walk filling a per-query batch, and the group array
 * filling. Neither is missing evidence — the index answered both times. The
 * sound, fail-closed reading is that EVERY group is impacted, and the proof
 * runner must then run the whole catalog. What stays a refusal is the case
 * where the index could not answer at all. */

static int test_ic_capacity_bound_runs_everything(void)
{
    int failures = 0;
    TEST("impact composition: a capacity bound runs the whole catalog") {
        const char *files[] = { "core/modules/net/src/tor_integration.c" };

        /* (a) the group array fills. The fixture names a few dozen real
         * proof-owning test files; the seam lowers the ceiling so the cap is
         * reachable without a fixture that has to out-name the catalog. */
        system("rm -rf " IC_FIX_GROUP);
        ASSERT(ic_write_call_pair(IC_FIX_GROUP));
        ASSERT(ic_write_depfiles(IC_FIX_GROUP));
        size_t n = sizeof(ic_many_group_files) /
                   sizeof(ic_many_group_files[0]);
        for (size_t i = 0; i < n; i++) {
            char fbody[256];
            (void)snprintf(fbody, sizeof(fbody),
                           "/* many-group fixture */\n"
                           "#include \"net/clp.h\"\n"
                           "int mg_%zu(int x) { return tor_leaf(x); }\n", i);
            ASSERT(ic_write(IC_FIX_GROUP, ic_many_group_files[i], fbody));
        }
        struct zcl_devloop_plan capped;
        zcl_devloop_test_plan_group_cap = 8;
        bool built = zcl_devloop_plan_files(files, 1, &capped) &&
                     zcl_devloop_plan_add_closure(IC_FIX_GROUP, files, 1,
                                                  &capped);
        zcl_devloop_test_plan_group_cap = 0;
        ASSERT(built);
        ASSERT(capped.closure_universal);
        ASSERT(!capped.closure_truncated);
        ASSERT(capped.dims[ZCL_DEVLOOP_DIM_SEMANTIC].status ==
               ZCL_DEVLOOP_DIM_COMPLETE);
        ASSERT(strcmp(capped.dims[ZCL_DEVLOOP_DIM_SEMANTIC].reason,
                      "closure-universal") == 0);
        const char *why = "unset";
        ASSERT(zcl_devloop_plan_proof_admissible(&capped, &why));
        ASSERT(strcmp(why, "") == 0);
        /* The cap kept what fit; it did not throw the partial evidence away. */
        ASSERT(capped.closure_groups_len > 0);

        /* And the SAME fixture under the production ceiling enumerates
         * normally — so (a) is testing the cap, not the fixture. */
        struct zcl_devloop_plan roomy;
        ASSERT(zcl_devloop_plan_files(files, 1, &roomy));
        ASSERT(zcl_devloop_plan_add_closure(IC_FIX_GROUP, files, 1, &roomy));
        ASSERT(!roomy.closure_universal);
        ASSERT(roomy.closure_groups_len > capped.closure_groups_len);

        /* (b) the proof runner turns a universal plan into the whole catalog,
         * and an ordinary plan into just its own groups. */
        static char selector[ZCL_DEVLOOP_MAX_PLAN_SELECTIONS *
                             (ZCL_TEST_GROUP_FULL_MAX + 1)];
        uint32_t selected = 0;
        memset(selector, 0, sizeof(selector));
        ASSERT(zcl_dev_proof_test_build_test_selector(
                   &capped, false, selector, sizeof(selector), &selected));
        ASSERT((size_t)selected == zcl_test_group_catalog_count());
        ASSERT(zcl_test_group_catalog_count() > 0);
        for (size_t i = 0; i < zcl_test_group_catalog_count(); i++) {
            char needle[ZCL_TEST_GROUP_FULL_MAX + 2];
            (void)snprintf(needle, sizeof(needle), "%s",
                           zcl_test_group_catalog_at(i));
            ASSERT(strstr(selector, needle) != NULL);
        }
        uint32_t exact_selected = 0;
        memset(selector, 0, sizeof(selector));
        ASSERT(zcl_dev_proof_test_build_test_selector(
                   &roomy, false, selector, sizeof(selector),
                   &exact_selected));
        ASSERT(exact_selected > 0);
        ASSERT((size_t)exact_selected < zcl_test_group_catalog_count());

        /* (c) no index at all is NOT capacity. It is the planner failing to
         * ask, and it still refuses. */
        struct zcl_devloop_plan blind;
        const char *header_files[] = {
            "core/modules/net/include/net/net.h"
        };
        ASSERT(zcl_devloop_plan_files(header_files, 1, &blind));
        ASSERT(zcl_devloop_plan_add_closure("test-tmp/no-such-impact-index",
                                            header_files, 1, &blind));
        ASSERT(!blind.closure_universal);
        ASSERT(blind.dims[ZCL_DEVLOOP_DIM_SEMANTIC].status ==
               ZCL_DEVLOOP_DIM_UNAVAILABLE);
        ASSERT(blind.dims[ZCL_DEVLOOP_DIM_INCLUDE].status ==
               ZCL_DEVLOOP_DIM_UNAVAILABLE);
        why = "unset";
        ASSERT(!zcl_devloop_plan_proof_admissible(&blind, &why));
        ASSERT(strcmp(why, "no-code-index") == 0);

        system("rm -rf " IC_FIX_GROUP);
        PASS();
    } _test_next:;
    return failures;
}

/* ── T5: every selected group says why it is there ────────────────────── */

static int test_ic_every_selection_has_a_reason(void)
{
    int failures = 0;
    TEST("impact composition: every selected group names its dimension") {
        system("rm -rf " IC_FIX_DEF);
        ASSERT(ic_write_call_pair(IC_FIX_DEF));
        ASSERT(ic_write(IC_FIX_DEF,
                        "engine/controllers/include/controllers/ic_rows.def",
                        "IC_ROW(alpha, 1)\n"));
        ASSERT(ic_write(IC_FIX_DEF, "build/obj/tor_integration.d",
                        "build/obj/tor_integration.o: "
                        "core/modules/net/src/tor_integration.c "
                        "core/modules/net/include/net/clp.h\n"));
        ASSERT(ic_write(IC_FIX_DEF, "build/obj/download.d",
                        "build/obj/download.o: core/modules/net/src/download.c "
                        "core/modules/net/include/net/clp.h "
                        "engine/controllers/include/controllers/ic_rows.def\n"));

        /* One changed file per dimension in a single plan: a .c (semantic), a
         * registry (include), and a doc (opaque — no graph could find it). */
        const char *files[] = {
            "core/modules/net/src/tor_integration.c",
            "engine/controllers/include/controllers/ic_rows.def",
            "docs/HANDOFF.md",
        };
        struct zcl_devloop_plan plan;
        ASSERT(zcl_devloop_plan_files(files, 3, &plan));
        ASSERT(zcl_devloop_plan_add_closure(IC_FIX_DEF, files, 3, &plan));

        /* Every planned group — from EITHER array — carries an explanation
         * with a real dimension name and a non-empty via file. */
        ASSERT(plan.path_groups_len + plan.closure_groups_len > 0);
        for (size_t i = 0; i < plan.path_groups_len; i++) {
            const struct zcl_devloop_selection *s =
                ic_selection(&plan, plan.path_groups[i]);
            ASSERT(s != NULL);
            ASSERT(s->via[0] != '\0');
            ASSERT(strcmp(zcl_devloop_dim_name(s->dim), "unknown") != 0);
        }
        for (size_t i = 0; i < plan.closure_groups_len; i++) {
            const struct zcl_devloop_selection *s =
                ic_selection(&plan, plan.closure_groups[i]);
            ASSERT(s != NULL);
            ASSERT(s->via[0] != '\0');
            ASSERT(strcmp(zcl_devloop_dim_name(s->dim), "unknown") != 0);
        }

        /* A doc's groups can only have come from a hand-authored mapping, and
         * the ledger says so. Asked on its own: attribution is deduped on the
         * group, and in the three-file plan above a .c file names the same
         * group first, so that entry honestly reads "semantic" — a graph DID
         * reach it. Alone, nothing but the .def rule can explain it. */
        const char *doc_only[] = { "docs/HANDOFF.md" };
        struct zcl_devloop_plan dplan;
        ASSERT(zcl_devloop_plan_files(doc_only, 1, &dplan));
        ASSERT(zcl_devloop_plan_add_closure(IC_FIX_DEF, doc_only, 1, &dplan));
        ASSERT(dplan.path_groups_len > 0);
        bool saw_opaque = false;
        for (size_t i = 0; i < dplan.selections_len; i++) {
            if (dplan.selections[i].dim == ZCL_DEVLOOP_DIM_OPAQUE &&
                strcmp(dplan.selections[i].via, "docs/HANDOFF.md") == 0)
                saw_opaque = true;
        }
        ASSERT(saw_opaque);
        for (size_t i = 0; i < dplan.path_groups_len; i++)
            ASSERT(ic_selection(&dplan, dplan.path_groups[i]) != NULL);

        /* And the whole explanation reaches the wire, with the per-dimension
         * completeness list beside it. */
        char body[65536];
        size_t n = zcl_devloop_plan_json_closure(IC_FIX_DEF, files, 3, body,
                                                 sizeof(body));
        ASSERT(n > 0 && n < sizeof(body));
        struct json_value root = {0};
        ASSERT(json_read(&root, body, n));
        ASSERT(json_get(&root, "selections") != NULL);
        ASSERT(json_get(&root, "dimensions") != NULL);
        ASSERT(json_get(&root, "proof_admissible") != NULL);
        json_free(&root);
        ASSERT(strstr(body, "\"name\":\"include\"") != NULL);
        ASSERT(strstr(body, "\"name\":\"opaque\"") != NULL);
        ASSERT(strstr(body, "\"name\":\"semantic\"") != NULL);

        char dbody[65536];
        size_t dn = zcl_devloop_plan_json_closure(IC_FIX_DEF, doc_only, 1,
                                                  dbody, sizeof(dbody));
        ASSERT(dn > 0 && dn < sizeof(dbody));
        ASSERT(strstr(dbody, "\"dimension\":\"opaque\"") != NULL);
        ASSERT(strstr(dbody, "\"via\":\"docs/HANDOFF.md\"") != NULL);

        /* The explanation is only worth writing if it can be DELIVERED. The
         * command registry hard-fails (RESPONSE_BUDGET_EXCEEDED, empty
         * document) any reply larger than the serving leaf's declared budget
         * instead of truncating it, so a renderer that writes past that number
         * does not produce a longer plan — it produces no plan at all, which
         * is exactly the regression this assert exists to catch. Pin the two
         * numbers to each other: the leaf must declare room for the document
         * ceiling plus the zcl.result.v1 envelope around it (measured at 340
         * bytes; 512 is the rounded reserve). */
        const struct zcl_command_spec *plan_spec =
            zcl_command_registry_find(zcl_command_catalog(), "dev.test.plan",
                                      NULL);
        ASSERT(plan_spec != NULL);
        ASSERT(plan_spec->budget_bytes >= ZCL_DEVLOOP_PLAN_WIRE_MAX + 512);
        const struct zcl_command_spec *change_plan_spec =
            zcl_command_registry_find(zcl_command_catalog(),
                                      "dev.change.plan", NULL);
        ASSERT(change_plan_spec != NULL);
        ASSERT(change_plan_spec->budget_bytes >=
               ZCL_DEVLOOP_PLAN_WIRE_MAX + 512);
        /* …and the renderer must actually honour that ceiling regardless of
         * how large a buffer it is handed. */
        ASSERT(n <= ZCL_DEVLOOP_PLAN_WIRE_MAX);
        ASSERT(dn <= ZCL_DEVLOOP_PLAN_WIRE_MAX);

        system("rm -rf " IC_FIX_DEF);
        PASS();
    } _test_next:;
    return failures;
}

/* ── T6: the union is a strict superset of system A alone ─────────────── */

/* The "do not replace either system" guarantee, made mechanical. Whatever the
 * hand-authored rules name for a changed path, the composed plan still names.
 * Run over the twelve representative change kinds plus the fixture paths, so a
 * future "simplification" that drops A cannot pass. */
static const char *const ic_superset_paths[] = {
    "platform/modules/util/include/util/supervisor.h",
    "platform/modules/util/src/supervisor.c",
    "core/modules/net/src/zmsg.c",
    "engine/controllers/include/controllers/diagnostics_dumpers.def",
    "tools/lint/check_core_seal.sh",
    "docs/HANDOFF.md",
    "platform/modules/sha3/src/sha3.c",
    "engine/models/src/store.c",
    "cognition/modules/codeindex/src/codeindex_impact.c",
    "core/consensus/src/pow.c",
    "platform/modules/base/include/base/hex.h",
    "engine/services/src/op_return_backfill_service.c",
    "core/modules/net/src/tor_integration.c",
    "core/modules/net/src/download.c",
};

static int test_ic_union_never_loses_a_rule_group(void)
{
    int failures = 0;
    TEST("impact composition: the union never loses a group system A named") {
        system("rm -rf " IC_FIX_MACRO);
        ASSERT(ic_write_call_pair(IC_FIX_MACRO));
        ASSERT(ic_write_depfiles(IC_FIX_MACRO));

        size_t n = sizeof(ic_superset_paths) / sizeof(ic_superset_paths[0]);
        size_t checked = 0;
        for (size_t i = 0; i < n; i++) {
            /* A alone, straight from the shared rule resolver. */
            struct agent_impact_acc acc = {0};
            (void)agent_impact_apply_shared_rules(ic_superset_paths[i], &acc);

            const char *one[] = { ic_superset_paths[i] };
            struct zcl_devloop_plan plan;
            ASSERT(zcl_devloop_plan_files(one, 1, &plan));
            ASSERT(zcl_devloop_plan_add_closure(IC_FIX_MACRO, one, 1, &plan));

            for (size_t g = 0; g < acc.groups_len; g++) {
                if (!ic_planned(&plan, acc.groups[g])) {
                    fprintf(stderr,
                            "  union LOST rule group '%s' for path '%s'\n",
                            acc.groups[g], ic_superset_paths[i]);
                    ASSERT(false);
                }
                checked++;
            }
        }
        /* The corpus must actually exercise something. */
        ASSERT(checked > 20);

        /* Scalar SHA3 moved into its own module and now has an explicit
         * path rule as well as the hard consensus-risk fallback.  The first
         * selection is therefore semantic, while consensus_parity remains
         * mandatory and visible in the composed plan. */
        const char *crypto[] = { "platform/modules/sha3/src/sha3.c" };
        struct zcl_devloop_plan cplan;
        ASSERT(zcl_devloop_plan_files(crypto, 1, &cplan));
        ASSERT(cplan.consensus_risk);
        ASSERT(ic_planned(&cplan, "consensus_parity"));
        const struct zcl_devloop_selection *s = ic_selection(&cplan,
                                                             "consensus_parity");
        ASSERT(s != NULL);
        ASSERT(s->dim == ZCL_DEVLOOP_DIM_SEMANTIC);

        system("rm -rf " IC_FIX_MACRO);
        PASS();
    } _test_next:;
    return failures;
}

/* ── T7: query only graph dimensions that can contain an edge ─────────── */

static int test_ic_dimension_applicability_and_exact_execution(void)
{
    int failures = 0;
    TEST("impact composition: test leaves produce an exact admissible plan") {
        const char *files[] = {
            "tests/harness/src/test_stage_repair_coin_backfill.c",
            "tools/agent_fast_ci.sh",
        };
        struct zcl_devloop_plan plan;
        ASSERT(zcl_devloop_plan_files(files, 2, &plan));
        /* No fixture/index exists at this path. Success proves the planner did
         * not open an irrelevant graph merely to report an empty answer. */
        ASSERT(zcl_devloop_plan_add_closure("test-tmp/no-such-impact-index",
                                            files, 2, &plan));
        ASSERT(plan.dims[ZCL_DEVLOOP_DIM_SEMANTIC].status ==
               ZCL_DEVLOOP_DIM_NOT_APPLICABLE);
        ASSERT(plan.dims[ZCL_DEVLOOP_DIM_INCLUDE].status ==
               ZCL_DEVLOOP_DIM_NOT_APPLICABLE);
        ASSERT(plan.closure_groups_len == 0);
        ASSERT(!plan.closure_truncated);
        const char *why = "unset";
        ASSERT(zcl_devloop_plan_proof_admissible(&plan, &why));
        ASSERT(strcmp(why, "") == 0);

        char body[ZCL_DEVLOOP_PLAN_WIRE_MAX + 1];
        size_t n = zcl_devloop_plan_json_closure(
            "test-tmp/no-such-impact-index", files, 2, body, sizeof(body));
        ASSERT(n > 0 && n <= ZCL_DEVLOOP_PLAN_WIRE_MAX);
        ASSERT(strstr(body, "\"execution_selector\":\"exact\"") != NULL);
        ASSERT(strstr(body, "\"test_stage_repair\"") == NULL);
        ASSERT(strstr(body, "\"test_stage_repair_coin_backfill\"") != NULL);
        ASSERT(strstr(body, "\"execution_set_valid\":true") != NULL);
        ASSERT(strstr(body, "\"execution_set_sha3\":") != NULL);
        ASSERT(strstr(body, "\"proof_admissible\":true") != NULL);

        /* An unmapped code edit and a stale catalog token each refuse for the
         * actionable reason before any graph availability can obscure it. */
        const char *unmapped[] = { "lib/novel/src/unmapped_agentic.c" };
        struct zcl_devloop_plan gap;
        ASSERT(zcl_devloop_plan_files(unmapped, 1, &gap));
        why = "unset";
        ASSERT(!zcl_devloop_plan_proof_admissible(&gap, &why));
        ASSERT(strcmp(why, "unmapped-code-change") == 0);

        /* Pure C23 service islands are product code, not harness internals.
         * Their direct path floor must name the product proof even when the
         * reverse-call graph happens to find infrastructure coverage. */
        const char *c23_services[] = {
            "contexts/commons/services/src/zcode_c23_corpus_service.c",
            "contexts/commons/services/src/zcode_c23_economics_service.c",
        };
        for (size_t i = 0;
             i < sizeof(c23_services) / sizeof(c23_services[0]); i++) {
            const char *service_files[] = { c23_services[i] };
            struct zcl_devloop_plan service;
            ASSERT(zcl_devloop_plan_files(service_files, 1, &service));
            ASSERT(service.action == ZCL_DEVLOOP_HOTSWAP);
            ASSERT(ic_group_in(service.path_groups,
                               service.path_groups_len,
                               "zcode_commons"));

            char service_body[ZCL_DEVLOOP_PLAN_WIRE_MAX + 1];
            size_t service_n = zcl_devloop_plan_json(
                service_files, 1, service_body, sizeof(service_body));
            ASSERT(service_n > 0);
            ASSERT(strstr(service_body, "\"live_eligible\":true") != NULL);
            ASSERT(strstr(service_body, "\"why_not_live\":\"\"") != NULL);
            ASSERT(strstr(service_body, "\"why_not_live_path\":\"\"")
                   != NULL);
        }

        const char *package_manifest[] = {
            "contexts/commons/packages/zarg/zcode-package.json",
        };
        struct zcl_devloop_plan package_plan;
        ASSERT(zcl_devloop_plan_files(package_manifest, 1, &package_plan));
        ASSERT(ic_planned(&package_plan, "zcode_package_dev"));
        ASSERT(ic_planned(&package_plan, "zcode_verify"));
        ASSERT(ic_planned(&package_plan, "zcode_package_registry"));
        ASSERT(ic_planned(&package_plan, "make_lint_gates"));
        ASSERT(zcl_devloop_plan_add_closure("test-tmp/no-such-impact-index",
                                            package_manifest, 1,
                                            &package_plan));
        why = "unset";
        ASSERT(zcl_devloop_plan_proof_admissible(&package_plan, &why));
        ASSERT(strcmp(why, "") == 0);

        struct agent_impact_acc executor = {0};
        (void)agent_impact_apply_shared_rules(
            "contexts/commons/services/src/build_fabric_package_executor.c", &executor);
        ASSERT(executor.shared_rule_hits > 0);
        bool executor_has_build_proof = false;
        for (size_t i = 0; i < executor.groups_len; i++)
            if (strcmp(executor.groups[i], "build_fabric") == 0)
                executor_has_build_proof = true;
        ASSERT(executor_has_build_proof);

        struct zcl_devloop_plan stale = plan;
        snprintf(stale.path_groups[0], sizeof(stale.path_groups[0]),
                 "missing_catalog_group");
        why = "unset";
        ASSERT(!zcl_devloop_plan_proof_admissible(&stale, &why));
        ASSERT(strcmp(why, "unknown-test-group") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_ic_snapshot_overlays_current_symbols(void)
{
    int failures = 0;
    TEST("impact composition: resident snapshot overlays current changed symbols") {
        system("rm -rf " IC_FIX_SNAPSHOT);
        ASSERT(ic_write(IC_FIX_SNAPSHOT, "core/modules/net/src/tor_integration.c",
                        "int old_unreferenced(void) { return 1; }\n"));
        ASSERT(ic_write(IC_FIX_SNAPSHOT, "core/modules/net/src/download.c",
                        "int future_leaf(void);\n"
                        "int download_future(void) { return future_leaf(); }\n"));
        ASSERT(ic_write_depfiles(IC_FIX_SNAPSHOT));

        const char *files[] = { "core/modules/net/src/tor_integration.c" };
        struct zcl_devloop_plan baseline;
        ASSERT(zcl_devloop_plan_files(files, 1, &baseline));
        ASSERT(zcl_devloop_plan_add_closure(
            IC_FIX_SNAPSHOT, files, 1, &baseline));
        ASSERT(!ic_planned(&baseline, "download"));

        ASSERT(ic_write(IC_FIX_SNAPSHOT, "core/modules/net/src/tor_integration.c",
                        "int future_leaf(void) { return 2; }\n"));
        struct zcl_devloop_plan snapshot;
        ASSERT(zcl_devloop_plan_files(files, 1, &snapshot));
        ASSERT(zcl_devloop_plan_add_closure_snapshot(
            IC_FIX_SNAPSHOT, files, 1, &snapshot));
        ASSERT(snapshot.closure_snapshot);
        ASSERT(ic_planned(&snapshot, "download"));
        ASSERT(zcl_devloop_plan_proof_admissible(&snapshot, NULL));

        system("rm -rf " IC_FIX_SNAPSHOT);
        PASS();
    } _test_next:;
    return failures;
}

static bool ic_acc_has_group(const struct agent_impact_acc *acc,
                             const char *group)
{
    for (size_t i = 0; i < acc->groups_len; i++)
        if (strcmp(acc->groups[i], group) == 0)
            return true;
    return false;
}

static int test_ic_code_capsule_stays_with_code_owner(void)
{
    int failures = 0;
    TEST("impact composition: code capsule proof stays with code commands") {
        struct agent_impact_acc zcode = {0};
        (void)agent_impact_apply_shared_rules(
            "tools/command/native_zcode_dev_command.c", &zcode);
        ASSERT(ic_acc_has_group(&zcode, "command_registry_catalog"));
        ASSERT(!ic_acc_has_group(&zcode, "code_capsule"));

        struct agent_impact_acc shared_header = {0};
        (void)agent_impact_apply_shared_rules(
            "tools/command/native_command.h", &shared_header);
        ASSERT(ic_acc_has_group(&shared_header,
                                "command_registry_catalog"));
        ASSERT(!ic_acc_has_group(&shared_header, "codeindex"));
        ASSERT(!ic_acc_has_group(&shared_header, "code_capsule"));
        ASSERT(!ic_acc_has_group(&shared_header, "code_impact"));

        struct agent_impact_acc code = {0};
        (void)agent_impact_apply_shared_rules(
            "tools/command/native_code_command.c", &code);
        ASSERT(ic_acc_has_group(&code, "command_registry_catalog"));
        ASSERT(ic_acc_has_group(&code, "code_capsule"));
        PASS();
    } _test_next:;
    return failures;
}

static int test_ic_generated_inventory_stays_focused(void)
{
    int failures = 0;
    TEST("impact composition: generated inventory selects only its native proof") {
        struct agent_impact_acc impact = {0};
        ASSERT(agent_impact_apply_shared_rules(
            "docs/CAPABILITY_INVENTORY.jsonl", &impact));
        ASSERT(impact.shared_rule_hits == 1);
        ASSERT(ic_acc_has_group(&impact, "code_inventory"));
        ASSERT(!ic_acc_has_group(&impact, "make_lint_gates"));
        PASS();
    } _test_next:;
    return failures;
}

static int test_ic_dev_proof_contract_is_direct(void)
{
    int failures = 0;
    TEST("impact composition: dev proof contract stops at its exact owner") {
        static const char *const files[] = {
#define AGENT_DIRECT_DEVELOPMENT_CONTRACT(path_) path_,
#include "controllers/agent_direct_development_contracts.def"
#undef AGENT_DIRECT_DEVELOPMENT_CONTRACT
        };
        for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
            struct agent_impact_acc impact = {0};
            ASSERT(agent_impact_path_is_direct_development_contract(files[i]));
            ASSERT(agent_impact_apply_shared_rules(files[i], &impact));
            ASSERT(impact.groups_len > 0);
        }
        struct zcl_devloop_plan plan;
        ASSERT(zcl_devloop_plan_files(files,
            sizeof(files) / sizeof(files[0]), &plan));
        ASSERT(zcl_devloop_plan_add_closure(
            "test-tmp/no-dev-proof-index", files,
            sizeof(files) / sizeof(files[0]), &plan));
        ASSERT(plan.closure_groups_len == 0);
        ASSERT(plan.dims[ZCL_DEVLOOP_DIM_SEMANTIC].status ==
               ZCL_DEVLOOP_DIM_NOT_APPLICABLE);
        ASSERT(plan.dims[ZCL_DEVLOOP_DIM_INCLUDE].status ==
               ZCL_DEVLOOP_DIM_NOT_APPLICABLE);
        ASSERT(zcl_devloop_plan_proof_admissible(&plan, NULL));
        ASSERT(agent_impact_path_is_direct_development_contract(
            "tools/command/native_dev_loop_command.h"));
        PASS();
    } _test_next:;
    return failures;
}

static int test_ic_lint_helpers_exclude_onion_stress(void)
{
    int failures = 0;
    TEST("impact composition: hermetic lint helpers exclude onion stress") {
        struct agent_impact_acc lint = {0};
        (void)agent_impact_apply_shared_rules(
            "tests/harness/src/lint_gate_hygiene_selftests.c", &lint);
        ASSERT(ic_acc_has_group(&lint, "make_lint_gates"));
        ASSERT(ic_acc_has_group(&lint, "binary_ab_fallback"));
        ASSERT(ic_acc_has_group(&lint, "self_backtrace"));
        ASSERT(!ic_acc_has_group(&lint, "onion_bootstrap"));

        struct agent_impact_acc onion = {0};
        (void)agent_impact_apply_shared_rules(
            "tests/harness/src/test_onion_bootstrap.c", &onion);
        ASSERT(ic_acc_has_group(&onion, "make_lint_gates"));
        ASSERT(ic_acc_has_group(&onion, "onion_bootstrap"));
        PASS();
    } _test_next:;
    return failures;
}

static struct zcl_dev_acceptance_receipt_v1 ic_valid_dev_proof_receipt(void)
{
    static const char local[] =
        "1111111111111111111111111111111111111111";
    static const char base[] =
        "2222222222222222222222222222222222222222";
    struct zcl_dev_acceptance_receipt_v1 receipt = {0};
    (void)zcl_dev_proof_oid_decode(local, receipt.local_commit,
                                   &receipt.local_commit_len);
    (void)zcl_dev_proof_oid_decode(base, receipt.remote_base,
                                   &receipt.remote_base_len);
    uint8_t *roots[] = {
        receipt.source_root, receipt.source_cas_root, receipt.mutation_root,
        receipt.changed_set_root, receipt.impact_policy_root,
        receipt.compiler_root, receipt.flags_root, receipt.environment_root,
        receipt.build_graph_root, receipt.child_set_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        memset(roots[i], (int)i + 1, ZCL_DEV_PROOF_ROOT_BYTES);
    for (size_t i = 0; i < ZCL_DEV_PROOF_DIMENSIONS; i++) {
        memset(receipt.dimensions[i].receipt_root, (int)i + 1,
               ZCL_DEV_PROOF_ROOT_BYTES);
        receipt.dimensions[i].selected = 1;
        receipt.dimensions[i].reused = 1;
    }
    receipt.policy_version = ZCL_DEV_PROOF_POLICY_VERSION;
    receipt.complete = 1;
    (void)zcl_dev_proof_receipt_child_set_root(
        &receipt, receipt.child_set_root);
    (void)zcl_dev_proof_receipt_seal(&receipt);
    return receipt;
}

static int test_ic_dev_proof_receipt_admission(void)
{
    int failures = 0;
    static const char local[] =
        "1111111111111111111111111111111111111111";
    static const char base[] =
        "2222222222222222222222222222222222222222";
    struct zcl_dev_acceptance_receipt_v1 receipt =
        ic_valid_dev_proof_receipt();
    uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES];
    uint8_t child[ZCL_DEV_PROOF_CHILD_WIRE_BYTES];
    struct zcl_dev_acceptance_receipt_v1 parsed;
    char why[128];
    TEST("impact composition: exact proof rejects inadmissible receipts") {
        ASSERT(zcl_dev_proof_receipt_serialize(&receipt, wire));
        ASSERT(zcl_dev_proof_receipt_parse(wire, sizeof(wire), &parsed));
        ASSERT(zcl_dev_proof_receipt_validate(&parsed, local, base,
                                              why, sizeof(why)));
        struct zcl_dev_proof_dimension child_dimension =
            parsed.dimensions[ZCL_DEV_PROOF_TEST];
        ASSERT(zcl_dev_proof_child_receipt_create(
            ZCL_DEV_PROOF_TEST, &child_dimension, child));
        ASSERT(zcl_dev_proof_child_receipt_validate(
            child, sizeof(child), ZCL_DEV_PROOF_TEST, &child_dimension));
        child[40] ^= 1u;
        ASSERT(!zcl_dev_proof_child_receipt_validate(
            child, sizeof(child), ZCL_DEV_PROOF_TEST, &child_dimension));
        ASSERT(!zcl_dev_proof_receipt_validate(
            &parsed, local,
            "3333333333333333333333333333333333333333",
            why, sizeof(why)));
        parsed = receipt;
        parsed.dimensions[ZCL_DEV_PROOF_TEST].skipped = 1;
        ASSERT(!zcl_dev_proof_receipt_validate(&parsed, local, base,
                                               why, sizeof(why)));
        parsed = receipt;
        parsed.child_set_root[0] ^= 1u;
        ASSERT(zcl_dev_proof_receipt_seal(&parsed));
        ASSERT(!zcl_dev_proof_receipt_validate(&parsed, local, base,
                                               why, sizeof(why)));
        parsed = receipt;
        memset(parsed.compiler_root, 0, sizeof(parsed.compiler_root));
        ASSERT(zcl_dev_proof_receipt_seal(&parsed));
        ASSERT(!zcl_dev_proof_receipt_validate(&parsed, local, base,
                                               why, sizeof(why)));
        wire[100] ^= 1u;
        ASSERT(zcl_dev_proof_receipt_parse(wire, sizeof(wire), &parsed));
        ASSERT(!zcl_dev_proof_receipt_validate(&parsed, local, base,
                                               why, sizeof(why)));
        PASS();
    } _test_next:;
    return failures;
}

static int test_ic_dev_proof_child_action_identity(void)
{
    int failures = 0;
    TEST("impact composition: proof child action is checkout-independent") {
        char source[65], cas[65];
        memset(source, '1', 64);
        memset(cas, '2', 64);
        source[64] = '\0';
        cas[64] = '\0';
        struct zcl_dev_proof_child_action_inputs_v1 inputs = {
            .source_sha256_hex = source,
            .source_cas_sha3_hex = cas,
            .selector = "build_fabric,vcs_core",
            .selected = 2,
        };
        memset(inputs.toolchain_capsule_root, 3, 32);
        memset(inputs.flags_root, 4, 32);
        memset(inputs.environment_root, 5, 32);
        memset(inputs.build_graph_root, 6, 32);
        struct vcs_build_action_v1 action_a = {0}, action_b = {0};
        uint8_t root_a[32], root_b[32];
        ASSERT(zcl_dev_proof_child_action_v1(
            &inputs, ZCL_DEV_PROOF_TEST, &action_a, root_a));
        ASSERT(zcl_dev_proof_child_action_v1(
            &inputs, ZCL_DEV_PROOF_TEST, &action_b, root_b));
        ASSERT(memcmp(root_a, root_b, sizeof(root_a)) == 0);
        ASSERT(memcmp(&action_a, &action_b, sizeof(action_a)) == 0);
        ASSERT(vcs_build_action_v1_work_kind(
            VCS_BUILD_ACTION_KIND_RESIDENT_PROOF_CHILD_V1) == 0);

        struct zcl_dev_proof_child_action_inputs_v1 changed = inputs;
        changed.selected++;
        ASSERT(zcl_dev_proof_child_action_v1(
            &changed, ZCL_DEV_PROOF_TEST, &action_b, root_b));
        ASSERT(memcmp(root_a, root_b, sizeof(root_a)) != 0);
        changed = inputs;
        changed.selector = "build_fabric";
        ASSERT(zcl_dev_proof_child_action_v1(
            &changed, ZCL_DEV_PROOF_TEST, &action_b, root_b));
        ASSERT(memcmp(root_a, root_b, sizeof(root_a)) != 0);

        uint8_t *mutable_roots[] = {
            changed.toolchain_capsule_root, changed.flags_root,
            changed.environment_root, changed.build_graph_root,
        };
        for (size_t i = 0; i < sizeof(mutable_roots) / sizeof(mutable_roots[0]);
             i++) {
            changed = inputs;
            uint8_t *root = i == 0 ? changed.toolchain_capsule_root :
                i == 1 ? changed.flags_root :
                i == 2 ? changed.environment_root : changed.build_graph_root;
            root[0] ^= 1u;
            ASSERT(zcl_dev_proof_child_action_v1(
                &changed, ZCL_DEV_PROOF_TEST, &action_b, root_b));
            ASSERT(memcmp(root_a, root_b, sizeof(root_a)) != 0);
        }
        (void)mutable_roots;

        char source_changed[65], cas_changed[65];
        memcpy(source_changed, source, sizeof(source_changed));
        memcpy(cas_changed, cas, sizeof(cas_changed));
        source_changed[0] = '3';
        changed = inputs;
        changed.source_sha256_hex = source_changed;
        ASSERT(zcl_dev_proof_child_action_v1(
            &changed, ZCL_DEV_PROOF_TEST, &action_b, root_b));
        ASSERT(memcmp(root_a, root_b, sizeof(root_a)) != 0);
        cas_changed[0] = '3';
        changed = inputs;
        changed.source_cas_sha3_hex = cas_changed;
        ASSERT(zcl_dev_proof_child_action_v1(
            &changed, ZCL_DEV_PROOF_TEST, &action_b, root_b));
        ASSERT(memcmp(root_a, root_b, sizeof(root_a)) != 0);

        changed = inputs;
        changed.selector = "";
        ASSERT(!zcl_dev_proof_child_action_v1(
            &changed, ZCL_DEV_PROOF_TEST, &action_b, root_b));
        changed.selected = 0;
        ASSERT(!zcl_dev_proof_child_action_v1(
            &changed, ZCL_DEV_PROOF_COMPILE, &action_b, root_b));
        changed.selected = 1;
        ASSERT(zcl_dev_proof_child_action_v1(
            &changed, ZCL_DEV_PROOF_COMPILE, &action_b, root_b));
        ASSERT(memcmp(root_a, root_b, sizeof(root_a)) != 0);
        changed.selector = "unexpected";
        ASSERT(!zcl_dev_proof_child_action_v1(
            &changed, ZCL_DEV_PROOF_COMPILE, &action_b, root_b));
        ASSERT(!zcl_dev_proof_child_action_v1(
            NULL, ZCL_DEV_PROOF_COMPILE, &action_b, root_b));
        PASS();
    } _test_next:;
    return failures;
}

/* T7 pins the landing-machine defect found 2026-09-04: a `.failed` marker
 * for the exact commit/base pair settled its outcome, yet `dev.proof.wait`
 * reported the SAME status/BLOCKED exit 3 as "still proving" — a landing
 * loop that treats exit 3 as "keep polling" then spins forever on a proof
 * that already finished failing (observed: 44 rounds, 40 minutes of dead
 * push-slot time against an idle child). The fix gives a settled failure
 * its own terminal result (FAILED status, non-3 exit) so a caller can tell
 * "still running" from "already lost" without parsing prose. It also pins
 * that `dev.proof.ensure` does not re-queue a pair whose failure is
 * already settled — an immutable commit/base identity would just re-derive
 * the identical deterministic failure. */
static int test_ic_proof_wait_reports_settled_failure(void)
{
    int failures = 0;
    TEST("impact composition: proof wait reports a settled failure, not blocked") {
#if !defined(_WIN32)
        char root[4096];
        static const char local[] =
            "cccccccccccccccccccccccccccccccccccccccc";
        static const char base[] =
            "2222222222222222222222222222222222222222";
        ASSERT(snprintf(root, sizeof(root),
                        IC_FIX_ROOT "/proof_wait_failed_%ld",
                        (long)getpid()) > 0);
        ASSERT(ic_write(root, "fixture", "proof wait fixture\n"));
        char state_dir[4096], failure_rel[4096];
        ASSERT(snprintf(state_dir, sizeof(state_dir),
                        "%s/.cache/zcl-dev-proof", root) > 0);
        ASSERT(snprintf(failure_rel, sizeof(failure_rel),
                        ".cache/zcl-dev-proof/%s-%s.failed", local,
                        base) > 0);
        ASSERT(ic_write(root, failure_rel, "child_proof_failed_exit_1"));

        /* Two throwaway attempt directories for this exact pair, as a real
         * failed proof leaves under attempts/<local>-<base>.XXXXXX/logs/
         * (see proof_attempt_paths_prepare in tools/dev/dev_proof.c) — the
         * flat .cache/zcl-dev-proof/logs/ directory is never written to.
         * mkdtemp's suffix is random, not time-ordered, so pin distinct
         * mtimes explicitly rather than relying on creation order. */
        char older_marker[4096], newer_marker[4096];
        char older_dir[4096], newer_dir[4096];
        ASSERT(snprintf(older_marker, sizeof(older_marker),
                        ".cache/zcl-dev-proof/attempts/%s-%s.older/logs/x",
                        local, base) > 0);
        ASSERT(snprintf(newer_marker, sizeof(newer_marker),
                        ".cache/zcl-dev-proof/attempts/%s-%s.newer/logs/x",
                        local, base) > 0);
        ASSERT(ic_write(root, older_marker, "stale attempt\n"));
        ASSERT(ic_write(root, newer_marker, "settled attempt\n"));
        ASSERT(snprintf(older_dir, sizeof(older_dir),
                        "%s/.cache/zcl-dev-proof/attempts/%s-%s.older",
                        root, local, base) > 0);
        ASSERT(snprintf(newer_dir, sizeof(newer_dir),
                        "%s/.cache/zcl-dev-proof/attempts/%s-%s.newer",
                        root, local, base) > 0);
        struct utimbuf older_times = { .actime = 1700000000,
                                       .modtime = 1700000000 };
        struct utimbuf newer_times = { .actime = 1800000000,
                                       .modtime = 1800000000 };
        ASSERT(utime(older_dir, &older_times) == 0);
        ASSERT(utime(newer_dir, &newer_times) == 0);
        /* dev_proof.c canonicalizes repo_root to an absolute, symlink-
         * resolved path (platform_directory_canonical_real) before it
         * derives any state path, so the expected log dir must be built
         * from that same canonical root, not the relative fixture path. */
        char canonical_newer_dir[4096];
        ASSERT(realpath(newer_dir, canonical_newer_dir) != NULL);
        char expected_log_dir[4096];
        ASSERT(snprintf(expected_log_dir, sizeof(expected_log_dir),
                        "%s/logs", canonical_newer_dir) > 0);

        /* Library layer: the settled pair reports FAILED immediately, no
         * further wait or re-request. */
        struct zcl_dev_proof_status status = {0};
        ASSERT(zcl_dev_proof_wait(root, local, base, 50, &status));
        ASSERT(status.state == ZCL_DEV_PROOF_STATE_FAILED);
        ASSERT(strcmp(status.detail, "child_proof_failed_exit_1") == 0);
        ASSERT(strcmp(status.log_dir, expected_log_dir) == 0);

        /* Command-dispatch layer (tools/command/native_dev_proof_command.c):
         * this is where the bug lived — proof_fail() hard-coded BLOCKED/
         * exit 3 for every non-PASSED state, including a settled FAILED.
         * zcl_dev_proof_wait_conclude() is the exact status/exit-code
         * mapping `dev.proof.wait` applies to an already-resolved status;
         * it is unconditional (no ZCL_DEV_BUILD dependency) precisely so
         * this contract is directly testable here without a dev build. */
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.dev_proof_status.v1");
        zcl_dev_proof_wait_conclude(&reply, &status);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_FAILED);
        ASSERT(reply.exit_code != ZCL_COMMAND_EXIT_BLOCKED);
        ASSERT(strcmp(reply.error.code, "PROOF_FAILED") == 0);
        ASSERT(strcmp(reply.error.evidence, "child_proof_failed_exit_1") == 0);
        const struct json_value *log_dir = json_get(&reply.data, "log_dir");
        ASSERT(log_dir && log_dir->type == JSON_STR &&
              json_get_str(log_dir)[0]);
        ASSERT(strcmp(json_get_str(log_dir), expected_log_dir) == 0);
        zcl_command_reply_free(&reply);

        /* Regression guard on the other side of the same contract: a
         * genuinely still-running proof stays BLOCKED/exit 3 — only a
         * SETTLED failure gets the new terminal FAILED/exit-1 treatment. */
        struct zcl_dev_proof_status running_status = {0};
        running_status.state = ZCL_DEV_PROOF_STATE_RUNNING;
        struct zcl_command_reply pending_reply;
        zcl_command_reply_init(&pending_reply, "zcl.dev_proof_status.v1");
        zcl_dev_proof_wait_conclude(&pending_reply, &running_status);
        ASSERT(pending_reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT(pending_reply.exit_code == ZCL_COMMAND_EXIT_BLOCKED);
        zcl_command_reply_free(&pending_reply);

        /* `dev.proof.ensure` must not re-queue a settled failure: no new
         * request file should appear for this exact pair. */
        struct zcl_dev_proof_status ensure_status = {0};
        ASSERT(zcl_dev_proof_ensure(root, local, base, &ensure_status));
        ASSERT(ensure_status.state == ZCL_DEV_PROOF_STATE_FAILED);
        char request_path[4096];
        ASSERT(snprintf(request_path, sizeof(request_path),
                        "%s/requests/%s-%s.request", state_dir, local,
                        base) > 0);
        ASSERT(access(request_path, F_OK) != 0);
#endif
        PASS();
    } _test_next:;
    return failures;
}

static int test_ic_resident_proof_queue(void)
{
    int failures = 0;
    TEST("impact composition: resident proof queue preserves unknown ancestry") {
#if defined(_WIN32)
        static const char local[] =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        static const char base[] =
            "1111111111111111111111111111111111111111";
        struct zcl_dev_proof_status status = {0};
        ASSERT(!zcl_dev_proof_queue_has_pending(IC_FIX_ROOT));
        ASSERT(zcl_dev_proof_status_read(IC_FIX_ROOT, local, base, &status));
        ASSERT(status.state == ZCL_DEV_PROOF_STATE_INVALID);
        ASSERT(strcmp(status.detail,
                      "windows_native_proof_worker_unavailable") == 0);
        memset(&status, 0, sizeof(status));
        ASSERT(!zcl_dev_proof_wait(IC_FIX_ROOT, local, base, 300000, &status));
        ASSERT(status.state == ZCL_DEV_PROOF_STATE_INVALID);
        ASSERT(strcmp(status.detail,
                      "windows_native_proof_worker_unavailable") == 0);
#else
        char root[4096];
        static const char local_a[] =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        static const char local_b[] =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        static const char base[] =
            "1111111111111111111111111111111111111111";
        ASSERT(snprintf(root, sizeof(root), IC_FIX_ROOT "/proof_queue_%ld",
                        (long)getpid()) > 0);
        ASSERT(ic_write(root, "fixture", "proof queue fixture\n"));
        ASSERT(ic_write(root, ".cache/fixture", "private state parent\n"));
        struct zcl_dev_proof_status status = {0};
        ASSERT(zcl_dev_proof_ensure(root, local_a, base, &status));
        ASSERT(status.state == ZCL_DEV_PROOF_STATE_RUNNING);
        ASSERT(strcmp(status.detail, "resident_proof_request_queued") == 0);
        ASSERT(zcl_dev_proof_ensure(root, local_b, base, &status));
        ASSERT(zcl_dev_proof_queue_has_pending(root));
        char why[256] = {0};
        ASSERT(zcl_dev_proof_queue_run_next(root, why, sizeof(why)) == 1);
        ASSERT(why[0]);
        ASSERT(zcl_dev_proof_queue_has_pending(root));
        ASSERT(zcl_dev_proof_status_read(root, local_a, base, &status));
        ASSERT(status.state == ZCL_DEV_PROOF_STATE_RUNNING);
        ASSERT(zcl_dev_proof_status_read(root, local_b, base, &status));
        ASSERT(status.state == ZCL_DEV_PROOF_STATE_FAILED);
        why[0] = 0;
        ASSERT(zcl_dev_proof_queue_run_next(root, why, sizeof(why)) == 1);
        ASSERT(why[0]);
        ASSERT(!zcl_dev_proof_queue_has_pending(root));
        ASSERT(zcl_dev_proof_status_read(root, local_a, base, &status));
        ASSERT(status.state == ZCL_DEV_PROOF_STATE_FAILED);
        char lease[4096];
        ASSERT(snprintf(lease, sizeof(lease),
                        "%s/.cache/zcl-dev-proof/leases/%s-%s.lease",
                        root, local_b, base) > 0);
        ASSERT(access(lease, F_OK) != 0);
#endif
        PASS();
    } _test_next:;
    return failures;
}

static int test_ic_cycle_reuse_requires_exact_proof_inputs(void)
{
    int failures = 0;
    static const char source[] =
        "1111111111111111111111111111111111111111111111111111111111111111";
    static const char inputs[] =
        "2222222222222222222222222222222222222222222222222222222222222222";
    static const char stale[] =
        "3333333333333333333333333333333333333333333333333333333333333333";
    static const char compile_root[] =
        "4444444444444444444444444444444444444444444444444444444444444444";
    static const char lint_root[] =
        "5555555555555555555555555555555555555555555555555555555555555555";
    static const char test_root[] =
        "6666666666666666666666666666666666666666666666666666666666666666";
    static const char shared_root[] =
        "7777777777777777777777777777777777777777777777777777777777777777";
    struct zcl_dev_proof_dimension dimensions[ZCL_DEV_PROOF_DIMENSIONS] = {0};
    dimensions[ZCL_DEV_PROOF_COMPILE].selected = 1;
    memset(dimensions[ZCL_DEV_PROOF_COMPILE].receipt_root, 0x44,
           ZCL_DEV_PROOF_ROOT_BYTES);
    dimensions[ZCL_DEV_PROOF_LINT].selected = 1;
    memset(dimensions[ZCL_DEV_PROOF_LINT].receipt_root, 0x55,
           ZCL_DEV_PROOF_ROOT_BYTES);
    dimensions[ZCL_DEV_PROOF_TEST].selected = 2;
    memset(dimensions[ZCL_DEV_PROOF_TEST].receipt_root, 0x66,
           ZCL_DEV_PROOF_ROOT_BYTES);
    char exact[1024];
    int exact_len = snprintf(
        exact, sizeof(exact),
        "{\"schema\":\"zcl.dev_cycle.v1\",\"status\":\"passed\","
        "\"phase\":\"verify\",\"proof_complete\":true,"
        "\"proof_scope\":\"source_wide_compile_tests_lint_fast\","
        "\"source_cas_sha3\":\"%s\",\"proof_inputs_sha3\":\"%s\","
        "\"proof_compile_root_sha3\":\"%s\","
        "\"proof_lint_root_sha3\":\"%s\","
        "\"proof_test_root_sha3\":\"%s\"}",
        source, inputs, compile_root, lint_root, test_root);
    char missing[1024];
    int missing_len = snprintf(
        missing, sizeof(missing),
        "{\"schema\":\"zcl.dev_cycle.v1\",\"status\":\"passed\","
        "\"phase\":\"verify\",\"proof_complete\":true,"
        "\"proof_scope\":\"source_wide_compile_tests_lint_fast\","
        "\"source_cas_sha3\":\"%s\","
        "\"proof_compile_root_sha3\":\"%s\","
        "\"proof_lint_root_sha3\":\"%s\","
        "\"proof_test_root_sha3\":\"%s\"}",
        source, compile_root, lint_root, test_root);
    char wrong_schema[1024];
    int wrong_schema_len = snprintf(
        wrong_schema, sizeof(wrong_schema),
        "{\"schema\":\"zcl.dev_cycle.v2\",\"status\":\"passed\","
        "\"phase\":\"verify\",\"proof_complete\":true,"
        "\"proof_scope\":\"source_wide_compile_tests_lint_fast\","
        "\"source_cas_sha3\":\"%s\",\"proof_inputs_sha3\":\"%s\","
        "\"proof_compile_root_sha3\":\"%s\","
        "\"proof_lint_root_sha3\":\"%s\","
        "\"proof_test_root_sha3\":\"%s\"}",
        source, inputs, compile_root, lint_root, test_root);
    char duplicate_source[1152];
    int duplicate_source_len = snprintf(
        duplicate_source, sizeof(duplicate_source),
        "{\"schema\":\"zcl.dev_cycle.v1\",\"status\":\"passed\","
        "\"phase\":\"verify\",\"proof_complete\":true,"
        "\"proof_scope\":\"source_wide_compile_tests_lint_fast\","
        "\"source_cas_sha3\":\"%s\",\"source_cas_sha3\":\"%s\","
        "\"proof_inputs_sha3\":\"%s\","
        "\"proof_compile_root_sha3\":\"%s\","
        "\"proof_lint_root_sha3\":\"%s\","
        "\"proof_test_root_sha3\":\"%s\"}",
        source, stale, inputs, compile_root, lint_root, test_root);
    char duplicate_dimension[1152];
    int duplicate_dimension_len = snprintf(
        duplicate_dimension, sizeof(duplicate_dimension),
        "{\"schema\":\"zcl.dev_cycle.v1\",\"status\":\"passed\","
        "\"phase\":\"verify\",\"proof_complete\":true,"
        "\"proof_scope\":\"source_wide_compile_tests_lint_fast\","
        "\"source_cas_sha3\":\"%s\",\"proof_inputs_sha3\":\"%s\","
        "\"proof_compile_root_sha3\":\"%s\","
        "\"proof_compile_root_sha3\":\"%s\","
        "\"proof_lint_root_sha3\":\"%s\","
        "\"proof_test_root_sha3\":\"%s\"}",
        source, inputs, compile_root, shared_root, lint_root, test_root);
    char shared_dimensions[1024];
    int shared_dimensions_len = snprintf(
        shared_dimensions, sizeof(shared_dimensions),
        "{\"schema\":\"zcl.dev_cycle.v1\",\"status\":\"passed\","
        "\"phase\":\"verify\",\"proof_complete\":true,"
        "\"proof_scope\":\"source_wide_compile_tests_lint_fast\","
        "\"source_cas_sha3\":\"%s\",\"proof_inputs_sha3\":\"%s\","
        "\"proof_compile_root_sha3\":\"%s\","
        "\"proof_lint_root_sha3\":\"%s\","
        "\"proof_test_root_sha3\":\"%s\"}",
        source, inputs, shared_root, shared_root, shared_root);
    TEST("impact composition: cycle reuse binds exact independent proof inputs") {
        ASSERT(exact_len > 0 && (size_t)exact_len < sizeof(exact));
        ASSERT(missing_len > 0 && (size_t)missing_len < sizeof(missing));
        ASSERT(wrong_schema_len > 0 &&
               (size_t)wrong_schema_len < sizeof(wrong_schema));
        ASSERT(duplicate_source_len > 0 &&
               (size_t)duplicate_source_len < sizeof(duplicate_source));
        ASSERT(duplicate_dimension_len > 0 &&
               (size_t)duplicate_dimension_len <
                   sizeof(duplicate_dimension));
        ASSERT(shared_dimensions_len > 0 &&
               (size_t)shared_dimensions_len < sizeof(shared_dimensions));
        ASSERT(zcl_dev_proof_cycle_reuse_admissible(
            exact, (size_t)exact_len, source, inputs, dimensions));
        ASSERT(!zcl_dev_proof_cycle_reuse_admissible(
            exact, (size_t)exact_len, source, stale, dimensions));
        ASSERT(!zcl_dev_proof_cycle_reuse_admissible(
            missing, (size_t)missing_len, source, inputs, dimensions));
        ASSERT(!zcl_dev_proof_cycle_reuse_admissible(
            exact, (size_t)exact_len, source, NULL, dimensions));
        ASSERT(!zcl_dev_proof_cycle_reuse_admissible(
            wrong_schema, (size_t)wrong_schema_len, source, inputs,
            dimensions));
        ASSERT(!zcl_dev_proof_cycle_reuse_admissible(
            duplicate_source, (size_t)duplicate_source_len, source, inputs,
            dimensions));
        ASSERT(!zcl_dev_proof_cycle_reuse_admissible(
            duplicate_dimension, (size_t)duplicate_dimension_len,
            source, inputs, dimensions));
        struct zcl_dev_proof_dimension shared[ZCL_DEV_PROOF_DIMENSIONS] = {0};
        shared[ZCL_DEV_PROOF_COMPILE].selected = 1;
        shared[ZCL_DEV_PROOF_LINT].selected = 1;
        shared[ZCL_DEV_PROOF_TEST].selected = 2;
        memset(shared[ZCL_DEV_PROOF_COMPILE].receipt_root, 0x77,
               ZCL_DEV_PROOF_ROOT_BYTES);
        memset(shared[ZCL_DEV_PROOF_LINT].receipt_root, 0x77,
               ZCL_DEV_PROOF_ROOT_BYTES);
        memset(shared[ZCL_DEV_PROOF_TEST].receipt_root, 0x77,
               ZCL_DEV_PROOF_ROOT_BYTES);
        ASSERT(!zcl_dev_proof_cycle_reuse_admissible(
            shared_dimensions, (size_t)shared_dimensions_len, source, inputs,
            shared));
        struct zcl_dev_proof_dimension mismatched[ZCL_DEV_PROOF_DIMENSIONS];
        memcpy(mismatched, dimensions, sizeof(mismatched));
        mismatched[ZCL_DEV_PROOF_TEST].receipt_root[0] ^= 1u;
        ASSERT(!zcl_dev_proof_cycle_reuse_admissible(
            exact, (size_t)exact_len, source, inputs, mismatched));
        PASS();
    } _test_next:;
    return failures;
}

static int test_ic_native_compositor_selects_physical_proof(void)
{
    int failures = 0;
    TEST("impact composition: every native compositor path selects UI proof") {
        static const char *const paths[] = {
            "contexts/explorer/views/src/ui_present_document.c",
            "contexts/explorer/views/include/views/ui_present_document.h",
            "contexts/explorer/views/src/ui_present_host.c",
            "contexts/explorer/views/include/views/ui_present_host.h",
        };
        for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
            struct agent_impact_acc impact = {0};
            ASSERT(agent_impact_apply_shared_rules(paths[i], &impact));
            ASSERT(ic_acc_has_group(&impact, "qr"));
            ASSERT(ic_acc_has_group(&impact, "spawn"));
            ASSERT(ic_acc_has_group(&impact, "native_api_contract"));
            ASSERT(ic_acc_has_group(&impact, "make_lint_gates"));
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_ic_fast_sync_splits_keep_proof_lane(void)
{
    int failures = 0;
    TEST("impact composition: new fast-sync splits keep focused proof lane") {
        static const char *const paths[] = {
            "core/modules/net/src/fast_sync_manifest_policy.c",
            "core/modules/net/include/net/fast_sync_future_policy.h",
        };
        for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
            struct agent_impact_acc impact = {0};
            ASSERT(agent_impact_apply_shared_rules(paths[i], &impact));
            ASSERT(impact.shared_rule_hits > 0);
            ASSERT(ic_acc_has_group(&impact, "fast_sync"));
            ASSERT(ic_acc_has_group(&impact, "snapshot_sync_service"));
            ASSERT(ic_acc_has_group(&impact, "make_lint_gates"));
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_ic_merkle_verifier_selects_proof_lane(void)
{
    int failures = 0;
    TEST("impact composition: Merkle verifier changes select proof tests") {
        struct agent_impact_acc impact = {0};
        ASSERT(agent_impact_apply_shared_rules(
            "cognition/modules/codeindex/src/codeindex_merkle.c", &impact));
        ASSERT(ic_acc_has_group(&impact, "code_merkle"));
        ASSERT(ic_acc_has_group(&impact, "code_merkle_proof"));
        ASSERT(ic_acc_has_group(&impact, "codeindex"));
        PASS();
    } _test_next:;
    return failures;
}

/* ── Proof step budgets ───────────────────────────────────────────────────
 *
 * The wall these replace was one constant for every step. Under load the test
 * dimension took 19 minutes against a 15-minute cap, the proof reported
 * `child_proof_failed_exit_124`, and the run it had just killed finished green
 * four minutes later. Every host hit it. These pin the replacement: a budget
 * sized from the plan, a kill decided by whether the step is still writing,
 * and a ceiling the environment may raise but never lower. */

#define IC_FIX_BUDGET IC_FIX_ROOT "/budget"

static void ic_budget_fixture(const char *sub, char out[4096])
{
    snprintf(out, 4096, "%s/%s", IC_FIX_BUDGET, sub);
    (void)ic_write(out, ".keep", "");
    char table[4096];
    snprintf(table, sizeof(table), "%s/timing/table.tsv", out);
    (void)remove(table);
}

static int test_ic_proof_budget_grows_with_groups(void)
{
    int failures = 0;
    TEST("proof budget: the test dimension is sized by the groups it will run") {
        char state[4096];
        ic_budget_fixture("grows", state);
        struct zcl_dev_proof_budget one =
            zcl_dev_proof_test_budget(state, "alpha", 1);
        struct zcl_dev_proof_budget three =
            zcl_dev_proof_test_budget(state, "alpha,beta,gamma", 3);
        struct zcl_dev_proof_budget ten = zcl_dev_proof_test_budget(
            state, "a,b,c,d,e,f,g,h,i,j", 10);
        ASSERT(one.budget_ms >= PROOF_TEST_FLOOR_MS);
        ASSERT(three.budget_ms > one.budget_ms);
        ASSERT(ten.budget_ms > three.budget_ms);
        /* Never past the ceiling, however many groups the plan names. */
        struct zcl_dev_proof_budget huge =
            zcl_dev_proof_test_budget(state, "", 100000);
        ASSERT(huge.budget_ms == huge.ceiling_ms);
        ASSERT(huge.ceiling_ms == PROOF_TIMEOUT_MS);
        /* A step with no history still gets the compiled-in allowance for
         * every group the plan named, even when the selector is unreadable. */
        ASSERT(one.budget_ms ==
               PROOF_TEST_FLOOR_MS + PROOF_TEST_GROUP_DEFAULT_MS);
        PASS();
    } _test_next:;
    return failures;
}

static int test_ic_proof_budget_learns_from_this_checkout(void)
{
    int failures = 0;
    TEST("proof budget: measured wall times lower and raise the allowance") {
        char state[4096];
        ic_budget_fixture("learns", state);
        struct zcl_dev_proof_budget cold =
            zcl_dev_proof_test_budget(state, "swift", 1);
        /* A group this checkout measures in two seconds needs far less than
         * the compiled default. */
        for (int i = 0; i < 3; i++)
            ASSERT(zcl_dev_proof_timing_note(state, "swift", 2000));
        struct zcl_dev_proof_budget quick =
            zcl_dev_proof_test_budget(state, "swift", 1);
        ASSERT(quick.budget_ms < cold.budget_ms);
        /* And a group measured at eight minutes needs far more. */
        ASSERT(zcl_dev_proof_timing_note(state, "slow", 480000));
        struct zcl_dev_proof_budget patient =
            zcl_dev_proof_test_budget(state, "slow", 1);
        ASSERT(patient.budget_ms > cold.budget_ms);
        ASSERT(zcl_dev_proof_timing_allowance_ms(state, "slow", 1) > 480000);
        /* An unknown key falls back to what the caller compiled in. */
        ASSERT(zcl_dev_proof_timing_allowance_ms(state, "never_seen", 4242) ==
               4242);
        /* The table remembers a bounded window, not every run ever. */
        for (int i = 0; i < (int)PROOF_HISTORY_MAX + 4; i++)
            ASSERT(zcl_dev_proof_timing_note(state, "swift", 1000));
        ASSERT(zcl_dev_proof_timing_allowance_ms(state, "swift", 1) ==
               1000 * 2 + 60000);
        PASS();
    } _test_next:;
    return failures;
}

static int test_ic_proof_ceiling_env_raises_only(void)
{
    int failures = 0;
    TEST("proof budget: the environment may raise the ceiling, never lower it") {
        ASSERT(zcl_dev_proof_ceiling_ms() == PROOF_TIMEOUT_MS);
        setenv("ZCL_PROOF_TIMEOUT_MS", "60000", 1);
        ASSERT(zcl_dev_proof_ceiling_ms() == PROOF_TIMEOUT_MS);
        setenv("ZCL_PROOF_TIMEOUT_MS", "5400000", 1);
        ASSERT(zcl_dev_proof_ceiling_ms() == 5400000);
        setenv("ZCL_PROOF_TIMEOUT_MS", "999999999", 1);
        ASSERT(zcl_dev_proof_ceiling_ms() == PROOF_TIMEOUT_MAX_MS);
        setenv("ZCL_PROOF_TIMEOUT_MS", "not-a-number", 1);
        ASSERT(zcl_dev_proof_ceiling_ms() == PROOF_TIMEOUT_MS);
        unsetenv("ZCL_PROOF_TIMEOUT_MS");
        ASSERT(zcl_dev_proof_ceiling_ms() == PROOF_TIMEOUT_MS);
        PASS();
    } _test_next:;
    return failures;
}

static int test_ic_proof_verdict_watches_progress_not_the_clock(void)
{
    int failures = 0;
    TEST("proof budget: a step still writing outlives the old fifteen-minute wall") {
        struct zcl_dev_proof_budget budget = {
            .budget_ms = 900000,
            .ceiling_ms = PROOF_TIMEOUT_MS,
            .no_progress_ms = PROOF_NO_PROGRESS_MS,
        };
        /* The exact run that was murdered: nineteen minutes in, still
         * printing, budget long spent. It lives. */
        ASSERT(zcl_dev_proof_budget_verdict(&budget, 19 * 60000, 1000) ==
               ZCL_DEV_PROOF_KILL_NONE);
        /* Silent for longer than the window, but inside its budget: also
         * alive — the harness's own 300 s per-group watchdog speaks first. */
        ASSERT(zcl_dev_proof_budget_verdict(&budget, 600000, 601000) ==
               ZCL_DEV_PROOF_KILL_NONE);
        /* Silent past the window with the budget spent: dead, and named. */
        ASSERT(zcl_dev_proof_budget_verdict(&budget, 1500000, 601000) ==
               ZCL_DEV_PROOF_KILL_NO_PROGRESS);
        /* A chatty runaway still hits the ceiling. */
        ASSERT(zcl_dev_proof_budget_verdict(&budget, PROOF_TIMEOUT_MS, 0) ==
               ZCL_DEV_PROOF_KILL_HARD_CEILING);
        ASSERT(strcmp(zcl_dev_proof_kill_cause_name(
                          ZCL_DEV_PROOF_KILL_NO_PROGRESS), "no_progress") == 0);
        ASSERT(strcmp(zcl_dev_proof_kill_cause_name(
                          ZCL_DEV_PROOF_KILL_HARD_CEILING),
                      "hard_ceiling") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_ic_proof_reads_the_harness_banners(void)
{
    int failures = 0;
    TEST("proof budget: per-group wall times come from the harness's own log") {
        char group[PROOF_TIMING_KEY_MAX];
        int64_t ms = 0;
        ASSERT(zcl_dev_proof_timing_parse_group_line(
            "==================== core_net (PASS, 12s) ====================\n",
            group, sizeof(group), &ms));
        ASSERT(strcmp(group, "core_net") == 0 && ms == 12000);
        /* A skip note sits between the status and the time. */
        ASSERT(zcl_dev_proof_timing_parse_group_line(
            "==================== wallet (PASS, 3 SKIP, 7s) ====================\n",
            group, sizeof(group), &ms));
        ASSERT(strcmp(group, "wallet") == 0 && ms == 7000);
        /* Only a pass says how long the work takes. */
        ASSERT(!zcl_dev_proof_timing_parse_group_line(
            "==================== core_net (FAIL, 12s) ====================\n",
            group, sizeof(group), &ms));
        ASSERT(!zcl_dev_proof_timing_parse_group_line(
            "==================== core_net (WEDGED-NO-OUTPUT, 12s) ====================\n",
            group, sizeof(group), &ms));
        ASSERT(!zcl_dev_proof_timing_parse_group_line(
            "SUITE VERDICT groups_ran=4\n", group, sizeof(group), &ms));

        char state[4096], log[4096];
        ic_budget_fixture("ingest", state);
        snprintf(log, sizeof(log), "%s/test.log", state);
        ASSERT(ic_write(
            state, "test.log",
            "noise before\n"
            "==================== alpha (PASS, 40s) ====================\n"
            "==================== beta (FAIL, 9s) ====================\n"
            "==================== gamma (PASS, 2 SKIP, 5s) ====================\n"
            "SUITE VERDICT groups_ran=3\n"));
        ASSERT(zcl_dev_proof_timing_ingest_test_log(state, log) == 2);
        ASSERT(zcl_dev_proof_timing_allowance_ms(state, "alpha", 1) ==
               40000 * 2 + 60000);
        ASSERT(zcl_dev_proof_timing_allowance_ms(state, "gamma", 1) ==
               5000 * 2 + 60000);
        ASSERT(zcl_dev_proof_timing_allowance_ms(state, "beta", 77) == 77);
        PASS();
    } _test_next:;
    return failures;
}

#if !defined(_WIN32)
static int test_ic_proof_run_watched_kills_only_the_silent(void)
{
    int failures = 0;
    TEST("proof budget: silence is killed, output is not, the ceiling is final") {
        char state[4096], log[4096];
        ic_budget_fixture("watched", state);
        snprintf(log, sizeof(log), "%s/step.log", state);

        /* A child that says nothing for longer than the window, with its
         * budget spent, is killed and the cause is named. */
        struct zcl_dev_proof_budget silent_budget = {
            .budget_ms = 200, .ceiling_ms = 20000, .no_progress_ms = 400};
        const char *quiet_argv[] = {"/bin/sh", "-c", "sleep 20", NULL};
        struct zcl_dev_proof_step_report quiet = {0};
        ASSERT(zcl_dev_proof_run_watched(".", log, quiet_argv, &silent_budget,
                                         &quiet) == 124);
        ASSERT(quiet.cause == ZCL_DEV_PROOF_KILL_NO_PROGRESS);
        ASSERT(quiet.elapsed_ms < 5000);
        ASSERT(quiet.budget_ms == 200);

        /* A child that keeps writing runs past its budget untouched — the
         * case the flat cap used to kill. */
        struct zcl_dev_proof_budget chatty_budget = {
            .budget_ms = 200, .ceiling_ms = 30000, .no_progress_ms = 3000};
        const char *chatty_argv[] = {
            "/bin/sh", "-c",
            "i=0; while [ $i -lt 12 ]; do echo tick; sleep 0.1; "
            "i=$((i+1)); done; exit 0", NULL};
        struct zcl_dev_proof_step_report chatty = {0};
        ASSERT(zcl_dev_proof_run_watched(".", log, chatty_argv, &chatty_budget,
                                         &chatty) == 0);
        ASSERT(chatty.cause == ZCL_DEV_PROOF_KILL_NONE);
        ASSERT(chatty.elapsed_ms > chatty.budget_ms);

        /* A chatty runaway still dies, at the ceiling, for that reason. */
        struct zcl_dev_proof_budget capped = {
            .budget_ms = 300, .ceiling_ms = 900, .no_progress_ms = 600000};
        const char *runaway_argv[] = {
            "/bin/sh", "-c", "while true; do echo tick; sleep 0.05; done",
            NULL};
        struct zcl_dev_proof_step_report runaway = {0};
        ASSERT(zcl_dev_proof_run_watched(".", log, runaway_argv, &capped,
                                         &runaway) == 124);
        ASSERT(runaway.cause == ZCL_DEV_PROOF_KILL_HARD_CEILING);

        /* Every step it ran is explained in phases.txt. */
        char phases[4096];
        snprintf(phases, sizeof(phases), "%s/phases.txt", state);
        (void)remove(phases);
        ASSERT(zcl_dev_proof_phase_record(phases, "test", &quiet));
        ASSERT(zcl_dev_proof_phase_record(phases, "lint", &chatty));
        char body[2048] = {0};
        FILE *f = fopen(phases, "r");
        ASSERT(f != NULL);
        size_t read = fread(body, 1, sizeof(body) - 1, f);
        fclose(f);
        body[read] = '\0';
        ASSERT(strstr(body, "step=test") != NULL);
        ASSERT(strstr(body, "budget_ms=200") != NULL);
        ASSERT(strstr(body, "elapsed_ms=") != NULL);
        ASSERT(strstr(body, "last_progress_age_ms=") != NULL);
        ASSERT(strstr(body, "cause=no_progress") != NULL);
        ASSERT(strstr(body, "step=lint") != NULL);
        ASSERT(strstr(body, "cause=none") != NULL);
        PASS();
    } _test_next:;
    return failures;
}
#endif
#if !defined(_WIN32)
static int test_ic_proof_steps_run_concurrently(void)
{
    int failures = 0;
    TEST("proof budget: independent steps run at once and still fail closed") {
        char state[4096], a[4096], b[4096];
        ic_budget_fixture("concurrent", state);
        snprintf(a, sizeof(a), "%s/a.log", state);
        snprintf(b, sizeof(b), "%s/b.log", state);
        struct zcl_dev_proof_budget budget = {
            .budget_ms = 60000, .ceiling_ms = 60000, .no_progress_ms = 30000};
        const char *busy_argv[] = {
            "/bin/sh", "-c",
            "i=0; while [ $i -lt 8 ]; do echo tick; sleep 0.1; "
            "i=$((i+1)); done; exit 0", NULL};
        struct zcl_dev_proof_step steps[2];
        int64_t began = platform_time_monotonic_ms();
        ASSERT(zcl_dev_proof_step_start(&steps[0], ".", a, busy_argv,
                                        &budget));
        ASSERT(zcl_dev_proof_step_start(&steps[1], ".", b, busy_argv,
                                        &budget));
        ASSERT(zcl_dev_proof_steps_wait(steps, 2) == 2);
        int64_t wall = platform_time_monotonic_ms() - began;
        /* Both took about 800 ms of their own; run together they cost about
         * one of them, not both. */
        ASSERT(steps[0].report.elapsed_ms >= 700);
        ASSERT(steps[1].report.elapsed_ms >= 700);
        ASSERT(wall < steps[0].report.elapsed_ms +
                          steps[1].report.elapsed_ms);
        /* Each keeps its own log. */
        ASSERT(steps[0].report.rc == 0 && steps[1].report.rc == 0);
        FILE *fa = fopen(a, "r");
        ASSERT(fa != NULL);
        char first[64] = {0};
        ASSERT(fgets(first, sizeof(first), fa) != NULL);
        fclose(fa);
        ASSERT(strncmp(first, "tick", 4) == 0);

        /* One failure in the set is the set's verdict, named by position. */
        const char *bad_argv[] = {"/bin/sh", "-c", "echo boom; exit 3", NULL};
        ASSERT(zcl_dev_proof_step_start(&steps[0], ".", a, busy_argv,
                                        &budget));
        ASSERT(zcl_dev_proof_step_start(&steps[1], ".", b, bad_argv, &budget));
        ASSERT(zcl_dev_proof_steps_wait(steps, 2) == 1);
        ASSERT(steps[1].report.rc == 3);
        ASSERT(steps[0].report.rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

#endif

static int test_ic_proof_generation_prefers_ram_when_it_fits(void)
{
    int failures = 0;
    TEST("proof budget: RAM-backed scratch is used only when it really fits") {
        char relative[4096], root[4096], probe[4096], cwd[2048];
        ic_budget_fixture("ramscratch", relative);
        ASSERT(getcwd(cwd, sizeof(cwd)) != NULL);
        snprintf(root, sizeof(root), "%s/%s", cwd, relative);
        /* Injected availability: the test pins the answer instead of asking
         * whatever filesystem this machine happens to mount. */
        setenv("ZCL_RAM_SCRATCH_ROOT", root, 1);
        ASSERT(platform_ram_scratch_root(probe, sizeof(probe), 1));
        ASSERT(strcmp(probe, root) == 0);
        /* Not enough headroom is a refusal, not a squeeze. */
        probe[0] = 'x';
        ASSERT(!platform_ram_scratch_root(probe, sizeof(probe), UINT64_MAX));
        ASSERT(probe[0] == '\0');
        /* A buffer too small to hold the answer is a refusal too. */
        char tiny[4];
        ASSERT(!platform_ram_scratch_root(tiny, sizeof(tiny), 1));
        ASSERT(tiny[0] == '\0');
        /* A path that is not a directory, and one that does not exist. */
        char file[4096];
        snprintf(file, sizeof(file), "%s/notadir", root);
        ASSERT(ic_write(relative, "notadir", "x"));
        setenv("ZCL_RAM_SCRATCH_ROOT", file, 1);
        ASSERT(!platform_ram_scratch_root(probe, sizeof(probe), 1));
        setenv("ZCL_RAM_SCRATCH_ROOT", "/no/such/ram/root", 1);
        ASSERT(!platform_ram_scratch_root(probe, sizeof(probe), 1));
        /* An override that is empty, or relative, refuses RAM backing rather
         * than quietly answering about /dev/shm instead. */
        setenv("ZCL_RAM_SCRATCH_ROOT", "", 1);
        ASSERT(!platform_ram_scratch_root(probe, sizeof(probe), 1));
        setenv("ZCL_RAM_SCRATCH_ROOT", relative, 1);
        ASSERT(!platform_ram_scratch_root(probe, sizeof(probe), 1));
        unsetenv("ZCL_RAM_SCRATCH_ROOT");

        /* The choice is a phases.txt fact, never a receipt field: two proofs
         * of the same source must admit each other whatever storage they
         * used. */
        char phases[4096];
        snprintf(phases, sizeof(phases), "%s/phases.txt", root);
        (void)remove(phases);
        ASSERT(zcl_dev_proof_phase_note(phases, "generation_storage", "ram"));
        ASSERT(zcl_dev_proof_phase_note(phases, "generation_root", root));
        char body[4096] = {0};
        FILE *f = fopen(phases, "r");
        ASSERT(f != NULL);
        size_t read = fread(body, 1, sizeof(body) - 1, f);
        fclose(f);
        body[read] = '\0';
        ASSERT(strstr(body, "generation_storage=ram") != NULL);
        ASSERT(strstr(body, "generation_root=") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

#if !defined(_WIN32)

static int test_ic_ram_scratch_reservations_hold_under_concurrency(void)
{
    int failures = 0;
    TEST("proof budget: RAM scratch is reserved, not just measured") {
        char relative[4096], root[4096], cwd[2048];
        ic_budget_fixture("ramreserve", relative);
        ASSERT(getcwd(cwd, sizeof(cwd)) != NULL);
        snprintf(root, sizeof(root), "%s/%s", cwd, relative);
        setenv("ZCL_RAM_SCRATCH_ROOT", root, 1);
        /* The room is measured on this filesystem, with a wide churn margin,
         * so ordinary activity cannot flip a verdict mid-test. */
        const uint64_t min_free = PLATFORM_RAM_SCRATCH_MIN_FREE_BYTES;
        const uint64_t margin = 1024ull * 1024ull * 1024ull;
        uint64_t free_bytes = 0;
        ASSERT(platform_disk_space_available(root, &free_bytes));
        ASSERT(free_bytes > min_free + 3 * margin);
        uint64_t first_bytes = free_bytes - min_free - margin;
        uint64_t second_bytes = 2 * margin;
        /* Two reservations that together exceed the room: the first is
         * admitted, the second is refused while the first is live, and
         * releasing the first gives the second its room back. */
        struct platform_ram_scratch_lease first = {0};
        ASSERT(platform_ram_scratch_reserve(root, first_bytes, &first));
        ASSERT(first.held);
        struct platform_ram_scratch_lease second = {0};
        ASSERT(!platform_ram_scratch_reserve(root, second_bytes, &second));
        ASSERT(!second.held);
        platform_ram_scratch_release(&first);
        ASSERT(!first.held);
        ASSERT(platform_ram_scratch_reserve(root, second_bytes, &second));
        ASSERT(second.held);
        platform_ram_scratch_release(&second);
        /* A released lease's room is hand-out-able again immediately. */
        struct platform_ram_scratch_lease again = {0};
        ASSERT(platform_ram_scratch_reserve(root, second_bytes, &again));
        platform_ram_scratch_release(&again);
        /* A lease under a dead pid is stale: its bytes do not count against
         * the room, and taking the lock removes its file. */
        pid_t child = fork();
        ASSERT(child >= 0);
        if (child == 0) _exit(0);
        int status = 0;
        ASSERT(waitpid(child, &status, 0) == child);
        char stale_rel[128];
        snprintf(stale_rel, sizeof(stale_rel), ".z23-leases/%ld-1",
                 (long)child);
        ASSERT(ic_write(relative, stale_rel, "1099511627777"));
        struct platform_ram_scratch_lease third = {0};
        ASSERT(platform_ram_scratch_reserve(root, second_bytes, &third));
        char stale[4096];
        snprintf(stale, sizeof(stale), "%s/%s", root, stale_rel);
        ASSERT(access(stale, F_OK) != 0);
        platform_ram_scratch_release(&third);
        unsetenv("ZCL_RAM_SCRATCH_ROOT");
        PASS();
    } _test_next:;
    return failures;
}

#endif


#if !defined(_WIN32)
/* The generation root moved to tmpfs, and link() does not cross filesystems.
 * For ten straight attempts the proof read EXDEV as "vendor/lib is missing"
 * and told the reader to run `make vendor` on a tree where vendor/lib was
 * present. This pins both halves of the cure: the copy happens, and it is
 * faithful. */
static int test_ic_proof_dependency_crosses_filesystems(void)
{
    int failures = 0;
    TEST("proof generation: a dependency crosses a filesystem boundary intact") {
        char relative[4096], cwd[2048], source[4096], same[4096];
        ic_budget_fixture("depcopy", relative);
        ASSERT(getcwd(cwd, sizeof(cwd)) != NULL);
        static const char body[] = "#!/bin/sh\nexec true\n";
        ASSERT(ic_write(relative, "payload.sh", body));
        snprintf(source, sizeof(source), "%s/%s/payload.sh", cwd, relative);
        ASSERT(chmod(source, 0755) == 0);
        /* Pin the source to a modification time that cannot be mistaken for
         * "now". A copy that stamps the target with the time of the copy
         * hands the generation an artifact newer than every source it was
         * built from, and make inside the generation then declares a stale
         * artifact up to date. link() preserves the time for free, so only a
         * copy can lose it — and only a check like this one can see that. */
        const struct timespec pinned[2] = {
            { .tv_sec = 1000000000, .tv_nsec = 0 },
            { .tv_sec = 1000000000, .tv_nsec = 123456000 },
        };
        ASSERT(utimensat(AT_FDCWD, source, pinned, 0) == 0);
        struct stat source_st;
        ASSERT(stat(source, &source_st) == 0);
        ASSERT(source_st.st_mtim.tv_sec == 1000000000);

        /* Same filesystem keeps the link fast path: one inode, not two. */
        snprintf(same, sizeof(same), "%s/%s/linked.sh", cwd, relative);
        ASSERT(zcl_dev_proof_dependency_materialize(source, same));
        struct stat same_st;
        ASSERT(stat(same, &same_st) == 0);
        ASSERT(same_st.st_dev == source_st.st_dev);
        ASSERT(same_st.st_ino == source_st.st_ino);
        ASSERT(same_st.st_mtim.tv_sec == source_st.st_mtim.tv_sec);
        ASSERT(same_st.st_mtim.tv_nsec == source_st.st_mtim.tv_nsec);

        /* Pin the fallback on every native host, including those without
         * /dev/shm. Only EXDEV is injected; copying and metadata are real. */
        char forced[4096];
        snprintf(forced, sizeof(forced), "%s/%s/copied.sh", cwd, relative);
        ASSERT(setenv("ZCL_DEV_PROOF_TEST_LINK_ERRNO", "EXDEV", 1) == 0);
        bool copied = zcl_dev_proof_dependency_materialize(source, forced);
        int cleared = unsetenv("ZCL_DEV_PROOF_TEST_LINK_ERRNO");
        ASSERT(cleared == 0);
        ASSERT(copied);
        struct stat forced_st;
        ASSERT(stat(forced, &forced_st) == 0);
        ASSERT(forced_st.st_dev == source_st.st_dev);
        ASSERT(forced_st.st_ino != source_st.st_ino);
        ASSERT((forced_st.st_mode & 07777) == (source_st.st_mode & 07777));
        ASSERT(forced_st.st_mtim.tv_sec == source_st.st_mtim.tv_sec);
        ASSERT(forced_st.st_mtim.tv_nsec == source_st.st_mtim.tv_nsec);
        ASSERT((size_t)forced_st.st_size == sizeof(body) - 1);
        char forced_body[sizeof(body)] = {0};
        FILE *forced_file = fopen(forced, "rb");
        ASSERT(forced_file != NULL);
        size_t forced_len = fread(forced_body, 1, sizeof(forced_body),
                                  forced_file);
        int closed = fclose(forced_file);
        ASSERT(closed == 0);
        ASSERT(forced_len == sizeof(body) - 1);
        ASSERT(memcmp(forced_body, body, sizeof(body) - 1) == 0);
        ASSERT(unlink(forced) == 0);

        /* An unrelated link error must retain its refusal and errno. */
        ASSERT(setenv("ZCL_DEV_PROOF_TEST_LINK_ERRNO", "EACCES", 1) == 0);
        bool denied = zcl_dev_proof_dependency_materialize(source, forced);
        int denied_errno = errno;
        cleared = unsetenv("ZCL_DEV_PROOF_TEST_LINK_ERRNO");
        ASSERT(cleared == 0);
        ASSERT(!denied);
        ASSERT(denied_errno == EACCES);
        ASSERT(lstat(forced, &forced_st) != 0 && errno == ENOENT);

        /* /dev/shm is the RAM-backed generation root in production. A box
         * without a writable one cannot observe the cross-device path at all,
         * so say so out loud rather than passing as if it had. */
        char ram_dir[4096], ram_target[4096];
        snprintf(ram_dir, sizeof(ram_dir), "/dev/shm/z23-ic-depcopy-%ld",
                 (long)getpid());
        if (mkdir(ram_dir, 0700) != 0 && errno != EEXIST) {
            printf("impact_composition: SKIP cross-filesystem dependency copy "
                   "(no writable /dev/shm on this host)\n");
            PASS();
            goto _test_next;
        }
        snprintf(ram_target, sizeof(ram_target), "%s/payload.sh", ram_dir);
        (void)unlink(ram_target);
        struct stat ram_st;
        if (stat(ram_dir, &ram_st) != 0 || ram_st.st_dev == source_st.st_dev) {
            (void)rmdir(ram_dir);
            printf("impact_composition: SKIP cross-filesystem dependency copy "
                   "(/dev/shm shares the filesystem of this checkout)\n");
            PASS();
            goto _test_next;
        }
        ASSERT(zcl_dev_proof_dependency_materialize(source, ram_target));
        struct stat copied_st;
        ASSERT(stat(ram_target, &copied_st) == 0);
        /* A copy, not a link: different filesystem, and the executable bit
         * that a hook or a .so depends on survived. */
        ASSERT(copied_st.st_dev != source_st.st_dev);
        ASSERT((copied_st.st_mode & 07777) == (source_st.st_mode & 07777));
        ASSERT((copied_st.st_mode & 0111) != 0);
        /* The copy is as old as what it was copied from, to the nanosecond. */
        ASSERT(copied_st.st_mtim.tv_sec == source_st.st_mtim.tv_sec);
        ASSERT(copied_st.st_mtim.tv_nsec == source_st.st_mtim.tv_nsec);
        ASSERT((size_t)copied_st.st_size == sizeof(body) - 1);
        char read_back[128] = {0};
        FILE *fh = fopen(ram_target, "rb");
        ASSERT(fh != NULL);
        size_t got = fread(read_back, 1, sizeof(read_back) - 1, fh);
        ASSERT(fclose(fh) == 0);
        ASSERT(got == sizeof(body) - 1);
        ASSERT(memcmp(read_back, body, sizeof(body) - 1) == 0);
        /* A directory recurses across the same boundary. */
        char dir_source[4096], dir_target[4096], nested[4096];
        snprintf(dir_source, sizeof(dir_source), "%s/%s/tree", cwd, relative);
        ASSERT(ic_write(relative, "tree/inner.txt", "inner\n"));
        snprintf(dir_target, sizeof(dir_target), "%s/tree", ram_dir);
        ASSERT(zcl_dev_proof_dependency_materialize(dir_source, dir_target));
        snprintf(nested, sizeof(nested), "%s/tree/inner.txt", ram_dir);
        struct stat nested_st;
        ASSERT(stat(nested, &nested_st) == 0);
        ASSERT(nested_st.st_size == 6);
        (void)unlink(nested);
        (void)rmdir(dir_target);
        (void)unlink(ram_target);
        (void)rmdir(ram_dir);
        PASS();
    } _test_next:;
    return failures;
}

#endif

/* Sealing a receipt now needs this box's Ed25519 signing key, which lives
 * under the resolved state root. Point that root into this group's own
 * test-tmp tree for the whole group, so a test run creates a throwaway key
 * instead of touching (or depending on) the operator's real one. The group
 * runs in its own child process, so the environment change is contained. */
static void ic_isolate_state_root(void)
{
    static char state[PATH_MAX];
    char base[PATH_MAX - 64];
    test_make_tmpdir(base, sizeof(base), "impact_composition", "state");
    if (snprintf(state, sizeof(state), "%s/state", base) > 0)
        setenv("XDG_STATE_HOME", state, 1);
}

/* ── the changed set a ten-lane landing batch actually produces ──────────
 *
 * A batch of ten-plus lanes is now the landing unit, so one proof legitimately
 * covers thousands of paths. What is pinned here is that the capture path
 * carries that many EXACTLY: it neither truncates a long list into a shorter
 * one that still parses, nor grows a stack frame to hold it, and it refuses
 * above its ceiling with the observed count in the reason. */

#define IC_FIX_CHANGED IC_FIX_ROOT "/changedset"
#define IC_CHANGED_REPO IC_FIX_CHANGED "/repo"

static bool ic_changed_fixture_build(void)
{
    /* One repository, three commits: base, base+1000 files, +3097 more (4097
     * total against base — one past the ceiling). */
    int rc = system(
        "set -e; rm -rf " IC_FIX_CHANGED "; mkdir -p " IC_CHANGED_REPO "; "
        "cd " IC_CHANGED_REPO "; git init -q .; "
        "git config user.email fixture@example.invalid; "
        "git config user.name fixture; git config commit.gpgsign false; "
        "echo base > base.txt; git add -A; git commit -qm base; "
        "git rev-parse HEAD > ../base.sha; "
        "i=0; while [ $i -lt 1000 ]; do echo x > f$i.c; i=$((i+1)); done; "
        "git add -A; git commit -qm batch; git rev-parse HEAD > ../one.sha; "
        "while [ $i -lt 4097 ]; do echo x > f$i.c; i=$((i+1)); done; "
        "git add -A; git commit -qm over; git rev-parse HEAD > ../two.sha; "
        ">/dev/null 2>&1");
    return rc == 0;
}

/* git writes --output relative to its own cwd, so the capture and record
 * paths handed to the proof seam must be absolute. */
static bool ic_changed_path(const char *rel, char *out, size_t out_len)
{
    char cwd[512];
    if (!getcwd(cwd, sizeof(cwd)))
        return false;
    return snprintf(out, out_len, "%s/" IC_FIX_CHANGED "/%s", cwd, rel) <
           (int)out_len;
}

static bool ic_read_sha(const char *rel, char out[65])
{
    char path[512];
    if (snprintf(path, sizeof(path), "%s/%s", IC_FIX_CHANGED, rel) >=
        (int)sizeof(path))
        return false;
    FILE *f = fopen(path, "r");
    if (!f)
        return false;
    char line[128] = {0};
    bool ok = fgets(line, sizeof(line), f) != NULL;
    fclose(f);
    if (!ok)
        return false;
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        line[--len] = 0;
    if (len == 0 || len >= 65)
        return false;
    (void)snprintf(out, 65, "%s", line);
    return true;
}

static int test_ic_changed_set_carries_a_landing_batch(void)
{
    int failures = 0;
    TEST("impact composition: a thousand-file changed set captures and plans") {
        ASSERT(ic_changed_fixture_build());
        char base[65], one[65];
        ASSERT(ic_read_sha("base.sha", base));
        ASSERT(ic_read_sha("one.sha", one));
        char capture[640], record[640];
        ASSERT(ic_changed_path("capture.txt", capture, sizeof(capture)));
        ASSERT(ic_changed_path("changed", record, sizeof(record)));

        struct zcl_dev_proof_changed_set set = {0};
        char why[256] = {0};
        /* This fixture is a throwaway repository under test-tmp/, so the
         * bounded git invocation is opted in for exactly this case. */
        ASSERT(setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1) == 0);
        bool captured = zcl_dev_proof_changed_set_capture(
            IC_CHANGED_REPO, base, one, capture, record, &set, why,
            sizeof(why));
        (void)unsetenv("ZCL_DEVLOOP_TEST_PROCESS");
        ASSERT(captured);
        ASSERT(set.count == 1000);
        ASSERT(set.files != NULL && set.bytes != NULL);
        for (size_t i = 0; i < set.count; i++)
            ASSERT(set.files[i] && set.files[i][0] && set.files[i][0] != '/');

        /* The persisted record holds every row, not a prefix of them. */
        FILE *f = fopen(record, "r");
        ASSERT(f != NULL);
        size_t lines = 0;
        int c, last = 0;
        while ((c = fgetc(f)) != EOF) {
            if (c == '\n')
                lines++;
            last = c;
        }
        fclose(f);
        ASSERT(lines == 1000);
        ASSERT(last == '\n');

        /* And the plan path accepts the whole batch. */
        struct zcl_devloop_plan plan;
        ASSERT(zcl_devloop_plan_files(set.files, set.count, &plan));
        /* The fixture paths match no impact rule by design, so groups are
         * proved separately: the same batch size with one real repo path in it
         * still selects that path's groups, which is what shows the ceiling
         * and not the rule table was the former limiter. */
        const char **mixed = zcl_calloc(set.count, sizeof(*mixed), "ic mixed");
        ASSERT(mixed != NULL);
        for (size_t i = 0; i < set.count; i++)
            mixed[i] = set.files[i];
        mixed[set.count - 1] = "tools/dev/devloop.c";
        bool mixed_planned = zcl_devloop_plan_files(mixed, set.count, &plan);
        free((void *)mixed);
        ASSERT(mixed_planned);
        ASSERT(plan.path_groups_len > 0);

        zcl_dev_proof_changed_set_release(&set);
        ASSERT(set.bytes == NULL && set.files == NULL && set.count == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_ic_changed_set_refuses_above_its_ceiling(void)
{
    int failures = 0;
    TEST("impact composition: an over-ceiling changed set refuses with its count") {
        ASSERT(ic_changed_fixture_build());
        char base[65], two[65];
        ASSERT(ic_read_sha("base.sha", base));
        ASSERT(ic_read_sha("two.sha", two));
        char capture[640], record[640];
        ASSERT(ic_changed_path("capture.txt", capture, sizeof(capture)));
        ASSERT(ic_changed_path("over", record, sizeof(record)));

        struct zcl_dev_proof_changed_set set = {0};
        char why[256] = {0};
        ASSERT(setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1) == 0);
        /* 4097 changed paths is exactly one past ZCL_DEVLOOP_MAX_FILES. */
        bool captured = zcl_dev_proof_changed_set_capture(
            IC_CHANGED_REPO, base, two, capture, record, &set, why,
            sizeof(why));
        (void)unsetenv("ZCL_DEVLOOP_TEST_PROCESS");
        ASSERT(!captured);
        ASSERT(set.count == 0 && set.files == NULL && set.bytes == NULL);
        ASSERT(strstr(why, "changed_set_invalid_or_truncated") != NULL);
        /* The refusal names the observed count — silence here is the defect
         * this case exists for. */
        ASSERT(strstr(why, "files=4097") != NULL);
        ASSERT(strstr(why, "max=4096") != NULL);
        /* A refused capture publishes no record. */
        FILE *f = fopen(record, "r");
        ASSERT(f == NULL);

        /* The plan path refuses the same set for the same reason. */
        const char **oversize = zcl_calloc((size_t)ZCL_DEVLOOP_MAX_FILES + 1,
                                           sizeof(*oversize), "ic oversize");
        ASSERT(oversize != NULL);
        for (size_t i = 0; i <= (size_t)ZCL_DEVLOOP_MAX_FILES; i++)
            oversize[i] = "tools/dev/devloop.c";
        struct zcl_devloop_plan plan;
        bool planned = zcl_devloop_plan_files(
            oversize, (size_t)ZCL_DEVLOOP_MAX_FILES + 1, &plan);
        free((void *)oversize);
        ASSERT(!planned);
        system("rm -rf " IC_FIX_CHANGED);
        PASS();
    } _test_next:;
    return failures;
}

static int test_ic_watch_overlay_keeps_its_own_ceiling(void)
{
    int failures = 0;
    TEST("impact composition: the watcher overlay keeps a ceiling of its own") {
        /* The two ceilings are deliberately different names with different
         * numbers: the proof/plan set is heap-resident and large, the inotify
         * overlay stays resident in the watcher frame and small, collapsing to
         * a full rebuild rather than dropping paths. Collapsing them back into
         * one number is what this case refuses. */
        ASSERT(ZCL_DEVLOOP_MAX_FILES == 4096);
        ASSERT(ZCL_DEVLOOP_WATCH_MAX_FILES == 256);
        ASSERT(ZCL_DEVLOOP_WATCH_MAX_FILES < ZCL_DEVLOOP_MAX_FILES);
        /* The overlay table must stay small enough to live in a frame. */
        ASSERT((size_t)ZCL_DEVLOOP_WATCH_MAX_FILES *
                   (size_t)ZCL_DEVLOOP_PATH_MAX <= 512u * 1024u);
        PASS();
    } _test_next:;
    return failures;
}

/* ── proof generation warm start ──────────────────────────────────────
 *
 * Fresh proof generations compile every translation unit because git
 * stamps every source with the checkout time. The warm start seeds the
 * new generation's build tree from the newest complete generation for
 * the same root (hard links for immutable object and depfile outputs, a
 * copy for the small executed wrapper, nothing else) and repairs make's
 * timestamp graph so exactly the changed set rebuilds. Every fixture
 * below is a self-contained tree under test-tmp/; nothing here runs a
 * real build. */

static bool pw_read_all(const char *path, char *out, size_t out_size,
                        size_t *len_out)
{
    FILE *f = fopen(path, "rb");
    size_t n = 0;
    int c;
    if (!f || !out || out_size == 0) {
        if (f) fclose(f);
        return false;
    }
    while ((c = fgetc(f)) != EOF) {
        if (n + 1 >= out_size) {
            fclose(f);
            return false;
        }
        out[n++] = (char)c;
    }
    if (ferror(f)) {
        fclose(f);
        return false;
    }
    fclose(f);
    out[n] = 0;
    if (len_out) *len_out = n;
    return true;
}

static bool pw_stat_ino(const char *path, unsigned long long *ino_out)
{
    struct stat st;
    if (!path || stat(path, &st) != 0) return false;
    if (ino_out) *ino_out = (unsigned long long)st.st_ino;
    return true;
}

static long long pw_mtime_ns(const char *path, bool *ok_out)
{
    struct stat st;
    long long ns = 0;
    bool ok = path && stat(path, &st) == 0;
    if (ok) {
#if defined(__APPLE__)
        ns = (long long)st.st_mtimespec.tv_sec * 1000000000LL +
             (long long)st.st_mtimespec.tv_nsec;
#else
        ns = (long long)st.st_mtim.tv_sec * 1000000000LL +
             (long long)st.st_mtim.tv_nsec;
#endif
    }
    if (ok_out) *ok_out = ok;
    return ns;
}

static int test_pw_tag_names_pool_entries(void)
{
    int failures = 0;
    TEST("proof warm start: tag predicate admits only generation tags") {
#if defined(_WIN32)
        ASSERT(true);
#else
        ASSERT(zcl_dev_proof_warm_tag("0b1953e6da8f5d4cbfd25564f3c02f7e"));
        ASSERT(zcl_dev_proof_warm_tag("00000000000000000000000000000000"));
        ASSERT(!zcl_dev_proof_warm_tag(NULL));
        ASSERT(!zcl_dev_proof_warm_tag(""));
        ASSERT(!zcl_dev_proof_warm_tag("0b1953e6da8f5d4cbfd25564f3c02f7"));
        ASSERT(!zcl_dev_proof_warm_tag(
            "0b1953e6da8f5d4cbfd25564f3c02f7e00"));
        ASSERT(!zcl_dev_proof_warm_tag("0B1953E6DA8F5DCBFD25564F3C02F7E"));
        ASSERT(!zcl_dev_proof_warm_tag("0b1953e6da8f5d4cbfd25564f3c02f7g"));
        ASSERT(!zcl_dev_proof_warm_tag("requests"));
        ASSERT(!zcl_dev_proof_warm_tag("../escape"));
#endif
        PASS();
    } _test_next:;
    return failures;
}

static int test_pw_classify_link_copy_skip(void)
{
    int failures = 0;
    TEST("proof warm start: classifier links outputs, copies wrapper") {
#if defined(_WIN32)
        ASSERT(true);
#else
        ASSERT(zcl_dev_proof_warm_classify("obj/epochs/e/a.o", true) ==
               ZCL_DEV_PROOF_WARM_LINK);
        ASSERT(zcl_dev_proof_warm_classify("obj/epochs/e/a.d", true) ==
               ZCL_DEV_PROOF_WARM_LINK);
        ASSERT(zcl_dev_proof_warm_classify("bin/zcc", true) ==
               ZCL_DEV_PROOF_WARM_COPY);
        /* Rewritten in place or live: never shared across generations. */
        ASSERT(zcl_dev_proof_warm_classify("bin/z23-dev", true) ==
               ZCL_DEV_PROOF_WARM_SKIP);
        ASSERT(zcl_dev_proof_warm_classify("obj/epochs/e/a.a", true) ==
               ZCL_DEV_PROOF_WARM_SKIP);
        ASSERT(zcl_dev_proof_warm_classify("obj/epochs/e/.build-session",
                                           true) ==
               ZCL_DEV_PROOF_WARM_SKIP);
        ASSERT(zcl_dev_proof_warm_classify("obj/epochs/e/.leases/x", true) ==
               ZCL_DEV_PROOF_WARM_SKIP);
        ASSERT(zcl_dev_proof_warm_classify("obj/.hidden/x.o", true) ==
               ZCL_DEV_PROOF_WARM_SKIP);
        ASSERT(zcl_dev_proof_warm_classify(
                   "obj/epochs/e/.stale.compile.9/p.o", true) ==
               ZCL_DEV_PROOF_WARM_SKIP);
        ASSERT(zcl_dev_proof_warm_classify(".proof-build-complete", true) ==
               ZCL_DEV_PROOF_WARM_SKIP);
        ASSERT(zcl_dev_proof_warm_classify("obj/epochs/e/a.o", false) ==
               ZCL_DEV_PROOF_WARM_SKIP);
        ASSERT(zcl_dev_proof_warm_classify(NULL, true) ==
               ZCL_DEV_PROOF_WARM_SKIP);
        ASSERT(zcl_dev_proof_warm_classify("", true) ==
               ZCL_DEV_PROOF_WARM_SKIP);
#endif
        PASS();
    } _test_next:;
    return failures;
}

static int test_pw_pick_newest_complete_idle(void)
{
    int failures = 0;
    TEST("proof warm start: donor pick is newest verifiable idle") {
#if defined(_WIN32)
        ASSERT(true);
#else
        struct zcl_dev_proof_warm_candidate none[1];
        memset(none, 0, sizeof(none));
        ASSERT(zcl_dev_proof_warm_pick(NULL, 0) < 0);
        ASSERT(zcl_dev_proof_warm_pick(none, 0) < 0);
        struct zcl_dev_proof_warm_candidate two[2];
        memset(two, 0, sizeof(two));
        two[0].completed = 100;
        two[0].touched = 100;
        two[0].head_ok = true;
        two[1].completed = 200;
        two[1].touched = 50;
        two[1].head_ok = true;
        ASSERT(zcl_dev_proof_warm_pick(two, 2) == 1);
        /* A live newest loses to an older idle generation. */
        two[1].live = true;
        ASSERT(zcl_dev_proof_warm_pick(two, 2) == 0);
        two[1].live = false;
        /* A moved checkout cannot donate even when newest. */
        two[1].head_ok = false;
        ASSERT(zcl_dev_proof_warm_pick(two, 2) == 0);
        two[1].head_ok = true;
        two[0].live = true;
        two[1].live = true;
        ASSERT(zcl_dev_proof_warm_pick(two, 2) < 0);
        two[0].live = false;
        two[1].live = false;
        /* Completion beats recency; recency breaks completion ties;
         * full ties keep the earlier candidate. */
        two[0].completed = 200;
        two[0].touched = 300;
        two[1].completed = 200;
        two[1].touched = 50;
        ASSERT(zcl_dev_proof_warm_pick(two, 2) == 0);
        two[0].touched = 50;
        ASSERT(zcl_dev_proof_warm_pick(two, 2) == 0);
#endif
        PASS();
    } _test_next:;
    return failures;
}

static int test_pw_marker_round_trip_and_refusals(void)
{
    int failures = 0;
    TEST("proof warm start: build-complete marker round-trips") {
#if defined(_WIN32)
        ASSERT(true);
#else
        char root[4096];
        static const char local[] =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        static const char base[] =
            "1111111111111111111111111111111111111111";
        test_make_tmpdir(root, sizeof(root), "proof_warm", "marker");
        char gen[4096];
        ASSERT(snprintf(gen, sizeof(gen), "%s/gen", root) > 0);
        ASSERT(ic_write(root, "gen/build/.keep", "marker parent\n"));
        struct zcl_dev_proof_build_identity_v1 identity_a;
        memset(identity_a.compiler, 0xaa, 32);
        memset(identity_a.flags, 0xbb, 32);
        memset(identity_a.environment, 0xdd, 32);
        memset(identity_a.build_graph, 0xcc, 32);
        ASSERT(zcl_dev_proof_warm_marker_write(gen, "/fixtures/proof-warm",
                                               local, base, 1700000000LL,
                                               &identity_a));
        char got_root[4096] = {0}, got_local[65] = {0}, got_base[65] = {0};
        int64_t completed = 0;
        struct zcl_dev_proof_build_identity_v1 got = {0};
        ASSERT(zcl_dev_proof_warm_marker_read(gen, got_root, got_local,
                                              got_base, &completed, &got));
        ASSERT(strcmp(got_root, "/fixtures/proof-warm") == 0);
        ASSERT(strcmp(got_local, local) == 0);
        ASSERT(strcmp(got_base, base) == 0);
        ASSERT(completed == 1700000000LL);
        ASSERT(memcmp(&got, &identity_a, sizeof(got)) == 0);
        /* Refusals: wrong schema, forged commit, missing file. */
        ASSERT(ic_write(root, "gen/build/.proof-build-complete",
                        "bogus-schema\nroot=/x\nlocal=aa\n"));
        ASSERT(!zcl_dev_proof_warm_marker_read(gen, got_root, got_local,
                                               got_base, &completed, &got));
        ASSERT(ic_write(root, "gen/build/.proof-build-complete",
                        "zcl.proof_build_complete.v1\nroot=/fixtures/"
                        "proof-warm\nlocal=zzzz\nbase=111111111111111111111"
                        "11111111111111111111\ncompleted=1700000000\n"));
        ASSERT(!zcl_dev_proof_warm_marker_read(gen, got_root, got_local,
                                               got_base, &completed, &got));
        ASSERT(!zcl_dev_proof_warm_marker_read(NULL, got_root, got_local,
                                               got_base, &completed, &got));
        ASSERT(test_rm_rf_recursive(root) == 0);
#endif
        PASS();
    } _test_next:;
    return failures;
}

static int test_pw_marker_identity_invalidates_stale_donor(void)
{
    int failures = 0;
    TEST("proof warm start: a donor's marker binds the build identity it "
        "was compiled under") {
#if defined(_WIN32)
        ASSERT(true);
#else
        char root[4096];
        static const char local[] =
            "2222222222222222222222222222222222222222";
        static const char base[] =
            "3333333333333333333333333333333333333333";
        test_make_tmpdir(root, sizeof(root), "proof_warm", "identity");
        char gen[4096];
        ASSERT(snprintf(gen, sizeof(gen), "%s/gen", root) > 0);
        ASSERT(ic_write(root, "gen/build/.keep", "identity parent\n"));
        /* The donor was built under identity A (say, today's compiler and
         * flags). */
        struct zcl_dev_proof_build_identity_v1 identity_a;
        memset(identity_a.compiler, 0x11, 32);
        memset(identity_a.flags, 0x22, 32);
        memset(identity_a.environment, 0x77, 32);
        memset(identity_a.build_graph, 0x33, 32);
        ASSERT(zcl_dev_proof_warm_marker_write(gen, "/fixtures/proof-warm",
                                               local, base, 1700000001LL,
                                               &identity_a));
        char got_root[4096] = {0}, got_local[65] = {0}, got_base[65] = {0};
        int64_t completed = 0;
        struct zcl_dev_proof_build_identity_v1 sealed = {0};
        ASSERT(zcl_dev_proof_warm_marker_read(gen, got_root, got_local,
                                              got_base, &completed, &sealed));
        /* This proof's OWN identity (say, after a compiler upgrade, a
         * CFLAGS change, or a vendor archive rebuilt in place -- none of
         * which move a tracked source blob, so the wrapper-inputs diff
         * would see no change) is B: every one of the four sealed roots
         * must differ from A, which is exactly what a donor-scan compare
         * (memcmp-equal across all four) is built to catch and refuse. */
        struct zcl_dev_proof_build_identity_v1 identity_b;
        memset(identity_b.compiler, 0x44, 32);
        memset(identity_b.flags, 0x55, 32);
        memset(identity_b.environment, 0x88, 32);
        memset(identity_b.build_graph, 0x66, 32);
        ASSERT(memcmp(sealed.compiler, identity_b.compiler, 32) != 0);
        ASSERT(memcmp(sealed.flags, identity_b.flags, 32) != 0);
        ASSERT(memcmp(sealed.environment, identity_b.environment, 32) != 0);
        ASSERT(memcmp(sealed.build_graph, identity_b.build_graph, 32) != 0);
        /* A single matching field is not enough to admit a donor: the same
         * compiler with different flags is still a different build. */
        ASSERT(memcmp(sealed.compiler, identity_a.compiler, 32) == 0);
        ASSERT(memcmp(sealed.flags, identity_b.flags, 32) != 0);
        /* A marker from before identity sealing existed (four fields
         * short) is a shortfall the field count refuses, not a run of zero
         * bytes an equality check could accidentally treat as a match. */
        ASSERT(ic_write(root, "gen/build/.proof-build-complete",
                        "zcl.proof_build_complete.v1\nroot=/fixtures/"
                        "proof-warm\nlocal=2222222222222222222222222222222"
                        "222222222\nbase=33333333333333333333333333333333"
                        "33333333\ncompleted=1700000001\n"));
        ASSERT(!zcl_dev_proof_warm_marker_read(gen, got_root, got_local,
                                               got_base, &completed,
                                               &sealed));
        ASSERT(test_rm_rf_recursive(root) == 0);
#endif
        PASS();
    } _test_next:;
    return failures;
}

#if !defined(_WIN32)
/* One build plan, written the way Make writes it for a checkout that lives
 * at `root`. The two values a second checkout genuinely cannot reproduce
 * are part of it on purpose: the -ffile-prefix-map that names the checkout,
 * and the epoch digest, which comes from a compiler fingerprint that hashes
 * the CC command string and therefore the checkout path. */
static bool ic_write_build_plan(const char *root, const char *epoch,
                                const char *compiler_id, const char *cflags,
                                const char *extra_line)
{
    char plan[8192];
    int n = snprintf(plan, sizeof(plan),
        "CC=%s/build/bin/zcc cc\n"
        "COMPILER_ID=%s\n"
        "BASE_GENERATION=%s\n"
        "DEV_CFLAGS=-std=c23 %s -ffile-prefix-map=%s=/zclassic23\n"
        "DEV_LDFLAGS=-pthread -pie\n"
        "DEV_LIBS=vendor/lib/libsecp256k1.a -lm\n"
        "DEV_OBJ_DIR=build/dev-obj/epochs/%s\n"
        "DEV_LINK_RSP=build/dev-obj/epochs/%s/link-inputs.rsp\n"
        "DEV_BASE_RELOC=build/dev-obj/epochs/%s/restart-base.o\n"
        "TEST_CFLAGS=-std=c23 -g -ffile-prefix-map=%s=/zclassic23\n"
        "TEST_LDFLAGS=-pthread -pie\n"
        "TEST_LIBS=vendor/lib/libsecp256k1.a -lm\n"
        "TEST_OBJ_DIR=build/test-obj/epochs/%s\n"
        "TEST_LINK_RSP=build/test-obj/epochs/%s/link-inputs.rsp\n"
        "TEST_BASE_RELOC=build/test-obj/epochs/%s/restart-base.o\n"
        "%s",
        root, compiler_id,
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        cflags, root, epoch, epoch, epoch, root, epoch, epoch, epoch,
        extra_line ? extra_line : "");
    return n > 0 && (size_t)n < (int)sizeof(plan) &&
           ic_write(root, "build/dev-loop/restart.env", plan);
}

static bool ic_root_set(const uint8_t root[32])
{
    uint8_t any = 0;
    for (size_t i = 0; i < 32; i++) any |= root[i];
    return any != 0;
}
#endif

/* The property the whole receipt rests on: one tree at two absolute paths
 * has one build identity. Until it did, a receipt was a statement about the
 * directory that produced it and meant nothing anywhere else. */
static int test_pw_identity_survives_a_second_checkout_path(void)
{
    int failures = 0;
    TEST("proof identity: two checkout paths, one set of roots") {
#if defined(_WIN32)
        ASSERT(true);
#else
        static const char epoch_a[] =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        static const char epoch_b[] =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        static const char compiler_id_a[] =
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        static const char compiler_id_b[] =
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        char root_a[4096], root_b[4096];
        test_make_tmpdir(root_a, sizeof(root_a), "proof_identity",
                         "checkout_a");
        test_make_tmpdir(root_b, sizeof(root_b), "proof_identity",
                         "checkout_b_longer_name");
        ASSERT(strcmp(root_a, root_b) != 0);
        ASSERT(ic_write_build_plan(root_a, epoch_a, compiler_id_a, "-O2",
                                   NULL));
        ASSERT(ic_write_build_plan(root_b, epoch_b, compiler_id_b, "-O2",
                                   NULL));
        struct zcl_dev_proof_build_identity_v1 a = {0}, b = {0};
        ASSERT(zcl_dev_proof_build_identity_v1_capture(root_a, &a));
        ASSERT(zcl_dev_proof_build_identity_v1_capture(root_b, &b));
        ASSERT(memcmp(&a, &b, sizeof(a)) == 0);
        /* Equal-because-empty would satisfy the line above and prove
         * nothing, so every root has to carry something. */
        ASSERT(ic_root_set(a.compiler) && ic_root_set(a.flags) &&
               ic_root_set(a.environment) && ic_root_set(a.build_graph));
        /* compiler_root is the toolchain capsule, not a hash of the plan. */
        struct vcs_toolchain_capsule_v1 capsule;
        uint8_t capsule_root[32];
        ASSERT(vcs_toolchain_capsule_v1_capture(&capsule));
        ASSERT(vcs_toolchain_capsule_v1_root(&capsule, capsule_root));
        ASSERT(memcmp(a.compiler, capsule_root, 32) == 0);
        /* A checkout root a prefix rewrite cannot model is refused rather
         * than half-applied. */
        struct zcl_dev_proof_build_identity_v1 refused = {0};
        ASSERT(!zcl_dev_proof_build_identity_v1_capture("/", &refused));
        ASSERT(!zcl_dev_proof_build_identity_v1_capture(root_a, NULL));
        /* The four roots this box puts in a receipt, printed so two boxes
         * can be compared without either running a proof. */
        char compiler_hex[65], flags_hex[65], environment_hex[65];
        char build_graph_hex[65];
        zcl_hex_encode(a.compiler, 32, compiler_hex);
        zcl_hex_encode(a.flags, 32, flags_hex);
        zcl_hex_encode(a.environment, 32, environment_hex);
        zcl_hex_encode(a.build_graph, 32, build_graph_hex);
        printf("impact_composition: proof build identity compiler=%s "
               "flags=%s environment=%s build_graph=%s\n",
               compiler_hex, flags_hex, environment_hex, build_graph_hex);
        ASSERT(test_rm_rf_recursive(root_a) == 0);
        ASSERT(test_rm_rf_recursive(root_b) == 0);
#endif
        PASS();
    } _test_next:;
    return failures;
}

/* Each root answers one question, and moving one input moves exactly one
 * root. A root that moved for someone else's reason is a root nobody can
 * read. */
static int test_pw_identity_keeps_its_four_roots_apart(void)
{
    int failures = 0;
    TEST("proof identity: one input moves exactly one root") {
#if defined(_WIN32)
        ASSERT(true);
#else
        static const char epoch[] =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        static const char compiler_id[] =
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        char root[4096];
        test_make_tmpdir(root, sizeof(root), "proof_identity", "separation");
        struct zcl_dev_proof_build_identity_v1 baseline = {0}, moved = {0};
        ASSERT(ic_write_build_plan(root, epoch, compiler_id, "-O2", NULL));
        ASSERT(zcl_dev_proof_build_identity_v1_capture(root, &baseline));

        /* A flag the plan passes moves flags_root and nothing else. */
        ASSERT(ic_write_build_plan(root, epoch, compiler_id, "-O0", NULL));
        ASSERT(zcl_dev_proof_build_identity_v1_capture(root, &moved));
        ASSERT(memcmp(moved.flags, baseline.flags, 32) != 0);
        ASSERT(memcmp(moved.compiler, baseline.compiler, 32) == 0);
        ASSERT(memcmp(moved.environment, baseline.environment, 32) == 0);
        ASSERT(memcmp(moved.build_graph, baseline.build_graph, 32) == 0);

        /* A plan line this build has never heard of lands in the build
         * graph. It must never be silently dropped: an input nobody hashes
         * is an input nobody notices changing. */
        ASSERT(ic_write_build_plan(root, epoch, compiler_id, "-O2",
                                   "DEV_SOMETHING_NEW=1\n"));
        ASSERT(zcl_dev_proof_build_identity_v1_capture(root, &moved));
        ASSERT(memcmp(moved.build_graph, baseline.build_graph, 32) != 0);
        ASSERT(memcmp(moved.compiler, baseline.compiler, 32) == 0);
        ASSERT(memcmp(moved.flags, baseline.flags, 32) == 0);
        ASSERT(memcmp(moved.environment, baseline.environment, 32) == 0);

        /* A plan line that is not KEY=VALUE is refused, not guessed at. */
        ASSERT(ic_write_build_plan(root, epoch, compiler_id, "-O2",
                                   "a line with no equals sign\n"));
        ASSERT(!zcl_dev_proof_build_identity_v1_capture(root, &moved));
        ASSERT(ic_write_build_plan(root, epoch, compiler_id, "-O2", NULL));

        /* An environment variable that reaches the compiler without going
         * through a flag moves environment_root and nothing else. */
        const char *saved_cflags = getenv("CFLAGS");
        char restore_cflags[4096] = {0};
        if (saved_cflags)
            snprintf(restore_cflags, sizeof(restore_cflags), "%s",
                     saved_cflags);
        ASSERT(setenv("CFLAGS", "-fsanitize=undefined", 1) == 0);
        ASSERT(zcl_dev_proof_build_identity_v1_capture(root, &moved));
        ASSERT(memcmp(moved.environment, baseline.environment, 32) != 0);
        ASSERT(memcmp(moved.compiler, baseline.compiler, 32) == 0);
        ASSERT(memcmp(moved.flags, baseline.flags, 32) == 0);
        ASSERT(memcmp(moved.build_graph, baseline.build_graph, 32) == 0);
        if (saved_cflags)
            ASSERT(setenv("CFLAGS", restore_cflags, 1) == 0);
        else
            ASSERT(unsetenv("CFLAGS") == 0);

        /* PATH moves nothing. It used to move environment_root, which is
         * why two boxes with one toolchain could never agree; the compiler
         * is identified by the bytes of the driver it resolves, not by the
         * search order that would have found it. */
        const char *saved_path = getenv("PATH");
        char restore_path[8192] = {0}, reordered[8192];
        ASSERT(saved_path != NULL);
        snprintf(restore_path, sizeof(restore_path), "%s", saved_path);
        ASSERT(snprintf(reordered, sizeof(reordered), "/nonexistent-probe:%s",
                        restore_path) < (int)sizeof(reordered));
        ASSERT(setenv("PATH", reordered, 1) == 0);
        ASSERT(zcl_dev_proof_build_identity_v1_capture(root, &moved));
        ASSERT(setenv("PATH", restore_path, 1) == 0);
        ASSERT(memcmp(&moved, &baseline, sizeof(moved)) == 0);

        /* A different compiler binary still moves compiler_root: the
         * capsule carries the driver's bytes, so replacing the driver
         * changes the root even though no path changed. */
        struct vcs_toolchain_capsule_v1 capsule, swapped;
        uint8_t here[32], elsewhere[32];
        ASSERT(vcs_toolchain_capsule_v1_capture(&capsule));
        ASSERT(vcs_toolchain_capsule_v1_root(&capsule, here));
        swapped = capsule;
        swapped.compiler_driver_sha3[0] ^= 1u;
        ASSERT(vcs_toolchain_capsule_v1_root(&swapped, elsewhere));
        ASSERT(memcmp(here, elsewhere, 32) != 0);
        ASSERT(memcmp(here, baseline.compiler, 32) == 0);

        ASSERT(test_rm_rf_recursive(root) == 0);
#endif
        PASS();
    } _test_next:;
    return failures;
}

/* A receipt whose roots were derived under the old meaning is named, not
 * compared. Comparing it would ask whether a hash of a checkout path equals
 * a hash of a toolchain. */
static int test_pw_receipt_refuses_an_older_root_policy(void)
{
    int failures = 0;
    static const char local[] =
        "1111111111111111111111111111111111111111";
    static const char base[] =
        "2222222222222222222222222222222222222222";
    TEST("proof identity: a receipt from the old root policy is refused") {
        struct zcl_dev_acceptance_receipt_v1 receipt =
            ic_valid_dev_proof_receipt();
        char why[128];
        ASSERT(zcl_dev_proof_receipt_validate(&receipt, local, base,
                                              why, sizeof(why)));
        ASSERT(ZCL_DEV_PROOF_POLICY_VERSION >= 2u);
        struct zcl_dev_acceptance_receipt_v1 old = receipt;
        old.policy_version = ZCL_DEV_PROOF_POLICY_VERSION - 1u;
        ASSERT(zcl_dev_proof_receipt_seal(&old));
        ASSERT(!zcl_dev_proof_receipt_validate(&old, local, base,
                                               why, sizeof(why)));
        ASSERT(strcmp(why, "receipt_schema_old") == 0);
        struct zcl_dev_acceptance_receipt_v1 newer = receipt;
        newer.policy_version = ZCL_DEV_PROOF_POLICY_VERSION + 1u;
        ASSERT(zcl_dev_proof_receipt_seal(&newer));
        ASSERT(!zcl_dev_proof_receipt_validate(&newer, local, base,
                                               why, sizeof(why)));
        ASSERT(strcmp(why, "receipt_schema_newer_than_this_build") == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* The one line a developer reads beside an admitted receipt: what the
 * sidecar warm_sidecar_write() left behind, turned into "warm-start from
 * donor <id>" or "cold: <typed reason>" -- never prose, never a env-var
 * name, and never silent about which of the two happened. */
static int test_pw_status_line_reports_warm_or_typed_cold(void)
{
    int failures = 0;
    TEST("proof warm start: the status line names the donor or the typed "
        "cold reason") {
        char root[4096];
        test_make_tmpdir(root, sizeof(root), "proof_warm", "statusline");
        char sidecar[4096];
        ASSERT(snprintf(sidecar, sizeof(sidecar), "%s/x.warmstart", root) >
              0);
        char line[256];
        /* warm=1 with a donor tag reports the donor. */
        ASSERT(ic_write(root, "x.warmstart",
                        "zcl.dev_proof_warmstart.v1\nwarm=1\n"
                        "donor=abc123donor\ndonor_local="
                        "4444444444444444444444444444444444444444\n"
                        "files_linked=12\nbytes_linked=4096\n"
                        "compile_mode=reused\ncompile_ms=10\n"
                        "bundle_ms=5\nreason=-\n"));
        ASSERT(zcl_dev_proof_test_warm_status_line(sidecar, line,
                                                   sizeof(line)));
        ASSERT(strcmp(line, "warm-start from donor abc123donor") == 0);
        /* warm=0 with a typed reason reports that reason, not prose. */
        ASSERT(ic_write(root, "x.warmstart",
                        "zcl.dev_proof_warmstart.v1\nwarm=0\ndonor=-\n"
                        "donor_local=-\nfiles_linked=0\nbytes_linked=0\n"
                        "compile_mode=built\ncompile_ms=9000\n"
                        "bundle_ms=0\nreason=no_eligible_donor\n"));
        ASSERT(zcl_dev_proof_test_warm_status_line(sidecar, line,
                                                   sizeof(line)));
        ASSERT(strcmp(line, "cold: no_eligible_donor") == 0);
        /* The opt-out switch's own reason surfaces the same way. */
        ASSERT(ic_write(root, "x.warmstart",
                        "zcl.dev_proof_warmstart.v1\nwarm=0\ndonor=-\n"
                        "donor_local=-\nfiles_linked=0\nbytes_linked=0\n"
                        "compile_mode=built\ncompile_ms=9000\n"
                        "bundle_ms=0\nreason=disabled\n"));
        ASSERT(zcl_dev_proof_test_warm_status_line(sidecar, line,
                                                   sizeof(line)));
        ASSERT(strcmp(line, "cold: disabled") == 0);
        /* A missing sidecar (no compile ran this cycle, e.g. a
         * cycle-reused receipt) refuses rather than fabricating a line;
         * the caller's own fixed fallback stands. */
        char missing[4096];
        ASSERT(snprintf(missing, sizeof(missing), "%s/none.warmstart",
                        root) > 0);
        ASSERT(!zcl_dev_proof_test_warm_status_line(missing, line,
                                                     sizeof(line)));
        /* A foreign or truncated file refuses the same way. */
        ASSERT(ic_write(root, "x.warmstart", "not-the-right-schema\n"));
        ASSERT(!zcl_dev_proof_test_warm_status_line(sidecar, line,
                                                     sizeof(line)));
        ASSERT(test_rm_rf_recursive(root) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* The opt-out switch the production prepare gates on. Proves each
 * spelling forces cold and that anything else (including unset) leaves
 * warm start armed. Restores the prior value: the variable is
 * process-global. */
static int test_pw_disable_switch_forces_cold(void)
{
    int failures = 0;
    TEST("proof warm start: opt-out switch forces cold") {
#if defined(_WIN32)
        ASSERT(true);
#else
        const char *prior = getenv("ZCL_DEV_PROOF_WARM");
        char saved[256] = {0};
        bool had = prior != NULL;
        if (had) (void)snprintf(saved, sizeof(saved), "%s", prior);
        unsetenv("ZCL_DEV_PROOF_WARM");
        ASSERT(!zcl_dev_proof_warm_disabled());
        ASSERT(setenv("ZCL_DEV_PROOF_WARM", "0", 1) == 0);
        ASSERT(zcl_dev_proof_warm_disabled());
        ASSERT(setenv("ZCL_DEV_PROOF_WARM", "off", 1) == 0);
        ASSERT(zcl_dev_proof_warm_disabled());
        ASSERT(setenv("ZCL_DEV_PROOF_WARM", "no", 1) == 0);
        ASSERT(zcl_dev_proof_warm_disabled());
        ASSERT(setenv("ZCL_DEV_PROOF_WARM", "1", 1) == 0);
        ASSERT(!zcl_dev_proof_warm_disabled());
        ASSERT(setenv("ZCL_DEV_PROOF_WARM", "", 1) == 0);
        ASSERT(!zcl_dev_proof_warm_disabled());
        if (had)
            ASSERT(setenv("ZCL_DEV_PROOF_WARM", saved, 1) == 0);
        else
            ASSERT(unsetenv("ZCL_DEV_PROOF_WARM") == 0);
#endif
        PASS();
    } _test_next:;
    return failures;
}

/* The link/copy decision, proven against inodes. Linked outputs share the
 * donor's inode; the test rebuilds one through staging plus rename (the
 * epoch publisher's exact semantics) and proves the donor keeps its bytes
 * and inode. The copied wrapper owns its inode; the test rewrites it in
 * place and proves the donor is untouched. */
static int test_pw_seed_links_replaces_and_copies(void)
{
    int failures = 0;
    TEST("proof warm start: seed links, replace and rewrite spare donor") {
#if defined(_WIN32)
        ASSERT(true);
#else
        char root[4096], donor[4096], gen[4096], gen_src[4096];
        test_make_tmpdir(root, sizeof(root), "proof_warm", "seed");
        ASSERT(snprintf(donor, sizeof(donor), "%s/donor/build", root) > 0);
        ASSERT(snprintf(gen, sizeof(gen), "%s/gen/build", root) > 0);
        ASSERT(snprintf(gen_src, sizeof(gen_src), "%s/gen", root) > 0);
        ASSERT(ic_write(root, "donor/build/obj/epochs/E/mod/a.o",
                        "OBJECT-A-V1"));
        ASSERT(ic_write(root, "donor/build/obj/epochs/E/mod/a.d", "DEP-A"));
        ASSERT(ic_write(root, "donor/build/obj/epochs/E/sub/b.o",
                        "OBJECT-B-V1!"));
        ASSERT(ic_write(root, "donor/build/bin/zcc", "WRAPPER-V1"));
        /* Decoys the seed must never touch: live state, crash staging,
         * in-place outputs, and the product binary. */
        ASSERT(ic_write(root, "donor/build/obj/epochs/E/.build-session",
                        "SESSION"));
        ASSERT(ic_write(root, "donor/build/obj/epochs/E/.leases/L1",
                        "LEASE"));
        ASSERT(ic_write(root,
                        "donor/build/obj/epochs/E/.stale.compile.9/p.o",
                        "PARTIAL"));
        ASSERT(ic_write(root, "donor/build/obj/epochs/E/mod/tool",
                        "BINARY"));
        ASSERT(ic_write(root, "donor/build/obj/epochs/E/mod/lib.a",
                        "ARCHIVE"));
        ASSERT(ic_write(root, "donor/build/obj/.hidden/x.o", "HIDDEN"));
        ASSERT(ic_write(root, "donor/build/bin/z23-dev", "PRODUCT"));
        ASSERT(ic_write(root, "gen/src/changed.c",
                        "int changed(void){return 1;}\n"));
        ASSERT(ic_write(root, "gen/src/same.c", "int same(void){return 0;}\n"));
        static const char *const changed[] = {"src/changed.c"};
        struct zcl_dev_proof_warm_stats stats = {0};
        ASSERT(zcl_dev_proof_warm_seed_and_retime(donor, gen, gen_src,
                                                  changed, 1, &stats));
        ASSERT(stats.files_linked == 4);
        ASSERT(stats.bytes_linked == strlen("OBJECT-A-V1") +
               strlen("DEP-A") + strlen("OBJECT-B-V1!") +
               strlen("WRAPPER-V1"));
        char gen_a_o[4096], donor_a_o[4096], gen_zcc[4096], donor_zcc[4096];
        ASSERT(snprintf(gen_a_o, sizeof(gen_a_o),
                        "%s/obj/epochs/E/mod/a.o", gen) > 0);
        ASSERT(snprintf(donor_a_o, sizeof(donor_a_o),
                        "%s/obj/epochs/E/mod/a.o", donor) > 0);
        ASSERT(snprintf(gen_zcc, sizeof(gen_zcc), "%s/bin/zcc", gen) > 0);
        ASSERT(snprintf(donor_zcc, sizeof(donor_zcc), "%s/bin/zcc",
                        donor) > 0);
        unsigned long long gen_a_ino = 0, donor_a_ino = 0;
        unsigned long long gen_zcc_ino = 0, donor_zcc_ino = 0;
        ASSERT(pw_stat_ino(gen_a_o, &gen_a_ino));
        ASSERT(pw_stat_ino(donor_a_o, &donor_a_ino));
        ASSERT(gen_a_ino == donor_a_ino);
        ASSERT(pw_stat_ino(gen_zcc, &gen_zcc_ino));
        ASSERT(pw_stat_ino(donor_zcc, &donor_zcc_ino));
        ASSERT(gen_zcc_ino != donor_zcc_ino);
        char buf[64];
        ASSERT(pw_read_all(gen_zcc, buf, sizeof(buf), NULL));
        ASSERT(strcmp(buf, "WRAPPER-V1") == 0);
        /* Decoys never arrive. */
        char probe[4096];
        static const char *const absent[] = {
            "obj/epochs/E/.build-session",
            "obj/epochs/E/.leases/L1",
            "obj/epochs/E/.stale.compile.9/p.o",
            "obj/epochs/E/mod/tool",
            "obj/epochs/E/mod/lib.a",
            "obj/.hidden/x.o",
            "bin/z23-dev",
        };
        for (size_t i = 0; i < sizeof(absent) / sizeof(absent[0]); i++) {
            ASSERT(snprintf(probe, sizeof(probe), "%s/%s", gen,
                            absent[i]) > 0);
            ASSERT(access(probe, F_OK) != 0);
        }
        /* Timestamp graph: changed is newer than the seeds, untouched
         * sources are older. */
        bool ok = false;
        char changed_c[4096], same_c[4096];
        ASSERT(snprintf(changed_c, sizeof(changed_c), "%s/src/changed.c",
                        gen_src) > 0);
        ASSERT(snprintf(same_c, sizeof(same_c), "%s/src/same.c",
                        gen_src) > 0);
        long long seed_ns = pw_mtime_ns(gen_a_o, &ok);
        ASSERT(ok);
        long long changed_ns = pw_mtime_ns(changed_c, &ok);
        ASSERT(ok);
        long long same_ns = pw_mtime_ns(same_c, &ok);
        ASSERT(ok);
        ASSERT(changed_ns > seed_ns);
        ASSERT(seed_ns > same_ns);
        /* Publisher semantics: rebuild through staging plus rename. The
         * donor keeps its bytes and its inode; the new object diverges. */
        ASSERT(ic_write(root, "gen/build/obj/epochs/E/mod/a.o.new",
                        "OBJECT-A-V2"));
        char gen_a_new[4096];
        ASSERT(snprintf(gen_a_new, sizeof(gen_a_new),
                        "%s/obj/epochs/E/mod/a.o.new", gen) > 0);
        ASSERT(rename(gen_a_new, gen_a_o) == 0);
        ASSERT(pw_read_all(donor_a_o, buf, sizeof(buf), NULL));
        ASSERT(strcmp(buf, "OBJECT-A-V1") == 0);
        ASSERT(pw_stat_ino(donor_a_o, &donor_a_ino));
        ASSERT(pw_stat_ino(gen_a_o, &gen_a_ino));
        ASSERT(gen_a_ino != donor_a_ino);
        ASSERT(pw_read_all(gen_a_o, buf, sizeof(buf), NULL));
        ASSERT(strcmp(buf, "OBJECT-A-V2") == 0);
        /* Copy semantics: rewrite the new wrapper in place. The donor
         * keeps its bytes on its own inode. */
        FILE *rewrite = fopen(gen_zcc, "r+b");
        ASSERT(rewrite != NULL);
        ASSERT(fwrite("MUTATED!!!", 1, strlen("MUTATED!!!"), rewrite) ==
               strlen("MUTATED!!!"));
        ASSERT(fclose(rewrite) == 0);
        ASSERT(pw_read_all(donor_zcc, buf, sizeof(buf), NULL));
        ASSERT(strcmp(buf, "WRAPPER-V1") == 0);
        ASSERT(pw_stat_ino(donor_zcc, &donor_zcc_ino));
        ASSERT(pw_stat_ino(gen_zcc, &gen_zcc_ino));
        ASSERT(gen_zcc_ino != donor_zcc_ino);
        ASSERT(test_rm_rf_recursive(root) == 0);
#endif
        PASS();
    } _test_next:;
    return failures;
}

static int test_pw_seed_cold_without_seedables(void)
{
    int failures = 0;
    TEST("proof warm start: seed refuses empty donors") {
#if defined(_WIN32)
        ASSERT(true);
#else
        char root[4096], donor[4096], gen[4096], gen_src[4096];
        test_make_tmpdir(root, sizeof(root), "proof_warm", "cold");
        ASSERT(snprintf(donor, sizeof(donor), "%s/donor/build", root) > 0);
        ASSERT(snprintf(gen, sizeof(gen), "%s/gen/build", root) > 0);
        ASSERT(snprintf(gen_src, sizeof(gen_src), "%s/gen", root) > 0);
        ASSERT(ic_write(root, "donor/build/obj/epochs/E/tool", "BINARY"));
        ASSERT(ic_write(root, "gen/src/same.c", "int same(void){return 0;}\n"));
        struct zcl_dev_proof_warm_stats stats = {0};
        ASSERT(!zcl_dev_proof_warm_seed_and_retime(donor, gen, gen_src,
                                                   NULL, 0, &stats));
        ASSERT(stats.files_linked == 0);
        char probe[4096];
        ASSERT(snprintf(probe, sizeof(probe), "%s/obj/epochs/E/tool",
                        gen) > 0);
        ASSERT(access(probe, F_OK) != 0);
        ASSERT(!zcl_dev_proof_warm_seed_and_retime(NULL, gen, gen_src, NULL,
                                                   0, &stats));
        ASSERT(test_rm_rf_recursive(root) == 0);
#endif
        PASS();
    } _test_next:;
    return failures;
}

int test_impact_composition(void)
{
    int failures = 0;
    ic_isolate_state_root();
    failures += test_ic_truncated_closure_preserves_groups();
    failures += test_ic_closure_capacity_follows_corpus();
    failures += test_ic_large_plan_preserves_groups();
    failures += test_ic_command_latency_scope_is_precise();
    failures += test_ic_registry_def_has_dependents();
    failures += test_ic_macro_only_header_has_dependents();
    failures += test_ic_incomplete_dimension_refuses_proof();
    failures += test_ic_capacity_bound_runs_everything();
    failures += test_ic_every_selection_has_a_reason();
    failures += test_ic_union_never_loses_a_rule_group();
    failures += test_ic_dimension_applicability_and_exact_execution();
    failures += test_ic_snapshot_overlays_current_symbols();
    failures += test_ic_code_capsule_stays_with_code_owner();
    failures += test_ic_generated_inventory_stays_focused();
    failures += test_ic_dev_proof_contract_is_direct();
    failures += test_ic_lint_helpers_exclude_onion_stress();
    failures += test_ic_dev_proof_receipt_admission();
    failures += test_ic_dev_proof_child_action_identity();
    failures += test_ic_resident_proof_queue();
    failures += test_ic_proof_wait_reports_settled_failure();
    failures += test_ic_cycle_reuse_requires_exact_proof_inputs();
    failures += test_ic_native_compositor_selects_physical_proof();
    failures += test_pw_tag_names_pool_entries();
    failures += test_pw_classify_link_copy_skip();
    failures += test_pw_pick_newest_complete_idle();
    failures += test_pw_marker_round_trip_and_refusals();
    failures += test_pw_marker_identity_invalidates_stale_donor();
    failures += test_pw_identity_survives_a_second_checkout_path();
    failures += test_pw_identity_keeps_its_four_roots_apart();
    failures += test_pw_receipt_refuses_an_older_root_policy();
    failures += test_pw_status_line_reports_warm_or_typed_cold();
    failures += test_pw_seed_links_replaces_and_copies();
    failures += test_pw_seed_cold_without_seedables();
    failures += test_pw_disable_switch_forces_cold();
    failures += test_ic_fast_sync_splits_keep_proof_lane();
    failures += test_ic_merkle_verifier_selects_proof_lane();
    failures += test_ic_proof_budget_grows_with_groups();
    failures += test_ic_proof_budget_learns_from_this_checkout();
    failures += test_ic_proof_ceiling_env_raises_only();
    failures += test_ic_proof_verdict_watches_progress_not_the_clock();
    failures += test_ic_proof_reads_the_harness_banners();
#if !defined(_WIN32)
    failures += test_ic_proof_run_watched_kills_only_the_silent();
    failures += test_ic_proof_steps_run_concurrently();
#endif
    failures += test_ic_proof_generation_prefers_ram_when_it_fits();
#if !defined(_WIN32)
    failures += test_ic_proof_dependency_crosses_filesystems();
    failures += test_ic_ram_scratch_reservations_hold_under_concurrency();
#endif
    failures += test_ic_changed_set_carries_a_landing_batch();
    failures += test_ic_changed_set_refuses_above_its_ceiling();
    failures += test_ic_watch_overlay_keeps_its_own_ceiling();
    return failures;
}
