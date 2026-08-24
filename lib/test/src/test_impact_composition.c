/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_impact_composition — adversarial proof that the two impact-planning
 * systems COMPOSE honestly.
 *
 * The two systems both stay. Neither is a cache of the other:
 *   A = app/controllers/include/controllers/agent_impact_rules.def, hand-
 *       authored judgement mapping a changed PATH to TEST GROUP NAMES. Not
 *       derivable from any graph; ~40% of the file is the rationale.
 *   B = lib/codeindex/, a scanned call graph plus the compiler's own depfiles,
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

#include "test/test_core.h"

#include "codeindex/codeindex.h"
#include "config/command_catalog.h"
#include "controllers/agent_impact_rules.h"
#include "devloop.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "test/testcache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

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
    return ic_write(root, "lib/net/src/tor_integration.c",
                    "/* tor fixture */\n"
                    "#include \"net/clp.h\"\n"
                    "int tor_leaf(int x) { return x + 1; }\n") &&
           ic_write(root, "lib/net/src/download.c",
                    "/* download fixture */\n"
                    "#include \"net/clp.h\"\n"
                    "int dl_top(int x) { return tor_leaf(x) * 2; }\n") &&
           ic_write(root, "lib/net/include/net/clp.h",
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
                    "lib/net/src/tor_integration.c "
                    "lib/net/include/net/clp.h\n") &&
           ic_write(root, "build/obj/download.d",
                    "build/obj/download.o: lib/net/src/download.c "
                    "lib/net/include/net/clp.h\n");
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
    bool ok = ic_write(root, "lib/net/src/zbigfanout.c", body);
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

        const char *files[] = { "lib/net/src/tor_integration.c" };
        struct zcl_devloop_plan plan;
        ASSERT(zcl_devloop_plan_files(files, 1, &plan));
        ASSERT(ic_group_in(plan.path_groups, plan.path_groups_len,
                           "test_tor"));

        ASSERT(zcl_devloop_plan_add_closure(IC_FIX_TRUNC, files, 1, &plan));
        ASSERT(plan.closure_attempted);

        /* The bound really fired — otherwise this whole case proves nothing. */
        ASSERT(plan.dims[ZCL_DEVLOOP_DIM_SEMANTIC].status ==
               ZCL_DEVLOOP_DIM_INCOMPLETE);
        ASSERT(strcmp(plan.dims[ZCL_DEVLOOP_DIM_SEMANTIC].reason,
                      "closure-truncated") == 0);
        ASSERT(plan.closure_truncated);

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

/* The second discard site: the plan's own group array filling up. Enough
 * distinct impacted files to exceed ZCL_DEVLOOP_MAX_PLAN_GROUPS; the old code
 * reset closure_groups_len to 0 on the way out of the loop. */
static const char *const ic_many_group_files[] = {
    "lib/test/src/test_simnet_wire_ibd.c",
    "lib/test/src/test_importblockindex_roundtrip.c",
    "lib/test/src/test_validate_script_hash_split_repair.c",
    "lib/test/src/test_subsystem_snapshot.c",
    "lib/test/src/test_stage_crash_sweep.c",
    "lib/test/src/test_stage_anchor_frontier_cap.c",
    "lib/test/src/test_sqlite.c",
    "lib/test/src/test_simnet_wallet_reorg.c",
    "lib/test/src/test_simnet_value_inflation.c",
    "lib/test/src/test_simnet_mempool_adv.c",
    "lib/test/src/test_simnet_input_value_range.c",
    "lib/test/src/test_simnet_fee_range.c",
    "lib/test/src/test_simnet_empty_vin_vout.c",
    "lib/test/src/test_simnet_duplicate_input.c",
    "lib/test/src/test_simnet_doublespend.c",
    "lib/test/src/test_simnet_cluster_reorg.c",
    "lib/test/src/test_simnet_cluster.c",
    "lib/test/src/test_simnet_chained_tx.c",
    "lib/test/src/test_simnet_block_sigops.c",
    "lib/test/src/test_self_folded_anchor.c",
    "lib/test/src/test_rom_manifest.c",
    "lib/test/src/test_simnet_fuzz.c",
    "lib/test/src/test_command_handler_snapshot.c",
    "lib/test/src/test_pow_diffadj_precedence.c",
};

static int test_ic_group_cap_preserves_groups(void)
{
    int failures = 0;
    TEST("impact composition: a FULL plan group set keeps its groups too") {
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

        const char *files[] = { "lib/net/src/tor_integration.c" };
        struct zcl_devloop_plan plan;
        ASSERT(zcl_devloop_plan_files(files, 1, &plan));
        ASSERT(zcl_devloop_plan_add_closure(IC_FIX_GROUP, files, 1, &plan));

        /* The array really filled. */
        ASSERT(plan.closure_groups_len == ZCL_DEVLOOP_MAX_PLAN_GROUPS);
        ASSERT(plan.dims[ZCL_DEVLOOP_DIM_SEMANTIC].status ==
               ZCL_DEVLOOP_DIM_INCOMPLETE);
        /* Kept, not discarded. */
        ASSERT(ic_planned(&plan, "download"));

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

        system("rm -rf " IC_FIX_GROUP);
        PASS();
    } _test_next:;
    return failures;
}

static int test_ic_command_latency_scope_is_precise(void)
{
    int failures = 0;
    TEST("impact composition: command latency follows only latency owners") {
        const char *code_files[] = { "lib/codeindex/src/codeindex.c" };
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
                        "app/controllers/include/controllers/ic_rows.def",
                        "/* registry fixture */\n"
                        "IC_ROW(alpha, 1)\n"
                        "IC_ROW(beta, 2)\n"));
        /* The compiler read the registry while building download.c. */
        ASSERT(ic_write(IC_FIX_DEF, "build/obj/tor_integration.d",
                        "build/obj/tor_integration.o: "
                        "lib/net/src/tor_integration.c "
                        "lib/net/include/net/clp.h\n"));
        ASSERT(ic_write(IC_FIX_DEF, "build/obj/download.d",
                        "build/obj/download.o: lib/net/src/download.c "
                        "lib/net/include/net/clp.h "
                        "app/controllers/include/controllers/ic_rows.def\n"));

        struct codeindex *ci = codeindex_open(IC_FIX_DEF);
        ASSERT(ci != NULL);

        /* The call graph has nothing to say — a registry defines no callable
         * symbol, so its reverse-caller closure is exactly itself. That is a
         * correct answer to the wrong question, and used to be the ONLY
         * question asked. */
        char changed[1][256];
        (void)snprintf(changed[0], sizeof(changed[0]),
                       "app/controllers/include/controllers/ic_rows.def");
        static char impacted[64][256];
        bool trunc = false;
        int nc = codeindex_impact_closure(ci, changed, 1, 0, impacted, 64,
                                          &trunc);
        ASSERT(nc == 1);

        /* The include dimension answers it. */
        static char deps[64][256];
        enum codeindex_include_dim dim = CODEINDEX_INCLUDE_DIM_UNAVAILABLE;
        int nd = codeindex_reverse_includes(
            ci, "app/controllers/include/controllers/ic_rows.def", deps, 64,
            &dim);
        ASSERT(nd == 1);
        ASSERT(dim == CODEINDEX_INCLUDE_DIM_COMPLETE);
        ASSERT(strcmp(deps[0], "lib/net/src/download.c") == 0);
        codeindex_close(ci);

        /* And the composed plan selects download.c's group, through the
         * INCLUDE dimension, naming the file it came through. */
        const char *files[] = {
            "app/controllers/include/controllers/ic_rows.def"
        };
        struct zcl_devloop_plan plan;
        ASSERT(zcl_devloop_plan_files(files, 1, &plan));
        ASSERT(zcl_devloop_plan_add_closure(IC_FIX_DEF, files, 1, &plan));
        ASSERT(ic_planned(&plan, "download"));
        const struct zcl_devloop_selection *sel = ic_selection(&plan,
                                                               "download");
        ASSERT(sel != NULL);
        ASSERT(sel->dim == ZCL_DEVLOOP_DIM_INCLUDE);
        ASSERT(strcmp(sel->via, "lib/net/src/download.c") == 0);

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
        ASSERT(ic_write(IC_FIX_MACRO, "lib/net/include/net/ic_macros.h",
                        "#ifndef NET_IC_MACROS_H\n#define NET_IC_MACROS_H\n"
                        "#define IC_WINDOW 4096\n"
                        "#define IC_DOUBLE(x) ((x) * 2)\n"
                        "#endif\n"));
        ASSERT(ic_write(IC_FIX_MACRO, "build/obj/tor_integration.d",
                        "build/obj/tor_integration.o: "
                        "lib/net/src/tor_integration.c "
                        "lib/net/include/net/clp.h\n"));
        ASSERT(ic_write(IC_FIX_MACRO, "build/obj/download.d",
                        "build/obj/download.o: lib/net/src/download.c "
                        "lib/net/include/net/clp.h "
                        "lib/net/include/net/ic_macros.h\n"));

        struct codeindex *ci = codeindex_open(IC_FIX_MACRO);
        ASSERT(ci != NULL);

        char changed[1][256];
        (void)snprintf(changed[0], sizeof(changed[0]),
                       "lib/net/include/net/ic_macros.h");
        static char impacted[64][256];
        bool trunc = false;
        int nc = codeindex_impact_closure(ci, changed, 1, 0, impacted, 64,
                                          &trunc);
        ASSERT(nc == 1);  /* call graph: the file and nothing else */

        static char deps[64][256];
        enum codeindex_include_dim dim = CODEINDEX_INCLUDE_DIM_UNAVAILABLE;
        int nd = codeindex_reverse_includes(ci,
                                            "lib/net/include/net/ic_macros.h",
                                            deps, 64, &dim);
        ASSERT(nd == 1);
        ASSERT(dim == CODEINDEX_INCLUDE_DIM_COMPLETE);
        ASSERT(strcmp(deps[0], "lib/net/src/download.c") == 0);
        codeindex_close(ci);

        const char *files[] = { "lib/net/include/net/ic_macros.h" };
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
        const char *files[] = { "lib/net/src/tor_integration.c" };
        struct zcl_devloop_plan good;
        ASSERT(zcl_devloop_plan_files(files, 1, &good));
        ASSERT(zcl_devloop_plan_add_closure(IC_FIX_MACRO, files, 1, &good));
        const char *why = "unset";
        ASSERT(zcl_devloop_plan_proof_admissible(&good, &why));
        ASSERT(strcmp(why, "") == 0);

        /* (b) a truncated closure: the tests still RUN (T1), but the plan is
         * no longer evidence that the change is covered. */
        system("rm -rf " IC_FIX_TRUNC);
        ASSERT(ic_write_call_pair(IC_FIX_TRUNC));
        ASSERT(ic_write_depfiles(IC_FIX_TRUNC));
        ASSERT(ic_write_fanout_caller(IC_FIX_TRUNC));
        struct zcl_devloop_plan cut;
        ASSERT(zcl_devloop_plan_files(files, 1, &cut));
        ASSERT(zcl_devloop_plan_add_closure(IC_FIX_TRUNC, files, 1, &cut));
        why = "unset";
        ASSERT(!zcl_devloop_plan_proof_admissible(&cut, &why));
        ASSERT(strcmp(why, "closure-truncated") == 0);
        /* Refusing did NOT cost the evidence. */
        ASSERT(ic_planned(&cut, "download"));

        /* (c) ONE standard, not two. The result cache already refuses to admit
         * a truncated closure; the plan must describe that same incompleteness
         * with the same word. They cannot share a symbol — testcache is a
         * test-binary-only module and is never linked into the node — so the
         * shared thing is the vocabulary, pinned here. */
        ASSERT(strcmp(why, testcache_reason_label(TESTCACHE_R_TRUNCATED)) == 0);

        /* (d) no depfiles at all: the include dimension was never answerable,
         * which is a different fact from "nothing depends on this". Same
         * refusal, and again the same word the result cache uses. */
        system("rm -rf " IC_FIX_NODEPS);
        ASSERT(ic_write_call_pair(IC_FIX_NODEPS));
        const char *header_files[] = { "lib/net/include/net/net.h" };
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
        size_t n = zcl_devloop_plan_json_closure(IC_FIX_TRUNC, files, 1, body,
                                                 sizeof(body));
        ASSERT(n > 0 && n < sizeof(body));
        ASSERT(strstr(body, "\"proof_admissible\":false") != NULL);
        ASSERT(strstr(body, "\"proof_refusal\":\"closure-truncated\"") != NULL);
        ASSERT(strstr(body, "\"live_eligible\":false") != NULL);
        ASSERT(strstr(body,
                      "\"why_not_live\":\"state_or_abi_contract_requires_process_reload\"")
               != NULL);
        ASSERT(strstr(body,
                      "\"why_not_live_path\":\"lib/net/src/tor_integration.c\"")
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

/* ── T5: every selected group says why it is there ────────────────────── */

static int test_ic_every_selection_has_a_reason(void)
{
    int failures = 0;
    TEST("impact composition: every selected group names its dimension") {
        system("rm -rf " IC_FIX_DEF);
        ASSERT(ic_write_call_pair(IC_FIX_DEF));
        ASSERT(ic_write(IC_FIX_DEF,
                        "app/controllers/include/controllers/ic_rows.def",
                        "IC_ROW(alpha, 1)\n"));
        ASSERT(ic_write(IC_FIX_DEF, "build/obj/tor_integration.d",
                        "build/obj/tor_integration.o: "
                        "lib/net/src/tor_integration.c "
                        "lib/net/include/net/clp.h\n"));
        ASSERT(ic_write(IC_FIX_DEF, "build/obj/download.d",
                        "build/obj/download.o: lib/net/src/download.c "
                        "lib/net/include/net/clp.h "
                        "app/controllers/include/controllers/ic_rows.def\n"));

        /* One changed file per dimension in a single plan: a .c (semantic), a
         * registry (include), and a doc (opaque — no graph could find it). */
        const char *files[] = {
            "lib/net/src/tor_integration.c",
            "app/controllers/include/controllers/ic_rows.def",
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
    "lib/util/include/util/supervisor.h",
    "lib/util/src/supervisor.c",
    "lib/net/src/zmsg.c",
    "app/controllers/include/controllers/diagnostics_dumpers.def",
    "tools/lint/check_core_seal.sh",
    "docs/HANDOFF.md",
    "lib/sha3/src/sha3.c",
    "app/models/src/store.c",
    "lib/codeindex/src/codeindex_impact.c",
    "core/consensus/src/pow.c",
    "lib/base/include/base/hex.h",
    "app/services/src/op_return_backfill_service.c",
    "lib/net/src/tor_integration.c",
    "lib/net/src/download.c",
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
        const char *crypto[] = { "lib/sha3/src/sha3.c" };
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
            "lib/test/src/test_stage_repair_coin_backfill.c",
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
        ASSERT(strstr(body, "\"test_stage_repair\"") != NULL);
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
            "app/services/src/zcode_c23_corpus_service.c",
            "app/services/src/zcode_c23_economics_service.c",
        };
        for (size_t i = 0;
             i < sizeof(c23_services) / sizeof(c23_services[0]); i++) {
            const char *service_files[] = { c23_services[i] };
            struct zcl_devloop_plan service;
            ASSERT(zcl_devloop_plan_files(service_files, 1, &service));
            ASSERT(service.action == ZCL_DEVLOOP_HOTSWAP);
            ASSERT(ic_group_in(service.path_groups,
                               service.path_groups_len,
                               "zcode_commons_v2"));

            char service_body[ZCL_DEVLOOP_PLAN_WIRE_MAX + 1];
            size_t service_n = zcl_devloop_plan_json(
                service_files, 1, service_body, sizeof(service_body));
            ASSERT(service_n > 0);
            ASSERT(strstr(service_body, "\"live_eligible\":true") != NULL);
            ASSERT(strstr(service_body, "\"why_not_live\":\"\"") != NULL);
            ASSERT(strstr(service_body, "\"why_not_live_path\":\"\"")
                   != NULL);
        }

        struct agent_impact_acc executor = {0};
        (void)agent_impact_apply_shared_rules(
            "app/services/src/build_fabric_package_executor.c", &executor);
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
        ASSERT(ic_write(IC_FIX_SNAPSHOT, "lib/net/src/tor_integration.c",
                        "int old_unreferenced(void) { return 1; }\n"));
        ASSERT(ic_write(IC_FIX_SNAPSHOT, "lib/net/src/download.c",
                        "int future_leaf(void);\n"
                        "int download_future(void) { return future_leaf(); }\n"));
        ASSERT(ic_write_depfiles(IC_FIX_SNAPSHOT));

        const char *files[] = { "lib/net/src/tor_integration.c" };
        struct zcl_devloop_plan baseline;
        ASSERT(zcl_devloop_plan_files(files, 1, &baseline));
        ASSERT(zcl_devloop_plan_add_closure(
            IC_FIX_SNAPSHOT, files, 1, &baseline));
        ASSERT(!ic_planned(&baseline, "download"));

        ASSERT(ic_write(IC_FIX_SNAPSHOT, "lib/net/src/tor_integration.c",
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

static int test_ic_native_compositor_selects_physical_proof(void)
{
    int failures = 0;
    TEST("impact composition: every native compositor path selects UI proof") {
        static const char *const paths[] = {
            "app/views/src/ui_present_document.c",
            "app/views/include/views/ui_present_document.h",
            "app/views/src/ui_present_host.c",
            "app/views/include/views/ui_present_host.h",
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

int test_impact_composition(void)
{
    int failures = 0;
    failures += test_ic_truncated_closure_preserves_groups();
    failures += test_ic_group_cap_preserves_groups();
    failures += test_ic_command_latency_scope_is_precise();
    failures += test_ic_registry_def_has_dependents();
    failures += test_ic_macro_only_header_has_dependents();
    failures += test_ic_incomplete_dimension_refuses_proof();
    failures += test_ic_every_selection_has_a_reason();
    failures += test_ic_union_never_loses_a_rule_group();
    failures += test_ic_dimension_applicability_and_exact_execution();
    failures += test_ic_snapshot_overlays_current_symbols();
    failures += test_ic_code_capsule_stays_with_code_owner();
    failures += test_ic_native_compositor_selects_physical_proof();
    return failures;
}
