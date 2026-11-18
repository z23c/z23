/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * code.emitter contract — resolving text the node EMITTED back to the code
 * that formatted it.
 *
 * Command assertions read the SERIALIZED reply (json_write into a budget-sized
 * buffer): a field dropped by the writer must be caught. Isolated source
 * fixtures exercise segment evidence through the public emitter scan.
 *
 * Coverage:
 *   1. glob rule            — the `blocker-id:` marker matcher, direct.
 *   2. dynamic blocker id   — `address_index.below_snapshot_seed` has no
 *                             literal anywhere (it is built by snprintf), so
 *                             only the declared marker can resolve it; it must
 *                             land on engine/services/src/index_fold_guard.c and
 *                             carry the blocker_remedy_bindings.def row.
 *   3. format discrimination— two near-identical format strings differ by one
 *                             character ("rebuild: fail-closed" vs "rebuild
 *                             fail-closed"); the emitted text must select the
 *                             one that produced it and reject the other.
 *   4. registry pin         — a bare dumper subsystem name occurs in hundreds
 *                             of literals, so diagnostics_dumpers.def's
 *                             owner_file decides, and the reply says so.
 *   5. honest miss          — text no in-tree literal accounts for reports
 *                             resolved=false WITH which joins missed and a
 *                             next step, never a bare empty result.
 *   6. budget               — the serialized reply fits
 *                             ZCL_COMMAND_RESULT_BUDGET.
 *   7. dense literals       — isolated source-view queries retain a late site
 *                             and preserve concatenation boundaries.
 *   8. source byte admission — embedded NUL refuses the entire file; a final
 *                             line without a newline remains admitted. */

#include "test/test_core.h"
#include "base/safe_alloc.h"
#include "codeindex/codeindex.h"
#include "codeindex/codeindex_emitter.h"
#include "command/native_command.h"
#include "kernel/command_registry.h"
#include "json/json.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Run code.emitter for `text` and serialize reply.data into `buf`. Returns the
 * serialized length. */
static size_t emit_run(const char *text, char *buf, size_t cap)
{
    struct json_value input;
    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&input, "text", text);
    struct zcl_command_request request = {
        .input = &input, .view = "normal", .invoked_name = "code.provenance.emitter",
    };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.code_emitter.v1");
    zcl_native_handle_code_emitter(&request, &reply);
    size_t n = json_write(&reply.data, buf, cap);
    zcl_command_reply_free(&reply);
    json_free(&input);
    return n;
}

/* ── 1: the marker glob rule ─────────────────────────────────────────────── */
static int test_code_emitter_glob(void)
{
    int failures = 0;
    TEST("code_emitter: blocker-id glob matches the dynamic-id families") {
        ASSERT(codeindex_emit_glob_match("*.below_snapshot_seed",
                                         "address_index.below_snapshot_seed"));
        ASSERT(codeindex_emit_glob_match("catalog.*.lag_exceeded",
                                         "catalog.op_return_index.lag_exceeded"));
        ASSERT(codeindex_emit_glob_match("worker.stall.*",
                                         "worker.stall.op.projection_backfill"));
        ASSERT(codeindex_emit_glob_match("stage_spin_*", "stage_spin_utxo_apply"));
        /* and does NOT over-match */
        ASSERT(!codeindex_emit_glob_match("catalog.*.lag_exceeded",
                                          "catalog.op_return_index.lag"));
        ASSERT(!codeindex_emit_glob_match("*.below_snapshot_seed",
                                          "address_index.below_snapshot_see"));
        ASSERT(!codeindex_emit_glob_match("worker.stall.*", "worker.stal"));
        PASS();
    } _test_next:;
    return failures;
}

/* ── 2: a dynamic blocker id resolves through its declared marker ───────── */
static int test_code_emitter_dynamic_blocker_id(void)
{
    int failures = 0;
    TEST("code_emitter: address_index.below_snapshot_seed resolves to "
         "index_fold_guard.c via its declared blocker-id marker, with the "
         "remedy row") {
        static char out[ZCL_COMMAND_RESULT_BUDGET * 2];
        size_t n = emit_run("address_index.below_snapshot_seed", out, sizeof(out));
        ASSERT(n > 0);
        ASSERT(strstr(out, "\"resolved\":true") != NULL);
        ASSERT(strstr(out, "engine/services/src/index_fold_guard.c") != NULL);
        ASSERT(strstr(out, "index_fold_note_absent_body") != NULL);
        ASSERT(strstr(out, "\"evidence_kind\":\"blocker_id_marker\"") != NULL);
        /* the blocker-remedy ratchet row, expanded into the handler */
        ASSERT(strstr(out, "*.below_snapshot_seed") != NULL);
        ASSERT(strstr(out, "OWNER") != NULL);
        /* the callers of the emitting function — the next hop out */
        ASSERT(strstr(out, "address_index_service.c") != NULL);
        /* the diagnostics_dumpers.def join, reached through the id's owner */
        ASSERT(strstr(out, "owner_component_of_id") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 3: one character apart, and it picks the right one ─────────────────── */
static int test_code_emitter_format_discrimination(void)
{
    int failures = 0;
    TEST("code_emitter: near-identical format strings are told apart by the "
         "emitted text (one character of difference)") {
        static char out[ZCL_COMMAND_RESULT_BUDGET * 2];

        /* The live blocker's reason: "…rebuild fail-closed reason=…" (no colon
         * after the subsystem). Only sync_controller_sapling_tree_resume.c
         * formats it that way. */
        size_t n = emit_run("sapling_tree_rebuild fail-closed "
                            "reason=intermediate_sapling_root_mismatch "
                            "height=3155873 commitments=1 mismatches=1",
                            out, sizeof(out));
        ASSERT(n > 0);
        ASSERT(strstr(out, "\"resolved\":true") != NULL);
        ASSERT(strstr(out, "sync_controller_sapling_tree_resume.c") != NULL);
        ASSERT(strstr(out, "sapling_tree_rebuild_raise_fail_blocker") != NULL);
        ASSERT(strstr(out, "\"evidence_kind\":\"format_string\"") != NULL);
        /* it names the snprintf as the call context, not a logger */
        ASSERT(strstr(out, "\"call_context\":\"snprintf\"") != NULL);

        /* The colon variant is a DIFFERENT site in a different file. Feeding
         * text produced by that one must not land on the file above. */
        n = emit_run("sapling_tree_rebuild: fail-closed "
                     "reason=intermediate_sapling_root_mismatch height=3155873 "
                     "commitments=1 mismatches=1",
                     out, sizeof(out));
        ASSERT(n > 0);
        const char *emitter = strstr(out, "\"emitter\"");
        ASSERT(emitter != NULL);
        const char *also = strstr(out, "\"also_emits\"");
        ASSERT(also != NULL && also > emitter);
        /* within the emitter object only, the resume file must be absent */
        size_t span = (size_t)(also - emitter);
        char head[1024];
        size_t copy = span < sizeof(head) - 1 ? span : sizeof(head) - 1;
        memcpy(head, emitter, copy);
        head[copy] = '\0';
        ASSERT(strstr(head, "sync_controller_sapling_tree_resume.c") == NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4: the registry outranks the text when the text is ambiguous ───────── */
static int test_code_emitter_registry_pin(void)
{
    int failures = 0;
    TEST("code_emitter: a bare dumper subsystem name resolves through the "
         "diagnostics_dumpers.def row's own function, not through text rank") {
        static char out[ZCL_COMMAND_RESULT_BUDGET * 2];
        size_t n = emit_run("reducer_frontier", out, sizeof(out));
        ASSERT(n > 0);
        ASSERT(strstr(out, "\"resolved\":true") != NULL);
        /* the .def row names the dump FUNCTION; the code index gives its exact
         * definition site. No text matching is involved in that answer. */
        ASSERT(strstr(out, "\"evidence_kind\":\"registry_row\"") != NULL);
        ASSERT(strstr(out, "\"selected_by\":\"diagnostics_dumpers_def_fn\"")
               != NULL);
        ASSERT(strstr(out, "reducer_frontier_dump_state_json") != NULL);
        ASSERT(strstr(out, "engine/reducer/jobs/src/reducer_frontier_dump.c") != NULL);
        /* the row's declared proof, verbatim from the .def */
        ASSERT(strstr(out, "tests/harness/src/test_reducer_frontier.c") != NULL);
        ASSERT(strstr(out, "exact_subsystem_name") != NULL);
        /* the text scan still ran and is still reported — it is context now,
         * not the answer. 395 sites mention this name; none of them decided. */
        ASSERT(strstr(out, "\"source_evidence\":\"literal_span\"") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 5: a miss names the miss ────────────────────────────────────────────── */
static int test_code_emitter_honest_miss(void)
{
    int failures = 0;
    TEST("code_emitter: unresolvable text reports which joins missed, what the "
         "scan covered, and a next step — never a bare empty result") {
        static char out[ZCL_COMMAND_RESULT_BUDGET * 2];
        /* Assembled at RUNTIME from short chunks: a literal spelling in this
         * file would land the scan on this test (the scanned tree includes
         * tests/harness/include/test/). The real example is a libsqlite3
         * message, unresolvable because vendor/ is outside the scan. */
        char absent[96];
        (void)snprintf(absent, sizeof(absent), "%s%s%s%s",
                       "attempt ", "to write ", "a readonly", " database");
        size_t n = emit_run(absent, out, sizeof(out));
        ASSERT(n > 0);
        ASSERT(strstr(out, "\"resolved\":false") != NULL);
        ASSERT(strstr(out, "\"next_step\":\"") != NULL);
        ASSERT(strstr(out, "\"source_evidence\":\"miss\"") != NULL);
        ASSERT(strstr(out, "\"diagnostics_dumpers_def\":\"miss\"") != NULL);
        ASSERT(strstr(out, "\"blocker_remedy_bindings_def\":\"miss\"") != NULL);
        /* the scan must PROVE it ran: a hollow scan reporting a clean miss is
         * the failure this field exists to make impossible. */
        const char *fs = strstr(out, "\"files_scanned\":");
        ASSERT(fs != NULL);
        long scanned = strtol(fs + strlen("\"files_scanned\":"), NULL, 10);
        ASSERT(scanned > 1000);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 5b: an empty input is a typed refusal with an error body ───────────── */
static int test_code_emitter_empty_input(void)
{
    int failures = 0;
    TEST("code_emitter: empty text is a typed failure carrying an error body, "
         "not a silent empty reply") {
        struct json_value input;
        json_init(&input); json_set_object(&input);
        (void)json_push_kv_str(&input, "text", "");
        struct zcl_command_request request = {
            .input = &input, .view = "normal", .invoked_name = "code.provenance.emitter",
        };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.code_emitter.v1");
        zcl_native_handle_code_emitter(&request, &reply);

        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(reply.error.code, "MISSING_TEXT");
        ASSERT(reply.error.message[0] != '\0');

        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 6: the reply fits the kernel's result budget ────────────────────────── */
static int test_code_emitter_budget(void)
{
    int failures = 0;
    TEST("code_emitter: the serialized reply fits ZCL_COMMAND_RESULT_BUDGET") {
        static char out[ZCL_COMMAND_RESULT_BUDGET * 4];
        /* The longest realistic input: the full reason
         * index_fold_note_absent_body() (index_fold_guard.c) formats for its
         * longest real caller id, op_return_index (op_return_backfill_service.c),
         * at a below-seed-floor absent body. */
        size_t n = emit_run(
            "op_return_index missing body at height 0, seed floor=3195247; "
            "backfill pre-seed bodies or accept partial coverage "
            "(-op_return_index=0); see operator_decision in dumpstate blocker",
            out, sizeof(out));
        ASSERT(n > 0);
        ASSERT(n <= ZCL_COMMAND_RESULT_BUDGET);
        ASSERT(strstr(out, "engine/services/src/index_fold_guard.c") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static bool emitter_pad_file(FILE *f)
{
    long used = ftell(f);
    if (used < 0) return false;
    for (size_t i = (size_t)used; i < (1u << 21); i++)
        if (fputc(' ', f) == EOF) return false;
    return true;
}

static bool emitter_write_runs(const char *path, size_t empty_runs, bool large)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = fputs("void f(void){", f) >= 0;
    for (size_t i = 0; i < empty_runs; i++)
        ok = fputs("\"\";", f) >= 0 && ok;
    ok = fputs("puts(\"unique-message\");}\n", f) >= 0 && ok;
    if (large) ok = emitter_pad_file(f) && ok;
    return fclose(f) == 0 && ok;
}

static bool emitter_final_site(struct codeindex *ci)
{
    struct ci_emit_site site;
    struct ci_emit_scan_report report;
    int hits = codeindex_emitter_sites(ci, "unique-message", NULL, &site, 1, &report);
    return hits == 1 && report.files_scanned == 1 &&
           report.files_unreadable == 0 && !report.enumeration_incomplete &&
           report.literal_runs == 1 && site.kind == CI_EMIT_LITERAL_EXACT &&
           site.line == 1 && strcmp(site.path, "cognition/dense.c") == 0;
}

static bool emitter_dense_fixture(char *root, size_t root_cap,
                                  char *path, size_t path_cap)
{
    char dir[PATH_MAX];
    if (!test_mkdtemp(root, root_cap, "emitter")) {
        root[0] = '\0';
        return false;
    }
    int n = snprintf(dir, sizeof(dir), "%s/cognition", root);
    if (n <= 0 || (size_t)n >= sizeof(dir)) return false;
    if (mkdir(dir, 0700) != 0) return false;
    n = snprintf(path, path_cap, "%s/dense.c", dir);
    if (n <= 0 || (size_t)n >= path_cap) return false;
    return emitter_write_runs(path, 0, false);
}

static bool emitter_check_dense_runs(struct codeindex *ci, const char *path)
{
    /* Small controls, then densities that exceed the old bytes/8 + 16 table.
     * The last fixture is exactly the largest admitted file size. */
    static const size_t counts[] = {0, 17, 200, 699000};
    bool ok = true;
    for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
        if (!emitter_write_runs(path, counts[i], i == 3)) return false;
        ok = emitter_final_site(ci) && ok;
    }
    return ok;
}

static bool emitter_check_joined_runs(struct codeindex *ci, const char *path)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool wrote = fputs("void f(void){puts(\"adjacent-\" /* gap */ \"message\");"
                       "puts(\"separate-\");puts(\"message\");}\n", f) >= 0;
    wrote = fclose(f) == 0 && wrote;
    if (!wrote) return false;
    struct ci_emit_site site;
    struct ci_emit_scan_report report;
    int joined = codeindex_emitter_sites(ci, "adjacent-message", NULL,
                                         &site, 1, &report);
    int separate = codeindex_emitter_sites(ci, "separate-message", NULL,
                                           &site, 1, NULL);
    return joined == 1 && separate == 0 && report.literal_runs == 3;
}

static int test_code_emitter_dense_runs(void)
{
    int failures = 0;
    TEST("code_emitter: dense literals retain the final unique-message site") {
        char root[PATH_MAX], path[PATH_MAX];
        bool setup = emitter_dense_fixture(root, sizeof(root), path, sizeof(path));
        struct codeindex *ci = setup ? codeindex_open_source_view(root) : NULL;
        bool opened = ci != NULL;
        bool dense = ci && emitter_check_dense_runs(ci, path);
        bool joined = ci && emitter_check_joined_runs(ci, path);
        codeindex_close(ci);
        int cleanup = test_rm_rf_recursive(root);
        ASSERT(setup && opened);
        ASSERT(dense);
        ASSERT(joined);
        ASSERT_EQ(cleanup, 0);
        PASS();
    } _test_next:;
    return failures;
}

static bool emitter_write_bytes(const char *path, const char *bytes, size_t size)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool wrote = fwrite(bytes, 1, size, f) == size;
    return fclose(f) == 0 && wrote;
}

static bool emitter_refused_source(struct codeindex *ci)
{
    struct ci_emit_site site;
    struct ci_emit_scan_report report;
    int hits = codeindex_emitter_sites(ci, "unique-message", NULL, &site, 1, &report);
    return hits == 0 && report.files_scanned == 0 &&
           report.files_unreadable == 1 && report.literal_runs == 0 &&
           report.candidates == 0 && !report.enumeration_incomplete;
}

static bool emitter_check_source_bytes(struct codeindex *ci, const char *path)
{
    static const char no_newline[] = "void f(void){puts(\"unique-message\");}";
    static const char nul_inside[] = "void f(void){puts(\"unique-message\0suffix\");}";
    static const char nul_after[] = "void f(void){puts(\"unique-message\");}\0suffix";
    if (!emitter_write_bytes(path, no_newline, sizeof(no_newline) - 1)) return false;
    bool admitted = emitter_final_site(ci);
    if (!emitter_write_bytes(path, nul_inside, sizeof(nul_inside) - 1)) return false;
    bool inside = emitter_refused_source(ci);
    if (!emitter_write_bytes(path, nul_after, sizeof(nul_after) - 1)) return false;
    bool after = emitter_refused_source(ci);
    return admitted && inside && after;
}

static int test_code_emitter_source_bytes(void)
{
    int failures = 0;
    TEST("code_emitter: NUL-bearing sources refuse; final no-newline stays valid") {
        char root[PATH_MAX] = {0}, path[PATH_MAX];
        bool setup = emitter_dense_fixture(root, sizeof(root), path, sizeof(path));
        struct codeindex *ci = setup ? codeindex_open_source_view(root) : NULL;
        bool opened = ci != NULL;
        bool bytes = ci && emitter_check_source_bytes(ci, path);
        codeindex_close(ci);
        int cleanup = test_rm_rf_recursive(root);
        ASSERT(setup && opened);
        ASSERT(bytes);
        ASSERT_EQ(cleanup, 0);
        PASS();
    } _test_next:;
    return failures;
}

struct emitter_segment_case {
    size_t repeated;
    const char *tail, *query_tail;
    int sites, chars, longest;
};

static bool emitter_segment_source(const char *path,
                                    const struct emitter_segment_case *c,
                                    char query[1024])
{
    char source[1024];
    const char *head = "void f(void){puts(\"";
    size_t h = strlen(head), n = c->repeated;
    if (n > 511) return false;
    memcpy(source, head, h);
    memset(source + h, 'a', n);
    int end = snprintf(source + h + n, sizeof(source) - h - n,
                       "%s\");}\n", c->tail);
    if (end < 0 || (size_t)end >= sizeof(source) - h - n) return false;
    memset(query, 'a', n);
    end = snprintf(query + n, 1024 - n, "%s", c->query_tail);
    if (end < 0 || (size_t)end >= 1024 - n) return false;
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    size_t len = strlen(source), wrote = fwrite(source, 1, len, f);
    int closed = fclose(f);
    return wrote == len && closed == 0;
}

static int emitter_segment_check(struct codeindex *ci, const char *query,
                                 const struct emitter_segment_case *c)
{
    int failures = 0;
    TEST("code_emitter: segment bounds preserve exact matching evidence") {
        struct ci_emit_site site[2];
        struct ci_emit_scan_report report;
        int found = codeindex_emitter_sites(ci, query, NULL, site, 2, &report);
        ASSERT(found == c->sites);
        ASSERT(report.files_scanned == 1 && report.files_unreadable == 0);
        ASSERT(!report.enumeration_incomplete && report.literal_runs == 1);
        if (found > 0) {
            ASSERT(site[0].kind == CI_EMIT_FORMAT_MATCH);
            ASSERT(site[0].literal_chars == c->chars);
            ASSERT(site[0].longest_segment == c->longest);
            ASSERT_STR_EQ(site[0].path, "cognition/segment.c");
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_code_emitter_segment_bounds(void)
{
    int failures = 0;
    char root[512] = "", dir[640], path[768], query[1024];
    struct codeindex *ci = NULL;
    TEST("code_emitter: overflowing segments cannot supply shortened evidence") {
        ASSERT(test_mkdtemp(root, sizeof(root), "emitter_segment") != NULL);
        (void)snprintf(dir, sizeof(dir), "%s/cognition", root);
        ASSERT(mkdir(dir, 0700) == 0);
        (void)snprintf(path, sizeof(path), "%s/segment.c", dir);
        static const struct emitter_segment_case cases[] = {
            {511, "Z%d", "Y7", 0, 0, 0}, /* exact reported mismatch */
            {511, "%%%d", "Y7", 0, 0, 0}, /* escaped percent overflows */
            {511, "%d", "7", 1, 511, 511}, /* largest fitting segment */
            {511, "%d later-segment", "7 later-segment", 1, 525, 511},
            {511, "%d later-segment", "7 wrong-segment", 1, 511, 511},
            /* 24 a's + literal "% value=" = 32, then " done" = 5. */
            {24, "%% value=%d done", "% value=7 done", 1, 37, 32},
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            ASSERT(emitter_segment_source(path, &cases[i], query));
            if (!ci) ci = codeindex_open_source_view(root);
            ASSERT(ci != NULL);
            failures += emitter_segment_check(ci, query, &cases[i]);
        }
        PASS();
    } _test_next:;
    if (ci) codeindex_close(ci);
    if (root[0]) {
        (void)snprintf(dir, sizeof(dir), "%s/cognition", root);
        test_cleanup_tmpdir(dir);
        (void)snprintf(dir, sizeof(dir), "%s/.codeindex", root);
        test_cleanup_tmpdir(dir);
        test_cleanup_tmpdir(root);
    }
    return failures;
}

static int test_code_emitter_primary_label(void)
{
    int failures = 0;
    char root[4096] = {0}, path[4096];
    TEST("code_emitter: an established primary label avoids referrer scans") {
        ASSERT(test_mkdtemp(root, sizeof root, "emitter_route"));
        int n = snprintf(path, sizeof path, "%s/tools", root);
        ASSERT(n > 0);
        ASSERT((size_t)n < sizeof path);
        ASSERT(mkdir(path, 0755) == 0);
        n = snprintf(path, sizeof path, "%s/tools/command", root);
        ASSERT(n > 0);
        ASSERT((size_t)n < sizeof path);
        ASSERT(mkdir(path, 0755) == 0);
        n = snprintf(path, sizeof path, "%s/tools/command/native_code_" "emitter1109.c", root);
        ASSERT(n > 0 && (size_t)n < sizeof path);
        FILE *f = fopen(path, "wb");
        ASSERT(f);
        bool wrote = fputs("void beacon(void) { puts(\"emitter-label-1109\"); }\n", f) >= 0;
        ASSERT(fclose(f) == 0 && wrote);
        n = snprintf(path, sizeof path, "%s/tests", root);
        ASSERT(n > 0);
        ASSERT((size_t)n < sizeof path);
        ASSERT(mkdir(path, 0755) == 0);
        n = snprintf(path, sizeof path, "%s/tests/harness", root);
        ASSERT(n > 0);
        ASSERT((size_t)n < sizeof path);
        ASSERT(mkdir(path, 0755) == 0);
        n = snprintf(path, sizeof path, "%s/tests/harness/src", root);
        ASSERT(n > 0);
        ASSERT((size_t)n < sizeof path);
        ASSERT(mkdir(path, 0755) == 0);
        n = snprintf(path, sizeof path, "%s/tests/harness/src/test_dev_job.c", root);
        ASSERT(n > 0 && (size_t)n < sizeof path);
        f = fopen(path, "wb");
        ASSERT(f);
        wrote = fputs("const char *s = \"native_code_" "emitter1109\";\n", f) >= 0;
        ASSERT(fclose(f) == 0 && wrote);
        struct json_value input;
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "text", "emitter-label-1109"));
        struct zcl_command_context ctx = {.source_root = root};
        struct zcl_command_request req = {.input = &input, .context = &ctx};
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.code_emitter.v1");
        zcl_alloc_fault_fail_next("agent_impact_names");
        zcl_native_handle_code_emitter(&req, &reply);
        bool armed = zcl_alloc_fault_armed_label() != NULL;
        zcl_alloc_fault_clear();
        ASSERT(armed);
        ASSERT(json_get_bool(json_get(&reply.data, "resolved")));
        char output[8192];
        ASSERT(json_write(&reply.data, output, sizeof output) > 0);
        ASSERT(strstr(output, "make t-fast ONLY=make_lint_gates") != NULL);
        zcl_command_reply_free(&reply); json_free(&input);
        PASS();
    } _test_next:;
    zcl_alloc_fault_clear();
    if (root[0]) test_rm_rf_recursive(root);
    return failures;
}

int test_code_emitter(void)
{
    int failures = 0;
    failures += test_code_emitter_primary_label();
    failures += test_code_emitter_glob();
    failures += test_code_emitter_dynamic_blocker_id();
    failures += test_code_emitter_format_discrimination();
    failures += test_code_emitter_segment_bounds();
    failures += test_code_emitter_registry_pin();
    failures += test_code_emitter_honest_miss();
    failures += test_code_emitter_empty_input();
    failures += test_code_emitter_budget();
    failures += test_code_emitter_dense_runs();
    failures += test_code_emitter_source_bytes();
    return failures;
}
