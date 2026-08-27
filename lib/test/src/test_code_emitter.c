/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * code.emitter contract — resolving text the node EMITTED back to the code
 * that formatted it.
 *
 * Every assertion here reads the SERIALIZED reply (json_write into a
 * budget-sized buffer), not the in-memory struct. A field present in
 * reply.data and dropped by the writer is a defect this project has shipped
 * before; asserting on the bytes the caller actually receives is the only way
 * to catch it.
 *
 * Coverage:
 *   1. glob rule            — the `blocker-id:` marker matcher, direct.
 *   2. dynamic blocker id   — `address_index.below_snapshot_seed` has no
 *                             literal anywhere (it is built by snprintf), so
 *                             only the declared marker can resolve it; it must
 *                             land on app/services/src/index_fold_guard.c and
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
 *                             ZCL_COMMAND_RESULT_BUDGET. */

#include "test/test_core.h"
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
        ASSERT(strstr(out, "app/services/src/index_fold_guard.c") != NULL);
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
        ASSERT(strstr(out, "app/jobs/src/reducer_frontier_dump.c") != NULL);
        /* the row's declared proof, verbatim from the .def */
        ASSERT(strstr(out, "lib/test/src/test_reducer_frontier.c") != NULL);
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
        /* Assembled at RUNTIME from chunks shorter than the format floors. A
         * literal spelling of this sentence in this very file would land the
         * scan on this test — the tree it scans includes lib/test/. The real
         * example is a libsqlite3 message ("attempt to write a readonly
         * database"), which is unresolvable because vendor/ is outside the
         * scan; here it is stitched so no in-tree literal can match it. */
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
        ASSERT(strstr(out, "app/services/src/index_fold_guard.c") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

int test_code_emitter(void)
{
    int failures = 0;
    failures += test_code_emitter_glob();
    failures += test_code_emitter_dynamic_blocker_id();
    failures += test_code_emitter_format_discrimination();
    failures += test_code_emitter_registry_pin();
    failures += test_code_emitter_honest_miss();
    failures += test_code_emitter_empty_input();
    failures += test_code_emitter_budget();
    return failures;
}
