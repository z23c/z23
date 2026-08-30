/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * code.corpus — honest distance to 100,000,000 lines of proven, tested,
 * non-duplicated C23.
 *
 * This handler renders and does not decide. Every number comes from
 * lib/science/science_corpus.c: the line half from a walk of the maintained
 * C23 roots, the proof half from the generated capability inventory, and a
 * `scope_agrees` flag saying whether those two halves were looking at the
 * same tree. The reasoning for each — and for why there is deliberately no
 * single "percent complete" — is in science/science_corpus.h.
 *
 * The one rule this file has to keep: the reply leads with what is NOT
 * proven. `headline` is the first field for that reason. A reader who stops
 * after one line must come away with the unflattering number, not the
 * flattering one.
 */

#include "native_command.h"

#include "json/json.h"
#include "kernel/command_registry.h"
#include "science/science_corpus.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Same resolution order as every other code.* leaf. */
static const char *corpus_source_root(const struct zcl_command_request *request)
{
    if (request && request->context && request->context->source_root &&
        request->context->source_root[0])
        return request->context->source_root;
    const char *env = getenv("ZCL_DEV_SOURCE_ROOT");
    return env && env[0] ? env : ".";
}

void zcl_native_handle_code_corpus(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    const char *root = corpus_source_root(request);
    char inventory[1024];
    const int n = snprintf(inventory, sizeof inventory,
                           "%s/docs/CAPABILITY_INVENTORY.jsonl", root);
    if (n <= 0 || (size_t)n >= sizeof inventory) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CORPUS_PATH",
                               "dispatch", true, false,
                               "source root path is too long", root);
        return;
    }

    struct science_corpus_report r;
    if (!science_corpus_measure(root, inventory, &r)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CORPUS_WALK",
                               "dispatch", true, false,
                               "could not walk the maintained C23 source roots",
                               root);
        return;
    }

    char headline[1024];
    if (science_corpus_headline(&r, headline, sizeof headline) == 0)
        (void)snprintf(headline, sizeof headline,
                       "corpus measured, but the headline did not fit");
    (void)json_push_kv_str(&reply->data, "headline", headline);

    /* What the tree holds, measured now. */
    (void)json_push_kv_int(&reply->data, "lines", (int64_t)r.lines);
    (void)json_push_kv_int(&reply->data, "files", (int64_t)r.files_walked);
    (void)json_push_kv_int(&reply->data, "bytes", (int64_t)r.bytes);
    (void)json_push_kv_int(&reply->data, "goal_lines",
                           (int64_t)SCIENCE_CORPUS_GOAL_LINES);
    (void)json_push_kv_int(&reply->data, "goal_permille",
                           science_corpus_goal_milli(&r));

    /* What is PROVEN, over a denominator that is named rather than implied. */
    struct json_value proof;
    json_init(&proof);
    json_set_object(&proof);
    (void)json_push_kv_bool(&proof, "measured", r.inventory_present);
    (void)json_push_kv_str(&proof, "denominator",
                           "public symbols in maintained C23 headers");
    /* The line-level fraction is the one a reader will assume was meant. It
     * is not measured anywhere in this tree, and guessing it — by crediting
     * every line of a file that holds one reached symbol, say — would be a
     * fabrication wearing a measurement's clothes. So it is named and refused. */
    (void)json_push_kv_str(&proof, "lines_proven",
                           "unmeasured: nothing in this tree attributes proof "
                           "at line granularity");
    (void)json_push_kv_int(&proof, "symbols_exposed",
                           (int64_t)r.symbols_exposed);
    (void)json_push_kv_int(&proof, "symbols_test_reached",
                           (int64_t)r.symbols_test_reached);
    (void)json_push_kv_int(&proof, "symbols_test_source_only_unproven",
                           (int64_t)r.symbols_test_source_only);
    (void)json_push_kv_int(&proof, "symbols_no_test_unproven",
                           (int64_t)r.symbols_no_test);
    (void)json_push_kv_int(&proof, "proven_permille",
                           science_corpus_proven_symbols_milli(&r));
    (void)json_push_kv(&reply->data, "proof", &proof);
    json_free(&proof);

    /* What counts AGAINST the goal: the same code twice, and contracts with
     * nothing asserting them. Both are corpus that has to be removed or
     * proven before it counts toward 100M. */
    struct json_value against;
    json_init(&against);
    json_set_object(&against);
    (void)json_push_kv_int(&against, "duplicate_candidates",
                           (int64_t)r.duplicates);
    (void)json_push_kv_int(&against, "untested_invariants",
                           (int64_t)r.untested_invariants);
    (void)json_push_kv_int(&against, "capabilities", (int64_t)r.capabilities);
    (void)json_push_kv(&reply->data, "counts_against", &against);
    json_free(&against);

    /* Whether the two halves were looking at the same tree. A reader must be
     * able to see that the proof figures are stale WITHOUT knowing that they
     * came from a different walk than the line count. */
    struct json_value scope;
    json_init(&scope);
    json_set_object(&scope);
    (void)json_push_kv_bool(&scope, "agrees", r.scope_agrees);
    (void)json_push_kv_int(&scope, "files_walked_now", (int64_t)r.files_walked);
    (void)json_push_kv_int(&scope, "files_inventory_scanned",
                           (int64_t)r.inventory_files_scanned);
    (void)json_push_kv_int(&scope, "inventory_production_files",
                           (int64_t)r.inventory_production_files);
    (void)json_push_kv_int(&scope, "inventory_test_files",
                           (int64_t)r.inventory_test_files);
    (void)json_push_kv_str(&scope, "roots",
                           "lib app core config tools domain adapters ports "
                           "src packages examples");
    (void)json_push_kv_str(&scope, "excluded",
                           "vendor, build output, fixtures, scratch trees, and "
                           "top-level directories the capability inventory does "
                           "not scan");
    (void)json_push_kv_str(
        &scope, "remedy",
        r.scope_agrees ? ""
                       : "run `make docs-capability-inventory`; until then the "
                         "proof figures describe an older tree");
    (void)json_push_kv(&reply->data, "scope", &scope);
    json_free(&scope);
}
