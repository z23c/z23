/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Render the capability inventory report as the committed JSON Lines
 * artifact, and decide whether a committed artifact is byte-identical to what
 * the live report renders now.
 *
 * Freshness is computed here at check time and stored nowhere: the artifact is
 * current iff its bytes equal this renderer's output for the live analysis. */

#include "codeindex/codeindex_inventory_render.h"

#include "base/log_macros.h"

#include <stdio.h>
#include <string.h>

static void json_string(FILE *out, const char *text)
{
    fputc('"', out);
    if (text) for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        switch (*p) {
        case '"': fputs("\\\"", out); break;
        case '\\': fputs("\\\\", out); break;
        case '\b': fputs("\\b", out); break; // posix-ere-ok:json-backspace-escape
        case '\f': fputs("\\f", out); break;
        case '\n': fputs("\\n", out); break;
        case '\r': fputs("\\r", out); break;
        case '\t': fputs("\\t", out); break;
        default:
            if (*p < 0x20) fprintf(out, "\\u%04x", (unsigned int)*p);
            else fputc(*p, out);
        }
    }
    fputc('"', out);
}

/* A symbol defined more than once in one path (preprocessor arms) needs a
 * line-free distinguisher: emit its 1-based ordinal among those definitions
 * in ascending line order. Single definitions emit nothing. The ordinal moves
 * only when an arm is added, removed or reordered, never on a pure shift. */
static void render_arm_ordinal(FILE *out,
                               const struct ci_inventory_report *report,
                               const char *path, const char *symbol, int line)
{
    bool others = false;
    int before = 0;
    for (int i = 0; i < report->definition_arm_count; i++) {
        const struct ci_inventory_definition_arm *arm =
            &report->definition_arms[i];
        if (strcmp(arm->definition_path, path) != 0 ||
            strcmp(arm->symbol, symbol) != 0 || arm->definition_line == line)
            continue;
        others = true;
        if (arm->definition_line < line) before++;
    }
    if (others) fprintf(out, ",\"arm\":%d", before + 1);
}

static void render_symbol(FILE *out, const struct ci_inventory_symbol *symbol)
{
    fputs("{\"name\":", out); json_string(out, symbol->name);
    fprintf(out, ",\"kind\":\"%c\",\"definition\":{\"path\":", symbol->kind);
    json_string(out, symbol->definition_path);
    fputs("},\"definition_evidence\":", out);
    json_string(out, symbol->definition_evidence);
    fputs(",\"definition_proof_needed\":", out);
    if (strcmp(symbol->definition_evidence,
               "multiple_preprocessor_arms_UNPROVEN") == 0)
        json_string(out, "consume the generated arm baseline, preprocess every named arm, and bind each emitted definition separately");
    else if (strcmp(symbol->definition_evidence, "unresolved_UNPROVEN") == 0)
        json_string(out, "preprocess the exact build profile and bind this declaration to one emitted definition");
    else fputs("null", out);
    fputs(",\"declaration\":{\"path\":", out);
    json_string(out, symbol->declaration_path);
    fputs("},\"signature\":", out);
    json_string(out, symbol->signature);
    fputs(",\"header_contract\":", out); json_string(out, symbol->contract);
    fprintf(out, ",\"production_use_files\":%d,\"test_use_files\":%d,"
                 "\"test_evidence\":",
            symbol->production_use_files, symbol->test_use_files);
    json_string(out, codeindex_inventory_test_evidence_name(symbol->test_evidence));
    fputs(",\"registered_test_group\":", out);
    if (symbol->registered_test_group[0]) json_string(out, symbol->registered_test_group);
    else fputs("null", out);
    fputs(",\"test_proof_needed\":", out);
    if (symbol->test_evidence != CI_INVENTORY_TEST_REGISTERED_REACHABLE)
        json_string(out, "a canonical registered root with an unambiguous path-bound direct-call chain to this exact definition");
    else fputs("null", out);
    fprintf(out, ",\"multi_arm_definition\":%s,\"definition_arm_count\":%d,"
                 "\"constant_return_body\":%s,\"constant_return_value\":",
            symbol->multi_arm_definition ? "true" : "false",
            symbol->definition_arm_count,
            symbol->constant_return_body ? "true" : "false");
    if (symbol->constant_return_body) json_string(out, symbol->constant_return_value);
    else fputs("null", out);
    fputc('}', out);
}

static void render_capability(FILE *out, const struct ci_inventory_report *report,
                              const struct ci_inventory_capability *cap)
{
    fputs("{\"record\":\"capability\",\"header\":", out);
    json_string(out, cap->header);
    fputs(",\"include_token\":", out); json_string(out, cap->include_token);
    fputs(",\"group\":", out); json_string(out, cap->group);
    fputs(",\"declared_purpose\":", out);
    if (cap->purpose[0]) json_string(out, cap->purpose); else fputs("null", out);
    fprintf(out, ",\"purpose_evidence\":\"%s\",\"symbol_count\":%d,"
                 "\"function_count\":%d,\"type_count\":%d,"
                 "\"macro_count\":%d,\"production_use_files\":%d,"
                 "\"test_use_files\":%d,\"registered_test_symbols\":%d,"
                 "\"symbols\":[",
            cap->purpose[0] ? "header_comment_UNPROVEN" : "missing_UNPROVEN",
            cap->symbol_count, cap->function_count, cap->type_count,
            cap->macro_count, cap->production_use_files, cap->test_use_files,
            cap->registered_test_symbols);
    for (int i = 0; i < cap->symbol_count; i++) {
        if (i) fputc(',', out);
        render_symbol(out, &report->symbols[cap->symbol_offset + i]);
    }
    fputs("]}\n", out);
}

static void render_duplicate(FILE *out,
                             const struct ci_inventory_report *report,
                             const struct ci_inventory_duplicate *d)
{
    fputs("{\"record\":\"duplicate\",\"kind\":", out);
    json_string(out, codeindex_inventory_duplicate_kind_name(d->kind));
    fputs(",\"a\":{\"symbol\":", out); json_string(out, d->symbol_a);
    fputs(",\"path\":", out); json_string(out, d->path_a);
    render_arm_ordinal(out, report, d->path_a, d->symbol_a, d->line_a);
    fputs("},\"b\":{\"symbol\":", out);
    json_string(out, d->symbol_b);
    fputs(",\"path\":", out); json_string(out, d->path_b);
    render_arm_ordinal(out, report, d->path_b, d->symbol_b, d->line_b);
    fprintf(out, "},\"body_tokens\":%d,\"body_lines\":%d,"
                 "\"different_symbol_names\":%s,\"evidence\":",
            d->body_tokens, d->body_lines,
            strcmp(d->symbol_a, d->symbol_b) != 0 ? "true" : "false");
    json_string(out, d->evidence);
    fputs(",\"proof_needed\":", out);
    if (d->proof_needed[0]) json_string(out, d->proof_needed);
    else fputs("null", out);
    fputs("}\n", out);
}

static void render_invariant(FILE *out,
                             const struct ci_inventory_report *report,
                             const struct ci_inventory_invariant *gap)
{
    fputs("{\"record\":\"untested_invariant\",\"header\":", out);
    json_string(out, gap->header);
    fputs(",\"symbol\":", out); json_string(out, gap->symbol);
    fputs(",\"definition\":{\"path\":", out);
    json_string(out, gap->definition_path);
    render_arm_ordinal(out, report, gap->definition_path, gap->symbol,
                       gap->definition_line);
    fputs("},\"header_contract\":", out);
    if (gap->contract[0]) json_string(out, gap->contract); else fputs("null", out);
    fprintf(out, ",\"production_use_files\":%d,\"test_use_files\":%d",
            gap->production_use_files, gap->test_use_files);
    fputs(",\"test_evidence\":", out);
    json_string(out, codeindex_inventory_test_evidence_name(gap->test_evidence));
    fputs(",\"registered_test_group\":", out);
    if (gap->registered_test_group[0]) json_string(out, gap->registered_test_group);
    else fputs("null", out);
    fprintf(out, ",\"multi_arm_definition\":%s,\"definition_scope\":",
            gap->multi_arm_definition ? "true" : "false");
    json_string(out, gap->definition_scope);
    fputs(",\"preprocessor_guard\":", out);
    if (gap->preprocessor_guard[0]) json_string(out, gap->preprocessor_guard);
    else fputs("null", out);
    fputs(",\"constant_return_evidence\":", out);
    json_string(out, gap->constant_return_evidence);
    fprintf(out, ",\"constant_return_body\":%s,\"constant_return_value\":",
            gap->constant_return_body ? "true" : "false");
    if (gap->constant_return_body) json_string(out, gap->constant_return_value);
    else fputs("null", out);
    fputs(",\"verdict\":", out); json_string(out, gap->verdict);
    fputs(",\"proof_needed\":", out); json_string(out, gap->proof_needed);
    fputs("}\n", out);
}

static void render_multi_arm_symbol(
    FILE *out, const struct ci_inventory_report *report,
    const struct ci_inventory_capability *cap,
    const struct ci_inventory_symbol *symbol)
{
    const char *source_path = NULL;
    bool multiple_paths = false;
    for (int i = 0; i < report->definition_arm_count; i++) {
        const struct ci_inventory_definition_arm *arm =
            &report->definition_arms[i];
        if (strcmp(arm->header, cap->header) != 0 ||
            strcmp(arm->symbol, symbol->name) != 0)
            continue;
        if (!source_path) source_path = arm->definition_path;
        else if (strcmp(source_path, arm->definition_path) != 0)
            multiple_paths = true;
    }
    fputs("{\"record\":\"multi_arm_symbol\",\"header\":", out);
    json_string(out, cap->header);
    fputs(",\"symbol\":", out); json_string(out, symbol->name);
    fputs(",\"source_path\":", out);
    if (source_path && !multiple_paths) json_string(out, source_path);
    else fputs("null", out);
    fprintf(out, ",\"definition_arm_count\":%d,"
                 "\"aggregate_definition\":\"UNPROVEN\","
                 "\"aggregate_constant_return\":\"UNPROVEN\","
                 "\"verdict\":\"UNPROVEN\",\"proof_needed\":",
            symbol->definition_arm_count);
    json_string(out, "preprocess every definition_arm under its named guard and prove exactly one selected implementation per build profile");
    fputs("}\n", out);
}

static void render_definition_arm(
    FILE *out, const struct ci_inventory_report *report,
    const struct ci_inventory_definition_arm *arm)
{
    fputs("{\"record\":\"definition_arm\",\"header\":", out);
    json_string(out, arm->header);
    fputs(",\"symbol\":", out); json_string(out, arm->symbol);
    fputs(",\"definition\":{\"path\":", out);
    json_string(out, arm->definition_path);
    render_arm_ordinal(out, report, arm->definition_path, arm->symbol,
                       arm->definition_line);
    fputs("},\"preprocessor_guard\":", out);
    if (arm->preprocessor_guard[0]) json_string(out, arm->preprocessor_guard);
    else fputs("null", out);
    fputs(",\"constant_return_evidence\":", out);
    json_string(out, arm->constant_return_evidence);
    fprintf(out, ",\"constant_return_body\":%s,\"constant_return_value\":",
            arm->constant_return_body ? "true" : "false");
    if (arm->constant_return_body) json_string(out, arm->constant_return_value);
    else fputs("null", out);
    fputs(",\"definition_scope\":\"preprocessor_arm_UNPROVEN\",\"verdict\":",
          out);
    json_string(out, arm->verdict);
    fputs(",\"proof_needed\":", out); json_string(out, arm->proof_needed);
    fputs("}\n", out);
}

static void render_test_root_gap(
    FILE *out, const struct ci_inventory_test_root_gap *gap)
{
    fputs("{\"record\":\"test_root_gap\",\"group\":", out);
    json_string(out, gap->group);
    fputs(",\"root_symbol\":", out); json_string(out, gap->root_symbol);
    fputs(",\"reason\":", out); json_string(out, gap->reason);
    fputs(",\"verdict\":", out); json_string(out, gap->verdict);
    fputs(",\"proof_needed\":", out); json_string(out, gap->proof_needed);
    fputs("}\n", out);
}

bool codeindex_inventory_render(FILE *out,
                                const struct ci_inventory_report *report)
{
    fprintf(out,
        "{\"record\":\"inventory\",\"schema\":\"zcl.code_capability_inventory.v1\","
        "\"generated_artifact_schema\":\"zcl.generated_artifact.v1\","
        "\"artifact_id\":\"zcl.code_capability_inventory.v1\","
        "\"asserts\":[\"public_capability_definition\",\"definition_arm_constant_return\",\"registered_test_reachability\"],"
        "\"generated_by\":\"tools/gen_capability_inventory.c\","
        "\"regenerate\":\"make docs-capability-inventory\","
        "\"consumes\":[{\"path\":\"tools/lint/arm_symbol_single_baseline.txt\","
        "\"artifact_id\":\"zcl.arm_symbol_single_baseline.v1\","
        "\"asserts\":\"multi_arm_definition(path,symbol)\"}],"
        "\"scope\":"
        "\"maintained C23 public headers under core/engine/contexts/cognition/"
        "platform plus their sources, tests, and tools; vendor and build output excluded\","
        "\"evidence_ceiling\":{\"purpose\":\"header prose is declared intent only and remains UNPROVEN\","
        "\"uses\":\"path-disambiguated direct calls or source include edges;"
        " function pointers, transitive-only includes, and unresolved names remain UNPROVEN\","
        "\"tests\":\"path-bound direct-call reachability from canonical registered roots, not proof that every comment sentence is asserted\","
        "\"duplicates\":\"normalized equality is evidence; alpha-shape equality is an UNPROVEN candidate\"},"
        "\"files_scanned\":%d,\"production_files\":%d,\"test_files\":%d,"
        "\"capabilities\":%d,\"symbols_exposed\":%d,\"registered_test_groups\":%d,"
        "\"registered_test_roots_found\":%d,\"registered_test_roots_missing\":%d,"
        "\"ambiguous_registered_test_roots\":%d,"
        "\"unresolved_include_sites\":%d,"
        "\"ambiguous_symbol_use_sites\":%d,"
        "\"ambiguous_test_call_edges\":%d,"
        "\"unresolved_symbol_definitions\":%d,"
        "\"scanner_partial_symbols\":%d,\"arm_baseline_symbols\":%d,"
        "\"multi_arm_symbols\":%d,\"definition_arms\":%d,\"duplicates\":%d,"
        "\"duplicate_tag_led_excluded\":%d,"
        "\"untested_invariants\":%d,\"test_root_gaps\":%d}\n",
        report->files_scanned, report->production_files, report->test_files,
        report->capability_count, report->symbol_count,
        report->registered_test_groups, report->registered_test_roots_found,
        report->registered_test_roots_missing,
        report->ambiguous_registered_test_roots,
        report->unresolved_include_sites,
        report->ambiguous_symbol_use_sites,
        report->ambiguous_test_call_edges,
        report->unresolved_symbol_definitions,
        report->scanner_partial_symbols,
        report->arm_baseline_symbols,
        report->multi_arm_symbol_count,
        report->definition_arm_count,
        report->duplicate_count, report->duplicate_tag_led_excluded,
        report->invariant_count,
        report->test_root_gap_count);
    for (int i = 0; i < report->capability_count; i++)
        render_capability(out, report, &report->capabilities[i]);
    for (int c = 0; c < report->capability_count; c++) {
        const struct ci_inventory_capability *cap = &report->capabilities[c];
        for (int i = cap->symbol_offset;
             i < cap->symbol_offset + cap->symbol_count; i++)
            if (report->symbols[i].multi_arm_definition)
                render_multi_arm_symbol(out, report, cap,
                                        &report->symbols[i]);
    }
    for (int i = 0; i < report->definition_arm_count; i++)
        render_definition_arm(out, report, &report->definition_arms[i]);
    for (int i = 0; i < report->duplicate_count; i++)
        render_duplicate(out, report, &report->duplicates[i]);
    for (int i = 0; i < report->invariant_count; i++)
        render_invariant(out, report, &report->invariants[i]);
    for (int i = 0; i < report->test_root_gap_count; i++)
        render_test_root_gap(out, &report->test_root_gaps[i]);
    return !ferror(out);
}

static bool render_streams_identical(FILE *rendered, FILE *committed)
{
    unsigned char a[4096], b[4096];
    for (;;) {
        const size_t na = fread(a, 1, sizeof(a), rendered);
        const size_t nb = fread(b, 1, sizeof(b), committed);
        if (na != nb || memcmp(a, b, na) != 0) return false;
        if (na < sizeof(a)) return !ferror(rendered) && !ferror(committed);
    }
}

bool codeindex_inventory_artifact_identical(
    const struct ci_inventory_report *report, const char *artifact_path,
    bool *identical)
{
    if (!report || !artifact_path || !identical)
        LOG_FAIL("codeindex.inventory_render", "compare needs report, path and output");
    *identical = false;
    FILE *committed = fopen(artifact_path, "rb");
    if (!committed) return true; /* absent is stale, not an error */
    FILE *rendered = tmpfile();
    if (!rendered) {
        fclose(committed);
        LOG_FAIL("codeindex.inventory_render", "cannot create render buffer");
    }
    bool ok = codeindex_inventory_render(rendered, report) &&
              fflush(rendered) == 0 && fseek(rendered, 0, SEEK_SET) == 0;
    if (ok) *identical = render_streams_identical(rendered, committed);
    fclose(rendered);
    fclose(committed);
    if (!ok)
        LOG_FAIL("codeindex.inventory_render", "live report render failed");
    return true;
}
