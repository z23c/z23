/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Generate the complete machine-readable C23 capability inventory.
 *
 * The
 * output is JSON Lines so every capability, duplicate candidate, and untested
 * header invariant remains independently searchable without loading one giant
 * document.  No finding or count is embedded here; all rows come from
 * codeindex_inventory_analyze().
 *
 * Usage: gen_capability_inventory <output.jsonl> [source-root]
 */

#define _POSIX_C_SOURCE 200809L
#include "base/hex.h"
#include "codeindex/codeindex_inventory.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void json_string(FILE *out, const char *text)
{
    fputc('"', out);
    if (text) for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        switch (*p) {
        case '"': fputs("\\\"", out); break;
        case '\\': fputs("\\\\", out); break;
        case '\b': fputs("\\b", out); break;
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

static void render_symbol(FILE *out, const struct ci_inventory_symbol *symbol)
{
    fputs("{\"name\":", out); json_string(out, symbol->name);
    fprintf(out, ",\"kind\":\"%c\",\"definition\":{\"path\":", symbol->kind);
    json_string(out, symbol->definition_path);
    fprintf(out, ",\"line\":%d},\"definition_evidence\":",
            symbol->definition_line);
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
    fprintf(out, ",\"line\":%d},\"signature\":", symbol->declaration_line);
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

static void render_duplicate(FILE *out, const struct ci_inventory_duplicate *d)
{
    fputs("{\"record\":\"duplicate\",\"kind\":", out);
    json_string(out, codeindex_inventory_duplicate_kind_name(d->kind));
    fputs(",\"a\":{\"symbol\":", out); json_string(out, d->symbol_a);
    fputs(",\"path\":", out); json_string(out, d->path_a);
    fprintf(out, ",\"line\":%d},\"b\":{\"symbol\":", d->line_a);
    json_string(out, d->symbol_b);
    fputs(",\"path\":", out); json_string(out, d->path_b);
    fprintf(out, ",\"line\":%d},\"body_tokens\":%d,\"body_lines\":%d,"
                 "\"different_symbol_names\":%s,\"evidence\":",
            d->line_b, d->body_tokens, d->body_lines,
            strcmp(d->symbol_a, d->symbol_b) != 0 ? "true" : "false");
    json_string(out, d->evidence);
    fputs(",\"proof_needed\":", out);
    if (d->proof_needed[0]) json_string(out, d->proof_needed);
    else fputs("null", out);
    fputs("}\n", out);
}

static void render_invariant(FILE *out, const struct ci_inventory_invariant *gap)
{
    fputs("{\"record\":\"untested_invariant\",\"header\":", out);
    json_string(out, gap->header);
    fputs(",\"symbol\":", out); json_string(out, gap->symbol);
    fputs(",\"definition\":{\"path\":", out);
    json_string(out, gap->definition_path);
    fprintf(out, ",\"line\":%d},\"header_contract\":", gap->definition_line);
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
    FILE *out, const struct ci_inventory_definition_arm *arm)
{
    fputs("{\"record\":\"definition_arm\",\"header\":", out);
    json_string(out, arm->header);
    fputs(",\"symbol\":", out); json_string(out, arm->symbol);
    fputs(",\"definition\":{\"path\":", out);
    json_string(out, arm->definition_path);
    fprintf(out, ",\"line\":%d},\"preprocessor_guard\":",
            arm->definition_line);
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

static bool render_report(FILE *out, const struct ci_inventory_report *report)
{
    char root[65];
    zcl_hex_encode(report->source_root_sha3,
                   sizeof(report->source_root_sha3), root);
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
        "\"source_root_sha3\":\"%s\",\"scope\":"
        "\"maintained C23 public headers under lib/app/core/config/domain/ports/"
        "adapters/packages plus their sources, tests, tools, and examples; vendor and build output excluded\","
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
        "\"untested_invariants\":%d,\"test_root_gaps\":%d}\n",
        root, report->files_scanned, report->production_files, report->test_files,
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
        report->duplicate_count, report->invariant_count,
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
        render_definition_arm(out, &report->definition_arms[i]);
    for (int i = 0; i < report->duplicate_count; i++)
        render_duplicate(out, &report->duplicates[i]);
    for (int i = 0; i < report->invariant_count; i++)
        render_invariant(out, &report->invariants[i]);
    for (int i = 0; i < report->test_root_gap_count; i++)
        render_test_root_gap(out, &report->test_root_gaps[i]);
    return !ferror(out);
}

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s <output.jsonl> [source-root]\n", argv[0]);
        return 2;
    }
    const char *output = argv[1];
    const char *root = argc == 3 ? argv[2] : ".";
    struct ci_inventory_report *report = codeindex_inventory_analyze(root);
    if (!report) {
        fprintf(stderr, "gen_capability_inventory: analysis failed for %s\n", root);
        return 1;
    }
    char temp[4096];
    int n = snprintf(temp, sizeof(temp), "%s.tmp.%ld", output, (long)getpid());
    if (n <= 0 || (size_t)n >= sizeof(temp)) {
        codeindex_inventory_free(report);
        fprintf(stderr, "gen_capability_inventory: output path too long\n");
        return 1;
    }
    FILE *out = fopen(temp, "wb");
    bool ok = out && render_report(out, report) && fflush(out) == 0 &&
        fsync(fileno(out)) == 0;
    if (out && fclose(out) != 0) ok = false;
    if (ok && rename(temp, output) != 0) ok = false;
    if (!ok) {
        int saved = errno;
        unlink(temp);
        fprintf(stderr, "gen_capability_inventory: write %s failed: %s\n",
                output, strerror(saved));
    } else {
        fprintf(stderr,
                "gen_capability_inventory: %d capabilities, %d symbols, %d duplicate candidates, %d untested invariants -> %s\n",
                report->capability_count, report->symbol_count,
                report->duplicate_count, report->invariant_count, output);
    }
    codeindex_inventory_free(report);
    return ok ? 0 : 1;
}
