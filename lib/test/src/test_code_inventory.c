/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Prove the capability census derives uses, tests, duplicates, gaps,
 * packages, and source identity from a bounded source fixture. */

#include "codeindex/codeindex_inventory.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define CI_FIX "test-tmp/code-inventory-fixture"

static int ci_failures;

#define CI_ASSERT(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "  code_inventory: FAIL %s:%d: %s\n", \
                __FILE__, __LINE__, #expr); \
        ci_failures++; \
    } \
} while (0)

static bool ci_write(const char *path, const char *text)
{
    FILE *out = fopen(path, "wb");
    if (!out) return false;
    size_t len = strlen(text);
    bool ok = fwrite(text, 1, len, out) == len && fclose(out) == 0;
    return ok;
}

static bool ci_fixture(void)
{
    if (system("rm -rf " CI_FIX " && mkdir -p "
               CI_FIX "/lib/demo/include/demo "
               CI_FIX "/lib/demo/src "
               CI_FIX "/lib/test/src "
               CI_FIX "/packages/zmini/include/zmini "
               CI_FIX "/packages/zmini/src "
               CI_FIX "/tools/dev") != 0) return false;
    return ci_write(CI_FIX "/lib/demo/include/demo/demo.h",
        "/* purpose: Validate demo values for the fixture. */\n"
        "#ifndef DEMO_H\n#define DEMO_H\n#include <stdbool.h>\n"
        "/** Must reject zero and return true only for valid even values. */\n"
        "bool demo_validate(int value);\n"
        "/** Must reject invalid values; this declaration is not proof. */\n"
        "bool demo_stub(int value);\n#endif\n") &&
        ci_write(CI_FIX "/lib/demo/src/demo.c",
        "#include \"demo/demo.h\"\n"
        "bool demo_validate(int value)\n{\n"
        "    if (value <= 0) return false;\n"
        "    if (value > 1000) return false;\n"
        "    return (value % 2) == 0;\n}\n"
        "bool demo_stub(int value)\n{\n"
        "    (void)value;\n    return true;\n}\n"
        "static int alpha_one(int value)\n{\n"
        "    int result = first_call(value, 7);\n"
        "    if (result < 0) return result;\n"
        "    result = second_call(result, value);\n"
        "    if (result == 0) return first_call(value, 7);\n"
        "    if (result > value) result = second_call(result, 7);\n"
        "    return result + 7;\n}\n") &&
        ci_write(CI_FIX "/lib/demo/src/copy.c",
        "#include <stdbool.h>\n"
        "bool demo_validate_copy(int value)\n{\n"
        "    if (value <= 0) return false;\n"
        "    if (value > 1000) return false;\n"
        "    return (value % 2) == 0;\n}\n"
        "static int alpha_two(int item)\n{\n"
        "    int answer = other_call(item, 9);\n"
        "    if (answer < 0) return answer;\n"
        "    answer = final_call(answer, item);\n"
        "    if (answer == 0) return other_call(item, 9);\n"
        "    if (answer > item) answer = final_call(answer, 9);\n"
        "    return answer + 9;\n}\n") &&
        ci_write(CI_FIX "/lib/test/src/test_fixture.c",
        "#include \"demo/demo.h\"\n"
        "int test_code_inventory_fixture(void)\n{\n"
        "    return demo_validate(2) ? 0 : 1;\n}\n") &&
        ci_write(CI_FIX "/packages/zmini/include/zmini/zmini.h",
        "/* purpose: Tiny package fixture. */\n"
        "#ifndef ZMINI_H\n#define ZMINI_H\n"
        "int zmini_add(int a, int b);\n#endif\n") &&
        ci_write(CI_FIX "/packages/zmini/src/zmini.c",
        "#include \"zmini/zmini.h\"\n"
        "int zmini_add(int a, int b) { return a + b; }\n") &&
        ci_write(CI_FIX "/tools/dev/test_group_catalog.def",
        "ZCL_TEST_GROUP(code_inventory_fixture)\n");
}

static const struct ci_inventory_capability *ci_cap(
    const struct ci_inventory_report *report, const char *header)
{
    for (int i = 0; i < report->capability_count; i++)
        if (strcmp(report->capabilities[i].header, header) == 0)
            return &report->capabilities[i];
    return NULL;
}

static const struct ci_inventory_symbol *ci_symbol(
    const struct ci_inventory_report *report,
    const struct ci_inventory_capability *cap, const char *name)
{
    if (!cap) return NULL;
    for (int i = 0; i < cap->symbol_count; i++) {
        const struct ci_inventory_symbol *symbol =
            &report->symbols[cap->symbol_offset + i];
        if (strcmp(symbol->name, name) == 0) return symbol;
    }
    return NULL;
}

int test_code_inventory(void)
{
    ci_failures = 0;
    CI_ASSERT(ci_fixture());
    struct ci_inventory_report *first = codeindex_inventory_analyze(CI_FIX);
    CI_ASSERT(first != NULL);
    if (!first) return 1;
    CI_ASSERT(first->registered_test_groups == 1);
    CI_ASSERT(first->registered_test_roots_found == 1);
    CI_ASSERT(first->registered_test_roots_missing == 0);

    const struct ci_inventory_capability *demo = ci_cap(
        first, "lib/demo/include/demo/demo.h");
    const struct ci_inventory_capability *package = ci_cap(
        first, "packages/zmini/include/zmini/zmini.h");
    CI_ASSERT(demo != NULL);
    CI_ASSERT(package != NULL);
    CI_ASSERT(demo && strcmp(demo->include_token, "demo/demo.h") == 0);
    CI_ASSERT(demo && demo->production_use_files >= 1);
    CI_ASSERT(demo && demo->test_use_files >= 1);
    CI_ASSERT(demo && demo->purpose_unproven);

    const struct ci_inventory_symbol *validate = ci_symbol(
        first, demo, "demo_validate");
    const struct ci_inventory_symbol *stub = ci_symbol(first, demo, "demo_stub");
    CI_ASSERT(validate != NULL);
    CI_ASSERT(validate && validate->test_evidence ==
              CI_INVENTORY_TEST_REGISTERED_REACHABLE);
    CI_ASSERT(validate && strcmp(validate->registered_test_group,
                                 "code_inventory_fixture") == 0);
    CI_ASSERT(stub != NULL);
    if (stub && !stub->constant_return_body)
        fprintf(stderr, "  code_inventory: stub definition=%s:%d\n",
                stub->definition_path, stub->definition_line);
    CI_ASSERT(stub && stub->constant_return_body);
    CI_ASSERT(stub && strcmp(stub->constant_return_value, "true") == 0);

    bool exact = false, shape = false, stub_gap = false;
    for (int i = 0; i < first->duplicate_count; i++) {
        const struct ci_inventory_duplicate *d = &first->duplicates[i];
        if (d->kind == CI_INVENTORY_DUPLICATE_EXACT_BODY &&
            ((strcmp(d->symbol_a, "demo_validate") == 0 &&
              strcmp(d->symbol_b, "demo_validate_copy") == 0) ||
             (strcmp(d->symbol_b, "demo_validate") == 0 &&
              strcmp(d->symbol_a, "demo_validate_copy") == 0))) exact = true;
        if (d->kind == CI_INVENTORY_DUPLICATE_ALPHA_SHAPE &&
            ((strcmp(d->symbol_a, "alpha_one") == 0 &&
              strcmp(d->symbol_b, "alpha_two") == 0) ||
             (strcmp(d->symbol_b, "alpha_one") == 0 &&
              strcmp(d->symbol_a, "alpha_two") == 0))) shape = true;
    }
    for (int i = 0; i < first->invariant_count; i++)
        if (strcmp(first->invariants[i].symbol, "demo_stub") == 0 &&
            strcmp(first->invariants[i].verdict, "UNPROVEN") == 0)
            stub_gap = true;
    CI_ASSERT(exact);
    CI_ASSERT(shape);
    CI_ASSERT(stub_gap);

    struct ci_inventory_report *same = codeindex_inventory_analyze(CI_FIX);
    CI_ASSERT(same != NULL);
    CI_ASSERT(same && memcmp(first->source_root_sha3,
                             same->source_root_sha3, 32) == 0);
    codeindex_inventory_free(same);
    CI_ASSERT(ci_write(CI_FIX "/packages/zmini/src/zmini.c",
        "#include \"zmini/zmini.h\"\n"
        "int zmini_add(int a, int b) { return a + b + 0; }\n"));
    struct ci_inventory_report *changed = codeindex_inventory_analyze(CI_FIX);
    CI_ASSERT(changed != NULL);
    CI_ASSERT(changed && memcmp(first->source_root_sha3,
                                changed->source_root_sha3, 32) != 0);
    codeindex_inventory_free(changed);
    codeindex_inventory_free(first);
    if (!ci_failures) (void)system("rm -rf " CI_FIX);
    printf("  code_inventory: %s\n", ci_failures ? "FAIL" : "PASS");
    return ci_failures ? 1 : 0;
}
