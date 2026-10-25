/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-log-macro-return-type
 * (gate_log_macro_return_type.c). Feeds source text straight to the scanner:
 * each mismatched pairing is named with its exact message, each correct
 * pairing, comment, string and conditional-brace idiom stays clean. No files
 * are created by these parser cases; the traversal regressions use private
 * temporary fixtures.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <string.h>
#include "gate_log_macro_return_type_priv.h"

struct lmrs_case {
    const char *what;
    const char *text;
    const char *want;
};

static const struct lmrs_case k_lmrs_cases[] = {
    { "LOG_ERR in a bool function",
      "static bool f(void)\n{\n    LOG_ERR(\"x\");\n    return false;\n}\n",
      "  t.c:3: f returns static bool but LOG_ERR returns -1\n" },
    { "LOG_NULL in a bool function",
      "bool g(int a)\n{\n    if (!a) LOG_NULL (\"x\");\n    return true;\n}\n",
      "  t.c:3: g returns bool but LOG_NULL returns NULL\n" },
    { "LOG_FAIL in an int function",
      "int h(void)\n{\n    LOG_FAIL(\"x\");\n    return 0;\n}\n",
      "  t.c:3: h returns int but LOG_FAIL returns false\n" },
    { "LOG_FAIL in a bool function and LOG_ERR in an int function",
      "bool a(void)\n{\n    LOG_FAIL(\"x\");\n}\nint b(void)\n{\n    LOG_ERR(\"x\");\n}\n",
      "" },
    { "LOG_NULL in a pointer function",
      "char *p(void)\n{\n    LOG_NULL(\"x\");\n}\n", "" },
    { "macro names inside comments and strings",
      "bool c(void)\n{\n    /* LOG_ERR(\"x\") */\n    puts(\"LOG_ERR(\");\n"
      "    /* spans\n       LOG_ERR(\"y\")\n    */\n    return 0; // LOG_NULL(\n}\n",
      "" },
    { "a function directly after a preprocessor line",
      "#include <stdio.h>\nbool d(void)\n{\n    LOG_ERR(\"x\");\n}\n",
      "  t.c:4: d returns bool but LOG_ERR returns -1\n" },
    { "a split #if/#else brace does not blame the next function",
      "int e(void)\n{\n#if defined(_WIN32)\n    if (!a()) {\n#else\n    if (!b()) {\n#endif\n"
      "        return 1;\n    }\n    return 0;\n}\nbool f2(void)\n{\n    LOG_FAIL(\"x\");\n}\n",
      "" },
    { "a mismatch after a split #if/#else brace is still found",
      "int e(void)\n{\n#if defined(_WIN32)\n    if (!a()) {\n#else\n    if (!b()) {\n#endif\n"
      "        return 1;\n    }\n    return 0;\n}\nbool f2(void)\n{\n    LOG_ERR(\"x\");\n}\n",
      "  t.c:14: f2 returns bool but LOG_ERR returns -1\n" },
    { "an attribute after the parameter list",
      "bool k(void) __attribute__((unused))\n{\n    LOG_ERR(\"x\");\n}\n",
      "  t.c:3: k returns bool but LOG_ERR returns -1\n" },
    { "a macro guard line above a function is not declaration text",
      "ZCL_GUARD(x)\nbool m(void)\n{\n    LOG_NULL(\"x\");\n}\n",
      "  t.c:4: m returns bool but LOG_NULL returns NULL\n" },
    { "an identifier that only contains the macro name",
      "bool n(void)\n{\n    MY_LOG_ERR(\"x\");\n    LOG_ERRNO(\"x\");\n}\n", "" },
};

static int lmrs_run_case(const struct lmrs_case *c)
{
    struct lmr_buf bad = { 0 };
    int rc = lmr_scan_text("t.c", c->text, strlen(c->text), &bad);
    const char *got = bad.p ? bad.p : "";
    int ok = rc == 0 && strcmp(got, c->want) == 0;
    if (!ok) {
        fprintf(stderr, "check_log_macro_return_type: SELFTEST FAILED — %s\n"
                        "  want: %s  got: %s\n", c->what, c->want, got);
    }
    lmr_buf_free(&bad);
    return ok;
}

int check_log_macro_return_type_selftest(void)
{
    int fails = lmr_filesystem_selftest();
    for (size_t i = 0; i < sizeof k_lmrs_cases / sizeof k_lmrs_cases[0]; i++)
        fails += !lmrs_run_case(&k_lmrs_cases[i]);
    if (fails)
        return 1;
    printf("[check_log_macro_return_type] SELFTEST PASS (bool, int and pointer pairings, "
           "comments, strings, attributes and split #if braces)\n");
    return 0;
}
