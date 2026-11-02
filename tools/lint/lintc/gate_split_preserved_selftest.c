/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-split-preserved (gate_split_preserved.c).
 * Feeds base and new source text straight to sp_compare: an unchanged file,
 * reworded and moved comments, a LOG call moved into a helper, added
 * includes, a returning LOG moved as LOG_ERROR_IN plus its return, a removed
 * duplicate function, comment-like text in strings and a
 * changed licence line. No files are created and git is not spawned.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gate_split_preserved_priv.h"

#define SPS_LIC "/* Copyright 2026 Rhett Creighton - Apache License 2.0 */\n"
#define SPS_LICX "/* Copyright 2026 Rhett Creightom - Apache License 2.0 */\n"
#define SPS_INC "#include <stdio.h>\n"
#define SPS_F1 "int f(void)\n{\n    /* keep me */\n    LOG_FAIL(\"f broke\");\n    return 0;\n}\n"
#define SPS_G1 "int g(void)\n{\n    // other note\n    return 1;\n}\n"
#define SPS_FN(name, note) "int " name "(void)\n{\n    /* " note " */\n    return 0;\n}\n"
#define SPS_DUP "\n/* twin note */\nint dup(void)\n{\n    /* inside twin */\n    LOG_ERR(\"dup %d\",\n            1);\n    return 0;\n}\n"
#define SPS_RBASE(mac, ret) SPS_LIC ret " f(void)\n{\n    " mac ";\n}\n"
#define SPS_RHELP(body) SPS_LIC "static int h(void)\n{\n    " body "}\n" "int f(void)\n{\n    return h();\n}\n"

struct sps_case {
    const char *what;
    const char *base;
    const char *cur;
    int dedup;
    int want_rc;
    const char *want; /* substring of the output, or NULL */
};

static int sps_exists(const char *header)
{
    return strcmp(header, "util/known.h") == 0;
}

static const struct sps_case k_sps_cases[] = {
    { "an unchanged file", SPS_LIC SPS_INC SPS_F1 SPS_G1, SPS_LIC SPS_INC SPS_F1 SPS_G1, 0, 0, NULL },
    { "a reworded comment",
      SPS_LIC SPS_F1, SPS_LIC "int f(void)\n{\n    /* keep me, please */\n    LOG_FAIL(\"f broke\");\n    return 0;\n}\n",
      0, 1, "t.c:4: base comment line lost or reworded: /* keep me */" },
    { "a comment moved to another function",
      SPS_LIC SPS_F1 SPS_G1,
      SPS_LIC "int f(void)\n{\n    LOG_FAIL(\"f broke\");\n    return 0;\n}\nint g(void)\n{\n"
      "    // other note\n    /* keep me */\n    return 1;\n}\n", 0, 0, NULL },
    { "a LOG_FAIL moved into a new helper",
      SPS_LIC SPS_F1,
      SPS_LIC "static bool h(void)\n{\n    LOG_FAIL(\"f broke\");\n    return false;\n}\n"
      "int f(void)\n{\n    /* keep me */\n    return h();\n}\n", 0, 1, "LOG call missing from f" },
    { "a LOG_FAIL_IN is not a kept form, so it is compared as written",
      SPS_LIC SPS_F1,
      SPS_LIC "static bool h(void)\n{\n    LOG_FAIL_IN(\"f\", \"f broke\");\n    return false;\n}\n"
      "int f(void)\n{\n    /* keep me */\n    return h();\n}\n", 0, 1, "LOG call missing from f" },
    { "a LOG_FAIL_IN naming another function",
      SPS_LIC SPS_F1,
      SPS_LIC "static bool h(void)\n{\n    LOG_FAIL_IN(\"g\", \"f broke\");\n    return false;\n}\n"
      "int f(void)\n{\n    /* keep me */\n    return h();\n}\n", 0, 1, "LOG call missing from f" },
    { "a LOG_FAIL_IN with changed arguments",
      SPS_LIC SPS_F1,
      SPS_LIC "static bool h(void)\n{\n    LOG_FAIL_IN(\"f\", \"f broke!\");\n    return false;\n}\n"
      "int f(void)\n{\n    /* keep me */\n    return h();\n}\n", 0, 1, "LOG call missing from f" },
    { "a LOG_RETURN_IN is not a kept form, so it is compared as written",
      SPS_LIC "int f(void)\n{\n    LOG_RETURN((-2), \"d\", \"x %d\", 1);\n}\n",
      SPS_LIC "static int h(void)\n{\n    LOG_RETURN_IN((-2), \"f\", \"d\", \"x %d\", 1);\n}\n"
      "int f(void)\n{\n    return h();\n}\n", 0, 1, "LOG call missing from f" },
    { "a LOG_WARN moved into a helper as LOG_WARN_IN naming the original",
      SPS_LIC "void f(void)\n{\n    LOG_WARN(\"d\", \"w\");\n}\n",
      SPS_LIC "static void h(void)\n{\n    LOG_WARN_IN(\"f\", \"d\", \"w\");\n}\n"
      "void f(void)\n{\n    h();\n}\n", 0, 0, NULL },
    { "a LOG_ERROR moved into a static helper that the named function calls",
      SPS_LIC "int f(void)\n{\n    LOG_ERROR(\"d\", \"e\");\n    return 0;\n}\n",
      SPS_LIC "static void h(void)\n{\n    LOG_ERROR_IN(\"f\", \"d\", \"e\");\n}\n"
      "int f(void)\n{\n    h();\n    return 0;\n}\n", 0, 0, NULL },
    { "a LOG_ERROR_IN naming a function that does not call the helper",
      SPS_LIC "int f(void)\n{\n    LOG_ERROR(\"d\", \"e\");\n    return 0;\n}\n",
      SPS_LIC "static void h(void)\n{\n    LOG_ERROR_IN(\"f\", \"d\", \"e\");\n}\n"
      "int f(void)\n{\n    return 0;\n}\n", 0, 1, "LOG call missing from f" },
    { "a LOG_ERROR_IN in a helper that is not static",
      SPS_LIC "int f(void)\n{\n    LOG_ERROR(\"d\", \"e\");\n    return 0;\n}\n",
      SPS_LIC "void h(void)\n{\n    LOG_ERROR_IN(\"f\", \"d\", \"e\");\n}\n"
      "int f(void)\n{\n    h();\n    return 0;\n}\n", 0, 1, "LOG call missing from f" },
    { "a LOG_ERROR_IN naming a function missing from the file",
      SPS_LIC "int f(void)\n{\n    LOG_ERROR(\"d\", \"e\");\n    return 0;\n}\n",
      SPS_LIC "static void h(void)\n{\n    LOG_ERROR_IN(\"nope\", \"d\", \"e\");\n}\n"
      "int f(void)\n{\n    h();\n    return 0;\n}\n", 0, 1, "LOG call missing from f" },
    { "a LOG_ERROR_IN whose named function reaches h only as a member call",
      SPS_LIC "int f(void)\n{\n    LOG_ERROR(\"d\", \"e\");\n    return 0;\n}\n",
      SPS_LIC "static void h(void)\n{\n    LOG_ERROR_IN(\"f\", \"d\", \"e\");\n}\n"
      "int f(void)\n{\n    o.h();\n    p -> h();\n    return 0;\n}\n", 0, 1,
      "LOG call missing from f" },
    { "a LOG_ERROR_IN whose named function calls h after a postfix decrement (n-->h())",
      SPS_LIC "int f(void)\n{\n    LOG_ERROR(\"d\", \"e\");\n    return 0;\n}\n",
      SPS_LIC "static int h(void)\n{\n    LOG_ERROR_IN(\"f\", \"d\", \"e\");\n    return 0;\n}\n"
      "int f(void)\n{\n    int n = 1;\n    if (n-->h())\n        return 1;\n    return 0;\n}\n",
      0, 0, NULL },
    { "a LOG_ERROR_IN whose named function reaches h only as p--->h()",
      SPS_LIC "int f(void)\n{\n    LOG_ERROR(\"d\", \"e\");\n    return 0;\n}\n",
      SPS_LIC "static int h(void)\n{\n    LOG_ERROR_IN(\"f\", \"d\", \"e\");\n    return 0;\n}\n"
      "int f(void)\n{\n    p--->h();\n    return 0;\n}\n", 0, 1, "LOG call missing from f" },
    { "a LOG_ERROR_IN with a space after '(' keeps it, as the plain call had it",
      SPS_LIC "int f(void)\n{\n    LOG_ERROR( \"d\", \"e\");\n    return 0;\n}\n",
      SPS_LIC "static void h(void)\n{\n    LOG_ERROR_IN( \"f\", \"d\", \"e\");\n}\n"
      "int f(void)\n{\n    h();\n    return 0;\n}\n", 0, 0, NULL },
    { "a LOG_ERR moved into a helper as LOG_ERROR_IN and return -1",
      SPS_RBASE("LOG_ERR(\"d\", \"e %d\", 1)", "int"), SPS_RHELP("LOG_ERROR_IN(\"f\", \"d\", \"e %d\", 1);\n    return -1;\n"),
      0, 0, NULL },
    { "a LOG_FAIL moved into a helper as LOG_ERROR_IN and return false",
      SPS_RBASE("LOG_FAIL(\"d\", \"e %d\", 1)", "bool"), SPS_RHELP("LOG_ERROR_IN(\"f\", \"d\", \"e %d\", 1);\n    return false;\n"),
      0, 0, NULL },
    { "a LOG_NULL moved into a helper as LOG_ERROR_IN and return NULL",
      SPS_RBASE("LOG_NULL(\"d\", \"e %d\", 1)", "int *"), SPS_RHELP("LOG_ERROR_IN(\"f\", \"d\", \"e %d\", 1);\n    return NULL;\n"),
      0, 0, NULL },
    { "a LOG_RETURN moved into a helper as LOG_ERROR_IN and the same return value",
      SPS_RBASE("LOG_RETURN((-2), \"d\", \"e %d\", 1)", "int"), SPS_RHELP("LOG_ERROR_IN(\"f\", \"d\", \"e %d\", 1);\n    return (-2);\n"),
      0, 0, NULL },
    { "a LOG_ERR moved as LOG_ERROR_IN without the return",
      SPS_RBASE("LOG_ERR(\"d\", \"e %d\", 1)", "int"), SPS_RHELP("LOG_ERROR_IN(\"f\", \"d\", \"e %d\", 1);\n"),
      0, 1, "LOG call missing from f" },
    { "a LOG_ERR moved as LOG_ERROR_IN with return 0",
      SPS_RBASE("LOG_ERR(\"d\", \"e %d\", 1)", "int"), SPS_RHELP("LOG_ERROR_IN(\"f\", \"d\", \"e %d\", 1);\n    return 0;\n"),
      0, 1, "LOG call missing from f" },
    { "a LOG_RETURN moved with a different return value",
      SPS_RBASE("LOG_RETURN((-2), \"d\", \"e %d\", 1)", "int"), SPS_RHELP("LOG_ERROR_IN(\"f\", \"d\", \"e %d\", 1);\n    return -2;\n"),
      0, 1, "LOG call missing from f" },
    { "a LOG_ERR moved with the return not the next statement",
      SPS_RBASE("LOG_ERR(\"d\", \"e %d\", 1)", "int"), SPS_RHELP("LOG_ERROR_IN(\"f\", \"d\", \"e %d\", 1);\n    cleanup();\n    return -1;\n"),
      0, 1, "LOG call missing from f" },
    { "a LOG_ERR moved with the return under a braceless if",
      SPS_RBASE("LOG_ERR(\"d\", \"e %d\", 1)", "int"), SPS_RHELP("if (x)\n        LOG_ERROR_IN(\"f\", \"d\", \"e %d\", 1);\n    return -1;\n"),
      0, 1, "LOG call missing from f" },
    { "a LOG_ERR moved with the name string not f",
      SPS_RBASE("LOG_ERR(\"d\", \"e %d\", 1)", "int"), SPS_RHELP("LOG_ERROR_IN(\"g\", \"d\", \"e %d\", 1);\n    return -1;\n"),
      0, 1, "LOG call missing from f" },
    { "a LOG_ERR moved with different arguments",
      SPS_RBASE("LOG_ERR(\"d\", \"e %d\", 1)", "int"), SPS_RHELP("LOG_ERROR_IN(\"f\", \"d\", \"e %d\", 2);\n    return -1;\n"),
      0, 1, "LOG call missing from f" },
    { "a LOG_ERR moved into a helper that f never calls",
      SPS_RBASE("LOG_ERR(\"d\", \"e %d\", 1)", "int"),
      SPS_LIC "static int h(void)\n{\n    LOG_ERROR_IN(\"f\", \"d\", \"e %d\", 1);\n    return -1;\n}\n"
      "int f(void)\n{\n    return 0;\n}\n", 0, 1, "LOG call missing from f" },
    { "a LOG call joined onto one line with other spacing",
      SPS_LIC SPS_DUP, SPS_LIC "\n/* twin note */\nint dup(void)\n{\n    /* inside twin */\n"
      "    LOG_ERR(\"dup %d\",     1);\n    return 0;\n}\n", 0, 0, NULL },
    { "an added include in split mode", SPS_LIC SPS_INC SPS_G1,
      SPS_LIC SPS_INC "#include \"util/known.h\"\n" SPS_G1, 0, 1, "t.c:3: include line added" },
    { "an added existing include in dedup mode", SPS_LIC SPS_INC SPS_G1,
      SPS_LIC SPS_INC "#include \"util/known.h\"\n" SPS_G1, 1, 0, NULL },
    { "an added missing include in dedup mode", SPS_LIC SPS_INC SPS_G1,
      SPS_LIC SPS_INC "#include \"util/nope.h\"\n" SPS_G1, 1, 1, "header that exists in the tree" },
    { "a removed include in dedup mode", SPS_LIC SPS_INC SPS_G1, SPS_LIC SPS_G1, 1, 1,
      "include line removed or changed" },
    { "a removed __has_include line", SPS_LIC "#if __has_include(<a/b.h>)\n#endif\n" SPS_G1,
      SPS_LIC SPS_G1, 0, 1, "include line removed or changed" },
    { "a removed duplicate function with its comments and LOG in dedup mode",
      SPS_LIC SPS_F1 SPS_DUP, SPS_LIC SPS_F1, 1, 0, NULL },
    { "the same removal in split mode", SPS_LIC SPS_F1 SPS_DUP, SPS_LIC SPS_F1, 0, 1,
      "LOG call missing from dup" },
    { "a LOG call dropped from a surviving function in dedup mode",
      SPS_LIC SPS_F1, SPS_LIC "int f(void)\n{\n    /* keep me */\n    return 0;\n}\n", 1, 1,
      "LOG call missing from f" },
    { "a comment dropped from a surviving function in dedup mode",
      SPS_LIC SPS_F1 SPS_G1, SPS_LIC SPS_F1 "int g(void)\n{\n    return 1;\n}\n", 1, 1,
      "base comment line lost" },
    { "a repeated comment lost with two removed functions, copy kept last, in dedup mode",
      SPS_LIC SPS_FN("a", "name must exist") SPS_FN("b", "name must exist") SPS_FN("k", "name must exist"),
      SPS_LIC SPS_FN("k", "name must exist"), 1, 0, NULL },
    { "the same repeated comment loss in split mode",
      SPS_LIC SPS_FN("a", "name must exist") SPS_FN("b", "name must exist") SPS_FN("k", "name must exist"),
      SPS_LIC SPS_FN("k", "name must exist"), 0, 1, "base comment line lost or reworded" },
    { "a comment lost from a kept function with no copy in a removed one, dedup mode",
      SPS_LIC SPS_FN("a", "only a") SPS_FN("k", "only k"), SPS_LIC "int k(void)\n{\n    return 0;\n}\n",
      1, 1, "lost or reworded: /* only k */" },
    { "two kept copies lost with one removed-function copy, dedup mode",
      SPS_LIC SPS_FN("a", "dup note") SPS_FN("k", "dup note") SPS_FN("m", "dup note"),
      SPS_LIC "int k(void)\n{\n    return 0;\n}\n" SPS_FN("m", "dup note"), 1, 1,
      "base comment line lost or reworded: /* dup note */" },
    { "comment-like text in strings and char literals",
      SPS_LIC "int s(void)\n{\n    const char *u = \"http://a\"; /* real */\n    char q = '\"';\n"
      "    const char *v = \"/* not */\";\n    return 1'000;\n}\n",
      SPS_LIC "int s(void)\n{\n    const char *u = \"http://b\"; /* real */\n    char q = '\"';\n"
      "    const char *v = \"x\";\n    return 1'000;\n}\n", 0, 0, NULL },
    { "a real comment after a string with a comment opener",
      SPS_LIC "int s(void)\n{\n    const char *u = \"/*\"; /* real */\n    return 1;\n}\n",
      SPS_LIC "int s(void)\n{\n    const char *u = \"/*\"; /* fake */\n    return 1;\n}\n",
      0, 1, "lost or reworded: /* real */" },
    { "a LOG_ name inside a string is not a call",
      SPS_LIC "int s(void)\n{\n    puts(\"LOG_FAIL(x)\");\n    return 1;\n}\n",
      SPS_LIC "int s(void)\n{\n    puts(\"ok\");\n    return 1;\n}\n", 0, 0, NULL },
    { "a changed licence line", SPS_LIC SPS_G1, SPS_LICX SPS_G1, 0, 1, "t.c:1: licence line changed" },
};

static int sps_run_case(const struct sps_case *c)
{
    char *buf = NULL;
    size_t blen = 0;
    FILE *out = open_memstream(&buf, &blen);
    int rc = out ? sp_compare("t.c", c->base, strlen(c->base), c->cur, strlen(c->cur),
                              c->dedup, sps_exists, out)
                 : 2;
    if (out)
        fclose(out);
    const char *got = buf ? buf : "";
    int ok = rc == c->want_rc && (!c->want || strstr(got, c->want));
    if (!ok)
        fprintf(stderr, "check_split_preserved: SELFTEST FAILED — %s\n  rc %d (want %d), output:\n%s\n",
                c->what, rc, c->want_rc, got);
    free(buf);
    return ok;
}

static size_t sps_count_fails(void)
{
    size_t fails = 0;
    for (size_t i = 0; i < sizeof k_sps_cases / sizeof k_sps_cases[0]; i++)
        if (!sps_run_case(&k_sps_cases[i]))
            fails++;
    return fails;
}

int check_split_preserved_selftest(void)
{
    if (sps_count_fails() != 0)
        return 1;
    puts("[check_split_preserved] SELFTEST PASS (licence, includes, LOG calls, comments, "
         "strings, split and dedup modes)");
    return 0;
}
