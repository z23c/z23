/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex_static_callers: the impact closure walks symbol identities, not
 * bare names. A static function is internal to its translation unit, so a
 * same-named static in another TU is not one of its callers.
 *
 * Coverage (all over one fixture tree under ./test-tmp/):
 *   1. two TUs each define `static int helper(void)`: editing one selects only
 *      its own callers, never the other TU or that TU's callers;
 *   2. a static CALLER found mid-walk keeps its file: `static run()` in two
 *      files, only the one that calls the changed function climbs;
 *   3. never under-select: a .c that #includes the static's file and calls it,
 *      a header whose inline body calls it, and a file that defines its own
 *      `helper` under #ifdef but includes the static's file on the other arm
 *      (seen through the depfile) all stay selected;
 *   4. a `static inline` defined in a header is defined in every includer: its
 *      callers are the includers' functions, and the header case keeps the
 *      conservative name walk (it does not shrink);
 *   5. the overlay walk (changed bytes scanned fresh) keys its seeds the same
 *      way and returns the identical set. */

#include "test/test_core.h"

#include "codeindex/codeindex.h"
#include "../../../cognition/modules/codeindex/src/codeindex_priv.h"
#include <sqlite3.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define SC_FIX "test-tmp/codeindex_static_callers"
#define SC_SRC "core/modules/net/src/"
#define SC_INC "core/modules/net/include/net/"
#define SC_OUT_CAP 64

static bool sc_write_in(const char *root, const char *rel, const char *content)
{
    char full[512];
    int n = snprintf(full, sizeof(full), "%s/%s", root, rel);
    if (n <= 0 || (size_t)n >= sizeof(full))
        return false;
    for (char *p = full + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            (void)mkdir(full, 0755);
            *p = '/';
        }
    }
    FILE *f = fopen(full, "wb");
    if (!f)
        return false;
    size_t len = strlen(content);
    bool ok = fwrite(content, 1, len, f) == len;
    return fclose(f) == 0 && ok;
}

static bool sc_write(const char *rel, const char *content)
{
    return sc_write_in(SC_FIX, rel, content);
}

static bool sc_write_fixture_two_tus(void)
{
    bool ok = true;
    /* 1: two TUs, one static name. */
    ok = ok && sc_write(SC_SRC "sc_x.c",
        "static int helper(void)\n{\n    return 1;\n}\n"
        "int sc_x_api(void)\n{\n    return helper();\n}\n");
    ok = ok && sc_write(SC_SRC "sc_y.c",
        "static int helper(void)\n{\n    return 2;\n}\n"
        "int sc_y_api(void)\n{\n    return helper();\n}\n");
    ok = ok && sc_write(SC_SRC "sc_x_user.c",
        "int sc_x_user(void)\n{\n    return sc_x_api();\n}\n");
    ok = ok && sc_write(SC_SRC "sc_y_user.c",
        "int sc_y_user(void)\n{\n    return sc_y_api();\n}\n");
    ok = ok && sc_write("build/obj/sc_y.d",
        "build/obj/sc_y.o: " SC_SRC "sc_y.c\n");
    /* Calls some OTHER helper (declared by its own header); its depfile
     * lists every input of its TU, and sc_x.c is not one of them. */
    ok = ok && sc_write(SC_INC "sc_ext.h", "int helper(void);\n");
    ok = ok && sc_write(SC_SRC "sc_ext.c",
        "#include \"net/sc_ext.h\"\n"
        "int sc_ext_fn(void)\n{\n    return helper();\n}\n");
    ok = ok && sc_write(SC_SRC "sc_ext_user.c",
        "int sc_ext_user(void)\n{\n    return sc_ext_fn();\n}\n");
    ok = ok && sc_write("build/obj/sc_ext.d",
        "build/obj/sc_ext.o: " SC_SRC "sc_ext.c " SC_INC "sc_ext.h\n");
    return ok;
}

static bool sc_write_fixture_reach(void)
{
    bool ok = true;
    /* 3: the ways a file other than sc_x.c CAN reach sc_x.c's helper. */
    ok = ok && sc_write(SC_SRC "sc_inc.c",
        "#include \"sc_x.c\"\n"
        "int sc_inc_fn(void)\n{\n    return helper() + 1;\n}\n");
    /* The same include with no depfile: nothing proves it away. */
    ok = ok && sc_write(SC_SRC "sc_inc2.c",
        "#include \"sc_x.c\"\n"
        "int sc_inc2_fn(void)\n{\n    return helper() + 2;\n}\n");
    ok = ok && sc_write(SC_SRC "sc_inc_user.c",
        "int sc_inc_user(void)\n{\n    return sc_inc_fn();\n}\n");
    ok = ok && sc_write(SC_INC "sc_x_inl.h",
        "static inline int sc_x_wrap(void)\n{\n    return helper();\n}\n");
    ok = ok && sc_write(SC_SRC "sc_alt.c",
        "#ifdef SC_ALT\n"
        "static int helper(void)\n{\n    return 3;\n}\n"
        "#else\n#include \"sc_x.c\"\n#endif\n"
        "int sc_alt_fn(void)\n{\n    return helper();\n}\n");
    ok = ok && sc_write("build/obj/sc_alt.d",
        "build/obj/sc_alt.o: " SC_SRC "sc_alt.c " SC_SRC "sc_x.c\n");
    ok = ok && sc_write("build/obj/sc_inc.d",
        "build/obj/sc_inc.o: " SC_SRC "sc_inc.c " SC_SRC "sc_x.c\n");
    return ok;
}

static bool sc_write_fixture_static_caller(void)
{
    bool ok = true;
    /* 2: a static caller discovered mid-walk. */
    ok = ok && sc_write(SC_SRC "sc_lib.c",
        "int sc_lib_fn(void)\n{\n    return 7;\n}\n");
    ok = ok && sc_write(SC_SRC "sc_p.c",
        "static int run(void)\n{\n    return sc_lib_fn();\n}\n"
        "int sc_p_api(void)\n{\n    return run();\n}\n");
    ok = ok && sc_write(SC_SRC "sc_q.c",
        "static int run(void)\n{\n    return 0;\n}\n"
        "int sc_q_api(void)\n{\n    return run();\n}\n");
    ok = ok && sc_write(SC_SRC "sc_p_user.c",
        "int sc_p_user(void)\n{\n    return sc_p_api();\n}\n");
    ok = ok && sc_write(SC_SRC "sc_q_user.c",
        "int sc_q_user(void)\n{\n    return sc_q_api();\n}\n");
    return ok;
}

static bool sc_write_fixture_static_inline(void)
{
    bool ok = true;
    /* 4: a static inline defined in a header. */
    ok = ok && sc_write(SC_INC "sc_inl.h",
        "#ifndef NET_SC_INL_H\n#define NET_SC_INL_H\n"
        "static inline int sc_hx(void)\n{\n    return 5;\n}\n#endif\n");
    ok = ok && sc_write(SC_SRC "sc_ha.c",
        "#include \"net/sc_inl.h\"\n"
        "int sc_ha_fn(void)\n{\n    return sc_hx();\n}\n");
    ok = ok && sc_write(SC_SRC "sc_hb.c",
        "#include \"net/sc_inl.h\"\n"
        "int sc_hb_fn(void)\n{\n    return sc_hx() + 1;\n}\n");
    ok = ok && sc_write(SC_SRC "sc_hc.c",
        "static int sc_hx(void)\n{\n    return 9;\n}\n"
        "int sc_hc_fn(void)\n{\n    return sc_hx();\n}\n");
    ok = ok && sc_write(SC_SRC "sc_hd.c",
        "int sc_hd_fn(void)\n{\n    return sc_ha_fn();\n}\n");
    ok = ok && sc_write("build/obj/sc_ha.d",
        "build/obj/sc_ha.o: " SC_SRC "sc_ha.c " SC_INC "sc_inl.h\n");
    ok = ok && sc_write("build/obj/sc_hb.d",
        "build/obj/sc_hb.o: " SC_SRC "sc_hb.c " SC_INC "sc_inl.h\n");
    return ok;
}

static bool sc_write_fixture_macro_includes(void)
{
    return sc_write(SC_SRC "sc_macro.c",
        "static int fdopen(int x) { return x; }\n"
        "#define fdopen(x) ((x) + 1)\nint sc_macro_user(void) { return fdopen(1); }\n") &&
        sc_write(SC_INC "sc_macro_other.h", "/* independent prerequisite */\n") &&
        sc_write(SC_SRC "sc_macro_other.c",
        "#include \"net/sc_macro_other.h\"\n"
        "int fdopen(int x) { return x; }\nint sc_macro_other(void) { return fdopen(2); }\n") &&
        sc_write("build/obj/sc_macro_other.d",
        "build/obj/sc_macro_other.o: " SC_SRC "sc_macro_other.c " SC_INC "sc_macro_other.h\n") &&
        sc_write(SC_SRC "sc_macro_inc.c",
        "#include \"sc_macro.c\"\nint sc_macro_inc(void) { return fdopen(3); }\n") &&
        sc_write("build/obj/sc_macro_inc.d",
        "build/obj/sc_macro_inc.o: " SC_SRC "sc_macro_inc.c " SC_SRC "sc_macro.c\n") &&
        sc_write(SC_SRC "sc_macro_unknown.c", "int sc_macro_unknown(void) { return fdopen(4); }\n") &&
        sc_write(SC_SRC "sc_macro_undef.c",
        "#include \"sc_macro.c\"\n#undef fdopen\n"
        "int sc_macro_undef(void) { return fdopen(5); }\n") &&
        sc_write("build/obj/sc_macro_undef.d",
        "build/obj/sc_macro_undef.o: " SC_SRC "sc_macro_undef.c " SC_SRC "sc_macro.c\n");
}
static bool sc_write_fixture_macro_other(void)
{
    return sc_write(SC_SRC "sc_macro_twin.c",
        "static int fdopen(int x) { return x; }\nint sc_macro_twin(void) { return fdopen(7); }\n") &&
        sc_write(SC_INC "sc_macro_fragment.h",
        "static inline int sc_macro_fragment(void) { return fdopen(8); }\n") &&
        sc_write(SC_INC "sc_macro_header.h", "#define sc_header_macro(x) ((x) + 1)\n") &&
        sc_write(SC_SRC "sc_macro_header_user.c",
        "int sc_macro_header_user(void) { return sc_header_macro(6); }\n") &&
        sc_write("build/obj/sc_macro_header_user.d",
        "build/obj/sc_macro_header_user.o: " SC_SRC "sc_macro_header_user.c\n");
}

static bool sc_write_fixture_decl(void)
{
    return sc_write(SC_INC "sc_decl_other.h", "/* independent */\n") &&
        sc_write(SC_SRC "sc_decl.c", "int sc_decl_target(void);\nint sc_decl_local(void) { return sc_decl_target(); }\n") &&
        sc_write(SC_SRC "sc_decl_parent.c", "int sc_decl_local(void);\nint sc_decl_parent(void) { return sc_decl_local(); }\n") &&
        sc_write(SC_SRC "sc_decl_other.c", "#include \"net/sc_decl_other.h\"\nint sc_decl_target(void);\nint sc_decl_other(void) { return sc_decl_target(); }\n") &&
        sc_write("build/obj/sc_decl_other.d", "build/obj/sc_decl_other.o: " SC_SRC "sc_decl_other.c " SC_INC "sc_decl_other.h\n") &&
        sc_write(SC_SRC "sc_decl_inc.c", "#include \"sc_decl.c\"\nint sc_decl_inc(void) { return sc_decl_target(); }\n") &&
        sc_write("build/obj/sc_decl_inc.d", "build/obj/sc_decl_inc.o: " SC_SRC "sc_decl_inc.c " SC_SRC "sc_decl.c\n") &&
        sc_write(SC_SRC "sc_decl_unknown.c", "int sc_decl_target(void);\nint sc_decl_unknown(void) { return sc_decl_target(); }\n") &&
        sc_write(SC_SRC "sc_decl_def.c", "int sc_decl_target(void) { return 1; }\n") &&
        sc_write(SC_INC "sc_decl_header.h", "int sc_decl_target(void);\n") &&
        sc_write(SC_SRC "sc_decl_mixed.c", "int sc_decl_target(void);\nint sc_decl_target(void) { return 1; }\n");
}

static bool sc_write_fixture(void)
{
    return sc_write_fixture_two_tus() &&
           sc_write_fixture_reach() &&
           sc_write_fixture_static_caller() &&
           sc_write_fixture_static_inline() &&
           sc_write_fixture_macro_includes() &&
           sc_write_fixture_macro_other() && sc_write_fixture_decl();
}

/* Run the store walk (or, with `overlay`, the fresh-bytes walk) for one
 * changed file and compare the result with `want`, a sorted NULL-terminated
 * list. Prints the first difference so a failure names the file. */
static bool sc_closure_is(struct codeindex *ci, const char *changed_path,
                          bool overlay, const char *const *want)
{
    char changed[1][256];
    snprintf(changed[0], sizeof(changed[0]), "%s", changed_path);
    char out[SC_OUT_CAP][256];
    bool truncated = true;
    int n = overlay
        ? codeindex_impact_closure_overlay(ci, SC_FIX, changed, 1, 0, out,
                                           SC_OUT_CAP, &truncated)
        : codeindex_impact_closure(ci, changed, 1, 0, out, SC_OUT_CAP,
                                   &truncated);
    int want_n = 0;
    while (want[want_n])
        want_n++;
    bool same = n == want_n && !truncated;
    for (int i = 0; same && i < n; i++)
        same = strcmp(out[i], want[i]) == 0;
    if (!same) {
        printf("\n    closure(%s%s) n=%d truncated=%d:", changed_path,
               overlay ? ", overlay" : "", n, truncated ? 1 : 0);
        for (int i = 0; i < n && i < SC_OUT_CAP; i++)
            printf(" %s", out[i]);
        printf("\n    want:");
        for (int i = 0; i < want_n; i++)
            printf(" %s", want[i]);
        printf("\n    ");
    }
    return same;
}

static bool sc_closure_has(struct codeindex *ci, const char *changed_path,
                           const char *needle, bool *has)
{
    char changed[1][256];
    snprintf(changed[0], sizeof(changed[0]), "%s", changed_path);
    char out[SC_OUT_CAP][256];
    bool truncated = true;
    int n = codeindex_impact_closure(ci, changed, 1, 0, out, SC_OUT_CAP,
                                     &truncated);
    *has = false;
    for (int i = 0; i < n; i++)
        if (strcmp(out[i], needle) == 0)
            *has = true;
    return n >= 0 && !truncated;
}

static bool sc_decl_has(struct codeindex *ci, const char *changed_path,
                        const char *needle, bool overlay, bool expected)
{
    char changed[1][256], out[SC_OUT_CAP][256];
    snprintf(changed[0], sizeof(changed[0]), "%s", changed_path);
    bool truncated = true, has = false;
    int n = overlay ? codeindex_impact_closure_overlay(ci, SC_FIX, changed, 1, 0, out, SC_OUT_CAP, &truncated)
                    : codeindex_impact_closure(ci, changed, 1, 0, out, SC_OUT_CAP, &truncated);
    for (int i = 0; i < n; ++i) if (!strcmp(out[i], needle)) has = true;
    if (n < 0 || truncated || has != expected)
        fprintf(stderr, "decl closure changed=%s needle=%s overlay=%d n=%d truncated=%d has=%d expected=%d\n",
                changed_path, needle, overlay, n, truncated, has, expected);
    return n >= 0 && !truncated && has == expected;
}

static bool sc_decl_graph(struct codeindex *ci)
{
    char paths[16][256];
    enum codeindex_include_dim dim = CODEINDEX_INCLUDE_DIM_UNAVAILABLE;
    int n = codeindex_includes_of_file(ci, SC_SRC "sc_decl_other.c", paths, 16);
    bool header = false, includer = false, other = false;
    for (int i = 0; i < n; ++i) if (!strcmp(paths[i], SC_INC "sc_decl_other.h")) header = true;
    n = codeindex_reverse_includes(ci, SC_SRC "sc_decl.c", paths, 16, &dim);
    for (int i = 0; i < n; ++i) {
        if (!strcmp(paths[i], SC_SRC "sc_decl_inc.c")) includer = true;
        if (!strcmp(paths[i], SC_SRC "sc_decl_other.c")) other = true;
    }
    return header && n >= 0 && includer && !other && dim == CODEINDEX_INCLUDE_DIM_COMPLETE;
}

static int test_sc_decl_scope(struct codeindex *ci)
{
    int failures = 0;
    TEST("codeindex_static_callers: C declaration seeds retain real users only") {
        ASSERT(sc_decl_graph(ci));
        for (int overlay = 0; overlay < 2; ++overlay) {
            ASSERT(sc_decl_has(ci, SC_SRC "sc_decl.c", SC_SRC "sc_decl.c", overlay, true));
            ASSERT(sc_decl_has(ci, SC_SRC "sc_decl.c", SC_SRC "sc_decl_parent.c", overlay, true));
            ASSERT(sc_decl_has(ci, SC_SRC "sc_decl.c", SC_SRC "sc_decl_inc.c", overlay, true));
            ASSERT(sc_decl_has(ci, SC_SRC "sc_decl.c", SC_SRC "sc_decl_unknown.c", overlay, true));
            ASSERT(sc_decl_has(ci, SC_SRC "sc_decl.c", SC_SRC "sc_decl_other.c", overlay, false));
            ASSERT(sc_decl_has(ci, SC_SRC "sc_decl_def.c", SC_SRC "sc_decl_other.c", overlay, true));
            ASSERT(sc_decl_has(ci, SC_INC "sc_decl_header.h", SC_SRC "sc_decl_other.c", overlay, true));
            ASSERT(sc_decl_has(ci, SC_SRC "sc_decl_mixed.c", SC_SRC "sc_decl_other.c", overlay, true));
        }
        PASS();
    } _test_next:;
    return failures;
}

static const char *const g_sc_x_want[] = {
    SC_INC "sc_x_inl.h",
    SC_SRC "sc_alt.c",
    SC_SRC "sc_inc.c",
    SC_SRC "sc_inc2.c",
    SC_SRC "sc_inc_user.c",
    SC_SRC "sc_x.c",
    SC_SRC "sc_x_user.c",
    NULL,
};

static int test_sc_two_tus_one_static_name(struct codeindex *ci)
{
    int failures = 0;
    TEST("codeindex_static_callers: editing one TU's static helper selects "
         "only that TU's callers") {
        ASSERT(sc_closure_is(ci, SC_SRC "sc_x.c", false, g_sc_x_want));
        bool has = true;
        ASSERT(sc_closure_has(ci, SC_SRC "sc_x.c", SC_SRC "sc_y.c", &has));
        ASSERT(!has);
        ASSERT(sc_closure_has(ci, SC_SRC "sc_x.c", SC_SRC "sc_y_user.c",
                              &has));
        ASSERT(!has);
        ASSERT(sc_closure_has(ci, SC_SRC "sc_x.c", SC_SRC "sc_ext.c", &has));
        ASSERT(!has);
        /* The other direction: sc_x.c defines its own helper and every
         * depfile-recorded TU lacks sc_y.c. The header inline body and the
         * depfile-less includer sc_inc2.c cannot be proven away, so they stay:
         * the rule drops only what it can prove. */
        static const char *const y_want[] = {
            SC_INC "sc_x_inl.h", SC_SRC "sc_inc2.c", SC_SRC "sc_y.c",
            SC_SRC "sc_y_user.c", NULL,
        };
        ASSERT(sc_closure_is(ci, SC_SRC "sc_y.c", false, y_want));
        PASS();
    } _test_next:;
    return failures;
}

static int test_sc_static_caller_keeps_its_file(struct codeindex *ci)
{
    int failures = 0;
    TEST("codeindex_static_callers: a static caller reached mid-walk climbs "
         "only in its own file") {
        static const char *const want[] = {
            SC_SRC "sc_lib.c", SC_SRC "sc_p.c", SC_SRC "sc_p_user.c", NULL,
        };
        ASSERT(sc_closure_is(ci, SC_SRC "sc_lib.c", false, want));
        PASS();
    } _test_next:;
    return failures;
}

static int test_sc_includers_never_dropped(struct codeindex *ci)
{
    int failures = 0;
    TEST("codeindex_static_callers: an includer, a header inline body and an "
         "#ifdef twin with a depfile edge stay selected") {
        bool has = false;
        ASSERT(sc_closure_has(ci, SC_SRC "sc_x.c", SC_SRC "sc_inc.c", &has));
        ASSERT(has);
        ASSERT(sc_closure_has(ci, SC_SRC "sc_x.c", SC_SRC "sc_inc_user.c",
                              &has));
        ASSERT(has);
        ASSERT(sc_closure_has(ci, SC_SRC "sc_x.c", SC_SRC "sc_inc2.c", &has));
        ASSERT(has);
        ASSERT(sc_closure_has(ci, SC_SRC "sc_x.c", SC_INC "sc_x_inl.h",
                              &has));
        ASSERT(has);
        ASSERT(sc_closure_has(ci, SC_SRC "sc_x.c", SC_SRC "sc_alt.c", &has));
        ASSERT(has);
        PASS();
    } _test_next:;
    return failures;
}

static int test_sc_header_static_inline_does_not_shrink(struct codeindex *ci)
{
    int failures = 0;
    TEST("codeindex_static_callers: a header static inline keeps every "
         "includer caller and the name walk") {
        /* sc_ha.c and sc_hb.c include the header and call it; sc_hd.c calls
         * sc_ha.c. sc_hc.c defines its own static sc_hx: the header case
         * deliberately stays on the name walk, so it is selected too. */
        static const char *const want[] = {
            SC_INC "sc_inl.h",
            SC_SRC "sc_ha.c",
            SC_SRC "sc_hb.c",
            SC_SRC "sc_hc.c",
            SC_SRC "sc_hd.c",
            NULL,
        };
        ASSERT(sc_closure_is(ci, SC_INC "sc_inl.h", false, want));
        PASS();
    } _test_next:;
    return failures;
}

static int test_sc_overlay_keys_seeds_the_same_way(struct codeindex *ci)
{
    int failures = 0;
    TEST("codeindex_static_callers: the overlay walk returns the identical "
         "file-scoped set") {
        ASSERT(sc_closure_is(ci, SC_SRC "sc_x.c", true, g_sc_x_want));
        PASS();
    } _test_next:;
    return failures;
}

static bool sc_macro_recorded_graph(struct codeindex *ci)
{
    char paths[16][256];
    int forward = codeindex_includes_of_file(ci, SC_SRC "sc_macro_other.c", paths, 16);
    bool header = false;
    for (int i = 0; i < forward && i < 16; ++i)
        if (!strcmp(paths[i], SC_INC "sc_macro_other.h")) header = true;
    enum codeindex_include_dim dim = CODEINDEX_INCLUDE_DIM_UNAVAILABLE;
    int reverse = codeindex_reverse_includes(ci, SC_SRC "sc_macro.c", paths, 16, &dim);
    bool includer = false;
    for (int i = 0; i < reverse && i < 16; ++i)
        if (!strcmp(paths[i], SC_SRC "sc_macro_inc.c")) includer = true;
    bool ok = forward > 0 && header && reverse >= 0 && includer && dim == CODEINDEX_INCLUDE_DIM_COMPLETE;
    if (!ok) fprintf(stderr, "macro graph forward=%d header=%d reverse=%d includer=%d dim=%d\n",
                     forward, header, reverse, includer, (int)dim);
    return ok;
}
static int test_sc_macro_scoping(struct codeindex *ci)
{
    int failures = 0;
    TEST("codeindex_static_callers: C macro scope retains real includers") {
        bool has = false;
        ASSERT(sc_macro_recorded_graph(ci));
        ASSERT(sc_closure_has(ci, SC_SRC "sc_macro.c", SC_SRC "sc_macro.c", &has) && has);
        ASSERT(sc_closure_has(ci, SC_SRC "sc_macro.c", SC_SRC "sc_macro_inc.c", &has) && has);
        ASSERT(sc_closure_has(ci, SC_SRC "sc_macro.c", SC_SRC "sc_macro_unknown.c", &has) && has);
        ASSERT(sc_closure_has(ci, SC_SRC "sc_macro.c", SC_SRC "sc_macro_undef.c", &has) && has);
        ASSERT(sc_closure_has(ci, SC_SRC "sc_macro.c", SC_SRC "sc_macro_twin.c", &has) && has);
        ASSERT(sc_closure_has(ci, SC_SRC "sc_macro.c", SC_INC "sc_macro_fragment.h", &has) && has);
        ASSERT(sc_closure_has(ci, SC_SRC "sc_macro.c", SC_SRC "sc_macro_other.c", &has) && !has);
        ASSERT(sc_closure_has(ci, SC_INC "sc_macro_header.h", SC_SRC "sc_macro_header_user.c", &has) && has);
        PASS();
    } _test_next:;
    return failures;
}

/* Work on a private in-memory copy; never modify the opened fixture index. */
static struct ci_store *sc_macro_copy_store(struct codeindex *ci)
{
    struct ci_store *store = ci_store_open_path(":memory:");
    if (!store) return NULL;
    sqlite3 *db = ci_store_db(store);
    sqlite3_backup *backup = sqlite3_backup_init(db, "main", ci_store_db(ci->store), "main");
    bool ok = backup && sqlite3_backup_step(backup, -1) == SQLITE_DONE;
    if (backup && sqlite3_backup_finish(backup) != SQLITE_OK) ok = false;
    if (!ok) { ci_store_close(store); return NULL; }
    return store;
}
static bool sc_macro_untrusted_setup(sqlite3 *db, unsigned mode)
{
    static const char *const sql[] = {
        "DELETE FROM meta WHERE k='include_narrow_unsafe'",
        "UPDATE meta SET v=x'31' WHERE k='include_narrow_unsafe'",
        "DELETE FROM includes",
        "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<4097) "
        "INSERT INTO files(path,\"group\",purpose,content_sha3,mtime,line_count) "
        "SELECT printf('macro-synthetic-%d.c',x),'','','',0,0 FROM n;"
        "INSERT INTO includes(file_id,dep_path) SELECT id,'" SC_SRC "sc_macro.c' "
        "FROM files WHERE path LIKE 'macro-synthetic-%.c'"
    };
    return mode < sizeof(sql) / sizeof(sql[0]) &&
           sqlite3_exec(db, sql[mode], NULL, NULL, NULL) == SQLITE_OK;
}
static bool sc_macro_untrusted_dim(struct codeindex *ci, unsigned mode,
                                   enum codeindex_include_dim *dim)
{
    char (*out)[256] = calloc(4096, sizeof(*out));
    if (!out) return false;
    int n = codeindex_reverse_includes(ci, SC_SRC "sc_macro.c", out, 4096, dim);
    free(out);
    return n >= 0 && *dim == (mode == 2 ? CODEINDEX_INCLUDE_DIM_UNAVAILABLE : CODEINDEX_INCLUDE_DIM_TRUNCATED);
}
/* Check the actual include verdict before checking conservative retention. */
static bool sc_macro_untrusted(struct codeindex *ci, unsigned mode)
{
    struct ci_store *store = sc_macro_copy_store(ci);
    if (!store) return false;
    bool ok = sc_macro_untrusted_setup(ci_store_db(store), mode);
    struct codeindex copy = *ci; copy.store = store;
    enum codeindex_include_dim dim = CODEINDEX_INCLUDE_DIM_COMPLETE;
    if (ok) ok = sc_macro_untrusted_dim(&copy, mode, &dim);
    bool has = false;
    if (ok) ok = sc_closure_has(&copy, SC_SRC "sc_macro.c", SC_SRC "sc_macro_other.c", &has) && has;
    ci_store_close(store);
    if (!ok) fprintf(stderr, "macro untrusted include mode=%u dim=%d retained=%d\n", mode, (int)dim, has);
    return ok;
}
static int test_sc_macro_untrusted(struct codeindex *ci)
{
    int failures = 0;
    TEST("codeindex_static_callers: incomplete macro include graphs retain callers") {
        bool ok = true;
        for (unsigned mode = 0; mode < 4; ++mode) ok = sc_macro_untrusted(ci, mode) && ok;
        ASSERT(ok);
        PASS();
    } _test_next:;
    return failures;
}

static bool sc_decl_untrusted(struct codeindex *ci, unsigned mode)
{
    struct ci_store *store = sc_macro_copy_store(ci);
    if (!store) return false;
    bool ok = sc_macro_untrusted_setup(ci_store_db(store), mode);
    struct codeindex copy = *ci;
    copy.store = store;
    char (*out)[256] = calloc(4096, sizeof(*out));
    enum codeindex_include_dim dim = CODEINDEX_INCLUDE_DIM_COMPLETE;
    if (!out) ok = false;
    if (ok) {
        int n = codeindex_reverse_includes(&copy, SC_SRC "sc_decl.c", out, 4096, &dim);
        ok = n < 0 || dim != CODEINDEX_INCLUDE_DIM_COMPLETE;
    }
    if (ok) ok = sc_decl_has(&copy, SC_SRC "sc_decl.c", SC_SRC "sc_decl_other.c", false, true);
    if (ok) ok = sc_decl_has(&copy, SC_SRC "sc_decl.c", SC_SRC "sc_decl_other.c", true, true);
    free(out);
    ci_store_close(store);
    return ok;
}

static int test_sc_decl_untrusted(struct codeindex *ci)
{
    int failures = 0;
    TEST("codeindex_static_callers: untrusted declaration include graphs retain callers") {
        for (unsigned mode = 0; mode < 3; ++mode) ASSERT(sc_decl_untrusted(ci, mode));
        PASS();
    } _test_next:;
    return failures;
}

static bool sc_decl_invalid(struct codeindex *ci, unsigned mode)
{
    struct ci_store *store = sc_macro_copy_store(ci);
    if (!store) return false;
    struct codeindex copy = *ci; copy.store = store;
    struct ci_symbol rows[32];
    int n = ci_store_symbols_in_file(store, SC_SRC "sc_decl.c", rows, 32);
    bool ok = false;
    for (int i = 0; i < n; ++i) {
        if (strcmp(rows[i].name, "sc_decl_target")) continue;
        sqlite3 *db = ci_store_db(store);
        ok = sqlite3_exec(db, "DELETE FROM symbols WHERE name='sc_decl_target' AND decl_path='" SC_SRC "sc_decl.c'", NULL, NULL, NULL) == SQLITE_OK;
        if (mode == 0) rows[i].partial = true;
        if (mode == 1) rows[i].decl_line = 0;
        if (mode == 2) rows[i].def_line = 1;
        if (mode == 3) rows[i].def_line = -1;
        ok = ok && ci_store_put_symbol(store, &rows[i]);
        if (ok) ok = sc_decl_has(&copy, SC_SRC "sc_decl.c", SC_SRC "sc_decl_other.c", false, true);
        break;
    }
    ci_store_close(store);
    return ok;
}

static int test_sc_decl_invalid(struct codeindex *ci)
{
    int failures = 0;
    TEST("codeindex_static_callers: incomplete declaration rows stay global") {
        for (unsigned mode = 0; mode < 4; ++mode) ASSERT(sc_decl_invalid(ci, mode));
        PASS();
    } _test_next:;
    return failures;
}

static int test_sc_cause_labels(void)
{
    int failures = 0;
    TEST("codeindex_static_callers: cause tokens are stable and total") {
        static const char *const labels[] = {
            "none", "file_set_capacity", "queue_symbol_capacity",
            "seed_query_saturated", "seed_symbol_capacity",
            "caller_query_saturated", "caller_symbol_capacity",
            "output_path_capacity", "output_format_error", "output_row_capacity"
        };
        for (size_t i = 0; i < sizeof(labels) / sizeof(labels[0]); i++)
            ASSERT(strcmp(codeindex_impact_cause_label((enum ci_impact_cause_reason)i), labels[i]) == 0);
        ASSERT(strcmp(codeindex_impact_cause_label((enum ci_impact_cause_reason)-1), "unknown") == 0);
        ASSERT(strcmp(codeindex_impact_cause_label((enum ci_impact_cause_reason)10), "unknown") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_sc_cause_value(void)
{
    int failures = 0;
    TEST("codeindex_static_callers: cause reset and bounded identity copies") {
        struct ci_impact_cause cause, zero; memset(&zero, 0, sizeof(zero));
        char path[257], node[401];
        memset(&cause, 0xff, sizeof(cause));
        codeindex_impact_cause_reset(&cause);
        ASSERT(memcmp(&cause, &zero, sizeof(cause)) == 0);
        codeindex_impact_cause_reset(NULL);
        memset(path, 'p', sizeof(path) - 1); path[256] = '\0';
        memset(node, 'n', sizeof(node) - 1); node[400] = '\0';
        codeindex_test_impact_cause_identity(&cause, path, node);
        ASSERT(cause.path_known && cause.path_truncated && cause.node_truncated);
        ASSERT(strlen(cause.path) == 255 && strlen(cause.node) == 399);
        ASSERT(strncmp(cause.path, path, 255) == 0 && strncmp(cause.node, node, 399) == 0);
        path[255] = '\0'; node[399] = '\0';
        codeindex_test_impact_cause_identity(&cause, path, node);
        ASSERT(cause.path_known && !cause.path_truncated && !cause.node_truncated);
        ASSERT(strcmp(cause.path, path) == 0 && strcmp(cause.node, node) == 0);
        codeindex_test_impact_cause_identity(&cause, NULL, NULL);
        ASSERT(memcmp(&cause, &zero, sizeof(cause)) == 0);
        PASS();
    } _test_next:;
    return failures;
}


/* ── forward closure binds a called name to EVERY definition ──────────────
 * `seed_fn` calls bv(). bv is defined external in a_low.c and in b_high.c
 * (each calling its own dep), and as a static, on a LOWER line than both, in
 * c_stat.c. Binding the call to the single lowest-line row would keep only
 * c_stat.c and drop the real callees' files: a stale PASS. */
#define SC_FWD_FIX "test-tmp/codeindex_forward_all_defs"
#define SC_FWD_WANT_N 6

static bool sc_fwd_write(const char *rel, const char *content)
{
    return sc_write_in(SC_FWD_FIX, rel, content);
}

static bool sc_fwd_fixture(void)
{
    bool ok = true;
    ok = ok && sc_fwd_write(SC_SRC "seed.c", "int seed_fn(void)\n{\n    return bv();\n}\n");
    ok = ok && sc_fwd_write(SC_SRC "c_stat.c", "static int bv(void) { return 1; }\n");
    ok = ok && sc_fwd_write(SC_SRC "a_low.c",
        "/* pad */\n/* pad */\n\nint bv(void)\n{\n    return a_dep();\n}\n");
    ok = ok && sc_fwd_write(SC_SRC "b_high.c",
        "/* pad */\n/* pad */\n/* pad */\n/* pad */\n\nint bv(void)\n{\n"
        "    return b_dep();\n}\n");
    ok = ok && sc_fwd_write(SC_SRC "a_dep.c", "int a_dep(void)\n{\n    return 2;\n}\n");
    ok = ok && sc_fwd_write(SC_SRC "b_dep.c", "int b_dep(void)\n{\n    return 3;\n}\n");
    return ok;
}

static bool sc_fwd_has(char (*out)[256], int n, const char *path)
{
    for (int i = 0; i < n; i++)
        if (strcmp(out[i], path) == 0)
            return true;
    return false;
}

static int test_sc_forward_closure_all_definitions(void)
{
    int failures = 0;
    TEST("codeindex_static_callers: forward closure keeps every definition of a called name") {
        TEST_DISCARD(system("rm -rf " SC_FWD_FIX));
        ASSERT(sc_fwd_fixture());
        struct codeindex *ci = codeindex_open(SC_FWD_FIX);
        ASSERT(ci != NULL);
        char out[SC_OUT_CAP][256];
        bool truncated = true, root_found = false;
        int n = codeindex_forward_closure(ci, "seed_fn", out, SC_OUT_CAP,
                                          &truncated, &root_found);
        const char *want[SC_FWD_WANT_N] = { SC_SRC "seed.c", SC_SRC "c_stat.c", SC_SRC "a_low.c",
                                            SC_SRC "b_high.c", SC_SRC "a_dep.c", SC_SRC "b_dep.c" };
        bool all = n >= 0 && root_found && !truncated;
        for (int i = 0; i < SC_FWD_WANT_N; i++) {
            bool has = all && sc_fwd_has(out, n, want[i]);
            if (!has)
                printf("\n    forward closure missing %s (n=%d)\n    ", want[i], n);
            all = all && has;
        }
        codeindex_close(ci);
        ASSERT(all);
        PASS();
    } _test_next:;
    TEST_DISCARD(system("rm -rf " SC_FWD_FIX));
    return failures;
}

static int test_sc_caller_edge_query(void)
{
    int failures = 0;
    TEST("codeindex_static_callers: edge query preserves identities and fails closed") {
        struct ci_store *s = ci_store_open_path(":memory:");
        ASSERT(s != NULL);
        sqlite3 *db = ci_store_db(s);
        ASSERT_EQ(sqlite3_exec(db,
            "DROP TABLE refs; CREATE TABLE refs (callee_name TEXT, ref_file TEXT, ref_line INTEGER, enclosing TEXT);"
            "INSERT INTO refs VALUES ('f','a.c',1,'run'),('f','a.c',2,'run'),"
            "('f','a.c',3,'other'),('f','b.c',4,'run'),"
            "('f','c.h',5,NULL),('f','c.h',6,'');",
            NULL, NULL, NULL), SQLITE_OK);
        struct ci_ref rows[8];
        int n = ci_store_caller_edges(s, "f", rows, 8);
        ASSERT_EQ(n, 4);
        ASSERT_STR_EQ(rows[0].ref_file, "a.c");
        ASSERT_STR_EQ(rows[0].enclosing, "run");
        ASSERT_EQ(rows[0].ref_line, 1);
        ASSERT_STR_EQ(rows[1].enclosing, "other");
        ASSERT_STR_EQ(rows[2].ref_file, "b.c");
        ASSERT_STR_EQ(rows[2].enclosing, "run");
        ASSERT_STR_EQ(rows[3].ref_file, "c.h");
        ASSERT_STR_EQ(rows[3].enclosing, "");
        ASSERT_EQ(sqlite3_exec(db, "INSERT INTO refs VALUES ('g',NULL,1,''),('g','',2,NULL)",
            NULL, NULL, NULL), SQLITE_OK);
        ASSERT(ci_store_caller_edges(s, "g", rows, 8) < 0);
        ASSERT_EQ(sqlite3_exec(db,
            "INSERT INTO refs VALUES ('long',printf('%0300d',0),1,'f'),"
            "('nul','a'||char(0)||'b',1,'f');", NULL, NULL, NULL), SQLITE_OK);
        ASSERT(ci_store_caller_edges(s, "long", rows, 8) < 0);
        ASSERT(ci_store_caller_edges(s, "nul", rows, 8) < 0);
        ASSERT_EQ(sqlite3_exec(db, "INSERT INTO refs VALUES ('blob',x'6162',1,'f')", NULL, NULL, NULL), SQLITE_OK);
        ASSERT(ci_store_caller_edges(s, "blob", rows, 8) < 0);
        struct ci_symbol sym = {0};
        snprintf(sym.name, sizeof(sym.name), "f");
        snprintf(sym.def_path, sizeof(sym.def_path), "a.c");
        sym.kind = 0x54;
        ASSERT(ci_store_put_symbol(s, &sym));
        ASSERT_EQ(sqlite3_exec(db, "DROP TABLE refs", NULL, NULL, NULL), SQLITE_OK);
        ASSERT(ci_store_caller_edges(s, "f", rows, 8) < 0);
        struct codeindex ci = { .store = s };
        const char changed[1][256] = {"a.c"};
        char out[8][256];
        bool truncated = false;
        ASSERT(codeindex_impact_closure(&ci, changed, 1, 0, out, 8, &truncated) < 0);
        ci_store_close(s);
        PASS();
    } _test_next:;
    return failures;
}

static bool sc_exact_put(struct ci_store *s, const char *name, char kind,
                         const char *def, const char *decl)
{
    struct ci_symbol sym = {0};
    snprintf(sym.name, sizeof(sym.name), "%s", name);
    snprintf(sym.def_path, sizeof(sym.def_path), "%s", def);
    snprintf(sym.decl_path, sizeof(sym.decl_path), "%s", decl);
    sym.kind = kind;
    sym.def_line = *def ? 1 : 0;
    sym.decl_line = *decl ? 1 : 0;
    return ci_store_put_symbol(s, &sym);
}

static bool sc_exact_order(const struct ci_symbol *rows)
{
    return rows[0].kind == 'T' && !strcmp(rows[0].def_path, "a.c") &&
           rows[1].kind == 't' && !strcmp(rows[1].def_path, "b.c") &&
           !rows[2].def_path[0] && !strcmp(rows[2].decl_path, "api.h");
}

static bool sc_exact_cases(struct codeindex *ci)
{
    struct ci_symbol rows[4]; int n = -1;
    if (codeindex_find_exact_checked(ci, "missing", rows, 4, &n) != CODEINDEX_EXACT_COMPLETE || n != 0) return false;
    if (codeindex_find_exact_checked(ci, "single", rows, 4, &n) != CODEINDEX_EXACT_COMPLETE || n != 1 || strcmp(rows[0].def_path, "only.c")) return false;
    if (codeindex_find_exact_checked(ci, "shared", rows, 3, &n) != CODEINDEX_EXACT_COMPLETE || n != 3) return false;
    if (!sc_exact_order(rows)) return false;
    n = -1;
    if (codeindex_find_exact_checked(ci, "shared", rows, 2, &n) != CODEINDEX_EXACT_TRUNCATED || n != 0) return false;
    n = -1;
    return codeindex_find_exact_checked(ci, "shared", rows, 0, &n) == CODEINDEX_EXACT_ERROR && n == 0;
}

struct sc_exact_interrupt { sqlite3 *db; int rows, requests; };
static int sc_exact_trace(unsigned kind, void *ctx, void *stmt, void *detail)
{
    (void)detail;
    struct sc_exact_interrupt *f = ctx;
    const char *sql = sqlite3_sql(stmt);
    if (kind == SQLITE_TRACE_ROW && sql && strstr(sql, "FROM symbols WHERE name=?") && ++f->rows == 1) {
        ++f->requests;
        sqlite3_interrupt(f->db);
    }
    return 0;
}

static bool sc_exact_step_error(struct codeindex *ci)
{
    sqlite3 *db = ci_store_db(ci->store);
    struct sc_exact_interrupt f = {.db = db};
    if (sqlite3_trace_v2(db, SQLITE_TRACE_ROW, sc_exact_trace, &f) != SQLITE_OK) return false;
    struct ci_symbol rows[4]; int n = -1;
    enum codeindex_exact_status status = codeindex_find_exact_checked(ci, "shared", rows, 4, &n);
    bool cleared = sqlite3_trace_v2(db, 0, NULL, NULL) == SQLITE_OK;
    if (!cleared || f.rows < 1 || f.requests != 1 || status != CODEINDEX_EXACT_ERROR || n != 0)
        fprintf(stderr, "checked exact step: rows=%d interrupts=%d status=%d count=%d\n", f.rows, f.requests, status, n);
    return cleared && f.rows >= 1 && f.requests == 1 && status == CODEINDEX_EXACT_ERROR && n == 0;
}

static bool sc_exact_corrupt(struct codeindex *ci)
{
    sqlite3 *db = ci_store_db(ci->store);
    if (sqlite3_exec(db, "UPDATE symbols SET row_sha3=zeroblob(32) WHERE name='shared' AND decl_path='api.h'", NULL, NULL, NULL) != SQLITE_OK) return false;
    struct ci_symbol rows[4]; int n = -1;
    enum codeindex_exact_status status = codeindex_find_exact_checked(ci, "shared", rows, 2, &n);
    if (status != CODEINDEX_EXACT_CORRUPT || n != 0)
        fprintf(stderr, "checked exact corrupt sentinel: status=%d count=%d\n", status, n);
    return status == CODEINDEX_EXACT_CORRUPT && n == 0;
}

static int test_sc_exact_checked(void)
{
    int failures = 0;
    TEST("codeindex_static_callers: exact enumeration refuses incomplete evidence") {
        struct ci_store *store = ci_store_open_path(":memory:");
        ASSERT(store != NULL);
        struct codeindex ci = {.store = store};
        bool seeded = sc_exact_put(store, "single", 'T', "only.c", "") &&
            sc_exact_put(store, "shared", 'T', "a.c", "") &&
            sc_exact_put(store, "shared", 't', "b.c", "") &&
            sc_exact_put(store, "shared", 'T', "", "api.h");
        bool cases = seeded && sc_exact_cases(&ci);
        bool step = seeded && sc_exact_step_error(&ci);
        bool corrupt = seeded && sc_exact_corrupt(&ci);
        ci_store_close(store);
        ASSERT(cases && step && corrupt);
        PASS();
    } _test_next:;
    return failures;
}

int test_codeindex_static_callers(void)
{
    int failures = test_sc_cause_labels() + test_sc_cause_value();
    failures += test_sc_caller_edge_query();
    failures += test_sc_exact_checked();
    struct codeindex *ci = NULL;
    TEST("codeindex_static_callers: fixture tree indexes") {
         TEST_DISCARD(system("rm -rf " SC_FIX));
        ASSERT(sc_write_fixture());
        ci = codeindex_open(SC_FIX);
        ASSERT(ci != NULL);
        PASS();
    } _test_next:;
    if (ci) {
        failures += test_sc_two_tus_one_static_name(ci);
        failures += test_sc_static_caller_keeps_its_file(ci);
        failures += test_sc_includers_never_dropped(ci);
        failures += test_sc_header_static_inline_does_not_shrink(ci);
        failures += test_sc_overlay_keys_seeds_the_same_way(ci);
        failures += test_sc_macro_scoping(ci);
        failures += test_sc_macro_untrusted(ci);
        failures += test_sc_decl_scope(ci);
        failures += test_sc_decl_untrusted(ci);
        failures += test_sc_decl_invalid(ci);
        codeindex_close(ci);
    }
     TEST_DISCARD(system("rm -rf " SC_FIX));
    failures += test_sc_forward_closure_all_definitions();
    return failures;
}
