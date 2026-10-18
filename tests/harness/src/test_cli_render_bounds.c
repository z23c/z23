/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private emitter regressions belong to the registered cli_render group.
 * Compile the implementation with renamed public entries so the tests can
 * exercise internal bounds without extending the production interface. */
#include "test/test_core.h"
#define zcl_cli_render_resolve cr_bounds_resolve
#define zcl_cli_render_doc cr_bounds_doc
#define zcl_cli_render_brief cr_bounds_brief
#define zcl_cli_render_start_hint cr_bounds_start_hint
#include "../../../tools/command/cli_render.c"
#undef zcl_cli_render_resolve
#undef zcl_cli_render_doc
#undef zcl_cli_render_brief
#undef zcl_cli_render_start_hint

static int test_command_key_bound(void)
{
    int failures = 0;
    TEST("command key: truncate before writing the terminator") {
        char key[80], out[256] = {0};
        memset(key, 'k', sizeof(key) - 1);
        key[sizeof(key) - 1] = '\0';
        struct buf b = {.p = out, .cap = sizeof(out)};
        struct zcl_cli_render_env e = {.width = 240};
        emit_kv_command_n(&b, &e, 6, key, "value", 5);
        ASSERT(!b.overflow);
        ASSERT(b.len == 73);
        ASSERT(strcmp(out + 65, "  value\n") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_table_header_bound(void)
{
    int failures = 0;
    TEST("table header: clamp the would-be length before padding") {
        char header[90], out[256] = {0};
        memset(header, 'h', sizeof(header) - 1);
        header[sizeof(header) - 1] = '\0';
        const char *headers[] = {header, "END"};
        struct buf b = {.p = out, .cap = sizeof(out)};
        struct zcl_cli_render_env e = {.width = 240};
        emit_table(&b, &e, 2, headers, NULL, 0);
        ASSERT(!b.overflow);
        ASSERT(b.len == 71);
        ASSERT(strcmp(out + 65, "  END\n") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_table_column_bound(void)
{
    int failures = 0;
    TEST("table columns: cap at eight without changing row stride") {
        const char *headers[] = {"A", "B", "C", "D", "E", "F", "G", "H", "I"};
        const char *cells[] = {
            "a", "b", "c", "d", "e", "f", "g", "h", "omitted",
            "j", "k", "l", "m", "n", "o", "p", "q", "omitted"
        };
        char out[256] = {0};
        struct buf b = {.p = out, .cap = sizeof(out)};
        struct zcl_cli_render_env e = {.width = 240};
        emit_table(&b, &e, 9, headers, cells, 2);
        ASSERT(!b.overflow);
        ASSERT(strcmp(out, "  A  B  C  D  E  F  G  H\n"
                           "  a  b  c  d  e  f  g  h\n"
                           "  j  k  l  m  n  o  p  q\n") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_trunc_sequence_bound(void)
{
    int failures = 0;
    TEST("truncation sequence: stop at NUL before copying") {
        /* The first malformed sequence consumes three ASCII bytes. This
         * reaches the partial tail while truncation still has budget.
         * Sentinels keep a restored faulty copy inside defined storage;
         * the embedded NUL and extra bytes then fail output assertions. */
        const char partial[] = {(char)0xf0, 'A', 'B', 'C',
                                (char)0xf0, (char)0x80, 0, 'X', 'Y', 0};
        char out[32] = {0};
        struct buf b = {.p = out, .cap = sizeof(out)};
        ASSERT(buf_puts_trunc(&b, partial, 4) == 4);
        ASSERT(!b.overflow);
        ASSERT(b.len == 9);
        ASSERT(memcmp(out, partial, 6) == 0);
        ASSERT(strcmp(out + 6, "…") == 0);
        PASS();
    } _test_next:;
    return failures;
}

int cli_render_bounds_cases(void)
{
    return test_command_key_bound() + test_table_header_bound() +
           test_table_column_bound() + test_trunc_sequence_bound();
}
