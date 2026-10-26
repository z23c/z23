/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zslot born-red suite. Exits nonzero if any check fails. */

#include "zslot/zslot.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

static int failures;

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

static unsigned char store[4096];

static void test_init(void)
{
    zslot t;
    CHECK(zslot_storage_bytes(4, 4) >= 4u * 16u);
    CHECK(zslot_storage_bytes(0, 4) == 0);
    CHECK(!zslot_init(NULL, store, sizeof(store), 4));
    CHECK(!zslot_init(&t, NULL, sizeof(store), 4));
    CHECK(!zslot_init(&t, store, 7, 4));
    CHECK(zslot_init(&t, store, sizeof(store), sizeof(uint32_t)));
    CHECK(zslot_cap(&t) >= 1);
    CHECK(zslot_live(&t) == 0);
    CHECK(zslot_live(NULL) == 0);
    CHECK(zslot_cap(NULL) == 0);
}

static void test_insert_get_remove(void)
{
    zslot t;
    CHECK(zslot_init(&t, store, sizeof(store), sizeof(uint32_t)));
    uint32_t a = 11, b = 22, c = 33;
    zslot_id ia = zslot_insert(&t, &a);
    zslot_id ib = zslot_insert(&t, &b);
    zslot_id ic = zslot_insert(&t, &c);
    CHECK(ia != ZSLOT_INVALID && ib != ZSLOT_INVALID && ic != ZSLOT_INVALID);
    CHECK(ia != ib && ib != ic && ia != ic);
    CHECK(zslot_live(&t) == 3);
    CHECK(zslot_id_generation(ia) == 1);
    CHECK(*((uint32_t *)zslot_get(&t, ia)) == 11);
    CHECK(*((uint32_t *)zslot_get(&t, ib)) == 22);
    CHECK(*((const uint32_t *)zslot_get_const(&t, ic)) == 33);
    CHECK(zslot_contains(&t, ia));
    CHECK(zslot_remove(&t, ib));
    CHECK(!zslot_contains(&t, ib));
    CHECK(zslot_get(&t, ib) == NULL);
    CHECK(zslot_live(&t) == 2);
    CHECK(!zslot_remove(&t, ib)); /* double-remove */
    CHECK(*((uint32_t *)zslot_get(&t, ia)) == 11);
    CHECK(*((uint32_t *)zslot_get(&t, ic)) == 33);
}

static void test_stale_and_reuse(void)
{
    zslot t;
    CHECK(zslot_init(&t, store, sizeof(store), sizeof(uint32_t)));
    uint32_t v = 7;
    zslot_id id = zslot_insert(&t, &v);
    uint32_t idx = zslot_id_index(id);
    CHECK(zslot_remove(&t, id));
    uint32_t w = 8;
    zslot_id id2 = zslot_insert(&t, &w);
    CHECK(id2 != ZSLOT_INVALID);
    CHECK(zslot_id_index(id2) == idx);
    CHECK(zslot_id_generation(id2) == zslot_id_generation(id) + 2);
    CHECK(zslot_get(&t, id) == NULL); /* stale generation */
    CHECK(*((uint32_t *)zslot_get(&t, id2)) == 8);
}

static void test_exhaust_and_null(void)
{
    unsigned char tiny[64];
    zslot t;
    CHECK(zslot_init(&t, tiny, sizeof(tiny), sizeof(uint32_t)));
    uint32_t cap = zslot_cap(&t);
    CHECK(cap >= 1 && cap <= 8);
    zslot_id ids[8];
    uint32_t val = 1;
    uint32_t n = 0;
    for (; n < cap; n++) {
        val = n + 1;
        ids[n] = zslot_insert(&t, &val);
        CHECK(ids[n] != ZSLOT_INVALID);
    }
    CHECK(zslot_insert(&t, &val) == ZSLOT_INVALID);
    CHECK(zslot_live(&t) == cap);
    CHECK(zslot_insert(NULL, &val) == ZSLOT_INVALID);
    CHECK(zslot_insert(&t, NULL) == ZSLOT_INVALID);
    CHECK(!zslot_remove(NULL, ids[0]));
    CHECK(!zslot_remove(&t, ZSLOT_INVALID));
    CHECK(!zslot_remove(&t, ((zslot_id)1 << 32) | 999u));
    CHECK(zslot_get(NULL, ids[0]) == NULL);
    CHECK(zslot_contains(NULL, ids[0]) == false);
}

static uint32_t visit_sum;
static uint32_t visit_n;

static void visit_add(zslot_id id, void *value, void *ctx)
{
    (void)id;
    (void)ctx;
    visit_n++;
    visit_sum += *(uint32_t *)value;
}

static void test_each(void)
{
    zslot t;
    CHECK(zslot_init(&t, store, sizeof(store), sizeof(uint32_t)));
    uint32_t a = 1, b = 2, c = 4;
    zslot_id ia = zslot_insert(&t, &a);
    zslot_id ib = zslot_insert(&t, &b);
    zslot_id ic = zslot_insert(&t, &c);
    CHECK(zslot_remove(&t, ib));
    visit_sum = 0;
    visit_n = 0;
    uint32_t n = zslot_each(&t, visit_add, NULL);
    CHECK(n == 2 && visit_n == 2 && visit_sum == 5);
    CHECK(zslot_each(NULL, visit_add, NULL) == 0);
    CHECK(zslot_each(&t, NULL, NULL) == 2);
    (void)ia;
    (void)ic;
}

static void test_zero_size_tokens(void)
{
    zslot t;
    CHECK(zslot_init(&t, store, sizeof(store), 0));
    zslot_id a = zslot_insert(&t, NULL);
    zslot_id b = zslot_insert(&t, NULL);
    CHECK(a != ZSLOT_INVALID && b != ZSLOT_INVALID && a != b);
    CHECK(zslot_contains(&t, a) && zslot_contains(&t, b));
    CHECK(zslot_get(&t, a) != NULL);
    CHECK(zslot_remove(&t, a));
    CHECK(!zslot_contains(&t, a));
    CHECK(zslot_contains(&t, b));
}

static void test_independent_payloads(void)
{
    zslot t;
    CHECK(zslot_init(&t, store, sizeof(store), 8));
    unsigned char x[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    unsigned char y[8] = {8, 7, 6, 5, 4, 3, 2, 1};
    zslot_id ix = zslot_insert(&t, x);
    zslot_id iy = zslot_insert(&t, y);
    CHECK(memcmp(zslot_get(&t, ix), x, 8) == 0);
    CHECK(memcmp(zslot_get(&t, iy), y, 8) == 0);
    memset(zslot_get(&t, ix), 0xAA, 8);
    CHECK(memcmp(zslot_get(&t, iy), y, 8) == 0);
}

static void test_cli(void);

int main(void)
{
    test_cli();
    test_init();
    test_insert_get_remove();
    test_stale_and_reuse();
    test_exhaust_and_null();
    test_each();
    test_zero_size_tokens();
    test_independent_payloads();
    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    puts("zslot: all tests passed");
    return 0;
}

static FILE *cli_source, *cli_sink, *cli_errors, *cli_failure_sink;
static size_t cli_flushes, cli_writes, cli_fail_write;
static bool cli_read_fault, cli_stale_errno;
static FILE *real_stdin(void) { return stdin; }
static FILE *real_stdout(void) { return stdout; }
static FILE *real_stderr(void) { return stderr; }
static FILE *cli_output(void) {
    cli_writes++;
    if (cli_fail_write && cli_writes >= cli_fail_write) cli_sink = cli_failure_sink;
    return cli_sink;
}
[[maybe_unused]] static int cli_flush(FILE *stream) {
    if (stream == cli_sink) cli_flushes++;
    return fflush(stream);
}
[[maybe_unused]] static int cli_error(FILE *stream) {
    return (stream == cli_source && cli_read_fault) || ferror(stream);
}
#undef stdin
#undef stdout
#undef stderr
#define stdin cli_source
#define stdout cli_sink
#define stderr cli_errors
#define printf(...) fprintf(cli_output(), __VA_ARGS__)
#define puts(text) fprintf(cli_output(), "%s\n", (text))
#define fflush cli_flush
#define ferror cli_error
#define store embedded_store
#define main embedded_cli_main
#include "../app/main.c"
#undef main
#undef store
#undef ferror
#undef fflush
#undef puts
#undef printf
#undef stdin
#undef stdout
#undef stderr
#define stdin real_stdin()
#define stdout real_stdout()
#define stderr real_stderr()

static FILE *required_stream(FILE *stream) {
    if (!stream) { fprintf(stderr, "zslot CLI fixture setup failed\n"); exit(2); }
    return stream;
}
static FILE *cli_input(const char *text) {
    FILE *source = required_stream(tmpfile());
    if (fputs(text, source) < 0 || fflush(source) != 0) exit(2);
    rewind(source);
    return source;
}
static int cli_invoke(FILE *source, FILE *sink, FILE *errors, const char *arg) {
    cli_source = source;
    cli_sink = sink;
    cli_errors = errors;
    cli_writes = cli_flushes = 0;
    char *args[] = {"zslot", (char *)arg, NULL};
    if (cli_stale_errno) errno = ERANGE;
    int rc = embedded_cli_main(arg ? 2 : 1, args);
    cli_source = stdin;
    cli_sink = stdout;
    cli_errors = stderr;
    return rc;
}
static void cli_bytes(FILE *stream, const char *want) {
    char bytes[1024];
    rewind(stream);
    size_t n = fread(bytes, 1, sizeof bytes, stream);
    if (n != strlen(want) || memcmp(bytes, want, n) != 0)
        fprintf(stderr, "CLI bytes expected=%s actual=%.*s\n", want, (int)n, bytes);
    CHECK(!ferror(stream) && n == strlen(want) && !memcmp(bytes, want, n));
}
static void cli_case(const char *cap, const char *ops, int status, const char *want) {
    FILE *source = cli_input(ops), *sink = required_stream(tmpfile());
    FILE *errors = required_stream(tmpfile());
    CHECK(cli_invoke(source, sink, errors, cap) == status);
    if (!*want) CHECK(cli_flushes == 0);
    cli_bytes(sink, want);
    CHECK(fclose(source) == 0 && fclose(sink) == 0 && fclose(errors) == 0);
}
static void cli_bad_field(const char *text, char op) {
    char ops[256];
    int n = snprintf(ops, sizeof ops, "n\n%c %s\n", op, text);
    if (n < 0 || (size_t)n >= sizeof ops) exit(2);
    cli_case("2", ops, 2, "n -> live 0/2\n");
}
static void cli_numeric_errors(void) {
    const char *bad[] = {"", " \t", "junk!", "1junk", "1 ", "-1",
        "999999999999999999999999999999999999"};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        cli_case(bad[i], "", 2, "");
        cli_bad_field(bad[i], 'i');
        cli_bad_field(bad[i], 'g');
        cli_bad_field(bad[i], 'r');
    }
    char negative_ulong[64], negative_hex[64];
    snprintf(negative_ulong, sizeof negative_ulong, "-%lu", ULONG_MAX);
    snprintf(negative_hex, sizeof negative_hex, "-%llx", ULLONG_MAX);
    cli_case(negative_ulong, "", 2, "");
    cli_bad_field(negative_ulong, 'i');
    cli_bad_field(negative_hex, 'g');
    cli_bad_field(negative_hex, 'r');
    cli_bad_field("4294967296", 'i');
    cli_bad_field("10000000000000000", 'g');
    cli_bad_field("10000000000000000", 'r');
    cli_case("0", "", 2, "");
    cli_case("257", "", 2, "");
}
static void cli_normal(void) {
    cli_stale_errno = true;
    cli_case(" \t+1", "i 4294967295\ng +0x100000000\nr 100000000\ng 100000000\ni -0\nn\n", 0,
        "i 4294967295 -> 0000000100000000\ng 0000000100000000 -> 4294967295\nr 0000000100000000 -> ok\ng 0000000100000000 -> MISS\ni 0 -> 0000000300000000\nn -> live 1/1\n");
    cli_stale_errno = false;
    cli_case("1", "g -0\nr 0\ng ffffffffffffffff\n", 0,
        "g 0000000000000000 -> MISS\nr 0000000000000000 -> rejected\ng ffffffffffffffff -> MISS\n");
    cli_case("1", "", 0, "");
    cli_case("1", "#comment\n\n", 0, "");
    cli_case(NULL, "", 2, "");
    cli_case("selftest", "", 0, "ok: stale-miss live=3 reused-index=1 gen 1 -> 3\n");
}
static void cli_read_errors(void) {
    cli_read_fault = true;
    cli_case("1", "n\n", 1, "n -> live 0/1\n");
    cli_read_fault = false;
#ifdef _WIN32
    FILE *source = required_stream(fopen("NUL", "w"));
#else
    FILE *source = required_stream(fopen("/dev/null", "w"));
#endif
    FILE *sink = required_stream(tmpfile()), *errors = required_stream(tmpfile());
    CHECK(cli_invoke(source, sink, errors, "1") == 1 && cli_flushes == 0 && ftell(sink) == 0);
    CHECK(fclose(source) == 0 && fclose(sink) == 0 && fclose(errors) == 0);
}
static void cli_sink_failure(const char *arg, const char *ops, size_t target, bool buffered) {
#ifdef _WIN32
    const char *null_path = "NUL";
#else
    const char *null_path = "/dev/null";
#endif
    FILE *source = cli_input(ops), *sink = required_stream(tmpfile());
    FILE *errors = required_stream(tmpfile());
    FILE *bad = required_stream(fopen(buffered ? "/dev/full" : null_path, buffered ? "w" : "r"));
    char buffer[4096];
    if (buffered && setvbuf(bad, buffer, _IOFBF, sizeof buffer) != 0) exit(2);
    cli_failure_sink = bad;
    cli_fail_write = target;
    CHECK(cli_invoke(source, sink, errors, arg) == 1);
    cli_fail_write = 0;
    cli_failure_sink = NULL;
    CHECK(ferror(bad));
    char diagnostic[256];
    rewind(errors);
    size_t n = fread(diagnostic, 1, sizeof diagnostic - 1, errors);
    diagnostic[n] = '\0';
    CHECK(!ferror(errors) && strstr(diagnostic, "output write failed") != NULL);
    CHECK(fclose(source) == 0 && fclose(sink) == 0 && fclose(errors) == 0);
    (void)fclose(bad);
}
static void cli_output_errors(void) {
    const struct { const char *arg, *ops; size_t target; } rows[] = {
        {"1", "i 7\n", 1}, {"1", "i 7\ni 8\n", 2},
        {"1", "g 0\n", 1}, {"1", "i 7\ng 100000000\n", 2},
        {"1", "r 0\n", 1}, {"1", "i 7\nr 100000000\n", 2},
        {"1", "n\n", 1}, {"selftest", "", 1},
        {"1", "n\ni junk\n", 1}
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        cli_sink_failure(rows[i].arg, rows[i].ops, rows[i].target, false);
#ifdef __linux__
        cli_sink_failure(rows[i].arg, rows[i].ops, rows[i].target, true);
#endif
    }
}
static void test_cli(void) {
    cli_numeric_errors();
    cli_normal();
    cli_read_errors();
    cli_output_errors();
}
