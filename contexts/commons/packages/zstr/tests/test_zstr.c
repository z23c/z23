/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Purpose: regression tests for bounded string helpers and split iteration.
 */
#include "zstr/zstr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

static void test_copy_concat(void)
{
    char buf[8];

    /* Exact fit, truncation, and edge capacities. */
    CHECK(zstr_copy(buf, sizeof buf, "hello") == 5);
    CHECK(strcmp(buf, "hello") == 0);
    CHECK(zstr_copy(buf, sizeof buf, "hello world") == 11);
    CHECK(strcmp(buf, "hello w") == 0);
    CHECK(zstr_copy(buf, 1, "abc") == 3);
    CHECK(buf[0] == '\0');
    CHECK(zstr_copy(buf, 0, "abc") == 3); /* nothing written */
    CHECK(zstr_copy(NULL, 0, "abc") == 3); /* length still reported */
    CHECK(zstr_copy(buf, sizeof buf, NULL) == 0);

    /* Concat. */
    CHECK(zstr_copy(buf, sizeof buf, "abc") == 3);
    CHECK(zstr_concat(buf, sizeof buf, "de") == 5);
    CHECK(strcmp(buf, "abcde") == 0);
    CHECK(zstr_concat(buf, sizeof buf, "fghij") == 10); /* would-be length */
    CHECK(strcmp(buf, "abcdefg") == 0);
    /* Overflow-safe repeated concat never overruns. */
    char tiny[4] = "";
    for (int i = 0; i < 10; i++)
        zstr_concat(tiny, sizeof tiny, "x");
    CHECK(strlen(tiny) == 3);
    /* Full buffer: strnlen-bounded, no write past cap. */
    char full[4] = {'a','b','c','d'}; /* not NUL-terminated! */
    CHECK(zstr_concat(full, sizeof full, "e") == 5); /* 4 + 1, nothing written */
    CHECK(zstr_concat(NULL, 0, "abc") == 3);
    CHECK(zstr_concat(buf, sizeof buf, NULL) == 0);
}

static void test_trim_case(void)
{
    char s1[] = "  hello\t\n";
    CHECK(strcmp(zstr_trim(s1), "hello") == 0);
    char s2[] = "   ";
    CHECK(strcmp(zstr_trim(s2), "") == 0);
    char s3[] = "x";
    CHECK(strcmp(zstr_trim(s3), "x") == 0);
    char s4[] = "";
    CHECK(strcmp(zstr_trim(s4), "") == 0);
    CHECK(zstr_trim(NULL) == NULL);

    char l[] = "HeLLo 123!";
    CHECK(strcmp(zstr_to_lower(l), "hello 123!") == 0);
    char u[] = "HeLLo 123!";
    CHECK(strcmp(zstr_to_upper(u), "HELLO 123!") == 0);
    CHECK(zstr_to_lower(NULL) == NULL);
    CHECK(zstr_to_upper(NULL) == NULL);

    CHECK(zstr_casecmp("Hello", "hello") == 0);
    CHECK(zstr_casecmp("abc", "abd") < 0);
    CHECK(zstr_casecmp("abd", "abc") > 0);
    CHECK(zstr_casecmp("abc", "abcd") < 0);
    CHECK(zstr_casecmp(NULL, NULL) == 0);
    CHECK(zstr_casecmp(NULL, "a") < 0);
    CHECK(zstr_case_equal("Content-Type", "content-type"));
    CHECK(!zstr_case_equal("a", "b"));
}

static void test_prefix_suffix_count(void)
{
    CHECK(zstr_starts_with("hello world", "hello"));
    CHECK(!zstr_starts_with("hello", "hello world"));
    CHECK(zstr_starts_with("x", ""));
    CHECK(zstr_starts_with("x", "x"));
    CHECK(!zstr_starts_with(NULL, "a"));
    CHECK(!zstr_starts_with("a", NULL));

    CHECK(zstr_ends_with("file.txt", ".txt"));
    CHECK(!zstr_ends_with("file.txt", ".md"));
    CHECK(zstr_ends_with("x", ""));
    CHECK(!zstr_ends_with("", "x"));
    CHECK(!zstr_ends_with(NULL, "a"));
    CHECK(!zstr_ends_with("a", NULL));

    CHECK(zstr_count("aaaa", "aa") == 2);
    CHECK(zstr_count("hello hello hello", "hello") == 3);
    CHECK(zstr_count("abc", "x") == 0);
    CHECK(zstr_count("abc", "") == 0);
    CHECK(zstr_count("", "x") == 0);
    CHECK(zstr_count("aaa", "aaa") == 1);
    CHECK(zstr_count("aaa", "aaaa") == 0);
    CHECK(zstr_count(NULL, "a") == 0);
    CHECK(zstr_count("a", NULL) == 0);
}

static void test_split(void)
{
    /* Basic with empty fields kept. */
    zstr_split_it it;
    zstr_span sp;
    zstr_split_init(&it, "a,,b,", ',');
    CHECK(zstr_split_next(&it, &sp) && sp.len == 1 && memcmp(sp.ptr, "a", 1) == 0);
    CHECK(zstr_split_next(&it, &sp) && sp.len == 0);
    CHECK(zstr_split_next(&it, &sp) && sp.len == 1 && memcmp(sp.ptr, "b", 1) == 0);
    CHECK(zstr_split_next(&it, &sp) && sp.len == 0);
    CHECK(!zstr_split_next(&it, &sp));
    CHECK(!zstr_split_next(&it, &sp)); /* stays exhausted */

    /* No delimiter present: single span. */
    zstr_split_init(&it, "whole", ',');
    CHECK(zstr_split_next(&it, &sp) && sp.len == 5);
    CHECK(!zstr_split_next(&it, &sp));

    /* Empty input: one empty span (like strsep). */
    zstr_split_init(&it, "", ',');
    CHECK(zstr_split_next(&it, &sp) && sp.len == 0);
    CHECK(!zstr_split_next(&it, &sp));

    /* NULL input: nothing. */
    zstr_split_init(&it, NULL, ',');
    CHECK(!zstr_split_next(&it, &sp));
    CHECK(!zstr_split_next(NULL, &sp));
    zstr_split_init(&it, "a", ',');
    CHECK(!zstr_split_next(&it, NULL));
    zstr_split_init(NULL, "a", ','); /* no crash */

    /* Multi-delimiter walk over a path. */
    const char *path = "/usr/local/bin";
    const char *want[] = {"", "usr", "local", "bin"};
    size_t wi = 0;
    zstr_split_init(&it, path, '/');
    while (zstr_split_next(&it, &sp)) {
        CHECK(wi < 4);
        CHECK(sp.len == strlen(want[wi]));
        CHECK(memcmp(sp.ptr, want[wi], sp.len) == 0);
        wi++;
    }
    CHECK(wi == 4);
}

static void test_split_nul_delimiter(void)
{
    /* The suffix is in-bounds: baseline incorrectly emits it as field two. */
    char input[] = {'a', '\0', 'X', '\0'};
    zstr_split_it it;
    zstr_span sp;
    zstr_split_init(&it, input, '\0');
    CHECK(zstr_split_next(&it, &sp));
    CHECK(sp.ptr == input && sp.len == 1 && sp.ptr[0] == 'a');
    CHECK(!zstr_split_next(&it, &sp));
    CHECK(!zstr_split_next(&it, &sp)); /* exhaustion remains stable */

    /* A genuinely one-byte empty string must never be read past its NUL. */
    char empty[] = {'\0'};
    zstr_split_init(&it, empty, '\0');
    CHECK(zstr_split_next(&it, &sp));
    CHECK(sp.ptr == empty && sp.len == 0);
    CHECK(!zstr_split_next(&it, &sp));
    CHECK(!zstr_split_next(&it, &sp));

    zstr_split_init(&it, NULL, '\0');
    CHECK(!zstr_split_next(&it, &sp));
}

static void test_null_source_contract(void)
{
    int failed = 0;
    const size_t caps[] = {1, 4, 8};
    for (size_t row = 0; row < sizeof caps / sizeof caps[0]; row++) {
        char dst[8];
        memset(dst, 'x', sizeof dst);
        size_t n = zstr_copy(dst, caps[row], NULL);
        if (n != 0 || dst[0] != '\0' || dst[7] != 'x') {
            fprintf(stderr, "FAIL null_copy row=%zu\n", row);
            failed = 1;
        }
    }
    CHECK(!failed);
}

static void test_cli(void);

int main(void)
{
    test_cli();
    test_null_source_contract();

    test_copy_concat();
    test_trim_case();
    test_prefix_suffix_count();
    test_split();
    test_split_nul_delimiter();
    puts("test_zstr: all groups passed (copy concat trim case prefix count split)");
    return 0;
}

static FILE *cli_sink, *cli_errors;
static size_t cli_live, cli_flushes, cli_writes, cli_next_calls;
static bool cli_allocation_failure;
static FILE *real_stdout(void) { return stdout; }
static FILE *real_stderr(void) { return stderr; }
static void *cli_malloc(size_t n)
{
    if (cli_allocation_failure) return NULL;
    void *p = malloc(n); // raw-alloc-ok:allocation-failure-fixture
    if (p) cli_live++;
    return p;
}
static void cli_free(void *p)
{
    if (p) { CHECK(cli_live > 0); cli_live--; }
    free(p);
}
static bool cli_next(zstr_split_it *it, zstr_span *span)
{
    cli_next_calls++;
    return zstr_split_next(it, span);
}
static FILE *cli_output(void)
{
    cli_writes++;
    return cli_sink;
}
[[maybe_unused]] static int cli_flush(FILE *stream)
{
    if (stream == cli_sink) cli_flushes++;
    return fflush(stream);
}
#undef stdout
#undef stderr
#define stdout cli_sink
#define stderr cli_errors
#define printf(...) fprintf(cli_output(), __VA_ARGS__)
#define puts(text) fprintf(cli_output(), "%s\n", (text))
#define fflush cli_flush
#define malloc cli_malloc
#define free cli_free
#define zstr_split_next cli_next
#define main embedded_cli_main
#include "../app/main.c"
#undef main
#undef zstr_split_next
#undef free
#undef malloc
#undef fflush
#undef puts
#undef printf
#undef stdout
#undef stderr
#define stdout real_stdout()
#define stderr real_stderr()

static int cli_invoke(FILE *sink, FILE *errors, int argc, char **args)
{
    cli_sink = sink;
    cli_errors = errors;
    cli_live = cli_flushes = cli_writes = cli_next_calls = 0;
    int rc = embedded_cli_main(argc, args);
    cli_sink = stdout;
    cli_errors = stderr;
    CHECK(cli_live == 0);
    return rc;
}
static void cli_message(FILE *errors, const char *want)
{
    char bytes[256];
    rewind(errors);
    size_t n = fread(bytes, 1, sizeof bytes - 1, errors);
    bytes[n] = 0;
    CHECK(!ferror(errors) && strstr(bytes, want) != NULL);
}
static void cli_case(int argc, char **args, int status, const char *want)
{
    FILE *sink = tmpfile(), *errors = tmpfile();
    CHECK(sink != NULL && errors != NULL);
    CHECK(cli_invoke(sink, errors, argc, args) == status);
    if (!*want) { CHECK(cli_flushes == 0 && cli_writes == 0); }
    char bytes[256];
    rewind(sink);
    size_t n = fread(bytes, 1, sizeof bytes, sink);
    CHECK(!ferror(sink) && n == strlen(want) && !memcmp(bytes, want, n));
    CHECK(fclose(sink) == 0 && fclose(errors) == 0);
}
static void cli_normal(void)
{
    char *trim[] = {"zstr", "trim", " \tHi \r\n", "ignored", NULL};
    cli_case(4, trim, 0, "Hi\n");
    char *lower[] = {"zstr", "lower", "AbC", NULL};
    cli_case(3, lower, 0, "abc\n");
    char *upper[] = {"zstr", "upper", "AbC", NULL};
    cli_case(3, upper, 0, "ABC\n");
    char *count[] = {"zstr", "count", "aaaa", "aa", NULL};
    cli_case(4, count, 0, "2\n");
    count[3] = "";
    cli_case(4, count, 0, "0\n");
    char *split[] = {"zstr", "split", ",", "a,,b,", NULL};
    cli_case(4, split, 0, "a\n\nb\n\n");
    split[3] = "";
    cli_case(4, split, 0, "\n");
    trim[2] = "";
    cli_case(3, trim, 0, "\n");
}
static void cli_failed_output(const char *command, bool buffered)
{
#ifdef _WIN32
    const char *null_path = "NUL";
#else
    const char *null_path = "/dev/null";
#endif
    FILE *sink = fopen(buffered ? "/dev/full" : null_path, buffered ? "w" : "r");
    FILE *errors = tmpfile();
    CHECK(sink != NULL && errors != NULL);
    char buffer[4096];
    if (buffered) { CHECK(setvbuf(sink, buffer, _IOFBF, sizeof buffer) == 0); }
    bool split = strcmp(command, "split") == 0;
    char *args[] = {"zstr", (char *)command, split ? "," : "AbC", split ? "a,,b," : "A", NULL};
    CHECK(cli_invoke(sink, errors, 4, args) == 1 && ferror(sink));
    if (!buffered) { CHECK(cli_writes == 1); }
    if (split) { CHECK(cli_next_calls == (buffered ? 5u : 1u)); }
    cli_message(errors, "write error");
    CHECK(fclose(errors) == 0);
    (void)fclose(sink);
}
static void cli_output_free(void)
{
#ifdef _WIN32
    FILE *sink = fopen("NUL", "r");
#else
    FILE *sink = fopen("/dev/null", "r");
#endif
    FILE *errors = tmpfile();
    CHECK(sink != NULL && errors != NULL);
    const char *commands[] = {"starts", "ends"};
    for (size_t i = 0; i < 2; i++) {
        char *args[] = {"zstr", (char *)commands[i], "abc", "", NULL};
        CHECK(cli_invoke(sink, errors, 4, args) == 0);
        CHECK(cli_flushes == 0 && cli_writes == 0 && !ferror(sink));
        args[3] = "xyz";
        CHECK(cli_invoke(sink, errors, 4, args) == 1);
        CHECK(cli_flushes == 0 && cli_writes == 0 && !ferror(sink));
    }
    char *bad[] = {"zstr", "split", "xx", "abc", NULL};
    CHECK(cli_invoke(sink, errors, 4, bad) == 2);
    CHECK(cli_flushes == 0 && cli_writes == 0 && !ferror(sink));
    CHECK(fclose(sink) == 0 && fclose(errors) == 0);
}
static void cli_allocation_errors(void)
{
    const char *commands[] = {"trim", "lower", "upper"};
    for (size_t i = 0; i < 3; i++) {
        FILE *sink = tmpfile(), *errors = tmpfile();
        CHECK(sink != NULL && errors != NULL);
        char *args[] = {"zstr", (char *)commands[i], "abc", NULL};
        cli_allocation_failure = true;
        CHECK(cli_invoke(sink, errors, 3, args) == 1);
        cli_allocation_failure = false;
        CHECK(cli_flushes == 0 && cli_writes == 0 && ftell(sink) == 0);
        cli_message(errors, "allocation failed");
        CHECK(fclose(sink) == 0 && fclose(errors) == 0);
    }
}
static void test_cli(void)
{
    cli_normal();
    const char *commands[] = {"trim", "lower", "upper", "count", "split"};
    for (size_t i = 0; i < 5; i++) {
        cli_failed_output(commands[i], false);
#ifdef __linux__
        cli_failed_output(commands[i], true);
#endif
    }
    cli_output_free();
    cli_allocation_errors();
    char *usage[] = {"zstr", NULL};
    cli_case(1, usage, 2, "");
}
