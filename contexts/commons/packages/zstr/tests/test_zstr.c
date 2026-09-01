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

int main(void)
{
    test_copy_concat();
    test_trim_case();
    test_prefix_suffix_count();
    test_split();
    puts("test_zstr: all groups passed (copy concat trim case prefix count split)");
    return 0;
}
