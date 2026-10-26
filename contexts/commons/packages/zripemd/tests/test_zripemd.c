/* zripemd tests — the standard RIPEMD-160 test suite. */
#include "zripemd/zripemd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static FILE *cli_sink;
#undef stdout
#define stdout cli_sink
#define printf(...) fprintf(cli_sink, __VA_ARGS__)
#define main zripemd_cli_main
#include "../app/main.c"
#undef main
#undef printf
#undef stdout

static int failures;

static void check(int cond, const char *name)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", name);
        failures++;
    }
}

static void vec(const char *msg, const char *want_hex, const char *name)
{
    char hex[ZRIPEMD160_HEX_LEN];

    zripemd160_hex(msg, strlen(msg), hex);
    check(strcmp(hex, want_hex) == 0, name);
}

static void test_standard_vectors(void)
{
    vec("", "9c1185a5c5e9fc54612808977ee8f548b2258d31", "empty");
    vec("a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe", "a");
    vec("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", "abc");
    vec("message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36",
        "message digest");
    vec("abcdefghijklmnopqrstuvwxyz",
        "f71c27109c692c1b56bbdceb5b9d2865b3708dbc", "alphabet");
    vec("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "12a053384a9c0c88e405a06c27dcf49ada62eb2b", "alnum");
    vec("1234567890123456789012345678901234567890"
        "1234567890123456789012345678901234567890",
        "9b752e45573d4b39f4dbd3323cab82bf63326bfb", "8x digits");
}

static void test_million_a(void)
{
    char *msg = malloc(1000000);
    char hex[ZRIPEMD160_HEX_LEN];

    check(msg != NULL, "million alloc");
    if (!msg)
        return;
    memset(msg, 'a', 1000000);
    zripemd160_hex(msg, 1000000, hex);
    check(strcmp(hex, "52783243c1697bdbe16d37f97f68f08325dc1528") == 0,
          "million a");
    free(msg);
}

static void test_incremental_split(void)
{
    const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    size_t len = strlen(msg);
    uint8_t want[ZRIPEMD160_DIGEST_LEN];

    zripemd160(msg, len, want);

    for (size_t split = 0; split <= len; split++) {
        zripemd160_ctx ctx;
        uint8_t got[ZRIPEMD160_DIGEST_LEN];

        zripemd160_init(&ctx);
        zripemd160_update(&ctx, msg, split);
        zripemd160_update(&ctx, msg + split, len - split);
        zripemd160_final(&ctx, got);
        if (memcmp(got, want, sizeof got) != 0) {
            check(0, "incremental split");
            return;
        }
    }
    check(1, "incremental split");
}

static void test_byte_at_a_time(void)
{
    const char *msg = "message digest";
    size_t len = strlen(msg);
    zripemd160_ctx ctx;
    uint8_t got[ZRIPEMD160_DIGEST_LEN], want[ZRIPEMD160_DIGEST_LEN];

    zripemd160(msg, len, want);
    zripemd160_init(&ctx);
    for (size_t i = 0; i < len; i++)
        zripemd160_update(&ctx, msg + i, 1);
    zripemd160_final(&ctx, got);
    check(memcmp(got, want, sizeof got) == 0, "byte at a time");
}

static int cli_case(FILE *output, int argc, char **args, int status,
                    const char *want)
{
    cli_sink = output;
    if (zripemd_cli_main(argc, args) != status) return 1;
    if (!want) return 0;
    rewind(output);
    char bytes[160];
    size_t n = fread(bytes, 1, sizeof bytes, output);
    return ferror(output) || n != strlen(want) || memcmp(bytes, want, n) != 0;
}

static int cli_output_case(int argc, char **args, const char *want)
{
    FILE *output = tmpfile();
    if (!output) return 1;
    int bad = cli_case(output, argc, args, 0, want);
    if (fclose(output) != 0) bad = 1;
#if defined(_WIN32)
    output = fopen("NUL", "r");
#else
    output = fopen("/dev/null", "r");
#endif
    if (!output) return 1;
    bad |= cli_case(output, argc, args, 1, NULL);
    if (fclose(output) != 0) bad = 1;
#if defined(__linux__)
    output = fopen("/dev/full", "w");
    if (!output) return 1;
    char buffer[4096];
    if (setvbuf(output, buffer, _IOFBF, sizeof buffer) != 0) {
        fclose(output);
        return 1;
    }
    bad |= cli_case(output, argc, args, 1, NULL);
    (void)fclose(output);
#endif
    return bad;
}

static void test_cli_output(void)
{
    char *args[] = {"zripemd", "abc", "", NULL};
    check(cli_output_case(2, args,
          "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc  abc\n") == 0,
          "CLI single argument output and errors");
    check(cli_output_case(3, args,
          "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc  abc\n"
          "9c1185a5c5e9fc54612808977ee8f548b2258d31  \n") == 0,
          "CLI multiple argument output and errors");
    FILE *output = tmpfile();
    if (!output) { check(0, "CLI usage fixture"); return; }
    check(cli_case(output, 1, args, 2, "") == 0, "CLI usage without output");
    check(fclose(output) == 0, "CLI usage fixture close");
}

int main(void)
{
    test_cli_output();
    test_standard_vectors();
    test_million_a();
    test_incremental_split();
    test_byte_at_a_time();
    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    puts("zripemd: all tests passed");
    return 0;
}
