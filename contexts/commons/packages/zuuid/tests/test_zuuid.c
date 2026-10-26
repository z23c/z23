#include "zuuid/zuuid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

/* The CLI already depends on sys/random.h; keep its fixtures Linux-only
 * so the library tests below remain portable. */
#ifdef __linux__
#include <sys/random.h>
static FILE *cli_sink, *cli_errors;
static unsigned cli_rng_calls, cli_flushes;
static ssize_t cli_random(void *buf, size_t n, unsigned flags)
{
    (void)flags;
    memset(buf, 0, n);
    cli_rng_calls++;
    return (ssize_t)n;
}
static int cli_puts(const char *s)
{
    return fputs(s, cli_sink) == EOF ? EOF : fputc('\n', cli_sink);
}
[[maybe_unused]] static int cli_flush(FILE *f) { cli_flushes++; return fflush(f); }
#undef stdout
#undef stderr
#define stdout cli_sink
#define stderr cli_errors
#define puts cli_puts
#define fflush cli_flush
#define getrandom cli_random
#define main zuuid_cli_main
#include "../app/main.c"
#undef main
#undef getrandom
#undef fflush
#undef puts
#undef stderr
#undef stdout

static void cli_verify(FILE *sink, FILE *errors, const char *want, unsigned kind)
{
    if (kind == 0) {
        char actual[128] = {0}; rewind(sink);
        CHECK(fread(actual, 1, sizeof actual - 1, sink) == strlen(want));
        CHECK(strcmp(actual, want) == 0);
    } else {
        char message[128] = {0}; rewind(errors);
        CHECK(ferror(sink));
        CHECK(fread(message, 1, sizeof message - 1, errors) > 0);
        CHECK(strstr(message, "zuuid: write error"));
    }
}

static FILE *cli_open_sink(unsigned kind)
{
    if (kind == 0) return tmpfile();
    return fopen(kind == 1 ? "/dev/null" : "/dev/full", kind == 1 ? "r" : "w");
}

static void test_cli_output(void)
{
    static const char *ops[] = {"nil", "parse", "new"};
    static const char *want[] = {
        "00000000-0000-0000-0000-000000000000\n",
        "f81d4fae-7dec-11d0-a765-00a0c91e6bf6\n",
        "00000000-0000-4000-8000-000000000000\n"
        "00000000-0000-4000-8000-000000000000\n"
        "00000000-0000-4000-8000-000000000000\n"
    };
    for (unsigned op = 0; op < 3; op++) {
        for (unsigned step = 0; step < 3; step++) {
            unsigned kind = (step + 1) % 3;
            FILE *sink = cli_open_sink(kind);
            FILE *errors = tmpfile();
            CHECK(sink && errors);
            char buffer[4096];
            if (kind == 2) { CHECK(setvbuf(sink, buffer, _IOFBF, sizeof buffer) == 0); }
            cli_sink = sink; cli_errors = errors;
            cli_rng_calls = cli_flushes = 0;
            char *args[] = {"zuuid", (char *)ops[op],
                op == 1 ? "F81D4FAE-7DEC-11D0-A765-00A0C91E6BF6" : "3", NULL};
            if (op == 0) args[2] = NULL;
            CHECK(zuuid_cli_main(op == 0 ? 2 : 3, args) == (kind ? 1 : 0));
            CHECK(cli_rng_calls == (op == 2 ? (kind == 1 ? 1u : 3u) : 0u));
            CHECK(cli_flushes == (kind == 1 ? 0u : 1u));
            cli_verify(sink, errors, want[op], kind);
            CHECK(fclose(errors) == 0);
            if (kind == 0) { CHECK(fclose(sink) == 0); }
            else (void)fclose(sink);
        }
    }
}
#endif

static void test_nil(void)
{
    zuuid n = zuuid_nil();
    CHECK(zuuid_is_nil(&n));
    CHECK(zuuid_version(&n) == 0);
    CHECK(zuuid_variant(&n) == 0);

    char s[ZUUID_STR_LEN];
    CHECK(zuuid_format(&n, s) == ZUUID_OK);
    CHECK(strcmp(s, "00000000-0000-0000-0000-000000000000") == 0);
    CHECK(strlen(s) == 36);

    zuuid back;
    CHECK(zuuid_parse(s, &back) == ZUUID_OK);
    CHECK(zuuid_equal(&n, &back));
}

static void test_parse_strict(void)
{
    zuuid u;
    char s[ZUUID_STR_LEN];

    CHECK(zuuid_parse("f81d4fae-7dec-11d0-a765-00a0c91e6bf6", &u) == ZUUID_OK);
    CHECK(u.b[0] == 0xf8 && u.b[1] == 0x1d && u.b[15] == 0xf6);
    CHECK(zuuid_format(&u, s) == ZUUID_OK);
    CHECK(strcmp(s, "f81d4fae-7dec-11d0-a765-00a0c91e6bf6") == 0);

    /* Uppercase accepted by parser; format is canonical lowercase. */
    CHECK(zuuid_parse("F81D4FAE-7DEC-11D0-A765-00A0C91E6BF6", &u) == ZUUID_OK);
    CHECK(zuuid_format(&u, s) == ZUUID_OK);
    CHECK(strcmp(s, "f81d4fae-7dec-11d0-a765-00a0c91e6bf6") == 0);
    CHECK(zuuid_format_upper(&u, s) == ZUUID_OK);
    CHECK(strcmp(s, "F81D4FAE-7DEC-11D0-A765-00A0C91E6BF6") == 0);

    /* Wrong length / hyphen placement / bad digit. */
    CHECK(zuuid_parse("f81d4fae-7dec-11d0-a765-00a0c91e6bf", &u) == ZUUID_ERR_FORMAT);
    CHECK(zuuid_parse("f81d4fae-7dec-11d0-a765-00a0c91e6bf6ff", &u) == ZUUID_ERR_FORMAT);
    CHECK(zuuid_parse("f81d4fae_7dec-11d0-a765-00a0c91e6bf6", &u) == ZUUID_ERR_FORMAT);
    CHECK(zuuid_parse("g81d4fae-7dec-11d0-a765-00a0c91e6bf6", &u) == ZUUID_ERR_BAD_CHAR);
    CHECK(zuuid_parse(NULL, &u) == ZUUID_ERR_NULL);
    CHECK(zuuid_parse(s, NULL) == ZUUID_ERR_NULL);
}

static void test_parse_lenient(void)
{
    zuuid a, b;
    const char *canon = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
    CHECK(zuuid_parse(canon, &a) == ZUUID_OK);

    CHECK(zuuid_parse_lenient("f81d4fae7dec11d0a76500a0c91e6bf6", &b) == ZUUID_OK);
    CHECK(zuuid_equal(&a, &b));
    CHECK(zuuid_parse_lenient("F81D4FAE7DEC11D0A76500A0C91E6BF6", &b) == ZUUID_OK);
    CHECK(zuuid_equal(&a, &b));
    CHECK(zuuid_parse_lenient("{f81d4fae-7dec-11d0-a765-00a0c91e6bf6}", &b) == ZUUID_OK);
    CHECK(zuuid_equal(&a, &b));
    CHECK(zuuid_parse_lenient("urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6", &b) == ZUUID_OK);
    CHECK(zuuid_equal(&a, &b));
    CHECK(zuuid_parse_lenient("{urn:uuid:f81d4fae7dec11d0a76500a0c91e6bf6}", &b) == ZUUID_OK);

    CHECK(zuuid_parse_lenient("xyz", &b) == ZUUID_ERR_FORMAT);
    CHECK(zuuid_parse_lenient("f81d4fae7dec11d0a76500a0c91e6bg6", &b) == ZUUID_ERR_BAD_CHAR);
    CHECK(zuuid_parse_lenient(NULL, &b) == ZUUID_ERR_NULL);
}

static void test_parse_failure_preserves_uuid(void)
{
    const char *canon = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
    zuuid before;
    memset(&before, 0xa5, sizeof before);
    for (size_t i = 0; i < 36; i++) {
        if (canon[i] == '-') continue;
        char malformed[ZUUID_STR_LEN];
        memcpy(malformed, canon, sizeof malformed);
        malformed[i] = 'g';
        for (int lenient = 0; lenient <= 1; lenient++) {
            zuuid out = before;
            zuuid_err err = lenient ? zuuid_parse_lenient(malformed, &out)
                                    : zuuid_parse(malformed, &out);
            CHECK(err == ZUUID_ERR_BAD_CHAR);
            CHECK(zuuid_equal(&out, &before));
            CHECK(zuuid_parse(canon, &out) == ZUUID_OK);
            CHECK(out.b[0] == 0xf8 && out.b[15] == 0xf6);
        }
    }
    zuuid out = before;
    CHECK(zuuid_parse(NULL, &out) == ZUUID_ERR_NULL);
    CHECK(zuuid_equal(&out, &before));
    CHECK(zuuid_parse("", &out) == ZUUID_ERR_FORMAT);
    CHECK(zuuid_equal(&out, &before));
}

static void test_compare(void)
{
    zuuid a, b, c;
    CHECK(zuuid_parse("00000000-0000-0000-0000-000000000001", &a) == ZUUID_OK);
    CHECK(zuuid_parse("00000000-0000-0000-0000-000000000002", &b) == ZUUID_OK);
    CHECK(zuuid_parse("10000000-0000-0000-0000-000000000000", &c) == ZUUID_OK);

    CHECK(zuuid_compare(&a, &a) == 0);
    CHECK(zuuid_compare(&a, &b) < 0);
    CHECK(zuuid_compare(&b, &a) > 0);
    CHECK(zuuid_compare(&a, &c) < 0); /* last byte 1 < first byte 0x10 */
    CHECK(zuuid_compare(NULL, NULL) == 0);
    CHECK(zuuid_compare(NULL, &a) < 0);
    CHECK(zuuid_compare(&a, NULL) > 0);
    CHECK(!zuuid_equal(&a, &b));
}

/* Deterministic counter RNG for tests. */
struct counter_rng { uint64_t v; };
static int counter_fill(void *ctx, uint8_t *buf, size_t n)
{
    struct counter_rng *r = ctx;
    for (size_t i = 0; i < n; i++) {
        r->v = r->v * 6364136223846793005ull + 1442695040888963407ull;
        buf[i] = (uint8_t)(r->v >> 56);
    }
    return 0;
}
static int fail_rng(void *ctx, uint8_t *buf, size_t n)
{
    (void)ctx; (void)buf; (void)n;
    return -1;
}

struct partial_rng { size_t written; int calls; };
static int partial_fail_rng(void *ctx, uint8_t *buf, size_t n)
{
    struct partial_rng *r = ctx;
    CHECK(n == ZUUID_BYTES && r->written <= n);
    r->calls++;
    memset(buf, 0x5a, r->written);
    return -1;
}

static void test_rng_failure_preserves_uuid(void)
{
    for (size_t n = 0; n <= ZUUID_BYTES; n++) {
        struct partial_rng rng = {n, 0};
        struct { unsigned char before; zuuid value; unsigned char after; } out;
        memset(&out, 0xa5, sizeof out);
        zuuid before = out.value;
        CHECK(zuuid_generate_v4(&out.value, partial_fail_rng, &rng) == ZUUID_ERR_RNG);
        CHECK(rng.calls == 1);
        CHECK(zuuid_equal(&out.value, &before));
        CHECK(out.before == 0xa5 && out.after == 0xa5);
        struct counter_rng good = {42};
        CHECK(zuuid_generate_v4(&out.value, counter_fill, &good) == ZUUID_OK);
        CHECK(zuuid_version(&out.value) == 4 && zuuid_variant(&out.value) == 1);
        CHECK(out.before == 0xa5 && out.after == 0xa5);
    }
}

static void test_generate_v4(void)
{
    struct counter_rng rng = {42};
    zuuid u;
    CHECK(zuuid_generate_v4(&u, counter_fill, &rng) == ZUUID_OK);
    CHECK(zuuid_version(&u) == 4);
    CHECK(zuuid_variant(&u) == 1);
    CHECK(!zuuid_is_nil(&u));

    /* Round trip through text. */
    char s[ZUUID_STR_LEN];
    zuuid back;
    CHECK(zuuid_format(&u, s) == ZUUID_OK);
    CHECK(zuuid_parse(s, &back) == ZUUID_OK);
    CHECK(zuuid_equal(&u, &back));

    /* Distinct draws. */
    zuuid v;
    CHECK(zuuid_generate_v4(&v, counter_fill, &rng) == ZUUID_OK);
    CHECK(!zuuid_equal(&u, &v));

    /* Many draws all carry v4 + RFC variant. */
    for (int i = 0; i < 1000; i++) {
        CHECK(zuuid_generate_v4(&v, counter_fill, &rng) == ZUUID_OK);
        CHECK(zuuid_version(&v) == 4);
        CHECK(zuuid_variant(&v) == 1);
    }

    /* Failure and NULL paths. */
    CHECK(zuuid_generate_v4(&v, fail_rng, NULL) == ZUUID_ERR_RNG);
    CHECK(zuuid_generate_v4(NULL, counter_fill, &rng) == ZUUID_ERR_NULL);
    CHECK(zuuid_generate_v4(&v, NULL, NULL) == ZUUID_ERR_NULL);
}

static void test_err_str(void)
{
    CHECK(strcmp(zuuid_err_str(ZUUID_OK), "ok") == 0);
    CHECK(strstr(zuuid_err_str(ZUUID_ERR_FORMAT), "shape") != NULL);
    CHECK(zuuid_err_str((zuuid_err)999) != NULL);
}

int main(void)
{
#ifdef __linux__
    test_cli_output();
#endif
    test_nil();
    test_parse_strict();
    test_parse_lenient();
    test_parse_failure_preserves_uuid();
    test_compare();
    test_generate_v4();
    test_rng_failure_preserves_uuid();
    test_err_str();
    puts("test_zuuid: all groups passed (nil strict lenient compare v4 errstr)");
    return 0;
}
