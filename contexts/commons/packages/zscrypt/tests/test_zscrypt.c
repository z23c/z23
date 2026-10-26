/* zscrypt tests — RFC 7914 section 12 scrypt vectors and RFC 7914
 * section 11 PBKDF2-HMAC-SHA256 vectors. */
#include "zscrypt/zscrypt.h"

#include <stdio.h>
#include <string.h>
#include <limits.h>

static FILE *cli_sink;
#undef stdout
#define stdout cli_sink
#define printf(...) fprintf(cli_sink, __VA_ARGS__)
#define putchar(c) fputc((c), cli_sink)
#define main zscrypt_cli_main
#include "../app/main.c"
#undef main
#undef putchar
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

static size_t unhex(const char *s, uint8_t *out)
{
    size_t n = 0;
    while (s[0] && s[1]) {
        unsigned v;
        sscanf(s, "%2x", &v);
        out[n++] = (uint8_t)v;
        s += 2;
    }
    return n;
}

static int eq_hex(const uint8_t *buf, size_t len, const char *hex)
{
    uint8_t want[256];
    size_t n = unhex(hex, want);
    return n == len && memcmp(buf, want, len) == 0;
}

/* RFC 7914 PBKDF2-HMAC-SHA256 test vectors (password "passwd",
 * salt "salt", 64-byte output). */
static void test_pbkdf2(void)
{
    uint8_t dk[64];

    check(zpbkdf2_sha256("passwd", 6, "salt", 4, 1, dk, sizeof dk) == 0,
          "pbkdf2 c=1 rc");
    check(eq_hex(dk, sizeof dk,
                 "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d"
                 "57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1"
                 "e30bd509112041d3a19783"), "pbkdf2 c=1");
    check(zpbkdf2_sha256("passwd", 6, "salt", 4, 16, dk, sizeof dk) == 0,
          "pbkdf2 c=16 rc");
    check(eq_hex(dk, sizeof dk,
                 "5d351acfb01c4e313f98eeba7aca5ad01159a33c482ae45a"
                 "67163a2dbdc7a6a0ec4c57e6315ab8113c3be353e97b192f5a"
                 "6011e87455e80835386eda263e43e9"), "pbkdf2 c=16");
}

/* RFC 7914 scrypt vectors. */
static void test_scrypt_vectors(void)
{
    uint8_t dk[64];

    check(zscrypt("", 0, "", 0, 16, 1, 1, dk, sizeof dk) == 0,
          "v1 rc");
    check(eq_hex(dk, sizeof dk,
                 "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdf"
                 "fa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb"
                 "2e0d3628cf35e20c38d18906"), "v1");

    check(zscrypt("password", 8, "NaCl", 4, 1024, 8, 16, dk,
                  sizeof dk) == 0, "v2 rc");
    check(eq_hex(dk, sizeof dk,
                 "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e7"
                 "7376634b3731622eaf30d92e22a3886ff109279d9830dac727"
                 "afb94a83ee6d8360cbdfa2cc0640"), "v2");

    check(zscrypt("pleaseletmein", 13, "SodiumChloride", 14,
                  16384, 8, 1, dk, sizeof dk) == 0, "v3 rc");
    check(eq_hex(dk, sizeof dk,
                 "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b5"
                 "43f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85"
                 "dc0d651e40dfcf017b45575887"), "v3");
}

static void test_variable_output_len(void)
{
    uint8_t dk32[32], dk64[64];

    check(zscrypt("password", 8, "NaCl", 4, 1024, 8, 16,
                  dk32, sizeof dk32) == 0, "32 rc");
    check(zscrypt("password", 8, "NaCl", 4, 1024, 8, 16,
                  dk64, sizeof dk64) == 0, "64 rc");
    /* The 32-byte output must be a prefix of the 64-byte output. */
    check(memcmp(dk32, dk64, sizeof dk32) == 0, "prefix property");
}

static void test_errors(void)
{
    uint8_t dk[16];

    check(zscrypt("pw", 2, "salt", 4, 1, 1, 1, dk, sizeof dk) == -1,
          "n=1 rejected");
    check(zscrypt("pw", 2, "salt", 4, 15, 1, 1, dk, sizeof dk) == -1,
          "non-power-of-two n rejected");
    check(zscrypt("pw", 2, "salt", 4, 16, 0, 1, dk, sizeof dk) == -1,
          "r=0 rejected");
    check(zscrypt("pw", 2, "salt", 4, 16, 1, 0, dk, sizeof dk) == -1,
          "p=0 rejected");
    check(zscrypt("pw", 2, "salt", 4, 16, 1, 1, NULL, 16) == -1,
          "null dk rejected");
    check(zscrypt("pw", 2, "salt", 4, 16, 1, 1, dk, 0) == -1,
          "zero dk_len rejected");
    check(zscrypt(NULL, 2, "salt", 4, 16, 1, 1, dk, sizeof dk) == -1,
          "null passwd with len rejected");
    check(zpbkdf2_sha256("pw", 2, "salt", 4, 0, dk, sizeof dk) == -1,
          "zero iters rejected");
    check(zpbkdf2_sha256("pw", 2, "salt", 4, 1, NULL, 16) == -1,
          "null pbkdf2 dk rejected");
}

static int cli_case(int argc, char **argv, int status, const char *want)
{
    FILE *output = tmpfile();
    if (!output) return 1;
    cli_sink = output;
    int bad = zscrypt_cli_main(argc, argv) != status;
    rewind(output);
    char bytes[80];
    size_t n = fread(bytes, 1, sizeof bytes, output);
    if (ferror(output) || n != strlen(want) || memcmp(bytes, want, n) != 0)
        bad = 1;
    if (fclose(output) != 0) bad = 1;
    return bad;
}

static void test_cli_args(void)
{
    char maximum[3 * sizeof(unsigned long) + 1];
    snprintf(maximum, sizeof maximum, "%lu", ULONG_MAX);
    unsigned long parsed = 0;
    check(parse_cost(maximum, &parsed) && parsed == ULONG_MAX,
          "CLI parser accepts ULONG_MAX without deriving");
    char *args[] = {"zscrypt", "pw", "salt", "2", "extra", NULL};
    const char *invalid[] = {"2junk", "", "+2", "-2", " 2", "2 ",
        "2\n", "184467440737095516160", "0x2"};
    for (size_t i = 0; i < sizeof invalid / sizeof invalid[0]; i++) {
        args[3] = (char *)invalid[i];
        check(cli_case(4, args, 2, "") == 0, "CLI rejects malformed N without output");
    }
    args[3] = "2";
    check(cli_case(5, args, 2, "") == 0, "CLI rejects extra argument");
    check(cli_case(1, args, 2, "") == 0, "CLI requires passphrase");
    const unsigned long costs[] = {2, 16384, 16384};
    for (size_t i = 0; i < sizeof costs / sizeof costs[0]; i++) {
        uint8_t dk[32];
        char want[66];
        const char *salt = i == 2 ? "zscrypt" : "salt";
        if (zscrypt("pw", 2, salt, strlen(salt), costs[i], 8, 1, dk, sizeof dk) != 0) {
            check(0, "CLI reference derivation");
            continue;
        }
        for (size_t j = 0; j < sizeof dk; j++)
            snprintf(want + 2 * j, 3, "%02x", dk[j]);
        want[64] = '\n'; want[65] = '\0';
        check(cli_case(4 - (int)i, args, 0, want) == 0, "CLI valid N and default output");
    }
    args[3] = "3";
    check(cli_case(4, args, 1, "") == 0, "CLI retains library power-of-two validation");
}

static int cli_output_failure(bool buffered)
{
#if defined(__linux__)
    FILE *output = fopen(buffered ? "/dev/full" : "/dev/null", buffered ? "w" : "r");
#elif defined(_WIN32)
    FILE *output = fopen("NUL", "r");
#else
    FILE *output = fopen("/dev/null", "r");
#endif
    if (!output) return 1;
    char buffer[4096];
    if (buffered && setvbuf(output, buffer, _IOFBF, sizeof buffer) != 0) {
        fclose(output);
        return 1;
    }
    cli_sink = output;
    char *args[] = {"zscrypt", "pw", "salt", "2", NULL};
    int bad = zscrypt_cli_main(4, args) != 1 || !ferror(output);
    if (buffered) (void)fclose(output);
    else if (fclose(output) != 0) bad = 1;
    return bad;
}

static void test_cli_output(void)
{
    char *args[] = {"zscrypt", "pw", "salt", "2", NULL};
    check(cli_case(4, args, 0, "4cbdb601720926082a6dd5a15313d860c799be83d7363e4ab7ba1f1d0194356b\n") == 0,
          "CLI known N2 output");
    check(cli_output_failure(false) == 0, "CLI refuses readonly output");
#if defined(__linux__)
    check(cli_output_failure(true) == 0, "CLI refuses buffered output failure");
#endif
}

int main(void)
{
    test_cli_output();
    test_cli_args();
    test_pbkdf2();
    test_scrypt_vectors();
    test_variable_output_len();
    test_errors();
    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    puts("zscrypt: all tests passed");
    return 0;
}
