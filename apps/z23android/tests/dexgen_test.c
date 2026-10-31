/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
/* Checks the generated classes.dex structurally. Usage: dexgen-test <scratch-dir> [dexdump] */
#define DEXGEN_NO_MAIN
#include "../dexgen.c"
#include <stdlib.h>

static int failures;
#define CHECK(cond) do { if (!(cond)) { fprintf(stderr, "dexgen_test: %s:%d: %s\n", __FILE__, __LINE__, #cond); ++failures; } } while (0)

static uint32_t rd32(const uint8_t *p) { return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint32_t rd16(const uint8_t *p) { return p[0] | (uint32_t)p[1] << 8; }

static void test_digests(void)
{
    static const uint8_t abc[] = "abc", wiki[] = "Wikipedia";
    static const uint8_t expected[20] = { 0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
                                          0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d };
    uint8_t digest[20];
    dexgen_sha1(abc, 3, digest);
    CHECK(!memcmp(digest, expected, 20));
    CHECK(dexgen_adler32(wiki, 9) == 0x11e60398u);
}
static void test_header(const uint8_t *d, size_t n)
{
    uint8_t digest[20];
    CHECK(!memcmp(d, "dex\n035\0", 8));
    CHECK(rd32(d + 32) == n && rd32(d + 36) == 0x70 && rd32(d + 40) == 0x12345678);
    CHECK(rd32(d + 8) == dexgen_adler32(d + 12, n - 12));
    dexgen_sha1(d + 32, n - 32, digest);
    CHECK(!memcmp(d + 12, digest, 20));
    CHECK(rd32(d + 56) == S_COUNT && rd32(d + 64) == T_COUNT && rd32(d + 72) == P_COUNT);
    CHECK(rd32(d + 80) == 0 && rd32(d + 88) == M_COUNT && rd32(d + 96) == 2);
    CHECK(rd32(d + 108) == rd32(d + 100) + 64 && rd32(d + 104) == n - rd32(d + 108));
}
/* The string at index i, read from its string_data item. */
static const char *string_at(const uint8_t *d, uint32_t i)
{
    return (const char *)d + rd32(d + rd32(d + 60) + 4 * i) + 1;
}
static void test_sorted_ids(const uint8_t *d)
{
    for (uint32_t i = 1; i < S_COUNT; ++i) CHECK(strcmp(string_at(d, i - 1), string_at(d, i)) < 0);
    for (uint32_t i = 1; i < T_COUNT; ++i) CHECK(rd32(d + rd32(d + 68) + 4 * (i - 1)) < rd32(d + rd32(d + 68) + 4 * i));
    const uint8_t *m = d + rd32(d + 92);
    for (uint32_t i = 1; i < M_COUNT; ++i) {
        const uint8_t *a = m + 8 * (i - 1), *b = m + 8 * i;
        CHECK(rd16(a) < rd16(b) || (rd16(a) == rd16(b) && (rd32(a + 4) < rd32(b + 4) ||
              (rd32(a + 4) == rd32(b + 4) && rd16(a + 2) < rd16(b + 2)))));
    }
    CHECK(!strcmp(string_at(d, rd32(d + rd32(d + 68) + 4 * T_NODE)), "Lorg/z23/nativeapp/NodeService;"));
    CHECK(!strcmp(string_at(d, rd32(d + rd32(d + 68) + 4 * T_KEYPROMPT)), "Lorg/z23/nativeapp/KeyPrompt;"));
    CHECK(!strcmp(string_at(d, rd32(d + rd32(d + 68) + 4 * T_CALLBACK)), "Landroid/hardware/biometrics/BiometricPrompt$AuthenticationCallback;"));
}
static void test_map(const uint8_t *d, size_t n)
{
    uint32_t off = rd32(d + 52), count = rd32(d + off), previous = 0;
    CHECK(off % 4 == 0 && off + 4 + 12 * count == n && count == 11);
    for (uint32_t i = 0; i < count; ++i) {
        const uint8_t *item = d + off + 4 + 12 * i;
        uint32_t at = rd32(item + 8);
        CHECK(i == 0 || at > previous);
        previous = at;
        if (rd16(item) == 0x1000) CHECK(at == off && rd32(item + 4) == 1);
        if (rd16(item) == 0x0001) CHECK(at == rd32(d + 60) && rd32(item + 4) == S_COUNT);
        if (rd16(item) == 0x2001) CHECK(rd32(item + 4) == C_COUNT && at % 4 == 0);
    }
}
/* True when the dexdump listing has a method called name on KeyPrompt with the given type, and when
 * native is set, with the native flag: the listing shows the class before the name, then the type and
 * the access flags. A missing or retyped method is a link failure on the phone. */
static bool key_prompt_method(const char *listing, const char *name, const char *type, bool native)
{
    char want[160], sig[220];
    snprintf(want, sizeof(want), "name          : '%s'", name);
    snprintf(sig, sizeof(sig), "type          : '%s'", type);
    for (const char *at = strstr(listing, want); at; at = strstr(at + 1, want)) {
        char window[512];
        size_t before = (size_t)(at - listing) < 100 ? (size_t)(at - listing) : 100;
        snprintf(window, sizeof(window), "%.*s", (int)(before + 260), at - before);
        const char *class_at = strstr(window, "(in Lorg/z23/nativeapp/KeyPrompt;)");
        const char *name_at = strstr(window, want);
        const char *type_at = strstr(window, sig);
        const char *access_at = strstr(window, "access        : ");
        if (class_at && name_at && type_at && access_at && class_at < name_at && name_at < type_at && type_at < access_at &&
            (!native || strstr(access_at, "NATIVE"))) return true;
    }
    fprintf(stderr, "dexgen_test: KeyPrompt lacks %s %s%s\n", name, type, native ? " (native)" : "");
    return false;
}
static void test_key_prompt_methods(const char *dexdump, const char *path, const char *scratch)
{
    char listing_path[512], cmd[1400];
    static char listing[1 << 16];
    snprintf(listing_path, sizeof(listing_path), "%s/listing.txt", scratch);
    snprintf(cmd, sizeof(cmd), "'%s' -d '%s' > '%s'", dexdump, path, listing_path);
    CHECK(system(cmd) == 0);
    FILE *f = fopen(listing_path, "rb");
    size_t got = f ? fread(listing, 1, sizeof(listing) - 1, f) : 0;
    CHECK(f && got > 0);
    if (f) (void)fclose(f);
    listing[got] = '\0';
    CHECK(key_prompt_method(listing, "onAuthenticationSucceeded", "(Landroid/hardware/biometrics/BiometricPrompt$AuthenticationResult;)V", true));
    CHECK(key_prompt_method(listing, "onAuthenticationError", "(ILjava/lang/CharSequence;)V", true));
    CHECK(key_prompt_method(listing, "<init>", "()V", false));
    remove(listing_path);
}
static void test_dexdump(const uint8_t *d, size_t n, const char *scratch, const char *dexdump)
{
    char path[512], cmd[1200];
    snprintf(path, sizeof(path), "%s/classes.dex", scratch);
    FILE *f = fopen(path, "wb");
    CHECK(f && fwrite(d, 1, n, f) == n);
    if (f) CHECK(fclose(f) == 0);
    if (!dexdump && getenv("Z23_NO_DEXDUMP")) { puts("dexgen_test: SKIPPED the dexdump checks (Z23_NO_DEXDUMP is set)"); return; }
    CHECK(dexdump && "dexdump is required: set DEXDUMP to the SDK build-tools dexdump, or set Z23_NO_DEXDUMP=1 to skip");
    if (!dexdump) return;
    snprintf(cmd, sizeof(cmd), "'%s' -c '%s' && '%s' -d '%s'", dexdump, path, dexdump, path);
    CHECK(system(cmd) == 0);
    test_key_prompt_methods(dexdump, path, scratch);
    remove(path);
}
int main(int argc, char **argv)
{
    static uint8_t first[DEX_MAX], second[DEX_MAX];
    if (argc < 2) { fputs("usage: dexgen-test <scratch-dir> [dexdump]\n", stderr); return 2; }
    test_digests();
    size_t n = dexgen_build(first, sizeof(first));
    CHECK(n > HEADER_SIZE);
    CHECK(dexgen_build(second, sizeof(second)) == n && !memcmp(first, second, n));
    CHECK(dexgen_build(second, n - 1) == 0);
    if (n > HEADER_SIZE) {
        test_header(first, n); test_sorted_ids(first); test_map(first, n);
        test_dexdump(first, n, argv[1], argc > 2 ? argv[2] : NULL);
    }
    if (failures) { fprintf(stderr, "dexgen_test: %d failure(s)\n", failures); return 1; }
    printf("dexgen_test: ok (%zu bytes)\n", n);
    return 0;
}
