/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: prove independent-builder attestations. A manifest is accepted only
 * when K distinct pinned builder keys attest its sha3_512 for one source
 * root; a duplicate builder, an unpinned builder, a mismatched hash, a
 * mismatched source root and a threshold above the pinned builders are each
 * refused with their own code, and the record parser is total. Fixtures sign
 * with real Ed25519 keys made by plugin_keygen; the "image" is plain bytes. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "plugin/plugin_attest.h"
#include "plugin/plugin_pack.h"
#include "plugin/plugin_store.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PAT_ROOT_A "1111111111111111111111111111111111111111111111111111111111111111"
#define PAT_ROOT_B "2222222222222222222222222222222222222222222222222222222222222222"

struct pat_fx {
    char base[PATH_MAX];
    char manifest[PATH_MAX];
    char exe[PATH_MAX];
    char other[PATH_MAX];     /* image bytes that differ from the manifest's */
    char pins[PATH_MAX];
    char key[4][PATH_MAX];    /* builder key files 0..3 */
    char pub[4][65];
    int serial;
};

static bool pat_write(const char *path, const char *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    bool ok = f && fwrite(data, 1, len, f) == len;
    if (f)
        ok = fclose(f) == 0 && ok;
    return ok;
}

static bool pat_slurp(const char *path, char *out, size_t cap, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    *len = fread(out, 1, cap - 1, f);
    fclose(f);
    out[*len] = '\0';
    return true;
}

static bool pat_path(char *out, size_t cap, const char *a, const char *b)
{
    int n = snprintf(out, cap, "%s/%s", a, b);
    return n > 0 && (size_t)n < cap;
}

/* Publisher side through the real packer, so the manifest hash is the exe's. */
static bool pat_publish(struct pat_fx *fx)
{
    char pubkey[PATH_MAX], dist[PATH_MAX], pub[65], exe[PATH_MAX];
    struct plugin_pack_result res;
    bool ok = pat_path(exe, sizeof(exe), fx->base, "hello.src") &&
              pat_write(exe, "the same bytes", 14) &&
              pat_path(pubkey, sizeof(pubkey), fx->base, "pub.key") &&
              plugin_keygen(pubkey, pub) == PLUGIN_OK &&
              pat_path(dist, sizeof(dist), fx->base, "dist");
    struct plugin_pack_request rq = { .exe_path = exe, .name = "hello", .version = "1.0.0",
                                      .key_path = pubkey, .out_dir = dist,
                                      .capabilities = 0 };
    ok = ok && plugin_pack(&rq, &res) == PLUGIN_OK;
    snprintf(fx->manifest, sizeof(fx->manifest), "%s", res.manifest_path);
    return ok && pat_path(fx->exe, sizeof(fx->exe), dist, "hello") &&
           pat_path(fx->other, sizeof(fx->other), fx->base, "other.bin") &&
           pat_write(fx->other, "different bytes", 15);
}

static bool pat_open(struct pat_fx *fx)
{
    memset(fx, 0, sizeof(*fx));
    if (!test_mkdtemp(fx->base, sizeof(fx->base), "plugin_attest"))
        return false;
    bool ok = pat_publish(fx);
    for (int i = 0; ok && i < 4; i++) {
        char leaf[16];
        snprintf(leaf, sizeof(leaf), "b%d.key", i);
        ok = pat_path(fx->key[i], sizeof(fx->key[i]), fx->base, leaf) &&
             plugin_keygen(fx->key[i], fx->pub[i]) == PLUGIN_OK;
    }
    return ok && pat_path(fx->pins, sizeof(fx->pins), fx->base, "builders.pin");
}

static void pat_close(struct pat_fx *fx)
{
    if (fx->base[0])
        (void)test_rm_rf_recursive(fx->base);
}

/* Pin builders 0..n-1, one per line, owner-only like a trust root. */
static bool pat_pin(struct pat_fx *fx, int n)
{
    char text[1024] = "# builder pins\n";
    for (int i = 0; i < n; i++) {
        strcat(text, fx->pub[i]);
        strcat(text, "\n");
    }
    return pat_write(fx->pins, text, strlen(text)) && chmod(fx->pins, 0600) == 0;
}

/* A fresh attestation directory for one case. */
static bool pat_dir(struct pat_fx *fx, char dir[PATH_MAX])
{
    char leaf[24];
    snprintf(leaf, sizeof(leaf), "att%d", ++fx->serial);
    return pat_path(dir, PATH_MAX, fx->base, leaf) && mkdir(dir, 0700) == 0;
}

static enum plugin_attest_status pat_make(const struct pat_fx *fx, int builder,
                                          const char *image, const char *name,
                                          const char *root, const char *toolchain,
                                          const char *dir)
{
    struct plugin_attest_request rq = {
        .image_path = image, .key_path = fx->key[builder], .name = name,
        .version = "1.0.0", .source_root = root, .toolchain = toolchain, .dir = dir
    };
    struct plugin_attest_result res;
    return plugin_attest_make(&rq, &res);
}

static enum plugin_attest_status pat_verify(const struct pat_fx *fx, const char *dir,
                                            int64_t k, const char *root,
                                            struct plugin_attest_report *rep)
{
    return plugin_attest_verify_dir(fx->manifest, dir, fx->pins, k, root, rep);
}

/* Copy a file under a second leaf: an attacker can always do this by hand. */
static bool pat_copy(const char *dir, const char *from_leaf, const char *to_leaf)
{
    char a[PATH_MAX], b[PATH_MAX], buf[2048];
    size_t n;
    return pat_path(a, sizeof(a), dir, from_leaf) && pat_path(b, sizeof(b), dir, to_leaf) &&
           pat_slurp(a, buf, sizeof(buf), &n) && pat_write(b, buf, n);
}

static bool pat_leaf_of(const struct pat_fx *fx, int builder, char leaf[64])
{
    return snprintf(leaf, 64, "hello-%.16s" PLUGIN_ATTEST_SUFFIX, fx->pub[builder]) > 0;
}

#define PAT_STATUS(st) plugin_attest_status_code(st)

static int pat_case_accept(void)
{
    int failures = 0;
    struct pat_fx fx;
    struct plugin_attest_report rep;
    char dir[PATH_MAX];
    TEST_CASE("two distinct pinned builders attesting one root and hash are accepted") {
        ASSERT(pat_open(&fx) && pat_pin(&fx, 3) && pat_dir(&fx, dir));
        ASSERT_EQ(pat_make(&fx, 0, fx.exe, "hello", PAT_ROOT_A, "gcc-14", dir), PLUGIN_ATTEST_OK);
        ASSERT_EQ(pat_make(&fx, 1, fx.exe, "hello", PAT_ROOT_A, "clang-19", dir), PLUGIN_ATTEST_OK);
        ASSERT_EQ(pat_verify(&fx, dir, 2, NULL, &rep), PLUGIN_ATTEST_OK);
        ASSERT_EQ(rep.attested, 2u);
        ASSERT_EQ(rep.pinned, 3u);
        ASSERT_EQ(rep.toolchains, 2u);
        ASSERT_STR_EQ(rep.source_root, PAT_ROOT_A);
        ASSERT_EQ(pat_verify(&fx, dir, 1, PAT_ROOT_A, &rep), PLUGIN_ATTEST_OK);
        ASSERT_EQ(plugin_attest_verify_dir(fx.manifest, dir, fx.pins, 2, NULL, &rep), PLUGIN_ATTEST_OK);
        pat_close(&fx);
    } TEST_END
    return failures;
}

static int pat_case_below_threshold(void)
{
    int failures = 0;
    struct pat_fx fx;
    struct plugin_attest_report rep;
    char dir[PATH_MAX];
    TEST_CASE("one attestation does not meet a threshold of two") {
        ASSERT(pat_open(&fx) && pat_pin(&fx, 2) && pat_dir(&fx, dir));
        ASSERT_EQ(pat_make(&fx, 0, fx.exe, "hello", PAT_ROOT_A, "gcc-14", dir), PLUGIN_ATTEST_OK);
        ASSERT_EQ(pat_verify(&fx, dir, 2, NULL, &rep), PLUGIN_ATTEST_BELOW_THRESHOLD);
        pat_close(&fx);
    } TEST_END
    return failures;
}

static int pat_case_duplicate(void)
{
    int failures = 0;
    struct pat_fx fx;
    struct plugin_attest_report rep;
    char dir[PATH_MAX], leaf[64];
    TEST_CASE("one builder attesting twice is a duplicate, not two builders") {
        ASSERT(pat_open(&fx) && pat_pin(&fx, 2) && pat_dir(&fx, dir) && pat_leaf_of(&fx, 0, leaf));
        ASSERT_EQ(pat_make(&fx, 0, fx.exe, "hello", PAT_ROOT_A, "gcc-14", dir), PLUGIN_ATTEST_OK);
        ASSERT(pat_copy(dir, leaf, "zz-copy" PLUGIN_ATTEST_SUFFIX));
        ASSERT_EQ(pat_verify(&fx, dir, 2, NULL, &rep), PLUGIN_ATTEST_DUPLICATE_BUILDER);
        ASSERT_STR_EQ(PAT_STATUS(PLUGIN_ATTEST_DUPLICATE_BUILDER), "PLUGIN_ATTEST_DUPLICATE_BUILDER");
        pat_close(&fx);
    } TEST_END
    return failures;
}

static int pat_case_unpinned(void)
{
    int failures = 0;
    struct pat_fx fx;
    struct plugin_attest_report rep;
    char dir[PATH_MAX];
    TEST_CASE("an attestation by a builder that is not pinned is refused") {
        ASSERT(pat_open(&fx) && pat_pin(&fx, 2) && pat_dir(&fx, dir));
        ASSERT_EQ(pat_make(&fx, 0, fx.exe, "hello", PAT_ROOT_A, "gcc-14", dir), PLUGIN_ATTEST_OK);
        ASSERT_EQ(pat_make(&fx, 3, fx.exe, "hello", PAT_ROOT_A, "gcc-14", dir), PLUGIN_ATTEST_OK);
        ASSERT_EQ(pat_verify(&fx, dir, 1, NULL, &rep), PLUGIN_ATTEST_BUILDER_UNPINNED);
        pat_close(&fx);
    } TEST_END
    return failures;
}

static int pat_case_hash(void)
{
    int failures = 0;
    struct pat_fx fx;
    struct plugin_attest_report rep;
    char dir[PATH_MAX];
    TEST_CASE("a builder that got different bytes than the manifest names is refused") {
        ASSERT(pat_open(&fx) && pat_pin(&fx, 2) && pat_dir(&fx, dir));
        ASSERT_EQ(pat_make(&fx, 0, fx.exe, "hello", PAT_ROOT_A, "gcc-14", dir), PLUGIN_ATTEST_OK);
        ASSERT_EQ(pat_make(&fx, 1, fx.other, "hello", PAT_ROOT_A, "clang-19", dir), PLUGIN_ATTEST_OK);
        ASSERT_EQ(pat_verify(&fx, dir, 1, NULL, &rep), PLUGIN_ATTEST_HASH_MISMATCH);
        pat_close(&fx);
    } TEST_END
    return failures;
}

static int pat_case_source_root(void)
{
    int failures = 0;
    struct pat_fx fx;
    struct plugin_attest_report rep;
    char dir[PATH_MAX];
    TEST_CASE("attestations for different source roots do not add up") {
        ASSERT(pat_open(&fx) && pat_pin(&fx, 2) && pat_dir(&fx, dir));
        ASSERT_EQ(pat_make(&fx, 0, fx.exe, "hello", PAT_ROOT_A, "gcc-14", dir), PLUGIN_ATTEST_OK);
        ASSERT_EQ(pat_make(&fx, 1, fx.exe, "hello", PAT_ROOT_B, "clang-19", dir), PLUGIN_ATTEST_OK);
        ASSERT_EQ(pat_verify(&fx, dir, 2, NULL, &rep), PLUGIN_ATTEST_SOURCE_ROOT_MISMATCH);
        ASSERT_EQ(pat_verify(&fx, dir, 1, PAT_ROOT_A, &rep), PLUGIN_ATTEST_SOURCE_ROOT_MISMATCH);
        pat_close(&fx);
    } TEST_END
    return failures;
}

static int pat_case_source_root_named(void)
{
    int failures = 0;
    struct pat_fx fx;
    struct plugin_attest_report rep;
    char dir[PATH_MAX];
    TEST_CASE("a source root the caller names must match every attestation") {
        ASSERT(pat_open(&fx) && pat_pin(&fx, 2) && pat_dir(&fx, dir));
        ASSERT_EQ(pat_make(&fx, 0, fx.exe, "hello", PAT_ROOT_A, "gcc-14", dir), PLUGIN_ATTEST_OK);
        ASSERT_EQ(pat_verify(&fx, dir, 1, PAT_ROOT_B, &rep), PLUGIN_ATTEST_SOURCE_ROOT_MISMATCH);
        pat_close(&fx);
    } TEST_END
    return failures;
}

static int pat_case_threshold(void)
{
    int failures = 0;
    struct pat_fx fx;
    struct plugin_attest_report rep;
    char dir[PATH_MAX];
    TEST_CASE("a threshold above the pinned builders is refused before any file is read") {
        ASSERT(pat_open(&fx) && pat_pin(&fx, 2) && pat_dir(&fx, dir));
        ASSERT_EQ(pat_make(&fx, 0, fx.exe, "hello", PAT_ROOT_A, "gcc-14", dir), PLUGIN_ATTEST_OK);
        ASSERT_EQ(pat_make(&fx, 1, fx.exe, "hello", PAT_ROOT_A, "gcc-14", dir), PLUGIN_ATTEST_OK);
        ASSERT_EQ(pat_verify(&fx, dir, 3, NULL, &rep), PLUGIN_ATTEST_THRESHOLD_EXCEEDS_PINS);
        ASSERT_EQ(rep.files, 0u);
        pat_close(&fx);
    } TEST_END
    return failures;
}

static int pat_case_threshold_dedupe(void)
{
    int failures = 0;
    struct pat_fx fx;
    struct plugin_attest_report rep;
    char dir[PATH_MAX];
    TEST_CASE("one key pinned three times is one pinned builder") {
        char text[512];
        ASSERT(pat_open(&fx) && pat_dir(&fx, dir));
        snprintf(text, sizeof(text), "%s\n%s\n%s\n", fx.pub[0], fx.pub[0], fx.pub[0]);
        ASSERT(pat_write(fx.pins, text, strlen(text)) && chmod(fx.pins, 0600) == 0);
        ASSERT_EQ(pat_verify(&fx, dir, 2, NULL, &rep), PLUGIN_ATTEST_THRESHOLD_EXCEEDS_PINS);
        ASSERT_EQ(rep.pinned, 1u);
        pat_close(&fx);
    } TEST_END
    return failures;
}

static int pat_case_threshold_low(void)
{
    int failures = 0;
    struct pat_fx fx;
    struct plugin_attest_report rep;
    char dir[PATH_MAX];
    TEST_CASE("a threshold below one is refused") {
        ASSERT(pat_open(&fx) && pat_pin(&fx, 2) && pat_dir(&fx, dir));
        ASSERT_EQ(pat_verify(&fx, dir, 0, NULL, &rep), PLUGIN_ATTEST_THRESHOLD_INVALID);
        ASSERT_EQ(pat_verify(&fx, dir, -1, NULL, &rep), PLUGIN_ATTEST_THRESHOLD_INVALID);
        pat_close(&fx);
    } TEST_END
    return failures;
}

static int pat_case_other_refusals(void)
{
    int failures = 0;
    struct pat_fx fx;
    struct plugin_attest_report rep;
    char dir[PATH_MAX];
    TEST_CASE("a record for another plugin name is refused") {
        ASSERT(pat_open(&fx) && pat_pin(&fx, 2) && pat_dir(&fx, dir));
        ASSERT_EQ(pat_make(&fx, 0, fx.exe, "other", PAT_ROOT_A, "gcc-14", dir), PLUGIN_ATTEST_OK);
        ASSERT_EQ(pat_verify(&fx, dir, 1, NULL, &rep), PLUGIN_ATTEST_SUBJECT_MISMATCH);
        pat_close(&fx);
    } TEST_END
    return failures;
}

static int pat_case_bad_signature(void)
{
    int failures = 0;
    struct pat_fx fx;
    struct plugin_attest_report rep;
    char dir[PATH_MAX], leaf[64], path[PATH_MAX], buf[2048];
    size_t n;
    TEST_CASE("a record with a flipped signature or image byte fails its signature") {
        ASSERT(pat_open(&fx) && pat_pin(&fx, 2) && pat_dir(&fx, dir) && pat_leaf_of(&fx, 0, leaf));
        ASSERT_EQ(pat_make(&fx, 0, fx.exe, "hello", PAT_ROOT_A, "gcc-14", dir), PLUGIN_ATTEST_OK);
        ASSERT(pat_path(path, sizeof(path), dir, leaf) && pat_slurp(path, buf, sizeof(buf), &n));
        char *sig = strstr(buf, "\"signature\":\"") + 13;
        sig[0] = sig[0] == '0' ? '1' : '0';
        ASSERT(pat_write(path, buf, n));
        ASSERT_EQ(pat_verify(&fx, dir, 1, NULL, &rep), PLUGIN_ATTEST_SIG_BAD);
        ASSERT(pat_make(&fx, 0, fx.exe, "hello", PAT_ROOT_A, "gcc-14", dir) == PLUGIN_ATTEST_OK &&
               pat_slurp(path, buf, sizeof(buf), &n));
        char *img = strstr(buf, "\"image_sha3_512\":\"") + 18;
        img[0] = img[0] == '0' ? '1' : '0';
        ASSERT(pat_write(path, buf, n));
        ASSERT_EQ(pat_verify(&fx, dir, 1, NULL, &rep), PLUGIN_ATTEST_SIG_BAD);
        pat_close(&fx);
    } TEST_END
    return failures;
}

static int pat_case_malformed_file(void)
{
    int failures = 0;
    struct pat_fx fx;
    struct plugin_attest_report rep;
    char dir[PATH_MAX], path[PATH_MAX];
    TEST_CASE("a malformed record in the directory is a refusal, not a skip") {
        ASSERT(pat_open(&fx) && pat_pin(&fx, 2) && pat_dir(&fx, dir));
        ASSERT_EQ(pat_make(&fx, 0, fx.exe, "hello", PAT_ROOT_A, "gcc-14", dir), PLUGIN_ATTEST_OK);
        ASSERT(pat_path(path, sizeof(path), dir, "zz.attest.json") && pat_write(path, "{}\n", 3));
        ASSERT_EQ(pat_verify(&fx, dir, 1, NULL, &rep), PLUGIN_ATTEST_MALFORMED);
        ASSERT_STR_EQ(rep.file, "zz.attest.json");
        pat_close(&fx);
    } TEST_END
    return failures;
}

static int pat_case_readdir_error(void)
{
    int failures = 0;
    struct pat_fx fx;
    struct plugin_attest_report rep;
    char dir[PATH_MAX];
    TEST_CASE("a directory read error is PLUGIN_ATTEST_IO, not a shorter directory") {
        ASSERT(pat_open(&fx) && pat_pin(&fx, 2) && pat_dir(&fx, dir));
        ASSERT_EQ(pat_make(&fx, 0, fx.exe, "hello", PAT_ROOT_A, "gcc-14", dir), PLUGIN_ATTEST_OK);
        ASSERT_EQ(pat_make(&fx, 1, fx.exe, "hello", PAT_ROOT_A, "clang-19", dir), PLUGIN_ATTEST_OK);
        plugin_attest_test_fail_readdir(3);
        ASSERT_EQ(pat_verify(&fx, dir, 1, NULL, &rep), PLUGIN_ATTEST_IO);
        plugin_attest_test_fail_readdir(UINT32_MAX);
        ASSERT_EQ(pat_verify(&fx, dir, 2, NULL, &rep), PLUGIN_ATTEST_OK);
        pat_close(&fx);
    } TEST_END
    return failures;
}

static int pat_case_status_text(void)
{
    int failures = 0;
    TEST_CASE("every refusal has a distinct code and a next action") {
        for (int s = PLUGIN_ATTEST_ARGUMENT; s <= PLUGIN_ATTEST_BELOW_THRESHOLD; s++) {
            const char *code = plugin_attest_status_code((enum plugin_attest_status)s);
            const char *next = plugin_attest_status_next_action((enum plugin_attest_status)s);
            ASSERT(strncmp(code, "PLUGIN_ATTEST_", 14) == 0 && next[0] != '\0');
            for (int u = PLUGIN_ATTEST_ARGUMENT; u < s; u++)
                ASSERT(strcmp(code, plugin_attest_status_code((enum plugin_attest_status)u)) != 0);
        }
        ASSERT_STR_EQ(plugin_attest_status_next_action(PLUGIN_ATTEST_OK), "");
        ASSERT_STR_EQ(plugin_attest_status_code((enum plugin_attest_status)999), "PLUGIN_ATTEST_UNKNOWN");
    } TEST_END
    return failures;
}

static int pat_case_manifest_digest_pin(void)
{
    int failures = 0;
    struct pat_fx fx;
    struct plugin_pack_result res;
    char exe[PATH_MAX], key[PATH_MAX], dist[PATH_MAX], pub[65];
    TEST_CASE("the signed-manifest digest of a fixed manifest is pinned to its hex value") {
        ASSERT(test_mkdtemp(fx.base, sizeof(fx.base), "plugin_attest"));
        ASSERT(pat_path(exe, sizeof(exe), fx.base, "exe") && pat_write(exe, "the same bytes", 14));
        ASSERT(pat_path(key, sizeof(key), fx.base, "k.key") && plugin_keygen(key, pub) == PLUGIN_OK);
        ASSERT(pat_path(dist, sizeof(dist), fx.base, "dist"));
        struct plugin_pack_request rq = { .exe_path = exe, .name = "hello", .version = "1.0.0",
                                          .key_path = key, .out_dir = dist };
        ASSERT_EQ(plugin_pack(&rq, &res), PLUGIN_OK);
        /* SHA3-512 of "z23.plugin.manifest.v1", NUL, the manifest bytes: computed
         * outside this tree with openssl before the digest helper was shared. */
        ASSERT_STR_EQ(res.generation,
            "464af05cdc16ecec1ccb60f942b11dc67ce19276dc9a216b2edab917af0966495eb3eda9a2d9a6f8d8a9a514ae10d217713d8de0ee5215ea8f0d56db2ca3bd01");
        (void)test_rm_rf_recursive(fx.base);
    } TEST_END
    return failures;
}

static int pat_case_pins(void)
{
    int failures = 0;
    struct pat_fx fx;
    struct plugin_attest_report rep;
    char dir[PATH_MAX];
    TEST_CASE("a pin file that is missing, writable by others or malformed is refused") {
        ASSERT(pat_open(&fx) && pat_dir(&fx, dir));
        ASSERT_EQ(pat_verify(&fx, dir, 1, NULL, &rep), PLUGIN_ATTEST_UPSTREAM);
        ASSERT_EQ(rep.cause, PLUGIN_ERR_NO_KEYS);
        ASSERT(pat_pin(&fx, 2) && chmod(fx.pins, 0666) == 0);
        ASSERT_EQ(pat_verify(&fx, dir, 1, NULL, &rep), PLUGIN_ATTEST_UPSTREAM);
        ASSERT_EQ(rep.cause, PLUGIN_ERR_KEYS_INSECURE);
        ASSERT(pat_write(fx.pins, "not-a-key\n", 10) && chmod(fx.pins, 0600) == 0);
        ASSERT_EQ(pat_verify(&fx, dir, 1, NULL, &rep), PLUGIN_ATTEST_PINS_MALFORMED);
        pat_close(&fx);
    } TEST_END
    return failures;
}

static int pat_case_parser(void)
{
    int failures = 0;
    struct pat_fx fx;
    char dir[PATH_MAX], leaf[64], path[PATH_MAX], buf[PLUGIN_ATTEST_RECORD_MAX];
    size_t n;
    struct plugin_attest_record rec, again;
    TEST_CASE("the parser is total: round trip, every prefix, every byte flip") {
        ASSERT(pat_open(&fx) && pat_dir(&fx, dir) && pat_leaf_of(&fx, 0, leaf));
        ASSERT_EQ(pat_make(&fx, 0, fx.exe, "hello", PAT_ROOT_A, "gcc-14", dir), PLUGIN_ATTEST_OK);
        ASSERT(pat_path(path, sizeof(path), dir, leaf) && pat_slurp(path, buf, sizeof(buf), &n));
        ASSERT_EQ(plugin_attest_parse(buf, n, &rec), PLUGIN_ATTEST_OK);
        char enc[PLUGIN_ATTEST_RECORD_MAX];
        ASSERT_EQ(plugin_attest_encode(&rec, enc, sizeof(enc)), n);
        ASSERT(memcmp(enc, buf, n) == 0);
        ASSERT_EQ(plugin_attest_check_signature(&rec), PLUGIN_ATTEST_OK);
        for (size_t i = 0; i < n; i++)
            ASSERT_EQ(plugin_attest_parse(buf, i, &again), PLUGIN_ATTEST_MALFORMED);
        buf[n] = '\n';
        ASSERT_EQ(plugin_attest_parse(buf, n + 1, &again), PLUGIN_ATTEST_MALFORMED);
        for (size_t i = 0; i < n; i++) {
            char saved = buf[i];
            buf[i] = saved == 'q' ? 'r' : 'q';
            enum plugin_attest_status st = plugin_attest_parse(buf, n, &again);
            ASSERT(st == PLUGIN_ATTEST_MALFORMED ||
                   (st == PLUGIN_ATTEST_OK && plugin_attest_check_signature(&again) != PLUGIN_ATTEST_OK));
            buf[i] = saved;
        }
        pat_close(&fx);
    } TEST_END
    return failures;
}

static int pat_case_deterministic(void)
{
    int failures = 0;
    struct pat_fx fx;
    char dir[PATH_MAX], leaf[64], path[PATH_MAX];
    char dir2[PATH_MAX], path2[PATH_MAX], one[PLUGIN_ATTEST_RECORD_MAX], two[PLUGIN_ATTEST_RECORD_MAX];
    size_t n1, n2;
    TEST_CASE("equal inputs give byte-identical attestations") {
        ASSERT(pat_open(&fx) && pat_dir(&fx, dir) && pat_dir(&fx, dir2) && pat_leaf_of(&fx, 0, leaf));
        ASSERT_EQ(pat_make(&fx, 0, fx.exe, "hello", PAT_ROOT_A, "gcc-14", dir), PLUGIN_ATTEST_OK);
        ASSERT_EQ(pat_make(&fx, 0, fx.exe, "hello", PAT_ROOT_A, "gcc-14", dir2), PLUGIN_ATTEST_OK);
        ASSERT(pat_path(path, sizeof(path), dir, leaf) && pat_path(path2, sizeof(path2), dir2, leaf));
        ASSERT(pat_slurp(path, one, sizeof(one), &n1) && pat_slurp(path2, two, sizeof(two), &n2));
        ASSERT(n1 == n2 && memcmp(one, two, n1) == 0);
        pat_close(&fx);
    } TEST_END
    return failures;
}

static int pat_case_make_refusals(void)
{
    int failures = 0;
    struct pat_fx fx;
    char dir[PATH_MAX];
    TEST_CASE("attest refuses a bad root, toolchain, name, key mode and image") {
        ASSERT(pat_open(&fx) && pat_dir(&fx, dir));
        ASSERT_EQ(pat_make(&fx, 0, fx.exe, "hello", "abc", "gcc-14", dir), PLUGIN_ATTEST_ARGUMENT);
        ASSERT_EQ(pat_make(&fx, 0, fx.exe, "hello", PAT_ROOT_A, "bad toolchain", dir), PLUGIN_ATTEST_ARGUMENT);
        ASSERT_EQ(pat_make(&fx, 0, fx.exe, "Hello", PAT_ROOT_A, "gcc-14", dir), PLUGIN_ATTEST_ARGUMENT);
        ASSERT_EQ(pat_make(&fx, 0, fx.base, "hello", PAT_ROOT_A, "gcc-14", dir), PLUGIN_ATTEST_UPSTREAM);
        ASSERT_EQ(chmod(fx.key[0], 0644), 0);
        ASSERT_EQ(pat_make(&fx, 0, fx.exe, "hello", PAT_ROOT_A, "gcc-14", dir), PLUGIN_ATTEST_UPSTREAM);
        pat_close(&fx);
    } TEST_END
    return failures;
}

static bool pat_call(zcl_command_handler_fn fn, const char *input_json,
                     struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    bool ok = json_read(&input, input_json, strlen(input_json));
    struct zcl_command_request request = { .input = &input, .view = "normal" };
    zcl_command_reply_init(reply, "zcl.plugin_test.v1");
    if (ok)
        fn(&request, reply);
    json_free(&input);
    return ok;
}

static int pat_case_commands(void)
{
    int failures = 0;
    struct pat_fx fx;
    struct zcl_command_reply r;
    char dir[PATH_MAX], in[4 * PATH_MAX];
    TEST_CASE("the two leaves attest, accept at K=2, and refuse with a PLUGIN_ATTEST code") {
        ASSERT(pat_open(&fx) && pat_pin(&fx, 2) && pat_dir(&fx, dir));
        for (int b = 0; b < 2; b++) {
            snprintf(in, sizeof(in),
                     "{\"image\":\"%s\",\"key\":\"%s\",\"name\":\"hello\",\"version\":\"1.0.0\","
                     "\"source-root\":\"%s\",\"toolchain\":\"tc-%d\",\"dir\":\"%s\"}",
                     fx.exe, fx.key[b], PAT_ROOT_A, b, dir);
            ASSERT(pat_call(zcl_native_handle_plugin_attest, in, &r));
            ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
            ASSERT(strstr(json_get_str(json_get(&r.data, "builder_key")), fx.pub[b]) != NULL);
            zcl_command_reply_free(&r);
        }
        snprintf(in, sizeof(in),
                 "{\"manifest\":\"%s\",\"attestations\":\"%s\",\"builders\":\"%s\",\"threshold\":2}",
                 fx.manifest, dir, fx.pins);
        ASSERT(pat_call(zcl_native_handle_plugin_attest_verify, in, &r));
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_EQ(json_get_int(json_get(&r.data, "attested")), 2);
        zcl_command_reply_free(&r);
        snprintf(in, sizeof(in),
                 "{\"manifest\":\"%s\",\"attestations\":\"%s\",\"builders\":\"%s\",\"threshold\":\"3\"}",
                 fx.manifest, dir, fx.pins);
        ASSERT(pat_call(zcl_native_handle_plugin_attest_verify, in, &r));
        ASSERT_STR_EQ(r.error.code, "PLUGIN_ATTEST_THRESHOLD_EXCEEDS_PINS");
        ASSERT(r.error.next_action[0] != '\0');
        zcl_command_reply_free(&r);
        pat_close(&fx);
    } TEST_END
    return failures;
}

static int pat_case_registered(void)
{
    int failures = 0;
    TEST_CASE("both leaves are registered, owner-only and the verifier writes nothing") {
        const struct zcl_command_registry *reg = zcl_command_catalog();
        const struct zcl_command_spec *s;
        ASSERT(reg);
        s = zcl_command_registry_find(reg, "plugin.attest", NULL);
        ASSERT(s && s->handler == zcl_native_handle_plugin_attest);
        ASSERT_EQ(s->authority, ZCL_COMMAND_AUTH_OWNER);
        s = zcl_command_registry_find(reg, "plugin.attest_verify", NULL);
        ASSERT(s && s->handler == zcl_native_handle_plugin_attest_verify);
        ASSERT_EQ(s->authority, ZCL_COMMAND_AUTH_OWNER);
        ASSERT_EQ(s->effect, ZCL_COMMAND_EFFECT_READ);
    } TEST_END
    return failures;
}

int test_plugin_attest(void)
{
    int failures = 0;
    printf("\n=== Plugin attestation tests ===\n");
    failures += pat_case_accept();
    failures += pat_case_below_threshold();
    failures += pat_case_duplicate();
    failures += pat_case_unpinned();
    failures += pat_case_hash();
    failures += pat_case_source_root();
    failures += pat_case_source_root_named();
    failures += pat_case_threshold();
    failures += pat_case_threshold_dedupe();
    failures += pat_case_threshold_low();
    failures += pat_case_other_refusals();
    failures += pat_case_bad_signature();
    failures += pat_case_malformed_file();
    failures += pat_case_readdir_error();
    failures += pat_case_status_text();
    failures += pat_case_manifest_digest_pin();
    failures += pat_case_pins();
    failures += pat_case_parser();
    failures += pat_case_deterministic();
    failures += pat_case_make_refusals();
    failures += pat_case_commands();
    failures += pat_case_registered();
    return failures;
}
