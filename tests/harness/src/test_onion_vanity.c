/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for core.network.onion.vanity (tools/command/native_onion_vanity.c)
 * and its search primitives (tools/command/onion_vanity_search.c). No
 * network, no Tor. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "kernel/command_registry.h"
#include "command/onion_vanity.h"
#include "crypto/ed25519.h"
#include "crypto/random_secret.h"
#include "json/json.h"
#include "net/tor_integration.h"
#include "support/cleanse.h"

#include <dirent.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define OVT_JSON_MAX 4096

struct ovt_reply {
    struct zcl_command_reply reply;
    char json[OVT_JSON_MAX];
};

/* Runs the leaf with `fmt` as the JSON input; `dir` and the file name are
 * formatted into it. */
static void ovt_run(struct ovt_reply *r, const char *input_json)
{
    struct json_value input;
    json_init(&input);
    (void)json_read(&input, input_json, strlen(input_json));
    struct zcl_command_request request = { .input = &input };
    zcl_command_reply_init(&r->reply, "zcl.core_network_onion_vanity.v1");
    zcl_native_handle_core_network_onion_vanity(&request, &r->reply);
    r->json[0] = '\0';
    (void)json_write(&r->reply.data, r->json, sizeof(r->json));
    json_free(&input);
}

static void ovt_free(struct ovt_reply *r) { zcl_command_reply_free(&r->reply); }

static const char *ovt_str(const struct ovt_reply *r, const char *key)
{
    return json_get_str(json_get(&r->reply.data, key));
}

static size_t ovt_entries(const char *dir)
{
    size_t n = 0;
    DIR *d = opendir(dir);
    if (!d)
        return (size_t)-1;
    for (struct dirent *e; (e = readdir(d)) != NULL;)
        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0)
            n++;
    closedir(d);
    return n;
}

static bool ovt_read_seed(const char *path, uint8_t seed[32])
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    size_t got = fread(seed, 1, 32, f);
    int extra = fgetc(f);
    fclose(f);
    return got == 32 && extra == EOF;
}

static bool ovt_contains(const char *hay, size_t hay_len, const void *needle,
                         size_t needle_len)
{
    for (size_t i = 0; i + needle_len <= hay_len; i++)
        if (memcmp(hay + i, needle, needle_len) == 0)
            return true;
    return false;
}

static void ovt_hex(const uint8_t *in, size_t n, bool upper, char *out)
{
    const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 15u];
    }
    out[2 * n] = '\0';
}

static void ovt_base64(const uint8_t *in, size_t n, bool urlsafe, char *out)
{
    const char *a = urlsafe
        ? "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        v |= i + 1 < n ? (uint32_t)in[i + 1] << 8 : 0;
        v |= i + 2 < n ? in[i + 2] : 0;
        out[o++] = a[(v >> 18) & 63];
        out[o++] = a[(v >> 12) & 63];
        out[o++] = i + 1 < n ? a[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < n ? a[v & 63] : '=';
    }
    out[o] = '\0';
}

/* True when `text` carries the seed as hex or base64, in any common form. */
static bool ovt_leaks_seed(const char *text, const uint8_t seed[32])
{
    char enc[96];
    size_t len = strlen(text);
    if (ovt_contains(text, len, seed, 32))
        return true;
    for (int upper = 0; upper < 2; upper++) {
        ovt_hex(seed, 32, upper != 0, enc);
        if (ovt_contains(text, len, enc, strlen(enc)))
            return true;
    }
    for (int urlsafe = 0; urlsafe < 2; urlsafe++) {
        ovt_base64(seed, 32, urlsafe != 0, enc);
        if (ovt_contains(text, len, enc, strlen(enc)))
            return true;
        enc[strlen(enc) - 1] = '\0'; /* unpadded form */
        if (ovt_contains(text, len, enc, strlen(enc)))
            return true;
    }
    return false;
}

static int t_prefix_validation(void)
{
    int failures = 0;
    TEST("onion vanity: prefix validation names each rejection") {
        struct onion_vanity_target t;
        char bad = 0;
        ASSERT_EQ(onion_vanity_target_parse("", &t, &bad),
                  ONION_VANITY_PREFIX_EMPTY);
        ASSERT_EQ(onion_vanity_target_parse("abcdefghijklm", &t, &bad),
                  ONION_VANITY_PREFIX_TOO_LONG);
        ASSERT_EQ(onion_vanity_target_parse("ab1", &t, &bad),
                  ONION_VANITY_PREFIX_BAD_CHAR);
        ASSERT_EQ(bad, '1');
        ASSERT_EQ(onion_vanity_target_parse("a-b", &t, &bad),
                  ONION_VANITY_PREFIX_BAD_CHAR);
        ASSERT_EQ(bad, '-');
        ASSERT_EQ(onion_vanity_target_parse("a8", &t, &bad),
                  ONION_VANITY_PREFIX_BAD_CHAR);
        ASSERT_EQ(onion_vanity_target_parse("Zz27", &t, &bad),
                  ONION_VANITY_PREFIX_OK);
        ASSERT_STR_EQ(t.text, "zz27");
        ASSERT_EQ(t.bits, 20u);
        ASSERT_EQ(onion_vanity_target_parse("abcdefghijkl", &t, &bad),
                  ONION_VANITY_PREFIX_OK);
        PASS();
    } _test_next:;
    return failures;
}

static int t_prefix_validation_leaf(const char *dir)
{
    int failures = 0;
    TEST("onion vanity: leaf rejects bad prefixes by name and writes nothing") {
        struct ovt_reply r;
        char in[512];
        snprintf(in, sizeof(in), "{\"prefix\":\"ab0\",\"output_path\":\"%s/seed\"}", dir);
        ovt_run(&r, in);
        ASSERT_STR_EQ(r.reply.error.code, "PREFIX_BAD_CHAR");
        ovt_free(&r);
        snprintf(in, sizeof(in), "{\"prefix\":\"\",\"output_path\":\"%s/seed\"}", dir);
        ovt_run(&r, in);
        ASSERT_STR_EQ(r.reply.error.code, "PREFIX_EMPTY");
        ovt_free(&r);
        snprintf(in, sizeof(in),
                 "{\"prefix\":\"aaaaaaaaaaaaa\",\"output_path\":\"%s/seed\"}", dir);
        ovt_run(&r, in);
        ASSERT_STR_EQ(r.reply.error.code, "PREFIX_TOO_LONG");
        ovt_free(&r);
        ASSERT_EQ(ovt_entries(dir), 0u);
        PASS();
    } _test_next:;
    return failures;
}

/* Finds `prefix`, then checks the file, the address, the mode, the staging
 * cleanup, the refusal to overwrite, and that the result carries no seed. */
static int t_find_and_write(const char *dir, const char *prefix)
{
    int failures = 0;
    TEST("onion vanity: prefix found, seed file drop-in, no leak") {
        char path[512], in[768];
        snprintf(path, sizeof(path), "%s/seed_%s", dir, prefix);
        snprintf(in, sizeof(in),
                 "{\"prefix\":\"%s\",\"output_path\":\"%s\",\"threads\":2}", prefix, path);
        size_t before = ovt_entries(dir);
        struct ovt_reply r;
        ovt_run(&r, in);
        ASSERT_EQ(r.reply.status, ZCL_COMMAND_STATUS_PASSED);
        const char *address = ovt_str(&r, "address");
        ASSERT(address != NULL);
        ASSERT_EQ(strlen(address), 62u);
        ASSERT(strncmp(address, prefix, strlen(prefix)) == 0);
        ASSERT(strcmp(address + 56, ".onion") == 0);

        uint8_t seed[32];
        ASSERT(ovt_read_seed(path, seed));
        char derived[64];
        ASSERT(onion_identity_address_from_seed(seed, derived, sizeof(derived)));
        ASSERT(strncmp(address, derived, 56) == 0);
        ASSERT(json_get_int(json_get(&r.reply.data, "tries")) >= 1);
        ASSERT(json_get_int(json_get(&r.reply.data, "threads")) == 2);
        ASSERT(json_get(&r.reply.data, "expected_tries") != NULL);

        struct stat st;
        ASSERT(stat(path, &st) == 0);
        ASSERT_EQ((unsigned)(st.st_mode & 07777), 0600u);
        ASSERT_EQ(ovt_entries(dir), before + 1);
        ASSERT(!ovt_leaks_seed(r.json, seed));
        ovt_free(&r);

        ovt_run(&r, in);
        ASSERT_STR_EQ(r.reply.error.code, "OUT_EXISTS");
        ASSERT(!ovt_leaks_seed(r.json, seed));
        ovt_free(&r);
        uint8_t again[32];
        ASSERT(ovt_read_seed(path, again));
        ASSERT(memcmp(seed, again, 32) == 0);
        ASSERT_EQ(ovt_entries(dir), before + 1);
        memory_cleanse(seed, sizeof(seed));
        PASS();
    } _test_next:;
    return failures;
}

static int t_leak_detector_positive_control(void)
{
    int failures = 0;
    TEST("onion vanity: the leak detector sees hex and base64 of a seed") {
        uint8_t seed[32];
        ASSERT(zcl_random_secret_bytes(seed, sizeof(seed), "ovt"));
        char enc[96], text[256];
        ovt_hex(seed, 32, false, enc);
        snprintf(text, sizeof(text), "{\"x\":\"%s\"}", enc);
        ASSERT(ovt_leaks_seed(text, seed));
        ovt_base64(seed, 32, false, enc);
        snprintf(text, sizeof(text), "{\"x\":\"%s\"}", enc);
        ASSERT(ovt_leaks_seed(text, seed));
        ASSERT(!ovt_leaks_seed("{\"x\":\"none\"}", seed));
        PASS();
    } _test_next:;
    return failures;
}

static int t_max_tries(const char *dir)
{
    int failures = 0;
    TEST("onion vanity: max_tries returns a named not-found and writes nothing") {
        char in[512];
        snprintf(in, sizeof(in),
                 "{\"prefix\":\"aaaaaaaa\",\"output_path\":\"%s/never\","
                 "\"threads\":3,\"max_tries\":200}", dir);
        struct ovt_reply r;
        ovt_run(&r, in);
        ASSERT_EQ(r.reply.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(r.reply.error.code, "NOT_FOUND_MAX_TRIES");
        ASSERT(strstr(r.reply.error.message, "200 tries") != NULL);
        ovt_free(&r);
        ASSERT_EQ(ovt_entries(dir), 0u);
        PASS();
    } _test_next:;
    return failures;
}

static int t_estimate_and_guard(const char *dir)
{
    int failures = 0;
    TEST("onion vanity: estimate_only reports figures; long search needs consent") {
        struct ovt_reply r;
        ovt_run(&r, "{\"prefix\":\"abc\",\"estimate_only\":true,\"threads\":2}");
        ASSERT_EQ(r.reply.status, ZCL_COMMAND_STATUS_PASSED);
        const struct json_value *e = json_get(&r.reply.data, "estimate");
        ASSERT(e != NULL);
        ASSERT_EQ(json_get_int(json_get(e, "prefix_length")), 3);
        ASSERT(json_get_real(json_get(e, "expected_tries")) == 32768.0);
        ASSERT(json_get_real(json_get(e, "tries_per_second")) > 0.0);
        ASSERT(!json_get_bool(json_get(e, "exceeds_one_hour")));
        ovt_free(&r);

        ovt_run(&r, "{\"prefix\":\"aaaaaaaaaa\",\"estimate_only\":true}");
        e = json_get(&r.reply.data, "estimate");
        ASSERT(e != NULL);
        ASSERT(json_get_bool(json_get(e, "exceeds_one_hour")));
        ovt_free(&r);

        char in[512];
        snprintf(in, sizeof(in),
                 "{\"prefix\":\"aaaaaaaaaa\",\"output_path\":\"%s/long\"}", dir);
        ovt_run(&r, in);
        ASSERT_EQ(r.reply.status, ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(r.reply.error.code, "SEARCH_TOO_LONG");
        ovt_free(&r);
        ASSERT_EQ(ovt_entries(dir), 0u);
        PASS();
    } _test_next:;
    return failures;
}

/* The public-key bit test and the address string must agree for real keys:
 * the true prefix matches, and the prefix with its last character changed
 * does not. */
static int t_pk_bits_match_address_string(void)
{
    int failures = 0;
    TEST("onion vanity: pk bit test agrees with the address string (1000 keys)") {
        static const char alpha[] = "abcdefghijklmnopqrstuvwxyz234567";
        for (unsigned i = 0; i < 1000; i++) {
            uint8_t seed[32], pk[32], sk[32];
            ASSERT(zcl_random_secret_bytes(seed, sizeof(seed), "ovt"));
            char address[64];
            ASSERT(onion_identity_address_from_seed(seed, address,
                                                   sizeof(address)));
            ed25519_keypair(pk, sk, seed);
            size_t len = 1 + i % ONION_VANITY_PREFIX_MAX;
            char prefix[ONION_VANITY_PREFIX_MAX + 1];
            memcpy(prefix, address, len);
            prefix[len] = '\0';
            struct onion_vanity_target t;
            ASSERT_EQ(onion_vanity_target_parse(prefix, &t, NULL),
                      ONION_VANITY_PREFIX_OK);
            ASSERT(onion_vanity_pk_matches(&t, pk));
            const char *at = strchr(alpha, prefix[len - 1]);
            prefix[len - 1] = alpha[((size_t)(at - alpha) + 1) % 32];
            ASSERT_EQ(onion_vanity_target_parse(prefix, &t, NULL),
                      ONION_VANITY_PREFIX_OK);
            ASSERT(!onion_vanity_pk_matches(&t, pk));
            memory_cleanse(seed, sizeof(seed));
            memory_cleanse(sk, sizeof(sk));
        }
        PASS();
    } _test_next:;
    return failures;
}

static atomic_bool g_ovt_done;

/* Raises SIGINT in bursts of three every 100 ms until the search has
 * returned. Signals sent before the leaf installs its handler are ignored by
 * the test's SIG_IGN, so the first burst that counts is the first after the
 * search is running. A burst delivers the second and third signal while the
 * leaf's handler is still the disposition in force: the leaf must keep its
 * handler across repeated signals (a one-shot handler resets to SIG_DFL after
 * the first, and the second then kills the process). */
static void *ovt_interrupt_repeatedly(void *arg)
{
    (void)arg;
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };
    while (!atomic_load(&g_ovt_done)) {
        nanosleep(&ts, NULL);
        for (int i = 0; i < 3; i++)
            raise(SIGINT);
    }
    return NULL;
}

static int t_interrupt(const char *dir)
{
    int failures = 0;
    TEST("onion vanity: SIGINT stops the search, writes nothing, restores the handler") {
        void (*saved)(int) = signal(SIGINT, SIG_IGN);
        pthread_t thread; // raw-pthread-ok: test driver, joined below
        atomic_store(&g_ovt_done, false);
        ASSERT_EQ(pthread_create(&thread, NULL, ovt_interrupt_repeatedly, NULL),
                  0);
        char in[512];
        snprintf(in, sizeof(in),
                 "{\"prefix\":\"aaaaaaaa\",\"output_path\":\"%s/never\","
                 "\"accept_long_search\":true,\"timeout_s\":60}", dir);
        struct ovt_reply r;
        ovt_run(&r, in);
        atomic_store(&g_ovt_done, true);
        pthread_join(thread, NULL);
        void (*after)(int) = signal(SIGINT, saved);
        ASSERT_STR_EQ(r.reply.error.code, "INTERRUPTED");
        ovt_free(&r);
        ASSERT(after == SIG_IGN);
        ASSERT_EQ(ovt_entries(dir), 0u);
        PASS();
    } _test_next:;
    return failures;
}

static int t_timeout(const char *dir)
{
    int failures = 0;
    TEST("onion vanity: timeout_s returns a named not-found") {
        char in[512];
        snprintf(in, sizeof(in),
                 "{\"prefix\":\"aaaaaaaa\",\"output_path\":\"%s/never\","
                 "\"accept_long_search\":true,\"timeout_s\":1}", dir);
        struct ovt_reply r;
        ovt_run(&r, in);
        ASSERT_STR_EQ(r.reply.error.code, "NOT_FOUND_TIMEOUT");
        ovt_free(&r);
        ASSERT_EQ(ovt_entries(dir), 0u);
        PASS();
    } _test_next:;
    return failures;
}

/* The registered leaf, dispatched through the registry: key types and ranges
 * are validated and the envelope is the one a CLI caller sees. */
static bool ovt_dispatch(const char *input_json, char *out, size_t out_size,
                         enum zcl_command_exit *exit_code)
{
    const struct zcl_command_registry *registry = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(
        registry, "core.network.onion.vanity", NULL);
    struct zcl_command_context context = {
        .registry = registry, .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
    };
    struct json_value input;
    char why[160];
    json_init(&input);
    bool ok = spec && json_read(&input, input_json, strlen(input_json)) &&
              zcl_command_registry_input_validate(spec, &input, why, sizeof(why));
    size_t n = ok ? zcl_command_registry_execute_json(
        registry, spec, &context, &input, false, spec->path, "normal", 0, 0,
        NULL, out, out_size - 1, exit_code) : 0;
    out[n < out_size ? n : out_size - 1] = '\0';
    json_free(&input);
    return ok && n > 0;
}

static int t_registry_dispatch(const char *dir)
{
    int failures = 0;
    TEST("onion vanity: registered leaf validates input and answers through the registry") {
        char out[OVT_JSON_MAX * 4];
        enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
        ASSERT(ovt_dispatch("{\"prefix\":\"abc\",\"estimate_only\":true,"
                            "\"threads\":2}", out, sizeof(out), &code));
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "\"expected_tries\":32768") != NULL);
        ASSERT(!ovt_dispatch("{\"prefix\":\"abc\",\"threads\":65}", out,
                             sizeof(out), &code));
        ASSERT(!ovt_dispatch("{\"prefix\":\"abc\",\"estimate_only\":\"yes\"}",
                             out, sizeof(out), &code));
        char in[512];
        snprintf(in, sizeof(in), "{\"prefix\":\"7\",\"output_path\":\"%s/via_registry\","
                 "\"threads\":2}", dir);
        ASSERT(ovt_dispatch(in, out, sizeof(out), &code));
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "\"status\":\"found\"") != NULL);
        ASSERT_EQ(ovt_entries(dir), 1u);
        PASS();
    } _test_next:;
    return failures;
}

/* The independent vector from test_onion_persistence.c: seed 00..1f derives
 * an address beginning aoqqpp7t. */
static int t_fixed_vector(void)
{
    int failures = 0;
    TEST("onion vanity: matcher agrees with the fixed seed 00..1f vector") {
        uint8_t seed[32], pk[32], sk[32];
        for (int i = 0; i < 32; i++)
            seed[i] = (uint8_t)i;
        char address[64];
        ASSERT(onion_identity_address_from_seed(seed, address, sizeof(address)));
        ASSERT(strncmp(address, "aoqqpp7t", 8) == 0);
        ed25519_keypair(pk, sk, seed);
        struct onion_vanity_target t;
        ASSERT_EQ(onion_vanity_target_parse("aoqqpp7t", &t, NULL),
                  ONION_VANITY_PREFIX_OK);
        ASSERT(onion_vanity_pk_matches(&t, pk));
        ASSERT_EQ(onion_vanity_target_parse("AOQQPP7T", &t, NULL),
                  ONION_VANITY_PREFIX_OK);
        ASSERT(onion_vanity_pk_matches(&t, pk));
        ASSERT_EQ(onion_vanity_target_parse("aoqqpp7s", &t, NULL),
                  ONION_VANITY_PREFIX_OK);
        ASSERT(!onion_vanity_pk_matches(&t, pk));
        PASS();
    } _test_next:;
    return failures;
}

static int t_missing_parent(const char *dir)
{
    int failures = 0;
    TEST("onion vanity: missing parent directory is refused before searching") {
        char in[512];
        snprintf(in, sizeof(in),
                 "{\"prefix\":\"q\",\"output_path\":\"%s/absent/seed\"}", dir);
        struct ovt_reply r;
        ovt_run(&r, in);
        ASSERT_STR_EQ(r.reply.error.code, "OUT_PATH_INVALID");
        ovt_free(&r);
        ASSERT_EQ(ovt_entries(dir), 0u);
        PASS();
    } _test_next:;
    return failures;
}

static int t_dangling_symlink(const char *dir)
{
    int failures = 0;
    TEST("onion vanity: a dangling symlink at output_path is refused, target untouched") {
        char link[512], target[512], in[1024];
        snprintf(link, sizeof(link), "%s/link", dir);
        snprintf(target, sizeof(target), "%s/target", dir);
        ASSERT_EQ(symlink(target, link), 0);
        snprintf(in, sizeof(in), "{\"prefix\":\"q\",\"output_path\":\"%s\"}", link);
        struct ovt_reply r;
        ovt_run(&r, in);
        ASSERT_STR_EQ(r.reply.error.code, "OUT_EXISTS");
        ovt_free(&r);
        struct stat st;
        ASSERT(stat(target, &st) != 0);
        ASSERT_EQ(ovt_entries(dir), 1u);
        PASS();
    } _test_next:;
    return failures;
}

static int t_find_one_char(const char *dir) { return t_find_and_write(dir, "q"); }
static int t_find_two_chars(const char *dir) { return t_find_and_write(dir, "m2"); }

/* Each case runs in its own empty directory. */
static int ovt_in_dir(int (*fn)(const char *))
{
    char dir[256];
    if (!test_mkdtemp(dir, sizeof(dir), "onion_vanity"))
        return 1;
    int failures = fn(dir);
    test_cleanup_tmpdir(dir);
    return failures;
}

int test_onion_vanity(void);
int test_onion_vanity(void)
{
    printf("\n=== onion vanity tests ===\n");
    int failures = 0;
    failures += t_prefix_validation();
    failures += t_leak_detector_positive_control();
    failures += t_pk_bits_match_address_string();
    failures += t_fixed_vector();
    failures += ovt_in_dir(t_prefix_validation_leaf);
    failures += ovt_in_dir(t_missing_parent);
    failures += ovt_in_dir(t_dangling_symlink);
    failures += ovt_in_dir(t_find_one_char);
    failures += ovt_in_dir(t_find_two_chars);
    failures += ovt_in_dir(t_registry_dispatch);
    failures += ovt_in_dir(t_max_tries);
    failures += ovt_in_dir(t_estimate_and_guard);
    failures += ovt_in_dir(t_timeout);
    failures += ovt_in_dir(t_interrupt);
    return failures;
}
