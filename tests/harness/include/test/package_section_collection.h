/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: actual package executable roots, retained archive API and policy IDs.
 * Included by the registered zcode_verify group after its fixture helpers. */
#ifndef ZCL_TEST_PACKAGE_SECTION_COLLECTION_H
#define ZCL_TEST_PACKAGE_SECTION_COLLECTION_H

#include "base/hex.h"
#include "platform/toolchain.h"

static bool zpr_receipt_policy_bound(const struct vcs_package_build_receipt *receipt)
{
    const struct platform_toolchain_commons_gc *gc = platform_toolchain_commons_gc();
    struct vcs_package_build_receipt old = *receipt;
    char marker[32];
    if (!gc) return false;
    int n = snprintf(marker, sizeof(marker), ";%s", gc->identity);
    char *at = n > 0 && (size_t)n < sizeof(marker) ? strstr(old.flags, marker) : NULL;
    if (!at) return false;
    if (strcmp(gc->identity, "gc=elf2") == 0)
        at[n - 1] = '1';
    else
        memmove(at, at + (size_t)n, strlen(at + (size_t)n) + 1u);
    uint8_t current_id[32], old_id[32];
    return vcs_package_build_id(receipt, current_id) == VCS_PACKAGE_BUILD_OK &&
        vcs_package_build_id(&old, old_id) == VCS_PACKAGE_BUILD_OK &&
        memcmp(current_id, old_id, 32u) != 0;
}

static int zpr_archive_api(const char *base, const char *emit)
{
    int failures = 0;
    static const char consumer[] =
        "extern int unused_function(void);\n"
        "extern int (*unused_data)(void);\n"
        "int unused_unrelated_provider(void) { return 17; }\n"
        "int main(void) { return unused_function() == 17 && unused_data() == 17 ? 0 : 1; }\n";
    char source[4500], archive[4500], binary[4500], output[512];
    snprintf(source, sizeof(source), "%s/api_consumer.c", base);
    snprintf(archive, sizeof(archive), "%s/lib/libaddpkg.a", emit);
    snprintf(binary, sizeof(binary), "%s/api_consumer", base);
    bool ready = zv_write_file(source, consumer, sizeof(consumer) - 1u, 0600);
    const char *compile[] = {"cc", "-std=c23", "-O1", source, archive, "-o", binary, NULL};
    int built = ready ? zcl_spawn_capture(compile, output, sizeof(output), 60000) : -1;
    const char *run[] = {binary, NULL};
    int ran = built == 0 ? zcl_spawn_capture(run, output, sizeof(output), 30000) : -1;
    ZV_CHECK("sections: installed archive still exports unused function and data APIs",
             built == 0 && ran == 0);
    return failures;
}

static int zpr_live_provider_case(const char *base, const char *lock,
                                  const char *work, const char *tag,
                                  const char *source)
{
    int failures = 0;
    const char test[] = "#include \"add.h\"\nint main(void) { return add(2, 3) == 5 ? 0 : 1; }\n";
    const char program[] = "#include \"add.h\"\nint main(void) { return add(2, 3); }\n";
    char store[4500], emit[4500], out[2048], root_hex[65];
    snprintf(store, sizeof(store), "%s/store_%s", base, tag);
    snprintf(emit, sizeof(emit), "%s/emit_%s", base, tag);
    uint8_t root[32], release[32], recipe[32];
    bool ready = zv_publish_fixture_ex(store, source, test, program, root, release, recipe);
    ZV_CHECK("sections: required-provider fixture publishes", ready);
    if (!ready) return failures;
    zv_hex_enc(root, 32u, root_hex);
    int rc = zv_run_emit(root_hex, store, emit, lock, NULL, work, out, sizeof(out));
    struct vcs_package_build_receipt receipt;
    bool refused = rc == 0 && zv_read_receipt(emit, &receipt) &&
        receipt.result_class == VCS_PACKAGE_BUILD_RESULT_BUILD_FAIL &&
        !vcs_package_build_installable(&receipt) && receipt.output_count == 0;
    ZV_CHECK(tag, refused);
    if (!refused) printf("  zcode_verify: required provider rc=%d out=%s\n", rc, out);
    return failures;
}

static int zpr_live_providers(const char *base, const char *lock, const char *work)
{
    static const struct { const char *tag, *source; } cases[] = {
        {"live_function_provider_refused",
         "extern int absent_live_provider(void);\n"
         "int add(int a, int b) { return a + b + absent_live_provider(); }\n"},
        {"live_constructor_provider_refused",
         "extern int absent_constructor_provider(void);\n"
         "__attribute__((constructor)) static void init(void) { (void)absent_constructor_provider(); }\n"
         "int add(int a, int b) { return a + b; }\n"},
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        failures += zpr_live_provider_case(base, lock, work, cases[i].tag, cases[i].source);
    return failures;
}

static int zpr_live_global_sanitizer(const char *base)
{
    int failures = 0;
    const char source[] = "int live_globals[2] = {3, 4};\nint add(int a, int b) { return a+b; }\n";
    const char test[] =
        "extern int live_globals[];\n"
        "int main(void) { volatile int index = 3; live_globals[index] = 17; return 0; }\n";
    char store[4500], work[4500], key[4500], out[2048], root_hex[65];
    snprintf(store, sizeof(store), "%s/store_live_global", base);
    snprintf(work, sizeof(work), "%s/work_live_global", base);
    snprintf(key, sizeof(key), "%s/global-test.key", base);
    uint8_t root[32], release[32], recipe[32];
    bool ready = zv_publish_fixture(store, source, test, root, release, recipe) &&
        zv_write_key_file(key, 0x22, 0600) && zv_mkdir_p(work);
    ZV_CHECK("sections: live-global sanitizer fixture publishes", ready);
    if (!ready) return failures;
    zv_hex_enc(root, 32u, root_hex);
    int rc = zv_run_verifier(root_hex, store, key, work, out, sizeof(out));
    struct vcs_package_attest att;
    bool detected = rc == 0 && zv_read_only_attestation(store, &att) &&
        vcs_package_attest_verify(&att) == VCS_PACKAGE_ATTEST_OK &&
        att.result_class == VCS_PACKAGE_ATTEST_RESULT_SANITIZER_FAIL &&
        att.sanitizer_count == 2u && att.sanitizers[0].outcome == VCS_PACKAGE_ATTEST_OUTCOME_FAIL;
    ZV_CHECK("sections: actual signed verdict still detects live global overflow", detected);
    if (!detected) printf("  zcode_verify: live global rc=%d out=%s\n", rc, out);
    return failures;
}

static int zpr_clean_sanitizers(const char *store)
{
    int failures = 0;
    struct vcs_package_attest att;
    bool clean = zv_read_only_attestation(store, &att) &&
        vcs_package_attest_verify(&att) == VCS_PACKAGE_ATTEST_OK &&
        att.result_class == VCS_PACKAGE_ATTEST_RESULT_TEST_PASS &&
        att.sanitizer_count == 2u &&
        att.sanitizers[0].outcome == VCS_PACKAGE_ATTEST_OUTCOME_PASS &&
        att.sanitizers[1].outcome == VCS_PACKAGE_ATTEST_OUTCOME_PASS;
    ZV_CHECK("sections: unused provider and live registration qualify with full sanitizers", clean);
    return failures;
}

static bool zpr_cache_keys_distinct(const struct json_value *kc,
                                    const char *profile, const char *target,
                                    const char *const *argv)
{
    const char *capsule_hex = json_get_str(json_get(kc, "capsule_root"));
    const char *preproc_hex = json_get_str(json_get(kc, "preprocessed_sha3"));
    uint8_t capsule[32], preproc[32], current[32], old[32];
    if (!capsule_hex || !preproc_hex) return false;
    return zcl_hex_decode_lower(capsule_hex, capsule, 32u) &&
        zcl_hex_decode_lower(preproc_hex, preproc, 32u) &&
        vcs_fastobj_key(capsule, target, profile, argv, preproc, current) &&
#if defined(__linux__)
        vcs_fastobj_key(capsule, target, "quick;gc=elf1", argv, preproc, old) &&
#else
        vcs_fastobj_key(capsule, target, "quick", argv, preproc, old) &&
#endif
        memcmp(current, old, 32u) != 0;
}

static bool zpr_cache_policy_bound(const struct json_value *sidecar)
{
    const struct platform_toolchain_commons_gc *gc = platform_toolchain_commons_gc();
    const struct json_value *kc = json_get(sidecar, "key_components");
    const char *profile = json_get_str(json_get(kc, "profile"));
    const char *target = json_get_str(json_get(kc, "target"));
    const struct json_value *array = json_get(kc, "argv");
    size_t count = json_size(array);
    char expected[32];
    if (!gc || !profile || !target || count >= 1024u)
        return false;
    int n = snprintf(expected, sizeof(expected), "quick;%s", gc->identity);
    if (n <= 0 || (size_t)n >= sizeof(expected) || strcmp(profile, expected) != 0)
        return false;
    const char *argv[1024];
    for (size_t i = 0; i < count; i++) {
        argv[i] = json_get_str(json_at(array, i));
        if (!argv[i]) return false;
    }
    argv[count] = NULL;
    return zpr_cache_keys_distinct(kc, profile, target, argv);
}

#endif
