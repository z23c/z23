/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the Tier-1 hot-swap loader's non-dlopen logic: path
 * acceptance, the dev-datadir guard, the generation registry, and the
 * native dumpstate handler.
 *
 * The test binary is built WITHOUT ZCL_DEV_BUILD, so hotswap_load_leaves() is
 * the release stub (refuses, no dlopen) — that release behavior is asserted
 * too. The pure predicates + registry + dumper compile in all builds and are
 * exercised directly. A real end-to-end dlopen is proven by `make
 * hotswap-so` / `make hotswap-sim` (see docs/work/HOTSWAP.md). */

#include "test/test_core.h"
#include "hotswap/hotswap.h"
#include "json/json.h"
#include "util/clientversion.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int test_hotswap_path_acceptance(void)
{
    int failures = 0;
    TEST("hotswap_path_is_acceptable enforces absolute/.so/exists/confined") {
        char why[192];
        /* Relative path. */
        ASSERT(!hotswap_path_is_acceptable("rel/gen.so", why, sizeof(why)));
        /* Not a .so. */
        ASSERT(!hotswap_path_is_acceptable("/tmp/gen.txt", why, sizeof(why)));
        /* Contains "..". */
        ASSERT(!hotswap_path_is_acceptable("/tmp/../etc/gen.so",
                                           why, sizeof(why)));
        /* Absolute .so that does not exist. */
        ASSERT(!hotswap_path_is_acceptable("/tmp/zcl_hs_absent_00.so",
                                           why, sizeof(why)));

        /* A real file under /tmp is accepted. */
        char okp[256];
        snprintf(okp, sizeof(okp), "/tmp/zcl_hs_ok_%d.so", (int)getpid());
        FILE *f = fopen(okp, "w");
        ASSERT(f != NULL);
        if (f) { fputs("x", f); fclose(f); }
        ASSERT(hotswap_path_is_acceptable(okp, why, sizeof(why)));
        unlink(okp);

        /* A real .so NOT under /tmp or a build/hotswap dir is rejected.
         * Do not derive this fixture from HOME: isolated proof lanes put
         * HOME under /tmp so parameter files and datadirs cannot touch the
         * operator's home, which would turn the intended rejection path into
         * an admitted /tmp path. /var/tmp is writable on the supported POSIX
         * hosts but resolves outside /tmp on both Darwin and Linux. */
        char rej[512];
        snprintf(rej, sizeof(rej), "/var/tmp/zcl_hs_reject_%d.so",
                 (int)getpid());
        FILE *g = fopen(rej, "w");
        ASSERT(g != NULL);
        if (g) { fputs("x", g); fclose(g); }
        ASSERT(!hotswap_path_is_acceptable(rej, why, sizeof(why)));
        unlink(rej);
        PASS();
    } _test_next:;
    return failures;
}

static int test_hotswap_datadir_guard(void)
{
    int failures = 0;
    TEST("hotswap_datadir_is_dev admits only exact worker dev datadir") {
        const char *home = getenv("HOME");
        char canonical[512], legacy[512], dev[512], soak[512], test[512];
        snprintf(canonical, sizeof(canonical), "%s/.zclassic-c23",
                 home ? home : "");
        snprintf(legacy, sizeof(legacy), "%s/.zclassic", home ? home : "");
        snprintf(dev, sizeof(dev), "%s/.zclassic-c23-dev", home ? home : "");
        snprintf(soak, sizeof(soak), "%s/.zclassic-c23-soak",
                 home ? home : "");
        snprintf(test, sizeof(test), "%s/.zclassic-c23-test",
                 home ? home : "");

        ASSERT(hotswap_datadir_is_dev(NULL) == false);
        ASSERT(hotswap_datadir_is_dev("") == false);
        ASSERT(hotswap_datadir_is_dev("/some/dev/datadir") == false);
        ASSERT(hotswap_datadir_is_dev(dev) == true);
        ASSERT(hotswap_datadir_is_dev(canonical) == false);
        ASSERT(hotswap_datadir_is_dev(legacy) == false);
        ASSERT(hotswap_datadir_is_dev(soak) == false);
        ASSERT(hotswap_datadir_is_dev(test) == false);
        PASS();
    } _test_next:;
    return failures;
}

static bool manifest_self_test_ok(const struct zcl_hotswap_host *host,
                                  char *why, size_t why_sz)
{
    (void)host;
    if (why && why_sz)
        why[0] = '\0';
    return true;
}

/* The `native.leaves` provider class (V4 host; see hotswap.h / hotswap_loader.c
 * hotswap_manifest_v2_validate()'s provider_id branch). source_identity /
 * probe_tools_csv below mirror the real native.leaves eligibility row in
 * engine/composition/hotswap_eligible.def (engine/controllers/src/status_native_handlers.c,
 * probe "core.status" — a param-free READ leaf, safe as a probe dispatch). */
static struct zcl_hotswap_manifest_v2 valid_leaf_manifest(void)
{
    return (struct zcl_hotswap_manifest_v2) {
        .schema_version = ZCL_HOTSWAP_MANIFEST_SCHEMA_V2,
        .struct_size = sizeof(struct zcl_hotswap_manifest_v2),
        .host_abi_version = ZCL_HOTSWAP_HOST_ABI_V4,
        .host_struct_size = ZCL_HOTSWAP_HOST_STRUCT_SIZE_V4,
        .required_host_capabilities = ZCL_HOTSWAP_V4_HOST_CAPABILITIES,
        .provider_id = "native.leaves",
        .build_identity = zcl_build_source_id_sha256(),
        .source_identity = "engine/controllers/src/status_native_handlers.c",
        .input_digest =
            "abcdef0123456789abcdef0123456789"
            "abcdef0123456789abcdef0123456789",
        .state_schema_version = 0,
        .stateless = true,
        .quiescence = ZCL_HOTSWAP_QUIESCENCE_NONE,
        .mapped_tests_csv = "hotswap_loader,command_handler_snapshot",
        .probe_tools_csv = "core.status",
        .self_test = manifest_self_test_ok,
    };
}

static int test_hotswap_leaf_manifest_v4_contract(void)
{
    int failures = 0;
    TEST("native.leaves manifest validates against the V4 host contract") {
        char why[256];
        struct zcl_hotswap_manifest_v2 manifest = valid_leaf_manifest();
        ASSERT(hotswap_manifest_v2_validate(&manifest, why, sizeof(why)));

        /* An artifact carrying an older host ABI is rejected. */
        manifest = valid_leaf_manifest();
        manifest.host_abi_version = ZCL_HOTSWAP_HOST_ABI_V4 - 1;
        ASSERT(!hotswap_manifest_v2_validate(&manifest, why, sizeof(why)));
        ASSERT(strstr(why, "ABI/size mismatch") != NULL ||
               strstr(why, "capabilities") != NULL);

        /* Isolate the capability mismatch with the current ABI and size. */
        manifest = valid_leaf_manifest();
        manifest.required_host_capabilities = ZCL_HOTSWAP_CAP_ATOMIC_COMMIT;
        ASSERT(!hotswap_manifest_v2_validate(&manifest, why, sizeof(why)));
        ASSERT(strstr(why, "capabilities") != NULL);

        /* An unknown provider_id is rejected outright — no ABI/caps checked. */
        manifest = valid_leaf_manifest();
        manifest.provider_id = "bogus.provider";
        ASSERT(!hotswap_manifest_v2_validate(&manifest, why, sizeof(why)));
        ASSERT(strstr(why, "unknown") != NULL);

        manifest = valid_leaf_manifest();
        manifest.provider_id = NULL;
        ASSERT(!hotswap_manifest_v2_validate(&manifest, why, sizeof(why)));
        ASSERT(strstr(why, "unknown") != NULL);

        /* Provider-agnostic provenance/eligibility checks (run after the
         * provider branch): schema/struct bump, build-identity binding,
         * source runtime-eligibility, probe metadata, digest shape, and the
         * stateless/self-test contract. */
        manifest = valid_leaf_manifest();
        manifest.schema_version++;
        ASSERT(!hotswap_manifest_v2_validate(&manifest, why, sizeof(why)));
        manifest = valid_leaf_manifest();
        manifest.host_struct_size++;
        ASSERT(!hotswap_manifest_v2_validate(&manifest, why, sizeof(why)));
        manifest = valid_leaf_manifest();
        manifest.build_identity = "wrong-build";
        ASSERT(!hotswap_manifest_v2_validate(&manifest, why, sizeof(why)));
        ASSERT(strstr(why, "build source identity mismatch") != NULL);
        manifest = valid_leaf_manifest();
        char dirty_suffix_identity[72];
        snprintf(dirty_suffix_identity, sizeof(dirty_suffix_identity),
                 "%s-dirty", zcl_build_source_id_sha256());
        manifest.build_identity = dirty_suffix_identity;
        ASSERT(!hotswap_manifest_v2_validate(&manifest, why, sizeof(why)));
        ASSERT(strstr(why, "build source identity mismatch") != NULL);
        manifest = valid_leaf_manifest();
        char different_source_id[65];
        snprintf(different_source_id, sizeof(different_source_id), "%s",
                 zcl_build_source_id_sha256());
        different_source_id[0] = different_source_id[0] == '0' ? '1' : '0';
        manifest.build_identity = different_source_id;
        ASSERT(!hotswap_manifest_v2_validate(&manifest, why, sizeof(why)));
        ASSERT(strstr(why, "build source identity mismatch") != NULL);
        manifest = valid_leaf_manifest();
        manifest.source_identity = "engine/controllers/src/api_controller_routes.c";
        ASSERT(!hotswap_manifest_v2_validate(&manifest, why, sizeof(why)));
        manifest = valid_leaf_manifest();
        manifest.probe_tools_csv = "ops.metrics";
        ASSERT(!hotswap_manifest_v2_validate(&manifest, why, sizeof(why)));
        ASSERT(strstr(why, "probe metadata mismatch") != NULL);
        manifest = valid_leaf_manifest();
        manifest.input_digest =
            "abcdef0123456789abcdef0123456789"
            "abcdef0123456789abcdef012345678";
        ASSERT(!hotswap_manifest_v2_validate(&manifest, why, sizeof(why)));
        manifest = valid_leaf_manifest();
        manifest.input_digest =
            "abcdef0123456789abcdef0123456789"
            "abcdef0123456789abcdef01234567zz";
        ASSERT(!hotswap_manifest_v2_validate(&manifest, why, sizeof(why)));
        manifest = valid_leaf_manifest();
        manifest.stateless = false;
        manifest.state_schema_version = 1;
        ASSERT(!hotswap_manifest_v2_validate(&manifest, why, sizeof(why)));
        manifest = valid_leaf_manifest();
        manifest.mapped_tests_csv = "";
        ASSERT(!hotswap_manifest_v2_validate(&manifest, why, sizeof(why)));
        manifest = valid_leaf_manifest();
        manifest.self_test = NULL;
        ASSERT(!hotswap_manifest_v2_validate(&manifest, why, sizeof(why)));
        PASS();
    } _test_next:;
    return failures;
}

static int test_hotswap_load_leaves_stub_and_registry(void)
{
    int failures = 0;
    TEST("release build: hotswap_load_leaves refuses; registry empty") {
        ASSERT(hotswap_generation_count() == 0);
        ASSERT(hotswap_native_activation_available() == false);
        ASSERT(strcmp(hotswap_native_unavailable_stage(), "release") == 0);
        ASSERT(strstr(hotswap_native_unavailable_reason(), "unavailable") !=
               NULL);

        struct hotswap_load_report rep;
        bool ok = hotswap_load_leaves("/tmp/whatever.so", "/tmp/dev-datadir",
                                      "app.names.list", NULL, NULL, &rep);
        ASSERT(ok == false);
        ASSERT(rep.ok == false);
        ASSERT(rep.error[0] != '\0');
        ASSERT(strstr(rep.error, "unavailable") != NULL);
        ASSERT(strcmp(rep.rejection_stage, "release") == 0);
        /* No dlopen happened → no generation registered. */
        ASSERT(hotswap_generation_count() == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_hotswap_dump_state(void)
{
    int failures = 0;
    TEST("hotswap_dump_state_json reports availability + empty registry") {
        struct json_value out;
        json_init(&out);
        ASSERT(hotswap_dump_state_json(&out, NULL) == true);

        const struct json_value *avail = json_get(&out, "available");
        ASSERT(avail != NULL);
        /* Test binary is not a ZCL_DEV_BUILD → available is false. */
        ASSERT(json_get_bool(avail) == false);
        ASSERT(strcmp(json_get_str(json_get(&out, "note")),
                      hotswap_native_unavailable_reason()) == 0);

        ASSERT(strcmp(json_get_str(json_get(&out, "schema")),
                      "zcl.hotswap_generation.v2") == 0);
        ASSERT(strcmp(json_get_str(json_get(&out, "mapping_policy")),
                      "successful_generations_permanently_mapped") == 0);
        ASSERT(strcmp(json_get_str(json_get(&out, "artifact_inode_policy")),
                      "successful_generation_fd_pinned") == 0);

        const struct json_value *gc = json_get(&out, "generation_count");
        ASSERT(gc != NULL);
        ASSERT(json_get_int(gc) == 0);

        const struct json_value *gens = json_get(&out, "generations");
        ASSERT(gens != NULL);
        ASSERT(gens->type == JSON_ARR);
        ASSERT(json_size(gens) == 0);
        json_free(&out);
        PASS();
    } _test_next:;
    return failures;
}


int test_hotswap_loader(void);

int test_hotswap_loader(void)
{
    int failures = 0;
    failures += test_hotswap_path_acceptance();
    failures += test_hotswap_datadir_guard();
    failures += test_hotswap_leaf_manifest_v4_contract();
    failures += test_hotswap_load_leaves_stub_and_registry();
    failures += test_hotswap_dump_state();
    return failures;
}
