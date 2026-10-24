/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Verify the resident plugin_publish_commit handler: a running host verifies
 * a release a CLI signed and commits the package into its own store, even when
 * a second handle made that store stale first. Every refusal (wrong root, bad
 * signature, oversize license, a path or datadir input, hosting off) happens
 * before any write. The image is inert and never executed. */
#include "test/plugin_dist_fixture.h"
#include "test/public_shape_fixture.h"
#include "config/boot_plugin_publish.h"
#include "base/hex.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "vcs/package_release.h"
#include "vcs/package_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct pp {
    struct pd_fixture f;
    struct plugin_pack_result v1, v2;
    struct plugin_manifest m1, m2;
    char *hex1, *hex2; /* signed releases for v1 and v2 */
};

static char *pp_release_hex(struct pp *p, const char *generation, uint64_t seq)
{
    struct plugin_dist_publish_request rq = {
        .plugins_dir = p->f.pub_plugins, .name = "demo", .generation = generation,
        .license_file = p->f.license, .spdx = "MIT", .release_key = p->f.release_key,
        .sequence = seq
    };
    struct plugin_dist_prepared *prep = NULL;
    struct plugin_dist_published pub;
    uint8_t *wire = NULL;
    size_t len = 0;
    char *hex = NULL;
    if (plugin_dist_prepare(&rq, &prep, &pub) == PLUGIN_DIST_OK &&
        plugin_dist_sign_release(prep, &rq, &wire, &len, &pub) == PLUGIN_DIST_OK &&
        (hex = malloc(len * 2 + 1)) != NULL)
        zcl_hex_encode(wire, len, hex);
    free(wire);
    plugin_dist_prepared_free(prep);
    return hex;
}

static bool pp_open(struct pp *p)
{
    int present = 0;
    memset(p, 0, sizeof(*p));
    if (!pd_open(&p->f) || !pd_pack(&p->f, "packed1", "1.0.0", &p->v1) ||
        !pd_pack(&p->f, "packed2", "2.0.0", &p->v2) ||
        !pd_keys(p->f.pub_plugins, p->v1.public_key) ||
        plugin_store_install(p->f.pub_plugins, p->v1.manifest_path, &p->m1, &present) != PLUGIN_OK ||
        plugin_store_install(p->f.pub_plugins, p->v2.manifest_path, &p->m2, &present) != PLUGIN_OK ||
        plugin_store_switch(p->f.pub_plugins, "demo", p->m1.generation) != PLUGIN_OK)
        return false;
    p->hex1 = pp_release_hex(p, p->m1.generation, 1);
    p->hex2 = pp_release_hex(p, p->m2.generation, 2);
    return p->hex1 && p->hex2;
}

static void pp_close(struct pp *p)
{
    free(p->hex1);
    free(p->hex2);
    pd_close(&p->f);
}

/* Runs the handler with name=demo and the given generation and release. */
static void pp_run(struct pp *p, const char *generation, const char *release, const char *license,
                   const char *extra_key, struct json_value *out)
{
    struct json_value in;
    json_init(&in);
    json_set_object(&in);
    json_push_kv_str(&in, "name", "demo");
    json_push_kv_str(&in, "generation", generation);
    json_push_kv_str(&in, "spdx", "MIT");
    json_push_kv_str(&in, "license", license);
    json_push_kv_str(&in, "release", release);
    if (extra_key)
        json_push_kv_str(&in, extra_key, "x/y");
    json_init(out);
    boot_plugin_publish_commit_run(&in, p->f.publisher.store, p->f.pub_plugins, p->f.scratch, out);
    json_free(&in);
}

static const char *pp_code(const struct json_value *out)
{
    const char *c = json_get_str(json_get(out, "code"));
    return c ? c : "";
}

static bool pp_ok(const struct json_value *out)
{
    const struct json_value *ok = json_get(out, "ok");
    return ok && json_get_bool(ok);
}

static size_t pp_count(struct pp *p)
{
    struct vcs_package_store_summary sums[8];
    return vcs_package_store_list_summaries(p->f.publisher.store, false, sums, 8);
}

/* A release whose signature has one bit flipped. */
static char *pp_forge(const char *hex)
{
    uint8_t wire[VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES], *out = NULL;
    size_t len = 0, out_len = 0;
    struct vcs_package_release r;
    char *forged = NULL;
    if (zcl_hex_decode_n(hex, wire, sizeof(wire), &len) &&
        vcs_package_release_parse(wire, len, &r) == VCS_PACKAGE_RELEASE_OK) {
        r.signature[0] ^= 1u;
        if (vcs_package_release_serialize(&r, &out, &out_len) == VCS_PACKAGE_RELEASE_OK &&
            (forged = malloc(out_len * 2 + 1)) != NULL)
            zcl_hex_encode(out, out_len, forged);
    }
    free(out);
    return forged;
}

static int pp_refusals(void)
{
    int failures = 0;
    struct pp p = {0};
    char *forged = NULL, *huge = NULL;
    TEST("plugin publish rpc: wrong root, bad signature, big license and path inputs write nothing") {
        struct json_value out;
        ASSERT(pp_open(&p));
        forged = pp_forge(p.hex1);
        huge = malloc(VCS_PACKAGE_RELEASE_LICENSE_TEXT_MAX_BYTES + 2);
        ASSERT(forged && huge);
        memset(huge, 'a', VCS_PACKAGE_RELEASE_LICENSE_TEXT_MAX_BYTES + 1);
        huge[VCS_PACKAGE_RELEASE_LICENSE_TEXT_MAX_BYTES + 1] = '\0';
        /* the v2 release for the v1 generation */
        pp_run(&p, p.m1.generation, p.hex2, TEST_LICENSE_TEXT_MIT, NULL, &out);
        ASSERT(!pp_ok(&out));
        ASSERT(strcmp(pp_code(&out), "PLUGIN_DIST_RELEASE") == 0);
        ASSERT(json_get_str(json_get(&out, "next_action")) != NULL);
        json_free(&out);
        pp_run(&p, p.m1.generation, forged, TEST_LICENSE_TEXT_MIT, NULL, &out);
        ASSERT(!pp_ok(&out));
        ASSERT(strcmp(pp_code(&out), "PLUGIN_DIST_RELEASE") == 0);
        json_free(&out);
        pp_run(&p, p.m1.generation, p.hex1, huge, NULL, &out);
        ASSERT(!pp_ok(&out));
        ASSERT(strcmp(pp_code(&out), "PLUGIN_DIST_LICENSE") == 0);
        json_free(&out);
        static const char *const keys[] = { "datadir", "plugins_dir", "path", "release_key" };
        for (size_t i = 0; i < 4; i++) {
            pp_run(&p, p.m1.generation, p.hex1, TEST_LICENSE_TEXT_MIT, keys[i], &out);
            ASSERT(!pp_ok(&out));
            ASSERT(strcmp(pp_code(&out), "PLUGIN_DIST_ARGUMENT") == 0);
            json_free(&out);
        }
        ASSERT_EQ(pp_count(&p), 0u);
        PASS();
    } _test_next:;
    free(forged);
    free(huge);
    pp_close(&p);
    return failures;
}

/* A second handle admits another download's manifest, leaving ours stale. */
static bool pp_make_stale(struct pp *p, uint8_t other_root[32], uint8_t **chunk, size_t *chunk_len)
{
    struct plugin_dist_publish_request rq = {
        .plugins_dir = p->f.pub_plugins, .name = "demo", .generation = p->m2.generation,
        .license_file = p->f.license, .spdx = "MIT", .release_key = p->f.release_key,
        .sequence = 9
    };
    struct plugin_dist_published other;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    struct vcs_package_store *second = vcs_package_store_open(p->f.publisher.datadir, 1ull << 30);
    bool ok = second && plugin_dist_publish(p->f.receiver.store, &rq, &other) == PLUGIN_DIST_OK &&
              vcs_package_store_get_manifest_wire(p->f.receiver.store, other.root, &wire,
                                                  &wire_len) == VCS_PACKAGE_STORE_OK &&
              vcs_package_store_put_manifest(second, wire, wire_len, other_root) ==
                  VCS_PACKAGE_STORE_OK &&
              vcs_package_store_get_chunk(p->f.receiver.store, other.root, "demo", 0, chunk,
                                          chunk_len) == VCS_PACKAGE_STORE_OK;
    free(wire);
    if (second)
        vcs_package_store_close(second);
    return ok;
}

static int pp_commit_stale(void)
{
    int failures = 0;
    struct pp p = {0};
    uint8_t other[32], *chunk = NULL;
    size_t chunk_len = 0;
    TEST("plugin publish rpc: a stale resident store is refreshed, the root is listed, other puts work") {
        struct json_value out;
        struct vcs_package_store_summary sums[8];
        ASSERT(pp_open(&p));
        ASSERT(pp_make_stale(&p, other, &chunk, &chunk_len));
        pp_run(&p, p.m1.generation, p.hex1, TEST_LICENSE_TEXT_MIT, NULL, &out);
        ASSERT(pp_ok(&out));
        const char *root = json_get_str(json_get(&out, "root"));
        ASSERT(root != NULL && strlen(root) == 64u);
        ASSERT(strcmp(json_get_str(json_get(&out, "manifest_sha3")), p.m1.generation) == 0);
        ASSERT_EQ(json_get_int(json_get(&out, "files")), 4);
        ASSERT(json_get_int(json_get(&out, "bytes")) > 0);
        size_t n = vcs_package_store_list_summaries(p.f.publisher.store, false, sums, 8);
        ASSERT_EQ(n, 2u);
        bool listed = false;
        for (size_t i = 0; i < n; i++) {
            char hex[65];
            zcl_hex_encode(sums[i].root, 32, hex);
            listed = listed || strcmp(hex, root) == 0;
        }
        ASSERT(listed);
        /* the other download's chunk still lands through the same handle */
        ASSERT_EQ(vcs_package_store_put_chunk(p.f.publisher.store, other, "demo", 0, chunk,
                                              chunk_len), VCS_PACKAGE_STORE_OK);
        json_free(&out);
        /* hosting off: a clean refusal with a next action */
        json_init(&out);
        struct json_value in;
        json_init(&in);
        json_set_object(&in);
        json_push_kv_str(&in, "name", "demo");
        json_push_kv_str(&in, "generation", p.m1.generation);
        json_push_kv_str(&in, "spdx", "MIT");
        json_push_kv_str(&in, "license", TEST_LICENSE_TEXT_MIT);
        json_push_kv_str(&in, "release", p.hex1);
        boot_plugin_publish_commit_run(&in, NULL, p.f.pub_plugins, p.f.scratch, &out);
        ASSERT(strcmp(pp_code(&out), "PLUGIN_PUBLISH_NO_STORE") == 0);
        ASSERT(json_get_str(json_get(&out, "next_action")) != NULL);
        json_free(&in);
        json_free(&out);
        PASS();
    } _test_next:;
    free(chunk);
    pp_close(&p);
    return failures;
}

/* Handler time for a large image (it runs on an RPC worker thread). */
static int pp_big_image(void)
{
    int failures = 0;
    struct pp p = {0};
    const size_t image_bytes = 32u * 1024u * 1024u;
    char *image = malloc(image_bytes);
    TEST("plugin publish rpc: a 32 MiB image commits (handler time printed)") {
        struct plugin_pack_result packed;
        struct plugin_manifest m;
        struct json_value out;
        char dir[1400], exe[1400];
        int present = 0;
        ASSERT(image != NULL);
        for (size_t i = 0; i < image_bytes; i++)
            image[i] = (char)(i * 2654435761u >> 24);
        ASSERT(pd_open(&p.f));
        p.hex1 = p.hex2 = NULL;
        ASSERT(pd_path(dir, sizeof(dir), p.f.base, "bigpack"));
        ASSERT(pd_path(exe, sizeof(exe), p.f.base, "bigimage"));
        ASSERT(pd_write(exe, image, image_bytes, 0644));
        struct plugin_pack_request rq = {
            .exe_path = exe, .name = "demo", .version = "3.0.0", .key_path = p.f.signing,
            .out_dir = dir, .capabilities = 0
        };
        ASSERT_EQ(plugin_pack(&rq, &packed), PLUGIN_OK);
        ASSERT(pd_keys(p.f.pub_plugins, packed.public_key));
        ASSERT_EQ(plugin_store_install(p.f.pub_plugins, packed.manifest_path, &m, &present), PLUGIN_OK);
        p.hex1 = pp_release_hex(&p, m.generation, 1);
        ASSERT(p.hex1 != NULL);
        int64_t t0 = platform_time_monotonic_ms();
        pp_run(&p, m.generation, p.hex1, TEST_LICENSE_TEXT_MIT, NULL, &out);
        int64_t t1 = platform_time_monotonic_ms();
        ASSERT(pp_ok(&out));
        json_free(&out);
        printf("[%lld ms] ", (long long)(t1 - t0));
        PASS();
    } _test_next:;
    free(image);
    free(p.hex1);
    pd_close(&p.f);
    return failures;
}

int test_plugin_publish_rpc(void)
{
    int failures = 0;
    failures += pp_refusals();
    failures += pp_commit_stale();
    failures += pp_big_image();
    test_shm_reap_own("zcode_swarm-test-tmp_");
    return failures;
}
