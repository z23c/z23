/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Verify peer-to-peer plugin distribution: publish a generation as a package
 * root, move it between two isolated datadirs through the real swarm engines,
 * and refuse by name every delivery that is not the exact signed generation
 * the receiver pinned. Peer handles are fixture inputs; the image is inert and
 * never executed. */
#include "test/plugin_dist_fixture.h"
#include "test/public_shape_fixture.h"
#include "vcs/package_public_shape.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---- 1. the whole journey, never switching ---------------------------- */
static int pd_journey(void)
{
    int failures = 0;
    struct pd_fixture f = {0};
    TEST("plugin dist: publish, swarm transfer, pinned install as a new generation") {
        struct plugin_pack_result packed;
        struct plugin_dist_published pub;
        struct plugin_dist_received got;
        ASSERT(pd_open(&f));
        ASSERT(pd_pack(&f, "packed1", "1.0.0", &packed));
        ASSERT_EQ(pd_publish(&f, "packed1", 1, &pub), PLUGIN_DIST_OK);
        ASSERT(strcmp(pub.generation, packed.generation) == 0);
        ASSERT_EQ(pub.files, 4u);
        struct vcs_package_public_verdict verdict;
        vcs_package_public_shape_classify(f.publisher.store, pub.root, &verdict);
        ASSERT(verdict.shape == VCS_PACKAGE_PUBLIC_RELEASE);
        /* Not yet transferred: named, not an install. */
        ASSERT_EQ(pd_receive(&f, pub.root, NULL, false, &got), PLUGIN_DIST_ERR_NOT_FETCHED);
        ASSERT(pd_transfer(&f, pub.root, 0, true));
        ASSERT(pd_keys(f.plugins, packed.public_key));
        ASSERT_EQ(pd_receive(&f, pub.root, pub.root, false, &got), PLUGIN_DIST_OK);
        ASSERT(strcmp(got.generation, packed.generation) == 0);
        ASSERT(!got.already_present);
        ASSERT(pd_generation_stored(&f, got.generation));
        ASSERT(pd_selection(&f, NULL)); /* never switches */
        ASSERT(pd_scratch_empty(&f));
        ASSERT_EQ(pd_receive(&f, pub.root, NULL, false, &got), PLUGIN_DIST_OK);
        ASSERT(got.already_present);
        ASSERT(pd_selection(&f, NULL));
        PASS();
    } _test_next:;
    pd_close(&f);
    return failures;
}


/* ---- 1c. publisher (hosting) -> fetcher; a fetch-only node does not re-serve - */
static bool pd_relay_pump(struct vcs_swarm_engine *from, uint64_t to_id,
                          struct vcs_swarm_engine *to, uint64_t from_id, uint64_t now)
{
    uint8_t frame[VCS_SWARM_OUTBOUND_FRAME_MAX];
    uint64_t target = 0;
    size_t length = 0;
    unsigned frames = 0;
    vcs_swarm_engine_tick(from, SW_DAY, now);
    while (vcs_swarm_engine_next_outbound(from, to_id, &target, frame, &length)) {
        if (++frames > 64)
            return false;
        struct vcs_swarm_frame_result served =
            vcs_swarm_engine_handle_frame(to, from_id, frame, length, SW_DAY, now);
        if (served.reply && served.reply_len) {
            struct vcs_swarm_frame_result got = vcs_swarm_engine_handle_frame(
                from, to_id, served.reply, served.reply_len, SW_DAY, now);
            free(got.reply);
        }
        free(served.reply);
    }
    return true;
}

static bool pd_relay_fetch(struct vcs_swarm_engine *server, struct sw_node *fetcher,
                           uint8_t seed, const uint8_t root[32])
{
    uint8_t hk[33], fk[33];
    const uint64_t provider = 21;
    sw_key(seed, hk);
    sw_key((uint8_t)(seed + 1), fk);
    if (!vcs_swarm_engine_peer_add(fetcher->engine, provider, hk) ||
        !vcs_swarm_engine_peer_add(server, 23, fk) ||
        vcs_swarm_engine_fetch_from_bounded(fetcher->engine, root, SW_DAY, 1, &provider, 1,
                                            4u * PD_CAP) != VCS_SWARM_FETCH_OK)
        return false;
    for (uint64_t now = 2; now < 34; now++) {
        struct vcs_swarm_download_status st;
        if (!pd_relay_pump(fetcher->engine, provider, server, 23, now))
            return false;
        if (vcs_swarm_engine_download_status(fetcher->engine, root, &st) &&
            st.state == VCS_SWARM_DL_COMPLETE)
            return true;
    }
    return false;
}

static int pd_relay(void)
{
    int failures = 0;
    struct pd_fixture f = {0};
    struct sw_node via_pub = {0}, via_host = {0};
    char plugins[1300], scratch[1300];
    TEST("plugin dist: a hosting publisher serves a third node; a fetch-only node cannot re-serve") {
        struct plugin_pack_result packed;
        struct plugin_dist_published pub;
        struct plugin_dist_received got;
        ASSERT(pd_open(&f));
        ASSERT(pd_pack(&f, "packed1", "1.0.0", &packed));
        ASSERT_EQ(pd_publish(&f, "packed1", 1, &pub), PLUGIN_DIST_OK);
        ASSERT(pd_transfer(&f, pub.root, 0, true)); /* publisher -> second node */
        ASSERT(sw_node_open(&via_host, "plugin-dist-via-host", sw_score_contributor));
        ASSERT(sw_node_open(&via_pub, "plugin-dist-via-pub", sw_score_contributor));
        /* The second node holds the bytes but no verified release record
         * (the release is not part of the chunk transfer), so it refuses to
         * host them: operators publish on each hosting node. */
        ASSERT(!pd_relay_fetch(f.receiver.engine, &via_host, 83, pub.root));
        ASSERT(pd_relay_fetch(f.publisher.engine, &via_pub, 85, pub.root));
        ASSERT(pd_path(plugins, sizeof(plugins), f.base, "fetcher-plugins"));
        ASSERT(pd_path(scratch, sizeof(scratch), f.base, "fetcher-scratch"));
        ASSERT(mkdir(plugins, 0700) == 0 && mkdir(scratch, 0700) == 0);
        ASSERT(pd_keys(plugins, packed.public_key));
        struct plugin_dist_receive_request rq = {
            .store = via_pub.store, .delivered_root = pub.root, .name = "demo",
            .plugins_dir = plugins, .scratch_dir = scratch
        };
        memcpy(rq.requested_root, pub.root, 32);
        ASSERT_EQ(plugin_dist_receive(&rq, &got), PLUGIN_DIST_OK);
        ASSERT(strcmp(got.generation, packed.generation) == 0);
        ASSERT(!got.already_present);
        PASS();
    } _test_next:;
    sw_node_close(&via_host);
    sw_node_close(&via_pub);
    if (via_host.datadir[0])
        (void)test_rm_rf_recursive(via_host.datadir);
    if (via_pub.datadir[0])
        (void)test_rm_rf_recursive(via_pub.datadir);
    pd_close(&f);
    return failures;
}
/* ---- 1b. publish by name from an installed generation ----------------- */
static int pd_installed_publish(void)
{
    int failures = 0;
    struct pd_fixture f = {0};
    TEST("plugin dist: publish an installed current generation by name") {
        struct plugin_pack_result packed;
        struct plugin_dist_published pub;
        struct plugin_manifest m;
        int present = 0;
        char manifest[1400];
        ASSERT(pd_open(&f));
        ASSERT(pd_pack(&f, "packed1", "1.0.0", &packed));
        ASSERT(pd_keys(f.pub_plugins, packed.public_key));
        ASSERT_EQ(plugin_store_install(f.pub_plugins, packed.manifest_path, &m, &present), PLUGIN_OK);
        struct plugin_dist_publish_request rq = {
            .plugins_dir = f.pub_plugins, .name = "demo", .license_file = f.license,
            .spdx = "MIT", .release_key = f.release_key, .sequence = 1
        };
        /* No current generation yet: refused, not guessed. */
        ASSERT_EQ(plugin_dist_publish(f.publisher.store, &rq, &pub), PLUGIN_DIST_ERR_SOURCE);
        ASSERT_EQ(plugin_store_switch(f.pub_plugins, "demo", m.generation), PLUGIN_OK);
        ASSERT_EQ(plugin_dist_publish(f.publisher.store, &rq, &pub), PLUGIN_DIST_OK);
        ASSERT(strcmp(pub.generation, m.generation) == 0);
        (void)manifest;
        PASS();
    } _test_next:;
    pd_close(&f);
    return failures;
}

/* ---- 2. root identity -------------------------------------------------- */
static int pd_refuse_root(void)
{
    int failures = 0;
    struct pd_fixture f = {0};
    TEST("plugin dist: a delivered root that is not the requested root is refused") {
        struct plugin_pack_result packed;
        struct plugin_dist_published pub;
        struct plugin_dist_received got;
        ASSERT(pd_open(&f));
        ASSERT(pd_pack(&f, "packed1", "1.0.0", &packed));
        ASSERT_EQ(pd_publish(&f, "packed1", 1, &pub), PLUGIN_DIST_OK);
        ASSERT(pd_transfer(&f, pub.root, 0, true));
        ASSERT(pd_keys(f.plugins, packed.public_key));
        uint8_t other[32];
        memcpy(other, pub.root, 32);
        other[7] ^= 0x40;
        ASSERT_EQ(pd_receive(&f, pub.root, other, false, &got), PLUGIN_DIST_ERR_ROOT_MISMATCH);
        ASSERT(!pd_generation_stored(&f, packed.generation));
        /* A root the store does not hold under that name is not fetched. */
        ASSERT_EQ(pd_receive(&f, other, NULL, false, &got), PLUGIN_DIST_ERR_NOT_FETCHED);
        PASS();
    } _test_next:;
    pd_close(&f);
    return failures;
}

/* ---- 3. publisher pin --------------------------------------------------- */
static int pd_refuse_unpinned(void)
{
    int failures = 0;
    struct pd_fixture f = {0};
    TEST("plugin dist: an unpinned publisher is refused and nothing is stored") {
        struct plugin_pack_result packed;
        struct plugin_dist_published pub;
        struct plugin_dist_received got;
        ASSERT(pd_open(&f));
        ASSERT(pd_pack(&f, "packed1", "1.0.0", &packed));
        ASSERT_EQ(pd_publish(&f, "packed1", 1, &pub), PLUGIN_DIST_OK);
        ASSERT(pd_transfer(&f, pub.root, 0, true));
        /* No publisher_keys at all. */
        ASSERT_EQ(pd_receive(&f, pub.root, NULL, false, &got), PLUGIN_DIST_ERR_PUBLISHER_UNPINNED);
        /* Some other key pinned: still not this publisher. */
        ASSERT(pd_keys(f.plugins,
            "0000000000000000000000000000000000000000000000000000000000000001"));
        ASSERT_EQ(pd_receive(&f, pub.root, NULL, false, &got), PLUGIN_DIST_ERR_PUBLISHER_UNPINNED);
        ASSERT(!pd_generation_stored(&f, packed.generation));
        ASSERT(pd_selection(&f, NULL));
        ASSERT(pd_scratch_empty(&f));
        PASS();
    } _test_next:;
    pd_close(&f);
    return failures;
}

/* ---- 4. image hash ------------------------------------------------------ */
static int pd_refuse_image(void)
{
    int failures = 0;
    struct pd_fixture f = {0};
    TEST("plugin dist: an image that does not match the signed sha3_512 is refused") {
        struct plugin_pack_result packed;
        struct plugin_dist_published pub;
        struct plugin_dist_received got;
        char exe[1400];
        ASSERT(pd_open(&f));
        ASSERT(pd_pack(&f, "packed1", "1.0.0", &packed));
        ASSERT(pd_path(exe, sizeof(exe), f.base, "packed1/demo"));
        chmod(exe, 0644);
        ASSERT(pd_write(exe, "tampered image\n", 15, 0644));
        /* An honest publish refuses to offer it. */
        ASSERT_EQ(pd_publish(&f, "packed1", 1, &pub), PLUGIN_DIST_ERR_SOURCE);
        /* A dishonest publisher offers it anyway; the receiver must not care. */
        plugin_dist_test_skip_source_check(true);
        enum plugin_dist_status ps = pd_publish(&f, "packed1", 1, &pub);
        plugin_dist_test_skip_source_check(false);
        ASSERT_EQ(ps, PLUGIN_DIST_OK);
        ASSERT(pd_transfer(&f, pub.root, 0, true));
        ASSERT(pd_keys(f.plugins, packed.public_key));
        ASSERT_EQ(pd_receive(&f, pub.root, NULL, false, &got), PLUGIN_DIST_ERR_IMAGE_HASH);
        ASSERT(!pd_generation_stored(&f, packed.generation));
        ASSERT(pd_scratch_empty(&f));
        PASS();
    } _test_next:;
    pd_close(&f);
    return failures;
}

/* ---- 5. truncated transfer ---------------------------------------------- */
static int pd_refuse_truncated(void)
{
    int failures = 0;
    struct pd_fixture f = {0};
    TEST("plugin dist: a partial transfer is refused, then resumes to completion") {
        struct plugin_pack_result packed;
        struct plugin_dist_published pub;
        struct plugin_dist_received got;
        ASSERT(pd_open(&f));
        ASSERT(pd_pack(&f, "packed1", "1.0.0", &packed));
        ASSERT_EQ(pd_publish(&f, "packed1", 1, &pub), PLUGIN_DIST_OK);
        ASSERT(pd_keys(f.plugins, packed.public_key));
        ASSERT(pd_transfer(&f, pub.root, 2, true)); /* manifest + one chunk */
        struct vcs_package_store_status st;
        ASSERT(vcs_package_store_package_status(f.receiver.store, pub.root, &st));
        ASSERT(st.tracked && !st.complete);
        ASSERT_EQ(pd_receive(&f, pub.root, NULL, false, &got), PLUGIN_DIST_ERR_TRUNCATED);
        ASSERT(!pd_generation_stored(&f, packed.generation));
        ASSERT(pd_scratch_empty(&f));
        ASSERT(pd_transfer(&f, pub.root, 0, false));
        ASSERT_EQ(pd_receive(&f, pub.root, NULL, false, &got), PLUGIN_DIST_OK);
        ASSERT(pd_generation_stored(&f, packed.generation));
        PASS();
    } _test_next:;
    pd_close(&f);
    return failures;
}

/* ---- 6. downgrade -------------------------------------------------------- */
static int pd_refuse_downgrade(void)
{
    int failures = 0;
    struct pd_fixture f = {0};
    TEST("plugin dist: a lower version than current needs the owner flag; current stays") {
        struct plugin_pack_result v1, v2;
        struct plugin_dist_published pub;
        struct plugin_dist_received got;
        struct plugin_manifest m;
        int present = 0;
        ASSERT(pd_open(&f));
        ASSERT(pd_pack(&f, "packed1", "1.0.0", &v1));
        ASSERT(pd_pack(&f, "packed2", "2.0.0", &v2));
        ASSERT(strcmp(v1.public_key, v2.public_key) == 0);
        ASSERT(pd_keys(f.plugins, v1.public_key));
        ASSERT_EQ(plugin_store_install(f.plugins, v2.manifest_path, &m, &present), PLUGIN_OK);
        ASSERT_EQ(plugin_store_switch(f.plugins, "demo", v2.generation), PLUGIN_OK);
        ASSERT_EQ(pd_publish(&f, "packed1", 1, &pub), PLUGIN_DIST_OK);
        ASSERT(pd_transfer(&f, pub.root, 0, true));
        ASSERT_EQ(pd_receive(&f, pub.root, NULL, false, &got), PLUGIN_DIST_ERR_DOWNGRADE);
        ASSERT(!pd_generation_stored(&f, v1.generation));
        ASSERT(pd_selection(&f, v2.generation));
        ASSERT(strcmp(got.current_version, "2.0.0") == 0);
        ASSERT_EQ(pd_receive(&f, pub.root, NULL, true, &got), PLUGIN_DIST_OK);
        ASSERT(got.downgrade_allowed);
        ASSERT(pd_generation_stored(&f, v1.generation));
        ASSERT(pd_selection(&f, v2.generation)); /* still the newer one */
        PASS();
    } _test_next:;
    pd_close(&f);
    return failures;
}

static int pd_versions(void)
{
    int failures = 0;
    TEST("plugin dist: dotted versions compare numerically; tails do not compare") {
        bool ok = false;
        ASSERT_EQ(plugin_dist_version_compare("1.10.0", "1.9.9", &ok), 1);
        ASSERT(ok);
        ASSERT_EQ(plugin_dist_version_compare("1.0", "1.0.0", &ok), 0);
        ASSERT_EQ(plugin_dist_version_compare("0.9.9", "1.0.0", &ok), -1);
        (void)plugin_dist_version_compare("1.0.0-rc1", "1.0.0", &ok);
        ASSERT(!ok);
        (void)plugin_dist_version_compare("1..0", "1.0.0", &ok);
        ASSERT(!ok);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- 7. publish refusals -------------------------------------------------- */
static int pd_refuse_publish(void)
{
    int failures = 0;
    struct pd_fixture f = {0};
    TEST("plugin dist: publish refuses a placeholder license, a missing key and a reused sequence") {
        struct plugin_pack_result v1, v2;
        struct plugin_dist_published pub;
        ASSERT(pd_open(&f));
        ASSERT(pd_pack(&f, "packed1", "1.0.0", &v1));
        ASSERT(pd_pack(&f, "packed2", "2.0.0", &v2));
        ASSERT(pd_write(f.license, "MIT\n", 4, 0644));
        ASSERT_EQ(pd_publish(&f, "packed1", 1, &pub), PLUGIN_DIST_ERR_LICENSE);
        ASSERT(pd_write(f.license, TEST_LICENSE_TEXT_MIT, strlen(TEST_LICENSE_TEXT_MIT), 0644));
        char dir[1400];
        ASSERT(pd_path(dir, sizeof(dir), f.base, "packed1"));
        struct plugin_dist_publish_request rq = {
            .name = "demo", .src_dir = dir, .license_file = f.license, .spdx = "MIT",
            .release_key = NULL, .sequence = 1
        };
        ASSERT_EQ(plugin_dist_publish(f.publisher.store, &rq, &pub), PLUGIN_DIST_ERR_RELEASE);
        ASSERT_EQ(pd_publish(&f, "packed1", 1, &pub), PLUGIN_DIST_OK);
        ASSERT_EQ(pd_publish(&f, "packed2", 1, &pub), PLUGIN_DIST_ERR_RELEASE);
        ASSERT_EQ(pd_publish(&f, "packed2", 2, &pub), PLUGIN_DIST_OK);
        PASS();
    } _test_next:;
    pd_close(&f);
    return failures;
}

/* ---- 8. over-cap image and symlinked license ----------------------------- */
static int pd_refuse_big_and_link(void)
{
    int failures = 0;
    struct pd_fixture f = {0};
    TEST("plugin dist: an image over the cap is refused before checkout; a symlinked license is refused") {
        struct plugin_pack_result packed;
        struct plugin_dist_published pub;
        struct plugin_dist_received got;
        char link[1400], original[1200];
        ASSERT(pd_open(&f));
        ASSERT(pd_pack(&f, "packed1", "1.0.0", &packed));
        /* A symlink in place of the license file is named, not a generic refusal. */
        ASSERT(pd_path(link, sizeof(link), f.base, "LICENSE.link"));
        ASSERT_EQ(symlink(f.license, link), 0);
        snprintf(original, sizeof(original), "%s", f.license);
        snprintf(f.license, sizeof(f.license), "%s", link);
        ASSERT_EQ(pd_publish(&f, "packed1", 1, &pub), PLUGIN_DIST_ERR_LICENSE);
        ASSERT(strstr(pub.detail, "symlink") != NULL);
        snprintf(f.license, sizeof(f.license), "%s", original);
        ASSERT_EQ(pd_publish(&f, "packed1", 1, &pub), PLUGIN_DIST_OK);
        ASSERT(pd_transfer(&f, pub.root, 0, true));
        ASSERT(pd_keys(f.plugins, packed.public_key));
        plugin_dist_test_set_image_max(8);
        enum plugin_dist_status st = pd_receive(&f, pub.root, NULL, false, &got);
        plugin_dist_test_set_image_max(0);
        ASSERT_EQ(st, PLUGIN_DIST_ERR_TOO_LARGE);
        ASSERT(!pd_generation_stored(&f, packed.generation));
        ASSERT(pd_scratch_empty(&f));
        ASSERT_EQ(pd_receive(&f, pub.root, NULL, false, &got), PLUGIN_DIST_OK);
        PASS();
    } _test_next:;
    plugin_dist_test_set_image_max(0);
    pd_close(&f);
    return failures;
}

int test_plugin_dist(void)
{
    int failures = 0;
    failures += pd_versions();
    failures += pd_journey();
    failures += pd_relay();
    failures += pd_installed_publish();
    failures += pd_refuse_root();
    failures += pd_refuse_unpinned();
    failures += pd_refuse_image();
    failures += pd_refuse_truncated();
    failures += pd_refuse_downgrade();
    failures += pd_refuse_publish();
    failures += pd_refuse_big_and_link();
    /* Every case has ended (pass or fail); drop this run's RAM trees. */
    test_shm_reap_own("zcode_swarm-test-tmp_");
    return failures;
}
