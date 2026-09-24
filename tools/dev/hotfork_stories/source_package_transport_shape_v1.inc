/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK story adapter source-package-transport-shape.v1
 * for contexts/commons/modules/vcs/src/source_package_transport.c.
 * Compiled only inside the capsule unity rendered by
 * tools/dev/hotfork_unity.h: phase 1 precedes the owner TU set, phase 2
 * follows it. check-hotfork-stories compiles every unity with the frozen
 * dev flags, so an owner API change cannot silently disable this story.
 */
#if !defined(ZCL_HOTFORK_STORY_PHASE)
#error "HOT_FORK stories are included only by the generated capsule unity"
#elif ZCL_HOTFORK_STORY_PHASE == 1
#define _GNU_SOURCE
#include "hotswap/hotfork_capsule.h"
#elif ZCL_HOTFORK_STORY_PHASE == 2
__attribute__((visibility("hidden"))) bool
zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out)
{
    if (!out) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->magic = ZCL_HOTFORK_OBSERVATION_MAGIC;
#define HF_CHECK(x) \
    do { \
        out->checks_run++; \
        if (x) \
            out->checks_passed++; \
    } while (0)
    size_t marker_len = 0;
    const uint8_t *marker = vcs_source_package_transport_marker(&marker_len);
    HF_CHECK(marker && marker_len == sizeof(source_transport_marker) - 1
             && memcmp(marker, source_transport_marker, marker_len) == 0);
    static uint8_t license[] = {1}, manifest[] = {2}, shard0[] = {3},
                   shard1[] = {4}, lane[] = {5}, authority[] = {6},
                   offline0[] = {7}, offline1[] = {8};
    struct vcs_source_package_transport transport = {0};
    transport.license_bytes = license;
    transport.license_len = sizeof(license);
    transport.source.manifest_wire = manifest;
    transport.source.manifest_wire_len = sizeof(manifest);
    transport.source.shard_count = 2;
    transport.source.shards[0] = (struct vcs_source_bundle_shard){
        .index = 0x0a, .wire = shard0, .wire_len = sizeof(shard0)};
    transport.source.shards[1] = (struct vcs_source_bundle_shard){
        .index = 0xff, .wire = shard1, .wire_len = sizeof(shard1)};
    transport.lane_wire = lane;
    transport.lane_wire_len = sizeof(lane);
    transport.offline_input_count = 2;
    transport.offline_inputs[0] = (struct vcs_source_package_file){
        .path = "offline-a", .bytes = offline0, .len = sizeof(offline0)};
    transport.offline_inputs[1] = (struct vcs_source_package_file){
        .path = "offline-b", .bytes = offline1, .len = sizeof(offline1)};
    HF_CHECK(vcs_source_package_transport_file_count(NULL) == 0);
    HF_CHECK(vcs_source_package_transport_file_count(&transport) == 8);
    const char *path = NULL;
    const uint8_t *bytes = NULL;
    size_t len = 0;
    HF_CHECK(
        vcs_source_package_transport_file_at(&transport, 0, &path, &bytes, &len)
        && strcmp(path, VCS_SOURCE_PACKAGE_LICENSE_PATH) == 0
        && bytes == license && len == 1);
    HF_CHECK(
        vcs_source_package_transport_file_at(&transport, 1, &path, &bytes, &len)
        && strcmp(path, VCS_SOURCE_PACKAGE_MANIFEST_PATH) == 0
        && bytes == manifest && len == 1);
    HF_CHECK(
        vcs_source_package_transport_file_at(&transport, 2, &path, &bytes, &len)
        && strcmp(path, "zclassic23-source/shard-0a.zvss") == 0
        && bytes == shard0 && len == 1);
    HF_CHECK(
        vcs_source_package_transport_file_at(&transport, 3, &path, &bytes, &len)
        && strcmp(path, "zclassic23-source/shard-ff.zvss") == 0
        && bytes == shard1 && len == 1);
    HF_CHECK(
        vcs_source_package_transport_file_at(&transport, 4, &path, &bytes, &len)
        && strcmp(path, VCS_SOURCE_PACKAGE_LANE_PATH) == 0 && bytes == lane
        && len == 1);
    HF_CHECK(
        vcs_source_package_transport_file_at(&transport, 5, &path, &bytes, &len)
        && strcmp(path, VCS_SOURCE_PACKAGE_MARKER_PATH) == 0 && bytes == marker
        && len == marker_len);
    HF_CHECK(
        vcs_source_package_transport_file_at(&transport, 6, &path, &bytes, &len)
        && strcmp(path, "offline-a") == 0 && bytes == offline0 && len == 1);
    HF_CHECK(
        vcs_source_package_transport_file_at(&transport, 7, &path, &bytes, &len)
        && strcmp(path, "offline-b") == 0 && bytes == offline1 && len == 1);
    HF_CHECK(!vcs_source_package_transport_file_at(&transport, 8, &path, &bytes,
                                                   &len));
    transport.authority_wire = authority;
    transport.authority_wire_len = sizeof(authority);
    HF_CHECK(vcs_source_package_transport_file_count(&transport) == 9);
    HF_CHECK(
        vcs_source_package_transport_file_at(&transport, 6, &path, &bytes, &len)
        && strcmp(path, VCS_SOURCE_PACKAGE_AUTHORITY_PATH) == 0
        && bytes == authority && len == 1);
    HF_CHECK(
        vcs_source_package_transport_file_at(&transport, 7, &path, &bytes, &len)
        && strcmp(path, "offline-a") == 0);
    HF_CHECK(vcs_source_package_offline_input_count() == 5);
    HF_CHECK(strcmp(vcs_source_package_offline_input_path(0),
                    "vendor/.cache/leveldb-1.23.tar.gz")
             == 0);
    HF_CHECK(strcmp(vcs_source_package_offline_input_path(4),
                    "vendor/.cache/zlib-1.3.1.tar.gz")
             == 0);
    HF_CHECK(vcs_source_package_offline_input_path(5) == NULL);
#undef HF_CHECK
    snprintf(out->exercised_surface, sizeof(out->exercised_surface),
             ZCL_HOTFORK_EXERCISED_SURFACE);
    snprintf(out->detail, sizeof(out->detail), "checks=%u/%u",
             out->checks_passed, out->checks_run);
    return out->checks_run == 19 && out->checks_passed == 19;
}
#else
#error "unknown HOT_FORK story phase"
#endif
