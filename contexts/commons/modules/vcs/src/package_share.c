/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Verify signed package shares and their bounded source contents. */
#include "vcs/package_share.h"
#include "codec/cursor.h"
#include "util/file_io.h"
#include "util/file_tree_ops.h"
#include "vcs/source_bundle.h"
#include "vcs/vcs.h"
#include <stdio.h>
#include <string.h>

static bool share_wire(struct zcl_codec_reader *r, size_t cap,
                       const uint8_t **out, size_t *len)
{
    uint32_t n = 0;
    if (!zcl_codec_read_u32le(r, &n) || n == 0 || n > cap) return false;
    *out = zcl_codec_take(r, n); *len = n;
    return *out != NULL;
}

static bool share_decode(struct vcs_package_share *s, const uint8_t *bytes,
                         size_t len)
{
    struct zcl_codec_reader r;
    uint8_t magic[8]; uint32_t version = 0;
    zcl_codec_reader_init(&r, bytes, len);
    return zcl_codec_read_bytes(&r, magic, sizeof(magic)) &&
          memcmp(magic, ZCL_PACKAGE_BUNDLE_MAGIC, sizeof(magic)) == 0 &&
          zcl_codec_read_u32le(&r, &version) && version == ZCL_PACKAGE_BUNDLE_VERSION &&
          share_wire(&r, VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES, &s->wires.release, &s->wires.release_len) &&
          share_wire(&r, VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES, &s->wires.manifest, &s->wires.manifest_len) &&
          share_wire(&r, VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES, &s->wires.recipe, &s->wires.recipe_len) &&
          zcl_codec_read_bytes(&r, s->tree, 32) &&
          share_wire(&r, VCS_SOURCE_BUNDLE_MAX_WIRE_BYTES, &s->source, &s->source_len) &&
          zcl_codec_reader_finish(&r);
}

bool vcs_package_share_load(struct vcs_package_share *s, const uint8_t *bytes,
                            size_t len, const char **reason)
{
    if (!s) return false;
    memset(s, 0, sizeof(*s));
    if (!bytes || !reason) return false;
    *reason = "not a version 1 .z23share file";
    if (len > VCS_SOURCE_BUNDLE_MAX_WIRE_BYTES || !share_decode(s, bytes, len)) return false;
    *reason = "the signed release envelope does not verify";
    if (vcs_package_release_parse(s->wires.release, s->wires.release_len, &s->release) != VCS_PACKAGE_RELEASE_OK ||
        vcs_package_release_id(&s->release, s->release_id) != VCS_PACKAGE_RELEASE_OK ||
        vcs_package_release_verify(&s->release) != VCS_PACKAGE_RELEASE_OK) return false;
    vcs_package_manifest_init(&s->manifest); vcs_package_recipe_init(&s->recipe); s->parsed = true;
    *reason = "the manifest or recipe wire does not parse";
    s->loaded = vcs_package_manifest_parse(s->wires.manifest, s->wires.manifest_len, &s->manifest) &&
        vcs_package_recipe_parse(s->wires.recipe, s->wires.recipe_len, &s->recipe) == VCS_PACKAGE_RECIPE_OK;
    return s->loaded;
}

static bool share_materialize(struct vcs_package_share *s)
{
    struct vcs_source_bundle_metrics metrics;
    bool ok = platform_temp_directory_create("z23-receive-", s->scratch, sizeof(s->scratch));
    int n = ok ? snprintf(s->src, sizeof(s->src), "%s/source", s->scratch) : 0;
    ok = ok && n > 0 && (size_t)n < sizeof(s->src) && zcl_mkdir_p(s->src, 0700).ok;
#ifdef _WIN32
    char store[VCS_PACKAGE_SHARE_PATH_MAX];
    n = ok ? snprintf(store, sizeof(store), "%s/store", s->scratch) : 0;
    ok = ok && n > 0 && (size_t)n < sizeof(store) && zcl_mkdir_p(store, 0700).ok &&
         vcs_source_bundle_import(s->source, s->source_len, s->tree, store, &metrics) == VCS_SOURCE_BUNDLE_OK &&
         vcs_tree_materialize_readonly_disposable(store, s->tree, s->src, VCS_SOURCE_BUNDLE_MAX_SOURCE_BYTES, 0) == VCS_OK;
#else
    ok = ok && vcs_source_bundle_materialize_disposable(s->source, s->source_len, s->tree, s->src, &metrics) == VCS_SOURCE_BUNDLE_OK;
#endif
    return ok;
}

bool vcs_package_share_check_source(struct vcs_package_share *s, const char **reason)
{
    if (!s || !s->loaded || !reason || s->source_checked) return false;
    s->source_checked = true;
    *reason = "the source tree does not rebuild from the bundle";
    if (!share_materialize(s)) return false;
    vcs_package_publish_report_init(&s->report);
    vcs_package_publish_validate(&s->release, &s->manifest, &s->report);
    vcs_package_publish_validate_recipe(&s->release, &s->manifest, &s->recipe, &s->report);
    vcs_package_publish_verify_chunks(&s->manifest, s->src, &s->report);
    if (s->report.failure_count || !s->report.release_ok || !s->report.manifest_ok || !s->report.recipe_ok) {
        *reason = s->report.failure_count ? vcs_package_publish_rule_string(s->report.failures[0].rule) : "publication rules";
        return false;
    }
    return true;
}

void vcs_package_share_cleanup(struct vcs_package_share *s)
{
    if (!s) return;
    if (s->scratch[0]) (void)zcl_tree_remove(s->scratch);
    if (s->parsed) { vcs_package_manifest_free(&s->manifest); vcs_package_recipe_free(&s->recipe); }
    memset(s, 0, sizeof(*s));
}
