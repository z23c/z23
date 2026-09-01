/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_index — implementation of the rebuildable search projection
 * declared in vcs/package_index.h. Every build re-reads the persisted
 * release envelopes and manifest wires; nothing is cached across builds. */

#include "vcs/package_index.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INDEX_LOG "vcs.index"

struct vcs_package_index {
    struct vcs_package_index_entry *entries;
    size_t count;
    size_t skipped_count;
};

/* Project one parsed manifest wire (read from <zcode_dir>/manifests/<root>)
 * into the entry's summary fields. Absent/unparseable manifests leave
 * manifest_present false — a release can be indexed before its package is
 * fully hosted. */
static void index_fill_manifest_summary(const char *zcode_dir,
                                        struct vcs_package_index_entry *e)
{
    char path[4400];
    int n = snprintf(path, sizeof(path), "%s/manifests/%s", zcode_dir,
                     e->package_root_hex);
    if (n < 0 || (size_t)n >= sizeof(path))
        return;
    FILE *f = fopen(path, "rb");
    if (!f)
        return;
    uint8_t *wire = zcl_malloc(VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES,
                               "index_manifest_wire");
    if (!wire) {
        fclose(f);
        LOG_ERROR(INDEX_LOG, "manifest wire buffer alloc failed");
        return;
    }
    size_t len = fread(wire, 1, VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES, f);
    bool trailing = !feof(f);
    fclose(f);
    if (trailing || len == 0) {
        free(wire);
        LOG_ERROR(INDEX_LOG, "manifest %s exceeds the wire bound",
                  e->package_root_hex);
        return;
    }
    struct vcs_package_manifest manifest;
    if (!vcs_package_manifest_parse(wire, len, &manifest)) {
        free(wire);
        LOG_ERROR(INDEX_LOG, "persisted manifest %s no longer parses",
                  e->package_root_hex);
        return;
    }
    free(wire);
    uint8_t expect[32];
    uint8_t root[32];
    if (!zcl_hex_decode_lower(e->package_root_hex, expect, 32) ||
        !vcs_package_manifest_root(&manifest, root) ||
        memcmp(expect, root, 32) != 0) {
        vcs_package_manifest_free(&manifest);
        LOG_ERROR(INDEX_LOG, "persisted manifest %s fails its root check",
                  e->package_root_hex);
        return;
    }
    e->manifest_present = true;
    e->file_count = (uint32_t)manifest.count;
    for (size_t i = 0; i < manifest.count; i++) {
        const struct vcs_package_file *mf = &manifest.files[i];
        e->total_bytes += mf->size;
        e->chunk_total += mf->chunk_count;
        if (strcmp(mf->path, VCS_PACKAGE_PUBLISH_LICENSE_PATH) == 0)
            e->license_present = true;
        if (mf->mode == VCS_PACKAGE_MODE_EXECUTABLE)
            e->executable_count++;
    }
    vcs_package_manifest_free(&manifest);
}

static int index_entry_cmp(const void *a, const void *b)
{
    const struct vcs_package_index_entry *ea = a;
    const struct vcs_package_index_entry *eb = b;
    int c = strcmp(ea->name, eb->name);
    if (c != 0)
        return c;
    return strcmp(ea->release_id_hex, eb->release_id_hex);
}

struct vcs_package_index *vcs_package_index_build(const char *zcode_dir)
{
    if (!zcode_dir)
        LOG_RETURN(NULL, INDEX_LOG, "null zcode_dir");
    struct vcs_package_release *releases =
        zcl_malloc(sizeof(*releases) * VCS_PACKAGE_PUBLISH_MAX_RELEASES,
                   "index_releases");
    if (!releases)
        LOG_RETURN(NULL, INDEX_LOG, "release array");
    size_t count = 0;
    size_t skipped = 0;
    if (!vcs_package_publish_load_releases(
            zcode_dir, releases, VCS_PACKAGE_PUBLISH_MAX_RELEASES, &count,
            &skipped)) {
        free(releases);
        LOG_RETURN(NULL, INDEX_LOG, "release load failed for %s", zcode_dir);
    }
    struct vcs_package_index *index =
        zcl_malloc(sizeof(*index), "vcs_package_index");
    if (!index) {
        free(releases);
        LOG_RETURN(NULL, INDEX_LOG, "index alloc");
    }
    index->entries = NULL;
    index->count = 0;
    index->skipped_count = skipped;
    if (count > 0) {
        index->entries = zcl_malloc(sizeof(*index->entries) * count,
                                    "index_entries");
        if (!index->entries) {
            free(index);
            free(releases);
            LOG_RETURN(NULL, INDEX_LOG, "entry array");
        }
    }
    for (size_t i = 0; i < count; i++) {
        const struct vcs_package_release *r = &releases[i];
        struct vcs_package_index_entry *e = &index->entries[index->count];
        memset(e, 0, sizeof(*e));
        uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
        if (vcs_package_release_id(r, id) != VCS_PACKAGE_RELEASE_OK) {
            LOG_ERROR(INDEX_LOG, "persisted release %zu has no id", i);
            continue;
        }
        zcl_hex_encode(id, 32, e->release_id_hex);
        zcl_hex_encode(r->package_root, 32, e->package_root_hex);
        snprintf(e->name, sizeof(e->name), "%s", r->name);
        snprintf(e->semver, sizeof(e->semver), "%s", r->semver);
        snprintf(e->license, sizeof(e->license), "%s", r->license);
        zcl_hex_encode(r->publisher_pubkey, VCS_PACKAGE_RELEASE_PUBKEY_BYTES,
                  e->publisher_hex);
        snprintf(e->chain_id, sizeof(e->chain_id), "%s", r->chain_id);
        snprintf(e->reward_address, sizeof(e->reward_address), "%s",
                 r->reward_address);
        e->publisher_sequence = r->publisher_sequence;
        e->has_parent = r->has_parent;
        if (r->has_parent)
            zcl_hex_encode(r->parent_root, 32, e->parent_root_hex);
        e->has_znam = r->has_znam;
        if (r->has_znam)
            snprintf(e->znam, sizeof(e->znam), "%s", r->znam);
        index_fill_manifest_summary(zcode_dir, e);
        index->count++;
    }
    free(releases);
    /* entries stays NULL for an empty store, and qsort declares its base
     * argument non-null even for a zero count. */
    if (index->count > 1)
        qsort(index->entries, index->count, sizeof(*index->entries),
              index_entry_cmp);
    return index;
}

void vcs_package_index_free(struct vcs_package_index *index)
{
    if (!index)
        return;
    free(index->entries);
    free(index);
}

size_t vcs_package_index_count(const struct vcs_package_index *index)
{
    return index ? index->count : 0;
}

size_t vcs_package_index_skipped_count(const struct vcs_package_index *index)
{
    return index ? index->skipped_count : 0;
}

const struct vcs_package_index_entry *vcs_package_index_at(
    const struct vcs_package_index *index, size_t i)
{
    if (!index || i >= index->count)
        return NULL;
    return &index->entries[i];
}

const struct vcs_package_index_entry *vcs_package_index_find_root(
    const struct vcs_package_index *index, const uint8_t package_root[32])
{
    if (!index || !package_root)
        return NULL;
    char root_hex[65];
    zcl_hex_encode(package_root, 32, root_hex);
    for (size_t i = 0; i < index->count; i++)
        if (strcmp(index->entries[i].package_root_hex, root_hex) == 0)
            return &index->entries[i];
    return NULL;
}

static bool index_entry_matches(const struct vcs_package_index_entry *e,
                                const struct vcs_package_search *s)
{
    if (s->publisher && s->publisher[0] &&
        strncmp(e->publisher_hex, s->publisher, strlen(s->publisher)) != 0)
        return false;
    if (s->name_prefix && s->name_prefix[0] &&
        strncmp(e->name, s->name_prefix, strlen(s->name_prefix)) != 0)
        return false;
    if (s->license && s->license[0] &&
        strcmp(e->license, s->license) != 0)
        return false;
    if (s->keyword && s->keyword[0] && !strstr(e->name, s->keyword))
        return false;
    return true;
}

size_t vcs_package_index_search(const struct vcs_package_index *index,
                                const struct vcs_package_search *search,
                                const struct vcs_package_index_entry **out,
                                size_t out_cap)
{
    if (!index || !search)
        return 0;
    size_t total = 0;
    for (size_t i = 0; i < index->count; i++) {
        if (!index_entry_matches(&index->entries[i], search))
            continue;
        if (out && total < out_cap)
            out[total] = &index->entries[i];
        total++;
    }
    return total;
}
