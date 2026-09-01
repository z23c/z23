/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_publish — implementation of the ZCODE publication validation
 * rules declared in vcs/package_publish.h. Pure validation plus bounded
 * read-only loading of persisted releases; persistence is the store's job
 * (the commit command drives vcs_package_store_put_* after these checks
 * pass). */

#include "vcs/package_publish.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define PUBLISH_LOG "vcs.publish"

const char *vcs_package_publish_rule_string(
    enum vcs_package_publish_rule rule)
{
    switch (rule) {
    case VCS_PACKAGE_PUBLISH_OK: return "ok";
    case VCS_PACKAGE_PUBLISH_RULE_RELEASE_PARSE:
        return "release-wire-not-canonical";
    case VCS_PACKAGE_PUBLISH_RULE_RELEASE_VERIFY:
        return "release-envelope-invalid";
    case VCS_PACKAGE_PUBLISH_RULE_MANIFEST_PARSE:
        return "manifest-grammar";
    case VCS_PACKAGE_PUBLISH_RULE_ROOT_MATCH:
        return "release-root-mismatch";
    case VCS_PACKAGE_PUBLISH_RULE_PACKAGE_CAP:
        return "package-exceeds-64mib-cap";
    case VCS_PACKAGE_PUBLISH_RULE_LICENSE_TEXT:
        return "license-text-missing";
    case VCS_PACKAGE_PUBLISH_RULE_HIDDEN_EXECUTABLE:
        return "hidden-executable-payload";
    case VCS_PACKAGE_PUBLISH_RULE_CHUNK_MISSING:
        return "chunk-source-missing";
    case VCS_PACKAGE_PUBLISH_RULE_CHUNK_SIZE:
        return "chunk-source-size-mismatch";
    case VCS_PACKAGE_PUBLISH_RULE_CHUNK_HASH:
        return "chunk-hash-mismatch";
    case VCS_PACKAGE_PUBLISH_RULE_ACCEPT:
        return "release-acceptance-failed";
    case VCS_PACKAGE_PUBLISH_RULE_RECIPE_MISSING:
        return "recipe-missing";
    case VCS_PACKAGE_PUBLISH_RULE_RECIPE_PARSE:
        return "recipe-wire-not-canonical";
    case VCS_PACKAGE_PUBLISH_RULE_RECIPE_VALIDATE:
        return "recipe-field-invalid";
    case VCS_PACKAGE_PUBLISH_RULE_RECIPE_ROOT_MATCH:
        return "recipe-root-mismatch";
    case VCS_PACKAGE_PUBLISH_RULE_RECIPE_PATH:
        return "recipe-path-not-in-manifest";
    case VCS_PACKAGE_PUBLISH_RULE_IO:
        return "io-failure";
    case VCS_PACKAGE_PUBLISH_RULE_ALLOC:
        return "allocation-failure";
    }
    return "unknown-rule";
}

void vcs_package_publish_report_init(struct vcs_package_publish_report *r)
{
    if (r)
        memset(r, 0, sizeof(*r));
}

void vcs_package_publish_fail(struct vcs_package_publish_report *r,
                              enum vcs_package_publish_rule rule,
                              const char *detail)
{
    if (!r)
        return;
    if (r->failure_count >= VCS_PACKAGE_PUBLISH_MAX_FAILURES) {
        r->failures_truncated = true;
        return;
    }
    struct vcs_package_publish_failure *f =
        &r->failures[r->failure_count++];
    f->rule = rule;
    snprintf(f->detail, sizeof(f->detail), "%s", detail ? detail : "");
}

/* True when any '/'-separated segment of the (already canonical) path
 * starts with '.', e.g. ".git/hooks/x" or "src/.tools/y". */
static bool publish_path_hidden(const char *path)
{
    if (!path)
        return false;
    if (path[0] == '.')
        return true;
    return strstr(path, "/.") != NULL;
}

void vcs_package_publish_validate(
    const struct vcs_package_release *release,
    const struct vcs_package_manifest *manifest,
    struct vcs_package_publish_report *report)
{
    if (!release || !manifest || !report) {
        vcs_package_publish_fail(report, VCS_PACKAGE_PUBLISH_RULE_ALLOC,
                                 "null release/manifest/report");
        return;
    }

    /* Rule 1: the envelope (field grammars incl. the v1 SPDX license
     * allowlist, release id, low-S, ECDSA over the publisher key). */
    enum vcs_package_release_error err = vcs_package_release_verify(release);
    if (err != VCS_PACKAGE_RELEASE_OK) {
        vcs_package_publish_fail(
            report, VCS_PACKAGE_PUBLISH_RULE_RELEASE_VERIFY,
            vcs_package_release_error_string(err));
        return;
    }
    report->release_ok = true;
    if (vcs_package_release_id(release, report->release_id) !=
        VCS_PACKAGE_RELEASE_OK) {
        vcs_package_publish_fail(report, VCS_PACKAGE_PUBLISH_RULE_ALLOC,
                                 "release id unavailable after verify");
        return;
    }

    /* Rules 3-6 over the manifest. */
    report->manifest_ok = true;
    uint64_t total_bytes = 0;
    uint32_t chunk_count = 0;
    bool license_present = false;
    for (size_t i = 0; i < manifest->count; i++) {
        const struct vcs_package_file *f = &manifest->files[i];
        total_bytes += f->size;
        chunk_count += f->chunk_count;
        if (strcmp(f->path, VCS_PACKAGE_PUBLISH_LICENSE_PATH) == 0)
            license_present = true;
        if (f->mode == VCS_PACKAGE_MODE_EXECUTABLE &&
            publish_path_hidden(f->path)) {
            vcs_package_publish_fail(
                report, VCS_PACKAGE_PUBLISH_RULE_HIDDEN_EXECUTABLE, f->path);
        }
    }
    report->total_bytes = total_bytes;
    report->file_count = (uint32_t)manifest->count;
    report->chunk_count = chunk_count;

    uint8_t root[32];
    if (!vcs_package_manifest_root(manifest, root)) {
        vcs_package_publish_fail(report, VCS_PACKAGE_PUBLISH_RULE_ALLOC,
                                 "manifest root unavailable after parse");
        return;
    }
    if (memcmp(root, release->package_root, 32) != 0)
        vcs_package_publish_fail(report, VCS_PACKAGE_PUBLISH_RULE_ROOT_MATCH,
                                 "release.package_root != manifest root");
    if (total_bytes > VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES)
        vcs_package_publish_fail(report, VCS_PACKAGE_PUBLISH_RULE_PACKAGE_CAP,
                                 "package total exceeds 64 MiB");
    if (!license_present)
        vcs_package_publish_fail(report,
                                 VCS_PACKAGE_PUBLISH_RULE_LICENSE_TEXT,
                                 "manifest has no top-level LICENSE file");
}

void vcs_package_publish_validate_recipe(
    const struct vcs_package_release *release,
    const struct vcs_package_manifest *manifest,
    const struct vcs_package_recipe *recipe,
    struct vcs_package_publish_report *report)
{
    if (!release || !manifest || !recipe || !report) {
        vcs_package_publish_fail(report, VCS_PACKAGE_PUBLISH_RULE_ALLOC,
                                 "null release/manifest/recipe/report");
        return;
    }

    /* Field grammars and bounds (the closed declarative grammar). */
    enum vcs_package_recipe_error rerr =
        vcs_package_recipe_validate(recipe);
    if (rerr != VCS_PACKAGE_RECIPE_OK) {
        vcs_package_publish_fail(report,
                                 VCS_PACKAGE_PUBLISH_RULE_RECIPE_VALIDATE,
                                 vcs_package_recipe_error_string(rerr));
        return;
    }

    /* The envelope commits the recipe by root. */
    uint8_t root[32];
    rerr = vcs_package_recipe_root(recipe, root);
    if (rerr != VCS_PACKAGE_RECIPE_OK) {
        vcs_package_publish_fail(report, VCS_PACKAGE_PUBLISH_RULE_ALLOC,
                                 "recipe root unavailable after validate");
        return;
    }
    if (memcmp(root, release->recipe_root, 32) != 0) {
        vcs_package_publish_fail(
            report, VCS_PACKAGE_PUBLISH_RULE_RECIPE_ROOT_MATCH,
            "recipe root != release.recipe_root");
        return;
    }

    /* Every referenced path resolves in the manifest. */
    char detail[160];
    if (!vcs_package_recipe_files_in_manifest(recipe, manifest, detail,
                                              sizeof(detail))) {
        vcs_package_publish_fail(report, VCS_PACKAGE_PUBLISH_RULE_RECIPE_PATH,
                                 detail);
        return;
    }
    memcpy(report->recipe_root, root, 32);
    report->recipe_ok = true;
}

bool vcs_package_publish_read_chunk(
    const char *dir, const struct vcs_package_file *file,
    uint32_t chunk_index, uint8_t *buf, size_t *len_out,
    enum vcs_package_publish_rule *rule_out)
{
    if (!dir || !file || !buf || !len_out || !rule_out) {
        LOG_FAIL(PUBLISH_LOG, "null read_chunk argument");
        return false;
    }
    *rule_out = VCS_PACKAGE_PUBLISH_OK;
    char path[4400];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, file->path);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        LOG_ERROR(PUBLISH_LOG, "chunk path too long: %s", file->path);
        *rule_out = VCS_PACKAGE_PUBLISH_RULE_IO;
        return false;
    }
    FILE *f = fopen(path, "rb");
    if (!f) {
        *rule_out = VCS_PACKAGE_PUBLISH_RULE_CHUNK_MISSING;
        return false;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        LOG_ERROR(PUBLISH_LOG, "seek %s", path);
        *rule_out = VCS_PACKAGE_PUBLISH_RULE_IO;
        return false;
    }
    long size = ftell(f);
    if (size < 0 || (uint64_t)size != file->size) {
        fclose(f);
        *rule_out = VCS_PACKAGE_PUBLISH_RULE_CHUNK_SIZE;
        return false;
    }
    uint64_t offset = (uint64_t)chunk_index * VCS_PACKAGE_CHUNK_BYTES;
    size_t want = (size_t)(file->size - offset);
    if (want > VCS_PACKAGE_CHUNK_BYTES)
        want = VCS_PACKAGE_CHUNK_BYTES;
    if (fseek(f, (long)offset, SEEK_SET) != 0 ||
        (want > 0 && fread(buf, 1, want, f) != want)) {
        fclose(f);
        LOG_ERROR(PUBLISH_LOG, "read %s chunk %u", path, chunk_index);
        *rule_out = VCS_PACKAGE_PUBLISH_RULE_IO;
        return false;
    }
    fclose(f);
    *len_out = want;
    return true;
}

void vcs_package_publish_verify_chunks(
    const struct vcs_package_manifest *manifest, const char *dir,
    struct vcs_package_publish_report *report)
{
    if (!manifest || !dir || !report) {
        vcs_package_publish_fail(report, VCS_PACKAGE_PUBLISH_RULE_ALLOC,
                                 "null manifest/dir/report");
        return;
    }
    uint8_t *buf = zcl_malloc(VCS_PACKAGE_CHUNK_BYTES, "publish_chunk_buf");
    if (!buf) {
        vcs_package_publish_fail(report, VCS_PACKAGE_PUBLISH_RULE_ALLOC,
                                 "chunk buffer");
        return;
    }
    uint32_t verified = 0;
    for (size_t i = 0; i < manifest->count; i++) {
        const struct vcs_package_file *f = &manifest->files[i];
        for (uint32_t c = 0; c < f->chunk_count; c++) {
            size_t len = 0;
            enum vcs_package_publish_rule rule;
            if (!vcs_package_publish_read_chunk(dir, f, c, buf, &len,
                                                &rule)) {
                char detail[160];
                snprintf(detail, sizeof(detail), "%s#%u", f->path, c);
                vcs_package_publish_fail(report, rule, detail);
                break; /* one named failure per file is enough */
            }
            if (!vcs_package_verify_chunk(f, c, buf, len)) {
                char detail[160];
                snprintf(detail, sizeof(detail), "%s#%u", f->path, c);
                vcs_package_publish_fail(
                    report, VCS_PACKAGE_PUBLISH_RULE_CHUNK_HASH, detail);
                break;
            }
            verified++;
        }
    }
    free(buf);
    report->chunks_verified = verified;
    report->chunks_checked = true;
}

/* qsort order: publisher pubkey, then sequence, then release id — the
 * deterministic replay order a stateless process classifies against. */
static int publish_release_cmp(const void *a, const void *b)
{
    const struct vcs_package_release *ra = a;
    const struct vcs_package_release *rb = b;
    int c = memcmp(ra->publisher_pubkey, rb->publisher_pubkey,
                   VCS_PACKAGE_RELEASE_PUBKEY_BYTES);
    if (c != 0)
        return c;
    if (ra->publisher_sequence != rb->publisher_sequence)
        return ra->publisher_sequence < rb->publisher_sequence ? -1 : 1;
    uint8_t ida[VCS_PACKAGE_RELEASE_ID_BYTES];
    uint8_t idb[VCS_PACKAGE_RELEASE_ID_BYTES];
    if (vcs_package_release_id(ra, ida) != VCS_PACKAGE_RELEASE_OK ||
        vcs_package_release_id(rb, idb) != VCS_PACKAGE_RELEASE_OK)
        return 0;
    return memcmp(ida, idb, 32);
}

static bool publish_name_is_hex64(const char *name)
{
    if (!name || strlen(name) != 64)
        return false;
    for (size_t i = 0; i < 64; i++) {
        char ch = name[i];
        bool ok = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
        if (!ok)
            return false;
    }
    return true;
}

bool vcs_package_publish_load_releases(const char *zcode_dir,
                                       struct vcs_package_release *out,
                                       size_t out_cap, size_t *count_out,
                                       size_t *skipped_out)
{
    if (!zcode_dir || !out || !count_out || !skipped_out)
        LOG_RETURN(false, PUBLISH_LOG, "null load_releases argument");
    *count_out = 0;
    *skipped_out = 0;
    char dir[4400];
    int n = snprintf(dir, sizeof(dir), "%s/releases", zcode_dir);
    if (n < 0 || (size_t)n >= sizeof(dir))
        LOG_RETURN(false, PUBLISH_LOG, "releases path too long");
    DIR *d = opendir(dir);
    if (!d)
        return true; /* no releases yet: an empty load, not an error */
    uint8_t *wire = zcl_malloc(VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES,
                               "publish_release_wire");
    if (!wire) {
        closedir(d);
        LOG_RETURN(false, PUBLISH_LOG, "release wire buffer");
    }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!publish_name_is_hex64(de->d_name))
            continue;
        if (*count_out >= out_cap) {
            (*skipped_out)++;
            continue;
        }
        char path[4400];
        n = snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        if (n < 0 || (size_t)n >= sizeof(path)) {
            (*skipped_out)++;
            continue;
        }
        FILE *f = fopen(path, "rb");
        if (!f) {
            (*skipped_out)++;
            continue;
        }
        size_t len = fread(wire, 1, VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES, f);
        bool trailing = !feof(f);
        fclose(f);
        if (trailing ||
            vcs_package_release_parse(wire, len,
                                      &out[*count_out]) !=
                VCS_PACKAGE_RELEASE_OK) {
            LOG_ERROR(PUBLISH_LOG, "skipping unparseable release %s",
                      de->d_name);
            (*skipped_out)++;
            continue;
        }
        (*count_out)++;
    }
    free(wire);
    closedir(d);
    qsort(out, *count_out, sizeof(*out), publish_release_cmp);
    return true;
}

bool vcs_package_publish_replay(const char *zcode_dir,
                                struct vcs_package_accept *accept,
                                size_t *replayed_out)
{
    if (!zcode_dir || !accept)
        LOG_RETURN(false, PUBLISH_LOG, "null replay argument");
    struct vcs_package_release *releases =
        zcl_malloc(sizeof(*releases) * VCS_PACKAGE_PUBLISH_MAX_RELEASES,
                   "publish_replay");
    if (!releases)
        LOG_RETURN(false, PUBLISH_LOG, "replay array");
    size_t count = 0;
    size_t skipped = 0;
    bool ok = vcs_package_publish_load_releases(
        zcode_dir, releases, VCS_PACKAGE_PUBLISH_MAX_RELEASES, &count,
        &skipped);
    if (ok) {
        size_t replayed = 0;
        for (size_t i = 0; i < count; i++) {
            enum vcs_package_accept_result ar =
                vcs_package_accept(accept, &releases[i]);
            if (ar == VCS_PACKAGE_ACCEPT_OK ||
                ar == VCS_PACKAGE_ACCEPT_DUPLICATE)
                replayed++;
            else
                LOG_ERROR(PUBLISH_LOG,
                          "persisted release %zu reclassifies as %s", i,
                          vcs_package_accept_result_string(ar));
        }
        if (replayed_out)
            *replayed_out = replayed;
    }
    free(releases);
    return ok;
}
