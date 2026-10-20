/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the multi-builder verdict. A manifest is accepted only when at
 * least K distinct pinned builder keys attest its sha3_512 for one source
 * root. A stray unpinned, duplicate, mismatched or malformed record is a
 * refusal, never a skip: a directory that disagrees with itself proves
 * nothing. Reads files only; installs and runs nothing. */

#include "plugin_internal.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "plugin/plugin_attest.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct pav_pins {
    uint8_t key[PLUGIN_ATTEST_PINS_MAX][32];
    uint32_t count;
};

struct pav_state {
    struct plugin_manifest manifest;
    struct pav_pins pins;
    const char *expected_root;
    char toolchains[PLUGIN_ATTEST_PINS_MAX][PLUGIN_ATTEST_TOOLCHAIN_MAX + 1];
};

static bool pav_pinned(const struct pav_pins *p, const uint8_t key[32])
{
    for (uint32_t i = 0; i < p->count; i++)
        if (memcmp(p->key[i], key, 32) == 0)
            return true;
    return false;
}

/* One pin per line; blank lines and # comments are ignored; a repeated key
 * counts once, so listing a key three times never raises the pinned count. */
static enum plugin_attest_status pav_pin_line(struct pav_pins *p, const char *line,
                                              size_t n)
{
    char hex[PLUGIN_ATTEST_HEX_KEY + 1];
    uint8_t key[32];
    if (n == 0 || line[0] == '#')
        return PLUGIN_ATTEST_OK;
    if (n != PLUGIN_ATTEST_HEX_KEY)
        return PLUGIN_ATTEST_PINS_MALFORMED;
    memcpy(hex, line, n);
    hex[n] = '\0';
    if (!zcl_hex_decode_lower(hex, key, sizeof(key)))
        return PLUGIN_ATTEST_PINS_MALFORMED;
    if (pav_pinned(p, key))
        return PLUGIN_ATTEST_OK;
    if (p->count >= PLUGIN_ATTEST_PINS_MAX)
        return PLUGIN_ATTEST_PINS_MALFORMED;
    memcpy(p->key[p->count++], key, 32);
    return PLUGIN_ATTEST_OK;
}

static enum plugin_attest_status pav_pins_scan(struct pav_pins *p, const char *bytes,
                                               size_t len)
{
    size_t pos = 0;
    while (pos < len) {
        size_t end = pos;
        while (end < len && bytes[end] != '\n')
            end++;
        size_t n = end - pos;
        while (n > 0 && bytes[pos + n - 1] == '\r')
            n--;
        enum plugin_attest_status st = pav_pin_line(p, bytes + pos, n);
        if (st != PLUGIN_ATTEST_OK)
            return st;
        pos = end + 1u;
    }
    return PLUGIN_ATTEST_OK;
}

/* The pin file and the manifest are read before any attestation. */
static enum plugin_attest_status pav_load_inputs(struct pav_state *s, const char *manifest,
                                                 const char *builders,
                                                 struct plugin_attest_report *rep)
{
    char *bytes = NULL;
    size_t len = 0;
    if (!plugin_read_file(manifest, PLUGIN_FILE_MAX, PLUGIN_OPEN_NOFOLLOW, &bytes, &len)) {
        rep->cause = PLUGIN_ERR_MANIFEST_MISSING;
        return PLUGIN_ATTEST_UPSTREAM;
    }
    rep->cause = plugin_manifest_parse(bytes, len, &s->manifest);
    free(bytes);
    if (rep->cause != PLUGIN_OK)
        return PLUGIN_ATTEST_UPSTREAM;
    rep->cause = plugin_keys_load(builders, &bytes, &len);
    if (rep->cause != PLUGIN_OK)
        return PLUGIN_ATTEST_UPSTREAM;
    enum plugin_attest_status st = pav_pins_scan(&s->pins, bytes, len);
    free(bytes);
    return st;
}

static enum plugin_attest_status pav_threshold(const struct pav_state *s, int64_t k,
                                               struct plugin_attest_report *rep)
{
    rep->pinned = s->pins.count;
    if (k < 1)
        return PLUGIN_ATTEST_THRESHOLD_INVALID;
    if (k > (int64_t)s->pins.count)
        return PLUGIN_ATTEST_THRESHOLD_EXCEEDS_PINS;
    rep->threshold = (uint32_t)k;
    return PLUGIN_ATTEST_OK;
}

static bool pav_seen_builder(const struct plugin_attest_report *rep, const char *key)
{
    for (uint32_t i = 0; i < rep->attested; i++)
        if (strcmp(rep->builders[i], key) == 0)
            return true;
    return false;
}

static void pav_note_toolchain(struct pav_state *s, struct plugin_attest_report *rep,
                               const char *tc)
{
    for (uint32_t i = 0; i < rep->toolchains; i++)
        if (strcmp(s->toolchains[i], tc) == 0)
            return;
    snprintf(s->toolchains[rep->toolchains++], sizeof(s->toolchains[0]), "%s", tc);
}

static enum plugin_attest_status pav_subject(const struct pav_state *s,
                                             const struct plugin_attest_record *r)
{
    bool same = strcmp(r->name, s->manifest.name) == 0 &&
                strcmp(r->version, s->manifest.version) == 0;
    return same ? PLUGIN_ATTEST_OK : PLUGIN_ATTEST_SUBJECT_MISMATCH;
}

static enum plugin_attest_status pav_builder(const struct pav_state *s,
                                             const struct plugin_attest_report *rep,
                                             const struct plugin_attest_record *r)
{
    uint8_t key[32];
    if (!zcl_hex_decode_lower(r->builder_key, key, sizeof(key)) ||
        !pav_pinned(&s->pins, key))
        return PLUGIN_ATTEST_BUILDER_UNPINNED;
    return pav_seen_builder(rep, r->builder_key) ? PLUGIN_ATTEST_DUPLICATE_BUILDER
                                                  : PLUGIN_ATTEST_OK;
}

static enum plugin_attest_status pav_bytes(const struct pav_state *s,
                                           const struct plugin_attest_record *r)
{
    return strcmp(r->image, s->manifest.exe_sha3) == 0 ? PLUGIN_ATTEST_OK
                                                        : PLUGIN_ATTEST_HASH_MISMATCH;
}

/* Every record names one source root: the caller's when given, else the
 * first record's. */
static enum plugin_attest_status pav_root(const struct pav_state *s,
                                          const struct plugin_attest_report *rep,
                                          const struct plugin_attest_record *r)
{
    const char *want = s->expected_root ? s->expected_root
                                        : (rep->attested ? rep->source_root : r->source_root);
    return strcmp(r->source_root, want) == 0 ? PLUGIN_ATTEST_OK
                                              : PLUGIN_ATTEST_SOURCE_ROOT_MISMATCH;
}

static enum plugin_attest_status pav_admit(struct pav_state *s,
                                           struct plugin_attest_report *rep,
                                           const struct plugin_attest_record *r)
{
    enum plugin_attest_status st = pav_subject(s, r);
    if (st == PLUGIN_ATTEST_OK)
        st = pav_builder(s, rep, r);
    if (st == PLUGIN_ATTEST_OK)
        st = pav_bytes(s, r);
    if (st == PLUGIN_ATTEST_OK)
        st = pav_root(s, rep, r);
    if (st != PLUGIN_ATTEST_OK)
        return st;
    if (rep->attested == 0) {
        snprintf(rep->name, sizeof(rep->name), "%s", r->name);
        snprintf(rep->version, sizeof(rep->version), "%s", r->version);
        snprintf(rep->source_root, sizeof(rep->source_root), "%s", r->source_root);
        snprintf(rep->image, sizeof(rep->image), "%s", r->image);
    }
    snprintf(rep->builders[rep->attested++], sizeof(rep->builders[0]), "%s", r->builder_key);
    pav_note_toolchain(s, rep, r->toolchain);
    return PLUGIN_ATTEST_OK;
}

static enum plugin_attest_status pav_file(struct pav_state *s,
                                          struct plugin_attest_report *rep,
                                          const char *dir, const char *leaf)
{
    char path[PLUGIN_PATH_MAX], *bytes = NULL;
    size_t len = 0;
    struct plugin_attest_record rec;
    snprintf(rep->file, sizeof(rep->file), "%s", leaf);
    if (!plugin_join(path, sizeof(path), dir, leaf, NULL, NULL))
        return PLUGIN_ATTEST_ARGUMENT;
    if (!plugin_read_file(path, PLUGIN_ATTEST_RECORD_MAX, PLUGIN_OPEN_NOFOLLOW, &bytes, &len))
        return PLUGIN_ATTEST_IO;
    enum plugin_attest_status st = plugin_attest_parse(bytes, len, &rec);
    free(bytes);
    if (st == PLUGIN_ATTEST_OK)
        st = plugin_attest_check_signature(&rec);
    if (st == PLUGIN_ATTEST_OK)
        st = pav_admit(s, rep, &rec);
    rep->files++;
    return st;
}

static int pav_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

typedef char pav_leaf[256];

static bool pav_is_attestation(const char *name)
{
    size_t n = strlen(name), sfx = strlen(PLUGIN_ATTEST_SUFFIX);
    return n > sfx && n < sizeof(pav_leaf) &&
           strcmp(name + n - sfx, PLUGIN_ATTEST_SUFFIX) == 0;
}

/* Sorted leaf names, so a refusal and a count do not depend on readdir order. */
static enum plugin_attest_status pav_list(const char *dir, pav_leaf *leaves, size_t *count)
{
    DIR *d = opendir(dir);
    if (!d)
        return PLUGIN_ATTEST_IO;
    enum plugin_attest_status st = PLUGIN_ATTEST_OK;
    struct dirent *e;
    *count = 0;
    while (st == PLUGIN_ATTEST_OK && (e = readdir(d)) != NULL) {
        if (!pav_is_attestation(e->d_name))
            continue;
        if (*count >= PLUGIN_ATTEST_FILES_MAX)
            st = PLUGIN_ATTEST_TOO_MANY_FILES;
        else
            snprintf(leaves[(*count)++], sizeof(pav_leaf), "%s", e->d_name);
    }
    closedir(d);
    if (st == PLUGIN_ATTEST_OK && *count > 1)
        qsort(leaves, *count, sizeof(pav_leaf), pav_cmp);
    return st;
}

static enum plugin_attest_status pav_scan(struct pav_state *s,
                                          struct plugin_attest_report *rep,
                                          const char *dir)
{
    pav_leaf *leaves = zcl_malloc(sizeof(pav_leaf) * PLUGIN_ATTEST_FILES_MAX, "plugin.attest.leaves");
    size_t count = 0;
    if (!leaves)
        return PLUGIN_ATTEST_IO;
    enum plugin_attest_status st = pav_list(dir, leaves, &count);
    for (size_t i = 0; st == PLUGIN_ATTEST_OK && i < count; i++)
        st = pav_file(s, rep, dir, leaves[i]);
    free(leaves);
    if (st == PLUGIN_ATTEST_OK)
        rep->file[0] = '\0';
    return st;
}

static bool pav_root_arg_ok(const char *root)
{
    return !root || (strlen(root) == PLUGIN_ATTEST_HEX_KEY &&
                     plugin_hex_valid(root, PLUGIN_ATTEST_HEX_KEY));
}

enum plugin_attest_status plugin_attest_verify_dir(
    const char *manifest_path, const char *attestations_dir,
    const char *builders_path, int64_t threshold, const char *expected_root,
    struct plugin_attest_report *report)
{
    if (!report)
        return PLUGIN_ATTEST_ARGUMENT;
    memset(report, 0, sizeof(*report));
    if (!manifest_path || !attestations_dir || !builders_path || !pav_root_arg_ok(expected_root))
        return PLUGIN_ATTEST_ARGUMENT;
    struct pav_state *s = zcl_malloc(sizeof(*s), "plugin.attest.state");
    if (!s)
        return PLUGIN_ATTEST_IO;
    memset(s, 0, sizeof(*s));
    s->expected_root = expected_root;
    enum plugin_attest_status st = pav_load_inputs(s, manifest_path, builders_path, report);
    if (st == PLUGIN_ATTEST_OK)
        st = pav_threshold(s, threshold, report);
    if (st == PLUGIN_ATTEST_OK)
        st = pav_scan(s, report, attestations_dir);
    if (st == PLUGIN_ATTEST_OK && report->attested < report->threshold)
        st = PLUGIN_ATTEST_BELOW_THRESHOLD;
    free(s);
    return st;
}
