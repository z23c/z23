/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * vcs_seal — implementation. See vcs/vcs_seal.h. */

#include "vcs/vcs_seal.h"
#include "vcs/vcs_object.h"

#include "vcs_priv.h"

#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const k_default_globs[] = {
    "core/",
    "domain/consensus/",
    "lib/consensus/",
    "lib/validation/",
    "lib/chain/",
    "lib/mining/",
    "app/jobs/",
};
#define K_DEFAULT_GLOB_COUNT \
    (sizeof(k_default_globs) / sizeof(k_default_globs[0]))

void vcs_seal_free_globs(char **globs, size_t n)
{
    if (!globs) return;
    for (size_t i = 0; i < n; i++)
        free(globs[i]);
    free(globs);
}

static bool globs_from_default(char ***out_globs, size_t *out_n)
{
    char **g = zcl_calloc(K_DEFAULT_GLOB_COUNT, sizeof(*g), "vcs_globs");
    if (!g)
        LOG_FAIL("vcs", "calloc default globs");
    for (size_t i = 0; i < K_DEFAULT_GLOB_COUNT; i++) {
        g[i] = zcl_strdup(k_default_globs[i], "vcs_glob");
        if (!g[i]) {
            vcs_seal_free_globs(g, i);
            LOG_FAIL("vcs", "strdup default glob");
        }
    }
    *out_globs = g;
    *out_n = K_DEFAULT_GLOB_COUNT;
    return true;
}

bool vcs_seal_load_globs(const char *repo_root, char ***out_globs, size_t *out_n)
{
    if (!repo_root || !out_globs || !out_n)
        LOG_FAIL("vcs", "null arg to load_globs");
    *out_globs = NULL;
    *out_n = 0;

    char path[4096];
    int n = snprintf(path, sizeof(path), "%s/.zvcs/sealed_paths", repo_root);
    if (n <= 0 || (size_t)n >= sizeof(path))
        LOG_FAIL("vcs", "sealed_paths path too long");

    FILE *f = fopen(path, "re");
    if (!f)
        return globs_from_default(out_globs, out_n);

    char **g = NULL;
    size_t count = 0, cap = 0;
    char line[VCS_PATH_MAX + 2];
    bool ok = true;
    while (fgets(line, sizeof(line), f)) {
        /* strip trailing newline / CR */
        size_t l = strlen(line);
        while (l > 0 && (line[l - 1] == '\n' || line[l - 1] == '\r'))
            line[--l] = '\0';
        /* strip leading whitespace */
        char *s = line;
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '\0' || *s == '#')
            continue;
        if (count == cap) {
            size_t ncap = cap ? cap * 2 : 16;
            char **ng = zcl_realloc(g, ncap * sizeof(*ng), "vcs_globs");
            if (!ng) { ok = false; break; }
            g = ng;
            cap = ncap;
        }
        g[count] = zcl_strdup(s, "vcs_glob");
        if (!g[count]) { ok = false; break; }
        count++;
    }
    fclose(f);
    if (!ok) {
        vcs_seal_free_globs(g, count);
        LOG_FAIL("vcs", "load_globs alloc failed");
    }
    if (count == 0) {
        /* An empty/all-comment file means "seal nothing", which is a valid
         * (if unusual) choice — honour it rather than silently defaulting. */
        free(g);
        *out_globs = NULL;
        *out_n = 0;
        return true;
    }
    *out_globs = g;
    *out_n = count;
    return true;
}

bool vcs_seal_path_matches(const char *path, char *const *globs, size_t nglobs)
{
    if (!path || !globs)
        return false;
    for (size_t i = 0; i < nglobs; i++) {
        const char *g = globs[i];
        if (!g || !g[0])
            continue;
        size_t gl = strlen(g);
        if (g[gl - 1] == '/') {
            if (strncmp(path, g, gl) == 0)
                return true;
        } else if (fnmatch(g, path, FNM_PATHNAME) == 0) {
            return true;
        }
    }
    return false;
}

static int hash_cmp(const void *a, const void *b)
{
    return memcmp(a, b, 32);
}

bool vcs_sealset_hash(const struct vcs_manifest *m, char *const *globs,
                      size_t nglobs, uint8_t out[32])
{
    if (!m || !out)
        LOG_FAIL("vcs", "null arg to sealset_hash");

    uint8_t (*hashes)[32] = NULL;
    size_t count = 0;
    if (m->count > 0) {
        hashes = zcl_malloc(m->count * 32, "vcs_sealset_hashes");
        if (!hashes)
            LOG_FAIL("vcs", "malloc sealset hashes");
    }
    for (size_t i = 0; i < m->count; i++) {
        if (!vcs_seal_path_matches(m->entries[i].path, globs, nglobs))
            continue;
        if (!vcs_manifest_entry_hash(&m->entries[i], hashes[count])) {
            free(hashes);
            LOG_FAIL("vcs", "entry_hash in sealset");
        }
        count++;
    }
    if (count > 1)
        qsort(hashes, count, 32, hash_cmp);

    uint8_t tag = VCS_TAG_SEALSET;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, &tag, 1);
    for (size_t i = 0; i < count; i++)
        sha3_256_write(&ctx, hashes[i], 32);
    sha3_256_finalize(&ctx, out);
    free(hashes);
    return true;
}

bool vcs_seal_grant_unseal(struct vcs_index *idx,
                           const uint8_t authorized_sealset[32])
{
    if (!idx || !authorized_sealset)
        LOG_FAIL("vcs", "null arg to grant_unseal");
    if (!vcs_index_begin(idx))
        LOG_FAIL("vcs", "grant_unseal: begin");
    if (!vcs_index_meta_set_in_tx(idx, VCS_SEAL_TOKEN_KEY, authorized_sealset,
                                  32)) {
        vcs_index_rollback(idx);
        LOG_FAIL("vcs", "grant_unseal: write");
    }
    if (!vcs_index_commit(idx))
        LOG_FAIL("vcs", "grant_unseal: commit");
    return true;
}

/* Shared read-only decision: OK when new_sealset==pin (or no pin yet), OK
 * when a token authorizing exactly new_sealset exists, REFUSED otherwise.
 * Never mutates the index. `*out_token_matched` (if non-NULL) reports
 * whether the OK verdict came from a matching token that a caller wanting
 * the consuming behavior (vcs_seal_check) still needs to spend. */
static enum vcs_seal_result seal_decide(struct vcs_index *idx,
                                        const uint8_t new_sealset[32],
                                        bool *out_token_matched)
{
    if (out_token_matched)
        *out_token_matched = false;
    if (!idx || !new_sealset)
        return VCS_SEAL_ERROR;

    uint8_t pin[32];
    bool have_pin = false;
    if (!vcs_index_seal_pin_get(idx, pin, &have_pin))
        return VCS_SEAL_ERROR;

    /* No pin yet (first snapshot) or unchanged: nothing to protect. */
    if (!have_pin || memcmp(pin, new_sealset, 32) == 0)
        return VCS_SEAL_OK;

    /* Changed — require a token authorizing exactly this new sealset. */
    uint8_t token[32];
    size_t tlen = 0;
    bool have_token = false;
    if (!vcs_index_meta_get(idx, VCS_SEAL_TOKEN_KEY, token, sizeof(token),
                            &tlen, &have_token))
        return VCS_SEAL_ERROR;
    if (!have_token || tlen != 32 || memcmp(token, new_sealset, 32) != 0)
        return VCS_SEAL_REFUSED;

    if (out_token_matched)
        *out_token_matched = true;
    return VCS_SEAL_OK;
}

enum vcs_seal_result vcs_seal_check(struct vcs_index *idx,
                                    const uint8_t new_sealset[32])
{
    bool token_matched = false;
    enum vcs_seal_result r = seal_decide(idx, new_sealset, &token_matched);
    if (r != VCS_SEAL_OK || !token_matched)
        return r;

    /* Valid one-shot token: consume it and allow. */
    if (!vcs_index_begin(idx))
        return VCS_SEAL_ERROR;
    if (!vcs_index_meta_delete_in_tx(idx, VCS_SEAL_TOKEN_KEY)) {
        vcs_index_rollback(idx);
        return VCS_SEAL_ERROR;
    }
    if (!vcs_index_commit(idx))
        return VCS_SEAL_ERROR;
    return VCS_SEAL_OK;
}

enum vcs_seal_result vcs_seal_peek(struct vcs_index *idx,
                                   const uint8_t new_sealset[32])
{
    return seal_decide(idx, new_sealset, NULL);
}
