/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Rebuildable CAS projection of signed publication observations. */
#include "vcs/zcode_publication_index.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_publication.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INDEX_LOG "vcs.publication_index"
#define INDEX_MAX_SCANNED 262144u

static const uint8_t result_magic[8] = {'Z','C','P','R','E','S','\r','\n'};
static const uint8_t receipt_magic[8] = {'Z','C','R','R','C','P','\r','\n'};

struct vcs_zcode_publication_index {
    struct vcs_zcode_publication_observation_entry *entries;
    size_t count;
    size_t scanned;
    bool complete;
};

static bool index_hex_lower(const char *s, size_t want)
{
    if (strlen(s) != want) return false;
    for (size_t i = 0; i < want; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

static bool index_intent_signer(const char *repo_root,
                                const uint8_t publication_root[32],
                                uint8_t signer[32])
{
    uint8_t *wire = NULL, checked[32];
    size_t len = 0;
    struct vcs_zcode_publication_v1 intent;
    bool ok = vcs_object_load_raw_bounded(repo_root, publication_root,
            VCS_ZCODE_PUBLICATION_WIRE_BYTES, &wire, &len) == 0 &&
        vcs_zcode_publication_parse(wire, len, &intent) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_publication_root(&intent, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(checked, publication_root, 32) == 0 &&
        vcs_zcode_publication_verify(&intent, intent.author_pubkey) == VCS_ZCODE_DEV_OK;
    if (ok) memcpy(signer, intent.author_pubkey, 32);
    free(wire);
    return ok;
}

static bool index_result(const char *repo_root, const uint8_t address[32],
                         const uint8_t *wire, size_t len,
                         struct vcs_zcode_publication_observation_entry *entry)
{
    struct vcs_zcode_publication_result_v1 result, checked;
    uint8_t publisher[32];
    if (vcs_zcode_publication_result_parse(wire, len, &result) != VCS_ZCODE_DEV_OK ||
        !index_intent_signer(repo_root, result.publication_root, publisher) ||
        !vcs_zcode_publication_result_load_verified(repo_root, address,
            publisher, result.producer_pubkey, &checked))
        return false;
    zcl_hex_encode(result.publication_root, 32, entry->publication_root_hex);
    zcl_hex_encode(result.producer_pubkey, 32, entry->signer_pubkey_hex);
    entry->kind = VCS_ZCODE_OBSERVATION_ATTEMPT_RESULT;
    entry->outcome = result.outcome;
    return true;
}

static bool index_receipt(const char *repo_root, const uint8_t address[32],
                          const uint8_t *wire, size_t len,
                          struct vcs_zcode_publication_observation_entry *entry)
{
    struct vcs_zcode_remote_receipt_v1 receipt, checked;
    uint8_t publisher[32];
    if (vcs_zcode_remote_receipt_parse(wire, len, &receipt) != VCS_ZCODE_DEV_OK ||
        !index_intent_signer(repo_root, receipt.publication_root, publisher) ||
        !vcs_zcode_remote_receipt_load_verified(repo_root, address,
            publisher, receipt.observer_pubkey, &checked))
        return false;
    zcl_hex_encode(receipt.publication_root, 32, entry->publication_root_hex);
    zcl_hex_encode(receipt.observer_pubkey, 32, entry->signer_pubkey_hex);
    entry->kind = VCS_ZCODE_OBSERVATION_REMOTE_RECEIPT;
    return true;
}

static void index_consider(const char *repo_root, const char *hex64,
                           struct vcs_zcode_publication_index *index)
{
    uint8_t address[32], *wire = NULL;
    size_t len = 0;
    if (!zcl_hex_decode_lower(hex64, address, 32)) return;
    int read_status = vcs_object_load_raw_bounded(repo_root, address,
        VCS_ZCODE_REMOTE_RECEIPT_WIRE_BYTES, &wire, &len);
    if (read_status == -2) return; /* another, larger CAS citizen */
    if (read_status != 0) {
        index->complete = false;
        LOG_ERROR(INDEX_LOG, "unreadable CAS object %.8s", hex64);
        return;
    }
    bool result = len >= 8 && memcmp(wire, result_magic, 8) == 0;
    bool receipt = len >= 8 && memcmp(wire, receipt_magic, 8) == 0;
    if (result || receipt) {
        struct vcs_zcode_publication_observation_entry entry = {0};
        bool ok = result ? index_result(repo_root, address, wire, len, &entry)
                         : index_receipt(repo_root, address, wire, len, &entry);
        if (!ok || index->count >= VCS_ZCODE_PUBLICATION_INDEX_MAX_OBSERVATIONS) {
            index->complete = false;
            LOG_ERROR(INDEX_LOG, "invalid or over-cap publication observation %.8s",
                      hex64);
        } else {
            zcl_hex_encode(address, 32, entry.root_hex);
            index->entries[index->count++] = entry;
        }
    }
    free(wire);
}

static void index_scan_shard(const char *repo_root, const char *path,
                             const char *shard,
                             struct vcs_zcode_publication_index *index)
{
    DIR *dir = opendir(path);
    if (!dir) {
        index->complete = false;
        LOG_ERROR(INDEX_LOG, "cannot open CAS shard %s", path);
        return;
    }
    struct dirent *de;
    for (;;) {
        errno = 0;
        de = readdir(dir);
        if (!de) {
            if (errno != 0) index->complete = false;
            break;
        }
        if (!index_hex_lower(de->d_name, 62)) continue;
        if (++index->scanned > INDEX_MAX_SCANNED) {
            index->complete = false;
            break;
        }
        char hex64[65];
        int n = snprintf(hex64, sizeof(hex64), "%s%s", shard, de->d_name);
        if (n == 64) index_consider(repo_root, hex64, index);
    }
    closedir(dir);
}

static int index_entry_cmp(const void *a, const void *b)
{
    return strcmp(((const struct vcs_zcode_publication_observation_entry *)a)->root_hex,
                  ((const struct vcs_zcode_publication_observation_entry *)b)->root_hex);
}

static void index_scan_root(const char *repo_root, const char *objects,
                            struct vcs_zcode_publication_index *index)
{
    DIR *dir = opendir(objects);
    if (!dir) {
        index->complete = false;
        return;
    }
    struct dirent *de;
    for (;;) {
        errno = 0;
        de = readdir(dir);
        if (!de) {
            if (errno != 0) index->complete = false;
            break;
        }
        if (!index_hex_lower(de->d_name, 2)) continue;
        char path[4400];
        int n = snprintf(path, sizeof(path), "%s/%s", objects, de->d_name);
        if (n <= 0 || (size_t)n >= sizeof(path)) {
            index->complete = false;
            continue;
        }
        index_scan_shard(repo_root, path, de->d_name, index);
        if (index->scanned > INDEX_MAX_SCANNED) break;
    }
    closedir(dir);
}

struct vcs_zcode_publication_index *vcs_zcode_publication_index_build(
    const char *repo_root)
{
    if (!repo_root || !repo_root[0])
        LOG_RETURN(NULL, INDEX_LOG, "missing workspace");
    struct vcs_zcode_publication_index *index =
        zcl_malloc(sizeof(*index), "publication_index");
    if (!index) LOG_RETURN(NULL, INDEX_LOG, "index allocation failed");
    memset(index, 0, sizeof(*index));
    index->complete = true;
    index->entries = zcl_malloc(sizeof(*index->entries) *
        VCS_ZCODE_PUBLICATION_INDEX_MAX_OBSERVATIONS,
        "publication_index_entries");
    if (!index->entries) {
        free(index);
        LOG_RETURN(NULL, INDEX_LOG, "entry allocation failed");
    }
    char objects[4400];
    int n = snprintf(objects, sizeof(objects), "%s/.zvcs/objects", repo_root);
    if (n <= 0 || (size_t)n >= sizeof(objects)) {
        vcs_zcode_publication_index_free(index);
        LOG_RETURN(NULL, INDEX_LOG, "objects path too long");
    }
    index_scan_root(repo_root, objects, index);
    if (index->count > 1)
        qsort(index->entries, index->count, sizeof(*index->entries), index_entry_cmp);
    return index;
}

void vcs_zcode_publication_index_free(struct vcs_zcode_publication_index *index)
{
    if (!index) return;
    free(index->entries);
    free(index);
}

bool vcs_zcode_publication_index_complete(
    const struct vcs_zcode_publication_index *index)
{
    return index && index->complete;
}

size_t vcs_zcode_publication_index_count(
    const struct vcs_zcode_publication_index *index)
{
    return index ? index->count : 0;
}

const struct vcs_zcode_publication_observation_entry *
vcs_zcode_publication_index_at(
    const struct vcs_zcode_publication_index *index, size_t i)
{
    return index && i < index->count ? &index->entries[i] : NULL;
}

static void index_recovery_observations(
    const struct vcs_zcode_publication_index *index, const char *root_hex,
    struct vcs_zcode_publication_recovery_view *out)
{
    for (size_t i = 0; i < index->count; i++) {
        const struct vcs_zcode_publication_observation_entry *entry =
            &index->entries[i];
        if (strcmp(entry->publication_root_hex, root_hex) != 0) continue;
        if (entry->kind == VCS_ZCODE_OBSERVATION_REMOTE_RECEIPT) {
            out->remote_receipts++;
        } else if (entry->kind == VCS_ZCODE_OBSERVATION_ATTEMPT_RESULT) {
            out->attempt_results++;
            if (entry->outcome == VCS_ZCODE_PUBLICATION_UNKNOWN)
                out->unknown_attempts++;
            else if (entry->outcome == VCS_ZCODE_PUBLICATION_ACCEPTED)
                out->accepted_attempts++;
            else if (entry->outcome == VCS_ZCODE_PUBLICATION_REJECTED)
                out->rejected_attempts++;
        }
    }
}

bool vcs_zcode_publication_index_recovery(
    const struct vcs_zcode_publication_index *index,
    const char *repo_root,
    const uint8_t publication_root[32],
    const uint8_t expected_signer[32],
    struct vcs_zcode_publication_recovery_view *out)
{
    if (!out) LOG_RETURN(false, INDEX_LOG, "missing recovery output");
    memset(out, 0, sizeof(*out));
    if (!index || !index->complete || !repo_root || !repo_root[0] ||
        !publication_root || !expected_signer)
        LOG_RETURN(false, INDEX_LOG, "incomplete recovery input");
    struct vcs_zcode_publication_v1 intent;
    if (!vcs_zcode_publication_load_verified(repo_root, publication_root,
            expected_signer, &intent))
        LOG_RETURN(false, INDEX_LOG, "publication intent is not stored and verified");
    char root_hex[65];
    zcl_hex_encode(publication_root, 32, root_hex);
    index_recovery_observations(index, root_hex, out);
    out->state = out->attempt_results || out->remote_receipts
        ? VCS_ZCODE_RECOVERY_RECONCILE_REMOTE
        : VCS_ZCODE_RECOVERY_RECHECK_UNDER_LEASE;
    return true;
}
