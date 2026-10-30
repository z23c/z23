/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Box-level receiver index of signed observation leaves. */
#include "dev_proof_observation_index.h"

#include "base/safe_alloc.h"
#include "base/serialize_le.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "platform/file_sync.h"
#include "platform/path_replace.h"
#include "platform/private_file.h"
#include <sys/stat.h>
#include <unistd.h>

#if defined(_WIN32)
#define INDEX_BINARY_MODE O_BINARY
#else
#define INDEX_BINARY_MODE 0
#endif

#define INDEX_MAGIC "Z23OIDX"
#define INDEX_MAGIC_BYTES 8u
#define INDEX_VERSION 1u
#define INDEX_OFF_VERSION 8u
#define INDEX_OFF_COUNT 12u

static bool oi_fail(char *why, size_t cap, const char *token)
{
    if (why && cap) (void)snprintf(why, cap, "%s", token);
    return false;
}

/* ── Row verification ────────────────────────────────────────────────── */

static bool oi_row_verify(const uint8_t *row, char *why, size_t why_len)
{
    struct zcl_dev_verdict_leaf_v1 leaf;
    char token[96];
    uint8_t derived[ZCL_DEV_PROOF_ROOT_BYTES];
    if (!zcl_dev_verdict_leaf_parse(row + ZCL_DEV_PROOF_ROOT_BYTES,
                                    ZCL_DEV_VERDICT_LEAF_WIRE_BYTES, &leaf,
                                    token, sizeof(token)) ||
        !zcl_dev_verdict_leaf_root(&leaf, derived, token, sizeof(token)) ||
        memcmp(derived, row, ZCL_DEV_PROOF_ROOT_BYTES) != 0)
        return oi_fail(why, why_len,
                       ZCL_DEV_OBSERVATION_INDEX_WHY_INVALID);
    return true;
}

/* ── File read/write ─────────────────────────────────────────────────── */

/* Read the index file into a freshly allocated row buffer. An absent file
 * is not an error. Every structural byte is checked: magic, version,
 * count bounds, reserved zeros, sorted unique roots, and each row's
 * root-binding. */
/* Slurp the whole index file. An absent file is not an error. */
static bool oi_read_file(const char *index_path, uint8_t **buf_out,
    size_t *len_out, bool *present_out, char *why, size_t why_len)
{
    *buf_out = NULL;
    *len_out = 0;
    *present_out = false;
    int fd = open(index_path, O_RDONLY | INDEX_BINARY_MODE);
    if (fd < 0) {
        if (errno == ENOENT) return true;
        return oi_fail(why, why_len, ZCL_DEV_OBSERVATION_INDEX_WHY_INVALID);
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 0 ||
        (uint64_t)st.st_size > UINT64_C(32) +
            ZCL_DEV_OBSERVATION_INDEX_MAX_ROWS *
                ZCL_DEV_OBSERVATION_INDEX_ROW_BYTES) {
        (void)close(fd);
        return oi_fail(why, why_len, ZCL_DEV_OBSERVATION_INDEX_WHY_INVALID);
    }
    size_t file_len = (size_t)st.st_size;
    uint8_t *buf = zcl_malloc(file_len ? file_len : 1u, "dev-obs-index-read");
    if (!buf) {
        (void)close(fd);
        return oi_fail(why, why_len, ZCL_DEV_OBSERVATION_INDEX_WHY_INVALID);
    }
    size_t got = 0;
    while (got < file_len) {
        ssize_t n = read(fd, buf + got, file_len - got);
        if (n <= 0) {
            free(buf);
            (void)close(fd);
            return oi_fail(why, why_len,
                           ZCL_DEV_OBSERVATION_INDEX_WHY_INVALID);
        }
        got += (size_t)n;
    }
    (void)close(fd);
    *buf_out = buf;
    *len_out = file_len;
    *present_out = true;
    return true;
}

/* Header framing and row-count consistency; binding-agnostic. */
static bool oi_read_framing(const uint8_t *buf, size_t file_len,
    uint32_t *rows_out, char *why, size_t why_len)
{
    if (file_len < ZCL_DEV_OBSERVATION_INDEX_WIRE_BYTES ||
        (file_len - ZCL_DEV_OBSERVATION_INDEX_WIRE_BYTES) %
            ZCL_DEV_OBSERVATION_INDEX_ROW_BYTES != 0)
        return oi_fail(why, why_len, ZCL_DEV_OBSERVATION_INDEX_WHY_INVALID);
    if (memcmp(buf, INDEX_MAGIC, INDEX_MAGIC_BYTES - 1) != 0 ||
        buf[INDEX_MAGIC_BYTES - 1] != 0 ||
        zcl_read_u32_le(buf + INDEX_OFF_VERSION) != INDEX_VERSION)
        return oi_fail(why, why_len, ZCL_DEV_OBSERVATION_INDEX_WHY_INVALID);
    for (size_t i = ZCL_DEV_OBSERVATION_INDEX_WIRE_BYTES - 16; i <
         ZCL_DEV_OBSERVATION_INDEX_WIRE_BYTES; i++) {
        if (buf[i] != 0)
            return oi_fail(why, why_len,
                           ZCL_DEV_OBSERVATION_INDEX_WHY_INVALID);
    }
    uint32_t rows = zcl_read_u32_le(buf + INDEX_OFF_COUNT);
    if ((size_t)rows != (file_len - ZCL_DEV_OBSERVATION_INDEX_WIRE_BYTES) /
                            ZCL_DEV_OBSERVATION_INDEX_ROW_BYTES ||
        rows > ZCL_DEV_OBSERVATION_INDEX_MAX_ROWS)
        return oi_fail(why, why_len, ZCL_DEV_OBSERVATION_INDEX_WHY_INVALID);
    *rows_out = rows;
    return true;
}

/* Every row must be sorted, unique, and bound to its wire. */
static bool oi_read_rows(const uint8_t *buf, uint32_t rows,
    char *why, size_t why_len)
{
    const uint8_t *at = buf + ZCL_DEV_OBSERVATION_INDEX_WIRE_BYTES;
    for (uint32_t r = 0; r < rows;
         r++, at += ZCL_DEV_OBSERVATION_INDEX_ROW_BYTES) {
        if (r && memcmp(at - ZCL_DEV_OBSERVATION_INDEX_ROW_BYTES, at,
                        ZCL_DEV_PROOF_ROOT_BYTES) >= 0)
            return oi_fail(why, why_len,
                           ZCL_DEV_OBSERVATION_INDEX_WHY_INVALID);
        if (!oi_row_verify(at, why, why_len))
            return false;
    }
    return true;
}

static bool oi_read(const char *index_path, uint8_t **rows_out,
    uint32_t *count_out, bool *present_out, char *why, size_t why_len)
{
    *rows_out = NULL;
    *count_out = 0;
    *present_out = false;
    uint8_t *buf = NULL;
    size_t file_len = 0;
    bool present = false;
    if (!oi_read_file(index_path, &buf, &file_len, &present, why, why_len))
        return false;
    if (!present) return true;
    uint32_t rows = 0;
    bool ok = oi_read_framing(buf, file_len, &rows, why, why_len) &&
              oi_read_rows(buf, rows, why, why_len);
    if (!ok) {
        free(buf);
        return false;
    }
    *rows_out = buf;
    *count_out = rows;
    *present_out = true;
    return true;
}

static bool oi_write_atomic(const char *index_path, const uint8_t *rows,
    uint32_t count, char *why, size_t why_len)
{
    char tmp[4096];
    int n = snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", index_path,
                     (long)getpid());
    if (n < 0 || n >= (int)sizeof(tmp))
        return oi_fail(why, why_len, ZCL_DEV_OBSERVATION_INDEX_WHY_ARGUMENTS);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | INDEX_BINARY_MODE, 0600);
    if (fd < 0)
        return oi_fail(why, why_len, ZCL_DEV_OBSERVATION_INDEX_WHY_INVALID);
    uint8_t header[ZCL_DEV_OBSERVATION_INDEX_WIRE_BYTES] = {0};
    (void)memcpy(header, INDEX_MAGIC, INDEX_MAGIC_BYTES - 1);
    zcl_write_u32_le(header + INDEX_OFF_VERSION, INDEX_VERSION);
    zcl_write_u32_le(header + INDEX_OFF_COUNT, count);
    size_t rows_len = (size_t)count * ZCL_DEV_OBSERVATION_INDEX_ROW_BYTES;
    bool ok = write(fd, header, sizeof(header)) == (ssize_t)sizeof(header) &&
              (rows_len == 0 ||
               write(fd, rows, rows_len) == (ssize_t)rows_len);
    if (ok && platform_file_sync(fd) != 0) ok = false;
    if (close(fd) != 0) ok = false;
    if (!ok || platform_path_replace(tmp, index_path) != 0) {
        (void)unlink(tmp);
        return oi_fail(why, why_len, ZCL_DEV_OBSERVATION_INDEX_WHY_INVALID);
    }
    return true;
}

static int oi_root_cmp(const void *a, const void *b)
{
    return memcmp(a, b, ZCL_DEV_PROOF_ROOT_BYTES);
}

/* Exclusive merge lock: one read-modify-write at a time box-wide. */
static bool oi_lock(const char *index_path, struct platform_private_file *lock,
    char *why, size_t why_len)
{
    char lock_path[4096];
    int n = snprintf(lock_path, sizeof(lock_path), "%s.lock", index_path);
    if (n < 0 || n >= (int)sizeof(lock_path))
        return oi_fail(why, why_len,
                       ZCL_DEV_OBSERVATION_INDEX_WHY_ARGUMENTS);
    if (!platform_private_file_open_locked_create_wait(lock_path, lock))
        return oi_fail(why, why_len,
                       ZCL_DEV_OBSERVATION_INDEX_WHY_INVALID);
    return true;
}

/* Inputs of one merge: the verified existing rows and a fresh enumeration.
 * *noop_out is true when the store holds nothing to fold in. */
static bool oi_merge_inputs(const char *index_path, const char *store_root,
    uint8_t **existing, uint32_t *existing_count,
    struct zcl_dev_observation_leaf **fresh, size_t *fresh_count,
    bool *noop_out, char *why, size_t why_len)
{
    *noop_out = false;
    bool present = false;
    if (!oi_read(index_path, existing, existing_count, &present,
                 why, why_len))
        return false;
    bool store_present = false;
    if (!zcl_dev_observation_enumerate(store_root, fresh, fresh_count,
                                       &store_present, why, why_len))
        return oi_fail(why, why_len, ZCL_DEV_OBSERVATION_INDEX_WHY_INVALID);
    if (!store_present || *fresh_count == 0) {
        /* Nothing to fold in: the index stays exactly as it was. */
        *noop_out = true;
        if (why && why_len) why[0] = 0;
    }
    return true;
}

/* ── Public API ──────────────────────────────────────────────────────── */

/* Union the verified existing rows with freshly enumerated leaves, sort by
 * root, and compact duplicates. The merged buffer is caller-freed. */
static bool oi_union_build(const uint8_t *existing, uint32_t existing_count,
    const struct zcl_dev_observation_leaf *fresh, size_t fresh_count,
    uint8_t **merged_out, uint32_t *unique_out,
    char *why, size_t why_len)
{
    *merged_out = NULL;
    *unique_out = 0;
    uint64_t merged_count = (uint64_t)existing_count + fresh_count;
    /* Each input is independently bounded. Their overlap must be compacted
     * before enforcing the limit on the distinct receiver projection. */
    if (existing_count > ZCL_DEV_OBSERVATION_INDEX_MAX_ROWS ||
        fresh_count > ZCL_DEV_OBSERVATION_INDEX_MAX_ROWS)
        return oi_fail(why, why_len, ZCL_DEV_OBSERVATION_INDEX_WHY_TOO_MANY);
    uint8_t *merged = zcl_malloc(
        (size_t)(merged_count ? merged_count : 1) *
            ZCL_DEV_OBSERVATION_INDEX_ROW_BYTES,
        "dev-obs-index-merge");
    if (!merged)
        return oi_fail(why, why_len, ZCL_DEV_OBSERVATION_INDEX_WHY_INVALID);
    uint8_t *at = merged;
    for (uint32_t r = 0; r < existing_count; r++) {
        (void)memcpy(at, existing + ZCL_DEV_OBSERVATION_INDEX_WIRE_BYTES +
                         (size_t)r * ZCL_DEV_OBSERVATION_INDEX_ROW_BYTES,
                     ZCL_DEV_OBSERVATION_INDEX_ROW_BYTES);
        at += ZCL_DEV_OBSERVATION_INDEX_ROW_BYTES;
    }
    for (size_t i = 0; i < fresh_count; i++) {
        (void)memcpy(at, fresh[i].root, ZCL_DEV_PROOF_ROOT_BYTES);
        if (!zcl_dev_verdict_leaf_serialize(&fresh[i].leaf,
                at + ZCL_DEV_PROOF_ROOT_BYTES, why, why_len)) {
            free(merged);
            return false;
        }
        at += ZCL_DEV_OBSERVATION_INDEX_ROW_BYTES;
    }
    qsort(merged, (size_t)merged_count, ZCL_DEV_OBSERVATION_INDEX_ROW_BYTES,
          oi_root_cmp);
    uint64_t unique = 0;
    for (uint64_t r = 0; r < merged_count; r++) {
        uint8_t *row = merged +
            (size_t)r * ZCL_DEV_OBSERVATION_INDEX_ROW_BYTES;
        if (unique &&
            memcmp(merged + (size_t)(unique - 1) *
                       ZCL_DEV_OBSERVATION_INDEX_ROW_BYTES,
                   row, ZCL_DEV_PROOF_ROOT_BYTES) == 0)
            continue;
        if (unique == ZCL_DEV_OBSERVATION_INDEX_MAX_ROWS) {
            free(merged);
            return oi_fail(why, why_len,
                           ZCL_DEV_OBSERVATION_INDEX_WHY_TOO_MANY);
        }
        if (unique != r)
            (void)memcpy(merged + (size_t)unique *
                             ZCL_DEV_OBSERVATION_INDEX_ROW_BYTES,
                         row, ZCL_DEV_OBSERVATION_INDEX_ROW_BYTES);
        unique++;
    }
    *merged_out = merged;
    *unique_out = (uint32_t)unique;
    return true;
}

bool zcl_dev_observation_index_merge(const char *index_path,
    const char *store_root, char *why, size_t why_len)
{
    if (!index_path || !index_path[0] || !store_root || !store_root[0])
        return oi_fail(why, why_len,
                       ZCL_DEV_OBSERVATION_INDEX_WHY_ARGUMENTS);
    struct platform_private_file lock;
    platform_private_file_init(&lock);
    if (!oi_lock(index_path, &lock, why, why_len))
        return false;

    uint8_t *existing = NULL;
    uint32_t existing_count = 0;
    struct zcl_dev_observation_leaf *fresh = NULL;
    size_t fresh_count = 0;
    bool noop = false;
    bool ok = oi_merge_inputs(index_path, store_root, &existing,
                              &existing_count, &fresh, &fresh_count,
                              &noop, why, why_len);
    if (ok && noop) {
        zcl_dev_observation_release(fresh);
        free(existing);
        platform_private_file_close(&lock);
        return true;
    }

    uint8_t *merged = NULL;
    uint32_t unique = 0;
    if (ok)
        ok = oi_union_build(existing, existing_count, fresh, fresh_count,
                            &merged, &unique, why, why_len);
    if (ok)
        ok = oi_write_atomic(index_path, merged, unique, why, why_len);
    free(merged);
    zcl_dev_observation_release(fresh);
    free(existing);
    platform_private_file_close(&lock);
    if (ok && why && why_len) why[0] = 0;
    return ok;
}

bool zcl_dev_observation_index_load(const char *index_path,
    struct zcl_dev_observation_leaf **leaves_out, size_t *count_out,
    bool *present_out, char *why, size_t why_len)
{
    if (!leaves_out || !count_out || !present_out)
        return oi_fail(why, why_len,
                       ZCL_DEV_OBSERVATION_INDEX_WHY_ARGUMENTS);
    *leaves_out = NULL;
    *count_out = 0;
    *present_out = false;
    uint8_t *rows = NULL;
    uint32_t count = 0;
    bool present = false;
    if (!oi_read(index_path, &rows, &count, &present, why, why_len))
        return false;
    if (!present) return true;
    struct zcl_dev_observation_leaf *leaves =
        zcl_malloc((size_t)(count ? count : 1) * sizeof(*leaves),
                   "dev-obs-index-leaves");
    if (!leaves) {
        free(rows);
        return oi_fail(why, why_len,
                       ZCL_DEV_OBSERVATION_INDEX_WHY_INVALID);
    }
    const uint8_t *at = rows + ZCL_DEV_OBSERVATION_INDEX_WIRE_BYTES;
    for (uint32_t r = 0; r < count; r++,
         at += ZCL_DEV_OBSERVATION_INDEX_ROW_BYTES) {
        struct zcl_dev_observation_leaf *slot = &leaves[r];
        (void)memcpy(slot->root, at, ZCL_DEV_PROOF_ROOT_BYTES);
        char token[96];
        if (!zcl_dev_verdict_leaf_parse(at + ZCL_DEV_PROOF_ROOT_BYTES,
                                        ZCL_DEV_VERDICT_LEAF_WIRE_BYTES,
                                        &slot->leaf, token,
                                        sizeof(token))) {
            free(leaves);
            free(rows);
            return oi_fail(why, why_len,
                           ZCL_DEV_OBSERVATION_INDEX_WHY_INVALID);
        }
        char group[ZCL_DEV_VERDICT_LEAF_GROUP_BYTES];
        (void)memcpy(group, slot->leaf.group, slot->leaf.group_len);
        group[slot->leaf.group_len] = 0;
        slot->eligible = zcl_dev_verdict_leaf_verify(&slot->leaf,
            slot->leaf.key, group, token, sizeof(token));
    }
    free(rows);
    *leaves_out = leaves;
    *count_out = count;
    *present_out = true;
    if (why && why_len) why[0] = 0;
    return true;
}


/* ── Box-level query ──────────────────────────────────────────────────── */

/* Internal per-(group, key) aggregation slot. */
#define OI_QUERY_MAX_SLOTS 1024u
struct oi_query_slot {
    char group[ZCL_DEV_VERDICT_LEAF_GROUP_BYTES];
    uint8_t group_len;
    uint8_t key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES];
    uint8_t verdict;
    uint8_t root[ZCL_DEV_PROOF_ROOT_BYTES]; /* newest-verdict tiebreak */
    uint64_t observed_unix;
    uint32_t observations;
    bool pass, fail;
};

static bool oi_slot_same(const struct oi_query_slot *slot, uint8_t group_len,
    const char *group, const uint8_t key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES])
{
    return slot->group_len == group_len &&
           memcmp(slot->group, group, group_len) == 0 &&
           memcmp(slot->key, key, ZCL_DEV_VERDICT_LEAF_KEY_BYTES) == 0;
}

/* Newest eligible observation wins the slot's verdict; ties break on the
 * larger root so the answer is deterministic regardless of leaf order. */
static void oi_query_slot_absorb(struct oi_query_slot *slot,
    const struct zcl_dev_observation_leaf *leaf)
{
    slot->observations++;
    if (leaf->leaf.verdict == ZCL_DEV_VERDICT_LEAF_PASS)
        slot->pass = true;
    else
        slot->fail = true;
    if (leaf->leaf.observed_unix > slot->observed_unix ||
        (leaf->leaf.observed_unix == slot->observed_unix &&
         memcmp(leaf->root, slot->root, ZCL_DEV_PROOF_ROOT_BYTES) > 0)) {
        slot->observed_unix = leaf->leaf.observed_unix;
        slot->verdict = (uint8_t)leaf->leaf.verdict;
        (void)memcpy(slot->root, leaf->root, ZCL_DEV_PROOF_ROOT_BYTES);
    }
}

static int oi_slot_cmp(const void *a, const void *b)
{
    const struct oi_query_slot *sa = a, *sb = b;
    size_t common = sa->group_len < sb->group_len ? sa->group_len
                                                  : sb->group_len;
    int by_group = memcmp(sa->group, sb->group, common);
    if (by_group != 0) return by_group;
    if (sa->group_len != sb->group_len)
        return sa->group_len < sb->group_len ? -1 : 1;
    return memcmp(sa->key, sb->key, ZCL_DEV_VERDICT_LEAF_KEY_BYTES);
}

static bool oi_query_accumulate(const struct zcl_dev_observation_leaf *leaves,
    size_t leaf_count, const char *group_filter,
    struct oi_query_slot **slots_out, size_t *slot_count_out,
    bool *slots_truncated, struct zcl_dev_observation_query_report *out)
{
    *slots_out = zcl_malloc(OI_QUERY_MAX_SLOTS * sizeof(**slots_out),
                            "dev-obs-query-slots");
    if (!*slots_out)
        return false;
    *slot_count_out = 0;
    *slots_truncated = false;
    for (size_t i = 0; i < leaf_count; i++) {
        const struct zcl_dev_observation_leaf *leaf = &leaves[i];
        uint8_t group_len = leaf->leaf.group_len;
        const char *group = leaf->leaf.group;
        if (group_filter &&
            !(group_len == strlen(group_filter) &&
              memcmp(group, group_filter, group_len) == 0))
            continue;
        out->total++;
        if (!leaf->eligible) {
            out->ineligible++;
            continue;
        }
        out->eligible++;
        uint64_t seen = leaf->leaf.observed_unix;
        if (out->oldest_observed_unix == 0 ||
            seen < out->oldest_observed_unix)
            out->oldest_observed_unix = seen;
        if (seen > out->newest_observed_unix)
            out->newest_observed_unix = seen;
        struct oi_query_slot *slot = NULL;
        for (size_t s = 0; s < *slot_count_out; s++) {
            if (oi_slot_same(&(*slots_out)[s], group_len, group,
                             leaf->leaf.key)) {
                slot = &(*slots_out)[s];
                break;
            }
        }
        if (!slot) {
            if (*slot_count_out >= OI_QUERY_MAX_SLOTS) {
                *slots_truncated = true;
                continue;
            }
            slot = &(*slots_out)[(*slot_count_out)++];
            memset(slot, 0, sizeof(*slot));
            slot->group_len = group_len;
            (void)memcpy(slot->group, group, group_len);
            (void)memcpy(slot->key, leaf->leaf.key,
                         ZCL_DEV_VERDICT_LEAF_KEY_BYTES);
        }
        oi_query_slot_absorb(slot, leaf);
    }
    return true;
}

/* Copy the sorted slots into the bounded public report. */
static void oi_query_fill_groups(const struct oi_query_slot *slots,
    size_t slot_count, bool slots_truncated,
    struct zcl_dev_observation_query_report *out)
{
    uint32_t named = slot_count < ZCL_DEV_OBSERVATION_QUERY_MAX_GROUPS
                         ? (uint32_t)slot_count
                         : ZCL_DEV_OBSERVATION_QUERY_MAX_GROUPS;
    for (size_t i = 0; i < slot_count; i++) {
        if (slots[i].pass && slots[i].fail &&
            out->conflicted_groups < UINT32_MAX)
            out->conflicted_groups++;
    }
    for (uint32_t i = 0; i < named; i++) {
        struct zcl_dev_observation_group_summary *g = &out->groups[i];
        g->group_len = slots[i].group_len;
        (void)memcpy(g->group, slots[i].group, slots[i].group_len);
        (void)memcpy(g->key, slots[i].key, ZCL_DEV_VERDICT_LEAF_KEY_BYTES);
        g->verdict = slots[i].verdict;
        g->observed_unix = slots[i].observed_unix;
        g->observations = slots[i].observations;
        g->conflict = slots[i].pass && slots[i].fail;
    }
    out->groups_named = named;
    out->truncated = slots_truncated || slot_count > named;
}

bool zcl_dev_observation_index_query(const char *index_path,
    const char *group_filter,
    struct zcl_dev_observation_query_report *out, char *why, size_t why_len)
{
    if (!index_path || !index_path[0] || !out)
        return oi_fail(why, why_len,
                       ZCL_DEV_OBSERVATION_INDEX_WHY_ARGUMENTS);
    memset(out, 0, sizeof(*out));
    struct zcl_dev_observation_leaf *leaves = NULL;
    size_t leaf_count = 0;
    bool present = false;
    if (!zcl_dev_observation_index_load(index_path, &leaves, &leaf_count,
                                        &present, why, why_len))
        return false;
    if (!present) {
        if (why && why_len) why[0] = 0;
        return true;
    }
    struct oi_query_slot *slots = NULL;
    size_t slot_count = 0;
    bool slots_truncated = false;
    bool ok = oi_query_accumulate(leaves, leaf_count, group_filter, &slots,
                                  &slot_count, &slots_truncated, out);
    zcl_dev_observation_release(leaves);
    if (!ok)
        return oi_fail(why, why_len, ZCL_DEV_OBSERVATION_INDEX_WHY_INVALID);

    qsort(slots, slot_count, sizeof(*slots), oi_slot_cmp);
    oi_query_fill_groups(slots, slot_count, slots_truncated, out);
    free(slots);
    if (why && why_len) why[0] = 0;
    return true;
}
