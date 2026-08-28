/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_reward — implementation of the simulated ZCODE reward ledger
 * and daily settlement queue declared in vcs/package_reward.h (slice 8).
 *
 * SIMULATION ONLY: settlement writes durable score facts under the
 * configured PLACEHOLDER token id; no real ZCODE ZSLP token is ever
 * created, minted, or sent, and there is no wallet/ZSLP sending here at
 * all (the real transfer is the owner-reviewed slice-14 flow).
 *
 * Persistence convention (the file-based store discipline, NOT SQLite/AR):
 * four directories of bounded canonical wires under
 * <datadir>/zcode/rewards/{queue,plans,ledger,commits}; every write is
 * temp + fsync + atomic rename; every load replays the wires into memory.
 * The SETTLED facts under rewards/ledger are the reward-history ledger —
 * the authority the slice-7 period caps read; rewards/commits is the
 * idempotence authority (written LAST in a commit); queue and plans are
 * workflow state. A crash between commit and ledger write is replay-safe:
 * re-committing the same plan id resumes by content id, never
 * double-paying. */

#include "vcs/package_reward.h"

#include "crypto/sha3.h"
#include "base/hex.h"
#include "platform/directory_compat.h"
#include "platform/os_proc.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "vcs/package_score.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#else
struct reward_dir {
    struct platform_directory_list list;
    size_t next;
    struct { const char *d_name; } entry;
};
typedef struct reward_dir DIR;
static DIR *opendir(const char *path)
{
    DIR *dir = calloc(1, sizeof(*dir));
    if (!dir || !platform_directory_list_regular_sorted(path, &dir->list)) {
        free(dir);
        return NULL;
    }
    return dir;
}
static void *readdir(DIR *dir)
{
    if (!dir || dir->next >= dir->list.count) return NULL;
    dir->entry.d_name = dir->list.entries[dir->next++].name;
    return &dir->entry;
}
static int closedir(DIR *dir)
{
    if (!dir) return -1;
    platform_directory_list_free(&dir->list);
    free(dir);
    return 0;
}
#define dirent reward_dirent
struct reward_dirent { const char *d_name; };
#endif

#define REWARD_LOG "vcs.reward"

/* Hash domains (never sign/hash undomained content). */
static const uint8_t k_domain_entry[] = "zcl.zcode_reward_entry.v1";
static const uint8_t k_domain_plan[] = "zcl.zcode_reward_plan.v1";
static const uint8_t k_domain_claim[] = "zcl.zcode_reward_claim_facts.v1";

/* Wire magics. */
#define REWARD_QUEUE_MAGIC "ZQW1"
#define REWARD_FACT_MAGIC "ZRF1"
#define REWARD_PLAN_MAGIC "ZPL1"
#define REWARD_COMMIT_MAGIC "ZRC1"

/* Wire sizes (fixed-layout, little-endian — see the encode/decode fns). */
#define REWARD_QUEUE_WIRE_BYTES 213u
#define REWARD_FACT_WIRE_BYTES 181u
#define REWARD_PLAN_ROW_BYTES 74u
#define REWARD_PLAN_HEADER_BYTES 16u
#define REWARD_COMMIT_ROW_BYTES 103u
#define REWARD_COMMIT_HEADER_BYTES 48u

static bool reward_name_is_hex64(const char *name)
{
    uint8_t scratch[32];
    return zcl_hex_decode_lower(name, scratch, 32);
}

/* ── little-endian wire helpers ─────────────────────────────────────── */

static void reward_put_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t reward_get_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void reward_put_i64le(uint8_t *p, int64_t v)
{
    uint64_t u = (uint64_t)v;
    for (size_t i = 0; i < 8; i++)
        p[i] = (uint8_t)(u >> (8u * i));
}

static int64_t reward_get_i64le(const uint8_t *p)
{
    uint64_t u = 0;
    for (size_t i = 0; i < 8; i++)
        u |= (uint64_t)p[i] << (8u * i);
    return (int64_t)u;
}

/* ── filesystem helpers (the package_store_io discipline) ───────────── */

static bool reward_mkdir_p(const char *path)
{
#if defined(_WIN32)
    return platform_private_directory_ensure(path);
#else
    char buf[4400];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(buf))
        return false;
    memcpy(buf, path, len + 1);
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, 0700) != 0 && errno != EEXIST)
            return false;
        *p = '/';
    }
    return mkdir(buf, 0700) == 0 || errno == EEXIST;
#endif
}

/* Durable write: temp sibling + fsync + atomic rename. A crash leaves
 * either the old file or the new one, never a torn one. */
static bool reward_atomic_write(const char *path, const uint8_t *data,
                                size_t data_len)
{
    static _Atomic uint64_t g_seq = 0;
    uint64_t seq = atomic_fetch_add(&g_seq, 1);
    char tmp[4400];
    int tn = snprintf(tmp, sizeof(tmp), "%s.tmp.%llu.%llu", path,
                      (unsigned long long)os_proc_current_pid(),
                      (unsigned long long)seq);
    if (tn <= 0 || (size_t)tn >= sizeof(tmp))
        LOG_FAIL(REWARD_LOG, "temp path too long for %s", path);
    struct platform_private_file file;
    platform_private_file_init(&file);
    bool ok = platform_private_file_create(tmp, &file) &&
              platform_private_file_write_at(&file, data, data_len, 0) &&
              platform_private_file_truncate(&file, data_len) &&
              platform_private_file_flush(&file) &&
              platform_private_file_replace(&file, tmp, path);
    if (!ok) {
        platform_private_file_close(&file);
        (void)platform_private_file_unlink_missing_ok(tmp);
        LOG_FAIL(REWARD_LOG, "durable replace %s -> %s failed", tmp, path);
    }
    return true;
}

/* Read a whole bounded file. NULL when missing, empty, oversize, or
 * unreadable (missing is not an error: callers treat it as absent). */
static uint8_t *reward_read_file(const char *path, size_t cap,
                                 size_t *out_len)
{
    *out_len = 0;
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path) ||
        !platform_positioned_file_snapshot(&file, &before)) {
        platform_positioned_file_close(&file);
        return NULL;
    }
    if (before.size == 0 || before.size > cap) {
        platform_positioned_file_close(&file);
        return NULL;
    }
    size_t len = (size_t)before.size;
    uint8_t *buf = zcl_malloc(len, "reward_read_file");
    if (!buf)
        LOG_NULL(REWARD_LOG, "alloc %zu for %s", len, path);
    if (platform_positioned_file_read(&file, buf, len, 0) != (int64_t)len ||
        !platform_positioned_file_snapshot(&file, &after) ||
        before.size != after.size || before.volume != after.volume ||
        before.file_low != after.file_low ||
        before.file_high != after.file_high ||
        before.modified_seconds != after.modified_seconds ||
        before.modified_nanoseconds != after.modified_nanoseconds ||
        before.changed_seconds != after.changed_seconds ||
        before.changed_nanoseconds != after.changed_nanoseconds) {
        platform_positioned_file_close(&file);
        free(buf);
        return NULL;
    }
    platform_positioned_file_close(&file);
    *out_len = len;
    return buf;
}

static bool reward_file_exists(const char *path)
{
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    bool exists = platform_positioned_file_open(&file, path);
    platform_positioned_file_close(&file);
    return exists;
}

static bool reward_child_path(char *out, size_t out_size,
                              const char *root, const char *child)
{
    size_t root_len = strlen(root), child_len = strlen(child);
    if (root_len + 1u + child_len + 1u > out_size) return false;
    memcpy(out, root, root_len);
    out[root_len] = '/';
    memcpy(out + root_len + 1u, child, child_len + 1u);
    return true;
}

/* ── ids (domain-separated SHA3-256 over canonical content) ─────────── */

static void reward_entry_id(const struct vcs_reward_entry *e,
                            uint8_t out[32])
{
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, k_domain_entry, sizeof(k_domain_entry) - 1u);
    uint8_t b[4];
    b[0] = (uint8_t)e->kind;
    b[1] = (uint8_t)e->category;
    b[2] = e->has_evidence_root ? 1u : 0u;
    b[3] = 0;
    sha3_256_write(&c, b, 3);
    reward_put_u32le(b, e->points);
    sha3_256_write(&c, b, 4);
    sha3_256_write(&c, e->release_root, 32);
    sha3_256_write(&c, e->contributor, 33);
    sha3_256_write(&c, e->facts_hash, 32);
    sha3_256_write(&c, e->evidence_root, 32);
    sha3_256_finalize(&c, out);
}

/* The claim's scoring facts ARE the claim: category + points + evidence. */
static void reward_claim_facts_hash(enum vcs_reward_category category,
                                    uint32_t points,
                                    const uint8_t evidence_root[32],
                                    uint8_t out[32])
{
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, k_domain_claim, sizeof(k_domain_claim) - 1u);
    uint8_t b[4];
    b[0] = (uint8_t)category;
    sha3_256_write(&c, b, 1);
    reward_put_u32le(b, points);
    sha3_256_write(&c, b, 4);
    sha3_256_write(&c, evidence_root, 32);
    sha3_256_finalize(&c, out);
}

static void reward_plan_id(int64_t day, const struct vcs_reward_plan_row *rows,
                           size_t row_count, uint8_t out[32])
{
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, k_domain_plan, sizeof(k_domain_plan) - 1u);
    uint8_t b[8];
    reward_put_i64le(b, day);
    sha3_256_write(&c, b, 8);
    for (size_t i = 0; i < row_count; i++) {
        if (rows[i].disposition != VCS_REWARD_DISP_PLANNED)
            continue;
        sha3_256_write(&c, rows[i].entry_id, 32);
        reward_put_u32le(b, rows[i].points_settled);
        sha3_256_write(&c, b, 4);
    }
    sha3_256_finalize(&c, out);
}

/* ── wire encode/decode ─────────────────────────────────────────────── */

static void reward_queue_wire_encode(const struct vcs_reward_entry *e,
                                     uint8_t out[REWARD_QUEUE_WIRE_BYTES])
{
    uint8_t *p = out;
    memcpy(p, REWARD_QUEUE_MAGIC, 4);
    p += 4;
    p[0] = (uint8_t)e->kind;
    p[1] = (uint8_t)e->category;
    /* PLANNED is derived at load, never persisted: a planned entry's wire
     * still says queued. */
    p[2] = (uint8_t)(e->state == VCS_REWARD_STATE_PLANNED
                         ? VCS_REWARD_STATE_QUEUED
                         : e->state);
    p[3] = e->has_evidence_root ? 1u : 0u;
    p += 4;
    reward_put_u32le(p, e->points);
    p += 4;
    memcpy(p, e->release_root, 32);
    p += 32;
    memcpy(p, e->contributor, 33);
    p += 33;
    memcpy(p, e->facts_hash, 32);
    p += 32;
    memcpy(p, e->evidence_root, 32);
    p += 32;
    memcpy(p, e->settled_by_plan, 32);
    p += 32;
    reward_put_i64le(p, e->settled_day);
    p += 8;
    memset(p, 0, VCS_REWARD_RULE_MAX);
    if (e->state == VCS_REWARD_STATE_REJECTED)
        memcpy(p, e->rejected_rule,
               strlen(e->rejected_rule) < VCS_REWARD_RULE_MAX - 1u
                   ? strlen(e->rejected_rule)
                   : VCS_REWARD_RULE_MAX - 1u);
}

static bool reward_queue_wire_decode(const uint8_t *wire, size_t len,
                                     struct vcs_reward_entry *out)
{
    if (len != REWARD_QUEUE_WIRE_BYTES ||
        memcmp(wire, REWARD_QUEUE_MAGIC, 4) != 0)
        return false;
    memset(out, 0, sizeof(*out));
    const uint8_t *p = wire + 4;
    out->kind = (enum vcs_reward_kind)p[0];
    out->category = (enum vcs_reward_category)p[1];
    out->state = (enum vcs_reward_state)p[2];
    out->has_evidence_root = p[3] != 0;
    p += 4;
    if (out->kind != VCS_REWARD_KIND_AUTO &&
        out->kind != VCS_REWARD_KIND_CLAIM)
        return false;
    if (out->category >= VCS_REWARD_CATEGORY_COUNT)
        return false;
    if (out->state != VCS_REWARD_STATE_QUEUED &&
        out->state != VCS_REWARD_STATE_SETTLED &&
        out->state != VCS_REWARD_STATE_REJECTED)
        return false;
    out->points = reward_get_u32le(p);
    p += 4;
    memcpy(out->release_root, p, 32);
    p += 32;
    memcpy(out->contributor, p, 33);
    p += 33;
    memcpy(out->facts_hash, p, 32);
    p += 32;
    memcpy(out->evidence_root, p, 32);
    p += 32;
    memcpy(out->settled_by_plan, p, 32);
    p += 32;
    out->settled_day = reward_get_i64le(p);
    p += 8;
    memcpy(out->rejected_rule, p, VCS_REWARD_RULE_MAX);
    out->rejected_rule[VCS_REWARD_RULE_MAX - 1u] = '\0';
    if (out->state != VCS_REWARD_STATE_REJECTED)
        out->rejected_rule[0] = '\0';
    return true;
}

struct vcs_reward_fact {
    uint8_t entry_id[32];
    uint8_t release_root[32];
    uint8_t contributor[33];
    uint8_t kind;
    uint8_t category;
    uint32_t points; /* settled */
    int64_t day;
    uint8_t facts_hash[32];
    uint8_t plan_id[32];
};

static void reward_fact_wire_encode(const struct vcs_reward_fact *f,
                                    uint8_t out[REWARD_FACT_WIRE_BYTES])
{
    uint8_t *p = out;
    memcpy(p, REWARD_FACT_MAGIC, 4);
    p += 4;
    reward_put_i64le(p, f->day);
    p += 8;
    p[0] = f->kind;
    p[1] = f->category;
    p[2] = 0;
    p[3] = 0;
    p += 4;
    reward_put_u32le(p, f->points);
    p += 4;
    memcpy(p, f->entry_id, 32);
    p += 32;
    memcpy(p, f->release_root, 32);
    p += 32;
    memcpy(p, f->contributor, 33);
    p += 33;
    memcpy(p, f->facts_hash, 32);
    p += 32;
    memcpy(p, f->plan_id, 32);
}

static bool reward_fact_wire_decode(const uint8_t *wire, size_t len,
                                    struct vcs_reward_fact *out)
{
    if (len != REWARD_FACT_WIRE_BYTES ||
        memcmp(wire, REWARD_FACT_MAGIC, 4) != 0)
        return false;
    memset(out, 0, sizeof(*out));
    const uint8_t *p = wire + 4;
    out->day = reward_get_i64le(p);
    p += 8;
    out->kind = p[0];
    out->category = p[1];
    p += 4;
    if (out->kind != VCS_REWARD_KIND_AUTO &&
        out->kind != VCS_REWARD_KIND_CLAIM)
        return false;
    if (out->category >= VCS_REWARD_CATEGORY_COUNT)
        return false;
    out->points = reward_get_u32le(p);
    p += 4;
    memcpy(out->entry_id, p, 32);
    p += 32;
    memcpy(out->release_root, p, 32);
    p += 32;
    memcpy(out->contributor, p, 33);
    p += 33;
    memcpy(out->facts_hash, p, 32);
    p += 32;
    memcpy(out->plan_id, p, 32);
    return true;
}

static size_t reward_plan_wire_bytes(size_t row_count)
{
    return REWARD_PLAN_HEADER_BYTES + row_count * REWARD_PLAN_ROW_BYTES;
}

static bool reward_plan_wire_encode(const struct vcs_reward_plan *plan,
                                    uint8_t *out, size_t *out_len)
{
    if (plan->row_count > VCS_REWARD_MAX_EVAL_ROWS)
        return false;
    uint8_t *p = out;
    memcpy(p, REWARD_PLAN_MAGIC, 4);
    p += 4;
    reward_put_i64le(p, plan->day);
    p += 8;
    reward_put_u32le(p, (uint32_t)plan->row_count);
    p += 4;
    for (size_t i = 0; i < plan->row_count; i++) {
        const struct vcs_reward_plan_row *r = &plan->rows[i];
        memcpy(p, r->entry_id, 32);
        p += 32;
        p[0] = (uint8_t)r->disposition;
        p++;
        memset(p, 0, VCS_REWARD_RULE_MAX);
        memcpy(p, r->rule,
               strlen(r->rule) < VCS_REWARD_RULE_MAX - 1u
                   ? strlen(r->rule)
                   : VCS_REWARD_RULE_MAX - 1u);
        p += VCS_REWARD_RULE_MAX;
        reward_put_u32le(p, r->points_requested);
        p += 4;
        reward_put_u32le(p, r->points_settled);
        p += 4;
        p[0] = r->weekly_cap_clamped ? 1u : 0u;
        p++;
    }
    *out_len = reward_plan_wire_bytes(plan->row_count);
    return true;
}

static bool reward_plan_wire_decode(const uint8_t *wire, size_t len,
                                    struct vcs_reward_plan *out)
{
    memset(out, 0, sizeof(*out));
    if (len < REWARD_PLAN_HEADER_BYTES ||
        memcmp(wire, REWARD_PLAN_MAGIC, 4) != 0)
        return false;
    const uint8_t *p = wire + 4;
    out->day = reward_get_i64le(p);
    p += 8;
    uint32_t row_count = reward_get_u32le(p);
    p += 4;
    if (row_count > VCS_REWARD_MAX_EVAL_ROWS ||
        len != reward_plan_wire_bytes(row_count))
        return false;
    if (row_count > 0) {
        out->rows = zcl_calloc(row_count, sizeof(*out->rows),
                               "reward_plan_rows");
        if (!out->rows) {
            LOG_FAIL(REWARD_LOG, "alloc %u plan rows", row_count);
            return false;
        }
    }
    out->row_count = row_count;
    for (size_t i = 0; i < row_count; i++) {
        struct vcs_reward_plan_row *r = &out->rows[i];
        memcpy(r->entry_id, p, 32);
        p += 32;
        r->disposition = (enum vcs_reward_disposition)p[0];
        p++;
        if (r->disposition > VCS_REWARD_DISP_DUPLICATE) {
            vcs_reward_plan_free(out);
            return false;
        }
        memcpy(r->rule, p, VCS_REWARD_RULE_MAX);
        r->rule[VCS_REWARD_RULE_MAX - 1u] = '\0';
        p += VCS_REWARD_RULE_MAX;
        r->points_requested = reward_get_u32le(p);
        p += 4;
        r->points_settled = reward_get_u32le(p);
        p += 4;
        r->weekly_cap_clamped = p[0] != 0;
        p++;
        switch (r->disposition) {
        case VCS_REWARD_DISP_PLANNED:
            out->planned_count++;
            out->points_total += r->points_settled;
            break;
        case VCS_REWARD_DISP_DEFERRED: out->deferred_count++; break;
        case VCS_REWARD_DISP_BLOCKED: out->blocked_count++; break;
        case VCS_REWARD_DISP_DUPLICATE: out->duplicate_count++; break;
        }
    }
    return true;
}

/* ── the ledger ─────────────────────────────────────────────────────── */

struct vcs_reward_loaded_plan {
    uint8_t id[32];
    int64_t day;
    uint8_t (*refs)[32]; /* PLANNED row entry ids */
    size_t ref_count;
    bool committed;
};

struct vcs_reward_ledger {
    char root[4400]; /* <zcode_dir>/rewards */
    struct vcs_reward_entry *entries; /* ascending entry_id */
    size_t entry_count;
    size_t entry_cap;
    struct vcs_reward_fact *facts;
    size_t fact_count;
    size_t fact_cap;
    struct vcs_reward_loaded_plan *plans; /* ascending id */
    size_t plan_count;
    size_t plan_cap;
    uint8_t (*commits)[32]; /* committed plan ids */
    size_t commit_count;
    size_t commit_cap;
    uint32_t corrupt;
    bool truncated;
};

void vcs_reward_plan_free(struct vcs_reward_plan *plan)
{
    if (!plan)
        return;
    free(plan->rows);
    plan->rows = NULL;
    plan->row_count = 0;
}

void vcs_reward_receipt_free(struct vcs_reward_receipt *receipt)
{
    if (!receipt)
        return;
    free(receipt->rows);
    receipt->rows = NULL;
    receipt->row_count = 0;
}

static int reward_id_cmp(const uint8_t a[32], const uint8_t b[32])
{
    return memcmp(a, b, 32);
}

/* Insertion position for `id` in the sorted entry array; *found set when
 * an exact match exists. */
static size_t reward_entry_lower_bound(const struct vcs_reward_ledger *l,
                                       const uint8_t id[32], bool *found)
{
    size_t lo = 0, hi = l->entry_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2u;
        int cmp = reward_id_cmp(l->entries[mid].entry_id, id);
        if (cmp == 0) {
            *found = true;
            return mid;
        }
        if (cmp < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    *found = false;
    return lo;
}

/* Insert (or return the existing) entry with the given id. NULL on
 * allocation failure (logged). On an existing id the existing entry is
 * returned and *inserted_out is false. */
static struct vcs_reward_entry *reward_entry_slot(
    struct vcs_reward_ledger *l, const uint8_t id[32], bool *inserted_out)
{
    bool found = false;
    size_t at = reward_entry_lower_bound(l, id, &found);
    if (found) {
        *inserted_out = false;
        return &l->entries[at];
    }
    if (l->entry_count == l->entry_cap) {
        size_t cap = l->entry_cap ? l->entry_cap * 2u : 32u;
        struct vcs_reward_entry *entries = zcl_realloc(
            l->entries, cap * sizeof(*entries), "reward_entries");
        if (!entries)
            LOG_NULL(REWARD_LOG, "grow entries to %zu", cap);
        l->entries = entries;
        l->entry_cap = cap;
    }
    memmove(&l->entries[at + 1], &l->entries[at],
            (l->entry_count - at) * sizeof(*l->entries));
    memset(&l->entries[at], 0, sizeof(l->entries[at]));
    l->entry_count++;
    *inserted_out = true;
    return &l->entries[at];
}

static struct vcs_reward_fact *reward_fact_slot(struct vcs_reward_ledger *l)
{
    if (l->fact_count == l->fact_cap) {
        size_t cap = l->fact_cap ? l->fact_cap * 2u : 32u;
        struct vcs_reward_fact *facts =
            zcl_realloc(l->facts, cap * sizeof(*facts), "reward_facts");
        if (!facts)
            LOG_NULL(REWARD_LOG, "grow facts to %zu", cap);
        l->facts = facts;
        l->fact_cap = cap;
    }
    memset(&l->facts[l->fact_count], 0, sizeof(l->facts[l->fact_count]));
    return &l->facts[l->fact_count++];
}

static bool reward_commit_known(const struct vcs_reward_ledger *l,
                                const uint8_t plan_id[32])
{
    for (size_t i = 0; i < l->commit_count; i++)
        if (reward_id_cmp(l->commits[i], plan_id) == 0)
            return true;
    return false;
}

static bool reward_commit_register(struct vcs_reward_ledger *l,
                                   const uint8_t plan_id[32])
{
    if (reward_commit_known(l, plan_id))
        return true;
    if (l->commit_count == l->commit_cap) {
        size_t cap = l->commit_cap ? l->commit_cap * 2u : 16u;
        uint8_t(*commits)[32] =
            zcl_realloc(l->commits, cap * sizeof(*commits),
                        "reward_commits");
        if (!commits) {
            LOG_FAIL(REWARD_LOG, "grow commits to %zu", cap);
            return false;
        }
        l->commits = commits;
        l->commit_cap = cap;
    }
    memcpy(l->commits[l->commit_count++], plan_id, 32);
    return true;
}

/* Register a plan (sorted by id). Existing id → existing slot. */
static struct vcs_reward_loaded_plan *reward_plan_slot(
    struct vcs_reward_ledger *l, const uint8_t id[32], bool *inserted_out)
{
    size_t lo = 0, hi = l->plan_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2u;
        int cmp = reward_id_cmp(l->plans[mid].id, id);
        if (cmp == 0) {
            *inserted_out = false;
            return &l->plans[mid];
        }
        if (cmp < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (l->plan_count == l->plan_cap) {
        size_t cap = l->plan_cap ? l->plan_cap * 2u : 16u;
        struct vcs_reward_loaded_plan *plans = zcl_realloc(
            l->plans, cap * sizeof(*plans), "reward_plans");
        if (!plans)
            LOG_NULL(REWARD_LOG, "grow plans to %zu", cap);
        l->plans = plans;
        l->plan_cap = cap;
    }
    memmove(&l->plans[lo + 1], &l->plans[lo],
            (l->plan_count - lo) * sizeof(*l->plans));
    memset(&l->plans[lo], 0, sizeof(l->plans[lo]));
    l->plan_count++;
    *inserted_out = true;
    return &l->plans[lo];
}

/* ── load / replay ──────────────────────────────────────────────────── */

/* Scan one directory of hex64-named wires; parse with `decode` (queue or
 * fact). Verified: the file name must equal the content-derived id. */
static void reward_load_queue_dir(struct vcs_reward_ledger *l,
                                  const char *dir)
{
    DIR *d = opendir(dir);
    if (!d)
        return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (!reward_name_is_hex64(ent->d_name))
            continue;
        if (l->entry_count >= VCS_REWARD_MAX_QUEUE_ENTRIES) {
            l->truncated = true;
            break;
        }
        char path[4400];
        int n = snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        if (n <= 0 || (size_t)n >= sizeof(path))
            continue;
        size_t wire_len = 0;
        uint8_t *wire = reward_read_file(path, VCS_REWARD_MAX_QUEUE_WIRE_BYTES,
                                         &wire_len);
        if (!wire) {
            l->corrupt++;
            continue;
        }
        struct vcs_reward_entry e;
        bool ok = reward_queue_wire_decode(wire, wire_len, &e);
        free(wire);
        if (!ok) {
            l->corrupt++;
            continue;
        }
        reward_entry_id(&e, e.entry_id);
        char id_hex[65];
        zcl_hex_encode(e.entry_id, 32, id_hex);
        if (strcmp(id_hex, ent->d_name) != 0) {
            /* The name must commit the content (rehash-on-read). */
            LOG_ERROR(REWARD_LOG, "queue wire %s commits a different id",
                      ent->d_name);
            l->corrupt++;
            continue;
        }
        bool inserted = false;
        struct vcs_reward_entry *slot =
            reward_entry_slot(l, e.entry_id, &inserted);
        if (!slot) {
            l->corrupt++;
            continue;
        }
        if (inserted)
            *slot = e;
    }
    closedir(d);
}

static void reward_load_fact_dir(struct vcs_reward_ledger *l, const char *dir)
{
    DIR *d = opendir(dir);
    if (!d)
        return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (!reward_name_is_hex64(ent->d_name))
            continue;
        if (l->fact_count >= VCS_REWARD_MAX_FACTS) {
            l->truncated = true;
            break;
        }
        char path[4400];
        int n = snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        if (n <= 0 || (size_t)n >= sizeof(path))
            continue;
        size_t wire_len = 0;
        uint8_t *wire = reward_read_file(path, VCS_REWARD_MAX_FACT_WIRE_BYTES,
                                         &wire_len);
        if (!wire) {
            l->corrupt++;
            continue;
        }
        struct vcs_reward_fact f;
        bool ok = reward_fact_wire_decode(wire, wire_len, &f);
        free(wire);
        if (!ok) {
            l->corrupt++;
            continue;
        }
        char id_hex[65];
        zcl_hex_encode(f.entry_id, 32, id_hex);
        if (strcmp(id_hex, ent->d_name) != 0) {
            LOG_ERROR(REWARD_LOG, "fact wire %s names a different entry",
                      ent->d_name);
            l->corrupt++;
            continue;
        }
        /* Dedup by entry id (a re-driven settle is a no-op). */
        bool dup = false;
        for (size_t i = 0; i < l->fact_count; i++)
            if (reward_id_cmp(l->facts[i].entry_id, f.entry_id) == 0) {
                dup = true;
                break;
            }
        if (dup)
            continue;
        if (!reward_fact_slot(l)) {
            l->corrupt++;
            continue;
        }
        l->facts[l->fact_count - 1] = f;
    }
    closedir(d);
}

static void reward_load_plan_dir(struct vcs_reward_ledger *l, const char *dir)
{
    DIR *d = opendir(dir);
    if (!d)
        return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (!reward_name_is_hex64(ent->d_name))
            continue;
        if (l->plan_count >= VCS_REWARD_MAX_PLANS) {
            l->truncated = true;
            break;
        }
        char path[4400];
        int n = snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        if (n <= 0 || (size_t)n >= sizeof(path))
            continue;
        size_t wire_len = 0;
        uint8_t *wire = reward_read_file(path, VCS_REWARD_MAX_PLAN_WIRE_BYTES,
                                         &wire_len);
        if (!wire) {
            l->corrupt++;
            continue;
        }
        struct vcs_reward_plan plan;
        bool ok = reward_plan_wire_decode(wire, wire_len, &plan);
        free(wire);
        if (!ok) {
            l->corrupt++;
            continue;
        }
        reward_plan_id(plan.day, plan.rows, plan.row_count, plan.plan_id);
        char id_hex[65];
        zcl_hex_encode(plan.plan_id, 32, id_hex);
        if (strcmp(id_hex, ent->d_name) != 0) {
            LOG_ERROR(REWARD_LOG, "plan wire %s commits a different id",
                      ent->d_name);
            l->corrupt++;
            vcs_reward_plan_free(&plan);
            continue;
        }
        bool inserted = false;
        struct vcs_reward_loaded_plan *lp =
            reward_plan_slot(l, plan.plan_id, &inserted);
        if (!lp) {
            l->corrupt++;
            vcs_reward_plan_free(&plan);
            continue;
        }
        if (inserted) {
            lp->day = plan.day;
            memcpy(lp->id, plan.plan_id, 32);
            if (plan.planned_count > 0) {
                lp->refs = zcl_calloc(plan.planned_count, sizeof(*lp->refs),
                                      "reward_plan_refs");
                if (!lp->refs) {
                    LOG_ERROR(REWARD_LOG, "alloc %u plan refs",
                              plan.planned_count);
                    l->corrupt++;
                    vcs_reward_plan_free(&plan);
                    continue;
                }
            }
            for (size_t i = 0; i < plan.row_count; i++)
                if (plan.rows[i].disposition == VCS_REWARD_DISP_PLANNED)
                    memcpy(lp->refs[lp->ref_count++], plan.rows[i].entry_id,
                           32);
        }
        vcs_reward_plan_free(&plan);
    }
    closedir(d);
}

static void reward_load_commit_dir(struct vcs_reward_ledger *l,
                                   const char *dir)
{
    DIR *d = opendir(dir);
    if (!d)
        return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        uint8_t id[32];
        if (!zcl_hex_decode_lower(ent->d_name, id, 32))
            continue;
        if (l->commit_count >= VCS_REWARD_MAX_COMMITS) {
            l->truncated = true;
            break;
        }
        /* A commit record that does not parse is NOT treated as settled:
         * the safe direction is to allow a resumable re-commit. */
        char path[4400];
        int n = snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        if (n <= 0 || (size_t)n >= sizeof(path))
            continue;
        size_t wire_len = 0;
        uint8_t *wire = reward_read_file(path,
                                         VCS_REWARD_MAX_COMMIT_WIRE_BYTES,
                                         &wire_len);
        if (!wire) {
            l->corrupt++;
            continue;
        }
        bool ok = wire_len >= REWARD_COMMIT_HEADER_BYTES &&
                  memcmp(wire, REWARD_COMMIT_MAGIC, 4) == 0;
        if (ok) {
            uint32_t rows = reward_get_u32le(wire + 4 + 8 + 32);
            ok = rows <= VCS_REWARD_MAX_BATCH_ENTRIES &&
                 wire_len == REWARD_COMMIT_HEADER_BYTES +
                                 (size_t)rows * REWARD_COMMIT_ROW_BYTES &&
                 memcmp(wire + 4 + 8, id, 32) == 0;
        }
        free(wire);
        if (!ok) {
            LOG_ERROR(REWARD_LOG, "commit record %s does not parse",
                      ent->d_name);
            l->corrupt++;
            continue;
        }
        if (!reward_commit_register(l, id))
            l->corrupt++;
    }
    closedir(d);
}

struct vcs_reward_ledger *vcs_reward_ledger_load(const char *zcode_dir)
{
    struct vcs_reward_ledger *l = zcl_calloc(1, sizeof(*l), "reward_ledger");
    if (!l) {
        LOG_ERROR(REWARD_LOG, "alloc ledger");
        return NULL;
    }
    int n = snprintf(l->root, sizeof(l->root), "%s/rewards",
                     zcode_dir ? zcode_dir : "");
    if (n <= 0 || (size_t)n >= sizeof(l->root)) {
        LOG_ERROR(REWARD_LOG, "rewards path too long for %s",
                  zcode_dir ? zcode_dir : "(null)");
        free(l);
        return NULL;
    }
    char dir[4400];
    if (!reward_child_path(dir, sizeof(dir), l->root, "queue")) goto bad_path;
    reward_load_queue_dir(l, dir);
    if (!reward_child_path(dir, sizeof(dir), l->root, "ledger")) goto bad_path;
    reward_load_fact_dir(l, dir);
    if (!reward_child_path(dir, sizeof(dir), l->root, "commits")) goto bad_path;
    reward_load_commit_dir(l, dir);
    if (!reward_child_path(dir, sizeof(dir), l->root, "plans")) goto bad_path;
    reward_load_plan_dir(l, dir);

    /* Mark committed plans and derive PLANNED entry states: an entry
     * named by an uncommitted plan reports planned (earliest plan id
     * wins; plans are sorted ascending). */
    for (size_t i = 0; i < l->plan_count; i++) {
        struct vcs_reward_loaded_plan *lp = &l->plans[i];
        lp->committed = reward_commit_known(l, lp->id);
        if (lp->committed)
            continue;
        for (size_t r = 0; r < lp->ref_count; r++) {
            bool found = false;
            size_t at = reward_entry_lower_bound(l, lp->refs[r], &found);
            if (found && l->entries[at].state == VCS_REWARD_STATE_QUEUED) {
                l->entries[at].state = VCS_REWARD_STATE_PLANNED;
                memcpy(l->entries[at].planned_by, lp->id, 32);
            }
        }
    }
    return l;
bad_path:
    vcs_reward_ledger_free(l);
    return NULL;
}

void vcs_reward_ledger_free(struct vcs_reward_ledger *l)
{
    if (!l)
        return;
    for (size_t i = 0; i < l->plan_count; i++)
        free(l->plans[i].refs);
    free(l->plans);
    free(l->commits);
    free(l->facts);
    free(l->entries);
    free(l);
}

size_t vcs_reward_ledger_entry_count(const struct vcs_reward_ledger *l)
{
    return l ? l->entry_count : 0;
}

size_t vcs_reward_ledger_fact_count(const struct vcs_reward_ledger *l)
{
    return l ? l->fact_count : 0;
}

uint32_t vcs_reward_ledger_corrupt_count(const struct vcs_reward_ledger *l)
{
    return l ? l->corrupt : 0;
}

bool vcs_reward_ledger_truncated(const struct vcs_reward_ledger *l)
{
    return l ? l->truncated : true;
}

const struct vcs_reward_entry *vcs_reward_ledger_entry_at(
    const struct vcs_reward_ledger *l, size_t index)
{
    if (!l || index >= l->entry_count)
        return NULL;
    return &l->entries[index];
}

bool vcs_reward_ledger_fact_at(const struct vcs_reward_ledger *l,
                               size_t index,
                               struct vcs_reward_fact_view *out)
{
    if (!l || !out)
        LOG_FAIL(REWARD_LOG, "fact_at: NULL %s", !l ? "ledger" : "out");
    if (index >= l->fact_count)
        LOG_FAIL(REWARD_LOG, "fact_at: index %zu of %zu", index,
                 l->fact_count);
    const struct vcs_reward_fact *f = &l->facts[index];
    memset(out, 0, sizeof(*out));
    memcpy(out->entry_id, f->entry_id, 32);
    memcpy(out->release_root, f->release_root, 32);
    memcpy(out->contributor, f->contributor, 33);
    out->kind = (enum vcs_reward_kind)f->kind;
    out->category = (enum vcs_reward_category)f->category;
    out->points = f->points;
    out->day = f->day;
    memcpy(out->facts_hash, f->facts_hash, 32);
    memcpy(out->plan_id, f->plan_id, 32);
    return true;
}

const struct vcs_reward_entry *vcs_reward_ledger_find(
    const struct vcs_reward_ledger *l, const uint8_t entry_id[32])
{
    if (!l)
        return NULL;
    bool found = false;
    size_t at = reward_entry_lower_bound(l, entry_id, &found);
    return found ? &l->entries[at] : NULL;
}

void vcs_reward_queue_tally(const struct vcs_reward_ledger *l,
                            struct vcs_reward_queue_tally *out)
{
    memset(out, 0, sizeof(*out));
    if (!l)
        return;
    for (size_t i = 0; i < l->entry_count; i++) {
        switch (l->entries[i].state) {
        case VCS_REWARD_STATE_QUEUED: out->queued++; break;
        case VCS_REWARD_STATE_PLANNED: out->planned++; break;
        case VCS_REWARD_STATE_SETTLED: out->settled++; break;
        case VCS_REWARD_STATE_REJECTED: out->rejected++; break;
        }
    }
}

/* ── enqueue ────────────────────────────────────────────────────────── */

static bool reward_is_zero(const uint8_t *bytes, size_t len)
{
    for (size_t i = 0; i < len; i++)
        if (bytes[i] != 0)
            return false;
    return true;
}

/* Persist one queue record and insert it into the in-memory ledger. */
static enum vcs_reward_enqueue_error reward_enqueue_finish(
    struct vcs_reward_ledger *l, struct vcs_reward_entry *e,
    uint8_t entry_id_out[32])
{
    reward_entry_id(e, e->entry_id);
    if (entry_id_out)
        memcpy(entry_id_out, e->entry_id, 32);
    bool found = false;
    (void)reward_entry_lower_bound(l, e->entry_id, &found);
    if (found)
        return VCS_REWARD_ENQUEUE_DUPLICATE;
    if (l->entry_count >= VCS_REWARD_MAX_QUEUE_ENTRIES)
        return VCS_REWARD_ENQUEUE_FULL;

    char dir[4400];
    if (!reward_child_path(dir, sizeof(dir), l->root, "queue"))
        return VCS_REWARD_ENQUEUE_IO;
    if (!reward_mkdir_p(dir)) {
        LOG_ERROR(REWARD_LOG, "mkdir %s: %s", dir, strerror(errno));
        return VCS_REWARD_ENQUEUE_IO;
    }
    char id_hex[65];
    zcl_hex_encode(e->entry_id, 32, id_hex);
    char path[4400];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, id_hex);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        LOG_ERROR(REWARD_LOG, "queue path too long");
        return VCS_REWARD_ENQUEUE_IO;
    }
    uint8_t wire[REWARD_QUEUE_WIRE_BYTES];
    reward_queue_wire_encode(e, wire);
    if (!reward_atomic_write(path, wire, sizeof(wire)))
        return VCS_REWARD_ENQUEUE_IO;

    bool inserted = false;
    struct vcs_reward_entry *slot =
        reward_entry_slot(l, e->entry_id, &inserted);
    if (!slot)
        return VCS_REWARD_ENQUEUE_IO;
    if (inserted)
        *slot = *e;
    return VCS_REWARD_ENQUEUE_OK;
}

enum vcs_reward_enqueue_error vcs_reward_enqueue_auto(
    struct vcs_reward_ledger *l, const uint8_t release_root[32],
    const uint8_t contributor[33], enum vcs_reward_category category,
    uint32_t points, const uint8_t facts_hash[32],
    uint8_t entry_id_out[32])
{
    if (!l || !release_root || !contributor || !facts_hash ||
        reward_is_zero(release_root, 32) || reward_is_zero(contributor, 33))
        return VCS_REWARD_ENQUEUE_BAD_INPUT;
    if (category >= VCS_REWARD_CATEGORY_COUNT)
        return VCS_REWARD_ENQUEUE_BAD_CATEGORY;
    uint32_t band_min = 0, band_max = 0;
    bool automatic = false;
    vcs_reward_category_band(category, &band_min, &band_max, &automatic);
    if (!automatic)
        return VCS_REWARD_ENQUEUE_BAD_CATEGORY;
    if (points == 0)
        return VCS_REWARD_ENQUEUE_ZERO_POINTS;
    /* Auto points are the slice-7 score total; the band constants bound
     * the category BASE, so the honest bound here is the frozen
     * per-release total cap. */
    if (points > VCS_SCORE_MAX_TOTAL_PER_RELEASE) {
        LOG_ERROR(REWARD_LOG, "auto points %u over the release cap", points);
        return VCS_REWARD_ENQUEUE_BAND;
    }
    if (reward_is_zero(facts_hash, 32))
        return VCS_REWARD_ENQUEUE_BAD_INPUT;

    struct vcs_reward_entry e;
    memset(&e, 0, sizeof(e));
    e.kind = VCS_REWARD_KIND_AUTO;
    e.category = category;
    memcpy(e.release_root, release_root, 32);
    memcpy(e.contributor, contributor, 33);
    e.points = points;
    memcpy(e.facts_hash, facts_hash, 32);
    e.state = VCS_REWARD_STATE_QUEUED;
    return reward_enqueue_finish(l, &e, entry_id_out);
}

enum vcs_reward_enqueue_error vcs_reward_enqueue_claim(
    struct vcs_reward_ledger *l, const uint8_t release_root[32],
    const uint8_t contributor[33], enum vcs_reward_category category,
    uint32_t points, const uint8_t evidence_root[32],
    uint8_t entry_id_out[32])
{
    if (!l || !release_root || !contributor || !evidence_root ||
        reward_is_zero(release_root, 32) || reward_is_zero(contributor, 33))
        return VCS_REWARD_ENQUEUE_BAD_INPUT;
    if (category >= VCS_REWARD_CATEGORY_COUNT)
        return VCS_REWARD_ENQUEUE_BAD_CATEGORY;
    uint32_t band_min = 0, band_max = 0;
    bool automatic = false;
    vcs_reward_category_band(category, &band_min, &band_max, &automatic);
    if (automatic)
        return VCS_REWARD_ENQUEUE_BAD_CATEGORY;
    if (reward_is_zero(evidence_root, 32))
        return VCS_REWARD_ENQUEUE_EVIDENCE;
    if (points == 0)
        return VCS_REWARD_ENQUEUE_ZERO_POINTS;
    if (points < band_min || points > band_max)
        return VCS_REWARD_ENQUEUE_BAND;

    struct vcs_reward_entry e;
    memset(&e, 0, sizeof(e));
    e.kind = VCS_REWARD_KIND_CLAIM;
    e.category = category;
    memcpy(e.release_root, release_root, 32);
    memcpy(e.contributor, contributor, 33);
    e.points = points;
    e.has_evidence_root = true;
    memcpy(e.evidence_root, evidence_root, 32);
    reward_claim_facts_hash(category, points, evidence_root, e.facts_hash);
    e.state = VCS_REWARD_STATE_QUEUED;
    return reward_enqueue_finish(l, &e, entry_id_out);
}

/* ── caps history ───────────────────────────────────────────────────── */

/* Gather the contributor's settled-fact history (optionally excluding one
 * plan's facts) into period entries. Returns the count. */
static size_t reward_history_for(const struct vcs_reward_ledger *l,
                                 const uint8_t contributor[33],
                                 const uint8_t exclude_plan[32],
                                 struct vcs_score_period_entry *out,
                                 size_t cap)
{
    size_t n = 0;
    for (size_t i = 0; i < l->fact_count && n < cap; i++) {
        const struct vcs_reward_fact *f = &l->facts[i];
        if (memcmp(f->contributor, contributor, 33) != 0)
            continue;
        if (exclude_plan && reward_id_cmp(f->plan_id, exclude_plan) == 0)
            continue;
        out[n].day = f->day;
        out[n].score = f->points;
        n++;
    }
    return n;
}

/* The ledger already settled (release, contributor, category)? */
static bool reward_fact_duplicate(const struct vcs_reward_ledger *l,
                                  const uint8_t release_root[32],
                                  const uint8_t contributor[33],
                                  enum vcs_reward_category category,
                                  const uint8_t exclude_plan[32])
{
    for (size_t i = 0; i < l->fact_count; i++) {
        const struct vcs_reward_fact *f = &l->facts[i];
        if (exclude_plan && reward_id_cmp(f->plan_id, exclude_plan) == 0)
            continue;
        if (f->category == (uint8_t)category &&
            memcmp(f->release_root, release_root, 32) == 0 &&
            memcmp(f->contributor, contributor, 33) == 0)
            return true;
    }
    return false;
}

static const struct vcs_reward_fact *reward_fact_find(
    const struct vcs_reward_ledger *l, const uint8_t entry_id[32])
{
    for (size_t i = 0; i < l->fact_count; i++)
        if (reward_id_cmp(l->facts[i].entry_id, entry_id) == 0)
            return &l->facts[i];
    return NULL;
}

/* ── plan ───────────────────────────────────────────────────────────── */

/* Evaluate one entry for a window: fills the row's disposition/rule/
 * settled points. `batch_rows`/`batch_count` are the PLANNED rows already
 * accepted into this window (they count against the caps batch-atomically).
 * `planned_so_far` enforces the batch bound. */
static void reward_plan_eval_entry(const struct vcs_reward_ledger *l,
                                   const struct vcs_reward_entry *e,
                                   int64_t day,
                                   const struct vcs_reward_plan_row *batch_rows,
                                   size_t batch_count,
                                   uint32_t planned_so_far,
                                   struct vcs_reward_plan_row *row)
{
    memcpy(row->entry_id, e->entry_id, 32);
    row->points_requested = e->points;
    row->points_settled = 0;

    if (e->kind == VCS_REWARD_KIND_CLAIM) {
        row->disposition = VCS_REWARD_DISP_BLOCKED;
        snprintf(row->rule, sizeof(row->rule), "%s",
                 VCS_REWARD_RULE_OWNER_REVIEW);
        return;
    }
    if (reward_fact_duplicate(l, e->release_root, e->contributor,
                              e->category, NULL)) {
        row->disposition = VCS_REWARD_DISP_DUPLICATE;
        snprintf(row->rule, sizeof(row->rule), "%s",
                 VCS_REWARD_RULE_DUPLICATE);
        return;
    }

    /* History = settled facts + this window's earlier planned rows for
     * the same contributor. The same walk catches a within-batch double
     * reward: an earlier planned row already claims this exact
     * (release, contributor, category). */
    struct vcs_score_period_entry history[VCS_REWARD_MAX_FACTS +
                                          VCS_REWARD_MAX_BATCH_ENTRIES];
    size_t hcount = reward_history_for(l, e->contributor, NULL, history,
                                       VCS_REWARD_MAX_FACTS);
    bool batch_dup = false;
    for (size_t i = 0; i < batch_count; i++) {
        const struct vcs_reward_entry *prior =
            vcs_reward_ledger_find(l, batch_rows[i].entry_id);
        if (!prior)
            continue;
        if (prior->category == e->category &&
            memcmp(prior->release_root, e->release_root, 32) == 0 &&
            memcmp(prior->contributor, e->contributor, 33) == 0)
            batch_dup = true;
        if (memcmp(prior->contributor, e->contributor, 33) == 0 &&
            hcount < sizeof(history) / sizeof(history[0])) {
            history[hcount].day = day;
            history[hcount].score = batch_rows[i].points_settled;
            hcount++;
        }
    }
    if (batch_dup) {
        row->disposition = VCS_REWARD_DISP_DUPLICATE;
        snprintf(row->rule, sizeof(row->rule), "%s",
                 VCS_REWARD_RULE_DUPLICATE);
        return;
    }
    struct vcs_score_period_caps caps;
    vcs_score_apply_period_caps(history, hcount, day, e->points, &caps);

    if (caps.daily_release_cap_hit) {
        row->disposition = VCS_REWARD_DISP_DEFERRED;
        snprintf(row->rule, sizeof(row->rule), "%s",
                 VCS_REWARD_RULE_DAILY_CAP);
        return;
    }
    if (caps.allowed_score == 0) {
        row->disposition = VCS_REWARD_DISP_DEFERRED;
        snprintf(row->rule, sizeof(row->rule), "%s",
                 VCS_REWARD_RULE_WEEKLY_CAP);
        return;
    }
    if (planned_so_far >= VCS_REWARD_MAX_BATCH_ENTRIES) {
        row->disposition = VCS_REWARD_DISP_DEFERRED;
        snprintf(row->rule, sizeof(row->rule), "%s",
                 VCS_REWARD_RULE_BATCH_FULL);
        return;
    }
    row->disposition = VCS_REWARD_DISP_PLANNED;
    row->points_settled = caps.allowed_score;
    row->weekly_cap_clamped = caps.allowed_score < e->points;
}

bool vcs_reward_plan_build(const struct vcs_reward_ledger *l, int64_t day,
                           struct vcs_reward_plan *out)
{
    memset(out, 0, sizeof(*out));
    if (!l) {
        LOG_FAIL(REWARD_LOG, "null ledger in plan_build");
        return false;
    }
    if (day < 0) {
        LOG_FAIL(REWARD_LOG, "negative window day %lld", (long long)day);
        return false;
    }
    out->day = day;

    size_t candidates = 0;
    for (size_t i = 0; i < l->entry_count; i++) {
        enum vcs_reward_state s = l->entries[i].state;
        if (s == VCS_REWARD_STATE_QUEUED || s == VCS_REWARD_STATE_PLANNED)
            candidates++;
    }
    if (candidates == 0) {
        reward_plan_id(day, NULL, 0, out->plan_id);
        return true;
    }
    if (candidates > VCS_REWARD_MAX_EVAL_ROWS)
        candidates = VCS_REWARD_MAX_EVAL_ROWS;
    out->rows = zcl_calloc(candidates, sizeof(*out->rows),
                           "reward_plan_build_rows");
    if (!out->rows) {
        LOG_FAIL(REWARD_LOG, "alloc %zu plan rows", candidates);
        return false;
    }

    /* Accepted PLANNED rows so far (a prefix of out->rows filtered by
     * disposition; tracked compactly for the batch-atomic caps). */
    struct vcs_reward_plan_row *batch = zcl_calloc(
        candidates, sizeof(*batch), "reward_plan_batch");
    if (!batch) {
        LOG_FAIL(REWARD_LOG, "alloc batch scratch");
        vcs_reward_plan_free(out);
        return false;
    }
    size_t batch_count = 0;
    for (size_t i = 0; i < l->entry_count &&
                        out->row_count < candidates; i++) {
        const struct vcs_reward_entry *e = &l->entries[i];
        if (e->state != VCS_REWARD_STATE_QUEUED &&
            e->state != VCS_REWARD_STATE_PLANNED)
            continue;
        struct vcs_reward_plan_row *row = &out->rows[out->row_count++];
        reward_plan_eval_entry(l, e, day, batch, batch_count,
                               out->planned_count, row);
        switch (row->disposition) {
        case VCS_REWARD_DISP_PLANNED:
            out->planned_count++;
            out->points_total += row->points_settled;
            batch[batch_count++] = *row;
            break;
        case VCS_REWARD_DISP_DEFERRED: out->deferred_count++; break;
        case VCS_REWARD_DISP_BLOCKED: out->blocked_count++; break;
        case VCS_REWARD_DISP_DUPLICATE: out->duplicate_count++; break;
        }
    }
    free(batch);
    reward_plan_id(day, out->rows, out->row_count, out->plan_id);
    return true;
}

enum vcs_reward_plan_persist_error vcs_reward_plan_persist(
    struct vcs_reward_ledger *l, const struct vcs_reward_plan *plan)
{
    if (!l || !plan)
        return VCS_REWARD_PLAN_PERSIST_IO;

    char dir[4400];
    if (!reward_child_path(dir, sizeof(dir), l->root, "plans"))
        return VCS_REWARD_PLAN_PERSIST_IO;
    if (!reward_mkdir_p(dir)) {
        LOG_ERROR(REWARD_LOG, "mkdir %s: %s", dir, strerror(errno));
        return VCS_REWARD_PLAN_PERSIST_IO;
    }
    char id_hex[65];
    zcl_hex_encode(plan->plan_id, 32, id_hex);
    char path[4400];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, id_hex);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        LOG_ERROR(REWARD_LOG, "plan path too long");
        return VCS_REWARD_PLAN_PERSIST_IO;
    }
    if (reward_file_exists(path))
        return VCS_REWARD_PLAN_PERSIST_DUPLICATE;
    if (l->plan_count >= VCS_REWARD_MAX_PLANS)
        return VCS_REWARD_PLAN_PERSIST_FULL;

    size_t wire_len = reward_plan_wire_bytes(plan->row_count);
    uint8_t *wire = zcl_malloc(wire_len, "reward_plan_wire");
    if (!wire) {
        LOG_ERROR(REWARD_LOG, "alloc %zu plan wire", wire_len);
        return VCS_REWARD_PLAN_PERSIST_IO;
    }
    size_t encoded = 0;
    if (!reward_plan_wire_encode(plan, wire, &encoded) ||
        encoded != wire_len ||
        !reward_atomic_write(path, wire, wire_len)) {
        free(wire);
        return VCS_REWARD_PLAN_PERSIST_IO;
    }
    free(wire);

    /* Register in memory and derive PLANNED states. */
    bool inserted = false;
    struct vcs_reward_loaded_plan *lp =
        reward_plan_slot(l, plan->plan_id, &inserted);
    if (!lp)
        return VCS_REWARD_PLAN_PERSIST_IO;
    if (inserted) {
        lp->day = plan->day;
        memcpy(lp->id, plan->plan_id, 32);
        if (plan->planned_count > 0) {
            lp->refs = zcl_calloc(plan->planned_count, sizeof(*lp->refs),
                                  "reward_plan_refs");
            if (!lp->refs) {
                LOG_ERROR(REWARD_LOG, "alloc %u plan refs",
                          plan->planned_count);
                return VCS_REWARD_PLAN_PERSIST_IO;
            }
        }
        for (size_t i = 0; i < plan->row_count; i++)
            if (plan->rows[i].disposition == VCS_REWARD_DISP_PLANNED)
                memcpy(lp->refs[lp->ref_count++], plan->rows[i].entry_id,
                       32);
    }
    for (size_t r = 0; r < lp->ref_count; r++) {
        bool found = false;
        size_t at = reward_entry_lower_bound(l, lp->refs[r], &found);
        if (found && l->entries[at].state == VCS_REWARD_STATE_QUEUED) {
            l->entries[at].state = VCS_REWARD_STATE_PLANNED;
            memcpy(l->entries[at].planned_by, lp->id, 32);
        }
    }
    return VCS_REWARD_PLAN_PERSIST_OK;
}

/* ── commit ─────────────────────────────────────────────────────────── */

/* Load a plan wire fresh from disk (the file is the plan truth). NULL
 * when missing; NULL + *corrupt_out when present but unreadable. */
static struct vcs_reward_plan *reward_plan_read(
    const struct vcs_reward_ledger *l, const uint8_t plan_id[32],
    bool *corrupt_out)
{
    *corrupt_out = false;
    char id_hex[65];
    zcl_hex_encode(plan_id, 32, id_hex);
    char path[4400];
    int n = snprintf(path, sizeof(path), "%s/plans/%s", l->root, id_hex);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        *corrupt_out = true;
        return NULL;
    }
    size_t wire_len = 0;
    uint8_t *wire =
        reward_read_file(path, VCS_REWARD_MAX_PLAN_WIRE_BYTES, &wire_len);
    if (!wire)
        return NULL;
    struct vcs_reward_plan *plan = zcl_calloc(1, sizeof(*plan), "reward_plan");
    if (!plan) {
        free(wire);
        *corrupt_out = true;
        LOG_NULL(REWARD_LOG, "alloc plan");
    }
    if (!reward_plan_wire_decode(wire, wire_len, plan)) {
        free(wire);
        free(plan);
        *corrupt_out = true;
        return NULL;
    }
    free(wire);
    reward_plan_id(plan->day, plan->rows, plan->row_count, plan->plan_id);
    if (reward_id_cmp(plan->plan_id, plan_id) != 0) {
        LOG_ERROR(REWARD_LOG, "plan wire %s commits a different id", id_hex);
        vcs_reward_plan_free(plan);
        free(plan);
        *corrupt_out = true;
        return NULL;
    }
    return plan;
}

/* Rewrite one queue record in place (state transition). */
static bool reward_entry_rewrite(const struct vcs_reward_ledger *l,
                                 const struct vcs_reward_entry *e)
{
    char id_hex[65];
    zcl_hex_encode(e->entry_id, 32, id_hex);
    char path[4400];
    int n = snprintf(path, sizeof(path), "%s/queue/%s", l->root, id_hex);
    if (n <= 0 || (size_t)n >= sizeof(path))
        LOG_FAIL(REWARD_LOG, "queue path too long");
    uint8_t wire[REWARD_QUEUE_WIRE_BYTES];
    reward_queue_wire_encode(e, wire);
    return reward_atomic_write(path, wire, sizeof(wire));
}

static bool reward_fact_write(const struct vcs_reward_ledger *l,
                              const struct vcs_reward_fact *f)
{
    char dir[4400];
    if (!reward_child_path(dir, sizeof(dir), l->root, "ledger"))
        LOG_FAIL(REWARD_LOG, "ledger path too long");
    if (!reward_mkdir_p(dir))
        LOG_FAIL(REWARD_LOG, "mkdir %s: %s", dir, strerror(errno));
    char id_hex[65];
    zcl_hex_encode(f->entry_id, 32, id_hex);
    char path[4400];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, id_hex);
    if (n <= 0 || (size_t)n >= sizeof(path))
        LOG_FAIL(REWARD_LOG, "fact path too long");
    if (reward_file_exists(path))
        return true; /* dedup: the identical fact is already durable */
    uint8_t wire[REWARD_FACT_WIRE_BYTES];
    reward_fact_wire_encode(f, wire);
    return reward_atomic_write(path, wire, sizeof(wire));
}

static bool reward_commit_record_write(const struct vcs_reward_ledger *l,
                                       const struct vcs_reward_plan *plan,
                                       const bool *rejected)
{
    char dir[4400];
    if (!reward_child_path(dir, sizeof(dir), l->root, "commits"))
        LOG_FAIL(REWARD_LOG, "commits path too long");
    if (!reward_mkdir_p(dir))
        LOG_FAIL(REWARD_LOG, "mkdir %s: %s", dir, strerror(errno));
    uint32_t rows = plan->planned_count;
    size_t wire_len =
        REWARD_COMMIT_HEADER_BYTES + (size_t)rows * REWARD_COMMIT_ROW_BYTES;
    uint8_t *wire = zcl_malloc(wire_len, "reward_commit_wire");
    if (!wire)
        LOG_FAIL(REWARD_LOG, "alloc %zu commit wire", wire_len);
    uint8_t *p = wire;
    memcpy(p, REWARD_COMMIT_MAGIC, 4);
    p += 4;
    reward_put_i64le(p, plan->day);
    p += 8;
    memcpy(p, plan->plan_id, 32);
    p += 32;
    reward_put_u32le(p, rows);
    p += 4;
    size_t written = 0;
    for (size_t i = 0; i < plan->row_count; i++) {
        const struct vcs_reward_plan_row *r = &plan->rows[i];
        if (r->disposition != VCS_REWARD_DISP_PLANNED)
            continue;
        const struct vcs_reward_entry *e =
            vcs_reward_ledger_find(l, r->entry_id);
        if (!e) {
            free(wire);
            LOG_FAIL(REWARD_LOG, "commit record entry vanished");
            return false;
        }
        memcpy(p, r->entry_id, 32);
        p += 32;
        memcpy(p, e->contributor, 33);
        p += 33;
        p[0] = (uint8_t)e->category;
        p++;
        p[0] = rejected[i] ? (uint8_t)VCS_REWARD_RECEIPT_REJECTED
                           : (uint8_t)VCS_REWARD_RECEIPT_SETTLED;
        p++;
        memset(p, 0, VCS_REWARD_RULE_MAX);
        if (rejected[i]) {
            const char *rule = VCS_REWARD_RULE_DUPLICATE;
            memcpy(p, rule, strlen(rule));
        }
        p += VCS_REWARD_RULE_MAX;
        reward_put_u32le(p, rejected[i] ? 0 : r->points_settled);
        p += 4;
        written++;
    }
    if (written != rows) {
        free(wire);
        LOG_FAIL(REWARD_LOG, "commit record row mismatch");
        return false;
    }
    char id_hex[65];
    zcl_hex_encode(plan->plan_id, 32, id_hex);
    char path[4400];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, id_hex);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        free(wire);
        LOG_FAIL(REWARD_LOG, "commit path too long");
        return false;
    }
    bool ok = reward_atomic_write(path, wire, wire_len);
    free(wire);
    return ok;
}

enum vcs_reward_commit_error vcs_reward_commit(
    struct vcs_reward_ledger *l, const uint8_t plan_id[32],
    struct vcs_reward_commit_result *out, char *detail, size_t detail_size)
{
    memset(out, 0, sizeof(*out));
    if (detail && detail_size > 0)
        detail[0] = '\0';
    if (!l || !plan_id)
        return VCS_REWARD_COMMIT_IO;
    if (reward_commit_known(l, plan_id))
        return VCS_REWARD_COMMIT_ALREADY_SETTLED;
    bool corrupt = false;
    struct vcs_reward_plan *plan = reward_plan_read(l, plan_id, &corrupt);
    if (!plan)
        return corrupt ? VCS_REWARD_COMMIT_IO
                       : VCS_REWARD_COMMIT_UNKNOWN_PLAN;

    enum vcs_reward_commit_error err = VCS_REWARD_COMMIT_OK;
    bool *rejected = NULL;
    bool *resumed = NULL;
    if (plan->row_count > 0) {
        rejected = zcl_calloc(plan->row_count, sizeof(*rejected),
                              "reward_commit_rejected");
        resumed = zcl_calloc(plan->row_count, sizeof(*resumed),
                             "reward_commit_resumed");
        if (!rejected || !resumed) {
            LOG_FAIL(REWARD_LOG, "alloc commit scratch");
            err = VCS_REWARD_COMMIT_IO;
            goto done;
        }
    }

    /* PASS 1 — validate every PLANNED row against the CURRENT ledger.
     * Nothing is written in this pass. Batch additions for the cap
     * recomputation accumulate in entry-id order exactly as plan_build
     * did, with this plan's own settled facts excluded (they are the
     * result, not the input). */
    {
        struct vcs_score_period_entry additions[VCS_REWARD_MAX_BATCH_ENTRIES];
        size_t addition_count = 0;
        char contributors[VCS_REWARD_MAX_BATCH_ENTRIES][33];
        uint8_t accepted_roots[VCS_REWARD_MAX_BATCH_ENTRIES][32];
        uint8_t accepted_cats[VCS_REWARD_MAX_BATCH_ENTRIES];
        for (size_t i = 0; i < plan->row_count; i++) {
            const struct vcs_reward_plan_row *r = &plan->rows[i];
            if (r->disposition != VCS_REWARD_DISP_PLANNED)
                continue;
            const struct vcs_reward_entry *e =
                vcs_reward_ledger_find(l, r->entry_id);
            char id_hex[65];
            zcl_hex_encode(r->entry_id, 32, id_hex);
            if (!e) {
                if (detail && detail_size > 0)
                    snprintf(detail, detail_size, "entry %s missing", id_hex);
                err = VCS_REWARD_COMMIT_STALE;
                goto done;
            }
            if (e->state == VCS_REWARD_STATE_REJECTED) {
                if (detail && detail_size > 0)
                    snprintf(detail, detail_size,
                             "entry %s rejected (%s)", id_hex,
                             e->rejected_rule);
                err = VCS_REWARD_COMMIT_STALE;
                goto done;
            }
            const struct vcs_reward_fact *fact =
                reward_fact_find(l, r->entry_id);
            if (e->state == VCS_REWARD_STATE_SETTLED) {
                if (reward_id_cmp(e->settled_by_plan, plan_id) != 0 ||
                    !fact) {
                    if (detail && detail_size > 0)
                        snprintf(detail, detail_size,
                                 "entry %s settled by another plan", id_hex);
                    err = VCS_REWARD_COMMIT_STALE;
                    goto done;
                }
                resumed[i] = true; /* replay of an interrupted commit */
            } else if (fact &&
                       reward_id_cmp(fact->plan_id, plan_id) != 0) {
                if (detail && detail_size > 0)
                    snprintf(detail, detail_size,
                             "entry %s settled by another plan", id_hex);
                err = VCS_REWARD_COMMIT_STALE;
                goto done;
            } else if (fact) {
                resumed[i] = true; /* fact durable, queue update crashed */
            }

            /* A same-(release, contributor, category) fact from ANOTHER
             * plan appeared since the plan was made: this entry can never
             * settle — reject it with the named rule, settle the rest.
             * The within-batch walk below catches the same collision
             * between two rows of THIS plan (defense in depth: plan_build
             * already excludes it). */
            if (!resumed[i] &&
                reward_fact_duplicate(l, e->release_root, e->contributor,
                                      e->category, plan_id)) {
                rejected[i] = true;
                continue;
            }
            if (!resumed[i]) {
                bool batch_dup = false;
                for (size_t a = 0; a < addition_count; a++)
                    if (accepted_cats[a] == (uint8_t)e->category &&
                        memcmp(accepted_roots[a], e->release_root, 32) ==
                            0 &&
                        memcmp(contributors[a], e->contributor, 33) == 0) {
                        batch_dup = true;
                        break;
                    }
                if (batch_dup) {
                    rejected[i] = true;
                    continue;
                }
            }

            /* Exact cap recomputation against the current ledger. */
            struct vcs_score_period_entry
                history[VCS_REWARD_MAX_FACTS + VCS_REWARD_MAX_BATCH_ENTRIES];
            size_t hcount = reward_history_for(l, e->contributor, plan_id,
                                               history,
                                               VCS_REWARD_MAX_FACTS);
            for (size_t a = 0; a < addition_count; a++) {
                if (memcmp(contributors[a], e->contributor, 33) == 0 &&
                    hcount < sizeof(history) / sizeof(history[0]))
                    history[hcount++] = additions[a];
            }
            struct vcs_score_period_caps caps;
            vcs_score_apply_period_caps(history, hcount, plan->day,
                                        r->points_requested, &caps);
            if (caps.allowed_score != r->points_settled ||
                caps.daily_release_cap_hit) {
                if (detail && detail_size > 0)
                    snprintf(detail, detail_size,
                             "entry %s: allowed %u != planned %u", id_hex,
                             caps.allowed_score, r->points_settled);
                err = VCS_REWARD_COMMIT_CAPS_CHANGED;
                goto done;
            }
            if (!rejected[i] &&
                addition_count < VCS_REWARD_MAX_BATCH_ENTRIES) {
                additions[addition_count].day = plan->day;
                additions[addition_count].score = r->points_settled;
                memcpy(contributors[addition_count], e->contributor, 33);
                memcpy(accepted_roots[addition_count], e->release_root, 32);
                accepted_cats[addition_count] = (uint8_t)e->category;
                addition_count++;
            }
        }
    }

    /* PASS 2 — write facts + queue transitions, commit record LAST. */
    for (size_t i = 0; i < plan->row_count; i++) {
        const struct vcs_reward_plan_row *r = &plan->rows[i];
        if (r->disposition != VCS_REWARD_DISP_PLANNED)
            continue;
        bool found = false;
        size_t at = reward_entry_lower_bound(l, r->entry_id, &found);
        if (!found) {
            err = VCS_REWARD_COMMIT_IO; /* validated above; cannot happen */
            goto done;
        }
        struct vcs_reward_entry *e = &l->entries[at];
        if (rejected[i]) {
            e->state = VCS_REWARD_STATE_REJECTED;
            snprintf(e->rejected_rule, sizeof(e->rejected_rule), "%s",
                     VCS_REWARD_RULE_DUPLICATE);
            if (!reward_entry_rewrite(l, e)) {
                err = VCS_REWARD_COMMIT_IO;
                goto done;
            }
            out->rejected_count++;
            continue;
        }
        if (!resumed[i]) {
            struct vcs_reward_fact f;
            memset(&f, 0, sizeof(f));
            memcpy(f.entry_id, e->entry_id, 32);
            memcpy(f.release_root, e->release_root, 32);
            memcpy(f.contributor, e->contributor, 33);
            f.kind = (uint8_t)e->kind;
            f.category = (uint8_t)e->category;
            f.points = r->points_settled;
            f.day = plan->day;
            memcpy(f.facts_hash, e->facts_hash, 32);
            memcpy(f.plan_id, plan_id, 32);
            if (!reward_fact_write(l, &f)) {
                err = VCS_REWARD_COMMIT_IO;
                goto done;
            }
            struct vcs_reward_fact *slot = reward_fact_slot(l);
            if (!slot) {
                err = VCS_REWARD_COMMIT_IO;
                goto done;
            }
            *slot = f;
        }
        if (e->state != VCS_REWARD_STATE_SETTLED) {
            e->state = VCS_REWARD_STATE_SETTLED;
            memcpy(e->settled_by_plan, plan_id, 32);
            e->settled_day = plan->day;
            if (!reward_entry_rewrite(l, e)) {
                err = VCS_REWARD_COMMIT_IO;
                goto done;
            }
        }
        out->settled_count++;
        out->points_settled += r->points_settled;
        if (resumed[i])
            out->resumed = true;
    }
    if (!reward_commit_record_write(l, plan, rejected) ||
        !reward_commit_register(l, plan_id)) {
        err = VCS_REWARD_COMMIT_IO;
        goto done;
    }
    {
        bool found = false;
        struct vcs_reward_loaded_plan *lp =
            reward_plan_slot(l, plan_id, &found);
        if (lp)
            lp->committed = true;
    }

done:
    free(rejected);
    free(resumed);
    vcs_reward_plan_free(plan);
    free(plan);
    return err;
}

/* ── receipt ────────────────────────────────────────────────────────── */

enum vcs_reward_receipt_error vcs_reward_receipt_load(
    const struct vcs_reward_ledger *l, const uint8_t plan_id[32],
    struct vcs_reward_receipt *out)
{
    memset(out, 0, sizeof(*out));
    if (!l || !plan_id)
        return VCS_REWARD_RECEIPT_IO;
    char id_hex[65];
    zcl_hex_encode(plan_id, 32, id_hex);
    char path[4400];
    int n = snprintf(path, sizeof(path), "%s/commits/%s", l->root, id_hex);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        LOG_ERROR(REWARD_LOG, "receipt path too long");
        return VCS_REWARD_RECEIPT_IO;
    }
    size_t wire_len = 0;
    uint8_t *wire = reward_read_file(path, VCS_REWARD_MAX_COMMIT_WIRE_BYTES,
                                     &wire_len);
    if (!wire) {
        if (reward_commit_known(l, plan_id))
            return VCS_REWARD_RECEIPT_IO; /* registered but unreadable */
        bool corrupt = false;
        struct vcs_reward_plan *plan =
            reward_plan_read(l, plan_id, &corrupt);
        if (plan) {
            vcs_reward_plan_free(plan);
            free(plan);
            return VCS_REWARD_RECEIPT_NOT_SETTLED;
        }
        return corrupt ? VCS_REWARD_RECEIPT_IO
                       : VCS_REWARD_RECEIPT_UNKNOWN_PLAN;
    }
    if (wire_len < REWARD_COMMIT_HEADER_BYTES ||
        memcmp(wire, REWARD_COMMIT_MAGIC, 4) != 0) {
        free(wire);
        LOG_ERROR(REWARD_LOG, "commit record %s does not parse", id_hex);
        return VCS_REWARD_RECEIPT_IO;
    }
    const uint8_t *p = wire + 4;
    out->day = reward_get_i64le(p);
    p += 8;
    memcpy(out->plan_id, p, 32);
    p += 32;
    uint32_t rows = reward_get_u32le(p);
    p += 4;
    if (rows > VCS_REWARD_MAX_BATCH_ENTRIES ||
        wire_len != REWARD_COMMIT_HEADER_BYTES +
                        (size_t)rows * REWARD_COMMIT_ROW_BYTES) {
        free(wire);
        LOG_ERROR(REWARD_LOG, "commit record %s row table", id_hex);
        return VCS_REWARD_RECEIPT_IO;
    }
    memcpy(out->token_id, vcs_reward_placeholder_token_id(), 32);
    if (rows > 0) {
        out->rows = zcl_calloc(rows, sizeof(*out->rows),
                               "reward_receipt_rows");
        if (!out->rows) {
            free(wire);
            LOG_ERROR(REWARD_LOG, "alloc %u receipt rows", rows);
            return VCS_REWARD_RECEIPT_IO;
        }
    }
    out->row_count = rows;
    for (size_t i = 0; i < rows; i++) {
        struct vcs_reward_receipt_row *r = &out->rows[i];
        memcpy(r->entry_id, p, 32);
        p += 32;
        memcpy(r->contributor, p, 33);
        p += 33;
        r->category = (enum vcs_reward_category)p[0];
        p++;
        r->outcome = (enum vcs_reward_receipt_outcome)p[0];
        p++;
        if (r->category >= VCS_REWARD_CATEGORY_COUNT ||
            r->outcome > VCS_REWARD_RECEIPT_REJECTED) {
            free(wire);
            vcs_reward_receipt_free(out);
            LOG_ERROR(REWARD_LOG, "commit record %s row %zu", id_hex, i);
            return VCS_REWARD_RECEIPT_IO;
        }
        memcpy(r->rule, p, VCS_REWARD_RULE_MAX);
        r->rule[VCS_REWARD_RULE_MAX - 1u] = '\0';
        p += VCS_REWARD_RULE_MAX;
        r->points = reward_get_u32le(p);
        p += 4;
        if (r->outcome == VCS_REWARD_RECEIPT_SETTLED) {
            out->settled_count++;
            out->points_total += r->points;
        } else {
            out->rejected_count++;
        }
    }
    free(wire);
    return VCS_REWARD_RECEIPT_OK;
}

/* ── contributor totals ─────────────────────────────────────────────── */

void vcs_reward_contributor_totals(const struct vcs_reward_ledger *l,
                                   const uint8_t contributor[33],
                                   struct vcs_reward_contributor_totals *out)
{
    memset(out, 0, sizeof(*out));
    if (!l || !contributor)
        return;
    for (size_t i = 0; i < l->fact_count; i++) {
        const struct vcs_reward_fact *f = &l->facts[i];
        if (memcmp(f->contributor, contributor, 33) != 0)
            continue;
        out->earned_score += f->points;
        out->settled_entries++;
    }
    /* v1 simulation: 1 score point = 1 simulated placeholder ZCODE. The
     * two facts stay SEPARATE fields by owner directive; neither is a
     * balance. */
    out->token_rewards_received = out->earned_score;
    for (size_t i = 0; i < l->entry_count; i++) {
        const struct vcs_reward_entry *e = &l->entries[i];
        if (memcmp(e->contributor, contributor, 33) != 0)
            continue;
        if (e->state == VCS_REWARD_STATE_QUEUED ||
            e->state == VCS_REWARD_STATE_PLANNED) {
            out->queued_entries++;
            out->queued_points += e->points;
        } else if (e->state == VCS_REWARD_STATE_REJECTED) {
            out->rejected_entries++;
        }
    }
}
