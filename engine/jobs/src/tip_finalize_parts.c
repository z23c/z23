/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * tip_finalize_parts - see jobs/tip_finalize_parts.h. */

#include "jobs/tip_finalize_parts.h"

#include "json/json.h"
#include "platform/time_compat.h"

#include <stdatomic.h>
#include <stddef.h>

#define TFP_SCHEMA "zcl.tip_finalize_parts.v1"
#define TFP_BUCKETS 40u
#define TFP_SLOTS ((size_t)TF_PART_COUNT + 1u)

_Static_assert(TF_PART_COUNT <= 32, "ran mask is 32 bits wide");

struct tfp_slot {
    _Atomic uint64_t count;
    _Atomic uint64_t total_us;
    _Atomic uint64_t max_us;
    _Atomic uint64_t hist[TFP_BUCKETS];
};

static struct tfp_slot g_slots[TFP_SLOTS];

static const char *const g_names[TFP_SLOTS] = {
    [TF_PART_BODY_ACQUIRE] = "body_acquire",
    [TF_PART_WALLET_SYNC] = "wallet_sync",
    [TF_PART_CONFIRM_ENQUEUE] = "confirm_enqueue",
    [TF_PART_SAPLING_DECRYPT] = "sapling_decrypt",
    [TF_PART_NOTE_DB] = "note_db",
    [TF_PART_NULLIFIERS] = "nullifiers",
    [TF_PART_WITNESS_BIRTHDAY] = "witness_birthday",
    [TF_PART_RECONCILE_BLOCK] = "reconcile_block",
    [TF_PART_MMR_APPEND] = "mmr_append",
    [TF_PART_MMB_APPEND] = "mmb_append",
    [TF_PART_COUNT] = "total",
};

int64_t tip_finalize_parts_start(const struct tip_finalize_parts_block *b)
{
    return b ? clock_now_monotonic_ns() : 0;
}

void tip_finalize_parts_add(struct tip_finalize_parts_block *b,
                            enum tip_finalize_part part, int64_t t0_ns)
{
    if (!b || (unsigned)part >= (unsigned)TF_PART_COUNT)
        return;
    int64_t d = clock_now_monotonic_ns() - t0_ns;
    b->ns[part] += d > 0 ? (uint64_t)d : 0;
    b->ran |= UINT32_C(1) << (unsigned)part;
}

static size_t tfp_bucket(uint64_t v)
{
    if (v == 0)
        return 0;
    size_t b = 64u - (size_t)__builtin_clzll(v);
    return b < TFP_BUCKETS ? b : TFP_BUCKETS - 1u;
}

static void tfp_observe(size_t slot, uint64_t us)
{
    struct tfp_slot *s = &g_slots[slot];
    atomic_fetch_add_explicit(&s->count, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&s->total_us, us, memory_order_relaxed);
    atomic_fetch_add_explicit(&s->hist[tfp_bucket(us)], 1,
                              memory_order_relaxed);
    uint64_t seen = atomic_load_explicit(&s->max_us, memory_order_relaxed);
    while (us > seen &&
           !atomic_compare_exchange_weak_explicit(
               &s->max_us, &seen, us, memory_order_relaxed,
               memory_order_relaxed)) {
    }
}

void tip_finalize_parts_publish(const struct tip_finalize_parts_block *b,
                                int64_t t0_ns)
{
    if (!b)
        return;
    int64_t total = clock_now_monotonic_ns() - t0_ns;
    for (size_t p = 0; p < (size_t)TF_PART_COUNT; p++)
        if (b->ran & (UINT32_C(1) << (unsigned)p))
            tfp_observe(p, b->ns[p] / 1000u);
    tfp_observe(TF_PART_COUNT, total > 0 ? (uint64_t)total / 1000u : 0);
}

static uint64_t tfp_quantile(const struct tfp_slot *s, uint64_t count,
                             unsigned pct)
{
    uint64_t target = (count * pct + 99u) / 100u;
    uint64_t seen = 0;
    for (size_t b = 0; b < TFP_BUCKETS; b++) {
        seen += atomic_load_explicit(&s->hist[b], memory_order_relaxed);
        if (seen >= target)
            return b == 0 ? 0 : (UINT64_C(1) << b) - 1u;
    }
    return 0;
}

bool tip_finalize_parts_stat(int part, struct tip_finalize_part_stat *out)
{
    if (!out || part < 0 || (size_t)part >= TFP_SLOTS)
        return false;  // raw-return-ok:range-check-on-caller-index
    const struct tfp_slot *s = &g_slots[part];
    out->count = atomic_load_explicit(&s->count, memory_order_relaxed);
    out->total_us = atomic_load_explicit(&s->total_us, memory_order_relaxed);
    out->max_us = atomic_load_explicit(&s->max_us, memory_order_relaxed);
    out->p50_us = out->count ? tfp_quantile(s, out->count, 50) : 0;
    out->p95_us = out->count ? tfp_quantile(s, out->count, 95) : 0;
    return true;
}

const char *tip_finalize_parts_name(int part)
{
    return (part >= 0 && (size_t)part < TFP_SLOTS) ? g_names[part] : NULL;
}

void tip_finalize_parts_reset(void)
{
    for (size_t i = 0; i < TFP_SLOTS; i++) {
        atomic_store(&g_slots[i].count, 0);
        atomic_store(&g_slots[i].total_us, 0);
        atomic_store(&g_slots[i].max_us, 0);
        for (size_t b = 0; b < TFP_BUCKETS; b++)
            atomic_store(&g_slots[i].hist[b], 0);
    }
}

/* Push {count,total_us,mean_us,max_us,p50_us,p95_us} under the part's name. */
static bool tfp_push_stat(struct json_value *obj, int part)
{
    struct tip_finalize_part_stat st;
    struct json_value o;
    if (!tip_finalize_parts_stat(part, &st))
        return false;  // raw-return-ok:range-check-on-caller-index
    json_init(&o);
    json_set_object(&o);
    json_push_kv_int(&o, "count", (int64_t)st.count);
    json_push_kv_int(&o, "total_us", (int64_t)st.total_us);
    json_push_kv_int(&o, "mean_us",
                     st.count ? (int64_t)(st.total_us / st.count) : 0);
    json_push_kv_int(&o, "max_us", (int64_t)st.max_us);
    json_push_kv_int(&o, "p50_us", (int64_t)st.p50_us);
    json_push_kv_int(&o, "p95_us", (int64_t)st.p95_us);
    bool ok = json_push_kv(obj, tip_finalize_parts_name(part), &o);
    json_free(&o);
    return ok;
}

bool tip_finalize_parts_dump_state_json(struct json_value *out,
                                        const char *key)
{
    (void)key;
    if (!out)
        return false;  // raw-return-ok:range-check-on-caller-index
    struct json_value parts;
    uint64_t sum = 0;
    json_set_object(out);
    json_push_kv_str(out, "schema", TFP_SCHEMA);
    json_init(&parts);
    json_set_object(&parts);
    for (int p = 0; p < TF_PART_COUNT; p++) {
        struct tip_finalize_part_stat st;
        (void)tip_finalize_parts_stat(p, &st);
        sum += st.total_us;
        if (!tfp_push_stat(&parts, p)) {
            json_free(&parts);
            return false;
        }
    }
    json_push_kv(out, "parts", &parts);
    json_free(&parts);
    struct tip_finalize_part_stat ts;
    (void)tip_finalize_parts_stat(TF_PART_TOTAL, &ts);
    json_push_kv_int(out, "parts_sum_us", (int64_t)sum);
    json_push_kv_int(out, "unaccounted_us",
                     ts.total_us > sum ? (int64_t)(ts.total_us - sum) : 0);
    return tfp_push_stat(out, TF_PART_TOTAL);
}
