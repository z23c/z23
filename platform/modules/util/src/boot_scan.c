/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_scan — implementation. See util/boot_scan.h for the contract.
 *
 * A fixed static table of {name, atomic value} slots. Registration copies a
 * name in under a mutex (the slow path, run once per scanner); the hot path is
 * a lock-free relaxed atomic add on a stable slot pointer. The table never
 * grows or reallocs, so slot pointers are stable for the process lifetime. */

#include "util/boot_scan.h"
#include "util/log_macros.h"

#include "json/json.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

struct boot_scan_slot {
    char                  name[BOOT_SCAN_NAME_MAX];
    atomic_uint_least64_t value;
};

static struct boot_scan_slot g_slots[BOOT_SCAN_MAX_COUNTERS];

/* g_count only grows (except in the test reset). A slot's name is fully
 * written BEFORE g_count is published with release ordering, so any reader
 * that acquire-loads index i also observes slot i's NUL-terminated name. */
static _Atomic size_t   g_count = 0;
static pthread_mutex_t  g_lock = PTHREAD_MUTEX_INITIALIZER;
static atomic_bool      g_full_warned = false;

/* strncmp bounded by the slot width — slot names are always truncated to
 * BOOT_SCAN_NAME_MAX-1 at registration, so a query longer than that still
 * matches the slot it created (never spins re-creating). */
static bool name_eq(const char *slot, const char *query)
{
    return strncmp(slot, query, BOOT_SCAN_NAME_MAX - 1) == 0;
}

static atomic_uint_least64_t *find(const char *name)
{
    size_t n = atomic_load_explicit(&g_count, memory_order_acquire);
    for (size_t i = 0; i < n; i++)
        if (name_eq(g_slots[i].name, name))
            return &g_slots[i].value;
    return NULL;
}

atomic_uint_least64_t *boot_scan_counter(const char *name)
{
    if (!name || !name[0])
        return NULL;

    /* Fast path: lock-free find. */
    atomic_uint_least64_t *hit = find(name);
    if (hit)
        return hit;

    pthread_mutex_lock(&g_lock);
    /* Re-check under the lock — another thread may have created it. */
    hit = find(name);
    if (hit) {
        pthread_mutex_unlock(&g_lock);
        return hit;
    }
    size_t n = atomic_load_explicit(&g_count, memory_order_relaxed);
    if (n >= BOOT_SCAN_MAX_COUNTERS) {
        pthread_mutex_unlock(&g_lock);
        if (!atomic_exchange_explicit(&g_full_warned, true,
                                      memory_order_relaxed))
            LOG_WARN("boot_scan",
                     "counter table full (%d) — '%s' will not be counted",
                     BOOT_SCAN_MAX_COUNTERS, name);
        return NULL;
    }
    size_t len = strnlen(name, BOOT_SCAN_NAME_MAX - 1);
    memcpy(g_slots[n].name, name, len);
    g_slots[n].name[len] = '\0';
    atomic_store_explicit(&g_slots[n].value, 0, memory_order_relaxed);
    /* Publish the fully-written slot last. */
    atomic_store_explicit(&g_count, n + 1, memory_order_release);
    pthread_mutex_unlock(&g_lock);
    return &g_slots[n].value;
}

uint64_t boot_scan_value(const char *name)
{
    if (!name)
        return 0;
    atomic_uint_least64_t *c = find(name);
    return c ? (uint64_t)atomic_load_explicit(c, memory_order_relaxed) : 0;
}

void boot_scan_dump_json(struct json_value *out)
{
    if (!out)
        return;
    json_set_object(out);
    size_t n = atomic_load_explicit(&g_count, memory_order_acquire);
    for (size_t i = 0; i < n; i++)
        json_push_kv_int(out, g_slots[i].name,
                         (int64_t)atomic_load_explicit(&g_slots[i].value,
                                                       memory_order_relaxed));
}

void boot_scan_log_summary(const char *tag)
{
    size_t n = atomic_load_explicit(&g_count, memory_order_acquire);
    if (n == 0) {
        LOG_INFO("boot_scan", "[boot-scan] %s: (no counters registered)",
                 tag ? tag : "");
        return;
    }
    /* One compact line. Bounded: BOOT_SCAN_MAX_COUNTERS entries, each
     * name<48 + a uint64 decimal — comfortably under 4 KB. */
    char line[4096];
    size_t off = 0;
    int w = snprintf(line, sizeof(line), "[boot-scan] %s:", tag ? tag : "");
    if (w > 0)
        off = (size_t)w < sizeof(line) ? (size_t)w : sizeof(line) - 1;
    for (size_t i = 0; i < n; i++) {
        w = snprintf(line + off, sizeof(line) - off, " %s=%llu",
                     g_slots[i].name,
                     (unsigned long long)atomic_load_explicit(
                         &g_slots[i].value, memory_order_relaxed));
        if (w <= 0)
            break;
        if ((size_t)w >= sizeof(line) - off) {
            off = sizeof(line) - 1;
            break;
        }
        off += (size_t)w;
    }
    LOG_INFO("boot_scan", "%s", line);
}

#ifdef ZCL_TESTING
void boot_scan_reset_for_testing(void)
{
    pthread_mutex_lock(&g_lock);
    for (size_t i = 0; i < BOOT_SCAN_MAX_COUNTERS; i++) {
        g_slots[i].name[0] = '\0';
        atomic_store_explicit(&g_slots[i].value, 0, memory_order_relaxed);
    }
    atomic_store_explicit(&g_count, 0, memory_order_release);
    pthread_mutex_unlock(&g_lock);
}
#endif
