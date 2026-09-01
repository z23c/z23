/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared data structures for fast wallet/block scanning.
 * Used by wallet_scan.c and legacy_import.c.
 *
 * addr_ht:   O(1) address ownership hash table (20-byte hashes)
 * utxo_set:  In-memory UTXO set with O(1) outpoint lookup
 * wtx_list:  Dynamic array of wallet transactions
 * extract_addr: Script → address hash extractor */

#ifndef ZCL_SERVICES_SCAN_UTIL_H
#define ZCL_SERVICES_SCAN_UTIL_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "util/safe_alloc.h"
#include "util/log_macros.h"

/* ── Address hash table ────────────────────────────────────── */

#define SCAN_ADDR_HT_BUCKETS 5381

struct scan_addr_entry {
    uint8_t hash[20];
    struct scan_addr_entry *next;
};

struct scan_addr_ht {
    struct scan_addr_entry *buckets[SCAN_ADDR_HT_BUCKETS];
    int count;
};

static inline unsigned scan_fnv20(const uint8_t h[20])
{
    unsigned v = 2166136261u;
    for (int i = 0; i < 20; i++) { v ^= h[i]; v *= 16777619u; }
    return v % SCAN_ADDR_HT_BUCKETS;
}

static inline void scan_aht_init(struct scan_addr_ht *t)
{
    memset(t, 0, sizeof(*t));
}

static inline void scan_aht_insert(struct scan_addr_ht *t, const uint8_t hash[20])
{
    unsigned b = scan_fnv20(hash);
    for (struct scan_addr_entry *e = t->buckets[b]; e; e = e->next)
        if (memcmp(e->hash, hash, 20) == 0) return;
    struct scan_addr_entry *e = zcl_malloc(sizeof(*e), "scan_addr_entry");
    if (!e) return;
    memcpy(e->hash, hash, 20);
    e->next = t->buckets[b];
    t->buckets[b] = e;
    t->count++;
}

static inline bool scan_aht_has(const struct scan_addr_ht *t, const uint8_t hash[20])
{
    unsigned b = scan_fnv20(hash);
    for (struct scan_addr_entry *e = t->buckets[b]; e; e = e->next)
        if (memcmp(e->hash, hash, 20) == 0) return true;
    return false;
}

static inline void scan_aht_free(struct scan_addr_ht *t)
{
    for (int i = 0; i < SCAN_ADDR_HT_BUCKETS; i++) {
        struct scan_addr_entry *e = t->buckets[i];
        while (e) { struct scan_addr_entry *n = e->next; free(e); e = n; }
    }
}

/* ── In-memory UTXO set ────────────────────────────────────── */

struct scan_mem_utxo {
    uint8_t txid[32];
    uint32_t vout;
    int64_t value;
    uint8_t addr_hash[20];
    uint8_t script[26];
    uint8_t script_len;
    int height;
    bool is_coinbase;
    bool spent;
    uint8_t spent_txid[32];
    int spent_vin;
};

#define SCAN_UTXO_HT_SIZE 16381

struct scan_utxo_ht_entry {
    int idx;
    struct scan_utxo_ht_entry *next;
};

struct scan_utxo_set {
    struct scan_mem_utxo *items;
    int count, cap;
    struct scan_utxo_ht_entry *buckets[SCAN_UTXO_HT_SIZE];
};

static inline unsigned scan_outpoint_hash(const uint8_t txid[32], uint32_t vout)
{
    unsigned v = 2166136261u;
    for (int i = 0; i < 32; i++) { v ^= txid[i]; v *= 16777619u; }
    v ^= vout; v *= 16777619u;
    return v % SCAN_UTXO_HT_SIZE;
}

static inline void scan_uset_init(struct scan_utxo_set *s)
{
    memset(s, 0, sizeof(*s));
    s->cap = 4096;
    s->items = zcl_calloc((size_t)s->cap, sizeof(struct scan_mem_utxo), "scan utxo set");
}

static inline void scan_uset_add(struct scan_utxo_set *s, const struct scan_mem_utxo *u)
{
    if (s->count >= s->cap) {
        int new_cap = s->cap * 2;
        struct scan_mem_utxo *grown = zcl_realloc(s->items,
            (size_t)new_cap * sizeof(struct scan_mem_utxo), "scan utxo set grow");
        if (!grown) {
            /* OOM: old s->items is intact (zcl_realloc never frees on fail).
             * Drop this UTXO rather than crash; loud so the gap is visible. */
            LOG_WARN("scan_util", "scan_uset_add: realloc to cap=%d failed; "
                     "dropping utxo (count=%d)", new_cap, s->count);
            return;
        }
        s->items = grown;
        s->cap = new_cap;
    }
    int i = s->count++;
    s->items[i] = *u;
    unsigned b = scan_outpoint_hash(u->txid, u->vout);
    struct scan_utxo_ht_entry *e = zcl_malloc(sizeof(*e), "scan_utxo_ht_entry");
    if (!e) return;
    e->idx = i;
    e->next = s->buckets[b];
    s->buckets[b] = e;
}

static inline int scan_uset_find(const struct scan_utxo_set *s,
                                  const uint8_t txid[32], uint32_t vout)
{
    unsigned b = scan_outpoint_hash(txid, vout);
    for (struct scan_utxo_ht_entry *e = s->buckets[b]; e; e = e->next) {
        struct scan_mem_utxo *u = &s->items[e->idx];
        if (u->vout == vout && memcmp(u->txid, txid, 32) == 0)
            return e->idx;
    }
    return -1;
}

static inline void scan_uset_free(struct scan_utxo_set *s)
{
    free(s->items);
    for (int i = 0; i < SCAN_UTXO_HT_SIZE; i++) {
        struct scan_utxo_ht_entry *e = s->buckets[i];
        while (e) { struct scan_utxo_ht_entry *n = e->next; free(e); e = n; }
    }
}

/* ── Wallet transaction list ───────────────────────────────── */

struct scan_mem_wtx {
    uint8_t txid[32];
    uint8_t *raw;
    size_t raw_len;
    int height;
    uint32_t time;
    bool from_me;
    int64_t fee;
};

struct scan_wtx_list {
    struct scan_mem_wtx *items;
    int count, cap;
};

static inline void scan_wl_init(struct scan_wtx_list *l)
{
    memset(l, 0, sizeof(*l));
    l->cap = 256;
    l->items = zcl_calloc((size_t)l->cap, sizeof(struct scan_mem_wtx), "scan wtx list");
}

static inline void scan_wl_add(struct scan_wtx_list *l, const struct scan_mem_wtx *t)
{
    if (l->count >= l->cap) {
        int new_cap = l->cap * 2;
        struct scan_mem_wtx *grown = zcl_realloc(l->items,
            (size_t)new_cap * sizeof(struct scan_mem_wtx), "scan wtx list grow");
        if (!grown) {
            /* OOM: old l->items is intact (zcl_realloc never frees on fail).
             * Drop this wtx rather than crash; loud so the gap is visible. */
            LOG_WARN("scan_util", "scan_wl_add: realloc to cap=%d failed; "
                     "dropping wtx (count=%d)", new_cap, l->count);
            return;
        }
        l->items = grown;
        l->cap = new_cap;
    }
    l->items[l->count++] = *t;
}

static inline void scan_wl_free(struct scan_wtx_list *l)
{
    for (int i = 0; i < l->count; i++) free(l->items[i].raw);
    free(l->items);
}

/* ── Script address extraction ─────────────────────────────── */

static inline bool scan_extract_addr(const uint8_t *s, size_t len, uint8_t h[20])
{
    /* P2PKH: OP_DUP OP_HASH160 <20> hash OP_EQUALVERIFY OP_CHECKSIG */
    if (len == 25 && s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14 &&
        s[23] == 0x88 && s[24] == 0xac) {
        memcpy(h, s + 3, 20); return true;
    }
    /* P2SH: OP_HASH160 <20> hash OP_EQUAL */
    if (len == 23 && s[0] == 0xa9 && s[1] == 0x14 && s[22] == 0x87) {
        memcpy(h, s + 2, 20); return true;
    }
    return false;
}

#endif /* ZCL_SERVICES_SCAN_UTIL_H */
