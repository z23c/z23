/* Copyright (c) 2012 Pieter Wuille
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * The peers.dat record codec. Kept in its own translation unit for the same
 * reason addrman_lookup.c is — the core table file is already oversized and
 * must not grow — and because this is the one part of addrman that parses
 * bytes an attacker can influence. Keeping it separate makes the boundary
 * between "data we computed" and "data we read back off disk" visible.
 */

#include "addrman_internal.h"
#include "core/serialize.h"
#include "util/timedata.h"
#include "util/safe_alloc.h"
#include "util/log_macros.h"

#include <stdlib.h>
#include <string.h>
/* ── peers.dat record codec ──────────────────────────────────────────────
 *
 * FORMAT VERSION HISTORY
 *   1  ip[16] port services nTime source.ip[16] last_success attempts
 *   2  ...everything in 1, then torv3[32] has_torv3 source.torv3[32]
 *      source.has_torv3 last_try
 *
 * Why version 2 exists: version 1 could not describe an onion peer AT ALL.
 * net_addr_from_onion() (net/netaddr.c) zeroes ip[16] and puts the entire
 * identity in torv3[32], so under version 1 EVERY onion peer serialized to
 * the same sixteen zero bytes and reloaded as an unroutable all-zero
 * address. On a Tor-first network that made peers.dat a no-op for the only
 * transport that matters: a node forgot every onion peer it had ever spoken
 * to on each restart and fell back to the shipped seed list. Version 2
 * writes the torv3 pubkey and its flag, for the address AND for the source
 * address that decides the entry's NEW-table bucket, so a remembered onion
 * peer — and the eclipse-resistance of where it was bucketed — survives a
 * restart or a kill -9.
 *
 * Version 2 also persists last_try. attempts already survived a restart, so
 * the 0.66^attempts decay carried over, but the "tried within the last ten
 * minutes" cooldown did not: every entry reloaded with last_try == 0 and was
 * immediately eligible again, so a peer that had just failed was re-dialed
 * at full preference on the very next boot.
 *
 * Readers accept 0, 1 and 2. Writers always emit the current version. */
#define ADDRMAN_SER_VERSION_LEGACY  1
#define ADDRMAN_SER_VERSION_ONION   2
#define ADDRMAN_SER_VERSION_CURRENT ADDRMAN_SER_VERSION_ONION

/* Upper bound on a persisted attempt count. Any real entry is far below
 * this; the clamp exists so a hostile file cannot smuggle a value that
 * misbehaves in arithmetic downstream. */
#define ADDRMAN_PERSISTED_ATTEMPTS_MAX (ADDRMAN_MAX_FAILURES * 100)

static bool addrman_write_entry(struct byte_stream *s,
                                const struct addr_info *e)
{
    return stream_write_bytes(s, e->addr.svc.addr.ip, 16) &&
           stream_write_u16_le(s, e->addr.svc.port) &&
           stream_write_u64_le(s, e->addr.nServices) &&
           stream_write_u32_le(s, e->addr.nTime) &&
           stream_write_bytes(s, e->source.ip, 16) &&
           stream_write_i64_le(s, e->last_success) &&
           stream_write_i32_le(s, e->attempts) &&
           /* version 2 tail */
           stream_write_bytes(s, e->addr.svc.addr.torv3, TORV3_ADDR_SIZE) &&
           stream_write_u8(s, e->addr.svc.addr.has_torv3 ? 1u : 0u) &&
           stream_write_bytes(s, e->source.torv3, TORV3_ADDR_SIZE) &&
           stream_write_u8(s, e->source.has_torv3 ? 1u : 0u) &&
           stream_write_i64_le(s, e->last_try);
}

/* True when `t` is the all-zero pubkey, which is never a real onion
 * identity — a torv3 field of zeroes means "this record does not actually
 * name an onion service", however the flag byte reads. */
static bool addrman_torv3_is_blank(const unsigned char t[TORV3_ADDR_SIZE])
{
    for (size_t i = 0; i < TORV3_ADDR_SIZE; i++)
        if (t[i] != 0)
            return false;
    return true;
}

/* Force one decoded net_addr into a shape the rest of the node can reason
 * about: the torv3 flag is a boolean or it is nothing, and it only stands
 * when an actual pubkey backs it. */
static void addrman_sanitize_addr(struct net_addr *a, uint8_t flag_byte)
{
    if (flag_byte != 1 || addrman_torv3_is_blank(a->torv3)) {
        memset(a->torv3, 0, TORV3_ADDR_SIZE);
        a->has_torv3 = false;
        return;
    }
    a->has_torv3 = true;
}

/* Aging policy applied when peers.dat is read back.
 *
 * The tables are already hard-bounded (ADDRMAN_NEW_BUCKET_COUNT and
 * ADDRMAN_TRIED_BUCKET_COUNT slots), so the store cannot grow without limit
 * either way. What this adds is that dead weight actually LEAVES rather than
 * occupying a slot forever and being re-drawn by every selection pass.
 *
 * The rule keys ONLY on what this node measured itself — attempt counts and
 * success times — never on nTime. nTime is a peer-supplied timestamp, and
 * addresses that arrive through net_address_init() (the fixed seed list among
 * them) carry a 1973 default that would make an nTime rule delete addresses
 * nobody has actually shown to be dead.
 *
 * An entry we have EVER connected to successfully is only dropped after it
 * has also failed ADDRMAN_MAX_FAILURES times AND gone quiet for longer than
 * the failure horizon. Anything we have never reached goes after
 * ADDRMAN_RETRIES failed attempts. Both mirror addr_info_is_terrible()'s
 * measurement-based clauses, so aging on disk and deprioritising in memory
 * cannot drift apart. */
static bool addrman_record_is_dead(const struct addr_info *e, int64_t now)
{
    /* addr_info_is_terrible()'s first clause, kept in step: an address tried
     * within the last minute is never written off, whatever its history says.
     * Version 2 persists last_try, so this clause now means something across
     * a restart — without it the loader could discard a record the running
     * node would have protected one second earlier. */
    if (e->last_try && e->last_try >= now - 60)
        return false;
    if (e->last_success == 0)
        return e->attempts >= ADDRMAN_RETRIES;
    return e->attempts >= ADDRMAN_MAX_FAILURES &&
           now - e->last_success > ADDRMAN_MIN_FAIL_DAYS * 24 * 60 * 60;
}

/* Read one persisted entry.
 *
 * Returns false ONLY when the stream is truncated or malformed at the byte
 * level — that is unrecoverable and aborts the load. A record that parses
 * cleanly but describes something we would never dial is reported through
 * `*usable = false`: the caller drops it and keeps reading, so one bad row
 * costs one row rather than the whole file.
 *
 * peers.dat is attacker-influenced by construction — peers tell us about
 * other peers and we write down what they said — so every field is treated
 * as hostile input here. */
static bool addrman_read_entry(struct byte_stream *s, uint8_t version,
                               int64_t now, struct addr_info *out,
                               bool *usable)
{
    *usable = false;
    memset(out, 0, sizeof(*out));
    out->used = true;

    int32_t attempts = 0;
    if (!stream_read_bytes(s, out->addr.svc.addr.ip, 16) ||
        !stream_read_u16_le(s, &out->addr.svc.port) ||
        !stream_read_u64_le(s, &out->addr.nServices) ||
        !stream_read_u32_le(s, &out->addr.nTime) ||
        !stream_read_bytes(s, out->source.ip, 16) ||
        !stream_read_i64_le(s, &out->last_success) ||
        !stream_read_i32_le(s, &attempts))
        return false;

    uint8_t addr_flag = 0, src_flag = 0;
    if (version >= ADDRMAN_SER_VERSION_ONION) {
        if (!stream_read_bytes(s, out->addr.svc.addr.torv3, TORV3_ADDR_SIZE) ||
            !stream_read_u8(s, &addr_flag) ||
            !stream_read_bytes(s, out->source.torv3, TORV3_ADDR_SIZE) ||
            !stream_read_u8(s, &src_flag) ||
            !stream_read_i64_le(s, &out->last_try))
            return false;
    }

    addrman_sanitize_addr(&out->addr.svc.addr, addr_flag);
    addrman_sanitize_addr(&out->source, src_flag);

    /* A NEGATIVE attempts count is the sharpest edge in this record.
     * addr_info_get_chance() computes pow(0.66, attempts), so attempts ==
     * -100 yields a selection chance of 0.66^-100 — astronomically above
     * 1.0, i.e. an entry that wins EVERY draw it appears in. A single
     * crafted row would pin outbound selection onto one address. Clamp it
     * here, and again in addr_info_get_chance() so no other producer can
     * reintroduce it. */
    if (attempts < 0)
        attempts = 0;
    if (attempts > ADDRMAN_PERSISTED_ATTEMPTS_MAX)
        attempts = ADDRMAN_PERSISTED_ATTEMPTS_MAX;
    out->attempts = attempts;

    /* Timestamps run backwards from now. A future value is not an attack so
     * much as a broken clock, but letting one through would keep an entry
     * permanently outside the failure horizon. */
    if (out->last_success < 0)
        out->last_success = 0;
    else if (out->last_success > now)
        out->last_success = now;
    if (out->last_try < 0)
        out->last_try = 0;
    else if (out->last_try > now)
        out->last_try = now;

    /* Dialability, not policy: a port of zero or an address that is not even
     * well-formed can never become a connection, so it is dead weight in a
     * bounded table. net_addr_is_valid() accepts any onion whose flag
     * survived sanitising above, and rejects the all-zero address that a
     * version-1 onion row decodes to. */
    if (out->addr.svc.port == 0 || !net_addr_is_valid(&out->addr.svc.addr))
        return true;

    /* Bounded aging: a record this node has proven dead does not come back. */
    if (addrman_record_is_dead(out, now))
        return true;

    *usable = true;
    return true;
}

bool addrman_serialize(const struct addr_man *am, struct byte_stream *s)
{
    if (!stream_write_u8(s, ADDRMAN_SER_VERSION_CURRENT)) LOG_FAIL("addrman", "serialize: failed to write version");
    if (!stream_write_u8(s, 32)) LOG_FAIL("addrman", "serialize: failed to write key size");
    if (!stream_write_bytes(s, am->nKey.data, 32)) LOG_FAIL("addrman", "serialize: failed to write nKey");
    if (!stream_write_i32_le(s, am->new_count)) LOG_FAIL("addrman", "serialize: failed to write new_count");
    if (!stream_write_i32_le(s, am->tried_count)) LOG_FAIL("addrman", "serialize: failed to write tried_count");

    int nUBuckets = ADDRMAN_NEW_BUCKET_COUNT ^ (1 << 30);
    if (!stream_write_i32_le(s, nUBuckets)) LOG_FAIL("addrman", "serialize: failed to write bucket count");

    int *mapUnkIds = zcl_calloc((size_t)am->id_count > 0 ? (size_t)am->id_count : 1, sizeof(int), "addr_unk_ids");
    if (!mapUnkIds) LOG_FAIL("addrman", "serialize: alloc failed for mapUnkIds");

    int nIds = 0;
    for (int i = 0; i < am->id_count; i++) {
        if (am->entries[i].used && am->entries[i].ref_count > 0) {
            mapUnkIds[i] = nIds;
            if (!addrman_write_entry(s, &am->entries[i])) { free(mapUnkIds); LOG_FAIL("addrman", "serialize: failed to write new entry i=%d", i); }
            nIds++;
        }
    }
    for (int i = 0; i < am->id_count; i++) {
        if (am->entries[i].used && am->entries[i].in_tried) {
            if (!addrman_write_entry(s, &am->entries[i])) { free(mapUnkIds); LOG_FAIL("addrman", "serialize: failed to write tried entry i=%d", i); }
        }
    }

    for (int bucket = 0; bucket < ADDRMAN_NEW_BUCKET_COUNT; bucket++) {
        int nSize = 0;
        for (int i = 0; i < ADDRMAN_BUCKET_SIZE; i++)
            if (am->vvNew[bucket][i] != -1) nSize++;
        if (!stream_write_i32_le(s, nSize)) { free(mapUnkIds); LOG_FAIL("addrman", "serialize: failed to write bucket size bucket=%d", bucket); }
        for (int i = 0; i < ADDRMAN_BUCKET_SIZE; i++) {
            if (am->vvNew[bucket][i] != -1) {
                int nIndex = mapUnkIds[am->vvNew[bucket][i]];
                if (!stream_write_i32_le(s, nIndex)) { free(mapUnkIds); LOG_FAIL("addrman", "serialize: failed to write bucket index bucket=%d i=%d", bucket, i); }
            }
        }
    }

    free(mapUnkIds);
    return true;
}

bool addrman_deserialize(struct addr_man *am, struct byte_stream *s)
{
    addrman_clear(am);

    uint8_t nVersion;
    if (!stream_read_u8(s, &nVersion)) LOG_FAIL("addrman", "deserialize: failed to read version");
    if (nVersion > ADDRMAN_SER_VERSION_CURRENT) {
        /* A file from a newer build. We cannot know where its records end,
         * so guessing would mis-parse every byte after the header. Refuse
         * cleanly; the caller starts with an empty table. */
        LOG_FAIL("addrman", "deserialize: unsupported version=%u (max %u)",
                 (unsigned)nVersion, (unsigned)ADDRMAN_SER_VERSION_CURRENT);
        return false;
    }
    uint8_t nKeySize;
    if (!stream_read_u8(s, &nKeySize)) LOG_FAIL("addrman", "deserialize: failed to read key size");
    if (nKeySize != 32) LOG_FAIL("addrman", "deserialize: invalid key size=%u expected 32", nKeySize);
    if (!stream_read_bytes(s, am->nKey.data, 32)) LOG_FAIL("addrman", "deserialize: failed to read nKey");

    int32_t nNew, nTried;
    if (!stream_read_i32_le(s, &nNew)) LOG_FAIL("addrman", "deserialize: failed to read new count");
    if (!stream_read_i32_le(s, &nTried)) LOG_FAIL("addrman", "deserialize: failed to read tried count");

    int32_t nUBuckets;
    if (!stream_read_i32_le(s, &nUBuckets)) LOG_FAIL("addrman", "deserialize: failed to read bucket count");
    if (nVersion != 0) nUBuckets ^= (1 << 30);

    /* Reject out-of-range counts BEFORE the (size_t) cast: a negative nNew/
     * nTried (corrupt/hostile peers.dat) would wrap to a huge need and force a
     * multi-GB zcl_realloc. LOG_FAIL alone (the prior form) logged but continued
     * into the overflow, so this must return false. A valid peers.dat never has
     * negative or over-cap counts, so this rejects only corrupt input. */
    if (nNew < 0 || nNew > ADDRMAN_NEW_BUCKET_COUNT * ADDRMAN_BUCKET_SIZE) {
        LOG_FAIL("addrman", "deserialize: nNew=%d out of range", nNew);
        return false;
    }
    if (nTried < 0 || nTried > ADDRMAN_TRIED_BUCKET_COUNT * ADDRMAN_BUCKET_SIZE) {
        LOG_FAIL("addrman", "deserialize: nTried=%d out of range", nTried);
        return false;
    }
    /* nUBuckets is NOT a reason to refuse the file. The bucket table is a
     * HINT about where addresses sat in the writer's table; the addresses
     * themselves are the thing worth keeping, and anything the hint fails to
     * place is re-bucketed below from its own address under our own nKey.
     * Rejecting the whole store because one word does not match this build's
     * table geometry would throw away the entire address book — the exact
     * outcome this store exists to prevent — over something we can recompute.
     * Clamp the walk instead; nothing is read after the table, so stopping
     * early costs nothing. */
    int table_buckets = nUBuckets;
    if (table_buckets < 0)
        table_buckets = 0;
    if (table_buckets > ADDRMAN_NEW_BUCKET_COUNT)
        table_buckets = ADDRMAN_NEW_BUCKET_COUNT;

    size_t need = (size_t)(nNew + nTried);
    if (need > am->entries_cap) {
        struct addr_info *p = zcl_realloc(am->entries,
                                       need * sizeof(struct addr_info), "addr_entries");
        if (!p) LOG_FAIL("addrman", "deserialize: realloc failed for entries need=%zu", need);
        memset(p + am->entries_cap, 0,
               (need - am->entries_cap) * sizeof(struct addr_info));
        am->entries = p;
        am->entries_cap = need;
    }

    const int64_t now = GetAdjustedTime();

    /* Dropping an unusable NEW row renumbers everything after it, and the
     * bucket table at the tail of the file refers to rows by their ORIGINAL
     * position. `remap` carries file position -> stored id (-1 when the row
     * was dropped) so the table still lands on the right entries. Compacting
     * like this keeps entries[0..id_count) hole-free, which the bucket
     * tables, the random order and the address index all rely on. */
    int *remap = NULL;
    if (nNew > 0) {
        remap = zcl_calloc((size_t)nNew, sizeof(int), "addr_deser_remap");
        if (!remap) LOG_FAIL("addrman", "deserialize: alloc failed for remap");
    }

    int placed = 0;
    int nDropped = 0;
    for (int n = 0; n < nNew; n++) {
        struct addr_info info;
        bool usable = false;
        if (!addrman_read_entry(s, nVersion, now, &info, &usable)) {
            free(remap);
            LOG_FAIL("addrman", "deserialize: failed to read new entry n=%d", n);
            return false;
        }
        if (!usable) {
            remap[n] = -1;
            nDropped++;
            continue;
        }

        int id = placed++;
        remap[n] = id;
        am->entries[id] = info;
        struct addr_info *stored = &am->entries[id];
        stored->random_pos = (int)am->random_size;
        addrman_random_push_locked(am, id);
        /* Bucket placement happens after the table is read, in one pass that
         * handles both "the table placed it" and "nothing did". */
    }
    am->id_count = placed;
    am->new_count = placed;

    int nLost = 0;
    for (int n = 0; n < nTried; n++) {
        struct addr_info info;
        bool usable = false;
        if (!addrman_read_entry(s, nVersion, now, &info, &usable)) {
            free(remap);
            LOG_FAIL("addrman", "deserialize: failed to read tried entry n=%d", n);
            return false;
        }
        if (!usable) {
            nLost++;
            nDropped++;
            continue;
        }

        int nKBucket = addr_info_get_tried_bucket(&info, &am->nKey);
        int nKBucketPos = addr_info_get_bucket_position(&info, &am->nKey,
                                                         false, nKBucket);
        if (am->vvTried[nKBucket][nKBucketPos] == -1) {
            info.random_pos = (int)am->random_size;
            info.in_tried = true;
            int id = am->id_count++;
            if ((size_t)id >= am->entries_cap) {
                size_t new_cap = am->entries_cap * 2;
                while (new_cap <= (size_t)id) new_cap *= 2;
                struct addr_info *p = zcl_realloc(am->entries,
                    new_cap * sizeof(struct addr_info), "addr_entries");
                if (!p) { am->id_count--; nLost++; continue; }
                memset(p + am->entries_cap, 0,
                    (new_cap - am->entries_cap) * sizeof(struct addr_info));
                am->entries = p;
                am->entries_cap = new_cap;
            }
            am->entries[id] = info;
            addrman_random_push_locked(am, id);
            am->vvTried[nKBucket][nKBucketPos] = id;
        } else {
            nLost++;
        }
    }
    am->tried_count = nTried - nLost;

    /* Apply the bucket table. Every failure here ABANDONS THE TABLE and keeps
     * the addresses: a truncated or nonsensical hint costs us the writer's
     * layout, which the pass below recomputes, and never the address book. */
    bool table_usable = (nVersion >= ADDRMAN_SER_VERSION_LEGACY &&
                         nUBuckets == ADDRMAN_NEW_BUCKET_COUNT);
    for (int bucket = 0; table_usable && bucket < table_buckets; bucket++) {
        int32_t nSize;
        if (!stream_read_i32_le(s, &nSize) ||
            nSize < 0 || nSize > ADDRMAN_BUCKET_SIZE) {
            LOG_WARN("addrman",
                     "load: bucket table unreadable at bucket=%d — "
                     "re-bucketing the remaining addresses ourselves", bucket);
            break;
        }
        for (int n = 0; n < nSize; n++) {
            int32_t nIndex;
            if (!stream_read_i32_le(s, &nIndex)) {
                LOG_WARN("addrman",
                         "load: bucket table truncated at bucket=%d — "
                         "re-bucketing the remaining addresses ourselves",
                         bucket);
                bucket = table_buckets;   /* stop the outer walk too */
                break;
            }
            if (nIndex < 0 || nIndex >= nNew)
                continue;
            int id = remap ? remap[nIndex] : -1;
            if (id < 0 || (size_t)id >= am->entries_cap)
                continue;   /* the row this slot named was dropped on load */
            struct addr_info *info = &am->entries[id];
            int nUBucketPos = addr_info_get_bucket_position(
                info, &am->nKey, true, bucket);
            if (am->vvNew[bucket][nUBucketPos] == -1 &&
                info->ref_count < ADDRMAN_NEW_BUCKETS_PER_ADDRESS) {
                info->ref_count++;
                am->vvNew[bucket][nUBucketPos] = id;
            }
        }
    }

    free(remap);
    remap = NULL;

    /* Anything the table did not place — because there was no usable table,
     * because it came from a build with different table geometry, or because
     * it ran out partway — is bucketed here from its own address under OUR
     * nKey. An address that loads into no bucket can never be selected, so
     * leaving it unplaced would be memory we kept and could not use. Deriving
     * the position ourselves is also the safer reading of an untrusted hint. */
    int rebucketed = 0;
    for (int i = 0; i < placed; i++) {
        struct addr_info *info = &am->entries[i];
        if (!info->used || info->in_tried || info->ref_count > 0)
            continue;
        int nUBucket = addr_info_get_new_bucket(info, &am->nKey,
                                                 &info->source);
        int nUBucketPos = addr_info_get_bucket_position(info, &am->nKey,
                                                         true, nUBucket);
        if (am->vvNew[nUBucket][nUBucketPos] == -1) {
            am->vvNew[nUBucket][nUBucketPos] = i;
            info->ref_count++;
            rebucketed++;
        }
    }
    if (rebucketed > 0)
        LOG_INFO("addrman", "load: re-bucketed %d address(es) from their own "
                            "addresses", rebucketed);

    if (nDropped > 0)
        LOG_WARN("addrman",
                 "load: dropped %d unusable address record(s) (kept %d)",
                 nDropped, am->id_count);

    /* Rebuild the in-memory address index from the loaded entries (the index
     * is never serialized). addrman_clear() above emptied it; size it to hold
     * every loaded id at < 50% load, then fold in all used entries. */
    {
        size_t want = ADDRMAN_INDEX_INITIAL_SLOTS;
        while ((size_t)(am->id_count + 1) * 2 >= want)
            want *= 2;
        addrman_index_rebuild_locked(am, want);
    }

    return true;
}
