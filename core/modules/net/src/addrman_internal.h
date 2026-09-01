/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Internal addrman lookup contract shared by its implementation units. */

#ifndef ZCL_NET_ADDRMAN_INTERNAL_H
#define ZCL_NET_ADDRMAN_INTERNAL_H

#include "net/addrman.h"

/* Caller holds am->cs. The address index is private to addrman.c; narrow
 * helpers in sibling translation units use this entry point rather than
 * reintroducing an O(n) scan. */
struct addr_info *addrman_find_addr_locked(struct addr_man *am,
                                           const struct net_addr *addr,
                                           int *id_out);

/* Starting slot count for the O(1) address index. The index is never
 * serialized, so addrman_codec.c rebuilds it from `entries` after a load and
 * needs the same starting size the core table uses. */
#define ADDRMAN_INDEX_INITIAL_SLOTS 8192

/* Append `id` to the random-order array. Caller holds am->cs. On allocation
 * failure the id is dropped with a warning and the array is left intact —
 * losing one address is always better than failing a load. */
void addrman_random_push_locked(struct addr_man *am, int id);

/* Rebuild the address index at `new_slots` capacity from every used entry.
 * Caller holds am->cs. Used after a deserialize, which populates `entries`
 * directly and leaves the index empty. */
void addrman_index_rebuild_locked(struct addr_man *am, size_t new_slots);

#endif
