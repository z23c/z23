/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zslot — generational handle table over caller storage.
 *
 * A slot map issues 64-bit handles (32-bit index + 32-bit generation)
 * for values of a fixed size. Getting a freed or never-issued handle
 * returns NULL instead of a dangling pointer. No malloc, no global
 * state, no clock: the caller owns the backing bytes.
 *
 * Generation 0 is never live, so handle 0 is always invalid. A slot
 * that would wrap its generation is retired rather than reused, so an
 * ancient handle cannot alias a new occupant.
 *
 * Occupied generations are odd; free generations are even. Insert
 * occupies the next odd value; remove advances to the next even value
 * and returns the index to the free list. The zslot struct must live
 * outside the backing storage.
 */
#ifndef ZSLOT_H
#define ZSLOT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t zslot_id;

#define ZSLOT_INVALID ((zslot_id)0)

typedef struct zslot zslot;

struct zslot {
    unsigned char *storage;
    uint32_t cap;
    uint32_t live;
    uint32_t free_head; /* cap when the free list is empty */
    uint32_t value_size;
    uint32_t stride;
};

/* Bytes of storage needed for `cap` slots of `value_size`. Returns 0
 * on overflow or when cap is 0. */
size_t zslot_storage_bytes(uint32_t cap, size_t value_size);

/* Initialize over storage[0..storage_bytes). False when the buffer
 * cannot hold at least one slot, args are NULL, or value_size makes
 * the stride overflow. */
bool zslot_init(zslot *t, void *storage, size_t storage_bytes,
                size_t value_size);

/* Copy `value_size` bytes from `value` into a free slot. NULL `value`
 * is allowed only when value_size is 0. Returns ZSLOT_INVALID when
 * the table is full or arguments are unusable. */
zslot_id zslot_insert(zslot *t, const void *value);

/* Free the slot named by `id`. False (no state change) on NULL table,
 * invalid/stale id, or double-remove. */
bool zslot_remove(zslot *t, zslot_id id);

/* Live payload, or NULL when `id` does not name a current occupant. */
void *zslot_get(zslot *t, zslot_id id);
const void *zslot_get_const(const zslot *t, zslot_id id);

bool zslot_contains(const zslot *t, zslot_id id);
uint32_t zslot_live(const zslot *t);
uint32_t zslot_cap(const zslot *t);

uint32_t zslot_id_index(zslot_id id);
uint32_t zslot_id_generation(zslot_id id);

typedef void (*zslot_visit_fn)(zslot_id id, void *value, void *ctx);

/* Visit every live slot in index order. Returns the number visited. */
uint32_t zslot_each(zslot *t, zslot_visit_fn fn, void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* ZSLOT_H */
