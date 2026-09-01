/* zintern — string interning pool (C23).
 *
 * Interning maps each distinct byte string to a dense, stable id
 * (uint32). Ids are never reused and strings are stored once, so
 * equality becomes integer comparison and ids double as indices
 * into side tables — the classic symbol-table pattern for
 * compilers, routers, and log pipelines.
 *
 * The pool owns copies of the interned bytes. Lookup of an existing
 * string is O(len); interning a new string is O(len) amortized.
 * Caller-injected allocation; a zeroed zintern_alloc uses
 * malloc/free. Interning fails cleanly (returns false) on
 * allocation failure with the pool unchanged.
 *
 * Apache-2.0 licensed. No dependencies beyond libc.
 */
#ifndef ZINTERN_H
#define ZINTERN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void *(*malloc_fn)(void *ctx, size_t size);
    void  (*free_fn)(void *ctx, void *ptr);
    void  *ctx;
} zintern_alloc;

typedef struct zintern zintern;

/* A zeroed zintern_alloc selects the hosted malloc/free. */
zintern *zintern_create(zintern_alloc alloc);
void     zintern_destroy(zintern *p);

/* Number of distinct interned strings. */
uint32_t zintern_count(const zintern *p);

/* Intern bytes[0..len); returns the id, or UINT32_MAX on allocation
 * failure (pool unchanged). Empty strings are legal. Ids are
 * assigned densely from 0 in first-intern order. */
uint32_t zintern_put(zintern *p, const void *bytes, size_t len);

/* Look up without inserting; returns UINT32_MAX when absent. */
uint32_t zintern_get(const zintern *p, const void *bytes, size_t len);

/* Recover the bytes for an id. Returns NULL for an out-of-range id.
 * The pointer is valid until zintern_destroy. */
const char *zintern_str(const zintern *p, uint32_t id, size_t *len);

#ifdef __cplusplus
}
#endif

#endif /* ZINTERN_H */
