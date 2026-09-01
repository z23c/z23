/* ztrie — byte-wise string trie (prefix tree) (C23).
 *
 * Keys are arbitrary byte strings. Operations: insert, exact lookup,
 * longest-prefix match, erase, and prefix enumeration. Nodes are
 * linked per child byte (256-way fanout via per-node child lists).
 * Caller-injected allocation; insert returns false on allocation
 * failure with the trie unchanged for the new branch (existing
 * entries untouched).
 *
 * Values are never owned. The key bytes are copied.
 *
 * Apache-2.0 licensed. No dependencies beyond libc.
 */
#ifndef ZTRIE_H
#define ZTRIE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void *(*malloc_fn)(void *ctx, size_t size);
    void  (*free_fn)(void *ctx, void *ptr);
    void   *ctx;
} ztrie_alloc;

typedef struct ztrie ztrie;

/* A zeroed ztrie_alloc selects the hosted malloc/free. */
ztrie *ztrie_create(ztrie_alloc alloc);
void   ztrie_destroy(ztrie *t);

size_t ztrie_len(const ztrie *t); /* number of keys */

/* Insert key[0..key_len) with value. Replaces the value when the key
 * exists (returns true, old value via old_out if given). False only on
 * allocation failure. */
bool ztrie_put(ztrie *t, const void *key, size_t key_len, void *value,
               void **old_out);

/* Exact lookup; NULL when absent (or when the stored value is NULL —
 * use ztrie_contains to distinguish). */
void *ztrie_get(const ztrie *t, const void *key, size_t key_len);
bool  ztrie_contains(const ztrie *t, const void *key, size_t key_len);

/* Longest-prefix match over text: finds the longest key that is a
 * prefix of text[0..text_len). Returns its value (NULL if none) and
 * the matched key length via match_len. */
void *ztrie_longest_prefix(const ztrie *t, const void *text,
                           size_t text_len, size_t *match_len);

/* Erase key; returns the removed value, NULL when absent. Prunes
 * childless nodes. */
void *ztrie_erase(ztrie *t, const void *key, size_t key_len);

/* Visit every key that starts with prefix, in byte-lexicographic
 * order. Return false from the callback to stop early. */
bool ztrie_foreach_prefix(const ztrie *t, const void *prefix,
                          size_t prefix_len,
                          bool (*fn)(const uint8_t *key, size_t key_len,
                                     void *value, void *ctx),
                          void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* ZTRIE_H */
