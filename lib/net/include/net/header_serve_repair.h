/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Bounded header-only repair for snapshot nodes whose local durable stores do
 * not retain an old Equihash solution. A getheaders serve miss arms one global
 * 64-header span. The send loop requests that span from an outbound full peer;
 * msg_headers independently hash-binds and full-PoW verifies every returned
 * candidate before caching it. No block body is requested and no consensus
 * write is delayed. */

#ifndef ZCL_NET_HEADER_SERVE_REPAIR_H
#define ZCL_NET_HEADER_SERVE_REPAIR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct block_index;
struct main_state;
struct msg_processor;
struct p2p_node;

void header_serve_repair_arm(struct main_state *ms,
                             const struct block_index *target);
bool header_serve_repair_wants(const struct block_index *bi);
void header_serve_repair_note_cached(const struct block_index *bi);
void header_serve_repair_maybe_send(struct msg_processor *mp,
                                    struct p2p_node *node,
                                    int64_t now_seconds);

#ifdef ZCL_TESTING
void header_serve_repair_test_reset(void);
bool header_serve_repair_test_armed(void);
size_t header_serve_repair_test_expected_count(void);
size_t header_serve_repair_test_cached_count(void);
#endif

#endif /* ZCL_NET_HEADER_SERVE_REPAIR_H */
