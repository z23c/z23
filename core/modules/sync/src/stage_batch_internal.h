/* Internal seam between the stage runner and outer batch lifecycle. */
#ifndef UTIL_STAGE_BATCH_INTERNAL_H
#define UTIL_STAGE_BATCH_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>

/* Enrol one cursor raise in the open outer batch's coalesced LCC proof. */
bool stage_batch_defer_lcc(const char *name, uint64_t old_cursor,
                           uint64_t new_cursor);

#endif
