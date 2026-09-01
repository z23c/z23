/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Failed-row byte readiness for validate_headers.  Kept separate from the
 * stage driver so the hot orchestration file stays within its size ratchet. */

#include "validate_headers_internal.h"

#include "jobs/stage_repair.h"
#include "jobs/stage_repair_internal.h"
#include "validation/chainstate.h"

#include <string.h>

bool validate_headers_recheck_ready(struct sqlite3 *db, int height,
                                    const struct block_index *bi,
                                    const char *reason)
{
    if (!db || height < 0 || !bi || !bi->phashBlock || !reason)
        return false;

    if (strcmp(reason, "header-source-hash-mismatch") == 0)
        return stage_repair_header_solution_available(db, height,
                                                      bi->phashBlock);

    if (strcmp(reason, STAGE_REPAIR_SOLUTIONLESS_REASON) != 0)
        return true;

    /* A solutionless row is a promise of later repair, not runnable work.
     * Re-validating an unchanged empty header cannot alter its verdict; the C3
     * stopwatch measured 58,000 fake advances and 4.1M failed validations from
     * doing exactly that.  Admit it only when the canonical index carries
     * solution bytes or the repair authority has a hash-bound full header.
     * The unchanged validator still decides PoW/Equihash after this predicate. */
    if (bi->nSolution && bi->nSolutionSize > 0)
        return true;
    return stage_repair_header_solution_available(db, height,
                                                  bi->phashBlock);
}
