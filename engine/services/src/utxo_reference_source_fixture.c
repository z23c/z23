/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fixture reference source — a deterministic, socket-free reference used by
 * unit tests and the in-process self-reference smoke. It stores a constant
 * commitment (hex + height) in a caller-owned backing struct and hands it
 * back verbatim from commitment_at. exact=true lets a real byte MATCH/DRIFT
 * be exercised without a live oracle; an exact=false fixture (empty hex)
 * exercises the coarse, never-page path.
 */

#include "services/utxo_reference_source.h"

#include "util/log_macros.h"

#include <stddef.h>
#include <string.h>

static struct zcl_result fixture_commitment_at(void *self, int32_t height,
                                               char ref_sha3[65],
                                               int32_t *ref_height)
{
    (void)height; /* the fixture is height-independent by construction */
    struct utxo_reference_source_fixture *fx = self;
    if (!fx || !ref_sha3 || !ref_height)
        return ZCL_ERR(-1, "fixture_commitment_at: null arg");

    /* Copy the constant out. ref_hex is NUL-terminated and capped at 64
     * hex chars (or "") by fixture_init, so this never truncates. */
    snprintf(ref_sha3, 65, "%s", fx->ref_hex);
    *ref_height = fx->ref_height;
    return ZCL_OK;
}

void utxo_reference_source_fixture_init(struct utxo_reference_source *src,
                                        struct utxo_reference_source_fixture *fx,
                                        const char *name,
                                        const char *ref_hex,
                                        int32_t ref_height,
                                        bool exact)
{
    if (!src || !fx)
        return;

    /* Persist the constant in the caller-owned backing store. An exact
     * fixture carries a 64-hex SHA3; a coarse fixture carries "" and the
     * comparator asserts height only. */
    snprintf(fx->ref_hex, sizeof(fx->ref_hex), "%s", ref_hex ? ref_hex : "");
    fx->ref_height = ref_height;

    src->name = name ? name : "fixture";
    src->exact = exact;
    src->commitment_at = fixture_commitment_at;
    src->self = fx;
}
