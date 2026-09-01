/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Internal seam: split out of consensus_state_bundle_validate.c so that TU
 * stays under the file-size ceiling. Canonical closed-set schema check for
 * external zcl.consensus_state_bundle.v1 files (table/column shapes, exact
 * CREATE TABLE tokens, bundle_meta cardinality). Cheap, O(1) rows — never the
 * O(bundle-size) content scan. */

#ifndef ZCL_CONSENSUS_STATE_BUNDLE_VALIDATE_SCHEMA_H
#define ZCL_CONSENSUS_STATE_BUNDLE_VALIDATE_SCHEMA_H

#include "config/consensus_state_bundle_validate.h"

struct sqlite3;

bool consensus_state_bundle_validate_canonical_schema(
    struct sqlite3 *db, struct consensus_state_install_result *result);

#endif /* ZCL_CONSENSUS_STATE_BUNDLE_VALIDATE_SCHEMA_H */
