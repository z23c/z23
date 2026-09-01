/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: findings plan/commit — command-leaf admission for
 * science_findings.v1 wires (acceptance gap G4: findings had no
 * command-leaf admission; only the fixture could seed them). Split out
 * of zcode_science_service.c for the file-size ceiling (E1); shares the
 * plan/commit plumbing declared in zcode_science_service.h. */

#include "services/zcode_science_service.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_science.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct zcl_result zcode_science_findings_plan(
    struct node_db *ndb, const char *workspace,
    const uint8_t *wire, size_t wire_len, int64_t now,
    struct zcode_science_plan_out *out)
{
    (void)workspace;
    struct vcs_zcode_science_findings_v1 findings;
    if (!wire || wire_len != VCS_ZCODE_SCIENCE_FINDINGS_WIRE_BYTES ||
        vcs_zcode_science_findings_parse(wire, wire_len, &findings) !=
            VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_science_findings_validate(&findings) !=
            VCS_ZCODE_SCIENCE_OK)
        return ZCL_ERR(-1, "science-findings-wire-invalid");
    return science_plan_open(ndb, ZCODE_SCIENCE_KIND_FINDINGS, wire,
                             wire_len, NULL, 0, now, out);
}

struct zcl_result zcode_science_findings_commit(
    struct node_db *ndb, const char *workspace,
    const uint8_t *wire, size_t wire_len, bool confirm, int64_t now,
    struct zcode_science_commit_out *out)
{
    if (!workspace || !wire)
        return ZCL_ERR(-1, "science-commit-input-invalid");
    struct db_zcode_science_plan plan;
    bool done = false;
    ZCL_CHECK(science_commit_prelude(ndb, ZCODE_SCIENCE_KIND_FINDINGS, wire,
                                     wire_len, NULL, 0, confirm, now, &plan,
                                     &done, out));
    if (done)
        return ZCL_OK;
    struct vcs_zcode_science_findings_v1 findings;
    uint8_t root[32];
    if (vcs_zcode_science_findings_parse(wire, wire_len, &findings) !=
            VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_science_findings_validate(&findings) !=
            VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_science_findings_root(&findings, root) !=
            VCS_ZCODE_SCIENCE_OK)
        return ZCL_ERR(-1, "science-findings-wire-invalid");
    char root_hex[65];
    zcl_hex_encode(root, 32, root_hex);
    if (!vcs_object_put_addressed(workspace, root, wire, wire_len))
        return ZCL_ERR(-1, "science-findings-cas-store-failed");
    /* Projection row — same mapping as the rebuild loop in
     * zcode_science_service.c (root, study, discussed result, retraction
     * target, severity, flags, sequence, created). */
    struct db_zcode_science_entry row;
    memset(&row, 0, sizeof(row));
    (void)snprintf(row.root, sizeof(row.root), "%s", root_hex);
    zcl_hex_encode(findings.study_root, 32, row.study_root);
    zcl_hex_encode(findings.result_root, 32, row.link_root);
    zcl_hex_encode(findings.retraction_target_root, 32, row.aux_root);
    row.code = findings.severity;
    row.flags = findings.flags;
    row.sequence = (int64_t)findings.sequence;
    row.created_at = findings.created_unix;
    if (!db_zcode_science_findings_save(ndb, &row))
        return ZCL_ERR(-1, "science-findings-projection-save-failed");
    ZCL_CHECK(science_plan_mark_committed(ndb, &plan, root_hex));
    (void)snprintf(out->result_root, sizeof(out->result_root), "%s", root_hex);
    return ZCL_OK;
}
