/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-doc-claims (gate_doc_claims.c). Runs the
 * full pre-scan self-check (gate_doc_claims_selfcheck.c): known-good and
 * known-bad claim fixtures in every predicate direction, fenced examples
 * skipped, malformed annotations reported, positive-reliance phrases
 * rejected without banning precise terminology, verdict reuse/fallback/
 * unlisted/once-per-gate/memo behavior, and the --global/--doc split
 * being disjoint and complete. Prints the PASS block on success.
 */
#include <stdio.h>
#include "lintc.h"
#include "gate_doc_claims_priv.h"

int check_doc_claims_selftest(void)
{
    int rc = dc_selfcheck();
    if (rc)
        return rc;
    printf("check_doc_claims: selftest PASS — evaluator fires in both "
           "directions\n");
    printf("  (file-present/absent, symbol-present/absent, "
           "gate-passes/fails,\n");
    printf("   fenced examples skipped, malformed annotations reported,\n");
    printf("   positive-reliance phrases rejected without banning precise "
           "terms,\n");
    printf("   the --global and --doc parts disjoint and together the plain "
           "run)\n");
    return 0;
}
