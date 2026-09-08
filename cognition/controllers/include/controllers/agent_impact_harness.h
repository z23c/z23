/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Root-abstraction routing for test-harness and lint-gate files that the
 * shared AGENT_IMPACT_RULE table (agent_impact_rules.def) cannot reach: that
 * table only fires on compiled-source dependency edges (an #include or a
 * hand-written glob), and a file under tests/harness/src/ or
 * tools/lint/lintc/ is never #included by anything else, so it never earns
 * an edge there. This module adds the two structural conventions that DO
 * cover those files, without adding one row per file to the hand-written
 * table:
 *
 *   1. tests/harness/src/test_<group>.c (or spec_<group>.c) names its own
 *      test group by construction — resolve it straight from the canonical
 *      catalog (tools/dev/test_group_catalog.def) instead of listing it.
 *   2. Any other harness .c file under tests/harness/src/ may still be a
 *      REGISTERED
 *      SOURCE of a Windows acceptance target
 *      (platform/modules/platform/tests/windows_acceptance.mk,
 *      ZCL_WINDOWS_ACCEPTANCE_<name>_SOURCES): that table already records
 *      which .c files each acceptance target links, so membership in it is
 *      read from the table, not re-derived by a second glob list.
 *   3. A harness or lint-gate file that names another source file inside a
 *      string literal (a binary name, a bare path) is evidence that file's
 *      correctness is exercised there even with no #include edge. The
 *      referencing file's OWN group (via rules 1/2 above, or the shared
 *      rule table) is added as a secondary candidate — never as the primary
 *      route. */

#ifndef ZCL_CONTROLLERS_AGENT_IMPACT_HARNESS_H
#define ZCL_CONTROLLERS_AGENT_IMPACT_HARNESS_H

#include <stdbool.h>
#include <stddef.h>

#include "controllers/agent_impact_rules.h"

/* Rule 1: true and fills `out` with the bare group name when `path` is
 * tests/harness/src/test_<group>.c or spec_<group>.c AND that exact ID is
 * registered in the test group catalog. False (out untouched) otherwise —
 * including for a harness file whose name looks like the convention but
 * whose group was never registered, which must stay a real miss rather than
 * a guess. */
bool agent_impact_harness_test_group_name(
    const char *path, char out[static ZCL_AGENT_IMPACT_GROUP_MAX]);

/* Pure parse over an already-read copy of windows_acceptance.mk's text:
 * true when `rel_path` appears as a token inside any
 * `ZCL_WINDOWS_ACCEPTANCE_<name>_SOURCES := ...` assignment (Makefile
 * backslash-newline continuations included). Exposed standalone so tests can
 * drive it with a synthetic table instead of the real file. */
bool agent_impact_windows_acceptance_table_lists(const char *table_text,
                                                 const char *rel_path);

/* True when `needle` occurs inside a C string literal anywhere in `text`
 * (a `"..."` span, backslash-escapes skipped so an escaped quote never ends
 * the span early). Comments and identifiers outside string literals never
 * match, which is what keeps this a "referenced by name" signal rather than
 * an unbounded substring grep. */
bool agent_impact_string_literal_contains(const char *text,
                                          const char *needle);

/* Applies rules 1 and 2 above to `path`, adding the resolved group(s) to
 * `acc` and bumping its match counter. Returns true when at least one group
 * was added. A no-op (returns false) for any path outside
 * tests/harness/src/. */
bool agent_impact_apply_harness_routes(const char *path,
                                       struct agent_impact_acc *acc);

/* Applies rule 3: scans tests/harness/src/ and tools/lint/lintc/ (excluding
 * `path` itself) for a string-literal reference to `path`'s basename, and
 * for every hit adds the referencing file's OWN group(s) (rules 1/2 plus the
 * shared rule table, never this scan recursively) to `acc`. Returns true
 * when at least one secondary candidate was added. A no-op for a basename
 * shorter than the module's noise floor, and — to keep the ~1,300-file scan
 * off the common `code tests` call — for any `path` outside `tools/`, the
 * only place a string literal names a source file by its produced binary
 * rather than an #include edge. */
bool agent_impact_apply_name_reference_routes(const char *path,
                                              struct agent_impact_acc *acc);

#endif
