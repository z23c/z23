/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_home_isolation — no test process may reach the operator's canonical
 * datadir through a default-datadir fallback.
 *
 * GetDefaultDataDir() resolves to $HOME/.zclassic-c23. A test that forgets
 * SetDataDir() therefore lands on the live node's datadir on any host that
 * runs one, and a stage fault there arms <datadir>/auto_reindex_request (a
 * file the next boot consumes). Every test runner entry point calls
 * zcl_test_isolate_environment() once, before any group runs:
 *
 *   - HOME and XDG_CONFIG/DATA/CACHE_HOME point inside a private root, so the
 *     default datadir is <private>/.zclassic-c23;
 *   - every datadir environment variable the node honours is unset;
 *   - ZCL_TEST_HARNESS=1 and ZCL_TEST_CANONICAL_DATADIR=<the real default
 *     datadir> are exported, which the storage-layer writer guard
 *     (storage/boot_auto_reindex.h) reads to refuse a write there;
 *   - ZCL_TEST_DISK_SCRATCH_ROOT=<real cache dir>/zclassic23/test-scratch is
 *     exported when that filesystem is not tmpfs, so block-I/O probes (fsync
 *     on tmpfs never moves ru_oublock) keep a disk-backed directory although
 *     HOME and XDG_CACHE_HOME moved into a possibly tmpfs private root.
 *     Consumers create it lazily; it is unset when no disk root exists.
 *
 * ZCL_TEST_REAL_HOME=1 is the explicit opt-in for the few tests that need
 * real chain or parameter files: HOME is left alone (the writer guard still
 * stands). */

#ifndef ZCL_TEST_HOME_ISOLATION_H
#define ZCL_TEST_HOME_ISOLATION_H

#include <stdbool.h>
#include <stddef.h>

/* Enter the isolated environment rooted at `private_root` (an existing,
 * private directory). A runner nested under an already isolated one keeps the
 * outer ZCL_TEST_CANONICAL_DATADIR. Returns false and fills `err` on failure;
 * the caller must then refuse to run tests. */
bool zcl_test_isolate_environment(const char *private_root,
                                  char *err, size_t err_cap);

/* Runner entry convenience: isolate, or print the reason and exit(2) so no
 * test ever runs un-isolated. */
void zcl_test_isolate_or_exit(const char *runner, const char *private_root);

/* True when this process runs under zcl_test_isolate_environment() with the
 * real HOME replaced. */
bool zcl_test_home_is_private(void);

/* For a test that needs real HOME data (chain files, params): returns true
 * after logging an explicit reason when the test must skip, i.e. HOME is
 * private and ZCL_TEST_REAL_HOME=1 is not set. */
bool zcl_test_real_home_skip(const char *what);

#endif
