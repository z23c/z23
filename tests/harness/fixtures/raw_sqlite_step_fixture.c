/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fixture for `test_make_lint_gates` — intentionally contains a raw
 * `sqlite3_step()` with no `// raw-sql-ok` annotation and no AR_STEP
 * wrapper. The lint-gate self-test copies this file into `app/` under
 * a unique name, runs `make check-raw-sqlite`, and asserts the grep
 * catches it (exit code 1). If someone loosens the grep pattern, this
 * test fails.
 *
 * This file lives under tests/harness/fixtures so the normal lint pass
 * (which excludes `test/`) doesn't see it.
 */

#include <sqlite3.h>

int fixture_raw_step(sqlite3_stmt *stmt);

int fixture_raw_step(sqlite3_stmt *stmt)
{
    return sqlite3_step(stmt);
}
