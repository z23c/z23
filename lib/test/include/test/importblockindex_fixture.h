/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef TEST_IMPORTBLOCKINDEX_FIXTURE_H
#define TEST_IMPORTBLOCKINDEX_FIXTURE_H

#include <stdbool.h>

/* Build one real, hash-bound, proof-of-work-valid legacy blocks/index row
 * for tests that must drive the external --importblockindex CLI. */
bool test_importblockindex_fixture_build_minimal(const char *src_dir);

#endif /* TEST_IMPORTBLOCKINDEX_FIXTURE_H */
