/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Share durable prebinding frontier fixtures between test groups. */
#ifndef ZCL_TEST_REDUCER_PREBINDING_FIXTURE_H
#define ZCL_TEST_REDUCER_PREBINDING_FIXTURE_H
#include <stdbool.h>
#include <stdint.h>
#include <sqlite3.h>
struct block_index;
bool rf_fixture_build_schema(sqlite3 *db);
bool rf_fixture_set_cursor(sqlite3 *db, const char *name, int64_t cursor);
bool rf_fixture_put_utxo_delta(sqlite3 *db, int32_t height, const uint8_t hash[32]);
bool rf_fixture_insert(sqlite3 *db, const char *sql, int height, const uint8_t hash[32]);
bool test_reducer_prebinding_seed(sqlite3 *db, struct block_index *genesis,
    const uint8_t served[32], const uint8_t coins[32]);
bool test_reducer_prebinding_anchor(sqlite3 *db, const uint8_t *hash);
#endif
