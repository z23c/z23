/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_API_CONTROLLER_COINS_H
#define ZCL_API_CONTROLLER_COINS_H

#include <stddef.h>
#include <stdint.h>

/* GET /api/v1/coins/roots[?count=N][&height=H]
 *
 * Read-only report of block-bound 100-block boundary coin roots (block hash
 * and coins-set commitment recorded by tip_finalize), with the tip and the
 * posture's validation fields. Boundaries that were not recorded, including
 * those finalized while utxo_apply was ahead, are reported as found=false.
 * Equal roots at equal block hashes show two nodes hold the same coin set;
 * they do not prove it correct. `path` is the request path including any query
 * string. Never blocks on cs_main or the progress store: a busy progress store
 * answers 503, an unreadable record 500. */
size_t api_serve_coin_roots(const char *path, uint8_t *response,
                            size_t response_max);

#endif /* ZCL_API_CONTROLLER_COINS_H */
