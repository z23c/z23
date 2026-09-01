/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_DB_MODEL_SWAP_CONTRACT_H
#define ZCL_DB_MODEL_SWAP_CONTRACT_H

#include "models/database.h"
#include "models/activerecord.h"
#include "script/htlc.h"
#include <stdbool.h>

/* ActiveRecord model: SwapContract (atomic cross-chain HTLC)
 *
 * Record type is `struct swap_contract`; HTLC script building and chain
 * enums live in script/htlc.h, but the at-rest contract row lives here.
 * Validator + callbacks live in engine/models/src/swap_contract.c.
 *
 * This is cross-chain money — the validator is intentionally strict.
 * A malformed swap_contract that reaches the DB risks orphaning funds
 * on the counter-chain when the local node can't reconstruct the
 * redeem path.
 *
 * Validation (db_swap_contract_validate):
 *   - swap_id:           non-empty, hex chars only
 *   - role:              SWAP_INITIATOR or SWAP_PARTICIPANT
 *   - state:             SWAP_PENDING..SWAP_EXPIRED
 *   - chain:             SWAP_CHAIN_ZCL..SWAP_CHAIN_DOGE
 *   - secret_hash:       non-zero
 *   - secret:            non-zero if has_secret set
 *   - amount:            positive (no zero-value swaps)
 *   - locktime:          non-zero (must have a refund deadline)
 *   - my_address:        non-empty
 *   - counter_address:   non-empty
 *   - redeem_script_len: in [1, 256]
 *   - p2sh_address:      non-empty
 *   - created_at:        non-negative
 */

struct swap_contract {
    char     swap_id[65];        /* hex(sha256(initiator+participant+hash)) */
    enum swap_role role;
    enum swap_state state;
    enum swap_chain chain;
    uint8_t  secret_hash[32];
    uint8_t  secret[32];         /* filled on redeem */
    bool     has_secret;
    int64_t  amount;             /* in zatoshis/satoshis */
    uint32_t locktime;
    char     my_address[64];
    char     counter_address[64];
    uint8_t  funding_txid[32];
    uint32_t funding_vout;
    uint8_t  redeem_script[256];
    size_t   redeem_script_len;
    char     p2sh_address[64];
    int64_t  created_at;
};

struct ar_callbacks *db_swap_contract_callbacks(void);
bool db_swap_contract_validate(const struct swap_contract *swap,
                               struct ar_errors *errors);

bool db_swap_save(struct node_db *ndb, const struct swap_contract *swap);
bool db_swap_find(struct node_db *ndb, const char *swap_id,
                  struct swap_contract *out);
int db_swap_list(struct node_db *ndb, struct swap_contract *out,
                 size_t max, int state_filter);
bool db_swap_update_state(struct node_db *ndb, const char *swap_id,
                          enum swap_state state, const uint8_t *secret);

#endif
