/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: make a keyed z_sendmany spend at most once. */

#ifndef ZCL_CONTROLLERS_WALLET_SEND_ONCE_H
#define ZCL_CONTROLLERS_WALLET_SEND_ONCE_H

#include "util/result.h"

#include <stdbool.h>

struct json_value;
struct uint256;

/* Optional fifth z_sendmany parameter: the caller's idempotency key. */
#define WALLET_SEND_ONCE_KEY_PARAM 4
/* Optional fourth z_sendmany parameter: the fee the plan quoted. */
#define WALLET_SEND_ONCE_FEE_PARAM 3

/* A run that failed before the wallet admitted any transaction answers
 * {"state":"released","message":...}: nothing was sent and the key is free.
 * The native handler maps it to this code. A moved fee answers fee_changed
 * with the key free. A built record that cannot be written before admission
 * refuses the send and answers released, because nothing was sent. Once a
 * transaction may have reached the pool the answer is outcome_unknown and the
 * key is held. A record that cannot be read or created, and a full table,
 * refuse the call with a plain error string that does not claim the key is
 * free. */
#define WALLET_SEND_ONCE_STATE_RELEASED "released"
#define WALLET_SEND_ONCE_STATE_FEE_CHANGED "fee_changed"
#define WALLET_SEND_ONCE_CODE_RELEASED "SEND_REFUSED_KEY_RELEASED"

/* 1..128 characters of letters, digits and . _ : - */
bool wallet_send_once_key_valid(const char *key);

typedef bool (*wallet_send_once_fn)(const struct json_value *params, bool help,
                                    struct json_value *result);

/* Run `plain` for an unkeyed call, unchanged. For a keyed call the row for the
 * key is read first. A key with no row is checked against the planned fee,
 * recorded, and `plain` runs at most once for it. The answer is an object
 * {"state":..., "txid":..., "replayed":...}.
 *   committed        the send finished; replayed only while the wallet still
 *                    holds the transaction
 *   in_progress      another request holds the key
 *   outcome_unknown  a transaction may exist (txid given when known); never
 *                    resent. Covers a recorded transaction that was not
 *                    confirmed as relayed, a committed one the wallet no
 *                    longer holds, and any failure after the wallet admitted
 *                    the transaction (the pool may have held it and a peer
 *                    may have fetched it, so it can still confirm). Also a row
 *                    whose digest matches only this request's legacy digest,
 *                    the form an earlier build stored, in any state and with no
 *                    txid: that digest cannot say this exact request was sent.
 *                    Likewise a request whose legacy digest cannot be recomputed
 *   key_conflict     same key, different parameters
 *   released         nothing was admitted; the key is free (state released)
 *   fee_changed      the planned fee differs from the wallet fee; key free
 * A row marked only built is never answered as committed, even when the wallet
 * holds the transaction: holding is not relaying. Rebroadcasting held,
 * unrelayed transactions at boot is a separate follow-up. A refusal returns
 * false with an explanatory string and never claims the key is free unless
 * the state is released or fee_changed. Retention uses wall-clock time: a
 * forward clock jump ages rows early. The record lives in node.db and cannot
 * outlive it: after a database loss or restore an earlier key is not
 * recognized. */
bool wallet_send_once_dispatch(const struct json_value *params, bool help,
                               wallet_send_once_fn plain,
                               struct json_value *result);

/* Called by wallet_commit_from_context with the finished transaction id,
 * before the wallet admits it. Inside a keyed send it makes the txid durable
 * (synchronous=FULL, in its own transaction) and refuses a second transaction
 * for the same key; elsewhere it is a no-op. A failure refuses the commit. */
struct zcl_result wallet_send_once_before_commit(const struct uint256 *txid);

/* Called after the admission attempt. Once admitted is true the key is never
 * released, whatever fails later. */
void wallet_send_once_after_commit(bool admitted);

#endif
