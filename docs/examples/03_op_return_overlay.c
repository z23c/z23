/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * 03_op_return_overlay — OP_RETURN data-carrier transactions through the
 * deterministic simulator.
 *
 * WHAT THIS DEMONSTRATES
 * -----------------------
 * An `OP_RETURN` output is a scriptPubKey whose FIRST opcode is OP_RETURN.
 * Bitcoin-family consensus (and this codebase, see
 * `script/script.h:script_is_unspendable`) treats any such output as
 * PROVABLY UNSPENDABLE: it can never be redeemed, so a full node does not
 * need to keep it in the live UTXO set. What a node DOES keep, forever, is
 * the raw transaction bytes inside the mined block — so an OP_RETURN output
 * is a place to nail arbitrary bytes to the chain's permanent history
 * without ever bloating the spendable-coin working set.
 *
 * That one primitive — "push bytes after OP_RETURN, pay a normal fee, mine
 * it" — is the ENTIRE substrate z23's overlay protocols are built on:
 *   - ZNAM (on-chain name registry, contexts/naming/modules/znam/) tags its payload with the
 *     4-byte Lokad ID "ZNAM" (znam.h: ZNAM_LOKAD_BYTES) followed by a
 *     command byte and command-specific fields.
 *   - ZSLP (token protocol, contexts/market/modules/zslp/) does the same with Lokad ID "SLP\0"
 *     (slp.h: SLP_LOKAD_BYTES).
 * Neither protocol needs a new opcode or a soft fork: they are just
 * agreed-upon BYTE LAYOUTS inside an OP_RETURN payload, parsed by an
 * application-layer indexer that watches the chain. This example builds
 * that primitive by hand, with a ZNAM-shaped payload, but stops short of
 * calling the real znam.h encoder — see the "Production counterpart" note
 * at the bottom for where that lives.
 *
 * MENTAL MODEL
 * ------------
 * `simnet` (engine/modules/sim/) builds real transactions and feeds them through the
 * REAL consensus function `connect_block()` against an in-RAM UTXO set — no
 * disk, no real PoW, no real funds, but genuine consensus validation. This
 * program:
 *   1. funds a wallet and mines it to spendable maturity,
 *   2. builds a value-less OP_RETURN carrier tx and reads its payload back
 *      OUT of the actual queued transaction bytes before it is mined,
 *   3. mines it, then proves the OP_RETURN output is NOT a spendable coin
 *      (pruned from the UTXO set) while its sibling change output IS,
 *   4. builds a second carrier that pairs a ZNAM-shaped payload with a real
 *      value transfer in the same transaction — the same shape a real
 *      "register a name and pay a fee" transaction uses.
 *
 * Everything is deterministic: one seed tape drives both the wallet keys
 * (RNG hook) and the virtual block clock (clock hook), so this program
 * produces byte-identical txids/fees/sizes on every run.
 *
 * BUILD / RUN
 * -----------
 *   make -C examples && ./examples/bin/03_op_return_overlay
 *
 * See docs/cookbook/03_op_return_overlay.md for expected output and API
 * notes.
 */

#include "core/amount.h"
#include "core/uint256.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "sim/seed_tape.h"
#include "sim/simnet.h"
#include "sim/simnet_mempool.h"
#include "sim/simnet_wallet.h"
#include "chain/chainparams.h"
#include "chain/chainparamsbase.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Parse a script generically with script_get_op (script/script.h), the same
 * walker connect_block's script interpreter and every indexer use to read
 * pushed bytes back out of a scriptPubKey. For an OP_RETURN carrier the
 * shape is always: [OP_RETURN] [one length-prefixed data push]. Returns
 * false if the script is not that exact shape. */
static bool read_op_return_payload(const struct script *s,
                                    uint8_t *out, size_t out_cap,
                                    size_t *out_len)
{
    size_t pc = 0;
    enum opcodetype op;
    if (!script_get_op(s, &pc, &op, NULL, NULL) || op != OP_RETURN)
        return false;
    if (pc >= s->size) { /* no payload push (empty OP_RETURN) is valid too */
        *out_len = 0;
        return true;
    }
    size_t datalen = 0;
    if (!script_get_op(s, &pc, &op, out, &datalen) || datalen > out_cap)
        return false;
    *out_len = datalen;
    return true;
}

/* Print one result row in the same shape docs/SIMULATOR_TXNS.md's cost
 * table uses, so learners can cross-reference measured fee/size. */
static void print_result(const char *label, const struct simnet_tx_result *r)
{
    char hex[65];
    uint256_get_hex(&r->txid, hex);
    printf("    %-28s txid=%s fee=%lld zats size=%zu bytes\n", label, hex,
           (long long)r->fee, r->tx_size);
}

int main(void)
{
    /* Fixed seed => byte-identical wallet keys, addresses, txids, fees, and
     * sizes on every run (docs/SIMULATOR.md "the simulator is deterministic"). */
    seed_tape_t *tape = seed_tape_open(0x03524554414B4954ULL, 1700000000);
    assert(tape != NULL);
    seed_tape_install(tape);

    /* Select a chain network before any chain/consensus/script code runs —
     * connect_block, coinbase subsidy, and address encoding all read their
     * parameters through chain_params_get(), which asserts one was chosen. */
    chain_params_select(CHAIN_MAIN);

    struct simnet sim;
    assert(simnet_init(&sim));
    simnet_use_seed_tape(&sim, tape);

    struct simnet_wallet *alice = simnet_wallet_create(&sim);
    struct simnet_wallet *bob = simnet_wallet_create(&sim);
    assert(alice && bob);

    printf("=== 03_op_return_overlay: OP_RETURN as a provably-unspendable "
           "data carrier ===\n");

    /* [1/4] Fund alice with one matured coinbase. simnet_wallet_fund mints
     * the coinbase then mines COINBASE_MATURITY (100) empty blocks so the
     * coin is real spendable value under the same predicate connect_block
     * enforces on the live chain — no shortcut. */
    printf("[1/4] minting a coinbase to alice, mining 100 blocks to"
           " maturity...\n");
    struct simnet_tx_result fund1;
    assert(simnet_wallet_fund(alice, 120000, &fund1));
    assert(simnet_wallet_balance(alice) == 120000);

    /* [2/4] Build a pure data-carrier OP_RETURN tx: no recipient, just
     * bytes. simnet_wallet_op_return builds the tx and enqueues it into the
     * sim's FIFO mempool (a deep copy, see simnet_mempool.h) — it is NOT
     * mined yet, so `sim.mempool_txs[sim.mempool_count - 1]` is the exact
     * transaction that WILL be mined, letting us read the payload back out
     * of the real queued bytes before it ever touches connect_block(). */
    printf("[2/4] building an OP_RETURN data carrier, reading the payload"
           " back BEFORE mining...\n");
    const uint8_t payload[] = { 'h', 'e', 'l', 'l', 'o', ',', ' ',
                                'c', 'h', 'a', 'i', 'n' };
    struct simnet_tx_result opret_only;
    assert(simnet_wallet_op_return(alice, payload, sizeof(payload), NULL,
                                   &opret_only));
    assert(sim.mempool_count >= 1);
    const struct transaction *queued = &sim.mempool_txs[sim.mempool_count - 1];
    assert(queued->num_vout >= 1);

    uint8_t recovered[MAX_SCRIPT_ELEMENT_SIZE];
    size_t recovered_len = 0;
    assert(read_op_return_payload(&queued->vout[0].script_pub_key,
                                  recovered, sizeof(recovered),
                                  &recovered_len));
    assert(recovered_len == sizeof(payload));
    assert(memcmp(recovered, payload, recovered_len) == 0);
    printf("    recovered payload (%zu bytes): \"%.*s\"\n", recovered_len,
           (int)recovered_len, recovered);
    print_result("OP_RETURN data carrier", &opret_only);

    /* [3/4] Mine it, then prove the consensus-level split: the OP_RETURN
     * output (vout 0) is provably unspendable, so connect_block's
     * coins_from_transaction() never adds it to the live UTXO set — but
     * the change output (opret_only.change_vout) IS ordinary spendable
     * value. The DATA is permanent in the mined block bytes; it just never
     * becomes a coin. */
    printf("[3/4] mining the carrier; confirming the OP_RETURN vout is"
           " pruned from the UTXO set while change is spendable...\n");
    assert(simnet_mempool_mint(&sim));
    int64_t unused_value = 0;
    assert(!simnet_coin_value(&sim, &opret_only.txid, 0, &unused_value));
    assert(opret_only.change_vout != UINT32_MAX);
    int64_t change_value = 0;
    assert(simnet_coin_value(&sim, &opret_only.txid, opret_only.change_vout,
                             &change_value));
    printf("    vout 0 (OP_RETURN) spendable=false;"
           " vout %u (change) spendable=true value=%lld zats\n",
           opret_only.change_vout, (long long)change_value);

    /* [4/4] The overlay pattern: pair a Lokad-tagged payload (the ZNAM
     * on-chain name registry uses the 4-byte tag "ZNAM", see
     * contexts/naming/modules/znam/include/znam/znam.h) with a REAL value output in the same
     * transaction — exactly the shape "register a name and pay a fee" or
     * "mint a token and move it" needs. This example only builds the raw
     * bytes by hand; it does not call the real znam.h encoder (see the
     * production-counterpart note below for that entry point). */
    printf("[4/4] building a Lokad-tagged overlay payload"
           " ('ZNAM' + fields) alongside a real value transfer to bob...\n");
    const uint8_t znam_payload[] = {
        'Z', 'N', 'A', 'M',       /* Lokad ID: identifies the protocol */
        0x01,                     /* command byte: 1 == REGISTER */
        6, 'a','l','i','c','e','z' /* length-prefixed name field */
    };
    struct simnet_tx_result fund2;
    assert(simnet_wallet_fund(alice, 60000, &fund2));
    struct simnet_wallet_recipient pay_bob = { .wallet = bob, .amount = 25000 };
    struct simnet_tx_result opret_with_value;
    assert(simnet_wallet_op_return(alice, znam_payload, sizeof(znam_payload),
                                   &pay_bob, &opret_with_value));
    assert(simnet_mempool_mint(&sim));
    assert(simnet_wallet_balance(bob) == 25000);
    print_result("OP_RETURN + value (ZNAM-shaped)", &opret_with_value);

    printf("\ntip height = %d\n", simnet_tip_height(&sim));

    simnet_wallet_free(alice);
    simnet_wallet_free(bob);
    simnet_free(&sim);
    seed_tape_uninstall();
    seed_tape_close(tape);

    printf("=== SUCCESS: built OP_RETURN data carriers, read them back "
           "pre-mine, and verified them through connect_block() ===\n");
    return 0;
}

/* Production counterpart:
 * ------------------------
 * The simnet wallet helper here (simnet_wallet_op_return) is a teaching
 * stand-in for the real node's OP_RETURN construction, which builds the
 * same shape against the live wallet and broadcasts it instead of minting
 * into an in-RAM view:
 *
 *   - Generic OP_RETURN + value transaction assembly:
 *       wallet_create_transaction() / wallet_create_transaction_multi()
 *       in contexts/wallet/modules/wallet/include/wallet/wallet.h
 *   - ZNAM (name registry) OP_RETURN encoding + commit:
 *       rpc_name_register()  in engine/controllers/src/name_controller.c
 *       (builds the "ZNAM" Lokad-tagged script; see contexts/naming/modules/znam/include/znam/znam.h
 *       for the full field layout: ZNAM_LOKAD_BYTES + ZNAM_CMD_* + fields)
 *   - ZSLP (token protocol) OP_RETURN encoding + commit:
 *       zslp_command_commit_with_op_return()
 *       in contexts/market/services/include/services/zslp_command_service.h
 *       (builds the "SLP\0" Lokad-tagged script; see contexts/market/modules/zslp/include/zslp/slp.h)
 *
 * Both protocols are read back the same way this example does: parse the
 * scriptPubKey with script_get_op(), check the Lokad ID, then decode the
 * protocol-specific fields — the only difference from this example's
 * read_op_return_payload() is which 4 bytes it checks for after OP_RETURN.
 */
