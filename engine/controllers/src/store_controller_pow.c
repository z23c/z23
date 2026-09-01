/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Store controller — proof-of-work order gate. Split out of
 * store_controller.c to stay under the app/ file-size ceiling (E1);
 * same shape (controller), same translation unit's worth of logic —
 * store_handle_request() in store_controller.c calls
 * store_pow_verify_and_claim() declared in store_controller_internal.h.
 *
 * ── Proof-of-work order gate ─────────────────────────────
 *
 * CSRF (store_controller.c) stops a tricked BROWSER from submitting an
 * order the visitor never intended — it does nothing against a direct
 * attacker with their own client, who can GET a product page, copy its
 * CSRF token, and flood POST /store/orders (or /store/buy/:id): each
 * hit mints a real Sapling z-address (real CPU) and writes an unbounded
 * `orders` row (real disk), all unauthenticated. This gate adds a
 * hashcash-style client puzzle ON TOP of CSRF (CSRF stays the floor,
 * unchanged in store_controller.c).
 *
 * The puzzle is the SHARED primitive, net/puzzle.h — one struct
 * puzzle_gate for this surface, the same implementation the file service
 * and the onion expensive-route tier use. It replaces this file's former
 * pairing of fast_sync_verify_pow() (fixed 20 bits, client-chosen
 * challenge) with a hand-rolled 4096-entry replay ring. What that swap
 * buys, at identical cost to an honest buyer:
 *
 *   - a SERVER-ISSUED, rotating challenge seed, so a flooder can no
 *     longer precompute solutions offline against a challenge it picks
 *     itself (the old peer_id was SHA3 of the product id — a constant);
 *   - LOAD-ADAPTIVE difficulty: the idle floor is pinned at the old fixed
 *     FAST_SYNC_POW_BITS so a quiet node asks a buyer for exactly what it
 *     asked before, and the price rises only while orders are actually
 *     flooding in;
 *   - single-use from the primitive's shared ring, deleting the third
 *     hand-rolled replay table in the tree.
 *
 * peer_token is SHA3-256("store:order:pow:<product_id>"), binding a solved
 * puzzle to one product so it cannot be replayed against another. An
 * honest buyer solves ONE puzzle per order (the browser JS solver lives in
 * contexts/explorer/views/src/store_view.c); a flood pays that CPU cost on every attempt
 * instead of getting mint+DB-write for free.
 *
 * NOTE on client identity: this HTTP surface is Tor-onion-only (see
 * core/modules/net/src/onion_service.c / tor_integration.c — the dynhost bridge
 * carries method/path/body only, no circuit or IP identity reaches the
 * app layer by design), so there is no per-IP axis to cap on. The bound
 * that IS available and meaningful is per-product (see the pending-order
 * caps in store_controller.c) plus the tiered onion budgets in
 * core/modules/net/src/onion_ratelimit.c, which classify /store/orders EXPENSIVE. */

#include "base/hex.h"
#include "controllers/store_controller_internal.h"
#include "net/puzzle.h"

/* Policy for this surface, all in the "never make an honest buyer worse
 * off than yesterday" direction:
 *   - min_bits is the OLD fixed difficulty, so an idle node's price is
 *     bit-for-bit what it was before this file moved onto the gate;
 *   - max_bits 24 (16x the floor) is the saturated ceiling — a browser JS
 *     solver is the client here, not a C sync peer, so the primitive's
 *     own 26-bit ceiling is too steep;
 *   - soft_rate 2 accepted orders/sec before the ramp starts: real store
 *     traffic is human-paced, and the onion EXPENSIVE budget already caps
 *     this route at 20 req/s;
 *   - a 180 s seed epoch, which with the primitive's one-epoch grace keeps
 *     a rendered page solvable for up to six minutes — longer than a slow
 *     Tor round trip plus a slow in-browser solve;
 *   - ts_skew 300 s, preserving fast_sync_verify_pow's old backward
 *     tolerance so a page that sat open still submits. */
static struct puzzle_gate g_store_pow_gate;
static pthread_once_t g_store_pow_once = PTHREAD_ONCE_INIT;

static const struct puzzle_policy g_store_pow_policy = {
    .min_bits          = FAST_SYNC_POW_BITS,
    .max_bits          = 24,
    .soft_rate_per_sec = 2,
    .rate_step_per_sec = 1,
    .seed_rotate_secs  = 180,
    .ts_skew_secs      = 300,
};

static void store_pow_gate_init_once(void)
{
    puzzle_gate_init(&g_store_pow_gate, &g_store_pow_policy);
}

/* pthread_once, not a "did I init yet" flag: a flag published before
 * puzzle_gate_init() returns lets a second thread fall through to the
 * gate's own lazy default init and race it. */
static void store_pow_gate_ready(void)
{
    pthread_once(&g_store_pow_once, store_pow_gate_init_once);
}

static void store_pow_bind_product(int64_t product_id, uint8_t out[32])
{
    char ctx[64];
    snprintf(ctx, sizeof(ctx), "store:order:pow:%lld", (long long)product_id);
    sha3_256((const unsigned char *)ctx, strlen(ctx), out);
}

/* Public: the live challenge for one product, for the view layer to embed
 * in the order form. The client hashes SHA3-256(seed || token || ts ||
 * nonce) itself — see the JS solver in contexts/explorer/views/src/store_view.c — so it
 * needs the server's current seed and difficulty, not just the
 * product-bound token. Mirrors store_csrf_token/store_csrf_context's
 * split: security-relevant derivation stays in the controller, the view
 * only embeds the result.
 *
 * Every call is a real challenge issuance: it rotates the seed when the
 * epoch has elapsed and re-reads the adaptive difficulty, so a page
 * rendered during a flood quotes the flood price. */
void store_pow_challenge(int64_t product_id, struct store_pow_challenge *out)
{
    uint8_t seed[32], token[32];
    int bits = 0;
    int64_t server_time = 0;

    if (!out)
        return; // raw-return-ok:nothing-to-fill-caller-passed-no-output-buffer

    memset(out, 0, sizeof(*out));
    store_pow_gate_ready();
    puzzle_gate_challenge(&g_store_pow_gate, seed, &bits, &server_time);
    store_pow_bind_product(product_id, token);

    zcl_hex_encode(seed, 32, out->seed_hex);
    zcl_hex_encode(token, 32, out->token_hex);
    out->bits = bits;
    out->server_time = server_time;
}

/* Verify + claim in one step. Returns true only for a solution that (a)
 * parses, (b) is within the timestamp window, (c) solves the LIVE
 * challenge for this product at the current difficulty (or the one-epoch
 * grace seed), and (d) has not been used before. Nothing is recorded for a
 * failed verify — only a genuinely solved puzzle consumes a single-use
 * slot, so a flood of unsolved guesses cannot evict real buyers from the
 * ring. Declared in store_controller_internal.h; called from
 * store_handle_request() in store_controller.c. */
bool store_pow_verify_and_claim(int64_t product_id,
                                const char *pow_ts_str,
                                const char *pow_nonce_str)
{
    uint8_t token[32];
    char *end = NULL;
    long long ts;
    unsigned long long nonce;

    if (!pow_ts_str || !pow_ts_str[0] || !pow_nonce_str || !pow_nonce_str[0])
        return false; // raw-return-ok:missing-puzzle-fields-refused-not-a-server-error

    ts = strtoll(pow_ts_str, &end, 10);
    if (!end || *end != '\0')
        return false; // raw-return-ok:malformed-client-field-not-a-server-error
    end = NULL;
    nonce = strtoull(pow_nonce_str, &end, 10);
    if (!end || *end != '\0')
        return false; // raw-return-ok:malformed-client-field-not-a-server-error

    store_pow_gate_ready();
    store_pow_bind_product(product_id, token);
    return puzzle_gate_verify(&g_store_pow_gate, token,
                              (int64_t)ts, (uint64_t)nonce);
}

/* Test-only: drop every issued seed and every claimed solution. Lets a
 * test file exercise the gate from a known-clean state without depending
 * on the order its cases happen to run in. */
void store_pow_reset_state(void)
{
    store_pow_gate_ready();
    puzzle_gate_init(&g_store_pow_gate, &g_store_pow_policy);
}
