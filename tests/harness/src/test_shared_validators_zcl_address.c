/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Focused coverage for zcl_validate_zcl_address()
 * (engine/models/src/shared_validators.c).
 *
 * This validator is referenced from two controllers (via the
 * `validates_zcl_address` model macro) but had zero direct test
 * coverage anywhere in tests/harness/src before this file: its own novel
 * logic — a charset gate (alnum + underscore only, meant to block XSS
 * via address echo), then a length-gated prefix dispatch to either the
 * transparent Base58Check decoder or the Sapling bech32 decoder — was
 * completely unpinned, independent of whether the underlying
 * decode_destination / sapling_decode_payment_address codecs are
 * exercised elsewhere (they are, via test_test_key_io_codec.c and the
 * sapling test group).
 *
 * Read from engine/models/src/shared_validators.c (current source):
 *
 *   bool zcl_validate_zcl_address(const char *addr)
 *   {
 *       if (!addr || !addr[0]) return false;
 *       size_t len = strlen(addr);
 *       for (i = 0; i < len; i++) {           // charset gate
 *           ok = alnum || '_';
 *           if (!ok) return false;
 *       }
 *       if (addr[0]=='t' && len>=26 && len<=36) {  // transparent arm
 *           ... return decode_destination(...);    // active-chain prefixes
 *       }
 *       if (strncmp(addr, active_hrp, hrp_len)==0 && addr[hrp_len]=='1') {
 *           ... return sapling_decode_payment_address(...);
 *       }
 *       return false;
 *   }
 *
 * Two control-flow details this file pins directly:
 *
 *   1. In the transparent arm, only `addr[0]` is read before the length
 *      check, so a 1-char string like "t" never touches addr[1] at all
 *      (the pre-2026-08 arm compared addr[1] against '1'/'3' first,
 *      which was still a safe in-bounds read of the NUL terminator).
 *      Every ZCL-family transparent address begins with 't', so the
 *      pre-filter loses nothing; decode_destination then enforces the
 *      ACTIVE chain's version bytes — t1/t3 under CHAIN_MAIN, exactly
 *      as before, so every outcome pinned below is unchanged.
 *
 *   2. In the Sapling arm, the prefix compared is the ACTIVE chain's
 *      bech32 HRP ("zs" under CHAIN_MAIN) plus the '1' separator, and
 *      `len > hrp_len` guards the addr[hrp_len] read, so a short string
 *      beginning with 'z' never reaches an out-of-bounds index. Under
 *      CHAIN_MAIN this is the same "zs1" gate as before.
 *
 * Pure and deterministic: no clock, no RNG, no network, no live DB.
 * Uses only the mainnet Base58Check version-prefix bytes (via
 * chain_params_get(), matching CHAIN_MAIN which test_parallel.c's
 * per-child setup and test.c's main() both select before any group
 * runs) and the Sapling bech32 payment-address codec, both of which
 * are pure codecs with no side effects. */

#include "test/test_core.h"

#include "models/shared_validators.h"
#include "keys/key_io.h"
#include "chain/chainparams.h"
#include "wallet/sapling_keys.h"
#include "script/standard.h"

#include <string.h>

/* Write `prefix` at the start of `buf`, pad the rest up to (but not
 * including) `total_len` with `fillch`, and NUL-terminate at
 * `total_len`. `buf` must be sized >= total_len + 1. Lets boundary
 * tests hit an EXACT string length without hand-counting fill
 * characters in a literal. */
static void tsv_fill_len(char *buf, size_t total_len, const char *prefix, char fillch)
{
    size_t pfx_len = strlen(prefix);
    memcpy(buf, prefix, pfx_len);
    for (size_t i = pfx_len; i < total_len; i++)
        buf[i] = fillch;
    buf[total_len] = '\0';
}

int test_shared_validators_zcl_address(void);
int test_shared_validators_zcl_address(void)
{
    int failures = 0;

    /* chain_params_select is idempotent — make CHAIN_MAIN active
     * regardless of which runner/order invoked this group, since the
     * validator's t1/t3 arm reads the currently-selected chain's
     * version-prefix bytes via chain_params_get(). */
    chain_params_select(CHAIN_MAIN);

    /* ── NULL / empty: rejected before the charset loop ──────────── */

    TEST("zcl_validate_zcl_address: NULL returns false") {
        ASSERT(!zcl_validate_zcl_address(NULL));
        PASS();
    }

    TEST("zcl_validate_zcl_address: empty string returns false") {
        ASSERT(!zcl_validate_zcl_address(""));
        PASS();
    }

    /* ── Happy path: real, decodably-valid addresses ─────────────── */

    const struct chain_params *cp = chain_params_get();
    size_t pk_len = 0, sc_len = 0;
    const unsigned char *pk_pfx = chain_params_base58_prefix(cp, B58_PUBKEY_ADDRESS, &pk_len);
    const unsigned char *sc_pfx = chain_params_base58_prefix(cp, B58_SCRIPT_ADDRESS, &sc_len);

    char t1_addr[64];
    TEST("zcl_validate_zcl_address: accepts a real t1 (P2PKH) address") {
        struct tx_destination dest;
        dest.type = DEST_KEY_ID;
        memset(dest.id.key.id.data, 0x11, 20);
        ASSERT(encode_destination(&dest, pk_pfx, pk_len, sc_pfx, sc_len, t1_addr, sizeof(t1_addr)));
        ASSERT_EQ(t1_addr[0], 't');
        ASSERT_EQ(t1_addr[1], '1');
        size_t n = strlen(t1_addr);
        /* Confirms the naturally-occurring encoded length actually
         * lands inside the [26,36] gate this validator enforces —
         * otherwise the "happy path decodes true" claim below would
         * be vacuous. */
        ASSERT(n >= 26 && n <= 36);
        ASSERT(zcl_validate_zcl_address(t1_addr));
        PASS();
    }

    char t3_addr[64];
    TEST("zcl_validate_zcl_address: accepts a real t3 (P2SH) address") {
        struct tx_destination dest;
        dest.type = DEST_SCRIPT_ID;
        memset(dest.id.script.hash.data, 0xAB, 20);
        ASSERT(encode_destination(&dest, pk_pfx, pk_len, sc_pfx, sc_len, t3_addr, sizeof(t3_addr)));
        ASSERT_EQ(t3_addr[0], 't');
        ASSERT_EQ(t3_addr[1], '3');
        size_t n = strlen(t3_addr);
        ASSERT(n >= 26 && n <= 36);
        ASSERT(zcl_validate_zcl_address(t3_addr));
        PASS();
    }

    /* Corrupted-checksum t1 address: same length, same prefix, still
     * inside the [26,36] gate, but decode_destination must reject it —
     * proves the t1/t3 arm genuinely calls the decoder rather than
     * returning true for anything shaped like an address. */
    TEST("zcl_validate_zcl_address: rejects a t1 address with a corrupted checksum") {
        char bad[64];
        strcpy(bad, t1_addr);
        size_t n = strlen(bad);
        bad[n - 1] = (bad[n - 1] == 'A') ? 'B' : 'A';
        ASSERT(!zcl_validate_zcl_address(bad));
        PASS();
    }

    char zs1_addr[128];
    TEST("zcl_validate_zcl_address: accepts a real zs1 (Sapling) address") {
        uint8_t diversifier[ZC_DIVERSIFIER_SIZE];
        uint8_t pk_d[32];
        memset(diversifier, 0x22, sizeof(diversifier));
        memset(pk_d, 0x33, sizeof(pk_d));
        ASSERT(sapling_encode_payment_address(diversifier, pk_d, "zs", zs1_addr, sizeof(zs1_addr)));
        ASSERT_EQ(zs1_addr[0], 'z');
        ASSERT_EQ(zs1_addr[1], 's');
        ASSERT_EQ(zs1_addr[2], '1');
        size_t n = strlen(zs1_addr);
        /* Confirms the natural bech32 encoding of an 11+32-byte
         * payload under a 2-char HRP lands >= 70, i.e. actually
         * inside this validator's zs1 length gate. */
        ASSERT(n >= 70);
        ASSERT(zcl_validate_zcl_address(zs1_addr));
        PASS();
    }

    TEST("zcl_validate_zcl_address: rejects a zs1 address with a corrupted checksum") {
        char bad[128];
        strcpy(bad, zs1_addr);
        size_t n = strlen(bad);
        bad[n - 1] = (bad[n - 1] == 'q') ? 'p' : 'q';
        ASSERT(!zcl_validate_zcl_address(bad));
        PASS();
    }

    /* ── Charset gate: one disallowed char anywhere rejects up front ── */

    TEST("zcl_validate_zcl_address: rejects a space injected into an otherwise-valid t1 address") {
        char bad[64];
        strcpy(bad, t1_addr);
        bad[5] = ' ';
        ASSERT(!zcl_validate_zcl_address(bad));
        PASS();
    }

    TEST("zcl_validate_zcl_address: rejects a hyphen injected into an otherwise-valid t1 address") {
        char bad[64];
        strcpy(bad, t1_addr);
        bad[5] = '-';
        ASSERT(!zcl_validate_zcl_address(bad));
        PASS();
    }

    TEST("zcl_validate_zcl_address: rejects a slash injected into an otherwise-valid t1 address") {
        char bad[64];
        strcpy(bad, t1_addr);
        bad[5] = '/';
        ASSERT(!zcl_validate_zcl_address(bad));
        PASS();
    }

    TEST("zcl_validate_zcl_address: rejects a '<' injected into an otherwise-valid t1 address (XSS char)") {
        char bad[64];
        strcpy(bad, t1_addr);
        bad[5] = '<';
        ASSERT(!zcl_validate_zcl_address(bad));
        PASS();
    }

    TEST("zcl_validate_zcl_address: rejects a '\"' injected into an otherwise-valid t1 address (XSS char)") {
        char bad[64];
        strcpy(bad, t1_addr);
        bad[5] = '"';
        ASSERT(!zcl_validate_zcl_address(bad));
        PASS();
    }

    TEST("zcl_validate_zcl_address: rejects an underscore injected into an otherwise-valid t1 address") {
        /* Underscore IS allowed by the charset gate itself (it exists
         * specifically to also admit zs1-shaped strings that only use
         * alnum, so the gate is deliberately a superset of both real
         * alphabets) — but it is never a valid Base58Check symbol, so
         * this must still be rejected, just one step later, by
         * decode_destination rather than by the charset loop. Distinct
         * from the disallowed-char cases above, which are rejected by
         * the charset loop itself before any decode is attempted. */
        char bad[64];
        strcpy(bad, t1_addr);
        bad[5] = '_';
        ASSERT(!zcl_validate_zcl_address(bad));
        PASS();
    }

    /* ── "t2...": reaches the decoder, fails mainnet version bytes ──── */

    TEST("zcl_validate_zcl_address: rejects a t2-prefixed string (neither t1 nor t3)") {
        char buf[40];
        tsv_fill_len(buf, 35, "t2", 'A');
        ASSERT(!zcl_validate_zcl_address(buf));
        PASS();
    }

    TEST("zcl_validate_zcl_address: rejects a t0-prefixed string of in-range length") {
        char buf[40];
        tsv_fill_len(buf, 30, "t0", 'A');
        ASSERT(!zcl_validate_zcl_address(buf));
        PASS();
    }

    /* ── 1-2 char strings beginning with 't': addr[1] read safely ──── */

    TEST("zcl_validate_zcl_address: 1-char \"t\" does not crash and returns false") {
        /* addr[1] here is the string's own NUL terminator: an
         * in-bounds read that correctly fails the '1'/'3' comparison
         * (see file header, point 1). */
        ASSERT(!zcl_validate_zcl_address("t"));
        PASS();
    }

    TEST("zcl_validate_zcl_address: 2-char \"t1\" is too short for the t-address gate") {
        ASSERT(!zcl_validate_zcl_address("t1"));
        PASS();
    }

    TEST("zcl_validate_zcl_address: 2-char \"t3\" is too short for the t-address gate") {
        ASSERT(!zcl_validate_zcl_address("t3"));
        PASS();
    }

    TEST("zcl_validate_zcl_address: 1-char \"z\" does not crash and returns false") {
        /* len(1) < 70 short-circuits the zs1 arm's `len>=70` guard
         * before addr[1]/addr[2] are ever read (see file header,
         * point 2). */
        ASSERT(!zcl_validate_zcl_address("z"));
        PASS();
    }

    TEST("zcl_validate_zcl_address: 2-char \"zs\" does not crash and returns false") {
        ASSERT(!zcl_validate_zcl_address("zs"));
        PASS();
    }

    /* ── t1/t3 length boundaries: exactly 25 / 26 / 36 / 37 ─────────── */

    TEST("zcl_validate_zcl_address: t-address length 25 (below gate) rejected") {
        char buf[40];
        tsv_fill_len(buf, 25, "t1", 'A');
        ASSERT(!zcl_validate_zcl_address(buf));
        PASS();
    }

    TEST("zcl_validate_zcl_address: t-address length 26 (bottom of gate) reaches decode and fails on garbage") {
        char buf[40];
        tsv_fill_len(buf, 26, "t1", 'A');
        ASSERT(!zcl_validate_zcl_address(buf));
        PASS();
    }

    TEST("zcl_validate_zcl_address: t-address length 36 (top of gate) reaches decode and fails on garbage") {
        char buf[40];
        tsv_fill_len(buf, 36, "t1", 'A');
        ASSERT(!zcl_validate_zcl_address(buf));
        PASS();
    }

    TEST("zcl_validate_zcl_address: t-address length 37 (above gate) rejected") {
        char buf[40];
        tsv_fill_len(buf, 37, "t1", 'A');
        ASSERT(!zcl_validate_zcl_address(buf));
        PASS();
    }

    /* Same four boundaries again under the t3 (script) prefix, since
     * the length gate is shared by both but the '1' vs '3' comparison
     * is a distinct branch of the '||'. */

    TEST("zcl_validate_zcl_address: t3-address length 25 (below gate) rejected") {
        char buf[40];
        tsv_fill_len(buf, 25, "t3", 'A');
        ASSERT(!zcl_validate_zcl_address(buf));
        PASS();
    }

    TEST("zcl_validate_zcl_address: t3-address length 37 (above gate) rejected") {
        char buf[40];
        tsv_fill_len(buf, 37, "t3", 'A');
        ASSERT(!zcl_validate_zcl_address(buf));
        PASS();
    }

    /* ── zs1 length boundary: exactly 69 / 70 ───────────────────────── */

    TEST("zcl_validate_zcl_address: zs1-address length 69 (below gate) rejected") {
        char buf[80];
        /* 'q' is both alnum (passes the charset gate) and a valid
         * bech32 data-charset symbol, so this exercises the length
         * gate itself rather than accidentally failing the charset
         * loop first. */
        tsv_fill_len(buf, 69, "zs1", 'q');
        ASSERT(!zcl_validate_zcl_address(buf));
        PASS();
    }

    TEST("zcl_validate_zcl_address: zs1-address length 70 (at gate) reaches decode and fails on garbage") {
        char buf[80];
        tsv_fill_len(buf, 70, "zs1", 'q');
        ASSERT(!zcl_validate_zcl_address(buf));
        PASS();
    }

    /* ── zs0 / zt1: prefix must match 'z','s','1' exactly ───────────── */

    TEST("zcl_validate_zcl_address: rejects a zs0-prefixed string of in-range length") {
        char buf[80];
        tsv_fill_len(buf, 75, "zs0", 'q');
        ASSERT(!zcl_validate_zcl_address(buf));
        PASS();
    }

    TEST("zcl_validate_zcl_address: rejects a zt1-prefixed string of in-range length") {
        char buf[80];
        tsv_fill_len(buf, 75, "zt1", 'q');
        ASSERT(!zcl_validate_zcl_address(buf));
        PASS();
    }

_test_next:;
    if (failures == 0)
        printf("test_shared_validators_zcl_address: all passed\n");
    else
        printf("test_shared_validators_zcl_address: %d FAILED\n", failures);
    return failures;
}
