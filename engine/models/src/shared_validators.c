/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ar-validate-skip:shared-helpers-not-a-row
 *   Pure helper module defining zcl_validate_zcl_address and friends
 *   used by validates_zcl_address. Has no record of its own. */

#include "models/shared_validators.h"

#include <string.h>

#include "keys/key_io.h"
#include "chain/chainparams.h"
#include "wallet/sapling_keys.h"

bool zcl_validate_zcl_address(const char *addr)
{
    if (!addr || !addr[0])
        return false;

    size_t len = strlen(addr);

    /* Charset gate: alphanumeric + underscore only. Both t-addrs and
     * zs1 Sapling addresses fit this set. Catches one-character typos
     * cheaply and prevents XSS via address echo in HTML. */
    for (size_t i = 0; i < len; i++) {
        char c = addr[i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_';
        if (!ok)
            return false;
    }

    /* Transparent address: Base58Check against the ACTIVE chain's P2PKH
     * or P2SH version bytes (t1/t3 on mainnet, the chain's own forms —
     * tm/t2 — on testnet/regtest). decode_destination validates the
     * version-prefix and checksum; the leading 't' (every ZCL-family
     * transparent address begins with one) plus the length bound is only
     * a cheap pre-filter. Gating on the literal mainnet second character
     * here false-rejected every non-mainnet transparent address — e.g. a
     * regtest tm... customer address in the store order route. Reading
     * only addr[0] keeps a 1-char "t" input a safe in-bounds read. */
    if (addr[0] == 't' && len >= 26 && len <= 36) {
        const struct chain_params *cp = chain_params_get();
        size_t pk_len = 0, sc_len = 0;
        const unsigned char *pk_pfx =
            chain_params_base58_prefix(cp, B58_PUBKEY_ADDRESS, &pk_len);
        const unsigned char *sc_pfx =
            chain_params_base58_prefix(cp, B58_SCRIPT_ADDRESS, &sc_len);
        struct tx_destination dest;
        return decode_destination(addr, pk_pfx, pk_len, sc_pfx, sc_len, &dest);
    }

    /* Sapling shielded address: the ACTIVE chain's bech32 HRP plus the
     * '1' separator ("zs1..." on mainnet, "ztestsapling1..."/
     * "zregtestsapling1..." off it). sapling_decode_payment_address
     * validates the checksum and the 11-byte diversifier + 32-byte pk_d
     * split while deliberately ignoring the HRP, so the prefix test here
     * is the only HRP check — the same pattern wallet_addr_is_sapling
     * uses. The literal "zs1" gate that used to sit here false-rejected
     * every non-mainnet Sapling address. */
    {
        const struct chain_params *cp = chain_params_get();
        const char *hrp =
            cp ? cp->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS] : NULL;
        size_t hrp_len = hrp ? strlen(hrp) : 0;
        if (hrp_len > 0 && len > hrp_len &&
            strncmp(addr, hrp, hrp_len) == 0 && addr[hrp_len] == '1') {
            uint8_t d[ZC_DIVERSIFIER_SIZE];
            uint8_t pk_d[32];
            return sapling_decode_payment_address(addr, d, pk_d);
        }
    }

    return false;
}
