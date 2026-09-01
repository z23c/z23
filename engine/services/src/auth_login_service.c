/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Auth login service implementation. See auth_login_service.h. Signatures are
 * verified over a domain-tagged pre-image (the "\x18ZClassic Signed Message:\n"
 * magic + compact-size length + the canonical body), so a login signature can
 * never be a transaction pre-image. Address comparison and nonce consumption
 * are constant-time / atomic; failure paths return one generic message to
 * avoid leaking unknown-address vs bad-signature as distinct outcomes. */

// one-result-type-ok:zcl-result-plus-pure-codec — the fallible login surface
// (auth_login_challenge/verify) returns struct zcl_result; the lone bool export
// (auth_login_signable_hash) is a pure, total pre-image codec, not a service op.

#include "services/auth_login_service.h"
#include "models/authz_policy.h"
#include "models/auth_challenge.h"

#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "crypto/random_secret.h"
#include "core/hash.h"
#include "core/uint256.h"
#include "keys/pubkey.h"
#include "keys/key_io.h"
#include "script/standard.h"
#include "chain/chainparams.h"
#include "crypto/ed25519.h"
#include "encoding/utilstrencodings.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* The magic prefix begins with its own length byte, per the Bitcoin/Zcash
 * signed-message convention. Any signature over this pre-image is domain
 * separated from transaction sighashes. */
static const char k_auth_magic[] = "\x18ZClassic Signed Message:\n";

/* Constant-time comparison of two NUL-terminated strings. Compares over a
 * fixed span so the running time does not depend on the mismatch position or
 * whether the lengths differ. Returns int, not bool, so callers can combine
 * results with a bitwise `&` (see the bind check below) without tripping the
 * bool-operand-of-& diagnostic that would push them toward short-circuiting
 * `&&`. 1 == equal, 0 == differ. */
static int auth_ct_streq(const char *a, const char *b)
{
    size_t la = strlen(a), lb = strlen(b);
    size_t n = la > lb ? la : lb;
    unsigned diff = (unsigned)(la ^ lb);
    for (size_t i = 0; i < n; i++) {
        unsigned char ca = i < la ? (unsigned char)a[i] : 0;
        unsigned char cb = i < lb ? (unsigned char)b[i] : 0;
        diff |= (unsigned)(ca ^ cb);
    }
    return diff == 0;
}

/* Write a Bitcoin compact-size integer; returns bytes written (<=9). */
static size_t auth_write_compact_size(unsigned char *out, uint64_t n)
{
    if (n < 0xFDULL) { out[0] = (unsigned char)n; return 1; }
    if (n <= 0xFFFFULL) {
        out[0] = 0xFD; out[1] = (unsigned char)n; out[2] = (unsigned char)(n >> 8);
        return 3;
    }
    if (n <= 0xFFFFFFFFULL) {
        out[0] = 0xFE;
        for (int i = 0; i < 4; i++) out[1 + i] = (unsigned char)(n >> (8 * i));
        return 5;
    }
    out[0] = 0xFF;
    for (int i = 0; i < 8; i++) out[1 + i] = (unsigned char)(n >> (8 * i));
    return 9;
}

/* Build the signed pre-image bytes: magic || compact_size(len) || body. */
static size_t auth_build_preimage(const char *body, unsigned char *out,
                                  size_t out_size)
{
    size_t mlen = sizeof(k_auth_magic) - 1;
    size_t blen = strlen(body);
    unsigned char cs[9];
    size_t cslen = auth_write_compact_size(cs, (uint64_t)blen);
    if (mlen + cslen + blen > out_size)
        return 0;
    size_t off = 0;
    memcpy(out + off, k_auth_magic, mlen); off += mlen;
    memcpy(out + off, cs, cslen); off += cslen;
    memcpy(out + off, body, blen); off += blen;
    return off;
}

bool auth_login_signable_hash(const char *message_body, struct uint256 *out)
{
    if (!message_body || !out)
        return false;
    unsigned char preimage[AUTH_MESSAGE_MAX + 64];
    size_t plen = auth_build_preimage(message_body, preimage, sizeof(preimage));
    if (plen == 0)
        return false;
    hash256(preimage, plen, out->data);
    return true;
}

/* Render the canonical multi-line message body. Deterministic given inputs. */
static bool auth_render_body(char *out, size_t out_size,
                             const char *server_id, const char *address,
                             const char *nonce_hex, int64_t issued_at,
                             int64_t expires_at)
{
    int n = snprintf(out, out_size,
        "ZCLASSIC23-AUTH v1\n"
        "server: %s\n"
        "purpose: login\n"
        "address: %s\n"
        "nonce: %s\n"
        "issued_at: %lld\n"
        "expires_at: %lld\n",
        server_id, address, nonce_hex,
        (long long)issued_at, (long long)expires_at);
    return n > 0 && (size_t)n < out_size;
}

static bool auth_encode_address_from_keyid(const struct key_id *kid,
                                           char *out, size_t out_size)
{
    struct tx_destination dest;
    memset(&dest, 0, sizeof(dest));
    dest.type = DEST_KEY_ID;
    dest.id.key = *kid;
    const struct chain_params *cp = chain_params_get();
    if (!cp)
        return false;
    size_t pl = 0, sl = 0;
    const unsigned char *pp = chain_params_base58_prefix(cp, B58_PUBKEY_ADDRESS, &pl);
    const unsigned char *sp = chain_params_base58_prefix(cp, B58_SCRIPT_ADDRESS, &sl);
    return encode_destination(&dest, pp, pl, sp, sl, out, out_size);
}

struct zcl_result auth_login_challenge(struct node_db *ndb,
                                       const char *server_id,
                                       const char *address,
                                       struct auth_challenge_issued *out)
{
    if (!ndb || !server_id || !address || !out)
        return ZCL_ERR(-1, "auth_login_challenge: null argument");
    if (!address[0] || strlen(address) > PRINCIPAL_ADDRESS_MAX)
        return ZCL_ERR(-2, "auth_login_challenge: invalid address");

    memset(out, 0, sizeof(*out));

    uint8_t nonce[32];
    if (!zcl_random_secret_bytes(nonce, sizeof(nonce), "auth_login_nonce"))
        return ZCL_ERR(-3, "auth_login_challenge: RNG failure");
    for (int i = 0; i < 32; i++)
        snprintf(out->nonce_hex + i * 2, 3, "%02x", nonce[i]);

    int64_t now = (int64_t)platform_time_wall_time_t();
    out->issued_at = now;
    out->expires_at = now + AUTH_CHALLENGE_TTL_SECONDS;

    if (!auth_render_body(out->message, sizeof(out->message), server_id,
                          address, out->nonce_hex, out->issued_at,
                          out->expires_at))
        return ZCL_ERR(-4, "auth_login_challenge: message render overflow");

    struct db_auth_challenge row;
    memset(&row, 0, sizeof(row));
    snprintf(row.nonce_hex, sizeof(row.nonce_hex), "%s", out->nonce_hex);
    snprintf(row.address, sizeof(row.address), "%s", address);
    row.issued_at = out->issued_at;
    row.expires_at = out->expires_at;
    row.consumed = false;
    if (!db_auth_challenge_save(ndb, &row))
        return ZCL_ERR(-5, "auth_login_challenge: failed to persist nonce");

    return ZCL_OK;
}

/* One generic verification failure so the caller cannot tell an unknown
 * address from a bad signature by message content. */
static struct zcl_result auth_verify_denied(void)
{
    return ZCL_ERR(-100, "authentication failed");
}

struct zcl_result auth_login_verify(struct node_db *ndb,
                                    const char *server_id,
                                    const char *address,
                                    const char *nonce_hex,
                                    const uint8_t *sig, size_t sig_len,
                                    const char *pubkey_hex,
                                    struct auth_session *out)
{
    if (!ndb || !server_id || !address || !nonce_hex || !sig || !out)
        return ZCL_ERR(-1, "auth_login_verify: null argument");
    memset(out, 0, sizeof(*out));

    enum principal_key_kind kind;
    if (sig_len == COMPACT_SIGNATURE_SIZE)
        kind = PRINCIPAL_KEY_SECP256K1;
    else if (sig_len == 64)
        kind = PRINCIPAL_KEY_ED25519;
    else
        return auth_verify_denied();

    /* Recover the issued/expiry to rebuild the exact signed message. */
    struct db_auth_challenge row;
    if (!db_auth_challenge_find(ndb, nonce_hex, &row))
        return auth_verify_denied();

    char body[AUTH_MESSAGE_MAX];
    if (!auth_render_body(body, sizeof(body), server_id, row.address,
                          nonce_hex, row.issued_at, row.expires_at))
        return auth_verify_denied();

    unsigned char preimage[AUTH_MESSAGE_MAX + 64];
    size_t plen = auth_build_preimage(body, preimage, sizeof(preimage));
    if (plen == 0)
        return auth_verify_denied();

    char recovered[PRINCIPAL_ADDRESS_MAX + 1] = {0};
    char stored_pubkey_hex[PRINCIPAL_PUBKEY_HEX_MAX + 1] = {0};

    if (kind == PRINCIPAL_KEY_SECP256K1) {
        struct uint256 h;
        hash256(preimage, plen, h.data);
        struct pubkey pk;
        pubkey_init(&pk);
        if (!pubkey_recover_compact(&pk, &h, sig))
            return auth_verify_denied();
        struct key_id kid = pubkey_get_id(&pk);
        if (!auth_encode_address_from_keyid(&kid, recovered, sizeof(recovered)))
            return auth_verify_denied();
        /* Each iteration writes exactly two hex digits plus its own NUL; the
         * next iteration overwrites that NUL, and the last one terminates the
         * string. stored_pubkey_hex is zero-initialised, so a zero-length key
         * still yields "". The per-call return is a constant 2 and was
         * previously accumulated into a variable nothing ever read. */
        for (unsigned i = 0; i < pk.size && i < PRINCIPAL_PUBKEY_HEX_MAX / 2; i++)
            snprintf(stored_pubkey_hex + i * 2, 3, "%02x", pk.vch[i]);
    } else {
        /* ed25519: recovery is impossible; the client must present its key. */
        if (!pubkey_hex || !pubkey_hex[0])
            return auth_verify_denied();
        uint8_t pk32[32];
        if (ParseHex(pubkey_hex, pk32, sizeof(pk32)) != 32)
            return auth_verify_denied();
        if (!ed25519_verify(sig, preimage, plen, pk32))
            return auth_verify_denied();
        struct key_id kid;
        hash160(pk32, sizeof(pk32), kid.id.data);
        if (!auth_encode_address_from_keyid(&kid, recovered, sizeof(recovered)))
            return auth_verify_denied();
        snprintf(stored_pubkey_hex, sizeof(stored_pubkey_hex), "%s", pubkey_hex);
    }

    /* Constant-time bind: the recovered signer must be the claimed address and
     * the address the nonce was issued to.
     *
     * The single `&` is LOAD-BEARING — do NOT "fix" it to `&&`. `&&`
     * short-circuits, so a caller whose address already mismatches would skip
     * the second compare entirely and the reply would come back measurably
     * sooner: a timing oracle that distinguishes "wrong claimed address" from
     * "wrong issued-to address" on the login path. `&` evaluates both
     * comparisons unconditionally. auth_ct_streq returns int for exactly this
     * reason, so this is an ordinary bitwise AND of two 0/1 ints. */
    bool addr_ok = auth_ct_streq(recovered, address) &
                   auth_ct_streq(recovered, row.address);
    if (!addr_ok)
        return auth_verify_denied();

    /* Atomic single-use consume — the replay/expiry gate. */
    int64_t now = (int64_t)platform_time_wall_time_t();
    if (!db_auth_challenge_consume(ndb, nonce_hex, row.address, now))
        return auth_verify_denied();

    /* Upsert / load the principal. A first-seen address registers as GUEST. */
    struct db_principal p;
    bool existed = db_principal_find(ndb, recovered, &p);
    if (!existed) {
        memset(&p, 0, sizeof(p));
        snprintf(p.address, sizeof(p.address), "%s", recovered);
        snprintf(p.pubkey_hex, sizeof(p.pubkey_hex), "%s", stored_pubkey_hex);
        p.key_kind = kind;
        p.role = PRINCIPAL_ROLE_GUEST;
        p.status = PRINCIPAL_STATUS_ACTIVE;
        p.sybil_proof_height = -1;
        p.created_at = now;
    }
    if (p.status == PRINCIPAL_STATUS_SUSPENDED)
        return ZCL_ERR(-101, "account is suspended");
    p.last_login = now;
    if (!db_principal_save(ndb, &p))
        return ZCL_ERR(-102, "auth_login_verify: failed to persist principal");

    snprintf(out->account, sizeof(out->account), "%s", recovered);
    out->role = p.role;
    /* Session caps/ceiling come from the authz table (single source), never
     * from a persisted mask a caller might have tampered with. */
    out->granted_capabilities = authz_caps_for_role(p.role);
    out->authority_ceiling = authz_ceiling_for_role(p.role);
    out->newly_registered = !existed;
    return ZCL_OK;
}
