/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Signed zcl.proof_checkpoint.v1 objects over an issuer's MMR of
 *          ticket observation roots, and the issuer-side append-only log. */

#include "vcs/proof_reuse.h"

#include "chain/mmr.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"

#include <stdlib.h>
#include <string.h>

#define PCK_LOG "vcs.proof_checkpoint"
#define PCK_MAGIC "Z23PCK1\0"
#define PCK_VERSION 1u
#define PCK_SIGN_DOMAIN "zcl.proof_checkpoint.v1"
#define PCK_ROOT_DOMAIN "zcl.proof_checkpoint_root.v1"
#define PCK_PEAKS_DOMAIN "zcl.proof_checkpoint.peaks.v1"
#define PCK_SIGN_MESSAGE_BYTES \
    ((sizeof(PCK_SIGN_DOMAIN) - 1u) + VCS_PROOF_CHECKPOINT_SIGNED_BYTES)

static bool pck_nonzero(const uint8_t *bytes, size_t len)
{
    uint8_t any = 0;
    for (size_t i = 0; i < len; i++) any |= bytes[i];
    return any != 0;
}

static void pck_hash(const char *domain, const uint8_t *bytes, size_t len,
                     uint8_t out[VCS_PROOF_ROOT_BYTES])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, strlen(domain));
    if (len) sha3_256_write(&sha, bytes, len);
    sha3_256_finalize(&sha, out);
}

bool vcs_proof_checkpoint_peaks_root(const struct mmr *m,
                                     uint8_t out[VCS_PROOF_ROOT_BYTES])
{
    uint8_t buf[MMR_SERIALIZED_MAX];
    if (!m || !out)
        LOG_RETURN(false, PCK_LOG, "peaks root: null argument");
    size_t n = mmr_serialize(m, buf, sizeof(buf));
    if (n == 0)
        LOG_RETURN(false, PCK_LOG, "peaks root: mmr serialize failed");
    pck_hash(PCK_PEAKS_DOMAIN, buf, n, out);
    return true;
}

static bool pck_body_valid(const struct vcs_proof_checkpoint_v1 *c)
{
    return c && c->leaf_count >= 1 && c->created_unix != 0 &&
           pck_nonzero(c->issuer_pubkey, VCS_PROOF_PUBKEY_BYTES) &&
           pck_nonzero(c->mmr_root, VCS_PROOF_ROOT_BYTES) &&
           pck_nonzero(c->peaks_root, VCS_PROOF_ROOT_BYTES);
}

static void pck_put_signed(const struct vcs_proof_checkpoint_v1 *c,
                           uint8_t *out)
{
    memcpy(out, PCK_MAGIC, 8);
    zcl_write_u32_le(out + 8, PCK_VERSION);
    zcl_write_u32_le(out + 12, 0);
    memcpy(out + 16, c->issuer_pubkey, VCS_PROOF_PUBKEY_BYTES);
    zcl_write_u64_le(out + 48, c->leaf_count);
    memcpy(out + 56, c->mmr_root, VCS_PROOF_ROOT_BYTES);
    memcpy(out + 88, c->peaks_root, VCS_PROOF_ROOT_BYTES);
    memcpy(out + 120, c->prev_checkpoint_root, VCS_PROOF_ROOT_BYTES);
    zcl_write_u64_le(out + 152, c->created_unix);
}

static void pck_message(const struct vcs_proof_checkpoint_v1 *c,
                        uint8_t out[PCK_SIGN_MESSAGE_BYTES])
{
    memcpy(out, PCK_SIGN_DOMAIN, sizeof(PCK_SIGN_DOMAIN) - 1u);
    pck_put_signed(c, out + sizeof(PCK_SIGN_DOMAIN) - 1u);
}

bool vcs_proof_checkpoint_sign(struct vcs_proof_checkpoint_v1 *c,
                               const uint8_t seed[32])
{
    if (!c || !seed || !pck_nonzero(seed, 32))
        LOG_RETURN(false, PCK_LOG, "checkpoint sign: missing input or seed");
    uint8_t secret[32];
    ed25519_keypair(c->issuer_pubkey, secret, seed);
    if (!pck_body_valid(c)) {
        memset(secret, 0, sizeof(secret));
        LOG_RETURN(false, PCK_LOG, "checkpoint sign: body not canonical");
    }
    uint8_t message[PCK_SIGN_MESSAGE_BYTES];
    pck_message(c, message);
    ed25519_sign(c->signature, message, sizeof(message), secret,
                 c->issuer_pubkey);
    memset(secret, 0, sizeof(secret));
    return true;
}

bool vcs_proof_checkpoint_signature_valid(
    const struct vcs_proof_checkpoint_v1 *c)
{
    if (!pck_body_valid(c)) return false;
    uint8_t message[PCK_SIGN_MESSAGE_BYTES];
    pck_message(c, message);
    return ed25519_verify(c->signature, message, sizeof(message),
                          c->issuer_pubkey);
}

bool vcs_proof_checkpoint_encode(const struct vcs_proof_checkpoint_v1 *c,
                                 uint8_t out[VCS_PROOF_CHECKPOINT_WIRE_BYTES])
{
    if (!out || !pck_body_valid(c) ||
        !pck_nonzero(c->signature, VCS_PROOF_SIGNATURE_BYTES))
        LOG_RETURN(false, PCK_LOG, "checkpoint encode: not canonical/signed");
    pck_put_signed(c, out);
    memcpy(out + VCS_PROOF_CHECKPOINT_SIGNED_BYTES, c->signature,
           VCS_PROOF_SIGNATURE_BYTES);
    return true;
}

bool vcs_proof_checkpoint_decode(const uint8_t *wire, size_t len,
                                 struct vcs_proof_checkpoint_v1 *out)
{
    if (!wire || !out)
        LOG_RETURN(false, PCK_LOG, "checkpoint decode: null input");
    memset(out, 0, sizeof(*out));
    if (len != VCS_PROOF_CHECKPOINT_WIRE_BYTES ||
        memcmp(wire, PCK_MAGIC, 8) != 0 ||
        zcl_read_u32_le(wire + 8) != PCK_VERSION ||
        zcl_read_u32_le(wire + 12) != 0)
        LOG_RETURN(false, PCK_LOG, "checkpoint decode: bad framing (%zu)", len);
    struct vcs_proof_checkpoint_v1 c;
    memcpy(c.issuer_pubkey, wire + 16, VCS_PROOF_PUBKEY_BYTES);
    c.leaf_count = zcl_read_u64_le(wire + 48);
    memcpy(c.mmr_root, wire + 56, VCS_PROOF_ROOT_BYTES);
    memcpy(c.peaks_root, wire + 88, VCS_PROOF_ROOT_BYTES);
    memcpy(c.prev_checkpoint_root, wire + 120, VCS_PROOF_ROOT_BYTES);
    c.created_unix = zcl_read_u64_le(wire + 152);
    memcpy(c.signature, wire + 160, VCS_PROOF_SIGNATURE_BYTES);
    if (!pck_body_valid(&c) ||
        !pck_nonzero(c.signature, VCS_PROOF_SIGNATURE_BYTES))
        LOG_RETURN(false, PCK_LOG, "checkpoint decode: non-canonical values");
    *out = c;
    return true;
}

bool vcs_proof_checkpoint_root(const uint8_t *wire, size_t len,
                               uint8_t out[VCS_PROOF_ROOT_BYTES])
{
    if (!wire || !out || len != VCS_PROOF_CHECKPOINT_WIRE_BYTES)
        LOG_RETURN(false, PCK_LOG, "checkpoint root: bad input (%zu)", len);
    pck_hash(PCK_ROOT_DOMAIN, wire, len, out);
    return true;
}

/* ── Issuer log ─────────────────────────────────────────────────────── */

struct vcs_proof_issuer_log {
    uint8_t seed[32];
    uint8_t pubkey[VCS_PROOF_PUBKEY_BYTES];
    struct mmr mmr;
    uint8_t last_root[VCS_PROOF_ROOT_BYTES];
    uint8_t (*wires)[VCS_PROOF_TICKET_WIRE_BYTES];
    size_t count;
    size_t cap;
};

struct vcs_proof_issuer_log *vcs_proof_issuer_log_new(const uint8_t seed[32])
{
    if (!seed || !pck_nonzero(seed, 32))
        LOG_RETURN(NULL, PCK_LOG, "issuer log: missing seed");
    struct vcs_proof_issuer_log *log =
        zcl_calloc(1, sizeof(*log), "proof_issuer_log");
    if (!log) LOG_RETURN(NULL, PCK_LOG, "issuer log: out of memory");
    uint8_t secret[32];
    memcpy(log->seed, seed, 32);
    ed25519_keypair(log->pubkey, secret, seed);
    memset(secret, 0, sizeof(secret));
    mmr_init(&log->mmr);
    return log;
}

void vcs_proof_issuer_log_free(struct vcs_proof_issuer_log *log)
{
    if (!log) return;
    free(log->wires);
    memset(log, 0, sizeof(*log));
    free(log);
}

void vcs_proof_issuer_log_pubkey(const struct vcs_proof_issuer_log *log,
                                 uint8_t out[VCS_PROOF_PUBKEY_BYTES])
{
    if (log && out) memcpy(out, log->pubkey, VCS_PROOF_PUBKEY_BYTES);
}

static bool pck_log_reserve(struct vcs_proof_issuer_log *log)
{
    if (log->count < log->cap) return true;
    size_t cap = log->cap ? log->cap * 2u : 64u;
    if (cap > SIZE_MAX / VCS_PROOF_TICKET_WIRE_BYTES)
        LOG_RETURN(false, PCK_LOG, "issuer log capacity overflow");
    uint8_t (*grown)[VCS_PROOF_TICKET_WIRE_BYTES] =
        zcl_realloc(log->wires, cap * VCS_PROOF_TICKET_WIRE_BYTES,
                    "proof_issuer_log_wires");
    if (!grown) LOG_RETURN(false, PCK_LOG, "issuer log: out of memory");
    log->wires = grown;
    log->cap = cap;
    return true;
}

bool vcs_proof_issuer_log_append(struct vcs_proof_issuer_log *log,
                                 struct vcs_proof_ticket_v1 *ticket,
                                 uint8_t wire[VCS_PROOF_TICKET_WIRE_BYTES])
{
    if (!log || !ticket || !wire)
        LOG_RETURN(false, PCK_LOG, "issuer append: null argument");
    if (!pck_log_reserve(log)) return false;
    ticket->issuer_seq = (uint64_t)log->count;
    uint8_t root[VCS_PROOF_ROOT_BYTES];
    if (!vcs_proof_ticket_sign(ticket, log->seed) ||
        !vcs_proof_ticket_encode(ticket, wire) ||
        !vcs_proof_ticket_observation_root(wire, VCS_PROOF_TICKET_WIRE_BYTES,
                                           root))
        LOG_RETURN(false, PCK_LOG, "issuer append: ticket not encodable");
    mmr_append(&log->mmr, root);
    memcpy(log->wires[log->count++], wire, VCS_PROOF_TICKET_WIRE_BYTES);
    return true;
}

bool vcs_proof_issuer_log_checkpoint(
    struct vcs_proof_issuer_log *log, uint64_t created_unix,
    uint8_t wire[VCS_PROOF_CHECKPOINT_WIRE_BYTES])
{
    if (!log || !wire || log->count == 0)
        LOG_RETURN(false, PCK_LOG, "issuer checkpoint: empty log or no buffer");
    struct vcs_proof_checkpoint_v1 c;
    memset(&c, 0, sizeof(c));
    c.leaf_count = log->mmr.num_leaves;
    mmr_root(&log->mmr, c.mmr_root);
    memcpy(c.prev_checkpoint_root, log->last_root, VCS_PROOF_ROOT_BYTES);
    c.created_unix = created_unix;
    if (!vcs_proof_checkpoint_peaks_root(&log->mmr, c.peaks_root) ||
        !vcs_proof_checkpoint_sign(&c, log->seed) ||
        !vcs_proof_checkpoint_encode(&c, wire) ||
        !vcs_proof_checkpoint_root(wire, VCS_PROOF_CHECKPOINT_WIRE_BYTES,
                                   log->last_root))
        LOG_RETURN(false, PCK_LOG, "issuer checkpoint: cannot sign");
    return true;
}

uint64_t vcs_proof_issuer_log_count(const struct vcs_proof_issuer_log *log)
{
    return log ? (uint64_t)log->count : 0;
}

const uint8_t *vcs_proof_issuer_log_ticket(
    const struct vcs_proof_issuer_log *log, uint64_t seq)
{
    if (!log || seq >= (uint64_t)log->count) return NULL;
    return log->wires[seq];
}
