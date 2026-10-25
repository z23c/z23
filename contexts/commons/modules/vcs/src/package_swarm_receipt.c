/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Dual-signed receipt draft/accept beside the frozen v1 swarm wire.
 * Transport identity stays a local pseudo-key; the caller supplies the
 * real secp256k1 endpoints. */

#include "vcs/package_swarm_node.h"

#include "base/log_macros.h"
#include "crypto/sha3.h"
#include "vcs/package_service.h"

#include <string.h>

static const uint8_t k_nonce_domain[] = "zcl.zcode.swarm-receipt-nonce.v1\0";

const char *vcs_swarm_receipt_status_string(
    enum vcs_swarm_receipt_status status)
{
    switch (status) {
    case VCS_SWARM_RECEIPT_OK: return "ok";
    case VCS_SWARM_RECEIPT_NO_TRANSFER: return "no-transfer";
    case VCS_SWARM_RECEIPT_BYTES_MISMATCH: return "bytes-mismatch";
    case VCS_SWARM_RECEIPT_UNVERIFIED: return "unverified-receipt";
    case VCS_SWARM_RECEIPT_NOT_PARTY: return "not-party";
    case VCS_SWARM_RECEIPT_WINDOW: return "outside-window";
    case VCS_SWARM_RECEIPT_DUPLICATE: return "duplicate";
    case VCS_SWARM_RECEIPT_BAD_INPUT: return "bad-input";
    case VCS_SWARM_RECEIPT_STALE: return "stale";
    }
    return "unknown";
}

static int pub_cmp(const uint8_t a[33], const uint8_t b[33])
{
    return memcmp(a, b, 33);
}

static void receipt_nonce(const uint8_t local_pub[33],
                          const uint8_t remote_pub[33],
                          const uint8_t root[32], uint64_t bytes,
                          uint8_t nonce[32])
{
    const uint8_t *lo = local_pub;
    const uint8_t *hi = remote_pub;
    if (pub_cmp(local_pub, remote_pub) > 0) {
        lo = remote_pub;
        hi = local_pub;
    }
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, k_nonce_domain, sizeof(k_nonce_domain));
    sha3_256_write(&ctx, lo, 33);
    sha3_256_write(&ctx, hi, 33);
    sha3_256_write(&ctx, root, 32);
    uint8_t le[8];
    uint64_t u = bytes;
    for (int i = 0; i < 8; i++) {
        le[i] = (uint8_t)(u & 0xffu);
        u >>= 8;
    }
    sha3_256_write(&ctx, le, sizeof(le));
    sha3_256_finalize(&ctx, nonce);
}

bool vcs_swarm_receipt_draft(
    const struct vcs_swarm_transfer *xfer,
    const uint8_t local_pub[33], const uint8_t remote_pub[33],
    int64_t day_start, int64_t day_end,
    struct vcs_service_receipt *out,
    enum vcs_service_receipt_role *local_role)
{
    if (!xfer || !local_pub || !remote_pub || !out || !local_role)
        return false;
    if (memcmp(local_pub, remote_pub, 33) == 0)
        return false;
    if (day_start > day_end)
        return false;

    uint64_t served = xfer->served;
    uint64_t fetched = xfer->fetched;
    if (served == 0 && fetched == 0)
        return false;

    memset(out, 0, sizeof(*out));
    memcpy(out->package_root, xfer->package_root, 32);
    if (served >= fetched) {
        *local_role = VCS_SERVICE_RECEIPT_UPLOADER;
        memcpy(out->uploader_pubkey, local_pub, 33);
        memcpy(out->downloader_pubkey, remote_pub, 33);
        out->verified_bytes = served;
    } else {
        *local_role = VCS_SERVICE_RECEIPT_DOWNLOADER;
        memcpy(out->uploader_pubkey, remote_pub, 33);
        memcpy(out->downloader_pubkey, local_pub, 33);
        out->verified_bytes = fetched;
    }
    out->day_start = day_start;
    out->day_end = day_end;
    receipt_nonce(local_pub, remote_pub, out->package_root,
                  out->verified_bytes, out->session_nonce);
    return true;
}

enum {
    RECEIPT_PARTY_OK = 0,
    RECEIPT_PARTY_NOT_ONE,
    RECEIPT_PARTY_SERVED_MISMATCH,
    RECEIPT_PARTY_FETCHED_MISMATCH
};

enum {
    RECEIPT_CREDIT_MAPPED = 0,
    RECEIPT_CREDIT_REFUSED,
    RECEIPT_CREDIT_UNKNOWN
};

static enum vcs_swarm_receipt_status receipt_accept_inputs(
    const struct vcs_service_book *book,
    const struct vcs_swarm_transfer *xfer,
    const uint8_t local_pub[33], const uint8_t *wire)
{
    if (!book || !xfer || !local_pub || !wire)
        return VCS_SWARM_RECEIPT_BAD_INPUT;
    if (xfer->served == 0 && xfer->fetched == 0)
        return VCS_SWARM_RECEIPT_NO_TRANSFER;
    return VCS_SWARM_RECEIPT_OK;
}

static int receipt_party_bytes(const struct vcs_service_receipt *parsed,
                               const struct vcs_swarm_transfer *xfer,
                               const uint8_t local_pub[33],
                               uint64_t expected)
{
    bool as_uploader = memcmp(local_pub, parsed->uploader_pubkey, 33) == 0;
    bool as_downloader =
        memcmp(local_pub, parsed->downloader_pubkey, 33) == 0;
    if (as_uploader == as_downloader)
        return RECEIPT_PARTY_NOT_ONE;
    if (as_uploader && expected != xfer->served)
        return RECEIPT_PARTY_SERVED_MISMATCH;
    if (as_downloader && expected != xfer->fetched)
        return RECEIPT_PARTY_FETCHED_MISMATCH;
    return RECEIPT_PARTY_OK;
}

static int receipt_credit_kind(enum vcs_service_credit_result cr,
                               enum vcs_swarm_receipt_status *out)
{
    switch (cr) {
    case VCS_SERVICE_CREDIT_OK:
        *out = VCS_SWARM_RECEIPT_OK;
        return RECEIPT_CREDIT_MAPPED;
    case VCS_SERVICE_CREDIT_DUPLICATE:
        *out = VCS_SWARM_RECEIPT_DUPLICATE;
        return RECEIPT_CREDIT_MAPPED;
    case VCS_SERVICE_CREDIT_UNVERIFIED:
        *out = VCS_SWARM_RECEIPT_UNVERIFIED;
        return RECEIPT_CREDIT_MAPPED;
    case VCS_SERVICE_CREDIT_NOT_PARTY:
        *out = VCS_SWARM_RECEIPT_NOT_PARTY;
        return RECEIPT_CREDIT_MAPPED;
    case VCS_SERVICE_CREDIT_WINDOW:
        *out = VCS_SWARM_RECEIPT_WINDOW;
        return RECEIPT_CREDIT_MAPPED;
    case VCS_SERVICE_CREDIT_BAD_INPUT:
    case VCS_SERVICE_CREDIT_REPLAYED_REQUEST:
    case VCS_SERVICE_CREDIT_FULL:
    case VCS_SERVICE_CREDIT_IO:
        return RECEIPT_CREDIT_REFUSED;
    }
    return RECEIPT_CREDIT_UNKNOWN;
}

enum vcs_swarm_receipt_status vcs_swarm_receipt_accept(
    struct vcs_service_book *book, const struct vcs_swarm_transfer *xfer,
    const uint8_t local_pub[33], int64_t day,
    const uint8_t *wire, size_t len)
{
    enum vcs_swarm_receipt_status inputs =
        receipt_accept_inputs(book, xfer, local_pub, wire);
    if (inputs == VCS_SWARM_RECEIPT_BAD_INPUT)
        LOG_RETURN(VCS_SWARM_RECEIPT_BAD_INPUT, "vcs.swarm-receipt",
                   "accept: null argument");
    if (inputs == VCS_SWARM_RECEIPT_NO_TRANSFER)
        LOG_RETURN(VCS_SWARM_RECEIPT_NO_TRANSFER, "vcs.swarm-receipt",
                   "accept: no verified transfer");

    struct vcs_service_receipt parsed;
    enum vcs_service_receipt_error verr =
        vcs_service_receipt_verify(wire, len, &parsed);
    if (verr != VCS_SERVICE_RECEIPT_OK)
        LOG_RETURN(VCS_SWARM_RECEIPT_UNVERIFIED, "vcs.swarm-receipt",
                   "accept: verify failed (%d)", (int)verr);

    if (memcmp(parsed.package_root, xfer->package_root, 32) != 0)
        LOG_RETURN(VCS_SWARM_RECEIPT_BYTES_MISMATCH, "vcs.swarm-receipt",
                   "accept: package root does not match the transfer");

    uint64_t expected = parsed.verified_bytes;
    int party = receipt_party_bytes(&parsed, xfer, local_pub, expected);
    if (party == RECEIPT_PARTY_NOT_ONE)
        LOG_RETURN(VCS_SWARM_RECEIPT_NOT_PARTY, "vcs.swarm-receipt",
                   "accept: local key is not exactly one endpoint");
    if (party == RECEIPT_PARTY_SERVED_MISMATCH)
        LOG_RETURN(VCS_SWARM_RECEIPT_BYTES_MISMATCH, "vcs.swarm-receipt",
                   "accept: claimed %llu served != %llu",
                   (unsigned long long)expected,
                   (unsigned long long)xfer->served);
    if (party == RECEIPT_PARTY_FETCHED_MISMATCH)
        LOG_RETURN(VCS_SWARM_RECEIPT_BYTES_MISMATCH, "vcs.swarm-receipt",
                   "accept: claimed %llu fetched != %llu",
                   (unsigned long long)expected,
                   (unsigned long long)xfer->fetched);

    enum vcs_service_credit_result cr = vcs_service_book_accept_receipt(
        book, wire, len, local_pub, day);
    enum vcs_swarm_receipt_status mapped = VCS_SWARM_RECEIPT_BAD_INPUT;
    int credit = receipt_credit_kind(cr, &mapped);
    if (credit == RECEIPT_CREDIT_REFUSED)
        LOG_RETURN(VCS_SWARM_RECEIPT_BAD_INPUT, "vcs.swarm-receipt",
                   "accept: book refused %s",
                   vcs_service_credit_result_string(cr));
    if (credit == RECEIPT_CREDIT_UNKNOWN)
        LOG_RETURN(VCS_SWARM_RECEIPT_BAD_INPUT, "vcs.swarm-receipt",
                   "accept: book refused %s",
                   vcs_service_credit_result_string(cr));
    return mapped;
}
