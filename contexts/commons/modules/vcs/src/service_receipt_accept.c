/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Local acceptance of a dual-signed verified-byte receipt into the
 * service book. Codec stays in package_service.c; this file only decides
 * who is credited. Advisory reputation, never consensus. */

#include "vcs/package_service.h"
#include "vcs/service_receipt.h"

#include "base/log_macros.h"

#include <string.h>

enum vcs_service_credit_result vcs_service_book_accept_receipt(
    struct vcs_service_book *book, const uint8_t *wire, size_t len,
    const uint8_t local_pubkey[33], int64_t day)
{
    if (!book || !wire || !local_pubkey)
        LOG_RETURN(VCS_SERVICE_CREDIT_BAD_INPUT, "vcs.service-receipt",
                   "accept: null book, wire, or local pubkey");

    struct vcs_service_receipt receipt;
    enum vcs_service_receipt_error verr =
        vcs_service_receipt_verify(wire, len, &receipt);
    if (verr != VCS_SERVICE_RECEIPT_OK)
        LOG_RETURN(VCS_SERVICE_CREDIT_UNVERIFIED, "vcs.service-receipt",
                   "accept: receipt verify failed (%d)", (int)verr);

    if (day < receipt.day_start || day > receipt.day_end)
        LOG_RETURN(VCS_SERVICE_CREDIT_WINDOW, "vcs.service-receipt",
                   "accept: day %lld outside [%lld, %lld]",
                   (long long)day, (long long)receipt.day_start,
                   (long long)receipt.day_end);

    bool local_uploader =
        memcmp(local_pubkey, receipt.uploader_pubkey, 33) == 0;
    bool local_downloader =
        memcmp(local_pubkey, receipt.downloader_pubkey, 33) == 0;
    if (local_uploader == local_downloader)
        LOG_RETURN(VCS_SERVICE_CREDIT_NOT_PARTY, "vcs.service-receipt",
                   "accept: local key is not exactly one receipt endpoint");

    uint8_t receipt_id[VCS_SERVICE_RECEIPT_ID_BYTES];
    vcs_service_receipt_id(&receipt, receipt_id);

    if (local_uploader)
        return vcs_service_credit_upload(book, receipt.downloader_pubkey,
                                         receipt_id, receipt.verified_bytes,
                                         day);
    return vcs_service_credit_download(book, receipt.uploader_pubkey,
                                       receipt_id, receipt.verified_bytes,
                                       day);
}
