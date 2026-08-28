/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: provide explicit Windows refusals for the POSIX service book. */
#include "vcs/package_service.h"

#if defined(_WIN32)
#include <string.h>

struct vcs_service_book *vcs_service_book_load(const char *zcode_dir)
{
    (void)zcode_dir;
    return NULL;
}
void vcs_service_book_free(struct vcs_service_book *book) { (void)book; }
size_t vcs_service_book_event_count(const struct vcs_service_book *book)
{ (void)book; return 0; }
uint32_t vcs_service_book_corrupt_count(const struct vcs_service_book *book)
{ (void)book; return 0; }
bool vcs_service_book_truncated(const struct vcs_service_book *book)
{ (void)book; return false; }
size_t vcs_service_book_key_count(const struct vcs_service_book *book)
{ (void)book; return 0; }
bool vcs_service_book_key_at(const struct vcs_service_book *book,
                             size_t index, uint8_t out[33])
{ (void)book; (void)index; (void)out; return false; }

const char *vcs_service_credit_result_string(
    enum vcs_service_credit_result result)
{
    switch (result) {
    case VCS_SERVICE_CREDIT_OK: return "credited";
    case VCS_SERVICE_CREDIT_DUPLICATE: return "duplicate";
    case VCS_SERVICE_CREDIT_REPLAYED_REQUEST: return "duplicate-request-replay";
    case VCS_SERVICE_CREDIT_BAD_INPUT: return "bad-input";
    case VCS_SERVICE_CREDIT_FULL: return "full";
    case VCS_SERVICE_CREDIT_IO: return "io";
    case VCS_SERVICE_CREDIT_UNVERIFIED: return "unverified-receipt";
    case VCS_SERVICE_CREDIT_NOT_PARTY: return "not-party";
    case VCS_SERVICE_CREDIT_WINDOW: return "outside-window";
    }
    return "unknown";
}

const char *vcs_service_record_result_string(
    enum vcs_service_record_result result)
{
    switch (result) {
    case VCS_SERVICE_RECORD_OK: return "recorded";
    case VCS_SERVICE_RECORD_DUPLICATE: return "duplicate";
    case VCS_SERVICE_RECORD_BAD_INPUT: return "bad-input";
    case VCS_SERVICE_RECORD_FULL: return "full";
    case VCS_SERVICE_RECORD_IO: return "io";
    }
    return "unknown";
}

enum vcs_service_credit_result vcs_service_credit_upload(
    struct vcs_service_book *book, const uint8_t contributor[33],
    const uint8_t request_id[32], uint64_t bytes, int64_t day)
{
    (void)book; (void)contributor; (void)request_id; (void)bytes; (void)day;
    return VCS_SERVICE_CREDIT_IO;
}
enum vcs_service_credit_result vcs_service_credit_download(
    struct vcs_service_book *book, const uint8_t contributor[33],
    const uint8_t request_id[32], uint64_t bytes, int64_t day)
{
    (void)book; (void)contributor; (void)request_id; (void)bytes; (void)day;
    return VCS_SERVICE_CREDIT_IO;
}
enum vcs_service_record_result vcs_service_record_publish(
    struct vcs_service_book *book, const uint8_t contributor[33],
    const uint8_t release_id[32], int64_t day)
{
    (void)book; (void)contributor; (void)release_id; (void)day;
    return VCS_SERVICE_RECORD_IO;
}
enum vcs_service_record_result vcs_service_record_offence(
    struct vcs_service_book *book, const uint8_t contributor[33],
    enum vcs_policy_offence kind, int64_t day)
{
    (void)book; (void)contributor; (void)kind; (void)day;
    return VCS_SERVICE_RECORD_IO;
}
enum vcs_service_record_result vcs_service_record_no_credit(
    struct vcs_service_book *book, const uint8_t contributor[33],
    enum vcs_policy_no_credit kind, uint64_t bytes, int64_t day)
{
    (void)book; (void)contributor; (void)kind; (void)bytes; (void)day;
    return VCS_SERVICE_RECORD_IO;
}
bool vcs_service_key_totals(const struct vcs_service_book *book,
                            const uint8_t contributor[33], int64_t day,
                            struct vcs_service_key_totals *out)
{
    (void)book; (void)contributor; (void)day;
    if (out) memset(out, 0, sizeof(*out));
    return false;
}
void vcs_service_book_totals(const struct vcs_service_book *book,
                             struct vcs_service_book_totals *out)
{
    (void)book;
    if (out) memset(out, 0, sizeof(*out));
}
#else
typedef int package_service_windows_requires_a_translation_unit;
#endif
