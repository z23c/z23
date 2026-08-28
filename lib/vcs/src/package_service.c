/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_service — the ZCODE local service book (slice 11). See the
 * header for the persistence convention, the credit discipline, and the
 * determinism contract. This file owns the durable event wires under
 * <zcode_dir>/service/events and the in-memory replay; every policy
 * question is answered by lib/vcs/package_policy.* over the facts read
 * here. */
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
#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "crypto/sha3.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SERVICE_LOG "vcs.service"

/* Hash domain (never hash undomained content). */
static const uint8_t k_domain_event[] = "zcl.zcode_service_event.v1";

/* Event kinds on the wire. */
enum {
    SVC_EVENT_UPLOAD = 1,
    SVC_EVENT_DOWNLOAD = 2,
    SVC_EVENT_PUBLISH = 3,
    SVC_EVENT_OFFENCE = 4,
    SVC_EVENT_NO_CREDIT = 5,
};

#define SVC_MAGIC0 'Z'
#define SVC_MAGIC1 'S'
#define SVC_MAGIC2 'V'
#define SVC_MAGIC3 '1'

/* ── small helpers ──────────────────────────────────────────────────── */

static bool svc_name_is_hex64(const char *name)
{
    uint8_t scratch[32];
    return zcl_hex_decode_lower(name, scratch, 32);
}

static bool svc_is_zero(const uint8_t *bytes, size_t len)
{
    for (size_t i = 0; i < len; i++)
        if (bytes[i] != 0)
            return false;
    return true;
}

static void svc_put_u64(uint8_t *p, uint64_t v)
{
    for (size_t i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

static uint64_t svc_get_u64(const uint8_t *p)
{
    uint64_t v = 0;
    for (size_t i = 0; i < 8; i++)
        v |= (uint64_t)p[i] << (8 * i);
    return v;
}

static void svc_put_u32(uint8_t *p, uint32_t v)
{
    for (size_t i = 0; i < 4; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

static uint32_t svc_get_u32(const uint8_t *p)
{
    uint32_t v = 0;
    for (size_t i = 0; i < 4; i++)
        v |= (uint32_t)p[i] << (8 * i);
    return v;
}

static bool svc_mkdir_p(const char *path)
{
    char buf[4400];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(buf))
        LOG_FAIL(SERVICE_LOG, "mkdir_p path too long: %.64s...", path);
    memcpy(buf, path, len + 1);
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, 0700) != 0 && errno != EEXIST)
            LOG_FAIL(SERVICE_LOG, "mkdir %s: %s", buf, strerror(errno));
        *p = '/';
    }
    if (mkdir(buf, 0700) != 0 && errno != EEXIST)
        LOG_FAIL(SERVICE_LOG, "mkdir %s: %s", buf, strerror(errno));
    return true;
}

/* Durable write: temp sibling + fsync + atomic rename (the
 * package_reward discipline). A crash leaves either the old file or the
 * new one, never a torn one. */
static bool svc_atomic_write(const char *path, const uint8_t *data,
                             size_t data_len)
{
    static _Atomic uint64_t g_seq = 0;
    uint64_t seq = atomic_fetch_add(&g_seq, 1);
    char tmp[4400];
    int tn = snprintf(tmp, sizeof(tmp), "%s.tmp.%ld.%llu", path,
                      (long)getpid(), (unsigned long long)seq);
    if (tn <= 0 || (size_t)tn >= sizeof(tmp))
        LOG_FAIL(SERVICE_LOG, "temp path too long for %s", path);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        LOG_FAIL(SERVICE_LOG, "open temp %s: %s", tmp, strerror(errno));
    size_t off = 0;
    while (off < data_len) {
        ssize_t w = write(fd, data + off, data_len - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            unlink(tmp);
            LOG_FAIL(SERVICE_LOG, "write temp %s: %s", tmp,
                     strerror(errno));
        }
        off += (size_t)w;
    }
    if (fsync(fd) != 0) {
        close(fd);
        unlink(tmp);
        LOG_FAIL(SERVICE_LOG, "fsync temp %s: %s", tmp, strerror(errno));
    }
    if (close(fd) != 0) {
        unlink(tmp);
        LOG_FAIL(SERVICE_LOG, "close temp %s: %s", tmp, strerror(errno));
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        LOG_FAIL(SERVICE_LOG, "rename %s -> %s: %s", tmp, path,
                 strerror(errno));
    }
    return true;
}

/* ── the wire (fixed 96 bytes) ──────────────────────────────────────── *
 * [0..3]   magic "ZSV1"
 * [4]      event kind (1..5)
 * [5]      sub-kind (offence / no-credit kind; 0 otherwise)
 * [6..7]   reserved, zero
 * [8..40]  contributor pubkey (33 compressed bytes)
 * [41..72] subject (request id / release id; zeros otherwise)
 * [73..80] bytes u64 LE (0 for publish/offence)
 * [81..88] day i64 LE
 * [89..92] seq u32 LE (offence / no-credit; 0 otherwise)
 * [93..95] reserved, zero */

struct svc_event {
    uint8_t kind;
    uint8_t sub;
    uint8_t contributor[33];
    uint8_t subject[32];
    uint64_t bytes;
    int64_t day;
    uint32_t seq;
};

static void svc_wire_encode(const struct svc_event *e,
                            uint8_t out[VCS_SERVICE_WIRE_BYTES])
{
    memset(out, 0, VCS_SERVICE_WIRE_BYTES);
    out[0] = SVC_MAGIC0;
    out[1] = SVC_MAGIC1;
    out[2] = SVC_MAGIC2;
    out[3] = SVC_MAGIC3;
    out[4] = e->kind;
    out[5] = e->sub;
    memcpy(out + 8, e->contributor, 33);
    memcpy(out + 41, e->subject, 32);
    svc_put_u64(out + 73, e->bytes);
    svc_put_u64(out + 81, (uint64_t)e->day);
    svc_put_u32(out + 89, e->seq);
}

static bool svc_wire_decode(const uint8_t *wire, size_t len,
                            struct svc_event *out)
{
    if (len != VCS_SERVICE_WIRE_BYTES)
        return false;
    if (wire[0] != SVC_MAGIC0 || wire[1] != SVC_MAGIC1 ||
        wire[2] != SVC_MAGIC2 || wire[3] != SVC_MAGIC3)
        return false;
    if (wire[6] != 0 || wire[7] != 0 || wire[93] != 0 || wire[94] != 0 ||
        wire[95] != 0)
        return false;
    memset(out, 0, sizeof(*out));
    out->kind = wire[4];
    out->sub = wire[5];
    memcpy(out->contributor, wire + 8, 33);
    memcpy(out->subject, wire + 41, 32);
    out->bytes = svc_get_u64(wire + 73);
    out->day = (int64_t)svc_get_u64(wire + 81);
    out->seq = svc_get_u32(wire + 89);
    if (out->kind < SVC_EVENT_UPLOAD || out->kind > SVC_EVENT_NO_CREDIT)
        return false;
    if (out->contributor[0] != 0x02 && out->contributor[0] != 0x03)
        return false;
    switch (out->kind) {
    case SVC_EVENT_UPLOAD:
    case SVC_EVENT_DOWNLOAD:
        if (out->sub != 0 || out->seq != 0 || out->bytes == 0 ||
            svc_is_zero(out->subject, 32))
            return false;
        break;
    case SVC_EVENT_PUBLISH:
        if (out->sub != 0 || out->seq != 0 || out->bytes != 0 ||
            svc_is_zero(out->subject, 32))
            return false;
        break;
    case SVC_EVENT_OFFENCE:
        if (out->sub >= VCS_POLICY_OFFENCE_COUNT || out->bytes != 0)
            return false;
        break;
    case SVC_EVENT_NO_CREDIT:
        if (out->sub >= VCS_POLICY_NO_CREDIT_COUNT)
            return false;
        break;
    default:
        return false;
    }
    return true;
}

static void svc_event_id(const uint8_t wire[VCS_SERVICE_WIRE_BYTES],
                         uint8_t out[32])
{
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, k_domain_event, sizeof(k_domain_event) - 1u);
    sha3_256_write(&c, wire, VCS_SERVICE_WIRE_BYTES);
    sha3_256_finalize(&c, out);
}

/* ── in-memory accounts ─────────────────────────────────────────────── */

struct svc_publish {
    uint8_t release_id[32];
    int64_t day;
};

struct svc_week {
    int64_t week_start;
    uint64_t bytes;
};

struct svc_account {
    uint8_t key[33];
    uint64_t up;
    uint64_t down;
    struct svc_publish *pubs;
    size_t pub_count;
    struct svc_week weeks[VCS_SERVICE_DOWNLOAD_WEEKS];
    size_t week_count;
    uint32_t offences[VCS_POLICY_OFFENCE_COUNT];
    uint32_t offence_total;
    uint64_t no_credit[VCS_POLICY_NO_CREDIT_COUNT];
    uint64_t no_credit_bytes;
};

struct vcs_service_book {
    char events_dir[4400];
    struct svc_account **accts; /* ascending by key */
    size_t acct_count;
    size_t acct_cap;
    uint8_t (*event_ids)[32];   /* ascending, for redelivery dedup */
    size_t id_count;
    uint8_t (*key_reqs)[65];    /* ascending contributor||request-id */
    size_t req_count;
    size_t event_count;
    uint32_t corrupt;
    bool truncated;
    uint64_t total_up;
    uint64_t total_down;
    uint64_t total_offences;
    uint64_t total_no_credit_bytes;
};

/* Binary-search a sorted array of fixed-width byte strings. Returns the
 * index when found (*found = true) or the insertion point. */
static size_t svc_bsearch(const void *base, size_t count, size_t width,
                          const uint8_t *needle, bool *found)
{
    size_t lo = 0, hi = count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int cmp = memcmp((const uint8_t *)base + mid * width, needle,
                         width);
        if (cmp == 0) {
            *found = true;
            return mid;
        }
        if (cmp < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    *found = false;
    return lo;
}

static struct svc_account *svc_account_find(
    const struct vcs_service_book *book, const uint8_t key[33],
    size_t *index_out, bool *found_out)
{
    size_t lo = 0, hi = book->acct_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int cmp = memcmp(book->accts[mid]->key, key, 33);
        if (cmp == 0) {
            *found_out = true;
            *index_out = mid;
            return book->accts[mid];
        }
        if (cmp < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    *found_out = false;
    *index_out = lo;
    return NULL;
}

static struct svc_account *svc_account_get(struct vcs_service_book *book,
                                           const uint8_t key[33],
                                           bool *created_out)
{
    size_t idx;
    bool found;
    struct svc_account *a = svc_account_find(book, key, &idx, &found);
    if (found) {
        if (created_out)
            *created_out = false;
        return a;
    }
    if (book->acct_count >= VCS_SERVICE_MAX_KEYS) {
        book->truncated = true;
        return NULL;
    }
    if (book->acct_count == book->acct_cap) {
        size_t cap = book->acct_cap ? book->acct_cap * 2 : 16;
        struct svc_account **na =
            zcl_malloc(cap * sizeof(*na), "svc_accts_grow");
        if (!na)
            return NULL;
        if (book->accts) {
            memcpy(na, book->accts,
                   book->acct_count * sizeof(*na));
            free(book->accts);
        }
        book->accts = na;
        book->acct_cap = cap;
    }
    a = zcl_malloc(sizeof(*a), "svc_account");
    if (!a)
        return NULL;
    memset(a, 0, sizeof(*a));
    memcpy(a->key, key, 33);
    memmove(&book->accts[idx + 1], &book->accts[idx],
            (book->acct_count - idx) * sizeof(*book->accts));
    book->accts[idx] = a;
    book->acct_count++;
    if (created_out)
        *created_out = true;
    return a;
}

static bool svc_event_id_seen(const struct vcs_service_book *book,
                              const uint8_t id[32], size_t *idx_out,
                              bool *found_out)
{
    *idx_out = svc_bsearch(book->event_ids, book->id_count, 32, id,
                           found_out);
    return *found_out;
}

static bool svc_event_id_insert(struct vcs_service_book *book,
                                const uint8_t id[32])
{
    size_t idx;
    bool found;
    if (svc_event_id_seen(book, id, &idx, &found) || found)
        return true; /* already known: nothing to insert */
    if (book->id_count >= VCS_SERVICE_MAX_EVENTS) {
        book->truncated = true;
        LOG_FAIL(SERVICE_LOG, "event id bound reached (%u)",
                 VCS_SERVICE_MAX_EVENTS);
    }
    size_t cap = book->id_count + 256;
    if (book->id_count == 0 || book->id_count % 256 == 0) {
        uint8_t (*ni)[32] = zcl_malloc(cap * sizeof(*ni), "svc_ids_grow");
        if (!ni)
            LOG_FAIL(SERVICE_LOG, "event id array alloc");
        if (book->event_ids) {
            memcpy(ni, book->event_ids, book->id_count * 32);
            free(book->event_ids);
        }
        book->event_ids = ni;
    }
    memmove(&book->event_ids[idx + 1], &book->event_ids[idx],
            (book->id_count - idx) * sizeof(*book->event_ids));
    memcpy(book->event_ids[idx], id, 32);
    book->id_count++;
    return true;
}

/* True when contributor||request_id is already known; inserts it when
 * not. False (logged, truncated set) when the request bound is reached. */
static bool svc_request_seen_or_insert(struct vcs_service_book *book,
                                       const uint8_t contributor[33],
                                       const uint8_t request_id[32],
                                       bool *seen_out)
{
    uint8_t kr[65];
    memcpy(kr, contributor, 33);
    memcpy(kr + 33, request_id, 32);
    bool found;
    size_t idx = svc_bsearch(book->key_reqs, book->req_count, 65, kr,
                             &found);
    if (found) {
        *seen_out = true;
        return true;
    }
    if (book->req_count >= VCS_SERVICE_MAX_REQUESTS) {
        book->truncated = true;
        LOG_FAIL(SERVICE_LOG, "request id bound reached (%u)",
                 VCS_SERVICE_MAX_REQUESTS);
    }
    if (book->req_count % 512 == 0) {
        size_t cap = book->req_count + 512;
        uint8_t (*nk)[65] = zcl_malloc(cap * sizeof(*nk), "svc_reqs_grow");
        if (!nk)
            LOG_FAIL(SERVICE_LOG, "request array alloc");
        if (book->key_reqs) {
            memcpy(nk, book->key_reqs, book->req_count * 65);
            free(book->key_reqs);
        }
        book->key_reqs = nk;
    }
    memmove(&book->key_reqs[idx + 1], &book->key_reqs[idx],
            (book->req_count - idx) * sizeof(*book->key_reqs));
    memcpy(book->key_reqs[idx], kr, 65);
    book->req_count++;
    *seen_out = false;
    return true;
}

/* ── event application (in-memory; shared by replay and recording) ──── */

static void svc_apply_upload(struct vcs_service_book *book,
                             struct svc_account *a,
                             const struct svc_event *e)
{
    a->up += e->bytes;
    book->total_up += e->bytes;
}

static void svc_apply_download(struct vcs_service_book *book,
                               struct svc_account *a,
                               const struct svc_event *e)
{
    a->down += e->bytes;
    book->total_down += e->bytes;
    int64_t ws = vcs_policy_week_start(e->day);
    size_t i = 0;
    while (i < a->week_count && a->weeks[i].week_start < ws)
        i++;
    if (i < a->week_count && a->weeks[i].week_start == ws) {
        a->weeks[i].bytes += e->bytes;
        return;
    }
    if (a->week_count < VCS_SERVICE_DOWNLOAD_WEEKS) {
        memmove(&a->weeks[i + 1], &a->weeks[i],
                (a->week_count - i) * sizeof(a->weeks[0]));
        a->weeks[i].week_start = ws;
        a->weeks[i].bytes = e->bytes;
        a->week_count++;
        return;
    }
    /* Full: only a NEWER week may evict the oldest bucket (old-week
     * resolution is what the windowed query never needs again). */
    if (ws > a->weeks[a->week_count - 1].week_start) {
        memmove(&a->weeks[0], &a->weeks[1],
                (a->week_count - 1) * sizeof(a->weeks[0]));
        a->weeks[a->week_count - 1].week_start = ws;
        a->weeks[a->week_count - 1].bytes = e->bytes;
    }
}

static void svc_apply_offence(struct vcs_service_book *book,
                              struct svc_account *a,
                              const struct svc_event *e)
{
    a->offences[e->sub]++;
    a->offence_total++;
    book->total_offences++;
}

static void svc_apply_no_credit(struct vcs_service_book *book,
                                struct svc_account *a,
                                const struct svc_event *e)
{
    a->no_credit[e->sub]++;
    a->no_credit_bytes += e->bytes;
    book->total_no_credit_bytes += e->bytes;
}

/* ── load / free ────────────────────────────────────────────────────── */

struct vcs_service_book *vcs_service_book_load(const char *zcode_dir)
{
    if (!zcode_dir || !zcode_dir[0])
        LOG_NULL(SERVICE_LOG, "missing zcode dir");
    struct vcs_service_book *book = zcl_malloc(sizeof(*book), "svc_book");
    if (!book)
        LOG_NULL(SERVICE_LOG, "book alloc");
    memset(book, 0, sizeof(*book));
    int n = snprintf(book->events_dir, sizeof(book->events_dir),
                     "%s/service/events", zcode_dir);
    if (n <= 0 || (size_t)n >= sizeof(book->events_dir)) {
        free(book);
        LOG_NULL(SERVICE_LOG, "zcode dir path too long");
    }

    DIR *dir = opendir(book->events_dir);
    if (!dir)
        return book; /* a missing events dir is an empty book */

    /* Collect the 64-hex names, sort ascending, replay in order. */
    char (*names)[65] = NULL;
    size_t name_count = 0, name_cap = 0;
    struct dirent *ent;
    bool scan_failed = false;
    while ((ent = readdir(dir)) != NULL) {
        if (!svc_name_is_hex64(ent->d_name))
            continue;
        if (name_count >= VCS_SERVICE_MAX_EVENTS) {
            book->truncated = true;
            break;
        }
        if (name_count == name_cap) {
            size_t cap = name_cap ? name_cap * 2 : 64;
            char (*nn)[65] = zcl_malloc(cap * sizeof(*nn), "svc_names");
            if (!nn) {
                scan_failed = true;
                break;
            }
            if (names) {
                memcpy(nn, names, name_count * sizeof(*nn));
                free(names);
            }
            names = nn;
            name_cap = cap;
        }
        memcpy(names[name_count], ent->d_name, 65);
        name_count++;
    }
    closedir(dir);
    if (scan_failed) {
        free(names);
        vcs_service_book_free(book);
        LOG_NULL(SERVICE_LOG, "event scan alloc");
    }
    /* Insertion sort (event counts are bounded; ascending id order). */
    for (size_t i = 1; i < name_count; i++) {
        char key[65];
        memcpy(key, names[i], 65);
        size_t j = i;
        while (j > 0 && memcmp(names[j - 1], key, 65) > 0) {
            memcpy(names[j], names[j - 1], 65);
            j--;
        }
        memcpy(names[j], key, 65);
    }

    for (size_t i = 0; i < name_count; i++) {
        char path[4400];
        int pn = snprintf(path, sizeof(path), "%s/%.64s", book->events_dir,
                          names[i]);
        if (pn <= 0 || (size_t)pn >= sizeof(path)) {
            book->corrupt++;
            continue;
        }
        uint8_t wire[VCS_SERVICE_WIRE_BYTES];
        FILE *f = fopen(path, "rb");
        if (!f) {
            book->corrupt++;
            continue;
        }
        size_t got = fread(wire, 1, sizeof(wire), f);
        int extra = fgetc(f);
        fclose(f);
        struct svc_event e;
        uint8_t file_id[32], want_id[32];
        if (got != sizeof(wire) || extra != EOF ||
            !svc_wire_decode(wire, got, &e) ||
            !zcl_hex_decode_lower(names[i], file_id, 32)) {
            LOG_WARN(SERVICE_LOG, "skipping corrupt event wire %.16s",
                     names[i]);
            book->corrupt++;
            continue;
        }
        svc_event_id(wire, want_id);
        if (memcmp(file_id, want_id, 32) != 0) {
            LOG_WARN(SERVICE_LOG,
                     "event wire id mismatch %.16s (content-addressed "
                     "name != content)", names[i]);
            book->corrupt++;
            continue;
        }
        size_t id_idx;
        bool id_found;
        (void)svc_event_id_seen(book, want_id, &id_idx, &id_found);
        if (id_found) /* impossible via filenames; belt and braces */
            continue;
        bool created = false;
        struct svc_account *a = svc_account_get(book, e.contributor,
                                                &created);
        if (!a) {
            book->truncated = true;
            continue;
        }
        switch (e.kind) {
        case SVC_EVENT_UPLOAD: {
            bool seen = false;
            if (!svc_request_seen_or_insert(book, e.contributor,
                                            e.subject, &seen))
                break; /* bound: counted truncated inside */
            if (!seen)
                svc_apply_upload(book, a, &e);
            break;
        }
        case SVC_EVENT_DOWNLOAD: {
            bool seen = false;
            if (!svc_request_seen_or_insert(book, e.contributor,
                                            e.subject, &seen))
                break;
            if (!seen)
                svc_apply_download(book, a, &e);
            break;
        }
        case SVC_EVENT_PUBLISH: {
            bool dup = false;
            for (size_t p = 0; p < a->pub_count; p++)
                if (memcmp(a->pubs[p].release_id, e.subject, 32) == 0) {
                    dup = true;
                    break;
                }
            if (dup)
                break;
            if (a->pub_count >= VCS_SERVICE_MAX_PUBLISHES_PER_KEY) {
                book->truncated = true;
                break;
            }
            struct svc_publish *np = zcl_malloc(
                (a->pub_count + 1) * sizeof(*np), "svc_pubs_grow");
            if (!np) {
                book->truncated = true;
                break;
            }
            if (a->pubs) {
                memcpy(np, a->pubs, a->pub_count * sizeof(*np));
                free(a->pubs);
            }
            a->pubs = np;
            memcpy(a->pubs[a->pub_count].release_id, e.subject, 32);
            a->pubs[a->pub_count].day = e.day;
            a->pub_count++;
            break;
        }
        case SVC_EVENT_OFFENCE:
            svc_apply_offence(book, a, &e);
            break;
        case SVC_EVENT_NO_CREDIT:
            svc_apply_no_credit(book, a, &e);
            break;
        }
        if (!svc_event_id_insert(book, want_id)) {
            /* alloc failure already logged */
            continue;
        }
        book->event_count++;
    }
    free(names);
    return book;
}

void vcs_service_book_free(struct vcs_service_book *book)
{
    if (!book)
        return;
    for (size_t i = 0; i < book->acct_count; i++) {
        free(book->accts[i]->pubs);
        free(book->accts[i]);
    }
    free(book->accts);
    free(book->event_ids);
    free(book->key_reqs);
    free(book);
}

size_t vcs_service_book_event_count(const struct vcs_service_book *book)
{
    return book ? book->event_count : 0;
}

uint32_t vcs_service_book_corrupt_count(const struct vcs_service_book *book)
{
    return book ? book->corrupt : 0;
}

bool vcs_service_book_truncated(const struct vcs_service_book *book)
{
    return book ? book->truncated : false;
}

size_t vcs_service_book_key_count(const struct vcs_service_book *book)
{
    return book ? book->acct_count : 0;
}

bool vcs_service_book_key_at(const struct vcs_service_book *book,
                             size_t index, uint8_t out[33])
{
    if (!book || !out || index >= book->acct_count)
        return false;
    memcpy(out, book->accts[index]->key, 33);
    return true;
}

/* ── recording ──────────────────────────────────────────────────────── */
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

/* Persist one event wire, then apply it in memory. The event id dedup
 * check runs BEFORE the write, so a redelivery is a dedup no-op. Returns
 * false on durable-write or allocation failure (logged; memory untouched)
 * and sets *dup_out when the event id was already known. */
static bool svc_persist_event(struct vcs_service_book *book,
                              const struct svc_event *e, bool *dup_out)
{
    *dup_out = false;
    uint8_t wire[VCS_SERVICE_WIRE_BYTES];
    svc_wire_encode(e, wire);
    uint8_t id[32];
    svc_event_id(wire, id);
    size_t idx;
    bool found;
    (void)svc_event_id_seen(book, id, &idx, &found);
    if (found) {
        *dup_out = true;
        return true;
    }
    if (book->id_count >= VCS_SERVICE_MAX_EVENTS)
        LOG_FAIL(SERVICE_LOG, "event bound reached (%u)",
                 VCS_SERVICE_MAX_EVENTS);
    if (!svc_mkdir_p(book->events_dir))
        return false; /* logged */
    char hex[65];
    zcl_hex_encode(id, 32, hex);
    char path[4400];
    int pn = snprintf(path, sizeof(path), "%s/%s", book->events_dir, hex);
    if (pn <= 0 || (size_t)pn >= sizeof(path))
        LOG_FAIL(SERVICE_LOG, "event path too long");
    if (!svc_atomic_write(path, wire, sizeof(wire)))
        return false; /* logged */
    if (!svc_event_id_insert(book, id))
        return false; /* logged */
    book->event_count++;
    return true;
}

static enum vcs_service_credit_result svc_credit(
    struct vcs_service_book *book, const uint8_t contributor[33],
    const uint8_t request_id[32], uint64_t bytes, int64_t day, bool upload)
{
    if (!book || !contributor || !request_id ||
        svc_is_zero(request_id, 32) || bytes == 0 ||
        (contributor[0] != 0x02 && contributor[0] != 0x03))
        return VCS_SERVICE_CREDIT_BAD_INPUT;

    /* Exact redelivery dedup (the event id covers kind+key+request+bytes
     * +day) must be checked BEFORE the request-id replay check so a
     * same-event retry reports DUPLICATE, not REPLAYED_REQUEST. */
    struct svc_event e;
    memset(&e, 0, sizeof(e));
    e.kind = upload ? SVC_EVENT_UPLOAD : SVC_EVENT_DOWNLOAD;
    memcpy(e.contributor, contributor, 33);
    memcpy(e.subject, request_id, 32);
    e.bytes = bytes;
    e.day = day;
    uint8_t wire[VCS_SERVICE_WIRE_BYTES];
    svc_wire_encode(&e, wire);
    uint8_t id[32];
    svc_event_id(wire, id);
    {
        size_t idx;
        bool found;
        (void)svc_event_id_seen(book, id, &idx, &found);
        if (found)
            return VCS_SERVICE_CREDIT_DUPLICATE;
    }

    /* A request id already seen is a REPLAYED REQUEST: no credit, ever
     * (repeated copies of the same request earn nothing). */
    bool seen = false;
    if (!svc_request_seen_or_insert(book, contributor, request_id, &seen))
        return VCS_SERVICE_CREDIT_FULL; /* bound; logged, truncated */
    if (seen)
        return VCS_SERVICE_CREDIT_REPLAYED_REQUEST;

    bool created = false;
    struct svc_account *a = svc_account_get(book, contributor, &created);
    if (!a)
        return VCS_SERVICE_CREDIT_FULL; /* bound/alloc; truncated set */

    bool dup = false;
    if (!svc_persist_event(book, &e, &dup))
        return VCS_SERVICE_CREDIT_IO; /* logged */
    if (dup)
        return VCS_SERVICE_CREDIT_DUPLICATE; /* raced redelivery */
    if (upload)
        svc_apply_upload(book, a, &e);
    else
        svc_apply_download(book, a, &e);
    return VCS_SERVICE_CREDIT_OK;
}

enum vcs_service_credit_result vcs_service_credit_upload(
    struct vcs_service_book *book, const uint8_t contributor[33],
    const uint8_t request_id[32], uint64_t bytes, int64_t day)
{
    return svc_credit(book, contributor, request_id, bytes, day, true);
}

enum vcs_service_credit_result vcs_service_credit_download(
    struct vcs_service_book *book, const uint8_t contributor[33],
    const uint8_t request_id[32], uint64_t bytes, int64_t day)
{
    return svc_credit(book, contributor, request_id, bytes, day, false);
}

enum vcs_service_record_result vcs_service_record_publish(
    struct vcs_service_book *book, const uint8_t contributor[33],
    const uint8_t release_id[32], int64_t day)
{
    if (!book || !contributor || !release_id ||
        svc_is_zero(release_id, 32) ||
        (contributor[0] != 0x02 && contributor[0] != 0x03))
        return VCS_SERVICE_RECORD_BAD_INPUT;
    bool created = false;
    struct svc_account *a = svc_account_get(book, contributor, &created);
    if (!a)
        return VCS_SERVICE_RECORD_FULL;
    for (size_t p = 0; p < a->pub_count; p++)
        if (memcmp(a->pubs[p].release_id, release_id, 32) == 0)
            return VCS_SERVICE_RECORD_DUPLICATE; /* republish: no 2nd event */
    if (a->pub_count >= VCS_SERVICE_MAX_PUBLISHES_PER_KEY)
        return VCS_SERVICE_RECORD_FULL;

    struct svc_event e;
    memset(&e, 0, sizeof(e));
    e.kind = SVC_EVENT_PUBLISH;
    memcpy(e.contributor, contributor, 33);
    memcpy(e.subject, release_id, 32);
    e.day = day;
    bool dup = false;
    if (!svc_persist_event(book, &e, &dup))
        return VCS_SERVICE_RECORD_IO;
    if (dup)
        return VCS_SERVICE_RECORD_DUPLICATE;

    struct svc_publish *np = zcl_malloc(
        (a->pub_count + 1) * sizeof(*np), "svc_pubs_grow");
    if (!np)
        return VCS_SERVICE_RECORD_IO; /* durable fact written; the in-memory
                                         view is rebuilt on next load */
    if (a->pubs) {
        memcpy(np, a->pubs, a->pub_count * sizeof(*np));
        free(a->pubs);
    }
    a->pubs = np;
    memcpy(a->pubs[a->pub_count].release_id, release_id, 32);
    a->pubs[a->pub_count].day = day;
    a->pub_count++;
    return VCS_SERVICE_RECORD_OK;
}

enum vcs_service_record_result vcs_service_record_offence(
    struct vcs_service_book *book, const uint8_t contributor[33],
    enum vcs_policy_offence kind, int64_t day)
{
    if (!book || !contributor || kind < 0 ||
        kind >= VCS_POLICY_OFFENCE_COUNT ||
        (contributor[0] != 0x02 && contributor[0] != 0x03))
        return VCS_SERVICE_RECORD_BAD_INPUT;
    bool created = false;
    struct svc_account *a = svc_account_get(book, contributor, &created);
    if (!a)
        return VCS_SERVICE_RECORD_FULL;

    struct svc_event e;
    memset(&e, 0, sizeof(e));
    e.kind = SVC_EVENT_OFFENCE;
    e.sub = (uint8_t)kind;
    memcpy(e.contributor, contributor, 33);
    e.day = day;
    e.seq = a->offences[kind]; /* deterministic: the running count */
    bool dup = false;
    if (!svc_persist_event(book, &e, &dup))
        return VCS_SERVICE_RECORD_IO;
    if (dup)
        return VCS_SERVICE_RECORD_DUPLICATE;
    svc_apply_offence(book, a, &e);
    return VCS_SERVICE_RECORD_OK;
}

enum vcs_service_record_result vcs_service_record_no_credit(
    struct vcs_service_book *book, const uint8_t contributor[33],
    enum vcs_policy_no_credit kind, uint64_t bytes, int64_t day)
{
    if (!book || !contributor || kind < 0 ||
        kind >= VCS_POLICY_NO_CREDIT_COUNT ||
        (contributor[0] != 0x02 && contributor[0] != 0x03))
        return VCS_SERVICE_RECORD_BAD_INPUT;
    bool created = false;
    struct svc_account *a = svc_account_get(book, contributor, &created);
    if (!a)
        return VCS_SERVICE_RECORD_FULL;

    struct svc_event e;
    memset(&e, 0, sizeof(e));
    e.kind = SVC_EVENT_NO_CREDIT;
    e.sub = (uint8_t)kind;
    memcpy(e.contributor, contributor, 33);
    e.bytes = bytes;
    e.day = day;
    e.seq = (uint32_t)a->no_credit[kind]; /* the running count */
    bool dup = false;
    if (!svc_persist_event(book, &e, &dup))
        return VCS_SERVICE_RECORD_IO;
    if (dup)
        return VCS_SERVICE_RECORD_DUPLICATE;
    svc_apply_no_credit(book, a, &e);
    return VCS_SERVICE_RECORD_OK;
}

/* ── queries ────────────────────────────────────────────────────────── */

bool vcs_service_key_totals(const struct vcs_service_book *book,
                            const uint8_t contributor[33], int64_t day,
                            struct vcs_service_key_totals *out)
{
    if (!book || !contributor || !out)
        LOG_FAIL(SERVICE_LOG, "null argument");
    memset(out, 0, sizeof(*out));
    size_t idx;
    bool found;
    struct svc_account *a = svc_account_find(book, contributor, &idx,
                                             &found);
    if (!found)
        return true; /* present:false — an unknown key is not an error */
    out->present = true;
    out->verified_bytes_uploaded = a->up;
    out->verified_bytes_downloaded = a->down;
    out->ratio_milli = vcs_policy_ratio_milli(a->up, a->down);
    out->publish_events = (uint32_t)a->pub_count;
    memcpy(out->offences, a->offences, sizeof(out->offences));
    out->offence_total = a->offence_total;
    memcpy(out->no_credit_events, a->no_credit,
           sizeof(out->no_credit_events));
    out->no_credit_bytes = a->no_credit_bytes;
    if (day >= 0) {
        int64_t ws = vcs_policy_week_start(day);
        for (size_t i = 0; i < a->week_count; i++)
            if (a->weeks[i].week_start == ws)
                out->downloaded_this_week = a->weeks[i].bytes;
        for (size_t p = 0; p < a->pub_count; p++)
            if (vcs_policy_week_start(a->pubs[p].day) == ws)
                out->publishes_this_week++;
    }
    return true;
}

void vcs_service_book_totals(const struct vcs_service_book *book,
                             struct vcs_service_book_totals *out)
{
    memset(out, 0, sizeof(*out));
    if (!book)
        return;
    out->verified_bytes_uploaded = book->total_up;
    out->verified_bytes_downloaded = book->total_down;
    out->offence_total = book->total_offences;
    out->no_credit_bytes = book->total_no_credit_bytes;
}
#endif
