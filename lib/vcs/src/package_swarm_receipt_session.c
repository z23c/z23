/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Dual-signed receipt session beside the frozen v1 swarm wire. Identity
 * and receipts never become ANNOUNCE/WANT/DATA/CANCEL types. */

#include "vcs/package_swarm_node.h"

#include "package_store_priv.h"

#include "crypto/random_secret.h"
#include "platform/file_metadata.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "support/cleanse.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <secp256k1.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SESSION_LOG "vcs.swarm-receipt"

struct receipt_peer {
    bool used;
    uint64_t peer;
    uint8_t remote_pub[33];
    bool have_remote;
    bool identity_sent;
    bool settled;
    bool offered;
    uint8_t offered_root[32];
    uint64_t offered_bytes;
};

struct vcs_swarm_receipt_session {
    secp256k1_context *ctx;
    uint8_t secret[32];
    uint8_t local_pub[33];
    struct receipt_peer peers[VCS_SWARM_MAX_PEERS];
};

static bool derive_pub(secp256k1_context *ctx, const uint8_t secret[32],
                       uint8_t pub[33])
{
    secp256k1_pubkey parsed;
    size_t plen = 33;
    if (secp256k1_ec_pubkey_create(ctx, &parsed, secret) != 1)
        return false;
    return secp256k1_ec_pubkey_serialize(ctx, pub, &plen, &parsed,
                                         SECP256K1_EC_COMPRESSED) == 1 &&
           plen == 33;
}

static struct vcs_swarm_receipt_session *session_from_secret(
    const uint8_t secret[32])
{
    struct vcs_swarm_receipt_session *s =
        zcl_malloc(sizeof(*s), "vcs_swarm_receipt_session");
    if (!s)
        LOG_NULL(SESSION_LOG, "session allocation failed");
    memset(s, 0, sizeof(*s));
    s->ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                      SECP256K1_CONTEXT_VERIFY);
    if (!s->ctx) {
        free(s);
        LOG_NULL(SESSION_LOG, "secp256k1 context failed");
    }
    memcpy(s->secret, secret, 32);
    if (!secp256k1_ec_seckey_verify(s->ctx, s->secret) ||
        !derive_pub(s->ctx, s->secret, s->local_pub)) {
        secp256k1_context_destroy(s->ctx);
        memory_cleanse(s->secret, sizeof(s->secret));
        free(s);
        LOG_NULL(SESSION_LOG, "receipt secret is not a secp256k1 key");
    }
    return s;
}

static bool read_key_0600(const char *path, uint8_t secret[32])
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path) ||
        !platform_positioned_file_is_private(&file) ||
        !platform_positioned_file_snapshot(&file, &before) ||
        before.size != 32) {
        platform_positioned_file_close(&file);
        LOG_FAIL(SESSION_LOG, "receipt key has wrong size or mode");
    }
    int64_t nr = platform_positioned_file_read(&file, secret, 32, 0);
    bool stable = platform_positioned_file_snapshot(&file, &after) &&
                  memcmp(&before, &after, sizeof(before)) == 0;
    platform_positioned_file_close(&file);
    if (nr != 32 || !stable) {
        memory_cleanse(secret, 32);
        LOG_FAIL(SESSION_LOG, "receipt key read was not exact");
    }
    return true;
}

struct vcs_swarm_receipt_session *vcs_swarm_receipt_session_open(
    const char *zcode_dir)
{
    if (!zcode_dir || !zcode_dir[0])
        LOG_NULL(SESSION_LOG, "receipt session: missing zcode_dir");
    if (!platform_private_directory_ensure(zcode_dir))
        LOG_NULL(SESSION_LOG, "receipt session: cannot create zcode_dir");
    char path[STORE_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", zcode_dir,
                     VCS_SWARM_RECEIPT_KEY_FILE);
    if (n <= 0 || (size_t)n >= sizeof(path))
        LOG_NULL(SESSION_LOG, "receipt key path too long");
    uint8_t secret[32];
    struct platform_file_metadata metadata;
    enum platform_file_metadata_result key_state =
        platform_file_metadata_read(path, &metadata);
    if (key_state == PLATFORM_FILE_METADATA_OK) {
        if (!read_key_0600(path, secret))
            return NULL;
    } else if (key_state == PLATFORM_FILE_METADATA_MISSING) {
        secp256k1_context *probe =
            secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        if (!probe)
            LOG_NULL(SESSION_LOG, "receipt key: secp context failed");
        do {
            if (!zcl_random_secret_bytes(secret, 32, "zcode_receipt_secp")) {
                secp256k1_context_destroy(probe);
                LOG_NULL(SESSION_LOG, "receipt key: no entropy");
            }
        } while (!secp256k1_ec_seckey_verify(probe, secret));
        secp256k1_context_destroy(probe);
        struct platform_private_file key;
        struct platform_private_file_identity key_identity;
        platform_private_file_init(&key);
        bool created = platform_private_file_create(path, &key) &&
                       platform_private_file_identity(&key, &key_identity);
        bool persisted = created &&
                         platform_private_file_write_at(&key, secret, 32, 0) &&
                         platform_private_file_truncate(&key, 32) &&
                         platform_private_file_flush(&key) &&
                         platform_private_parent_flush(zcode_dir);
        if (!persisted && created)
            (void)platform_private_file_retire_if_identity(
                &key, path, &key_identity);
        platform_private_file_close(&key);
        if (!persisted) {
            memory_cleanse(secret, 32);
            LOG_NULL(SESSION_LOG, "receipt key: persist failed");
        }
    } else {
        LOG_NULL(SESSION_LOG, "receipt key: cannot inspect %s", path);
    }
    struct vcs_swarm_receipt_session *s = session_from_secret(secret);
    memory_cleanse(secret, 32);
    return s;
}

struct vcs_swarm_receipt_session *vcs_swarm_receipt_session_open_secret(
    const uint8_t secret[32])
{
    if (!secret)
        LOG_NULL(SESSION_LOG, "open_secret: null secret");
    return session_from_secret(secret);
}

void vcs_swarm_receipt_session_free(struct vcs_swarm_receipt_session *s)
{
    if (!s)
        return;
    if (s->ctx)
        secp256k1_context_destroy(s->ctx);
    memory_cleanse(s->secret, sizeof(s->secret));
    memset(s, 0, sizeof(*s));
    free(s);
}

static struct receipt_peer *peer_find(struct vcs_swarm_receipt_session *s,
                                      uint64_t peer, bool create)
{
    if (!s || peer == 0)
        return NULL;
    int empty = -1;
    for (size_t i = 0; i < VCS_SWARM_MAX_PEERS; i++) {
        if (s->peers[i].used && s->peers[i].peer == peer)
            return &s->peers[i];
        if (!s->peers[i].used && empty < 0)
            empty = (int)i;
    }
    if (!create || empty < 0)
        return NULL;
    struct receipt_peer *p = &s->peers[empty];
    memset(p, 0, sizeof(*p));
    p->used = true;
    p->peer = peer;
    return p;
}

bool vcs_swarm_receipt_session_local_pub(
    const struct vcs_swarm_receipt_session *s, uint8_t out[33])
{
    if (!s || !out)
        return false;
    memcpy(out, s->local_pub, 33);
    return true;
}

bool vcs_swarm_receipt_session_remote_pub(
    const struct vcs_swarm_receipt_session *s, uint64_t peer,
    uint8_t out[33])
{
    if (!s || !out || peer == 0)
        return false;
    for (size_t i = 0; i < VCS_SWARM_MAX_PEERS; i++) {
        if (s->peers[i].used && s->peers[i].peer == peer &&
            s->peers[i].have_remote) {
            memcpy(out, s->peers[i].remote_pub, 33);
            return true;
        }
    }
    return false;
}

bool vcs_swarm_receipt_session_settled(
    const struct vcs_swarm_receipt_session *s, uint64_t peer)
{
    if (!s || peer == 0)
        return false;
    for (size_t i = 0; i < VCS_SWARM_MAX_PEERS; i++)
        if (s->peers[i].used && s->peers[i].peer == peer)
            return s->peers[i].settled;
    return false;
}

size_t vcs_swarm_receipt_session_peer_ids(
    const struct vcs_swarm_receipt_session *s, uint64_t *out, size_t max)
{
    if (!s || (!out && max > 0))
        return 0;
    size_t n = 0;
    for (size_t i = 0; i < VCS_SWARM_MAX_PEERS && n < max; i++)
        if (s->peers[i].used)
            out[n++] = s->peers[i].peer;
    return n;
}

bool vcs_swarm_receipt_identity_encode(
    const struct vcs_swarm_receipt_session *s, uint8_t *out, size_t cap,
    size_t *len)
{
    if (!s || !out || !len)
        LOG_FAIL(SESSION_LOG, "identity encode: null argument");
    if (cap < VCS_SWARM_RECEIPT_IDENTITY_BYTES)
        LOG_FAIL(SESSION_LOG, "identity encode: cap %zu", cap);
    memcpy(out, VCS_SWARM_RECEIPT_IDENTITY_MAGIC, 4);
    memcpy(out + 4, s->local_pub, 33);
    *len = VCS_SWARM_RECEIPT_IDENTITY_BYTES;
    return true;
}

bool vcs_swarm_receipt_identity_take(
    struct vcs_swarm_receipt_session *s, uint64_t peer, uint8_t *out,
    size_t cap, size_t *len)
{
    struct receipt_peer *p = peer_find(s, peer, true);
    if (!p || p->identity_sent)
        return false;
    if (!vcs_swarm_receipt_identity_encode(s, out, cap, len))
        return false;
    p->identity_sent = true;
    return true;
}

bool vcs_swarm_receipt_identity_note(
    struct vcs_swarm_receipt_session *s, uint64_t peer,
    const uint8_t *payload, size_t len)
{
    if (!s || !payload || peer == 0)
        LOG_FAIL(SESSION_LOG, "identity note: null argument");
    if (len != VCS_SWARM_RECEIPT_IDENTITY_BYTES ||
        memcmp(payload, VCS_SWARM_RECEIPT_IDENTITY_MAGIC, 4) != 0)
        LOG_FAIL(SESSION_LOG, "identity note: bad frame");
    secp256k1_pubkey parsed;
    if (!secp256k1_ec_pubkey_parse(s->ctx, &parsed, payload + 4, 33))
        LOG_FAIL(SESSION_LOG, "identity note: remote pubkey not on-curve");
    if (memcmp(payload + 4, s->local_pub, 33) == 0)
        LOG_FAIL(SESSION_LOG, "identity note: remote key equals local");
    struct receipt_peer *p = peer_find(s, peer, true);
    if (!p)
        LOG_FAIL(SESSION_LOG, "identity note: peer table full");
    memcpy(p->remote_pub, payload + 4, 33);
    p->have_remote = true;
    return true;
}

static bool sig_present(const uint8_t sig[64])
{
    for (size_t i = 0; i < 64; i++)
        if (sig[i] != 0)
            return true;
    return false;
}

bool vcs_swarm_receipt_session_offer(
    struct vcs_swarm_receipt_session *s,
    const struct vcs_swarm_transfer *xfer, uint64_t peer, int64_t day,
    uint8_t out[VCS_SERVICE_RECEIPT_WIRE_BYTES])
{
    if (!s || !xfer || !out || peer == 0)
        return false;
    struct receipt_peer *p = peer_find(s, peer, false);
    if (!p || !p->have_remote)
        return false;
    uint64_t now_bytes =
        xfer->served >= xfer->fetched ? xfer->served : xfer->fetched;
    if (p->offered && memcmp(p->offered_root, xfer->package_root, 32) == 0 &&
        p->offered_bytes == now_bytes)
        return false;
    struct vcs_service_receipt draft;
    enum vcs_service_receipt_role role = VCS_SERVICE_RECEIPT_DOWNLOADER;
    if (!vcs_swarm_receipt_draft(xfer, s->local_pub, p->remote_pub, day, day,
                                 &draft, &role))
        return false;
    if (vcs_service_receipt_sign(&draft, role, s->ctx, s->secret) !=
        VCS_SERVICE_RECEIPT_OK)
        LOG_FAIL(SESSION_LOG, "offer: local sign failed");
    if (vcs_service_receipt_serialize(&draft, out,
                                      VCS_SERVICE_RECEIPT_WIRE_BYTES) !=
        VCS_SERVICE_RECEIPT_OK)
        LOG_FAIL(SESSION_LOG, "offer: serialize failed");
    memcpy(p->offered_root, xfer->package_root, 32);
    p->offered_bytes = draft.verified_bytes;
    p->offered = true;
    return true;
}

static enum vcs_swarm_receipt_status mark_settled(
    struct receipt_peer *p, enum vcs_swarm_receipt_status st)
{
    if (p && (st == VCS_SWARM_RECEIPT_OK || st == VCS_SWARM_RECEIPT_DUPLICATE))
        p->settled = true;
    return st;
}

enum vcs_swarm_receipt_status vcs_swarm_receipt_session_handle(
    struct vcs_swarm_receipt_session *s, struct vcs_service_book *book,
    const struct vcs_swarm_transfer *xfer, uint64_t peer, int64_t day,
    const uint8_t *wire, size_t len, uint8_t **reply, size_t *reply_len)
{
    if (reply)
        *reply = NULL;
    if (reply_len)
        *reply_len = 0;
    if (!s || !book || !xfer || !wire || peer == 0)
        LOG_RETURN(VCS_SWARM_RECEIPT_BAD_INPUT, SESSION_LOG,
                   "handle: null argument");
    struct vcs_service_receipt parsed;
    enum vcs_service_receipt_error perr =
        vcs_service_receipt_parse(wire, len, &parsed);
    if (perr != VCS_SERVICE_RECEIPT_OK)
        LOG_RETURN(VCS_SWARM_RECEIPT_UNVERIFIED, SESSION_LOG,
                   "handle: parse failed (%d)", (int)perr);
    bool local_up = memcmp(s->local_pub, parsed.uploader_pubkey, 33) == 0;
    bool local_down = memcmp(s->local_pub, parsed.downloader_pubkey, 33) == 0;
    if (local_up == local_down)
        LOG_RETURN(VCS_SWARM_RECEIPT_NOT_PARTY, SESSION_LOG,
                   "handle: local key is not exactly one endpoint");
    enum vcs_service_receipt_role local_role = local_up
        ? VCS_SERVICE_RECEIPT_UPLOADER : VCS_SERVICE_RECEIPT_DOWNLOADER;
    enum vcs_service_receipt_role remote_role = local_up
        ? VCS_SERVICE_RECEIPT_DOWNLOADER : VCS_SERVICE_RECEIPT_UPLOADER;
    const uint8_t *remote_pub = local_up ? parsed.downloader_pubkey
                                         : parsed.uploader_pubkey;
    struct receipt_peer *p = peer_find(s, peer, true);
    if (p && p->have_remote && memcmp(p->remote_pub, remote_pub, 33) != 0)
        LOG_RETURN(VCS_SWARM_RECEIPT_NOT_PARTY, SESSION_LOG,
                   "handle: receipt endpoint is not this session's peer");
    if (p && !p->have_remote) {
        memcpy(p->remote_pub, remote_pub, 33);
        p->have_remote = true;
    }
    uint64_t local_bytes = local_up ? xfer->served : xfer->fetched;
    if (parsed.verified_bytes < local_bytes)
        return VCS_SWARM_RECEIPT_STALE;
    if (parsed.verified_bytes > local_bytes)
        LOG_RETURN(VCS_SWARM_RECEIPT_BYTES_MISMATCH, SESSION_LOG,
                   "handle: claimed %llu > local %llu",
                   (unsigned long long)parsed.verified_bytes,
                   (unsigned long long)local_bytes);
    bool sig_local = local_up ? sig_present(parsed.uploader_signature)
                              : sig_present(parsed.downloader_signature);
    bool sig_remote = local_up ? sig_present(parsed.downloader_signature)
                               : sig_present(parsed.uploader_signature);
    if (sig_local && sig_remote)
        return mark_settled(p, vcs_swarm_receipt_accept(
                                   book, xfer, s->local_pub, day, wire, len));
    if (sig_local || !sig_remote)
        LOG_RETURN(VCS_SWARM_RECEIPT_UNVERIFIED, SESSION_LOG,
                   "handle: expected counterparty-only offer");
    if (vcs_service_receipt_verify_role(&parsed, remote_role) !=
        VCS_SERVICE_RECEIPT_OK)
        LOG_RETURN(VCS_SWARM_RECEIPT_UNVERIFIED, SESSION_LOG,
                   "handle: offer signature refused");
    if (vcs_service_receipt_sign(&parsed, local_role, s->ctx, s->secret) !=
        VCS_SERVICE_RECEIPT_OK)
        LOG_RETURN(VCS_SWARM_RECEIPT_BAD_INPUT, SESSION_LOG,
                   "handle: local complete-sign failed");
    uint8_t full[VCS_SERVICE_RECEIPT_WIRE_BYTES];
    if (vcs_service_receipt_serialize(&parsed, full, sizeof(full)) !=
        VCS_SERVICE_RECEIPT_OK)
        LOG_RETURN(VCS_SWARM_RECEIPT_BAD_INPUT, SESSION_LOG,
                   "handle: complete serialize failed");
    enum vcs_swarm_receipt_status st = vcs_swarm_receipt_accept(
        book, xfer, s->local_pub, day, full, sizeof(full));
    if (st == VCS_SWARM_RECEIPT_OK && reply && reply_len) {
        uint8_t *buf = zcl_malloc(sizeof(full), "vcs_swarm_receipt_reply");
        if (!buf)
            LOG_RETURN(VCS_SWARM_RECEIPT_BAD_INPUT, SESSION_LOG,
                       "handle: reply alloc failed");
        memcpy(buf, full, sizeof(full));
        *reply = buf;
        *reply_len = sizeof(full);
    }
    return mark_settled(p, st);
}
