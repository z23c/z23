/* purpose: Implement the role-bound PSK handshake and verified-before-release records (project-specific protocol; not an independently proved protocol, see device_host_psk.h). */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/device_host_psk.h"
#include "crypto/hkdf_sha3.h"
#include "sha3/sha3.h"
#include "base/cleanse.h"
#include "base/serialize_le.h"
#include "platform/clock.h"
#include "platform/rng.h"
#include "util/log_macros.h"
#include <string.h>

/* BE16 fields use the canonical LE16 codec plus its canonical bswap16;
 * serialize_le.h owns the byte conversion without a second private codec. */
enum { PSK_C_HELLO = 1, PSK_S_HELLO, PSK_C_CONFIRM, PSK_S_READY, PSK_DATA, PSK_FIN };
#ifdef ZCL_TESTING
static _Thread_local uint8_t test_nonce[32];
static _Thread_local bool test_nonce_set, test_nonce_refuse;
void device_host_psk_test_nonce(const uint8_t nonce[32], bool refuse)
{
    memory_cleanse(test_nonce, sizeof(test_nonce));
    if (nonce) memcpy(test_nonce, nonce, 32);
    test_nonce_set = true; test_nonce_refuse = refuse;
}
#endif
static void psk_header(uint8_t header[24], unsigned type, size_t body, uint64_t sequence)
{
    memcpy(header, "Z23PSK01", 8); zcl_write_u16_le(header + 8, zcl_bswap16((uint16_t)(1)));
    header[10] = (uint8_t)type; header[11] = 0;
    zcl_write_u32_be(header + 12, (uint32_t)(body)); zcl_write_u64_be(header + 16, (uint64_t)(sequence));
}
static bool psk_equal(const uint8_t *left, const uint8_t *right, size_t length)
{
    unsigned difference = 0;
    for (size_t i = 0; i < length; ++i) difference |= left[i] ^ right[i];
    return difference == 0;
}
static bool psk_overlap(const void *left, size_t left_size, const void *right, size_t right_size)
{
    if (!left_size || !right_size) return false;
    uintptr_t a = (uintptr_t)left, b = (uintptr_t)right;
    if (!a || !b || left_size > UINTPTR_MAX - a || right_size > UINTPTR_MAX - b) return true;
    return a < b + right_size && b < a + left_size;
}
/* Chunks in a frame body of plaintext + 64 per chunk (a FIN body of 64 is one empty chunk). */
static size_t psk_chunk_count(size_t body)
{
    return (body + DEVICE_HOST_PSK_CHUNK + 63) / (DEVICE_HOST_PSK_CHUNK + 64);
}
/* Capability advertisement without a wire change: bytes 16..31 of a hello nonce are a public
 * hash of bytes 0..15, so a peer that does not know the capability (random nonce) matches with
 * probability 2^-128. Both nonces are in the transcript, so stripping or forging the tag makes
 * the confirmations fail; it cannot silently downgrade or upgrade a session. */
static void psk_caps_tag(const uint8_t nonce[16], uint8_t tag[16])
{
    uint8_t input[48] = "Z23PSK1/LARGE-RECORDS", digest[32];
    memcpy(input + 32, nonce, 16); sha3_256(input, sizeof(input), digest);
    memcpy(tag, digest, 16); memory_cleanse(digest, sizeof(digest));
}
static bool psk_nonce_advertises(const uint8_t nonce[32])
{
    uint8_t tag[16]; psk_caps_tag(nonce, tag);
    return psk_equal(tag, nonce + 16, 16);
}
static bool psk_nonce(uint8_t nonce[32], bool *advertised)
{
    *advertised = false;
#ifdef ZCL_TESTING
    if (test_nonce_set) { /* public vectors are used verbatim and advertise nothing */
        bool ok = !test_nonce_refuse;
        if (ok) memcpy(nonce, test_nonce, 32);
        memory_cleanse(test_nonce, sizeof(test_nonce)); test_nonce_set = false; test_nonce_refuse = false;
        return ok;
    }
#endif
    if (!rng_host_fill(nonce, 32)) return false;
    psk_caps_tag(nonce, nonce + 16); *advertised = true; return true;
}
static bool psk_buffer_valid(const struct device_host_psk_session *session, const void *bytes, size_t length)
{
    if (!length) return true;
    return bytes && !psk_overlap(session, sizeof(*session), bytes, length);
}
void device_host_psk_fail(struct device_host_psk_session *session, enum device_host_psk_result result)
{
    if (!session || session->phase == DEVICE_HOST_PSK_FAILED) return;
    if (result != DEVICE_HOST_PSK_REFUSED && result != DEVICE_HOST_PSK_DEADLINE && result != DEVICE_HOST_PSK_CANCELLED)
        result = DEVICE_HOST_PSK_REFUSED;
    if (session->borrowed_guard) device_pairing_guard_release(session->borrowed_guard);
    device_pairing_guard_cache_destroy(&session->authority);
    memory_cleanse(session, sizeof(*session)); session->phase = DEVICE_HOST_PSK_FAILED; session->terminal = result;
}
void device_host_psk_destroy(struct device_host_psk_session *session)
{
    if (!session) return;
    if (session->borrowed_guard) device_pairing_guard_release(session->borrowed_guard);
    device_pairing_guard_cache_destroy(&session->authority);
    memory_cleanse(session, sizeof(*session));
}
void device_host_psk_init(struct device_host_psk_session *session)
{
    if (session) memset(session, 0, sizeof(*session));
}
static enum device_host_psk_result psk_refuse(struct device_host_psk_session *session, const char *why)
{
    LOG_ERROR("device_host_psk", "%s", why);
    device_host_psk_fail(session, DEVICE_HOST_PSK_REFUSED);
    return session ? session->terminal : DEVICE_HOST_PSK_REFUSED;
}
static enum device_host_psk_result psk_current(struct device_host_psk_session *session)
{
    if (!session) return DEVICE_HOST_PSK_REFUSED;
    if (session->phase == DEVICE_HOST_PSK_FAILED) return session->terminal;
    if (session->phase == DEVICE_HOST_PSK_FINISHED) return DEVICE_HOST_PSK_EOF;
    if (session->borrowed_guard) return DEVICE_HOST_PSK_BUSY;
    if (session->spec.cancelled && atomic_load(session->spec.cancelled)) {
        device_host_psk_fail(session, DEVICE_HOST_PSK_CANCELLED); return DEVICE_HOST_PSK_CANCELLED;
    }
    int64_t now = clock_now_monotonic_ns();
    if (now <= 0 || now >= session->spec.deadline_ns) {
        device_host_psk_fail(session, DEVICE_HOST_PSK_DEADLINE); return DEVICE_HOST_PSK_DEADLINE;
    }
    return DEVICE_HOST_PSK_PROGRESS;
}
static uint64_t psk_wall(void)
{
    int64_t ms = clock_now_wall_ms(); return ms > 0 ? (uint64_t)ms / 1000 : 0;
}
/* Filesystem admission may outlive a previously sampled network deadline or
 * grant interval. Recheck after acquisition, with the authority still held. */
static enum device_host_psk_result psk_release_boundary(struct device_host_psk_session *session,
    const struct db_device_pairing *row)
{
    enum device_host_psk_result current = psk_current(session);
    if (current != DEVICE_HOST_PSK_PROGRESS) return current;
    uint64_t now = psk_wall();
    if (now < row->paired_at || now >= row->expires_at)
        return psk_refuse(session, "authority interval ended during acquisition");
    return DEVICE_HOST_PSK_PROGRESS;
}
static bool psk_authorize(struct device_host_psk_session *session, struct device_pairing_guard *guard)
{
    return device_pairing_guard_acquire_host_psk_cached(session->spec.store, session->spec.peer,
        session->spec.approved_root, psk_wall(), &session->snapshot.row.host_scope.binding.psk,
        session->spec.direction, session->spec.port, &session->authority, guard);
}
static bool psk_model_guard_matches(const struct device_host_psk_session *session,
    const struct device_pairing_guard *guard)
{
    if (!guard || !guard->held || memcmp(guard->root, session->spec.approved_root, 32)) return false;
    const struct device_pairing_psk_binding *a = &session->snapshot.row.host_scope.binding.psk;
    const struct device_pairing_psk_binding *b = &guard->row.host_scope.binding.psk;
    uint16_t port = session->spec.direction == DEVICE_PAIRING_HOST_INBOUND ?
        guard->row.host_scope.inbound_port : guard->row.host_scope.outbound_port;
    return guard->row.host_scope.binding.backend_profile == DEVICE_PAIRING_HOST_SHAKE256_WRAP_PSK &&
        port == session->spec.port && psk_equal(a->credential_id, b->credential_id, 32) &&
        a->key_epoch == b->key_epoch && psk_equal(a->endpoint_a, b->endpoint_a, 32) &&
        psk_equal(a->endpoint_b, b->endpoint_b, 32);
}
static bool psk_expand(const struct device_host_psk_session *session, const char *label,
    const uint8_t transcript[64], uint8_t key[32])
{
    uint8_t info[96]; size_t length = strlen(label);
    if (length > 30) return false;
    zcl_write_u16_le(info, zcl_bswap16((uint16_t)(length))); memcpy(info + 2, label, length); memcpy(info + 2 + length, transcript, 64);
    bool ok = hkdf_sha3_256_expand(session->prk, info, 2 + length + 64, key, 32);
    memory_cleanse(info, sizeof(info)); return ok;
}
static bool psk_confirmation(struct device_host_psk_session *session, const char *key_label,
    const char *ad_label, size_t prior_confirmations, uint8_t tag[64])
{
    uint8_t key[32], ad[256]; size_t length = strlen(ad_label);
    if (length > 30 || prior_confirmations > 2) return false;
    bool ok = psk_expand(session, key_label, session->t0, key);
    zcl_write_u16_le(ad, zcl_bswap16((uint16_t)(length))); memcpy(ad + 2, ad_label, length); memcpy(ad + 2 + length, session->t0, 64);
    size_t used = 2 + length + 64;
    if (prior_confirmations) { memcpy(ad + used, session->transcript + 286, 64); used += 64; }
    if (prior_confirmations == 2) { memcpy(ad + used, session->transcript + 374, 64); used += 64; }
    struct shake_wrap_state state = {0};
    if (ok) ok = shake_wrap_init(&state, key) && shake_wrap_seal(&state, ad, used, NULL, 0, tag, 64);
    shake_wrap_destroy(&state); memory_cleanse(key, sizeof(key)); memory_cleanse(ad, sizeof(ad));
    return ok;
}
static void psk_transcript_zero(struct device_host_psk_session *session)
{
    static const uint8_t domain[] = "Z23PSK1/TRANSCRIPT";
    struct sha3_512_ctx hash;
    sha3_512_init(&hash); sha3_512_write(&hash, domain, sizeof(domain) - 1);
    sha3_512_write(&hash, session->transcript, 198);
    sha3_512_write(&hash, session->transcript + 198, 88);
    sha3_512_finalize(&hash, session->t0); memory_cleanse(&hash, sizeof(hash));
    hkdf_sha3_256_extract(session->t0, 64, session->snapshot.secret, 32, session->prk);
}
static bool psk_established_keys(struct device_host_psk_session *session)
{
    static const uint8_t domain[] = "Z23PSK1/ESTABLISHED";
    struct sha3_512_ctx hash;
    sha3_512_init(&hash); sha3_512_write(&hash, domain, sizeof(domain) - 1);
    sha3_512_write(&hash, session->transcript, sizeof(session->transcript)); sha3_512_finalize(&hash, session->t1);
    uint8_t c2s[32], s2c[32];
    bool ok = psk_expand(session, "Z23PSK1/C2S", session->t1, c2s) && psk_expand(session, "Z23PSK1/S2C", session->t1, s2c);
    if (ok) ok = shake_wrap_init(&session->send, session->client_role ? c2s : s2c) &&
        shake_wrap_init(&session->receive, session->client_role ? s2c : c2s);
    memory_cleanse(&hash, sizeof(hash)); memory_cleanse(c2s, sizeof(c2s)); memory_cleanse(s2c, sizeof(s2c));
    memory_cleanse(session->prk, sizeof(session->prk)); memory_cleanse(session->snapshot.secret, sizeof(session->snapshot.secret));
    return ok;
}
static void psk_queue_handshake(struct device_host_psk_session *session, size_t offset, size_t length,
    enum device_host_psk_phase phase)
{
    memcpy(session->pending, session->transcript + offset, length);
    session->pending_used = length; session->pending_sent = 0; session->phase = phase;
}
static void psk_client_hello(struct device_host_psk_session *session)
{
    uint8_t *wire = session->transcript;
    psk_header(wire, PSK_C_HELLO, 174, 0); zcl_write_u32_be(wire + 24, (uint32_t)(2));
    const struct device_pairing_psk_binding *binding = &session->snapshot.row.host_scope.binding.psk;
    zcl_write_u64_be(wire + 28, (uint64_t)(binding->key_epoch)); memcpy(wire + 36, binding->credential_id, 32);
    memcpy(wire + 68, session->client, 32); memcpy(wire + 100, session->server, 32);
    memcpy(wire + 132, session->nonce, 32); zcl_write_u16_le(wire + 164, zcl_bswap16((uint16_t)(session->spec.port)));
    memcpy(wire + 166, session->spec.approved_root, 32);
    psk_queue_handshake(session, 0, 198, DEVICE_HOST_PSK_CLIENT_SEND_HELLO);
}
static enum device_host_psk_result device_host_psk_start_state(struct device_host_psk_session *session,
    const struct device_host_psk_spec *spec)
{
    if (!session) return DEVICE_HOST_PSK_REFUSED;
    if (session->phase != DEVICE_HOST_PSK_FRESH) return psk_refuse(session, "context cannot restart/reuse");
    if (!spec || psk_overlap(session, sizeof(*session), spec, sizeof(*spec))) return psk_refuse(session, "invalid independent session specification");
    session->spec = *spec;
    enum device_host_psk_result current = psk_current(session);
    if (current != DEVICE_HOST_PSK_PROGRESS) return current;
    struct device_pairing_guard guard = {0};
    bool ok = device_pairing_psk_snapshot_acquire(spec->store, spec->peer, spec->approved_root,
        psk_wall(), spec->direction, spec->port, &guard, &session->snapshot);
    device_pairing_guard_release(&guard);
    if (!ok || !psk_nonce(session->nonce, &session->advertised_large)) return psk_refuse(session, "current private credential or qualified entropy unavailable");
    current = psk_release_boundary(session, &session->snapshot.row);
    if (current != DEVICE_HOST_PSK_PROGRESS) return current;
    session->client_role = spec->direction == DEVICE_PAIRING_HOST_OUTBOUND;
    memcpy(session->client, session->client_role ? session->snapshot.row.local_key : spec->peer, 32);
    memcpy(session->server, session->client_role ? spec->peer : session->snapshot.row.local_key, 32);
    if (session->client_role) psk_client_hello(session); else session->phase = DEVICE_HOST_PSK_SERVER_WAIT_HELLO;
    return DEVICE_HOST_PSK_PROGRESS;
}
static bool psk_hello_matches(const struct device_host_psk_session *session, const uint8_t *wire)
{
    const struct device_pairing_psk_binding *binding = &session->snapshot.row.host_scope.binding.psk;
    return zcl_read_u32_be(wire + 24) == 2 && zcl_read_u64_be(wire + 28) == binding->key_epoch &&
        psk_equal(wire + 36, binding->credential_id, 32) && psk_equal(wire + 68, session->client, 32) &&
        psk_equal(wire + 100, session->server, 32) && zcl_bswap16(zcl_read_u16_le(wire + 164)) == session->spec.port;
}
static bool psk_server_hello(struct device_host_psk_session *session)
{
    if (!psk_hello_matches(session, session->incoming)) return false;
    session->large_records = session->advertised_large && psk_nonce_advertises(session->incoming + 132);
    memcpy(session->transcript, session->incoming, 198);
    uint8_t *wire = session->transcript + 198;
    psk_header(wire, PSK_S_HELLO, 128, 0); memcpy(wire + 24, session->nonce, 32);
    memcpy(wire + 56, session->spec.approved_root, 32); psk_transcript_zero(session);
    if (!psk_confirmation(session, "Z23PSK1/SCONF", "Z23PSK1/SERVER", 0, wire + 88)) return false;
    psk_queue_handshake(session, 198, 152, DEVICE_HOST_PSK_SERVER_SEND_HELLO); return true;
}
static bool psk_check_confirmation(struct device_host_psk_session *session,
    const char *key_label, const char *ad_label, size_t prior, const uint8_t actual[64])
{
    uint8_t expected[64];
    bool ok = psk_confirmation(session, key_label, ad_label, prior, expected) && psk_equal(expected, actual, sizeof(expected));
    memory_cleanse(expected, sizeof(expected)); return ok;
}
static bool psk_client_confirm(struct device_host_psk_session *session)
{
    session->large_records = session->advertised_large && psk_nonce_advertises(session->incoming + 24);
    memcpy(session->transcript + 198, session->incoming, 152); psk_transcript_zero(session);
    if (!psk_check_confirmation(session, "Z23PSK1/SCONF", "Z23PSK1/SERVER", 0, session->incoming + 88)) return false;
    uint8_t *wire = session->transcript + 350;
    psk_header(wire, PSK_C_CONFIRM, 64, 0);
    if (!psk_confirmation(session, "Z23PSK1/CCONF", "Z23PSK1/CLIENT", 1, wire + 24)) return false;
    psk_queue_handshake(session, 350, 88, DEVICE_HOST_PSK_CLIENT_SEND_CONFIRM); return true;
}
static bool psk_server_confirm(struct device_host_psk_session *session)
{
    if (!psk_check_confirmation(session, "Z23PSK1/CCONF", "Z23PSK1/CLIENT", 1, session->incoming + 24)) return false;
    memcpy(session->transcript + 350, session->incoming, 88); session->phase = DEVICE_HOST_PSK_NEED_TARGET; return true;
}
static bool psk_client_ready(struct device_host_psk_session *session)
{
    if (!psk_check_confirmation(session, "Z23PSK1/SREADY", "Z23PSK1/READY", 2, session->incoming + 24)) return false;
    memcpy(session->transcript + 438, session->incoming, 88);
    if (!psk_established_keys(session)) return false;
    struct device_pairing_guard guard = {0}; bool ok = psk_authorize(session, &guard);
    if (ok) ok = psk_release_boundary(session, &guard.row) == DEVICE_HOST_PSK_PROGRESS;
    device_pairing_guard_release(&guard);
    if (ok) session->phase = DEVICE_HOST_PSK_ESTABLISHED;
    return ok;
}
static size_t psk_record_ad(const struct device_host_psk_session *session,
    const uint8_t header[24], uint64_t total, uint8_t ad[96])
{
    memcpy(ad, session->t1, 64); memcpy(ad + 64, header, 24);
    if (header[10] == PSK_FIN) { zcl_write_u64_be(ad + 88, (uint64_t)(total)); return 96; }
    return 88;
}
static void psk_finish_if_drained(struct device_host_psk_session *session)
{
    if (session->send_fin && session->receive_fin && !session->pending_used && !session->plaintext_used) {
        shake_wrap_destroy(&session->send); shake_wrap_destroy(&session->receive);
        session->phase = DEVICE_HOST_PSK_FINISHED;
    }
}
static bool psk_receive_record(struct device_host_psk_session *session)
{
    size_t body = session->incoming_expected - 24, chunks = psk_chunk_count(body);
    size_t plain = body - chunks * SHAKE_WRAP_TAG_SIZE;
    uint8_t ad[96]; size_t ad_length = psk_record_ad(session, session->incoming, session->receive_total, ad);
    bool ok = true; size_t in = 24, out = 0;
    /* Every chunk tag is checked; nothing is released until the whole frame has verified. */
    for (size_t i = 0; i < chunks && ok; ++i) {
        size_t take = body - (in - 24) < DEVICE_HOST_PSK_CHUNK + SHAKE_WRAP_TAG_SIZE ? body - (in - 24) : DEVICE_HOST_PSK_CHUNK + SHAKE_WRAP_TAG_SIZE;
        ok = shake_wrap_open(&session->receive, ad, ad_length, session->incoming + in, take,
            session->plaintext + out, sizeof(session->plaintext) - out);
        in += take; out += take - SHAKE_WRAP_TAG_SIZE;
    }
    memory_cleanse(ad, sizeof(ad));
    if (!ok) return false;
    session->receive_sequence++;
    if (session->incoming[10] == PSK_FIN) session->receive_fin = true;
    else {
        if (UINT64_MAX - session->receive_total < plain) return false;
        session->receive_total += plain; session->plaintext_used = plain; session->plaintext_sent = 0;
    }
    psk_finish_if_drained(session); return true;
}
static bool psk_accept_frame(struct device_host_psk_session *session)
{
    switch (session->phase) {
    case DEVICE_HOST_PSK_SERVER_WAIT_HELLO: return psk_server_hello(session);
    case DEVICE_HOST_PSK_CLIENT_WAIT_HELLO: return psk_client_confirm(session);
    case DEVICE_HOST_PSK_SERVER_WAIT_CONFIRM: return psk_server_confirm(session);
    case DEVICE_HOST_PSK_CLIENT_WAIT_READY: return psk_client_ready(session);
    case DEVICE_HOST_PSK_ESTABLISHED: return psk_receive_record(session);
    default: return false;
    }
}
static bool psk_handshake_header(const struct device_host_psk_session *session, unsigned type, size_t body)
{
    switch (session->phase) {
    case DEVICE_HOST_PSK_SERVER_WAIT_HELLO: return type == PSK_C_HELLO && body == 174;
    case DEVICE_HOST_PSK_CLIENT_WAIT_HELLO: return type == PSK_S_HELLO && body == 128;
    case DEVICE_HOST_PSK_SERVER_WAIT_CONFIRM: return type == PSK_C_CONFIRM && body == 64;
    case DEVICE_HOST_PSK_CLIENT_WAIT_READY: return type == PSK_S_READY && body == 64;
    default: return false;
    }
}
/* DATA body = plaintext + 64 per chunk. Legacy sessions: one chunk, 65..4160. Large sessions:
 * full 4160-byte chunks then one final chunk of 65..4160, total plaintext <= RECORD_MAX. */
static bool psk_data_body_valid(const struct device_host_psk_session *session, size_t body)
{
    if (body < 65) return false;
    size_t limit = session->large_records ? DEVICE_HOST_PSK_RECORD_MAX : DEVICE_HOST_PSK_CHUNK;
    size_t chunks = psk_chunk_count(body);
    size_t last = body - (chunks - 1) * (DEVICE_HOST_PSK_CHUNK + 64);
    return last >= 65 && body - chunks * 64 <= limit;
}
static bool psk_established_header(const struct device_host_psk_session *session, unsigned type, size_t body)
{
    if (session->receive_fin || session->receive_sequence >= DEVICE_HOST_PSK_FRAME_LIMIT) return false;
    if (type == PSK_FIN) return body == 64;
    return type == PSK_DATA && psk_data_body_valid(session, body) &&
        session->receive_sequence < DEVICE_HOST_PSK_FRAME_LIMIT - 1;
}
static bool psk_header_valid(struct device_host_psk_session *session)
{
    const uint8_t *wire = session->incoming;
    if (memcmp(wire, "Z23PSK01", 8) || zcl_bswap16(zcl_read_u16_le(wire + 8)) != 1 || wire[11]) return false;
    unsigned type = wire[10]; size_t body = (size_t)zcl_read_u32_be(wire + 12);
    uint64_t sequence = zcl_read_u64_be(wire + 16);
    if (session->phase == DEVICE_HOST_PSK_ESTABLISHED) {
        if (sequence != session->receive_sequence || !psk_established_header(session, type, body)) return false;
    } else if (sequence || !psk_handshake_header(session, type, body)) return false;
    session->incoming_expected = 24 + body; return true;
}
static bool psk_receive_geometry(const struct device_host_psk_session *session,
    const uint8_t *bytes, size_t length, const size_t *consumed)
{
    return consumed && psk_buffer_valid(session, consumed, sizeof(*consumed)) && psk_buffer_valid(session, bytes, length) &&
        !psk_overlap(bytes, length, consumed, sizeof(*consumed));
}
static enum device_host_psk_result psk_receive_current(struct device_host_psk_session *session, size_t length)
{
    if (session && session->phase == DEVICE_HOST_PSK_FINISHED && length)
        return psk_refuse(session, "extra bytes after both authenticated FIN directions");
    return psk_current(session);
}
static enum device_host_psk_result device_host_psk_receive_bytes_state(struct device_host_psk_session *session,
    const uint8_t *bytes, size_t length, size_t *consumed)
{
    enum device_host_psk_result current = psk_receive_current(session, length);
    if (current != DEVICE_HOST_PSK_PROGRESS) return current;
    if (!psk_receive_geometry(session, bytes, length, consumed)) return psk_refuse(session, "invalid independent receive storage");
    *consumed = 0;
    if (session->plaintext_used) return DEVICE_HOST_PSK_WAIT;
    if (session->phase != DEVICE_HOST_PSK_ESTABLISHED && session->pending_used) return DEVICE_HOST_PSK_WAIT;
    size_t expected = session->incoming_expected ? session->incoming_expected : 24;
    size_t take = expected - session->incoming_used;
    if (take > length) take = length;
    if (take) memcpy(session->incoming + session->incoming_used, bytes, take);
    session->incoming_used += take; *consumed = take;
    if (session->incoming_used < expected) return DEVICE_HOST_PSK_PROGRESS;
    if (expected == 24 && !session->incoming_expected) {
        if (!psk_header_valid(session)) return psk_refuse(session, "invalid fixed header, sequence or message state");
        return DEVICE_HOST_PSK_PROGRESS;
    }
    if (!psk_accept_frame(session)) return psk_refuse(session, "handshake or authenticated record refused");
    memory_cleanse(session->incoming, sizeof(session->incoming)); session->incoming_used = 0; session->incoming_expected = 0;
    if (session->phase == DEVICE_HOST_PSK_NEED_TARGET) return DEVICE_HOST_PSK_TARGET_REQUIRED;
    return DEVICE_HOST_PSK_PROGRESS;
}
static enum device_host_psk_result psk_queue_checks(struct device_host_psk_session *session,
    const uint8_t *plaintext, size_t length, unsigned type)
{
    enum device_host_psk_result current = psk_current(session);
    if (current != DEVICE_HOST_PSK_PROGRESS) return current;
    if (session->phase != DEVICE_HOST_PSK_ESTABLISHED || session->send_fin) return psk_refuse(session, "send direction is not established/open");
    if (session->pending_used) return DEVICE_HOST_PSK_WAIT;
    if (!psk_buffer_valid(session, plaintext, length) || length > device_host_psk_record_limit(session)) return psk_refuse(session, "invalid plaintext geometry");
    if (session->send_sequence >= DEVICE_HOST_PSK_FRAME_LIMIT) return psk_refuse(session, "direction frame limit exhausted");
    if (type == PSK_DATA && (!length || session->send_sequence >= DEVICE_HOST_PSK_FRAME_LIMIT - 1))
        return psk_refuse(session, "DATA requires nonempty bytes and a non-FIN-reserved sequence");
    if (UINT64_MAX - session->send_total < length) return psk_refuse(session, "direction byte total overflow");
    return DEVICE_HOST_PSK_PROGRESS;
}
/* held == NULL: acquire and release this record's authority here. held != NULL: the caller
 * already took one authority for this record under the shared lock and carries it through
 * seal and send; it must be the exact current root/binding/port and stays caller-owned. */
static enum device_host_psk_result psk_queue_record(struct device_host_psk_session *session,
    const uint8_t *plaintext, size_t length, unsigned type, const struct device_pairing_guard *held)
{
    enum device_host_psk_result current = psk_queue_checks(session, plaintext, length, type);
    if (current != DEVICE_HOST_PSK_PROGRESS) return current;
    struct device_pairing_guard own = {0};
    if (held) {
        if (!psk_buffer_valid(session, held, sizeof(*held)) || !psk_model_guard_matches(session, held))
            return psk_refuse(session, "carried send authority is not the exact current authority");
    } else if (!psk_authorize(session, &own)) return psk_refuse(session, "current send authority unavailable");
    current = psk_release_boundary(session, held ? &held->row : &own.row);
    if (current != DEVICE_HOST_PSK_PROGRESS) {
        device_pairing_guard_release(&own); return current;
    }
    size_t chunks = length ? (length + DEVICE_HOST_PSK_CHUNK - 1) / DEVICE_HOST_PSK_CHUNK : 1;
    psk_header(session->pending, type, length + chunks * SHAKE_WRAP_TAG_SIZE, session->send_sequence);
    uint8_t ad[96]; size_t ad_length = psk_record_ad(session, session->pending, session->send_total, ad);
    bool ok = true; size_t in = 0, out = 24;
    for (size_t i = 0; i < chunks && ok; ++i) {
        size_t take = length - in < DEVICE_HOST_PSK_CHUNK ? length - in : DEVICE_HOST_PSK_CHUNK;
        ok = shake_wrap_seal(&session->send, ad, ad_length, plaintext + in, take, session->pending + out, sizeof(session->pending) - out);
        in += take; out += take + SHAKE_WRAP_TAG_SIZE;
    }
    memory_cleanse(ad, sizeof(ad)); device_pairing_guard_release(&own);
    if (!ok) return psk_refuse(session, "record sealing failed");
    session->send_sequence++; session->send_total += length; session->send_fin = type == PSK_FIN;
    session->pending_used = 24 + length + chunks * SHAKE_WRAP_TAG_SIZE; session->pending_sent = 0;
    return DEVICE_HOST_PSK_PROGRESS;
}
static enum device_host_psk_result device_host_psk_queue_data_state(struct device_host_psk_session *session,
    const uint8_t *plaintext, size_t length)
{
    return psk_queue_record(session, plaintext, length, PSK_DATA, NULL);
}
static enum device_host_psk_result device_host_psk_queue_data_held_state(struct device_host_psk_session *session,
    const struct device_pairing_guard *guard, const uint8_t *plaintext, size_t length)
{
    if (!guard || !guard->held) return psk_refuse(session, "carried send authority is not held");
    return psk_queue_record(session, plaintext, length, PSK_DATA, guard);
}
static enum device_host_psk_result device_host_psk_queue_fin_state(struct device_host_psk_session *session)
{
    return psk_queue_record(session, NULL, 0, PSK_FIN, NULL);
}
static bool psk_span_geometry(const struct device_host_psk_session *session,
    const struct device_pairing_guard *guard, const uint8_t **bytes, const size_t *length)
{
    return guard && bytes && length && psk_buffer_valid(session, guard, sizeof(*guard)) &&
        psk_buffer_valid(session, bytes, sizeof(*bytes)) && psk_buffer_valid(session, length, sizeof(*length)) &&
        !psk_overlap(guard, sizeof(*guard), bytes, sizeof(*bytes)) &&
        !psk_overlap(guard, sizeof(*guard), length, sizeof(*length)) && !psk_overlap(bytes, sizeof(*bytes), length, sizeof(*length));
}
/* carried: the guard is already held for this record (taken by the caller under the shared
 * lock) and is borrowed as-is after exact-authority and interval checks; otherwise the
 * guard is an unheld output and the authority is acquired here. */
static enum device_host_psk_result psk_span_acquire(struct device_host_psk_session *session,
    struct device_pairing_guard *guard, const uint8_t **bytes, size_t *length, bool plaintext, bool carried)
{
    enum device_host_psk_result current = psk_current(session);
    if (current != DEVICE_HOST_PSK_PROGRESS) return current;
    if (!psk_span_geometry(session, guard, bytes, length)) return psk_refuse(session, "invalid independent guarded span storage");
    if (carried != guard->held) return psk_refuse(session, carried ? "carried guarded span requires a held guard" :
        "guarded span requires an initialized unheld guard");
    *bytes = NULL; *length = 0;
    size_t used = plaintext ? session->plaintext_used : session->pending_used;
    if (!used) return DEVICE_HOST_PSK_WAIT;
    if (carried) {
        if (!psk_model_guard_matches(session, guard)) return psk_refuse(session, "carried release authority is not the exact current authority");
    } else if (!psk_authorize(session, guard)) return psk_refuse(session, "current release authority unavailable");
    current = psk_release_boundary(session, &guard->row);
    if (current != DEVICE_HOST_PSK_PROGRESS) {
        device_pairing_guard_release(guard); return current;
    }
    session->borrowed_guard = guard; session->borrowing_plaintext = plaintext;
    size_t sent = plaintext ? session->plaintext_sent : session->pending_sent;
    *bytes = (plaintext ? session->plaintext : session->pending) + sent; *length = used - sent;
    return DEVICE_HOST_PSK_PROGRESS;
}
static enum device_host_psk_result device_host_psk_pending_acquire_state(struct device_host_psk_session *session,
    struct device_pairing_guard *guard, const uint8_t **bytes, size_t *length)
{
    return psk_span_acquire(session, guard, bytes, length, false, false);
}
static enum device_host_psk_result device_host_psk_plaintext_acquire_state(struct device_host_psk_session *session,
    struct device_pairing_guard *guard, const uint8_t **bytes, size_t *length)
{
    return psk_span_acquire(session, guard, bytes, length, true, false);
}
static enum device_host_psk_result device_host_psk_pending_acquire_held_state(struct device_host_psk_session *session,
    struct device_pairing_guard *guard, const uint8_t **bytes, size_t *length)
{
    return psk_span_acquire(session, guard, bytes, length, false, true);
}
static enum device_host_psk_result device_host_psk_plaintext_acquire_held_state(struct device_host_psk_session *session,
    struct device_pairing_guard *guard, const uint8_t **bytes, size_t *length)
{
    return psk_span_acquire(session, guard, bytes, length, true, true);
}
static void psk_sent_handshake(struct device_host_psk_session *session)
{
    switch (session->phase) {
    case DEVICE_HOST_PSK_CLIENT_SEND_HELLO: session->phase = DEVICE_HOST_PSK_CLIENT_WAIT_HELLO; break;
    case DEVICE_HOST_PSK_CLIENT_SEND_CONFIRM: session->phase = DEVICE_HOST_PSK_CLIENT_WAIT_READY; break;
    case DEVICE_HOST_PSK_SERVER_SEND_HELLO: session->phase = DEVICE_HOST_PSK_SERVER_WAIT_CONFIRM; break;
    case DEVICE_HOST_PSK_SERVER_SEND_READY: session->phase = DEVICE_HOST_PSK_ESTABLISHED; break;
    default: break;
    }
}
static enum device_host_psk_result psk_span_complete(struct device_host_psk_session *session,
    struct device_pairing_guard *guard, size_t count, bool plaintext)
{
    if (!session) return DEVICE_HOST_PSK_REFUSED;
    if (session->phase == DEVICE_HOST_PSK_FAILED) return session->terminal;
    if (!session->borrowed_guard || session->borrowed_guard != guard || session->borrowing_plaintext != plaintext)
        return psk_refuse(session, "guarded span completion does not match acquisition");
    size_t *used = plaintext ? &session->plaintext_used : &session->pending_used;
    size_t *sent = plaintext ? &session->plaintext_sent : &session->pending_sent;
    if (count > *used - *sent) return psk_refuse(session, "write count exceeds exact pending suffix");
    *sent += count;
    device_pairing_guard_release(guard); session->borrowed_guard = NULL;
    if (*sent == *used) {
        memory_cleanse(plaintext ? session->plaintext : session->pending, *used);
        *used = 0; *sent = 0;
        if (!plaintext) psk_sent_handshake(session);
    }
    psk_finish_if_drained(session); return DEVICE_HOST_PSK_PROGRESS;
}
static enum device_host_psk_result device_host_psk_pending_written_state(struct device_host_psk_session *session,
    struct device_pairing_guard *guard, size_t count)
{
    return psk_span_complete(session, guard, count, false);
}
static enum device_host_psk_result device_host_psk_plaintext_released_state(struct device_host_psk_session *session,
    struct device_pairing_guard *guard, size_t count)
{
    return psk_span_complete(session, guard, count, true);
}
static enum device_host_psk_result device_host_psk_target_admitted_state(struct device_host_psk_session *session,
    const struct device_pairing_guard *guard)
{
    enum device_host_psk_result current = psk_current(session);
    if (current != DEVICE_HOST_PSK_PROGRESS) return current;
    if (session->phase != DEVICE_HOST_PSK_NEED_TARGET || !psk_buffer_valid(session, guard, sizeof(*guard)) ||
        !psk_model_guard_matches(session, guard)) return psk_refuse(session, "target readiness requires mutual confirmation and held exact current authority");
    uint64_t now = psk_wall();
    if (now < guard->row.paired_at || now >= guard->row.expires_at) return psk_refuse(session, "target readiness authority interval ended");
    uint8_t *wire = session->transcript + 438;
    psk_header(wire, PSK_S_READY, 64, 0);
    if (!psk_confirmation(session, "Z23PSK1/SREADY", "Z23PSK1/READY", 2, wire + 24) || !psk_established_keys(session))
        return psk_refuse(session, "server readiness key derivation failed");
    psk_queue_handshake(session, 438, 88, DEVICE_HOST_PSK_SERVER_SEND_READY);
    return DEVICE_HOST_PSK_PROGRESS;
}
static enum device_host_psk_result device_host_psk_transport_eof_state(struct device_host_psk_session *session)
{
    enum device_host_psk_result current = psk_current(session);
    if (current != DEVICE_HOST_PSK_PROGRESS) return current;
    if (!session->receive_fin || session->incoming_used) return psk_refuse(session, "raw EOF without complete authenticated FIN is truncation");
    psk_finish_if_drained(session); return DEVICE_HOST_PSK_PROGRESS;
}

struct host_status_range { const void *bytes; size_t size; };
static bool host_status_storage(const void *status, size_t size,
    const struct host_status_range *ranges, size_t count)
{
    if (!status || size > UINTPTR_MAX - (uintptr_t)status) return false;
    for (size_t i = 0; i < count; ++i)
        if (ranges[i].bytes && psk_overlap(status, size, ranges[i].bytes, ranges[i].size))
            return false;
    return true;
}

static struct zcl_result host_domain_result(enum device_host_psk_result value, enum device_host_psk_result *status,
    int error, const char *operation)
{
    static const char *const names[] = {"progress", "wait", "target_required", "ready", "eof", "refused", "deadline", "cancelled", "busy"};
    *status = value;
    if ((unsigned)value <= DEVICE_HOST_PSK_EOF) return ZCL_OK;
    (void)error;
    const char *name = (unsigned)value < sizeof(names) / sizeof(names[0]) ? names[value] : "invalid_state";
    int code = (unsigned)value < sizeof(names) / sizeof(names[0]) ? -100 - (int)value : -199;
    return ZCL_ERR(code, "%s: host psk %s", operation, name);
}

struct zcl_result device_host_psk_start(struct device_host_psk_session *session,
    const struct device_host_psk_spec *spec, enum device_host_psk_result *status)
{
    const struct host_status_range ranges[] = {{session, sizeof(*session)}, {spec, sizeof(*spec)}, {session ? session->borrowed_guard : NULL, sizeof(struct device_pairing_guard)}};
    if (!host_status_storage(status, sizeof(*status), ranges, sizeof(ranges) / sizeof(ranges[0])))
        return ZCL_ERR(-1000, "device_host_psk_start: status output must be independent");
    *status = DEVICE_HOST_PSK_REFUSED;
    enum device_host_psk_result value = device_host_psk_start_state(session, spec);
    return host_domain_result(value, status, 0, __func__);
}

struct zcl_result device_host_psk_receive_bytes(struct device_host_psk_session *session,
    const uint8_t *bytes,
    size_t length,
    size_t *consumed, enum device_host_psk_result *status)
{
    const struct host_status_range ranges[] = {{session, sizeof(*session)}, {bytes, length}, {consumed, sizeof(*consumed)}, {session ? session->borrowed_guard : NULL, sizeof(struct device_pairing_guard)}};
    if (!host_status_storage(status, sizeof(*status), ranges, sizeof(ranges) / sizeof(ranges[0])))
        return ZCL_ERR(-1000, "device_host_psk_receive_bytes: status output must be independent");
    *status = DEVICE_HOST_PSK_REFUSED;
    enum device_host_psk_result value = device_host_psk_receive_bytes_state(session, bytes, length, consumed);
    return host_domain_result(value, status, 0, __func__);
}

struct zcl_result device_host_psk_queue_data(struct device_host_psk_session *session,
    const uint8_t *plaintext,
    size_t length, enum device_host_psk_result *status)
{
    const struct host_status_range ranges[] = {{session, sizeof(*session)}, {plaintext, length}, {session ? session->borrowed_guard : NULL, sizeof(struct device_pairing_guard)}};
    if (!host_status_storage(status, sizeof(*status), ranges, sizeof(ranges) / sizeof(ranges[0])))
        return ZCL_ERR(-1000, "device_host_psk_queue_data: status output must be independent");
    *status = DEVICE_HOST_PSK_REFUSED;
    enum device_host_psk_result value = device_host_psk_queue_data_state(session, plaintext, length);
    return host_domain_result(value, status, 0, __func__);
}

struct zcl_result device_host_psk_queue_fin(struct device_host_psk_session *session, enum device_host_psk_result *status)
{
    const struct host_status_range ranges[] = {{session, sizeof(*session)}, {session ? session->borrowed_guard : NULL, sizeof(struct device_pairing_guard)}};
    if (!host_status_storage(status, sizeof(*status), ranges, sizeof(ranges) / sizeof(ranges[0])))
        return ZCL_ERR(-1000, "device_host_psk_queue_fin: status output must be independent");
    *status = DEVICE_HOST_PSK_REFUSED;
    enum device_host_psk_result value = device_host_psk_queue_fin_state(session);
    return host_domain_result(value, status, 0, __func__);
}

struct zcl_result device_host_psk_pending_acquire(struct device_host_psk_session *session,
    struct device_pairing_guard *guard,
    const uint8_t **bytes,
    size_t *length, enum device_host_psk_result *status)
{
    const struct host_status_range ranges[] = {{session, sizeof(*session)}, {guard, sizeof(*guard)}, {bytes, sizeof(*bytes)}, {length, sizeof(*length)}, {session ? session->borrowed_guard : NULL, sizeof(struct device_pairing_guard)}};
    if (!host_status_storage(status, sizeof(*status), ranges, sizeof(ranges) / sizeof(ranges[0])))
        return ZCL_ERR(-1000, "device_host_psk_pending_acquire: status output must be independent");
    *status = DEVICE_HOST_PSK_REFUSED;
    enum device_host_psk_result value = device_host_psk_pending_acquire_state(session, guard, bytes, length);
    return host_domain_result(value, status, 0, __func__);
}

struct zcl_result device_host_psk_pending_written(struct device_host_psk_session *session,
    struct device_pairing_guard *guard,
    size_t count, enum device_host_psk_result *status)
{
    const struct host_status_range ranges[] = {{session, sizeof(*session)}, {guard, sizeof(*guard)}, {session ? session->borrowed_guard : NULL, sizeof(struct device_pairing_guard)}};
    if (!host_status_storage(status, sizeof(*status), ranges, sizeof(ranges) / sizeof(ranges[0])))
        return ZCL_ERR(-1000, "device_host_psk_pending_written: status output must be independent");
    *status = DEVICE_HOST_PSK_REFUSED;
    enum device_host_psk_result value = device_host_psk_pending_written_state(session, guard, count);
    return host_domain_result(value, status, 0, __func__);
}

struct zcl_result device_host_psk_plaintext_acquire(struct device_host_psk_session *session,
    struct device_pairing_guard *guard,
    const uint8_t **bytes,
    size_t *length, enum device_host_psk_result *status)
{
    const struct host_status_range ranges[] = {{session, sizeof(*session)}, {guard, sizeof(*guard)}, {bytes, sizeof(*bytes)}, {length, sizeof(*length)}, {session ? session->borrowed_guard : NULL, sizeof(struct device_pairing_guard)}};
    if (!host_status_storage(status, sizeof(*status), ranges, sizeof(ranges) / sizeof(ranges[0])))
        return ZCL_ERR(-1000, "device_host_psk_plaintext_acquire: status output must be independent");
    *status = DEVICE_HOST_PSK_REFUSED;
    enum device_host_psk_result value = device_host_psk_plaintext_acquire_state(session, guard, bytes, length);
    return host_domain_result(value, status, 0, __func__);
}

struct zcl_result device_host_psk_plaintext_released(struct device_host_psk_session *session,
    struct device_pairing_guard *guard,
    size_t count, enum device_host_psk_result *status)
{
    const struct host_status_range ranges[] = {{session, sizeof(*session)}, {guard, sizeof(*guard)}, {session ? session->borrowed_guard : NULL, sizeof(struct device_pairing_guard)}};
    if (!host_status_storage(status, sizeof(*status), ranges, sizeof(ranges) / sizeof(ranges[0])))
        return ZCL_ERR(-1000, "device_host_psk_plaintext_released: status output must be independent");
    *status = DEVICE_HOST_PSK_REFUSED;
    enum device_host_psk_result value = device_host_psk_plaintext_released_state(session, guard, count);
    return host_domain_result(value, status, 0, __func__);
}

struct zcl_result device_host_psk_target_admitted(struct device_host_psk_session *session,
    const struct device_pairing_guard *guard, enum device_host_psk_result *status)
{
    const struct host_status_range ranges[] = {{session, sizeof(*session)}, {guard, sizeof(*guard)}, {session ? session->borrowed_guard : NULL, sizeof(struct device_pairing_guard)}};
    if (!host_status_storage(status, sizeof(*status), ranges, sizeof(ranges) / sizeof(ranges[0])))
        return ZCL_ERR(-1000, "device_host_psk_target_admitted: status output must be independent");
    *status = DEVICE_HOST_PSK_REFUSED;
    enum device_host_psk_result value = device_host_psk_target_admitted_state(session, guard);
    return host_domain_result(value, status, 0, __func__);
}

struct zcl_result device_host_psk_transport_eof(struct device_host_psk_session *session, enum device_host_psk_result *status)
{
    const struct host_status_range ranges[] = {{session, sizeof(*session)}, {session ? session->borrowed_guard : NULL, sizeof(struct device_pairing_guard)}};
    if (!host_status_storage(status, sizeof(*status), ranges, sizeof(ranges) / sizeof(ranges[0])))
        return ZCL_ERR(-1000, "device_host_psk_transport_eof: status output must be independent");
    *status = DEVICE_HOST_PSK_REFUSED;
    enum device_host_psk_result value = device_host_psk_transport_eof_state(session);
    return host_domain_result(value, status, 0, __func__);
}

struct zcl_result device_host_psk_queue_data_held(struct device_host_psk_session *session,
    const struct device_pairing_guard *guard, const uint8_t *plaintext, size_t length, enum device_host_psk_result *status)
{
    const struct host_status_range ranges[] = {{session, sizeof(*session)}, {guard, sizeof(*guard)}, {plaintext, length}, {session ? session->borrowed_guard : NULL, sizeof(struct device_pairing_guard)}};
    if (!host_status_storage(status, sizeof(*status), ranges, sizeof(ranges) / sizeof(ranges[0])))
        return ZCL_ERR(-1000, "device_host_psk_queue_data_held: status output must be independent");
    *status = DEVICE_HOST_PSK_REFUSED;
    enum device_host_psk_result value = device_host_psk_queue_data_held_state(session, guard, plaintext, length);
    return host_domain_result(value, status, 0, __func__);
}

struct zcl_result device_host_psk_pending_acquire_held(struct device_host_psk_session *session,
    struct device_pairing_guard *guard, const uint8_t **bytes, size_t *length, enum device_host_psk_result *status)
{
    const struct host_status_range ranges[] = {{session, sizeof(*session)}, {guard, sizeof(*guard)}, {bytes, sizeof(*bytes)}, {length, sizeof(*length)}, {session ? session->borrowed_guard : NULL, sizeof(struct device_pairing_guard)}};
    if (!host_status_storage(status, sizeof(*status), ranges, sizeof(ranges) / sizeof(ranges[0])))
        return ZCL_ERR(-1000, "device_host_psk_pending_acquire_held: status output must be independent");
    *status = DEVICE_HOST_PSK_REFUSED;
    enum device_host_psk_result value = device_host_psk_pending_acquire_held_state(session, guard, bytes, length);
    return host_domain_result(value, status, 0, __func__);
}

struct zcl_result device_host_psk_plaintext_acquire_held(struct device_host_psk_session *session,
    struct device_pairing_guard *guard, const uint8_t **bytes, size_t *length, enum device_host_psk_result *status)
{
    const struct host_status_range ranges[] = {{session, sizeof(*session)}, {guard, sizeof(*guard)}, {bytes, sizeof(*bytes)}, {length, sizeof(*length)}, {session ? session->borrowed_guard : NULL, sizeof(struct device_pairing_guard)}};
    if (!host_status_storage(status, sizeof(*status), ranges, sizeof(ranges) / sizeof(ranges[0])))
        return ZCL_ERR(-1000, "device_host_psk_plaintext_acquire_held: status output must be independent");
    *status = DEVICE_HOST_PSK_REFUSED;
    enum device_host_psk_result value = device_host_psk_plaintext_acquire_held_state(session, guard, bytes, length);
    return host_domain_result(value, status, 0, __func__);
}
size_t device_host_psk_record_limit(const struct device_host_psk_session *session)
{
    return session && session->large_records ? DEVICE_HOST_PSK_RECORD_MAX : DEVICE_HOST_PSK_CHUNK;
}
