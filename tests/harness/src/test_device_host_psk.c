/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "test/test_core.h"
#include "services/device_host_psk.h"
#include "platform/clock.h"
#include "base/hex.h"
#include "base/cleanse.h"
#include "base/serialize_le.h"
#include <stdio.h>
#include <string.h>
static_assert(_Generic(device_host_psk_start(NULL, NULL, NULL), struct zcl_result: 1, default: 0),
    "fallible domain API returns canonical zcl_result");
static_assert(_Generic(device_host_psk_receive_bytes(NULL, NULL, 0, NULL, NULL), struct zcl_result: 1, default: 0),
    "fallible domain API returns canonical zcl_result");
static_assert(_Generic(device_host_psk_queue_data(NULL, NULL, 0, NULL), struct zcl_result: 1, default: 0),
    "fallible domain API returns canonical zcl_result");
static_assert(_Generic(device_host_psk_queue_fin(NULL, NULL), struct zcl_result: 1, default: 0),
    "fallible domain API returns canonical zcl_result");
static_assert(_Generic(device_host_psk_pending_acquire(NULL, NULL, NULL, NULL, NULL), struct zcl_result: 1, default: 0),
    "fallible domain API returns canonical zcl_result");
static_assert(_Generic(device_host_psk_pending_written(NULL, NULL, 0, NULL), struct zcl_result: 1, default: 0),
    "fallible domain API returns canonical zcl_result");
static_assert(_Generic(device_host_psk_plaintext_acquire(NULL, NULL, NULL, NULL, NULL), struct zcl_result: 1, default: 0),
    "fallible domain API returns canonical zcl_result");
static_assert(_Generic(device_host_psk_plaintext_released(NULL, NULL, 0, NULL), struct zcl_result: 1, default: 0),
    "fallible domain API returns canonical zcl_result");
static_assert(_Generic(device_host_psk_target_admitted(NULL, NULL, NULL), struct zcl_result: 1, default: 0),
    "fallible domain API returns canonical zcl_result");
static_assert(_Generic(device_host_psk_transport_eof(NULL, NULL), struct zcl_result: 1, default: 0),
    "fallible domain API returns canonical zcl_result");

/* Preserve the existing domain-state assertions while checking EVERY migrated
 * call's rich-result/status contract. Counter is folded into group failure. */
static unsigned typed_state_failures;
static void typed_state_check(struct zcl_result result, bool normal)
{
    if (result.ok != normal || (result.ok && result.code != 0) ||
        (!result.ok && (!result.code || !result.message[0] || !result.source_file)))
        ++typed_state_failures;
}
static enum device_host_psk_result typed_test_device_host_psk_start(struct device_host_psk_session *session,
    const struct device_host_psk_spec *spec)
{
    enum device_host_psk_result status = DEVICE_HOST_PSK_REFUSED;
    struct zcl_result result = device_host_psk_start(session, spec, &status);
    typed_state_check(result, (unsigned)status <= DEVICE_HOST_PSK_EOF);
    return status;
}
static enum device_host_psk_result typed_test_device_host_psk_receive_bytes(struct device_host_psk_session *session,
    const uint8_t *bytes,
    size_t length,
    size_t *consumed)
{
    enum device_host_psk_result status = DEVICE_HOST_PSK_REFUSED;
    struct zcl_result result = device_host_psk_receive_bytes(session, bytes, length, consumed, &status);
    typed_state_check(result, (unsigned)status <= DEVICE_HOST_PSK_EOF);
    return status;
}
static enum device_host_psk_result typed_test_device_host_psk_queue_data(struct device_host_psk_session *session,
    const uint8_t *plaintext,
    size_t length)
{
    enum device_host_psk_result status = DEVICE_HOST_PSK_REFUSED;
    struct zcl_result result = device_host_psk_queue_data(session, plaintext, length, &status);
    typed_state_check(result, (unsigned)status <= DEVICE_HOST_PSK_EOF);
    return status;
}
static enum device_host_psk_result typed_test_device_host_psk_queue_fin(struct device_host_psk_session *session)
{
    enum device_host_psk_result status = DEVICE_HOST_PSK_REFUSED;
    struct zcl_result result = device_host_psk_queue_fin(session, &status);
    typed_state_check(result, (unsigned)status <= DEVICE_HOST_PSK_EOF);
    return status;
}
static enum device_host_psk_result typed_test_device_host_psk_pending_acquire(struct device_host_psk_session *session,
    struct device_pairing_guard *guard,
    const uint8_t **bytes,
    size_t *length)
{
    enum device_host_psk_result status = DEVICE_HOST_PSK_REFUSED;
    struct zcl_result result = device_host_psk_pending_acquire(session, guard, bytes, length, &status);
    typed_state_check(result, (unsigned)status <= DEVICE_HOST_PSK_EOF);
    return status;
}
static enum device_host_psk_result typed_test_device_host_psk_pending_written(struct device_host_psk_session *session,
    struct device_pairing_guard *guard,
    size_t count)
{
    enum device_host_psk_result status = DEVICE_HOST_PSK_REFUSED;
    struct zcl_result result = device_host_psk_pending_written(session, guard, count, &status);
    typed_state_check(result, (unsigned)status <= DEVICE_HOST_PSK_EOF);
    return status;
}
static enum device_host_psk_result typed_test_device_host_psk_plaintext_acquire(struct device_host_psk_session *session,
    struct device_pairing_guard *guard,
    const uint8_t **bytes,
    size_t *length)
{
    enum device_host_psk_result status = DEVICE_HOST_PSK_REFUSED;
    struct zcl_result result = device_host_psk_plaintext_acquire(session, guard, bytes, length, &status);
    typed_state_check(result, (unsigned)status <= DEVICE_HOST_PSK_EOF);
    return status;
}
static enum device_host_psk_result typed_test_device_host_psk_plaintext_released(struct device_host_psk_session *session,
    struct device_pairing_guard *guard,
    size_t count)
{
    enum device_host_psk_result status = DEVICE_HOST_PSK_REFUSED;
    struct zcl_result result = device_host_psk_plaintext_released(session, guard, count, &status);
    typed_state_check(result, (unsigned)status <= DEVICE_HOST_PSK_EOF);
    return status;
}
static enum device_host_psk_result typed_test_device_host_psk_target_admitted(struct device_host_psk_session *session,
    const struct device_pairing_guard *guard)
{
    enum device_host_psk_result status = DEVICE_HOST_PSK_REFUSED;
    struct zcl_result result = device_host_psk_target_admitted(session, guard, &status);
    typed_state_check(result, (unsigned)status <= DEVICE_HOST_PSK_EOF);
    return status;
}
static enum device_host_psk_result typed_test_device_host_psk_transport_eof(struct device_host_psk_session *session)
{
    enum device_host_psk_result status = DEVICE_HOST_PSK_REFUSED;
    struct zcl_result result = device_host_psk_transport_eof(session, &status);
    typed_state_check(result, (unsigned)status <= DEVICE_HOST_PSK_EOF);
    return status;
}

struct psk_vector { unsigned orientation; const char *name, *hex; };
#include "test_device_host_psk_vectors.h"
struct psk_fixture {
    char directory[2][1024];
    struct device_pairing_store store[2]; struct db_device_pairing row[2];
    uint8_t root[2][32], secret[32];
    const clock_iface_t *previous; clock_iface_t clock;
    int64_t wall_ms;
    unsigned wall_calls, jump_after;
    bool deadline_after_acquire, cancel_on_wall;
    atomic_bool cancelled;
};
static int64_t psk_fixture_mono(void *context)
{
    struct psk_fixture *f = context;
    if (f->deadline_after_acquire && f->wall_calls) return INT64_MAX;
    return f->previous->now_monotonic_ns(f->previous->self);
}
static int64_t psk_fixture_wall(void *context)
{
    struct psk_fixture *f = context;
    f->wall_calls++;
    if (f->cancel_on_wall) atomic_store(&f->cancelled, true);
    if (f->jump_after && f->wall_calls > f->jump_after) return 200000;
    return f->wall_ms;
}
static void psk_fixture_close(struct psk_fixture *f)
{
    if (f->previous) clock_set_default(f->previous);
    for (size_t i = 0; i < 2; ++i) if (f->directory[i][0]) test_rm_rf(f->directory[i]);
    memory_cleanse(f, sizeof(*f));
}
static bool psk_fixture_open_keys(struct psk_fixture *f, bool wrong_peer_secret)
{
    memset(f, 0, sizeof(*f)); f->wall_ms = 150000; atomic_init(&f->cancelled, false);
    uint8_t a[32], b[32];
    for (size_t j = 0; j < 32; ++j) { a[j] = (uint8_t)(0x40 + j); b[j] = (uint8_t)(0x60 + j); f->secret[j] = (uint8_t)j; }
    for (size_t i = 0; i < 2; ++i) {
        if (!test_mkdtemp(f->directory[i], sizeof(f->directory[i]), "host-psk")) return false;
        struct db_device_pairing *row = &f->row[i];
        for (size_t j = 0; j < 32; ++j) row->profile[j] = (uint8_t)(0x10 + j);
        memcpy(row->local_key, i ? b : a, 32); memcpy(row->peer_key, i ? a : b, 32);
        row->paired_at = 100; row->expires_at = 200; row->capabilities = DEVICE_PAIRING_CAP_HOST_FORWARD;
        row->host_scope.inbound_port = 2222; row->host_scope.outbound_port = 2222;
        row->host_scope.binding.backend_profile = DEVICE_PAIRING_HOST_SHAKE256_WRAP_PSK;
        struct device_pairing_psk_binding *binding = &row->host_scope.binding.psk;
        for (size_t j = 0; j < 32; ++j) binding->credential_id[j] = (uint8_t)(0x20 + j);
        binding->key_epoch = UINT64_C(0x0102030405060708);
        memcpy(binding->endpoint_a, a, 32); memcpy(binding->endpoint_b, b, 32);
        uint8_t proposal[32]; struct device_pairing_psk_publication report;
        uint8_t secret[32]; memcpy(secret, f->secret, sizeof(secret));
        if (wrong_peer_secret && i) secret[0] ^= 1;
        if (!device_pairing_store_open(&f->store[i], f->directory[i], row->profile, row->local_key) ||
            !device_pairing_host_proposal_root(row, proposal) ||
            !db_device_pairing_insert_host_psk(&f->store[i], row, secret, proposal, &report)) return false;
        struct db_device_pairing found;
        if (!db_device_pairing_inspect(&f->store[i], row->peer_key, &found, f->root[i])) return false;
    }
    f->previous = clock_default(); f->clock = (clock_iface_t){.now_monotonic_ns = psk_fixture_mono, .now_wall_ms = psk_fixture_wall, .self = f};
    clock_set_default(&f->clock); return true;
}
static bool psk_fixture_open(struct psk_fixture *f)
{
    return psk_fixture_open_keys(f, false);
}
static struct device_host_psk_spec psk_fixture_spec(struct psk_fixture *f, unsigned node, bool client)
{
    struct device_host_psk_spec spec = {.store = &f->store[node], .direction = client ? DEVICE_PAIRING_HOST_OUTBOUND : DEVICE_PAIRING_HOST_INBOUND,
        .port = 2222, .deadline_ns = clock_now_monotonic_ns() + INT64_C(60000000000), .cancelled = &f->cancelled};
    memcpy(spec.peer, f->row[node].peer_key, 32); memcpy(spec.approved_root, f->root[node], 32); return spec;
}
static bool psk_fixture_start(struct psk_fixture *f, unsigned orientation,
    struct device_host_psk_session *client, struct device_host_psk_session *server)
{
    device_host_psk_init(client); device_host_psk_init(server);
    struct device_host_psk_spec c = psk_fixture_spec(f, orientation, true), s = psk_fixture_spec(f, 1 - orientation, false);
    uint8_t nonce[32];
    for (size_t i = 0; i < 32; ++i) nonce[i] = (uint8_t)(0x80 + i + orientation);
    device_host_psk_test_nonce(nonce, false);
    if (typed_test_device_host_psk_start(client, &c) != DEVICE_HOST_PSK_PROGRESS) return false;
    for (size_t i = 0; i < 32; ++i) nonce[i] = (uint8_t)(0xa0 + i + orientation);
    device_host_psk_test_nonce(nonce, false);
    return typed_test_device_host_psk_start(server, &s) == DEVICE_HOST_PSK_PROGRESS;
}
static bool psk_vector_equal(unsigned orientation, const char *name, const uint8_t *bytes, size_t length)
{
    for (size_t i = 0; i < sizeof(psk_vectors) / sizeof(psk_vectors[0]); ++i) {
        const struct psk_vector *vector = &psk_vectors[i];
        if (vector->orientation != orientation || strcmp(vector->name, name)) continue;
        uint8_t expected[DEVICE_HOST_PSK_WIRE];
        if (length > sizeof(expected) || strlen(vector->hex) != length * 2 || !zcl_hex_decode(vector->hex, expected, length)) return false;
        bool ok = !memcmp(expected, bytes, length);
        if (!ok) fprintf(stderr, "PSK oracle mismatch orientation=%u field=%s length=%zu\n", orientation, name, length);
        return ok;
    }
    return false;
}
static bool psk_take_wire(struct device_host_psk_session *sender, uint8_t wire[DEVICE_HOST_PSK_WIRE], size_t *length)
{
    struct device_pairing_guard guard = {0}; const uint8_t *bytes = NULL;
    enum device_host_psk_result result = typed_test_device_host_psk_pending_acquire(sender, &guard, &bytes, length);
    if (result != DEVICE_HOST_PSK_PROGRESS) { device_pairing_guard_release(&guard); return false; }
    memcpy(wire, bytes, *length);
    result = typed_test_device_host_psk_pending_written(sender, &guard, *length);
    device_pairing_guard_release(&guard);
    return result == DEVICE_HOST_PSK_PROGRESS;
}
static enum device_host_psk_result psk_feed(struct device_host_psk_session *receiver,
    const uint8_t *wire, size_t length, size_t fragment)
{
    size_t position = 0; enum device_host_psk_result result = DEVICE_HOST_PSK_PROGRESS;
    while (position < length) {
        size_t size = length - position; if (size > fragment) size = fragment;
        size_t consumed = 0; result = typed_test_device_host_psk_receive_bytes(receiver, wire + position, size, &consumed);
        if (result != DEVICE_HOST_PSK_PROGRESS && result != DEVICE_HOST_PSK_TARGET_REQUIRED) return result;
        if (!consumed) return DEVICE_HOST_PSK_WAIT;
        position += consumed;
    }
    return result;
}
static bool psk_target_ready(struct device_host_psk_session *server)
{
    struct device_pairing_guard guard = {0};
    bool held = device_pairing_guard_acquire_host_psk(server->spec.store, server->spec.peer,
        server->spec.approved_root, 150, &server->snapshot.row.host_scope.binding.psk, DEVICE_PAIRING_HOST_INBOUND, 2222, &guard);
    enum device_host_psk_result result = DEVICE_HOST_PSK_REFUSED;
    if (held) result = typed_test_device_host_psk_target_admitted(server, &guard);
    device_pairing_guard_release(&guard);
    return held && result == DEVICE_HOST_PSK_PROGRESS;
}
static bool psk_flight(struct device_host_psk_session *sender, struct device_host_psk_session *receiver,
    unsigned orientation, const char *name, size_t fragment)
{
    uint8_t wire[DEVICE_HOST_PSK_WIRE]; size_t length = 0;
    if (!psk_take_wire(sender, wire, &length)) return false;
    if (name && !psk_vector_equal(orientation, name, wire, length)) return false;
    enum device_host_psk_result result = psk_feed(receiver, wire, length, fragment);
    return result == DEVICE_HOST_PSK_PROGRESS || result == DEVICE_HOST_PSK_TARGET_REQUIRED;
}
static bool psk_handshake(struct psk_fixture *f, unsigned orientation,
    struct device_host_psk_session *client, struct device_host_psk_session *server)
{
    if (!psk_fixture_start(f, orientation, client, server)) return false;
    if (!psk_flight(client, server, orientation, "C_HELLO", 1) || !psk_flight(server, client, orientation, "S_HELLO", 7)) return false;
    if (!psk_vector_equal(orientation, "T0", client->t0, 64) || memcmp(client->t0, server->t0, 64)) return false;
    if (!psk_flight(client, server, orientation, "C_CONFIRM", 1) || server->phase != DEVICE_HOST_PSK_NEED_TARGET || server->pending_used) return false;
    if (!psk_target_ready(server) || server->phase != DEVICE_HOST_PSK_SERVER_SEND_READY) return false;
    if (!psk_flight(server, client, orientation, "S_READY", 3)) return false;
    return client->phase == DEVICE_HOST_PSK_ESTABLISHED && server->phase == DEVICE_HOST_PSK_ESTABLISHED &&
        psk_vector_equal(orientation, "T1", client->t1, 64) && !memcmp(client->t1, server->t1, 64);
}
static bool psk_release_plaintext(struct device_host_psk_session *receiver, const uint8_t *expected, size_t size)
{
    struct device_pairing_guard guard = {0}; const uint8_t *bytes = NULL; size_t length = 0;
    enum device_host_psk_result result = typed_test_device_host_psk_plaintext_acquire(receiver, &guard, &bytes, &length);
    if (result != DEVICE_HOST_PSK_PROGRESS) { device_pairing_guard_release(&guard); return false; }
    bool equal = length == size && !memcmp(bytes, expected, size);
    result = typed_test_device_host_psk_plaintext_released(receiver, &guard, length); device_pairing_guard_release(&guard);
    return equal && result == DEVICE_HOST_PSK_PROGRESS;
}
static bool psk_oracle_plaintext(unsigned orientation, const char *name, uint8_t bytes[4096], size_t *length)
{
    for (size_t i = 0; i < sizeof(psk_vectors) / sizeof(psk_vectors[0]); ++i) {
        const struct psk_vector *vector = &psk_vectors[i];
        if (vector->orientation != orientation || strcmp(vector->name, name)) continue;
        *length = strlen(vector->hex) / 2; return *length <= 4096 && zcl_hex_decode(vector->hex, bytes, *length);
    }
    return false;
}
static int psk_oracle_roundtrip(void)
{
    int failures = 0; struct psk_fixture f = {0}; struct device_host_psk_session c = {0}, s = {0};
    TEST_CASE("host PSK: independent complete handshake and DATA/FIN oracle in both initiated directions") {
        for (unsigned orientation = 0; orientation < 2; ++orientation) {
            ASSERT(psk_fixture_open(&f)); ASSERT(psk_vector_equal(orientation, "A_GRANT_ROOT", f.root[0], 32));
            ASSERT(psk_vector_equal(orientation, "B_GRANT_ROOT", f.root[1], 32));
            ASSERT(psk_handshake(&f, orientation, &c, &s));
            uint8_t plaintext[4096]; size_t length = 0;
            ASSERT(psk_oracle_plaintext(orientation, "C2S_PLAINTEXT", plaintext, &length));
            ASSERT_EQ(typed_test_device_host_psk_queue_data(&c, plaintext, length), DEVICE_HOST_PSK_PROGRESS);
            ASSERT(psk_flight(&c, &s, orientation, "C2S_DATA", 13)); ASSERT(psk_release_plaintext(&s, plaintext, length));
            ASSERT(psk_oracle_plaintext(orientation, "S2C_PLAINTEXT", plaintext, &length));
            ASSERT_EQ(typed_test_device_host_psk_queue_data(&s, plaintext, length), DEVICE_HOST_PSK_PROGRESS);
            ASSERT(psk_flight(&s, &c, orientation, "S2C_DATA", 17)); ASSERT(psk_release_plaintext(&c, plaintext, length));
            ASSERT_EQ(typed_test_device_host_psk_queue_fin(&c), DEVICE_HOST_PSK_PROGRESS);
            ASSERT(psk_flight(&c, &s, orientation, "C2S_FIN", 1)); ASSERT(s.receive_fin); ASSERT(!s.send_fin);
            ASSERT_EQ(typed_test_device_host_psk_queue_fin(&s), DEVICE_HOST_PSK_PROGRESS);
            ASSERT(psk_flight(&s, &c, orientation, "S2C_FIN", 7));
            ASSERT_EQ(c.phase, DEVICE_HOST_PSK_FINISHED); ASSERT_EQ(s.phase, DEVICE_HOST_PSK_FINISHED);
            uint8_t extra = 0; size_t consumed = 0;
            ASSERT_EQ(typed_test_device_host_psk_receive_bytes(&s, &extra, 1, &consumed), DEVICE_HOST_PSK_REFUSED);
            device_host_psk_destroy(&c); device_host_psk_destroy(&s); psk_fixture_close(&f);
        }
    } TEST_END
    device_host_psk_destroy(&c); device_host_psk_destroy(&s); psk_fixture_close(&f); return failures;
}
static bool psk_failed_erased(const struct device_host_psk_session *session)
{
    struct device_host_psk_session expected = {0};
    expected.phase = DEVICE_HOST_PSK_FAILED; expected.terminal = session->terminal;
    return !memcmp(session, &expected, sizeof(expected));
}
static int psk_confirmation_refusals(void)
{
    int failures = 0; struct psk_fixture f = {0}; struct device_host_psk_session c = {0}, s = {0};
    TEST_CASE("host PSK: wrong-secret and altered server confirmation cannot advance and valid retry never revives") {
        for (unsigned defect = 0; defect < 5; ++defect) {
            ASSERT(psk_fixture_open_keys(&f, defect == 0)); ASSERT(psk_fixture_start(&f, 0, &c, &s));
            ASSERT(psk_flight(&c, &s, 0, NULL, 198));
            uint8_t wire[DEVICE_HOST_PSK_WIRE], original[DEVICE_HOST_PSK_WIRE]; size_t length = 0;
            ASSERT(psk_take_wire(&s, wire, &length)); memcpy(original, wire, length);
            const size_t offsets[] = {0, 24, 56, 88, 151};
            if (defect) wire[offsets[defect]] ^= 1;
            ASSERT_EQ(psk_feed(&c, wire, length, 7), DEVICE_HOST_PSK_REFUSED);
            ASSERT(psk_failed_erased(&c));
            ASSERT_EQ(psk_feed(&c, original, length, 7), DEVICE_HOST_PSK_REFUSED);
            ASSERT_EQ(c.phase, DEVICE_HOST_PSK_FAILED); ASSERT_EQ(c.pending_used, 0);
            device_host_psk_destroy(&c); device_host_psk_destroy(&s); psk_fixture_close(&f);
        }
    } TEST_END
    device_host_psk_destroy(&c); device_host_psk_destroy(&s); psk_fixture_close(&f); return failures;
}
static int psk_server_hello_refusals(void)
{
    int failures = 0; struct psk_fixture f = {0}; struct device_host_psk_session c = {0}, s = {0};
    TEST_CASE("host PSK: server refuses a C_HELLO with any one bound field altered and emits no S_HELLO") {
        /* version, epoch, credential id, client key, server key, port */
        const size_t offsets[] = {27, 35, 36, 68, 100, 164};
        for (unsigned defect = 0; defect <= 6; ++defect) {
            ASSERT(psk_fixture_open(&f)); ASSERT(psk_fixture_start(&f, 0, &c, &s));
            uint8_t wire[DEVICE_HOST_PSK_WIRE]; size_t length = 0;
            ASSERT(psk_take_wire(&c, wire, &length)); ASSERT_EQ(length, 198);
            if (defect < 6) wire[offsets[defect]] ^= 1;
            enum device_host_psk_result result = psk_feed(&s, wire, length, 198);
            if (defect == 6) {
                ASSERT_EQ(result, DEVICE_HOST_PSK_PROGRESS); ASSERT(s.pending_used > 0);
            } else {
                ASSERT_EQ(result, DEVICE_HOST_PSK_REFUSED); ASSERT(psk_failed_erased(&s));
                ASSERT_EQ(s.pending_used, 0);
                uint8_t out[DEVICE_HOST_PSK_WIRE]; size_t out_length = 0;
                ASSERT(!psk_take_wire(&s, out, &out_length));
            }
            device_host_psk_destroy(&c); device_host_psk_destroy(&s); psk_fixture_close(&f);
        }
    } TEST_END
    device_host_psk_destroy(&c); device_host_psk_destroy(&s); psk_fixture_close(&f); return failures;
}
static int psk_record_refusals(void)
{
    int failures = 0; struct psk_fixture f = {0}; struct device_host_psk_session c = {0}, s = {0};
    TEST_CASE("host PSK: bad record tag, reflected record and sequence replay release no plaintext") {
        for (unsigned defect = 0; defect < 3; ++defect) {
            ASSERT(psk_fixture_open(&f)); ASSERT(psk_handshake(&f, 0, &c, &s));
            const uint8_t plaintext[] = {1,2,3}; uint8_t wire[DEVICE_HOST_PSK_WIRE], original[DEVICE_HOST_PSK_WIRE]; size_t length = 0;
            ASSERT_EQ(typed_test_device_host_psk_queue_data(&c, plaintext, sizeof(plaintext)), DEVICE_HOST_PSK_PROGRESS);
            ASSERT(psk_take_wire(&c, wire, &length)); memcpy(original, wire, length);
            if (defect == 0) wire[length - 1] ^= 1;
            if (defect == 1) wire[23] = 1;
            struct device_host_psk_session *receiver = defect == 2 ? &c : &s;
            ASSERT_EQ(psk_feed(receiver, wire, length, 1), DEVICE_HOST_PSK_REFUSED);
            ASSERT(psk_failed_erased(receiver));
            ASSERT_EQ(psk_feed(receiver, original, length, 1), DEVICE_HOST_PSK_REFUSED);
            struct device_pairing_guard guard = {0}; const uint8_t *bytes = NULL; size_t size = 0;
            ASSERT_EQ(typed_test_device_host_psk_plaintext_acquire(receiver, &guard, &bytes, &size), DEVICE_HOST_PSK_REFUSED);
            ASSERT(bytes == NULL); ASSERT_EQ(size, 0); ASSERT(!guard.held);
            device_host_psk_destroy(&c); device_host_psk_destroy(&s); psk_fixture_close(&f);
        }
    } TEST_END
    device_host_psk_destroy(&c); device_host_psk_destroy(&s); psk_fixture_close(&f); return failures;
}
static int psk_pending_and_target(void)
{
    int failures = 0; struct psk_fixture f = {0}; struct device_host_psk_session c = {0}, s = {0};
    struct device_pairing_guard guard = {0};
    TEST_CASE("host PSK: exact pending suffix, held guard excludes revoke and no early DATA or automatic target readiness") {
        ASSERT(psk_fixture_open(&f)); ASSERT(psk_fixture_start(&f, 0, &c, &s));
        const uint8_t *bytes = NULL; size_t size = 0;
        ASSERT_EQ(typed_test_device_host_psk_pending_acquire(&c, &guard, &bytes, &size), DEVICE_HOST_PSK_PROGRESS);
        ASSERT_EQ(size, 198); ASSERT(guard.held);
        uint8_t first = bytes[0], saved[198]; memcpy(saved, bytes, sizeof(saved));
        enum device_pairing_publication publication;
        bool excluded = !db_device_pairing_revoke_expected(&f.store[0], f.row[0].peer_key, 150, f.root[0], &publication);
        enum device_host_psk_result completed = typed_test_device_host_psk_pending_written(&c, &guard, 1);
        ASSERT(excluded); ASSERT_EQ(completed, DEVICE_HOST_PSK_PROGRESS); ASSERT_EQ(c.phase, DEVICE_HOST_PSK_CLIENT_SEND_HELLO);
        ASSERT_EQ(typed_test_device_host_psk_pending_acquire(&c, &guard, &bytes, &size), DEVICE_HOST_PSK_PROGRESS);
        bool exact = size == 197 && !memcmp(bytes, saved + 1, 197);
        completed = typed_test_device_host_psk_pending_written(&c, &guard, size);
        ASSERT(exact); ASSERT_EQ(completed, DEVICE_HOST_PSK_PROGRESS); ASSERT_EQ(first, saved[0]);
        ASSERT_EQ(c.phase, DEVICE_HOST_PSK_CLIENT_WAIT_HELLO);
        ASSERT_EQ(psk_feed(&s, saved, sizeof(saved), 1), DEVICE_HOST_PSK_PROGRESS);
        size_t consumed = 99; const uint8_t extra[] = {1,2,3};
        ASSERT_EQ(typed_test_device_host_psk_receive_bytes(&s, extra, sizeof(extra), &consumed), DEVICE_HOST_PSK_WAIT);
        ASSERT_EQ(consumed, 0); ASSERT_EQ(s.incoming_used, 0);
        ASSERT(psk_flight(&s, &c, 0, NULL, 1)); ASSERT(psk_flight(&c, &s, 0, NULL, 1));
        ASSERT_EQ(s.phase, DEVICE_HOST_PSK_NEED_TARGET); ASSERT_EQ(s.pending_used, 0);
        ASSERT_EQ(typed_test_device_host_psk_pending_acquire(&s, &guard, &bytes, &size), DEVICE_HOST_PSK_WAIT); ASSERT_EQ(size, 0);
        ASSERT(psk_target_ready(&s)); ASSERT_EQ(s.phase, DEVICE_HOST_PSK_SERVER_SEND_READY);
        ASSERT(psk_flight(&s, &c, 0, NULL, 1));
    } TEST_END
    device_pairing_guard_release(&guard); device_host_psk_destroy(&c); device_host_psk_destroy(&s); psk_fixture_close(&f); return failures;
}
static int psk_acquisition_boundary(void)
{
    int failures = 0; struct psk_fixture f = {0}; struct device_host_psk_session c = {0}, s = {0};
    struct device_pairing_guard guard = {0};
    TEST_CASE("host PSK: post-acquisition wall expiry and monotonic deadline refuse before exporting write bytes") {
        for (unsigned deadline = 0; deadline < 2; ++deadline) {
            ASSERT(psk_fixture_open(&f)); ASSERT(psk_fixture_start(&f, 0, &c, &s));
            f.wall_calls = 0; f.jump_after = deadline ? 0 : 1; f.deadline_after_acquire = deadline != 0;
            const uint8_t *bytes = NULL; size_t size = 0;
            enum device_host_psk_result result = typed_test_device_host_psk_pending_acquire(&c, &guard, &bytes, &size);
            f.deadline_after_acquire = false; f.jump_after = 0;
            ASSERT_EQ(result, deadline ? DEVICE_HOST_PSK_DEADLINE : DEVICE_HOST_PSK_REFUSED);
            ASSERT(!guard.held); ASSERT(bytes == NULL); ASSERT_EQ(size, 0); ASSERT(psk_failed_erased(&c));
            device_host_psk_destroy(&c); device_host_psk_destroy(&s); psk_fixture_close(&f);
        }
    } TEST_END
    device_pairing_guard_release(&guard); device_host_psk_destroy(&c); device_host_psk_destroy(&s); psk_fixture_close(&f); return failures;
}
static int psk_guard_reuse_and_revoke(void)
{
    int failures = 0; struct psk_fixture f = {0}; struct device_host_psk_session c = {0}, s = {0};
    struct device_pairing_guard guard = {0};
    TEST_CASE("host PSK: unrelated held guard remains releasable; revoked decoded plaintext never exports") {
        ASSERT(psk_fixture_open(&f)); ASSERT(psk_fixture_start(&f, 0, &c, &s));
        ASSERT(device_pairing_guard_acquire_host_psk(&f.store[1], f.row[1].peer_key, f.root[1], 150,
            &f.row[1].host_scope.binding.psk, DEVICE_PAIRING_HOST_INBOUND, 2222, &guard));
        const uint8_t *bytes = NULL; size_t size = 0;
        enum device_host_psk_result result = typed_test_device_host_psk_pending_acquire(&c, &guard, &bytes, &size);
        bool retained = guard.held; device_pairing_guard_release(&guard);
        ASSERT_EQ(result, DEVICE_HOST_PSK_REFUSED); ASSERT(retained);
        device_host_psk_destroy(&c); device_host_psk_destroy(&s);
        ASSERT(psk_handshake(&f, 0, &c, &s));
        const uint8_t plaintext[] = {11,12};
        ASSERT_EQ(typed_test_device_host_psk_queue_data(&c, plaintext, sizeof(plaintext)), DEVICE_HOST_PSK_PROGRESS);
        ASSERT(psk_flight(&c, &s, 0, NULL, 1)); ASSERT_EQ(s.plaintext_used, sizeof(plaintext));
        enum device_pairing_publication publication;
        ASSERT(db_device_pairing_revoke_expected(&f.store[1], f.row[1].peer_key, 150, f.root[1], &publication));
        ASSERT_EQ(typed_test_device_host_psk_plaintext_acquire(&s, &guard, &bytes, &size), DEVICE_HOST_PSK_REFUSED);
        ASSERT(bytes == NULL); ASSERT_EQ(size, 0); ASSERT(!guard.held); ASSERT(psk_failed_erased(&s));
    } TEST_END
    device_pairing_guard_release(&guard); device_host_psk_destroy(&c); device_host_psk_destroy(&s); psk_fixture_close(&f); return failures;
}
static int psk_fin_counter_and_truncation(void)
{
    int failures = 0; struct psk_fixture f = {0}; struct device_host_psk_session c = {0}, s = {0};
    TEST_CASE("host PSK: final DATA reserves FIN, byte-total mismatch fails and raw EOF is not orderly FIN") {
        ASSERT(psk_fixture_open(&f)); ASSERT(psk_handshake(&f, 0, &c, &s));
        c.send_sequence = DEVICE_HOST_PSK_FRAME_LIMIT - 2; s.receive_sequence = c.send_sequence;
        const uint8_t byte = 1;
        ASSERT_EQ(typed_test_device_host_psk_queue_data(&c, &byte, 1), DEVICE_HOST_PSK_PROGRESS);
        ASSERT(psk_flight(&c, &s, 0, NULL, 1)); ASSERT(psk_release_plaintext(&s, &byte, 1));
        ASSERT_EQ(typed_test_device_host_psk_queue_fin(&c), DEVICE_HOST_PSK_PROGRESS);
        ASSERT(psk_flight(&c, &s, 0, NULL, 1)); ASSERT(s.receive_fin);
        ASSERT_EQ(s.receive_sequence, DEVICE_HOST_PSK_FRAME_LIMIT);
        device_host_psk_destroy(&c); device_host_psk_destroy(&s);
        ASSERT(psk_handshake(&f, 0, &c, &s)); c.send_sequence = DEVICE_HOST_PSK_FRAME_LIMIT - 1;
        ASSERT_EQ(typed_test_device_host_psk_queue_data(&c, &byte, 1), DEVICE_HOST_PSK_REFUSED); ASSERT(psk_failed_erased(&c));
        device_host_psk_destroy(&c); device_host_psk_destroy(&s);
        ASSERT(psk_handshake(&f, 0, &c, &s)); s.receive_total = 1;
        ASSERT_EQ(typed_test_device_host_psk_queue_fin(&c), DEVICE_HOST_PSK_PROGRESS);
        uint8_t wire[DEVICE_HOST_PSK_WIRE]; size_t length = 0; ASSERT(psk_take_wire(&c, wire, &length));
        ASSERT_EQ(psk_feed(&s, wire, length, 1), DEVICE_HOST_PSK_REFUSED); ASSERT(psk_failed_erased(&s));
        device_host_psk_destroy(&c); device_host_psk_destroy(&s);
        ASSERT(psk_fixture_start(&f, 0, &c, &s));
        ASSERT_EQ(typed_test_device_host_psk_transport_eof(&s), DEVICE_HOST_PSK_REFUSED); ASSERT(psk_failed_erased(&s));
    } TEST_END
    device_host_psk_destroy(&c); device_host_psk_destroy(&s); psk_fixture_close(&f); return failures;
}
static void psk_test_header(uint8_t wire[24], unsigned type, unsigned body)
{
    memset(wire, 0, 24); memcpy(wire, "Z23PSK01", 8); wire[9] = 1; wire[10] = (uint8_t)type;
    wire[14] = (uint8_t)(body >> 8); wire[15] = (uint8_t)body;
}
static unsigned psk_phase_type(enum device_host_psk_phase phase)
{
    switch (phase) {
    case DEVICE_HOST_PSK_SERVER_WAIT_HELLO: return 1;
    case DEVICE_HOST_PSK_CLIENT_WAIT_HELLO: return 2;
    case DEVICE_HOST_PSK_SERVER_WAIT_CONFIRM: return 3;
    case DEVICE_HOST_PSK_CLIENT_WAIT_READY: return 4;
    default: return 0;
    }
}
static int psk_wrong_states(void)
{
    int failures = 0; struct psk_fixture f = {0}; struct device_host_psk_session c = {0}, s = {0};
    TEST_CASE("host PSK: each handshake and record type refuses every wrong receive phase") {
        ASSERT(psk_fixture_open(&f));
        const enum device_host_psk_phase phases[] = {DEVICE_HOST_PSK_SERVER_WAIT_HELLO, DEVICE_HOST_PSK_CLIENT_WAIT_HELLO,
            DEVICE_HOST_PSK_SERVER_WAIT_CONFIRM, DEVICE_HOST_PSK_CLIENT_WAIT_READY, DEVICE_HOST_PSK_NEED_TARGET};
        const unsigned bodies[] = {0,174,128,64,64,65,64};
        for (size_t p = 0; p < sizeof(phases) / sizeof(phases[0]); ++p) {
            for (unsigned type = 1; type <= 6; ++type) {
                if (type == psk_phase_type(phases[p])) continue;
                ASSERT(psk_fixture_start(&f, 0, &c, &s));
                /* Owned white-box phase geometry; no key/state clone or output. */
                s.phase = phases[p]; s.pending_used = 0;
                uint8_t header[24]; psk_test_header(header, type, bodies[type]); size_t consumed = 0;
                ASSERT_EQ(typed_test_device_host_psk_receive_bytes(&s, header, sizeof(header), &consumed), DEVICE_HOST_PSK_REFUSED);
                ASSERT(psk_failed_erased(&s)); device_host_psk_destroy(&c); device_host_psk_destroy(&s);
            }
        }
    } TEST_END
    device_host_psk_destroy(&c); device_host_psk_destroy(&s); psk_fixture_close(&f); return failures;
}
static int psk_failure_reason(void)
{
    int failures = 0; struct psk_fixture f = {0}; struct device_host_psk_session c = {0}, s = {0};
    TEST_CASE("host PSK: public failure hook cannot turn wiped FAILED into a success or restartable state") {
        ASSERT(psk_fixture_open(&f));
        const enum device_host_psk_result reasons[] = {DEVICE_HOST_PSK_PROGRESS, DEVICE_HOST_PSK_WAIT,
            DEVICE_HOST_PSK_TARGET_REQUIRED, DEVICE_HOST_PSK_READY, DEVICE_HOST_PSK_EOF, DEVICE_HOST_PSK_BUSY};
        for (size_t i = 0; i < sizeof(reasons) / sizeof(reasons[0]); ++i) {
            ASSERT(psk_fixture_start(&f, 0, &c, &s));
            uint8_t wire[DEVICE_HOST_PSK_WIRE]; size_t length = 0, consumed = 0; ASSERT(psk_take_wire(&c, wire, &length));
            device_host_psk_fail(&s, reasons[i]);
            ASSERT_EQ(s.terminal, DEVICE_HOST_PSK_REFUSED); ASSERT(psk_failed_erased(&s));
            ASSERT_EQ(typed_test_device_host_psk_receive_bytes(&s, wire, length, &consumed), DEVICE_HOST_PSK_REFUSED);
            ASSERT(psk_failed_erased(&s)); device_host_psk_destroy(&c); device_host_psk_destroy(&s);
        }
    } TEST_END
    device_host_psk_destroy(&c); device_host_psk_destroy(&s); psk_fixture_close(&f); return failures;
}
static int psk_late_confirmations(void)
{
    int failures = 0; struct psk_fixture f = {0}; struct device_host_psk_session c = {0}, s = {0};
    TEST_CASE("host PSK: altered C_CONFIRM blocks target readiness and altered S_READY blocks client admission") {
        for (unsigned ready = 0; ready < 2; ++ready) {
            ASSERT(psk_fixture_open(&f)); ASSERT(psk_fixture_start(&f, 0, &c, &s));
            ASSERT(psk_flight(&c, &s, 0, NULL, 1)); ASSERT(psk_flight(&s, &c, 0, NULL, 1));
            uint8_t wire[DEVICE_HOST_PSK_WIRE], original[DEVICE_HOST_PSK_WIRE]; size_t length = 0;
            struct device_host_psk_session *receiver = &s;
            if (ready) {
                ASSERT(psk_flight(&c, &s, 0, NULL, 1)); ASSERT(psk_target_ready(&s));
                ASSERT(psk_take_wire(&s, wire, &length)); receiver = &c;
            } else ASSERT(psk_take_wire(&c, wire, &length));
            memcpy(original, wire, length); wire[length - 1] ^= 1;
            ASSERT_EQ(psk_feed(receiver, wire, length, 1), DEVICE_HOST_PSK_REFUSED);
            ASSERT(psk_failed_erased(receiver)); ASSERT_EQ(receiver->pending_used, 0);
            ASSERT_EQ(psk_feed(receiver, original, length, 1), DEVICE_HOST_PSK_REFUSED);
            device_host_psk_destroy(&c); device_host_psk_destroy(&s); psk_fixture_close(&f);
        }
    } TEST_END
    device_host_psk_destroy(&c); device_host_psk_destroy(&s); psk_fixture_close(&f); return failures;
}
static int psk_accepted_replay(void)
{
    int failures = 0; struct psk_fixture f = {0}; struct device_host_psk_session c = {0}, s = {0};
    TEST_CASE("host PSK: replaying an actually authenticated and released DATA frame cannot release twice") {
        ASSERT(psk_fixture_open(&f)); ASSERT(psk_handshake(&f, 0, &c, &s));
        const uint8_t plaintext[] = {7,8,9}; uint8_t wire[DEVICE_HOST_PSK_WIRE]; size_t length = 0;
        ASSERT_EQ(typed_test_device_host_psk_queue_data(&c, plaintext, sizeof(plaintext)), DEVICE_HOST_PSK_PROGRESS);
        ASSERT(psk_take_wire(&c, wire, &length)); ASSERT_EQ(psk_feed(&s, wire, length, 1), DEVICE_HOST_PSK_PROGRESS);
        ASSERT(psk_release_plaintext(&s, plaintext, sizeof(plaintext))); ASSERT_EQ(s.receive_sequence, 1);
        ASSERT_EQ(psk_feed(&s, wire, length, 1), DEVICE_HOST_PSK_REFUSED); ASSERT(psk_failed_erased(&s));
    } TEST_END
    device_host_psk_destroy(&c); device_host_psk_destroy(&s); psk_fixture_close(&f); return failures;
}
static int psk_partial_record_suffixes(void)
{
    int failures = 0; struct psk_fixture f = {0}; struct device_host_psk_session c = {0}, s = {0};
    struct device_pairing_guard guard = {0};
    struct shake_wrap_state sealed = {0}, opened = {0};
    TEST_CASE("host PSK: partial DATA and verified plaintext retain exact suffix and advance cryptographic state once") {
        ASSERT(psk_fixture_open(&f)); ASSERT(psk_handshake(&f, 0, &c, &s));
        const uint8_t plaintext[] = {21,22,23,24};
        ASSERT_EQ(typed_test_device_host_psk_queue_data(&c, plaintext, sizeof(plaintext)), DEVICE_HOST_PSK_PROGRESS);
        sealed = c.send;
        uint8_t wire[DEVICE_HOST_PSK_WIRE], expected[DEVICE_HOST_PSK_WIRE]; size_t wire_length = c.pending_used;
        memcpy(expected, c.pending, wire_length);
        const uint8_t *bytes = NULL; size_t length = 0;
        ASSERT_EQ(typed_test_device_host_psk_pending_acquire(&c, &guard, &bytes, &length), DEVICE_HOST_PSK_PROGRESS);
        bool full = length == wire_length; memcpy(wire, bytes, 3);
        enum device_host_psk_result completed = typed_test_device_host_psk_pending_written(&c, &guard, 3);
        ASSERT(full); ASSERT_EQ(completed, DEVICE_HOST_PSK_PROGRESS);
        ASSERT_EQ(c.send_sequence, 1); ASSERT_EQ(c.send_total, sizeof(plaintext)); ASSERT(!memcmp(&c.send, &sealed, sizeof(sealed)));
        ASSERT_EQ(typed_test_device_host_psk_pending_acquire(&c, &guard, &bytes, &length), DEVICE_HOST_PSK_PROGRESS);
        bool suffix = length == wire_length - 3 && !memcmp(bytes, expected + 3, length);
        memcpy(wire + 3, bytes, length); completed = typed_test_device_host_psk_pending_written(&c, &guard, length);
        ASSERT(suffix); ASSERT_EQ(completed, DEVICE_HOST_PSK_PROGRESS); ASSERT(!memcmp(wire, expected, wire_length));
        ASSERT_EQ(c.send_sequence, 1); ASSERT(!memcmp(&c.send, &sealed, sizeof(sealed)));
        ASSERT_EQ(psk_feed(&s, wire, wire_length, 1), DEVICE_HOST_PSK_PROGRESS);
        opened = s.receive;
        ASSERT_EQ(typed_test_device_host_psk_plaintext_acquire(&s, &guard, &bytes, &length), DEVICE_HOST_PSK_PROGRESS);
        bool first = length == sizeof(plaintext) && bytes[0] == plaintext[0];
        completed = typed_test_device_host_psk_plaintext_released(&s, &guard, 1);
        ASSERT(first); ASSERT_EQ(completed, DEVICE_HOST_PSK_PROGRESS);
        ASSERT_EQ(s.receive_sequence, 1); ASSERT_EQ(s.receive_total, sizeof(plaintext)); ASSERT(!memcmp(&s.receive, &opened, sizeof(opened)));
        ASSERT_EQ(typed_test_device_host_psk_plaintext_acquire(&s, &guard, &bytes, &length), DEVICE_HOST_PSK_PROGRESS);
        suffix = length == sizeof(plaintext) - 1 && !memcmp(bytes, plaintext + 1, length);
        completed = typed_test_device_host_psk_plaintext_released(&s, &guard, length);
        ASSERT(suffix); ASSERT_EQ(completed, DEVICE_HOST_PSK_PROGRESS); ASSERT_EQ(s.plaintext_used, 0);
        ASSERT_EQ(s.receive_sequence, 1); ASSERT(!memcmp(&s.receive, &opened, sizeof(opened)));
    } TEST_END
    shake_wrap_destroy(&sealed); shake_wrap_destroy(&opened);
    device_pairing_guard_release(&guard); device_host_psk_destroy(&c); device_host_psk_destroy(&s); psk_fixture_close(&f); return failures;
}
static int psk_entropy_and_cancel(void)
{
    int failures = 0; struct psk_fixture f = {0}; struct device_host_psk_session c = {0}, s = {0};
    struct device_pairing_guard guard = {0};
    TEST_CASE("host PSK: entropy refusal and cancellation during current-authority acquisition release no bytes") {
        ASSERT(psk_fixture_open(&f)); device_host_psk_init(&c);
        struct device_host_psk_spec spec = psk_fixture_spec(&f, 0, true);
        device_host_psk_test_nonce(NULL, true);
        ASSERT_EQ(typed_test_device_host_psk_start(&c, &spec), DEVICE_HOST_PSK_REFUSED); ASSERT(psk_failed_erased(&c));
        device_host_psk_destroy(&c); ASSERT(psk_fixture_start(&f, 0, &c, &s));
        f.cancel_on_wall = true; f.wall_calls = 0;
        const uint8_t *bytes = NULL; size_t length = 0;
        enum device_host_psk_result result = typed_test_device_host_psk_pending_acquire(&c, &guard, &bytes, &length);
        f.cancel_on_wall = false; atomic_store(&f.cancelled, false);
        ASSERT_EQ(result, DEVICE_HOST_PSK_CANCELLED); ASSERT(!guard.held); ASSERT(bytes == NULL); ASSERT_EQ(length, 0);
        ASSERT(psk_failed_erased(&c));
    } TEST_END
    device_pairing_guard_release(&guard); device_host_psk_destroy(&c); device_host_psk_destroy(&s); psk_fixture_close(&f); return failures;
}
static int psk_typed_custody(void)
{
    int failures = 0; struct psk_fixture f = {0};
    struct device_host_psk_session c = {0}, s = {0};
    struct device_pairing_guard guard = {0};
    TEST_CASE("host PSK typed boundary: status aliases refuse unchanged and BUSY retains exact held span") {
        ASSERT(psk_fixture_open(&f)); ASSERT(psk_fixture_start(&f, 0, &c, &s));
        enum device_host_psk_phase phase = c.phase;
        struct zcl_result result = device_host_psk_queue_fin(&c, (enum device_host_psk_result *)&c.phase);
        ASSERT(!result.ok); ASSERT_EQ(c.phase, phase); ASSERT_EQ(c.pending_used, 198);
        result = device_host_psk_queue_fin(&c, NULL);
        ASSERT(!result.ok); ASSERT_EQ(c.phase, phase); ASSERT_EQ(c.pending_used, 198);
        const uint8_t *bytes = NULL; size_t length = 0; enum device_host_psk_result status;
        result = device_host_psk_pending_acquire(&c, &guard, &bytes, &length, &status);
        ASSERT(result.ok); ASSERT_EQ(result.code, 0); ASSERT_EQ(status, DEVICE_HOST_PSK_PROGRESS);
        ASSERT(guard.held); ASSERT_EQ(length, 198);
        result = device_host_psk_pending_written(&c, &guard, 0, (enum device_host_psk_result *)&guard.row);
        ASSERT(!result.ok); ASSERT(guard.held); ASSERT(c.borrowed_guard == &guard); ASSERT_EQ(c.pending_sent, 0);
        const uint8_t *before = bytes;
        result = device_host_psk_pending_acquire(&c, &guard, &bytes, &length, (enum device_host_psk_result *)&bytes);
        ASSERT(!result.ok); ASSERT(bytes == before); ASSERT_EQ(length, 198); ASSERT(guard.held);
        result = device_host_psk_queue_fin(&c, &status);
        ASSERT(!result.ok); ASSERT_EQ(status, DEVICE_HOST_PSK_BUSY);
        ASSERT(guard.held); ASSERT(c.borrowed_guard == &guard); ASSERT_EQ(c.pending_sent, 0);
        result = device_host_psk_pending_written(&c, &guard, 0, &status);
        ASSERT(result.ok); ASSERT_EQ(result.code, 0); ASSERT_EQ(status, DEVICE_HOST_PSK_PROGRESS); ASSERT(!guard.held);
        result = device_host_psk_pending_acquire(&s, &guard, &bytes, &length, &status);
        ASSERT(result.ok); ASSERT_EQ(result.code, 0); ASSERT_EQ(status, DEVICE_HOST_PSK_WAIT);
        ASSERT(bytes == NULL); ASSERT_EQ(length, 0); ASSERT(!guard.held);
    } TEST_END
    device_pairing_guard_release(&guard); device_host_psk_destroy(&c); device_host_psk_destroy(&s);
    psk_fixture_close(&f); return failures;
}
/* Large-record profile. Sessions here use the live entropy path, so both hello nonces carry the
 * capability tag; a session started with a public test vector nonce advertises nothing and is the
 * legacy 4 KiB peer. */
static bool psk_live_start(struct psk_fixture *f, struct device_host_psk_session *client,
    struct device_host_psk_session *server, unsigned legacy)
{
    device_host_psk_init(client); device_host_psk_init(server);
    struct device_host_psk_spec c = psk_fixture_spec(f, 0, true), s = psk_fixture_spec(f, 1, false);
    uint8_t nonce[32];
    for (size_t i = 0; i < 32; ++i) nonce[i] = (uint8_t)(0xc0 + i);
    if (legacy & 1u) device_host_psk_test_nonce(nonce, false);
    if (typed_test_device_host_psk_start(client, &c) != DEVICE_HOST_PSK_PROGRESS) return false;
    if (legacy & 2u) device_host_psk_test_nonce(nonce, false);
    return typed_test_device_host_psk_start(server, &s) == DEVICE_HOST_PSK_PROGRESS;
}
static bool psk_live_handshake(struct psk_fixture *f, struct device_host_psk_session *client,
    struct device_host_psk_session *server, unsigned legacy)
{
    if (!psk_live_start(f, client, server, legacy)) return false;
    return psk_flight(client, server, 0, NULL, 1) && psk_flight(server, client, 0, NULL, 7) &&
        psk_flight(client, server, 0, NULL, 1) && server->phase == DEVICE_HOST_PSK_NEED_TARGET &&
        psk_target_ready(server) && psk_flight(server, client, 0, NULL, 3) &&
        client->phase == DEVICE_HOST_PSK_ESTABLISHED && server->phase == DEVICE_HOST_PSK_ESTABLISHED;
}
static bool psk_take_big(struct device_host_psk_session *sender, uint8_t wire[DEVICE_HOST_PSK_WIRE_MAX], size_t *length)
{
    struct device_pairing_guard guard = {0}; const uint8_t *bytes = NULL;
    enum device_host_psk_result result = typed_test_device_host_psk_pending_acquire(sender, &guard, &bytes, length);
    if (result != DEVICE_HOST_PSK_PROGRESS) { device_pairing_guard_release(&guard); return false; }
    memcpy(wire, bytes, *length);
    result = typed_test_device_host_psk_pending_written(sender, &guard, *length);
    device_pairing_guard_release(&guard);
    return result == DEVICE_HOST_PSK_PROGRESS;
}
static void psk_fill(uint8_t *bytes, size_t size)
{
    for (size_t i = 0; i < size; ++i) bytes[i] = (uint8_t)(i * 131u + (i >> 8) + 7u);
}
static int psk_large_case_1(void)
{
    int failures = 0; struct psk_fixture f = {0}; struct device_host_psk_session c = {0}, s = {0};
    static uint8_t plaintext[DEVICE_HOST_PSK_RECORD_MAX + 1], wire[DEVICE_HOST_PSK_WIRE_MAX];
    psk_fill(plaintext, sizeof(plaintext));
    TEST_CASE("host PSK: a record at the large maximum round-trips both ways under one verify-then-release") {
        ASSERT(psk_fixture_open(&f)); ASSERT(psk_live_handshake(&f, &c, &s, 0));
        ASSERT(c.large_records && s.large_records);
        ASSERT_EQ(device_host_psk_record_limit(&c), DEVICE_HOST_PSK_RECORD_MAX);
        for (unsigned direction = 0; direction < 2; ++direction) {
            struct device_host_psk_session *from = direction ? &s : &c, *to = direction ? &c : &s;
            size_t length = 0;
            ASSERT_EQ(typed_test_device_host_psk_queue_data(from, plaintext, DEVICE_HOST_PSK_RECORD_MAX), DEVICE_HOST_PSK_PROGRESS);
            ASSERT(psk_take_big(from, wire, &length));
            ASSERT_EQ(length, DEVICE_HOST_PSK_WIRE_MAX);
            ASSERT_EQ(psk_feed(to, wire, length, 1000), DEVICE_HOST_PSK_PROGRESS);
            ASSERT(psk_release_plaintext(to, plaintext, DEVICE_HOST_PSK_RECORD_MAX));
        }
        /* A short record after a long one still chains correctly. */
        size_t length = 0;
        ASSERT_EQ(typed_test_device_host_psk_queue_data(&c, plaintext, 4097), DEVICE_HOST_PSK_PROGRESS);
        ASSERT(psk_take_big(&c, wire, &length)); ASSERT_EQ(length, 24u + 4097u + 128u);
        ASSERT_EQ(psk_feed(&s, wire, length, 4096), DEVICE_HOST_PSK_PROGRESS);
        ASSERT(psk_release_plaintext(&s, plaintext, 4097));
    } TEST_END
    device_host_psk_destroy(&c); device_host_psk_destroy(&s); psk_fixture_close(&f);
    return failures;
}
static int psk_large_case_2(void)
{
    int failures = 0; struct psk_fixture f = {0}; struct device_host_psk_session c = {0}, s = {0};
    static uint8_t plaintext[DEVICE_HOST_PSK_RECORD_MAX + 1];
    psk_fill(plaintext, sizeof(plaintext));
    TEST_CASE("host PSK: the sender refuses one byte over the large maximum") {
        ASSERT(psk_fixture_open(&f)); ASSERT(psk_live_handshake(&f, &c, &s, 0));
        ASSERT_EQ(typed_test_device_host_psk_queue_data(&c, plaintext, DEVICE_HOST_PSK_RECORD_MAX + 1), DEVICE_HOST_PSK_REFUSED);
        ASSERT(psk_failed_erased(&c));
    } TEST_END
    device_host_psk_destroy(&c); device_host_psk_destroy(&s); psk_fixture_close(&f);
    return failures;
}
static int psk_large_case_3(void)
{
    int failures = 0; struct psk_fixture f = {0}; struct device_host_psk_session c = {0}, s = {0};
    static uint8_t plaintext[DEVICE_HOST_PSK_RECORD_MAX + 1], wire[DEVICE_HOST_PSK_WIRE_MAX];
    psk_fill(plaintext, sizeof(plaintext));
    TEST_CASE("host PSK: the receiver refuses a header one byte over the large maximum and releases nothing") {
        ASSERT(psk_fixture_open(&f)); ASSERT(psk_live_handshake(&f, &c, &s, 0));
        size_t length = 0;
        ASSERT_EQ(typed_test_device_host_psk_queue_data(&c, plaintext, DEVICE_HOST_PSK_RECORD_MAX), DEVICE_HOST_PSK_PROGRESS);
        ASSERT(psk_take_big(&c, wire, &length));
        zcl_write_u32_be(wire + 12, (uint32_t)(DEVICE_HOST_PSK_RECORD_MAX + 1 + 5 * 64));
        ASSERT_EQ(psk_feed(&s, wire, DEVICE_HOST_PSK_HEADER, DEVICE_HOST_PSK_HEADER), DEVICE_HOST_PSK_REFUSED);
        ASSERT(psk_failed_erased(&s));
    } TEST_END
    device_host_psk_destroy(&c); device_host_psk_destroy(&s); psk_fixture_close(&f);
    return failures;
}
static int psk_large_case_4(void)
{
    int failures = 0; struct psk_fixture f = {0}; struct device_host_psk_session c = {0}, s = {0};
    static uint8_t plaintext[DEVICE_HOST_PSK_RECORD_MAX + 1], wire[DEVICE_HOST_PSK_WIRE_MAX];
    psk_fill(plaintext, sizeof(plaintext));
    TEST_CASE("host PSK: a forged tag in the last chunk of a large record refuses the whole record") {
        ASSERT(psk_fixture_open(&f)); ASSERT(psk_live_handshake(&f, &c, &s, 0));
        size_t length = 0;
        ASSERT_EQ(typed_test_device_host_psk_queue_data(&c, plaintext, DEVICE_HOST_PSK_RECORD_MAX), DEVICE_HOST_PSK_PROGRESS);
        ASSERT(psk_take_big(&c, wire, &length)); wire[length - 1] ^= 1;
        ASSERT_EQ(psk_feed(&s, wire, length, 5000), DEVICE_HOST_PSK_REFUSED);
        ASSERT(psk_failed_erased(&s));
    } TEST_END
    device_host_psk_destroy(&c); device_host_psk_destroy(&s); psk_fixture_close(&f);
    return failures;
}
static int psk_large_case_5(void)
{
    int failures = 0; struct psk_fixture f = {0}; struct device_host_psk_session c = {0}, s = {0};
    static uint8_t plaintext[DEVICE_HOST_PSK_RECORD_MAX + 1], wire[DEVICE_HOST_PSK_WIRE_MAX];
    psk_fill(plaintext, sizeof(plaintext));
    TEST_CASE("host PSK: a legacy-max peer interoperates at 4096 and the new side refuses over it") {
        for (unsigned legacy = 1; legacy <= 2; ++legacy) {
            ASSERT(psk_fixture_open(&f)); ASSERT(psk_live_handshake(&f, &c, &s, legacy));
            ASSERT(!c.large_records && !s.large_records);
            ASSERT_EQ(device_host_psk_record_limit(&c), DEVICE_HOST_PSK_CHUNK);
            ASSERT_EQ(device_host_psk_record_limit(&s), DEVICE_HOST_PSK_CHUNK);
            size_t length = 0;
            ASSERT_EQ(typed_test_device_host_psk_queue_data(&c, plaintext, DEVICE_HOST_PSK_CHUNK), DEVICE_HOST_PSK_PROGRESS);
            ASSERT(psk_take_big(&c, wire, &length)); ASSERT_EQ(length, DEVICE_HOST_PSK_WIRE);
            ASSERT_EQ(psk_feed(&s, wire, length, 777), DEVICE_HOST_PSK_PROGRESS);
            ASSERT(psk_release_plaintext(&s, plaintext, DEVICE_HOST_PSK_CHUNK));
            ASSERT_EQ(typed_test_device_host_psk_queue_data(&s, plaintext, DEVICE_HOST_PSK_CHUNK + 1), DEVICE_HOST_PSK_REFUSED);
            ASSERT(psk_failed_erased(&s));
            device_host_psk_destroy(&c); device_host_psk_destroy(&s); psk_fixture_close(&f);
        }
        /* Receive side: a two-chunk frame (4097 bytes) is not accepted without the capability. */
        ASSERT(psk_fixture_open(&f)); ASSERT(psk_live_handshake(&f, &c, &s, 0));
        size_t length = 0; uint8_t header[DEVICE_HOST_PSK_HEADER];
        ASSERT_EQ(typed_test_device_host_psk_queue_data(&c, plaintext, 4097), DEVICE_HOST_PSK_PROGRESS);
        ASSERT(psk_take_big(&c, wire, &length)); memcpy(header, wire, sizeof(header));
        device_host_psk_destroy(&c); device_host_psk_destroy(&s); psk_fixture_close(&f);
        ASSERT(psk_fixture_open(&f)); ASSERT(psk_live_handshake(&f, &c, &s, 1));
        ASSERT_EQ(psk_feed(&s, header, sizeof(header), sizeof(header)), DEVICE_HOST_PSK_REFUSED);
        ASSERT(psk_failed_erased(&s));
    } TEST_END
    device_host_psk_destroy(&c); device_host_psk_destroy(&s); psk_fixture_close(&f);
    return failures;
}
static int psk_large_records(void)
{
    return psk_large_case_1() + psk_large_case_2() + psk_large_case_3() + psk_large_case_4() + psk_large_case_5();
}
int test_device_host_psk(void);
int test_device_host_psk(void)
{
    typed_state_failures = 0;
    int failures = psk_oracle_roundtrip();
    failures += psk_confirmation_refusals(); failures += psk_server_hello_refusals(); failures += psk_record_refusals();
    failures += psk_pending_and_target(); failures += psk_acquisition_boundary();
    failures += psk_guard_reuse_and_revoke(); failures += psk_fin_counter_and_truncation();
    failures += psk_wrong_states(); failures += psk_failure_reason();
    failures += psk_late_confirmations(); failures += psk_accepted_replay();
    failures += psk_partial_record_suffixes(); failures += psk_entropy_and_cancel();
    failures += psk_typed_custody(); failures += psk_large_records();
    return failures + (int)typed_state_failures;
}
