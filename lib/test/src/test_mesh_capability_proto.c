/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Canonical and adversarial capability-lifecycle codec acceptance. */

#include "test/test_core.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "session/mesh_capability_proto.h"

#include <string.h>

static void capability_fill(uint8_t out[32], uint8_t first)
{
    for (size_t i = 0; i < 32; i++)
        out[i] = (uint8_t)(first + i * 13u);
}

static void make_proposal(struct mesh_capability_proposal_v1 *frame)
{
    memset(frame, 0, sizeof(*frame));
    capability_fill(frame->network_genesis, 0x01);
    capability_fill(frame->proposal_id, 0x11);
    capability_fill(frame->target_master_pubkey, 0x21);
    capability_fill(frame->subject_master_pubkey, 0x31);
    capability_fill(frame->subject_noise_static, 0x41);
    capability_fill(frame->input_root, 0x51);
    capability_fill(frame->nonce, 0x61);
    capability_fill(frame->idempotency_key, 0x71);
    frame->capability = MESH_CAPABILITY_KIND_REMOTE_BUILD;
    frame->result_mask = MESH_CAPABILITY_RESULT_STORE |
                         MESH_CAPABILITY_RESULT_RETURN;
    frame->max_bytes = UINT64_C(1048576);
    frame->max_cpu_milliseconds = UINT64_C(30000);
    frame->max_memory_bytes = UINT64_C(268435456);
    frame->max_processes = 4;
    frame->max_concurrency = 2;
    frame->max_wall_milliseconds = UINT64_C(60000);
    frame->not_before_unix = UINT64_C(1800000000);
    frame->expires_unix = frame->not_before_unix + 600;
    frame->deny_mask = MESH_CAPABILITY_POLICY_DENY_REQUIRED;
}

static bool make_view(struct mesh_capability_frame_view_v1 *view,
                      enum mesh_capability_frame_kind kind)
{
    memset(view, 0, sizeof(*view));
    view->kind = kind;
    switch (kind) {
    case MESH_CAPABILITY_FRAME_PROPOSAL:
        make_proposal(&view->body.proposal);
        break;
    case MESH_CAPABILITY_FRAME_COMMIT: {
        struct mesh_capability_commit_v1 *f = &view->body.commit;
        capability_fill(f->proposal_id, 0x11);
        capability_fill(f->proposal_root, 0x12);
        capability_fill(f->commit_id, 0x13);
        capability_fill(f->target_master_pubkey, 0x14);
        capability_fill(f->subject_master_pubkey, 0x15);
        capability_fill(f->transcript_hash, 0x16);
        f->connection_generation = 7;
        f->plan_generation = 0;
        f->committed_unix = UINT64_C(1800000010);
        break;
    }
    case MESH_CAPABILITY_FRAME_GRANT: {
        struct mesh_capability_grant_v1 *f = &view->body.grant;
        capability_fill(f->proposal_id, 0x21);
        capability_fill(f->proposal_root, 0x22);
        capability_fill(f->commit_id, 0x23);
        capability_fill(f->grant_id, 0x24);
        capability_fill(f->grant_nonce, 0x25);
        capability_fill(f->target_master_pubkey, 0x26);
        capability_fill(f->subject_master_pubkey, 0x27);
        f->issued_unix = UINT64_C(1800000010);
        f->not_before_unix = UINT64_C(1800000020);
        f->expires_unix = UINT64_C(1800000620);
        f->revocation_generation = 0;
        break;
    }
    case MESH_CAPABILITY_FRAME_REFUSAL: {
        struct mesh_capability_refusal_v1 *f = &view->body.refusal;
        capability_fill(f->request_id, 0x31);
        capability_fill(f->request_root, 0x32);
        capability_fill(f->target_master_pubkey, 0x33);
        f->reason = MESH_CAPABILITY_REFUSAL_OWNER_DECLINED;
        f->observed_unix = UINT64_C(1800000030);
        f->authority_generation = 0;
        break;
    }
    case MESH_CAPABILITY_FRAME_RENEW: {
        struct mesh_capability_renew_v1 *f = &view->body.renew;
        capability_fill(f->request_id, 0x41);
        capability_fill(f->prior_grant_id, 0x42);
        capability_fill(f->replacement_proposal_id, 0x43);
        capability_fill(f->replacement_proposal_root, 0x44);
        capability_fill(f->target_master_pubkey, 0x45);
        capability_fill(f->subject_master_pubkey, 0x46);
        f->requested_not_before_unix = UINT64_C(1800000100);
        f->requested_expires_unix = UINT64_C(1800000700);
        f->revocation_generation = 0;
        break;
    }
    case MESH_CAPABILITY_FRAME_CANCEL: {
        struct mesh_capability_cancel_v1 *f = &view->body.cancel;
        capability_fill(f->cancel_id, 0x51);
        capability_fill(f->grant_id, 0x52);
        capability_fill(f->operation_id, 0x53);
        capability_fill(f->target_master_pubkey, 0x54);
        capability_fill(f->subject_master_pubkey, 0x55);
        f->requested_unix = UINT64_C(1800000200);
        break;
    }
    case MESH_CAPABILITY_FRAME_ACK: {
        struct mesh_capability_ack_v1 *f = &view->body.ack;
        capability_fill(f->ack_id, 0x61);
        capability_fill(f->request_id, 0x62);
        capability_fill(f->request_root, 0x63);
        capability_fill(f->target_master_pubkey, 0x64);
        capability_fill(f->subject_master_pubkey, 0x65);
        f->acknowledged_kind = MESH_CAPABILITY_FRAME_CANCEL;
        f->status = MESH_CAPABILITY_ACK_APPLIED;
        f->observed_unix = UINT64_C(1800000210);
        f->authority_generation = 0;
        break;
    }
    default:
        return false;
    }
    uint8_t seed[32], public_key[32], secret[32];
    capability_fill(seed, 0x91);
    ed25519_keypair(public_key, secret, seed);
    memset(secret, 0, sizeof(secret));
    switch (kind) {
    case MESH_CAPABILITY_FRAME_PROPOSAL:
        memcpy(view->body.proposal.signer_online_pubkey, public_key, 32); break;
    case MESH_CAPABILITY_FRAME_COMMIT:
        memcpy(view->body.commit.signer_online_pubkey, public_key, 32); break;
    case MESH_CAPABILITY_FRAME_GRANT:
        memcpy(view->body.grant.signer_online_pubkey, public_key, 32); break;
    case MESH_CAPABILITY_FRAME_REFUSAL:
        memcpy(view->body.refusal.signer_online_pubkey, public_key, 32); break;
    case MESH_CAPABILITY_FRAME_RENEW:
        memcpy(view->body.renew.signer_online_pubkey, public_key, 32); break;
    case MESH_CAPABILITY_FRAME_CANCEL:
        memcpy(view->body.cancel.signer_online_pubkey, public_key, 32); break;
    case MESH_CAPABILITY_FRAME_ACK:
        memcpy(view->body.ack.signer_online_pubkey, public_key, 32); break;
    }
    return mesh_capability_frame_v1_sign(view, seed) ==
           MESH_CAPABILITY_PROTO_OK;
}

static size_t kind_size(enum mesh_capability_frame_kind kind)
{
    static const size_t sizes[] = {
        0, MESH_CAPABILITY_PROPOSAL_V1_WIRE_BYTES,
        MESH_CAPABILITY_COMMIT_V1_WIRE_BYTES,
        MESH_CAPABILITY_GRANT_V1_WIRE_BYTES,
        MESH_CAPABILITY_REFUSAL_V1_WIRE_BYTES,
        MESH_CAPABILITY_RENEW_V1_WIRE_BYTES,
        MESH_CAPABILITY_CANCEL_V1_WIRE_BYTES,
        MESH_CAPABILITY_ACK_V1_WIRE_BYTES,
    };
    return kind >= MESH_CAPABILITY_FRAME_PROPOSAL &&
                   kind <= MESH_CAPABILITY_FRAME_ACK
               ? sizes[kind] : 0;
}

static enum mesh_capability_proto_error encode_view(
    const struct mesh_capability_frame_view_v1 *view, uint8_t *out,
    size_t capacity, size_t *out_len)
{
    switch (view->kind) {
    case MESH_CAPABILITY_FRAME_PROPOSAL:
        return mesh_capability_proposal_v1_encode(
            &view->body.proposal, out, capacity, out_len);
    case MESH_CAPABILITY_FRAME_COMMIT:
        return mesh_capability_commit_v1_encode(
            &view->body.commit, out, capacity, out_len);
    case MESH_CAPABILITY_FRAME_GRANT:
        return mesh_capability_grant_v1_encode(
            &view->body.grant, out, capacity, out_len);
    case MESH_CAPABILITY_FRAME_REFUSAL:
        return mesh_capability_refusal_v1_encode(
            &view->body.refusal, out, capacity, out_len);
    case MESH_CAPABILITY_FRAME_RENEW:
        return mesh_capability_renew_v1_encode(
            &view->body.renew, out, capacity, out_len);
    case MESH_CAPABILITY_FRAME_CANCEL:
        return mesh_capability_cancel_v1_encode(
            &view->body.cancel, out, capacity, out_len);
    case MESH_CAPABILITY_FRAME_ACK:
        return mesh_capability_ack_v1_encode(
            &view->body.ack, out, capacity, out_len);
    }
    return MESH_CAPABILITY_PROTO_KIND_INVALID;
}

static uint8_t *test_view_public_key(
    struct mesh_capability_frame_view_v1 *view)
{
    switch (view->kind) {
    case MESH_CAPABILITY_FRAME_PROPOSAL:
        return view->body.proposal.signer_online_pubkey;
    case MESH_CAPABILITY_FRAME_COMMIT:
        return view->body.commit.signer_online_pubkey;
    case MESH_CAPABILITY_FRAME_GRANT:
        return view->body.grant.signer_online_pubkey;
    case MESH_CAPABILITY_FRAME_REFUSAL:
        return view->body.refusal.signer_online_pubkey;
    case MESH_CAPABILITY_FRAME_RENEW:
        return view->body.renew.signer_online_pubkey;
    case MESH_CAPABILITY_FRAME_CANCEL:
        return view->body.cancel.signer_online_pubkey;
    case MESH_CAPABILITY_FRAME_ACK:
        return view->body.ack.signer_online_pubkey;
    }
    return NULL;
}

static uint8_t *test_view_signature(
    struct mesh_capability_frame_view_v1 *view)
{
    switch (view->kind) {
    case MESH_CAPABILITY_FRAME_PROPOSAL: return view->body.proposal.signature;
    case MESH_CAPABILITY_FRAME_COMMIT: return view->body.commit.signature;
    case MESH_CAPABILITY_FRAME_GRANT: return view->body.grant.signature;
    case MESH_CAPABILITY_FRAME_REFUSAL: return view->body.refusal.signature;
    case MESH_CAPABILITY_FRAME_RENEW: return view->body.renew.signature;
    case MESH_CAPABILITY_FRAME_CANCEL: return view->body.cancel.signature;
    case MESH_CAPABILITY_FRAME_ACK: return view->body.ack.signature;
    }
    return NULL;
}

static int lifecycle_roundtrip(void)
{
    int failures = 0;
    TEST_CASE("capability lifecycle frames have one canonical wire") {
        uint8_t wire[MESH_CAPABILITY_FRAME_V1_MAX];
        uint8_t again[MESH_CAPABILITY_FRAME_V1_MAX];
        for (int raw = MESH_CAPABILITY_FRAME_PROPOSAL;
             raw <= MESH_CAPABILITY_FRAME_ACK; raw++) {
            enum mesh_capability_frame_kind kind =
                (enum mesh_capability_frame_kind)raw;
            struct mesh_capability_frame_view_v1 original, decoded;
            size_t wire_len = 0, again_len = 0;
            ASSERT(make_view(&original, kind));
            ASSERT_EQ(encode_view(&original, wire, sizeof(wire), &wire_len),
                      MESH_CAPABILITY_PROTO_OK);
            ASSERT_EQ(wire_len, kind_size(kind));
            ASSERT(memcmp(wire, "ZCAP", 4) == 0);
            ASSERT_EQ(zcl_read_u16_le(wire + 4),
                      MESH_CAPABILITY_PROTO_VERSION);
            ASSERT_EQ(wire[6], raw);
            ASSERT_EQ(wire[7], MESH_CAPABILITY_PROTO_FLAGS_NONE);
            ASSERT_EQ(mesh_capability_frame_v1_decode(
                          &decoded, wire, wire_len),
                      MESH_CAPABILITY_PROTO_OK);
            ASSERT_EQ(decoded.kind, kind);
            if (kind == MESH_CAPABILITY_FRAME_COMMIT)
                ASSERT_EQ(decoded.body.commit.plan_generation, 0u);
            if (kind == MESH_CAPABILITY_FRAME_GRANT)
                ASSERT_EQ(decoded.body.grant.revocation_generation, 0u);
            if (kind == MESH_CAPABILITY_FRAME_REFUSAL)
                ASSERT_EQ(decoded.body.refusal.authority_generation, 0u);
            if (kind == MESH_CAPABILITY_FRAME_RENEW)
                ASSERT_EQ(decoded.body.renew.revocation_generation, 0u);
            if (kind == MESH_CAPABILITY_FRAME_ACK)
                ASSERT_EQ(decoded.body.ack.authority_generation, 0u);
            ASSERT_EQ(encode_view(&decoded, again, sizeof(again), &again_len),
                      MESH_CAPABILITY_PROTO_OK);
            ASSERT_EQ(again_len, wire_len);
            ASSERT(memcmp(again, wire, wire_len) == 0);
        }
    } TEST_END
    return failures;
}

static int exact_length_refusal(void)
{
    int failures = 0;
    TEST_CASE("capability frames reject truncation trailing bytes and capacity") {
        uint8_t wire[MESH_CAPABILITY_FRAME_V1_MAX + 1u];
        for (int raw = MESH_CAPABILITY_FRAME_PROPOSAL;
             raw <= MESH_CAPABILITY_FRAME_ACK; raw++) {
            enum mesh_capability_frame_kind kind =
                (enum mesh_capability_frame_kind)raw;
            struct mesh_capability_frame_view_v1 original, decoded;
            size_t wire_len = 99;
            ASSERT(make_view(&original, kind));
            ASSERT_EQ(encode_view(&original, wire, kind_size(kind) - 1u,
                                  &wire_len),
                      MESH_CAPABILITY_PROTO_SIZE);
            ASSERT_EQ(wire_len, 0u);
            ASSERT_EQ(encode_view(&original, wire, sizeof(wire), &wire_len),
                      MESH_CAPABILITY_PROTO_OK);
            ASSERT_EQ(mesh_capability_frame_v1_decode(
                          &decoded, wire, wire_len - 1u),
                      MESH_CAPABILITY_PROTO_SIZE);
            ASSERT(zcl_bytes_all_zero((const uint8_t *)&decoded, sizeof(decoded)));
            wire[wire_len] = 0;
            ASSERT_EQ(mesh_capability_frame_v1_decode(
                          &decoded, wire, wire_len + 1u),
                      MESH_CAPABILITY_PROTO_SIZE);
            ASSERT(zcl_bytes_all_zero((const uint8_t *)&decoded, sizeof(decoded)));
        }
    } TEST_END
    return failures;
}

static int envelope_refusal(void)
{
    int failures = 0;
    TEST_CASE("capability frame domain version kind and flags fail closed") {
        struct mesh_capability_frame_view_v1 proposal, decoded;
        uint8_t wire[MESH_CAPABILITY_PROPOSAL_V1_WIRE_BYTES];
        size_t wire_len = 0;
        ASSERT(make_view(&proposal, MESH_CAPABILITY_FRAME_PROPOSAL));
        ASSERT_EQ(encode_view(&proposal, wire, sizeof(wire), &wire_len),
                  MESH_CAPABILITY_PROTO_OK);
        wire[0] ^= 1;
        ASSERT_EQ(mesh_capability_frame_v1_decode(&decoded, wire, wire_len),
                  MESH_CAPABILITY_PROTO_MAGIC);
        wire[0] ^= 1; wire[4] = 2;
        ASSERT_EQ(mesh_capability_frame_v1_decode(&decoded, wire, wire_len),
                  MESH_CAPABILITY_PROTO_VERSION_INVALID);
        wire[4] = 1; wire[7] = 1;
        ASSERT_EQ(mesh_capability_frame_v1_decode(&decoded, wire, wire_len),
                  MESH_CAPABILITY_PROTO_FLAGS);
        wire[7] = 0; wire[6] = 0;
        ASSERT_EQ(mesh_capability_frame_v1_decode(&decoded, wire, wire_len),
                  MESH_CAPABILITY_PROTO_KIND_INVALID);
        ASSERT(zcl_bytes_all_zero((const uint8_t *)&decoded, sizeof(decoded)));
    } TEST_END
    return failures;
}

static int proposal_bounds(void)
{
    int failures = 0;
    TEST_CASE("capability proposal bounds resources authority and lifetime") {
        struct mesh_capability_proposal_v1 proposal, trial;
        uint8_t wire[MESH_CAPABILITY_PROPOSAL_V1_WIRE_BYTES];
        size_t wire_len = 1;
        struct mesh_capability_frame_view_v1 signed_proposal;
        ASSERT(make_view(&signed_proposal, MESH_CAPABILITY_FRAME_PROPOSAL));
        proposal = signed_proposal.body.proposal;

        trial = proposal; memset(trial.proposal_id, 0, 32);
        ASSERT_EQ(mesh_capability_proposal_v1_encode(
                      &trial, wire, sizeof(wire), &wire_len),
                  MESH_CAPABILITY_PROTO_FIELD);
        trial = proposal; trial.capability |= trial.capability << 1;
        ASSERT_EQ(mesh_capability_proposal_v1_encode(
                      &trial, wire, sizeof(wire), &wire_len),
                  MESH_CAPABILITY_PROTO_FIELD);
        trial = proposal; trial.capability = UINT64_C(1) << 63;
        ASSERT_EQ(mesh_capability_proposal_v1_encode(
                      &trial, wire, sizeof(wire), &wire_len),
                  MESH_CAPABILITY_PROTO_FIELD);
        trial = proposal; trial.result_mask = 0;
        ASSERT_EQ(mesh_capability_proposal_v1_encode(
                      &trial, wire, sizeof(wire), &wire_len),
                  MESH_CAPABILITY_PROTO_FIELD);
        trial = proposal; trial.result_mask |= UINT64_C(1) << 63;
        ASSERT_EQ(mesh_capability_proposal_v1_encode(
                      &trial, wire, sizeof(wire), &wire_len),
                  MESH_CAPABILITY_PROTO_FIELD);
        trial = proposal;
        trial.deny_mask &= ~MESH_CAPABILITY_POLICY_DENY_WALLET;
        ASSERT_EQ(mesh_capability_proposal_v1_encode(
                      &trial, wire, sizeof(wire), &wire_len),
                  MESH_CAPABILITY_PROTO_FIELD);
        trial = proposal; trial.max_bytes = MESH_CAPABILITY_MAX_BYTES + 1u;
        ASSERT_EQ(mesh_capability_proposal_v1_encode(
                      &trial, wire, sizeof(wire), &wire_len),
                  MESH_CAPABILITY_PROTO_LIMIT);
        trial = proposal; trial.max_bytes = 0;
        ASSERT_EQ(mesh_capability_proposal_v1_encode(
                      &trial, wire, sizeof(wire), &wire_len),
                  MESH_CAPABILITY_PROTO_LIMIT);
        trial = proposal; trial.max_cpu_milliseconds = 0;
        ASSERT_EQ(mesh_capability_proposal_v1_encode(
                      &trial, wire, sizeof(wire), &wire_len),
                  MESH_CAPABILITY_PROTO_LIMIT);
        trial = proposal; trial.max_memory_bytes = 0;
        ASSERT_EQ(mesh_capability_proposal_v1_encode(
                      &trial, wire, sizeof(wire), &wire_len),
                  MESH_CAPABILITY_PROTO_LIMIT);
        trial = proposal; trial.max_processes = 0;
        ASSERT_EQ(mesh_capability_proposal_v1_encode(
                      &trial, wire, sizeof(wire), &wire_len),
                  MESH_CAPABILITY_PROTO_LIMIT);
        trial = proposal; trial.max_concurrency = 0;
        ASSERT_EQ(mesh_capability_proposal_v1_encode(
                      &trial, wire, sizeof(wire), &wire_len),
                  MESH_CAPABILITY_PROTO_LIMIT);
        trial = proposal; trial.max_wall_milliseconds = 0;
        ASSERT_EQ(mesh_capability_proposal_v1_encode(
                      &trial, wire, sizeof(wire), &wire_len),
                  MESH_CAPABILITY_PROTO_LIMIT);
        trial = proposal; trial.expires_unix = trial.not_before_unix;
        ASSERT_EQ(mesh_capability_proposal_v1_encode(
                      &trial, wire, sizeof(wire), &wire_len),
                  MESH_CAPABILITY_PROTO_TIME);
        trial = proposal;
        trial.expires_unix = trial.not_before_unix +
                             MESH_CAPABILITY_MAX_LIFETIME_SECONDS + 1u;
        ASSERT_EQ(mesh_capability_proposal_v1_encode(
                      &trial, wire, sizeof(wire), &wire_len),
                  MESH_CAPABILITY_PROTO_TIME);
    } TEST_END
    return failures;
}

static int lifecycle_field_refusal(void)
{
    int failures = 0;
    TEST_CASE("capability lifecycle frames reject invalid fields and status") {
        uint8_t wire[MESH_CAPABILITY_FRAME_V1_MAX];
        size_t wire_len = 1;
        struct mesh_capability_frame_view_v1 view;

        ASSERT(make_view(&view, MESH_CAPABILITY_FRAME_COMMIT));
        view.body.commit.connection_generation = 0;
        ASSERT_EQ(encode_view(&view, wire, sizeof(wire), &wire_len),
                  MESH_CAPABILITY_PROTO_FIELD);
        ASSERT(make_view(&view, MESH_CAPABILITY_FRAME_GRANT));
        view.body.grant.expires_unix = view.body.grant.not_before_unix;
        ASSERT_EQ(encode_view(&view, wire, sizeof(wire), &wire_len),
                  MESH_CAPABILITY_PROTO_TIME);
        ASSERT(make_view(&view, MESH_CAPABILITY_FRAME_GRANT));
        view.body.grant.issued_unix = view.body.grant.not_before_unix + 1u;
        ASSERT_EQ(encode_view(&view, wire, sizeof(wire), &wire_len),
                  MESH_CAPABILITY_PROTO_TIME);
        ASSERT(make_view(&view, MESH_CAPABILITY_FRAME_REFUSAL));
        view.body.refusal.reason =
            (enum mesh_capability_refusal_reason)0;
        ASSERT_EQ(encode_view(&view, wire, sizeof(wire), &wire_len),
                  MESH_CAPABILITY_PROTO_STATUS);
        ASSERT(make_view(&view, MESH_CAPABILITY_FRAME_RENEW));
        view.body.renew.requested_expires_unix =
            view.body.renew.requested_not_before_unix;
        ASSERT_EQ(encode_view(&view, wire, sizeof(wire), &wire_len),
                  MESH_CAPABILITY_PROTO_TIME);
        ASSERT(make_view(&view, MESH_CAPABILITY_FRAME_CANCEL));
        memset(view.body.cancel.operation_id, 0, 32);
        ASSERT_EQ(encode_view(&view, wire, sizeof(wire), &wire_len),
                  MESH_CAPABILITY_PROTO_FIELD);
        ASSERT(make_view(&view, MESH_CAPABILITY_FRAME_ACK));
        view.body.ack.acknowledged_kind = MESH_CAPABILITY_FRAME_ACK;
        ASSERT_EQ(encode_view(&view, wire, sizeof(wire), &wire_len),
                  MESH_CAPABILITY_PROTO_STATUS);
        ASSERT(make_view(&view, MESH_CAPABILITY_FRAME_ACK));
        view.body.ack.status = (enum mesh_capability_ack_status)0;
        ASSERT_EQ(encode_view(&view, wire, sizeof(wire), &wire_len),
                  MESH_CAPABILITY_PROTO_STATUS);
        ASSERT_EQ(wire_len, 0u);
    } TEST_END
    return failures;
}

static int reserved_bytes_refusal(void)
{
    int failures = 0;
    TEST_CASE("capability reserved bytes cannot carry hidden extensions") {
        uint8_t wire[MESH_CAPABILITY_FRAME_V1_MAX];
        size_t wire_len = 0;
        struct mesh_capability_frame_view_v1 view, decoded;

        ASSERT(make_view(&view, MESH_CAPABILITY_FRAME_REFUSAL));
        ASSERT_EQ(encode_view(&view, wire, sizeof(wire), &wire_len),
                  MESH_CAPABILITY_PROTO_OK);
        wire[106] = 1;
        ASSERT_EQ(mesh_capability_frame_v1_decode(&decoded, wire, wire_len),
                  MESH_CAPABILITY_PROTO_FLAGS);
        ASSERT(zcl_bytes_all_zero((const uint8_t *)&decoded, sizeof(decoded)));

        ASSERT(make_view(&view, MESH_CAPABILITY_FRAME_ACK));
        ASSERT_EQ(encode_view(&view, wire, sizeof(wire), &wire_len),
                  MESH_CAPABILITY_PROTO_OK);
        wire[170] = 1;
        ASSERT_EQ(mesh_capability_frame_v1_decode(&decoded, wire, wire_len),
                  MESH_CAPABILITY_PROTO_FLAGS);
        ASSERT(zcl_bytes_all_zero((const uint8_t *)&decoded, sizeof(decoded)));
    } TEST_END
    return failures;
}

static int signature_and_root_refusal(void)
{
    int failures = 0;
    TEST_CASE("capability frames bind kind fields signer and signature") {
        uint8_t wire[MESH_CAPABILITY_FRAME_V1_MAX];
        uint8_t roots[MESH_CAPABILITY_FRAME_ACK][32];
        uint8_t wrong_seed[32];
        capability_fill(wrong_seed, 0xb1);
        for (int raw = MESH_CAPABILITY_FRAME_PROPOSAL;
             raw <= MESH_CAPABILITY_FRAME_ACK; raw++) {
            enum mesh_capability_frame_kind kind =
                (enum mesh_capability_frame_kind)raw;
            struct mesh_capability_frame_view_v1 view, trial, decoded;
            size_t wire_len = 0;
            ASSERT(make_view(&view, kind));
            ASSERT_EQ(mesh_capability_frame_v1_validate(&view),
                      MESH_CAPABILITY_PROTO_OK);
            ASSERT_EQ(mesh_capability_frame_v1_root(&view, roots[raw - 1]),
                      MESH_CAPABILITY_PROTO_OK);
            ASSERT(!zcl_bytes_all_zero((const uint8_t *)roots[raw - 1], 32));

            trial = view;
            test_view_signature(&trial)[0] ^= 1;
            ASSERT_EQ(mesh_capability_frame_v1_validate(&trial),
                      MESH_CAPABILITY_PROTO_SIGNATURE);
            ASSERT_EQ(encode_view(&trial, wire, sizeof(wire), &wire_len),
                      MESH_CAPABILITY_PROTO_SIGNATURE);
            ASSERT_EQ(wire_len, 0u);

            trial = view;
            test_view_public_key(&trial)[0] ^= 1;
            ASSERT_EQ(mesh_capability_frame_v1_validate(&trial),
                      MESH_CAPABILITY_PROTO_SIGNATURE);

            trial = view;
            memset(test_view_public_key(&trial), 0, 32);
            ASSERT_EQ(encode_view(&trial, wire, sizeof(wire), &wire_len),
                      MESH_CAPABILITY_PROTO_FIELD);
            ASSERT_EQ(wire_len, 0u);

            trial = view;
            ASSERT_EQ(mesh_capability_frame_v1_sign(&trial, wrong_seed),
                      MESH_CAPABILITY_PROTO_KEY_MISMATCH);
            ASSERT(zcl_bytes_all_zero((const uint8_t *)test_view_signature(&trial), 64));

            ASSERT_EQ(encode_view(&view, wire, sizeof(wire), &wire_len),
                      MESH_CAPABILITY_PROTO_OK);
            wire[wire_len - 1u] ^= 1;
            ASSERT_EQ(mesh_capability_frame_v1_decode(
                          &decoded, wire, wire_len),
                      MESH_CAPABILITY_PROTO_SIGNATURE);
            ASSERT(zcl_bytes_all_zero((const uint8_t *)&decoded, sizeof(decoded)));
        }
        for (size_t i = 0; i < MESH_CAPABILITY_FRAME_ACK; i++)
            for (size_t j = i + 1; j < MESH_CAPABILITY_FRAME_ACK; j++)
                ASSERT(memcmp(roots[i], roots[j], 32) != 0);
    } TEST_END
    return failures;
}

int test_mesh_capability_proto(void)
{
    int failures = 0;
    failures += lifecycle_roundtrip();
    failures += exact_length_refusal();
    failures += envelope_refusal();
    failures += proposal_bounds();
    failures += lifecycle_field_refusal();
    failures += reserved_bytes_refusal();
    failures += signature_and_root_refusal();
    return failures;
}

#ifdef MESH_CAPABILITY_PROTO_STANDALONE_TEST
int main(void)
{
    return test_mesh_capability_proto() == 0 ? 0 : 1;
}
#endif
