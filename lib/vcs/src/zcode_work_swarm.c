/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical codec and quorum verification for P2P ZCODE work. */

#include "vcs/zcode_work_swarm.h"

#include "base/bytes.h"
#include "codec/cursor.h"
#include "util/log_macros.h"
#include "vcs/signed_evidence.h"

#include <string.h>

#define ZCWS_CAPABILITY_BODY_BYTES 120u
#define ZCWS_CAPABILITY_BYTES 184u
#define ZCWS_REQUEST_BODY_BYTES 308u
#define ZCWS_REQUEST_BYTES 372u
#define ZCWS_RESULT_BYTES 592u
#define ZCWS_CANCEL_BODY_BYTES 80u
#define ZCWS_CANCEL_BYTES 144u
#define ZCWS_PROGRESS_BODY_BYTES 160u
#define ZCWS_PROGRESS_BYTES 224u
#define ZCWS_ADMISSION_BODY_BYTES 136u
#define ZCWS_ADMISSION_BYTES 200u

static const uint8_t zcws_magic[4] = { 'Z', 'C', 'W', 'S' };

static bool zcws_zero(const uint8_t *value, size_t len)
{
    return !zcl_bytes_any_set(value, len);
}

static bool zcws_work_kind(uint8_t kind)
{
    return kind >= VCS_ZCODE_WORK_PROPOSE &&
           kind <= VCS_ZCODE_WORK_DIAGNOSE;
}

static bool zcws_capability_valid(
    const struct vcs_zcode_work_capability_v1 *c)
{
    const uint32_t known = (UINT32_C(1) << VCS_ZCODE_WORK_PROPOSE) |
        (UINT32_C(1) << VCS_ZCODE_WORK_BUILD) |
        (UINT32_C(1) << VCS_ZCODE_WORK_TEST) |
        (UINT32_C(1) << VCS_ZCODE_WORK_FUZZ) |
        (UINT32_C(1) << VCS_ZCODE_WORK_REVIEW) |
        (UINT32_C(1) << VCS_ZCODE_WORK_REPRODUCE) |
        (UINT32_C(1) << VCS_ZCODE_WORK_DIAGNOSE);
    return c && zcl_bytes_any_set(c->signer_pubkey, 32) &&
           zcl_bytes_any_set(c->toolchain_capsule_root, 32) &&
           c->work_kinds != 0 && (c->work_kinds & ~known) == 0 &&
           c->target == VCS_ZCODE_WORK_TARGET_LINUX_X86_64_V3 &&
           (c->confinement & ~VCS_ZCODE_WORK_CONFINEMENT_V1_MASK) == 0 &&
           c->max_cpu_seconds > 0 &&
           c->max_memory_bytes > 0 &&
           c->max_memory_bytes <= VCS_ZCODE_TASK_MAX_MEMORY_BYTES &&
           c->max_output_bytes > 0 &&
           c->max_output_bytes <= VCS_ZCODE_TASK_MAX_OUTPUT_BYTES &&
           c->max_lease_seconds >= 5 && c->max_lease_seconds <= 600 &&
           c->slots > 0 && c->slots <= 64 &&
           c->queue_headroom <= c->slots && c->expires_unix > 0;
}

static bool zcws_request_valid(const struct vcs_zcode_work_request_v1 *r)
{
    if (!r || r->request_id == 0 ||
        !zcl_bytes_any_set(r->requester_pubkey, 32) ||
        !zcl_bytes_any_set(r->task_root, 32) || !zcws_work_kind(r->work_kind) ||
        !zcl_bytes_any_set(r->action_root, 32) ||
        !zcl_bytes_any_set(r->input_root, 32) ||
        !zcl_bytes_any_set(r->context_root, 32) ||
        !zcl_bytes_any_set(r->proof_policy_root, 32) ||
        !zcl_bytes_any_set(r->toolchain_capsule_root, 32) ||
        r->target != VCS_ZCODE_WORK_TARGET_LINUX_X86_64_V3 ||
        r->max_cpu_seconds == 0 || r->max_memory_bytes == 0 ||
        r->max_memory_bytes > VCS_ZCODE_TASK_MAX_MEMORY_BYTES ||
        r->max_output_bytes == 0 ||
        r->max_output_bytes > VCS_ZCODE_TASK_MAX_OUTPUT_BYTES ||
        r->deadline_unix <= 0)
        return false;
    return r->work_kind == VCS_ZCODE_WORK_PROPOSE
        ? zcws_zero(r->candidate_root, 32)
        : zcl_bytes_any_set(r->candidate_root, 32);
}

static bool zcws_result_shape(const struct vcs_zcode_work_result_v1 *r)
{
    return r && r->request_id != 0 && zcl_bytes_any_set(r->task_root, 32) &&
           zcl_bytes_any_set(r->candidate_root, 32) &&
           zcl_bytes_any_set(r->action_root, 32) &&
           zcl_bytes_any_set(r->output_root, 32) &&
           vcs_zcode_work_receipt_validate(&r->receipt) == VCS_ZCODE_DEV_OK;
}

static bool zcws_cancel_valid(const struct vcs_zcode_work_cancel_v1 *c)
{
    return c && c->request_id != 0 && zcl_bytes_any_set(c->task_root, 32) &&
           zcl_bytes_any_set(c->requester_pubkey, 32);
}

static bool zcws_progress_valid(
    const struct vcs_zcode_work_progress_v1 *p)
{
    return p && p->request_id != 0 &&
           zcl_bytes_any_set(p->task_root, 32) &&
           zcl_bytes_any_set(p->candidate_root, 32) &&
           zcl_bytes_any_set(p->action_root, 32) &&
           (p->stage == VCS_ZCODE_WORK_PROGRESS_CONTEXT_READY ||
            p->stage == VCS_ZCODE_WORK_PROGRESS_EXECUTION_STARTED) &&
           p->observed_unix > 0 && zcl_bytes_any_set(p->signer_pubkey, 32);
}

static bool zcws_admission_valid(
    const struct vcs_zcode_work_admission_v1 *a)
{
    if (!a || a->request_id == 0 ||
        !zcl_bytes_any_set(a->requester_pubkey, 32) ||
        !zcl_bytes_any_set(a->action_root, 32) ||
        !zcl_bytes_any_set(a->worker_signer, 32))
        return false;
    if (a->disposition == VCS_ZCODE_WORK_ADMISSION_GRANTED ||
        a->disposition == VCS_ZCODE_WORK_ADMISSION_ATTACHED)
        return a->reason == VCS_ZCODE_WORK_ADMISSION_REASON_NONE &&
               a->slot != UINT16_MAX && a->lease_generation > 0 &&
               a->deadline_unix > 0;
    if (a->disposition == VCS_ZCODE_WORK_ADMISSION_BUSY)
        return a->reason == VCS_ZCODE_WORK_ADMISSION_REASON_NO_SLOT &&
               a->slot == UINT16_MAX && a->lease_generation == 0 &&
               a->deadline_unix == 0;
    if (a->disposition == VCS_ZCODE_WORK_ADMISSION_REFUSED)
        return (a->reason == VCS_ZCODE_WORK_ADMISSION_REASON_POLICY ||
                a->reason == VCS_ZCODE_WORK_ADMISSION_REASON_BINDING ||
                a->reason == VCS_ZCODE_WORK_ADMISSION_REASON_CAPACITY) &&
               a->slot == UINT16_MAX && a->lease_generation == 0 &&
               a->deadline_unix == 0;
    return false;
}

size_t vcs_zcode_work_swarm_wire_size(
    const struct vcs_zcode_work_swarm_message *m)
{
    if (!m) return 0;
    if (m->type == VCS_ZCODE_WORK_SWARM_CAPABILITY)
        return zcws_capability_valid(&m->body.capability)
            ? ZCWS_CAPABILITY_BYTES : 0;
    if (m->type == VCS_ZCODE_WORK_SWARM_REQUEST)
        return zcws_request_valid(&m->body.request) ? ZCWS_REQUEST_BYTES : 0;
    if (m->type == VCS_ZCODE_WORK_SWARM_RESULT)
        return zcws_result_shape(&m->body.result) ? ZCWS_RESULT_BYTES : 0;
    if (m->type == VCS_ZCODE_WORK_SWARM_CANCEL)
        return zcws_cancel_valid(&m->body.cancel) ? ZCWS_CANCEL_BYTES : 0;
    if (m->type == VCS_ZCODE_WORK_SWARM_PROGRESS)
        return zcws_progress_valid(&m->body.progress)
            ? ZCWS_PROGRESS_BYTES : 0;
    if (m->type == VCS_ZCODE_WORK_SWARM_ADMISSION)
        return zcws_admission_valid(&m->body.admission)
            ? ZCWS_ADMISSION_BYTES : 0;
    return 0;
}

bool vcs_zcode_work_swarm_serialize(
    const struct vcs_zcode_work_swarm_message *m,
    uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!out_len)
        LOG_FAIL("vcs.work_swarm", "null serialization length");
    *out_len = 0;
    size_t need = vcs_zcode_work_swarm_wire_size(m);
    if (!need || !out || out_cap < need)
        LOG_FAIL("vcs.work_swarm", "invalid message or short output");
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, out, out_cap);
    bool ok = zcl_codec_write_bytes(&writer, zcws_magic,
                                    sizeof(zcws_magic)) &&
        zcl_codec_write_u16le(&writer, VCS_ZCODE_WORK_SWARM_VERSION) &&
        zcl_codec_write_u8(&writer, m->type) &&
        zcl_codec_write_u8(&writer, 0);
    if (m->type == VCS_ZCODE_WORK_SWARM_CAPABILITY) {
        const struct vcs_zcode_work_capability_v1 *c = &m->body.capability;
        ok = ok && zcl_codec_write_bytes(&writer, c->signer_pubkey, 32) &&
            zcl_codec_write_bytes(&writer, c->toolchain_capsule_root, 32) &&
            zcl_codec_write_u32le(&writer, c->work_kinds) &&
            zcl_codec_write_u32le(&writer, c->target) &&
            zcl_codec_write_u32le(&writer, c->confinement) &&
            zcl_codec_write_u32le(&writer, c->max_cpu_seconds) &&
            zcl_codec_write_u64le(&writer, c->max_memory_bytes) &&
            zcl_codec_write_u64le(&writer, c->max_output_bytes) &&
            zcl_codec_write_u32le(&writer, c->max_lease_seconds) &&
            zcl_codec_write_u16le(&writer, c->slots) &&
            zcl_codec_write_u16le(&writer, c->queue_headroom) &&
            zcl_codec_write_i64le(&writer, c->expires_unix) &&
            zcl_codec_write_bytes(&writer, c->signature, 64);
    } else if (m->type == VCS_ZCODE_WORK_SWARM_REQUEST) {
        const struct vcs_zcode_work_request_v1 *r = &m->body.request;
        static const uint8_t reserved[6] = {0};
        ok = ok && zcl_codec_write_u64le(&writer, r->request_id) &&
            zcl_codec_write_bytes(&writer, r->requester_pubkey, 32) &&
            zcl_codec_write_bytes(&writer, r->task_root, 32) &&
            zcl_codec_write_bytes(&writer, r->candidate_root, 32) &&
            zcl_codec_write_bytes(&writer, r->action_root, 32) &&
            zcl_codec_write_bytes(&writer, r->input_root, 32) &&
            zcl_codec_write_bytes(&writer, r->context_root, 32) &&
            zcl_codec_write_bytes(&writer, r->proof_policy_root, 32) &&
            zcl_codec_write_bytes(&writer, r->toolchain_capsule_root, 32) &&
            zcl_codec_write_u8(&writer, r->work_kind) &&
            zcl_codec_write_u8(&writer, r->target) &&
            zcl_codec_write_bytes(&writer, reserved, sizeof(reserved)) &&
            zcl_codec_write_u32le(&writer, r->max_cpu_seconds) &&
            zcl_codec_write_u64le(&writer, r->max_memory_bytes) &&
            zcl_codec_write_u64le(&writer, r->max_output_bytes) &&
            zcl_codec_write_i64le(&writer, r->deadline_unix) &&
            zcl_codec_write_bytes(&writer, r->signature, 64);
    } else if (m->type == VCS_ZCODE_WORK_SWARM_RESULT) {
        const struct vcs_zcode_work_result_v1 *r = &m->body.result;
        uint8_t receipt[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES];
        if (vcs_zcode_work_receipt_serialize(&r->receipt, receipt) !=
                VCS_ZCODE_DEV_OK)
            LOG_FAIL("vcs.work_swarm", "receipt serialization failed");
        ok = ok && zcl_codec_write_u64le(&writer, r->request_id) &&
            zcl_codec_write_bytes(&writer, r->task_root, 32) &&
            zcl_codec_write_bytes(&writer, r->candidate_root, 32) &&
            zcl_codec_write_bytes(&writer, r->action_root, 32) &&
            zcl_codec_write_bytes(&writer, r->output_root, 32) &&
            zcl_codec_write_bytes(&writer, receipt, sizeof(receipt));
    } else if (m->type == VCS_ZCODE_WORK_SWARM_CANCEL) {
        ok = ok && zcl_codec_write_u64le(
                &writer, m->body.cancel.request_id) &&
            zcl_codec_write_bytes(&writer, m->body.cancel.task_root, 32) &&
            zcl_codec_write_bytes(&writer, m->body.cancel.requester_pubkey,
                                  32) &&
            zcl_codec_write_bytes(&writer, m->body.cancel.signature, 64);
    } else if (m->type == VCS_ZCODE_WORK_SWARM_PROGRESS) {
        const struct vcs_zcode_work_progress_v1 *p = &m->body.progress;
        static const uint8_t reserved[7] = {0};
        ok = ok && zcl_codec_write_u64le(&writer, p->request_id) &&
            zcl_codec_write_bytes(&writer, p->task_root, 32) &&
            zcl_codec_write_bytes(&writer, p->candidate_root, 32) &&
            zcl_codec_write_bytes(&writer, p->action_root, 32) &&
            zcl_codec_write_u8(&writer, p->stage) &&
            zcl_codec_write_bytes(&writer, reserved, sizeof(reserved)) &&
            zcl_codec_write_i64le(&writer, p->observed_unix) &&
            zcl_codec_write_bytes(&writer, p->signer_pubkey, 32) &&
            zcl_codec_write_bytes(&writer, p->signature, 64);
    } else {
        const struct vcs_zcode_work_admission_v1 *a = &m->body.admission;
        static const uint8_t reserved[4] = {0};
        ok = ok && zcl_codec_write_u64le(&writer, a->request_id) &&
            zcl_codec_write_bytes(&writer, a->requester_pubkey, 32) &&
            zcl_codec_write_bytes(&writer, a->action_root, 32) &&
            zcl_codec_write_bytes(&writer, a->worker_signer, 32) &&
            zcl_codec_write_u64le(&writer, a->lease_generation) &&
            zcl_codec_write_i64le(&writer, a->deadline_unix) &&
            zcl_codec_write_u16le(&writer, a->slot) &&
            zcl_codec_write_u8(&writer, a->disposition) &&
            zcl_codec_write_u8(&writer, a->reason) &&
            zcl_codec_write_bytes(&writer, reserved, sizeof(reserved)) &&
            zcl_codec_write_bytes(&writer, a->signature, 64);
    }
    size_t written = 0;
    if (!ok || !zcl_codec_writer_finish(&writer, &written) || written != need)
        LOG_FAIL("vcs.work_swarm", "wire size invariant failed");
    *out_len = written;
    return true;
}

static bool zcws_signed_id(uint8_t type, const void *object, uint8_t out[32])
{
    if (!object || !out) return false;
    struct vcs_zcode_work_swarm_message message = { .type = type };
    const char *domain = NULL;
    size_t domain_len = 0, body_len = 0;
    if (type == VCS_ZCODE_WORK_SWARM_CAPABILITY) {
        message.body.capability =
            *(const struct vcs_zcode_work_capability_v1 *)object;
        static const char d[] = "zcl.zcode.work_capability.v1";
        domain = d; domain_len = sizeof(d); body_len = ZCWS_CAPABILITY_BODY_BYTES;
    } else if (type == VCS_ZCODE_WORK_SWARM_REQUEST) {
        message.body.request =
            *(const struct vcs_zcode_work_request_v1 *)object;
        static const char d[] = "zcl.zcode.work_request.v1";
        domain = d; domain_len = sizeof(d); body_len = ZCWS_REQUEST_BODY_BYTES;
    } else if (type == VCS_ZCODE_WORK_SWARM_CANCEL) {
        message.body.cancel =
            *(const struct vcs_zcode_work_cancel_v1 *)object;
        static const char d[] = "zcl.zcode.work_cancel.v1";
        domain = d; domain_len = sizeof(d); body_len = ZCWS_CANCEL_BODY_BYTES;
    } else if (type == VCS_ZCODE_WORK_SWARM_PROGRESS) {
        message.body.progress =
            *(const struct vcs_zcode_work_progress_v1 *)object;
        static const char d[] = "zcl.zcode.work_progress.v1";
        domain = d; domain_len = sizeof(d); body_len = ZCWS_PROGRESS_BODY_BYTES;
    } else if (type == VCS_ZCODE_WORK_SWARM_ADMISSION) {
        message.body.admission =
            *(const struct vcs_zcode_work_admission_v1 *)object;
        static const char d[] = "zcl.zcode.work_admission.v1";
        domain = d; domain_len = sizeof(d); body_len = ZCWS_ADMISSION_BODY_BYTES;
    } else {
        return false;
    }
    uint8_t wire[VCS_ZCODE_WORK_SWARM_MAX_WIRE_BYTES];
    size_t wire_len = 0;
    if (!vcs_zcode_work_swarm_serialize(&message, wire, sizeof(wire),
                                        &wire_len) || wire_len < body_len)
        return false;
    return vcs_signed_evidence_root(domain, domain_len, wire, body_len, out);
}

bool vcs_zcode_work_capability_seal(
    struct vcs_zcode_work_capability_v1 *c,
    const uint8_t secret[32], const uint8_t pubkey[32])
{
    if (!c || !secret || !pubkey || !zcl_bytes_any_set(pubkey, 32)) return false;
    memcpy(c->signer_pubkey, pubkey, 32);
    uint8_t id[32];
    if (!zcws_signed_id(VCS_ZCODE_WORK_SWARM_CAPABILITY, c, id)) return false;
    return vcs_signed_evidence_seal_root(id, secret, pubkey, c->signature);
}

bool vcs_zcode_work_capability_verify(
    const struct vcs_zcode_work_capability_v1 *c)
{
    uint8_t id[32];
    return zcws_capability_valid(c) &&
           zcws_signed_id(VCS_ZCODE_WORK_SWARM_CAPABILITY, c, id) &&
           vcs_signed_evidence_verify_root(
               id, c->signature, c->signer_pubkey, c->signer_pubkey);
}

bool vcs_zcode_work_request_seal(
    struct vcs_zcode_work_request_v1 *r,
    const uint8_t secret[32], const uint8_t pubkey[32])
{
    if (!r || !secret || !pubkey || !zcl_bytes_any_set(pubkey, 32)) return false;
    memcpy(r->requester_pubkey, pubkey, 32);
    uint8_t id[32];
    if (!zcws_signed_id(VCS_ZCODE_WORK_SWARM_REQUEST, r, id)) return false;
    return vcs_signed_evidence_seal_root(id, secret, pubkey, r->signature);
}

bool vcs_zcode_work_request_verify(const struct vcs_zcode_work_request_v1 *r)
{
    uint8_t id[32];
    return zcws_request_valid(r) &&
           zcws_signed_id(VCS_ZCODE_WORK_SWARM_REQUEST, r, id) &&
           vcs_signed_evidence_verify_root(
               id, r->signature, r->requester_pubkey, r->requester_pubkey);
}

bool vcs_zcode_work_request_id(
    const struct vcs_zcode_work_request_v1 *request, uint8_t out[32])
{
    return request && out && vcs_zcode_work_request_verify(request) &&
           zcws_signed_id(VCS_ZCODE_WORK_SWARM_REQUEST, request, out);
}

bool vcs_zcode_work_cancel_seal(
    struct vcs_zcode_work_cancel_v1 *c,
    const uint8_t secret[32], const uint8_t pubkey[32])
{
    if (!c || !secret || !pubkey || !zcl_bytes_any_set(pubkey, 32)) return false;
    memcpy(c->requester_pubkey, pubkey, 32);
    uint8_t id[32];
    if (!zcws_signed_id(VCS_ZCODE_WORK_SWARM_CANCEL, c, id)) return false;
    return vcs_signed_evidence_seal_root(id, secret, pubkey, c->signature);
}

bool vcs_zcode_work_cancel_verify(const struct vcs_zcode_work_cancel_v1 *c)
{
    uint8_t id[32];
    return zcws_cancel_valid(c) &&
           zcws_signed_id(VCS_ZCODE_WORK_SWARM_CANCEL, c, id) &&
           vcs_signed_evidence_verify_root(
               id, c->signature, c->requester_pubkey,
               c->requester_pubkey);
}

bool vcs_zcode_work_progress_seal(
    struct vcs_zcode_work_progress_v1 *p,
    const uint8_t secret[32], const uint8_t pubkey[32])
{
    if (!p || !secret || !pubkey || !zcl_bytes_any_set(pubkey, 32)) return false;
    memcpy(p->signer_pubkey, pubkey, 32);
    uint8_t id[32];
    if (!zcws_signed_id(VCS_ZCODE_WORK_SWARM_PROGRESS, p, id)) return false;
    return vcs_signed_evidence_seal_root(id, secret, pubkey, p->signature);
}

bool vcs_zcode_work_progress_verify(
    const struct vcs_zcode_work_progress_v1 *p)
{
    uint8_t id[32];
    return zcws_progress_valid(p) &&
           zcws_signed_id(VCS_ZCODE_WORK_SWARM_PROGRESS, p, id) &&
           vcs_signed_evidence_verify_root(
               id, p->signature, p->signer_pubkey, p->signer_pubkey);
}

bool vcs_zcode_work_progress_verify_for_request(
    const struct vcs_zcode_work_request_v1 *q,
    const struct vcs_zcode_work_progress_v1 *p,
    const uint8_t expected_signer[32])
{
    return zcws_request_valid(q) && vcs_zcode_work_progress_verify(p) &&
        expected_signer && q->request_id == p->request_id &&
        memcmp(q->task_root, p->task_root, 32) == 0 &&
        memcmp(q->candidate_root, p->candidate_root, 32) == 0 &&
        memcmp(q->action_root, p->action_root, 32) == 0 &&
        memcmp(expected_signer, p->signer_pubkey, 32) == 0;
}

bool vcs_zcode_work_admission_seal(
    struct vcs_zcode_work_admission_v1 *a,
    const uint8_t secret[32], const uint8_t pubkey[32])
{
    if (!a || !secret || !pubkey || !zcl_bytes_any_set(pubkey, 32)) return false;
    memcpy(a->worker_signer, pubkey, 32);
    uint8_t id[32];
    if (!zcws_signed_id(VCS_ZCODE_WORK_SWARM_ADMISSION, a, id)) return false;
    return vcs_signed_evidence_seal_root(id, secret, pubkey, a->signature);
}

bool vcs_zcode_work_admission_verify(
    const struct vcs_zcode_work_admission_v1 *a)
{
    uint8_t id[32];
    return zcws_admission_valid(a) &&
           zcws_signed_id(VCS_ZCODE_WORK_SWARM_ADMISSION, a, id) &&
           vcs_signed_evidence_verify_root(
               id, a->signature, a->worker_signer, a->worker_signer);
}

bool vcs_zcode_work_admission_verify_for_request(
    const struct vcs_zcode_work_request_v1 *q,
    const struct vcs_zcode_work_admission_v1 *a,
    const uint8_t expected_signer[32])
{
    return zcws_request_valid(q) && vcs_zcode_work_admission_verify(a) &&
        expected_signer && q->request_id == a->request_id &&
        memcmp(q->requester_pubkey, a->requester_pubkey, 32) == 0 &&
        memcmp(q->action_root, a->action_root, 32) == 0 &&
        memcmp(expected_signer, a->worker_signer, 32) == 0;
}

static bool zcws_header_valid(const uint8_t *wire, size_t len, uint8_t *type)
{
    if (!wire || !type || len < VCS_ZCODE_WORK_SWARM_HEADER_BYTES ||
        len > VCS_ZCODE_WORK_SWARM_MAX_WIRE_BYTES)
        return false;
    struct zcl_codec_reader reader;
    uint8_t magic[sizeof(zcws_magic)], reserved;
    uint16_t version;
    zcl_codec_reader_init(&reader, wire, VCS_ZCODE_WORK_SWARM_HEADER_BYTES);
    return zcl_codec_read_bytes(&reader, magic, sizeof(magic)) &&
        zcl_codec_read_u16le(&reader, &version) &&
        zcl_codec_read_u8(&reader, type) &&
        zcl_codec_read_u8(&reader, &reserved) &&
        zcl_codec_reader_finish(&reader) &&
        memcmp(magic, zcws_magic, sizeof(magic)) == 0 &&
        version == VCS_ZCODE_WORK_SWARM_VERSION && reserved == 0;
}

bool vcs_zcode_work_swarm_parse(
    const uint8_t *wire, size_t len, struct vcs_zcode_work_swarm_message *out)
{
    if (!out) LOG_FAIL("vcs.work_swarm", "null parse output");
    memset(out, 0, sizeof(*out));
    uint8_t type = 0;
    if (!zcws_header_valid(wire, len, &type))
        LOG_FAIL("vcs.work_swarm", "invalid work swarm header");
    out->type = type;
    struct zcl_codec_reader reader;
    zcl_codec_reader_init(&reader, wire + VCS_ZCODE_WORK_SWARM_HEADER_BYTES,
                          len - VCS_ZCODE_WORK_SWARM_HEADER_BYTES);
    bool ok = true;
    if (type == VCS_ZCODE_WORK_SWARM_CAPABILITY &&
        len == ZCWS_CAPABILITY_BYTES) {
        struct vcs_zcode_work_capability_v1 *c = &out->body.capability;
        ok = zcl_codec_read_bytes(&reader, c->signer_pubkey, 32) &&
            zcl_codec_read_bytes(&reader, c->toolchain_capsule_root, 32) &&
            zcl_codec_read_u32le(&reader, &c->work_kinds) &&
            zcl_codec_read_u32le(&reader, &c->target) &&
            zcl_codec_read_u32le(&reader, &c->confinement) &&
            zcl_codec_read_u32le(&reader, &c->max_cpu_seconds) &&
            zcl_codec_read_u64le(&reader, &c->max_memory_bytes) &&
            zcl_codec_read_u64le(&reader, &c->max_output_bytes) &&
            zcl_codec_read_u32le(&reader, &c->max_lease_seconds) &&
            zcl_codec_read_u16le(&reader, &c->slots) &&
            zcl_codec_read_u16le(&reader, &c->queue_headroom) &&
            zcl_codec_read_i64le(&reader, &c->expires_unix) &&
            zcl_codec_read_bytes(&reader, c->signature, 64);
        if (!ok || !zcws_capability_valid(c) ||
            !vcs_zcode_work_capability_verify(c)) goto reject;
    } else if (type == VCS_ZCODE_WORK_SWARM_REQUEST &&
               len == ZCWS_REQUEST_BYTES) {
        struct vcs_zcode_work_request_v1 *r = &out->body.request;
        uint8_t reserved[6];
        ok = zcl_codec_read_u64le(&reader, &r->request_id) &&
            zcl_codec_read_bytes(&reader, r->requester_pubkey, 32) &&
            zcl_codec_read_bytes(&reader, r->task_root, 32) &&
            zcl_codec_read_bytes(&reader, r->candidate_root, 32) &&
            zcl_codec_read_bytes(&reader, r->action_root, 32) &&
            zcl_codec_read_bytes(&reader, r->input_root, 32) &&
            zcl_codec_read_bytes(&reader, r->context_root, 32) &&
            zcl_codec_read_bytes(&reader, r->proof_policy_root, 32) &&
            zcl_codec_read_bytes(&reader, r->toolchain_capsule_root, 32) &&
            zcl_codec_read_u8(&reader, &r->work_kind) &&
            zcl_codec_read_u8(&reader, &r->target) &&
            zcl_codec_read_bytes(&reader, reserved, sizeof(reserved)) &&
            zcl_codec_read_u32le(&reader, &r->max_cpu_seconds) &&
            zcl_codec_read_u64le(&reader, &r->max_memory_bytes) &&
            zcl_codec_read_u64le(&reader, &r->max_output_bytes) &&
            zcl_codec_read_i64le(&reader, &r->deadline_unix) &&
            zcl_codec_read_bytes(&reader, r->signature, 64);
        if (!ok || !zcws_zero(reserved, sizeof(reserved)) ||
            !zcws_request_valid(r) || !vcs_zcode_work_request_verify(r))
            goto reject;
    } else if (type == VCS_ZCODE_WORK_SWARM_RESULT &&
               len == ZCWS_RESULT_BYTES) {
        struct vcs_zcode_work_result_v1 *r = &out->body.result;
        uint8_t receipt[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES];
        ok = zcl_codec_read_u64le(&reader, &r->request_id) &&
            zcl_codec_read_bytes(&reader, r->task_root, 32) &&
            zcl_codec_read_bytes(&reader, r->candidate_root, 32) &&
            zcl_codec_read_bytes(&reader, r->action_root, 32) &&
            zcl_codec_read_bytes(&reader, r->output_root, 32) &&
            zcl_codec_read_bytes(&reader, receipt, sizeof(receipt));
        if (!ok || vcs_zcode_work_receipt_parse(
                receipt, sizeof(receipt), &r->receipt) != VCS_ZCODE_DEV_OK)
            goto reject;
        if (!zcws_result_shape(r)) goto reject;
    } else if (type == VCS_ZCODE_WORK_SWARM_CANCEL &&
               len == ZCWS_CANCEL_BYTES) {
        ok = zcl_codec_read_u64le(
                &reader, &out->body.cancel.request_id) &&
            zcl_codec_read_bytes(&reader, out->body.cancel.task_root, 32) &&
            zcl_codec_read_bytes(&reader,
                                 out->body.cancel.requester_pubkey, 32) &&
            zcl_codec_read_bytes(&reader, out->body.cancel.signature, 64);
        if (!ok || !zcws_cancel_valid(&out->body.cancel) ||
            !vcs_zcode_work_cancel_verify(&out->body.cancel)) goto reject;
    } else if (type == VCS_ZCODE_WORK_SWARM_PROGRESS &&
               len == ZCWS_PROGRESS_BYTES) {
        struct vcs_zcode_work_progress_v1 *p = &out->body.progress;
        uint8_t reserved[7];
        ok = zcl_codec_read_u64le(&reader, &p->request_id) &&
            zcl_codec_read_bytes(&reader, p->task_root, 32) &&
            zcl_codec_read_bytes(&reader, p->candidate_root, 32) &&
            zcl_codec_read_bytes(&reader, p->action_root, 32) &&
            zcl_codec_read_u8(&reader, &p->stage) &&
            zcl_codec_read_bytes(&reader, reserved, sizeof(reserved)) &&
            zcl_codec_read_i64le(&reader, &p->observed_unix) &&
            zcl_codec_read_bytes(&reader, p->signer_pubkey, 32) &&
            zcl_codec_read_bytes(&reader, p->signature, 64);
        if (!ok || !zcws_zero(reserved, sizeof(reserved)) ||
            !vcs_zcode_work_progress_verify(p)) goto reject;
    } else if (type == VCS_ZCODE_WORK_SWARM_ADMISSION &&
               len == ZCWS_ADMISSION_BYTES) {
        struct vcs_zcode_work_admission_v1 *a = &out->body.admission;
        uint8_t reserved[4];
        ok = zcl_codec_read_u64le(&reader, &a->request_id) &&
            zcl_codec_read_bytes(&reader, a->requester_pubkey, 32) &&
            zcl_codec_read_bytes(&reader, a->action_root, 32) &&
            zcl_codec_read_bytes(&reader, a->worker_signer, 32) &&
            zcl_codec_read_u64le(&reader, &a->lease_generation) &&
            zcl_codec_read_i64le(&reader, &a->deadline_unix) &&
            zcl_codec_read_u16le(&reader, &a->slot) &&
            zcl_codec_read_u8(&reader, &a->disposition) &&
            zcl_codec_read_u8(&reader, &a->reason) &&
            zcl_codec_read_bytes(&reader, reserved, sizeof(reserved)) &&
            zcl_codec_read_bytes(&reader, a->signature, 64);
        if (!ok || !zcws_zero(reserved, sizeof(reserved)) ||
            !vcs_zcode_work_admission_verify(a)) goto reject;
    } else {
        goto reject;
    }
    if (!zcl_codec_reader_finish(&reader)) goto reject;
    return true;
reject:
    memset(out, 0, sizeof(*out));
    LOG_FAIL("vcs.work_swarm", "noncanonical work swarm payload");
}

bool vcs_zcode_work_result_verify(
    const struct vcs_zcode_work_request_v1 *q,
    const struct vcs_zcode_work_result_v1 *r,
    const uint8_t expected_signer[32])
{
    if (!zcws_request_valid(q) || !zcws_result_shape(r) ||
        !expected_signer || q->request_id != r->request_id ||
        memcmp(q->task_root, r->task_root, 32) != 0 ||
        memcmp(q->action_root, r->action_root, 32) != 0 ||
        memcmp(r->task_root, r->receipt.task_root, 32) != 0 ||
        memcmp(r->candidate_root, r->receipt.candidate_root, 32) != 0 ||
        memcmp(r->action_root, r->receipt.action_root, 32) != 0 ||
        memcmp(q->input_root, r->receipt.input_root, 32) != 0 ||
        memcmp(r->output_root, r->receipt.output_root, 32) != 0 ||
        memcmp(q->proof_policy_root, r->receipt.proof_policy_root, 32) != 0 ||
        memcmp(q->toolchain_capsule_root,
               r->receipt.toolchain_capsule_root, 32) != 0 ||
        r->receipt.work_kind != q->work_kind ||
        (r->receipt.status != VCS_ZCODE_WORK_PASS &&
         r->receipt.status != VCS_ZCODE_WORK_FAIL))
        return false;
    if (q->work_kind != VCS_ZCODE_WORK_PROPOSE &&
        memcmp(q->candidate_root, r->candidate_root, 32) != 0)
        return false;
    return vcs_zcode_work_receipt_verify(&r->receipt, expected_signer) ==
           VCS_ZCODE_DEV_OK;
}

size_t vcs_zcode_work_result_quorum(
    const struct vcs_zcode_work_request_v1 *request,
    const struct vcs_zcode_work_result_v1 *results, size_t result_count,
    const uint8_t (*approved)[32], size_t approved_count,
    size_t required, uint8_t output_root[32])
{
    if (output_root) memset(output_root, 0, 32);
    if (!request || !results || !approved || !output_root || required == 0 ||
        result_count > VCS_ZCODE_WORK_SWARM_MAX_RESULTS ||
        approved_count > VCS_ZCODE_WORK_SWARM_MAX_APPROVED)
        return 0;
    uint8_t counted[VCS_ZCODE_WORK_SWARM_MAX_APPROVED][32];
    size_t count = 0;
    for (size_t i = 0; i < result_count; i++) {
        const uint8_t *signer = results[i].receipt.signer_pubkey;
        bool allowed = false, duplicate = false;
        for (size_t j = 0; j < approved_count; j++)
            if (memcmp(signer, approved[j], 32) == 0) allowed = true;
        for (size_t j = 0; j < count; j++)
            if (memcmp(signer, counted[j], 32) == 0) duplicate = true;
        if (!allowed || duplicate ||
            results[i].receipt.status != VCS_ZCODE_WORK_PASS ||
            !vcs_zcode_work_result_verify(request, &results[i], signer))
            continue;
        if (count == 0)
            memcpy(output_root, results[i].output_root, 32);
        else if (memcmp(output_root, results[i].output_root, 32) != 0)
            continue;
        memcpy(counted[count++], signer, 32);
    }
    if (count < required) memset(output_root, 0, 32);
    return count;
}
