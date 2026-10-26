/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical codec and quorum verification for P2P ZCODE work. */

#include "vcs/zcode_work_swarm.h"
#include "vcs/zcode_work_node.h"

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

const char *vcs_zcode_work_node_result_string(
    enum vcs_zcode_work_node_result r)
{
    static const char *const names[] = {
        "ok", "malformed-frame", "unknown-peer", "capability-stale",
        "work-lease-expired", "capability-mismatch", "replayed-work-frame",
        "unrequested-result", "request-result-binding", "bounded-queue-full",
        "local-worker-disabled",
    };
    return r >= 0 && (size_t)r < sizeof(names) / sizeof(names[0])
        ? names[r] : "unknown";
}

static bool zcws_zero(const uint8_t *value, size_t len)
{
    return !zcl_bytes_any_set(value, len);
}

static bool zcws_work_kind(uint8_t kind)
{
    return kind >= VCS_ZCODE_WORK_PROPOSE &&
           kind <= VCS_ZCODE_WORK_DIAGNOSE;
}

static bool zcws_capability_keys_valid(
    const struct vcs_zcode_work_capability_v1 *c)
{
    const uint32_t known = (UINT32_C(1) << VCS_ZCODE_WORK_PROPOSE) |
        (UINT32_C(1) << VCS_ZCODE_WORK_BUILD) |
        (UINT32_C(1) << VCS_ZCODE_WORK_TEST) |
        (UINT32_C(1) << VCS_ZCODE_WORK_FUZZ) |
        (UINT32_C(1) << VCS_ZCODE_WORK_REVIEW) |
        (UINT32_C(1) << VCS_ZCODE_WORK_REPRODUCE) |
        (UINT32_C(1) << VCS_ZCODE_WORK_DIAGNOSE);
    return zcl_bytes_any_set(c->signer_pubkey, 32) &&
           zcl_bytes_any_set(c->toolchain_capsule_root, 32) &&
           c->work_kinds != 0 && (c->work_kinds & ~known) == 0 &&
           c->target == VCS_ZCODE_WORK_TARGET_LINUX_X86_64_V3 &&
           (c->confinement & ~VCS_ZCODE_WORK_CONFINEMENT_V1_MASK) == 0;
}

static bool zcws_capability_limits_valid(
    const struct vcs_zcode_work_capability_v1 *c)
{
    return c->max_cpu_seconds > 0 &&
           c->max_memory_bytes > 0 &&
           c->max_memory_bytes <= VCS_ZCODE_TASK_MAX_MEMORY_BYTES &&
           c->max_output_bytes > 0 &&
           c->max_output_bytes <= VCS_ZCODE_TASK_MAX_OUTPUT_BYTES &&
           c->max_lease_seconds >= 5 && c->max_lease_seconds <= 600 &&
           c->slots > 0 && c->slots <= 64 &&
           c->queue_headroom <= c->slots && c->expires_unix > 0;
}

static bool zcws_capability_valid(
    const struct vcs_zcode_work_capability_v1 *c)
{
    return c && zcws_capability_keys_valid(c) &&
           zcws_capability_limits_valid(c);
}

static bool zcws_request_roots_set(const struct vcs_zcode_work_request_v1 *r)
{
    return zcl_bytes_any_set(r->requester_pubkey, 32) &&
        zcl_bytes_any_set(r->task_root, 32) &&
        zcl_bytes_any_set(r->action_root, 32) &&
        zcl_bytes_any_set(r->input_root, 32) &&
        zcl_bytes_any_set(r->context_root, 32) &&
        zcl_bytes_any_set(r->proof_policy_root, 32) &&
        zcl_bytes_any_set(r->toolchain_capsule_root, 32);
}

static bool zcws_request_limits_valid(const struct vcs_zcode_work_request_v1 *r)
{
    return r->target == VCS_ZCODE_WORK_TARGET_LINUX_X86_64_V3 &&
        r->max_cpu_seconds != 0 && r->max_memory_bytes != 0 &&
        r->max_memory_bytes <= VCS_ZCODE_TASK_MAX_MEMORY_BYTES &&
        r->max_output_bytes != 0 &&
        r->max_output_bytes <= VCS_ZCODE_TASK_MAX_OUTPUT_BYTES &&
        r->deadline_unix > 0;
}

static bool zcws_request_candidate_valid(
    const struct vcs_zcode_work_request_v1 *r)
{
    return r->work_kind == VCS_ZCODE_WORK_PROPOSE
        ? zcws_zero(r->candidate_root, 32)
        : zcl_bytes_any_set(r->candidate_root, 32);
}

static bool zcws_request_valid(const struct vcs_zcode_work_request_v1 *r)
{
    return r && r->request_id != 0 && zcws_request_roots_set(r) &&
        zcws_work_kind(r->work_kind) && zcws_request_limits_valid(r) &&
        zcws_request_candidate_valid(r);
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

static bool zcws_admission_ids_set(
    const struct vcs_zcode_work_admission_v1 *a)
{
    return a->request_id != 0 &&
        zcl_bytes_any_set(a->requester_pubkey, 32) &&
        zcl_bytes_any_set(a->action_root, 32) &&
        zcl_bytes_any_set(a->worker_signer, 32);
}

static bool zcws_admission_grant_valid(
    const struct vcs_zcode_work_admission_v1 *a)
{
    return a->reason == VCS_ZCODE_WORK_ADMISSION_REASON_NONE &&
        a->slot != UINT16_MAX && a->lease_generation > 0 &&
        a->deadline_unix > 0;
}

static bool zcws_admission_busy_valid(
    const struct vcs_zcode_work_admission_v1 *a)
{
    return a->reason == VCS_ZCODE_WORK_ADMISSION_REASON_NO_SLOT &&
        a->slot == UINT16_MAX && a->lease_generation == 0 &&
        a->deadline_unix == 0;
}

static bool zcws_admission_refused_valid(
    const struct vcs_zcode_work_admission_v1 *a)
{
    return (a->reason == VCS_ZCODE_WORK_ADMISSION_REASON_POLICY ||
            a->reason == VCS_ZCODE_WORK_ADMISSION_REASON_BINDING ||
            a->reason == VCS_ZCODE_WORK_ADMISSION_REASON_CAPACITY) &&
        a->slot == UINT16_MAX && a->lease_generation == 0 &&
        a->deadline_unix == 0;
}

static bool zcws_admission_disposition_valid(
    const struct vcs_zcode_work_admission_v1 *a)
{
    if (a->disposition == VCS_ZCODE_WORK_ADMISSION_GRANTED ||
        a->disposition == VCS_ZCODE_WORK_ADMISSION_ATTACHED)
        return zcws_admission_grant_valid(a);
    if (a->disposition == VCS_ZCODE_WORK_ADMISSION_BUSY)
        return zcws_admission_busy_valid(a);
    if (a->disposition == VCS_ZCODE_WORK_ADMISSION_REFUSED)
        return zcws_admission_refused_valid(a);
    return false;
}

static bool zcws_admission_valid(
    const struct vcs_zcode_work_admission_v1 *a)
{
    return a && zcws_admission_ids_set(a) &&
        zcws_admission_disposition_valid(a);
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

static bool zcws_write_capability(struct zcl_codec_writer *writer,
    const struct vcs_zcode_work_capability_v1 *c)
{
    return zcl_codec_write_bytes(writer, c->signer_pubkey, 32) &&
        zcl_codec_write_bytes(writer, c->toolchain_capsule_root, 32) &&
        zcl_codec_write_u32le(writer, c->work_kinds) &&
        zcl_codec_write_u32le(writer, c->target) &&
        zcl_codec_write_u32le(writer, c->confinement) &&
        zcl_codec_write_u32le(writer, c->max_cpu_seconds) &&
        zcl_codec_write_u64le(writer, c->max_memory_bytes) &&
        zcl_codec_write_u64le(writer, c->max_output_bytes) &&
        zcl_codec_write_u32le(writer, c->max_lease_seconds) &&
        zcl_codec_write_u16le(writer, c->slots) &&
        zcl_codec_write_u16le(writer, c->queue_headroom) &&
        zcl_codec_write_i64le(writer, c->expires_unix) &&
        zcl_codec_write_bytes(writer, c->signature, 64);
}

static bool zcws_write_request_head(struct zcl_codec_writer *writer,
    const struct vcs_zcode_work_request_v1 *r)
{
    static const uint8_t reserved[6] = {0};
    return zcl_codec_write_u64le(writer, r->request_id) &&
        zcl_codec_write_bytes(writer, r->requester_pubkey, 32) &&
        zcl_codec_write_bytes(writer, r->task_root, 32) &&
        zcl_codec_write_bytes(writer, r->candidate_root, 32) &&
        zcl_codec_write_bytes(writer, r->action_root, 32) &&
        zcl_codec_write_bytes(writer, r->input_root, 32) &&
        zcl_codec_write_bytes(writer, r->context_root, 32) &&
        zcl_codec_write_bytes(writer, r->proof_policy_root, 32) &&
        zcl_codec_write_bytes(writer, r->toolchain_capsule_root, 32) &&
        zcl_codec_write_u8(writer, r->work_kind) &&
        zcl_codec_write_u8(writer, r->target) &&
        zcl_codec_write_bytes(writer, reserved, sizeof(reserved));
}

static bool zcws_write_request(struct zcl_codec_writer *writer,
    const struct vcs_zcode_work_request_v1 *r)
{
    return zcws_write_request_head(writer, r) &&
        zcl_codec_write_u32le(writer, r->max_cpu_seconds) &&
        zcl_codec_write_u64le(writer, r->max_memory_bytes) &&
        zcl_codec_write_u64le(writer, r->max_output_bytes) &&
        zcl_codec_write_i64le(writer, r->deadline_unix) &&
        zcl_codec_write_bytes(writer, r->signature, 64);
}

static bool zcws_write_result(struct zcl_codec_writer *writer,
    const struct vcs_zcode_work_result_v1 *r,
    const uint8_t receipt[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES])
{
    return zcl_codec_write_u64le(writer, r->request_id) &&
        zcl_codec_write_bytes(writer, r->task_root, 32) &&
        zcl_codec_write_bytes(writer, r->candidate_root, 32) &&
        zcl_codec_write_bytes(writer, r->action_root, 32) &&
        zcl_codec_write_bytes(writer, r->output_root, 32) &&
        zcl_codec_write_bytes(writer, receipt,
                              VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES);
}

static bool zcws_write_cancel(struct zcl_codec_writer *writer,
    const struct vcs_zcode_work_cancel_v1 *c)
{
    return zcl_codec_write_u64le(writer, c->request_id) &&
        zcl_codec_write_bytes(writer, c->task_root, 32) &&
        zcl_codec_write_bytes(writer, c->requester_pubkey, 32) &&
        zcl_codec_write_bytes(writer, c->signature, 64);
}

static bool zcws_write_progress(struct zcl_codec_writer *writer,
    const struct vcs_zcode_work_progress_v1 *p)
{
    static const uint8_t reserved[7] = {0};
    return zcl_codec_write_u64le(writer, p->request_id) &&
        zcl_codec_write_bytes(writer, p->task_root, 32) &&
        zcl_codec_write_bytes(writer, p->candidate_root, 32) &&
        zcl_codec_write_bytes(writer, p->action_root, 32) &&
        zcl_codec_write_u8(writer, p->stage) &&
        zcl_codec_write_bytes(writer, reserved, sizeof(reserved)) &&
        zcl_codec_write_i64le(writer, p->observed_unix) &&
        zcl_codec_write_bytes(writer, p->signer_pubkey, 32) &&
        zcl_codec_write_bytes(writer, p->signature, 64);
}

static bool zcws_write_admission(struct zcl_codec_writer *writer,
    const struct vcs_zcode_work_admission_v1 *a)
{
    static const uint8_t reserved[4] = {0};
    return zcl_codec_write_u64le(writer, a->request_id) &&
        zcl_codec_write_bytes(writer, a->requester_pubkey, 32) &&
        zcl_codec_write_bytes(writer, a->action_root, 32) &&
        zcl_codec_write_bytes(writer, a->worker_signer, 32) &&
        zcl_codec_write_u64le(writer, a->lease_generation) &&
        zcl_codec_write_i64le(writer, a->deadline_unix) &&
        zcl_codec_write_u16le(writer, a->slot) &&
        zcl_codec_write_u8(writer, a->disposition) &&
        zcl_codec_write_u8(writer, a->reason) &&
        zcl_codec_write_bytes(writer, reserved, sizeof(reserved)) &&
        zcl_codec_write_bytes(writer, a->signature, 64);
}

static bool zcws_write_body(struct zcl_codec_writer *writer,
    const struct vcs_zcode_work_swarm_message *m)
{
    if (m->type == VCS_ZCODE_WORK_SWARM_CAPABILITY)
        return zcws_write_capability(writer, &m->body.capability);
    if (m->type == VCS_ZCODE_WORK_SWARM_REQUEST)
        return zcws_write_request(writer, &m->body.request);
    if (m->type == VCS_ZCODE_WORK_SWARM_CANCEL)
        return zcws_write_cancel(writer, &m->body.cancel);
    if (m->type == VCS_ZCODE_WORK_SWARM_PROGRESS)
        return zcws_write_progress(writer, &m->body.progress);
    return zcws_write_admission(writer, &m->body.admission);
}

static bool zcws_write_header(struct zcl_codec_writer *writer,
    const struct vcs_zcode_work_swarm_message *m)
{
    return zcl_codec_write_bytes(writer, zcws_magic, sizeof(zcws_magic)) &&
        zcl_codec_write_u16le(writer, VCS_ZCODE_WORK_SWARM_VERSION) &&
        zcl_codec_write_u8(writer, m->type) &&
        zcl_codec_write_u8(writer, 0);
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
    bool ok = zcws_write_header(&writer, m);
    if (m->type == VCS_ZCODE_WORK_SWARM_RESULT) {
        const struct vcs_zcode_work_result_v1 *r = &m->body.result;
        uint8_t receipt[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES];
        if (vcs_zcode_work_receipt_serialize(&r->receipt, receipt) !=
                VCS_ZCODE_DEV_OK)
            LOG_FAIL("vcs.work_swarm", "receipt serialization failed");
        ok = ok && zcws_write_result(&writer, r, receipt);
    } else {
        ok = ok && zcws_write_body(&writer, m);
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

static bool zcws_parse_request_head(struct zcl_codec_reader *reader,
    struct vcs_zcode_work_request_v1 *r)
{
    uint8_t reserved[6];
    return zcl_codec_read_u64le(reader, &r->request_id) &&
        zcl_codec_read_bytes(reader, r->requester_pubkey, 32) &&
        zcl_codec_read_bytes(reader, r->task_root, 32) &&
        zcl_codec_read_bytes(reader, r->candidate_root, 32) &&
        zcl_codec_read_bytes(reader, r->action_root, 32) &&
        zcl_codec_read_bytes(reader, r->input_root, 32) &&
        zcl_codec_read_bytes(reader, r->context_root, 32) &&
        zcl_codec_read_bytes(reader, r->proof_policy_root, 32) &&
        zcl_codec_read_bytes(reader, r->toolchain_capsule_root, 32) &&
        zcl_codec_read_u8(reader, &r->work_kind) &&
        zcl_codec_read_u8(reader, &r->target) &&
        zcl_codec_read_bytes(reader, reserved, sizeof(reserved)) &&
        zcws_zero(reserved, sizeof(reserved));
}

static bool zcws_parse_capability(struct zcl_codec_reader *reader,
    struct vcs_zcode_work_capability_v1 *c)
{
    return zcl_codec_read_bytes(reader, c->signer_pubkey, 32) &&
        zcl_codec_read_bytes(reader, c->toolchain_capsule_root, 32) &&
        zcl_codec_read_u32le(reader, &c->work_kinds) &&
        zcl_codec_read_u32le(reader, &c->target) &&
        zcl_codec_read_u32le(reader, &c->confinement) &&
        zcl_codec_read_u32le(reader, &c->max_cpu_seconds) &&
        zcl_codec_read_u64le(reader, &c->max_memory_bytes) &&
        zcl_codec_read_u64le(reader, &c->max_output_bytes) &&
        zcl_codec_read_u32le(reader, &c->max_lease_seconds) &&
        zcl_codec_read_u16le(reader, &c->slots) &&
        zcl_codec_read_u16le(reader, &c->queue_headroom) &&
        zcl_codec_read_i64le(reader, &c->expires_unix) &&
        zcl_codec_read_bytes(reader, c->signature, 64) &&
        zcws_capability_valid(c) &&
        vcs_zcode_work_capability_verify(c);
}

static bool zcws_parse_request(struct zcl_codec_reader *reader,
    struct vcs_zcode_work_request_v1 *r)
{
    return zcws_parse_request_head(reader, r) &&
        zcl_codec_read_u32le(reader, &r->max_cpu_seconds) &&
        zcl_codec_read_u64le(reader, &r->max_memory_bytes) &&
        zcl_codec_read_u64le(reader, &r->max_output_bytes) &&
        zcl_codec_read_i64le(reader, &r->deadline_unix) &&
        zcl_codec_read_bytes(reader, r->signature, 64) &&
        zcws_request_valid(r) &&
        vcs_zcode_work_request_verify(r);
}

static bool zcws_parse_result(struct zcl_codec_reader *reader,
    struct vcs_zcode_work_result_v1 *r)
{
    uint8_t receipt[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES];
    return zcl_codec_read_u64le(reader, &r->request_id) &&
        zcl_codec_read_bytes(reader, r->task_root, 32) &&
        zcl_codec_read_bytes(reader, r->candidate_root, 32) &&
        zcl_codec_read_bytes(reader, r->action_root, 32) &&
        zcl_codec_read_bytes(reader, r->output_root, 32) &&
        zcl_codec_read_bytes(reader, receipt, sizeof(receipt)) &&
        vcs_zcode_work_receipt_parse(receipt, sizeof(receipt),
                                     &r->receipt) == VCS_ZCODE_DEV_OK &&
        zcws_result_shape(r);
}

static bool zcws_parse_cancel(struct zcl_codec_reader *reader,
    struct vcs_zcode_work_cancel_v1 *c)
{
    return zcl_codec_read_u64le(reader, &c->request_id) &&
        zcl_codec_read_bytes(reader, c->task_root, 32) &&
        zcl_codec_read_bytes(reader, c->requester_pubkey, 32) &&
        zcl_codec_read_bytes(reader, c->signature, 64) &&
        zcws_cancel_valid(c) &&
        vcs_zcode_work_cancel_verify(c);
}

static bool zcws_parse_progress(struct zcl_codec_reader *reader,
    struct vcs_zcode_work_progress_v1 *p)
{
    uint8_t reserved[7];
    return zcl_codec_read_u64le(reader, &p->request_id) &&
        zcl_codec_read_bytes(reader, p->task_root, 32) &&
        zcl_codec_read_bytes(reader, p->candidate_root, 32) &&
        zcl_codec_read_bytes(reader, p->action_root, 32) &&
        zcl_codec_read_u8(reader, &p->stage) &&
        zcl_codec_read_bytes(reader, reserved, sizeof(reserved)) &&
        zcl_codec_read_i64le(reader, &p->observed_unix) &&
        zcl_codec_read_bytes(reader, p->signer_pubkey, 32) &&
        zcl_codec_read_bytes(reader, p->signature, 64) &&
        zcws_zero(reserved, sizeof(reserved)) &&
        vcs_zcode_work_progress_verify(p);
}

static bool zcws_parse_admission(struct zcl_codec_reader *reader,
    struct vcs_zcode_work_admission_v1 *a)
{
    uint8_t reserved[4];
    return zcl_codec_read_u64le(reader, &a->request_id) &&
        zcl_codec_read_bytes(reader, a->requester_pubkey, 32) &&
        zcl_codec_read_bytes(reader, a->action_root, 32) &&
        zcl_codec_read_bytes(reader, a->worker_signer, 32) &&
        zcl_codec_read_u64le(reader, &a->lease_generation) &&
        zcl_codec_read_i64le(reader, &a->deadline_unix) &&
        zcl_codec_read_u16le(reader, &a->slot) &&
        zcl_codec_read_u8(reader, &a->disposition) &&
        zcl_codec_read_u8(reader, &a->reason) &&
        zcl_codec_read_bytes(reader, reserved, sizeof(reserved)) &&
        zcl_codec_read_bytes(reader, a->signature, 64) &&
        zcws_zero(reserved, sizeof(reserved)) &&
        vcs_zcode_work_admission_verify(a);
}

static bool zcws_parse_body(uint8_t type, size_t len,
    struct zcl_codec_reader *reader, struct vcs_zcode_work_swarm_message *out)
{
    if (type == VCS_ZCODE_WORK_SWARM_CAPABILITY &&
        len == ZCWS_CAPABILITY_BYTES)
        return zcws_parse_capability(reader, &out->body.capability);
    if (type == VCS_ZCODE_WORK_SWARM_REQUEST && len == ZCWS_REQUEST_BYTES)
        return zcws_parse_request(reader, &out->body.request);
    if (type == VCS_ZCODE_WORK_SWARM_RESULT && len == ZCWS_RESULT_BYTES)
        return zcws_parse_result(reader, &out->body.result);
    if (type == VCS_ZCODE_WORK_SWARM_CANCEL && len == ZCWS_CANCEL_BYTES)
        return zcws_parse_cancel(reader, &out->body.cancel);
    if (type == VCS_ZCODE_WORK_SWARM_PROGRESS && len == ZCWS_PROGRESS_BYTES)
        return zcws_parse_progress(reader, &out->body.progress);
    if (type == VCS_ZCODE_WORK_SWARM_ADMISSION &&
        len == ZCWS_ADMISSION_BYTES)
        return zcws_parse_admission(reader, &out->body.admission);
    return false;
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
    if (!zcws_parse_body(type, len, &reader, out)) goto reject;
    if (!zcl_codec_reader_finish(&reader)) goto reject;
    return true;
reject:
    memset(out, 0, sizeof(*out));
    LOG_FAIL("vcs.work_swarm", "noncanonical work swarm payload");
}

static bool zcws_result_request_bound(
    const struct vcs_zcode_work_request_v1 *q,
    const struct vcs_zcode_work_result_v1 *r)
{
    return q->request_id == r->request_id &&
        memcmp(q->task_root, r->task_root, 32) == 0 &&
        memcmp(q->action_root, r->action_root, 32) == 0;
}

static bool zcws_result_receipt_roots(
    const struct vcs_zcode_work_request_v1 *q,
    const struct vcs_zcode_work_result_v1 *r)
{
    return memcmp(r->task_root, r->receipt.task_root, 32) == 0 &&
        memcmp(r->candidate_root, r->receipt.candidate_root, 32) == 0 &&
        memcmp(r->action_root, r->receipt.action_root, 32) == 0 &&
        memcmp(q->input_root, r->receipt.input_root, 32) == 0 &&
        memcmp(r->output_root, r->receipt.output_root, 32) == 0 &&
        memcmp(q->proof_policy_root, r->receipt.proof_policy_root, 32) == 0 &&
        memcmp(q->toolchain_capsule_root,
               r->receipt.toolchain_capsule_root, 32) == 0;
}

static bool zcws_result_status_ok(
    const struct vcs_zcode_work_request_v1 *q,
    const struct vcs_zcode_work_result_v1 *r)
{
    return r->receipt.work_kind == q->work_kind &&
        (r->receipt.status == VCS_ZCODE_WORK_PASS ||
         r->receipt.status == VCS_ZCODE_WORK_FAIL);
}

static bool zcws_result_candidate_bound(
    const struct vcs_zcode_work_request_v1 *q,
    const struct vcs_zcode_work_result_v1 *r)
{
    return q->work_kind == VCS_ZCODE_WORK_PROPOSE ||
        memcmp(q->candidate_root, r->candidate_root, 32) == 0;
}

bool vcs_zcode_work_result_verify(
    const struct vcs_zcode_work_request_v1 *q,
    const struct vcs_zcode_work_result_v1 *r,
    const uint8_t expected_signer[32])
{
    return zcws_request_valid(q) && zcws_result_shape(r) &&
        expected_signer && zcws_result_request_bound(q, r) &&
        zcws_result_receipt_roots(q, r) && zcws_result_status_ok(q, r) &&
        zcws_result_candidate_bound(q, r) &&
        vcs_zcode_work_receipt_verify(&r->receipt, expected_signer) ==
            VCS_ZCODE_DEV_OK;
}

static bool zcws_quorum_signer_allowed(
    const uint8_t (*approved)[32], size_t approved_count,
    const uint8_t signer[32])
{
    for (size_t j = 0; j < approved_count; j++)
        if (memcmp(signer, approved[j], 32) == 0) return true;
    return false;
}

static bool zcws_quorum_signer_counted(
    uint8_t (*counted)[32], size_t count, const uint8_t signer[32])
{
    for (size_t j = 0; j < count; j++)
        if (memcmp(signer, counted[j], 32) == 0) return true;
    return false;
}

static size_t zcws_quorum_count_one(
    const struct vcs_zcode_work_request_v1 *request,
    const struct vcs_zcode_work_result_v1 *result,
    const uint8_t (*approved)[32], size_t approved_count,
    uint8_t (*counted)[32], size_t count, uint8_t output_root[32])
{
    const uint8_t *signer = result->receipt.signer_pubkey;
    if (!zcws_quorum_signer_allowed(approved, approved_count, signer) ||
        zcws_quorum_signer_counted(counted, count, signer) ||
        result->receipt.status != VCS_ZCODE_WORK_PASS ||
        !vcs_zcode_work_result_verify(request, result, signer))
        return 0;
    if (count == 0)
        memcpy(output_root, result->output_root, 32);
    else if (memcmp(output_root, result->output_root, 32) != 0)
        return 0;
    memcpy(counted[count], signer, 32);
    return 1;
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
    for (size_t i = 0; i < result_count; i++)
        count += zcws_quorum_count_one(request, &results[i], approved,
                                       approved_count, counted, count,
                                       output_root);
    if (count < required) memset(output_root, 0, 32);
    return count;
}

bool vcs_zcode_work_capability_allows(
    const struct vcs_zcode_work_capability_v1 *cap,
    const struct vcs_zcode_work_request_v1 *request, int64_t now)
{
    return cap && request && now < cap->expires_unix &&
           request->deadline_unix > now && cap->queue_headroom > 0 &&
           request->deadline_unix - now <= cap->max_lease_seconds &&
           (cap->work_kinds & (UINT32_C(1) << request->work_kind)) != 0 &&
           (cap->confinement & VCS_ZCODE_WORK_CONFINEMENT_V1_MASK) ==
               VCS_ZCODE_WORK_CONFINEMENT_V1_MASK &&
           cap->target == request->target &&
           memcmp(cap->toolchain_capsule_root,
                  request->toolchain_capsule_root, 32) == 0 &&
           request->max_cpu_seconds <= cap->max_cpu_seconds &&
           request->max_memory_bytes <= cap->max_memory_bytes &&
           request->max_output_bytes <= cap->max_output_bytes;
}

bool vcs_zcode_work_capability_matches(
    const struct vcs_zcode_work_capability_v1 *cap,
    const struct vcs_zcode_work_request_v1 *request, int64_t now)
{
    if (!cap) return false;
    struct vcs_zcode_work_capability_v1 available = *cap;
    available.queue_headroom = available.slots;
    return vcs_zcode_work_capability_allows(&available, request, now);
}

bool vcs_zcode_work_same_action_binding(
    const struct vcs_zcode_work_request_v1 *a,
    const struct vcs_zcode_work_request_v1 *b)
{
    return memcmp(a->task_root, b->task_root, 32) == 0 &&
        memcmp(a->candidate_root, b->candidate_root, 32) == 0 &&
        memcmp(a->action_root, b->action_root, 32) == 0 &&
        memcmp(a->input_root, b->input_root, 32) == 0 &&
        memcmp(a->context_root, b->context_root, 32) == 0 &&
        memcmp(a->proof_policy_root, b->proof_policy_root, 32) == 0 &&
        memcmp(a->toolchain_capsule_root,
               b->toolchain_capsule_root, 32) == 0 &&
        a->work_kind == b->work_kind && a->target == b->target &&
        a->max_cpu_seconds == b->max_cpu_seconds &&
        a->max_memory_bytes == b->max_memory_bytes &&
        a->max_output_bytes == b->max_output_bytes;
}

bool vcs_zcode_work_same_result(const struct vcs_zcode_work_result_v1 *a,
                      const struct vcs_zcode_work_result_v1 *b)
{
    struct vcs_zcode_work_swarm_message ma = {
        .type = VCS_ZCODE_WORK_SWARM_RESULT, .body.result = *a,
    };
    struct vcs_zcode_work_swarm_message mb = {
        .type = VCS_ZCODE_WORK_SWARM_RESULT, .body.result = *b,
    };
    uint8_t wa[VCS_ZCODE_WORK_SWARM_MAX_WIRE_BYTES];
    uint8_t wb[VCS_ZCODE_WORK_SWARM_MAX_WIRE_BYTES];
    size_t la = 0, lb = 0;
    return vcs_zcode_work_swarm_serialize(&ma, wa, sizeof(wa), &la) &&
        vcs_zcode_work_swarm_serialize(&mb, wb, sizeof(wb), &lb) &&
        la == lb && memcmp(wa, wb, la) == 0;
}
