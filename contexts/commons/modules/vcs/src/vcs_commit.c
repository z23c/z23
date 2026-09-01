/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * vcs_commit — implementation. See vcs/vcs_commit.h. */

#include "vcs/vcs_commit.h"
#include "vcs/vcs_object.h"

#include "vcs_priv.h"

#include "util/log_macros.h"

#include <string.h>

/* Write the canonical preimage into buf (VCS_COMMIT_PREIMAGE_BYTES). Fixed
 * char fields are copied with their full declared width (NUL padding is part
 * of the canonical form). */
static void write_preimage(const struct vcs_commit *c, uint8_t *buf)
{
    size_t off = 0;
    vcs_wr_u32le(buf + off, c->version); off += 4;
    memcpy(buf + off, c->parent, 32); off += 32;
    memcpy(buf + off, c->tree_hash, 32); off += 32;
    memcpy(buf + off, c->sealset_hash, 32); off += 32;
    memcpy(buf + off, c->generation_sha256, 32); off += 32;
    vcs_wr_u32le(buf + off, c->verdict_status); off += 4;
    memcpy(buf + off, c->phase, VCS_COMMIT_PHASE_LEN); off += VCS_COMMIT_PHASE_LEN;
    vcs_wr_u64le(buf + off, c->elapsed_ms); off += 8;
    memcpy(buf + off, c->failure_hash, 32); off += 32;
    memcpy(buf + off, c->agent_id, VCS_COMMIT_AGENT_LEN); off += VCS_COMMIT_AGENT_LEN;
    memcpy(buf + off, c->session_id, VCS_COMMIT_SESSION_LEN); off += VCS_COMMIT_SESSION_LEN;
    memcpy(buf + off, c->task_ref, VCS_COMMIT_TASK_LEN); off += VCS_COMMIT_TASK_LEN;
    vcs_wr_u64le(buf + off, (uint64_t)c->committed_at); off += 8;
    /* off == VCS_COMMIT_PREIMAGE_BYTES */
}

bool vcs_commit_preimage(const struct vcs_commit *c,
                         uint8_t out[VCS_COMMIT_PREIMAGE_BYTES])
{
    if (!c || !out)
        LOG_FAIL("vcs", "null arg to commit_preimage");
    write_preimage(c, out);
    return true;
}

bool vcs_commit_serialize(struct vcs_commit *c,
                          uint8_t out[VCS_COMMIT_RECORD_BYTES])
{
    if (!c || !out)
        LOG_FAIL("vcs", "null arg to commit_serialize");
    write_preimage(c, out);
    uint8_t self[32];
    sha3_256(out, VCS_COMMIT_PREIMAGE_BYTES, self);
    memcpy(out + VCS_COMMIT_PREIMAGE_BYTES, self, 32);
    memcpy(c->self_sha3, self, 32);
    return true;
}

/* Read the VCS_COMMIT_PREIMAGE_BYTES of fields from in into *out (does not
 * touch self_sha3). Returns false on a bad version. */
static bool read_preimage_fields(const uint8_t *in, struct vcs_commit *out)
{
    memset(out, 0, sizeof(*out));
    size_t off = 0;
    out->version = vcs_rd_u32le(in + off); off += 4;
    if (out->version != VCS_COMMIT_VERSION)
        LOG_FAIL("vcs", "bad commit version %u", out->version);
    memcpy(out->parent, in + off, 32); off += 32;
    memcpy(out->tree_hash, in + off, 32); off += 32;
    memcpy(out->sealset_hash, in + off, 32); off += 32;
    memcpy(out->generation_sha256, in + off, 32); off += 32;
    out->verdict_status = vcs_rd_u32le(in + off); off += 4;
    memcpy(out->phase, in + off, VCS_COMMIT_PHASE_LEN); off += VCS_COMMIT_PHASE_LEN;
    out->phase[VCS_COMMIT_PHASE_LEN - 1] = '\0';
    out->elapsed_ms = vcs_rd_u64le(in + off); off += 8;
    memcpy(out->failure_hash, in + off, 32); off += 32;
    memcpy(out->agent_id, in + off, VCS_COMMIT_AGENT_LEN); off += VCS_COMMIT_AGENT_LEN;
    out->agent_id[VCS_COMMIT_AGENT_LEN - 1] = '\0';
    memcpy(out->session_id, in + off, VCS_COMMIT_SESSION_LEN); off += VCS_COMMIT_SESSION_LEN;
    out->session_id[VCS_COMMIT_SESSION_LEN - 1] = '\0';
    memcpy(out->task_ref, in + off, VCS_COMMIT_TASK_LEN); off += VCS_COMMIT_TASK_LEN;
    out->task_ref[VCS_COMMIT_TASK_LEN - 1] = '\0';
    out->committed_at = (int64_t)vcs_rd_u64le(in + off); off += 8;
    return true;
}

bool vcs_commit_deserialize(const uint8_t *in, size_t len,
                            struct vcs_commit *out, bool *self_ok)
{
    if (self_ok) *self_ok = false;
    if (!in || !out)
        LOG_FAIL("vcs", "null arg to commit_deserialize");
    if (len != VCS_COMMIT_RECORD_BYTES)
        LOG_FAIL("vcs", "bad commit record length %zu", len);
    if (!read_preimage_fields(in, out))
        return false;
    memcpy(out->self_sha3, in + VCS_COMMIT_PREIMAGE_BYTES, 32);

    uint8_t recomputed[32];
    sha3_256(in, VCS_COMMIT_PREIMAGE_BYTES, recomputed);
    if (self_ok)
        *self_ok = (memcmp(recomputed, out->self_sha3, 32) == 0);
    return true;
}

bool vcs_commit_parse_preimage(const uint8_t *pre, size_t len,
                               struct vcs_commit *out)
{
    if (!pre || !out)
        LOG_FAIL("vcs", "null arg to parse_preimage");
    if (len != VCS_COMMIT_PREIMAGE_BYTES)
        LOG_FAIL("vcs", "bad preimage length %zu", len);
    if (!read_preimage_fields(pre, out))
        return false;
    sha3_256(pre, VCS_COMMIT_PREIMAGE_BYTES, out->self_sha3);
    return true;
}

bool vcs_commit_id(const struct vcs_commit *c, uint8_t out[32])
{
    if (!c || !out)
        LOG_FAIL("vcs", "null arg to commit_id");
    uint8_t pre[VCS_COMMIT_PREIMAGE_BYTES];
    write_preimage(c, pre);
    vcs_sha3_tag(VCS_TAG_COMMIT, pre, sizeof(pre), out);
    return true;
}
