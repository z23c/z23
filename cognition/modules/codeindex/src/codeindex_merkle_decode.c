/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Decode and verify bounded wire-format codeindex Merkle proofs. */

#include "codeindex_priv.h"
#include "codeindex/codeindex_merkle.h"

#include "base/serialize_le.h"
#include "util/log_macros.h"

#include <string.h>

static const char merkle_proof_wire_domain[] = "zcl.codeindex.merkle.proof.v1";

struct merkle_cursor {
    const unsigned char *p;
    size_t left;
    bool bad;
};

static bool merkle_take(struct merkle_cursor *cursor, void *out, size_t size)
{
    if (cursor->bad || cursor->left < size) {
        cursor->bad = true;
        return false;
    }
    memcpy(out, cursor->p, size);
    cursor->p += size;
    cursor->left -= size;
    return true;
}

static uint32_t merkle_take_u32(struct merkle_cursor *cursor)
{
    uint8_t bytes[4] = {0};
    if (!merkle_take(cursor, bytes, sizeof(bytes))) return 0;
    return zcl_read_u32_le(bytes);
}

/* Length-prefixed string into a fixed field, refusing anything that would not
 * fit or that hides a NUL. */
static bool merkle_take_str(struct merkle_cursor *cursor, char *out,
                            size_t outcap)
{
    uint8_t bytes[2] = {0};
    if (!merkle_take(cursor, bytes, sizeof(bytes))) return false;
    size_t length = zcl_read_u16_le(bytes);
    if (length >= outcap) {
        cursor->bad = true;
        return false;
    }
    memset(out, 0, outcap);
    if (length && !merkle_take(cursor, out, length)) return false;
    out[length] = '\0';
    if (memchr(out, '\0', length) != NULL) {
        cursor->bad = true;
        return false;
    }
    return true;
}

bool ci_merkle_proof_decode(const unsigned char *in, size_t len,
                            struct ci_merkle_proof *out)
{
    if (!in || !out) LOG_FAIL("codeindex", "null arg to merkle_proof_decode");
    memset(out, 0, sizeof(*out));
    if (len <= sizeof(merkle_proof_wire_domain) ||
        len > CI_MERKLE_PROOF_WIRE_MAX ||
        memcmp(in, merkle_proof_wire_domain,
               sizeof(merkle_proof_wire_domain)) != 0)
        return false;

    struct merkle_cursor cursor = {
        .p = in + sizeof(merkle_proof_wire_domain),
        .left = len - sizeof(merkle_proof_wire_domain),
        .bad = false,
    };
    unsigned char kind = 0;
    if (!merkle_take(&cursor, &kind, 1) || kind > CI_MERKLE_KIND_DIR)
        return false;
    out->kind = kind;
    if (!merkle_take_str(&cursor, out->path, sizeof(out->path))) return false;
    uint32_t nlevels = merkle_take_u32(&cursor);
    uint32_t nchildren = merkle_take_u32(&cursor);
    if (cursor.bad || nlevels > CI_MERKLE_PROOF_MAX_LEVELS ||
        nchildren > CI_MERKLE_PROOF_MAX_CHILDREN)
        return false;

    uint32_t run = 0;
    for (uint32_t i = 0; i < nlevels; i++) {
        struct ci_merkle_proof_level *level = &out->level[i];
        if (!merkle_take_str(&cursor, level->path, sizeof(level->path)))
            return false;
        uint32_t count = merkle_take_u32(&cursor);
        uint32_t index = merkle_take_u32(&cursor);
        if (cursor.bad || count == 0 || index >= count ||
            count > nchildren - run)
            return false;
        level->first_child = run;
        level->nchildren = count;
        level->index = index;
        for (uint32_t child_index = 0; child_index < count; child_index++) {
            struct ci_merkle_proof_child *child =
                &out->children[run + child_index];
            unsigned char child_kind = 0;
            if (!merkle_take(&cursor, &child_kind, 1) ||
                child_kind > CI_MERKLE_KIND_DIR)
                return false;
            child->kind = child_kind;
            if (!merkle_take_str(&cursor, child->name, sizeof(child->name)) ||
                !merkle_take(&cursor, child->digest.bytes, 32))
                return false;
        }
        run += count;
    }
    if (cursor.bad || cursor.left != 0 || run != nchildren) return false;
    out->nlevels = nlevels;
    out->nchildren = nchildren;
    return true;
}

bool ci_merkle_proof_verify_bytes(const unsigned char *in, size_t len,
                                  const struct zcl_sha3_digest *claimed,
                                  const struct zcl_sha3_digest *root,
                                  char out_path[256], uint8_t *out_kind,
                                  bool *ok)
{
    if (!claimed || !root || !ok)
        LOG_FAIL("codeindex", "null arg to merkle_proof_verify_bytes");
    *ok = false;
    if (out_path) out_path[0] = '\0';
    if (out_kind) *out_kind = 0;
    if (!in) return true;

    struct ci_merkle_proof *proof = ci_merkle_proof_alloc();
    if (!proof)
        LOG_FAIL("codeindex", "allocate merkle proof for byte verification");
    bool result = true;
    if (ci_merkle_proof_decode(in, len, proof)) {
        result = ci_merkle_proof_verify(proof, claimed, root, ok);
        if (result) {
            if (out_path) ci_cpy(out_path, 256, proof->path);
            if (out_kind) *out_kind = proof->kind;
        }
    }
    ci_merkle_proof_free(proof);
    return result;
}
