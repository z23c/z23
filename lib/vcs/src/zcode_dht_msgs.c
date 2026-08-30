/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Signed Noise-bound ZCODE DHT routing and record frames. */

#include "vcs/zcode_dht_msgs.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "support/cleanse.h"

#include <string.h>

static const uint8_t msgs_magic[8] =
    {'Z','C','D','H','T','M',0x0D,0x0A};

static size_t write_header(uint8_t *wire, enum vcs_zcode_dht_msg_kind kind)
{
    memcpy(wire, msgs_magic, 8);
    zcl_write_u16_le(wire + 8, VCS_ZCODE_DHT_MSGS_WIRE_VERSION);
    wire[10] = (uint8_t)kind;
    return VCS_ZCODE_DHT_MSGS_HEADER_BYTES;
}

static enum vcs_zcode_dht_error write_auth(
    uint8_t *wire, size_t *off, uint64_t generation,
    const uint8_t sender[32], const uint8_t query[16],
    const struct vcs_zcode_dht_delegation *delegation)
{
    if (!generation || !zcl_bytes_any_set(sender, 32)) return VCS_ZCODE_DHT_ERR_ID_ZERO;
    if (!zcl_bytes_any_set(query, 16)) return VCS_ZCODE_DHT_ERR_QUERY_ID;
    zcl_write_u64_le(wire + *off, generation); *off += 8;
    memcpy(wire + *off, sender, 32); *off += 32;
    memcpy(wire + *off, query, 16); *off += 16;
    if (vcs_zcode_dht_delegation_encode(delegation, wire + *off) !=
        VCS_ZCODE_DHT_DELEGATION_OK) return VCS_ZCODE_DHT_ERR_DELEGATION;
    *off += VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES;
    uint8_t derived[32];
    if (!vcs_zcode_dht_delegation_node_id(derived, delegation) ||
        memcmp(derived, sender, 32) != 0)
        return VCS_ZCODE_DHT_ERR_DELEGATION;
    return VCS_ZCODE_DHT_OK;
}

static enum vcs_zcode_dht_error sign_frame(
    uint8_t *wire, size_t unsigned_len, const uint8_t transcript[32],
    const uint8_t online_seed[32],
    const struct vcs_zcode_dht_delegation *delegation)
{
    if (!zcl_bytes_any_set(transcript, 32) || !online_seed)
        return VCS_ZCODE_DHT_ERR_SESSION;
    uint8_t pub[32], secret[32];
    ed25519_keypair(pub, secret, online_seed);
    if (memcmp(pub, delegation->online_pubkey, 32) != 0) {
        memory_cleanse(secret, sizeof(secret));
        return VCS_ZCODE_DHT_ERR_IDENTITY;
    }
    uint8_t preimage[sizeof(VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN) + 32 +
                     VCS_ZCODE_DHT_MAX_FRAME_BYTES];
    size_t off = 0;
    memcpy(preimage + off, VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN,
           sizeof(VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN));
    off += sizeof(VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN);
    memcpy(preimage + off, transcript, 32); off += 32;
    memcpy(preimage + off, wire, unsigned_len); off += unsigned_len;
    ed25519_sign(wire + unsigned_len, preimage, off, secret, pub);
    memory_cleanse(secret, sizeof(secret));
    memory_cleanse(preimage, off);
    return VCS_ZCODE_DHT_OK;
}

enum vcs_zcode_dht_error vcs_zcode_dht_msg_serialize_find_node(
    const struct vcs_zcode_dht_msg_find_node *m,
    const uint8_t transcript[32], const uint8_t online_seed[32],
    uint8_t *wire, size_t cap, size_t *len_out)
{
    if (!len_out) return VCS_ZCODE_DHT_ERR_NULL;
    *len_out = 0;
    if (!m || !wire || !transcript || !online_seed)
        return VCS_ZCODE_DHT_ERR_NULL;
    if (!zcl_bytes_any_set(m->target_node_id, 32)) return VCS_ZCODE_DHT_ERR_ID_ZERO;
    if (cap < VCS_ZCODE_DHT_FIND_NODE_WIRE_BYTES)
        return VCS_ZCODE_DHT_ERR_WIRE_SIZE;
    size_t off = write_header(wire, VCS_ZCODE_DHT_MSG_FIND_NODE);
    enum vcs_zcode_dht_error e = write_auth(
        wire, &off, m->session_generation, m->sender_node_id, m->query_id,
        &m->delegation);
    if (e != VCS_ZCODE_DHT_OK) return e;
    memcpy(wire + off, m->target_node_id, 32); off += 32;
    e = sign_frame(wire, off, transcript, online_seed, &m->delegation);
    if (e != VCS_ZCODE_DHT_OK) return e;
    off += VCS_ZCODE_DHT_MSG_SIGNATURE_BYTES;
    *len_out = off; return off == VCS_ZCODE_DHT_FIND_NODE_WIRE_BYTES
        ? VCS_ZCODE_DHT_OK : VCS_ZCODE_DHT_ERR_WIRE_SIZE;
}

enum vcs_zcode_dht_error vcs_zcode_dht_msg_serialize_nodes(
    const struct vcs_zcode_dht_msg_nodes *m,
    const uint8_t transcript[32], const uint8_t online_seed[32],
    uint8_t *wire, size_t cap, size_t *len_out)
{
    if (!len_out) return VCS_ZCODE_DHT_ERR_NULL;
    *len_out = 0;
    if (!m || !wire || !transcript || !online_seed)
        return VCS_ZCODE_DHT_ERR_NULL;
    if (m->contact_count > VCS_ZCODE_DHT_K) return VCS_ZCODE_DHT_ERR_LIMIT;
    for (uint32_t i = 0; i < m->contact_count; i++) {
        if (!zcl_bytes_any_set(m->node_ids[i], 32)) return VCS_ZCODE_DHT_ERR_ID_ZERO;
        if (i && memcmp(m->node_ids[i - 1], m->node_ids[i], 32) >= 0)
            return VCS_ZCODE_DHT_ERR_WIRE_ORDER;
    }
    size_t need = VCS_ZCODE_DHT_MSGS_HEADER_BYTES +
        VCS_ZCODE_DHT_MSGS_AUTH_BYTES + 1 + (size_t)m->contact_count * 32 +
        VCS_ZCODE_DHT_MSG_SIGNATURE_BYTES;
    if (cap < need) return VCS_ZCODE_DHT_ERR_WIRE_SIZE;
    size_t off = write_header(wire, VCS_ZCODE_DHT_MSG_NODES);
    enum vcs_zcode_dht_error e = write_auth(
        wire, &off, m->session_generation, m->sender_node_id, m->query_id,
        &m->delegation);
    if (e != VCS_ZCODE_DHT_OK) return e;
    wire[off++] = (uint8_t)m->contact_count;
    for (uint32_t i = 0; i < m->contact_count; i++) {
        memcpy(wire + off, m->node_ids[i], 32); off += 32;
    }
    e = sign_frame(wire, off, transcript, online_seed, &m->delegation);
    if (e != VCS_ZCODE_DHT_OK) return e;
    off += VCS_ZCODE_DHT_MSG_SIGNATURE_BYTES;
    *len_out = off; return off == need ? VCS_ZCODE_DHT_OK
                                       : VCS_ZCODE_DHT_ERR_WIRE_SIZE;
}

static size_t selector_length(
    const char name[VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES])
{
    size_t length = 0;
    while (length < VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES && name[length])
        length++;
    return length;
}

static bool selector_valid(const struct vcs_zcode_dht_record_selector *s)
{
    if (!s || s->kind < VCS_ZCODE_DHT_RECORD_PROVIDER ||
        s->kind > VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK ||
        !zcl_bytes_any_set(s->root, 32))
        return false;
    size_t length = selector_length(s->namespace_name);
    if (!length || length > VCS_ZCODE_DHT_RECORD_NAMESPACE_MAX)
        return false;
    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char)s->namespace_name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '.' || c == '_' || c == '-'))
            return false;
    }
    for (size_t i = length; i < VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES; i++)
        if (s->namespace_name[i] != '\0')
            return false;
    return true;
}

static size_t write_selector(
    uint8_t *wire, const struct vcs_zcode_dht_record_selector *selector)
{
    size_t length = selector_length(selector->namespace_name);
    wire[0] = (uint8_t)selector->kind;
    wire[1] = (uint8_t)length;
    memset(wire + 2, 0, VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES);
    memcpy(wire + 2, selector->namespace_name, length);
    memcpy(wire + 2 + VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES, selector->root,
           32);
    return VCS_ZCODE_DHT_RECORD_SELECTOR_BYTES;
}

static bool selector_matches(
    const struct vcs_zcode_dht_record_selector *selector,
    const struct vcs_zcode_dht_record *record)
{
    const uint8_t *root = record->kind == VCS_ZCODE_DHT_RECORD_POINTER
                              ? record->semantic_root
                              : record->transport_root;
    return selector->kind == record->kind &&
           strcmp(selector->namespace_name, record->namespace_name) == 0 &&
           memcmp(selector->root, root, 32) == 0;
}

static enum vcs_zcode_dht_error serialize_find_record_common(
    const struct vcs_zcode_dht_msg_find_record *m,
    const uint8_t transcript[32], const uint8_t online_seed[32],
    uint8_t *wire, size_t cap, size_t *len_out)
{
    if (!len_out) return VCS_ZCODE_DHT_ERR_NULL;
    *len_out = 0;
    if (!m || !wire || !transcript || !online_seed)
        return VCS_ZCODE_DHT_ERR_NULL;
    if (!selector_valid(&m->selector) ||
        m->page_offset >= VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_ROOT ||
        m->page_offset % VCS_ZCODE_DHT_RECORDS_PER_FRAME != 0)
        return VCS_ZCODE_DHT_ERR_WIRE_ORDER;
    if (cap < VCS_ZCODE_DHT_FIND_RECORD_WIRE_BYTES)
        return VCS_ZCODE_DHT_ERR_WIRE_SIZE;
    size_t off = write_header(wire, VCS_ZCODE_DHT_MSG_FIND_RECORD);
    enum vcs_zcode_dht_error e = write_auth(
        wire, &off, m->session_generation, m->sender_node_id, m->query_id,
        &m->delegation);
    if (e != VCS_ZCODE_DHT_OK) return e;
    off += write_selector(wire + off, &m->selector);
    wire[off++] = m->page_offset;
    e = sign_frame(wire, off, transcript, online_seed, &m->delegation);
    if (e != VCS_ZCODE_DHT_OK) return e;
    off += VCS_ZCODE_DHT_MSG_SIGNATURE_BYTES;
    *len_out = off;
    return off == VCS_ZCODE_DHT_FIND_RECORD_WIRE_BYTES
               ? VCS_ZCODE_DHT_OK : VCS_ZCODE_DHT_ERR_WIRE_SIZE;
}

enum vcs_zcode_dht_error vcs_zcode_dht_msg_serialize_find_record(
    const struct vcs_zcode_dht_msg_find_record *m,
    const uint8_t transcript[32], const uint8_t online_seed[32],
    uint8_t *wire, size_t cap, size_t *len_out)
{
    return serialize_find_record_common(m, transcript, online_seed, wire, cap,
                                        len_out);
}

enum vcs_zcode_dht_error vcs_zcode_dht_msg_serialize_records(
    const struct vcs_zcode_dht_msg_records *m,
    const uint8_t transcript[32], const uint8_t online_seed[32],
    uint8_t *wire, size_t cap, size_t *len_out)
{
    if (!len_out) return VCS_ZCODE_DHT_ERR_NULL;
    *len_out = 0;
    if (!m || !wire || !transcript || !online_seed)
        return VCS_ZCODE_DHT_ERR_NULL;
    if (!selector_valid(&m->selector) ||
        m->page_offset >= VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_ROOT ||
        m->page_offset % VCS_ZCODE_DHT_RECORDS_PER_FRAME != 0 ||
        (m->next_offset &&
         (m->next_offset !=
              m->page_offset + VCS_ZCODE_DHT_RECORDS_PER_FRAME ||
          m->next_offset >= VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_ROOT)))
        return VCS_ZCODE_DHT_ERR_WIRE_ORDER;
    if (m->record_count > VCS_ZCODE_DHT_RECORDS_PER_FRAME ||
        (m->next_offset &&
         m->record_count != VCS_ZCODE_DHT_RECORDS_PER_FRAME))
        return VCS_ZCODE_DHT_ERR_LIMIT;
    size_t need = VCS_ZCODE_DHT_MSGS_HEADER_BYTES +
                  VCS_ZCODE_DHT_MSGS_AUTH_BYTES +
                  VCS_ZCODE_DHT_RECORD_SELECTOR_BYTES + 3u +
                  (size_t)m->record_count * VCS_ZCODE_DHT_RECORD_WIRE_BYTES +
                  VCS_ZCODE_DHT_MSG_SIGNATURE_BYTES;
    if (cap < need) return VCS_ZCODE_DHT_ERR_WIRE_SIZE;
    size_t off = write_header(wire, VCS_ZCODE_DHT_MSG_RECORDS);
    enum vcs_zcode_dht_error e = write_auth(
        wire, &off, m->session_generation, m->sender_node_id, m->query_id,
        &m->delegation);
    if (e != VCS_ZCODE_DHT_OK) return e;
    off += write_selector(wire + off, &m->selector);
    wire[off++] = m->page_offset;
    wire[off++] = m->next_offset;
    wire[off++] = (uint8_t)m->record_count;
    for (uint32_t i = 0; i < m->record_count; i++) {
        if (!selector_matches(&m->selector, &m->records[i]))
            return VCS_ZCODE_DHT_ERR_WIRE_ORDER;
        if (memcmp(m->records[i].network_genesis,
                   m->delegation.network_genesis, 32) != 0)
            return VCS_ZCODE_DHT_ERR_NETWORK;
        if (vcs_zcode_dht_record_encode(&m->records[i], wire + off) !=
            VCS_ZCODE_DHT_RECORD_OK)
            return VCS_ZCODE_DHT_ERR_WIRE_ORDER;
        if (i && memcmp(wire + off - VCS_ZCODE_DHT_RECORD_WIRE_BYTES,
                        wire + off, VCS_ZCODE_DHT_RECORD_WIRE_BYTES) >= 0)
            return VCS_ZCODE_DHT_ERR_WIRE_ORDER;
        off += VCS_ZCODE_DHT_RECORD_WIRE_BYTES;
    }
    e = sign_frame(wire, off, transcript, online_seed, &m->delegation);
    if (e != VCS_ZCODE_DHT_OK) return e;
    off += VCS_ZCODE_DHT_MSG_SIGNATURE_BYTES;
    *len_out = off;
    return off == need ? VCS_ZCODE_DHT_OK : VCS_ZCODE_DHT_ERR_WIRE_SIZE;
}

enum vcs_zcode_dht_error vcs_zcode_dht_msg_serialize_store_record(
    const struct vcs_zcode_dht_msg_store_record *m,
    const uint8_t transcript[32], const uint8_t online_seed[32],
    uint8_t *wire, size_t cap, size_t *len_out)
{
    if (!len_out) return VCS_ZCODE_DHT_ERR_NULL;
    *len_out = 0;
    if (!m || !wire || !transcript || !online_seed)
        return VCS_ZCODE_DHT_ERR_NULL;
    if (cap < VCS_ZCODE_DHT_STORE_RECORD_WIRE_BYTES)
        return VCS_ZCODE_DHT_ERR_WIRE_SIZE;
    if (memcmp(m->record.network_genesis, m->delegation.network_genesis, 32) !=
        0) return VCS_ZCODE_DHT_ERR_NETWORK;
    size_t off = write_header(wire, VCS_ZCODE_DHT_MSG_STORE_RECORD);
    enum vcs_zcode_dht_error e = write_auth(
        wire, &off, m->session_generation, m->sender_node_id, m->query_id,
        &m->delegation);
    if (e != VCS_ZCODE_DHT_OK) return e;
    if (vcs_zcode_dht_record_encode(&m->record, wire + off) !=
        VCS_ZCODE_DHT_RECORD_OK) return VCS_ZCODE_DHT_ERR_WIRE_ORDER;
    off += VCS_ZCODE_DHT_RECORD_WIRE_BYTES;
    e = sign_frame(wire, off, transcript, online_seed, &m->delegation);
    if (e != VCS_ZCODE_DHT_OK) return e;
    off += VCS_ZCODE_DHT_MSG_SIGNATURE_BYTES;
    *len_out = off;
    return off == VCS_ZCODE_DHT_STORE_RECORD_WIRE_BYTES
               ? VCS_ZCODE_DHT_OK : VCS_ZCODE_DHT_ERR_WIRE_SIZE;
}

enum vcs_zcode_dht_error vcs_zcode_dht_msg_serialize_store_result(
    const struct vcs_zcode_dht_msg_store_result *m,
    const uint8_t transcript[32], const uint8_t online_seed[32],
    uint8_t *wire, size_t cap, size_t *len_out)
{
    if (!len_out) return VCS_ZCODE_DHT_ERR_NULL;
    *len_out = 0;
    if (!m || !wire || !transcript || !online_seed)
        return VCS_ZCODE_DHT_ERR_NULL;
    if (m->status < VCS_ZCODE_DHT_STORE_STORED ||
        m->status > VCS_ZCODE_DHT_STORE_REJECTED ||
        !zcl_bytes_any_set(m->record_digest, 32)) return VCS_ZCODE_DHT_ERR_WIRE_ORDER;
    if (cap < VCS_ZCODE_DHT_STORE_RESULT_WIRE_BYTES)
        return VCS_ZCODE_DHT_ERR_WIRE_SIZE;
    size_t off = write_header(wire, VCS_ZCODE_DHT_MSG_STORE_RESULT);
    enum vcs_zcode_dht_error e = write_auth(
        wire, &off, m->session_generation, m->sender_node_id, m->query_id,
        &m->delegation);
    if (e != VCS_ZCODE_DHT_OK) return e;
    wire[off++] = (uint8_t)m->status;
    memcpy(wire + off, m->record_digest, 32); off += 32;
    e = sign_frame(wire, off, transcript, online_seed, &m->delegation);
    if (e != VCS_ZCODE_DHT_OK) return e;
    off += VCS_ZCODE_DHT_MSG_SIGNATURE_BYTES;
    *len_out = off;
    return off == VCS_ZCODE_DHT_STORE_RESULT_WIRE_BYTES
               ? VCS_ZCODE_DHT_OK : VCS_ZCODE_DHT_ERR_WIRE_SIZE;
}

static enum vcs_zcode_dht_error verify_signature(
    const uint8_t *wire, size_t unsigned_len, const uint8_t signature[64],
    const uint8_t transcript[32], const uint8_t online_pubkey[32])
{
    uint8_t preimage[sizeof(VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN) + 32 +
                     VCS_ZCODE_DHT_MAX_FRAME_BYTES];
    size_t off = 0;
    memcpy(preimage + off, VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN,
           sizeof(VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN));
    off += sizeof(VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN);
    memcpy(preimage + off, transcript, 32); off += 32;
    memcpy(preimage + off, wire, unsigned_len); off += unsigned_len;
    bool ok = ed25519_verify(signature, preimage, off, online_pubkey);
    memory_cleanse(preimage, off);
    return ok ? VCS_ZCODE_DHT_OK : VCS_ZCODE_DHT_ERR_SIGNATURE;
}

static enum vcs_zcode_dht_error read_auth(
    const uint8_t *wire, size_t *off,
    const struct vcs_zcode_dht_msg_verify_context *v, uint64_t *generation,
    uint8_t sender[32], uint8_t query[16],
    struct vcs_zcode_dht_delegation *delegation)
{
    *generation = zcl_read_u64_le(wire + *off); *off += 8;
    memcpy(sender, wire + *off, 32); *off += 32;
    memcpy(query, wire + *off, 16); *off += 16;
    if (!*generation || !zcl_bytes_any_set(sender, 32)) return VCS_ZCODE_DHT_ERR_ID_ZERO;
    if (!zcl_bytes_any_set(query, 16)) return VCS_ZCODE_DHT_ERR_QUERY_ID;
    if (vcs_zcode_dht_delegation_decode(delegation, wire + *off,
            VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES) !=
        VCS_ZCODE_DHT_DELEGATION_OK) return VCS_ZCODE_DHT_ERR_DELEGATION;
    *off += VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES;
    if (!v->noise_established || !zcl_bytes_any_set(v->noise_transcript_hash, 32))
        return VCS_ZCODE_DHT_ERR_SESSION;
    if (vcs_zcode_dht_delegation_verify(
            delegation, v->network_genesis, v->remote_noise_static, 0, NULL,
            v->now_unix) != VCS_ZCODE_DHT_DELEGATION_OK ||
        (v->chain_verify && !v->chain_verify(v->chain_ctx, delegation)))
        return VCS_ZCODE_DHT_ERR_DELEGATION;
    uint8_t derived[32];
    if (!vcs_zcode_dht_delegation_node_id(derived, delegation) ||
        memcmp(derived, sender, 32) != 0)
        return VCS_ZCODE_DHT_ERR_IDENTITY;
    return VCS_ZCODE_DHT_OK;
}

static enum vcs_zcode_dht_error read_selector(
    const uint8_t *wire, struct vcs_zcode_dht_record_selector *selector)
{
    uint8_t kind = wire[0], length = wire[1];
    if (kind < VCS_ZCODE_DHT_RECORD_PROVIDER ||
        kind > VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK || !length ||
        length > VCS_ZCODE_DHT_RECORD_NAMESPACE_MAX)
        return VCS_ZCODE_DHT_ERR_WIRE_ORDER;
    selector->kind = (enum vcs_zcode_dht_record_kind)kind;
    memcpy(selector->namespace_name, wire + 2, length);
    for (size_t i = length; i < VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES; i++)
        if (wire[2 + i] != 0) return VCS_ZCODE_DHT_ERR_WIRE_ORDER;
    memcpy(selector->root,
           wire + 2 + VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES, 32);
    return selector_valid(selector) ? VCS_ZCODE_DHT_OK
                                    : VCS_ZCODE_DHT_ERR_WIRE_ORDER;
}

static enum vcs_zcode_dht_error record_parse_error(
    enum vcs_zcode_dht_record_error error)
{
    if (error == VCS_ZCODE_DHT_RECORD_EXPIRED)
        return VCS_ZCODE_DHT_ERR_EXPIRED;
    if (error == VCS_ZCODE_DHT_RECORD_NETWORK)
        return VCS_ZCODE_DHT_ERR_NETWORK;
    if (error == VCS_ZCODE_DHT_RECORD_SIGNATURE)
        return VCS_ZCODE_DHT_ERR_SIGNATURE;
    if (error == VCS_ZCODE_DHT_RECORD_PROVIDER_ID ||
        error == VCS_ZCODE_DHT_RECORD_SIGNER)
        return VCS_ZCODE_DHT_ERR_IDENTITY;
    if (error == VCS_ZCODE_DHT_RECORD_NOT_YET_VALID ||
        error == VCS_ZCODE_DHT_RECORD_WINDOW)
        return VCS_ZCODE_DHT_ERR_DELEGATION;
    return VCS_ZCODE_DHT_ERR_WIRE_ORDER;
}

enum vcs_zcode_dht_error vcs_zcode_dht_msg_parse(
    const uint8_t *wire, size_t len,
    const struct vcs_zcode_dht_msg_verify_context *v,
    struct vcs_zcode_dht_msg *out)
{
    if (!wire || !v || !out) return VCS_ZCODE_DHT_ERR_NULL;
    memset(out, 0, sizeof(*out));
    /* Parse into a private scratch object. No authenticated-looking prefix is
     * ever observable after a late signature/session/order rejection. */
    struct vcs_zcode_dht_msg parsed;
    memset(&parsed, 0, sizeof(parsed));
    struct vcs_zcode_dht_msg *dst = &parsed;
    if (len < VCS_ZCODE_DHT_MSGS_HEADER_BYTES + VCS_ZCODE_DHT_MSGS_AUTH_BYTES +
              VCS_ZCODE_DHT_MSG_SIGNATURE_BYTES)
        return VCS_ZCODE_DHT_ERR_WIRE_SIZE;
    if (memcmp(wire, msgs_magic, 8) != 0) return VCS_ZCODE_DHT_ERR_WIRE_MAGIC;
    if (zcl_read_u16_le(wire + 8) != VCS_ZCODE_DHT_MSGS_WIRE_VERSION)
        return VCS_ZCODE_DHT_ERR_VERSION;
    uint8_t kind = wire[10];
    if (kind < VCS_ZCODE_DHT_MSG_FIND_NODE ||
        kind > VCS_ZCODE_DHT_MSG_STORE_RESULT)
        return VCS_ZCODE_DHT_ERR_WIRE_KIND;
    const size_t payload_off = VCS_ZCODE_DHT_MSGS_HEADER_BYTES +
                               VCS_ZCODE_DHT_MSGS_AUTH_BYTES;
    uint32_t count = 0;
    if (kind == VCS_ZCODE_DHT_MSG_FIND_NODE) {
        if (len != VCS_ZCODE_DHT_FIND_NODE_WIRE_BYTES)
            return VCS_ZCODE_DHT_ERR_WIRE_SIZE;
    } else if (kind == VCS_ZCODE_DHT_MSG_NODES) {
        if (payload_off >= len - VCS_ZCODE_DHT_MSG_SIGNATURE_BYTES)
            return VCS_ZCODE_DHT_ERR_WIRE_SIZE;
        count = wire[payload_off];
        if (count > VCS_ZCODE_DHT_K)
            return VCS_ZCODE_DHT_ERR_LIMIT;
        size_t expected = payload_off + 1 + (size_t)count * 32 +
                          VCS_ZCODE_DHT_MSG_SIGNATURE_BYTES;
        if (len != expected)
            return VCS_ZCODE_DHT_ERR_WIRE_SIZE;
    } else if (kind == VCS_ZCODE_DHT_MSG_FIND_RECORD) {
        if (len != VCS_ZCODE_DHT_FIND_RECORD_WIRE_BYTES)
            return VCS_ZCODE_DHT_ERR_WIRE_SIZE;
    } else if (kind == VCS_ZCODE_DHT_MSG_RECORDS) {
        size_t count_offset = payload_off +
                              VCS_ZCODE_DHT_RECORD_SELECTOR_BYTES + 2u;
        if (count_offset >= len - VCS_ZCODE_DHT_MSG_SIGNATURE_BYTES)
            return VCS_ZCODE_DHT_ERR_WIRE_SIZE;
        count = wire[count_offset];
        if (count > VCS_ZCODE_DHT_RECORDS_PER_FRAME)
            return VCS_ZCODE_DHT_ERR_LIMIT;
        size_t expected = count_offset + 1u +
                          (size_t)count * VCS_ZCODE_DHT_RECORD_WIRE_BYTES +
                          VCS_ZCODE_DHT_MSG_SIGNATURE_BYTES;
        if (len != expected) return VCS_ZCODE_DHT_ERR_WIRE_SIZE;
    } else if (kind == VCS_ZCODE_DHT_MSG_STORE_RECORD) {
        if (len != VCS_ZCODE_DHT_STORE_RECORD_WIRE_BYTES)
            return VCS_ZCODE_DHT_ERR_WIRE_SIZE;
    } else if (len != VCS_ZCODE_DHT_STORE_RESULT_WIRE_BYTES) {
        return VCS_ZCODE_DHT_ERR_WIRE_SIZE;
    }
    size_t off = VCS_ZCODE_DHT_MSGS_HEADER_BYTES;
    uint64_t *generation = NULL;
    uint8_t *sender = NULL, *query = NULL;
    struct vcs_zcode_dht_delegation *delegation = NULL;
    switch ((enum vcs_zcode_dht_msg_kind)kind) {
    case VCS_ZCODE_DHT_MSG_FIND_NODE:
        generation = &dst->find_node.session_generation;
        sender = dst->find_node.sender_node_id;
        query = dst->find_node.query_id;
        delegation = &dst->find_node.delegation;
        break;
    case VCS_ZCODE_DHT_MSG_NODES:
        generation = &dst->nodes.session_generation;
        sender = dst->nodes.sender_node_id;
        query = dst->nodes.query_id;
        delegation = &dst->nodes.delegation;
        break;
    case VCS_ZCODE_DHT_MSG_FIND_RECORD:
        generation = &dst->find_record.session_generation;
        sender = dst->find_record.sender_node_id;
        query = dst->find_record.query_id;
        delegation = &dst->find_record.delegation;
        break;
    case VCS_ZCODE_DHT_MSG_RECORDS:
        generation = &dst->records.session_generation;
        sender = dst->records.sender_node_id;
        query = dst->records.query_id;
        delegation = &dst->records.delegation;
        break;
    case VCS_ZCODE_DHT_MSG_STORE_RECORD:
        generation = &dst->store_record.session_generation;
        sender = dst->store_record.sender_node_id;
        query = dst->store_record.query_id;
        delegation = &dst->store_record.delegation;
        break;
    case VCS_ZCODE_DHT_MSG_STORE_RESULT:
        generation = &dst->store_result.session_generation;
        sender = dst->store_result.sender_node_id;
        query = dst->store_result.query_id;
        delegation = &dst->store_result.delegation;
        break;
    }
    enum vcs_zcode_dht_error e = read_auth(
        wire, &off, v, generation, sender, query, delegation);
    if (e != VCS_ZCODE_DHT_OK) return e;
    size_t unsigned_len = len - VCS_ZCODE_DHT_MSG_SIGNATURE_BYTES;
    e = verify_signature(wire, unsigned_len, wire + unsigned_len,
                         v->noise_transcript_hash,
                         delegation->online_pubkey);
    if (e != VCS_ZCODE_DHT_OK) return e;
    if (*generation != v->session_generation) return VCS_ZCODE_DHT_ERR_SESSION;
    if (kind == VCS_ZCODE_DHT_MSG_FIND_NODE) {
        memcpy(dst->find_node.target_node_id, wire + off, 32); off += 32;
        if (!zcl_bytes_any_set(dst->find_node.target_node_id, 32))
            return VCS_ZCODE_DHT_ERR_ID_ZERO;
    } else if (kind == VCS_ZCODE_DHT_MSG_NODES) {
        off++;
        for (uint32_t i = 0; i < count; i++) {
            memcpy(dst->nodes.node_ids[i], wire + off, 32); off += 32;
            if (!zcl_bytes_any_set(dst->nodes.node_ids[i], 32))
                return VCS_ZCODE_DHT_ERR_ID_ZERO;
            if (i && memcmp(dst->nodes.node_ids[i - 1],
                            dst->nodes.node_ids[i], 32) >= 0)
                return VCS_ZCODE_DHT_ERR_WIRE_ORDER;
        }
        dst->nodes.contact_count = count;
    } else if (kind == VCS_ZCODE_DHT_MSG_FIND_RECORD) {
        e = read_selector(wire + off, &dst->find_record.selector);
        if (e != VCS_ZCODE_DHT_OK) return e;
        off += VCS_ZCODE_DHT_RECORD_SELECTOR_BYTES;
        dst->find_record.page_offset = wire[off++];
        if (dst->find_record.page_offset >=
                VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_ROOT ||
            dst->find_record.page_offset %
                VCS_ZCODE_DHT_RECORDS_PER_FRAME != 0)
            return VCS_ZCODE_DHT_ERR_WIRE_ORDER;
    } else if (kind == VCS_ZCODE_DHT_MSG_RECORDS) {
        e = read_selector(wire + off, &dst->records.selector);
        if (e != VCS_ZCODE_DHT_OK) return e;
        off += VCS_ZCODE_DHT_RECORD_SELECTOR_BYTES;
        dst->records.page_offset = wire[off++];
        dst->records.next_offset = wire[off++];
        off++;
        if (dst->records.page_offset >=
                VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_ROOT ||
            dst->records.page_offset % VCS_ZCODE_DHT_RECORDS_PER_FRAME != 0 ||
            (dst->records.next_offset &&
             (dst->records.next_offset !=
                  dst->records.page_offset +
                      VCS_ZCODE_DHT_RECORDS_PER_FRAME ||
              dst->records.next_offset >=
                  VCS_ZCODE_DHT_RECORD_STORE_MAX_PER_ROOT ||
              count != VCS_ZCODE_DHT_RECORDS_PER_FRAME)))
            return VCS_ZCODE_DHT_ERR_WIRE_ORDER;
        struct vcs_zcode_dht_record_verify_context record_verify = {
            .now_unix = v->now_unix,
            .chain_verify = v->chain_verify,
            .chain_ctx = v->chain_ctx,
        };
        memcpy(record_verify.network_genesis, v->network_genesis, 32);
        for (uint32_t i = 0; i < count; i++) {
            if (i && memcmp(wire + off - VCS_ZCODE_DHT_RECORD_WIRE_BYTES,
                            wire + off,
                            VCS_ZCODE_DHT_RECORD_WIRE_BYTES) >= 0)
                return VCS_ZCODE_DHT_ERR_WIRE_ORDER;
            enum vcs_zcode_dht_record_error record_error =
                vcs_zcode_dht_record_parse(
                    wire + off, VCS_ZCODE_DHT_RECORD_WIRE_BYTES,
                    &record_verify, &dst->records.records[i]);
            if (record_error != VCS_ZCODE_DHT_RECORD_OK)
                return record_parse_error(record_error);
            if (!selector_matches(&dst->records.selector,
                                  &dst->records.records[i]))
                return VCS_ZCODE_DHT_ERR_WIRE_ORDER;
            off += VCS_ZCODE_DHT_RECORD_WIRE_BYTES;
        }
        dst->records.record_count = count;
    } else if (kind == VCS_ZCODE_DHT_MSG_STORE_RECORD) {
        struct vcs_zcode_dht_record_verify_context record_verify = {
            .now_unix = v->now_unix,
            .chain_verify = v->chain_verify,
            .chain_ctx = v->chain_ctx,
        };
        memcpy(record_verify.network_genesis, v->network_genesis, 32);
        enum vcs_zcode_dht_record_error record_error =
            vcs_zcode_dht_record_parse(
                wire + off, VCS_ZCODE_DHT_RECORD_WIRE_BYTES, &record_verify,
                &dst->store_record.record);
        if (record_error != VCS_ZCODE_DHT_RECORD_OK)
            return record_parse_error(record_error);
        off += VCS_ZCODE_DHT_RECORD_WIRE_BYTES;
    } else {
        uint8_t status = wire[off++];
        if (status < VCS_ZCODE_DHT_STORE_STORED ||
            status > VCS_ZCODE_DHT_STORE_REJECTED ||
            !zcl_bytes_any_set(wire + off, 32))
            return VCS_ZCODE_DHT_ERR_WIRE_ORDER;
        dst->store_result.status = (enum vcs_zcode_dht_store_status)status;
        memcpy(dst->store_result.record_digest, wire + off, 32); off += 32;
    }
    dst->kind = (enum vcs_zcode_dht_msg_kind)kind;
    *out = parsed;
    return VCS_ZCODE_DHT_OK;
}
