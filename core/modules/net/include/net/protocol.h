/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2013 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_PROTOCOL_H
#define ZCL_PROTOCOL_H

#include "net/netaddr.h"
#include "core/uint256.h"
#include <stdbool.h>
#include <stdint.h>

#define MESSAGE_START_SIZE 4
#define COMMAND_SIZE 12
#define MAX_SIZE 0x02000000

enum {
    NODE_NETWORK = (1 << 0),
    NODE_BLOOM = (1 << 2),
    /* zclassicd v2.1.2-beta6 fast-bootstrap service bit. A node may only
     * advertise this when it can serve getbsman/bsman + getbschk/bschk
     * snapshot messages; do not set it for ordinary block-serving peers. */
    NODE_BOOTSTRAP = (1 << 24),
    /* zclassic23 Noise-encrypted transport capability. Advertised only when
     * -noisetransport is enabled; a HINT for OUTBOUND gating (the authoritative
     * INBOUND discriminator is the 4-byte magic peek, which no gossip can
     * strip). In the zcl23-reserved high range, same family as NODE_BOOTSTRAP;
     * ignored by zclassicd. */
    NODE_NOISE_TRANSPORT = (1 << 25),
    /* NOTE — file-service (bundle-seeder) capability is NOT a service bit and
     * must not become one. It is advertised by the "zfileaddr" P2P message
     * (sent in core/modules/net/src/msg_version.c after a ZCL23 handshake, handled by
     * handle_zfileaddr in core/modules/net/src/msgprocessor.c), because a service bit
     * carries no PORT and seeders legitimately run on ports other than
     * FS_PORT. Adding a bit here would be a second, weaker mechanism beside
     * the one that already works. */
};

enum {
    MSG_TX = 1,
    MSG_BLOCK,
    MSG_FILTERED_BLOCK,
};

enum {
    MSG_HEADER_SIZE = MESSAGE_START_SIZE + COMMAND_SIZE +
                      (int)sizeof(unsigned int) + (int)sizeof(unsigned int)
};

struct msg_header {
    char pchMessageStart[MESSAGE_START_SIZE];
    char pchCommand[COMMAND_SIZE];
    unsigned int nMessageSize;
    unsigned int nChecksum;
};

struct inv_item {
    int type;
    struct uint256 hash;
};

void msg_header_init(struct msg_header *h,
                     const unsigned char msgstart[MESSAGE_START_SIZE]);

void msg_header_init_full(struct msg_header *h,
                          const unsigned char msgstart[MESSAGE_START_SIZE],
                          const char *command, unsigned int msg_size);

/* Copy the header's command field into out as a NUL-terminated string.
 * Reads at most COMMAND_SIZE bytes (the field is not guaranteed
 * NUL-terminated) and truncates to fit out_size, always writing a
 * trailing NUL. Returns the number of command bytes written (excluding
 * the NUL). Requires out_size >= 1; h and out must be non-NULL. */
int msg_header_get_command(const struct msg_header *h,
                           char *out, size_t out_size);

bool msg_header_is_valid(const struct msg_header *h,
                         const unsigned char msgstart[MESSAGE_START_SIZE]);

/* Zero-initialize inv: type 0, null hash. inv must be non-NULL. */
void inv_item_init(struct inv_item *inv);
/* Set inv to the given type and hash (hash is copied). inv and hash
 * must be non-NULL. */
void inv_item_init_typed(struct inv_item *inv, int type,
                         const struct uint256 *hash);
/* Set inv's type from a type name (e.g. "tx", "block") and copy hash.
 * Returns 0 on a known name; -1 if type_name matches no known type. */
int inv_item_init_by_name(struct inv_item *inv, const char *type_name,
                          const struct uint256 *hash);
/* True if inv->type is a recognized inventory type. */
bool inv_item_is_known_type(const struct inv_item *inv);
/* Return the wire command name for inv's type. Returns the static
 * string "UNKNOWN" if inv is NULL or its type is unrecognized. The
 * returned pointer is a static string and must not be freed. */
const char *inv_item_get_command(const struct inv_item *inv);
/* Format inv as "<command> <hexhash>" into out (NUL-terminated,
 * truncated to out_size). Returns the snprintf result (length that
 * would have been written), or -1 if inv or out is NULL. */
int inv_item_to_string(const struct inv_item *inv, char *out, size_t out_size);
/* Total order over inv items: by type, then by hash. a and b must be
 * non-NULL. */
bool inv_item_less(const struct inv_item *a, const struct inv_item *b);

#define CADDR_TIME_VERSION 31402

struct byte_stream;

bool net_address_serialize(const struct net_address *a, struct byte_stream *s,
                           bool include_time);
bool net_address_deserialize(struct net_address *a, struct byte_stream *s,
                             bool include_time);

bool inv_item_serialize(const struct inv_item *inv, struct byte_stream *s);
bool inv_item_deserialize(struct inv_item *inv, struct byte_stream *s);

#endif
