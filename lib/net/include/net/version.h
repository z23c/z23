/* Copyright (c) 2012-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_VERSION_H
#define ZCL_VERSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct p2p_node;

#define PROTOCOL_VERSION 170011
#define INIT_PROTO_VERSION 209
#define GETHEADERS_VERSION 31800
#define MIN_PEER_PROTO_VERSION 170002
#define CADDR_TIME_VERSION 31402
#define BIP0031_VERSION 60000
#define MEMPOOL_GD_VERSION 60002
#define NO_BLOOM_VERSION 170004

void msg_version_set_external_ip(const char *ip_str, uint16_t port);
bool msg_version_get_external_ip(char *buf, size_t buflen, uint16_t *port);
#ifdef ZCL_TESTING
void msg_version_clear_external_ip_for_test(void);
#endif
/* ── Published build identity ──────────────────────────────────────────
 *
 * A node states which build family it is running by appending a stable
 * `(src:<12 hex>)` source-identity prefix
 * comment to its P2P subversion string, e.g.
 *
 *     /ZClassic23:0.1.0(src:3f2a91c8d507)/
 *
 * The value is the first 12 hexadecimal digits of
 * zcl_build_source_id_sha256() — the SHA-256 the build system baked into this
 * executable from the source tree that produced it. The full value remains
 * available through machine-readable local binary identity. The prefix is a
 * compile-time constant: no environment variable, config file, or RPC can
 * change what a running node publishes. It is also content-only (relative
 * paths, file modes, file digests), so it names a BUILD and never an
 * operator: no hostname, user, filesystem path, or network address enters it.
 *
 * Limits of the claim: this is a self-report, not a proof. Anyone who
 * recompiles can advertise any string they like. It is therefore INFORMATION
 * and never a gate — nothing about connectivity, scoring, banning, relay, or
 * acceptance may read it. A peer that publishes no identity (an older build,
 * a different implementation) is "unknown", which is a normal answer.
 *
 * Limit on privacy, stated because it decides who should publish what: the
 * value names no operator, but it is still a token, and a token only a few
 * nodes publish links those nodes. Every node built from the same source
 * publishes the SAME hex and is anonymous inside that set; a node built from
 * a locally modified tree publishes a hex only its own boxes have, so an
 * observer who sees it at two onion addresses learns those two came from one
 * builder. That is the unavoidable cost of stating a build at all. The remedy
 * is to run a build other people also run — never a switch that lets a node
 * claim one, which would turn this field from a fact into a lie.
 *
 * All four entry points below are thread-safe and never allocate or log.
 * The three readers are pure; msg_version_user_agent() returns a pointer to a
 * buffer formatted exactly once under pthread_once and never mutated after,
 * so it is safe to call from any thread at any point in the handshake. */
#define ZCL_BUILD_IDENTITY_HEX_LEN 64
#define ZCL_BUILD_IDENTITY_BUFSIZE (ZCL_BUILD_IDENTITY_HEX_LEN + 1)
#define ZCL_BUILD_IDENTITY_PREFIX_HEX_LEN 12
#define ZCL_BUILD_IDENTITY_PREFIX_BUFSIZE \
    (ZCL_BUILD_IDENTITY_PREFIX_HEX_LEN + 1)

/* The subversion string this node advertises in every version message. It is
 * "/ZClassic23:0.1.0(src:<12 hex>)/" when this binary carries an exact baked
 * source identity, and the bare "/ZClassic23:0.1.0/" when it does not (an
 * unstamped standalone build). Never NULL; always shorter than
 * MAX_SUBVERSION_LENGTH. */
const char *msg_version_user_agent(void);

/* This binary's own 64-hex build identity. Writes a NUL-terminated 64-hex
 * string into `out` and returns true when the identity is exact; writes ""
 * and returns false otherwise. `outlen` must be >= ZCL_BUILD_IDENTITY_BUFSIZE.
 * A false return is "this build is not stamped", never an error. */
bool msg_version_local_build_identity(char *out, size_t outlen);

/* Read a PEER's legacy full build identity out of the subversion string it
 * sent.
 * Returns true and writes 64 lowercase hex + NUL into `out` when the peer
 * published a well-formed identity; returns false and writes "" when it did
 * not — an absent, empty, or malformed token is "unknown", which is a normal
 * answer for a peer and must never be turned into a penalty. `subver` is
 * untrusted remote input; the value produced from it is display-only.
 * When a subversion carries more than one `(src:...)` comment the FIRST
 * well-formed one wins (the same anchor-on-first rule
 * tools/scripts/source_identity_lib.sh documents for the JSON reader). */
bool msg_version_parse_build_identity(const char *subver, char *out,
                                      size_t outlen);

/* Read the compact source prefix a peer publishes. The current 12-hex wire
 * form is accepted directly; the first 12 digits of the legacy 64-hex form
 * are also returned so mixed-version fleets remain comparable. */
bool msg_version_parse_build_identity_prefix(const char *subver, char *out,
                                             size_t outlen);

bool msg_version_classify_peer(const char *subver, uint64_t services,
                               bool *is_magicbean, bool *is_zcl23);
bool msg_version_peer_uses_external_host(const struct p2p_node *node);

#endif
