/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pure parts of `ops host legacy status`: the binary identity check, port
 * conflicts among configured instances, and catch-up rate and ETA from two
 * height samples. No RPC and no wall clock in here; the caller supplies the
 * samples and the time. */
#ifndef ZCL_COMMAND_LEGACY_STATUS_H
#define ZCL_COMMAND_LEGACY_STATUS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum lstat_identity {
    LSTAT_ID_MATCH,
    LSTAT_ID_MISMATCH,
    LSTAT_ID_MISSING,
    LSTAT_ID_UNPINNED
};

const char *lstat_identity_name(enum lstat_identity id);

/* sha256 of `binary` against the pinned lowercase hex (NULL or empty:
 * UNPINNED). `actual` receives the computed digest when the file is read. */
enum lstat_identity lstat_identity(const char *binary, const char *pinned,
                                   char actual[65]);

struct lstat_inst {
    char name[32];
    int port;
    int rpcport;
};

#define LSTAT_CONFLICT_MAX 96
/* Every pair of instances sharing a port number (port or rpcport, in any
 * combination). Writes up to `max` text rows; returns the row count. */
size_t lstat_port_conflicts(const struct lstat_inst *inst, size_t n,
                            char (*rows)[LSTAT_CONFLICT_MAX], size_t max);

struct lstat_rate {
    bool known;
    int64_t blocks_per_min_x100; /* >=0 when known */
    bool eta_known;
    int64_t eta_seconds; /* 0 when gap <= 0 */
};

/* Two samples (height, unix seconds) and the remaining gap. Unknown when the
 * samples are missing, out of order, or the height went backwards. */
struct lstat_rate lstat_rate(int64_t prev_height, int64_t prev_unix,
                             int64_t height, int64_t unix_now, int64_t gap);

enum lstat_creds { LSTAT_CREDS_MATCH, LSTAT_CREDS_MISMATCH, LSTAT_CREDS_UNKNOWN };
const char *lstat_creds_name(enum lstat_creds c);

/* Would the node's legacy mirror, reading `node_conf`, authenticate to the
 * instance whose conf is `instance_conf`? both credential pairs are compared by
 * SHA3-256 digest only and wiped. UNKNOWN when the instance conf has no
 * credentials; MISMATCH when the mirror source lacks them or differs. */
enum lstat_creds lstat_mirror_creds(const char *node_conf,
                                    const char *instance_conf);

/* The file the node's mirror reads: `override_path` (the caller says what the
 * running node uses), else ZCL_LEGACY_ORACLE_CONF of THIS process, else
 * $HOME/.zclassic/zclassic.conf. Returns "input", "env" or "default". */
const char *lstat_node_conf(const char *override_path, char *out, size_t cap);

/* A node with no connections cannot catch up: a seeded datadir has no
 * peers.dat, so it needs an addnode or a dnsseed. True when connections is 0
 * and the node is behind the z23 tip (gap > 0), or its height did not move
 * since the previous sample. */
bool lstat_no_peers(int64_t connections, int64_t height, int64_t z23_height,
                    int64_t prev_height);

#endif /* ZCL_COMMAND_LEGACY_STATUS_H */
