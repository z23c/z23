/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Quorum oracle (T2.2) — multi-source consensus on (height → hash).
 *
 * Generalises the zclassicd-only `zclassicd_oracle_service` into a
 * pluggable N-source vote. Today wires two sources:
 *
 *   QO_SRC_LOCAL       — our own active_chain at the probed height
 *   QO_SRC_ZCLASSICD   — RPC getblockhash against the local zclassicd
 *
 * QO_SRC_PEER is populated from the latest recently accepted zclassic23
 * header per peer via quorum_oracle_record_peer_header_vote(). Lower historical
 * repair pages never downgrade or refresh that current-height evidence.
 *
 * Verdict logic:
 *   - If at least `min_agree` non-error sources return the same hash,
 *     the quorum matches.
 *   - If two sources return DIFFERENT non-error hashes, the quorum
 *     disagrees and oracle_policy is fed the disagreement.
 *
 * Callers that need stronger trust than "zclassicd only" (e.g.
 * rolling-anchor window commit) should consult this service. */

#ifndef ZCL_SERVICES_QUORUM_ORACLE_SERVICE_H
#define ZCL_SERVICES_QUORUM_ORACLE_SERVICE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "util/result.h"

struct json_value;

enum quorum_oracle_source {
    QO_SRC_LOCAL     = 0,
    QO_SRC_ZCLASSICD = 1,
    QO_SRC_PEER      = 2,
    QO_SRC_NUM       = 3,
};

struct quorum_oracle_source_result {
    bool present;                /* did this source contribute a hash? */
    bool error;                  /* present && error → RPC/IO failure */
    char hash_hex[65];           /* lowercased, NUL-terminated */
    int peer_count;              /* QO_SRC_PEER: unique live peers in vote */
};

enum quorum_oracle_verdict {
    QO_VERDICT_NO_DATA       = 0, /* not enough sources contributed */
    QO_VERDICT_QUORUM_MATCH  = 1, /* min_agree sources concur */
    QO_VERDICT_QUORUM_SPLIT  = 2, /* sources disagree */
};

struct quorum_oracle_result {
    int height;
    struct quorum_oracle_source_result by_source[QO_SRC_NUM];
    enum quorum_oracle_verdict verdict;
    int agreeing_sources;        /* how many produced the winning hash */
    char winning_hash_hex[65];   /* set on QO_VERDICT_QUORUM_MATCH */
};

struct quorum_oracle_config {
    int min_agree;               /* default 2 */
};

void quorum_oracle_init(const struct quorum_oracle_config *cfg);

/* Synchronous probe. Returns ZCL_OK on a completed probe (verdict +
 * per-source fields populated in *out, including QO_VERDICT_NO_DATA);
 * returns non-ok only on logic-level argument failure (NULL out,
 * negative height). On QO_VERDICT_QUORUM_SPLIT the disagreement is
 * forwarded to oracle_policy. */
struct zcl_result quorum_oracle_probe(int height, struct quorum_oracle_result *out);

void quorum_oracle_record_peer_header_vote(uint32_t peer_id,
                                           int height,
                                           const char hash_hex[65]);

bool quorum_oracle_dump_state_json(struct json_value *out, const char *key);

/* ── Read-only peer-vote copy-out (observation surfaces) ─────────────────
 *
 * One row per live peer-header vote the oracle has registered. This is a
 * pure copy-out under the oracle's own leaf lock: it reads nothing else,
 * writes nothing, and touches neither the tally nor the verdict. Added for
 * services/mesh_observation.h, which republishes each row as a peer CLAIM —
 * explicitly labelled as a claim, and cross-checked by the emitter against
 * its own chain before anything downstream sees it.
 *
 * It deliberately does NOT expose or influence the quorum verdict. The
 * oracle's own 2-of-3 shape (QO_SRC_LOCAL and QO_SRC_ZCLASSICD are the same
 * box, and every peer collapses to one vote) is a separate defect on a
 * separate lane; nothing here is a workaround for it. */
#define QO_PEER_VOTE_VIEW_MAX 64

struct qo_peer_vote_view {
    uint32_t peer_id;
    int      height;
    char     hash_hex[65];
    int64_t  unix_time;   /* wall clock when the vote was recorded */
};

/* Copies up to `max` present votes into out[]; returns the number copied. */
int quorum_oracle_peer_votes_snapshot(struct qo_peer_vote_view *out,
                                      size_t max);

#ifdef ZCL_TESTING
/* Clear only the in-memory peer-vote register. Tests use this to prove its
 * bounded replacement semantics without resetting unrelated oracle policy or
 * probe counters. */
void quorum_oracle_peer_votes_reset_for_test(void);
#endif

#endif /* ZCL_SERVICES_QUORUM_ORACLE_SERVICE_H */
