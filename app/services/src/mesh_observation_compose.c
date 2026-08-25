// one-result-type-ok:pure-fold-no-fallible-service-surface — one pure
// function plus two name lookups; no I/O, and an input it cannot evaluate
// produces MESH_UNVERIFIED with a named basis, which is a RESULT not an error.
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * mesh_observation_compose() — how ANY reader derives a conclusion from the
 * observation records it collected.
 *
 * PURE. No I/O, no locks, no allocation, no globals, no clock read (the
 * reader passes now_unix). Every reader running this build over the same N
 * records and the same chain gets the same answer, and can replay it offline
 * from saved documents. There is no privileged party anywhere in it: the
 * reader's own record is simply slot 0, and slot ORDER changes nothing.
 *
 * WHAT THIS FUNCTION DELIBERATELY CANNOT SEE
 * ------------------------------------------
 * Its signature takes slots, a reader chain, a two-field budget and a clock
 * value. It receives no latency measurement and no self-declared hardware
 * capability of any kind. On this fleet two boxes are seek-bound spinning
 * disks at 91% IO pressure; a threshold that graded them failed for being
 * slow would be a hardware franchise, i.e. another authority. Here that is
 * not a promise to be careful — the inputs do not exist, so it does not
 * compile. A source-inspection test in the suite pins that, so a future edit
 * that plumbs a latency or capability field in fails the build's own gate.
 *
 * The only route by which slowness touches a conclusion is COVERAGE: a slow
 * node's document arrives late or not at all, which lowers records_fresh,
 * which moves the result toward UNVERIFIED. There is no arithmetic path from
 * "a node was slow" to "a node was wrong".
 *
 * THE ALGORITHM, IN ORDER. Each step may only REFUSE; none may upgrade a
 * later step's result, and no path returns AGREEING without having executed
 * every step before it.
 *
 *   0  nothing is assumed          -> zeroed, UNVERIFIED, "not_evaluated"
 *   1  coverage                    -> zero fresh records returns UNVERIFIED
 *   2  independence (by identity)  -> too few distinct returns UNVERIFIED
 *   3  pick a checkable height     -> none returns UNVERIFIED
 *   4  RECOMPUTE against our chain -> agree / disagree / no_common_height
 *   5  adjacency                   -> reported, and it never feeds the state
 *   6  the state, from step 4 only
 */

#include "services/mesh_observation.h"

#include <stdio.h>
#include <string.h>

const char *mesh_state_name(enum mesh_state s)
{
    switch (s) {
    case MESH_UNVERIFIED:  return "unverified";
    case MESH_AGREEING:    return "agreeing";
    case MESH_DISAGREEING: return "disagreeing";
    case MESH_SPLIT_VIEW:  return "split_view";
    case MESH_STATE_NUM:   break;
    }
    return "unverified";
}

void mesh_compose_budget_defaults(struct mesh_compose_budget *b)
{
    if (!b)
        return;
    b->freshness_secs  = MESH_OBS_FRESHNESS_SECS_DEFAULT;
    b->min_independent = MESH_OBS_MIN_INDEPENDENT_DEFAULT;
}

/* ── small pure helpers ─────────────────────────────────────────────── */

static bool hex64_ok(const char *s)
{
    if (!s)
        return false;
    size_t i = 0;
    for (; i < 64; i++) {
        char c = s[i];
        bool d = (c >= '0' && c <= '9');
        bool l = (c >= 'a' && c <= 'f');
        bool u = (c >= 'A' && c <= 'F');
        if (!d && !l && !u)
            return false;
    }
    return s[64] == '\0';
}

static char lower_of(char c)
{
    return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
}

/* Byte comparison over two validated 64-hex strings, case-insensitive.
 * Returns <0, 0, >0 like memcmp so it doubles as the chainwork ordering. */
static int hex64_cmp(const char *a, const char *b)
{
    for (size_t i = 0; i < 64; i++) {
        unsigned char ca = (unsigned char)lower_of(a[i]);
        unsigned char cb = (unsigned char)lower_of(b[i]);
        if (ca != cb)
            return ca < cb ? -1 : 1;
    }
    return 0;
}

/* Freshness is recomputed wherever it is needed rather than cached in a
 * per-slot array, so this function allocates nothing for any N. */
static bool slot_is_fresh(const struct mesh_obs_slot *s, int64_t freshness_secs,
                          int64_t now_unix)
{
    if (!s || !s->parsed)
        return false;
    int64_t t = s->rec.self.sampled_unix;
    if (t <= 0)
        return false;
    int64_t age = now_unix - t;
    if (age < 0)
        age = -age;   /* a clock skew in either direction is still an age */
    return age <= freshness_secs;
}

/* This record's own hash at `height`, from its tip or its anchor ladder.
 * Returns false when the record says nothing about that height — which is
 * evidence NEITHER way. */
static bool record_hash_at(const struct mesh_observation *rec, int64_t height,
                           const char **out)
{
    if (!rec || height < 0)
        return false;
    if (rec->self.tip_height == height && hex64_ok(rec->self.tip_hash_hex)) {
        *out = rec->self.tip_hash_hex;
        return true;
    }
    for (int r = 0; r < MESH_OBS_ANCHORS; r++) {
        const struct mesh_obs_anchor *a = &rec->self.anchors[r];
        if (a->present && a->height == height && hex64_ok(a->hash_hex)) {
            *out = a->hash_hex;
            return true;
        }
    }
    return false;
}

/* An identity string for a fresh record: its onion, falling back to its
 * build source_id when it publishes no onion. Empty means "no identity
 * published", and such a record contributes to no distinct count. */
static const char *record_identity(const struct mesh_observation *rec)
{
    if (rec->self.onion[0])
        return rec->self.onion;
    if (rec->self.source_id[0])
        return rec->self.source_id;
    return "";
}

/* How many fresh records publish a hash at `height`. */
static int supporters_at(const struct mesh_obs_slot *slots, size_t n,
                         int64_t freshness_secs, int64_t now_unix,
                         int64_t height)
{
    int count = 0;
    for (size_t i = 0; i < n; i++) {
        if (!slot_is_fresh(&slots[i], freshness_secs, now_unix))
            continue;
        const char *h = NULL;
        if (record_hash_at(&slots[i].rec, height, &h))
            count++;
    }
    return count;
}

/* ── the fold ───────────────────────────────────────────────────────── */

void mesh_observation_compose(const struct mesh_obs_slot *slots, size_t n,
                              const struct mesh_reader_chain *reader,
                              const struct mesh_compose_budget *budget,
                              int64_t now_unix,
                              struct mesh_conclusion *out)
{
    if (!out)
        return;

    /* Step 0 — nothing is assumed. Every early return below leaves the
     * state exactly as it is set here. */
    memset(out, 0, sizeof(*out));
    out->state = MESH_UNVERIFIED;
    out->checked_height = -1;
    snprintf(out->basis, sizeof(out->basis), "%s", "not_evaluated");

    struct mesh_compose_budget b;
    mesh_compose_budget_defaults(&b);
    if (budget) {
        if (budget->freshness_secs > 0)
            b.freshness_secs = budget->freshness_secs;
        if (budget->min_independent > 0)
            b.min_independent = budget->min_independent;
    }
    out->min_independent_required = (int32_t)b.min_independent;

    if (!slots)
        n = 0;
    out->records_offered = (int32_t)n;

    /* ── Step 1 — coverage. Every slot lands in exactly one bucket. ──── */
    for (size_t i = 0; i < n; i++) {
        const struct mesh_obs_slot *s = &slots[i];
        if (s->fetch == MESH_OBS_NOT_PROBED) {
            out->records_not_probed++;      /* I did not look. Not a failure. */
            continue;
        }
        if (!s->parsed) {
            /* A named refusal is a malformed document; anything else that
             * came back unusable — including a spent budget — is SILENCE,
             * and silence is never counter-evidence. */
            if (s->refusal[0])
                out->records_malformed++;
            else
                out->records_silent++;
            continue;
        }
        out->records_parsed++;
        if (slot_is_fresh(s, b.freshness_secs, now_unix))
            out->records_fresh++;
        else
            out->records_stale++;
    }

    if (out->records_fresh == 0) {
        /* R4: a conclusion over zero items is UNVERIFIED, never healthy. */
        snprintf(out->basis, sizeof(out->basis), "%s", "no_fresh_records");
        return;
    }

    /* ── Step 2 — independence, BY IDENTITY, not by address group. ─────
     *
     * net_addr_get_group() returns the identical key for every torv3
     * address, so a ">= 2 distinct groups" bar is unreachable on an
     * onion-only fleet — the exact shape of unreachable gate this surface
     * exists to stop rebuilding. Identity here is the published onion (the
     * torv3 address IS an ed25519 public key), falling back to the build
     * source_id. */
    for (size_t i = 0; i < n; i++) {
        if (!slot_is_fresh(&slots[i], b.freshness_secs, now_unix))
            continue;
        const char *id = record_identity(&slots[i].rec);
        if (!id[0])
            continue;
        bool seen_before = false;
        for (size_t j = 0; j < i && !seen_before; j++) {
            if (!slot_is_fresh(&slots[j], b.freshness_secs, now_unix))
                continue;
            const char *jd = record_identity(&slots[j].rec);
            if (jd[0] && strcmp(jd, id) == 0)
                seen_before = true;
        }
        if (!seen_before)
            out->distinct_identities++;
    }

    if (out->distinct_identities < out->min_independent_required) {
        /* A node alone is not a failure and not an error. It keeps
         * validating and keeps following the most-work valid-PoW chain
         * exactly as before; "I cannot corroborate" is the true statement. */
        snprintf(out->basis, sizeof(out->basis), "%s",
                 out->distinct_identities == 1
                     ? "only_self"
                     : "insufficient_independent_records");
        return;
    }

    /* ── Step 3 — pick the checkable height. ───────────────────────────
     *
     * Deepest rung first (back=144 -> back=0): a deep rung is the one most
     * likely to be common across records and the least likely to be
     * churning under a reorg. Within one rung the SMALLEST qualifying
     * height wins, which makes the choice a minimum over a set and
     * therefore independent of slot order. */
    int64_t chosen = -1;
    bool reader_usable = reader && reader->hash_at;
    char reader_hash[MESH_OBS_HEXHASH];
    reader_hash[0] = '\0';

    for (int r = MESH_OBS_ANCHORS - 1; r >= 0 && chosen < 0; r--) {
        int64_t best = -1;
        char best_hash[MESH_OBS_HEXHASH];
        best_hash[0] = '\0';
        if (!reader_usable)
            break;
        for (size_t i = 0; i < n; i++) {
            if (!slot_is_fresh(&slots[i], b.freshness_secs, now_unix))
                continue;
            const struct mesh_obs_anchor *a = &slots[i].rec.self.anchors[r];
            if (!a->present || a->height < 0 || !hex64_ok(a->hash_hex))
                continue;
            if (best >= 0 && a->height >= best)
                continue;   /* prune: we want the smallest qualifying height */
            if (supporters_at(slots, n, b.freshness_secs, now_unix,
                              a->height) < out->min_independent_required)
                continue;
            char probe[MESH_OBS_HEXHASH];
            probe[0] = '\0';
            if (!reader->hash_at(reader->ctx, a->height, probe))
                continue;
            if (!hex64_ok(probe))
                continue;   /* the reader's own answer must be well-formed */
            best = a->height;
            memcpy(best_hash, probe, sizeof(best_hash));
        }
        if (best >= 0) {
            chosen = best;
            memcpy(reader_hash, best_hash, sizeof(reader_hash));
        }
    }

    if (chosen < 0) {
        /* The honest case for a reader that is far behind, or that holds no
         * chain at all: "I cannot check". Never "they disagree", and never
         * "we agree". */
        out->no_common_height = out->records_fresh;
        snprintf(out->basis, sizeof(out->basis), "%s",
                 "no_common_checkable_height");
        return;
    }

    /* ── Step 4 — RECOMPUTE. ───────────────────────────────────────────
     *
     * The READER's own hash is the comparison basis. No record's hash is
     * ever compared to another record's hash — that is what makes this a
     * recomputation rather than a poll. */
    out->checked_height = chosen;
    memcpy(out->reader_hash_at_checked, reader_hash,
           sizeof(out->reader_hash_at_checked));

    for (size_t i = 0; i < n; i++) {
        if (!slot_is_fresh(&slots[i], b.freshness_secs, now_unix))
            continue;
        const char *theirs = NULL;
        if (!record_hash_at(&slots[i].rec, chosen, &theirs)) {
            out->no_common_height++;
            continue;
        }
        if (hex64_cmp(theirs, reader_hash) == 0)
            out->agree_at_anchor++;
        else
            out->disagree_at_anchor++;
    }

    /* ── Step 5 — adjacency. Reported, never a state input. ────────────
     *
     * A's edge to B and B's edge to A are both claims. An edge both sides
     * assert is reciprocated; an edge only one side asserts is a claim
     * about a third party that the third party did not confirm, and it
     * counts toward nothing. The matrix exists only here, in a reader's
     * composition of N rows — nobody publishes it. */
    for (size_t i = 0; i < n; i++) {
        if (!slot_is_fresh(&slots[i], b.freshness_secs, now_unix))
            continue;
        const struct mesh_observation *ri = &slots[i].rec;
        const char *my_id = ri->self.onion;
        int ec = ri->edge_count;
        if (ec < 0)
            ec = 0;
        if (ec > MESH_OBS_EDGES_MAX)
            ec = MESH_OBS_EDGES_MAX;

        for (int e = 0; e < ec; e++) {
            const struct mesh_obs_edge *ed = &ri->edges[e];
            out->edges_asserted++;

            /* Find the named counterparty among the fresh records. */
            const struct mesh_observation *rc = NULL;
            if (ed->peer_onion[0]) {
                for (size_t j = 0; j < n && !rc; j++) {
                    if (j == i)
                        continue;
                    if (!slot_is_fresh(&slots[j], b.freshness_secs, now_unix))
                        continue;
                    if (slots[j].rec.self.onion[0] &&
                        strcmp(slots[j].rec.self.onion, ed->peer_onion) == 0)
                        rc = &slots[j].rec;
                }
            }

            bool reciprocated = false;
            if (rc && my_id[0]) {
                int cec = rc->edge_count;
                if (cec < 0)
                    cec = 0;
                if (cec > MESH_OBS_EDGES_MAX)
                    cec = MESH_OBS_EDGES_MAX;
                for (int k = 0; k < cec && !reciprocated; k++) {
                    if (rc->edges[k].peer_onion[0] &&
                        strcmp(rc->edges[k].peer_onion, my_id) == 0)
                        reciprocated = true;
                }
            }
            if (reciprocated)
                out->edges_reciprocated++;
            else
                out->edges_one_sided++;

            /* A third-party claim, cross-checked against that third party's
             * OWN record. A mismatch is an observation the READER derived —
             * about this publisher's honesty or its staleness — not one the
             * publisher supplied. */
            if (rc && ed->claimed_height >= 0 &&
                hex64_ok(ed->claimed_tip_hash_hex)) {
                const char *own = NULL;
                if (record_hash_at(rc, ed->claimed_height, &own) &&
                    hex64_cmp(own, ed->claimed_tip_hash_hex) != 0)
                    out->edges_contradicted++;
            }
        }
    }

    /* Heaviest claimed work, and whether the reader already holds at least
     * that much. Nothing here acts on a claimed chainwork; it is reported so
     * a reader can go fetch and VALIDATE the headers itself, which is the
     * only way it would ever act on the claim. */
    for (size_t i = 0; i < n; i++) {
        if (!slot_is_fresh(&slots[i], b.freshness_secs, now_unix))
            continue;
        const char *w = slots[i].rec.self.tip_chainwork_hex;
        if (!hex64_ok(w))
            continue;
        if (!out->max_chainwork_hex[0] ||
            hex64_cmp(w, out->max_chainwork_hex) > 0)
            memcpy(out->max_chainwork_hex, w, sizeof(out->max_chainwork_hex));
    }
    if (out->max_chainwork_hex[0] && reader &&
        hex64_ok(reader->tip_chainwork_hex))
        out->reader_holds_max_chainwork =
            hex64_cmp(reader->tip_chainwork_hex, out->max_chainwork_hex) >= 0;

    /* ── Step 6 — the state, from step 4 ONLY. ─────────────────────────
     *
     * Disagreement is positive counter-evidence: it cannot be averaged,
     * out-voted, or majority-ruled away. There is deliberately no
     * `if (agree > disagree)` here and no tie-break, because a tie-break
     * would itself be a verdict. Both tallies survive into the output so a
     * reader sees the actual split rather than a winner. */
    if (out->disagree_at_anchor >= 1 && out->agree_at_anchor >= 1)
        out->state = MESH_SPLIT_VIEW;
    else if (out->disagree_at_anchor >= 1)
        out->state = MESH_DISAGREEING;
    else if (out->agree_at_anchor >= out->min_independent_required)
        out->state = MESH_AGREEING;
    else
        out->state = MESH_UNVERIFIED;

    snprintf(out->basis, sizeof(out->basis),
             "agree=%d disagree=%d fresh=%d indep=%d",
             (int)out->agree_at_anchor, (int)out->disagree_at_anchor,
             (int)out->records_fresh, (int)out->distinct_identities);
}
