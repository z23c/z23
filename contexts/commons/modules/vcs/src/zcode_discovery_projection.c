/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zcode_discovery_projection — implementation of the rebuildable
 * discovery-graph projection declared in
 * vcs/zcode_discovery_projection.h. Read-only over the workspace CAS and
 * the S3 science index; never consulted by evidence admission, routing,
 * rewards, or protocol control. */

#include "vcs/zcode_discovery_projection.h"

#include "base/bytes.h"
#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_science.h"
#include "vcs/zcode_science_index.h"

#include <stdlib.h>
#include <string.h>

#define ZDP_LOG "vcs.discovery_projection"

static int zdp_root_cmp(const void *a, const void *b)
{
    return memcmp(a, b, 32);
}

static int zdp_size_cmp(const void *a, const void *b)
{
    size_t sa = *(const size_t *)a, sb = *(const size_t *)b;
    return sa < sb ? -1 : sa > sb ? 1 : 0;
}

/* ── citation-set encoding ───────────────────────────────────────── */

static void zdp_citation_set_hash(const uint8_t *payload, size_t count,
                                  uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)VCS_ZCODE_DISCOVERY_CITATION_SET_DOMAIN,
                   sizeof(VCS_ZCODE_DISCOVERY_CITATION_SET_DOMAIN));
    sha3_256_write(&sha, payload, count * 32u);
    sha3_256_finalize(&sha, out);
}

bool vcs_zcode_discovery_citation_set_encode(
    const uint8_t *roots, size_t root_count, uint8_t *out_payload,
    size_t *out_count, uint8_t out_root[32])
{
    if (!roots || !out_payload || !out_count || !out_root || root_count == 0 ||
        root_count > VCS_ZCODE_DISCOVERY_PROJECTION_MAX_CITATION_SET)
        LOG_FAIL(ZDP_LOG, "citation-set encode: bad args");
    memcpy(out_payload, roots, root_count * 32u);
    qsort(out_payload, root_count, 32, zdp_root_cmp);
    size_t unique = 0;
    for (size_t i = 0; i < root_count; i++) {
        if (unique > 0 &&
            memcmp(out_payload + unique * 32u - 32u, out_payload + i * 32u,
                   32) == 0)
            continue;
        if (unique != i)
            memcpy(out_payload + unique * 32u, out_payload + i * 32u, 32);
        unique++;
    }
    *out_count = unique;
    zdp_citation_set_hash(out_payload, unique, out_root);
    return true;
}

/* Validate a CAS-loaded citation-set payload against its committed root:
 * canonical ascending duplicate-free form, within the size bound, and the
 * recomputed commitment must equal the root the study carries. */
static bool zdp_citation_set_valid(const uint8_t *payload, size_t len,
                                   const uint8_t committed_root[32])
{
    if (!payload || len == 0 || (len % 32u) != 0 ||
        len / 32u > VCS_ZCODE_DISCOVERY_PROJECTION_MAX_CITATION_SET)
        return false;
    for (size_t i = 1; i < len / 32u; i++)
        if (memcmp(payload + (i - 1u) * 32u, payload + i * 32u, 32) >= 0)
            return false;
    uint8_t recomputed[32];
    zdp_citation_set_hash(payload, len / 32u, recomputed);
    return memcmp(recomputed, committed_root, 32) == 0;
}

/* ── corpus snapshot ─────────────────────────────────────────────── */

static void zdp_corpus_absorb_hex(struct sha3_256_ctx *sha, const char *hex)
{
    uint8_t root[32];
    if (zcl_hex_decode_lower(hex, root, 32))
        sha3_256_write(sha, root, 32);
}

bool vcs_zcode_discovery_corpus_root(
    const struct vcs_zcode_science_index *index, uint8_t out[32])
{
    if (!index || !out)
        LOG_FAIL(ZDP_LOG, "corpus root: bad args");
    struct sha3_256_ctx sha;
    uint8_t le[4];
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)VCS_ZCODE_DISCOVERY_CORPUS_DOMAIN,
                   sizeof(VCS_ZCODE_DISCOVERY_CORPUS_DOMAIN));
    size_t counts[6] = {
        vcs_zcode_science_index_study_count(index),
        vcs_zcode_science_index_result_count(index),
        vcs_zcode_science_index_reproduction_count(index),
        vcs_zcode_science_index_findings_count(index),
        vcs_zcode_science_index_vote_count(index),
        vcs_zcode_science_index_review_count(index),
    };
    for (size_t i = 0; i < 6; i++) {
        zcl_write_u32_le(le, (uint32_t)counts[i]);
        sha3_256_write(&sha, le, sizeof(le));
    }
    for (size_t i = 0; i < counts[0]; i++)
        zdp_corpus_absorb_hex(
            &sha, vcs_zcode_science_index_study_at(index, i)->study_root_hex);
    for (size_t i = 0; i < counts[1]; i++)
        zdp_corpus_absorb_hex(
            &sha, vcs_zcode_science_index_result_at(index, i)->result_root_hex);
    for (size_t i = 0; i < counts[2]; i++)
        zdp_corpus_absorb_hex(&sha, vcs_zcode_science_index_reproduction_at(
                                        index, i)->reproduction_root_hex);
    for (size_t i = 0; i < counts[3]; i++)
        zdp_corpus_absorb_hex(&sha, vcs_zcode_science_index_findings_at(
                                        index, i)->findings_root_hex);
    for (size_t i = 0; i < counts[4]; i++)
        zdp_corpus_absorb_hex(
            &sha, vcs_zcode_science_index_vote_at(index, i)->vote_id_hex);
    for (size_t i = 0; i < counts[5]; i++)
        zdp_corpus_absorb_hex(
            &sha, vcs_zcode_science_index_review_at(index, i)->review_root_hex);
    sha3_256_finalize(&sha, out);
    return true;
}

/* ── filter policy commitment ────────────────────────────────────── */

static void zdp_filter_absorb_field(struct sha3_256_ctx *sha,
                                    const char *value)
{
    uint8_t le[2];
    if (!value) {
        zcl_write_u16_le(le, UINT16_MAX);
        sha3_256_write(sha, le, sizeof(le));
        return;
    }
    size_t len = strlen(value);
    if (len > 255u)
        len = 255u;
    zcl_write_u16_le(le, (uint16_t)len);
    sha3_256_write(sha, le, sizeof(le));
    sha3_256_write(sha, (const uint8_t *)value, len);
}

void vcs_zcode_discovery_filter_policy_root(
    const char *search, const char *category, const char *hardware,
    const uint8_t *network_genesis, uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)VCS_ZCODE_DISCOVERY_FILTER_DOMAIN,
                   sizeof(VCS_ZCODE_DISCOVERY_FILTER_DOMAIN));
    zdp_filter_absorb_field(&sha, search);
    zdp_filter_absorb_field(&sha, category);
    zdp_filter_absorb_field(&sha, hardware);
    uint8_t present = network_genesis ? 1u : 0u;
    sha3_256_write(&sha, &present, 1);
    if (network_genesis)
        sha3_256_write(&sha, network_genesis, 32);
    sha3_256_finalize(&sha, out);
}

/* ── union-find over member roots ────────────────────────────────── */

struct zdp_uf {
    uint8_t (*roots)[32];
    size_t *parent;
    size_t count;
    size_t capacity;
};

static bool zdp_uf_grow(struct zdp_uf *uf)
{
    size_t next = uf->capacity ? uf->capacity * 2u : 64u;
    uint8_t(*roots)[32] =
        zcl_realloc(uf->roots, next * sizeof(*roots), "zdp_uf_roots");
    if (!roots)
        LOG_FAIL(ZDP_LOG, "union-find roots grow");
    size_t *parent =
        zcl_realloc(uf->parent, next * sizeof(*parent), "zdp_uf_parent");
    if (!parent) {
        uf->roots = roots; /* keep the grown block; capacity untouched */
        LOG_FAIL(ZDP_LOG, "union-find parent grow");
    }
    uf->roots = roots;
    uf->parent = parent;
    uf->capacity = next;
    return true;
}

/* Find-or-add one root. Returns SIZE_MAX on allocation failure. */
static size_t zdp_uf_add(struct zdp_uf *uf, const uint8_t root[32])
{
    for (size_t i = 0; i < uf->count; i++)
        if (memcmp(uf->roots[i], root, 32) == 0)
            return i;
    if (uf->count == uf->capacity && !zdp_uf_grow(uf))
        return SIZE_MAX;
    size_t idx = uf->count++;
    memcpy(uf->roots[idx], root, 32);
    uf->parent[idx] = idx;
    return idx;
}

static size_t zdp_uf_find(struct zdp_uf *uf, size_t idx)
{
    size_t root = idx;
    while (uf->parent[root] != root)
        root = uf->parent[root];
    while (uf->parent[idx] != root) {
        size_t next = uf->parent[idx];
        uf->parent[idx] = root;
        idx = next;
    }
    return root;
}

static void zdp_uf_union(struct zdp_uf *uf, size_t a, size_t b)
{
    size_t ra = zdp_uf_find(uf, a);
    size_t rb = zdp_uf_find(uf, b);
    if (ra != rb)
        uf->parent[rb] = ra;
}

/* ── dynamic root lists (lineage members / citations) ────────────── */

struct zdp_root_list {
    uint8_t (*roots)[32];
    size_t count;
    size_t capacity;
};

static bool zdp_root_list_add(struct zdp_root_list *list,
                              const uint8_t root[32])
{
    for (size_t i = 0; i < list->count; i++)
        if (memcmp(list->roots[i], root, 32) == 0)
            return true;
    if (list->count == list->capacity) {
        size_t next = list->capacity ? list->capacity * 2u : 16u;
        uint8_t(*roots)[32] =
            zcl_realloc(list->roots, next * sizeof(*roots), "zdp_root_list");
        if (!roots)
            LOG_FAIL(ZDP_LOG, "root list grow");
        list->roots = roots;
        list->capacity = next;
    }
    memcpy(list->roots[list->count++], root, 32);
    return true;
}

static void zdp_root_list_sort(struct zdp_root_list *list)
{
    if (list->count > 1)
        qsort(list->roots, list->count, 32, zdp_root_cmp);
}

/* ── CAS loads (parse + rederived-root agreement, index discipline) ── */

static bool zdp_cas_load(const char *workspace, const uint8_t root[32],
                         uint8_t **wire, size_t *wire_len)
{
    return vcs_object_load_raw(workspace, root, wire, wire_len) == 0;
}

/* Load the study wire addressed by study_root and copy out its citations
 * root. False when the wire is missing or disagrees with its address — the
 * study stays a node, it just contributes no citation edges. */
static bool zdp_study_citations_root(const char *workspace,
                                     const uint8_t study_root[32],
                                     uint8_t citations_root_out[32])
{
    uint8_t *wire = NULL, checked[32];
    size_t len = 0;
    struct vcs_zcode_study_spec_v1 study;
    bool ok = zdp_cas_load(workspace, study_root, &wire, &len) &&
        vcs_zcode_study_spec_parse(wire, len, &study) ==
            VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_study_spec_root(&study, checked) == VCS_ZCODE_SCIENCE_OK &&
        memcmp(checked, study_root, 32) == 0;
    free(wire);
    if (ok)
        memcpy(citations_root_out, study.citations_root, 32);
    return ok;
}

/* Load the lineage's citation-set object and append its targets. */
static bool zdp_absorb_citations(const char *workspace,
                                 const uint8_t citations_root[32],
                                 struct zdp_root_list *out)
{
    if (!zcl_bytes_any_set(citations_root, 32))
        return true; /* nothing committed: no edges, not an error */
    uint8_t *payload = NULL;
    size_t len = 0;
    if (!zdp_cas_load(workspace, citations_root, &payload, &len))
        return true; /* object not in this CAS: no edges */
    bool canonical = zdp_citation_set_valid(payload, len, citations_root);
    if (canonical) {
        for (size_t i = 0; i < len / 32u; i++)
            if (!zdp_root_list_add(out, payload + i * 32u)) {
                free(payload);
                return false;
            }
    }
    free(payload);
    return true;
}

/* Load a candidate wire and union its base/candidate source roots into the
 * study's lineage — the zcode_dev lineage recording (a candidate derives
 * from base_source_root). Parse + rederived-root agreement only. */
static bool zdp_absorb_candidate_lineage(const char *workspace,
                                         const uint8_t candidate_root[32],
                                         const uint8_t study_root[32],
                                         struct zdp_uf *uf)
{
    uint8_t *wire = NULL, checked[32];
    size_t len = 0;
    struct vcs_zcode_candidate_v1 candidate;
    bool ok = zdp_cas_load(workspace, candidate_root, &wire, &len) &&
        vcs_zcode_candidate_parse(wire, len, &candidate) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_candidate_root(&candidate, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(checked, candidate_root, 32) == 0;
    free(wire);
    if (!ok)
        return true; /* no wire here: no lineage hint, not an error */
    size_t study = zdp_uf_add(uf, study_root);
    size_t base = zdp_uf_add(uf, candidate.base_source_root);
    size_t source = zdp_uf_add(uf, candidate.candidate_source_root);
    if (study == SIZE_MAX || base == SIZE_MAX || source == SIZE_MAX)
        return false;
    zdp_uf_union(uf, study, base);
    zdp_uf_union(uf, study, source);
    return true;
}

/* ── allowlist ───────────────────────────────────────────────────── */

static bool zdp_allowlisted(const uint8_t (*allowlist)[32], size_t count,
                            const uint8_t root[32])
{
    if (!allowlist)
        return true;
    size_t lo = 0, hi = count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int cmp = memcmp(root, allowlist[mid], 32);
        if (cmp == 0)
            return true;
        if (cmp < 0)
            hi = mid;
        else
            lo = mid + 1;
    }
    return false;
}

/* ── scan ────────────────────────────────────────────────────────── */

void vcs_zcode_discovery_scan_free(struct vcs_zcode_discovery_scan_v1 *scan)
{
    if (!scan)
        return;
    for (size_t i = 0; i < scan->lineage_count; i++) {
        free(scan->lineages[i].members);
        free(scan->lineages[i].citations);
    }
    free(scan->lineages);
    free(scan);
}

struct vcs_zcode_discovery_scan_v1 *vcs_zcode_discovery_projection_scan(
    const char *workspace,
    const struct vcs_zcode_science_index *index,
    const uint8_t (*study_allowlist)[32], size_t allowlist_count,
    const uint8_t *network_genesis, int64_t now_unix)
{
    if (!workspace || !index)
        LOG_NULL(ZDP_LOG, "scan: null workspace or index");
    struct vcs_zcode_discovery_scan_v1 *scan =
        zcl_malloc(sizeof(*scan), "zdp_scan");
    if (!scan)
        LOG_NULL(ZDP_LOG, "scan alloc");
    memset(scan, 0, sizeof(*scan));
    struct zdp_uf uf;
    memset(&uf, 0, sizeof(uf));
    struct zdp_root_list *study_members = NULL; /* per-allowlisted-study */
    bool ok = false;

    if (!vcs_zcode_discovery_corpus_root(index, scan->corpus_root))
        goto done;

    size_t study_total = vcs_zcode_science_index_study_count(index);
    study_members = zcl_calloc(study_total ? study_total : 1,
                               sizeof(*study_members), "zdp_study_members");
    if (!study_members) {
        LOG_ERROR(ZDP_LOG, "study member lists alloc");
        goto done;
    }

    /* Pass 1: every allowlisted study opens a lineage: study root +
     * source root are the first members. */
    for (size_t i = 0; i < study_total; i++) {
        const struct vcs_zcode_science_index_study_entry *se =
            vcs_zcode_science_index_study_at(index, i);
        uint8_t study_root[32], source_root[32];
        if (!zcl_hex_decode_lower(se->study_root_hex, study_root, 32) ||
            !zcl_hex_decode_lower(se->source_root_hex, source_root, 32))
            continue;
        if (!zdp_allowlisted(study_allowlist, allowlist_count, study_root))
            continue;
        size_t s = zdp_uf_add(&uf, study_root);
        size_t src = zdp_uf_add(&uf, source_root);
        if (s == SIZE_MAX || src == SIZE_MAX)
            goto done;
        zdp_uf_union(&uf, s, src);
        if (!zdp_root_list_add(&study_members[i], study_root))
            goto done;
    }

    /* Pass 2: projected results of allowlisted studies pull their
     * candidate's base/candidate source roots into the same lineage — one
     * version chain or fork set collapses to one property. */
    size_t result_total = vcs_zcode_science_index_result_count(index);
    for (size_t i = 0; i < result_total; i++) {
        const struct vcs_zcode_science_index_result_entry *re =
            vcs_zcode_science_index_result_at(index, i);
        uint8_t study_root[32], candidate_root[32];
        if (!zcl_hex_decode_lower(re->study_root_hex, study_root, 32) ||
            !zcl_hex_decode_lower(re->candidate_root_hex, candidate_root, 32))
            continue;
        if (!zdp_allowlisted(study_allowlist, allowlist_count, study_root))
            continue;
        if (!zdp_absorb_candidate_lineage(workspace, candidate_root,
                                          study_root, &uf))
            goto done;
    }

    /* Group members into lineages by union-find representative, in member
     * (scan) order; each lineage's representative root is its smallest
     * member. */
    size_t *lineage_of_set = NULL;
    {
        size_t set_count = uf.count;
        lineage_of_set = zcl_calloc(set_count ? set_count : 1,
                                    sizeof(*lineage_of_set),
                                    "zdp_lineage_of_set");
        if (!lineage_of_set) {
            LOG_ERROR(ZDP_LOG, "lineage map alloc");
            goto done;
        }
        for (size_t i = 0; i < set_count; i++)
            lineage_of_set[i] = SIZE_MAX;
        /* Only sets containing an allowlisted study become lineages. */
        for (size_t i = 0; i < study_total; i++) {
            if (study_members[i].count == 0)
                continue;
            uint8_t study_root[32];
            memcpy(study_root, study_members[i].roots[0], 32);
            size_t idx = zdp_uf_add(&uf, study_root);
            if (idx == SIZE_MAX) {
                free(lineage_of_set);
                goto done;
            }
            size_t rep = zdp_uf_find(&uf, idx);
            if (lineage_of_set[rep] == SIZE_MAX) {
                size_t li = scan->lineage_count;
                struct vcs_zcode_discovery_lineage_v1 *grown = zcl_realloc(
                    scan->lineages, (li + 1u) * sizeof(*scan->lineages),
                    "zdp_lineages");
                if (!grown) {
                    LOG_ERROR(ZDP_LOG, "lineages grow");
                    free(lineage_of_set);
                    goto done;
                }
                scan->lineages = grown;
                memset(&scan->lineages[li], 0, sizeof(*scan->lineages));
                lineage_of_set[rep] = li;
                scan->lineage_count++;
            }
            scan->lineages[lineage_of_set[rep]].study_count++;
        }
        /* Absorb every union-find member into its lineage. */
        for (size_t i = 0; i < set_count; i++) {
            size_t rep = zdp_uf_find(&uf, i);
            if (rep >= set_count || lineage_of_set[rep] == SIZE_MAX)
                continue;
            struct vcs_zcode_discovery_lineage_v1 *lin =
                &scan->lineages[lineage_of_set[rep]];
            struct zdp_root_list tmp = {
                .roots = (uint8_t(*)[32])lin->members,
                .count = lin->member_count,
                .capacity = lin->member_count,
            };
            if (!zdp_root_list_add(&tmp, uf.roots[i])) {
                lin->members = tmp.roots;
                lin->member_count = tmp.count;
                free(lineage_of_set);
                goto done;
            }
            lin->members = tmp.roots;
            lin->member_count = tmp.count;
        }
        free(lineage_of_set);
    }

    /* Per lineage: sorted members (node root = smallest member) and the
     * canonical citation targets of its studies. */
    for (size_t li = 0; li < scan->lineage_count; li++) {
        struct vcs_zcode_discovery_lineage_v1 *lin = &scan->lineages[li];
        struct zdp_root_list members = {
            .roots = lin->members, .count = lin->member_count,
            .capacity = lin->member_count,
        };
        zdp_root_list_sort(&members);
        struct zdp_root_list citations = { .roots = NULL };
        for (size_t m = 0; m < lin->member_count; m++) {
            /* Citation sets attach to STUDY roots only; source/candidate
             * members are not study wires and simply fail the load. */
            uint8_t citations_root[32];
            if (!zdp_study_citations_root(workspace, lin->members[m],
                                          citations_root))
                continue;
            if (!zdp_absorb_citations(workspace, citations_root, &citations)) {
                free(citations.roots);
                goto done;
            }
        }
        zdp_root_list_sort(&citations);
        lin->citations = citations.roots;
        lin->citation_count = citations.count;
    }

    /* Sort lineages by representative (smallest member) root ascending:
     * sort (root, index) pairs, then permute. */
    if (scan->lineage_count > 1) {
        struct zdp_lineage_order {
            uint8_t root[32];
            size_t index;
        } *order = zcl_calloc(scan->lineage_count, sizeof(*order),
                              "zdp_lineage_order");
        struct vcs_zcode_discovery_lineage_v1 *sorted = zcl_calloc(
            scan->lineage_count, sizeof(*sorted), "zdp_lineages_sorted");
        if (!order || !sorted) {
            free(sorted);
            free(order);
            goto done;
        }
        for (size_t i = 0; i < scan->lineage_count; i++) {
            memcpy(order[i].root, scan->lineages[i].members[0], 32);
            order[i].index = i;
        }
        qsort(order, scan->lineage_count, sizeof(*order), zdp_root_cmp);
        for (size_t i = 0; i < scan->lineage_count; i++)
            sorted[i] = scan->lineages[order[i].index];
        free(scan->lineages);
        scan->lineages = sorted;
        free(order);
    }

    /* Votes: only signature-valid, non-expired, in-network, non-replay,
     * positive-signal votes become seed weight — verified here, one vote
     * per voter per lineage and one vote per voter+sequence. Processed in
     * the index's vote-id order, so arrival order never changes the
     * outcome and the first VALID vote in that order wins the voter's
     * sequence slot (a later same-voter+sequence entry is the replay). */
    {
        struct {
            uint8_t voter[32];
            uint64_t sequence;
            size_t lineage;
        } *seen = NULL;
        size_t seen_count = 0;
        size_t vote_total = vcs_zcode_science_index_vote_count(index);
        for (size_t i = 0; i < vote_total; i++) {
            const struct vcs_zcode_science_index_vote_entry *ve =
                vcs_zcode_science_index_vote_at(index, i);
            scan->votes_considered++;
            if (ve->expired)
                continue;
            if (ve->signal != VCS_ZCODE_CURATION_USEFUL &&
                ve->signal != VCS_ZCODE_CURATION_INTERESTING)
                continue; /* FLAG and unknown signals are never seeds */
            if (!network_genesis)
                continue;
            uint8_t vote_id[32], voter[32], property[32];
            if (!zcl_hex_decode_lower(ve->vote_id_hex, vote_id, 32) ||
                !zcl_hex_decode_lower(ve->voter_zid_root_hex, voter, 32) ||
                !zcl_hex_decode_lower(ve->property_root_hex, property, 32))
                continue;
            uint8_t *wire = NULL;
            size_t len = 0;
            struct vcs_zcode_curation_vote_v1 vote;
            uint8_t rederived_id[32];
            bool verified = zdp_cas_load(workspace, vote_id, &wire, &len) &&
                vcs_zcode_curation_vote_parse(wire, len, &vote) ==
                    VCS_ZCODE_SCIENCE_OK &&
                vcs_zcode_curation_vote_id(&vote, rederived_id) ==
                    VCS_ZCODE_SCIENCE_OK &&
                memcmp(rederived_id, vote_id, 32) == 0 &&
                vcs_zcode_curation_vote_verify(&vote, network_genesis,
                                               vote.voter_zid_root,
                                               vote.signer_pubkey,
                                               now_unix) ==
                    VCS_ZCODE_SCIENCE_OK;
            free(wire);
            if (!verified)
                continue;
            /* Resolve the voted property onto an admitted lineage. */
            size_t lineage = SIZE_MAX;
            for (size_t li = 0; li < scan->lineage_count; li++) {
                const struct vcs_zcode_discovery_lineage_v1 *lin =
                    &scan->lineages[li];
                size_t lo = 0, hi = lin->member_count;
                while (lo < hi) {
                    size_t mid = lo + (hi - lo) / 2;
                    int cmp = memcmp(property, lin->members[mid], 32);
                    if (cmp == 0) {
                        lineage = li;
                        break;
                    }
                    if (cmp < 0)
                        hi = mid;
                    else
                        lo = mid + 1;
                }
                if (lineage != SIZE_MAX)
                    break;
            }
            if (lineage == SIZE_MAX)
                continue; /* a vote on something outside the filter */
            bool replayed = false;
            for (size_t s = 0; s < seen_count; s++)
                if (memcmp(seen[s].voter, voter, 32) == 0 &&
                    (seen[s].lineage == lineage ||
                     seen[s].sequence == ve->sequence)) {
                    replayed = true;
                    break;
                }
            if (replayed)
                continue; /* one vote per voter per lineage and per sequence */
            {
                void *grown = zcl_realloc(seen, (seen_count + 1u) *
                                          sizeof(*seen), "zdp_vote_seen");
                if (!grown) {
                    LOG_ERROR(ZDP_LOG, "vote-seen grow");
                    free(seen);
                    goto done;
                }
                seen = grown;
                memcpy(seen[seen_count].voter, voter, 32);
                seen[seen_count].sequence = ve->sequence;
                seen[seen_count].lineage = lineage;
                seen_count++;
            }
            scan->lineages[lineage].seed_weight +=
                ve->signal == VCS_ZCODE_CURATION_USEFUL
                    ? VCS_ZCODE_DISCOVERY_PROJECTION_WEIGHT_USEFUL
                    : VCS_ZCODE_DISCOVERY_PROJECTION_WEIGHT_INTERESTING;
            scan->votes_accepted++;
        }
        free(seen);
    }

    ok = true;
done:
    if (study_members) {
        for (size_t i = 0; i < study_total; i++)
            free(study_members[i].roots);
        free(study_members);
    }
    free(uf.roots);
    free(uf.parent);
    if (!ok) {
        vcs_zcode_discovery_scan_free(scan);
        return NULL;
    }
    return scan;
}

/* ── assemble ────────────────────────────────────────────────────── */

void vcs_zcode_discovery_graph_free(struct vcs_zcode_discovery_graph_v1 *g)
{
    if (!g)
        return;
    free(g->nodes);
    free(g->edges);
    free(g->seeds);
    free(g->in_degree);
    free(g->node_seed_weight);
    memset(g, 0, sizeof(*g));
}

struct zdp_member_ref {
    uint8_t root[32];
    size_t node;
};

static int zdp_member_ref_cmp(const void *a, const void *b)
{
    return memcmp(((const struct zdp_member_ref *)a)->root,
                  ((const struct zdp_member_ref *)b)->root, 32);
}

static bool zdp_node_of_member(const struct zdp_member_ref *refs,
                               size_t ref_count, const uint8_t root[32],
                               size_t *node_out)
{
    size_t lo = 0, hi = ref_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int cmp = memcmp(root, refs[mid].root, 32);
        if (cmp == 0) {
            *node_out = refs[mid].node;
            return true;
        }
        if (cmp < 0)
            hi = mid;
        else
            lo = mid + 1;
    }
    return false;
}

enum vcs_zcode_discovery_rank_error vcs_zcode_discovery_projection_assemble(
    const struct vcs_zcode_discovery_scan_v1 *scan,
    struct vcs_zcode_discovery_graph_v1 *out)
{
    if (!scan || !out)
        return VCS_ZCODE_DISCOVERY_RANK_ERR_NULL;
    memset(out, 0, sizeof(*out));
    for (size_t i = 0; i < scan->lineage_count; i++)
        if (scan->lineages[i].member_count == 0 ||
            !scan->lineages[i].members)
            return VCS_ZCODE_DISCOVERY_RANK_ERR_LIMIT; /* memberless lineage */
    size_t admitted = scan->lineage_count;
    if (admitted > VCS_ZCODE_DISCOVERY_RANK_MAX_NODES) {
        out->omitted_node_count =
            (uint32_t)(admitted - VCS_ZCODE_DISCOVERY_RANK_MAX_NODES);
        admitted = VCS_ZCODE_DISCOVERY_RANK_MAX_NODES;
    }
    out->node_count = admitted;
    if (admitted == 0)
        return VCS_ZCODE_DISCOVERY_RANK_OK; /* the empty corpus */

    out->nodes = zcl_calloc(admitted, sizeof(*out->nodes), "zdp_nodes");
    out->in_degree = zcl_calloc(admitted, sizeof(*out->in_degree),
                                "zdp_in_degree");
    out->node_seed_weight = zcl_calloc(admitted,
                                       sizeof(*out->node_seed_weight),
                                       "zdp_node_seed_weight");
    if (!out->nodes || !out->in_degree || !out->node_seed_weight) {
        vcs_zcode_discovery_graph_free(out);
        return VCS_ZCODE_DISCOVERY_RANK_ERR_ALLOCATION;
    }
    for (size_t i = 0; i < admitted; i++)
        memcpy(out->nodes[i].property_root, scan->lineages[i].members[0],
               32);

    /* member root -> node index, for citation and seed resolution. */
    size_t ref_count = 0;
    for (size_t i = 0; i < admitted; i++)
        ref_count += scan->lineages[i].member_count;
    struct zdp_member_ref *refs = zcl_calloc(ref_count ? ref_count : 1,
                                             sizeof(*refs), "zdp_member_refs");
    if (!refs) {
        vcs_zcode_discovery_graph_free(out);
        return VCS_ZCODE_DISCOVERY_RANK_ERR_ALLOCATION;
    }
    size_t at = 0;
    for (size_t i = 0; i < admitted; i++)
        for (size_t m = 0; m < scan->lineages[i].member_count; m++) {
            memcpy(refs[at].root, scan->lineages[i].members[m], 32);
            refs[at].node = i;
            at++;
        }
    if (ref_count > 1)
        qsort(refs, ref_count, sizeof(*refs), zdp_member_ref_cmp);
    /* Union-find members are disjoint across lineages in a real scan; a
     * synthetic scan may repeat one — the lowest node root wins, so drop
     * later duplicates deterministically. */
    size_t kept = 0;
    for (size_t i = 0; i < ref_count; i++) {
        if (kept > 0 && memcmp(refs[kept - 1].root, refs[i].root, 32) == 0)
            continue;
        refs[kept++] = refs[i];
    }
    ref_count = kept;

    /* Edges: per citing node, resolve citation targets onto admitted
     * nodes, dedupe, keep the first MAX_NODE_CITATIONS ascending. */
    size_t edge_capacity = admitted *
                           VCS_ZCODE_DISCOVERY_PROJECTION_MAX_NODE_CITATIONS;
    if (edge_capacity > VCS_ZCODE_DISCOVERY_RANK_MAX_EDGES)
        edge_capacity = VCS_ZCODE_DISCOVERY_RANK_MAX_EDGES;
    out->edges = zcl_calloc(edge_capacity ? edge_capacity : 1,
                            sizeof(*out->edges), "zdp_edges");
    size_t *targets = zcl_calloc(
        VCS_ZCODE_DISCOVERY_PROJECTION_MAX_CITATION_SET,
        sizeof(*targets), "zdp_targets");
    if (!out->edges || !targets) {
        free(targets);
        free(refs);
        vcs_zcode_discovery_graph_free(out);
        return VCS_ZCODE_DISCOVERY_RANK_ERR_ALLOCATION;
    }
    for (size_t i = 0; i < admitted; i++) {
        const struct vcs_zcode_discovery_lineage_v1 *lin =
            &scan->lineages[i];
        size_t target_count = 0;
        for (size_t c = 0; c < lin->citation_count; c++) {
            size_t node;
            if (!zdp_node_of_member(refs, ref_count, lin->citations[c],
                                    &node))
                continue; /* cites outside the filtered corpus */
            if (node == i)
                continue; /* a self-citation is never an edge */
            bool duplicate = false;
            for (size_t t = 0; t < target_count; t++)
                if (targets[t] == node) {
                    duplicate = true;
                    break;
                }
            if (!duplicate && target_count <
                VCS_ZCODE_DISCOVERY_PROJECTION_MAX_CITATION_SET)
                targets[target_count++] = node;
        }
        if (target_count > 1)
            qsort(targets, target_count, sizeof(*targets), zdp_size_cmp);
        size_t keep = target_count;
        if (keep > VCS_ZCODE_DISCOVERY_PROJECTION_MAX_NODE_CITATIONS) {
            out->omitted_edge_count +=
                (uint32_t)(keep -
                           VCS_ZCODE_DISCOVERY_PROJECTION_MAX_NODE_CITATIONS);
            keep = VCS_ZCODE_DISCOVERY_PROJECTION_MAX_NODE_CITATIONS;
        }
        for (size_t t = 0; t < keep; t++) {
            if (out->edge_count >= VCS_ZCODE_DISCOVERY_RANK_MAX_EDGES) {
                out->omitted_edge_count += (uint32_t)(keep - t);
                break; /* the global edge bound: rest omitted ascending */
            }
            struct vcs_zcode_discovery_edge_v1 *edge =
                &out->edges[out->edge_count++];
            memcpy(edge->citing_property_root, out->nodes[i].property_root,
                   32);
            memcpy(edge->cited_property_root,
                   out->nodes[targets[t]].property_root, 32);
            out->in_degree[targets[t]]++;
        }
    }
    free(targets);
    free(refs);

    /* Seeds: capped aggregate weights, in node order. */
    out->seeds = zcl_calloc(admitted, sizeof(*out->seeds), "zdp_seeds");
    if (!out->seeds) {
        vcs_zcode_discovery_graph_free(out);
        return VCS_ZCODE_DISCOVERY_RANK_ERR_ALLOCATION;
    }
    for (size_t i = 0; i < admitted; i++) {
        uint32_t weight = scan->lineages[i].seed_weight;
        if (weight == 0)
            continue;
        if (weight > VCS_ZCODE_DISCOVERY_RANK_MAX_SEED_WEIGHT)
            weight = VCS_ZCODE_DISCOVERY_RANK_MAX_SEED_WEIGHT;
        memcpy(out->seeds[out->seed_count].property_root,
               out->nodes[i].property_root, 32);
        out->seeds[out->seed_count].weight = weight;
        out->node_seed_weight[i] = weight;
        out->seed_count++;
    }
    return VCS_ZCODE_DISCOVERY_RANK_OK;
}

/* ── compute + convergence residual ──────────────────────────────── */

struct zdp_step_graph {
    size_t node_count;
    uint32_t *edge_from;
    uint32_t *edge_to;
    size_t edge_count;
    uint32_t *seed_node;
    uint32_t *seed_weight;
    size_t seed_count;
    uint64_t seed_weight_total;
};

/* Mirror of the pure core's personalization: seeds in node order, empty
 * seed set means uniform, remainders land on the earliest entries. */
static void zdp_add_personalization(const struct zdp_step_graph *graph,
                                    uint64_t amount, uint64_t *destination)
{
    uint64_t assigned = 0;
    if (graph->seed_count == 0) {
        uint64_t each = amount / graph->node_count;
        uint64_t remainder = amount % graph->node_count;
        for (size_t i = 0; i < graph->node_count; i++)
            destination[i] += each + (i < remainder ? 1u : 0u);
        return;
    }
    for (size_t i = 0; i < graph->seed_count; i++) {
        uint64_t share = amount * graph->seed_weight[i] /
                         graph->seed_weight_total;
        destination[graph->seed_node[i]] += share;
        assigned += share;
    }
    uint64_t remainder = amount - assigned;
    for (size_t i = 0; i < (size_t)remainder; i++)
        destination[graph->seed_node[i]]++;
}

enum vcs_zcode_discovery_rank_error vcs_zcode_discovery_projection_compute(
    const struct vcs_zcode_discovery_graph_v1 *graph,
    const uint8_t filter_policy_root[32],
    struct vcs_zcode_discovery_rank_entry_v1 *entries,
    struct vcs_zcode_discovery_rank_result_v1 *result,
    uint64_t *residual_out)
{
    if (!graph || !filter_policy_root || !entries || !result ||
        !residual_out)
        return VCS_ZCODE_DISCOVERY_RANK_ERR_NULL;
    *residual_out = 0;
    if (graph->node_count == 0)
        return VCS_ZCODE_DISCOVERY_RANK_ERR_LIMIT;
    enum vcs_zcode_discovery_rank_error error =
        vcs_zcode_discovery_rank_compute(
            graph->nodes, graph->node_count, graph->edges, graph->edge_count,
            graph->seeds, graph->seed_count, filter_policy_root, entries,
            graph->node_count, result);
    if (error != VCS_ZCODE_DISCOVERY_RANK_OK)
        return error;

    /* The residual: recompute ONE more fixed-v1 iteration from the result
     * mass vector and measure the exact integer L1 movement. Graph arrays
     * are already in the core's canonical order (nodes ascending, edges by
     * citing/cited, seeds by node), so this mirrors it exactly. */
    struct zdp_step_graph step;
    memset(&step, 0, sizeof(step));
    step.node_count = graph->node_count;
    step.edge_count = graph->edge_count;
    step.seed_count = graph->seed_count;
    step.edge_from = zcl_calloc(step.edge_count ? step.edge_count : 1,
                                sizeof(*step.edge_from), "zdp_step_ef");
    step.edge_to = zcl_calloc(step.edge_count ? step.edge_count : 1,
                              sizeof(*step.edge_to), "zdp_step_et");
    step.seed_node = zcl_calloc(step.seed_count ? step.seed_count : 1,
                                sizeof(*step.seed_node), "zdp_step_sn");
    step.seed_weight = zcl_calloc(step.seed_count ? step.seed_count : 1,
                                  sizeof(*step.seed_weight), "zdp_step_sw");
    uint64_t *current = zcl_calloc(step.node_count, sizeof(*current),
                                   "zdp_step_current");
    uint64_t *next = zcl_calloc(step.node_count, sizeof(*next),
                                "zdp_step_next");
    uint64_t *budgets = zcl_calloc(step.node_count, sizeof(*budgets),
                                   "zdp_step_budgets");
    if (!step.edge_from || !step.edge_to || !step.seed_node ||
        !step.seed_weight || !current || !next || !budgets) {
        error = VCS_ZCODE_DISCOVERY_RANK_ERR_ALLOCATION;
        goto done;
    }
    for (size_t i = 0; i < step.edge_count; i++) {
        /* nodes are sorted ascending: binary search both endpoints */
        size_t lo, hi;
        lo = 0;
        hi = step.node_count;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            int cmp = memcmp(graph->edges[i].citing_property_root,
                             graph->nodes[mid].property_root, 32);
            if (cmp == 0) {
                step.edge_from[i] = (uint32_t)mid;
                break;
            }
            if (cmp < 0)
                hi = mid;
            else
                lo = mid + 1;
        }
        lo = 0;
        hi = step.node_count;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            int cmp = memcmp(graph->edges[i].cited_property_root,
                             graph->nodes[mid].property_root, 32);
            if (cmp == 0) {
                step.edge_to[i] = (uint32_t)mid;
                break;
            }
            if (cmp < 0)
                hi = mid;
            else
                lo = mid + 1;
        }
    }
    for (size_t i = 0; i < step.seed_count; i++) {
        size_t lo = 0, hi = step.node_count;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            int cmp = memcmp(graph->seeds[i].property_root,
                             graph->nodes[mid].property_root, 32);
            if (cmp == 0) {
                step.seed_node[i] = (uint32_t)mid;
                break;
            }
            if (cmp < 0)
                hi = mid;
            else
                lo = mid + 1;
        }
        step.seed_weight[i] = graph->seeds[i].weight;
        step.seed_weight_total += graph->seeds[i].weight;
    }
    /* Result entries are ordered by mass; scatter mass back to node order. */
    for (size_t i = 0; i < result->entry_count; i++) {
        size_t lo = 0, hi = step.node_count;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            int cmp = memcmp(result->entries[i].property_root,
                             graph->nodes[mid].property_root, 32);
            if (cmp == 0) {
                current[mid] = result->entries[i].mass;
                break;
            }
            if (cmp < 0)
                hi = mid;
            else
                lo = mid + 1;
        }
    }

    const uint64_t teleport_mass =
        VCS_ZCODE_DISCOVERY_RANK_MASS *
        (VCS_ZCODE_DISCOVERY_RANK_DAMPING_DENOMINATOR -
         VCS_ZCODE_DISCOVERY_RANK_DAMPING_NUMERATOR) /
        VCS_ZCODE_DISCOVERY_RANK_DAMPING_DENOMINATOR;
    const uint64_t link_mass =
        VCS_ZCODE_DISCOVERY_RANK_MASS - teleport_mass;
    zdp_add_personalization(&step, teleport_mass, next);
    uint64_t budget_sum = 0;
    for (size_t i = 0; i < step.node_count; i++) {
        budgets[i] = current[i] *
                     VCS_ZCODE_DISCOVERY_RANK_DAMPING_NUMERATOR /
                     VCS_ZCODE_DISCOVERY_RANK_DAMPING_DENOMINATOR;
        budget_sum += budgets[i];
    }
    uint64_t source_remainder = link_mass - budget_sum;
    for (size_t i = 0; i < (size_t)source_remainder &&
                        i < step.node_count; i++)
        budgets[i]++;
    {
        size_t cursor = 0;
        for (size_t i = 0; i < step.node_count; i++) {
            size_t out_start = cursor;
            while (cursor < step.edge_count && step.edge_from[cursor] == i)
                cursor++;
            size_t out_count = cursor - out_start;
            if (out_count == 0) {
                zdp_add_personalization(&step, budgets[i], next);
                continue;
            }
            uint64_t each = budgets[i] / out_count;
            uint64_t remainder = budgets[i] % out_count;
            for (size_t j = 0; j < out_count; j++)
                next[step.edge_to[out_start + j]] +=
                    each + (j < remainder ? 1u : 0u);
        }
    }
    for (size_t i = 0; i < step.node_count; i++)
        *residual_out += next[i] > current[i] ? next[i] - current[i]
                                              : current[i] - next[i];

done:
    free(budgets);
    free(next);
    free(current);
    free(step.seed_weight);
    free(step.seed_node);
    free(step.edge_to);
    free(step.edge_from);
    return error;
}
