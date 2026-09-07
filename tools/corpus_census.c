/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * corpus-census: offline driver for the C23 corpus odometer (slice 1b).
 * Reads contexts/commons/corpus/scopes.def, enumerates each scope's tracked files with
 * `git ls-files -z` (untracked scratch — test-tmp/, build/, .zvcs/ — can
 * never enter the census), binds every evidence bit to a REAL recomputable
 * artifact, feeds the pure census core (contexts/commons/modules/vcs zcode_c23_corpus_census),
 * and emits the first signed c23_corpus_checkpoint.v1 plus its shards, an
 * evidence bundle, and a KPI report under the --out directory.
 *
 * EVIDENCE ROOT RECIPES (all roots are vcs_signed_evidence_root over the
 * named domain, domain length INCLUDING the terminating NUL; the evidence
 * JSON "recipes" object restates these verbatim):
 *
 *   zcl.zcode.corpus.release.v1
 *     wire = concat over the scope's sorted repo-relative paths of
 *            path || NUL || u64-LE size || sha3_256(content).
 *   zcl.zcode.corpus.license.v1
 *     wire = license-path || NUL || u64-LE size || sha3_256(content) for
 *            the license file actually bound (scope-local LICENSE when one
 *            exists, else the repo-root LICENSE).
 *   zcl.zcode.corpus.author_binding.v1
 *     wire = the ASCII author string: "ZClassic23 founding contributors"
 *            (kind human) or "zclassic23-agent-fleet" (kind ai).
 *   zcl.zcode.corpus.assignment_evidence.v1
 *     wire = the exact scopes.def line bytes for this scope (no trailing
 *            newline).
 *   zcl.zcode.corpus.dependency_closure.v1
 *     wire = concat over the scope's zcode-package.json dependencies (file
 *            order) of name || NUL || root-hex-ascii || NUL || semver || NUL;
 *            empty wire when the scope declares no pinned dependencies.
 *   zcl.zcode.corpus.moderation_set.v1
 *     wire = empty (founding empty moderation set; no canonical founding
 *            root exists in zcode_family_moderation.c, so this corpus-local
 *            construction is defined here and disclosed).
 *   zcl.zcode.corpus.panel.v1
 *     wire = the ASCII literal "founding-self-screen".
 *   zcl.zcode.corpus.admission_evidence.v1
 *     wire = the scope's source_assignment_root (32 bytes).
 *   zcl.zcode.corpus.passport.v1
 *     wire = name || NUL || spdx || NUL || release_root || license_root ||
 *            api-header-presence byte || recipe-presence byte.
 *   zcl.zcode.corpus.quality.v1
 *     wire = concat over sorted tools/lint/ tracked paths of
 *            path || NUL || sha3_256(content); computed only when
 *            --quality-attested 1 (the operator asserts `make lint` passed
 *            at census time; this tool never runs lint itself).
 *   zcl.zcode.corpus.reproduction.v1
 *     wire = release_root || method-literal, where the method is
 *            "dual-worktree" (a temp `git worktree add --detach HEAD`
 *            re-enumerated and rehashed byte-identically) or, when the
 *            worktree pass is unavailable in this environment, the weaker
 *            "in-process-reenumeration" fallback (disclosed in the report).
 *   zcl.zcode.corpus.proof.v1
 *     wire = release_root || source_assignment_root || admission_root ||
 *            quality_root || reproduction_root (zero slots = unattested).
 *   zcl.zcode.corpus.possession.v1
 *     wire = concat of the scope's sorted .zvcs CAS blob hashes. REPORT
 *            ONLY: entries keep possession_root ZERO and DURABLE clear —
 *            nothing is 5-ACK/3-operator-group durable yet.
 *   zcl.zcode.corpus.replication.v1
 *     wire = concat(shard roots in checkpoint order) ||
 *            "single-host-founding-v1" (disclosed in the report).
 *
 * PACKAGE SCOPES (second def line form — a published Commons package bound
 * to its EXACT published bytes):
 *
 *   package <name> | root <64hex package root> | store <label> \
 *       | kind <human|ai|import> | spdx <id>
 *
 * `store` is a LABEL — one path component, never a path. It resolves to
 * <store-root>/<label> where store-root is --store-root, else
 * $ZCL_CORPUS_STORE_ROOT, else $HOME. The def line is copied verbatim into
 * every evidence record and hashed into assignment_evidence_root, so an
 * absolute datadir there would publish the operator's home directory in
 * every committed artifact; the bytes are bound by the def `root`, not by
 * where they happen to sit on one host.
 *
 * Enumeration reads the package store at <store-root>/<label>/zcode
 * instead of git:
 * the committed manifest (manifests/<root-hex>) is parsed and re-rooted
 * (fail closed on mismatch with the def root), the release envelope naming
 * that package root is found under releases/ (signature re-verified,
 * exactly one match required), and every file's bytes are reassembled from
 * CAS chunks with the committed chunk hash re-checked on read (the same
 * verify-on-read predicate the store enforces). The store is NEVER opened
 * through vcs_package_store_open: the census is a read-only observer, so it
 * performs no recovery sweep, access-count bump, or GC on the datadir.
 * Files are fed to the census core with package-relative paths exactly as
 * repo scopes are; tests/ paths carry the tests claim.
 *
 * Package-scope evidence bindings (all recorded in the report/evidence):
 *   release_root    — the def `root`, verified against the re-derived
 *                     manifest root of the stored manifest.
 *   RECIPE          — the release envelope's recipe_root, with the recipe
 *                     wire present under recipes/ and re-rooted (fail
 *                     closed on mismatch).
 *   REPRODUCIBLE    — vcs_package_reproduce_scan() over
 *                     <store>/zcode/receipts reports reproduced (>= 2
 *                     DISTINCT build receipt ids committing byte-identical
 *                     output sets); the matching receipt ids are recorded
 *                     in the report. Method literal
 *                     "receipts-dual-confined-build"; the reproduction wire
 *                     is release_root || method || concat(sorted receipt
 *                     ids). STRONGER than dual-worktree: two byte-identical
 *                     confined builds, not two source re-enumerations.
 *   COMPLETE_POSSESSION — every manifest chunk re-read from the CAS and
 *                     hash-verified (the read-only equivalent of
 *                     vcs_package_store_verify_possession(root,
 *                     require_pinned=false)); possession_root is computed
 *                     over the sorted unique chunk hashes and stays
 *                     REPORT-ONLY (DURABLE remains clear; 5-ACK/3-group
 *                     unmet).
 *   author_binding  — the release envelope's publisher pubkey as 66
 *                     lowercase hex ASCII (binds the key, not a literal
 *                     string).
 *   QUALITY_PROFILE — package mapping: "confined build+test receipt green"
 *                     — the same receipts evidence as REPRODUCIBLE. Wire =
 *                     release_root || "confined-build-test-receipt-green"
 *                     || concat(sorted receipt ids). Set iff reproduced.
 *   TESTS/API/LICENSE — from package content exactly as repo scopes
 *                     (tests/ semantic lines, .h semantic lines, the
 *                     package LICENSE file bound by the same license wire;
 *                     the def spdx must equal the release envelope's
 *                     license, fail closed on mismatch).
 *   source_assignment kind comes from the def line; admission is the same
 *   self-screened construction as repo scopes.
 *
 * FILE-CLAIM PRECEDENCE (deterministic; real ambiguity fails closed): a
 * tests-prefix claim beats another scope's src-prefix claim; among
 * same-kind claims the LONGEST matching prefix wins (so
 * tests/harness/src/test_base beats the shared tests/harness/include/test/ remainder scope); two
 * equal-length competing claims from different scopes are a fatal error.
 * No file is ever counted twice.
 *
 * DETERMINISM: no wall-clock and no randomness enter any signed object or
 * artifact byte (the OS RNG is touched only when GENERATING a missing
 * signer seed file). Same tree + def + seed + cutoff args => byte-identical
 * artifacts.
 *
 * SIGNER SEED: --signer-seed-file (default
 * $HOME/.config/zclassic23/corpus-census-signer.seed) holds exactly 32 RAW
 * bytes (not hex). A missing file is generated from the kernel CSPRNG and
 * written mode 0600 with the NEW pubkey logged; the seed is never written
 * anywhere under the repo.
 *
 * Usage:
 *   corpus-census --repo <repo root> --def <scopes.def> --out <dir> \
 *       --cutoff-height N --cutoff-mtp N \
 *       [--signer-seed-file PATH] [--sequence N] [--predecessor-root HEX64] \
 *       [--quality-attested 0|1] [--install <datadir>] \
 *       [--previous-report PATH]
 *
 * --install atomically drops the signed checkpoint wire at
 * <datadir>/zcode/corpus/checkpoint.hex, where `zcode commons corpus
 * status` picks it up. --previous-report reads the previous sequence's
 * report JSON and adds the growth-delta KPI block (raw deltas plus floor
 * per-day rates when >= 1 day elapsed between cutoffs). For sequence >1
 * the predecessor root and the previous report default to
 * <out>/report-<seq-1>.json; the explicit flags override the discovery.
 *
 * SOURCE LAYOUT (each sibling documents its own slice in detail):
 *   corpus_census_priv.h    — shared structs/decls every sibling below uses
 *   corpus_census_defs.c    — scopes.def line grammar and file loading
 *   corpus_census_scopes.c  — git enumeration and claim resolution
 *   corpus_census_measure.c — per-scope release/license/recipe/quality
 *   corpus_census_package.c — package-store (read-only observer) reads
 *   corpus_census_args.c    — CLI flags and the signer seed
 *   corpus_census_report.c  — the evidence bundle and KPI report JSON
 *   corpus_census.c (here)  — small shared utilities, evidence-object
 *                             signing, artifact writers, and main()'s
 *                             staged pipeline
 */

#define _GNU_SOURCE

#include "corpus_census_priv.h"

#include "base/bytes.h"
#include "base/checked.h"
#include "base/cleanse.h"
#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "vcs/package_reproduce.h"
#include "vcs/signed_evidence.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_commons.h"
#include "vcs/zcode_family_admission.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

const char k_domain_release[] = "zcl.zcode.corpus.release.v1";
const char k_domain_license[] = "zcl.zcode.corpus.license.v1";
const char k_domain_author[] = "zcl.zcode.corpus.author_binding.v1";
const char k_domain_assignment_evidence[] =
    "zcl.zcode.corpus.assignment_evidence.v1";
const char k_domain_dep_closure[] =
    "zcl.zcode.corpus.dependency_closure.v1";
const char k_domain_moderation[] = "zcl.zcode.corpus.moderation_set.v1";
const char k_domain_panel[] = "zcl.zcode.corpus.panel.v1";
const char k_domain_admission_evidence[] =
    "zcl.zcode.corpus.admission_evidence.v1";
const char k_domain_passport[] = "zcl.zcode.corpus.passport.v1";
const char k_domain_recipe[] = "zcl.zcode.corpus.recipe.v1";
const char k_domain_quality[] = "zcl.zcode.corpus.quality.v1";
const char k_domain_reproduction[] = "zcl.zcode.corpus.reproduction.v1";
const char k_domain_proof[] = "zcl.zcode.corpus.proof.v1";
const char k_domain_possession[] = "zcl.zcode.corpus.possession.v1";
const char k_domain_replication[] = "zcl.zcode.corpus.replication.v1";

const char k_author_human[] = "ZClassic23 founding contributors";
const char k_author_ai[] = "zclassic23-agent-fleet";
const char k_panel_literal[] = "founding-self-screen";
const char k_repro_worktree[] = "dual-worktree";
const char k_repro_fallback[] = "in-process-reenumeration";
const char k_repro_receipts[] = "receipts-dual-confined-build";
const char k_quality_receipts[] = "confined-build-test-receipt-green";
const char k_replication_literal[] = "single-host-founding-v1";

/* ── small growable containers ────────────────────────────────────── */

void vec_free(struct str_vec *vec)
{
    if (!vec) return;
    for (size_t i = 0; i < vec->n; i++) free(vec->v[i]);
    free(vec->v);
    memset(vec, 0, sizeof(*vec));
}

bool vec_push_len(struct str_vec *vec, const char *s, size_t len)
{
    if (vec->n == vec->cap) {
        size_t next = vec->cap ? vec->cap * 2u : 16u;
        size_t bytes = 0;
        if (!zcl_size_mul(next, sizeof(char *), &bytes))
            LOG_FAIL(CENSUS_LOG, "vec capacity overflow");
        char **nv = zcl_realloc(vec->v, bytes, "corpus.vec");
        if (!nv)
            LOG_FAIL(CENSUS_LOG, "vec realloc to %zu entries", vec->n + 1u);
        vec->v = nv;
        vec->cap = next;
    }
    char *copy = zcl_malloc(len + 1u, "corpus.vec.str");
    if (!copy)
        LOG_FAIL(CENSUS_LOG, "vec string alloc %zu", len);
    memcpy(copy, s, len);
    copy[len] = '\0';
    vec->v[vec->n++] = copy;
    return true;
}

bool vec_push(struct str_vec *vec, const char *s)
{
    return vec_push_len(vec, s, strlen(s));
}

int cmp_strp(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* qsort comparator over fixed 32-byte values (chunk hashes, receipt ids). */
int cmp_bytes32(const void *a, const void *b)
{
    return memcmp(a, b, 32);
}

void buf_free(struct buf *b)
{
    if (!b) return;
    free(b->p);
    memset(b, 0, sizeof(*b));
}

bool buf_put(struct buf *b, const void *data, size_t len)
{
    size_t need = 0;
    if (!zcl_size_add(b->len, len, &need))
        LOG_FAIL(CENSUS_LOG, "wire buffer size overflow");
    if (need > b->cap) {
        size_t next = b->cap ? b->cap : 256u;
        while (next < need) {
            if (!zcl_size_mul(next, 2u, &next))
                LOG_FAIL(CENSUS_LOG, "wire buffer capacity overflow");
        }
        uint8_t *np = zcl_realloc(b->p, next, "corpus.wire");
        if (!np)
            LOG_FAIL(CENSUS_LOG, "wire buffer realloc to %zu", need);
        b->p = np;
        b->cap = next;
    }
    if (len) memcpy(b->p + b->len, data, len);
    b->len += len;
    return true;
}

bool buf_put_u64le(struct buf *b, uint64_t v)
{
    uint8_t le[8];
    zcl_write_u64_le(le, v);
    return buf_put(b, le, sizeof(le));
}

/* ── roots, hex, charset helpers ──────────────────────────────────── */

bool evidence_root(const char *domain, const uint8_t *wire, size_t wire_len,
                   uint8_t out[32])
{
    if (!vcs_signed_evidence_root(domain, strlen(domain) + 1u, wire,
                                  wire_len, out))
        LOG_FAIL(CENSUS_LOG, "evidence root failed for domain %s", domain);
    return true;
}

void root_hex(const uint8_t root[32], char out[65])
{
    zcl_hex_encode(root, 32, out);
}

void json_push_root(struct json_value *obj, const char *key,
                    const uint8_t root[32])
{
    char hex[65];
    root_hex(root, hex);
    (void)json_push_kv_str(obj, key, hex);
}

/* Push one string onto a JSON array (json_push_back copies). */
void json_push_str(struct json_value *arr, const char *s)
{
    struct json_value v;
    json_init(&v);
    json_set_str(&v, s);
    (void)json_push_back(arr, &v);
    json_free(&v);
}

/* Path/prefix arguments are interpolated into single-quoted shell command
 * segments; restrict them to a charset that needs no escaping instead of
 * trusting quoting. */
bool shell_safe(const char *s)
{
    if (!s || !*s) return false;
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!(isalnum(c) || c == '.' || c == '_' || c == '/' || c == '-'))
            return false;
    }
    return true;
}

bool counted_extension(const char *path)
{
    size_t len = strlen(path);
    return (len >= 3 && strcmp(path + len - 2, ".c") == 0) ||
           (len >= 3 && strcmp(path + len - 2, ".h") == 0) ||
           (len >= 5 && strcmp(path + len - 4, ".def") == 0);
}

char *dup_str(const char *s, const char *label)
{
    size_t len = strlen(s);
    char *copy = zcl_malloc(len + 1u, label);
    if (!copy) {
        LOG_ERROR(CENSUS_LOG, "string alloc %zu for %s", len, label);
        return NULL;
    }
    memcpy(copy, s, len + 1u);
    return copy;
}

/* ── signed evidence objects (assignment, admission, passport, proof) ── */

static const char *author_string(uint16_t kind)
{
    return kind == VCS_ZCODE_SOURCE_AI_AUTHORED ? k_author_ai
                                                : k_author_human;
}

static bool scope_assignment_build(const struct scope_def *def,
                                   size_t scope_index, uint64_t cutoff_height,
                                   int64_t cutoff_mtp,
                                   const struct scope_measure *m,
                                   const char *author_override,
                                   const uint8_t seed[32],
                                   uint8_t assignment_root_out[32],
                                   uint8_t *wire_out, size_t *wire_len_out)
{
    uint8_t author_root[32], def_evidence_root[32];
    /* Package scopes bind the release envelope's publisher pubkey (66
     * lowercase hex ASCII, passed as author_override) as the author
     * binding; repo scopes bind the declared-kind literal string. */
    const char *author =
        author_override ? author_override : author_string(def->kind);
    if (!evidence_root(k_domain_author, (const uint8_t *)author,
                       strlen(author), author_root) ||
        !evidence_root(k_domain_assignment_evidence,
                       (const uint8_t *)def->def_line,
                       strlen(def->def_line), def_evidence_root))
        LOG_FAIL(CENSUS_LOG, "scope %s: assignment sub-roots failed",
                 def->name);
    struct vcs_zcode_source_assignment_v1 assignment;
    memset(&assignment, 0, sizeof(assignment));
    assignment.schema_version = 1;
    assignment.flags = VCS_ZCODE_C23_CORPUS_REQUIRED_FLAGS;
    assignment.source_kind = def->kind;
    assignment.sequence = (uint64_t)scope_index + 1u;
    assignment.assigned_height = cutoff_height;
    assignment.assigned_mtp = cutoff_mtp;
    memcpy(assignment.source_root, m->release_root, 32);
    memcpy(assignment.author_binding_root, author_root, 32);
    memcpy(assignment.license_root, m->license_root, 32);
    memcpy(assignment.assignment_evidence_root, def_evidence_root, 32);
    /* upstream roots stay zero for human/ai kinds. */
    enum vcs_zcode_c23_error error =
        vcs_zcode_source_assignment_v1_sign(&assignment, seed);
    if (error != VCS_ZCODE_C23_OK)
        LOG_FAIL(CENSUS_LOG, "scope %s: assignment sign: %s", def->name,
                 vcs_zcode_c23_error_string(error));
    error = vcs_zcode_source_assignment_v1_root(&assignment,
                                                assignment_root_out);
    if (error != VCS_ZCODE_C23_OK)
        LOG_FAIL(CENSUS_LOG, "scope %s: assignment root: %s", def->name,
                 vcs_zcode_c23_error_string(error));
    error = vcs_zcode_source_assignment_v1_encode(
        &assignment, wire_out, VCS_ZCODE_SOURCE_ASSIGNMENT_WIRE_BYTES,
        wire_len_out);
    if (error != VCS_ZCODE_C23_OK)
        LOG_FAIL(CENSUS_LOG, "scope %s: assignment encode: %s", def->name,
                 vcs_zcode_c23_error_string(error));
    memory_cleanse(&assignment, sizeof(assignment));
    return true;
}

static bool scope_admission_build(
    const struct scope_def *def, uint64_t cutoff_height, int64_t cutoff_mtp,
    const struct scope_measure *m, const uint8_t assignment_root[32],
    const uint8_t family_policy_root[32],
    const uint8_t moderation_set_root[32], const uint8_t seed[32],
    uint8_t admission_root_out[32], uint8_t *wire_out, size_t *wire_len_out)
{
    uint8_t panel_rt[32], evidence_rt[32];
    if (!evidence_root(k_domain_panel, (const uint8_t *)k_panel_literal,
                       strlen(k_panel_literal), panel_rt) ||
        !evidence_root(k_domain_admission_evidence, assignment_root, 32,
                       evidence_rt))
        LOG_FAIL(CENSUS_LOG, "scope %s: admission sub-roots failed",
                 def->name);
    struct vcs_zcode_commons_admission_v1 admission;
    memset(&admission, 0, sizeof(admission));
    admission.schema_version = 1;
    admission.flags = VCS_ZCODE_COMMONS_REQUIRED_FLAGS;
    /* Founding self-screen: the pass-state rule requires
     * state == SELF_SCREENED + tier, so tier 0 (SELF_SCREENED) pairs with
     * the SELF_SCREENED state. Disclosed: 0 independent operator groups. */
    admission.state = VCS_ZCODE_ADMISSION_SELF_SCREENED;
    admission.tier = VCS_ZCODE_MODERATION_TIER_SELF_SCREENED;
    admission.coverage_complete = 1;
    admission.closure_complete = 1;
    admission.sequence = 1;
    admission.decided_height = cutoff_height;
    admission.decided_mtp = cutoff_mtp;
    admission.expires_height =
        cutoff_height + CORPUS_CENSUS_ADMISSION_EXPIRY_BLOCKS;
    admission.expires_mtp =
        cutoff_mtp + CORPUS_CENSUS_ADMISSION_EXPIRY_MTP_SECONDS;
    memcpy(admission.content_root, m->release_root, 32);
    memcpy(admission.dependency_closure_root, m->dep_closure_root, 32);
    memcpy(admission.family_policy_root, family_policy_root, 32);
    memcpy(admission.moderation_set_root, moderation_set_root, 32);
    memcpy(admission.panel_root, panel_rt, 32);
    memcpy(admission.evidence_root, evidence_rt, 32);
    /* predecessor stays zero for sequence 1. */
    enum vcs_zcode_family_admission_error error =
        vcs_zcode_commons_admission_v1_sign(&admission, seed);
    if (error != VCS_ZCODE_FAMILY_ADMISSION_OK)
        LOG_FAIL(CENSUS_LOG, "scope %s: admission sign: %s", def->name,
                 vcs_zcode_family_admission_error_string(error));
    error = vcs_zcode_commons_admission_v1_root(&admission,
                                                admission_root_out);
    if (error != VCS_ZCODE_FAMILY_ADMISSION_OK)
        LOG_FAIL(CENSUS_LOG, "scope %s: admission root: %s", def->name,
                 vcs_zcode_family_admission_error_string(error));
    error = vcs_zcode_commons_admission_v1_encode(
        &admission, wire_out, VCS_ZCODE_COMMONS_ADMISSION_WIRE_BYTES,
        wire_len_out);
    if (error != VCS_ZCODE_FAMILY_ADMISSION_OK)
        LOG_FAIL(CENSUS_LOG, "scope %s: admission encode: %s", def->name,
                 vcs_zcode_family_admission_error_string(error));
    memory_cleanse(&admission, sizeof(admission));
    return true;
}

static bool scope_passport_root_compute(const struct scope_def *def,
                                        const struct scope_measure *m,
                                        uint8_t passport_root_out[32])
{
    struct buf wire = {0};
    uint8_t api_byte = m->has_api ? 1u : 0u;
    uint8_t recipe_byte = zcl_bytes_any_set(m->recipe_root, 32) ? 1u : 0u;
    bool ok = buf_put(&wire, def->name, strlen(def->name) + 1u) &&
              buf_put(&wire, def->spdx, strlen(def->spdx) + 1u) &&
              buf_put(&wire, m->release_root, 32) &&
              buf_put(&wire, m->license_root, 32) &&
              buf_put(&wire, &api_byte, 1) &&
              buf_put(&wire, &recipe_byte, 1) &&
              evidence_root(k_domain_passport, wire.p, wire.len,
                            passport_root_out);
    buf_free(&wire);
    if (!ok)
        LOG_FAIL(CENSUS_LOG, "scope %s: passport root failed", def->name);
    return true;
}

static bool scope_proof_root_compute(const struct scope_def *def,
                                     const struct scope_measure *m,
                                     const uint8_t assignment_root[32],
                                     const uint8_t admission_root[32],
                                     const uint8_t quality_root[32],
                                     const uint8_t reproduction_root[32],
                                     uint8_t proof_root_out[32])
{
    struct buf wire = {0};
    bool ok = buf_put(&wire, m->release_root, 32) &&
              buf_put(&wire, assignment_root, 32) &&
              buf_put(&wire, admission_root, 32) &&
              buf_put(&wire, quality_root, 32) &&
              buf_put(&wire, reproduction_root, 32) &&
              evidence_root(k_domain_proof, wire.p, wire.len, proof_root_out);
    buf_free(&wire);
    if (!ok)
        LOG_FAIL(CENSUS_LOG, "scope %s: proof root failed", def->name);
    return true;
}

static bool scope_passport_proof(const struct scope_def *def,
                                 const struct scope_measure *m,
                                 const uint8_t assignment_root[32],
                                 const uint8_t admission_root[32],
                                 const uint8_t quality_root[32],
                                 const uint8_t reproduction_root[32],
                                 uint8_t passport_root_out[32],
                                 uint8_t proof_root_out[32])
{
    if (!scope_passport_root_compute(def, m, passport_root_out))
        return false;
    return scope_proof_root_compute(def, m, assignment_root, admission_root,
                                    quality_root, reproduction_root,
                                    proof_root_out);
}

/* ── artifact writers ─────────────────────────────────────────────── */

bool write_text_atomic(const char *dir, const char *name,
                       const char *content, size_t len)
{
    size_t path_cap = strlen(dir) + strlen(name) + 8u;
    char *path = zcl_malloc(path_cap, "corpus.artifact");
    if (!path)
        LOG_FAIL(CENSUS_LOG, "artifact path alloc for %s", name);
    (void)snprintf(path, path_cap, "%s/%s", dir, name);
    char *tmp = zcl_malloc(path_cap, "corpus.artifact.tmp");
    if (!tmp) {
        free(path);
        LOG_FAIL(CENSUS_LOG, "artifact tmp path alloc for %s", name);
    }
    (void)snprintf(tmp, path_cap, "%s/.%s.tmp", dir, name);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        LOG_ERROR(CENSUS_LOG, "create %s: %s", tmp, strerror(errno));
        free(tmp);
        free(path);
        return false;
    }
    size_t off = 0;
    bool ok = true;
    while (ok && off < len) {
        ssize_t w = write(fd, content + off, len - off);
        if (w <= 0) ok = false;
        else off += (size_t)w;
    }
    if (ok && fsync(fd) != 0) ok = false;
    if (close(fd) != 0) ok = false;
    if (ok && rename(tmp, path) != 0) ok = false;
    if (!ok) {
        LOG_ERROR(CENSUS_LOG, "write %s: %s", path, strerror(errno));
        unlink(tmp);
    }
    free(tmp);
    free(path);
    if (!ok) return false;
    return true;
}

bool write_hex_artifact(const char *dir, const char *name,
                        const uint8_t *wire, size_t wire_len)
{
    size_t hex_len = wire_len * 2u;
    char *hex = zcl_malloc(hex_len + 2u, "corpus.hex");
    if (!hex)
        LOG_FAIL(CENSUS_LOG, "hex alloc %zu for %s", hex_len, name);
    zcl_hex_encode(wire, wire_len, hex);
    hex[hex_len] = '\n';
    bool ok = write_text_atomic(dir, name, hex, hex_len + 1u);
    free(hex);
    return ok;
}

bool write_json_artifact(const char *dir, const char *name,
                         struct json_value *doc)
{
    size_t need = json_write(doc, NULL, 0);
    char *text = zcl_malloc(need + 2u, "corpus.json.out");
    if (!text)
        LOG_FAIL(CENSUS_LOG, "json buffer alloc %zu for %s", need, name);
    size_t written = json_write(doc, text, need + 1u);
    if (written > need) {
        free(text);
        LOG_FAIL(CENSUS_LOG, "json write overflow for %s", name);
    }
    text[written] = '\n';
    bool ok = write_text_atomic(dir, name, text, written + 1u);
    free(text);
    return ok;
}

/* Fail-closed report hygiene: every JSON object must carry unique sibling
 * keys. The writer is append-only and the reader first-match, so a
 * duplicate key is an ambiguous report defect (it once produced 18
 * duplicate "incomplete" entries in excluded_loc_by_reason). Checked
 * recursively over the finished document before it is written. */
static bool report_keys_unique(const struct json_value *v)
{
    if (v->type == JSON_OBJ) {
        for (size_t i = 0; i < v->num_children; i++)
            for (size_t j = i + 1; j < v->num_children; j++)
                if (strcmp(v->keys[i], v->keys[j]) == 0)
                    return false;
    }
    if (v->type == JSON_OBJ || v->type == JSON_ARR)
        for (size_t i = 0; i < v->num_children; i++)
            if (!report_keys_unique(&v->children[i]))
                return false;
    return true;
}

/* ── git provenance for the report (never in signed objects) ──────── */

static bool git_capture(const char *repo, const char *git_args, char *out,
                        size_t out_sz)
{
    char cmd[CORPUS_CENSUS_CMD_MAX];
    if (snprintf(cmd, sizeof(cmd), "git -C '%s' %s", repo, git_args) >=
        (int)sizeof(cmd))
        LOG_FAIL(CENSUS_LOG, "git capture command overflow");
    FILE *pipe = popen(cmd, "r"); /* shellout-ok: standalone CLI tool */
    if (!pipe)
        LOG_FAIL(CENSUS_LOG, "popen git %s", git_args);
    size_t got = fread(out, 1, out_sz - 1u, pipe);
    int status = pclose(pipe); /* shellout-ok: standalone CLI tool */
    if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status)) {
        out[0] = '\0';
        LOG_FAIL(CENSUS_LOG, "git %s failed", git_args);
    }
    out[got] = '\0';
    while (got && isspace((unsigned char)out[got - 1])) out[--got] = '\0';
    return true;
}

/* ── main: staged pipeline ─────────────────────────────────────────── */

/* Parse argv and resolve the repo root (the seed never-under-repo guard
 * needs the canonical path). */
static int census_stage_args(int argc, char **argv, struct census_ctx *ctx)
{
    if (!args_parse(argc, argv, &ctx->args)) {
        usage(stderr);
        return 2;
    }
    if (!realpath(ctx->args.repo, ctx->repo_real))
        LOG_ERR(CENSUS_LOG, "realpath %s: %s", ctx->args.repo,
                strerror(errno));
    if (!shell_safe(ctx->repo_real))
        LOG_ERR(CENSUS_LOG, "repo path %s has unsafe characters",
                ctx->repo_real);
    return 0;
}

/* Read the discovered previous-sequence report (if any) and extract its
 * checkpoint_root, without yet acting on it. */
static int census_predecessor_read_report(struct census_ctx *ctx,
                                          struct json_value *prev,
                                          uint8_t **prev_wire,
                                          const char **prev_root_hex)
{
    struct census_args *args = &ctx->args;
    int n = snprintf(ctx->discovered_report, sizeof(ctx->discovered_report),
                     "%s/report-%06llu.json", args->out,
                     (unsigned long long)(args->sequence - 1));
    if (n < 0 || (size_t)n >= sizeof(ctx->discovered_report))
        LOG_ERR(CENSUS_LOG, "previous report path overflow");
    size_t prev_len = 0;
    *prev_root_hex = NULL;
    if (store_file_read(ctx->discovered_report, 4u * 1024u * 1024u,
                        prev_wire, &prev_len) && *prev_wire &&
        json_read(prev, (const char *)*prev_wire, prev_len))
        *prev_root_hex = json_get_str(json_get(prev, "checkpoint_root"));
    return 0;
}

/* Bind the predecessor root (explicit, or discovered from prev_root_hex)
 * and default previous_report to the discovered report path. */
static int census_predecessor_apply(struct census_ctx *ctx,
                                    const char *prev_root_hex)
{
    struct census_args *args = &ctx->args;
    if (!args->predecessor_given) {
        if (!prev_root_hex || strlen(prev_root_hex) != 64 ||
            !zcl_hex_decode_lower(prev_root_hex, args->predecessor, 32))
            LOG_ERR(CENSUS_LOG, "sequence %llu needs "
                    "--predecessor-root (or a readable %s with a "
                    "checkpoint_root)",
                    (unsigned long long)args->sequence,
                    ctx->discovered_report);
        args->predecessor_given = true;
        LOG_INFO(CENSUS_LOG, "predecessor root %.16s... from %s",
                 prev_root_hex, ctx->discovered_report);
    }
    if (!args->previous_report && prev_root_hex)
        args->previous_report = ctx->discovered_report;
    return 0;
}

/* Sequence-chain defaults: when advancing the sequence inside an out dir
 * that already holds the previous sequence's report, bind the predecessor
 * root and the growth-delta input from that report automatically. Explicit
 * flags always win; when the predecessor is neither given nor discoverable
 * the run fails closed rather than cutting an unchained checkpoint. */
static int census_stage_predecessor(struct census_ctx *ctx)
{
    struct census_args *args = &ctx->args;
    if (args->sequence <= 1 ||
        (args->predecessor_given && args->previous_report))
        return 0;
    uint8_t *prev_wire = NULL;
    struct json_value prev;
    json_init(&prev);
    const char *prev_root_hex = NULL;
    int rc = census_predecessor_read_report(ctx, &prev, &prev_wire,
                                            &prev_root_hex);
    if (rc == 0)
        rc = census_predecessor_apply(ctx, prev_root_hex);
    free(prev_wire);
    json_free(&prev);
    return rc;
}

/* Load or generate the signer seed and derive the signer keypair. */
static int census_stage_signer(struct census_ctx *ctx)
{
    char default_seed[4096];
    const char *seed_path = ctx->args.seed_path;
    if (!seed_path) {
        const char *home = getenv("HOME");
        if (!home || !shell_safe(home))
            LOG_ERR(CENSUS_LOG, "HOME is unset or unsafe; pass "
                    "--signer-seed-file explicitly");
        if (snprintf(default_seed, sizeof(default_seed),
                     "%s/.config/zclassic23/corpus-census-signer.seed",
                     home) >= (int)sizeof(default_seed))
            LOG_ERR(CENSUS_LOG, "default seed path overflow");
        seed_path = default_seed;
    }
    if (!seed_load_or_create(seed_path, ctx->repo_real, ctx->seed,
                             &ctx->seed_created))
        return 1;
    uint8_t signer_secret[32];
    ed25519_keypair(ctx->signer_pubkey, signer_secret, ctx->seed);
    memory_cleanse(signer_secret, sizeof(signer_secret));
    root_hex(ctx->signer_pubkey, ctx->pubkey_hex);
    if (ctx->seed_created)
        LOG_WARN(CENSUS_LOG,
                 "generated NEW corpus-census signer seed at %s "
                 "(mode 0600, raw 32 bytes); signer_pubkey=%s", seed_path,
                 ctx->pubkey_hex);
    else
        LOG_INFO(CENSUS_LOG, "signer_pubkey=%s seed=%s", ctx->pubkey_hex,
                 seed_path);
    return 0;
}

/* Load scopes.def and cross-check the frozen family-c23.v1 policy root. */
static int census_stage_defs_and_policy(struct census_ctx *ctx)
{
    if (!def_load(ctx->args.def, &ctx->defs, &ctx->scope_count,
                 ctx->def_sha3))
        return 1;
    LOG_INFO(CENSUS_LOG, "loaded %zu scopes from %s", ctx->scope_count,
             ctx->args.def);
    for (size_t s = 0; s < ctx->scope_count; s++) {
        if (ctx->defs[s].is_package) ctx->any_package = true;
        else ctx->any_repo = true;
    }

    struct vcs_zcode_family_policy_v1 policy;
    vcs_zcode_family_policy_v1_default(&policy);
    uint8_t frozen_root[32];
    if (vcs_zcode_family_policy_v1_root(&policy, ctx->family_policy_root) !=
            VCS_ZCODE_COMMONS_OK)
        LOG_ERR(CENSUS_LOG, "family policy root failed");
    if (!zcl_hex_decode_lower(CORPUS_CENSUS_FAMILY_POLICY_ROOT_HEX,
                              frozen_root, 32))
        LOG_ERR(CENSUS_LOG, "frozen family policy root hex decode failed");
    if (memcmp(ctx->family_policy_root, frozen_root, 32) != 0)
        LOG_ERR(CENSUS_LOG,
                "family-c23.v1 default policy root no longer matches the "
                "frozen constant " CORPUS_CENSUS_FAMILY_POLICY_ROOT_HEX);
    if (!evidence_root(k_domain_moderation, NULL, 0,
                       ctx->moderation_set_root))
        return 1;
    return 0;
}

/* Claim resolution over the live tree, then load each package scope's
 * store (manifest + release envelope, fail closed) and take its canonical
 * file list. */
static int census_stage_claims(struct census_ctx *ctx)
{
    if (!claims_resolve(ctx->args.repo, ctx->defs, ctx->scope_count,
                        &ctx->files))
        return 1;
    ctx->runs = zcl_calloc(ctx->scope_count, sizeof(*ctx->runs),
                          "corpus.runs");
    if (!ctx->runs)
        LOG_ERR(CENSUS_LOG, "runs alloc %zu", ctx->scope_count);
    for (size_t s = 0; s < ctx->scope_count; s++) {
        if (!ctx->defs[s].is_package) continue;
        if (!package_ctx_load(&ctx->runs[s].pkg, &ctx->defs[s],
                              ctx->args.store_root))
            return 1;
        ctx->runs[s].pkg_loaded = true;
        if (!package_scope_enumerate(&ctx->runs[s].pkg, &ctx->files[s]))
            return 1;
        /* The LABEL, not the resolved directory: this line is read from
         * captured build logs that get pasted into issues. */
        LOG_INFO(CENSUS_LOG, "package scope %s: %zu files from store '%s'",
                 ctx->defs[s].name, ctx->files[s].n, ctx->defs[s].store);
    }
    return 0;
}

/* Per-scope measurement: release/license/recipe/deps. The repo CAS holds
 * every scope file's bytes for COMPLETE_POSSESSION, and the global quality
 * root is computed only when the operator attests lint passed. */
static int census_stage_measure(struct census_ctx *ctx)
{
    if (!vcs_object_store_init(ctx->args.repo))
        LOG_ERR(CENSUS_LOG, "cannot initialize %s/.zvcs object store",
                ctx->args.repo);

    if (ctx->args.quality_attested &&
        !quality_root_compute(ctx->args.repo, ctx->quality_root))
        return 1;

    for (size_t s = 0; s < ctx->scope_count; s++) {
        struct scope_run *run = &ctx->runs[s];
        const struct package_ctx *pkg =
            ctx->defs[s].is_package ? &run->pkg : NULL;
        run->measure.possession_ok = true;
        struct buf wire = {0};
        if (!scope_release_wire(ctx->args.repo, &ctx->files[s], &wire,
                                &run->measure, ctx->defs[s].name, pkg))
            return 1;
        if (pkg) {
            /* The package scope's release root is the EXACT published
             * package root from the def, already verified against the
             * re-derived manifest root of the stored manifest. */
            memcpy(run->measure.release_root, ctx->defs[s].package_root, 32);
            if (!package_possession_root(pkg, run->measure.possession_root))
                return 1;
        } else if (!evidence_root(k_domain_release, wire.p, wire.len,
                                  run->measure.release_root)) {
            buf_free(&wire);
            return 1;
        }
        buf_free(&wire);
        if (!scope_license_bind(ctx->args.repo, &ctx->defs[s], &run->measure,
                                pkg))
            return 1;
        if (!scope_recipe_bind(ctx->args.repo, &ctx->defs[s], &run->measure,
                               pkg))
            return 1;
        run->in_census = true;
    }
    return 0;
}

/* Package-scope reproduction: a receipts scan for >= 2 distinct
 * byte-identical confined builds. */
static int census_stage_reproduce_packages(struct census_ctx *ctx)
{
    for (size_t s = 0; s < ctx->scope_count; s++) {
        if (!ctx->defs[s].is_package) continue;
        struct scope_run *run = &ctx->runs[s];
        size_t rlen = strlen(run->pkg.zcode_dir) + sizeof("/receipts");
        char *rdir = zcl_malloc(rlen, "corpus.pkg.receipts");
        if (!rdir)
            LOG_ERR(CENSUS_LOG, "receipts path alloc");
        (void)snprintf(rdir, rlen, "%s/receipts", run->pkg.zcode_dir);
        struct vcs_reproduce_report repro;
        if (!vcs_package_reproduce_scan(rdir, ctx->defs[s].package_root,
                                        run->pkg.release.recipe_root,
                                        &repro)) {
            LOG_ERROR(CENSUS_LOG, "package %s: receipts dir %s unreadable",
                      ctx->defs[s].name, rdir);
            free(rdir);
            return 1;
        }
        free(rdir);
        ctx->repro_matched[s] = repro.reproduced;
        for (size_t i = 0; i < repro.row_count; i++) {
            if (repro.rows[i].rule != VCS_REPRODUCE_MATCH) continue;
            char rid_hex[65];
            zcl_hex_encode(repro.rows[i].receipt_id, 32, rid_hex);
            if (!vec_push(&run->receipt_ids, rid_hex))
                LOG_ERR(CENSUS_LOG, "receipt id push failed");
        }
        LOG_INFO(CENSUS_LOG,
                 "package %s: reproduction scan: reproduced=%d matching=%u "
                 "scanned=%u", ctx->defs[s].name, (int)repro.reproduced,
                 repro.matching, repro.scanned);
    }
    return 0;
}

/* REPRODUCIBLE: dual-materialization rederivation at HEAD for repo scopes
 * (package scopes already have repro_matched preset by the receipts
 * scan). */
static int census_stage_reproduce(struct census_ctx *ctx)
{
    ctx->repro_matched = zcl_calloc(ctx->scope_count,
                                    sizeof(*ctx->repro_matched),
                                    "corpus.repro");
    if (!ctx->repro_matched)
        LOG_ERR(CENSUS_LOG, "repro alloc %zu", ctx->scope_count);

    int rc = census_stage_reproduce_packages(ctx);
    if (rc) return rc;

    uint8_t (*expected)[32] =
        zcl_calloc(ctx->scope_count, sizeof(*expected), "corpus.expected");
    if (!expected)
        LOG_ERR(CENSUS_LOG, "expected roots alloc %zu", ctx->scope_count);
    for (size_t s = 0; s < ctx->scope_count; s++)
        memcpy(expected[s], ctx->runs[s].measure.release_root, 32);
    if (!worktree_rederive(ctx->args.repo, ctx->defs, ctx->scope_count,
                           (const uint8_t (*)[32])expected,
                           ctx->repro_matched, &ctx->worktree_used)) {
        free(expected);
        return 1;
    }
    if (!ctx->worktree_used) {
        /* Weaker binding: second in-process enumeration + recompute.
         * Disclosed in the report. */
        if (!rederive_release_roots(ctx->args.repo, ctx->defs,
                                    ctx->scope_count,
                                    (const uint8_t (*)[32])expected,
                                    ctx->repro_matched)) {
            free(expected);
            return 1;
        }
    }
    free(expected);
    ctx->repro_method =
        ctx->worktree_used ? k_repro_worktree : k_repro_fallback;
    if (ctx->any_repo)
        LOG_INFO(CENSUS_LOG, "repo reproduction binding method: %s",
                 ctx->repro_method);
    if (ctx->any_package)
        LOG_INFO(CENSUS_LOG,
                 "package reproduction binding method: "
                 "receipts-dual-confined-build");
    return 0;
}

/* The reproduction wire and, for package scopes, the receipts-derived
 * quality root. */
static bool census_scope_reproduction_wire_build(struct census_ctx *ctx,
                                                 size_t s)
{
    struct scope_run *run = &ctx->runs[s];
    const struct scope_measure *m = &run->measure;
    struct buf rwire = {0};
    bool rok = buf_put(&rwire, m->release_root, 32);
    if (ctx->defs[s].is_package) {
        /* Package binding: release_root || method || concat of the sorted
         * matching receipt ids (the strong two-confined-builds binding). */
        rok = rok &&
            buf_put(&rwire, k_repro_receipts, strlen(k_repro_receipts));
        for (size_t i = 0; rok && i < run->receipt_ids.n; i++) {
            uint8_t rid[32];
            if (!zcl_hex_decode_lower(run->receipt_ids.v[i], rid, 32)) {
                rok = false;
                break;
            }
            rok = buf_put(&rwire, rid, 32);
        }
    } else {
        rok = rok && buf_put(&rwire, ctx->repro_method,
                             strlen(ctx->repro_method));
    }
    if (rok)
        rok = evidence_root(k_domain_reproduction, rwire.p, rwire.len,
                            run->reproduction_root);
    buf_free(&rwire);
    if (!rok) return false;
    if (!ctx->defs[s].is_package) return true;

    /* Package QUALITY_PROFILE mapping: "confined build+test receipt
     * green" — the same receipts evidence. */
    struct buf qwire = {0};
    bool qok = buf_put(&qwire, m->release_root, 32) &&
               buf_put(&qwire, k_quality_receipts, strlen(k_quality_receipts));
    for (size_t i = 0; qok && i < run->receipt_ids.n; i++) {
        uint8_t rid[32];
        if (!zcl_hex_decode_lower(run->receipt_ids.v[i], rid, 32)) {
            qok = false;
            break;
        }
        qok = buf_put(&qwire, rid, 32);
    }
    if (qok)
        qok = evidence_root(k_domain_quality, qwire.p, qwire.len,
                            run->quality_root);
    buf_free(&qwire);
    return qok;
}

/* The evidence mask carries exactly the bits whose bindings succeeded. */
static uint64_t census_scope_evidence_mask(const struct census_ctx *ctx,
                                           size_t s)
{
    const struct scope_run *run = &ctx->runs[s];
    const struct scope_measure *m = &run->measure;
    uint64_t mask = 0;
    if (m->has_api) mask |= VCS_ZCODE_C23_EVIDENCE_API;
    if (zcl_bytes_any_set(m->recipe_root, 32))
        mask |= VCS_ZCODE_C23_EVIDENCE_RECIPE;
    if (m->has_tests_sem) mask |= VCS_ZCODE_C23_EVIDENCE_TESTS;
    if (m->license_ok) mask |= VCS_ZCODE_C23_EVIDENCE_PERMISSIVE_LICENSE;
    if (ctx->defs[s].is_package
            ? (run->reproduced && zcl_bytes_any_set(run->quality_root, 32))
            : (ctx->args.quality_attested &&
               zcl_bytes_any_set(run->quality_root, 32)))
        mask |= VCS_ZCODE_C23_EVIDENCE_QUALITY_PROFILE;
    mask |= VCS_ZCODE_C23_EVIDENCE_SOURCE_ASSIGNMENT;
    if (run->reproduced) mask |= VCS_ZCODE_C23_EVIDENCE_REPRODUCIBLE;
    mask |= VCS_ZCODE_C23_EVIDENCE_FAMILY_QUORUM;
    if (m->possession_ok && zcl_bytes_any_set(m->possession_root, 32))
        mask |= VCS_ZCODE_C23_EVIDENCE_COMPLETE_POSSESSION;
    return mask;
}

/* Reload the scope's bytes and feed them to the pure census core. */
static bool census_scope_feed_core(struct census_ctx *ctx, size_t s,
                                   struct vcs_zcode_corpus_census *census,
                                   uint64_t mask)
{
    struct scope_run *run = &ctx->runs[s];
    const struct scope_measure *m = &run->measure;
    struct vcs_zcode_corpus_census_file *cfiles = NULL;
    if (ctx->files[s].n) {
        cfiles = zcl_calloc(ctx->files[s].n, sizeof(*cfiles),
                            "corpus.census.files");
        if (!cfiles)
            LOG_FAIL(CENSUS_LOG, "census files alloc %zu", ctx->files[s].n);
    }
    for (size_t i = 0; i < ctx->files[s].n; i++) {
        cfiles[i].path = ctx->files[s].paths[i];
        bool loaded = ctx->defs[s].is_package
            ? package_file_load(&run->pkg, ctx->files[s].paths[i],
                                (uint8_t **)&cfiles[i].bytes, &cfiles[i].len,
                                &cfiles[i].declared_size)
            : file_load(ctx->args.repo, ctx->files[s].paths[i],
                       (uint8_t **)&cfiles[i].bytes, &cfiles[i].len,
                       &cfiles[i].declared_size);
        if (!loaded) {
            for (size_t k = 0; k < i; k++) free((void *)cfiles[k].bytes);
            free(cfiles);
            return false;
        }
    }
    struct vcs_zcode_corpus_census_scope_input input;
    memset(&input, 0, sizeof(input));
    input.name = ctx->defs[s].name;
    input.source_kind = ctx->defs[s].kind;
    input.license_spdx = ctx->defs[s].spdx;
    memcpy(input.license_root, m->license_root, 32);
    input.evidence_mask = mask;
    memcpy(input.release_root, m->release_root, 32);
    memcpy(input.passport_root, run->passport_root, 32);
    memcpy(input.proof_root, run->proof_root, 32);
    memcpy(input.source_assignment_root, run->assignment_root, 32);
    memcpy(input.admission_root, run->admission_root, 32);
    /* possession_root stays ZERO in the entry: nothing is durable yet; the
     * computed root is recorded in the report only. */
    input.release_sequence = 1;
    input.files = cfiles;
    input.file_count = ctx->files[s].n;
    bool ok = vcs_zcode_corpus_census_process_scope(census, &input,
                                                    &run->result);
    for (size_t k = 0; k < ctx->files[s].n; k++) free((void *)cfiles[k].bytes);
    free(cfiles);
    return ok;
}

/* Signed evidence + census per scope, in sorted scope order. */
/* One scope's assignment/admission/passport/evidence-feed work for the
 * evidence stage; split out of census_stage_evidence to keep the per-scope
 * loop body a single named unit. */
static bool census_evidence_scope_build(struct census_ctx *ctx, size_t s,
                                        struct vcs_zcode_corpus_census *census)
{
    struct scope_run *run = &ctx->runs[s];
    run->reproduced = ctx->repro_matched[s];
    if (run->reproduced && !census_scope_reproduction_wire_build(ctx, s))
        return false;
    if (!scope_assignment_build(&ctx->defs[s], s, ctx->args.cutoff_height,
                                ctx->args.cutoff_mtp, &run->measure,
                                ctx->defs[s].is_package
                                    ? run->pkg.publisher_hex : NULL,
                                ctx->seed, run->assignment_root,
                                run->assignment_wire,
                                &run->assignment_wire_len))
        return false;
    if (!scope_admission_build(&ctx->defs[s], ctx->args.cutoff_height,
                               ctx->args.cutoff_mtp, &run->measure,
                               run->assignment_root,
                               ctx->family_policy_root,
                               ctx->moderation_set_root, ctx->seed,
                               run->admission_root, run->admission_wire,
                               &run->admission_wire_len))
        return false;
    /* Package scopes carry their own receipts-green quality root
     * (computed above when reproduced); repo scopes share the global
     * lint-attested quality root. */
    if (!ctx->defs[s].is_package)
        memcpy(run->quality_root, ctx->quality_root, 32);
    if (!scope_passport_proof(&ctx->defs[s], &run->measure,
                              run->assignment_root, run->admission_root,
                              run->quality_root, run->reproduction_root,
                              run->passport_root, run->proof_root))
        return false;

    uint64_t mask = census_scope_evidence_mask(ctx, s);
    run->evidence_mask = mask;
    return census_scope_feed_core(ctx, s, census, mask);
}

/* Zero-unit scopes share the empty-lineage root; the assembly fails closed
 * on a collision, so keep only the first (they carry no countable content)
 * and report the rest as omitted. Sets ctx->census_count and each run's
 * in_census flag. */
static void census_evidence_filter_kept(struct census_ctx *ctx)
{
    bool empty_seen = false;
    ctx->census_count = 0;
    for (size_t s = 0; s < ctx->scope_count; s++) {
        if (ctx->runs[s].result.units_total == 0) {
            if (empty_seen) {
                ctx->runs[s].in_census = false;
                LOG_WARN(CENSUS_LOG,
                         "scope %s has zero semantic units; omitting "
                         "from the census (lineage collision guard)",
                         ctx->defs[s].name);
            } else {
                empty_seen = true;
            }
        }
        if (ctx->runs[s].in_census) ctx->census_count++;
    }
}

/* Allocate the kept-scope array, fill it from the in_census runs, and
 * assemble the global census over it. */
static int census_evidence_assemble_kept(struct census_ctx *ctx)
{
    if (!ctx->census_count)
        LOG_ERR(CENSUS_LOG, "no scopes to assemble");
    ctx->kept = zcl_calloc(ctx->census_count, sizeof(*ctx->kept),
                          "corpus.kept");
    if (!ctx->kept)
        LOG_ERR(CENSUS_LOG, "kept alloc %zu", ctx->census_count);
    size_t kept_n = 0;
    for (size_t s = 0; s < ctx->scope_count; s++)
        if (ctx->runs[s].in_census) ctx->kept[kept_n++] = ctx->runs[s].result;

    enum vcs_zcode_c23_error error = vcs_zcode_corpus_census_assemble(
        ctx->kept, ctx->census_count, ctx->family_policy_root,
        ctx->moderation_set_root, &ctx->assembly);
    if (error != VCS_ZCODE_C23_OK)
        LOG_ERR(CENSUS_LOG, "census assemble: %s",
                vcs_zcode_c23_error_string(error));
    return 0;
}

static int census_stage_evidence(struct census_ctx *ctx)
{
    struct vcs_zcode_corpus_census census;
    vcs_zcode_corpus_census_init(&census);
    for (size_t s = 0; s < ctx->scope_count; s++) {
        if (!census_evidence_scope_build(ctx, s, &census))
            return 1;
    }
    free(ctx->repro_matched);
    ctx->repro_matched = NULL;

    census_evidence_filter_kept(ctx);
    int rc = census_evidence_assemble_kept(ctx);
    vcs_zcode_corpus_census_free(&census);
    return rc;
}

/* Shard the globally sorted census entries into the inline-readable cap
 * and build each shard's checkpoint binding. */
/* Compute the shard count and allocate the parallel per-shard arrays that
 * census_stage_shards fills in. */
static int census_shards_alloc(struct census_ctx *ctx)
{
    ctx->shard_count = (ctx->census_count + CORPUS_CENSUS_SHARD_ENTRY_CAP -
                        1u) / CORPUS_CENSUS_SHARD_ENTRY_CAP;
    if (ctx->shard_count > CORPUS_CENSUS_CHECKPOINT_INLINE_SHARD_CAP)
        LOG_ERR(CENSUS_LOG,
                "%zu shards exceed the %u inline checkpoint reader cap; "
                "raise the reader budget before emitting more",
                ctx->shard_count, CORPUS_CENSUS_CHECKPOINT_INLINE_SHARD_CAP);
    ctx->bindings = zcl_calloc(ctx->shard_count, sizeof(*ctx->bindings),
                              "corpus.bindings");
    ctx->shard_wires = zcl_calloc(ctx->shard_count,
                                  sizeof(*ctx->shard_wires),
                                  "corpus.shardwires");
    if (!ctx->bindings || !ctx->shard_wires)
        LOG_ERR(CENSUS_LOG, "shard arrays alloc %zu", ctx->shard_count);
    ctx->shard_wire_lens = zcl_calloc(ctx->shard_count,
                                      sizeof(*ctx->shard_wire_lens),
                                      "corpus.shardlens");
    if (!ctx->shard_wire_lens)
        LOG_ERR(CENSUS_LOG, "shard lens alloc %zu", ctx->shard_count);
    ctx->shard_roots = zcl_calloc(ctx->shard_count, sizeof(*ctx->shard_roots),
                                 "corpus.shardroots");
    if (!ctx->shard_roots)
        LOG_ERR(CENSUS_LOG, "shard roots alloc %zu", ctx->shard_count);
    return 0;
}

/* Accumulate one shard binding's LOC/unit totals across one entry. */
static int census_shard_binding_sum(
    struct vcs_zcode_c23_checkpoint_shard_v1 *b,
    const struct vcs_zcode_c23_corpus_entry_v1 *entry, size_t i)
{
    uint64_t entry_loc = 0;
    bool sum_ok =
        zcl_u64_add(entry->production_loc, entry->test_loc,
                    &entry_loc) &&
        zcl_u64_add(b->production_loc, entry->production_loc,
                    &b->production_loc) &&
        zcl_u64_add(b->test_loc, entry->test_loc, &b->test_loc) &&
        zcl_u64_add(b->physical_lines, entry->physical_lines,
                    &b->physical_lines) &&
        zcl_u64_add(b->unique_semantic_units,
                    entry->unique_semantic_units,
                    &b->unique_semantic_units);
    if (sum_ok && (entry->flags & VCS_ZCODE_C23_ENTRY_DURABLE))
        sum_ok = zcl_u64_add(b->durable_loc, entry_loc,
                             &b->durable_loc);
    if (!sum_ok)
        LOG_ERR(CENSUS_LOG, "shard %zu binding sum overflow", i);
    return 0;
}

/* Build, validate, encode and root shard `i`, then fill its checkpoint
 * binding from the assembled entries it covers. */
static int census_shard_build_one(struct census_ctx *ctx, size_t i)
{
    size_t first = i * CORPUS_CENSUS_SHARD_ENTRY_CAP;
    size_t count = ctx->census_count - first;
    if (count > CORPUS_CENSUS_SHARD_ENTRY_CAP)
        count = CORPUS_CENSUS_SHARD_ENTRY_CAP;
    struct vcs_zcode_c23_corpus_shard_v1 shard;
    memset(&shard, 0, sizeof(shard));
    shard.schema_version = 1;
    shard.flags = VCS_ZCODE_C23_CORPUS_REQUIRED_FLAGS;
    memcpy(shard.rules_root, ctx->assembly.rules_root, 32);
    memcpy(shard.family_policy_root, ctx->family_policy_root, 32);
    memcpy(shard.moderation_set_root, ctx->moderation_set_root, 32);
    shard.entries = &ctx->assembly.entries[first];
    shard.entry_count = count;
    enum vcs_zcode_c23_error error =
        vcs_zcode_c23_corpus_shard_v1_validate(&shard);
    if (error != VCS_ZCODE_C23_OK)
        LOG_ERR(CENSUS_LOG, "shard %zu validate: %s", i,
                vcs_zcode_c23_error_string(error));
    size_t wire_size = vcs_zcode_c23_corpus_shard_v1_wire_size(count);
    if (!wire_size || wire_size > 8192u)
        LOG_ERR(CENSUS_LOG, "shard %zu wire size %zu", i, wire_size);
    uint8_t *wire = zcl_malloc(wire_size, "corpus.shard.wire");
    if (!wire)
        LOG_ERR(CENSUS_LOG, "shard wire alloc %zu", wire_size);
    size_t wire_len = 0;
    error = vcs_zcode_c23_corpus_shard_v1_encode(&shard, wire, wire_size,
                                                 &wire_len);
    if (error != VCS_ZCODE_C23_OK || wire_len != wire_size) {
        free(wire);
        LOG_ERR(CENSUS_LOG, "shard %zu encode: %s", i,
                vcs_zcode_c23_error_string(error));
    }
    error = vcs_zcode_c23_corpus_shard_v1_root(&shard,
                                               ctx->shard_roots[i]);
    if (error != VCS_ZCODE_C23_OK) {
        free(wire);
        LOG_ERR(CENSUS_LOG, "shard %zu root: %s", i,
                vcs_zcode_c23_error_string(error));
    }
    ctx->shard_wires[i] = wire;
    ctx->shard_wire_lens[i] = wire_len;

    struct vcs_zcode_c23_checkpoint_shard_v1 *b = &ctx->bindings[i];
    memcpy(b->shard_root, ctx->shard_roots[i], 32);
    memcpy(b->first_lineage_root,
           ctx->assembly.entries[first].semantic_lineage_root, 32);
    memcpy(b->last_lineage_root,
           ctx->assembly.entries[first + count - 1u].semantic_lineage_root,
           32);
    b->entry_count = count;
    for (size_t e = first; e < first + count; e++) {
        int rc = census_shard_binding_sum(b, &ctx->assembly.entries[e], i);
        if (rc != 0) return rc;
    }
    return 0;
}

/* replication_evidence_root: concatenated shard roots + the disclosed
 * single-host-founding literal. */
static int census_replication_root_build(struct census_ctx *ctx)
{
    struct buf wire = {0};
    bool ok = true;
    for (size_t i = 0; ok && i < ctx->shard_count; i++)
        ok = buf_put(&wire, ctx->shard_roots[i], 32);
    ok = ok &&
         buf_put(&wire, k_replication_literal,
                 strlen(k_replication_literal)) &&
         evidence_root(k_domain_replication, wire.p, wire.len,
                       ctx->replication_root);
    buf_free(&wire);
    if (!ok)
        LOG_ERR(CENSUS_LOG, "replication evidence root failed");
    return 0;
}

static int census_stage_shards(struct census_ctx *ctx)
{
    int rc = census_shards_alloc(ctx);
    if (rc != 0) return rc;
    for (size_t i = 0; i < ctx->shard_count; i++) {
        rc = census_shard_build_one(ctx, i);
        if (rc != 0) return rc;
    }
    return census_replication_root_build(ctx);
}

/* Sign the checkpoint and encode its wire. */
static int census_stage_checkpoint(struct census_ctx *ctx)
{
    struct vcs_zcode_c23_corpus_checkpoint_v1 *checkpoint = &ctx->checkpoint;
    memset(checkpoint, 0, sizeof(*checkpoint));
    checkpoint->schema_version = 1;
    checkpoint->flags = VCS_ZCODE_C23_CORPUS_REQUIRED_FLAGS;
    checkpoint->milestone = VCS_ZCODE_C23_MILESTONE_NONE;
    checkpoint->sequence = ctx->args.sequence;
    memcpy(checkpoint->predecessor_checkpoint_root, ctx->args.predecessor, 32);
    memcpy(checkpoint->rules_root, ctx->assembly.rules_root, 32);
    memcpy(checkpoint->family_policy_root, ctx->family_policy_root, 32);
    memcpy(checkpoint->moderation_set_root, ctx->moderation_set_root, 32);
    memcpy(checkpoint->replication_evidence_root, ctx->replication_root, 32);
    checkpoint->cutoff_height = ctx->args.cutoff_height;
    checkpoint->cutoff_mtp = ctx->args.cutoff_mtp;
    checkpoint->total_entries = ctx->census_count;
    checkpoint->production_loc = ctx->assembly.production_loc;
    checkpoint->test_loc = ctx->assembly.test_loc;
    checkpoint->durable_loc = ctx->assembly.durable_loc;
    checkpoint->physical_lines = ctx->assembly.physical_lines;
    checkpoint->unique_semantic_units = ctx->assembly.unique_semantic_units;
    checkpoint->excluded_entries = ctx->assembly.excluded_entries;
    checkpoint->shards = ctx->bindings;
    checkpoint->shard_count = ctx->shard_count;
    enum vcs_zcode_c23_error error =
        vcs_zcode_c23_corpus_checkpoint_v1_sign(checkpoint, ctx->seed);
    if (error != VCS_ZCODE_C23_OK)
        LOG_ERR(CENSUS_LOG, "checkpoint sign: %s",
                vcs_zcode_c23_error_string(error));
    error = vcs_zcode_c23_corpus_checkpoint_v1_root(checkpoint,
                                                    ctx->checkpoint_root);
    if (error != VCS_ZCODE_C23_OK)
        LOG_ERR(CENSUS_LOG, "checkpoint root: %s",
                vcs_zcode_c23_error_string(error));
    ctx->checkpoint_wire_len = 0;
    size_t checkpoint_wire_size =
        vcs_zcode_c23_corpus_checkpoint_v1_wire_size(ctx->shard_count);
    if (!checkpoint_wire_size || checkpoint_wire_size > 8192u)
        LOG_ERR(CENSUS_LOG, "checkpoint wire size %zu",
                checkpoint_wire_size);
    ctx->checkpoint_wire =
        zcl_malloc(checkpoint_wire_size, "corpus.checkpoint.wire");
    if (!ctx->checkpoint_wire)
        LOG_ERR(CENSUS_LOG, "checkpoint wire alloc %zu",
                checkpoint_wire_size);
    error = vcs_zcode_c23_corpus_checkpoint_v1_encode(
        checkpoint, ctx->checkpoint_wire, checkpoint_wire_size,
        &ctx->checkpoint_wire_len);
    if (error != VCS_ZCODE_C23_OK ||
        ctx->checkpoint_wire_len != checkpoint_wire_size) {
        free(ctx->checkpoint_wire);
        LOG_ERR(CENSUS_LOG, "checkpoint encode: %s",
                vcs_zcode_c23_error_string(error));
    }
    return 0;
}

/* Write the checkpoint hex + every shard hex into the report out dir. */
static int census_write_checkpoint_artifacts(struct census_ctx *ctx)
{
    if (mkdir(ctx->args.out, 0755) != 0 && errno != EEXIST)
        LOG_ERR(CENSUS_LOG, "mkdir %s: %s", ctx->args.out, strerror(errno));
    char name[128];
    (void)snprintf(name, sizeof(name), "checkpoint-%06llu.hex",
                   (unsigned long long)ctx->args.sequence);
    if (!write_hex_artifact(ctx->args.out, name, ctx->checkpoint_wire,
                            ctx->checkpoint_wire_len))
        return 1;
    strcpy(ctx->checkpoint_file, name);
    for (size_t i = 0; i < ctx->shard_count; i++) {
        (void)snprintf(name, sizeof(name), "shard-%06llu-%zu.hex",
                       (unsigned long long)ctx->args.sequence, i);
        if (!write_hex_artifact(ctx->args.out, name, ctx->shard_wires[i],
                                ctx->shard_wire_lens[i]))
            return 1;
    }
    return 0;
}

/* Install the checkpoint wire into <datadir>/zcode/corpus/checkpoint.hex,
 * creating the two parent directories as needed. */
static int census_install_checkpoint(struct census_ctx *ctx)
{
    if (mkdir(ctx->args.install_datadir, 0755) != 0 && errno != EEXIST) {
        LOG_ERROR(CENSUS_LOG, "install mkdir %s: %s",
                  ctx->args.install_datadir, strerror(errno));
        return 1;
    }
    size_t dir_cap = strlen(ctx->args.install_datadir) + 32u;
    char *zcode_dir = zcl_malloc(dir_cap, "corpus.install.dir");
    if (!zcode_dir)
        LOG_ERR(CENSUS_LOG, "install dir alloc");
    (void)snprintf(zcode_dir, dir_cap, "%s/zcode", ctx->args.install_datadir);
    if (mkdir(zcode_dir, 0755) != 0 && errno != EEXIST) {
        LOG_ERROR(CENSUS_LOG, "install mkdir %s: %s", zcode_dir,
                  strerror(errno));
        free(zcode_dir);
        return 1;
    }
    size_t cdir_cap = dir_cap + 8u;
    char *corpus_dir = zcl_malloc(cdir_cap, "corpus.install.cdir");
    if (!corpus_dir) {
        free(zcode_dir);
        LOG_ERR(CENSUS_LOG, "install corpus dir alloc");
    }
    (void)snprintf(corpus_dir, cdir_cap, "%s/corpus", zcode_dir);
    free(zcode_dir);
    if (mkdir(corpus_dir, 0755) != 0 && errno != EEXIST) {
        LOG_ERROR(CENSUS_LOG, "install mkdir %s: %s", corpus_dir,
                  strerror(errno));
        free(corpus_dir);
        return 1;
    }
    bool installed = write_hex_artifact(corpus_dir, "checkpoint.hex",
                                        ctx->checkpoint_wire,
                                        ctx->checkpoint_wire_len);
    free(corpus_dir);
    if (!installed) return 1;
    LOG_INFO(CENSUS_LOG, "installed resident checkpoint into %s/zcode/"
             "corpus/checkpoint.hex", ctx->args.install_datadir);
    return 0;
}

/* Write the checkpoint + shard artifacts, and optionally install the
 * checkpoint wire into a datadir. */
static int census_stage_write_checkpoint(struct census_ctx *ctx)
{
    int rc = census_write_checkpoint_artifacts(ctx);
    if (rc != 0) return rc;
    if (!ctx->args.install_datadir) return 0;
    return census_install_checkpoint(ctx);
}

/* git HEAD + dirty-tree provenance for the report (never in signed
 * objects). */
static int census_stage_git_provenance(struct census_ctx *ctx)
{
    char dirty_probe[8192] = {0};
    if (!git_capture(ctx->args.repo, "rev-parse HEAD", ctx->head_hex,
                     sizeof(ctx->head_hex)) ||
        !git_capture(ctx->args.repo, "status --porcelain", dirty_probe,
                     sizeof(dirty_probe)))
        return 1;
    ctx->repo_dirty = dirty_probe[0] != '\0';
    return 0;
}

/* Build and write the evidence bundle, then the KPI report. Both builders
 * return false only for the handful of allocation/overflow checks that
 * used to exit main() via LOG_ERR (exit code -1); every other failure
 * inside them is unreachable (unchecked JSON pushes never fail). */
static int census_stage_write_documents(struct census_ctx *ctx)
{
    char name[128];
    struct json_value evidence;
    if (!census_build_evidence_bundle(ctx, &evidence))
        return -1;
    (void)snprintf(name, sizeof(name), "evidence-%06llu.json",
                   (unsigned long long)ctx->args.sequence);
    if (!write_json_artifact(ctx->args.out, name, &evidence)) {
        json_free(&evidence);
        return 1;
    }
    json_free(&evidence);

    struct json_value report;
    if (!census_build_kpi_report(ctx, &report))
        return -1;
    (void)snprintf(name, sizeof(name), "report-%06llu.json",
                   (unsigned long long)ctx->args.sequence);
    if (!report_keys_unique(&report)) {
        LOG_ERROR(CENSUS_LOG, "report %s contains duplicate JSON keys",
                  name);
        json_free(&report);
        return 1;
    }
    if (!write_json_artifact(ctx->args.out, name, &report)) {
        json_free(&report);
        return 1;
    }
    json_free(&report);
    return 0;
}

static void census_stage_summary(const struct census_ctx *ctx)
{
    uint64_t admitted = 0;
    (void)zcl_u64_add(ctx->assembly.production_loc, ctx->assembly.test_loc,
                      &admitted);
    char root_text[65];
    root_hex(ctx->checkpoint_root, root_text);
    printf("corpus-census: sequence=%llu scopes=%zu census_entries=%zu "
           "shards=%zu\n",
           (unsigned long long)ctx->args.sequence, ctx->scope_count,
           ctx->census_count, ctx->shard_count);
    printf("  admitted_production_loc=%llu admitted_test_loc=%llu "
           "admitted_total_loc=%llu\n",
           (unsigned long long)ctx->assembly.production_loc,
           (unsigned long long)ctx->assembly.test_loc,
           (unsigned long long)admitted);
    printf("  durably_hosted_loc=%llu physical_lines=%llu "
           "unique_semantic_units=%llu\n",
           (unsigned long long)ctx->assembly.durable_loc,
           (unsigned long long)ctx->assembly.physical_lines,
           (unsigned long long)ctx->assembly.unique_semantic_units);
    printf("  packages_admitted=%llu packages_excluded=%llu\n",
           (unsigned long long)(ctx->census_count -
                                ctx->assembly.excluded_entries),
           (unsigned long long)ctx->assembly.excluded_entries);
    printf("  signer_pubkey=%s\n  checkpoint_root=%s\n", ctx->pubkey_hex,
           root_text);
    printf("  artifacts: %s/{%s,shard-%06llu-*.hex,evidence-%06llu.json,"
           "report-%06llu.json}\n",
           ctx->args.out, ctx->checkpoint_file,
           (unsigned long long)ctx->args.sequence,
           (unsigned long long)ctx->args.sequence,
           (unsigned long long)ctx->args.sequence);
}

static void census_stage_cleanup(struct census_ctx *ctx)
{
    memory_cleanse(ctx->seed, sizeof(ctx->seed));
    for (size_t i = 0; i < ctx->shard_count; i++) free(ctx->shard_wires[i]);
    free(ctx->shard_wires);
    free(ctx->shard_wire_lens);
    free(ctx->shard_roots);
    free(ctx->bindings);
    free(ctx->checkpoint_wire);
    vcs_zcode_corpus_census_assembly_free(&ctx->assembly);
    free(ctx->kept);
    for (size_t s = 0; s < ctx->scope_count; s++) {
        scope_measure_free(&ctx->runs[s].measure);
        package_ctx_free(&ctx->runs[s].pkg);
        vec_free(&ctx->runs[s].receipt_ids);
        scope_files_free(&ctx->files[s]);
        scope_def_free(&ctx->defs[s]);
    }
    free(ctx->runs);
    free(ctx->files);
    free(ctx->defs);
}

int main(int argc, char **argv)
{
    struct census_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    int rc;
    if ((rc = census_stage_args(argc, argv, &ctx)) != 0) return rc;
    if ((rc = census_stage_predecessor(&ctx)) != 0) return rc;
    if ((rc = census_stage_signer(&ctx)) != 0) return rc;
    if ((rc = census_stage_defs_and_policy(&ctx)) != 0) return rc;
    if ((rc = census_stage_claims(&ctx)) != 0) return rc;
    if ((rc = census_stage_measure(&ctx)) != 0) return rc;
    if ((rc = census_stage_reproduce(&ctx)) != 0) return rc;
    if ((rc = census_stage_evidence(&ctx)) != 0) return rc;
    if ((rc = census_stage_shards(&ctx)) != 0) return rc;
    if ((rc = census_stage_checkpoint(&ctx)) != 0) return rc;
    if ((rc = census_stage_write_checkpoint(&ctx)) != 0) return rc;
    if ((rc = census_stage_git_provenance(&ctx)) != 0) return rc;
    if ((rc = census_stage_write_documents(&ctx)) != 0) return rc;
    census_stage_summary(&ctx);
    census_stage_cleanup(&ctx);
    return 0;
}
