/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * corpus-census: offline driver for the C23 corpus odometer (slice 1b).
 * Reads corpus/scopes.def, enumerates each scope's tracked files with
 * `git ls-files -z` (untracked scratch — test-tmp/, build/, .zvcs/ — can
 * never enter the census), binds every evidence bit to a REAL recomputable
 * artifact, feeds the pure census core (lib/vcs zcode_c23_corpus_census),
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
 * lib/test/src/test_base beats the shared lib/test/ remainder scope); two
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
 */

#define _GNU_SOURCE

#include "base/checked.h"
#include "base/bytes.h"
#include "base/cleanse.h"
#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "json/json.h"
#include "platform/rng.h"
#include "sha3/sha3.h"
#include "vcs/package_build.h"
#include "vcs/package_manifest.h"
#include "vcs/package_recipe.h"
#include "vcs/package_release.h"
#include "vcs/package_reproduce.h"
#include "vcs/package_score.h"
#include "vcs/signed_evidence.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_c23_corpus.h"
#include "vcs/zcode_c23_corpus_census.h"
#include "vcs/zcode_commons.h"
#include "vcs/zcode_family_admission.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define CENSUS_LOG "corpus.census"

/* Shards are capped at 28 entries so every shard wire stays within the
 * 8192-byte inline bound of the shipped `zcode commons corpus shard
 * verify`/`shard page` readers (112-byte header + 28*280-byte entries =
 * 7952; the protocol cap VCS_ZCODE_C23_SHARD_ENTRY_MAX is 4096). The
 * checkpoint reader inlines at most (8192-388)/144 = 54 shard bindings. */
#define CORPUS_CENSUS_SHARD_ENTRY_CAP 28u
#define CORPUS_CENSUS_CHECKPOINT_INLINE_SHARD_CAP 54u

/* Admission expiry horizon for founding self-screened admissions:
 * cutoff + 525600 blocks / +31536000 MTP seconds (~1 year). */
#define CORPUS_CENSUS_ADMISSION_EXPIRY_BLOCKS UINT64_C(525600)
#define CORPUS_CENSUS_ADMISSION_EXPIRY_MTP_SECONDS INT64_C(31536000)

/* The frozen family-c23.v1 policy root (docs/work/ZC23_FAMILY_COMMONS.md);
 * cross-checked at runtime against vcs_zcode_family_policy_v1_default(). */
#define CORPUS_CENSUS_FAMILY_POLICY_ROOT_HEX \
    "460d650c5be714f27dde287c368eafb781467026a1c06a8215fbe17dc610ea86"

#define CORPUS_CENSUS_DEF_MAX_BYTES (1024u * 1024u)
#define CORPUS_CENSUS_MAX_PREFIXES 16u
#define CORPUS_CENSUS_CMD_MAX 4096u

static const char k_domain_release[] = "zcl.zcode.corpus.release.v1";
static const char k_domain_license[] = "zcl.zcode.corpus.license.v1";
static const char k_domain_author[] = "zcl.zcode.corpus.author_binding.v1";
static const char k_domain_assignment_evidence[] =
    "zcl.zcode.corpus.assignment_evidence.v1";
static const char k_domain_dep_closure[] =
    "zcl.zcode.corpus.dependency_closure.v1";
static const char k_domain_moderation[] = "zcl.zcode.corpus.moderation_set.v1";
static const char k_domain_panel[] = "zcl.zcode.corpus.panel.v1";
static const char k_domain_admission_evidence[] =
    "zcl.zcode.corpus.admission_evidence.v1";
static const char k_domain_passport[] = "zcl.zcode.corpus.passport.v1";
static const char k_domain_recipe[] = "zcl.zcode.corpus.recipe.v1";
static const char k_domain_quality[] = "zcl.zcode.corpus.quality.v1";
static const char k_domain_reproduction[] =
    "zcl.zcode.corpus.reproduction.v1";
static const char k_domain_proof[] = "zcl.zcode.corpus.proof.v1";
static const char k_domain_possession[] = "zcl.zcode.corpus.possession.v1";
static const char k_domain_replication[] = "zcl.zcode.corpus.replication.v1";

static const char k_author_human[] = "ZClassic23 founding contributors";
static const char k_author_ai[] = "zclassic23-agent-fleet";
static const char k_panel_literal[] = "founding-self-screen";
static const char k_repro_worktree[] = "dual-worktree";
static const char k_repro_fallback[] = "in-process-reenumeration";
static const char k_repro_receipts[] = "receipts-dual-confined-build";
static const char k_quality_receipts[] = "confined-build-test-receipt-green";
static const char k_replication_literal[] = "single-host-founding-v1";

/* ── small growable containers ────────────────────────────────────── */

struct str_vec {
    char **v;
    size_t n, cap;
};

static void vec_free(struct str_vec *vec)
{
    if (!vec) return;
    for (size_t i = 0; i < vec->n; i++) free(vec->v[i]);
    free(vec->v);
    memset(vec, 0, sizeof(*vec));
}

static bool vec_push_len(struct str_vec *vec, const char *s, size_t len)
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

static bool vec_push(struct str_vec *vec, const char *s)
{
    return vec_push_len(vec, s, strlen(s));
}

static int cmp_strp(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* qsort comparator over fixed 32-byte values (chunk hashes, receipt ids). */
static int cmp_bytes32(const void *a, const void *b)
{
    return memcmp(a, b, 32);
}

struct buf {
    uint8_t *p;
    size_t len, cap;
};

static void buf_free(struct buf *b)
{
    if (!b) return;
    free(b->p);
    memset(b, 0, sizeof(*b));
}

static bool buf_put(struct buf *b, const void *data, size_t len)
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

static bool buf_put_u64le(struct buf *b, uint64_t v)
{
    uint8_t le[8];
    zcl_write_u64_le(le, v);
    return buf_put(b, le, sizeof(le));
}

/* ── roots, hex, charset helpers ──────────────────────────────────── */

static bool evidence_root(const char *domain, const uint8_t *wire,
                          size_t wire_len, uint8_t out[32])
{
    if (!vcs_signed_evidence_root(domain, strlen(domain) + 1u, wire,
                                  wire_len, out))
        LOG_FAIL(CENSUS_LOG, "evidence root failed for domain %s", domain);
    return true;
}

static void root_hex(const uint8_t root[32], char out[65])
{
    zcl_hex_encode(root, 32, out);
}

static void json_push_root(struct json_value *obj, const char *key,
                           const uint8_t root[32])
{
    char hex[65];
    root_hex(root, hex);
    (void)json_push_kv_str(obj, key, hex);
}

/* Push one string onto a JSON array (json_push_back copies). */
static void json_push_str(struct json_value *arr, const char *s)
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
static bool shell_safe(const char *s)
{
    if (!s || !*s) return false;
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!(isalnum(c) || c == '.' || c == '_' || c == '/' || c == '-'))
            return false;
    }
    return true;
}

static bool counted_extension(const char *path)
{
    size_t len = strlen(path);
    return (len >= 3 && strcmp(path + len - 2, ".c") == 0) ||
           (len >= 3 && strcmp(path + len - 2, ".h") == 0) ||
           (len >= 5 && strcmp(path + len - 4, ".def") == 0);
}

/* ── scope definition file ────────────────────────────────────────── */

struct prefix {
    char *text;   /* as written in the def */
    bool is_dir;  /* trailing '/' => directory tree prefix */
};

struct scope_def {
    char *name;
    char *spdx;
    char *def_line;        /* raw line bytes, no trailing newline */
    uint16_t kind;         /* enum vcs_zcode_source_kind_v1 */
    struct prefix src[CORPUS_CENSUS_MAX_PREFIXES];
    size_t nsrc;
    struct prefix tests[CORPUS_CENSUS_MAX_PREFIXES];
    size_t ntests;
    /* Package scope (second def line form): enumerate the published
     * package at package_root from <store>/zcode instead of git. */
    bool is_package;
    char *store;           /* datadir path (package scopes only) */
    uint8_t package_root[32];
};

static void scope_def_free(struct scope_def *def)
{
    if (!def) return;
    free(def->name);
    free(def->spdx);
    free(def->def_line);
    free(def->store);
    for (size_t i = 0; i < def->nsrc; i++) free(def->src[i].text);
    for (size_t i = 0; i < def->ntests; i++) free(def->tests[i].text);
    memset(def, 0, sizeof(*def));
}

static bool prefix_list_parse(struct prefix *out, size_t *count,
                              const char *list, size_t line_no)
{
    size_t n = 0;
    const char *p = list;
    for (;;) {
        const char *comma = strchr(p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen(p);
        if (!len || n == CORPUS_CENSUS_MAX_PREFIXES) {
            LOG_ERROR(CENSUS_LOG, "line %zu: bad prefix list '%s'",
                      line_no, list);
            return false;
        }
        char *copy = zcl_malloc(len + 1u, "corpus.prefix");
        if (!copy)
            LOG_FAIL(CENSUS_LOG, "prefix alloc %zu (line %zu)", len,
                     line_no);
        memcpy(copy, p, len);
        copy[len] = '\0';
        if (!shell_safe(copy)) {
            LOG_ERROR(CENSUS_LOG, "line %zu: bad prefix '%s'", line_no,
                      copy);
            free(copy);
            return false;
        }
        out[n].text = copy;
        out[n].is_dir = copy[len - 1] == '/';
        n++;
        if (!comma) break;
        p = comma + 1;
    }
    *count = n;
    return true;
}

static char *trim(char *s)
{
    while (isspace((unsigned char)*s)) s++;
    size_t len = strlen(s);
    while (len && isspace((unsigned char)s[len - 1])) s[--len] = '\0';
    return s;
}

static bool key_value(const char *token, const char *key,
                      const char **value)
{
    size_t klen = strlen(key);
    if (strncmp(token, key, klen) != 0 || token[klen] != ' ') return false;
    token += klen + 1;
    while (isspace((unsigned char)*token)) token++;
    if (!*token) return false;
    *value = token;
    return true;
}

static char *dup_str(const char *s, const char *label)
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

static bool kind_parse(const char *value, uint16_t *kind_out)
{
    if (strcmp(value, "human") == 0)
        *kind_out = VCS_ZCODE_SOURCE_HUMAN_AUTHORED;
    else if (strcmp(value, "ai") == 0)
        *kind_out = VCS_ZCODE_SOURCE_AI_AUTHORED;
    else if (strcmp(value, "import") == 0)
        *kind_out = VCS_ZCODE_SOURCE_CANONICAL_IMPORT;
    else
        return false;
    return true;
}

/* store_label_valid — the `store` field of a package def line is a LABEL,
 * not a path: one path component drawn from [A-Za-z0-9._-], never '.' or
 * '..', never containing '/' or '~'.
 *
 * WHY A LABEL AND NOT A PATH. The census copies the def line verbatim into
 * every evidence record (`scopes_def_line`) and hashes it into
 * assignment_evidence_root, and emits the store field again as `"store"` in
 * both the evidence and the KPI report. When that field held an absolute
 * datadir, 2,302 copies of the operator's home directory shipped in the
 * committed corpus artifacts — a clearnet locator in a repository whose
 * privacy rule is that committed files carry no local filesystem paths,
 * usernames, or hostnames. The path was never what the evidence was ABOUT:
 * every root is computed over content hashes, and the def `root` (the
 * package manifest root, re-derived from the store and refused on mismatch)
 * is what actually binds the bytes. The store field only says WHICH local
 * store to read, so it is now a stable name that means the same thing on
 * every host, resolved through --store-root / $ZCL_CORPUS_STORE_ROOT / $HOME
 * at run time. */
static bool store_label_valid(const char *s)
{
    if (!s || !*s) return false;
    if (strcmp(s, ".") == 0 || strcmp(s, "..") == 0) return false;
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!(isalnum(c) || c == '.' || c == '_' || c == '-'))
            return false;
    }
    return true;
}

/* The package line form:
 *   package <name> | root <64hex> | store <label> | kind <k> | spdx <id>
 */
static bool def_parse_package_line(struct scope_def *def, const char *line,
                                   size_t line_no)
{
    memset(def, 0, sizeof(*def));
    def->is_package = true;
    def->def_line = dup_str(line, "corpus.defline");
    char *work = dup_str(line, "corpus.defwork");
    if (!def->def_line || !work) {
        free(work);
        return false;
    }
    bool ok = false;
    const char *value = NULL;
    size_t field = 0;
    for (char *tok = strtok(work, "|"); tok; tok = strtok(NULL, "|")) {
        char *t = trim(tok);
        if (field == 0 && key_value(t, "package", &value)) {
            if (!shell_safe(value) ||
                !(def->name = dup_str(value, "corpus.scopename"))) {
                LOG_ERROR(CENSUS_LOG, "line %zu: bad package name", line_no);
                goto done;
            }
        } else if (field == 1 && key_value(t, "root", &value)) {
            if (strlen(value) != 64 ||
                !zcl_hex_decode_lower(value, def->package_root, 32) ||
                !zcl_bytes_any_set(def->package_root, 32)) {
                LOG_ERROR(CENSUS_LOG,
                          "line %zu: bad package root (want 64 lowercase "
                          "hex, nonzero)", line_no);
                goto done;
            }
        } else if (field == 2 && key_value(t, "store", &value)) {
            if (!store_label_valid(value) ||
                !(def->store = dup_str(value, "corpus.store"))) {
                LOG_ERROR(CENSUS_LOG,
                          "line %zu: store must be a LABEL — one path "
                          "component, [A-Za-z0-9._-], not '.' or '..' — "
                          "not a path (got '%s'). The label resolves to "
                          "<store-root>/<label> at run time; an absolute "
                          "path here would publish the operator's home "
                          "directory in every committed census artifact",
                          line_no, value ? value : "");
                goto done;
            }
        } else if (field == 3 && key_value(t, "kind", &value)) {
            if (!kind_parse(value, &def->kind)) {
                LOG_ERROR(CENSUS_LOG, "line %zu: bad kind '%s'", line_no,
                          value);
                goto done;
            }
        } else if (field == 4 && key_value(t, "spdx", &value)) {
            if (!shell_safe(value) ||
                !(def->spdx = dup_str(value, "corpus.spdx"))) {
                LOG_ERROR(CENSUS_LOG, "line %zu: bad spdx", line_no);
                goto done;
            }
        } else {
            LOG_ERROR(CENSUS_LOG,
                      "line %zu: expected package|root|store|kind|spdx "
                      "field order, got '%s'", line_no, t);
            goto done;
        }
        field++;
    }
    if (!def->name || !zcl_bytes_any_set(def->package_root, 32) || !def->store ||
        !def->kind || !def->spdx) {
        LOG_ERROR(CENSUS_LOG,
                  "line %zu: package scope needs package, root, store, "
                  "kind and spdx", line_no);
        goto done;
    }
    ok = true;
done:
    free(work);
    if (!ok) scope_def_free(def);
    return ok;
}

static bool def_parse_line(struct scope_def *def, const char *line,
                           size_t line_no)
{
    memset(def, 0, sizeof(*def));
    if (strncmp(line, "package ", 8) == 0)
        return def_parse_package_line(def, line, line_no);
    def->def_line = dup_str(line, "corpus.defline");
    char *work = dup_str(line, "corpus.defwork");
    if (!def->def_line || !work) {
        free(work);
        return false;
    }

    bool ok = false;
    bool seen_tests = false;
    const char *value = NULL;
    size_t field = 0;
    for (char *tok = strtok(work, "|"); tok; tok = strtok(NULL, "|")) {
        char *t = trim(tok);
        if (field == 0 && key_value(t, "scope", &value)) {
            if (!shell_safe(value) || !(def->name = dup_str(value, "corpus.scopename"))) {
                LOG_ERROR(CENSUS_LOG, "line %zu: bad scope name", line_no);
                goto done;
            }
        } else if (field == 1 && key_value(t, "kind", &value)) {
            if (strcmp(value, "human") == 0)
                def->kind = VCS_ZCODE_SOURCE_HUMAN_AUTHORED;
            else if (strcmp(value, "ai") == 0)
                def->kind = VCS_ZCODE_SOURCE_AI_AUTHORED;
            else if (strcmp(value, "import") == 0)
                def->kind = VCS_ZCODE_SOURCE_CANONICAL_IMPORT;
            else {
                LOG_ERROR(CENSUS_LOG, "line %zu: bad kind '%s'", line_no,
                          value);
                goto done;
            }
        } else if (field == 2 && key_value(t, "spdx", &value)) {
            if (!shell_safe(value) ||
                !(def->spdx = dup_str(value, "corpus.spdx"))) {
                LOG_ERROR(CENSUS_LOG, "line %zu: bad spdx", line_no);
                goto done;
            }
        } else if (field == 3 && key_value(t, "src", &value)) {
            if (!prefix_list_parse(def->src, &def->nsrc, value, line_no))
                goto done;
        } else if (field >= 3 && !seen_tests &&
                   key_value(t, "tests", &value)) {
            if (!prefix_list_parse(def->tests, &def->ntests, value, line_no))
                goto done;
            seen_tests = true;
        } else {
            LOG_ERROR(CENSUS_LOG,
                      "line %zu: expected scope|kind|spdx|src[,tests] "
                      "field order, got '%s'", line_no, t);
            goto done;
        }
        field++;
    }
    if (!def->name || !def->kind || !def->spdx ||
        (!def->nsrc && !def->ntests)) {
        LOG_ERROR(CENSUS_LOG,
                  "line %zu: scope needs scope, kind, spdx and at least "
                  "one of src/tests", line_no);
        goto done;
    }
    ok = true;
done:
    free(work);
    if (!ok) scope_def_free(def);
    return ok;
}

static int cmp_scope_def(const void *a, const void *b)
{
    return strcmp(((const struct scope_def *)a)->name,
                  ((const struct scope_def *)b)->name);
}

static bool def_load(const char *path, struct scope_def **defs_out,
                     size_t *count_out, uint8_t def_sha3[32])
{
    FILE *f = fopen(path, "rb");
    if (!f)
        LOG_FAIL(CENSUS_LOG, "open def %s: %s", path, strerror(errno));
    struct str_vec lines = {0};
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    char *line = NULL;
    size_t cap = 0, total = 0;
    ssize_t got;
    bool ok = false;
    struct scope_def *defs = NULL;
    while ((got = getline(&line, &cap, f)) >= 0) {
        total += (size_t)got;
        if (total > CORPUS_CENSUS_DEF_MAX_BYTES) {
            LOG_ERROR(CENSUS_LOG, "def %s over %u bytes", path,
                      CORPUS_CENSUS_DEF_MAX_BYTES);
            goto done;
        }
        sha3_256_write(&sha, (const uint8_t *)line, (size_t)got);
        while (got && (line[got - 1] == '\n' || line[got - 1] == '\r'))
            line[--got] = '\0';
        char *t = trim(line);
        if (!*t || *t == '#') continue;
        if (!vec_push(&lines, t)) goto done;
    }
    sha3_256_finalize(&sha, def_sha3);
    if (ferror(f)) {
        LOG_ERROR(CENSUS_LOG, "read def %s: %s", path, strerror(errno));
        goto done;
    }
    if (!lines.n) {
        LOG_ERROR(CENSUS_LOG, "def %s defines no scopes", path);
        goto done;
    }
    defs = zcl_calloc(lines.n, sizeof(*defs), "corpus.defs");
    if (!defs) {
        LOG_ERROR(CENSUS_LOG, "defs alloc %zu", lines.n);
        goto done;
    }
    for (size_t i = 0; i < lines.n; i++) {
        if (!def_parse_line(&defs[i], lines.v[i], i + 1u))
            goto done;
    }
    qsort(defs, lines.n, sizeof(*defs), cmp_scope_def);
    for (size_t i = 1; i < lines.n; i++) {
        if (strcmp(defs[i - 1].name, defs[i].name) == 0) {
            LOG_ERROR(CENSUS_LOG, "duplicate scope name %s", defs[i].name);
            goto done;
        }
    }
    *defs_out = defs;
    *count_out = lines.n;
    defs = NULL;
    ok = true;
done:
    if (defs) {
        for (size_t i = 0; i < lines.n; i++) scope_def_free(&defs[i]);
        free(defs);
    }
    free(line);
    vec_free(&lines);
    fclose(f);
    return ok;
}

/* ── git enumeration and claim resolution ─────────────────────────── */

/* Does `path` match prefix `pfx`? Directory prefixes (trailing '/') match
 * the whole tree; other prefixes are literal file prefixes. */
static bool prefix_matches(const struct prefix *pfx, const char *path)
{
    return strncmp(path, pfx->text, strlen(pfx->text)) == 0;
}

struct match {
    char *path;
    size_t scope;
    size_t plen;
    bool via_tests;
};

static int cmp_match(const void *a, const void *b)
{
    const struct match *ma = a, *mb = b;
    int c = strcmp(ma->path, mb->path);
    if (c) return c;
    if (ma->via_tests != mb->via_tests) return ma->via_tests ? -1 : 1;
    if (ma->plen != mb->plen) return ma->plen > mb->plen ? -1 : 1;
    if (ma->scope != mb->scope) return ma->scope < mb->scope ? -1 : 1;
    return 0;
}

/* Per-scope resolved claim: sorted paths plus parallel via_tests flags. */
struct scope_files {
    char **paths;
    uint8_t *via_tests;
    size_t n, cap;
};

static void scope_files_free(struct scope_files *sf)
{
    if (!sf) return;
    for (size_t i = 0; i < sf->n; i++) free(sf->paths[i]);
    free(sf->paths);
    free(sf->via_tests);
    memset(sf, 0, sizeof(*sf));
}

static bool scope_files_push(struct scope_files *sf, const char *path,
                             bool via_tests)
{
    if (sf->n == sf->cap) {
        size_t next = sf->cap ? sf->cap * 2u : 32u;
        size_t pb = 0, fb = 0;
        if (!zcl_size_mul(next, sizeof(char *), &pb) ||
            !zcl_size_mul(next, sizeof(uint8_t), &fb))
            LOG_FAIL(CENSUS_LOG, "scope files capacity overflow");
        /* zcl_realloc never frees the original on failure; grow the two
         * arrays one at a time so a half-grown pair stays consistent. */
        char **np = zcl_realloc(sf->paths, pb, "corpus.files");
        if (!np)
            LOG_FAIL(CENSUS_LOG, "scope paths realloc to %zu", sf->n + 1u);
        sf->paths = np;
        uint8_t *nf = zcl_realloc(sf->via_tests, fb, "corpus.files.vt");
        if (!nf)
            LOG_FAIL(CENSUS_LOG, "scope flags realloc to %zu", sf->n + 1u);
        sf->via_tests = nf;
        sf->cap = next;
    }
    sf->paths[sf->n] = dup_str(path, "corpus.file.path");
    if (!sf->paths[sf->n])
        LOG_FAIL(CENSUS_LOG, "file path dup %s", path);
    sf->via_tests[sf->n] = via_tests ? 1u : 0u;
    sf->n++;
    return true;
}

/* Enumerate one prefix's tracked files under `root` via git ls-files -z.
 * The git pathspec is a deliberate SUPERSET of the prefix semantics (the
 * bare prefix: git recurses into directory pathspecs and accepts globs);
 * the exact prefix_matches() filter plus the counted-extension filter
 * decide membership, so untracked scratch can never enter the census. */
static bool git_ls_files_prefix(const char *root, const struct prefix *pfx,
                                struct str_vec *out)
{
    char cmd[CORPUS_CENSUS_CMD_MAX];
    if (pfx->is_dir) {
        char stripped[1024];
        size_t len = strlen(pfx->text);
        if (len >= sizeof(stripped))
            LOG_FAIL(CENSUS_LOG, "prefix too long: %s", pfx->text);
        memcpy(stripped, pfx->text, len - 1u);
        stripped[len - 1u] = '\0';
        if (snprintf(cmd, sizeof(cmd),
                     "git -C '%s' ls-files -z -- '%s'", root,
                     stripped) >= (int)sizeof(cmd))
            LOG_FAIL(CENSUS_LOG, "git command over %u bytes",
                     CORPUS_CENSUS_CMD_MAX);
    } else {
        if (snprintf(cmd, sizeof(cmd),
                     "git -C '%s' ls-files -z -- '%s' '%s*'", root,
                     pfx->text, pfx->text) >= (int)sizeof(cmd))
            LOG_FAIL(CENSUS_LOG, "git command over %u bytes",
                     CORPUS_CENSUS_CMD_MAX);
    }
    FILE *pipe = popen(cmd, "r"); /* shellout-ok: standalone CLI tool */
    if (!pipe)
        LOG_FAIL(CENSUS_LOG, "popen git ls-files for %s", pfx->text);
    bool ok = true;
    struct buf raw = {0};
    uint8_t chunk[65536];
    size_t got;
    while ((got = fread(chunk, 1, sizeof(chunk), pipe)) > 0) {
        if (!buf_put(&raw, chunk, got)) {
            ok = false;
            break;
        }
    }
    int status = pclose(pipe); /* shellout-ok: standalone CLI tool */
    if (!ok || status == -1 || !WIFEXITED(status) || WEXITSTATUS(status)) {
        buf_free(&raw);
        LOG_FAIL(CENSUS_LOG, "git ls-files failed for prefix %s",
                 pfx->text);
    }
    size_t off = 0;
    while (off < raw.len) {
        size_t end = off;
        while (end < raw.len && raw.p[end] != 0) end++;
        if (end > off && prefix_matches(pfx, (const char *)raw.p + off) &&
            counted_extension((const char *)raw.p + off)) {
            if (!vec_push_len(out, (const char *)raw.p + off, end - off)) {
                buf_free(&raw);
                LOG_FAIL(CENSUS_LOG, "enumeration push failed for %s",
                         pfx->text);
            }
        }
        off = end + 1u;
    }
    buf_free(&raw);
    return true;
}

/* Enumerate every scope under `root` and resolve each matched path to
 * exactly one scope. Precedence: tests-kind claims beat src-kind claims;
 * among same-kind claims the longest prefix wins; equal-length competition
 * between two scopes is a fatal overlap error. */
static bool claims_resolve(const char *root, const struct scope_def *defs,
                           size_t scope_count, struct scope_files **out)
{
    struct match *matches = NULL;
    size_t match_count = 0, match_cap = 0;
    struct scope_files *resolved = NULL;
    bool ok = false;

    for (size_t s = 0; s < scope_count; s++) {
        for (size_t pi = 0; pi < defs[s].nsrc + defs[s].ntests; pi++) {
            const struct prefix *pfx =
                pi < defs[s].nsrc ? &defs[s].src[pi]
                                  : &defs[s].tests[pi - defs[s].nsrc];
            bool via_tests = pi >= defs[s].nsrc;
            struct str_vec paths = {0};
            if (!git_ls_files_prefix(root, pfx, &paths)) {
                vec_free(&paths);
                goto done;
            }
            for (size_t k = 0; k < paths.n; k++) {
                if (match_count == match_cap) {
                    size_t next = match_cap ? match_cap * 2u : 256u;
                    size_t bytes = 0;
                    if (!zcl_size_mul(next, sizeof(*matches), &bytes)) {
                        vec_free(&paths);
                        LOG_FAIL(CENSUS_LOG, "match capacity overflow");
                    }
                    struct match *nm =
                        zcl_realloc(matches, bytes, "corpus.matches");
                    if (!nm) {
                        vec_free(&paths);
                        LOG_FAIL(CENSUS_LOG, "match realloc to %zu",
                                 match_count + 1u);
                    }
                    matches = nm;
                    match_cap = next;
                }
                matches[match_count].path =
                    dup_str(paths.v[k], "corpus.match.path");
                if (!matches[match_count].path) {
                    vec_free(&paths);
                    goto done;
                }
                matches[match_count].scope = s;
                matches[match_count].plen = strlen(pfx->text);
                matches[match_count].via_tests = via_tests;
                match_count++;
            }
            vec_free(&paths);
        }
    }

    resolved = zcl_calloc(scope_count, sizeof(*resolved),
                          "corpus.resolved");
    if (!resolved) {
        LOG_ERROR(CENSUS_LOG, "resolved alloc %zu", scope_count);
        goto done;
    }
    if (match_count) {
        qsort(matches, match_count, sizeof(*matches), cmp_match);
        size_t i = 0;
        while (i < match_count) {
            size_t j = i;
            while (j < match_count &&
                   strcmp(matches[j].path, matches[i].path) == 0)
                j++;
            const struct match *win = &matches[i];
            for (size_t k = i + 1; k < j; k++) {
                const struct match *m = &matches[k];
                if (m->scope != win->scope &&
                    m->via_tests == win->via_tests &&
                    m->plen == win->plen) {
                    LOG_ERROR(CENSUS_LOG,
                              "file %s claimed by scopes %s and %s at "
                              "equal precedence; fix the scopes def",
                              win->path, defs[win->scope].name,
                              defs[m->scope].name);
                    goto done;
                }
            }
            if (!scope_files_push(&resolved[win->scope], win->path,
                                  win->via_tests))
                goto done;
            i = j;
        }
    }
    /* Matches were globally sorted by path, so each scope's push order is
     * ascending: resolved[s].paths needs no second sort. */
    *out = resolved;
    resolved = NULL;
    ok = true;
done:
    if (resolved) {
        for (size_t s = 0; s < scope_count; s++)
            scope_files_free(&resolved[s]);
        free(resolved);
    }
    for (size_t i = 0; i < match_count; i++) free(matches[i].path);
    free(matches);
    return ok;
}

/* ── file loading and per-scope measurement ───────────────────────── */

/* Read one repo file. Content over VCS_ZCODE_C23_MAX_FILE_BYTES is NOT
 * read: bytes stays NULL and declared carries the real size, which the
 * census core turns into the OVERSIZE exclusion. */
static bool file_load(const char *root, const char *relpath,
                      uint8_t **bytes_out, size_t *len_out,
                      uint64_t *declared_out)
{
    *bytes_out = NULL;
    *len_out = 0;
    *declared_out = 0;
    size_t full_len = strlen(root) + strlen(relpath) + 2u;
    char *full = zcl_malloc(full_len, "corpus.path");
    if (!full)
        LOG_FAIL(CENSUS_LOG, "path alloc for %s", relpath);
    (void)snprintf(full, full_len, "%s/%s", root, relpath);
    int fd = open(full, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        LOG_ERROR(CENSUS_LOG, "open %s: %s", full, strerror(errno));
        free(full);
        return false;
    }
    free(full);
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
        LOG_ERROR(CENSUS_LOG, "stat %s: %s", relpath, strerror(errno));
        close(fd);
        return false;
    }
    *declared_out = (uint64_t)st.st_size;
    if ((uint64_t)st.st_size > VCS_ZCODE_C23_MAX_FILE_BYTES) {
        close(fd);
        return true; /* oversize: no bytes, declared size only */
    }
    size_t len = (size_t)st.st_size;
    uint8_t *bytes = zcl_malloc(len ? len : 1u, "corpus.file.bytes");
    if (!bytes) {
        close(fd);
        LOG_FAIL(CENSUS_LOG, "file bytes alloc %zu for %s", len, relpath);
    }
    size_t off = 0;
    while (off < len) {
        ssize_t r = read(fd, bytes + off, len - off);
        if (r <= 0) {
            LOG_ERROR(CENSUS_LOG, "read %s: %s", relpath,
                      r == 0 ? "short file" : strerror(errno));
            free(bytes);
            close(fd);
            return false;
        }
        off += (size_t)r;
    }
    close(fd);
    *bytes_out = bytes;
    *len_out = len;
    return true;
}

/* ── package-scope store reads (READ-ONLY observer) ───────────────────
 *
 * A package scope reads <store-root>/<label>/zcode directly: the manifest,
 * the release envelope, the recipe wire, and CAS chunks. Every object is
 * re-parsed and re-hashed on read (chunk bytes must equal the hash committed
 * at their manifest coordinates), so a corrupted or tampered store fails the
 * census closed. The store is never opened through vcs_package_store_open —
 * no recovery sweep, GC, pin, or access-count mutation. */

struct package_ctx {
    char *zcode_dir;       /* owned: <store>/zcode */
    struct vcs_package_manifest manifest;
    struct vcs_package_release release;
    uint8_t release_id[32];
    char publisher_hex[VCS_PACKAGE_RELEASE_PUBKEY_BYTES * 2u + 1u];
};

static void package_ctx_free(struct package_ctx *ctx)
{
    if (!ctx) return;
    free(ctx->zcode_dir);
    vcs_package_manifest_free(&ctx->manifest);
    memset(ctx, 0, sizeof(*ctx));
}

/* Read one bounded regular file fully (allocates *out; caller frees). */
static bool store_file_read(const char *path, size_t max_bytes,
                            uint8_t **out, size_t *out_len)
{
    *out = NULL;
    *out_len = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        LOG_ERROR(CENSUS_LOG, "open %s: %s", path, strerror(errno));
        return false;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uint64_t)st.st_size > max_bytes) {
        LOG_ERROR(CENSUS_LOG, "stat %s: not a regular file within %zu bytes",
                  path, max_bytes);
        close(fd);
        return false;
    }
    size_t len = (size_t)st.st_size;
    uint8_t *bytes = zcl_malloc(len ? len : 1u, "corpus.store.file");
    if (!bytes) {
        close(fd);
        LOG_FAIL(CENSUS_LOG, "store file alloc %zu for %s", len, path);
    }
    size_t off = 0;
    while (off < len) {
        ssize_t r = read(fd, bytes + off, len - off);
        if (r <= 0) {
            LOG_ERROR(CENSUS_LOG, "read %s: %s", path,
                      r == 0 ? "short file" : strerror(errno));
            free(bytes);
            close(fd);
            return false;
        }
        off += (size_t)r;
    }
    close(fd);
    *out = bytes;
    *out_len = len;
    return true;
}

/* Load and re-root the committed manifest for the def's package root. */
static bool package_manifest_load(struct package_ctx *ctx,
                                  const uint8_t root[32])
{
    char hex[65];
    root_hex(root, hex);
    size_t plen = strlen(ctx->zcode_dir) + sizeof("/manifests/") + 64u;
    char *path = zcl_malloc(plen, "corpus.pkg.manifest");
    if (!path)
        LOG_FAIL(CENSUS_LOG, "manifest path alloc");
    (void)snprintf(path, plen, "%s/manifests/%s", ctx->zcode_dir, hex);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    bool ok = store_file_read(path, VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES,
                              &wire, &wire_len);
    free(path);
    if (!ok) return false;
    if (!vcs_package_manifest_parse(wire, wire_len, &ctx->manifest)) {
        LOG_ERROR(CENSUS_LOG, "stored manifest %s fails the grammar", hex);
        free(wire);
        return false;
    }
    free(wire);
    uint8_t derived[32];
    if (!vcs_package_manifest_root(&ctx->manifest, derived))
        LOG_FAIL(CENSUS_LOG, "manifest root derivation failed");
    if (memcmp(derived, root, 32) != 0) {
        char dhex[65];
        root_hex(derived, dhex);
        LOG_ERROR(CENSUS_LOG,
                  "stored manifest root %s does not match the def root %s",
                  dhex, hex);
        vcs_package_manifest_free(&ctx->manifest);
        return false;
    }
    return true;
}

/* Find the release envelope naming this package root under releases/:
 * exactly one signature-verified match, else fail closed. */
static bool package_release_find(struct package_ctx *ctx,
                                 const uint8_t root[32])
{
    size_t dlen = strlen(ctx->zcode_dir) + sizeof("/releases");
    char *dirpath = zcl_malloc(dlen, "corpus.pkg.releases");
    if (!dirpath)
        LOG_FAIL(CENSUS_LOG, "releases path alloc");
    (void)snprintf(dirpath, dlen, "%s/releases", ctx->zcode_dir);
    DIR *dir = opendir(dirpath);
    if (!dir) {
        LOG_ERROR(CENSUS_LOG, "opendir %s: %s", dirpath, strerror(errno));
        free(dirpath);
        return false;
    }
    size_t found = 0;
    bool ok = true;
    struct dirent *ent;
    while (ok && (ent = readdir(dir)) != NULL) {
        size_t nlen = strlen(ent->d_name);
        if (nlen != 64) continue;
        uint8_t id[32];
        if (!zcl_hex_decode_lower(ent->d_name, id, 32)) continue;
        size_t plen = dlen + 1u + 64u;
        char *path = zcl_malloc(plen, "corpus.pkg.release");
        if (!path)
            LOG_FAIL(CENSUS_LOG, "release path alloc");
        (void)snprintf(path, plen, "%s/%s", dirpath, ent->d_name);
        uint8_t *wire = NULL;
        size_t wire_len = 0;
        bool read_ok = store_file_read(path, VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES,
                                       &wire, &wire_len);
        free(path);
        if (!read_ok) {
            ok = false;
            break;
        }
        struct vcs_package_release release;
        enum vcs_package_release_error perr =
            vcs_package_release_parse(wire, wire_len, &release);
        free(wire);
        if (perr != VCS_PACKAGE_RELEASE_OK ||
            memcmp(release.package_root, root, 32) != 0)
            continue;
        if (vcs_package_release_verify(&release) != VCS_PACKAGE_RELEASE_OK) {
            LOG_ERROR(CENSUS_LOG, "release %s fails signature verification",
                      ent->d_name);
            ok = false;
            break;
        }
        uint8_t computed_id[32];
        if (vcs_package_release_id(&release, computed_id) !=
                VCS_PACKAGE_RELEASE_OK ||
            memcmp(computed_id, id, 32) != 0) {
            LOG_ERROR(CENSUS_LOG,
                      "release file %s does not hash to its own id",
                      ent->d_name);
            ok = false;
            break;
        }
        found++;
        ctx->release = release;
        memcpy(ctx->release_id, id, 32);
    }
    closedir(dir);
    free(dirpath);
    if (!ok) return false;
    if (found != 1) {
        char hex[65];
        root_hex(root, hex);
        LOG_ERROR(CENSUS_LOG,
                  "package %s: %zu release envelopes name the root (want "
                  "exactly 1)", hex, found);
        return false;
    }
    zcl_hex_encode(ctx->release.publisher_pubkey,
                   VCS_PACKAGE_RELEASE_PUBKEY_BYTES, ctx->publisher_hex);
    return true;
}

/* Read one package file's bytes back from the CAS, re-hashing every chunk
 * against its committed manifest coordinates (fail closed on any mismatch).
 * Over-cap content yields NULL bytes with the declared size, exactly like
 * file_load (the census core turns it into the OVERSIZE exclusion). */
static bool package_file_load(const struct package_ctx *ctx,
                              const char *path, uint8_t **bytes_out,
                              size_t *len_out, uint64_t *declared_out)
{
    *bytes_out = NULL;
    *len_out = 0;
    *declared_out = 0;
    const struct vcs_package_file *file = NULL;
    for (size_t i = 0; i < ctx->manifest.count; i++) {
        if (strcmp(ctx->manifest.files[i].path, path) == 0) {
            file = &ctx->manifest.files[i];
            break;
        }
    }
    if (!file)
        LOG_FAIL(CENSUS_LOG, "package file %s not in the manifest", path);
    *declared_out = file->size;
    if (file->size > VCS_ZCODE_C23_MAX_FILE_BYTES)
        return true; /* oversize: no bytes, declared size only */
    size_t len = (size_t)file->size;
    uint8_t *bytes = zcl_malloc(len ? len : 1u, "corpus.pkg.file");
    if (!bytes)
        LOG_FAIL(CENSUS_LOG, "package file alloc %zu for %s", len, path);
    size_t off = 0;
    for (uint32_t c = 0; c < file->chunk_count; c++) {
        const uint8_t *hash = file->chunk_hashes + (size_t)c * 32u;
        char hex[65];
        zcl_hex_encode(hash, 32, hex);
        size_t plen = strlen(ctx->zcode_dir) + sizeof("/cas/sha3//") + 66u;
        char *cpath = zcl_malloc(plen, "corpus.pkg.chunk");
        if (!cpath)
            LOG_FAIL(CENSUS_LOG, "chunk path alloc");
        (void)snprintf(cpath, plen, "%s/cas/sha3/%2.2s/%s", ctx->zcode_dir,
                       hex, hex);
        uint8_t *chunk = NULL;
        size_t chunk_len = 0;
        bool ok = store_file_read(cpath, VCS_PACKAGE_CHUNK_BYTES, &chunk,
                                  &chunk_len);
        free(cpath);
        if (!ok) {
            free(bytes);
            LOG_FAIL(CENSUS_LOG,
                     "package %s: chunk %u of %s missing from the CAS",
                     ctx->release.name, c, path);
        }
        uint8_t actual[32];
        sha3_256(chunk, chunk_len, actual);
        bool last = c + 1u == file->chunk_count;
        size_t expect = last ? len - off : VCS_PACKAGE_CHUNK_BYTES;
        if (memcmp(actual, hash, 32) != 0 || chunk_len != expect ||
            chunk_len > len - off) {
            free(chunk);
            free(bytes);
            LOG_FAIL(CENSUS_LOG,
                     "package %s: chunk %u of %s fails hash/size "
                     "verification", ctx->release.name, c, path);
        }
        memcpy(bytes + off, chunk, chunk_len);
        off += chunk_len;
        free(chunk);
    }
    if (off != len)
        LOG_FAIL(CENSUS_LOG, "package file %s reassembled to %zu of %zu",
                 path, off, len);
    *bytes_out = bytes;
    *len_out = len;
    return true;
}

/* Load the manifest and release for one package scope (fail closed). Also
 * cross-checks the def spdx against the release envelope's license. */
static bool package_ctx_load(struct package_ctx *ctx,
                             const struct scope_def *def,
                             const char *store_root)
{
    memset(ctx, 0, sizeof(*ctx));
    /* The def carries a LABEL; the operator-local root that it hangs off is
     * a run-time coordinate (--store-root / $ZCL_CORPUS_STORE_ROOT / $HOME)
     * and is deliberately absent from every committed artifact. */
    if (!store_root || !*store_root) {
        LOG_ERROR(CENSUS_LOG,
                  "package scope %s needs a store root: pass --store-root "
                  "<dir> (or set ZCL_CORPUS_STORE_ROOT / HOME); the store "
                  "label '%s' resolves to <store-root>/%s",
                  def->name, def->store, def->store);
        return false;
    }
    size_t len = strlen(store_root) + 1u + strlen(def->store) +
                 sizeof("/zcode");
    ctx->zcode_dir = zcl_malloc(len, "corpus.pkg.zcode");
    if (!ctx->zcode_dir)
        LOG_FAIL(CENSUS_LOG, "zcode dir alloc");
    (void)snprintf(ctx->zcode_dir, len, "%s/%s/zcode", store_root,
                   def->store);
    if (!package_manifest_load(ctx, def->package_root) ||
        !package_release_find(ctx, def->package_root)) {
        package_ctx_free(ctx);
        return false;
    }
    if (strcmp(ctx->release.license, def->spdx) != 0) {
        LOG_ERROR(CENSUS_LOG,
                  "package %s: def spdx %s != release license %s",
                  def->name, def->spdx, ctx->release.license);
        package_ctx_free(ctx);
        return false;
    }
    return true;
}

/* The package-scope possession root (REPORT ONLY): the evidence root over
 * the sorted unique chunk hashes of the manifest. Every chunk was already
 * re-read and hash-verified during measurement, so a nonzero root here
 * means complete, verified CAS possession. */
static bool package_possession_root(const struct package_ctx *ctx,
                                    uint8_t out[32])
{
    size_t total = 0;
    for (size_t i = 0; i < ctx->manifest.count; i++) {
        if (!zcl_size_add(total, ctx->manifest.files[i].chunk_count,
                          &total))
            LOG_FAIL(CENSUS_LOG, "chunk count overflow");
    }
    struct buf wire = {0};
    bool ok = true;
    if (total) {
        uint8_t *hashes = zcl_malloc(total * 32u, "corpus.pkg.chunks");
        if (!hashes)
            LOG_FAIL(CENSUS_LOG, "chunk hashes alloc %zu", total);
        size_t n = 0;
        for (size_t i = 0; i < ctx->manifest.count; i++) {
            const struct vcs_package_file *f = &ctx->manifest.files[i];
            memcpy(hashes + n * 32u, f->chunk_hashes,
                   (size_t)f->chunk_count * 32u);
            n += f->chunk_count;
        }
        qsort(hashes, n, 32, cmp_bytes32);
        for (size_t i = 0; i < n; i++) {
            if (i && memcmp(hashes + i * 32u, hashes + (i - 1u) * 32u, 32) == 0)
                continue; /* dedup shared chunks */
            ok = buf_put(&wire, hashes + i * 32u, 32);
            if (!ok) break;
        }
        free(hashes);
    }
    if (ok)
        ok = evidence_root(k_domain_possession, wire.p, wire.len, out);
    buf_free(&wire);
    if (!ok)
        LOG_FAIL(CENSUS_LOG, "package possession root failed");
    return true;
}

/* Enumerate a package scope's files from the verified manifest: paths are
 * package-relative, already in canonical ascending order, and tests/ paths
 * carry the tests claim (same classification input as repo scopes). */
static bool package_scope_enumerate(const struct package_ctx *ctx,
                                    struct scope_files *sf)
{
    for (size_t i = 0; i < ctx->manifest.count; i++) {
        const char *path = ctx->manifest.files[i].path;
        if (!scope_files_push(sf, path, strncmp(path, "tests/", 6) == 0))
            LOG_FAIL(CENSUS_LOG, "package enumeration push failed for %s",
                     path);
    }
    return true;
}

struct scope_measure {
    uint8_t release_root[32];
    uint8_t license_root[32];
    uint8_t recipe_root[32];
    uint8_t dep_closure_root[32];
    uint8_t possession_root[32];
    char *license_path;      /* repo-relative, bound in license_root */
    char *recipe_path;       /* repo-relative, bound in recipe_root */
    bool recipe_is_package;  /* zcode-package.json vs repo Makefile */
    bool license_ok;         /* file read AND spdx on the v1 allowlist */
    bool has_api;            /* >=1 .h file with semantic lines */
    bool has_tests_sem;      /* >0 semantic lines in tests-claimed files */
    bool possession_ok;      /* every blob stored and hash-verified */
    uint64_t prod_loc;       /* driver-side would-be semantic LOC */
    uint64_t test_loc;       /* (path classification, same engine) */
    uint64_t physical;
    uint64_t file_count;
    struct json_value *deps; /* owned JSON array for the evidence bundle */
};

static void scope_measure_free(struct scope_measure *m)
{
    if (!m) return;
    free(m->license_path);
    free(m->recipe_path);
    if (m->deps) {
        json_free(m->deps);
        free(m->deps);
    }
    memset(m, 0, sizeof(*m));
}

/* The release wire for one scope's claimed files under `root`:
 * concat over sorted paths of path || NUL || u64-LE size || sha3(content).
 * When `measure` is NULL this is the pure rederivation (worktree pass);
 * no CAS writes, no tallies. When `pkg` is non-NULL the paths are
 * package-relative and the bytes come from the package store's CAS
 * (verify-on-read) instead of the repo tree, and no .zvcs possession
 * probe runs (package possession is the chunk-verified read itself). */
static bool scope_release_wire(const char *root, const struct scope_files *sf,
                               struct buf *wire, struct scope_measure *measure,
                               const char *scope_name,
                               const struct package_ctx *pkg)
{
    struct str_vec blob_hashes = {0}; /* hex, for the possession root */
    for (size_t i = 0; i < sf->n; i++) {
        const char *path = sf->paths[i];
        uint8_t *bytes = NULL;
        size_t len = 0;
        uint64_t declared = 0;
        bool loaded = pkg
            ? package_file_load(pkg, path, &bytes, &len, &declared)
            : file_load(root, path, &bytes, &len, &declared);
        if (!loaded) {
            vec_free(&blob_hashes);
            LOG_FAIL(CENSUS_LOG, "scope %s: cannot read %s", scope_name,
                     path);
        }
        uint8_t digest[32];
        sha3_256(bytes, bytes ? len : 0, digest);
        if (!buf_put(wire, path, strlen(path) + 1u) ||
            !buf_put_u64le(wire, declared) ||
            !buf_put(wire, digest, sizeof(digest))) {
            free(bytes);
            vec_free(&blob_hashes);
            LOG_FAIL(CENSUS_LOG, "scope %s: release wire build failed",
                     scope_name);
        }
        if (measure) {
            measure->file_count++;
            if (bytes) {
                enum vcs_score_exclude_reason reason =
                    VCS_SCORE_EXCLUDE_NONE;
                enum vcs_score_file_kind kind =
                    vcs_score_classify_path(path, &reason);
                struct vcs_score_line_tally tally;
                memset(&tally, 0, sizeof(tally));
                vcs_score_classify_lines(bytes, len, &tally);
                uint64_t physical = (uint64_t)tally.semantic + tally.blank +
                                    tally.comment_only + tally.brace_only;
                if (!zcl_u64_add(measure->physical, physical,
                                 &measure->physical)) {
                    free(bytes);
                    vec_free(&blob_hashes);
                    LOG_FAIL(CENSUS_LOG, "scope %s: physical overflow",
                             scope_name);
                }
                if (kind != VCS_SCORE_FILE_EXCLUDED) {
                    uint64_t *dst =
                        kind == VCS_SCORE_FILE_TEST ? &measure->test_loc
                                                    : &measure->prod_loc;
                    if (!zcl_u64_add(*dst, tally.semantic, dst)) {
                        free(bytes);
                        vec_free(&blob_hashes);
                        LOG_FAIL(CENSUS_LOG, "scope %s: loc overflow",
                                 scope_name);
                    }
                }
                size_t plen = strlen(path);
                if (tally.semantic && plen >= 2 &&
                    strcmp(path + plen - 2, ".h") == 0)
                    measure->has_api = true;
                if (tally.semantic && sf->via_tests[i])
                    measure->has_tests_sem = true;
                /* COMPLETE_POSSESSION: store the blob into the repo .zvcs
                 * CAS, re-read it (the get re-verifies the content hash),
                 * and byte-compare. Package scopes skip this probe: the
                 * chunk-verified CAS read above already proved possession
                 * of this file's exact bytes. */
                if (pkg) {
                    /* possession proven by the verified read */
                } else {
                uint8_t hash[32];
                if (!vcs_object_put(root, bytes, len, VCS_TAG_BLOB, hash)) {
                    LOG_ERROR(CENSUS_LOG, "scope %s: CAS put failed for %s",
                              scope_name, path);
                    measure->possession_ok = false;
                } else {
                    uint8_t *back = NULL;
                    size_t back_len = 0;
                    if (vcs_object_get(root, hash, VCS_TAG_BLOB, &back,
                                       &back_len) != 0 ||
                        back_len != len ||
                        (len && memcmp(back, bytes, len) != 0)) {
                        LOG_ERROR(CENSUS_LOG,
                                  "scope %s: CAS verify failed for %s",
                                  scope_name, path);
                        measure->possession_ok = false;
                    } else {
                        char hex[65];
                        zcl_hex_encode(hash, 32, hex);
                        if (!vec_push(&blob_hashes, hex)) {
                            free(back);
                            free(bytes);
                            vec_free(&blob_hashes);
                            LOG_FAIL(CENSUS_LOG, "blob hash vec push");
                        }
                    }
                    free(back);
                }
                }
            } else {
                /* Oversize/unavailable content can never be possessed. */
                measure->possession_ok = false;
            }
        }
        free(bytes);
    }
    if (measure && measure->possession_ok && blob_hashes.n) {
        qsort(blob_hashes.v, blob_hashes.n, sizeof(char *), cmp_strp);
        struct buf pwire = {0};
        bool ok = true;
        for (size_t i = 0; ok && i < blob_hashes.n; i++) {
            uint8_t hash[32];
            if (!zcl_hex_decode_lower(blob_hashes.v[i], hash, 32) ||
                !buf_put(&pwire, hash, 32))
                ok = false;
        }
        if (ok)
            ok = evidence_root(k_domain_possession, pwire.p, pwire.len,
                               measure->possession_root);
        buf_free(&pwire);
        if (!ok) {
            vec_free(&blob_hashes);
            LOG_FAIL(CENSUS_LOG, "scope %s: possession root failed",
                     scope_name);
        }
    }
    vec_free(&blob_hashes);
    return true;
}

/* Bind the scope's license: the first scope-local LICENSE among its src
 * directory prefixes, else the repo-root LICENSE. A package scope binds
 * its own LICENSE from the store (the fixed package layout requires one);
 * the def spdx was already cross-checked against the release envelope. */
static bool scope_license_bind(const char *root, const struct scope_def *def,
                               struct scope_measure *m,
                               const struct package_ctx *pkg)
{
    if (pkg) {
        uint8_t *bytes = NULL;
        size_t len = 0;
        uint64_t declared = 0;
        if (!package_file_load(pkg, "LICENSE", &bytes, &len, &declared) ||
            !bytes) {
            LOG_ERROR(CENSUS_LOG, "package %s: cannot read LICENSE",
                      def->name);
            free(bytes);
            return false;
        }
        struct buf wire = {0};
        uint8_t digest[32];
        sha3_256(bytes, len, digest);
        bool built = buf_put(&wire, "LICENSE", sizeof("LICENSE")) &&
                     buf_put_u64le(&wire, declared) &&
                     buf_put(&wire, digest, sizeof(digest));
        free(bytes);
        if (built)
            built = evidence_root(k_domain_license, wire.p, wire.len,
                                  m->license_root);
        buf_free(&wire);
        if (!built)
            LOG_FAIL(CENSUS_LOG, "package %s: license root failed",
                     def->name);
        m->license_path = dup_str("LICENSE", "corpus.lic.bound");
        if (!m->license_path)
            LOG_FAIL(CENSUS_LOG, "license path dup");
        m->license_ok = vcs_package_release_license_allowed(def->spdx);
        if (!m->license_ok)
            LOG_WARN(CENSUS_LOG, "package %s: spdx %s is off the v1 "
                     "allowlist", def->name, def->spdx);
        return true;
    }
    struct str_vec candidates = {0};
    bool ok = false;
    for (size_t i = 0; i < def->nsrc; i++) {
        if (!def->src[i].is_dir) continue;
        size_t len = strlen(def->src[i].text) + strlen("LICENSE") + 1u;
        char *rel = zcl_malloc(len, "corpus.lic.path");
        if (!rel) {
            vec_free(&candidates);
            LOG_FAIL(CENSUS_LOG, "license path alloc");
        }
        (void)snprintf(rel, len, "%sLICENSE", def->src[i].text);
        if (!vec_push(&candidates, rel)) {
            free(rel);
            vec_free(&candidates);
            LOG_FAIL(CENSUS_LOG, "license candidate push");
        }
        free(rel);
    }
    if (!vec_push(&candidates, "LICENSE")) {
        vec_free(&candidates);
        LOG_FAIL(CENSUS_LOG, "license candidate push");
    }
    for (size_t i = 0; i < candidates.n; i++) {
        uint8_t *bytes = NULL;
        size_t len = 0;
        uint64_t declared = 0;
        size_t full_len = strlen(root) + strlen(candidates.v[i]) + 2u;
        char *full = zcl_malloc(full_len, "corpus.lic.full");
        if (!full) {
            vec_free(&candidates);
            LOG_FAIL(CENSUS_LOG, "license full path alloc");
        }
        (void)snprintf(full, full_len, "%s/%s", root, candidates.v[i]);
        bool exists = access(full, R_OK) == 0;
        free(full);
        if (!exists) continue;
        if (!file_load(root, candidates.v[i], &bytes, &len, &declared) ||
            !bytes) {
            LOG_ERROR(CENSUS_LOG, "scope %s: cannot read license %s",
                      def->name, candidates.v[i]);
            goto done;
        }
        struct buf wire = {0};
        uint8_t digest[32];
        sha3_256(bytes, len, digest);
        bool built = buf_put(&wire, candidates.v[i],
                             strlen(candidates.v[i]) + 1u) &&
                     buf_put_u64le(&wire, declared) &&
                     buf_put(&wire, digest, sizeof(digest));
        free(bytes);
        if (built)
            built = evidence_root(k_domain_license, wire.p, wire.len,
                                  m->license_root);
        buf_free(&wire);
        if (!built) goto done;
        m->license_path = dup_str(candidates.v[i], "corpus.lic.bound");
        if (!m->license_path) goto done;
        m->license_ok = vcs_package_release_license_allowed(def->spdx);
        if (!m->license_ok)
            LOG_WARN(CENSUS_LOG, "scope %s: spdx %s is off the v1 "
                     "allowlist", def->name, def->spdx);
        ok = true;
        goto done;
    }
    LOG_ERROR(CENSUS_LOG, "scope %s: no license file found", def->name);
done:
    vec_free(&candidates);
    return ok;
}

/* Pinned dependencies from a zcode-package.json document -> the dependency
 * closure wire (file order) plus the owned m->deps JSON array for the
 * evidence bundle. Shared by the repo-scope and package-scope binds. */
static bool dep_closure_bind(struct scope_measure *m, const uint8_t *bytes,
                             size_t blen, const char *scope_name,
                             const char *meta_path)
{
    struct buf cwire = {0};
    struct json_value doc;
    json_init(&doc);
    if (!m || m->deps)
        LOG_FAIL(CENSUS_LOG, "dependency closure output is invalid");
    struct json_value *deps = zcl_malloc(sizeof(*deps), "corpus.deps");
    if (!deps)
        LOG_FAIL(CENSUS_LOG, "deps json alloc");
    json_init(deps);
    json_set_array(deps);
    bool ok = true;
    if (!json_read(&doc, (const char *)bytes, blen)) {
        LOG_ERROR(CENSUS_LOG, "scope %s: %s is not valid JSON",
                  scope_name, meta_path);
        ok = false;
    }
    const struct json_value *list =
        ok ? json_get(&doc, "dependencies") : NULL;
    if (ok && list && list->type != JSON_ARR) {
        LOG_ERROR(CENSUS_LOG, "scope %s: dependencies not an array",
                  scope_name);
        ok = false;
    }
    if (ok && list) {
        for (size_t d = 0; ok && d < list->num_children; d++) {
            const struct json_value *dep = json_at(list, d);
            const char *dname = json_get_str(json_get(dep, "name"));
            const char *droot = json_get_str(json_get(dep, "root"));
            const char *dsemver = json_get_str(json_get(dep, "semver"));
            if (!dname || !droot || !dsemver || strlen(droot) != 64) {
                LOG_ERROR(CENSUS_LOG,
                          "scope %s: malformed dependency %zu",
                          scope_name, d);
                ok = false;
                break;
            }
            struct json_value row;
            json_init(&row);
            json_set_object(&row);
            (void)json_push_kv_str(&row, "name", dname);
            (void)json_push_kv_str(&row, "root", droot);
            (void)json_push_kv_str(&row, "semver", dsemver);
            (void)json_push_back(deps, &row);
            json_free(&row);
            ok = buf_put(&cwire, dname, strlen(dname) + 1u) &&
                 buf_put(&cwire, droot, strlen(droot) + 1u) &&
                 buf_put(&cwire, dsemver, strlen(dsemver) + 1u);
        }
    }
    json_free(&doc);
    if (ok)
        ok = evidence_root(k_domain_dep_closure, cwire.p, cwire.len,
                           m->dep_closure_root);
    buf_free(&cwire);
    if (ok) {
        m->deps = deps;
        deps = NULL;
    }
    if (deps) {
        json_free(deps);
        free(deps);
    }
    return ok;
}

/* Package-scope recipe bind: the RECIPE bit is the release envelope's
 * recipe_root with the recipe wire present in the store and re-rooted
 * (fail closed on mismatch). The dependency closure comes from the
 * package's own zcode-package.json bytes. */
static bool package_recipe_bind(const struct scope_def *def,
                                struct scope_measure *m,
                                const struct package_ctx *pkg)
{
    char roothex[65];
    root_hex(pkg->release.recipe_root, roothex);
    size_t plen = strlen(pkg->zcode_dir) + sizeof("/recipes/") + 64u;
    char *path = zcl_malloc(plen, "corpus.pkg.recipe");
    if (!path)
        LOG_FAIL(CENSUS_LOG, "recipe path alloc");
    (void)snprintf(path, plen, "%s/recipes/%s", pkg->zcode_dir, roothex);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    bool ok = store_file_read(path, VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES,
                              &wire, &wire_len);
    free(path);
    if (!ok) return false;
    struct vcs_package_recipe recipe;
    enum vcs_package_recipe_error rerr =
        vcs_package_recipe_parse(wire, wire_len, &recipe);
    free(wire);
    if (rerr != VCS_PACKAGE_RECIPE_OK) {
        LOG_ERROR(CENSUS_LOG, "package %s: stored recipe fails the grammar",
                  def->name);
        return false;
    }
    uint8_t derived[32];
    rerr = vcs_package_recipe_root(&recipe, derived);
    vcs_package_recipe_free(&recipe);
    if (rerr != VCS_PACKAGE_RECIPE_OK ||
        memcmp(derived, pkg->release.recipe_root, 32) != 0) {
        LOG_ERROR(CENSUS_LOG,
                  "package %s: stored recipe does not re-root to the "
                  "envelope's recipe_root", def->name);
        return false;
    }
    memcpy(m->recipe_root, pkg->release.recipe_root, 32);
    size_t rlen = strlen(roothex) + sizeof("recipes/");
    m->recipe_path = zcl_malloc(rlen, "corpus.recipe.bound");
    if (!m->recipe_path)
        LOG_FAIL(CENSUS_LOG, "recipe path alloc");
    (void)snprintf(m->recipe_path, rlen, "recipes/%s", roothex);
    m->recipe_is_package = true;
    uint8_t *meta = NULL;
    size_t meta_len = 0;
    uint64_t declared = 0;
    if (!package_file_load(pkg, "zcode-package.json", &meta, &meta_len,
                           &declared) ||
        !meta) {
        LOG_ERROR(CENSUS_LOG, "package %s: cannot read zcode-package.json",
                  def->name);
        free(meta);
        return false;
    }
    ok = dep_closure_bind(m, meta, meta_len, def->name,
                          "zcode-package.json");
    free(meta);
    if (!ok)
        LOG_FAIL(CENSUS_LOG, "package %s: dependency closure failed",
                 def->name);
    return true;
}

/* Bind the scope's build recipe: its zcode-package.json when one exists at
 * a src directory prefix (pinned dependencies feed the admission closure
 * root), else the repo Makefile (the declared core-scope build recipe). A
 * package scope binds the release envelope's recipe from the store. */
static bool scope_recipe_bind(const char *root, const struct scope_def *def,
                              struct scope_measure *m,
                              const struct package_ctx *pkg)
{
    if (pkg)
        return package_recipe_bind(def, m, pkg);
    for (size_t i = 0; i < def->nsrc; i++) {
        if (!def->src[i].is_dir) continue;
        const char *name = "zcode-package.json";
        size_t len = strlen(def->src[i].text) + strlen(name) + 1u;
        char *rel = zcl_malloc(len, "corpus.recipe.path");
        if (!rel)
            LOG_FAIL(CENSUS_LOG, "recipe path alloc");
        (void)snprintf(rel, len, "%s%s", def->src[i].text, name);
        size_t full_len = strlen(root) + len + 1u;
        char *full = zcl_malloc(full_len, "corpus.recipe.full");
        if (!full) {
            free(rel);
            LOG_FAIL(CENSUS_LOG, "recipe full path alloc");
        }
        (void)snprintf(full, full_len, "%s/%s", root, rel);
        bool exists = access(full, R_OK) == 0;
        free(full);
        if (!exists) {
            free(rel);
            continue;
        }
        uint8_t *bytes = NULL;
        size_t blen = 0;
        uint64_t declared = 0;
        if (!file_load(root, rel, &bytes, &blen, &declared) || !bytes) {
            LOG_ERROR(CENSUS_LOG, "scope %s: cannot read %s", def->name,
                      rel);
            free(rel);
            return false;
        }
        /* Pinned dependencies -> dependency closure wire (file order). */
        bool ok = dep_closure_bind(m, bytes, blen, def->name, rel);
        if (ok) {
            uint8_t digest[32];
            struct buf rwire = {0};
            sha3_256(bytes, blen, digest);
            ok = buf_put(&rwire, rel, strlen(rel) + 1u) &&
                 buf_put_u64le(&rwire, declared) &&
                 buf_put(&rwire, digest, sizeof(digest)) &&
                 evidence_root(k_domain_recipe, rwire.p, rwire.len,
                               m->recipe_root);
            buf_free(&rwire);
        }
        free(bytes);
        if (!ok) {
            free(rel);
            LOG_FAIL(CENSUS_LOG, "scope %s: recipe bind failed",
                     def->name);
        }
        m->recipe_path = rel;
        m->recipe_is_package = true;
        return true;
    }
    /* Declared core scope: the repo Makefile is the build recipe. */
    uint8_t *bytes = NULL;
    size_t blen = 0;
    uint64_t declared = 0;
    if (!file_load(root, "Makefile", &bytes, &blen, &declared) || !bytes)
        LOG_FAIL(CENSUS_LOG, "scope %s: cannot read repo Makefile",
                 def->name);
    uint8_t digest[32];
    struct buf rwire = {0};
    sha3_256(bytes, blen, digest);
    free(bytes);
    bool ok = buf_put(&rwire, "Makefile", sizeof("Makefile")) &&
              buf_put_u64le(&rwire, declared) &&
              buf_put(&rwire, digest, sizeof(digest)) &&
              evidence_root(k_domain_recipe, rwire.p, rwire.len,
                            m->recipe_root);
    buf_free(&rwire);
    if (!ok)
        LOG_FAIL(CENSUS_LOG, "scope %s: Makefile recipe root failed",
                 def->name);
    /* Empty dependency closure root (no declared pinned deps). */
    if (!evidence_root(k_domain_dep_closure, NULL, 0, m->dep_closure_root))
        LOG_FAIL(CENSUS_LOG, "scope %s: empty closure root failed",
                 def->name);
    m->recipe_path = dup_str("Makefile", "corpus.recipe.bound");
    if (!m->recipe_path)
        LOG_FAIL(CENSUS_LOG, "recipe path dup");
    m->recipe_is_package = false;
    return true;
}

/* ── reproduction (REPRODUCIBLE bit) ──────────────────────────────── */

/* Re-enumerate every scope under `root` and recompute its release root.
 * Returns false only on hard failure; per-scope mismatch is reported
 * through matched[i]. */
static bool rederive_release_roots(const char *root,
                                   const struct scope_def *defs,
                                   size_t scope_count,
                                   const uint8_t (*expected)[32],
                                   bool *matched)
{
    struct scope_files *files = NULL;
    if (!claims_resolve(root, defs, scope_count, &files))
        LOG_FAIL(CENSUS_LOG, "re-enumeration under %s failed", root);
    bool ok = true;
    for (size_t s = 0; ok && s < scope_count; s++) {
        /* Package scopes are not in git: their reproduction binding is the
         * receipts scan, preset in matched[s] by the caller. */
        if (defs[s].is_package) continue;
        struct buf wire = {0};
        if (!scope_release_wire(root, &files[s], &wire, NULL,
                                defs[s].name, NULL)) {
            ok = false;
            buf_free(&wire);
            break;
        }
        uint8_t root_out[32];
        if (!evidence_root(k_domain_release, wire.p, wire.len, root_out)) {
            buf_free(&wire);
            ok = false;
            break;
        }
        buf_free(&wire);
        matched[s] = memcmp(root_out, expected[s], 32) == 0;
        if (!matched[s])
            LOG_WARN(CENSUS_LOG,
                     "scope %s: rederived release root differs under %s",
                     defs[s].name, root);
    }
    for (size_t s = 0; s < scope_count; s++) scope_files_free(&files[s]);
    free(files);
    return ok;
}

/* Dual-materialization rederivation: check the repo out at HEAD into a
 * temporary detached worktree, re-enumerate and recompute every scope's
 * release_root there, and require byte-identical roots. A scope whose
 * content is not fully committed at HEAD (e.g. not-yet-committed driver
 * files) honestly mismatches and loses the bit; the report names it. On
 * any worktree machinery failure the caller falls back to an in-process
 * re-enumeration pass (weaker binding, disclosed). */
static bool worktree_rederive(const char *repo,
                              const struct scope_def *defs,
                              size_t scope_count,
                              const uint8_t (*expected)[32], bool *matched,
                              bool *worktree_used)
{
    *worktree_used = false;
    char tmp[512];
    const char *tmpdir = getenv("TMPDIR");
    if (!tmpdir || !shell_safe(tmpdir)) tmpdir = "/tmp";
    if (snprintf(tmp, sizeof(tmp), "%s/corpus-census-wt-XXXXXX", tmpdir) >=
        (int)sizeof(tmp))
        LOG_FAIL(CENSUS_LOG, "worktree path template overflow");
    if (!mkdtemp(tmp))
        LOG_FAIL(CENSUS_LOG, "mkdtemp under %s: %s", tmpdir,
                 strerror(errno));
    char cmd[1024];
    if (snprintf(cmd, sizeof(cmd),
                 "git -C '%s' worktree add --detach '%s' HEAD >/dev/null 2>&1",
                 repo, tmp) >= (int)sizeof(cmd)) {
        rmdir(tmp);
        LOG_FAIL(CENSUS_LOG, "worktree command overflow");
    }
    int status = system(cmd); /* shellout-ok: standalone CLI tool */
    if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status)) {
        LOG_WARN(CENSUS_LOG,
                 "git worktree add failed (status=%d); falling back to "
                 "in-process re-enumeration", status);
        rmdir(tmp);
        return true;
    }
    *worktree_used = true;
    bool ok = rederive_release_roots(tmp, defs, scope_count, expected,
                                     matched);
    if (snprintf(cmd, sizeof(cmd),
                 "git -C '%s' worktree remove --force '%s' >/dev/null 2>&1",
                 repo, tmp) < (int)sizeof(cmd)) {
        status = system(cmd); /* shellout-ok: standalone CLI tool */
        if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status))
            LOG_WARN(CENSUS_LOG,
                     "git worktree remove failed for %s (status=%d); "
                     "leaving the temp dir for the operator", tmp, status);
    }
    if (!ok)
        LOG_FAIL(CENSUS_LOG, "worktree rederivation failed");
    return true;
}

/* ── quality profile (QUALITY_PROFILE bit) ────────────────────────── */

/* quality_root over the sorted (path || NUL || sha3(content)) pairs of
 * every tracked tools/lint/ file. Computed only when the operator passes
 * --quality-attested 1, asserting `make lint` passed at census time. */
static bool quality_root_compute(const char *root, uint8_t out[32])
{
    char cmd[CORPUS_CENSUS_CMD_MAX];
    if (snprintf(cmd, sizeof(cmd), "git -C '%s' ls-files -z -- tools/lint",
                 root) >= (int)sizeof(cmd))
        LOG_FAIL(CENSUS_LOG, "quality git command overflow");
    FILE *pipe = popen(cmd, "r"); /* shellout-ok: standalone CLI tool */
    if (!pipe)
        LOG_FAIL(CENSUS_LOG, "popen git ls-files tools/lint");
    struct buf raw = {0};
    uint8_t chunk[65536];
    size_t got;
    bool ok = true;
    while ((got = fread(chunk, 1, sizeof(chunk), pipe)) > 0) {
        if (!buf_put(&raw, chunk, got)) {
            ok = false;
            break;
        }
    }
    int status = pclose(pipe); /* shellout-ok: standalone CLI tool */
    if (!ok || status == -1 || !WIFEXITED(status) || WEXITSTATUS(status)) {
        buf_free(&raw);
        LOG_FAIL(CENSUS_LOG, "git ls-files tools/lint failed");
    }
    struct str_vec paths = {0};
    size_t off = 0;
    while (off < raw.len) {
        size_t end = off;
        while (end < raw.len && raw.p[end] != 0) end++;
        if (end > off &&
            !vec_push_len(&paths, (const char *)raw.p + off, end - off)) {
            buf_free(&raw);
            vec_free(&paths);
            LOG_FAIL(CENSUS_LOG, "quality path push");
        }
        off = end + 1u;
    }
    buf_free(&raw);
    if (!paths.n) {
        vec_free(&paths);
        LOG_FAIL(CENSUS_LOG, "tools/lint has no tracked files");
    }
    qsort(paths.v, paths.n, sizeof(char *), cmp_strp);
    struct buf wire = {0};
    for (size_t i = 0; ok && i < paths.n; i++) {
        uint8_t *bytes = NULL;
        size_t len = 0;
        uint64_t declared = 0;
        if (!file_load(root, paths.v[i], &bytes, &len, &declared) ||
            !bytes) {
            ok = false;
            break;
        }
        uint8_t digest[32];
        sha3_256(bytes, len, digest);
        free(bytes);
        ok = buf_put(&wire, paths.v[i], strlen(paths.v[i]) + 1u) &&
             buf_put(&wire, digest, sizeof(digest));
    }
    vec_free(&paths);
    if (ok)
        ok = evidence_root(k_domain_quality, wire.p, wire.len, out);
    buf_free(&wire);
    if (!ok)
        LOG_FAIL(CENSUS_LOG, "quality root computation failed");
    return true;
}

/* ── signed evidence objects (assignment, admission) ──────────────── */

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

static bool scope_passport_proof(const struct scope_def *def,
                                 const struct scope_measure *m,
                                 const uint8_t assignment_root[32],
                                 const uint8_t admission_root[32],
                                 const uint8_t quality_root[32],
                                 const uint8_t reproduction_root[32],
                                 uint8_t passport_root_out[32],
                                 uint8_t proof_root_out[32])
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
    memset(&wire, 0, sizeof(wire));
    ok = buf_put(&wire, m->release_root, 32) &&
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

/* ── signer seed ──────────────────────────────────────────────────── */

/* Load exactly 32 RAW seed bytes from `path`, or generate them from the
 * kernel CSPRNG and write the file mode 0600 (parents 0700) when missing.
 * The seed file must never live under the repo. */
static bool seed_load_or_create(const char *path, const char *repo_real,
                                uint8_t seed[32], bool *created_out)
{
    *created_out = false;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        struct stat st;
        uint8_t buf[32];
        size_t off = 0;
        bool ok = fstat(fd, &st) == 0 && st.st_size == 32;
        while (ok && off < sizeof(buf)) {
            ssize_t r = read(fd, buf + off, sizeof(buf) - off);
            if (r <= 0) ok = false;
            else off += (size_t)r;
        }
        close(fd);
        if (!ok)
            LOG_FAIL(CENSUS_LOG,
                     "signer seed %s must be exactly 32 raw bytes", path);
        memcpy(seed, buf, sizeof(buf));
        memory_cleanse(buf, sizeof(buf));
        return true;
    }
    if (errno != ENOENT)
        LOG_FAIL(CENSUS_LOG, "open signer seed %s: %s", path,
                 strerror(errno));

    /* Generate. Resolve the parent against the repo to enforce the
     * never-under-the-repo boundary before writing anything. */
    const char *slash = strrchr(path, '/');
    if (!slash)
        LOG_FAIL(CENSUS_LOG, "signer seed path %s has no directory", path);
    size_t dir_len = (size_t)(slash - path);
    char *dir = zcl_malloc(dir_len + 1u, "corpus.seed.dir");
    if (!dir)
        LOG_FAIL(CENSUS_LOG, "seed dir alloc");
    memcpy(dir, path, dir_len);
    dir[dir_len] = '\0';
    char resolved[4096];
    if (realpath(dir, resolved) && repo_real) {
        size_t rlen = strlen(repo_real);
        if (strncmp(resolved, repo_real, rlen) == 0 &&
            (resolved[rlen] == '/' || resolved[rlen] == '\0')) {
            free(dir);
            LOG_FAIL(CENSUS_LOG,
                     "signer seed %s would live under the repo %s", path,
                     repo_real);
        }
    }
    free(dir);
    if (!rng_fill(seed, 32))
        LOG_FAIL(CENSUS_LOG, "kernel CSPRNG refused 32 bytes");
    /* mkdir -p the parent (single level deep is the default layout; create
     * intermediate components one by one). */
    char *mutable = dup_str(path, "corpus.seed.path");
    if (!mutable)
        LOG_FAIL(CENSUS_LOG, "seed path dup");
    for (char *p = mutable + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(mutable, 0700) != 0 && errno != EEXIST) {
                LOG_ERROR(CENSUS_LOG, "mkdir %s: %s", mutable,
                          strerror(errno));
                free(mutable);
                return false;
            }
            *p = '/';
        }
    }
    free(mutable);
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        LOG_FAIL(CENSUS_LOG, "create signer seed %s: %s", path,
                 strerror(errno));
    size_t off = 0;
    bool ok = true;
    while (ok && off < 32) {
        ssize_t w = write(fd, seed + off, 32 - off);
        if (w <= 0) ok = false;
        else off += (size_t)w;
    }
    if (ok && fsync(fd) != 0) ok = false;
    if (close(fd) != 0) ok = false;
    if (!ok)
        LOG_FAIL(CENSUS_LOG, "write signer seed %s: %s", path,
                 strerror(errno));
    *created_out = true;
    return true;
}

/* ── artifact writers ─────────────────────────────────────────────── */

static bool write_text_atomic(const char *dir, const char *name,
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

static bool write_hex_artifact(const char *dir, const char *name,
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

static bool write_json_artifact(const char *dir, const char *name,
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

/* ── report helpers ───────────────────────────────────────────────── */

static const char *exclusion_name(uint32_t bit)
{
    switch (bit) {
    case VCS_ZCODE_C23_EXCLUDE_VENDOR: return "vendor";
    case VCS_ZCODE_C23_EXCLUDE_MECHANICAL: return "mechanical";
    case VCS_ZCODE_C23_EXCLUDE_UNASSIGNED: return "unassigned";
    case VCS_ZCODE_C23_EXCLUDE_LICENSE: return "license";
    case VCS_ZCODE_C23_EXCLUDE_UNSUPPORTED: return "unsupported";
    case VCS_ZCODE_C23_EXCLUDE_OVERSIZE: return "oversize";
    case VCS_ZCODE_C23_EXCLUDE_INCOMPLETE: return "incomplete";
    case VCS_ZCODE_C23_EXCLUDE_DUPLICATE: return "duplicate";
    case VCS_ZCODE_C23_EXCLUDE_CONFLICT: return "conflict";
    case VCS_ZCODE_C23_EXCLUDE_REVIEW_REQUIRED: return "review_required";
    case VCS_ZCODE_C23_EXCLUDE_STALE_ADMISSION: return "stale_admission";
    case VCS_ZCODE_C23_EXCLUDE_INCOMPLETE_POSSESSION:
        return "incomplete_possession";
    }
    return "unknown";
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

static const struct {
    uint64_t bit;
    const char *name;
} k_evidence_bits[] = {
    {VCS_ZCODE_C23_EVIDENCE_API, "api"},
    {VCS_ZCODE_C23_EVIDENCE_RECIPE, "recipe"},
    {VCS_ZCODE_C23_EVIDENCE_TESTS, "tests"},
    {VCS_ZCODE_C23_EVIDENCE_PERMISSIVE_LICENSE, "permissive_license"},
    {VCS_ZCODE_C23_EVIDENCE_QUALITY_PROFILE, "quality_profile"},
    {VCS_ZCODE_C23_EVIDENCE_SOURCE_ASSIGNMENT, "source_assignment"},
    {VCS_ZCODE_C23_EVIDENCE_REPRODUCIBLE, "reproducible"},
    {VCS_ZCODE_C23_EVIDENCE_FAMILY_QUORUM, "family_quorum"},
    {VCS_ZCODE_C23_EVIDENCE_COMPLETE_POSSESSION, "complete_possession"},
};

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

static const char *kind_name(uint16_t kind)
{
    switch (kind) {
    case VCS_ZCODE_SOURCE_HUMAN_AUTHORED: return "human";
    case VCS_ZCODE_SOURCE_AI_AUTHORED: return "ai";
    case VCS_ZCODE_SOURCE_CANONICAL_IMPORT: return "import";
    default: return "unknown";
    }
}

/* ── per-scope runtime state ──────────────────────────────────────── */

struct scope_run {
    struct scope_measure measure;
    uint8_t assignment_root[32];
    uint8_t admission_root[32];
    uint8_t passport_root[32];
    uint8_t proof_root[32];
    uint8_t reproduction_root[32];
    uint8_t quality_root[32]; /* shared global value, copied per scope */
    uint8_t assignment_wire[VCS_ZCODE_SOURCE_ASSIGNMENT_WIRE_BYTES];
    size_t assignment_wire_len;
    uint8_t admission_wire[VCS_ZCODE_COMMONS_ADMISSION_WIRE_BYTES];
    size_t admission_wire_len;
    uint64_t evidence_mask;
    bool reproduced;
    bool in_census;
    /* Package scopes only: the loaded store context and the hex receipt
     * ids the reproduction scan matched (reported, and bound into the
     * reproduction/quality wires). */
    bool pkg_loaded;
    struct package_ctx pkg;
    struct str_vec receipt_ids;
    struct vcs_zcode_corpus_census_scope_result result;
};

/* ── argument parsing ─────────────────────────────────────────────── */

struct census_args {
    const char *repo;
    const char *def;
    const char *out;
    const char *seed_path;
    const char *install_datadir;
    const char *previous_report;
    /* Where package-store LABELS resolve. scopes.def carries a label, never
     * a path (see store_label_valid), so the committed def and every
     * artifact derived from it stay free of the operator's home directory.
     * --store-root, else $ZCL_CORPUS_STORE_ROOT, else $HOME. */
    const char *store_root;
    uint64_t cutoff_height;
    int64_t cutoff_mtp;
    uint64_t sequence;
    uint8_t predecessor[32];
    bool predecessor_given;
    bool quality_attested;
};

static bool parse_u64(const char *s, uint64_t *out)
{
    if (!s || !*s) return false;
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno || !end || *end) return false;
    *out = (uint64_t)v;
    return true;
}

static bool parse_i64(const char *s, int64_t *out)
{
    if (!s || !*s) return false;
    errno = 0;
    char *end = NULL;
    long long v = strtoll(s, &end, 10);
    if (errno || !end || *end) return false;
    *out = (int64_t)v;
    return true;
}

static void usage(FILE *stream)
{
    fprintf(stream,
        "usage: corpus-census --repo <repo root> --def <scopes.def> "
        "--out <dir>\n"
        "       --cutoff-height N --cutoff-mtp N [--signer-seed-file PATH]\n"
        "       [--sequence N] [--predecessor-root HEX64] "
        "[--quality-attested 0|1]\n"
        "       [--install <datadir>] [--previous-report PATH]\n"
        "       [--store-root DIR]   package-store labels in scopes.def "
        "resolve to\n"
        "                            <DIR>/<label>; default "
        "$ZCL_CORPUS_STORE_ROOT else $HOME\n"
        "       (sequence >1 auto-discovers the predecessor root and the\n"
        "       previous report from <out>/report-<seq-1>.json)\n");
}

static bool args_parse(int argc, char **argv, struct census_args *args)
{
    memset(args, 0, sizeof(*args));
    args->sequence = 1;
    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];
        if (strncmp(arg, "--", 2) != 0) return false;
        char *eq = strchr(arg, '=');
        char *value = NULL;
        char key[64];
        if (eq) {
            size_t klen = (size_t)(eq - arg);
            if (klen >= sizeof(key)) return false;
            memcpy(key, arg, klen);
            key[klen] = '\0';
            value = eq + 1;
        } else {
            if (strlen(arg) >= sizeof(key)) return false;
            strcpy(key, arg);
            if (i + 1 >= argc) return false;
            value = argv[++i];
        }
        if (strcmp(key, "--repo") == 0) args->repo = value;
        else if (strcmp(key, "--def") == 0) args->def = value;
        else if (strcmp(key, "--out") == 0) args->out = value;
        else if (strcmp(key, "--signer-seed-file") == 0)
            args->seed_path = value;
        else if (strcmp(key, "--sequence") == 0) {
            if (!parse_u64(value, &args->sequence)) return false;
        } else if (strcmp(key, "--cutoff-height") == 0) {
            if (!parse_u64(value, &args->cutoff_height)) return false;
        } else if (strcmp(key, "--cutoff-mtp") == 0) {
            if (!parse_i64(value, &args->cutoff_mtp)) return false;
        } else if (strcmp(key, "--quality-attested") == 0) {
            uint64_t v = 0;
            if (!parse_u64(value, &v) || v > 1) return false;
            args->quality_attested = v == 1;
        } else if (strcmp(key, "--predecessor-root") == 0) {
            if (strlen(value) != 64 ||
                !zcl_hex_decode_lower(value, args->predecessor, 32))
                return false;
            args->predecessor_given = true;
        } else if (strcmp(key, "--install") == 0) {
            args->install_datadir = value;
        } else if (strcmp(key, "--previous-report") == 0) {
            args->previous_report = value;
        } else if (strcmp(key, "--store-root") == 0) {
            args->store_root = value;
        } else {
            return false;
        }
    }
    /* Package-store label resolution root. Never committed anywhere: it is
     * an operator-local coordinate, which is exactly why it is a flag/env
     * and not a field in scopes.def. */
    if (!args->store_root) args->store_root = getenv("ZCL_CORPUS_STORE_ROOT");
    if (!args->store_root) args->store_root = getenv("HOME");
    if (!args->repo || !args->def || !args->out || !args->cutoff_height ||
        args->cutoff_mtp <= 0 || !args->sequence)
        return false;
    bool pred_nonzero =
        args->predecessor_given && zcl_bytes_any_set(args->predecessor, 32);
    /* sequence 1 requires the zero predecessor root; sequence >1 either
     * takes an explicit nonzero root or discovers it from the previous
     * sequence's report in the out dir (main, fail-closed). */
    if (args->sequence == 1 && pred_nonzero) return false;
    if (!shell_safe(args->repo))
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

/* ── main ─────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    struct census_args args;
    if (!args_parse(argc, argv, &args)) {
        usage(stderr);
        return 2;
    }

    /* Resolve the repo root (the seed never-under-repo guard needs the
     * canonical path). */
    char repo_real[4096];
    if (!realpath(args.repo, repo_real))
        LOG_ERR(CENSUS_LOG, "realpath %s: %s", args.repo, strerror(errno));
    if (!shell_safe(repo_real))
        LOG_ERR(CENSUS_LOG, "repo path %s has unsafe characters",
                repo_real);

    /* Sequence-chain defaults: when advancing the sequence inside an out
     * dir that already holds the previous sequence's report, bind the
     * predecessor root and the growth-delta input from that report
     * automatically. Explicit flags always win; when the predecessor is
     * neither given nor discoverable the run fails closed rather than
     * cutting an unchained checkpoint. */
    char discovered_report[4400];
    if (args.sequence > 1 &&
        (!args.predecessor_given || !args.previous_report)) {
        int n = snprintf(discovered_report, sizeof(discovered_report),
                         "%s/report-%06llu.json", args.out,
                         (unsigned long long)(args.sequence - 1));
        if (n < 0 || (size_t)n >= sizeof(discovered_report))
            LOG_ERR(CENSUS_LOG, "previous report path overflow");
        uint8_t *prev_wire = NULL;
        size_t prev_len = 0;
        struct json_value prev;
        json_init(&prev);
        const char *prev_root_hex = NULL;
        if (store_file_read(discovered_report, 4u * 1024u * 1024u,
                            &prev_wire, &prev_len) && prev_wire &&
            json_read(&prev, (const char *)prev_wire, prev_len))
            prev_root_hex = json_get_str(json_get(&prev, "checkpoint_root"));
        if (!args.predecessor_given) {
            if (!prev_root_hex || strlen(prev_root_hex) != 64 ||
                !zcl_hex_decode_lower(prev_root_hex, args.predecessor, 32))
                LOG_ERR(CENSUS_LOG, "sequence %llu needs "
                        "--predecessor-root (or a readable %s with a "
                        "checkpoint_root)",
                        (unsigned long long)args.sequence,
                        discovered_report);
            args.predecessor_given = true;
            LOG_INFO(CENSUS_LOG, "predecessor root %.16s... from %s",
                     prev_root_hex, discovered_report);
        }
        if (!args.previous_report && prev_root_hex)
            args.previous_report = discovered_report;
        free(prev_wire);
        json_free(&prev);
    }

    /* Signer seed. */
    char default_seed[4096];
    const char *seed_path = args.seed_path;
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
    uint8_t seed[32];
    bool seed_created = false;
    if (!seed_load_or_create(seed_path, repo_real, seed, &seed_created))
        return 1;
    uint8_t signer_pubkey[32], signer_secret[32];
    ed25519_keypair(signer_pubkey, signer_secret, seed);
    memory_cleanse(signer_secret, sizeof(signer_secret));
    char pubkey_hex[65];
    root_hex(signer_pubkey, pubkey_hex);
    if (seed_created)
        LOG_WARN(CENSUS_LOG,
                 "generated NEW corpus-census signer seed at %s "
                 "(mode 0600, raw 32 bytes); signer_pubkey=%s", seed_path,
                 pubkey_hex);
    else
        LOG_INFO(CENSUS_LOG, "signer_pubkey=%s seed=%s", pubkey_hex,
                 seed_path);

    /* Scope definition. */
    struct scope_def *defs = NULL;
    size_t scope_count = 0;
    uint8_t def_sha3[32];
    if (!def_load(args.def, &defs, &scope_count, def_sha3))
        return 1;
    LOG_INFO(CENSUS_LOG, "loaded %zu scopes from %s", scope_count,
             args.def);
    bool any_package = false;
    bool any_repo = false;
    for (size_t s = 0; s < scope_count; s++) {
        if (defs[s].is_package) any_package = true;
        else any_repo = true;
    }

    /* Frozen family policy root, cross-checked against the library. */
    struct vcs_zcode_family_policy_v1 policy;
    vcs_zcode_family_policy_v1_default(&policy);
    uint8_t family_policy_root[32], frozen_root[32];
    if (vcs_zcode_family_policy_v1_root(&policy, family_policy_root) !=
            VCS_ZCODE_COMMONS_OK)
        LOG_ERR(CENSUS_LOG, "family policy root failed");
    if (!zcl_hex_decode_lower(CORPUS_CENSUS_FAMILY_POLICY_ROOT_HEX,
                              frozen_root, 32))
        LOG_ERR(CENSUS_LOG, "frozen family policy root hex decode failed");
    if (memcmp(family_policy_root, frozen_root, 32) != 0)
        LOG_ERR(CENSUS_LOG,
                "family-c23.v1 default policy root no longer matches the "
                "frozen constant " CORPUS_CENSUS_FAMILY_POLICY_ROOT_HEX);
    uint8_t moderation_set_root[32];
    if (!evidence_root(k_domain_moderation, NULL, 0, moderation_set_root))
        return 1;

    /* Claim resolution over the live tree. */
    struct scope_files *files = NULL;
    if (!claims_resolve(args.repo, defs, scope_count, &files))
        return 1;

    /* Per-scope measurement: release/license/recipe/deps/possession. */
    struct scope_run *runs =
        zcl_calloc(scope_count, sizeof(*runs), "corpus.runs");
    if (!runs)
        LOG_ERR(CENSUS_LOG, "runs alloc %zu", scope_count);

    /* Package scopes enumerate from the store, not git: load and verify
     * the manifest + release envelope (fail closed), then take the
     * manifest's canonical file list. */
    for (size_t s = 0; s < scope_count; s++) {
        if (!defs[s].is_package) continue;
        if (!package_ctx_load(&runs[s].pkg, &defs[s], args.store_root))
            return 1;
        runs[s].pkg_loaded = true;
        if (!package_scope_enumerate(&runs[s].pkg, &files[s]))
            return 1;
        /* The LABEL, not the resolved directory: this line is read from
         * captured build logs that get pasted into issues. */
        LOG_INFO(CENSUS_LOG, "package scope %s: %zu files from store '%s'",
                 defs[s].name, files[s].n, defs[s].store);
    }

    /* The repo CAS holds every scope file's bytes (COMPLETE_POSSESSION). */
    if (!vcs_object_store_init(args.repo))
        LOG_ERR(CENSUS_LOG, "cannot initialize %s/.zvcs object store",
                args.repo);

    /* Global quality root (only when the operator attests lint passed). */
    uint8_t quality_root[32] = {0};
    if (args.quality_attested &&
        !quality_root_compute(args.repo, quality_root))
        return 1;

    for (size_t s = 0; s < scope_count; s++) {
        struct scope_run *run = &runs[s];
        const struct package_ctx *pkg =
            defs[s].is_package ? &run->pkg : NULL;
        run->measure.possession_ok = true;
        struct buf wire = {0};
        if (!scope_release_wire(args.repo, &files[s], &wire,
                                &run->measure, defs[s].name, pkg))
            return 1;
        if (pkg) {
            /* The package scope's release root is the EXACT published
             * package root from the def, already verified against the
             * re-derived manifest root of the stored manifest. */
            memcpy(run->measure.release_root, defs[s].package_root, 32);
            if (!package_possession_root(pkg, run->measure.possession_root))
                return 1;
        } else if (!evidence_root(k_domain_release, wire.p, wire.len,
                                  run->measure.release_root)) {
            buf_free(&wire);
            return 1;
        }
        buf_free(&wire);
        if (!scope_license_bind(args.repo, &defs[s], &run->measure, pkg))
            return 1;
        if (!scope_recipe_bind(args.repo, &defs[s], &run->measure, pkg))
            return 1;
        run->in_census = true;
    }

    /* REPRODUCIBLE: dual-materialization rederivation at HEAD for repo
     * scopes; the receipts scan (two DISTINCT byte-identical confined
     * builds) for package scopes. */
    bool *repro_matched =
        zcl_calloc(scope_count, sizeof(*repro_matched), "corpus.repro");
    if (!repro_matched)
        LOG_ERR(CENSUS_LOG, "repro alloc %zu", scope_count);
    for (size_t s = 0; s < scope_count; s++) {
        if (!defs[s].is_package) continue;
        struct scope_run *run = &runs[s];
        size_t rlen = strlen(run->pkg.zcode_dir) + sizeof("/receipts");
        char *rdir = zcl_malloc(rlen, "corpus.pkg.receipts");
        if (!rdir)
            LOG_ERR(CENSUS_LOG, "receipts path alloc");
        (void)snprintf(rdir, rlen, "%s/receipts", run->pkg.zcode_dir);
        struct vcs_reproduce_report repro;
        if (!vcs_package_reproduce_scan(rdir, defs[s].package_root,
                                        run->pkg.release.recipe_root,
                                        &repro)) {
            LOG_ERROR(CENSUS_LOG, "package %s: receipts dir %s unreadable",
                      defs[s].name, rdir);
            free(rdir);
            return 1;
        }
        free(rdir);
        repro_matched[s] = repro.reproduced;
        for (size_t i = 0; i < repro.row_count; i++) {
            if (repro.rows[i].rule != VCS_REPRODUCE_MATCH) continue;
            char rid_hex[65];
            zcl_hex_encode(repro.rows[i].receipt_id, 32, rid_hex);
            if (!vec_push(&run->receipt_ids, rid_hex))
                LOG_ERR(CENSUS_LOG, "receipt id push failed");
        }
        LOG_INFO(CENSUS_LOG,
                 "package %s: reproduction scan: reproduced=%d matching=%u "
                 "scanned=%u", defs[s].name, (int)repro.reproduced,
                 repro.matching, repro.scanned);
    }
    bool worktree_used = false;
    {
        /* expected roots in scope order for the rederivation pass */
        uint8_t (*expected)[32] =
            zcl_calloc(scope_count, sizeof(*expected), "corpus.expected");
        if (!expected)
            LOG_ERR(CENSUS_LOG, "expected roots alloc %zu", scope_count);
        for (size_t s = 0; s < scope_count; s++)
            memcpy(expected[s], runs[s].measure.release_root, 32);
        if (!worktree_rederive(args.repo, defs, scope_count,
                               (const uint8_t (*)[32])expected,
                               repro_matched, &worktree_used)) {
            free(expected);
            return 1;
        }
        if (!worktree_used) {
            /* Weaker binding: second in-process enumeration + recompute.
             * Disclosed in the report. */
            if (!rederive_release_roots(args.repo, defs, scope_count,
                                        (const uint8_t (*)[32])expected,
                                        repro_matched)) {
                free(expected);
                return 1;
            }
        }
        free(expected);
    }
    const char *repro_method =
        worktree_used ? k_repro_worktree : k_repro_fallback;
    if (any_repo)
        LOG_INFO(CENSUS_LOG, "repo reproduction binding method: %s",
                 repro_method);
    if (any_package)
        LOG_INFO(CENSUS_LOG,
                 "package reproduction binding method: "
                 "receipts-dual-confined-build");

    /* Signed evidence + census per scope, in sorted scope order. */
    struct vcs_zcode_corpus_census census;
    vcs_zcode_corpus_census_init(&census);
    for (size_t s = 0; s < scope_count; s++) {
        struct scope_run *run = &runs[s];
        const struct scope_measure *m = &run->measure;
        run->reproduced = repro_matched[s];
        if (run->reproduced) {
            struct buf rwire = {0};
            bool rok = buf_put(&rwire, m->release_root, 32);
            if (defs[s].is_package) {
                /* Package binding: release_root || method || concat of the
                 * sorted matching receipt ids (the strong two-confined-
                 * builds binding). */
                rok = rok &&
                    buf_put(&rwire, k_repro_receipts,
                            strlen(k_repro_receipts));
                for (size_t i = 0; rok && i < run->receipt_ids.n; i++) {
                    uint8_t rid[32];
                    if (!zcl_hex_decode_lower(run->receipt_ids.v[i], rid,
                                              32)) {
                        rok = false;
                        break;
                    }
                    rok = buf_put(&rwire, rid, 32);
                }
            } else {
                rok = rok &&
                    buf_put(&rwire, repro_method, strlen(repro_method));
            }
            if (rok)
                rok = evidence_root(k_domain_reproduction, rwire.p,
                                    rwire.len, run->reproduction_root);
            buf_free(&rwire);
            if (!rok)
                return 1;
            /* Package QUALITY_PROFILE mapping: "confined build+test
             * receipt green" — the same receipts evidence. */
            if (defs[s].is_package) {
                struct buf qwire = {0};
                bool qok = buf_put(&qwire, m->release_root, 32) &&
                           buf_put(&qwire, k_quality_receipts,
                                   strlen(k_quality_receipts));
                for (size_t i = 0; qok && i < run->receipt_ids.n; i++) {
                    uint8_t rid[32];
                    if (!zcl_hex_decode_lower(run->receipt_ids.v[i], rid,
                                              32)) {
                        qok = false;
                        break;
                    }
                    qok = buf_put(&qwire, rid, 32);
                }
                if (qok)
                    qok = evidence_root(k_domain_quality, qwire.p,
                                        qwire.len, run->quality_root);
                buf_free(&qwire);
                if (!qok)
                    return 1;
            }
        }
        if (!scope_assignment_build(&defs[s], s, args.cutoff_height,
                                    args.cutoff_mtp, m,
                                    defs[s].is_package
                                        ? run->pkg.publisher_hex : NULL,
                                    seed,
                                    run->assignment_root,
                                    run->assignment_wire,
                                    &run->assignment_wire_len))
            return 1;
        if (!scope_admission_build(&defs[s], args.cutoff_height,
                                   args.cutoff_mtp, m, run->assignment_root,
                                   family_policy_root, moderation_set_root,
                                   seed, run->admission_root,
                                   run->admission_wire,
                                   &run->admission_wire_len))
            return 1;
        /* Package scopes carry their own receipts-green quality root
         * (computed above when reproduced); repo scopes share the global
         * lint-attested quality root. */
        if (!defs[s].is_package)
            memcpy(run->quality_root, quality_root, 32);
        if (!scope_passport_proof(&defs[s], m, run->assignment_root,
                                  run->admission_root, run->quality_root,
                                  run->reproduction_root,
                                  run->passport_root, run->proof_root))
            return 1;

        /* The evidence mask carries exactly the bits whose bindings
         * succeeded. */
        uint64_t mask = 0;
        if (m->has_api) mask |= VCS_ZCODE_C23_EVIDENCE_API;
        if (zcl_bytes_any_set(m->recipe_root, 32)) mask |= VCS_ZCODE_C23_EVIDENCE_RECIPE;
        if (m->has_tests_sem) mask |= VCS_ZCODE_C23_EVIDENCE_TESTS;
        if (m->license_ok)
            mask |= VCS_ZCODE_C23_EVIDENCE_PERMISSIVE_LICENSE;
        if (defs[s].is_package
                ? (run->reproduced && zcl_bytes_any_set(run->quality_root, 32))
                : (args.quality_attested && zcl_bytes_any_set(run->quality_root, 32)))
            mask |= VCS_ZCODE_C23_EVIDENCE_QUALITY_PROFILE;
        mask |= VCS_ZCODE_C23_EVIDENCE_SOURCE_ASSIGNMENT;
        if (run->reproduced) mask |= VCS_ZCODE_C23_EVIDENCE_REPRODUCIBLE;
        mask |= VCS_ZCODE_C23_EVIDENCE_FAMILY_QUORUM;
        if (m->possession_ok && zcl_bytes_any_set(m->possession_root, 32))
            mask |= VCS_ZCODE_C23_EVIDENCE_COMPLETE_POSSESSION;
        run->evidence_mask = mask;

        /* Reload the scope's bytes for the census core. */
        struct vcs_zcode_corpus_census_file *cfiles = NULL;
        if (files[s].n) {
            cfiles = zcl_calloc(files[s].n, sizeof(*cfiles),
                                "corpus.census.files");
            if (!cfiles)
                LOG_ERR(CENSUS_LOG, "census files alloc %zu", files[s].n);
        }
        for (size_t i = 0; i < files[s].n; i++) {
            cfiles[i].path = files[s].paths[i];
            bool loaded = defs[s].is_package
                ? package_file_load(&run->pkg, files[s].paths[i],
                                    (uint8_t **)&cfiles[i].bytes,
                                    &cfiles[i].len, &cfiles[i].declared_size)
                : file_load(args.repo, files[s].paths[i],
                            (uint8_t **)&cfiles[i].bytes, &cfiles[i].len,
                            &cfiles[i].declared_size);
            if (!loaded) {
                for (size_t k = 0; k < i; k++) free((void *)cfiles[k].bytes);
                free(cfiles);
                return 1;
            }
        }
        struct vcs_zcode_corpus_census_scope_input input;
        memset(&input, 0, sizeof(input));
        input.name = defs[s].name;
        input.source_kind = defs[s].kind;
        input.license_spdx = defs[s].spdx;
        memcpy(input.license_root, m->license_root, 32);
        input.evidence_mask = mask;
        memcpy(input.release_root, m->release_root, 32);
        memcpy(input.passport_root, run->passport_root, 32);
        memcpy(input.proof_root, run->proof_root, 32);
        memcpy(input.source_assignment_root, run->assignment_root, 32);
        memcpy(input.admission_root, run->admission_root, 32);
        /* possession_root stays ZERO in the entry: nothing is durable
         * yet; the computed root is recorded in the report only. */
        input.release_sequence = 1;
        input.files = cfiles;
        input.file_count = files[s].n;
        if (!vcs_zcode_corpus_census_process_scope(&census, &input,
                                                   &run->result)) {
            for (size_t k = 0; k < files[s].n; k++)
                free((void *)cfiles[k].bytes);
            free(cfiles);
            return 1;
        }
        for (size_t k = 0; k < files[s].n; k++)
            free((void *)cfiles[k].bytes);
        free(cfiles);
    }
    free(repro_matched);
    repro_matched = NULL;

    /* Zero-unit scopes share the empty-lineage root; the assembly fails
     * closed on a collision, so keep only the first (they carry no
     * countable content) and report the rest as omitted. */
    size_t census_count = 0;
    {
        bool empty_seen = false;
        for (size_t s = 0; s < scope_count; s++) {
            if (runs[s].result.units_total == 0) {
                if (empty_seen) {
                    runs[s].in_census = false;
                    LOG_WARN(CENSUS_LOG,
                             "scope %s has zero semantic units; omitting "
                             "from the census (lineage collision guard)",
                             defs[s].name);
                } else {
                    empty_seen = true;
                }
            }
            if (runs[s].in_census) census_count++;
        }
    }
    if (!census_count)
        LOG_ERR(CENSUS_LOG, "no scopes to assemble");
    struct vcs_zcode_corpus_census_scope_result *kept =
        zcl_calloc(census_count, sizeof(*kept), "corpus.kept");
    if (!kept)
        LOG_ERR(CENSUS_LOG, "kept alloc %zu", census_count);
    size_t kept_n = 0;
    for (size_t s = 0; s < scope_count; s++)
        if (runs[s].in_census) kept[kept_n++] = runs[s].result;

    struct vcs_zcode_corpus_census_assembly assembly;
    enum vcs_zcode_c23_error error = vcs_zcode_corpus_census_assemble(
        kept, census_count, family_policy_root, moderation_set_root,
        &assembly);
    if (error != VCS_ZCODE_C23_OK)
        LOG_ERR(CENSUS_LOG, "census assemble: %s",
                vcs_zcode_c23_error_string(error));
    vcs_zcode_corpus_census_free(&census);

    /* Shard the globally sorted entries into the inline-readable cap. */
    size_t shard_count = (census_count + CORPUS_CENSUS_SHARD_ENTRY_CAP - 1u) /
                         CORPUS_CENSUS_SHARD_ENTRY_CAP;
    if (shard_count > CORPUS_CENSUS_CHECKPOINT_INLINE_SHARD_CAP)
        LOG_ERR(CENSUS_LOG,
                "%zu shards exceed the %u inline checkpoint reader cap; "
                "raise the reader budget before emitting more",
                shard_count, CORPUS_CENSUS_CHECKPOINT_INLINE_SHARD_CAP);
    struct vcs_zcode_c23_checkpoint_shard_v1 *bindings =
        zcl_calloc(shard_count, sizeof(*bindings), "corpus.bindings");
    uint8_t **shard_wires =
        zcl_calloc(shard_count, sizeof(*shard_wires), "corpus.shardwires");
    if (!bindings || !shard_wires)
        LOG_ERR(CENSUS_LOG, "shard arrays alloc %zu", shard_count);
    size_t *shard_wire_lens =
        zcl_calloc(shard_count, sizeof(*shard_wire_lens),
                   "corpus.shardlens");
    if (!shard_wire_lens)
        LOG_ERR(CENSUS_LOG, "shard lens alloc %zu", shard_count);
    uint8_t (*shard_roots)[32] =
        zcl_calloc(shard_count, sizeof(*shard_roots), "corpus.shardroots");
    if (!shard_roots)
        LOG_ERR(CENSUS_LOG, "shard roots alloc %zu", shard_count);
    for (size_t i = 0; i < shard_count; i++) {
        size_t first = i * CORPUS_CENSUS_SHARD_ENTRY_CAP;
        size_t count = census_count - first;
        if (count > CORPUS_CENSUS_SHARD_ENTRY_CAP)
            count = CORPUS_CENSUS_SHARD_ENTRY_CAP;
        struct vcs_zcode_c23_corpus_shard_v1 shard;
        memset(&shard, 0, sizeof(shard));
        shard.schema_version = 1;
        shard.flags = VCS_ZCODE_C23_CORPUS_REQUIRED_FLAGS;
        memcpy(shard.rules_root, assembly.rules_root, 32);
        memcpy(shard.family_policy_root, family_policy_root, 32);
        memcpy(shard.moderation_set_root, moderation_set_root, 32);
        shard.entries = &assembly.entries[first];
        shard.entry_count = count;
        error = vcs_zcode_c23_corpus_shard_v1_validate(&shard);
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
        error = vcs_zcode_c23_corpus_shard_v1_encode(&shard, wire,
                                                     wire_size, &wire_len);
        if (error != VCS_ZCODE_C23_OK || wire_len != wire_size) {
            free(wire);
            LOG_ERR(CENSUS_LOG, "shard %zu encode: %s", i,
                    vcs_zcode_c23_error_string(error));
        }
        error = vcs_zcode_c23_corpus_shard_v1_root(&shard, shard_roots[i]);
        if (error != VCS_ZCODE_C23_OK) {
            free(wire);
            LOG_ERR(CENSUS_LOG, "shard %zu root: %s", i,
                    vcs_zcode_c23_error_string(error));
        }
        shard_wires[i] = wire;
        shard_wire_lens[i] = wire_len;

        struct vcs_zcode_c23_checkpoint_shard_v1 *b = &bindings[i];
        memcpy(b->shard_root, shard_roots[i], 32);
        memcpy(b->first_lineage_root,
               assembly.entries[first].semantic_lineage_root, 32);
        memcpy(b->last_lineage_root,
               assembly.entries[first + count - 1u].semantic_lineage_root,
               32);
        b->entry_count = count;
        for (size_t e = first; e < first + count; e++) {
            const struct vcs_zcode_c23_corpus_entry_v1 *entry =
                &assembly.entries[e];
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
        }
    }

    /* replication_evidence_root: concatenated shard roots + the disclosed
     * single-host-founding literal. */
    uint8_t replication_root[32];
    {
        struct buf wire = {0};
        bool ok = true;
        for (size_t i = 0; ok && i < shard_count; i++)
            ok = buf_put(&wire, shard_roots[i], 32);
        ok = ok && buf_put(&wire, k_replication_literal,
                           strlen(k_replication_literal)) &&
             evidence_root(k_domain_replication, wire.p, wire.len,
                           replication_root);
        buf_free(&wire);
        if (!ok)
            LOG_ERR(CENSUS_LOG, "replication evidence root failed");
    }

    struct vcs_zcode_c23_corpus_checkpoint_v1 checkpoint;
    memset(&checkpoint, 0, sizeof(checkpoint));
    checkpoint.schema_version = 1;
    checkpoint.flags = VCS_ZCODE_C23_CORPUS_REQUIRED_FLAGS;
    checkpoint.milestone = VCS_ZCODE_C23_MILESTONE_NONE;
    checkpoint.sequence = args.sequence;
    memcpy(checkpoint.predecessor_checkpoint_root, args.predecessor, 32);
    memcpy(checkpoint.rules_root, assembly.rules_root, 32);
    memcpy(checkpoint.family_policy_root, family_policy_root, 32);
    memcpy(checkpoint.moderation_set_root, moderation_set_root, 32);
    memcpy(checkpoint.replication_evidence_root, replication_root, 32);
    checkpoint.cutoff_height = args.cutoff_height;
    checkpoint.cutoff_mtp = args.cutoff_mtp;
    checkpoint.total_entries = census_count;
    checkpoint.production_loc = assembly.production_loc;
    checkpoint.test_loc = assembly.test_loc;
    checkpoint.durable_loc = assembly.durable_loc;
    checkpoint.physical_lines = assembly.physical_lines;
    checkpoint.unique_semantic_units = assembly.unique_semantic_units;
    checkpoint.excluded_entries = assembly.excluded_entries;
    checkpoint.shards = bindings;
    checkpoint.shard_count = shard_count;
    error = vcs_zcode_c23_corpus_checkpoint_v1_sign(&checkpoint, seed);
    if (error != VCS_ZCODE_C23_OK)
        LOG_ERR(CENSUS_LOG, "checkpoint sign: %s",
                vcs_zcode_c23_error_string(error));
    uint8_t checkpoint_root[32];
    error = vcs_zcode_c23_corpus_checkpoint_v1_root(&checkpoint,
                                                    checkpoint_root);
    if (error != VCS_ZCODE_C23_OK)
        LOG_ERR(CENSUS_LOG, "checkpoint root: %s",
                vcs_zcode_c23_error_string(error));
    size_t checkpoint_wire_size =
        vcs_zcode_c23_corpus_checkpoint_v1_wire_size(shard_count);
    if (!checkpoint_wire_size || checkpoint_wire_size > 8192u)
        LOG_ERR(CENSUS_LOG, "checkpoint wire size %zu",
                checkpoint_wire_size);
    uint8_t *checkpoint_wire =
        zcl_malloc(checkpoint_wire_size, "corpus.checkpoint.wire");
    if (!checkpoint_wire)
        LOG_ERR(CENSUS_LOG, "checkpoint wire alloc %zu",
                checkpoint_wire_size);
    size_t checkpoint_wire_len = 0;
    error = vcs_zcode_c23_corpus_checkpoint_v1_encode(
        &checkpoint, checkpoint_wire, checkpoint_wire_size,
        &checkpoint_wire_len);
    if (error != VCS_ZCODE_C23_OK ||
        checkpoint_wire_len != checkpoint_wire_size) {
        free(checkpoint_wire);
        LOG_ERR(CENSUS_LOG, "checkpoint encode: %s",
                vcs_zcode_c23_error_string(error));
    }

    /* ── artifacts ────────────────────────────────────────────────── */
    if (mkdir(args.out, 0755) != 0 && errno != EEXIST)
        LOG_ERR(CENSUS_LOG, "mkdir %s: %s", args.out, strerror(errno));
    char name[128];
    (void)snprintf(name, sizeof(name), "checkpoint-%06llu.hex",
                   (unsigned long long)args.sequence);
    if (!write_hex_artifact(args.out, name, checkpoint_wire,
                            checkpoint_wire_len))
        return 1;
    char checkpoint_file[160];
    strcpy(checkpoint_file, name);
    for (size_t i = 0; i < shard_count; i++) {
        (void)snprintf(name, sizeof(name), "shard-%06llu-%zu.hex",
                       (unsigned long long)args.sequence, i);
        if (!write_hex_artifact(args.out, name, shard_wires[i],
                                shard_wire_lens[i]))
            return 1;
    }

    /* Optional install: drop the signed checkpoint wire where
     * `zcode commons corpus status` reads it back
     * (<datadir>/zcode/corpus/checkpoint.hex). Write-only, atomic, never
     * touches any other datadir content. */
    if (args.install_datadir) {
        if (mkdir(args.install_datadir, 0755) != 0 && errno != EEXIST) {
            LOG_ERROR(CENSUS_LOG, "install mkdir %s: %s",
                      args.install_datadir, strerror(errno));
            return 1;
        }
        size_t dir_cap = strlen(args.install_datadir) + 32u;
        char *zcode_dir = zcl_malloc(dir_cap, "corpus.install.dir");
        if (!zcode_dir)
            LOG_ERR(CENSUS_LOG, "install dir alloc");
        (void)snprintf(zcode_dir, dir_cap, "%s/zcode", args.install_datadir);
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
                                            checkpoint_wire,
                                            checkpoint_wire_len);
        free(corpus_dir);
        if (!installed)
            return 1;
        LOG_INFO(CENSUS_LOG, "installed resident checkpoint into %s/zcode/"
                 "corpus/checkpoint.hex", args.install_datadir);
    }

    /* git provenance for the report (unsigned). */
    char head_hex[128] = {0};
    char dirty_probe[8192] = {0};
    if (!git_capture(args.repo, "rev-parse HEAD", head_hex,
                     sizeof(head_hex)) ||
        !git_capture(args.repo, "status --porcelain", dirty_probe,
                     sizeof(dirty_probe)))
        return 1;
    bool repo_dirty = dirty_probe[0] != '\0';

    /* ── evidence bundle ──────────────────────────────────────────── */
    struct json_value evidence;
    json_init(&evidence);
    json_set_object(&evidence);
    (void)json_push_kv_str(&evidence, "schema",
                           "zcl.c23_corpus_census.evidence.v1");
    (void)json_push_kv_bool(&evidence, "simulation_only", true);
    (void)json_push_kv_bool(&evidence, "not_owner_approved", true);
    (void)json_push_kv_int(&evidence, "sequence", (int64_t)args.sequence);
    (void)json_push_kv_int(&evidence, "cutoff_height",
                           (int64_t)args.cutoff_height);
    (void)json_push_kv_int(&evidence, "cutoff_mtp",
                           (int64_t)args.cutoff_mtp);
    (void)json_push_kv_str(&evidence, "signer_pubkey", pubkey_hex);
    {
        char hex[65];
        root_hex(def_sha3, hex);
        (void)json_push_kv_str(&evidence, "scopes_def_sha3", hex);
    }
    {
        struct json_value recipes;
        json_init(&recipes);
        json_set_object(&recipes);
        (void)json_push_kv_str(&recipes, "release_root",
            "vcs_signed_evidence_root(\"zcl.zcode.corpus.release.v1\" incl "
            "NUL, concat over sorted repo-relative paths of path || NUL || "
            "u64-LE size || sha3_256(content))");
        (void)json_push_kv_str(&recipes, "license_root",
            "same-style root over license-path || NUL || u64-LE size || "
            "sha3_256(content) for the license file actually used "
            "(scope-local LICENSE else repo-root LICENSE), domain "
            "zcl.zcode.corpus.license.v1");
        (void)json_push_kv_str(&recipes, "author_binding_root",
            "domain zcl.zcode.corpus.author_binding.v1 over the ASCII "
            "author string (\"ZClassic23 founding contributors\" for kind "
            "human, \"zclassic23-agent-fleet\" for kind ai)");
        (void)json_push_kv_str(&recipes, "assignment_evidence_root",
            "domain zcl.zcode.corpus.assignment_evidence.v1 over the exact "
            "scopes.def line bytes for the scope (no trailing newline)");
        (void)json_push_kv_str(&recipes, "dependency_closure_root",
            "domain zcl.zcode.corpus.dependency_closure.v1 over concat of "
            "name || NUL || root-hex-ascii || NUL || semver || NUL per "
            "zcode-package.json dependency (file order); empty wire for "
            "the declared empty set");
        (void)json_push_kv_str(&recipes, "moderation_set_root",
            "domain zcl.zcode.corpus.moderation_set.v1 over the EMPTY wire "
            "(founding empty moderation set; corpus-local construction, "
            "no canonical founding root exists in "
            "zcode_family_moderation.c)");
        (void)json_push_kv_str(&recipes, "panel_root",
            "domain zcl.zcode.corpus.panel.v1 over the ASCII literal "
            "\"founding-self-screen\"");
        (void)json_push_kv_str(&recipes, "admission_evidence_root",
            "domain zcl.zcode.corpus.admission_evidence.v1 over the "
            "scope's 32-byte source_assignment_root");
        (void)json_push_kv_str(&recipes, "passport_root",
            "domain zcl.zcode.corpus.passport.v1 over name || NUL || spdx "
            "|| NUL || release_root || license_root || api-presence byte "
            "|| recipe-presence byte");
        (void)json_push_kv_str(&recipes, "recipe_root",
            "domain zcl.zcode.corpus.recipe.v1 over recipe-path || NUL || "
            "u64-LE size || sha3_256(content); the recipe is the scope's "
            "zcode-package.json when present, else the repo Makefile "
            "(declared core-scope build recipe)");
        (void)json_push_kv_str(&recipes, "quality_root",
            "domain zcl.zcode.corpus.quality.v1 over sorted tools/lint/ "
            "path || NUL || sha3_256(content) pairs; computed only with "
            "--quality-attested 1");
        (void)json_push_kv_str(&recipes, "reproduction_root",
            "domain zcl.zcode.corpus.reproduction.v1 over release_root || "
            "method literal (\"dual-worktree\" or "
            "\"in-process-reenumeration\")");
        (void)json_push_kv_str(&recipes, "proof_root",
            "domain zcl.zcode.corpus.proof.v1 over release_root || "
            "source_assignment_root || admission_root || quality_root || "
            "reproduction_root (zero slots = unattested)");
        (void)json_push_kv_str(&recipes, "possession_root",
            "domain zcl.zcode.corpus.possession.v1 over the scope's sorted "
            ".zvcs CAS blob hashes; REPORT ONLY — entries keep "
            "possession_root zero and DURABLE clear");
        (void)json_push_kv_str(&recipes, "replication_evidence_root",
            "domain zcl.zcode.corpus.replication.v1 over concat(shard "
            "roots in checkpoint order) || \"single-host-founding-v1\"");
        if (any_package) {
            (void)json_push_kv_str(&recipes, "package_release_root",
                "the def's package root, verified against the re-derived "
                "manifest root of the store's committed manifest "
                "(manifests/<root-hex>) — the EXACT published bytes");
            (void)json_push_kv_str(&recipes, "package_recipe_root",
                "the release envelope's recipe_root with the recipe wire "
                "present under recipes/ and re-rooted (fail closed on "
                "mismatch)");
            (void)json_push_kv_str(&recipes, "package_reproduction_root",
                "domain zcl.zcode.corpus.reproduction.v1 over release_root "
                "|| \"receipts-dual-confined-build\" || concat(sorted "
                "matching receipt ids) — vcs_package_reproduce_scan over "
                "<store>/zcode/receipts: >= 2 DISTINCT build receipts "
                "committing byte-identical output sets");
            (void)json_push_kv_str(&recipes, "package_quality_root",
                "domain zcl.zcode.corpus.quality.v1 over release_root || "
                "\"confined-build-test-receipt-green\" || concat(sorted "
                "receipt ids); the package QUALITY mapping is the same "
                "receipts evidence as REPRODUCIBLE, set iff reproduced");
            (void)json_push_kv_str(&recipes, "package_author_binding_root",
                "domain zcl.zcode.corpus.author_binding.v1 over the release "
                "envelope's publisher pubkey as 66 lowercase hex ASCII");
            (void)json_push_kv_str(&recipes, "package_possession_root",
                "domain zcl.zcode.corpus.possession.v1 over the sorted "
                "unique manifest chunk hashes; every chunk was re-read "
                "from the CAS and hash-verified (read-only equivalent of "
                "vcs_package_store_verify_possession require_pinned=false); "
                "REPORT ONLY — possession_root zero and DURABLE clear in "
                "the entry");
        }
        (void)json_push_kv(&evidence, "recipes", &recipes);
        json_free(&recipes);
    }
    {
        struct json_value founding;
        json_init(&founding);
        json_set_object(&founding);
        json_push_root(&founding, "family_policy_root", family_policy_root);
        json_push_root(&founding, "moderation_set_root",
                       moderation_set_root);
        json_push_root(&founding, "quality_root", quality_root);
        json_push_root(&founding, "replication_evidence_root",
                       replication_root);
        (void)json_push_kv_str(&founding, "reproduction_method",
                               repro_method);
        (void)json_push_kv_str(&founding, "panel_literal",
                               k_panel_literal);
        (void)json_push_kv_int(&founding, "admission_expiry_blocks",
            (int64_t)CORPUS_CENSUS_ADMISSION_EXPIRY_BLOCKS);
        (void)json_push_kv_int(&founding, "admission_expiry_mtp_seconds",
            (int64_t)CORPUS_CENSUS_ADMISSION_EXPIRY_MTP_SECONDS);
        (void)json_push_kv(&evidence, "founding", &founding);
        json_free(&founding);
    }
    {
        struct json_value scopes;
        json_init(&scopes);
        json_set_object(&scopes);
        for (size_t s = 0; s < scope_count; s++) {
            const struct scope_run *run = &runs[s];
            const struct scope_measure *m = &run->measure;
            struct json_value obj;
            json_init(&obj);
            json_set_object(&obj);
            (void)json_push_kv_str(&obj, "kind", kind_name(defs[s].kind));
            (void)json_push_kv_str(&obj, "spdx", defs[s].spdx);
            (void)json_push_kv_str(&obj, "license_file",
                                   m->license_path ? m->license_path : "");
            (void)json_push_kv_str(&obj, "recipe_file",
                                   m->recipe_path ? m->recipe_path : "");
            (void)json_push_kv_bool(&obj, "recipe_is_zcode_package",
                                    m->recipe_is_package);
            (void)json_push_kv_str(&obj, "scopes_def_line",
                                   defs[s].def_line);
            {
                struct json_value roots;
                json_init(&roots);
                json_set_object(&roots);
                json_push_root(&roots, "release_root", m->release_root);
                json_push_root(&roots, "license_root", m->license_root);
                json_push_root(&roots, "recipe_root", m->recipe_root);
                json_push_root(&roots, "dependency_closure_root",
                               m->dep_closure_root);
                json_push_root(&roots, "possession_root",
                               m->possession_root);
                json_push_root(&roots, "source_assignment_root",
                               run->assignment_root);
                json_push_root(&roots, "admission_root",
                               run->admission_root);
                json_push_root(&roots, "passport_root",
                               run->passport_root);
                json_push_root(&roots, "proof_root", run->proof_root);
                json_push_root(&roots, "quality_root", run->quality_root);
                json_push_root(&roots, "reproduction_root",
                               run->reproduction_root);
                (void)json_push_kv(&obj, "roots", &roots);
                json_free(&roots);
            }
            if (m->deps)
                (void)json_push_kv(&obj, "dependencies", m->deps);
            else {
                struct json_value empty;
                json_init(&empty);
                json_set_array(&empty);
                (void)json_push_kv(&obj, "dependencies", &empty);
                json_free(&empty);
            }
            {
                size_t hex_len = VCS_ZCODE_COMMONS_ADMISSION_WIRE_BYTES * 2u;
                char *hex = zcl_malloc(hex_len + 1u, "corpus.ev.hex");
                if (!hex)
                    LOG_ERR(CENSUS_LOG, "evidence hex alloc");
                zcl_hex_encode(run->assignment_wire,
                               run->assignment_wire_len, hex);
                (void)json_push_kv_str(&obj, "assignment_wire", hex);
                zcl_hex_encode(run->admission_wire,
                               run->admission_wire_len, hex);
                (void)json_push_kv_str(&obj, "admission_wire", hex);
                free(hex);
            }
            if (defs[s].is_package) {
                const struct package_ctx *pk = &run->pkg;
                struct json_value pobj;
                json_init(&pobj);
                json_set_object(&pobj);
                json_push_root(&pobj, "package_root", defs[s].package_root);
                json_push_root(&pobj, "release_id", pk->release_id);
                json_push_root(&pobj, "recipe_root",
                               pk->release.recipe_root);
                /* The store LABEL, never the resolved directory: this
                 * record is committed. */
                (void)json_push_kv_str(&pobj, "store", defs[s].store);
                (void)json_push_kv_str(&pobj, "release_name",
                                       pk->release.name);
                (void)json_push_kv_str(&pobj, "semver",
                                       pk->release.semver);
                (void)json_push_kv_str(&pobj, "publisher_pubkey",
                                       pk->publisher_hex);
                (void)json_push_kv_str(&pobj, "reproduction_method",
                                       k_repro_receipts);
                (void)json_push_kv_bool(&pobj, "reproduced",
                                        run->reproduced);
                struct json_value ids;
                json_init(&ids);
                json_set_array(&ids);
                for (size_t i = 0; i < run->receipt_ids.n; i++)
                    json_push_str(&ids, run->receipt_ids.v[i]);
                (void)json_push_kv(&pobj, "receipt_ids", &ids);
                json_free(&ids);
                (void)json_push_kv(&obj, "package", &pobj);
                json_free(&pobj);
            }
            (void)json_push_kv(&scopes, defs[s].name, &obj);
            json_free(&obj);
        }
        (void)json_push_kv(&evidence, "scopes", &scopes);
        json_free(&scopes);
    }
    (void)snprintf(name, sizeof(name), "evidence-%06llu.json",
                   (unsigned long long)args.sequence);
    if (!write_json_artifact(args.out, name, &evidence)) {
        json_free(&evidence);
        return 1;
    }
    json_free(&evidence);

    /* ── KPI report ───────────────────────────────────────────────── */
    struct json_value report;
    json_init(&report);
    json_set_object(&report);
    (void)json_push_kv_str(&report, "schema",
                           "zcl.c23_corpus_census.report.v1");
    (void)json_push_kv_bool(&report, "simulation_only", true);
    (void)json_push_kv_bool(&report, "not_owner_approved", true);
    (void)json_push_kv_int(&report, "sequence", (int64_t)args.sequence);
    (void)json_push_kv_str(&report, "signer_pubkey", pubkey_hex);
    json_push_root(&report, "checkpoint_root", checkpoint_root);
    json_push_root(&report, "rules_root", assembly.rules_root);
    json_push_root(&report, "family_policy_root", family_policy_root);
    json_push_root(&report, "moderation_set_root", moderation_set_root);
    (void)json_push_kv_bool(&report, "quality_attested",
                            args.quality_attested);
    (void)json_push_kv_str(&report, "reproduction_method", repro_method);
    {
        struct json_value cutoff;
        json_init(&cutoff);
        json_set_object(&cutoff);
        (void)json_push_kv_int(&cutoff, "height",
                               (int64_t)args.cutoff_height);
        (void)json_push_kv_int(&cutoff, "mtp", (int64_t)args.cutoff_mtp);
        (void)json_push_kv(&report, "cutoff", &cutoff);
        json_free(&cutoff);
    }
    {
        struct json_value repo;
        json_init(&repo);
        json_set_object(&repo);
        (void)json_push_kv_str(&repo, "head", head_hex);
        (void)json_push_kv_bool(&repo, "dirty", repo_dirty);
        (void)json_push_kv(&report, "repo", &repo);
        json_free(&repo);
    }
    {
        uint64_t admitted = 0;
        (void)zcl_u64_add(assembly.production_loc, assembly.test_loc,
                          &admitted);
        /* Downstream-used LOC: admitted package scopes whose exact package
         * root is pinned in another scope's dependency closure. Counted
         * once per depended-upon package. A scope with an absent or EMPTY
         * dependencies list can never contribute use — that trap is now
         * counted and reported explicitly instead of silently skipped. */
        uint64_t downstream = 0;
        uint64_t dep_pinned_scopes = 0;
        uint64_t dep_empty_scopes = 0;
        {
            bool *used = zcl_calloc(scope_count ? scope_count : 1,
                                    sizeof(*used), "corpus.kpi.used");
            if (!used)
                LOG_ERR(CENSUS_LOG, "downstream-used alloc");
            for (size_t t = 0; t < scope_count; t++) {
                const struct json_value *deps = runs[t].measure.deps;
                if (!deps || deps->type != JSON_ARR ||
                    deps->num_children == 0) {
                    dep_empty_scopes++;
                    continue;
                }
                dep_pinned_scopes++;
                for (size_t d = 0; d < deps->num_children; d++) {
                    const char *droot =
                        json_get_str(json_get(json_at(deps, d), "root"));
                    if (!droot || strlen(droot) != 64) continue;
                    for (size_t s = 0; s < scope_count; s++) {
                        if (s == t || used[s] || !defs[s].is_package ||
                            !(runs[s].result.entry.flags &
                              VCS_ZCODE_C23_ENTRY_COUNTED))
                            continue;
                        char hex[65];
                        root_hex(defs[s].package_root, hex);
                        if (strcmp(droot, hex) != 0) continue;
                        used[s] = true;
                        uint64_t loc = 0;
                        if (!zcl_u64_add(runs[s].measure.prod_loc,
                                         runs[s].measure.test_loc, &loc) ||
                            !zcl_u64_add(downstream, loc, &downstream))
                            LOG_ERR(CENSUS_LOG, "downstream-used overflow");
                    }
                }
            }
            free(used);
        }
        struct json_value kpis;
        json_init(&kpis);
        json_set_object(&kpis);
        (void)json_push_kv_int(&kpis, "admitted_production_loc",
                               (int64_t)assembly.production_loc);
        (void)json_push_kv_int(&kpis, "admitted_test_loc",
                               (int64_t)assembly.test_loc);
        (void)json_push_kv_int(&kpis, "admitted_total_loc",
                               (int64_t)admitted);
        (void)json_push_kv_int(&kpis, "durably_hosted_loc",
                               (int64_t)assembly.durable_loc);
        (void)json_push_kv_int(&kpis, "downstream_used_loc",
                               (int64_t)downstream);
        (void)json_push_kv_int(&kpis, "scopes_with_pinned_dependencies",
                               (int64_t)dep_pinned_scopes);
        (void)json_push_kv_int(&kpis, "scopes_without_pinned_dependencies",
                               (int64_t)dep_empty_scopes);
        (void)json_push_kv_int(&kpis, "physical_lines",
                               (int64_t)assembly.physical_lines);
        (void)json_push_kv_int(&kpis, "unique_semantic_units",
                               (int64_t)assembly.unique_semantic_units);
        (void)json_push_kv_int(&kpis, "packages_admitted",
                               (int64_t)(census_count -
                                         assembly.excluded_entries));
        (void)json_push_kv_int(&kpis, "packages_excluded",
                               (int64_t)assembly.excluded_entries);
        (void)json_push_kv(&report, "kpis", &kpis);
        json_free(&kpis);
    }
    /* Growth-rate KPI: raw deltas against the previous sequence's report.
     * Per-day rates are floor integers emitted only when at least one full
     * day elapsed between the two cutoffs (never fake precision). */
    if (args.previous_report) {
        uint8_t *prev_wire = NULL;
        size_t prev_len = 0;
        if (!store_file_read(args.previous_report, 4u * 1024u * 1024u,
                             &prev_wire, &prev_len) || !prev_wire)
            LOG_ERR(CENSUS_LOG, "previous report %s unreadable",
                    args.previous_report);
        struct json_value prev;
        json_init(&prev);
        bool ok = json_read(&prev, (const char *)prev_wire, prev_len);
        free(prev_wire);
        const struct json_value *pk =
            ok ? json_get(&prev, "kpis") : NULL;
        const struct json_value *pc =
            ok ? json_get(&prev, "cutoff") : NULL;
        int64_t prev_total = pk ? json_get_int(json_get(
            pk, "admitted_total_loc")) : -1;
        int64_t prev_pkgs = pk ? json_get_int(json_get(
            pk, "packages_admitted")) : -1;
        int64_t prev_mtp = pc ? json_get_int(json_get(pc, "mtp")) : -1;
        int64_t prev_seq = ok ? json_get_int(json_get(&prev, "sequence"))
                              : -1;
        if (!ok || prev_total < 0 || prev_pkgs < 0 || prev_mtp <= 0 ||
            prev_seq < 0) {
            json_free(&prev);
            LOG_ERR(CENSUS_LOG, "previous report %s lacks the KPI fields",
                    args.previous_report);
        }
        uint64_t this_total_u = 0;
        if (!zcl_u64_add(assembly.production_loc, assembly.test_loc,
                         &this_total_u))
            LOG_ERR(CENSUS_LOG, "delta total overflow");
        int64_t this_total = (int64_t)this_total_u;
        int64_t this_pkgs =
            (int64_t)(census_count - assembly.excluded_entries);
        int64_t days = (args.cutoff_mtp - prev_mtp) / 86400;
        struct json_value delta;
        json_init(&delta);
        json_set_object(&delta);
        (void)json_push_kv_int(&delta, "previous_sequence", prev_seq);
        (void)json_push_kv_int(&delta, "days_elapsed", days);
        (void)json_push_kv_int(&delta, "admitted_loc_added",
                               this_total - prev_total);
        (void)json_push_kv_int(&delta, "packages_added",
                               this_pkgs - prev_pkgs);
        if (days > 0) {
            (void)json_push_kv_int(&delta, "admitted_loc_per_day",
                (this_total - prev_total) / days);
            (void)json_push_kv_int(&delta, "packages_per_day_x100",
                (this_pkgs - prev_pkgs) * 100 / days);
        }
        (void)json_push_kv(&report, "delta_vs_previous", &delta);
        json_free(&delta);
        json_free(&prev);
    }
    {
        struct json_value excluded, file, entry;
        json_init(&excluded);
        json_set_object(&excluded);
        json_init(&file);
        json_set_object(&file);
        for (size_t r = 0; r < VCS_ZCODE_CENSUS_FILE_REASON_COUNT; r++) {
            uint64_t sum = 0;
            for (size_t s = 0; s < scope_count; s++)
                if (!zcl_u64_add(sum,
                                 runs[s].result.file_excluded_loc[r], &sum))
                    LOG_ERR(CENSUS_LOG, "file exclusion sum overflow");
            (void)json_push_kv_int(&file,
                vcs_zcode_corpus_census_file_reason_string(
                    (enum vcs_zcode_corpus_census_file_reason)r),
                (int64_t)sum);
        }
        json_init(&entry);
        json_set_object(&entry);
        /* entry-level: driver-side would-be LOC per primary reason.
         * Accumulate in a fixed table and emit each reason EXACTLY once:
         * json_push_kv is append-only and json_get returns the first
         * match, so the former read-modify-push loop emitted ambiguous
         * duplicate keys carrying partial sums. Slots 0..11 are the
         * VCS_ZCODE_C23_EXCLUDE_* bits; slot 12 is "unknown". */
        {
            uint64_t sums[13] = {0};
            for (size_t s = 0; s < scope_count; s++) {
                uint32_t mask = runs[s].result.scope_exclusion_mask;
                if (!mask) continue;
                uint32_t bit =
                    vcs_zcode_corpus_census_primary_exclusion(mask);
                size_t slot = 12;
                if (bit && !(bit & ~VCS_ZCODE_C23_EXCLUSION_MASK)) {
                    slot = 0;
                    while ((bit & 1u) == 0) {
                        bit >>= 1;
                        slot++;
                    }
                }
                uint64_t would = 0;
                if (!zcl_u64_add(runs[s].measure.prod_loc,
                                 runs[s].measure.test_loc, &would) ||
                    !zcl_u64_add(sums[slot], would, &sums[slot]))
                    LOG_ERR(CENSUS_LOG, "would-be loc overflow");
            }
            for (size_t i = 0; i < 13; i++) {
                if (!sums[i]) continue;
                const char *name = i < 12
                    ? exclusion_name((uint32_t)(UINT64_C(1) << i))
                    : "unknown";
                (void)json_push_kv_int(&entry, name, (int64_t)sums[i]);
            }
        }
        (void)json_push_kv(&excluded, "file_level_semantic_loc", &file);
        (void)json_push_kv(&excluded, "entry_level_would_be_loc", &entry);
        json_free(&file);
        json_free(&entry);
        (void)json_push_kv(&report, "excluded_loc_by_reason", &excluded);
        json_free(&excluded);
    }
    {
        struct json_value scopes;
        json_init(&scopes);
        json_set_array(&scopes);
        for (size_t s = 0; s < scope_count; s++) {
            const struct scope_run *run = &runs[s];
            const struct scope_measure *m = &run->measure;
            struct json_value obj;
            json_init(&obj);
            json_set_object(&obj);
            (void)json_push_kv_str(&obj, "name", defs[s].name);
            (void)json_push_kv_str(&obj, "kind", kind_name(defs[s].kind));
            (void)json_push_kv_str(&obj, "spdx", defs[s].spdx);
            (void)json_push_kv_bool(&obj, "in_census", run->in_census);
            (void)json_push_kv_bool(&obj, "counted",
                (run->result.entry.flags & VCS_ZCODE_C23_ENTRY_COUNTED) != 0);
            (void)json_push_kv_int(&obj, "production_loc_would_be",
                                   (int64_t)m->prod_loc);
            (void)json_push_kv_int(&obj, "test_loc_would_be",
                                   (int64_t)m->test_loc);
            (void)json_push_kv_int(&obj, "physical_lines",
                (int64_t)run->result.entry.physical_lines);
            (void)json_push_kv_int(&obj, "unique_semantic_units",
                (int64_t)run->result.entry.unique_semantic_units);
            (void)json_push_kv_int(&obj, "units_total",
                                   (int64_t)run->result.units_total);
            (void)json_push_kv_int(&obj, "units_already_claimed",
                (int64_t)run->result.units_already_claimed);
            (void)json_push_kv_int(&obj, "files_claimed",
                                   (int64_t)files[s].n);
            (void)json_push_kv_int(&obj, "files_scanned",
                (int64_t)run->result.scanned_files);
            (void)json_push_kv_int(&obj, "files_excluded",
                (int64_t)run->result.excluded_files);
            {
                char mask_hex[19];
                (void)snprintf(mask_hex, sizeof(mask_hex), "0x%016" PRIx64,
                               run->evidence_mask);
                (void)json_push_kv_str(&obj, "evidence_mask", mask_hex);
            }
            {
                struct json_value missing;
                json_init(&missing);
                json_set_array(&missing);
                for (size_t b = 0; b < ARRAY_LEN(k_evidence_bits); b++) {
                    if (!(run->evidence_mask & k_evidence_bits[b].bit))
                        json_push_str(&missing, k_evidence_bits[b].name);
                }
                (void)json_push_kv(&obj, "missing_evidence", &missing);
                json_free(&missing);
            }
            (void)json_push_kv_int(&obj, "exclusion_mask",
                (int64_t)run->result.scope_exclusion_mask);
            (void)json_push_kv_str(&obj, "primary_exclusion",
                exclusion_name(vcs_zcode_corpus_census_primary_exclusion(
                    run->result.scope_exclusion_mask)));
            (void)json_push_kv_bool(&obj, "possession_suppressed",
                                    run->result.possession_suppressed);
            (void)json_push_kv_bool(&obj, "reproduced", run->reproduced);
            if (defs[s].is_package) {
                struct json_value pobj;
                json_init(&pobj);
                json_set_object(&pobj);
                /* The store LABEL, never the resolved directory: this
                 * record is committed. */
                (void)json_push_kv_str(&pobj, "store", defs[s].store);
                json_push_root(&pobj, "release_id", run->pkg.release_id);
                (void)json_push_kv_str(&pobj, "publisher_pubkey",
                                       run->pkg.publisher_hex);
                (void)json_push_kv_str(&pobj, "reproduction_method",
                                       k_repro_receipts);
                struct json_value ids;
                json_init(&ids);
                json_set_array(&ids);
                for (size_t i = 0; i < run->receipt_ids.n; i++)
                    json_push_str(&ids, run->receipt_ids.v[i]);
                (void)json_push_kv(&pobj, "receipt_ids", &ids);
                json_free(&ids);
                (void)json_push_kv(&obj, "package", &pobj);
                json_free(&pobj);
            }
            {
                struct json_value roots;
                json_init(&roots);
                json_set_object(&roots);
                json_push_root(&roots, "semantic_lineage_root",
                               run->result.entry.semantic_lineage_root);
                json_push_root(&roots, "release_root", m->release_root);
                json_push_root(&roots, "passport_root",
                               run->passport_root);
                json_push_root(&roots, "proof_root", run->proof_root);
                json_push_root(&roots, "source_assignment_root",
                               run->assignment_root);
                json_push_root(&roots, "admission_root",
                               run->admission_root);
                json_push_root(&roots, "possession_root_report_only",
                               m->possession_root);
                (void)json_push_kv(&obj, "roots", &roots);
                json_free(&roots);
            }
            (void)json_push_back(&scopes, &obj);
            json_free(&obj);
        }
        (void)json_push_kv(&report, "scopes", &scopes);
        json_free(&scopes);
    }
    {
        struct json_value shards;
        json_init(&shards);
        json_set_array(&shards);
        for (size_t i = 0; i < shard_count; i++) {
            struct json_value obj;
            json_init(&obj);
            json_set_object(&obj);
            (void)json_push_kv_int(&obj, "index", (int64_t)i);
            json_push_root(&obj, "shard_root", shard_roots[i]);
            json_push_root(&obj, "first_lineage_root",
                           bindings[i].first_lineage_root);
            json_push_root(&obj, "last_lineage_root",
                           bindings[i].last_lineage_root);
            (void)json_push_kv_int(&obj, "entry_count",
                                   (int64_t)bindings[i].entry_count);
            (void)json_push_kv_int(&obj, "production_loc",
                                   (int64_t)bindings[i].production_loc);
            (void)json_push_kv_int(&obj, "test_loc",
                                   (int64_t)bindings[i].test_loc);
            (void)json_push_kv_int(&obj, "durable_loc",
                                   (int64_t)bindings[i].durable_loc);
            (void)json_push_kv_int(&obj, "physical_lines",
                                   (int64_t)bindings[i].physical_lines);
            (void)json_push_kv_int(&obj, "unique_semantic_units",
                                (int64_t)bindings[i].unique_semantic_units);
            (void)json_push_kv_int(&obj, "wire_bytes",
                                   (int64_t)shard_wire_lens[i]);
            (void)json_push_back(&shards, &obj);
            json_free(&obj);
        }
        (void)json_push_kv(&report, "shards", &shards);
        json_free(&shards);
    }
    {
        struct json_value disclosures;
        json_init(&disclosures);
        json_set_array(&disclosures);
        json_push_str(&disclosures,
            "founding self-screen admission: every scope's admission is a "
            "self-signed SELF_SCREENED commons_admission.v1 (tier 0); 0 "
            "independent operator groups participated");
        if (any_repo)
            json_push_str(&disclosures,
                "reproduction binding is dual-worktree source rederivation "
                "(git worktree at HEAD, byte-identical release roots), NOT "
                "independent build reproduction");
        json_push_str(&disclosures,
            "quality bit reflects the operator's --quality-attested flag "
            "(make lint pass state at census time), not an independent "
            "review");
        json_push_str(&disclosures,
            "durable hosting: none yet; possession_root is recorded in "
            "this report only — every entry carries possession_root=0 and "
            "no DURABLE flag (nothing is 5-ACK/3-operator-group durable)");
        json_push_str(&disclosures,
            "simulation-only, not owner-approved; no live ZC23 token "
            "economics");
        json_push_str(&disclosures,
            "source_kind is DECLARED provenance: no per-file authorship "
            "marker exists in-tree, so all scopes are declared human "
            "(pre-existing node code); an overstated kind would be "
            "detectable only by out-of-band review");
        json_push_str(&disclosures,
            "vendor/ and core/ are out of corpus by design (third-party "
            "material and the byte-sealed consensus core)");
        if (any_package) {
            json_push_str(&disclosures,
                "package scopes: reproduction is the STRONG binding (>= 2 "
                "distinct byte-identical confined build receipts), but the "
                "builds ran on ONE host — independent-operator reproduction "
                "is future work");
            json_push_str(&disclosures,
                "package scopes: the QUALITY bit maps to 'confined "
                "build+test receipt green' (the same receipts evidence as "
                "REPRODUCIBLE), not a human quality review");
            json_push_str(&disclosures,
                "package scopes: the census reads the package store "
                "read-only (no store open, recovery sweep, GC, or "
                "access-count mutation); complete possession is the "
                "chunk-hash-verified full read, DURABLE stays clear");
        }
        (void)json_push_kv(&report, "disclosures", &disclosures);
        json_free(&disclosures);
    }
    (void)snprintf(name, sizeof(name), "report-%06llu.json",
                   (unsigned long long)args.sequence);
    if (!report_keys_unique(&report)) {
        LOG_ERROR(CENSUS_LOG, "report %s contains duplicate JSON keys",
                  name);
        json_free(&report);
        return 1;
    }
    if (!write_json_artifact(args.out, name, &report)) {
        json_free(&report);
        return 1;
    }
    json_free(&report);

    /* ── stdout KPI summary ───────────────────────────────────────── */
    {
        uint64_t admitted = 0;
        (void)zcl_u64_add(assembly.production_loc, assembly.test_loc,
                          &admitted);
        char root_text[65];
        root_hex(checkpoint_root, root_text);
        printf("corpus-census: sequence=%llu scopes=%zu census_entries=%zu "
               "shards=%zu\n",
               (unsigned long long)args.sequence, scope_count,
               census_count, shard_count);
        printf("  admitted_production_loc=%llu admitted_test_loc=%llu "
               "admitted_total_loc=%llu\n",
               (unsigned long long)assembly.production_loc,
               (unsigned long long)assembly.test_loc,
               (unsigned long long)admitted);
        printf("  durably_hosted_loc=%llu physical_lines=%llu "
               "unique_semantic_units=%llu\n",
               (unsigned long long)assembly.durable_loc,
               (unsigned long long)assembly.physical_lines,
               (unsigned long long)assembly.unique_semantic_units);
        printf("  packages_admitted=%llu packages_excluded=%llu\n",
               (unsigned long long)(census_count -
                                    assembly.excluded_entries),
               (unsigned long long)assembly.excluded_entries);
        printf("  signer_pubkey=%s\n  checkpoint_root=%s\n", pubkey_hex,
               root_text);
        printf("  artifacts: %s/{%s,shard-%06llu-*.hex,evidence-%06llu.json,"
               "report-%06llu.json}\n",
               args.out, checkpoint_file,
               (unsigned long long)args.sequence,
               (unsigned long long)args.sequence,
               (unsigned long long)args.sequence);
    }

    /* ── cleanup ──────────────────────────────────────────────────── */
    memory_cleanse(seed, sizeof(seed));
    for (size_t i = 0; i < shard_count; i++) free(shard_wires[i]);
    free(shard_wires);
    free(shard_wire_lens);
    free(shard_roots);
    free(bindings);
    free(checkpoint_wire);
    vcs_zcode_corpus_census_assembly_free(&assembly);
    free(kept);
    for (size_t s = 0; s < scope_count; s++) {
        scope_measure_free(&runs[s].measure);
        package_ctx_free(&runs[s].pkg);
        vec_free(&runs[s].receipt_ids);
        scope_files_free(&files[s]);
        scope_def_free(&defs[s]);
    }
    free(runs);
    free(files);
    free(defs);
    return 0;
}
