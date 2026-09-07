/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * corpus-census private header: the shared struct definitions, constants,
 * and cross-file function declarations that tools/corpus_census.c and its
 * sibling files (corpus_census_defs.c, corpus_census_scopes.c,
 * corpus_census_measure.c, corpus_census_package.c, corpus_census_args.c,
 * corpus_census_report.c) need to call into one another. Nothing here is
 * part of any other tool's or module's public surface: this header exists
 * only to let one driver's own translation units share one set of types.
 */

#ifndef ZCL_TOOLS_CORPUS_CENSUS_PRIV_H
#define ZCL_TOOLS_CORPUS_CENSUS_PRIV_H

#include "base/bytes.h"
#include "base/hex.h"
#include "json/json.h"
#include "vcs/package_manifest.h"
#include "vcs/package_release.h"
#include "vcs/zcode_c23_corpus.h"
#include "vcs/zcode_c23_corpus_census.h"
#include "vcs/zcode_family_admission.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

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

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

/* Evidence-root domain literals and disclosed method/author strings,
 * defined once in tools/corpus_census.c and shared by every sibling. */
extern const char k_domain_release[];
extern const char k_domain_license[];
extern const char k_domain_author[];
extern const char k_domain_assignment_evidence[];
extern const char k_domain_dep_closure[];
extern const char k_domain_moderation[];
extern const char k_domain_panel[];
extern const char k_domain_admission_evidence[];
extern const char k_domain_passport[];
extern const char k_domain_recipe[];
extern const char k_domain_quality[];
extern const char k_domain_reproduction[];
extern const char k_domain_proof[];
extern const char k_domain_possession[];
extern const char k_domain_replication[];

extern const char k_author_human[];
extern const char k_author_ai[];
extern const char k_panel_literal[];
extern const char k_repro_worktree[];
extern const char k_repro_fallback[];
extern const char k_repro_receipts[];
extern const char k_quality_receipts[];
extern const char k_replication_literal[];

/* ── small growable containers (tools/corpus_census.c) ────────────── */

struct str_vec {
    char **v;
    size_t n, cap;
};

void vec_free(struct str_vec *vec);
bool vec_push_len(struct str_vec *vec, const char *s, size_t len);
bool vec_push(struct str_vec *vec, const char *s);
int cmp_strp(const void *a, const void *b);
int cmp_bytes32(const void *a, const void *b);

struct buf {
    uint8_t *p;
    size_t len, cap;
};

void buf_free(struct buf *b);
bool buf_put(struct buf *b, const void *data, size_t len);
bool buf_put_u64le(struct buf *b, uint64_t v);

/* ── roots, hex, charset helpers (tools/corpus_census.c) ──────────── */

bool evidence_root(const char *domain, const uint8_t *wire, size_t wire_len,
                   uint8_t out[32]);
void root_hex(const uint8_t root[32], char out[65]);
void json_push_root(struct json_value *obj, const char *key,
                    const uint8_t root[32]);
void json_push_str(struct json_value *arr, const char *s);
bool shell_safe(const char *s);
bool counted_extension(const char *path);
char *dup_str(const char *s, const char *label);

/* ── scope definition file (corpus_census_defs.c) ─────────────────── */

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

void scope_def_free(struct scope_def *def);
bool def_load(const char *path, struct scope_def **defs_out,
             size_t *count_out, uint8_t def_sha3[32]);

/* ── git enumeration and claim resolution (corpus_census_scopes.c) ── */

/* Per-scope resolved claim: sorted paths plus parallel via_tests flags. */
struct scope_files {
    char **paths;
    uint8_t *via_tests;
    size_t n, cap;
};

void scope_files_free(struct scope_files *sf);
bool scope_files_push(struct scope_files *sf, const char *path,
                      bool via_tests);
bool claims_resolve(const char *root, const struct scope_def *defs,
                    size_t scope_count, struct scope_files **out);
bool file_load(const char *root, const char *relpath, uint8_t **bytes_out,
               size_t *len_out, uint64_t *declared_out);

/* ── package-scope store reads (corpus_census_package.c) ──────────── */

struct package_ctx {
    char *zcode_dir;       /* owned: <store>/zcode */
    struct vcs_package_manifest manifest;
    struct vcs_package_release release;
    uint8_t release_id[32];
    char publisher_hex[VCS_PACKAGE_RELEASE_PUBKEY_BYTES * 2u + 1u];
};

void package_ctx_free(struct package_ctx *ctx);
bool store_file_read(const char *path, size_t max_bytes, uint8_t **out,
                     size_t *out_len);
bool package_file_load(const struct package_ctx *ctx, const char *path,
                       uint8_t **bytes_out, size_t *len_out,
                       uint64_t *declared_out);
bool package_ctx_load(struct package_ctx *ctx, const struct scope_def *def,
                      const char *store_root);
bool package_possession_root(const struct package_ctx *ctx, uint8_t out[32]);
bool package_scope_enumerate(const struct package_ctx *ctx,
                             struct scope_files *sf);

/* ── per-scope measurement (corpus_census_measure.c) ──────────────── */

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

void scope_measure_free(struct scope_measure *m);
bool dep_closure_bind(struct scope_measure *m, const uint8_t *bytes,
                      size_t blen, const char *scope_name,
                      const char *meta_path);
bool scope_release_wire(const char *root, const struct scope_files *sf,
                        struct buf *wire, struct scope_measure *measure,
                        const char *scope_name, const struct package_ctx *pkg);
bool scope_license_bind(const char *root, const struct scope_def *def,
                        struct scope_measure *m, const struct package_ctx *pkg);
bool scope_recipe_bind(const char *root, const struct scope_def *def,
                       struct scope_measure *m, const struct package_ctx *pkg);
bool package_recipe_bind(const struct scope_def *def, struct scope_measure *m,
                         const struct package_ctx *pkg);
bool quality_root_compute(const char *root, uint8_t out[32]);
bool rederive_release_roots(const char *root, const struct scope_def *defs,
                            size_t scope_count,
                            const uint8_t (*expected)[32], bool *matched);
bool worktree_rederive(const char *repo, const struct scope_def *defs,
                       size_t scope_count, const uint8_t (*expected)[32],
                       bool *matched, bool *worktree_used);

/* ── argument parsing / signer seed (corpus_census_args.c) ────────── */

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

void usage(FILE *stream);
bool args_parse(int argc, char **argv, struct census_args *args);
bool seed_load_or_create(const char *path, const char *repo_real,
                         uint8_t seed[32], bool *created_out);

/* ── per-scope runtime state (tools/corpus_census.c) ──────────────── */

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

/* ── the whole run's state, threaded through main()'s named stages
 * (tools/corpus_census.c) and read by the report builder
 * (corpus_census_report.c) ───────────────────────────────────────── */

struct census_ctx {
    struct census_args args;
    char repo_real[4096];
    /* Backing storage for args.previous_report when it is discovered (not
     * given explicitly): args.previous_report then points into this
     * buffer, which must outlive the discovery stage. */
    char discovered_report[4400];
    uint8_t seed[32];
    uint8_t signer_pubkey[32];
    char pubkey_hex[65];
    bool seed_created;

    struct scope_def *defs;
    size_t scope_count;
    uint8_t def_sha3[32];
    bool any_package;
    bool any_repo;

    uint8_t family_policy_root[32];
    uint8_t moderation_set_root[32];

    struct scope_files *files;
    struct scope_run *runs;
    uint8_t quality_root[32];

    /* REPRODUCIBLE bit: per-scope match flags, live between the
     * reproduction stage and the per-scope evidence/census stage. */
    bool *repro_matched;
    bool worktree_used;
    const char *repro_method;

    struct vcs_zcode_corpus_census_assembly assembly;
    size_t census_count;
    struct vcs_zcode_corpus_census_scope_result *kept;

    size_t shard_count;
    struct vcs_zcode_c23_checkpoint_shard_v1 *bindings;
    uint8_t **shard_wires;
    size_t *shard_wire_lens;
    uint8_t (*shard_roots)[32];
    uint8_t replication_root[32];

    struct vcs_zcode_c23_corpus_checkpoint_v1 checkpoint;
    uint8_t checkpoint_root[32];
    uint8_t *checkpoint_wire;
    size_t checkpoint_wire_len;
    char checkpoint_file[160];

    char head_hex[128];
    bool repo_dirty;
};

/* ── artifact writers (tools/corpus_census.c) ─────────────────────── */

bool write_text_atomic(const char *dir, const char *name,
                       const char *content, size_t len);
bool write_hex_artifact(const char *dir, const char *name,
                        const uint8_t *wire, size_t wire_len);
bool write_json_artifact(const char *dir, const char *name,
                         struct json_value *doc);

/* ── report builder (corpus_census_report.c) ──────────────────────── */

bool census_build_evidence_bundle(const struct census_ctx *ctx,
                                  struct json_value *evidence);
bool census_build_kpi_report(const struct census_ctx *ctx,
                             struct json_value *report);

#endif /* ZCL_TOOLS_CORPUS_CENSUS_PRIV_H */
