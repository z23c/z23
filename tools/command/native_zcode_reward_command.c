/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for the `zcode reward` read pair (slice 7: bounded
 * deterministic contribution scoring + the reward eligibility gate list;
 * the queue/plan/commit/receipt settlement leaves are slice 8 and live in
 * native_zcode_reward_settle_command.c over contexts/commons/modules/vcs/package_reward.*):
 *
 *   zcode reward score     compute the deterministic score breakdown for
 *                          one release root: category, semantic lines
 *                          counted/excluded with reasons, the lineage diff
 *                          (moved/renamed/re-added/duplicated code scores
 *                          zero), the per-release caps, and the total
 *   zcode reward eligible  evaluate the full eight-gate eligibility list
 *                          for one release root (package root verifies,
 *                          release signature, license, parent lineage,
 *                          gcc build, clang build, tests, and the slice-6
 *                          2-of-N approved-verifier quorum); eligible is
 *                          true only when EVERY gate passes and every
 *                          failed gate is named
 *
 * Truth discipline (unchanged from slices 3-6): the CAS bytes under
 * <datadir>/zcode are the only package truth; the index is rebuilt at
 * call time. Score inputs come from the persisted manifest/chunk bytes
 * only — same bytes, same score. These commands are read-only; nothing
 * here accrues, queues, or settles a reward. */

#include "base/hex.h"
#include "command/native_command.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "vcs/package_attest.h"
#include "vcs/package_eligible.h"
#include "vcs/package_index.h"
#include "vcs/package_manifest.h"
#include "vcs/package_publish.h" /* VCS_PACKAGE_PUBLISH_LICENSE_PATH */
#include "vcs/package_release.h"
#include "vcs/package_reproduce.h"
#include "vcs/package_score.h"
#include "vcs/package_verify_policy.h"

#include <dirent.h>
#include <stdio.h>
#include <string.h>

/* Bound on attestation files scanned per eligibility call (the slice-6
 * verify command's bound). */
#define ZR_VERIFY_MAX_SCAN 256u

/* ── small input/hex/file helpers (the zcode.command pattern) ───────── */

static const char *zr_input_str(const struct json_value *input,
                                const char *key)
{
    const struct json_value *v = json_get(input, key);
    return v ? json_get_str(v) : NULL;
}

static const char *zr_datadir(const struct zcl_command_request *request)
{
    const char *dd = zr_input_str(request->input, "datadir");
    if (dd && dd[0])
        return dd;
    dd = zcl_native_command_datadir();
    return (dd && dd[0]) ? dd : NULL;
}

/* Read one bounded file fully (allocates *out; caller frees). False when
 * missing, unreadable, empty, or over cap. */
static bool zr_read_object(const char *path, size_t cap, uint8_t **out,
                           size_t *out_len)
{
    *out = NULL;
    *out_len = 0;
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    uint8_t *buf = zcl_malloc(cap, "zr_read_object");
    if (!buf) {
        fclose(f);
        return false;
    }
    size_t len = fread(buf, 1, cap, f);
    bool ok = !ferror(f) && feof(f) && len > 0;
    fclose(f);
    if (!ok) {
        free(buf);
        return false;
    }
    *out = buf;
    *out_len = len;
    return true;
}

/* ── shared release+manifest load ───────────────────────────────────── */

struct zr_target {
    char zcode_dir[4400];
    char root_hex[65];
    struct vcs_package_release release;
    char release_id_hex[65];
    uint8_t release_id[32];
    struct vcs_package_manifest manifest;
    bool manifest_loaded;
};

static void zr_target_free(struct zr_target *t)
{
    if (t->manifest_loaded)
        vcs_package_manifest_free(&t->manifest);
    memset(t, 0, sizeof(*t));
}

/* Resolve datadir + root, build the index, find the release, and read
 * the persisted envelope and manifest wires. Returns false with the
 * error body set on any hard failure. */
static bool zr_target_load(const struct zcl_command_request *request,
                           struct zcl_command_reply *reply,
                           struct zr_target *t, const char *command)
{
    memset(t, 0, sizeof(*t));
    const char *datadir = zr_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given (input datadir or --datadir)",
                               command);
        return false;
    }
    const char *root_hex = zr_input_str(request->input, "root");
    uint8_t root[32];
    size_t root_len = 0;
    if (!root_hex || !zcl_hex_decode_n(root_hex, root, 32, &root_len) ||
        root_len != 32) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_ROOT",
                               "normalize", false, false,
                               "root must be a 64-hex package root",
                               root_hex ? root_hex : "");
        return false;
    }
    snprintf(t->root_hex, sizeof(t->root_hex), "%s", root_hex);
    int n = snprintf(t->zcode_dir, sizeof(t->zcode_dir), "%s/zcode", datadir);
    if (n < 0 || (size_t)n >= sizeof(t->zcode_dir)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "DATADIR_TOO_LONG",
                               "normalize", false, false,
                               "datadir path too long", datadir);
        return false;
    }
    struct vcs_package_index *index = vcs_package_index_build(t->zcode_dir);
    if (!index) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "INDEX_BUILD",
                               "execute", false, false,
                               "the package index could not be built",
                               t->zcode_dir);
        return false;
    }
    const struct vcs_package_index_entry *e =
        vcs_package_index_find_root(index, root);
    if (!e) {
        vcs_package_index_free(index);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "UNKNOWN_PACKAGE",
                               "execute", false, false,
                               "no published release names this package root",
                               root_hex);
        return false;
    }
    char path[4400];
    snprintf(path, sizeof(path), "%s/releases/%s", t->zcode_dir,
             e->release_id_hex);
    snprintf(t->release_id_hex, sizeof(t->release_id_hex), "%s",
             e->release_id_hex);
    vcs_package_index_free(index);

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (!zr_read_object(path, VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES, &wire,
                        &wire_len) ||
        vcs_package_release_parse(wire, wire_len, &t->release) !=
            VCS_PACKAGE_RELEASE_OK) {
        free(wire);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "RELEASE_READ",
                               "execute", false, false,
                               "the persisted release envelope is unreadable",
                               t->release_id_hex);
        return false;
    }
    free(wire);
    (void)vcs_package_release_id(&t->release, t->release_id);

    snprintf(path, sizeof(path), "%s/manifests/%s", t->zcode_dir,
             t->root_hex);
    wire = NULL;
    wire_len = 0;
    if (!zr_read_object(path, VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES, &wire,
                        &wire_len) ||
        !vcs_package_manifest_parse(wire, wire_len, &t->manifest)) {
        free(wire);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "MANIFEST_READ",
                               "execute", false, false,
                               "the persisted manifest is unreadable",
                               t->root_hex);
        return false;
    }
    free(wire);
    t->manifest_loaded = true;
    return true;
}

/* Read one manifest file's full content from the CAS, verifying every
 * chunk hash. Allocates *bytes_out (caller frees; NULL for a zero-byte
 * file). Never reads a file over VCS_SCORE_MAX_FILE_BYTES: *oversize_out
 * is set and no bytes are returned. */
static bool zr_read_file_content(const char *zcode_dir,
                                 const struct vcs_package_file *file,
                                 uint8_t **bytes_out, size_t *len_out,
                                 bool *oversize_out)
{
    *bytes_out = NULL;
    *len_out = 0;
    *oversize_out = false;
    if (file->size > VCS_SCORE_MAX_FILE_BYTES) {
        *oversize_out = true;
        return true;
    }
    if (file->size == 0)
        return true;
    uint8_t *buf = zcl_malloc((size_t)file->size, "zr_file_content");
    if (!buf)
        return false;
    size_t off = 0;
    for (uint32_t c = 0; c < file->chunk_count; c++) {
        char hex[65];
        zcl_hex_encode(file->chunk_hashes + 32u * c, 32, hex);
        char path[4400];
        int n = snprintf(path, sizeof(path), "%s/cas/sha3/%.2s/%s",
                         zcode_dir, hex, hex);
        if (n < 0 || (size_t)n >= sizeof(path)) {
            free(buf);
            return false;
        }
        uint8_t *chunk = NULL;
        size_t chunk_len = 0;
        if (!zr_read_object(path, VCS_PACKAGE_CHUNK_BYTES, &chunk,
                            &chunk_len) ||
            off + chunk_len > (size_t)file->size ||
            !vcs_package_verify_chunk(file, c, chunk, chunk_len)) {
            free(chunk);
            free(buf);
            return false;
        }
        memcpy(buf + off, chunk, chunk_len);
        off += chunk_len;
        free(chunk);
    }
    if (off != (size_t)file->size) {
        free(buf);
        return false;
    }
    *bytes_out = buf;
    *len_out = off;
    return true;
}

/* ── lineage walk (shared) ──────────────────────────────────────────── */

/* Walk the ancestor chain from `release`, absorbing every scorable
 * ancestor file's units into `lineage` (unfinalized on return; the
 * caller finalizes). *complete_out is false when a link was missing or
 * unreadable (the walk still scored the readable prefix) or the depth
 * cap stopped the walk. *ancestors_out counts releases walked. Returns
 * false only on allocation failure. */
static bool zr_lineage_absorb(const struct zr_target *t,
                              const struct vcs_package_release *release,
                              struct vcs_score_set *lineage,
                              uint32_t *ancestors_out, bool *complete_out)
{
    *ancestors_out = 0;
    *complete_out = true;
    struct vcs_package_release cur = *release;
    while (cur.has_parent) {
        if (*ancestors_out >= VCS_SCORE_MAX_LINEAGE_DEPTH) {
            *complete_out = false;
            break;
        }
        char parent_hex[65];
        zcl_hex_encode(cur.parent_root, 32, parent_hex);
        char path[4400];
        snprintf(path, sizeof(path), "%s/releases/%s", t->zcode_dir,
                 parent_hex);
        uint8_t *wire = NULL;
        size_t wire_len = 0;
        struct vcs_package_release parent;
        if (!zr_read_object(path, VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES, &wire,
                            &wire_len) ||
            vcs_package_release_parse(wire, wire_len, &parent) !=
                VCS_PACKAGE_RELEASE_OK) {
            free(wire);
            *complete_out = false;
            break;
        }
        free(wire);
        char proot_hex[65];
        zcl_hex_encode(parent.package_root, 32, proot_hex);
        snprintf(path, sizeof(path), "%s/manifests/%s", t->zcode_dir,
                 proot_hex);
        wire = NULL;
        wire_len = 0;
        struct vcs_package_manifest pm;
        if (!zr_read_object(path, VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES, &wire,
                            &wire_len) ||
            !vcs_package_manifest_parse(wire, wire_len, &pm)) {
            free(wire);
            *complete_out = false;
            break;
        }
        free(wire);
        bool ok = true;
        for (size_t i = 0; i < pm.count && ok; i++) {
            const struct vcs_package_file *f = &pm.files[i];
            uint8_t *bytes = NULL;
            size_t len = 0;
            bool oversize = false;
            if (!zr_read_file_content(t->zcode_dir, f, &bytes, &len,
                                      &oversize)) {
                vcs_package_manifest_free(&pm);
                *complete_out = false;
                return true; /* unreadable ancestor content: partial walk */
            }
            if (!oversize)
                ok = vcs_score_set_absorb_file(lineage, f->path, bytes, len);
            free(bytes);
        }
        vcs_package_manifest_free(&pm);
        if (!ok)
            return false;
        (*ancestors_out)++;
        cur = parent;
    }
    return true;
}

/* ── zcode reward score ─────────────────────────────────────────────── */

void zcl_native_handle_zcode_reward_score(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    struct zr_target t;
    if (!zr_target_load(request, reply, &t, "zcode.reward.score"))
        return;

    /* Read every manifest file's content (files over the per-file scoring
     * cap stay unread and are excluded by declared size). */
    struct vcs_score_input_file *inputs = NULL;
    uint8_t **contents = NULL;
    bool ok = true;
    if (t.manifest.count > 0) {
        inputs = zcl_calloc(t.manifest.count, sizeof(*inputs),
                            "zr_score_inputs");
        contents = zcl_calloc(t.manifest.count, sizeof(*contents),
                              "zr_score_contents");
        if (!inputs || !contents) {
            free(inputs);
            free(contents);
            zr_target_free(&t);
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INTERNAL, "ALLOC",
                                   "execute", false, false,
                                   "score input buffers", t.root_hex);
            return;
        }
    }
    for (size_t i = 0; i < t.manifest.count && ok; i++) {
        const struct vcs_package_file *f = &t.manifest.files[i];
        inputs[i].path = f->path;
        inputs[i].declared_size = f->size;
        size_t len = 0;
        bool oversize = false;
        if (!zr_read_file_content(t.zcode_dir, f, &contents[i], &len,
                                  &oversize)) {
            ok = false;
            break;
        }
        if (!oversize) {
            inputs[i].bytes = contents[i];
            inputs[i].len = len;
        }
    }
    if (!ok) {
        for (size_t i = 0; i < t.manifest.count; i++)
            free(contents ? contents[i] : NULL);
        free(contents);
        free(inputs);
        zr_target_free(&t);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CHUNK_READ",
                               "execute", false, false,
                               "a committed chunk is missing or does not "
                               "verify against the manifest", t.root_hex);
        return;
    }

    struct vcs_score_set lineage;
    vcs_score_set_init(&lineage);
    uint32_t ancestors = 0;
    bool lineage_complete = true;
    ok = zr_lineage_absorb(&t, &t.release, &lineage, &ancestors,
                           &lineage_complete);
    if (ok)
        vcs_score_set_finalize(&lineage);
    struct vcs_score_release score;
    if (ok)
        ok = vcs_score_release_compute(inputs, t.manifest.count, &lineage,
                                       t.release.has_parent, &score);
    for (size_t i = 0; i < t.manifest.count; i++)
        free(contents ? contents[i] : NULL);
    free(contents);
    free(inputs);
    if (!ok) {
        vcs_score_set_free(&lineage);
        zr_target_free(&t);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ALLOC",
                               "execute", false, false,
                               "score computation", t.root_hex);
        return;
    }

    char pub_hex[67];
    zcl_hex_encode(t.release.publisher_pubkey, 33, pub_hex);
    (void)json_push_kv_str(&reply->data, "credit_class",
                           "legacy_non_credit");
    (void)json_push_kv_str(&reply->data, "name", t.release.name);
    (void)json_push_kv_str(&reply->data, "semver", t.release.semver);
    (void)json_push_kv_str(&reply->data, "release_id", t.release_id_hex);
    (void)json_push_kv_str(&reply->data, "package_root", t.root_hex);
    (void)json_push_kv_str(&reply->data, "publisher", pub_hex);
    (void)json_push_kv_bool(&reply->data, "has_parent",
                            t.release.has_parent);
    (void)json_push_kv_str(&reply->data, "category",
                           vcs_score_category_string(score.category));
    (void)json_push_kv_int(&reply->data, "category_base",
                           (int64_t)score.category_base);

    struct json_value lin;
    json_init(&lin);
    json_set_object(&lin);
    (void)json_push_kv_int(&lin, "ancestors_walked", (int64_t)ancestors);
    (void)json_push_kv_int(&lin, "depth_cap",
                           (int64_t)VCS_SCORE_MAX_LINEAGE_DEPTH);
    (void)json_push_kv_bool(&lin, "complete", lineage_complete);
    (void)json_push_kv_int(&lin, "lineage_units", (int64_t)lineage.count);
    (void)json_push_kv(&reply->data, "lineage", &lin);
    json_free(&lin);

    struct json_value lines;
    json_init(&lines);
    json_set_object(&lines);
    (void)json_push_kv_int(&lines, "semantic",
                           (int64_t)score.semantic_lines);
    (void)json_push_kv_int(&lines, "blank", (int64_t)score.blank_lines);
    (void)json_push_kv_int(&lines, "comment_only",
                           (int64_t)score.comment_lines);
    (void)json_push_kv_int(&lines, "brace_only",
                           (int64_t)score.brace_lines);
    (void)json_push_kv(&reply->data, "lines", &lines);
    json_free(&lines);

    struct json_value units;
    json_init(&units);
    json_set_object(&units);
    (void)json_push_kv_int(&units, "total", (int64_t)score.units_total);
    (void)json_push_kv_int(&units, "duplicate_within_release",
                           (int64_t)score.units_duplicate);
    (void)json_push_kv_int(&units, "already_rewarded",
                           (int64_t)score.units_already_rewarded);
    (void)json_push_kv_int(&units, "new_source",
                           (int64_t)score.new_source_units);
    (void)json_push_kv_int(&units, "new_test",
                           (int64_t)score.new_test_units);
    (void)json_push_kv(&reply->data, "units", &units);
    json_free(&units);

    struct json_value points;
    json_init(&points);
    json_set_object(&points);
    (void)json_push_kv_int(&points, "raw_line_points",
                           (int64_t)score.raw_line_points);
    (void)json_push_kv_int(&points, "line_cap",
                           (int64_t)VCS_SCORE_MAX_LINE_POINTS_PER_RELEASE);
    (void)json_push_kv_bool(&points, "line_cap_applied",
                            score.line_cap_applied);
    (void)json_push_kv_int(&points, "line_points",
                           (int64_t)score.line_points);
    (void)json_push_kv_int(&points, "raw_total", (int64_t)score.raw_total);
    (void)json_push_kv_int(&points, "release_cap",
                           (int64_t)VCS_SCORE_MAX_TOTAL_PER_RELEASE);
    (void)json_push_kv_bool(&points, "release_cap_applied",
                            score.release_cap_applied);
    (void)json_push_kv_int(&points, "total", (int64_t)score.total);
    (void)json_push_kv(&reply->data, "points", &points);
    json_free(&points);

    struct json_value caps;
    json_init(&caps);
    json_set_object(&caps);
    (void)json_push_kv_int(&caps, "max_line_points_per_release",
                           (int64_t)VCS_SCORE_MAX_LINE_POINTS_PER_RELEASE);
    (void)json_push_kv_int(&caps, "max_total_per_release",
                           (int64_t)VCS_SCORE_MAX_TOTAL_PER_RELEASE);
    (void)json_push_kv_int(&caps, "max_per_contributor_week",
                           (int64_t)VCS_SCORE_MAX_PER_CONTRIBUTOR_WEEK);
    (void)json_push_kv_int(&caps, "max_releases_per_day",
                           (int64_t)VCS_SCORE_MAX_RELEASES_PER_DAY);
    (void)json_push_kv_int(&caps, "source_line_points",
                           (int64_t)VCS_SCORE_SOURCE_LINE_POINTS);
    (void)json_push_kv_int(&caps, "test_line_points",
                           (int64_t)VCS_SCORE_TEST_LINE_POINTS);
    (void)json_push_kv(&reply->data, "caps", &caps);
    json_free(&caps);

    size_t table_count = 0;
    const struct vcs_score_category_constant *table =
        vcs_score_category_table(&table_count);
    struct json_value tbl;
    json_init(&tbl);
    json_set_array(&tbl);
    for (size_t i = 0; i < table_count; i++) {
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "name", table[i].name);
        (void)json_push_kv_int(&row, "min_points",
                               (int64_t)table[i].min_points);
        (void)json_push_kv_int(&row, "max_points",
                               (int64_t)table[i].max_points);
        (void)json_push_kv_bool(&row, "automatic", table[i].automatic);
        (void)json_push_back(&tbl, &row);
        json_free(&row);
    }
    (void)json_push_kv(&reply->data, "scoring_table", &tbl);
    json_free(&tbl);

    struct json_value files;
    json_init(&files);
    json_set_array(&files);
    for (size_t i = 0; i < score.file_report_count; i++) {
        const struct vcs_score_file_report *fr = &score.files[i];
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "path", fr->path);
        (void)json_push_kv_str(&row, "kind",
                               vcs_score_file_kind_string(fr->kind));
        if (fr->kind == VCS_SCORE_FILE_EXCLUDED)
            (void)json_push_kv_str(
                &row, "reason",
                vcs_score_exclude_reason_string(fr->reason));
        (void)json_push_kv_int(&row, "semantic_lines",
                               (int64_t)fr->lines.semantic);
        (void)json_push_kv_int(&row, "new_units",
                               (int64_t)fr->new_units);
        (void)json_push_kv_int(&row, "points", (int64_t)fr->points);
        (void)json_push_back(&files, &row);
        json_free(&row);
    }
    (void)json_push_kv(&reply->data, "files", &files);
    json_free(&files);
    (void)json_push_kv_int(&reply->data, "files_scored",
                           (int64_t)score.files_scored);
    (void)json_push_kv_int(&reply->data, "files_excluded",
                           (int64_t)score.files_excluded);
    (void)json_push_kv_bool(&reply->data, "files_truncated",
                            score.file_reports_truncated);
    (void)json_push_kv_str(
        &reply->data, "determinism_note",
        "same persisted bytes -> same score: no wall-clock, no randomness; "
        "semantic units are logical statements (whitespace, brace style, "
        "and line splits normalized away) diffed against the whole "
        "ancestor lineage by content, so moved/renamed/re-added/duplicated "
        "code scores zero");
    (void)json_push_kv_str(
        &reply->data, "settlement_note",
        "read-only scoring: accrual, weekly/daily cap enforcement against "
        "the reward-history ledger, and SIMULATED settlement are slice 8 — "
        "zcode reward queue/plan/commit/receipt (placeholder token id "
        "only; the real ZSLP transfer is slice 14)");
    vcs_score_set_free(&lineage);
    zr_target_free(&t);
}

/* ── zcode reward eligible ──────────────────────────────────────────── */

void zcl_native_handle_zcode_reward_eligible(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    struct zr_target t;
    if (!zr_target_load(request, reply, &t, "zcode.reward.eligible"))
        return;

    struct vcs_reward_eligibility_input in;
    memset(&in, 0, sizeof(in));

    /* Gate 1: the manifest root matches the envelope and every committed
     * chunk re-verifies from the CAS. */
    in.manifest_parsed = true;
    {
        uint8_t computed[32];
        in.root_matches =
            vcs_package_manifest_root(&t.manifest, computed) &&
            memcmp(computed, t.release.package_root, 32) == 0;
    }
    in.chunks_checked = true;
    for (size_t i = 0; i < t.manifest.count; i++) {
        const struct vcs_package_file *f = &t.manifest.files[i];
        in.chunks_total += f->chunk_count;
        for (uint32_t c = 0; c < f->chunk_count; c++) {
            char hex[65];
            zcl_hex_encode(f->chunk_hashes + 32u * c, 32, hex);
            char path[4400];
            int n = snprintf(path, sizeof(path), "%s/cas/sha3/%.2s/%s",
                             t.zcode_dir, hex, hex);
            if (n < 0 || (size_t)n >= sizeof(path))
                continue;
            uint8_t *chunk = NULL;
            size_t chunk_len = 0;
            if (zr_read_object(path, VCS_PACKAGE_CHUNK_BYTES, &chunk,
                               &chunk_len) &&
                vcs_package_verify_chunk(f, c, chunk, chunk_len))
                in.chunks_verified++;
            free(chunk);
        }
    }

    /* Gate 2. */
    in.release_verifies =
        vcs_package_release_verify(&t.release) == VCS_PACKAGE_RELEASE_OK;

    /* Gate 3: the envelope grammar already enforces the SPDX allowlist at
     * parse time (an off-allowlist release can never persist); the LICENSE
     * text file must also be in the manifest. */
    {
        bool license_file = false;
        for (size_t i = 0; i < t.manifest.count; i++) {
            if (strcmp(t.manifest.files[i].path,
                       VCS_PACKAGE_PUBLISH_LICENSE_PATH) == 0) {
                license_file = true;
                break;
            }
        }
        in.license_accepted = license_file;
    }

    /* Gate 4: parent lineage (release-id chain, same publisher key,
     * sequence +1, parent envelope verifies). */
    char lineage_detail[VCS_REWARD_GATE_DETAIL_MAX];
    if (!t.release.has_parent) {
        in.lineage_valid = true;
        snprintf(lineage_detail, sizeof(lineage_detail),
                 "root release (no parent)");
    } else {
        char parent_hex[65];
        zcl_hex_encode(t.release.parent_root, 32, parent_hex);
        char path[4400];
        snprintf(path, sizeof(path), "%s/releases/%s", t.zcode_dir,
                 parent_hex);
        uint8_t *wire = NULL;
        size_t wire_len = 0;
        struct vcs_package_release parent;
        bool parsed =
            zr_read_object(path, VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES, &wire,
                           &wire_len) &&
            vcs_package_release_parse(wire, wire_len, &parent) ==
                VCS_PACKAGE_RELEASE_OK;
        free(wire);
        if (!parsed) {
            in.lineage_valid = false;
            snprintf(lineage_detail, sizeof(lineage_detail),
                     "parent release %s not hosted or unparseable",
                     parent_hex);
        } else if (vcs_package_release_verify(&parent) !=
                   VCS_PACKAGE_RELEASE_OK) {
            in.lineage_valid = false;
            snprintf(lineage_detail, sizeof(lineage_detail),
                     "parent release envelope does not verify");
        } else if (memcmp(parent.publisher_pubkey,
                          t.release.publisher_pubkey, 33) != 0) {
            in.lineage_valid = false;
            snprintf(lineage_detail, sizeof(lineage_detail),
                     "parent signed by a different publisher key");
        } else if (t.release.publisher_sequence !=
                   parent.publisher_sequence + 1u) {
            in.lineage_valid = false;
            snprintf(lineage_detail, sizeof(lineage_detail),
                     "sequence %llu does not follow parent %llu",
                     (unsigned long long)t.release.publisher_sequence,
                     (unsigned long long)parent.publisher_sequence);
        } else {
            in.lineage_valid = true;
            snprintf(lineage_detail, sizeof(lineage_detail),
                     "parent %s verifies; sequence +1", parent_hex);
        }
    }
    in.lineage_detail = lineage_detail;

    /* Gates 5-8: the slice-6 quorum. A missing allowlist is not a hard
     * error here — it is a failed quorum gate, named. */
    struct vcs_verifier_policy policy;
    vcs_verifier_policy_init(&policy);
    enum vcs_verifier_policy_error perr = VCS_VERIFIER_POLICY_OK;
    char path[4400];
    snprintf(path, sizeof(path), "%s/approved_verifiers", t.zcode_dir);
    bool policy_loaded = vcs_verifier_policy_load(&policy, path, &perr);
    size_t candidate_count = 0;
    struct vcs_verify_candidate *candidates = zcl_malloc(
        ZR_VERIFY_MAX_SCAN * sizeof(*candidates), "zr_verify_candidates");
    if (!candidates) {
        zr_target_free(&t);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ALLOC",
                               "execute", false, false,
                               "verify candidate buffer", t.root_hex);
        return;
    }
    if (policy_loaded) {
        snprintf(path, sizeof(path), "%s/attestations", t.zcode_dir);
        DIR *dir = opendir(path);
        if (dir) {
            struct dirent *ent;
            while ((ent = readdir(dir)) != NULL) {
                uint8_t scratch[32];
                size_t scratch_len = 0;
                if (!zcl_hex_decode_n(ent->d_name, scratch, 32,
                                   &scratch_len) ||
                    scratch_len != 32)
                    continue;
                if (candidate_count == ZR_VERIFY_MAX_SCAN)
                    break;
                char apath[4400];
                int an = snprintf(apath, sizeof(apath), "%s/%s", path,
                                  ent->d_name);
                if (an < 0 || (size_t)an >= sizeof(apath))
                    continue;
                uint8_t *wire = NULL;
                size_t wire_len = 0;
                struct vcs_verify_candidate *cand =
                    &candidates[candidate_count];
                cand->parsed = false;
                if (zr_read_object(apath, VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES,
                                   &wire, &wire_len)) {
                    cand->parsed =
                        vcs_package_attest_parse(wire, wire_len,
                                                 &cand->attestation) ==
                        VCS_PACKAGE_ATTEST_OK;
                }
                free(wire);
                candidate_count++;
            }
            closedir(dir);
        }
    }
    struct vcs_verify_quorum quorum;
    memset(&quorum, 0, sizeof(quorum));
    if (policy_loaded) {
        uint8_t root[32];
        size_t root_len = 0;
        (void)zcl_hex_decode_n(t.root_hex, root, 32, &root_len);
        vcs_verify_evaluate(candidates, candidate_count, root,
                            t.release.recipe_root,
                            t.release.publisher_pubkey, &policy, &quorum);
    }
    in.quorum_verified = policy_loaded && quorum.verified;
    if (in.quorum_verified) {
        /* The counted attestations of the quorum class carry the build
         * facts: read gcc/clang outcomes from them directly. */
        for (size_t i = 0;
             i < candidate_count && i < quorum.row_count; i++) {
            if (quorum.rows[i].rule != VCS_VERIFY_ROW_COUNTED ||
                quorum.rows[i].result_class != quorum.quorum_class)
                continue;
            const struct vcs_package_attest *a = &candidates[i].attestation;
            for (size_t k = 0; k < a->compiler_count; k++) {
                if (strcmp(a->compilers[k].id, "gcc") == 0 &&
                    a->compilers[k].outcome ==
                        VCS_PACKAGE_ATTEST_OUTCOME_PASS)
                    in.gcc_pass = true;
                if (strcmp(a->compilers[k].id, "clang") == 0 &&
                    a->compilers[k].outcome ==
                        VCS_PACKAGE_ATTEST_OUTCOME_PASS)
                    in.clang_pass = true;
            }
        }
        in.tests_pass =
            quorum.quorum_class == VCS_PACKAGE_ATTEST_RESULT_TEST_PASS;
    }
    free(candidates);

    /* The headline signal (gates 5-8): a recorded bit-identical
     * reproduction among the filed build receipts outranks the signer
     * quorum, which is the latency fast path over it. */
    {
        uint8_t root[32];
        size_t root_len = 0;
        struct vcs_reproduce_report repro;
        snprintf(path, sizeof(path), "%s/receipts", t.zcode_dir);
        if (zcl_hex_decode_n(t.root_hex, root, 32, &root_len) &&
            root_len == 32 &&
            vcs_package_reproduce_scan(path, root, t.release.recipe_root,
                                       &repro))
            in.reproduction_verified = repro.reproduced;
    }

    struct vcs_reward_eligibility elig;
    vcs_reward_eligibility_evaluate(&in, &elig);

    char pub_hex[67];
    zcl_hex_encode(t.release.publisher_pubkey, 33, pub_hex);
    (void)json_push_kv_str(&reply->data, "name", t.release.name);
    (void)json_push_kv_str(&reply->data, "semver", t.release.semver);
    (void)json_push_kv_str(&reply->data, "release_id", t.release_id_hex);
    (void)json_push_kv_str(&reply->data, "package_root", t.root_hex);
    (void)json_push_kv_str(&reply->data, "publisher", pub_hex);
    (void)json_push_kv_bool(&reply->data, "eligible", elig.eligible);
    (void)json_push_kv_bool(&reply->data, "reproduction_verified",
                            elig.reproduction_verified);
    (void)json_push_kv_int(&reply->data, "failed_count",
                           (int64_t)elig.failed_count);
    struct json_value gates;
    json_init(&gates);
    json_set_array(&gates);
    for (size_t i = 0; i < VCS_REWARD_GATE_COUNT; i++) {
        const struct vcs_reward_gate_row *row = &elig.gates[i];
        struct json_value g;
        json_init(&g);
        json_set_object(&g);
        (void)json_push_kv_str(&g, "gate", vcs_reward_gate_string(row->gate));
        (void)json_push_kv_bool(&g, "passed", row->passed);
        (void)json_push_kv_str(&g, "detail", row->detail);
        (void)json_push_back(&gates, &g);
        json_free(&g);
    }
    (void)json_push_kv(&reply->data, "gates", &gates);
    json_free(&gates);
    struct json_value failed;
    json_init(&failed);
    json_set_array(&failed);
    for (size_t i = 0; i < VCS_REWARD_GATE_COUNT; i++) {
        if (elig.gates[i].passed)
            continue;
        struct json_value g;
        json_init(&g);
        json_set_str(&g, vcs_reward_gate_string(elig.gates[i].gate));
        (void)json_push_back(&failed, &g);
        json_free(&g);
    }
    (void)json_push_kv(&reply->data, "failed_gates", &failed);
    json_free(&failed);
    (void)json_push_kv_bool(&reply->data, "approved_verifiers_loaded",
                            policy_loaded);
    (void)json_push_kv_int(&reply->data, "attestations_evaluated",
                           (int64_t)candidate_count);
    (void)json_push_kv_bool(&reply->data, "quorum_reached",
                            policy_loaded && quorum.quorum_reached);
    (void)json_push_kv_int(&reply->data, "quorum_signers",
                           (int64_t)quorum.quorum_signers);
    (void)json_push_kv_str(
        &reply->data, "eligibility_note",
        "a release earns nothing until every gate passes; the build/test "
        "gates are read from the counted quorum attestations (the node "
        "never compiles or executes downloaded code)");
    zr_target_free(&t);
}
