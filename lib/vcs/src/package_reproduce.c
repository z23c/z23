/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_reproduce — implementation of the bit-identical reproduction
 * verdict declared in vcs/package_reproduce.h. Pure evaluation over two
 * parsed build receipts, plus one bounded directory scan (the package_index
 * / package_verify_policy load() precedent). No compiler, no execution, no
 * network, no trust decisions of its own. */

#include "vcs/package_reproduce.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"

#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REPRO_LOG "vcs.reproduce"

const char *vcs_reproduce_rule_string(enum vcs_reproduce_rule rule)
{
    switch (rule) {
    case VCS_REPRODUCE_MATCH: return "match";
    case VCS_REPRODUCE_REFERENCE_INVALID: return "reference-invalid";
    case VCS_REPRODUCE_REBUILD_INVALID: return "rebuild-invalid";
    case VCS_REPRODUCE_REFERENCE_NOT_INSTALLABLE:
        return "reference-not-installable";
    case VCS_REPRODUCE_REBUILD_NOT_INSTALLABLE:
        return "rebuild-not-installable";
    case VCS_REPRODUCE_PACKAGE_ROOT_MISMATCH: return "package-root-mismatch";
    case VCS_REPRODUCE_RECIPE_ROOT_MISMATCH: return "recipe-root-mismatch";
    case VCS_REPRODUCE_LOCK_ROOT_MISMATCH: return "lock-root-mismatch";
    case VCS_REPRODUCE_DEP_SET_MISMATCH: return "dependency-set-mismatch";
    case VCS_REPRODUCE_OUTPUT_MISSING: return "output-missing";
    case VCS_REPRODUCE_OUTPUT_UNEXPECTED: return "output-unexpected";
    case VCS_REPRODUCE_OUTPUT_HASH_MISMATCH: return "output-hash-mismatch";
    case VCS_REPRODUCE_OUTPUT_SIZE_MISMATCH: return "output-size-mismatch";
    }
    return "unknown-rule";
}

static void repro_verdict(struct vcs_reproduce_verdict *out,
                          enum vcs_reproduce_rule rule, const char *fmt,
                          ...)
{
    out->reproduced = rule == VCS_REPRODUCE_MATCH;
    out->rule = (uint8_t)rule;
    va_list ap;
    va_start(ap, fmt);
    if (fmt)
        (void)vsnprintf(out->detail, sizeof(out->detail), fmt, ap);
    else
        out->detail[0] = '\0';
    va_end(ap);
}

/* Path plus truncated expected/actual hashes: full hashes live in the
 * receipts themselves; the detail only needs to name the divergence
 * loudly inside VCS_REPRODUCE_DETAIL_MAX. */
static void repro_hash_detail(char *out, size_t cap, const char *path,
                              const uint8_t expected[32],
                              const uint8_t actual[32])
{
    char want[17];
    char got[17];
    zcl_hex_encode(expected, 8, want);
    zcl_hex_encode(actual, 8, got);
    (void)snprintf(out, cap, "%.80s: expected sha3 %s..., got %s...", path,
                   want, got);
}

void vcs_package_reproduce_compare(
    const struct vcs_package_build_receipt *reference,
    const struct vcs_package_build_receipt *rebuild,
    struct vcs_reproduce_verdict *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    if (!reference ||
        vcs_package_build_validate(reference) != VCS_PACKAGE_BUILD_OK) {
        repro_verdict(out, VCS_REPRODUCE_REFERENCE_INVALID,
                      "the reference receipt does not validate");
        return;
    }
    if (!rebuild ||
        vcs_package_build_validate(rebuild) != VCS_PACKAGE_BUILD_OK) {
        repro_verdict(out, VCS_REPRODUCE_REBUILD_INVALID,
                      "the rebuild receipt does not validate");
        return;
    }
    /* A build that did not pass has nothing to reproduce: byte-identity of
     * an empty output set would be vacuous, so the verdict names it. */
    if (!vcs_package_build_installable(reference)) {
        repro_verdict(out, VCS_REPRODUCE_REFERENCE_NOT_INSTALLABLE,
                      "reference verdict %s is not a passing build",
                      vcs_package_build_result_string(
                          (enum vcs_package_build_result)
                              reference->result_class));
        return;
    }
    if (!vcs_package_build_installable(rebuild)) {
        repro_verdict(out, VCS_REPRODUCE_REBUILD_NOT_INSTALLABLE,
                      "rebuild verdict %s is not a passing build",
                      vcs_package_build_result_string(
                          (enum vcs_package_build_result)
                              rebuild->result_class));
        return;
    }
    if (memcmp(reference->package_root, rebuild->package_root, 32) != 0) {
        repro_verdict(out, VCS_REPRODUCE_PACKAGE_ROOT_MISMATCH,
                      "the receipts name different package roots");
        return;
    }
    if (memcmp(reference->recipe_root, rebuild->recipe_root, 32) != 0) {
        repro_verdict(out, VCS_REPRODUCE_RECIPE_ROOT_MISMATCH,
                      "the receipts name different recipe roots");
        return;
    }
    if (memcmp(reference->lock_root, rebuild->lock_root, 32) != 0) {
        repro_verdict(out, VCS_REPRODUCE_LOCK_ROOT_MISMATCH,
                      "the receipts name different dependency locks");
        return;
    }
    if (reference->dep_count != rebuild->dep_count ||
        memcmp(reference->dep_roots, rebuild->dep_roots,
               reference->dep_count * 32u) != 0) {
        repro_verdict(out, VCS_REPRODUCE_DEP_SET_MISMATCH,
                      "the locked dependency sets differ (%zu vs %zu roots)",
                      reference->dep_count, rebuild->dep_count);
        return;
    }
    /* Both output lists are strictly ascending by path (the receipt
     * grammar), so a merge walk finds the first divergence in one pass. */
    size_t i = 0;
    size_t j = 0;
    while (i < reference->output_count || j < rebuild->output_count) {
        if (i == reference->output_count) {
            repro_verdict(out, VCS_REPRODUCE_OUTPUT_UNEXPECTED,
                          "%.120s: the rebuild emitted an output the "
                          "reference does not commit",
                          rebuild->outputs[j].path);
            return;
        }
        if (j == rebuild->output_count) {
            repro_verdict(out, VCS_REPRODUCE_OUTPUT_MISSING,
                          "%.120s: committed by the reference, not emitted "
                          "by the rebuild",
                          reference->outputs[i].path);
            return;
        }
        int cmp = strcmp(reference->outputs[i].path,
                         rebuild->outputs[j].path);
        if (cmp < 0) {
            repro_verdict(out, VCS_REPRODUCE_OUTPUT_MISSING,
                          "%.120s: committed by the reference, not emitted "
                          "by the rebuild",
                          reference->outputs[i].path);
            return;
        }
        if (cmp > 0) {
            repro_verdict(out, VCS_REPRODUCE_OUTPUT_UNEXPECTED,
                          "%.120s: the rebuild emitted an output the "
                          "reference does not commit",
                          rebuild->outputs[j].path);
            return;
        }
        if (memcmp(reference->outputs[i].sha3, rebuild->outputs[j].sha3,
                   32) != 0) {
            char detail[VCS_REPRODUCE_DETAIL_MAX];
            repro_hash_detail(detail, sizeof(detail),
                              reference->outputs[i].path,
                              reference->outputs[i].sha3,
                              rebuild->outputs[j].sha3);
            repro_verdict(out, VCS_REPRODUCE_OUTPUT_HASH_MISMATCH, "%s",
                          detail);
            return;
        }
        if (reference->outputs[i].bytes != rebuild->outputs[j].bytes) {
            repro_verdict(out, VCS_REPRODUCE_OUTPUT_SIZE_MISMATCH,
                          "%.100s: %llu bytes committed, %llu emitted",
                          reference->outputs[i].path,
                          (unsigned long long)reference->outputs[i].bytes,
                          (unsigned long long)rebuild->outputs[j].bytes);
            return;
        }
        i++;
        j++;
    }
    repro_verdict(out, VCS_REPRODUCE_MATCH, NULL);
}

/* ── the receipts-directory scan ────────────────────────────────────── */

struct repro_entry {
    uint8_t id[32];
    struct vcs_package_build_receipt receipt;
    bool matched; /* reference row, or MATCH against it — set in the row pass */
};

static int repro_entry_cmp(const void *a, const void *b)
{
    const struct repro_entry *ea = a;
    const struct repro_entry *eb = b;
    return memcmp(ea->id, eb->id, 32);
}

/* Read one bounded file fully (NULL on any failure/oversize). */
static uint8_t *repro_read_file(const char *path, size_t *out_len)
{
    *out_len = 0;
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    uint8_t *buf = zcl_malloc(VCS_REPRODUCE_MAX_WIRE_BYTES,
                              "reproduce_receipt");
    if (!buf) {
        fclose(f);
        LOG_NULL(REPRO_LOG, "alloc receipt buffer for %s", path);
    }
    size_t len = fread(buf, 1, VCS_REPRODUCE_MAX_WIRE_BYTES, f);
    bool bad = ferror(f) || !feof(f) || len == 0;
    fclose(f);
    if (bad) {
        free(buf);
        return NULL;
    }
    *out_len = len;
    return buf;
}

bool vcs_package_reproduce_scan(const char *receipts_dir,
                                const uint8_t package_root[32],
                                const uint8_t recipe_root[32],
                                struct vcs_reproduce_report *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!receipts_dir || !package_root || !recipe_root)
        return false;
    DIR *dir = opendir(receipts_dir);
    if (!dir)
        return errno == ENOENT; /* no receipts recorded: an empty report */

    struct repro_entry *entries = NULL;
    size_t count = 0;
    struct dirent *ent;
    bool io_failed = false;
    while ((ent = readdir(dir)) != NULL) {
        uint8_t scratch[32];
        size_t scratch_len = 0;
        if (!zcl_hex_decode_n(ent->d_name, scratch, 32, &scratch_len) ||
            scratch_len != 32)
            continue;
        out->scanned++;
        char path[4400];
        int n = snprintf(path, sizeof(path), "%s/%s", receipts_dir,
                         ent->d_name);
        if (n < 0 || (size_t)n >= sizeof(path))
            continue;
        size_t wire_len = 0;
        uint8_t *wire = repro_read_file(path, &wire_len);
        if (!wire)
            continue;
        struct vcs_package_build_receipt receipt;
        enum vcs_package_build_error perr =
            vcs_package_build_parse(wire, wire_len, &receipt);
        free(wire);
        if (perr != VCS_PACKAGE_BUILD_OK ||
            memcmp(receipt.package_root, package_root, 32) != 0 ||
            memcmp(receipt.recipe_root, recipe_root, 32) != 0 ||
            !vcs_package_build_installable(&receipt))
            continue;
        struct repro_entry *grown =
            zcl_realloc(entries, (count + 1u) * sizeof(*grown),
                        "reproduce_entries");
        if (!grown) {
            LOG_ERROR(REPRO_LOG, "alloc %zu receipt entries", count + 1u);
            io_failed = true;
            break;
        }
        entries = grown;
        if (vcs_package_build_id(&receipt, entries[count].id) !=
            VCS_PACKAGE_BUILD_OK)
            continue;
        entries[count].receipt = receipt;
        entries[count].matched = false;
        count++;
    }
    closedir(dir);
    if (io_failed) {
        free(entries);
        return false;
    }

    /* Deterministic reference: the lowest receipt id. Identical rebuilds
     * by one toolchain file ONE receipt (same id, same name), so every row
     * past the reference is a genuinely distinct build event. */
    if (count > 0)
        qsort(entries, count, sizeof(*entries), repro_entry_cmp);
    out->matching = (uint32_t)count;
    bool all_match = count >= 2;
    for (size_t i = 0; i < count; i++) {
        struct vcs_reproduce_verdict v;
        if (i == 0) {
            memset(&v, 0, sizeof(v));
            v.reproduced = true;
            v.rule = (uint8_t)VCS_REPRODUCE_MATCH;
        } else {
            vcs_package_reproduce_compare(&entries[0].receipt,
                                          &entries[i].receipt, &v);
        }
        if (!v.reproduced)
            all_match = false;
        entries[i].matched = v.reproduced;
        if (out->row_count < VCS_REPRODUCE_MAX_ROWS) {
            struct vcs_reproduce_row *row = &out->rows[out->row_count++];
            memcpy(row->receipt_id, entries[i].id, 32);
            row->reference = i == 0;
            row->rule = v.rule;
            snprintf(row->detail, sizeof(row->detail), "%s", v.detail);
            row->has_toolchain_capsule =
                entries[i].receipt.has_toolchain_capsule;
            memcpy(row->toolchain_capsule_root,
                   entries[i].receipt.toolchain_capsule_root, 32);
        } else {
            out->rows_truncated = true;
            all_match = false; /* unexamined receipts: never claim it */
        }
    }
    out->reproduced = all_match;

    /* Toolchain diversity among the MATCHING rows: the distinct nonzero
     * pinned capsule roots. A capsule-less (v1) receipt adds nothing —
     * it proves byte-identity, not toolchain independence. Rows beyond
     * the display cap still count here (they were compared above). */
    for (size_t i = 0; i < count; i++) {
        if (!entries[i].matched ||
            !entries[i].receipt.has_toolchain_capsule)
            continue;
        const uint8_t *root = entries[i].receipt.toolchain_capsule_root;
        bool zero = true;
        for (size_t b = 0; b < 32 && zero; b++)
            zero = root[b] == 0;
        if (zero)
            continue;
        bool seen = false;
        for (size_t j = 0; j < i && !seen; j++)
            if (entries[j].matched &&
                entries[j].receipt.has_toolchain_capsule &&
                memcmp(entries[j].receipt.toolchain_capsule_root, root,
                       32) == 0)
                seen = true;
        if (!seen)
            out->distinct_toolchains++;
    }
    out->cross_toolchain = out->distinct_toolchains >= 2;
    free(entries);
    return true;
}
