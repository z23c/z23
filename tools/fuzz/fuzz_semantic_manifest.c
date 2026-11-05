/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * fuzz_semantic_manifest — libFuzzer harness for the semantic manifest v1
 * reader (contexts/commons/modules/vcs/src/semantic_manifest*.c,
 * docs/work/SEMANTIC_MANIFEST.md). A semantic manifest is a byte string a
 * libclang sensor writes to disk today and a future action-root consumer
 * will read from anywhere: another node, a cache, a peer. Z23 is the reader
 * only, so this harness fuzzes exactly the untrusted-input boundary: the
 * strict decoder never trusts a byte it has not validated.
 *
 * For every input this checks four properties:
 *
 *   1. The strict decoder never crashes, leaks or reads out of bounds:
 *      validate, root, hint root, every section root, facts info, and every
 *      record-walk API the header exposes (section_v1_each,
 *      manifest_v1_each, absent_v1_each).
 *   2. CANONICAL FORM MEANS EXACTLY ONE ENCODING. If the strict decoder
 *      accepts an input, this harness walks its decoded records
 *      (manifest_v1_each gives the exact record_bytes, "raw", per record)
 *      and feeds them straight back into the builder
 *      (vcs_semantic_builder_v1_add takes ready-made record bytes, per
 *      semantic_manifest_build.c's sm_add_raw) plus, when the facts
 *      extension is present, vcs_semantic_builder_v1_enable_facts with the
 *      exact caps read back via vcs_semantic_facts_v1_info. The builder
 *      sorts, deduplicates and re-validates its own output
 *      (vcs_semantic_builder_v1_finish). Since the input was already
 *      accepted by the strict decoder, it was already in canonical order;
 *      rebuilding it must therefore reproduce the identical bytes and the
 *      identical root. Anything else means the format allows two byte
 *      strings for one logical manifest, which the format's own doc
 *      ("Ordering is canonical, not normalized") says cannot happen: this
 *      harness treats that as a fatal abort, not a soft finding, so it is
 *      never silently skipped by libFuzzer.
 *   3. The dump renderer (vcs_semantic_manifest_v1_dump), run on an accepted
 *      input into a memory stream, succeeds, writes no NUL byte (its own
 *      contract: texts are hex-escaped, not embedded raw) and is
 *      deterministic across two independent calls.
 *   4. Facts info (vcs_semantic_facts_v1_info) is consistent with the
 *      sections the manifest actually carries: present iff a FACTS record
 *      exists (tag 10 has records), complete iff no TRUNCATED record
 *      (tag 15) exists, and revision is 1 to 4 exactly when present.
 *
 * If a decoded record cannot be re-expressed by the builder — a record
 * whose section the builder API refuses to accept directly (only FACTS and
 * TRUNCATED, which the builder always writes itself via finish(), never via
 * add()) — that is itself a finding: see SM_SECTION_IS_BUILDER_INTERNAL
 * below, which is the one section pair this harness does not feed back
 * through add() and instead reconstructs via enable_facts().
 *
 * Pure in-memory entry points, no sockets, deterministic per iteration.
 * Runs with -fsanitize=fuzzer,address,undefined under clang.
 */

#include "vcs/semantic_manifest.h"

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

volatile sig_atomic_t g_shutdown_requested = 0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define SM_MAX_INPUT (1u << 20) /* matches the golden vector's scale; bigger inputs cost time, not new bugs */

/* A section the builder writes only from inside finish(); add() refuses it
 * (semantic_manifest_build.c: vcs_semantic_builder_v1_add rejects FACTS and
 * TRUNCATED explicitly). Every other section (1-9 base, 11-14 facts) is fed
 * back verbatim as raw record bytes. */
static bool sm_section_is_builder_internal(enum vcs_semantic_section_v1 s)
{
    return s == VCS_SEMANTIC_SECTION_V1_FACTS ||
           s == VCS_SEMANTIC_SECTION_V1_TRUNCATED;
}

struct sm_rebuild_ctx {
    struct vcs_semantic_builder_v1 *b;
    bool add_failed;
    enum vcs_semantic_section_v1 add_failed_section;
};

static bool sm_rebuild_cb(void *ctx_v, enum vcs_semantic_section_v1 section,
                          const struct vcs_semantic_fields_v1 *fields,
                          const uint8_t *raw, size_t raw_len)
{
    struct sm_rebuild_ctx *ctx = ctx_v;
    struct vcs_semantic_record_v1 rec = {0};
    (void)fields;

    if (sm_section_is_builder_internal(section))
        return true; /* finish() regenerates these; never fed through add() */

    /* raw/raw_len is exactly one decoded record_bytes span (the header's own
     * words: "the record body, without its length prefix"), and
     * vcs_semantic_builder_v1_add copies a record's bytes verbatim into the
     * named section (sm_add_raw) — so handing it the decoded bytes directly
     * is the one honest round trip: it does not re-derive the encoding from
     * the fields view, it re-plays the exact bytes the decoder already
     * accepted. */
    rec.bytes = (uint8_t *)raw; /* not written through; add() only reads */
    rec.len = raw_len;
    rec.cap = raw_len;
    rec.failed = false;

    if (!vcs_semantic_builder_v1_add(ctx->b, section, &rec)) {
        ctx->add_failed = true;
        ctx->add_failed_section = section;
        return false;
    }
    return true;
}

/* Property 4: facts info must line up with what sections are actually
 * present. Aborts (not a soft finding) on a real inconsistency; those bytes
 * belong in the crash corpus. */
static void sm_check_facts_consistency(const uint8_t *bytes, size_t len)
{
    struct vcs_semantic_facts_info_v1 info;
    uint32_t facts_records = 0, truncated_records = 0;

    memset(&info, 0, sizeof(info));
    if (!vcs_semantic_facts_v1_info(bytes, len, &info))
        return; /* invalid manifest: nothing to check */

    if (!vcs_semantic_section_count_v1(bytes, len, VCS_SEMANTIC_SECTION_V1_FACTS,
                                       &facts_records))
        facts_records = 0;
    if (!vcs_semantic_section_count_v1(bytes, len,
                                       VCS_SEMANTIC_SECTION_V1_TRUNCATED,
                                       &truncated_records))
        truncated_records = 0;

    if (info.present != (facts_records > 0)) {
        fprintf(stderr,
                "fuzz_semantic_manifest: facts_v1_info.present=%d but FACTS "
                "records=%u\n",
                (int)info.present, facts_records);
        __builtin_trap();
    }
    if (info.present && info.complete != (truncated_records == 0)) {
        fprintf(stderr,
                "fuzz_semantic_manifest: facts_v1_info.complete=%d but "
                "TRUNCATED records=%u\n",
                (int)info.complete, truncated_records);
        __builtin_trap();
    }
    if (info.present && (info.revision < 1 || info.revision > 4)) {
        fprintf(stderr,
                "fuzz_semantic_manifest: facts_v1_info.revision=%u out of "
                "range while present\n",
                (unsigned)info.revision);
        __builtin_trap();
    }
}

/* Property 3: the dump renderer, run into a memory stream, succeeds, emits
 * no NUL byte, and is byte-identical across two independent calls. */
static void sm_check_dump(const uint8_t *bytes, size_t len)
{
    char *buf_a = NULL, *buf_b = NULL;
    size_t len_a = 0, len_b = 0;
    FILE *fa = open_memstream(&buf_a, &len_a);
    FILE *fb = open_memstream(&buf_b, &len_b);
    bool ok_a, ok_b;

    if (fa == NULL || fb == NULL) {
        if (fa) fclose(fa);
        if (fb) fclose(fb);
        free(buf_a);
        free(buf_b);
        return; /* allocation pressure, not a finding */
    }

    ok_a = vcs_semantic_manifest_v1_dump(bytes, len, fa);
    fclose(fa);
    ok_b = vcs_semantic_manifest_v1_dump(bytes, len, fb);
    fclose(fb);

    if (ok_a != ok_b) {
        fprintf(stderr,
                "fuzz_semantic_manifest: dump() non-deterministic success "
                "(%d vs %d)\n",
                (int)ok_a, (int)ok_b);
        __builtin_trap();
    }
    if (ok_a) {
        if (len_a != len_b || (len_a > 0 && memcmp(buf_a, buf_b, len_a) != 0)) {
            fprintf(stderr,
                    "fuzz_semantic_manifest: dump() non-deterministic output "
                    "(%zu vs %zu bytes)\n",
                    len_a, len_b);
            __builtin_trap();
        }
        if (memchr(buf_a, '\0', len_a) != NULL) {
            fprintf(stderr,
                    "fuzz_semantic_manifest: dump() emitted a NUL byte\n");
            __builtin_trap();
        }
    }
    free(buf_a);
    free(buf_b);
}

static bool sm_absent_cb(void *ctx, const char *dir, size_t dir_len,
                         const char *name, size_t name_len)
{
    (void)ctx; (void)dir; (void)dir_len; (void)name; (void)name_len;
    return true; /* keep walking every record; never stops early on purpose */
}

static bool sm_each_noop_cb(void *ctx, const struct vcs_semantic_fields_v1 *f)
{
    (void)ctx; (void)f;
    return true;
}

/* Read the accepted manifest's facts header and arm the builder with it. */
static void sm_rearm_facts(struct vcs_semantic_builder_v1 *b,
                           const uint8_t *bytes, size_t len,
                           struct vcs_semantic_facts_info_v1 *info)
{
    memset(info, 0, sizeof(*info));
    if (!vcs_semantic_facts_v1_info(bytes, len, info) || !info->present)
        return;
    struct vcs_semantic_facts_v1 caps = {0};
    memcpy(caps.namespace_root, info->namespace_root, 32);
    memcpy(caps.producer, info->producer, 32);
    caps.max_records = info->max_records;
    caps.max_section_bytes = info->max_section_bytes;
    caps.revision = info->revision;
    if (vcs_semantic_builder_v1_enable_facts(b, &caps))
        return;
    /* The decoder accepted a facts header this exact builder API
     * cannot re-arm (out-of-range caps it nonetheless read back
     * from an accepted manifest). That is a real finding: the
     * builder and the decoder disagree about what caps are valid,
     * so an accepted manifest cannot always be reproduced. */
    fprintf(stderr,
            "fuzz_semantic_manifest: FINDING: accepted facts header "
            "(max_records=%u max_section_bytes=%llu revision=%u) "
            "cannot be re-armed by vcs_semantic_builder_v1_enable_"
            "facts\n",
            info->max_records,
            (unsigned long long)info->max_section_bytes,
            (unsigned)info->revision);
    __builtin_trap();
}

/* Property 2: rebuild an accepted manifest from its decoded records and
 * demand byte-identical output and an equal root. Aborts on mismatch. */
static void sm_check_rebuild(const uint8_t *bytes, size_t len,
                             const uint8_t root[32])
{
    struct vcs_semantic_builder_v1 *b = vcs_semantic_builder_v1_new();
    struct sm_rebuild_ctx ctx = {.b = b};
    struct vcs_semantic_facts_info_v1 info;
    uint8_t *out = NULL;
    size_t out_len = 0;
    char why[256] = {0};

    if (b == NULL)
        return;

    sm_rearm_facts(b, bytes, len, &info);

    if (!vcs_semantic_manifest_v1_each(bytes, len, sm_rebuild_cb, &ctx)) {
        if (ctx.add_failed) {
            fprintf(stderr,
                    "fuzz_semantic_manifest: FINDING: builder cannot "
                    "re-express an accepted record in section %d — the "
                    "builder is not surjective onto what the decoder "
                    "accepts\n",
                    (int)ctx.add_failed_section);
            __builtin_trap();
        }
        vcs_semantic_builder_v1_free(b);
        return; /* each() itself refused mid-walk: not this property's job */
    }

    if (!vcs_semantic_builder_v1_finish(b, &out, &out_len, why, sizeof(why))) {
        /* A record cap can cut the main file out of FILES: the validator
         * accepts that because TRUNCATED names the section (files_cut). The
         * replay below has no TRUNCATED record to hand finish(), so it asks
         * for a complete manifest with no main file, and refusing that is
         * correct. Only that refusal of an incomplete manifest is exempt;
         * any other one is still a finding. */
        if (info.present && !info.complete &&
            strstr(why, "identity main file is not the one main file") != NULL) {
            vcs_semantic_builder_v1_free(b);
            return;
        }
        fprintf(stderr,
                "fuzz_semantic_manifest: FINDING: builder refused to finish "
                "an all-accepted-record rebuild: %s\n",
                why);
        __builtin_trap();
    }
    vcs_semantic_builder_v1_free(b);

    /* FINDING (documented, not a decoder bug — see docs/work/
     * SEMANTIC_MANIFEST.md, "finish() writes the FACTS and TRUNCATED
     * sections itself; a producer never adds to them"): an INCOMPLETE facts
     * manifest (info.present && !info.complete) is not byte-reproducible
     * from its own decoded records. TRUNCATED only records a section's
     * name, kept count and dropped count — never the dropped records'
     * bytes — so replaying just the surviving records back through the
     * builder hands finish() a set that already fits the caps. finish()
     * therefore emits NO new TRUNCATED record and complete=1, which is a
     * different (smaller) manifest than the original, even though every
     * surviving record was reproduced exactly. The format's own doc says
     * this plainly: "complete = 0 ... makes the manifest non-authoritative
     * for impact" — an incomplete manifest is a lossy view of a larger
     * session by design, and the builder cannot re-derive a session larger
     * than the one it was actually given. Canonical form (exactly one
     * encoding) still holds for every COMPLETE manifest, checked strictly
     * below; it does not hold, and cannot hold, across an information-losing
     * cut. */
    if (info.present && !info.complete) {
        free(out);
        return;
    }

    if (out_len != len || memcmp(out, bytes, len) != 0) {
        fprintf(stderr,
                "fuzz_semantic_manifest: FINDING: rebuild is not byte-"
                "identical (%zu vs %zu bytes) — canonical form is not "
                "exactly one encoding\n",
                out_len, len);
        /* Diagnostic only, and only on this already-fatal path: which
         * section's record count moved in the rebuild, and the facts caps
         * that were in force. */
        for (int t = 1; t < VCS_SEMANTIC_SECTION_V1_COUNT; t++) {
            uint32_t before = 0, after = 0;
            (void)vcs_semantic_section_count_v1(
                bytes, len, (enum vcs_semantic_section_v1)t, &before);
            (void)vcs_semantic_section_count_v1(
                out, out_len, (enum vcs_semantic_section_v1)t, &after);
            fprintf(stderr, "  section %d (%s): before=%u after=%u\n", t,
                    vcs_semantic_section_v1_name((enum vcs_semantic_section_v1)t),
                    before, after);
        }
        fprintf(stderr,
                "  caps: present=%d complete=%d revision=%u "
                "max_records=%u max_section_bytes=%llu\n",
                (int)info.present, (int)info.complete, (unsigned)info.revision,
                info.max_records, (unsigned long long)info.max_section_bytes);
        free(out);
        __builtin_trap();
    }

    {
        uint8_t rebuilt_root[32];
        char rwhy[128] = {0};
        if (!vcs_semantic_root_v1(out, out_len, rebuilt_root, rwhy,
                                  sizeof(rwhy)) ||
            memcmp(rebuilt_root, root, 32) != 0) {
            fprintf(stderr,
                    "fuzz_semantic_manifest: FINDING: rebuilt root differs "
                    "from the original root\n");
            free(out);
            __builtin_trap();
        }
    }
    free(out);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char why[256];
    uint8_t root[32], hint_root[32];
    bool valid;

    if (size == 0 || size > SM_MAX_INPUT)
        return 0;

    /* Property 1: none of these may crash, leak, or read out of bounds,
     * valid input or not. */
    why[0] = '\0';
    valid = vcs_semantic_manifest_v1_validate(data, size, why, sizeof(why));

    (void)vcs_semantic_root_v1(data, size, root, why, sizeof(why));
    (void)vcs_semantic_hint_root_v1(data, size, hint_root, why, sizeof(why));
    for (int t = 1; t < VCS_SEMANTIC_SECTION_V1_COUNT; t++) {
        uint8_t section_root[32];
        uint32_t count = 0;
        (void)vcs_semantic_section_root_v1(data, size,
                                           (enum vcs_semantic_section_v1)t,
                                           section_root);
        (void)vcs_semantic_section_count_v1(
            data, size, (enum vcs_semantic_section_v1)t, &count);
        (void)vcs_semantic_section_v1_each(
            data, size, (enum vcs_semantic_section_v1)t, sm_each_noop_cb,
            NULL);
    }
    (void)vcs_semantic_manifest_v1_each(data, size, NULL, NULL);
    /* NULL cb above must fail cleanly, not crash; the real walk cb runs
     * below via sm_check_rebuild. */
    (void)vcs_semantic_absent_v1_each(data, size, sm_absent_cb, NULL);
    sm_check_facts_consistency(data, size);

    /* diff() against itself: same input twice must be exact_equal and
     * hint_equal with zero function churn, and must not crash on a second,
     * independent validate of the same bytes. */
    {
        struct vcs_semantic_diff_v1 d;
        memset(&d, 0, sizeof(d));
        if (vcs_semantic_manifest_v1_diff(data, size, data, size, &d, NULL,
                                          NULL) &&
            valid) {
            if (!d.exact_equal || !d.hint_equal || d.functions_added != 0 ||
                d.functions_removed != 0 || d.functions_changed != 0) {
                fprintf(stderr,
                        "fuzz_semantic_manifest: FINDING: diff(x, x) is not "
                        "a fixed point\n");
                __builtin_trap();
            }
        }
    }

    if (!valid)
        return 0;

    /* Property 2 and property 3 only make sense on accepted input. */
    sm_check_rebuild(data, size, root);
    sm_check_dump(data, size);

    return 0;
}
