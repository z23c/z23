/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `z23 zcode node verify` — "did I get the same bytes as the publisher,
 * produced by MY OWN machine?"
 *
 * A shopkeeper's friend across the country installs the same node. Either
 * they take the publisher's word for what is in it, or they build it
 * themselves and compare. Everything in this file exists to make the second
 * one a single command an ordinary user can type.
 *
 * ── WHAT IT REFUSES TO BE ────────────────────────────────────────────────
 * It never checks a published hash against the file it was published beside.
 * That check has one participant and proves nothing: whoever wrote the
 * artifact wrote the hash. The refusal is structural, not a convention —
 * lib/vcs/node_reproduce.c will not compare two receipts unless one carries
 * producer RECEIVED and the other producer LOCAL_REBUILD, so there is no
 * argument list that makes this command grade a publisher against
 * themselves.
 *
 * It asks no central service. The only inputs are the artifact already on
 * this disk and the source tree already in this checkout; the rebuild runs
 * with ZCL_VENDOR_OFFLINE=1 so a cache miss cannot become a download.
 *
 * ── THE THREE THINGS IT MEASURES ─────────────────────────────────────────
 *   1. the artifact you have — SHA3-256 over its bytes, and (when it is this
 *      very process's own executable) the source identity BAKED INTO it,
 *      which is directory-independent by construction
 *      (lib/util/include/util/clientversion.h);
 *   2. the artifact your machine builds — tools/scripts/node_reproduce.sh
 *      builds z23 in an isolated build dir and emits a receipt;
 *   3. the toolchain BOTH artifacts record, read the SAME way from each
 *      ELF's `.comment` section by the one implementation below. Measuring
 *      the two sides differently would make every honest build look like a
 *      toolchain mismatch, so there is deliberately only one reader.
 *
 * ── WHY THE ANSWER IS NEVER JUST "DIFFERS" ───────────────────────────────
 * A bare mismatch is useless: the user cannot tell "my gcc is newer" from
 * "this binary is not built from the source it names", and a diagnosis-free
 * red light gets ignored, which makes the whole feature worthless. The
 * comparator names which of the two it is whenever the evidence supports a
 * name, and says UNDIAGNOSED — not a guess — when it does not.
 *
 * ── WHY A PASS IS USUALLY "PARTIAL" TODAY ────────────────────────────────
 * The linked node binary is reproducible. Roughly a dozen vendored static
 * archives under vendor/lib/ are NOT rebuilt by this run at all, and one of
 * them (libsecp256k1.a) is a binary committed to the tree whose own
 * vendor/provenance manifest records source_status=legacy-import-source-
 * unresolved. The driver emits each as an `unverified` row, the comparator
 * carries them into the report, and their presence makes the verdict
 * PARTIAL rather than MATCH. That is the honest ceiling today. Quietly
 * dropping them to print a green MATCH is exactly how a verified result
 * comes to mean nothing.
 */

#include "command/native_command.h"

#include "base/hex.h"
#include "json/json.h"
#include "platform/os_proc.h"
#include "sha3/sha3.h"
#include "util/clientversion.h"
#include "util/spawn.h"
#include "vcs/node_reproduce.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define NV_CMD "zcode.node.verify"
/* The one artifact path both receipts name. The real files live at
 * different absolute paths on the two sides; the comparator pairs rows by
 * this logical name. */
#define NV_ARTIFACT_PATH "bin/z23"
/* A build of the whole node. Generous, because refusing a slow honest
 * machine is the failure this repo keeps writing down: a timeout tuned on
 * fast storage grades a seek-bound box "broken". */
#define NV_DEFAULT_TIMEOUT_S 5400
#define NV_MAX_TIMEOUT_S 43200
#define NV_COMMENT_MAX 4096u

static void nv_fail(struct zcl_command_reply *reply, const char *code,
                    const char *message, const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, "execute", false,
                           false, message, evidence ? evidence : NV_CMD);
}

static const char *nv_str(const struct json_value *in, const char *key)
{
    const struct json_value *v = in ? json_get(in, key) : NULL;
    const char *s = v ? json_get_str(v) : NULL;
    return s && s[0] ? s : NULL;
}

/* ── SHA3-256 over a whole file ─────────────────────────────────────────── */

static bool nv_file_digest(const char *path, uint8_t out[32], uint64_t *bytes)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    unsigned char buf[65536];
    uint64_t total = 0;
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        sha3_256_write(&ctx, buf, n);
        total += n;
    }
    bool ok = ferror(f) == 0;
    (void)fclose(f);
    if (!ok)
        return false;
    sha3_256_finalize(&ctx, out);
    if (bytes)
        *bytes = total;
    return true;
}

/* ── the ELF `.comment` reader ──────────────────────────────────────────
 *
 * `.comment` carries the compiler's own identity string and SURVIVES
 * `strip -s`, so it is present in the shipped artifact and in a fresh
 * local build alike — the only toolchain observable both sides really
 * have. ELF64 little-endian only; anything else yields "unknown", which
 * the comparator turns into UNDIAGNOSED rather than into a verdict it
 * cannot support. Every offset is bounds-checked against the file size:
 * this parses a file that may be hostile. */

static bool nv_read_at(FILE *f, uint64_t off, void *dst, size_t len,
                       uint64_t file_size)
{
    if (len == 0 || off > file_size || file_size - off < (uint64_t)len)
        return false;
    if (off > (uint64_t)LONG_MAX || fseek(f, (long)off, SEEK_SET) != 0)
        return false;
    return fread(dst, 1, len, f) == len;
}

static uint16_t nv_le16(const unsigned char *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t nv_le32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t nv_le64(const unsigned char *p)
{
    return (uint64_t)nv_le32(p) | ((uint64_t)nv_le32(p + 4) << 32);
}

/* Copy the raw `.comment` bytes of the ELF at `path` into `out`. Returns
 * the byte count, or 0 when the file is not an ELF64-LE or has no
 * `.comment`. */
static size_t nv_elf_comment(const char *path, unsigned char *out, size_t cap)
{
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 64)
        return 0;
    uint64_t fsz = (uint64_t)st.st_size;
    FILE *f = fopen(path, "rb");
    if (!f)
        return 0;

    size_t got = 0;
    unsigned char eh[64];
    if (!nv_read_at(f, 0, eh, sizeof(eh), fsz))
        goto done;
    if (memcmp(eh, "\x7f" "ELF", 4) != 0 || eh[4] != 2 || eh[5] != 1)
        goto done; /* not ELF64 little-endian */

    uint64_t shoff = nv_le64(eh + 0x28);
    uint16_t shentsize = nv_le16(eh + 0x3A);
    uint16_t shnum = nv_le16(eh + 0x3C);
    uint16_t shstrndx = nv_le16(eh + 0x3E);
    if (shentsize < 64 || shnum == 0 || shstrndx >= shnum)
        goto done;

    /* The section-header string table, so section names can be read. */
    unsigned char sh[64];
    if (!nv_read_at(f, shoff + (uint64_t)shstrndx * shentsize, sh, sizeof(sh),
                    fsz))
        goto done;
    uint64_t stroff = nv_le64(sh + 0x18);
    uint64_t strsz = nv_le64(sh + 0x20);
    if (strsz == 0 || strsz > (1u << 20))
        goto done;
    char *strtab = malloc((size_t)strsz + 1);
    if (!strtab)
        goto done;
    if (!nv_read_at(f, stroff, strtab, (size_t)strsz, fsz)) {
        free(strtab);
        goto done;
    }
    strtab[strsz] = '\0';

    for (uint16_t i = 0; i < shnum; i++) {
        if (!nv_read_at(f, shoff + (uint64_t)i * shentsize, sh, sizeof(sh),
                        fsz))
            break;
        uint32_t name = nv_le32(sh + 0x00);
        if (name >= strsz || strcmp(strtab + name, ".comment") != 0)
            continue;
        uint64_t off = nv_le64(sh + 0x18);
        uint64_t size = nv_le64(sh + 0x20);
        if (size == 0 || size > cap)
            break;
        if (nv_read_at(f, off, out, (size_t)size, fsz))
            got = (size_t)size;
        break;
    }
    free(strtab);

done:
    (void)fclose(f);
    return got;
}

/* Fill `hex` (65 bytes) with SHA3-256 over the ELF's `.comment` bytes and
 * `desc` with a printable rendering of them. Both become "" / "" when the
 * section is absent — an honest UNKNOWN, never a fabricated identity. */
static void nv_toolchain(const char *path, char hex[65], char *desc,
                         size_t desc_cap)
{
    hex[0] = '\0';
    if (desc && desc_cap)
        desc[0] = '\0';
    unsigned char raw[NV_COMMENT_MAX];
    size_t n = nv_elf_comment(path, raw, sizeof(raw));
    if (n == 0)
        return;
    uint8_t d[32];
    zcl_sha3_256(raw, n, d);
    zcl_hex_encode(d, 32, hex);
    if (!desc || desc_cap == 0)
        return;
    /* `.comment` is a run of NUL-separated strings. Render them separated by
     * "; " so several producers stay visible in one printable line. */
    size_t w = 0;
    for (size_t i = 0; i < n && w + 1 < desc_cap;) {
        size_t len = strnlen((const char *)raw + i, n - i);
        if (len > 0) {
            if (w > 0 && w + 2 < desc_cap) {
                desc[w++] = ';';
                desc[w++] = ' ';
            }
            for (size_t k = 0; k < len && w + 1 < desc_cap; k++) {
                unsigned char c = raw[i + k];
                desc[w++] = (c >= 0x20 && c < 0x7f) ? (char)c : '?';
            }
        }
        i += len + 1;
    }
    desc[w] = '\0';
}

/* ── the local rebuild driver ───────────────────────────────────────────── */

/* Test-only seam, precedent consensus_state_producer_receipt_test_set_identity
 * (config/include/config/consensus_state_producer_receipt.h). A test
 * substitutes a driver that writes a controlled receipt so the parse,
 * compare and render path can be proven in seconds instead of the minutes a
 * whole-program LTO link costs. There is deliberately NO input field and no
 * environment variable that reaches this: a user cannot hand this command a
 * receipt, because a receipt someone else wrote is the publisher's claim,
 * which is the one thing this command must never accept as evidence. */
static zcl_node_verify_driver_fn g_nv_driver;

void zcl_native_node_verify_test_set_driver(zcl_node_verify_driver_fn fn)
{
    g_nv_driver = fn;
}

static int nv_run_driver(const char *script, const char *source_dir,
                         const char *scratch_dir, const char *out_path,
                         const char *profile, int jobs, int timeout_s,
                         char *log, size_t log_cap)
{
    if (g_nv_driver)
        return g_nv_driver(source_dir, scratch_dir, out_path, profile, jobs);

    char a_src[PATH_MAX + 16], a_scratch[PATH_MAX + 16];
    char a_out[PATH_MAX + 16], a_profile[64], a_jobs[32];
    (void)snprintf(a_src, sizeof(a_src), "--source=%s", source_dir);
    (void)snprintf(a_scratch, sizeof(a_scratch), "--scratch=%s", scratch_dir);
    (void)snprintf(a_out, sizeof(a_out), "--out=%s", out_path);
    (void)snprintf(a_profile, sizeof(a_profile), "--profile=%s", profile);
    (void)snprintf(a_jobs, sizeof(a_jobs), "--jobs=%d", jobs);
    const char *argv[] = { script, a_src, a_scratch, a_out,
                           a_profile, a_jobs, NULL };
    return zcl_spawn_capture(argv, log, log_cap, timeout_s * 1000);
}

/* ── reply rendering ────────────────────────────────────────────────────── */

static bool nv_push_rows(struct json_value *data,
                         const struct vcs_node_repro_report *rep)
{
    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    bool ok = true;
    for (size_t i = 0; i < rep->row_count && ok; i++) {
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        ok = json_push_kv_str(&row, "artifact", rep->rows[i].path) &&
             json_push_kv_str(
                 &row, "rule",
                 vcs_node_repro_rule_string(
                     (enum vcs_node_repro_rule)rep->rows[i].rule)) &&
             json_push_kv_str(&row, "detail", rep->rows[i].detail) &&
             json_push_back(&rows, &row);
        json_free(&row);
    }
    ok = ok && json_push_kv(data, "artifacts", &rows);
    json_free(&rows);
    return ok;
}

static bool nv_push_gaps(struct json_value *data,
                         const struct vcs_node_repro_report *rep)
{
    struct json_value gaps;
    json_init(&gaps);
    json_set_array(&gaps);
    bool ok = true;
    for (size_t i = 0; i < rep->gap_count && ok; i++) {
        struct json_value g;
        json_init(&g);
        json_set_object(&g);
        ok = json_push_kv_str(&g, "component", rep->gaps[i].component) &&
             json_push_kv_str(&g, "reason", rep->gaps[i].reason) &&
             json_push_back(&gaps, &g);
        json_free(&g);
    }
    ok = ok && json_push_kv(data, "unverified", &gaps);
    json_free(&gaps);
    return ok;
}

static bool nv_push_receipt(struct json_value *data, const char *key,
                            const struct vcs_node_receipt *r,
                            const char *real_path)
{
    struct json_value o;
    json_init(&o);
    json_set_object(&o);
    char hex[65] = "";
    if (r->artifact_count > 0)
        zcl_hex_encode(r->artifacts[0].sha3, 32, hex);
    bool ok =
        json_push_kv_str(
            &o, "producer",
            vcs_node_producer_string((enum vcs_node_producer)r->producer)) &&
        json_push_kv_str(&o, "path", real_path ? real_path : "") &&
        json_push_kv_str(&o, "sha3_256", hex) &&
        json_push_kv_int(&o, "bytes",
                         r->artifact_count > 0
                             ? (int64_t)r->artifacts[0].bytes
                             : 0) &&
        json_push_kv_str(&o, "source_id",
                         r->source_id[0] ? r->source_id : "unknown") &&
        json_push_kv_str(&o, "toolchain_id",
                         r->toolchain_id[0] ? r->toolchain_id : "unknown") &&
        json_push_kv_str(&o, "toolchain", r->toolchain_desc) &&
        json_push_kv(data, key, &o);
    json_free(&o);
    return ok;
}

/* What the user should do next, in plain words, for each verdict. A red
 * light nobody can act on is a red light everybody learns to ignore. */
static const char *nv_advice(enum vcs_node_repro_verdict v)
{
    switch (v) {
    case VCS_NODE_REPRO_MATCH:
        return "the bytes you are running are the bytes your own machine "
               "builds from this source. You did not have to trust the "
               "publisher, and you did not have to trust whoever wrote the "
               "code either.";
    case VCS_NODE_REPRO_PARTIAL:
        return "every artifact this machine could rebuild is byte-identical. "
               "The components listed under `unverified` were NOT rebuilt "
               "here and are NOT covered by that; read them before treating "
               "this as a full verification.";
    case VCS_NODE_REPRO_SOURCE_DIFFERS:
        return "this checkout is not the source that binary was built from, "
               "so nothing has been shown about the publisher yet. Check out "
               "the source identity the binary names and run this again.";
    case VCS_NODE_REPRO_TOOLCHAIN_DIFFERS:
        return "your compiler differs from the publisher's, which is the "
               "ordinary reason two honest builds of one source differ. This "
               "is NOT evidence against the publisher. To settle it, build "
               "with the toolchain named under `received.toolchain`.";
    case VCS_NODE_REPRO_CLAIM_FALSE:
        return "same source, same recorded toolchain, different bytes. Every "
               "input the publisher declared agrees with yours and the output "
               "does not, so the artifact you were given is not what this "
               "source and toolchain produce. Do not dismiss this; publish "
               "the two hashes and ask other people to run the same command.";
    case VCS_NODE_REPRO_UNDIAGNOSED:
        return "the bytes differ and the evidence does not say why. Rather "
               "than guess between a toolchain gap and a bad artifact, this "
               "reports neither. Supply the missing identity (see `detail`) "
               "and run it again.";
    case VCS_NODE_REPRO_NO_ARTIFACTS:
        return "nothing was compared, so nothing was verified. This is not a "
               "pass.";
    case VCS_NODE_REPRO_NOT_LOCAL:
        return "refused: one side must be the artifact you received and the "
               "other must be bytes this machine built. Comparing a "
               "publisher's hash with the publisher's hash proves nothing.";
    case VCS_NODE_REPRO_UNEVALUATED:
    case VCS_NODE_REPRO_RECEIPT_INVALID:
        break;
    }
    return "no verdict was reached; treat this as unverified.";
}

/* ── the handler ────────────────────────────────────────────────────────── */

struct nv_ctx {
    char artifact[PATH_MAX];
    char source_dir[PATH_MAX];
    char scratch[PATH_MAX];
    char receipt_path[PATH_MAX];
    char rebuilt_path[PATH_MAX];
    char script[PATH_MAX];
    const char *profile;
    int jobs;
    int timeout_s;
    bool artifact_is_self;
};

/* Resolve every path and policy input, or name the refusal. */
static bool nv_resolve(const struct zcl_command_request *request,
                       struct zcl_command_reply *reply, struct nv_ctx *c)
{
    memset(c, 0, sizeof(*c));
    const struct json_value *in = request->input;

    char self[PATH_MAX] = "";
    bool have_self = os_proc_exe_path(self, sizeof(self));
    const char *artifact = nv_str(in, "artifact");
    if (!artifact) {
        if (!have_self) {
            nv_fail(reply, "ARTIFACT_UNRESOLVED",
                    "this platform did not report this process's own "
                    "executable path; pass artifact=<path> naming the node "
                    "binary you want checked",
                    NULL);
            return false;
        }
        artifact = self;
    }
    if (!realpath(artifact, c->artifact)) {
        nv_fail(reply, "ARTIFACT_MISSING",
                "that artifact path does not resolve to a file on this disk",
                artifact);
        return false;
    }
    /* The source identity baked into an executable is readable only for the
     * executable THIS process is running. For any other file we say so
     * rather than executing it to ask — running an artifact whose
     * provenance is exactly what is in question is not a verification
     * step. */
    c->artifact_is_self = have_self && strcmp(c->artifact, self) == 0;

    const char *src = nv_str(in, "source_dir");
    char cwd[PATH_MAX];
    if (!src && getcwd(cwd, sizeof(cwd)))
        src = cwd;
    if (!src || !realpath(src, c->source_dir)) {
        nv_fail(reply, "NO_SOURCE_TREE",
                "pass source_dir=<path to a z23 checkout>: rebuilding is the "
                "whole check, and without source there is nothing to rebuild",
                src ? src : "");
        return false;
    }
    int n = snprintf(c->script, sizeof(c->script),
                     "%s/tools/scripts/node_reproduce.sh", c->source_dir);
    if (n <= 0 || (size_t)n >= sizeof(c->script) ||
        (!g_nv_driver && access(c->script, X_OK) != 0)) {
        nv_fail(reply, "NO_SOURCE_TREE",
                "that directory has no executable "
                "tools/scripts/node_reproduce.sh, so it is not a z23 "
                "checkout this command can rebuild from",
                c->source_dir);
        return false;
    }

    const char *scratch = nv_str(in, "scratch_dir");
    if (scratch) {
        n = snprintf(c->scratch, sizeof(c->scratch), "%s", scratch);
    } else {
        const char *home = getenv("HOME");
        if (!home || !home[0]) {
            nv_fail(reply, "NO_SCRATCH_DIR",
                    "no scratch_dir was given and HOME is unset, so there is "
                    "nowhere to put an isolated build tree", NULL);
            return false;
        }
        n = snprintf(c->scratch, sizeof(c->scratch),
                     "%s/.local/state/zclassic23/scratch/node-verify", home);
    }
    if (n <= 0 || (size_t)n >= sizeof(c->scratch)) {
        nv_fail(reply, "SCRATCH_PATH_TOO_LONG",
                "the scratch directory path is too long", c->scratch);
        return false;
    }
    (void)snprintf(c->receipt_path, sizeof(c->receipt_path),
                   "%s/rebuild.receipt", c->scratch);
    (void)snprintf(c->rebuilt_path, sizeof(c->rebuilt_path),
                   "%s/build/bin/z23", c->scratch);

    const char *profile = nv_str(in, "profile");
    if (!profile)
        profile = "default";
    if (strcmp(profile, "default") != 0 && strcmp(profile, "release") != 0) {
        nv_fail(reply, "BAD_PROFILE",
                "profile must be 'default' (what make z23 builds) or "
                "'release' (the tools/release.sh flag profile)", profile);
        return false;
    }
    c->profile = profile;

    const struct json_value *jv = in ? json_get(in, "jobs") : NULL;
    long jobs = jv ? (long)json_get_int(jv) : 0;
    if (jobs <= 0)
        jobs = (long)sysconf(_SC_NPROCESSORS_ONLN);
    if (jobs <= 0)
        jobs = 4;
    if (jobs > 4096)
        jobs = 4096;
    c->jobs = (int)jobs;

    const struct json_value *tv = in ? json_get(in, "timeout_seconds") : NULL;
    long secs = tv ? (long)json_get_int(tv) : 0;
    if (secs <= 0)
        secs = NV_DEFAULT_TIMEOUT_S;
    if (secs > NV_MAX_TIMEOUT_S)
        secs = NV_MAX_TIMEOUT_S;
    c->timeout_s = (int)secs;
    return true;
}

/* Read the receipt the driver wrote. Bounded; a receipt this build cannot
 * fully parse is a refusal, never a partial parse. */
static bool nv_load_receipt(const char *path, struct vcs_node_receipt *out,
                            char *why, size_t why_cap)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        (void)snprintf(why, why_cap, "no receipt at %s (%s)", path,
                       strerror(errno));
        return false;
    }
    static char text[VCS_NODE_REPRO_MAX_WIRE_BYTES + 1];
    size_t n = fread(text, 1, sizeof(text) - 1, f);
    bool over = fread(text + n, 1, 1, f) == 1;
    (void)fclose(f);
    if (over) {
        (void)snprintf(why, why_cap, "receipt exceeds %u bytes",
                       (unsigned)VCS_NODE_REPRO_MAX_WIRE_BYTES);
        return false;
    }
    return vcs_node_receipt_decode(text, n, out, why, why_cap);
}

void zcl_native_handle_zcode_node_verify(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    struct nv_ctx c;
    if (!nv_resolve(request, reply, &c))
        return;

    /* ── 1. the artifact the user HAS ─────────────────────────────────── */
    struct vcs_node_receipt received;
    memset(&received, 0, sizeof(received));
    received.producer = VCS_NODE_PRODUCER_RECEIVED;
    received.artifact_count = 1;
    (void)snprintf(received.artifacts[0].path,
                   sizeof(received.artifacts[0].path), "%s",
                   NV_ARTIFACT_PATH);
    if (!nv_file_digest(c.artifact, received.artifacts[0].sha3,
                        &received.artifacts[0].bytes)) {
        nv_fail(reply, "ARTIFACT_UNREADABLE",
                "the artifact could not be read end to end, so its bytes "
                "cannot be hashed", c.artifact);
        return;
    }
    if (c.artifact_is_self) {
        const char *sid = zcl_build_source_id_sha256();
        if (sid && strlen(sid) == 64)
            (void)snprintf(received.source_id, sizeof(received.source_id),
                           "%s", sid);
    }
    nv_toolchain(c.artifact, received.toolchain_id, received.toolchain_desc,
                 sizeof(received.toolchain_desc));

    /* ── 2. the bytes THIS machine builds ─────────────────────────────── */
    static char log[8192];
    log[0] = '\0';
    (void)remove(c.receipt_path);
    int rc = nv_run_driver(c.script, c.source_dir, c.scratch, c.receipt_path,
                           c.profile, c.jobs, c.timeout_s, log, sizeof(log));
    if (rc != 0) {
        char msg[512];
        (void)snprintf(msg, sizeof(msg),
                       "the local rebuild did not complete (driver exit %d); "
                       "nothing was compared, so nothing is verified", rc);
        nv_fail(reply, "REBUILD_FAILED", msg, c.scratch);
        return;
    }

    struct vcs_node_receipt rebuilt;
    char why[256] = "";
    if (!nv_load_receipt(c.receipt_path, &rebuilt, why, sizeof(why))) {
        nv_fail(reply, "REBUILD_RECEIPT_INVALID",
                why[0] ? why : "the rebuild receipt could not be read",
                c.receipt_path);
        return;
    }
    /* The toolchain of the REBUILT artifact is measured here, by the same
     * reader that measured the received one, unless the receipt already
     * carried one. Two different measurements would make every honest build
     * look like a toolchain mismatch. */
    if (!rebuilt.toolchain_id[0])
        nv_toolchain(c.rebuilt_path, rebuilt.toolchain_id, NULL, 0);

    /* ── 3. the verdict ───────────────────────────────────────────────── */
    struct vcs_node_repro_report rep;
    bool full_match = vcs_node_reproduce_compare(&received, &rebuilt, &rep);
    enum vcs_node_repro_verdict verdict =
        (enum vcs_node_repro_verdict)rep.verdict;

    struct json_value *data = &reply->data;
    bool ok =
        json_push_kv_str(data, "verdict",
                         vcs_node_repro_verdict_string(verdict)) &&
        json_push_kv_bool(data, "bytes_match", full_match) &&
        json_push_kv_bool(data, "fully_verified",
                          verdict == VCS_NODE_REPRO_MATCH) &&
        /* THE ENVELOPE IS NOT THE VERDICT. `status:PASSED` on this leaf means
         * the check RAN — the registry drops the whole `data` object on any
         * other status (command_registry.c:2158-2164), and a mismatch whose
         * diagnosis was thrown away is the useless bare red light this
         * command exists to replace. Read `verdict`. `partial` is NOT a
         * pass. */
        json_push_kv_str(
            data, "status_means",
            "the envelope status says this check ran to completion; it is "
            "NOT the verdict. Read `verdict`: only `match` is a full pass, "
            "and `partial` is not a pass") &&
        json_push_kv_str(data, "detail", rep.detail) &&
        json_push_kv_str(data, "means", nv_advice(verdict)) &&
        nv_push_receipt(data, "received", &received, c.artifact) &&
        nv_push_receipt(data, "rebuilt", &rebuilt, c.rebuilt_path) &&
        json_push_kv_bool(data, "source_identity_known", rep.source_id_known) &&
        json_push_kv_bool(data, "source_identity_agrees",
                          rep.source_id_agrees) &&
        json_push_kv_bool(data, "toolchain_known", rep.toolchain_known) &&
        json_push_kv_bool(data, "toolchain_agrees", rep.toolchain_agrees) &&
        json_push_kv_int(data, "artifacts_compared", (int64_t)rep.compared) &&
        json_push_kv_int(data, "artifacts_matched", (int64_t)rep.matched) &&
        json_push_kv_int(data, "artifacts_differed", (int64_t)rep.differed) &&
        json_push_kv_int(data, "unverified_count",
                         (int64_t)rep.unverified) &&
        nv_push_rows(data, &rep) && nv_push_gaps(data, &rep) &&
        json_push_kv_str(data, "profile", c.profile) &&
        json_push_kv_str(data, "source_dir", c.source_dir) &&
        json_push_kv_str(data, "scratch_dir", c.scratch) &&
        json_push_kv_bool(data, "artifact_is_this_process",
                          c.artifact_is_self) &&
        json_push_kv_str(
            data, "scope",
            "this compares the artifact named under `received` against bytes "
            "built here from `source_dir`. It asked no server, and it never "
            "checked a published hash against the file it was published "
            "beside. Components listed under `unverified` were not rebuilt "
            "and are NOT covered by the verdict.") &&
        json_push_kv_bool(data, "github_contacted", false);

    if (!c.artifact_is_self)
        ok = ok && json_push_kv_str(
                       data, "source_identity_note",
                       "the source identity baked into an executable is "
                       "readable only for the one this process is running; "
                       "for any other file it stays unknown, because "
                       "executing an artifact to ask what it is made of is "
                       "not a verification step");

    if (!ok) {
        nv_fail(reply, "VERIFY_REPLY_REFUSED",
                "the verify reply object refused a field", c.artifact);
        return;
    }

    /* No `next` is emitted on purpose. Every gap this check did not cover is
     * already IN this reply, under `unverified`, by value — a follow-up
     * command the user has to remember to run is a gap they will not see. */
}
