/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Content addressing, receipt JSON and the receipt store of the
 * one-file lab.
 *
 * A root is the SHA3-512 of length-prefixed fields: for each field the tag,
 * a zero byte, the 64-bit little-endian length, then the bytes. The same
 * source and the same canonical inputs always give the same root. */
#include "command/lab.h"

#include "base/hex.h"
#include "base/serialize_le.h"
#include "base/safe_alloc.h"
#include "sha3/sha3.h"
#include "util/write_all.h"
#include "util/path_util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
    LAB_STDOUT_ESCAPED = 20000,
    LAB_STDERR_ESCAPED = 12000,
    LAB_TAIL_ESCAPED = 6144,
    LAB_RECEIPT_MAX = 64 * 1024,
};

struct lab_hasher {
    struct sha3_512_ctx ctx;
};

struct lab_hasher *lab_hasher_new(const char *kind)
{
    struct lab_hasher *h = zcl_malloc(sizeof(*h), "lab.hasher");
    if (!h)
        return NULL;
    sha3_512_init(&h->ctx);
    lab_hasher_field(h, "z23.lab.v2", kind, strlen(kind));
    return h;
}

void lab_hasher_field(struct lab_hasher *h, const char *tag, const void *data,
                      size_t len)
{
    unsigned char le[8];
    zcl_write_u64_le(le, (uint64_t)len);
    sha3_512_write(&h->ctx, (const unsigned char *)tag, strlen(tag) + 1);
    sha3_512_write(&h->ctx, le, sizeof(le));
    if (len)
        sha3_512_write(&h->ctx, (const unsigned char *)data, len);
}

void lab_hasher_u64(struct lab_hasher *h, const char *tag, uint64_t v)
{
    unsigned char le[8];
    zcl_write_u64_le(le, v);
    lab_hasher_field(h, tag, le, sizeof(le));
}

void lab_hasher_finish(struct lab_hasher *h, char hex[LAB_ROOT_HEX + 1])
{
    unsigned char digest[SHA3_512_OUTPUT_SIZE];
    sha3_512_finalize(&h->ctx, digest);
    zcl_hex_encode(digest, sizeof(digest), hex);
    free(h);
}

/* ── receipt store ──────────────────────────────────────────────────── */

bool lab_root_valid(const char *root)
{
    return zcl_is_lower_hex(root, LAB_ROOT_HEX);
}

static bool lab_receipt_path(const struct lab_dirs *d, const char *root,
                             const char *suffix, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/%s%s", d->receipts, root, suffix);
    return lab_root_valid(root) && n > 0 && (size_t)n < cap;
}

bool lab_receipt_store(const struct lab_dirs *d, const char *root,
                       const struct json_value *receipt)
{
    char path[LAB_PATH], tmp[LAB_PATH + 24];
    size_t need = json_write(receipt, NULL, 0);
    char *buf = need < LAB_RECEIPT_MAX ? zcl_malloc(need + 1, "lab.receipt")
                                       : NULL;
    if (!buf || !lab_receipt_path(d, root, ".json", path, sizeof(path))) {
        free(buf);
        return false;
    }
    (void)json_write(receipt, buf, need + 1);
    snprintf(tmp, sizeof(tmp), "%s.%ld.tmp", path, (long)getpid());
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    bool ok = fd >= 0 && zcl_write_all(fd, buf, need);
    if (fd >= 0)
        ok = close(fd) == 0 && ok;
    ok = ok && rename(tmp, path) == 0;
    if (!ok)
        (void)unlink(tmp);
    free(buf);
    return ok;
}

bool lab_receipt_load(const struct lab_dirs *d, const char *root,
                      struct json_value *receipt)
{
    char path[LAB_PATH];
    if (!lab_receipt_path(d, root, ".json", path, sizeof(path)))
        return false;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    char *buf = fd >= 0 ? zcl_malloc(LAB_RECEIPT_MAX + 1, "lab.load") : NULL;
    ssize_t n = buf ? read(fd, buf, LAB_RECEIPT_MAX) : -1;
    if (fd >= 0)
        close(fd);
    bool ok = n > 0 && json_read(receipt, buf, (size_t)n);
    free(buf);
    return ok;
}

/* ── presentation ───────────────────────────────────────────────────── */

static size_t lab_utf8_need(unsigned char lead)
{
    if (lead < 0x80)
        return 1;
    if ((lead >> 5) == 6)
        return 2;
    if ((lead >> 4) == 14)
        return 3;
    return (lead >> 3) == 30 ? 4 : 0;
}

/* The code point of a sequence whose continuation bytes are checked. */
static uint32_t lab_utf8_point(const unsigned char *s, size_t need)
{
    uint32_t cp = need == 2 ? s[0] & 0x1fu : need == 3 ? s[0] & 0x0fu
                                                        : s[0] & 0x07u;
    for (size_t i = 1; i < need; i++)
        cp = (cp << 6) | (s[i] & 0x3fu);
    return cp;
}

/* Length of a well-formed UTF-8 sequence at s, or 0 when ill-formed:
 * truncated, overlong, a surrogate, or beyond U+10FFFF. */
static size_t lab_utf8_len(const unsigned char *s, size_t left)
{
    static const uint32_t least[] = { 0, 0, 0x80, 0x800, 0x10000 };
    size_t need = lab_utf8_need(s[0]);
    if (need == 0 || need > left)
        return 0;
    for (size_t i = 1; i < need; i++)
        if ((s[i] & 0xc0) != 0x80)
            return 0;
    if (need == 1)
        return 1;
    uint32_t cp = lab_utf8_point(s, need);
    bool surrogate = cp >= 0xd800 && cp <= 0xdfff;
    return cp >= least[need] && cp <= 0x10ffff && !surrogate ? need : 0;
}

static size_t lab_escaped_cost(unsigned char c)
{
    return (c == '"' || c == '\\' || c == '\n' || c == '\r' || c == '\t') ? 2 : 1;
}

/* Append one input unit to out; returns bytes consumed, or 0 at the cap. */
static size_t lab_text_unit(const unsigned char *s, size_t left, char *out,
                            size_t *olen, size_t *cost, size_t cap)
{
    static const char repl[] = "\xef\xbf\xbd";
    size_t n = lab_utf8_len(s, left);
    bool plain = n == 1 && (s[0] >= 0x20 || s[0] == '\n' || s[0] == '\r' ||
                            s[0] == '\t') && s[0] != 0x7f;
    size_t add = plain ? lab_escaped_cost(s[0]) : n > 1 ? n : 3;
    if (*cost + add > cap)
        return 0;
    if (plain || n > 1)
        memcpy(out + *olen, s, n);
    else
        memcpy(out + *olen, repl, 3);
    *olen += plain || n > 1 ? n : 3;
    *cost += add;
    return n ? n : 1;
}

bool lab_json_text(struct json_value *obj, const char *key, const char *text,
                   size_t len, size_t escaped_cap, bool *cut)
{
    char *out = zcl_malloc(escaped_cap * 3 + 8, "lab.text");
    size_t olen = 0, cost = 0, i = 0;
    if (!out)
        return false;
    while (i < len) {
        size_t used = lab_text_unit((const unsigned char *)text + i, len - i,
                                    out, &olen, &cost, escaped_cap);
        if (used == 0) {
            *cut = true;
            break;
        }
        i += used;
    }
    out[olen] = '\0';
    bool ok = json_push_kv_str(obj, key, out);
    free(out);
    return ok;
}

/* ── receipt sections ───────────────────────────────────────────────── */

static bool lab_json_diag(struct json_value *rows, const struct lab_diag *d)
{
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    bool ok = json_push_kv_int(&row, "line", d->line) &&
              json_push_kv_int(&row, "col", d->col) &&
              json_push_kv_str(&row, "severity", d->severity) &&
              json_push_kv_str(&row, "message", d->message) &&
              json_push_back(rows, &row);
    json_free(&row);
    return ok;
}

bool lab_json_compile(struct json_value *out, const struct lab_compile *c)
{
    struct json_value rows;
    bool cut = false;
    json_init(&rows);
    json_set_array(&rows);
    bool ok = true;
    for (size_t i = 0; ok && i < c->n_diag; i++)
        ok = lab_json_diag(&rows, &c->diag[i]);
    json_set_object(out);
    ok = ok && json_push_kv_bool(out, "ok", c->ok) &&
         json_push_kv_int(out, "wall_us", c->wall_us) &&
         json_push_kv(out, "diagnostics", &rows) &&
         lab_json_text(out, "raw_tail", c->tail, strlen(c->tail),
                       LAB_TAIL_ESCAPED, &cut) &&
         json_push_kv_str(out, "detail", c->detail);
    json_free(&rows);
    return ok;
}

static bool lab_run_numbers(struct json_value *out, const struct lab_proc *p,
                            bool ran)
{
    return json_push_kv_bool(out, "ran", ran) &&
           json_push_kv_int(out, "exit_code", ran ? p->exit_code : -1) &&
           json_push_kv_int(out, "signal", ran ? p->term_signal : 0) &&
           json_push_kv_str(out, "signal_name",
                            ran ? lab_signal_name(p->term_signal) : "") &&
           json_push_kv_bool(out, "timed_out", ran && p->timed_out) &&
           json_push_kv_bool(out, "disk_exceeded", ran && p->disk_exceeded) &&
           json_push_kv_int(out, "wall_us", ran ? p->wall_us : 0) &&
           json_push_kv_int(out, "max_rss_kb", ran ? p->max_rss_kb : 0);
}

bool lab_json_run(struct json_value *out, const struct lab_proc *p, bool ran,
                  bool *cut_out)
{
    bool out_cut = ran && p->out_cut, err_cut = ran && p->err_cut;
    json_set_object(out);
    bool ok = lab_run_numbers(out, p, ran) &&
              lab_json_text(out, "stdout", ran ? p->out : "",
                            ran ? p->out_len : 0, LAB_STDOUT_ESCAPED, &out_cut) &&
              json_push_kv_bool(out, "stdout_truncated", out_cut) &&
              lab_json_text(out, "stderr", ran ? p->err : "",
                            ran ? p->err_len : 0, LAB_STDERR_ESCAPED, &err_cut) &&
              json_push_kv_bool(out, "stderr_truncated", err_cut);
    if (cut_out)
        *cut_out = out_cut || err_cut;
    return ok;
}

bool lab_json_sanitizer(struct json_value *out, const struct lab_compile *c,
                        bool requested, size_t findings, const char *first)
{
    const char *status = c->sanitized ? "enabled"
                       : c->sanitizers_unavailable ? "unavailable"
                       : (requested && !c->ok) ? "not_built" : "disabled";
    bool cut = false;
    json_set_object(out);
    return json_push_kv_bool(out, "enabled", c->sanitized) &&
           json_push_kv_str(out, "status", status) &&
           json_push_kv_int(out, "findings", (int64_t)findings) &&
           lab_json_text(out, "first", first, strlen(first), LAB_FIRST_MAX,
                         &cut);
}

bool lab_json_confinement(struct json_value *out, bool applied, bool pidns)
{
    json_set_object(out);
    return json_push_kv_bool(out, "landlock", applied) &&
           json_push_kv_bool(out, "pidns", applied && pidns) &&
           json_push_kv_int(out, "landlock_abi", applied ? lab_landlock_abi() : 0) &&
           json_push_kv_bool(out, "seccomp", applied) &&
           json_push_kv_bool(out, "no_new_privs", applied) &&
           json_push_kv_str(out, "network", "denied") &&
           json_push_kv_str(out, "filesystem", "private workdir") &&
           json_push_kv_str(out, "processes", "no fork; threads only") &&
           json_push_kv_str(out, "signals",
                            applied && pidns ? "own PID namespace"
                                             : "own process only (seccomp)");
}

size_t lab_scan_sanitizer(const char *text, size_t len, char *first, size_t cap)
{
    static const char *const marks[] = {
        "runtime error:", "ERROR: AddressSanitizer",
        "ERROR: UndefinedBehaviorSanitizer",
    };
    size_t count = 0, at = len;
    first[0] = '\0';
    for (size_t m = 0; m < sizeof(marks) / sizeof(marks[0]); m++) {
        size_t mlen = strlen(marks[m]);
        for (size_t i = 0; i + mlen <= len; i++) {
            if (memcmp(text + i, marks[m], mlen) != 0)
                continue;
            count++;
            if (i < at)
                at = i;
        }
    }
    if (count == 0)
        return 0;
    while (at > 0 && text[at - 1] != '\n')
        at--;
    size_t n = len - at < cap - 1 ? len - at : cap - 1;
    memcpy(first, text + at, n);
    first[n] = '\0';
    return count;
}
