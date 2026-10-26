/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Validate and project lint receipt chains for dev.fleet. */

#include "command/native_dev_fleet.h"
#include "command/native_dev_fleet_internal.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "platform/directory_compat.h"
#include "sha3/sha3.h"
#include "util/path_util.h"

#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLEET_RECEIPT_MAX (64u * 1024u)
#define FLEET_LOG_MAX (16u * 1024u * 1024u)
#define FLEET_RECEIPT_FILES_MAX 4096u
#define FLEET_GATE_MAX 256u

struct fleet_receipt {
    unsigned long long index;
    char file[256];
    char whole_sha[65];
    char prev_sha[65];
    char gate[64];
    char branch[256];
    char head[65];
    char head_after[65];
    char status_sha[65];
    char diff_sha[65];
    char output[256];
    char output_sha[65];
    char verdict[16];
    char worktree[ZCL_FLEET_PATH_MAX];
    unsigned long exit_status;
    unsigned long expect_missing;
    unsigned long forbid_present;
};

struct fleet_gate {
    char name[96];
    bool red;
    bool current;
    char since[65];
};

static void fleet_reason(char *why, size_t cap, const char *message)
{
    if (why && cap) (void)snprintf(why, cap, "%s", message);
}

static void fleet_hash(const void *data, size_t len, char out[65])
{
    unsigned char digest[32];
    sha3_256((const unsigned char *)data, len, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
}

static bool fleet_hash_file(const char *path, char out[65])
{
    FILE *file = fopen(path, "rb");
    if (!file) return false;
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    unsigned char buffer[8192];
    bool ok = true;
    size_t total = 0;
    for (;;) {
        size_t got = fread(buffer, 1, sizeof(buffer), file);
        if (got) {
            if (total > FLEET_LOG_MAX - got) { ok = false; break; }
            total += got;
            sha3_256_write(&hash, buffer, got);
        }
        if (got < sizeof(buffer)) {
            if (ferror(file)) ok = false;
            break;
        }
    }
    if (fclose(file) != 0) ok = false;
    if (!ok) return false;
    unsigned char digest[32];
    sha3_256_finalize(&hash, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
    return true;
}

static bool fleet_suffix(const char *text, const char *suffix)
{
    size_t a = strlen(text), b = strlen(suffix);
    return a >= b && strcmp(text + a - b, suffix) == 0;
}

static bool fleet_lower_hex(const char *text, size_t length)
{
    if (!text || strlen(text) != length) return false;
    for (size_t i = 0; i < length; i++)
        if (!isdigit((unsigned char)text[i]) &&
            !(text[i] >= 'a' && text[i] <= 'f')) return false;
    return true;
}

static bool fleet_field(const char *body, const char *key,
                        char *out, size_t cap)
{
    size_t key_len = strlen(key);
    const char *line = body;
    while (*line) {
        const char *end = strchr(line, '\n');
        size_t len = end ? (size_t)(end - line) : strlen(line);
        if (len > key_len && memcmp(line, key, key_len) == 0 &&
            line[key_len] == '=') {
            size_t value_len = len - key_len - 1;
            if (value_len + 1 > cap) return false;
            memcpy(out, line + key_len + 1, value_len);
            out[value_len] = 0;
            return true;
        }
        if (!end) break;
        line = end + 1;
    }
    return false;
}

/* Plain unsigned decimal: 1..20 ASCII digits and nothing else, no sign, no
 * space, no empty value, and not above max. *out is written only on success. */
static bool fleet_decimal(const char *text, unsigned long long max,
                          unsigned long long *out)
{
    size_t length = strlen(text);
    if (length < 1u || length > 20u) return false;
    unsigned long long value = 0;
    for (size_t i = 0; i < length; i++) {
        if (text[i] < '0' || text[i] > '9') return false;
        unsigned digit = (unsigned)(text[i] - '0');
        if (value > (ULLONG_MAX - digit) / 10u) return false;
        value = value * 10u + digit;
    }
    if (value > max) return false;
    *out = value;
    return true;
}

/* Slurps one receipt file into a NUL-terminated heap buffer; NULL when the
 * path cannot be joined or opened, the buffer cannot be allocated, or the
 * read fails or exceeds the receipt limit. */
static char *fleet_receipt_load(const char *dir, const char *name,
                                size_t *len_out)
{
    char path[ZCL_FLEET_PATH_MAX];
    bool joined = zcl_path_join(path, sizeof(path), dir, name);
    if (!joined) return NULL;
    FILE *file = fopen(path, "rb");
    if (!file) return NULL;
    char *raw = zcl_malloc(FLEET_RECEIPT_MAX + 1u, "fleet_receipt");
    if (!raw) { (void)fclose(file); return NULL; }
    size_t len = fread(raw, 1, FLEET_RECEIPT_MAX + 1u, file);
    bool ok = !ferror(file) && len <= FLEET_RECEIPT_MAX;
    if (fclose(file) != 0) ok = false;
    if (!ok) { free(raw); return NULL; }
    raw[len] = 0;
    *len_out = len;
    return raw;
}

/* Points at the last receipt_sha3= that starts a line; NULL when the seal
 * is missing or sits at the very first byte. */
static const char *fleet_receipt_find_seal(const char *raw)
{
    const char *seal = NULL;
    for (const char *p = raw; (p = strstr(p, "receipt_sha3=")) != NULL; p++) {
        if (p == raw || p[-1] == '\n') seal = p;
    }
    if (!seal || seal == raw || seal[-1] != '\n') return NULL;
    return seal;
}

/* The seal line must hold exactly the digest, with one optional newline. */
static bool fleet_receipt_seal_tail_ok(const char *raw, size_t len,
                                       const char *seal)
{
    const char *seal_value = seal + strlen("receipt_sha3=");
    size_t seal_tail = len - (size_t)(seal_value - raw);
    return seal_tail == 64u ||
           (seal_tail == 65u && seal_value[64] == '\n');
}

/* The seal's declared digest must be lowercase hex and match the hash of
 * everything before the seal line. */
static bool fleet_receipt_seal_digest_ok(const char *raw, const char *seal)
{
    char declared[65];
    char body_sha[65];
    bool declared_ok = fleet_field(seal, "receipt_sha3", declared,
                                   sizeof(declared)) &&
                       fleet_lower_hex(declared, 64);
    if (!declared_ok) return false;
    fleet_hash(raw, (size_t)(seal - raw), body_sha);
    return strcmp(body_sha, declared) == 0;
}

/* Reads every receipt field, in chain order, into the receipt and the four
 * numeric texts; false as soon as one is missing or too long. */
static bool fleet_receipt_read_fields(const char *raw,
                                      struct fleet_receipt *receipt,
                                      char *index_text, char *exit_text,
                                      char *expect_text, char *forbid_text)
{
    const struct {
        const char *key;
        char *dest;
        size_t cap;
    } fields[] = {
        {"chain_index", index_text, 32},
        {"prev_receipt_sha3", receipt->prev_sha, sizeof(receipt->prev_sha)},
        {"gate", receipt->gate, sizeof(receipt->gate)},
        {"branch", receipt->branch, sizeof(receipt->branch)},
        {"worktree_path", receipt->worktree, sizeof(receipt->worktree)},
        {"head_sha", receipt->head, sizeof(receipt->head)},
        {"head_sha_after", receipt->head_after, sizeof(receipt->head_after)},
        {"tree_status_sha3", receipt->status_sha, sizeof(receipt->status_sha)},
        {"tree_diff_sha3_after", receipt->diff_sha, sizeof(receipt->diff_sha)},
        {"output_path", receipt->output, sizeof(receipt->output)},
        {"output_sha3", receipt->output_sha, sizeof(receipt->output_sha)},
        {"verdict", receipt->verdict, sizeof(receipt->verdict)},
        {"exit_status", exit_text, 32},
        {"expect_missing", expect_text, 32},
        {"forbid_present", forbid_text, 32},
    };
    bool ok = true;
    for (size_t i = 0; ok && i < sizeof(fields) / sizeof(fields[0]); i++)
        ok = fleet_field(raw, fields[i].key, fields[i].dest, fields[i].cap);
    return ok;
}

/* Parses the four numeric texts; each value is written only when its own
 * text is a plain decimal within range. */
static bool fleet_receipt_parse_numbers(const char *index_text,
                                        const char *exit_text,
                                        const char *expect_text,
                                        const char *forbid_text,
                                        unsigned long long *index_value,
                                        unsigned long long *exit_value,
                                        unsigned long long *expect_value,
                                        unsigned long long *forbid_value)
{
    return fleet_decimal(index_text, ULLONG_MAX, index_value) &&
           fleet_decimal(exit_text, ULONG_MAX, exit_value) &&
           fleet_decimal(expect_text, ULONG_MAX, expect_value) &&
           fleet_decimal(forbid_text, ULONG_MAX, forbid_value);
}

/* head_sha is a short or full lowercase digest and prev_receipt_sha3 is
 * either GENESIS or a full digest. */
static bool fleet_receipt_head_shapes_ok(const struct fleet_receipt *receipt)
{
    bool head_ok = fleet_lower_hex(receipt->head, 40) ||
                   fleet_lower_hex(receipt->head, 64);
    bool prev_ok = strcmp(receipt->prev_sha, "GENESIS") == 0 ||
                   fleet_lower_hex(receipt->prev_sha, 64);
    return head_ok && prev_ok;
}

/* output_path is a bare filename and output_sha3 a full digest. */
static bool fleet_receipt_output_ok(const struct fleet_receipt *receipt)
{
    return !strchr(receipt->output, '/') &&
           !strchr(receipt->output, '\\') &&
           fleet_lower_hex(receipt->output_sha, 64);
}

/* The numbers parsed, head_sha equals head_sha_after, every digest field is
 * well formed and the branch is non-empty. */
static bool fleet_receipt_fields_consistent(const struct fleet_receipt *receipt,
                                            bool numbers_ok)
{
    bool shapes_ok = fleet_receipt_head_shapes_ok(receipt);
    return numbers_ok &&
           strcmp(receipt->head, receipt->head_after) == 0 &&
           shapes_ok &&
           fleet_lower_hex(receipt->status_sha, 64) &&
           fleet_lower_hex(receipt->diff_sha, 64) && receipt->branch[0] &&
           fleet_receipt_output_ok(receipt);
}

/* Reads one receipt file, verifies its seal against the bytes before it and
 * fills the receipt; false when any check fails. */
static bool fleet_read_receipt(const char *dir, const char *name,
                               struct fleet_receipt *receipt)
{
    size_t len = 0;
    char *raw = fleet_receipt_load(dir, name, &len);
    if (!raw) return false;
    const char *seal = fleet_receipt_find_seal(raw);
    bool sealed = seal && fleet_receipt_seal_tail_ok(raw, len, seal) &&
                  fleet_receipt_seal_digest_ok(raw, seal);
    if (!sealed) { free(raw); return false; }
    fleet_hash(raw, len, receipt->whole_sha);
    char index_text[32] = "", exit_text[32] = "";
    char expect_text[32] = "", forbid_text[32] = "";
    bool ok = fleet_receipt_read_fields(raw, receipt, index_text, exit_text,
                                        expect_text, forbid_text);
    unsigned long long index_value = 0, exit_value = 0, expect_value = 0;
    unsigned long long forbid_value = 0;
    bool numbers_ok = ok &&
        fleet_receipt_parse_numbers(index_text, exit_text, expect_text,
                                    forbid_text, &index_value, &exit_value,
                                    &expect_value, &forbid_value);
    bool consistent = fleet_receipt_fields_consistent(receipt, numbers_ok);
    if (!consistent) ok = false;
    if (ok) {
        receipt->index = index_value;
        receipt->exit_status = (unsigned long)exit_value;
        receipt->expect_missing = (unsigned long)expect_value;
        receipt->forbid_present = (unsigned long)forbid_value;
    }
    (void)snprintf(receipt->file, sizeof(receipt->file), "%s", name);
    free(raw);
    return ok;
}

static int fleet_receipt_compare(const void *left, const void *right)
{
    const struct fleet_receipt *a = left, *b = right;
    if (a->index < b->index) return -1;
    if (a->index > b->index) return 1;
    return strcmp(a->file, b->file);
}

static bool fleet_lint_receipt(const char *gate)
{
    return strcmp(gate, "lint") == 0;
}

static struct fleet_gate *fleet_gate_get(struct fleet_gate gates[],
                                         size_t *count, const char *name)
{
    for (size_t i = 0; i < *count; i++)
        if (strcmp(gates[i].name, name) == 0) return &gates[i];
    if (*count >= FLEET_GATE_MAX || strlen(name) >= sizeof(gates[0].name))
        return NULL;
    struct fleet_gate *gate = &gates[(*count)++];
    memset(gate, 0, sizeof(*gate));
    (void)snprintf(gate->name, sizeof(gate->name), "%s", name);
    return gate;
}

static bool fleet_apply_log(const char *path, const char *head, bool current,
                            struct fleet_gate gates[], size_t *gate_count,
                            bool *fail_seen, bool *success_banner)
{
    FILE *file = fopen(path, "rb");
    if (!file) return false;
    char line[1024];
    bool ok = true;
    *fail_seen = false;
    *success_banner = false;
    while (fgets(line, sizeof(line), file)) {
        if (strstr(line, "LINT: all checks passed")) *success_banner = true;
        bool red = strncmp(line, "FAIL check-", 11) == 0;
        bool green = strncmp(line, "PASS check-", 11) == 0 ||
                     strncmp(line, "CACHED check-", 13) == 0;
        if (!red && !green) continue;
        if (red) *fail_seen = true;
        char *name = strchr(line, ' ');
        if (!name) continue;
        name++;
        size_t length = strcspn(name, " \t\r\n");
        name[length] = 0;
        struct fleet_gate *gate = fleet_gate_get(gates, gate_count, name);
        if (!gate) { ok = false; break; }
        if (red && !gate->red)
            (void)snprintf(gate->since, sizeof(gate->since), "%s", head);
        gate->red = red;
        gate->current = current;
    }
    if (ferror(file)) ok = false;
    if (fclose(file) != 0) ok = false;
    return ok;
}

static bool fleet_current_fingerprint(const struct zcl_fleet_worktree *worktree,
                                      char status[65], char diff[65])
{
    char *capture = zcl_malloc(1024u * 1024u, "fleet_fingerprint");
    if (!capture) return false;
    bool truncated = false;
    const char *status_args[] = {"status", "--porcelain", NULL};
    int rc = zcl_dev_fleet_git_capture(worktree->path, status_args, capture,
                                       1024u * 1024u, &truncated);
    if (rc != 0 || truncated) { free(capture); return false; }
    size_t length = strlen(capture);
    while (length && (capture[length - 1] == '\n' || capture[length - 1] == '\r'))
        length--;
    fleet_hash(capture, length, status);
    const char *diff_args[] = {"diff", "HEAD", NULL};
    rc = zcl_dev_fleet_git_capture(worktree->path, diff_args, capture,
                                   1024u * 1024u, &truncated);
    if (rc == 0 && !truncated) fleet_hash(capture, strlen(capture), diff);
    free(capture);
    return rc == 0 && !truncated;
}

bool zcl_dev_fleet_gate_owner_only(const char *gate)
{
    return gate && (strcmp(gate, "check-core-seal") == 0 ||
                    strcmp(gate, "check-git-hooks-installed") == 0);
}

static bool fleet_push_gate(struct json_value *array,
                            const struct fleet_gate *gate)
{
    struct json_value row;
    json_init(&row); json_set_object(&row);
    bool ok = json_push_kv_str(&row, "gate", gate->name) &&
              json_push_kv_str(&row, "since_commit", gate->since) &&
              json_push_kv_bool(&row, "owner_only",
                                zcl_dev_fleet_gate_owner_only(gate->name)) &&
              json_push_back(array, &row);
    json_free(&row);
    return ok;
}

/* Writes the lint projection into lane and releases red; false (with why
 * set) when it cannot be allocated. */
static bool fleet_lint_finish(struct json_value *lane, struct json_value *red,
                              const char *state, size_t lint_count,
                              size_t red_count, size_t owner_red, char *why,
                              size_t why_size)
{
    bool ok = json_push_kv_str(lane, "lint_status", state) &&
              json_push_kv_int(lane, "lint_receipt_count", (int64_t)lint_count) &&
              json_push_kv(lane, "red_gates", red) &&
              json_push_kv_int(lane, "red_gate_count", (int64_t)red_count) &&
              json_push_kv_int(lane, "owner_only_red_gate_count",
                               (int64_t)owner_red);
    json_free(red);
    if (!ok) fleet_reason(why, why_size, "cannot allocate lint projection");
    return ok;
}

/* Receipts form one hash chain: indices count from zero and each names the
 * previous receipt's digest. */
static bool fleet_receipt_chain_valid(const struct fleet_receipt *receipts,
                                      size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (receipts[i].index != i) return false;
        if (i == 0 && strcmp(receipts[i].prev_sha, "GENESIS") != 0)
            return false;
        if (i && strcmp(receipts[i].prev_sha, receipts[i - 1].whole_sha) != 0)
            return false;
    }
    return true;
}

static bool fleet_verdict_consistent(const struct fleet_receipt *receipt,
                                     bool fail_seen, bool success_banner)
{
    if (strcmp(receipt->verdict, "PASS") == 0)
        return receipt->exit_status == 0 && receipt->expect_missing == 0 &&
               receipt->forbid_present == 0 && !fail_seen && success_banner;
    if (strcmp(receipt->verdict, "FAIL") == 0)
        return fail_seen;
    return false;
}

/* Replays one lint receipt's log into gates; false when the receipt does not
 * match this worktree, its log, or its verdict. */
static bool fleet_apply_lint_receipt(
    const struct fleet_receipt *receipt,
    const struct zcl_fleet_worktree *worktree, const char *directory,
    const char *status, const char *diff, struct fleet_gate *gates,
    size_t *gate_count, bool *current)
{
    char log_path[ZCL_FLEET_PATH_MAX], log_sha[65], log_sha_after[65];
    bool fail_seen = false, success_banner = false;
    *current = strcmp(receipt->head, worktree->head) == 0 &&
               strcmp(receipt->status_sha, status) == 0 &&
               strcmp(receipt->diff_sha, diff) == 0;
    if (strcmp(receipt->worktree, worktree->path) != 0 ||
        strcmp(receipt->branch, worktree->branch) != 0)
        return false;
    if (!zcl_path_join(log_path, sizeof(log_path), directory, receipt->output) ||
        !fleet_hash_file(log_path, log_sha) ||
        strcmp(log_sha, receipt->output_sha) != 0 ||
        !fleet_apply_log(log_path, receipt->head, *current, gates, gate_count,
                         &fail_seen, &success_banner) ||
        !fleet_hash_file(log_path, log_sha_after) ||
        strcmp(log_sha_after, receipt->output_sha) != 0)
        return false;
    return fleet_verdict_consistent(receipt, fail_seen, success_banner);
}

static bool fleet_collect_red(struct json_value *red,
                              const struct fleet_gate *gates,
                              size_t gate_count, size_t *red_count,
                              size_t *owner_red)
{
    for (size_t i = 0; i < gate_count; i++) {
        if (!gates[i].red || !gates[i].current) continue;
        if (!fleet_push_gate(red, &gates[i])) return false;
        (*red_count)++;
        if (zcl_dev_fleet_gate_owner_only(gates[i].name)) (*owner_red)++;
    }
    return true;
}

/* Reads and replays the receipts; *state names the outcome and the counts
 * are filled for the projection. */
static void fleet_replay_receipts(
    const struct zcl_fleet_worktree *worktree, const char *directory,
    struct fleet_receipt *receipts, size_t count, struct json_value *red,
    const char **state, size_t *lint_count, size_t *red_count,
    size_t *owner_red)
{
    bool valid = fleet_receipt_chain_valid(receipts, count);
    char status[65], diff[65];
    if (valid && !fleet_current_fingerprint(worktree, status, diff))
        valid = false;
    struct fleet_gate gates[FLEET_GATE_MAX] = {0};
    size_t gate_count = 0;
    bool current_seen = false;
    for (size_t i = 0; valid && i < count; i++) {
        if (!fleet_lint_receipt(receipts[i].gate)) continue;
        (*lint_count)++;
        valid = fleet_apply_lint_receipt(&receipts[i], worktree, directory,
                                         status, diff, gates, &gate_count,
                                         &current_seen);
    }
    if (valid && current_seen)
        valid = fleet_collect_red(red, gates, gate_count, red_count,
                                  owner_red);
    *state = !valid ? "invalid" : !*lint_count ? "unobserved" :
             current_seen ? (*red_count ? "red" : "green") : "stale";

}

bool zcl_dev_fleet_receipts_json(const struct zcl_fleet_worktree *worktree,
                                 struct json_value *lane, size_t *owner_red,
                                 char *why, size_t why_size)
{
    *owner_red = 0;
    struct json_value red;
    json_init(&red); json_set_array(&red);
    if (!worktree->present)
        return fleet_lint_finish(lane, &red, "unobserved", 0, 0, 0, why,
                                 why_size);
    char directory[ZCL_FLEET_PATH_MAX];
    if (snprintf(directory, sizeof(directory), "%s/.cache/agent-receipts",
                 worktree->path) >= (int)sizeof(directory)) {
        json_free(&red); fleet_reason(why, why_size, "receipt path too long");
        return false;
    }
    struct platform_directory_list files = {0};
    if (!platform_directory_list_regular_sorted(directory, &files))
        return fleet_lint_finish(lane, &red, "unobserved", 0, 0, 0, why,
                                 why_size);
    if (files.count > FLEET_RECEIPT_FILES_MAX) {
        platform_directory_list_free(&files);
        return fleet_lint_finish(lane, &red, "invalid", 0, 0, 0, why,
                                 why_size);
    }
    struct fleet_receipt *receipts = zcl_calloc(files.count,
                                                sizeof(*receipts),
                                                "fleet_receipts");
    if (!receipts && files.count) {
        platform_directory_list_free(&files); json_free(&red);
        fleet_reason(why, why_size, "cannot allocate receipt inventory");
        return false;
    }
    size_t count = 0;
    bool loaded = true;
    for (size_t i = 0; i < files.count; i++) {
        if (!fleet_suffix(files.entries[i].name, ".receipt")) continue;
        if (!fleet_read_receipt(directory, files.entries[i].name,
                                &receipts[count++])) { loaded = false; break; }
    }
    platform_directory_list_free(&files);
    if (count > 1)
        qsort(receipts, count, sizeof(*receipts), fleet_receipt_compare);
    const char *state = "invalid";
    size_t lint_count = 0, red_count = 0;
    if (loaded)
        fleet_replay_receipts(worktree, directory, receipts, count,
                                    &red, &state, &lint_count, &red_count,
                                    owner_red);
    bool ok = fleet_lint_finish(lane, &red, state, lint_count, red_count,
                                *owner_red, why, why_size);
    free(receipts);
    return ok;
}
