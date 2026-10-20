/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: signed plugin index entries and the local index directory.
 * See plugin/plugin_index.h for the canonical encoding and the fold rules. */

#include "plugin_internal.h"
#include "plugin/plugin_index.h"

#include "base/cleanse.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "crypto/ed25519.h"
#include "json/json.h"
#include "sha3/sha3.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define PI_SCHEMA "z23.plugin.index.v1"

const char *plugin_index_status_code(enum plugin_index_status status)
{
    switch (status) {
    case PLUGIN_INDEX_OK: return "PLUGIN_INDEX_OK";
    case PLUGIN_INDEX_ARGUMENT: return "PLUGIN_INDEX_ARGUMENT";
    case PLUGIN_INDEX_MALFORMED: return "PLUGIN_INDEX_MALFORMED";
    case PLUGIN_INDEX_BAD_SIGNATURE: return "PLUGIN_INDEX_BAD_SIGNATURE";
    case PLUGIN_INDEX_ROLLBACK: return "PLUGIN_INDEX_ROLLBACK";
    case PLUGIN_INDEX_EQUIVOCATION: return "PLUGIN_INDEX_EQUIVOCATION";
    case PLUGIN_INDEX_SOURCE: return "PLUGIN_INDEX_SOURCE";
    case PLUGIN_INDEX_PINS: return "PLUGIN_INDEX_PINS";
    case PLUGIN_INDEX_TOO_MANY: return "PLUGIN_INDEX_TOO_MANY";
    case PLUGIN_INDEX_IO: return "PLUGIN_INDEX_IO";
    }
    return "PLUGIN_INDEX_UNKNOWN";
}

static bool pi_digit(char c)
{
    return c >= '0' && c <= '9';
}

/* Compares the digit runs at a and b as numbers and advances both past them. */
static int pi_digit_runs(const char **pa, const char **pb)
{
    const char *a = *pa, *b = *pb;
    while (*a == '0' && pi_digit(a[1]))
        a++;
    while (*b == '0' && pi_digit(b[1]))
        b++;
    size_t la = 0, lb = 0;
    while (pi_digit(a[la]))
        la++;
    while (pi_digit(b[lb]))
        lb++;
    int c = la != lb ? (la < lb ? -1 : 1) : memcmp(a, b, la);
    *pa = a + la;
    *pb = b + lb;
    return c < 0 ? -1 : c > 0;
}

int plugin_index_version_cmp(const char *a, const char *b)
{
    while (*a || *b) {
        if (pi_digit(*a) && pi_digit(*b)) {
            int c = pi_digit_runs(&a, &b);
            if (c)
                return c;
            continue;
        }
        if ((unsigned char)*a != (unsigned char)*b)
            return (unsigned char)*a < (unsigned char)*b ? -1 : 1;
        a++;
        b++;
    }
    return 0;
}

static bool pi_caps_text(unsigned mask, char *out, size_t cap)
{
    size_t used = 0;
    out[0] = '\0';
    for (unsigned i = 0; plugin_capability_name(i); i++) {
        if (!(mask & (1u << i)))
            continue;
        int n = snprintf(out + used, cap - used, "%s\"%s\"", used ? "," : "",
                         plugin_capability_name(i));
        if (n < 0 || (size_t)n >= cap - used)
            return false;
        used += (size_t)n;
    }
    return true;
}

/* The entry text up to and including the timestamp value: the signed body. */
static bool pi_body(const struct plugin_index_entry *e, char *out, size_t cap,
                    size_t *len)
{
    char caps[160];
    if (!pi_caps_text(e->capabilities, caps, sizeof(caps)))
        return false;
    int n = snprintf(out, cap,
                     "{\"schema\":\"" PI_SCHEMA "\",\"name\":\"%s\","
                     "\"version\":\"%s\",\"interface_version\":%lld,"
                     "\"capabilities\":[%s],\"root\":\"%s\","
                     "\"publisher\":\"%s\",\"timestamp\":%lld",
                     e->name, e->version, (long long)e->interface_version,
                     caps, e->root, e->publisher, (long long)e->timestamp);
    if (n <= 0 || (size_t)n >= cap)
        return false;
    *len = (size_t)n;
    return true;
}

/* SHA3-512 of the domain tag, its NUL and the body, hashed in one pass. */
static void pi_signing_digest(const char *body, size_t len,
                              uint8_t digest[PLUGIN_DIGEST_BYTES])
{
    unsigned char msg[sizeof(PI_SCHEMA) + PLUGIN_INDEX_ENTRY_MAX];
    if (len > PLUGIN_INDEX_ENTRY_MAX)
        len = PLUGIN_INDEX_ENTRY_MAX; /* bodies are bounded by the caller */
    memcpy(msg, PI_SCHEMA, sizeof(PI_SCHEMA));
    memcpy(msg + sizeof(PI_SCHEMA), body, len);
    zcl_sha3_512(msg, sizeof(PI_SCHEMA) + len, digest);
}

static void pi_entry_digest(const char *bytes, size_t len,
                            char hex[PLUGIN_HEX_SHA3_512 + 1])
{
    uint8_t d[PLUGIN_DIGEST_BYTES];
    zcl_sha3_512((const unsigned char *)bytes, len, d);
    zcl_hex_encode(d, sizeof(d), hex);
}

static bool pi_fields_valid(const struct plugin_index_entry *e)
{
    unsigned all = 0;
    for (unsigned i = 0; plugin_capability_name(i); i++)
        all |= 1u << i;
    return plugin_name_valid(e->name) && plugin_version_valid(e->version) &&
           (e->interface_version == 1 || e->interface_version == 2) &&
           (e->capabilities & ~all) == 0 &&
           strlen(e->root) == PLUGIN_INDEX_HEX_KEY &&
           plugin_hex_valid(e->root, PLUGIN_INDEX_HEX_KEY) &&
           strlen(e->publisher) == PLUGIN_INDEX_HEX_KEY &&
           plugin_hex_valid(e->publisher, PLUGIN_INDEX_HEX_KEY) &&
           e->timestamp >= 0;
}

enum plugin_index_status plugin_index_encode(struct plugin_index_entry *entry,
                                             const uint8_t seed[32],
                                             char *out, size_t cap,
                                             size_t *len)
{
    uint8_t pk[32], sig[64], digest[PLUGIN_DIGEST_BYTES];
    char body[PLUGIN_INDEX_ENTRY_MAX], sig_hex[129];
    size_t body_len;
    if (!entry || !seed || !out || !len)
        return PLUGIN_INDEX_ARGUMENT;
    plugin_key_public(seed, pk);
    zcl_hex_encode(pk, sizeof(pk), entry->publisher);
    if (!pi_fields_valid(entry) ||
        !pi_body(entry, body, sizeof(body), &body_len))
        return PLUGIN_INDEX_ARGUMENT;
    pi_signing_digest(body, body_len, digest);
    ed25519_sign(sig, digest, sizeof(digest), seed, pk);
    zcl_hex_encode(sig, sizeof(sig), sig_hex);
    int n = snprintf(out, cap, "%s,\"signature\":\"%s\"}\n", body, sig_hex);
    if (n <= 0 || (size_t)n >= cap || (size_t)n > PLUGIN_INDEX_ENTRY_MAX)
        return PLUGIN_INDEX_ARGUMENT;
    *len = (size_t)n;
    pi_entry_digest(out, *len, entry->digest);
    return PLUGIN_INDEX_OK;
}

/* Copies the string field key of obj into dst; false when absent, not a
 * string or too long. */
static bool pi_field(const struct json_value *obj, const char *key,
                     char *dst, size_t cap)
{
    const struct json_value *v = json_get(obj, key);
    const char *s = v && v->type == JSON_STR ? json_get_str(v) : NULL;
    if (!s || strlen(s) >= cap)
        return false;
    memcpy(dst, s, strlen(s) + 1);
    return true;
}

static bool pi_int(const struct json_value *obj, const char *key, int64_t *out)
{
    const struct json_value *v = json_get(obj, key);
    if (!v || v->type != JSON_INT)
        return false;
    *out = json_get_int(v);
    return true;
}

static bool pi_caps(const struct json_value *arr, unsigned *mask)
{
    *mask = 0;
    if (!arr || arr->type != JSON_ARR)
        return false;
    for (size_t i = 0; i < json_size(arr); i++) {
        const struct json_value *item = json_at(arr, i);
        const char *s = item && item->type == JSON_STR ? json_get_str(item) : NULL;
        if (!s || !plugin_capability_add(s, strlen(s), mask))
            return false;
    }
    return true;
}

/* Reads the fields; the canonical re-encoding check happens in the caller. */
static bool pi_fields_read(const struct json_value *root,
                           struct plugin_index_entry *e, char sig[129])
{
    char schema[sizeof(PI_SCHEMA) + 1];
    if (root->type != JSON_OBJ)
        return false;
    return pi_field(root, "schema", schema, sizeof(schema)) &&
           strcmp(schema, PI_SCHEMA) == 0 &&
           pi_field(root, "signature", sig, 129) &&
           pi_field(root, "name", e->name, sizeof(e->name)) &&
           pi_field(root, "version", e->version, sizeof(e->version)) &&
           pi_field(root, "root", e->root, sizeof(e->root)) &&
           pi_field(root, "publisher", e->publisher, sizeof(e->publisher)) &&
           pi_int(root, "interface_version", &e->interface_version) &&
           pi_int(root, "timestamp", &e->timestamp) &&
           pi_caps(json_get(root, "capabilities"), &e->capabilities);
}

/* True when e re-encodes, with sig_hex, to exactly the input bytes: key
 * order, whitespace, repeated or unknown keys, escapes and upper case hex all
 * make the encodings differ. Leaves the signed body in body. */
static bool pi_canonical(const struct plugin_index_entry *e, const char *sig_hex,
                         const char *bytes, size_t len, char *body,
                         size_t body_cap, size_t *body_len)
{
    char again[PLUGIN_INDEX_ENTRY_MAX + 1];
    if (!pi_body(e, body, body_cap, body_len))
        return false;
    int n = snprintf(again, sizeof(again), "%s,\"signature\":\"%s\"}\n", body,
                     sig_hex);
    return n > 0 && (size_t)n == len && memcmp(again, bytes, len) == 0;
}

enum plugin_index_status plugin_index_parse(const char *bytes, size_t len,
                                            struct plugin_index_entry *out)
{
    struct plugin_index_entry e;
    struct json_value root;
    char sig_hex[129];
    char body[PLUGIN_INDEX_ENTRY_MAX];
    size_t body_len = 0;
    uint8_t pk[32], sig[64], digest[PLUGIN_DIGEST_BYTES];
    if (!bytes || !out)
        return PLUGIN_INDEX_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if (len == 0 || len > PLUGIN_INDEX_ENTRY_MAX)
        return PLUGIN_INDEX_MALFORMED;
    memset(&e, 0, sizeof(e));
    json_init(&root);
    bool ok = json_read(&root, bytes, len) && pi_fields_read(&root, &e, sig_hex) &&
              pi_fields_valid(&e) && strlen(sig_hex) == 128 &&
              plugin_hex_valid(sig_hex, 128) &&
              pi_canonical(&e, sig_hex, bytes, len, body, sizeof(body), &body_len) &&
              zcl_hex_decode_lower(e.publisher, pk, 32) &&
              zcl_hex_decode_lower(sig_hex, sig, 64);
    json_free(&root);
    if (!ok)
        return PLUGIN_INDEX_MALFORMED;
    pi_signing_digest(body, body_len, digest);
    if (!ed25519_verify(sig, digest, sizeof(digest), pk))
        return PLUGIN_INDEX_BAD_SIGNATURE;
    pi_entry_digest(bytes, len, e.digest);
    *out = e;
    return PLUGIN_INDEX_OK;
}

/* ---- directory -------------------------------------------------------- */

struct pi_set {
    struct plugin_index_entry *items;
    size_t count;
};

static int pi_order(const void *pa, const void *pb)
{
    const struct plugin_index_entry *a = pa, *b = pb;
    int c = strcmp(a->publisher, b->publisher);
    if (!c)
        c = strcmp(a->name, b->name);
    if (!c && a->timestamp != b->timestamp)
        c = a->timestamp < b->timestamp ? -1 : 1;
    return c ? c : strcmp(a->digest, b->digest);
}

static bool pi_suffix(const char *name)
{
    size_t n = strlen(name), s = strlen(PLUGIN_INDEX_SUFFIX);
    return n > s && strcmp(name + n - s, PLUGIN_INDEX_SUFFIX) == 0;
}

static bool pi_refuse(struct plugin_index_report *rep, const char *file,
                      enum plugin_index_status st)
{
    struct plugin_index_refusal *grown = zcl_realloc(
        rep->refusals, (rep->refusal_count + 1) * sizeof(*grown),
        "plugin_index.refusals");
    if (!grown)
        return false;
    rep->refusals = grown;
    struct plugin_index_refusal *r = &grown[rep->refusal_count++];
    snprintf(r->file, sizeof(r->file), "%s", file);
    r->code = plugin_index_status_code(st);
    return true;
}

static enum plugin_index_status pi_read_one(const char *dir, const char *file,
                                            struct plugin_index_entry *e)
{
    char path[PLUGIN_PATH_MAX], *bytes = NULL;
    size_t len = 0;
    if (!plugin_join(path, sizeof(path), dir, file, NULL, NULL))
        return PLUGIN_INDEX_MALFORMED;
    if (!plugin_read_file(path, PLUGIN_INDEX_ENTRY_MAX, PLUGIN_OPEN_NOFOLLOW,
                          &bytes, &len))
        return errno == EFBIG ? PLUGIN_INDEX_MALFORMED : PLUGIN_INDEX_IO;
    enum plugin_index_status st = plugin_index_parse(bytes, len, e);
    free(bytes);
    return st;
}

static bool pi_set_push(struct pi_set *set, const struct plugin_index_entry *e)
{
    struct plugin_index_entry *grown = zcl_realloc(
        set->items, (set->count + 1) * sizeof(*grown), "plugin_index.set");
    if (!grown)
        return false;
    set->items = grown;
    set->items[set->count++] = *e;
    return true;
}

#ifdef ZCL_TESTING
static bool g_pi_fail_armed;
static unsigned g_pi_fail_after;

void plugin_index_test_fail_readdir(bool armed, unsigned after)
{
    g_pi_fail_armed = armed;
    g_pi_fail_after = after;
}
#endif

/* readdir that tells the end of the directory (NULL, errno 0) from a failed
 * read (NULL, errno set). */
static struct dirent *pi_readdir(DIR *d)
{
#ifdef ZCL_TESTING
    if (g_pi_fail_armed) {
        if (g_pi_fail_after == 0) {
            errno = EIO;
            return NULL;
        }
        g_pi_fail_after--;
    }
#endif
    errno = 0;
    return readdir(d);
}

/* Reads each entry file of dir into set (and failures into rep, when given). */
static enum plugin_index_status pi_scan(const char *dir, struct pi_set *set,
                                        struct plugin_index_report *rep)
{
    DIR *d = opendir(dir);
    if (!d)
        return PLUGIN_INDEX_IO;
    enum plugin_index_status result = PLUGIN_INDEX_OK;
    size_t files = 0;
    struct dirent *de;
    while (result == PLUGIN_INDEX_OK && (de = pi_readdir(d)) != NULL) {
        struct plugin_index_entry e;
        if (!pi_suffix(de->d_name))
            continue;
        if (++files > PLUGIN_INDEX_FILES_MAX) {
            result = PLUGIN_INDEX_TOO_MANY;
            break;
        }
        enum plugin_index_status st = pi_read_one(dir, de->d_name, &e);
        if (rep)
            rep->scanned++;
        if (st == PLUGIN_INDEX_OK)
            result = pi_set_push(set, &e) ? PLUGIN_INDEX_OK : PLUGIN_INDEX_IO;
        else if (rep && !pi_refuse(rep, de->d_name, st))
            result = PLUGIN_INDEX_IO;
    }
    /* A failed read ends the loop like the end of the directory does; only
     * errno tells them apart, and a partial set must never look complete. */
    int read_error = de == NULL ? errno : 0;
    closedir(d);
    if (result == PLUGIN_INDEX_OK && read_error != 0)
        result = PLUGIN_INDEX_IO;
    return result;
}

/* Loads every verifying entry in dir, sorted, byte-identical copies dropped. */
static enum plugin_index_status pi_load(const char *dir, struct pi_set *set,
                                        struct plugin_index_report *rep)
{
    set->items = NULL;
    set->count = 0;
    enum plugin_index_status st = pi_scan(dir, set, rep);
    if (st != PLUGIN_INDEX_OK) {
        free(set->items);
        set->items = NULL;
        set->count = 0;
        return st;
    }
    if (set->count > 1)
        qsort(set->items, set->count, sizeof(*set->items), pi_order);
    size_t kept = 0;
    for (size_t i = 0; i < set->count; i++) {
        if (kept && strcmp(set->items[kept - 1].digest, set->items[i].digest) == 0) {
            if (rep)
                rep->duplicates++;
            continue;
        }
        set->items[kept++] = set->items[i];
    }
    set->count = kept;
    return PLUGIN_INDEX_OK;
}

static bool pi_same_claim(const struct plugin_index_entry *a,
                          const struct plugin_index_entry *b)
{
    return strcmp(a->version, b->version) == 0 &&
           a->interface_version == b->interface_version &&
           a->capabilities == b->capabilities && strcmp(a->root, b->root) == 0;
}

static bool pi_stream_same(const struct plugin_index_entry *a,
                           const struct plugin_index_entry *b)
{
    return strcmp(a->publisher, b->publisher) == 0 &&
           strcmp(a->name, b->name) == 0;
}

/* The refusal an entry meets against one earlier entry of its stream. */
static enum plugin_index_status pi_conflict(const struct plugin_index_entry *seen,
                                            const struct plugin_index_entry *e)
{
    int c = plugin_index_version_cmp(e->version, seen->version);
    if (c < 0)
        return PLUGIN_INDEX_ROLLBACK;
    if (c == 0 && !pi_same_claim(seen, e))
        return PLUGIN_INDEX_EQUIVOCATION;
    return PLUGIN_INDEX_OK;
}

static bool pi_write_new(const char *dir, const char *bytes, size_t len,
                         const char *digest)
{
    char path[PLUGIN_PATH_MAX], tmp[PLUGIN_PATH_MAX], leaf[160];
    if (snprintf(leaf, sizeof(leaf), "%s" PLUGIN_INDEX_SUFFIX, digest) <= 0 ||
        !plugin_join(path, sizeof(path), dir, leaf, NULL, NULL) ||
        snprintf(tmp, sizeof(tmp), "%s.tmp", path) <= 0)
        return false;
    (void)unlink(tmp);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0)
        return false;
    bool ok = write(fd, bytes, len) == (ssize_t)len && fsync(fd) == 0;
    ok = close(fd) == 0 && ok;
    ok = ok && rename(tmp, path) == 0;
    if (!ok)
        (void)unlink(tmp);
    return ok;
}

/* Checks e against the loaded set: sets *present when e is already there and
 * returns the first rollback or equivocation against its own stream. */
static enum plugin_index_status pi_admit(const struct pi_set *set,
                                         const struct plugin_index_entry *e,
                                         bool *present)
{
    *present = false;
    for (size_t i = 0; i < set->count; i++) {
        const struct plugin_index_entry *s = &set->items[i];
        if (strcmp(s->digest, e->digest) == 0) {
            *present = true;
            continue;
        }
        if (!pi_stream_same(s, e))
            continue;
        enum plugin_index_status st = pi_conflict(s, e);
        if (st != PLUGIN_INDEX_OK)
            return st;
    }
    return PLUGIN_INDEX_OK;
}

enum plugin_index_status plugin_index_add(const char *dir, const char *bytes,
                                          size_t len,
                                          struct plugin_index_entry *out,
                                          bool *already_present)
{
    struct plugin_index_entry e;
    struct pi_set set;
    bool present = false;
    if (!dir || !*dir || !bytes)
        return PLUGIN_INDEX_ARGUMENT;
    enum plugin_index_status st = plugin_index_parse(bytes, len, &e);
    if (st != PLUGIN_INDEX_OK)
        return st;
    if (!plugin_mkdirs(dir))
        return PLUGIN_INDEX_IO;
    st = pi_load(dir, &set, NULL);
    if (st != PLUGIN_INDEX_OK)
        return st;
    st = pi_admit(&set, &e, &present);
    free(set.items);
    if (st != PLUGIN_INDEX_OK)
        return st;
    if (!present && !pi_write_new(dir, bytes, len, e.digest))
        return PLUGIN_INDEX_IO;
    if (already_present)
        *already_present = present;
    if (out)
        *out = e;
    return PLUGIN_INDEX_OK;
}

/* ---- search ----------------------------------------------------------- */

static bool pi_row_push(struct plugin_index_report *rep,
                        const struct plugin_index_entry *e)
{
    struct plugin_index_row *grown = zcl_realloc(
        rep->rows, (rep->row_count + 1) * sizeof(*grown), "plugin_index.rows");
    if (!grown)
        return false;
    rep->rows = grown;
    grown[rep->row_count].entry = *e;
    grown[rep->row_count].pinned = false;
    rep->row_count++;
    return true;
}

/* Folds one (publisher, name) stream in timestamp order: the highest version
 * wins; a lower version after a higher one is a rollback; a conflicting claim
 * at the same version is refused and the first one seen stays. */
static bool pi_fold_stream(struct plugin_index_report *rep,
                           const struct plugin_index_entry *items, size_t n)
{
    const struct plugin_index_entry *best = &items[0];
    for (size_t i = 1; i < n; i++) {
        const struct plugin_index_entry *e = &items[i];
        enum plugin_index_status c = pi_conflict(best, e);
        if (c != PLUGIN_INDEX_OK) {
            char file[PLUGIN_INDEX_FILE_MAX + 1];
            snprintf(file, sizeof(file), "%s" PLUGIN_INDEX_SUFFIX, e->digest);
            if (!pi_refuse(rep, file, c))
                return false;
            continue;
        }
        rep->superseded++;
        best = e;
    }
    return pi_row_push(rep, best);
}

static int pi_row_order(const void *pa, const void *pb)
{
    const struct plugin_index_row *a = pa, *b = pb;
    int c = strcmp(a->entry.name, b->entry.name);
    if (!c)
        c = strcmp(a->entry.publisher, b->entry.publisher);
    return c;
}

/* Next key line of a pin file: sets *pos past it and returns its length, or
 * (size_t)-1 at the end. Blank lines have length 0. */
static size_t pi_line(const char *keys, size_t len, size_t *pos)
{
    if (*pos >= len)
        return (size_t)-1;
    size_t start = *pos, end = start;
    while (end < len && keys[end] != '\n')
        end++;
    *pos = end + 1;
    size_t n = end - start;
    while (n > 0 && keys[start + n - 1] == '\r')
        n--;
    return n;
}

/* One 64-hex key per line, as publisher_keys. */
static enum plugin_index_status pi_pins_check(const char *keys, size_t len)
{
    size_t pos = 0;
    while (pos < len) {
        size_t at = pos;
        size_t n = pi_line(keys, len, &pos);
        char key[PLUGIN_INDEX_HEX_KEY + 1];
        if (n == 0)
            continue;
        if (n != PLUGIN_INDEX_HEX_KEY)
            return PLUGIN_INDEX_PINS;
        memcpy(key, keys + at, n);
        key[n] = '\0';
        if (!plugin_hex_valid(key, n))
            return PLUGIN_INDEX_PINS;
    }
    return PLUGIN_INDEX_OK;
}

static bool pi_pinned(const char *keys, size_t len, const char *publisher)
{
    size_t pos = 0;
    while (pos < len) {
        size_t at = pos;
        size_t n = pi_line(keys, len, &pos);
        if (n == PLUGIN_INDEX_HEX_KEY && memcmp(keys + at, publisher, n) == 0)
            return true;
    }
    return false;
}

static enum plugin_index_status pi_collect(
    struct plugin_index_report *rep, const struct pi_set *set,
    const struct plugin_index_query *q, const char *keys, size_t keys_len)
{
    for (size_t i = 0; i < set->count;) {
        size_t j = i + 1;
        while (j < set->count && pi_stream_same(&set->items[i], &set->items[j]))
            j++;
        if (!pi_fold_stream(rep, set->items + i, j - i))
            return PLUGIN_INDEX_IO;
        i = j;
    }
    size_t kept = 0;
    for (size_t i = 0; i < rep->row_count; i++) {
        struct plugin_index_row *r = &rep->rows[i];
        if ((q->name && strcmp(q->name, r->entry.name) != 0) ||
            (r->entry.capabilities & q->capabilities) != q->capabilities)
            continue;
        r->pinned = pi_pinned(keys, keys_len, r->entry.publisher);
        rep->rows[kept++] = *r;
    }
    rep->row_count = kept;
    if (kept > 1)
        qsort(rep->rows, kept, sizeof(*rep->rows), pi_row_order);
    return PLUGIN_INDEX_OK;
}

enum plugin_index_status plugin_index_search(
    const char *dir, const char *pins_path,
    const struct plugin_index_query *query, struct plugin_index_report *report)
{
    struct plugin_index_query none = {0};
    struct pi_set set;
    char *keys = NULL;
    size_t keys_len = 0;
    if (!dir || !*dir || !pins_path || !*pins_path || !report)
        return PLUGIN_INDEX_ARGUMENT;
    memset(report, 0, sizeof(*report));
    if (plugin_keys_load(pins_path, &keys, &keys_len) != PLUGIN_OK ||
        pi_pins_check(keys, keys_len) != PLUGIN_INDEX_OK) {
        free(keys);
        return PLUGIN_INDEX_PINS;
    }
    enum plugin_index_status st = pi_load(dir, &set, report);
    if (st == PLUGIN_INDEX_OK) {
        st = pi_collect(report, &set, query ? query : &none, keys, keys_len);
        free(set.items);
    }
    free(keys);
    if (st != PLUGIN_INDEX_OK)
        plugin_index_report_free(report);
    return st;
}

void plugin_index_report_free(struct plugin_index_report *report)
{
    if (!report)
        return;
    free(report->rows);
    free(report->refusals);
    memset(report, 0, sizeof(*report));
}

/* ---- publisher side --------------------------------------------------- */

static bool pi_sig_path(const char *manifest, char *out, size_t cap)
{
    static const char tail[] = ".plugin.json";
    size_t n = strlen(manifest), t = sizeof(tail) - 1;
    if (n <= t || n - t + 12 >= cap || strcmp(manifest + n - t, tail) != 0)
        return false;
    memcpy(out, manifest, n - t);
    memcpy(out + n - t, ".plugin.sig", 12);
    return true;
}

/* Verifies the manifest and its signature under the single key keyline. */
static enum plugin_status pi_manifest_load(const struct plugin_index_publish *rq,
                                           const char *keyline,
                                           struct plugin_manifest *m)
{
    char sig_path[PLUGIN_PATH_MAX], *mb = NULL, *sb = NULL;
    size_t ml = 0, sl = 0;
    enum plugin_status st = PLUGIN_OK;
    if (!pi_sig_path(rq->manifest_path, sig_path, sizeof(sig_path)))
        return PLUGIN_ERR_ARGUMENT;
    if (!plugin_read_file(rq->manifest_path, PLUGIN_FILE_MAX,
                          PLUGIN_OPEN_NOFOLLOW, &mb, &ml))
        st = PLUGIN_ERR_MANIFEST_MISSING;
    else if (!plugin_read_file(sig_path, PLUGIN_FILE_MAX, PLUGIN_OPEN_NOFOLLOW,
                               &sb, &sl))
        st = PLUGIN_ERR_SIG_MISSING;
    else
        st = plugin_verify_manifest_keys(mb, ml, sb, sl, keyline,
                                         strlen(keyline), m);
    free(mb);
    free(sb);
    return st;
}

enum plugin_index_status plugin_index_publish(
    const struct plugin_index_publish *rq, struct plugin_index_entry *out,
    bool *already_present, enum plugin_status *cause)
{
    uint8_t seed[PLUGIN_KEY_FILE_BYTES], pk[32];
    struct plugin_manifest m;
    struct plugin_index_entry e;
    char keyline[PLUGIN_INDEX_HEX_KEY + 2], bytes[PLUGIN_INDEX_ENTRY_MAX + 1];
    size_t len = 0;
    enum plugin_status ps = PLUGIN_OK;
    enum plugin_index_status st = PLUGIN_INDEX_SOURCE;
    if (!rq || !rq->dir || !rq->root || !rq->manifest_path || !rq->key_path ||
        !plugin_hex_valid(rq->root, PLUGIN_INDEX_HEX_KEY) ||
        strlen(rq->root) != PLUGIN_INDEX_HEX_KEY || rq->timestamp < 0)
        return PLUGIN_INDEX_ARGUMENT;
    ps = plugin_key_load(rq->key_path, seed);
    if (ps == PLUGIN_OK) {
        plugin_key_public(seed, pk);
        zcl_hex_encode(pk, sizeof(pk), keyline);
        keyline[PLUGIN_INDEX_HEX_KEY] = '\n';
        keyline[PLUGIN_INDEX_HEX_KEY + 1] = '\0';
        ps = pi_manifest_load(rq, keyline, &m);
    }
    if (ps == PLUGIN_OK) {
        memset(&e, 0, sizeof(e));
        snprintf(e.name, sizeof(e.name), "%s", m.name);
        snprintf(e.version, sizeof(e.version), "%s", m.version);
        snprintf(e.root, sizeof(e.root), "%s", rq->root);
        e.interface_version = m.interface_version;
        e.capabilities = m.capabilities;
        e.timestamp = rq->timestamp;
        st = plugin_index_encode(&e, seed, bytes, sizeof(bytes), &len);
    }
    memory_cleanse(seed, sizeof(seed));
    if (cause)
        *cause = ps;
    if (ps != PLUGIN_OK || st != PLUGIN_INDEX_OK)
        return st;
    return plugin_index_add(rq->dir, bytes, len, out, already_present);
}
