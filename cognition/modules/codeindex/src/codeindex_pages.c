/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Purpose: Read unsigned page hints from the sealed codeindex generation. */
#include "codeindex/codeindex_pages.h"
#include "codeindex_priv.h"
#include "base/safe_alloc.h"
#include "vcs/vcs_object.h"
#include "json/json.h"
#include "zutf8/zutf8.h"
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

enum { CI_PAGE_MANIFEST_MAX = 1024 * 1024, CI_PAGE_BATCH_MAX = 256 };

#if defined(_WIN32)
bool codeindex_pages_import_hints(struct codeindex *ci, const void *manifest,
    size_t manifest_size, const struct ci_page *pages, size_t count,
    uint8_t artifact_root[32])
{
    (void)ci; (void)manifest; (void)manifest_size; (void)pages; (void)count;
    (void)artifact_root;
    return false;
}
#endif

static bool page_manifest_line(const uint8_t *manifest, size_t size, const char *body)
{
    size_t body_len = strlen(body);
    for (size_t start = 0; start < size;) {
        const uint8_t *end = memchr(manifest + start, '\n', size - start);
        size_t len = end ? (size_t)(end - (manifest + start)) : size - start;
        if (len == body_len && !memcmp(manifest + start, body, len)) return true;
        start += len + (end != NULL);
    }
    return false;
}

static bool page_hex(const char *s, size_t cap)
{
    size_t n = strnlen(s, cap);
    if (n != 40 && n != 64) return false;
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return true;
}

static bool page_json_text(const struct json_value *value, size_t min, size_t max)
{
    const char *text = json_get_str(value);
    if (!text) return false;
    size_t n = strnlen(text, max + 1);
    if (n < min || n > max || !zutf8_validate_n(text, n)) return false;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)text[i] < 32 || (unsigned char)text[i] == 127) return false;
    return true;
}

static bool page_json_keys(const struct json_value *obj, const char *const *keys, size_t n)
{
    if (!obj || obj->type != JSON_OBJ) return false;
    size_t present = 0;
    for (size_t i = 0; i < n; i++) if (json_get(obj, keys[i])) present++;
    return present == obj->num_children;
}

static bool page_json_lessons(const struct json_value *array)
{
    static const char *const keys[] = {"rule", "why", "evidence"};
    if (!array || array->type != JSON_ARR || json_size(array) > 32) return false;
    for (size_t i = 0; i < json_size(array); i++) {
        const struct json_value *row = json_at(array, i);
        if (!page_json_keys(row, keys, 3) || !page_json_text(json_get(row, "rule"), 1, 1024) ||
            !page_json_text(json_get(row, "why"), 0, 1024)) return false;
        const struct json_value *evidence = json_get(row, "evidence");
        if (evidence && !page_json_text(evidence, 0, 1024)) return false;
    }
    return true;
}

static bool page_json_applies(const struct json_value *array)
{
    if (!array || array->type != JSON_ARR || json_size(array) > 32) return false;
    for (size_t i = 0; i < json_size(array); i++)
        if (!page_json_text(json_at(array, i), 1, 512)) return false;
    return true;
}

static bool page_json_shape(const struct json_value *value, const struct ci_page *page)
{
    static const char *const keys[] = {"dir", "tree", "topic", "summary", "lessons", "applies_to", "updated"};
    if (!page_json_keys(value, keys, 7) || value->num_children != 7 ||
        !page_json_text(json_get(value, "dir"), 1, 255) ||
        !page_json_text(json_get(value, "tree"), 40, 64) ||
        !page_json_text(json_get(value, "topic"), 1, 128) ||
        !page_json_text(json_get(value, "summary"), 1, 1024) ||
        !page_json_text(json_get(value, "updated"), 20, 20) ||
        !page_json_lessons(json_get(value, "lessons")) ||
        !page_json_applies(json_get(value, "applies_to"))) return false;
    const char *dir = json_get_str(json_get(value, "dir"));
    const char *tree = json_get_str(json_get(value, "tree"));
    return !strcmp(dir, page->directory) && !strcmp(tree, page->tree_oid);
}

static bool page_hint_valid(const uint8_t *manifest, size_t size, const struct ci_page *page)
{
    size_t body_len = strnlen(page->body, sizeof(page->body));
    size_t dir_len = strnlen(page->directory, sizeof(page->directory));
    if (!dir_len || dir_len >= sizeof(page->directory) || !body_len || body_len >= sizeof(page->body) ||
        !page_hex(page->tree_oid, sizeof(page->tree_oid)) ||
        !page_hex(page->source_commit, sizeof(page->source_commit)) ||
        !page_manifest_line(manifest, size, page->body) || !json_valid(page->body, body_len))
        return false;
    struct json_value value;
    json_init(&value);
    bool ok = !strstr(page->body, "\\u0000") && !strstr(page->body, "\\U0000") &&
              json_read(&value, page->body, body_len) && page_json_shape(&value, page);
    json_free(&value);
    return ok;
}

bool ci_pages_validate_hints(const void *manifest, size_t size,
                             const struct ci_page *pages, size_t count)
{
    if (!manifest || !size || size > CI_PAGE_MANIFEST_MAX || !pages || !count || count > CI_PAGE_BATCH_MAX ||
        memchr(manifest, 0, size)) return false;
    for (size_t i = 0; i < count; i++) {
        if (!page_hint_valid(manifest, size, &pages[i])) return false;
        for (size_t j = 0; j < i; j++)
            if (!strcmp(pages[i].directory, pages[j].directory) &&
                !strcmp(pages[i].tree_oid, pages[j].tree_oid)) return false;
    }
    return true;
}

static bool page_insert_one(sqlite3_stmt *s, const struct ci_page *p, const uint8_t root[32])
{
    bool ok = sqlite3_bind_text(s, 1, p->directory, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_text(s, 2, p->tree_oid, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_text(s, 3, p->source_commit, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_text(s, 4, p->body, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_blob(s, 5, root, 32, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_DONE; // raw-sql-ok:codeindex-derived
    return sqlite3_reset(s) == SQLITE_OK && sqlite3_clear_bindings(s) == SQLITE_OK && ok;
}

bool ci_pages_stage_insert(struct ci_store *store, const struct ci_page *pages,
                           size_t count, const uint8_t artifact_root[32])
{
    sqlite3_stmt *s = NULL;
    sqlite3 *db = ci_store_db(store);
    if (!db || sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO pages(directory,tree_oid,source_commit,body,artifact_root) "
        "VALUES(?1,?2,?3,?4,?5)", -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = true;
    for (size_t i = 0; ok && i < count; i++) ok = page_insert_one(s, &pages[i], artifact_root);
    if (sqlite3_finalize(s) != SQLITE_OK) ok = false;
    return ok;
}

bool ci_pages_set_state(struct ci_store *store, int state)
{
    sqlite3_stmt *s = NULL;
    sqlite3 *db = ci_store_db(store);
    if (!db || state < 0 || state > 2 ||
        sqlite3_prepare_v2(db, "UPDATE pages_state SET state=?1 WHERE id=1", -1, &s, NULL) != SQLITE_OK)
        return false;
    bool ok = sqlite3_bind_int(s, 1, state) == SQLITE_OK &&
              sqlite3_step(s) == SQLITE_DONE && sqlite3_changes(db) == 1; // raw-sql-ok:codeindex-derived
    if (sqlite3_finalize(s) != SQLITE_OK) ok = false;
    return ok;
}

static int page_state(sqlite3 *db)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT state FROM pages_state WHERE id=1", -1, &s, NULL) != SQLITE_OK)
        return -1;
    int state = -1;
    if (sqlite3_step(s) == SQLITE_ROW && sqlite3_column_type(s, 0) == SQLITE_INTEGER) { // raw-sql-ok:codeindex-derived
        int value = sqlite3_column_int(s, 0);
        if (value >= 0 && value <= 2 && sqlite3_step(s) == SQLITE_DONE) state = value; // raw-sql-ok:codeindex-derived
    }
    if (sqlite3_finalize(s) != SQLITE_OK) state = -1;
    return state;
}

bool ci_pages_note_import(struct ci_store *store)
{
    int state = page_state(ci_store_db(store));
    return state >= 0 && ci_pages_set_state(store, state == 2 ? 2 : 1);
}

static bool page_text(sqlite3_stmt *s, int col, char *out, size_t cap)
{
    if (sqlite3_column_type(s, col) != SQLITE_TEXT) return false;
    int n = sqlite3_column_bytes(s, col);
    const unsigned char *text = sqlite3_column_text(s, col);
    if (!text || n <= 0 || (size_t)n >= cap || memchr(text, 0, (size_t)n)) return false;
    memcpy(out, text, (size_t)n);
    out[n] = '\0';
    return true;
}

static bool page_row(sqlite3_stmt *s, struct ci_page *row)
{
    if (!page_text(s, 0, row->directory, sizeof(row->directory)) ||
        !page_text(s, 1, row->tree_oid, sizeof(row->tree_oid)) ||
        !page_text(s, 2, row->source_commit, sizeof(row->source_commit)) ||
        !page_text(s, 3, row->body, sizeof(row->body)) ||
        sqlite3_column_type(s, 4) != SQLITE_BLOB || sqlite3_column_bytes(s, 4) != 32)
        return false;
    const void *root = sqlite3_column_blob(s, 4);
    if (!root) return false;
    memcpy(row->artifact_root, root, 32);
    return true;
}

static bool page_artifact_ok(const char *root, const struct ci_page *row)
{
    uint8_t *data = NULL, digest[32];
    size_t size = 0;
    if (vcs_object_load_raw_bounded(root, row->artifact_root, CI_PAGE_MANIFEST_MAX,
                                    &data, &size) != 0) return false;
    struct sha3_256_ctx hash;
    uint8_t tag = VCS_TAG_BLOB;
    sha3_256_init(&hash);
    sha3_256_write(&hash, &tag, 1);
    sha3_256_write(&hash, data, size);
    sha3_256_finalize(&hash, digest);
    bool ok = !memcmp(digest, row->artifact_root, sizeof(digest)) &&
              page_manifest_line(data, size, row->body);
    free(data);
    return ok;
}

static bool page_copy_rows(struct ci_store *from, struct ci_store *to)
{
    sqlite3_stmt *read = NULL, *write = NULL;
    bool ok = sqlite3_prepare_v2(ci_store_db(from),
        "SELECT directory,tree_oid,source_commit,body,artifact_root FROM pages "
        "ORDER BY directory,tree_oid,source_commit,artifact_root", -1, &read, NULL) == SQLITE_OK &&
        sqlite3_prepare_v2(ci_store_db(to),
        "INSERT INTO pages(directory,tree_oid,source_commit,body,artifact_root) VALUES(?1,?2,?3,?4,?5)",
        -1, &write, NULL) == SQLITE_OK;
    int rc = SQLITE_ERROR;
    size_t count = 0;
    struct ci_page row;
    while (ok && (rc = sqlite3_step(read)) == SQLITE_ROW) { // raw-sql-ok:codeindex-derived
        if (++count > 65536 || !page_row(read, &row) ||
            !page_insert_one(write, &row, row.artifact_root)) ok = false;
    }
    if (ok && rc != SQLITE_DONE) ok = false;
    if (read && sqlite3_finalize(read) != SQLITE_OK) ok = false;
    if (write && sqlite3_finalize(write) != SQLITE_OK) ok = false;
    return ok;
}

bool ci_pages_copy(struct ci_store *from, struct ci_store *to)
{
    if (!from || !to) return false;
    ci_store_lock(from);
    bool valid = false;
    bool ok = ci_store_retrieval_projection_is_valid(from, &valid) && valid;
    int state = ok ? page_state(ci_store_db(from)) : -1;
    ok = state >= 0 && page_copy_rows(from, to) && ci_pages_set_state(to, state);
    ci_store_unlock(from);
    return ok;
}

static int page_collect(sqlite3 *db, const char *directory, struct ci_page *rows, int cap)
{
    sqlite3_stmt *s = NULL;
    bool ok = sqlite3_prepare_v2(db, "SELECT directory,tree_oid,source_commit,body,artifact_root "
        "FROM pages WHERE directory=?1 ORDER BY tree_oid COLLATE BINARY,"
        "source_commit COLLATE BINARY,artifact_root", -1, &s, NULL) == SQLITE_OK &&
        sqlite3_bind_text(s, 1, directory, -1, SQLITE_TRANSIENT) == SQLITE_OK;
    int count = 0, rc = SQLITE_ERROR;
    while (ok && (rc = sqlite3_step(s)) == SQLITE_ROW) { // raw-sql-ok:codeindex-derived
        if (count == cap || !page_row(s, &rows[count])) { ok = false; break; }
        count++;
    }
    if (ok && rc != SQLITE_DONE) ok = false;
    if (s && sqlite3_finalize(s) != SQLITE_OK) ok = false;
    return ok ? count : -1;
}

static int page_collect_verified(struct codeindex *ci, const char *directory,
                                 struct ci_page *rows, int cap, bool *prior_untrusted)
{
    ci_store_lock(ci->store);
    bool valid = false;
    bool ok = ci_store_retrieval_projection_is_valid(ci->store, &valid) && valid;
    int state = ok ? page_state(ci_store_db(ci->store)) : -1;
    if (state >= 0) *prior_untrusted = state == 2;
    int count = state >= 0 ? page_collect(ci_store_db(ci->store), directory, rows, cap) : -1;
    ci_store_unlock(ci->store);
    for (int i = 0; i < count; i++)
        if (!page_artifact_ok(ci->root, &rows[i])) return -2;
    return count;
}

int codeindex_pages_list(struct codeindex *ci, const char *directory,
                         struct ci_page *out, int cap, bool *prior_untrusted)
{
    if (prior_untrusted) *prior_untrusted = false;
    if (!ci || !ci->store || !directory || !directory[0] || !out || !prior_untrusted || cap < 1 || cap > 256)
        return -1;
    struct ci_page *rows = zcl_calloc((size_t)cap, sizeof(*rows), "codeindex page results");
    if (!rows) return -1;
    int count = page_collect_verified(ci, directory, rows, cap, prior_untrusted);
    if (count >= 0) memcpy(out, rows, (size_t)count * sizeof(*out));
    free(rows);
    return count;
}
