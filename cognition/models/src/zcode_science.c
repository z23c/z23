/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: ActiveRecord persistence for ZCODE science plans and the
 *          rebuildable study/result/reproduction/findings/vote/review
 *          projections. */

#include "models/zcode_science.h"

#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

DEFINE_MODEL_CALLBACKS(zcode_science_plan)
DEFINE_MODEL_CALLBACKS(zcode_science_entry)

static bool science_hex(const char *value, bool zero_allowed)
{
    if (!value) return false;
    if (zero_allowed && !value[0]) return true;
    if (strlen(value) != 64) return false;
    for (size_t i = 0; i < 64; i++)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f')))
            return false;
    return true;
}

static bool science_kind_valid(const char *kind)
{
    return kind &&
           (strcmp(kind, "study") == 0 || strcmp(kind, "work") == 0 ||
            strcmp(kind, "findings") == 0 || strcmp(kind, "review") == 0 ||
            strcmp(kind, "vote") == 0);
}

static bool science_wire_hex_valid(const char *wire_hex)
{
    if (!wire_hex) return false;
    size_t len = strlen(wire_hex);
    if (len == 0 || (len & 1u) != 0 || len >= ZCODE_SCIENCE_PLAN_WIRE_HEX_MAX)
        return false;
    for (size_t i = 0; i < len; i++)
        if (!((wire_hex[i] >= '0' && wire_hex[i] <= '9') ||
              (wire_hex[i] >= 'a' && wire_hex[i] <= 'f')))
            return false;
    return true;
}

bool db_zcode_science_plan_validate(
    const struct db_zcode_science_plan *row, struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!row) {
        validates_custom(errors, false, "record", "is null");
        return false;
    }
    validates_custom(errors, science_hex(row->plan_root, false),
                     "plan_root", "must be a SHA3 root");
    validates_custom(errors, science_kind_valid(row->kind), "kind",
                     "must be study, work, findings, review, or vote");
    validates_custom(errors, science_hex(row->request_hash, false),
                     "request_hash", "must be a SHA3 request identity");
    validates_custom(errors, science_wire_hex_valid(row->wire_hex),
                     "wire_hex", "must be even-length lowercase hex");
    validates_custom(errors, science_hex(row->result_root, true),
                     "result_root", "must be empty or a SHA3 root");
    validates_custom(errors,
                     strcmp(row->state, ZCODE_SCIENCE_PLAN_STATE_PLANNED) ==
                         0 ||
                         strcmp(row->state,
                                ZCODE_SCIENCE_PLAN_STATE_COMMITTED) == 0,
                     "state", "must be PLANNED or COMMITTED");
    validates_custom(errors,
                     (strcmp(row->state, ZCODE_SCIENCE_PLAN_STATE_COMMITTED) ==
                      0) == (row->result_root[0] != '\0'),
                     "state_roots", "COMMITTED requires a result root");
    validates_custom(errors, row->expires_unix > 0, "expires_unix",
                     "must be positive");
    validates_non_negative(errors, row, created_at);
    return !ar_errors_any(errors);
}

bool db_zcode_science_entry_validate(
    const struct db_zcode_science_entry *row, struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!row) {
        validates_custom(errors, false, "record", "is null");
        return false;
    }
    validates_custom(errors, science_hex(row->root, false), "root",
                     "must be a SHA3 root");
    validates_custom(errors, science_hex(row->study_root, true), "study_root",
                     "must be empty or a SHA3 root");
    validates_custom(errors, science_hex(row->link_root, true), "link_root",
                     "must be empty or a SHA3 root");
    validates_custom(errors, science_hex(row->aux_root, true), "aux_root",
                     "must be empty or a SHA3 root");
    validates_custom(errors, science_hex(row->author, true), "author",
                     "must be empty or a 32-byte hex key");
    validates_non_negative(errors, row, code);
    validates_non_negative(errors, row, flags);
    validates_non_negative(errors, row, sequence);
    validates_non_negative(errors, row, created_at);
    validates_non_negative(errors, row, expires_at);
    return !ar_errors_any(errors);
}

bool db_zcode_science_plan_save(
    struct node_db *ndb, const struct db_zcode_science_plan *row)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !row)
        LOG_FAIL("model", "db_zcode_science_plan_save: bad args");
    AR_ADHOC_SAVE(ndb, st,
        "INSERT INTO zcode_science_plans "
        "(plan_root,kind,request_hash,wire_hex,result_root,state,"
        "expires_unix,created_at) VALUES(?,?,?,?,?,?,?,?) "
        "ON CONFLICT(plan_root) DO UPDATE SET "
        "result_root=excluded.result_root,state=excluded.state",
        db_zcode_science_plan_callbacks(), "zcode_science_plan", row,
        db_zcode_science_plan_validate,
        AR_BIND_TEXT(st, 1, row->plan_root);
        AR_BIND_TEXT(st, 2, row->kind);
        AR_BIND_TEXT(st, 3, row->request_hash);
        AR_BIND_TEXT(st, 4, row->wire_hex);
        AR_BIND_TEXT(st, 5, row->result_root);
        AR_BIND_TEXT(st, 6, row->state);
        AR_BIND_INT(st, 7, row->expires_unix);
        AR_BIND_INT(st, 8, row->created_at));
}

static void plan_read(struct db_zcode_science_plan *out, sqlite3_stmt *st)
{
    AR_READ_STR(st, 0, out->plan_root, sizeof(out->plan_root));
    AR_READ_STR(st, 1, out->kind, sizeof(out->kind));
    AR_READ_STR(st, 2, out->request_hash, sizeof(out->request_hash));
    AR_READ_STR(st, 3, out->wire_hex, sizeof(out->wire_hex));
    AR_READ_STR(st, 4, out->result_root, sizeof(out->result_root));
    AR_READ_STR(st, 5, out->state, sizeof(out->state));
    out->expires_unix = AR_COL_INT(st, 6);
    out->created_at = AR_COL_INT(st, 7);
}

#define ZCODE_SCIENCE_PLAN_COLS \
    "plan_root,kind,request_hash,wire_hex,result_root,state," \
    "expires_unix,created_at"

bool db_zcode_science_plan_find_by_request(
    struct node_db *ndb, const char *request_hash,
    struct db_zcode_science_plan *out)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !request_hash || !out) return false;
    AR_QUERY_ONE_BOOL(ndb, st,
        "SELECT " ZCODE_SCIENCE_PLAN_COLS " FROM zcode_science_plans "
        "WHERE request_hash=?",
        AR_BIND_TEXT(st, 1, request_hash), plan_read(out, st));
}

bool db_zcode_science_plan_find(
    struct node_db *ndb, const char *plan_root,
    struct db_zcode_science_plan *out)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !plan_root || !out) return false;
    AR_QUERY_ONE_BOOL(ndb, st,
        "SELECT " ZCODE_SCIENCE_PLAN_COLS " FROM zcode_science_plans "
        "WHERE plan_root=?",
        AR_BIND_TEXT(st, 1, plan_root), plan_read(out, st));
}

#define SCIENCE_ENTRY_BINDS(st, row) \
    AR_BIND_TEXT(st, 1, (row)->root); \
    AR_BIND_TEXT(st, 2, (row)->study_root); \
    AR_BIND_TEXT(st, 3, (row)->link_root); \
    AR_BIND_TEXT(st, 4, (row)->aux_root); \
    AR_BIND_TEXT(st, 5, (row)->author); \
    AR_BIND_INT(st, 6, (row)->code); \
    AR_BIND_INT(st, 7, (row)->flags); \
    AR_BIND_INT(st, 8, (row)->sequence); \
    AR_BIND_INT(st, 9, (row)->created_at); \
    AR_BIND_INT(st, 10, (row)->expires_at)

static void entry_read(struct db_zcode_science_entry *out, sqlite3_stmt *st)
{
    memset(out, 0, sizeof(*out));
    AR_READ_STR(st, 0, out->root, sizeof(out->root));
    AR_READ_STR(st, 1, out->study_root, sizeof(out->study_root));
    AR_READ_STR(st, 2, out->link_root, sizeof(out->link_root));
    AR_READ_STR(st, 3, out->aux_root, sizeof(out->aux_root));
    AR_READ_STR(st, 4, out->author, sizeof(out->author));
    out->code = AR_COL_INT(st, 5);
    out->flags = AR_COL_INT(st, 6);
    out->sequence = AR_COL_INT(st, 7);
    out->created_at = AR_COL_INT(st, 8);
    out->expires_at = AR_COL_INT(st, 9);
}

#define ZCODE_SCIENCE_ENTRY_COLS \
    "root,study_root,link_root,aux_root,author,code,flags,sequence," \
    "created_at,expires_at"

#define ZCODE_SCIENCE_TABLE_MODEL(NAME, TABLE)                              \
    bool db_zcode_science_##NAME##_save(                                    \
        struct node_db *ndb, const struct db_zcode_science_entry *row)      \
    {                                                                       \
        sqlite3_stmt *st = NULL;                                            \
        if (!ndb || !ndb->open || !row)                                     \
            LOG_FAIL("model", "db_zcode_science_" #NAME "_save: bad args"); \
        AR_ADHOC_SAVE(ndb, st,                                              \
            "INSERT INTO " TABLE " "                                        \
            "(root,study_root,link_root,aux_root,author,code,flags,"        \
            "sequence,created_at,expires_at) "                              \
            "VALUES(?,?,?,?,?,?,?,?,?,?) "                                  \
            "ON CONFLICT(root) DO NOTHING",                                 \
            db_zcode_science_entry_callbacks(),                             \
            "zcode_science_" #NAME, row,                                    \
            db_zcode_science_entry_validate,                                \
            SCIENCE_ENTRY_BINDS(st, row));                                  \
    }                                                                       \
    bool db_zcode_science_##NAME##_find(                                    \
        struct node_db *ndb, const char *root,                              \
        struct db_zcode_science_entry *out)                                 \
    {                                                                       \
        sqlite3_stmt *st = NULL;                                            \
        if (!ndb || !ndb->open || !root || !out) return false;              \
        AR_QUERY_ONE_BOOL(ndb, st,                                          \
            "SELECT " ZCODE_SCIENCE_ENTRY_COLS " FROM " TABLE " "           \
            "WHERE root=?",                                                 \
            AR_BIND_TEXT(st, 1, root), entry_read(out, st));                \
    }

ZCODE_SCIENCE_TABLE_MODEL(study, "zcode_science_studies")
ZCODE_SCIENCE_TABLE_MODEL(result, "zcode_science_results")
ZCODE_SCIENCE_TABLE_MODEL(reproduction, "zcode_science_reproductions")
ZCODE_SCIENCE_TABLE_MODEL(findings, "zcode_science_findings")
ZCODE_SCIENCE_TABLE_MODEL(vote, "zcode_science_votes")
ZCODE_SCIENCE_TABLE_MODEL(review, "zcode_science_reviews")

int db_zcode_science_study_list(
    struct node_db *ndb, struct db_zcode_science_entry *out, int max)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !out || max <= 0) return 0;
    AR_QUERY_LIST(ndb, st,
        "SELECT " ZCODE_SCIENCE_ENTRY_COLS " FROM zcode_science_studies "
        "ORDER BY created_at ASC, root ASC",
        out, (size_t)max, , entry_read(&out[count], st));
}

/* S5 (additive): the zcode.science.discover filter-first predicate read.
 * search is a substring over the study/hypothesis root hex (LIKE with
 * caller-escaped wildcards); category is one of active|expired|retracted,
 * decided against expires_at and the 0x10000 retraction bit at now_unix.
 * Deterministic order: root ascending. */
int db_zcode_science_study_list_filtered(
    struct node_db *ndb, const char *search_like, const char *category,
    int64_t now_unix, struct db_zcode_science_entry *out, int max)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !out || max <= 0) return 0;
    char sql[512];
    int n = snprintf(sql, sizeof(sql),
        "SELECT " ZCODE_SCIENCE_ENTRY_COLS " FROM zcode_science_studies "
        "WHERE 1=1");
    if (n <= 0) return 0;
    size_t off = (size_t)n;
    if (search_like)
        off += (size_t)snprintf(sql + off, sizeof(sql) - off,
            " AND (root LIKE ? ESCAPE '\\' OR link_root LIKE ? ESCAPE '\\')");
    if (category && strcmp(category, "active") == 0)
        off += (size_t)snprintf(sql + off, sizeof(sql) - off,
            " AND expires_at > ? AND (flags & 65536) = 0");
    else if (category && strcmp(category, "expired") == 0)
        off += (size_t)snprintf(sql + off, sizeof(sql) - off,
            " AND expires_at <= ?");
    else if (category && strcmp(category, "retracted") == 0)
        off += (size_t)snprintf(sql + off, sizeof(sql) - off,
            " AND (flags & 65536) <> 0");
    if (off >= sizeof(sql) - 24) return 0;
    off += (size_t)snprintf(sql + off, sizeof(sql) - off,
        " ORDER BY root ASC");
    if (off >= sizeof(sql)) return 0;
    AR_QUERY_LIST(ndb, st, sql, out, (size_t)max,
        int bind_at = 1;
        if (search_like) {
            AR_BIND_TEXT(st, bind_at, search_like);
            bind_at++;
            AR_BIND_TEXT(st, bind_at, search_like);
            bind_at++;
        }
        if (category && strcmp(category, "retracted") != 0) {
            AR_BIND_INT(st, bind_at, now_unix);
            bind_at++;
        }
        (void)bind_at;,
        entry_read(&out[count], st));
}

bool db_zcode_science_vote_sequence_seen(
    struct node_db *ndb, const char *voter_zid_root, int64_t sequence,
    const char *except_vote_id)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !voter_zid_root) return false;
    AR_QUERY_EXISTS(ndb, st,
        "SELECT root FROM zcode_science_votes "
        "WHERE author=? AND sequence=? AND root<>?",
        AR_BIND_TEXT(st, 1, voter_zid_root);
        AR_BIND_INT(st, 2, sequence);
        AR_BIND_TEXT(st, 3, except_vote_id ? except_vote_id : ""));
}

static bool entry_delete_all(struct node_db *ndb, const char *table)
{
    char sql[128];
    sqlite3_stmt *st = NULL;
    int n = snprintf(sql, sizeof(sql), "DELETE FROM %s", table);
    if (n <= 0 || (size_t)n >= sizeof(sql))
        LOG_FAIL("model", "entry_delete_all: table name too long");
    struct db_zcode_science_entry record;
    memset(&record, 0, sizeof(record));
    AR_ADHOC_DESTROY(ndb, st, sql,
                     db_zcode_science_entry_callbacks(), &record, );
}

bool db_zcode_science_projection_clear(struct node_db *ndb)
{
    static const char *const tables[] = {
        "zcode_science_studies", "zcode_science_results",
        "zcode_science_reproductions", "zcode_science_findings",
        "zcode_science_votes", "zcode_science_reviews",
    };
    if (!ndb || !ndb->open)
        LOG_FAIL("model", "db_zcode_science_projection_clear: bad args");
    bool ok = true;
    for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); i++)
        if (!entry_delete_all(ndb, tables[i]))
            ok = false;
    if (!ok)
        LOG_FAIL("model", "db_zcode_science_projection_clear: a delete failed");
    return true;
}
