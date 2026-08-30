/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Adversarial coverage for the typed model query builder
 * (app/models/src/query_builder.c).
 *
 * The builder exists to make ONE property true by construction: a
 * caller-supplied value can only reach a statement as a bound parameter,
 * and an identifier can only come from the closed set in
 * app/models/include/models/query_schema.def. Most of this file is an
 * attempt to DEFEAT that property, because a safety claim nobody tried to
 * break is a claim nobody should believe.
 *
 * The attacks fall into four families:
 *
 *   1. Value smuggling — classic SQL-injection payloads pushed through
 *      every value entry point, then asserted absent from the emitted text.
 *   2. Identifier smuggling — the API takes enums, so the only remaining
 *      lever is an integer cast into one. Out-of-range ids and a column
 *      belonging to a different table must fail the statement CLOSED.
 *   3. Structural abuse — empty IN(), buffer and bind-array overflow, a
 *      clause in the wrong section, an unterminated predicate group, a
 *      poisoned subquery.
 *   4. Arity — the emitted '?' count and the collected bind count must
 *      agree, or qb_prepare_db() refuses rather than binding an implicit
 *      NULL.
 *
 * The last section is a live round trip against an in-memory node.db
 * through the CONVERTED models, so the safety proof is not only about text:
 * an injection payload written through the builder comes back byte-for-byte
 * as data, and the table it tried to drop is still there.
 *
 * No clock dependence beyond a monotonic "epoch is a plausible integer"
 * bound, no network, no live datadir — the fixture is ":memory:". */

#include "test/test_core.h"

#include "models/database.h"
#include "models/query_builder.h"
#include "models/peer.h"
#include "models/auth_challenge.h"
#include "models/onion_announcement.h"
#include "models/parity_sample.h"
#include "models/op_return_index.h"
#include "models/peer_chain_observation.h"

/* Two payloads that end a statement early and start another. If either
 * ever reaches SQL text, the builder has failed its only job. */
#define QB_ATTACK_DROP  "'; DROP TABLE auth_challenges; --"
#define QB_ATTACK_TAUT  "x' OR '1'='1"

static int qb_count_char(const char *s, char c)
{
    int n = 0;
    for (; *s; s++)
        if (*s == c) n++;
    return n;
}

int test_activerecord_query_builder(void);
int test_activerecord_query_builder(void)
{
    int failures = 0;

    /* ── 1. Emitted text is exactly what the builder chose ─────────── */

    TEST("qb: SELECT emits the closed identifiers and one '?' per value") {
        struct qb q;
        qb_select(&q, QB_T_peers);
        qb_select_column(&q, QB_C_peers_id);
        qb_select_column(&q, QB_C_peers_port);
        qb_where_int(&q, QB_C_peers_port, QB_EQ, 8033);
        qb_order_by(&q, QB_C_peers_last_seen, QB_DESC);
        qb_limit(&q, 10);
        ASSERT(qb_ok(&q));
        ASSERT_STR_EQ(qb_sql(&q),
            "SELECT id,port FROM peers WHERE port=? "
            "ORDER BY last_seen DESC LIMIT ?");
        ASSERT_EQ(qb_bind_count(&q), 2);
        PASS();
    }

    TEST("qb: UPDATE, DELETE, INSERT and upsert emit their expected shapes") {
        struct qb q;
        qb_update(&q, QB_T_peers);
        qb_set_int(&q, QB_C_peers_last_seen, 5);
        qb_set_increment(&q, QB_C_peers_attempts, 1);
        qb_where_int(&q, QB_C_peers_port, QB_EQ, 1);
        ASSERT_STR_EQ(qb_sql(&q),
            "UPDATE peers SET last_seen=?,attempts=attempts+? WHERE port=?");

        struct qb d;
        qb_delete(&d, QB_T_auth_challenges);
        qb_group_begin(&d, QB_OR);
        qb_where_int(&d, QB_C_auth_challenges_issued_at, QB_LT, 7);
        qb_where_int(&d, QB_C_auth_challenges_consumed, QB_EQ, 1);
        qb_group_end(&d);
        ASSERT_STR_EQ(qb_sql(&d),
            "DELETE FROM auth_challenges WHERE (issued_at<? OR consumed=?)");

        struct qb i;
        qb_insert(&i, QB_T_onion_announcements, QB_INSERT_OR_REPLACE);
        qb_value_text(&i, QB_C_onion_announcements_onion_address, "a.onion");
        qb_value_int(&i, QB_C_onion_announcements_announced_at, 3);
        ASSERT_STR_EQ(qb_sql(&i),
            "INSERT OR REPLACE INTO onion_announcements "
            "(onion_address,announced_at) VALUES (?,?)");

        static const enum qb_column target[] = { QB_C_zswap_ads_quote_root };
        struct qb u;
        qb_insert(&u, QB_T_zswap_ads, QB_INSERT_PLAIN);
        qb_value_int(&u, QB_C_zswap_ads_token_amount, 1);
        qb_on_conflict_do_update(&u, target, 1);
        qb_conflict_set_excluded(&u, QB_C_zswap_ads_last_seen_unix);
        qb_conflict_set_increment(&u, QB_C_zswap_ads_seen_count, 1);
        ASSERT_STR_EQ(qb_sql(&u),
            "INSERT INTO zswap_ads (token_amount) VALUES (?) "
            "ON CONFLICT(quote_root) DO UPDATE SET "
            "last_seen_unix=excluded.last_seen_unix,"
            "seen_count=zswap_ads.seen_count+?");
        PASS();
    }

    TEST("qb: a built subquery splices its text AND its binds, in order") {
        struct qb keep;
        qb_select(&keep, QB_T_parity_samples);
        qb_select_column(&keep, QB_C_parity_samples_id);
        qb_order_by(&keep, QB_C_parity_samples_id, QB_DESC);
        qb_limit(&keep, 50);

        struct qb q;
        qb_delete(&q, QB_T_parity_samples);
        qb_where_int(&q, QB_C_parity_samples_ts, QB_LT, 99);
        qb_where_in_select(&q, QB_C_parity_samples_id, true, &keep);
        ASSERT_STR_EQ(qb_sql(&q),
            "DELETE FROM parity_samples WHERE ts<? AND id NOT IN "
            "(SELECT id FROM parity_samples ORDER BY id DESC LIMIT ?)");
        /* One bind of the parent, then the subquery's — the same order the
         * '?' appear, which is what qb_prepare_db() relies on. */
        ASSERT_EQ(qb_bind_count(&q), 2);
        ASSERT_EQ(qb_count_char(qb_sql(&q), '?'), qb_bind_count(&q));
        PASS();
    }

    /* ── 2. Value smuggling ─────────────────────────────────────────── */

    TEST("qb ATTACK: an injection payload never reaches SQL text (WHERE)") {
        struct qb q;
        qb_select(&q, QB_T_auth_challenges);
        qb_select_column(&q, QB_C_auth_challenges_address);
        qb_where_text(&q, QB_C_auth_challenges_nonce_hex, QB_EQ,
                      QB_ATTACK_DROP);
        qb_where_text(&q, QB_C_auth_challenges_address, QB_EQ,
                      QB_ATTACK_TAUT);
        const char *sql = qb_sql(&q);
        ASSERT(qb_ok(&q));
        ASSERT(strstr(sql, "DROP") == NULL);
        ASSERT(strstr(sql, "--") == NULL);
        ASSERT(strstr(sql, "OR '1'") == NULL);
        ASSERT(strchr(sql, '\'') == NULL);   /* no quote character at all */
        ASSERT_STR_EQ(sql,
            "SELECT address FROM auth_challenges "
            "WHERE nonce_hex=? AND address=?");
        ASSERT_EQ(qb_bind_count(&q), 2);
        PASS();
    }

    TEST("qb ATTACK: the same payload through INSERT/UPDATE/IN is inert") {
        struct qb ins;
        qb_insert(&ins, QB_T_auth_challenges, QB_INSERT_PLAIN);
        qb_value_text(&ins, QB_C_auth_challenges_nonce_hex, QB_ATTACK_DROP);
        ASSERT(strstr(qb_sql(&ins), "DROP") == NULL);
        ASSERT_STR_EQ(qb_sql(&ins),
            "INSERT INTO auth_challenges (nonce_hex) VALUES (?)");

        struct qb upd;
        qb_update(&upd, QB_T_auth_challenges);
        qb_set_text(&upd, QB_C_auth_challenges_address, QB_ATTACK_DROP);
        qb_where_text(&upd, QB_C_auth_challenges_nonce_hex, QB_EQ,
                      QB_ATTACK_TAUT);
        ASSERT(strstr(qb_sql(&upd), "DROP") == NULL);
        ASSERT_STR_EQ(qb_sql(&upd),
            "UPDATE auth_challenges SET address=? WHERE nonce_hex=?");

        const char *const hostile[] = { QB_ATTACK_DROP, QB_ATTACK_TAUT };
        struct qb in;
        qb_select(&in, QB_T_auth_challenges);
        qb_select_one(&in);
        qb_where_in_text(&in, QB_C_auth_challenges_address, hostile, 2);
        ASSERT(strstr(qb_sql(&in), "DROP") == NULL);
        ASSERT_STR_EQ(qb_sql(&in),
            "SELECT 1 FROM auth_challenges WHERE address IN (?,?)");
        PASS();
    }

    TEST("qb ATTACK: a blob of raw SQL bytes is bound, never emitted") {
        /* Text is not the only door: a blob column takes arbitrary bytes. */
        struct qb q;
        qb_select(&q, QB_T_peers);
        qb_select_column(&q, QB_C_peers_id);
        qb_where_blob(&q, QB_C_peers_ip, QB_EQ, QB_ATTACK_DROP,
                      strlen(QB_ATTACK_DROP));
        ASSERT(strstr(qb_sql(&q), "DROP") == NULL);
        ASSERT_STR_EQ(qb_sql(&q), "SELECT id FROM peers WHERE ip=?");
        PASS();
    }

    /* ── 3. Identifier smuggling ────────────────────────────────────── */

    TEST("qb ATTACK: an out-of-range column id fails the statement closed") {
        struct qb q;
        qb_select(&q, QB_T_peers);
        qb_select_column(&q, (enum qb_column)(QB_COLUMN_COUNT + 7));
        ASSERT(!qb_ok(&q));
        ASSERT_STR_EQ(qb_sql(&q), "");
        ASSERT(strstr(qb_error(&q), "closed schema set") != NULL);

        struct qb n;
        qb_select(&n, QB_T_peers);
        qb_where_int(&n, (enum qb_column)-1, QB_EQ, 1);
        ASSERT(!qb_ok(&n));
        ASSERT_STR_EQ(qb_sql(&n), "");
        PASS();
    }

    TEST("qb ATTACK: a column from another table is refused") {
        struct qb q;
        qb_select(&q, QB_T_auth_challenges);
        qb_select_column(&q, QB_C_auth_challenges_address);
        /* peers.ip is a real, in-range column — just not this table's. */
        qb_where_blob(&q, QB_C_peers_ip, QB_EQ, "abc", 3);
        ASSERT(!qb_ok(&q));
        ASSERT_STR_EQ(qb_sql(&q), "");
        ASSERT(strstr(qb_error(&q), "does not belong") != NULL);
        PASS();
    }

    TEST("qb ATTACK: out-of-range table, operator, direction and mode") {
        struct qb t;
        qb_select(&t, (enum qb_table)(QB_TABLE_COUNT + 1));
        ASSERT(!qb_ok(&t));

        struct qb o;
        qb_select(&o, QB_T_peers);
        qb_select_column(&o, QB_C_peers_id);
        qb_where_int(&o, QB_C_peers_port, (enum qb_op)99, 1);
        ASSERT(!qb_ok(&o));

        struct qb d;
        qb_select(&d, QB_T_peers);
        qb_select_column(&d, QB_C_peers_id);
        qb_order_by(&d, QB_C_peers_id, (enum qb_dir)42);
        ASSERT(!qb_ok(&d));

        struct qb m;
        qb_insert(&m, QB_T_peers, (enum qb_insert_mode)77);
        ASSERT(!qb_ok(&m));
        PASS();
    }

    /* ── 4. Structural abuse ────────────────────────────────────────── */

    TEST("qb ATTACK: empty IN() is refused, not silently matched") {
        struct qb q;
        qb_select(&q, QB_T_peers);
        qb_select_column(&q, QB_C_peers_id);
        qb_where_in_int(&q, QB_C_peers_port, NULL, 0);
        ASSERT(!qb_ok(&q));
        ASSERT(strstr(qb_error(&q), "IN ()") != NULL);
        PASS();
    }

    TEST("qb ATTACK: overflowing the bind array fails closed") {
        struct qb q;
        qb_select(&q, QB_T_peers);
        qb_select_column(&q, QB_C_peers_id);
        for (int i = 0; i < QB_MAX_BINDS + 5; i++)
            qb_where_int(&q, QB_C_peers_port, QB_EQ, i);
        ASSERT(!qb_ok(&q));
        ASSERT_STR_EQ(qb_sql(&q), "");
        PASS();
    }

    TEST("qb ATTACK: overflowing the SQL buffer fails closed") {
        struct qb q;
        qb_select(&q, QB_T_peer_chain_observations);
        /* Long identifiers, repeated far past QB_SQL_MAX. */
        for (int i = 0; i < 400; i++)
            qb_select_column(&q, QB_C_peer_chain_observations_observed_at);
        ASSERT(!qb_ok(&q));
        ASSERT(strstr(qb_error(&q), "exceeds") != NULL);
        PASS();
    }

    TEST("qb ATTACK: a clause in the wrong section is refused") {
        struct qb a;
        qb_select(&a, QB_T_peers);
        qb_value_int(&a, QB_C_peers_port, 1);      /* values on a SELECT */
        ASSERT(!qb_ok(&a));

        struct qb b;
        qb_insert(&b, QB_T_peers, QB_INSERT_PLAIN);
        qb_value_int(&b, QB_C_peers_port, 1);
        qb_where_int(&b, QB_C_peers_port, QB_EQ, 1);  /* WHERE on an INSERT */
        ASSERT(!qb_ok(&b));

        struct qb c;
        qb_update(&c, QB_T_peers);
        qb_where_int(&c, QB_C_peers_port, QB_EQ, 1);  /* UPDATE with no SET */
        ASSERT(!qb_ok(&c));

        struct qb d;
        qb_select(&d, QB_T_peers);
        qb_select_column(&d, QB_C_peers_id);
        qb_limit(&d, 5);
        qb_order_by(&d, QB_C_peers_id, QB_ASC);       /* ORDER after LIMIT */
        ASSERT(!qb_ok(&d));

        struct qb e;
        qb_select(&e, QB_T_peers);                    /* empty projection */
        qb_where_int(&e, QB_C_peers_port, QB_EQ, 1);
        ASSERT(!qb_ok(&e));
        PASS();
    }

    TEST("qb ATTACK: an unterminated predicate group is refused") {
        struct qb q;
        qb_delete(&q, QB_T_peers);
        qb_group_begin(&q, QB_OR);
        qb_where_int(&q, QB_C_peers_port, QB_EQ, 1);
        /* no qb_group_end */
        ASSERT_STR_EQ(qb_sql(&q), "");
        ASSERT(!qb_ok(&q));
        ASSERT(strstr(qb_error(&q), "left open") != NULL);
        PASS();
    }

    TEST("qb ATTACK: a poisoned subquery poisons its parent") {
        struct qb bad;
        qb_select(&bad, QB_T_parity_samples);
        qb_select_column(&bad, (enum qb_column)(QB_COLUMN_COUNT + 3));
        ASSERT(!qb_ok(&bad));

        struct qb q;
        qb_delete(&q, QB_T_parity_samples);
        qb_where_in_select(&q, QB_C_parity_samples_id, true, &bad);
        ASSERT(!qb_ok(&q));
        ASSERT_STR_EQ(qb_sql(&q), "");
        PASS();
    }

    TEST("qb ATTACK: the failure latch swallows every later call") {
        struct qb q;
        qb_select(&q, QB_T_peers);
        qb_select_column(&q, (enum qb_column)(QB_COLUMN_COUNT + 1));
        const char *first = qb_error(&q);
        char kept[QB_ERROR_MAX];
        snprintf(kept, sizeof(kept), "%s", first);
        /* Everything after the first refusal must be inert — no text, no
         * binds, and the ORIGINAL reason preserved. */
        qb_select_column(&q, QB_C_peers_id);
        qb_where_int(&q, QB_C_peers_port, QB_EQ, 1);
        qb_order_by(&q, QB_C_peers_id, QB_ASC);
        qb_limit(&q, 10);
        ASSERT(!qb_ok(&q));
        ASSERT_EQ(qb_bind_count(&q), 0);
        ASSERT_STR_EQ(qb_sql(&q), "");
        ASSERT_STR_EQ(qb_error(&q), kept);
        PASS();
    }

    /* ── 5. Arity: '?' in the text == values collected ──────────────── */

    TEST("qb: emitted placeholder count equals the collected bind count") {
        struct qb q;
        qb_insert(&q, QB_T_op_return_index, QB_INSERT_OR_IGNORE);
        qb_value_blob(&q, QB_C_op_return_index_txid, "0123456789abcdef", 16);
        qb_value_int(&q, QB_C_op_return_index_vout_n, 1);
        qb_value_int(&q, QB_C_op_return_index_height, 2);
        qb_value_blob(&q, QB_C_op_return_index_tag, "t", 1);
        qb_value_text(&q, QB_C_op_return_index_tag_text, "t");
        qb_value_int(&q, QB_C_op_return_index_payload_len, 0);
        qb_value_null(&q, QB_C_op_return_index_payload_sha3);
        ASSERT(qb_ok(&q));
        ASSERT_EQ(qb_count_char(qb_sql(&q), '?'), qb_bind_count(&q));
        ASSERT_EQ(qb_bind_count(&q), 7);

        struct qb s;
        qb_select(&s, QB_T_peers);
        qb_select_column(&s, QB_C_peers_id);
        qb_where_between_int(&s, QB_C_peers_last_seen, 1, 2);
        const int64_t ports[] = { 1, 2, 3 };
        qb_where_in_int(&s, QB_C_peers_port, ports, 3);
        qb_where_null(&s, QB_C_peers_source, true);
        qb_limit(&s, 4);
        qb_offset(&s, 5);
        ASSERT(qb_ok(&s));
        ASSERT_EQ(qb_count_char(qb_sql(&s), '?'), qb_bind_count(&s));
        ASSERT_STR_EQ(qb_sql(&s),
            "SELECT id FROM peers WHERE last_seen BETWEEN ? AND ? "
            "AND port IN (?,?,?) AND source IS NULL LIMIT ? OFFSET ?");
        PASS();
    }

    /* ── 6. Live round trip through the converted models ────────────── */

    TEST("qb LIVE: an injection payload round-trips as data, not code") {
        struct node_db ndb;
        ASSERT(node_db_open(&ndb, ":memory:"));

        struct db_auth_challenge c;
        memset(&c, 0, sizeof(c));
        snprintf(c.nonce_hex, sizeof(c.nonce_hex), "%s", "deadbeef");
        snprintf(c.address, sizeof(c.address), "%s", QB_ATTACK_DROP);
        c.issued_at = 1000;
        c.expires_at = 2000;
        ASSERT(db_auth_challenge_save(&ndb, &c));

        /* The table the payload tried to drop still answers. */
        ASSERT_EQ(db_auth_challenge_pending_count(&ndb), 1);

        struct db_auth_challenge got;
        memset(&got, 0, sizeof(got));
        ASSERT(db_auth_challenge_find(&ndb, "deadbeef", &got));
        ASSERT_STR_EQ(got.address, QB_ATTACK_DROP);

        /* And a lookup BY the payload finds it as an ordinary string, so
         * the value is being compared, not executed. */
        struct qb q;
        qb_select(&q, QB_T_auth_challenges);
        qb_select_count_star(&q);
        qb_where_text(&q, QB_C_auth_challenges_address, QB_EQ,
                      QB_ATTACK_DROP);
        sqlite3_stmt *s = NULL;
        ASSERT(QB_PREPARE(&ndb, &q, s));
        ASSERT(sqlite3_step(s) == SQLITE_ROW);
        ASSERT_EQ((int)sqlite3_column_int64(s, 0), 1);
        sqlite3_finalize(s);

        ASSERT(db_auth_challenge_consume(&ndb, "deadbeef", QB_ATTACK_DROP,
                                         1500));
        ASSERT_EQ(db_auth_challenge_pending_count(&ndb), 0);
        ASSERT_EQ(db_auth_challenge_reap(&ndb, 0), 1);
        node_db_close(&ndb);
        PASS();
    }

    TEST("qb LIVE: peer mark_tried now stores an epoch, not the text '%s'") {
        /* The literal this converted read strftime('%%s','now'), which
         * SQLite evaluates to the two characters "%s". The builder emits
         * the single-percent form, so last_try is a real epoch again. */
        struct node_db ndb;
        ASSERT(node_db_open(&ndb, ":memory:"));

        struct db_peer p;
        memset(&p, 0, sizeof(p));
        p.ip[15] = 1;
        p.port = 8033;
        p.last_seen = 1700000000;
        ASSERT(db_peer_save(&ndb, &p));

        ASSERT(db_peer_mark_tried(&ndb, p.ip, p.port));
        struct db_peer found;
        ASSERT(db_peer_find_by_addr(&ndb, p.ip, p.port, &found));
        ASSERT_EQ(found.attempts, 1);
        /* 1.7e9 is 2023-11; any real epoch is above it and below 2^40. */
        ASSERT(found.last_try > 1700000000);
        ASSERT(found.last_try < (int64_t)1 << 40);

        ASSERT(db_peer_mark_seen(&ndb, p.ip, p.port, 1700000100));
        ASSERT(db_peer_find_by_addr(&ndb, p.ip, p.port, &found));
        ASSERT_EQ(found.attempts, 0);
        ASSERT_EQ(found.last_seen, (int64_t)1700000100);

        ASSERT(db_peer_update_score(&ndb, p.ip, p.port, 77, true));
        ASSERT(db_peer_find_by_addr(&ndb, p.ip, p.port, &found));
        ASSERT_EQ((int)found.bandwidth_score, 77);
        ASSERT(found.is_zcl23);
        node_db_close(&ndb);
        PASS();
    }

    TEST("qb LIVE: fast_zcl23 keeps its reachable-port policy after conversion") {
        struct node_db ndb;
        ASSERT(node_db_open(&ndb, ":memory:"));

        struct db_peer good;
        memset(&good, 0, sizeof(good));
        good.ip[15] = 2;
        good.port = 8033;                    /* in the policy set */
        good.last_seen = 1700000000;
        good.is_zcl23 = true;
        ASSERT(db_peer_save(&ndb, &good));

        struct db_peer offpolicy;
        memset(&offpolicy, 0, sizeof(offpolicy));
        offpolicy.ip[15] = 3;
        offpolicy.port = 5555;               /* NOT in the policy set */
        offpolicy.last_seen = 1700000001;
        offpolicy.is_zcl23 = true;
        ASSERT(db_peer_save(&ndb, &offpolicy));

        struct db_peer out[8];
        int n = db_peer_fast_zcl23(&ndb, out, 8);
        ASSERT_EQ(n, 1);
        ASSERT_EQ((int)out[0].port, 8033);

        /* db_peer_recent is unfiltered, so it sees both. */
        ASSERT_EQ(db_peer_recent(&ndb, out, 8), 2);
        node_db_close(&ndb);
        PASS();
    }

    TEST("qb LIVE: subselect prune keeps exactly the newest rows") {
        struct node_db ndb;
        ASSERT(node_db_open(&ndb, ":memory:"));

        for (int i = 0; i < 12; i++) {
            struct db_parity_sample s;
            memset(&s, 0, sizeof(s));
            s.ts = 1700000000 + i;
            s.our_height = i;
            s.oracle_height = i;
            s.heights_equal_at = i;
            ASSERT(db_parity_sample_save(&ndb, &s));
        }
        ASSERT_EQ(db_parity_sample_count(&ndb), 12);
        ASSERT(db_parity_sample_prune(&ndb, 5));
        ASSERT_EQ(db_parity_sample_count(&ndb), 5);

        struct db_parity_sample recent[8];
        int n = db_parity_sample_recent(&ndb, recent, 8);
        ASSERT_EQ(n, 5);
        ASSERT_EQ((int)recent[0].our_height, 11);   /* newest first */
        ASSERT_EQ((int)recent[4].our_height, 7);

        /* Same shape on the other model that uses the NOT IN (SELECT ...). */
        for (int i = 0; i < 6; i++) {
            struct db_peer_chain_observation o;
            memset(&o, 0, sizeof(o));
            o.peer_id = i;
            snprintf(o.addr, sizeof(o.addr), "10.0.0.%d", i);
            snprintf(o.user_agent, sizeof(o.user_agent), "/z23:%d/", i);
            o.observed_at = 1700000000 + i;
            ASSERT(db_peer_chain_observation_save(&ndb, &o));
        }
        ASSERT_EQ(db_peer_chain_observation_count(&ndb), 6);
        ASSERT(db_peer_chain_observation_prune(&ndb, 2));
        ASSERT_EQ(db_peer_chain_observation_count(&ndb), 2);
        node_db_close(&ndb);
        PASS();
    }

    TEST("qb LIVE: op_return_index optional filter and bound prune") {
        struct node_db ndb;
        ASSERT(node_db_open(&ndb, ":memory:"));

        for (int i = 0; i < 6; i++) {
            struct op_return_index_row r;
            memset(&r, 0, sizeof(r));
            memset(r.txid, 0x10 + i, 32);
            r.vout_n = 0;
            r.height = 100 + i;
            r.tag[0] = (uint8_t)('A' + (i % 2));
            r.tag_len = 1;
            snprintf(r.tag_text, sizeof(r.tag_text), "%c",
                     'A' + (i % 2));
            r.payload_len = 1;
            memset(r.payload_sha3, 0x22, 32);
            ASSERT(db_op_return_index_save(&ndb, &r));
        }
        ASSERT_EQ((int)op_return_index_count(&ndb), 6);
        ASSERT_EQ((int)op_return_index_count_by_tag_text(&ndb, "A"), 3);
        ASSERT_EQ((int)op_return_index_count_by_tag_text(&ndb, QB_ATTACK_DROP),
                  0);

        struct op_return_index_row rows[16];
        ASSERT_EQ(op_return_index_query(&ndb, 0, 1000, NULL, rows, 16), 6);
        ASSERT_EQ(op_return_index_query(&ndb, 0, 1000, "A", rows, 16), 3);
        ASSERT_EQ(op_return_index_query(&ndb, 102, 103, NULL, rows, 16), 2);
        ASSERT_EQ((int)rows[0].height, 103);        /* height DESC */

        ASSERT(op_return_index_prune_below(&ndb, 103));
        ASSERT_EQ((int)op_return_index_count(&ndb), 3);
        ASSERT(op_return_index_truncate(&ndb));
        ASSERT_EQ((int)op_return_index_count(&ndb), 0);
        node_db_close(&ndb);
        PASS();
    }

    TEST("qb LIVE: onion announcement exists/recent keep their ordering") {
        struct node_db ndb;
        ASSERT(node_db_open(&ndb, ":memory:"));

        struct db_onion_announcement a;
        memset(&a, 0, sizeof(a));
        snprintf(a.onion_address, sizeof(a.onion_address), "%s",
                 "aaaaaaaaaaaaaaaa.onion");
        a.announced_at = 1700000000;
        ASSERT(db_onion_announcement_save(&ndb, &a));

        struct db_onion_announcement b;
        memset(&b, 0, sizeof(b));
        snprintf(b.onion_address, sizeof(b.onion_address), "%s",
                 "bbbbbbbbbbbbbbbb.onion");
        b.announced_at = 1700000100;
        ASSERT(db_onion_announcement_save(&ndb, &b));

        ASSERT(db_onion_announcement_exists(&ndb, "aaaaaaaaaaaaaaaa.onion"));
        ASSERT(!db_onion_announcement_exists(&ndb, QB_ATTACK_DROP));

        struct db_onion_announcement out[4];
        int n = db_onion_announcement_recent(&ndb, out, 4);
        ASSERT_EQ(n, 2);
        ASSERT_STR_EQ(out[0].onion_address, "bbbbbbbbbbbbbbbb.onion");
        node_db_close(&ndb);
        PASS();
    }

_test_next:;
    if (failures == 0)
        printf("test_activerecord_query_builder: all passed\n");
    else
        printf("test_activerecord_query_builder: %d FAILED\n", failures);
    return failures;
}
