/* Fixture copied into app/ by test_make_lint_gates.c. It must trip
 * check_raw_sqlite.sh because wallet-table DML forwarded through
 * node_db_exec bypasses the model owner. */
struct node_db {
    void *db;
};

extern bool node_db_exec(struct node_db *ndb, const char *sql);

static bool forward_wallet_dml(struct node_db *ndb, const char *sql)
{
    return node_db_exec(ndb, sql);
}

void lint_fixture_raw_node_db_exec(struct node_db *ndb)
{
    (void)forward_wallet_dml(ndb,
                            "DELETE FROM " "wallet_" "utxos");
}
