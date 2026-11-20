<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->
<!-- claim: symbol-present db_peer_chain_observation_prune engine/models/src/peer_chain_observation.c # retained observation pruning -->

# Peer observation prune diagnostics

On 2026-11-15, source base `d16b5a1ad53421746bd69cd829e8e3af21f0a01a` was tested with GCC 14.2.0 on an AMD Ryzen 9 7950X3D. The observation prune operation now reports the SQLite statement return code and its stable description when execution fails. It continues to return failure. This diagnostic does not repair database corruption.

An isolated database verified WAL mode, inserted 10,005 observations and retained 10,000. A query-only connection then caused the same prune to fail with `SQLITE_READONLY`; the fixture checked the reported code and description and that the retained count remained 10,000. Before the change, the focused test failed solely because the diagnostic was absent. After the change, `DEVBUILD_CLASS=normal devbuild --wait make -j28 t-fast ONLY=network_monitor` passed one group with no skips. The red log SHA-256 is `603f9904451c145ba33a22ba29046af7bf562d3a1c166ae986771cfa92f2f398`; the final passing log SHA-256 is `fbd491c8dbf485400f69df07106ee2440188960f1b5167c3754d1959750c409d`.

A boot-time check reported corruption in the observation table. The current live prune return code has not been observed; the fixture does not establish its cause or demonstrate a live repair.

## Indexed cutoff comparison

On 2026-11-20, an isolated in-memory SQLite 3.49.0 fixture on an AMD Ryzen 9 7950X3D compared the original `NOT IN`, a scalar cutoff and an excess-ID `IN` form using the observation table columns and observed-at index. GCC 14.2.0 compiled the fixture with `-std=c23 -O2`, using the repository SQLite archive. The fixture rebuilt the table before each statement, populated sparse IDs as `n * 3 - 15000`, used retention 10,000 and read `SQLITE_STMTSTATUS_VM_STEP` after `SQLITE_DONE`:

| Rows | Removed | Original | Cutoff | Excess-ID IN |
| ---: | ---: | ---: | ---: | ---: |
| 10,000 | 0 | 140,016 | 20,029 | 20,025 |
| 10,005 | 5 | 140,111 | 20,092 | 20,125 |
| 100,000 | 90,000 | 1,850,016 | 1,100,032 | 1,820,025 |

Reproduce with this standalone fixture from the repository root; it creates no persistent database:

```c
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
static const char *sql[] = {
"DELETE FROM t WHERE id NOT IN (SELECT id FROM t ORDER BY id DESC LIMIT 10000)",
"DELETE FROM t WHERE id <= (SELECT id FROM t ORDER BY id DESC LIMIT 1 OFFSET 10000)",
"DELETE FROM t WHERE id IN (SELECT id FROM t ORDER BY id DESC LIMIT 9223372036854775807 OFFSET 10000)"};
int main(void) {
 for (int n=10000;n<=100000;n=n==10000?10005:100000) {
  for (int k=0;k<3;k++) {
   sqlite3 *d=0; sqlite3_stmt *s=0; char buf[1024];
   if(sqlite3_open(":memory:",&d)) return 1;
   snprintf(buf,sizeof buf,"CREATE TABLE t(id INTEGER PRIMARY KEY AUTOINCREMENT, peer_id INTEGER NOT NULL, addr TEXT NOT NULL DEFAULT '', user_agent TEXT NOT NULL DEFAULT '', version INTEGER NOT NULL DEFAULT 0, best_height INTEGER NOT NULL DEFAULT -1, tip_hash TEXT NOT NULL DEFAULT '', latency_us INTEGER NOT NULL DEFAULT 0, inbound INTEGER NOT NULL DEFAULT 0, first_seen INTEGER NOT NULL DEFAULT 0, last_seen INTEGER NOT NULL DEFAULT 0, observed_at INTEGER NOT NULL); CREATE INDEX idx_peer_chain_obs_observed_at ON t(observed_at DESC); WITH RECURSIVE x(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM x WHERE n<%d) INSERT INTO t(id,peer_id,observed_at) SELECT n*3-15000,n,n FROM x",n);
   if(sqlite3_exec(d,buf,0,0,0)||sqlite3_prepare_v2(d,sql[k],-1,&s,0)||sqlite3_step(s)!=SQLITE_DONE) return 2;
   printf("rows=%d query=%d vm_steps=%d deleted=%d\n",n,k,sqlite3_stmt_status(s,SQLITE_STMTSTATUS_VM_STEP,0),sqlite3_changes(d));
   sqlite3_finalize(s); sqlite3_close(d);
  }
  if(n==100000) break;
 }
 return 0;
}
```

Compile with `devbuild --wait cc -std=c23 -O2 -Wall -Wextra -Werror -Ivendor/include fixture.c vendor/lib/libsqlite3.a -lpthread -ldl -lm -o fixture` and run `./fixture`. These are fixture VM counts, not live node timings.
