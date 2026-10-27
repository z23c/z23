<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# SQLite transaction trace statement lifetime

Date: 2026-10-27.
Source baseline: 6eb3e270903f645a7336670fe7da9dfeecc156cc.

## Observed failure and source mechanism

Repeated crash stacks stopped in sqlite3_stmt_busy. Exact-binary disassembly and
the transaction-trace diagnostic strings identified its caller as dumper_main.
This identifies the failing inspection path; it does not identify which
production thread finalized the statement.

The source enumerated statements with sqlite3_next_stmt, then called
sqlite3_stmt_busy and sqlite3_sql without retaining the connection mutex.
SQLite releases its internal connection mutex before sqlite3_next_stmt returns.
A concurrent sqlite3_finalize can therefore destroy the returned statement before
the inspection dereferences it or passes it back to sqlite3_next_stmt.

The private registry mutex protected connection membership and coordinated
unregister-before-close. It did not protect prepared statements from their
owners. For example, the coins-view close path finalized cached statements
before unregistering its still-open connection.

<!-- claim: symbol-present dumper_main platform/modules/util/src/db_txn_trace.c -->
<!-- claim: symbol-present coins_view_sqlite_close engine/modules/storage/src/coins_view_sqlite.c -->

## Repair and locking contract

The dumper retains the SQLite connection mutex across transaction-state reads,
statement enumeration, busy checks and every use of borrowed SQL text. Registry
membership remains protected for the whole inspection, so a complying unregister
and close wait for the observer.

Registration refuses a connection without a SQLite mutex and prints an explicit
reason. Such a handle is not registered or represented as an inspected healthy
connection. Entering a null SQLite mutex is a no-op and cannot establish this
lifetime guarantee.

Registry operations must run outside SQLite callbacks and without the
caller holding the connection mutex. An enabled scan can wait behind other
SQLite work; no fixed diagnostic completion latency is claimed.

Registration, relabeling and removal mutate callback-visible registry fields
under the same connection mutex. The lock order remains registry mutex followed
by connection mutex. The SQLite trace callback does not acquire the registry
mutex; adding that reverse acquisition would invert the order.

<!-- claim: symbol-present zcl_db_txn_trace_register platform/modules/util/src/db_txn_trace.c -->
<!-- claim: symbol-present zcl_db_txn_trace_unregister platform/modules/util/src/db_txn_trace.c -->

## Isolated regression contract

Run the focused group from the repository root:

~~~sh
make t-fast ONLY=db_txn_trace
~~~

On maintainer hosts, prefix the command with devbuild --wait.

The regression includes the actual diagnostic implementation with test-only API
redirection. An isolated FULLMUTEX in-memory database and a stepped SELECT make
the busy-statement inspection execute. A second thread probes the real SQLite
connection mutex immediately after enumeration and at statement/SQL inspection;
the mutex must remain held across those uses. A finalizer must remain blocked
during inspection and complete after the scan releases the mutex.

A separate NOMUTEX connection must be refused without changing global SQLite
configuration. The test redirects sleeping to bound the diagnostic cycle; it
does not require a live node, canonical database, production process attachment
or a timing-dependent crash.

The source-level interleaving identifies the missing statement-lifetime
protection. Attribution to a particular production finalizer remains
unproven.

## Observed regression evidence

The registered regression ran against both implementations on 2026-10-27.
The RED variant changed only its test translation unit's include selector to an
immutable copy of the parent implementation. Assertion bytes stayed identical;
the production source was not swapped. The runner retried the failing group
alone once and observed the same failure.

The parent reported 16 passing checks and five failures: NOMUTEX registration
was accepted, the finalizer-exclusion assertion failed, and mutex exclusion failed after
statement enumeration and at the busy/SQL-pointer uses. The registered group
failed with make exit 2. Fixture setup, snapshot and cleanup checks passed;
there were no skips or flaky results.

The fixed implementation passed all 21 checks in one registered group, with make
exit 0 and no failed, skipped or flaky groups. Separate-thread probes observed
the connection mutex busy at all three pointer-use boundaries. The finalizer
remained excluded during inspection and successfully finalized afterward. The
actual dumper published one busy statement; NOMUTEX registration was refused.
All test threads joined and both SQLite handles closed. The test did not
deliberately dereference a freed pointer.

The fixed test-body receipt recorded 42 ms. This isolated test observation is
not a diagnostic completion-latency guarantee.

<!-- claim: symbol-present test_db_txn_trace tests/harness/src/test_db_txn_trace.c -->

Evidence identities:

- Parent source blob: 3d81236621a3321ef6362dfc7159f3d4fb3c91c4.
- Fixed source blob: a05214f1837baec3c52297931985eced919b990e.
- Fixed test blob: f824a9b808eaa55a42ff2e443a893f093dba7fa0.
- RED log SHA256:
  7840cfa3b28f8842bf4c3ee2b2bd859a17f59f807113ece16c1b197da3b38759.
- GREEN log SHA256:
  c267d115a1dc65e5261f30d1476210da675207c10da2c6019c5c42bfc81d4bdc.
