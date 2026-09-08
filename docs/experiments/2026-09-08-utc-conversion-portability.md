<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Reuse the existing UTC conversion seam

The mandatory Windows syntax scan for the composed performance proof found
seven translation units calling POSIX `gmtime_r` directly. Those callers now
use `zcl_utc_tm` from the existing `base/utc_tm.h`, which selects the platform's
reentrant calendar conversion. The shared header and time-reading authority
are unchanged.

Successful formatting retains the existing UTC output. Conversion failures
preserve empty or unknown display fields. The JSON logger retains its existing
epoch fallback. Database quarantine retains its file operations and uses the
numeric input epoch when calendar formatting is unavailable. Claim creation
refuses before writing its ledger if its current UTC timestamp cannot be
represented. Previously unchecked calls no longer pass uninitialized calendar
fields to `strftime`.

Validation applies the Windows gate's actual compiler flags to the seven
affected sources and runs the registered `format_helpers_codec`, `log_json`,
`devagent_claim`, and `db_migration_idempotent` fixtures. The formatter fixture
includes a known UTC timestamp and an unrepresentable timestamp. The migration
fixture uses isolated databases; no canonical datadir or custody operation is
part of this experiment. Focused results are recorded with the commit; the
coordinator retains the complete publication proof requirement.
