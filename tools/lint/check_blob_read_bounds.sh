#!/usr/bin/env bash
# Fixed-size SQLite blob reads in app models must use AR_READ_BLOB or prove the
# SQLite blob length before memcpy. This catches the class where a short BLOB at
# rest is copied as 16/32/43/etc. bytes from sqlite3_column_blob().
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/scan_exclusions.sh
source "$ROOT/tools/lint/scan_exclusions.sh"

fail=0
shopt -s nullglob

for f in app/models/src/*.c; do
    lint_path_is_excluded "$f" && continue
    awk '
    function trim(s) {
        sub(/^[ \t]+/, "", s)
        sub(/[ \t]+$/, "", s)
        return s
    }
    function remember_blob(var) {
        blob_seen[var] = 1
        blob_guarded[var] = 0
        blob_age[var] = 0
    }
    function age_blobs(    v) {
        for (v in blob_seen) {
            blob_age[v]++
            if (blob_age[v] > 16) {
                delete blob_seen[v]
                delete blob_guarded[v]
                delete blob_age[v]
            }
        }
    }
    function has_blob_guard_nearby() {
        return recent_guard > 0
    }
    function memcpy_uses_blob_var(line,    v, pat) {
        for (v in blob_seen) {
            pat = "(^|[^A-Za-z0-9_])" v "([^A-Za-z0-9_]|$)"
            if (line ~ pat)
                return v
        }
        return ""
    }
    function has_fixed_copy_len(line) {
        return line ~ /,[ \t]*(\(?size_t\)?[ \t]*)?([0-9]+|sizeof[ \t]*\([^;]*\))[ \t]*\)[ \t]*;[ \t]*(\/\/.*)?$/
    }
    {
        line = $0
        age_blobs()
        if (recent_guard > 0)
            recent_guard--

        if (line ~ /AR_READ_BLOB[ \t]*\(/)
            next

        if (line ~ /(sqlite3_column_bytes|AR_COL_BYTES)[ \t]*\(/) {
            recent_guard = 6
            for (v in blob_seen)
                blob_guarded[v] = 1
        }

        # match() with a capture array is a gawk extension; POSIX awk and
        # the BSD awk on macOS hosts offer only RSTART/RLENGTH. Split into
        # two matches so both awks parse identically.
        if (match(line, /[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*(\([^)]*\)[ \t]*)?sqlite3_column_blob[ \t]*\(/)) {
            head = substr(line, RSTART, RLENGTH)
            if (match(head, /^[A-Za-z_][A-Za-z0-9_]*/))
                remember_blob(substr(head, RSTART, RLENGTH))
        }

        if (line ~ /memcpy[ \t]*\(/) {
            used = memcpy_uses_blob_var(line)
            if (line ~ /sqlite3_column_blob[ \t]*\(/) {
                if (!has_blob_guard_nearby() && has_fixed_copy_len(line)) {
                    print FILENAME ":" FNR ": memcpy directly from sqlite3_column_blob without nearby column_bytes guard"
                    bad = 1
                }
            } else if (used != "") {
                if (!blob_guarded[used] && !has_blob_guard_nearby() &&
                    has_fixed_copy_len(line)) {
                    print FILENAME ":" FNR ": memcpy from sqlite3_column_blob variable " used " without column_bytes guard"
                    bad = 1
                }
            }
        }
    }
    END { if (bad) exit 1 }
    ' "$f" || fail=1
done

if (( fail != 0 )); then
    echo "FAIL: unsafe fixed-size sqlite3_column_blob memcpy in app models." >&2
    echo "      Use AR_READ_BLOB(stmt,col,dest,len), or guard with sqlite3_column_bytes first." >&2
    exit 1
fi

echo "check_blob_read_bounds: clean — app model blob memcpy sites are length-guarded"
