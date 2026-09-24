#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Add cumulative range, refactor, and terminal-output milestones to tiny-lines.
set -euo pipefail

if [[ $# != 3 || ! $2 =~ ^([1-9]|[1-9][0-9]|100)$ ||
      ( $3 != normal && $3 != wrong && $3 != wrong_ui ) ]]; then
    printf 'usage: %s PACKAGE_DIR REVISION(1..100) normal|wrong|wrong_ui\n' "$0" >&2
    exit 2
fi
package=$1
revision=$2
mode=$3
if [[ $mode == wrong_ui && $revision -lt 75 ]]; then
    printf 'wrong_ui needs revision >= 75\n' >&2
    exit 2
fi
root=$(cd "$(dirname "$0")/../.." && pwd -P)
base_mode=normal
if [[ $mode == wrong ]]; then base_mode=wrong; fi
bash "$root/tools/dev/factory-evolving-fixture.sh" \
    "$package" "$revision" "$base_mode"

if ((revision >= 25)); then
    header=$(mktemp "$package/include/.history.XXXXXX")
    awk -v ui="$((revision >= 75))" -v strict="$((revision >= 90))" '
        /^#include <stdbool.h>$/ { print; if (ui) print "#include <stddef.h>"; next }
        /^#endif$/ {
            print "bool history_range(unsigned first, unsigned count, unsigned *out_sum);"
            if (ui) print "bool history_render(unsigned count, bool json, char *out, size_t capacity);"
            if (strict) print "bool history_parse_count(const char *text, unsigned *out_count);"
        }
        { print }
    ' "$package/include/history.h" > "$header"
    mv "$header" "$package/include/history.h"

    if ((revision >= 50)); then
        source=$(mktemp "$package/src/.history.XXXXXX")
        awk '
            /^bool history_prefix\(/ {
                if (++found != 1) exit 1
                print "bool history_prefix(unsigned count, unsigned *out_sum)"
                print "{"
                print "    return history_range(0, count, out_sum);"
                print "}"
                skipping=1
                next
            }
            skipping { if ($0 == "}") skipping=0; next }
            { print }
            END { if (found != 1 || skipping) exit 1 }
        ' "$package/src/history.c" > "$source"
        mv "$source" "$package/src/history.c"
    fi

    cat >> "$package/src/history.c" <<'EOF'

bool history_range(unsigned first, unsigned count, unsigned *out_sum)
{
    if (out_sum) *out_sum = 0;
    const size_t length = sizeof(values) / sizeof(values[0]);
    if (!out_sum || first > length || count > length - first) return false;
    for (size_t i = first; i < (size_t)first + count; i++) *out_sum += values[i];
    return true;
}
EOF
fi

if ((revision >= 75)); then
    format='count=%u sum=%u\n'
    if [[ $mode == wrong_ui ]]; then format='count=%u total=%u\n'; fi
    cat >> "$package/src/history.c" <<EOF

#include <stdio.h>
bool history_render(unsigned count, bool json, char *out, size_t capacity)
{
    if (!out || capacity == 0) return false;
    out[0] = '\0';
    unsigned sum = 0;
    if (!history_prefix(count, &sum)) return false;
    const int written = snprintf(out, capacity,
                                 json ? "{\"count\":%u,\"sum\":%u}\\n"
                                      : "$format",
                                 count, sum);
    if (written < 0 || (size_t)written >= capacity) {
        out[0] = '\0';
        return false;
    }
    return true;
}
EOF

    cat > "$package/examples/history_cli.c" <<'EOF'
/* Copyright 2026 Rhett Creighton - MIT License */
#include "history.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
EOF
    printf '#define HISTORY_STRICT_COUNT %u\n' "$((revision >= 90))" \
        >> "$package/examples/history_cli.c"
    cat >> "$package/examples/history_cli.c" <<'EOF'

int main(int argc, char **argv)
{
    if ((argc != 2 && argc != 3) || (argc == 3 && strcmp(argv[2], "--json"))) {
        fprintf(stderr, "usage: history-cli COUNT [--json]\n");
        return 2;
    }
    unsigned count = 0;
#if HISTORY_STRICT_COUNT
    if (!history_parse_count(argv[1], &count)) {
        fprintf(stderr, "invalid count: %s\n", argv[1]);
        return 2;
    }
#else
    char *end = NULL;
    errno = 0;
    const unsigned long parsed = strtoul(argv[1], &end, 10);
    if (errno || end == argv[1] || *end || parsed > UINT_MAX) {
        fprintf(stderr, "invalid count: %s\n", argv[1]);
        return 2;
    }
    count = (unsigned)parsed;
#endif
    char output[64];
    if (!history_render(count, argc == 3, output, sizeof(output))) {
        fprintf(stderr, "count outside available history\n");
        return 1;
    }
    fputs(output, stdout);
    return 0;
}
EOF
fi

if ((revision >= 90)); then
    cat >> "$package/src/history.c" <<'EOF'

#include <limits.h>
bool history_parse_count(const char *text, unsigned *out_count)
{
    if (out_count) *out_count = 0;
    if (!text || !*text || !out_count) return false;
    unsigned value = 0;
    for (size_t i = 0; text[i]; i++) {
        if (i >= 10 || text[i] < '0' || text[i] > '9') return false;
        const unsigned digit = (unsigned)(text[i] - '0');
        if (value > (UINT_MAX - digit) / 10) return false;
        value = value * 10 + digit;
    }
    *out_count = value;
    return true;
}
EOF
fi

tests=$(mktemp "$package/tests/.history.XXXXXX")
awk -v revision="$revision" '
    /^#include <stdio.h>$/ { print; if (revision >= 75) print "#include <string.h>"; next }
    /^    return 0;$/ {
        if (revision >= 25) {
            print "    for (unsigned first = 0; first <= " revision "; first++) {"
            print "        for (unsigned count = 0; count <= " revision " - first; count++) {"
            print "            const unsigned upper = first + count;"
            print "            const unsigned expected = upper * (upper + 1) / 2 - first * (first + 1) / 2;"
            print "            if (!history_range(first, count, &actual) || actual != expected) return 1;"
            print "        }"
            print "    }"
            print "    if (!history_range(" revision ", 0, &actual) || actual != 0) return 1;"
            print "    if (history_range(" revision + 1 ", 0, &actual)) return 1;"
            print "    if (history_range(0, 1, NULL)) return 1;"
        }
        if (revision >= 75) {
            print "    char output[64], expected[64], small[3];"
            print "    for (unsigned count = 0; count <= " revision "; count++) {"
            print "        const unsigned total = count * (count + 1) / 2;"
            print "        snprintf(expected, sizeof(expected), \"count=%u sum=%u\\n\", count, total);"
            print "        if (!history_render(count, false, output, sizeof(output)) ||"
            print "            strcmp(output, expected)) return 1;"
            print "        snprintf(expected, sizeof(expected), \"{\\\"count\\\":%u,\\\"sum\\\":%u}\\n\","
            print "                 count, total);"
            print "        if (!history_render(count, true, output, sizeof(output)) ||"
            print "            strcmp(output, expected)) return 1;"
            print "    }"
            print "    if (history_render(" revision ", false, small, sizeof(small)) || small[0]) return 1;"
            print "    if (history_render(" revision + 1 ", false, output, sizeof(output)) || output[0]) return 1;"
        }
        if (revision >= 90) {
            print "    unsigned parsed = 99;"
            print "    if (!history_parse_count(\"75\", &parsed) || parsed != 75) return 1;"
            print "    if (history_parse_count(\" 75\", &parsed) || parsed) return 1;"
            print "    if (history_parse_count(\"+75\", &parsed) || parsed) return 1;"
            print "    if (history_parse_count(\"-0\", &parsed) || parsed) return 1;"
            print "    if (history_parse_count(\"42949672960\", &parsed) || parsed) return 1;"
            print "    if (history_parse_count(\"\", &parsed) || parsed) return 1;"
        }
    }
    { print }
' "$package/tests/test_history.c" > "$tests"
mv "$tests" "$package/tests/test_history.c"
printf 'mixed_revision=%s mode=%s range=%s refactor=%s ui=%s parser_fix=%s\n' \
    "$revision" "$mode" "$((revision >= 25))" "$((revision >= 50))" \
    "$((revision >= 75))" "$((revision >= 90))"
sha256sum "$package/src/history.c" "$package/tests/test_history.c"
