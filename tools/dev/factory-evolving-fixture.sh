#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Generate a C23 package whose test covers every accepted history prefix.
set -euo pipefail

if [[ $# != 3 || ! $2 =~ ^([1-9]|[1-9][0-9]|100)$ ]]; then
    printf 'usage: %s PACKAGE_DIR REVISION(1..100) normal|wrong\n' "$0" >&2
    exit 2
fi
package=$1
revision=$2
mode=$3
[[ $mode == normal || $mode == wrong ]] || exit 2
[[ -f $package/zcode-package.json && -f $package/src/tiny_lines.c ]] || exit 2
mkdir -p "$package/include" "$package/src" "$package/tests"

cat > "$package/include/history.h" <<'EOF'
/* Copyright 2026 Rhett Creighton - MIT License */
#ifndef FIXTURE_HISTORY_H
#define FIXTURE_HISTORY_H
#include <stdbool.h>
bool history_prefix(unsigned count, unsigned *out_sum);
#endif
EOF

{
    cat <<'EOF'
/* Copyright 2026 Rhett Creighton - MIT License */
#include "history.h"
#include <stddef.h>
static const unsigned values[] = {
EOF
    for ((i=1; i<=revision; i++)); do
        value=$i
        if [[ $mode == wrong && $i == 2 ]]; then value=99; fi
        printf '    %u,\n' "$value"
    done
    cat <<'EOF'
};
bool history_prefix(unsigned count, unsigned *out_sum)
{
    if (out_sum) *out_sum = 0;
    if (!out_sum || count > sizeof(values) / sizeof(values[0])) return false;
    for (unsigned i = 0; i < count; i++) *out_sum += values[i];
    return true;
}
EOF
} > "$package/src/history.c"

{
    cat <<'EOF'
/* Copyright 2026 Rhett Creighton - MIT License */
#include "history.h"
#include <stdio.h>
int history_test(void)
{
    unsigned actual = 0;
    if (!history_prefix(0, &actual) || actual != 0) return 1;
EOF
    for ((i=1; i<=revision; i++)); do
        expected=$((i * (i + 1) / 2))
        printf '    if (!history_prefix(%u, &actual) || actual != %u) {\n' "$i" "$expected"
        printf '        fprintf(stderr, "history prefix %u: expected %u, got %%u\\n", actual);\n' "$i" "$expected"
        printf '        return 1;\n    }\n'
    done
    printf '    if (history_prefix(%u, &actual)) return 1;\n' "$((revision + 1))"
    cat <<'EOF'
    if (history_prefix(0, NULL)) return 1;
    return 0;
}
EOF
} > "$package/tests/test_history.c"

if ! grep -q 'int history_test(void);' "$package/tests/test_tiny_lines.c"; then
    rewritten=$(mktemp "$package/tests/.tiny-lines.XXXXXX")
    awk '
        /^int main\(void\)/ { print "int history_test(void);" }
        /^    return 0;/ { print "    CHECK(history_test() == 0);" }
        { print }
    ' "$package/tests/test_tiny_lines.c" > "$rewritten"
    chmod 644 "$rewritten"
    mv "$rewritten" "$package/tests/test_tiny_lines.c"
fi

printf 'revision=%s mode=%s\n' "$revision" "$mode"
sha256sum "$package/include/history.h" "$package/src/history.c" "$package/tests/test_history.c"
