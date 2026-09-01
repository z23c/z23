/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Lint-gate fixture (NOT compiled into any binary; lives under
 * tests/harness/fixtures/, which the build globs never pick up). It stands in for a
 * hot-swap-eligible TU that WRONGLY defines a mutable file-scope static — the
 * exact hazard check_hotswap_static_state.sh must catch. The self-test in
 * test_make_lint_gates.c points a temp manifest at this file and asserts the
 * gate trips (exit 1). The const array + the annotated static below are
 * negative controls the gate must NOT flag. */

static int g_hotswap_bad_counter = 0;      /* mutable file-scope static: FLAG */

static const int k_hotswap_ok_table[] = {1, 2, 3};  /* const: OK */

static int g_hotswap_allowlisted = 0; /* hotswap-static-ok: fixture negative control */
