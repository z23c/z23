#!/usr/bin/env bash
# migrate-role-names-selftest.sh — sandbox fixture + regression proof for
# platform/deploy/migrate-role-names.sh's handling of the systemd "%h" specifier.
#
# Builds a fake $HOME mirroring the REAL repo convention (platform/deploy/zcl-serve.service
# uses "-datadir=%h/.zclassic-c23-serve" — a systemd specifier a shell never
# expands on its own), with a numbered unit + numbered datadir, then runs
# migrate-role-names.sh --dry-run and for-real against ONLY that sandbox
# (HOME is redirected to the sandbox; systemctl is stubbed on PATH so the
# real host is never touched — no real systemctl call, no real
# ~/.zclassic-c23-* datadir is ever read or written).
#
# Regression this guards: an earlier version of the script extracted
# "-datadir=" from the old unit as a raw string and used it as a filesystem
# path without expanding "%h". Every existence/rename check against that
# literal "%h/..." string silently no-opped, so the numbered datadir was
# never renamed onto the canonical name — yet the script still enabled and
# started the new unit, which (via systemd's own, correct "%h" expansion)
# pointed at an empty canonical datadir, silently orphaning the operator's
# synced state. See the git history of migrate-role-names.sh.
#
# Usage: platform/deploy/migrate-role-names-selftest.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MIGRATE_SCRIPT="$SCRIPT_DIR/migrate-role-names.sh"

FAILED=0

pass() {
    printf '[migrate-role-names-selftest] PASS: %s\n' "$*"
}

failmsg() {
    printf '[migrate-role-names-selftest] FAIL: %s\n' "$*" >&2
    FAILED=1
}

[ -x "$MIGRATE_SCRIPT" ] || failmsg "migrate-role-names.sh is not executable"

SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/migrate-role-names-selftest.XXXXXX")"
cleanup() {
    rm -rf "$SANDBOX"
}
trap cleanup EXIT

# systemctl stub — never touches the real host. Logs every invocation it
# receives so the test can assert on what was (and wasn't) called, and
# always exits 0 so the migration script's own logic (not a fake failure)
# drives the test.
STUB_BIN="$SANDBOX/stubbin"
mkdir -p "$STUB_BIN"
STUB_LOG="$SANDBOX/systemctl-calls.log"
cat > "$STUB_BIN/systemctl" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$STUB_LOG"
exit 0
EOF
chmod +x "$STUB_BIN/systemctl"

# ── build fixture 1: a real-shaped numbered install ────────────────────────
HOME_DIR="$SANDBOX/home"
mkdir -p "$HOME_DIR/.config/systemd/user"
mkdir -p "$HOME_DIR/.zclassic-c23-serve1"
echo "marker: this is the operator's real synced state" > "$HOME_DIR/.zclassic-c23-serve1/MARKER"

# Old numbered unit — mirrors the shape of platform/deploy/zcl-serve.service: its
# ExecStart uses the literal (shell-unexpanded) systemd "%h" specifier,
# exactly like a real installed unit would.
cat > "$HOME_DIR/.config/systemd/user/zcl-serve1.service" <<'UNIT'
[Unit]
Description=Z23 Serve1 lane (secondary full node + block explorer)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=%h/zclassic23/build/bin/zclassic23 \
    -datadir=%h/.zclassic-c23-serve1 \
    -port=39072 \
    -rpcport=39073 \
    -fsport=39074 \
    -httpsport=39473 \
    -listen \
    -txindex \
    -tor \
    -showmetrics=0
Restart=always
RestartSec=5
TimeoutStopSec=90
KillMode=control-group
OOMScoreAdjust=-500
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=%h/.zclassic-c23-serve1 %h/zclassic23/vendor/tor/etc
PrivateTmp=yes
StandardOutput=append:%h/.zclassic-c23-serve1/node.log
StandardError=append:%h/.zclassic-c23-serve1/node.log
LimitCORE=infinity
Environment="ZCL_CORE_DIR=%h/.zclassic-c23-serve1/cores"

[Install]
WantedBy=default.target
UNIT

run_migrate() {
    # Prepend the stub dir so systemctl resolves to it, never the real one.
    HOME="$HOME_DIR" PATH="$STUB_BIN:$PATH" "$MIGRATE_SCRIPT" "$@"
}

# ── 1. --dry-run: must plan the rename, must NOT touch anything ───────────
: > "$STUB_LOG"
if ! DRY_OUT="$(run_migrate --dry-run 2>&1)"; then
    failmsg "dry-run exited non-zero"
fi
printf '%s\n' "$DRY_OUT"

if [ -d "$HOME_DIR/.zclassic-c23-serve1" ] && [ -f "$HOME_DIR/.zclassic-c23-serve1/MARKER" ]; then
    pass "dry-run left the numbered datadir untouched"
else
    failmsg "dry-run mutated the numbered datadir"
fi
if [ ! -e "$HOME_DIR/.zclassic-c23-serve" ]; then
    pass "dry-run did not create the canonical datadir"
else
    failmsg "dry-run created the canonical datadir"
fi
if [ ! -e "$HOME_DIR/.config/systemd/user/zcl-serve.service" ]; then
    pass "dry-run did not write the new unit"
else
    failmsg "dry-run wrote the new unit"
fi
if printf '%s\n' "$DRY_OUT" | grep -q '\[dry-run\] serve datadir: would: mv'; then
    pass "dry-run plan explicitly mentions the serve datadir rename (the %h-unexpanded bug made this go silent)"
else
    failmsg "dry-run plan does not mention the serve datadir rename"
fi
if [ -s "$STUB_LOG" ]; then
    failmsg "dry-run invoked systemctl ($(cat "$STUB_LOG"))"
else
    pass "dry-run never invoked systemctl"
fi

# ── 2. real run: must actually rename, preserve %h, and stop-before-rename ─
: > "$STUB_LOG"
if ! REAL_OUT="$(run_migrate 2>&1)"; then
    failmsg "real run exited non-zero"
fi
printf '%s\n' "$REAL_OUT"

if [ -d "$HOME_DIR/.zclassic-c23-serve" ] && [ -f "$HOME_DIR/.zclassic-c23-serve/MARKER" ]; then
    pass "real run renamed the numbered datadir onto the canonical name (marker file intact) — the %h-unexpanded orphaning bug is gone"
else
    failmsg "real run did NOT rename the datadir onto the canonical name — this is the orphaning bug"
fi
if [ -e "$HOME_DIR/.zclassic-c23-serve1" ]; then
    failmsg "real run left the old numbered datadir in place after a successful rename"
else
    pass "old numbered datadir is gone post-rename"
fi

NEW_UNIT="$HOME_DIR/.config/systemd/user/zcl-serve.service"
if [ -f "$NEW_UNIT" ]; then
    pass "real run wrote the canonical unit file"
    if grep -Eq -- '-datadir=%h/\.zclassic-c23-serve([[:space:]]|$)' "$NEW_UNIT"; then
        pass "canonical unit's ExecStart keeps the systemd %h specifier, pointing at the canonical (unnumbered) datadir"
    else
        failmsg "canonical unit's ExecStart does not read '-datadir=%h/.zclassic-c23-serve' (got: $(grep datadir "$NEW_UNIT" || true))"
    fi
    if grep -qi 'serve1' "$NEW_UNIT"; then
        failmsg "canonical unit still contains an instance-numbered 'serve1'/'Serve1' string (case-insensitive strip did not fire): $(grep -i serve1 "$NEW_UNIT")"
    else
        pass "instance-number strings fully stripped, including the capitalized Description= text"
    fi
else
    failmsg "real run did not write the canonical unit file"
fi

if grep -q -- '--user enable --now zcl-serve.service' "$STUB_LOG" 2>/dev/null; then
    pass "real run enabled+started the new unit (stubbed systemctl)"
else
    failmsg "real run never called 'systemctl --user enable --now zcl-serve.service' (stub log: $(cat "$STUB_LOG" 2>/dev/null))"
fi
if grep -q -- '--user stop zcl-serve1.service' "$STUB_LOG" 2>/dev/null; then
    pass "real run stopped the old unit"
else
    failmsg "real run never stopped the old unit"
fi
stop_line="$(grep -n -- '--user stop' "$STUB_LOG" 2>/dev/null | head -1 | cut -d: -f1 || true)"
enable_line="$(grep -n -- 'enable --now' "$STUB_LOG" 2>/dev/null | head -1 | cut -d: -f1 || true)"
if [ -n "$stop_line" ] && [ -n "$enable_line" ] && [ "$stop_line" -lt "$enable_line" ]; then
    pass "old unit was stopped BEFORE the new unit was enabled/started (datadir rename happens in between, never under a live process)"
else
    failmsg "stop did not happen before enable --now (stop_line=$stop_line enable_line=$enable_line)"
fi

# ── 3. idempotency: a second real run must not fail or re-mutate ──────────
: > "$STUB_LOG"
if ! IDEMPOTENT_OUT="$(run_migrate 2>&1)"; then
    failmsg "second real run exited non-zero"
fi
printf '%s\n' "$IDEMPOTENT_OUT"
if printf '%s\n' "$IDEMPOTENT_OUT" | grep -q 'SKIPPED (new unit already present)'; then
    pass "second run reports SKIPPED for the unit (already migrated)"
else
    failmsg "second run did not report the expected SKIPPED verdict for the unit"
fi
if [ -d "$HOME_DIR/.zclassic-c23-serve" ] && [ -f "$HOME_DIR/.zclassic-c23-serve/MARKER" ]; then
    pass "second run left the already-migrated canonical datadir intact"
else
    failmsg "second run disturbed the already-migrated canonical datadir"
fi
if [ -s "$STUB_LOG" ]; then
    failmsg "second (idempotent) run invoked systemctl unexpectedly ($(cat "$STUB_LOG"))"
else
    pass "second run made no systemctl calls (nothing left to migrate)"
fi

# ── 4. regression case: an unlocatable datadir must refuse, never migrate
# blind ─────────────────────────────────────────────────────────────────
REFUSE_HOME="$SANDBOX/home-refuse"
mkdir -p "$REFUSE_HOME/.config/systemd/user"
# Deliberately no ~/.zclassic-c23-serve2 anywhere on disk: this reproduces
# "the recorded datadir cannot be located by path or by glob fallback" —
# the exact condition under which the old script would silently proceed.
cat > "$REFUSE_HOME/.config/systemd/user/zcl-serve2.service" <<'UNIT'
[Unit]
Description=Z23 Serve2 lane
[Service]
Type=simple
ExecStart=%h/zclassic23/build/bin/zclassic23 -datadir=%h/.zclassic-c23-serve2 -port=39072
[Install]
WantedBy=default.target
UNIT

: > "$STUB_LOG"
set +e
REFUSE_OUT="$(HOME="$REFUSE_HOME" PATH="$STUB_BIN:$PATH" "$MIGRATE_SCRIPT" 2>&1)"
REFUSE_RC=$?
set -e
printf '%s\n' "$REFUSE_OUT"
if [ "$REFUSE_RC" -ne 0 ] && printf '%s\n' "$REFUSE_OUT" | grep -q 'REFUSING:'; then
    pass "unlocatable-datadir case refuses loudly instead of migrating the unit blind"
else
    failmsg "unlocatable-datadir case did not refuse (rc=$REFUSE_RC) — this is the silent-orphan regression"
fi
if [ -e "$REFUSE_HOME/.config/systemd/user/zcl-serve.service" ]; then
    failmsg "refusal case still wrote the new unit file"
else
    pass "refusal case never wrote the new unit file"
fi
if [ -s "$STUB_LOG" ]; then
    failmsg "refusal case still invoked systemctl ($(cat "$STUB_LOG"))"
else
    pass "refusal case never invoked systemctl (old unit never stopped, new unit never started)"
fi

if [ "$FAILED" -eq 0 ]; then
    printf '[migrate-role-names-selftest] ALL CHECKS PASSED\n'
    exit 0
else
    printf '[migrate-role-names-selftest] SOME CHECKS FAILED\n' >&2
    exit 1
fi
