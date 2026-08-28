#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# make_app_bundle.sh — wrap an already-built C23 tool binary in the minimal
# launchable macOS .app bundle, reproducibly.
#
#   usage: make_app_bundle.sh <binary> <app-name> <out-dir>
#   produces: <out-dir>/<app-name>.app/Contents/{MacOS/<exe>,Info.plist,PkgInfo}
#             plus Contents/_CodeSignature/CodeResources (written by codesign)
#
# Why a script and not a Makefile rule: the bundle is a by-product any lane or
# operator can produce for ANY package binary, not a per-tool rule the
# Makefile would have to grow one entry at a time. `make app-bundle` is the
# one wired convenience path over this script.
#
# REPRODUCIBILITY CONTRACT — the reason this file exists rather than a
# hand-rolled mkdir/cp in a lane script:
#
#   * Identical <binary> + <app-name> + <out-dir-must-not-matter> in two
#     invocations produce byte-identical bundle trees, signature included.
#   * Info.plist carries only pinned literal fields. No build date, no build
#     host, no version derived from the working tree — a bundle's identity is
#     the executable it wraps, and CFBundleVersion is pinned so a rebuild on
#     another day cannot differ.
#   * Files are created in a fixed order with fixed modes and a fixed mtime
#     (TZ=UTC epoch anchor), so even a tar of the tree is reproducible.
#   * The signature is ad-hoc (`codesign --sign -`) with the timestamp server
#     disabled (--timestamp=none). arm64 macOS refuses to execute an unsigned
#     binary at all, so ad-hoc is the floor, and --timestamp=none is what
#     keeps it deterministic: a timestamp server stamps wall-clock time into
#     the signature, which would make two builds of identical input differ.
#   * codesign embeds the signature in the Mach-O and writes CodeResources,
#     so hashing every file under the bundle hashes the signature too.
#     tools/lint/check_app_bundle_reproducible.sh proves this end to end.
#
# The bundle is the MINIMAL launchable one: no Resources/, no icon, no
# entitlements, no hardened-runtime option. A GUI app can grow those later;
# the contract above is the part that must not rot.
#
# Exit: 0 and the bundle path on stdout; nonzero with a `make_app_bundle:`
# message on stderr otherwise.

set -euo pipefail

die() {
    echo "make_app_bundle: $1" >&2
    exit 1
}

[ "$#" -eq 3 ] || die "usage: make_app_bundle.sh <binary> <app-name> <out-dir>"

BINARY="$1"
APP_NAME="$2"
OUT_DIR="$3"

command -v codesign >/dev/null 2>&1 ||
    die "codesign not found — this script produces a macOS .app bundle (arm64 macOS refuses to run an unsigned binary)"
command -v plutil >/dev/null 2>&1 ||
    die "plutil not found — cannot validate the Info.plist this script writes"

[ -f "$BINARY" ] || die "input binary not found: $BINARY"
[ -x "$BINARY" ] || die "input binary is not executable: $BINARY"

# A hostile app name is a path component in disguise. Allow exactly what a
# bundle name may be; reject everything else (including leading dots).
case "$APP_NAME" in
    ''|.*|*[!A-Za-z0-9._-]*)
        die "app-name must match [A-Za-z0-9][A-Za-z0-9._-]* — got '$APP_NAME'" ;;
esac
case "$APP_NAME" in
    *.app) EXE_APP_STEM="${APP_NAME%.app}" ;;
    *)     EXE_APP_STEM="$APP_NAME" ;;
esac

EXE_NAME="$(basename "$BINARY")"
case "$EXE_NAME" in
    ''|.*|*[!A-Za-z0-9._-]*)
        die "executable name must match [A-Za-z0-9][A-Za-z0-9._-]* — got '$EXE_NAME'" ;;
esac

# CFBundleIdentifier, derived but pinned: same app name in, same identifier
# out, on every host. Reverse-DNS style, alphanumerics, hyphens and dots only.
BUNDLE_ID_TAIL="$(printf '%s' "$EXE_APP_STEM" | tr '[:upper:]' '[:lower:]' | tr -C '[:alnum:]' '-')"
# Collapse runs and strip edges so '..' or 'a--b' cannot yield an empty or
# double-delimited identifier component.
BUNDLE_ID_TAIL="$(printf '%s' "$BUNDLE_ID_TAIL" | sed -e 's/-\{2,\}/-/g' -e 's/^-*//' -e 's/-*$//')"
[ -n "$BUNDLE_ID_TAIL" ] ||
    die "app-name '$APP_NAME' reduces to an empty CFBundleIdentifier component"
BUNDLE_ID="org.z23.${BUNDLE_ID_TAIL}"

BUNDLE="$OUT_DIR/${EXE_APP_STEM}.app"
CONTENTS="$BUNDLE/Contents"
MACOS_DIR="$CONTENTS/MacOS"

# Rebuild from scratch: a leftover CodeResources or a stale executable from an
# earlier run would make the tree a function of history, not of input.
rm -rf "$BUNDLE"
mkdir -p "$MACOS_DIR"

# 1. The executable. Plain cp (no -p): mtimes and modes are normalized below,
#    and cp without -X does not carry extended attributes across.
cp "$BINARY" "$MACOS_DIR/$EXE_NAME"

# 2. Info.plist — pinned literal fields, fixed order, tab indentation. The
#    version fields are pinned on purpose: they describe the bundle format,
#    not a release, so a rebuild can never embed a different value.
cat > "$CONTENTS/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>en</string>
	<key>CFBundleExecutable</key>
PLIST
printf '\t<string>%s</string>\n' "$EXE_NAME" >> "$CONTENTS/Info.plist"
cat >> "$CONTENTS/Info.plist" <<'PLIST'
	<key>CFBundleIdentifier</key>
PLIST
printf '\t<string>%s</string>\n' "$BUNDLE_ID" >> "$CONTENTS/Info.plist"
cat >> "$CONTENTS/Info.plist" <<'PLIST'
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
PLIST
printf '\t<string>%s</string>\n' "$EXE_APP_STEM" >> "$CONTENTS/Info.plist"
cat >> "$CONTENTS/Info.plist" <<'PLIST'
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>1.0</string>
	<key>CFBundleVersion</key>
	<string>1</string>
	<key>LSMinimumSystemVersion</key>
	<string>11.0</string>
</dict>
</plist>
PLIST

# 3. PkgInfo — exactly 8 bytes, no trailing newline, per the bundle format.
printf 'APPL????' > "$CONTENTS/PkgInfo"

# 4. Normalize everything the signature does NOT cover, before signing: modes,
#    extended attributes (a copied binary can carry com.apple.provenance-style
#    xattrs that differ per host), and a fixed mtime so even a tar of the tree
#    is byte-reproducible. TZ=UTC pins `touch -t` across hosts.
find "$BUNDLE" -type d -exec chmod 0755 {} +
find "$BUNDLE" -type f -exec chmod 0644 {} +
chmod 0755 "$MACOS_DIR/$EXE_NAME"
if command -v xattr >/dev/null 2>&1; then
    xattr -cr "$BUNDLE" 2>/dev/null || true
fi
find "$BUNDLE" -exec env TZ=UTC touch -t 200001010000.00 {} +

# 5. Ad-hoc sign, no timestamp authority. --force because the arm64 linker has
#    usually already applied its own ad-hoc signature to the executable.
codesign --force --sign - --timestamp=none "$BUNDLE" >/dev/null 2>&1 ||
    die "codesign failed for $BUNDLE"

# 6. codesign rewrote the executable and wrote CodeResources: re-apply the
#    fixed modes and mtime. This cannot invalidate the signature — it covers
#    content, not metadata.
find "$BUNDLE" -type f -exec chmod 0644 {} +
chmod 0755 "$MACOS_DIR/$EXE_NAME"
find "$BUNDLE" -exec env TZ=UTC touch -t 200001010000.00 {} +

# 7. Prove the result is a valid, launchable-shaped bundle before handing it
#    back. A bundle that fails these is worse than no bundle.
codesign --verify --strict "$BUNDLE" >/dev/null 2>&1 ||
    die "codesign --verify --strict rejected $BUNDLE"
plutil -lint "$CONTENTS/Info.plist" >/dev/null ||
    die "plutil rejected $CONTENTS/Info.plist"
[ -f "$CONTENTS/PkgInfo" ] || die "PkgInfo missing from $CONTENTS"
[ -x "$MACOS_DIR/$EXE_NAME" ] || die "executable missing from $MACOS_DIR"

printf '%s\n' "$BUNDLE"
