<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->
# Slow-node platform boundaries

## Intention

Keep an honest node alive during a declared, bounded Tor/socket wait without
letting an expired wait hide a wedged dial loop. Refuse a Windows data
directory unless its live owner, ACL, and reparse state satisfy the private
directory contract before boot publishes or opens that path. Compile the
Windows seam at the same `_WIN32_WINNT` floor as the product build.

## Environment

- Local: `2026-08-28T22:23:13-04:00` (`AST`)
- UTC: `2026-08-29T02:23:13Z`
- CPU: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics
- Native compiler: GCC 16.1.1 20260430
- Windows cross-compiler: GCC 16.1.0 (`x86_64-w64-mingw32`)

## Evidence

- `make -j16 t-fast ONLY=sd_notify`: one group passed, zero failed, zero
  skipped. A controlled pipe wait stayed alive only while its explicit lease
  was active; the identical unleased blocked mirror remained dead.
- `make -j16 t-fast ONLY=encoding`: four groups passed, zero failed, zero
  skipped. `SetDataDir` refused a symlinked directory and recovered only after
  replacement with a private real directory.
- `make windows-acceptance-compile`: strict C23 cross-link passed, including
  the new data-directory privacy program and wallet-restore refusal program.
- The data-directory program returned `77` under Wine because Wine could not
  prove the native Windows SID/DACL semantics. This is unobserved, not a
  Windows runtime pass; an actual Windows worker must provide that receipt.
- `tools/lint/check_windows_platform_seam.sh --self-test` passed, then 29
  platform-seam files cross-compiled at the Makefile-owned Windows API floor
  with zero known diagnostic sites.

No production node, canonical data directory, wallet, or deployment was
mutated by these checks.
