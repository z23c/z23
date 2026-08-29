<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Surface cleanup and embedded terminal boundary

Observed 2026-08-28T21:46:04-04:00 / 2026-08-29T01:46:04Z.

The explorer's generic disk-cache API had one remaining caller and one fixed
key. Specializing it to the statistics cache removed two exported declarations,
two caller-controlled parameters, and an unused-function diagnostic waiver.
Strict `explorer` acceptance ran three groups with zero failures and zero skips.

The machine-mesh plan now separates typed unattended work from owner-granted
interactive terminals. The terminal transport is embedded C23 over the paired
authenticated session, uses ConPTY on Windows and PTYs on POSIX hosts, and
requires a worker boundary that cannot read node or custody secrets. It does
not require a separately installed SSH server.

`make lint` passed all 158 gates. The complete patch removes more lines than it
adds and does not touch consensus, wallet, database migration, or deployment
authority.
