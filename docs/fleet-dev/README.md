<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Maintainer fleet tooling (opt-in)

This page is for maintainers who run Z23 development on several machines. It
is not needed to contribute; volunteers start at
[`.github/CONTRIBUTING.md`](../../.github/CONTRIBUTING.md). Nothing here
carries a machine name, address or credential: those live in a local file that
is never committed.

## Set up a new machine

1. Build the runner with `make z23-fx` and the `z23` binary as in
   [`docs/BUILD.md`](../BUILD.md). Put
   `build/bin/z23-fx` and `build/bin/z23` on `PATH`.
2. Create the private fleet file from the placeholder example:

   ```sh
   mkdir -p ~/.config/z23
   cp docs/fleet-dev/fleet.example.json ~/.config/z23/fleet.json
   chmod 600 ~/.config/z23/fleet.json
   ```

   Edit it: `name` is the short name you type, `ssh` is a host alias from
   `~/.ssh/config` (or `user@host`), `roles` are free labels. Names and roles
   use letters, digits, `_` and `-`; `all` is reserved. Keep this file out of
   every repository.
3. Check the route: `z23-fx dev1 'uname -sm'`, then `z23-fx all 'uname -sm'`.
4. Install the opt-in plugin in Claude Code:

   ```sh
   claude plugin marketplace add <path-or-url-of-this-repo>
   claude plugin install z23-fleet@z23
   ```

   It adds five agents (`z23-capsule-facts`, `z23-scout`, `z23-implement`,
   `z23-watch`, `z23-review`) and two skills (`z23-dev-card`, `z23-dev-fleet`).
   Its steer-gateway tools still need a maintainer-issued grant, see
   [`.claude/plugin-fleet/README.md`](../../.claude/plugin-fleet/README.md).

## z23-fx

```text
z23-fx [--config=PATH] [--print-argv] HOST|all|@ROLE 'command'
```

The command is passed to `ssh` as one argument; no local shell sees it. One
host keeps stdin and stdout, so `z23-fx dev1 'cat > FILE' < local` works.
`all` and `@ROLE` run in parallel and print `name | line`. Each machine uses
`ssh -o BatchMode=yes -o ConnectTimeout=8` and a control socket
`z23-fx-%C` under `$XDG_RUNTIME_DIR` (else `~/.ssh`). The exit status is the
largest status of any machine; configuration and usage errors exit 2.
`--print-argv` prints the exact argv per machine as JSON and starts nothing.

## Daily loop

| Question | Command |
| --- | --- |
| What is going on? | `z23 dev fleet start` |
| Open cards and problems | `z23 fleet board list --room=work --open` |
| Machine load and disk | `z23 fleet vitals table`, `z23 fleet machines` |
| Lanes on every machine | `z23-fx all 'git -C LANE_PARENT worktree list'` |
| Read a log or directory | `z23-fx NAME 'tail -n 40 LOG'` |
| Wait for a detached job | agent `z23-watch`, or `z23-fx NAME 'timeout 100 sh -c "until tail -n 3 LOG \| grep -q RC=; do sleep 20; done"'` |
| Edit a remote file | edit locally, `git diff \| z23-fx NAME 'git -C LANE apply'` |
| Run one card | skill `z23-dev-card` |
| Review a contributor branch | `z23 dev vcs ports --base=origin/main --tip=REMOTE/BRANCH` |
| Stack lanes (in a checkout) | `build/bin/z23-dev dev train build`, `... train check`, `... train status` |
| Land a reviewed commit (in a checkout) | `build/bin/z23-dev dev land submit`, `... land drive`, `... land status` |

The old private views map as: `overview` to `dev fleet start`, `trees` to
the worktree line above, `peek` to `tail`, `pull` and `push` to the patch line,
`wait` to `z23-watch`, `landlog` to `dev land status`, `capsule` and `board` to
the work-room board.

Not yet native, with the fallback used today: `z23 work list|show|submit` (read
the board or `docs/work/cards.jsonl`); a card validator (agent
`z23-capsule-facts` checks the fields); one command listing lanes across
machines (plain git through `z23-fx`); remote file edit (patch apply); waiting
on a detached remote job (`z23-watch`).

## Not migrated

The maintainer's run history, ledgers, grants, worker rosters and retired
agent configurations stay in the maintainer's private archive. This repository
holds only procedures that work from public commands and the local fleet file.
