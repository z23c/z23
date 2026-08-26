<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->
# RAM development workspace for rotating-disk hosts

The provisioner creates one disposable 6 GiB tmpfs checkout for an agent,
keeps the authoritative source checkout on persistent storage, and preserves
an existing zram swap. It does not inspect or control a node service, wallet,
or canonical datadir. Commands run in a user systemd scope with 8 GiB
`MemoryHigh`, 10 GiB `MemoryMax`, and reduced CPU and I/O weights.

## Measured baseline

Measurements taken on 2026-08-26 before provisioning:

| Host | RAM | CPU | Storage | Largest observed build | Existing swap |
| --- | ---: | ---: | --- | ---: | --- |
| slow host A | 15.6 GiB | 8 cores | rotating 1 TB ext4 | 5.29 GiB | 8 GiB zram + 4 GiB disk |
| slow host B | 15.6 GiB | 8 cores | rotating 1 TB ext4 | 3.22 GiB | 8 GiB zram + 4 GiB disk |

The 6 GiB workspace cap fits the largest observed build without reserving the
memory up front. It is a capacity choice, not an unmeasured speed claim. The
repository's Git object store is approximately 65 MiB; bootstrap makes an
independent copy in RAM rather than relying on mutable object alternates.

## Install and use

Run from the persistent, clean `main` checkout:

```bash
sudo deploy/provision-z23-build-host.sh install \
  --user="$USER" --repo="$PWD"
sudo -u "$USER" z23-ram-dev bootstrap
sudo -u "$USER" z23-ram-dev run -- make -j"$(nproc)"
sudo -u "$USER" z23-ram-dev path
```

`path` prints the exact RAM checkout to use as an external agent's working
directory. Launch an interactive Grok session in the bounded scope with normal
terminal scrollback:

```bash
z23-ram-dev run -- grok --minimal --no-alt-screen
```

Interactive commands receive a pseudo-terminal; non-interactive commands keep
pipe semantics. Temporary files, the checkout, build output, ZCC entries, and
XDG caches stay within the single tmpfs cap. Home-directory credentials, Grok
session transcripts, and the persistent source checkout remain durable outside
it.

RAM work is lost at shutdown. Commit all files, push the commit to `main`, and
then record and verify the checkpoint:

```bash
sudo -u "$USER" z23-ram-dev checkpoint
sudo -u "$USER" z23-ram-dev status
```

Checkpoint first copies the clean commit into a persistent local recovery ref, then
fetches and verifies that `origin/main` contains it. It refuses a dirty tree
or an unpushed commit. A later bootstrap fast-forwards the persistent checkout
and starts at the exact verified `origin/main`; it refuses while a recovery
checkpoint remains unpublished.

## Verify and remove

```bash
sudo deploy/provision-z23-build-host.sh status
sudo deploy/provision-z23-build-host.sh uninstall
```

Uninstall refuses when the current RAM commit lacks a clean, verified
checkpoint. To intentionally discard it, use
`uninstall --confirm-discard-ram`. Existing zram is never replaced or stopped;
only a zram device created by this provisioner is removed.
