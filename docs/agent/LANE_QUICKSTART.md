<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Lane quickstart

Dispatch: [LANE_LAUNCH.md](LANE_LAUNCH.md). Report:
[LANE_REPORT.md](LANE_REPORT.md). Do not copy either here.

1. Setup. One worktree per lane. Record the origin/main commit as baseline.

```
cd /path/to/checkout && git fetch -q origin && \
git worktree add -q ~/.z23/lanes/<name> -b agent/<name>-<date> origin/main && \
cd ~/.z23/lanes/<name> && git submodule update --init --recursive -q && \
make worktree-prime && make install-hooks && make -j32 z23
```

Workspace: lanes live in the node's hidden workspace tree, not beside the
real checkouts; see
[`../zrc/0005-node-workspace-layout-and-hygiene.md`](../zrc/0005-node-workspace-layout-and-hygiene.md).

2. Find what your change touches. The first command prints the test groups
   that cover a file. Run those groups with the second. Note:
   `make test_parallel ONLY=x` only builds.

```
build/bin/z23 code tests <file>
ulimit -s unlimited; make -j32 t-fast ONLY=<group>
```

3. Gate. Iterate with lint-fast. Before you report, background full lint
   and read its summary (minutes). Then verdict prints one screen: red
   gates with their fix hint, failed groups, and a final VERDICT line.
   Quote those lines; never paraphrase.

```
make lint-fast
make lint
make verdict
```

4. Red gate that is not your change: `check-git-hooks-installed` means this
   worktree has not run `make install-hooks` yet; run it. Anything else
   red after your change is yours.

5. Land. Main rejects merge commits. Re-run the routed groups after a
   rebase that touched your files, then hand off; the orchestrator pushes.
   Commit trailer: `Co-Authored-By: <agent name> <noreply address>` as
   your harness specifies.

```
git fetch origin && git rebase origin/main
```

6. Traps, one line each:
   - Never edit a shell script while a run of it is in flight.
   - A foreground command longer than 10 minutes gets killed; background
     it and poll a log.
   - Use `grep -a` on logs.
   - Never python. Never jq.
   - Never touch core/, wallet custody, consensus seals, or a live node.
   - One worktree per lane; never two lanes in one checkout.

7. Report. Use the shape in [LANE_REPORT.md](LANE_REPORT.md). End with:

```
head <hash>, base <hash>, acceptance green, ready for review
```
