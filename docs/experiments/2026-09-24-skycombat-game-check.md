<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# SkyCombat game-check and cold app build

Date: 2026-09-24T11:51:44-04:00 (2026-09-24T15:51:44+00:00).
Base commit: `5dd34812a1de5a948e1bb121e1d9619ecdcf55a4`.
Compiler: GCC 16.1.1 20260430, `-std=c23`.
CPU: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics.

The untouched `make -j8 game-check` failed under `-Werror` because
`apps/skycombat/src/models/test_multiplayer_complete.c` initialized and
incremented `frame` without reading it. Its source SHA-256 was
`9a60fc7e6b560a1c875c33a6319fe414e5ca888ce587610bc9b6ba9aa4e82280`.
Removing those two dead statements produced source SHA-256
`0f767ecb000bd289e86513b859c51467c48cd13e08cbfd5a7480d69626935305`.
The full `game-check` then compiled 71 game and 5 raylib translation units.
The game binary linked afterward at SHA-256
`9a7a46565f2414bd8ccb5c9ee6ebb7c60b951ea690177f958123993091e4082c`,
identical to the previously previewed app binary.

A fresh worktree's first `game-check` also entered the node vendor bootstrap:
it built zlib, SQLite, OpenSSL, libevent, LevelDB, and copied Tor archives
before compiling the game. Neither game target links these archives.
The Makefile now classifies `game`, `game-check`, and `game-platform-probe` as
game-only goals for both the node vendor and Tor bootstrap decisions. Mixed
goals continue to bootstrap node dependencies. The missing-Tor warning now
appears only when a Tor-linked goal is requested. Final Makefile SHA-256 is
`1254eb68c7e60fbb6df87722937455fe32d51944610538ede7c9077b12efc4eb`.

Two fresh isolated worktrees with the edited game source and game-only
bootstrap classification ran `make -j8 game-check` successfully. The first
took 74.935 s; the second, with the warning correction, took 18.873 s.
The latter `make -j8 game` took 18.016 s. The two game-check timings are not
a controlled speedup comparison: concurrent host load differed. The second
worktree retained only the repository's one preexisting vendor archive and
did not populate node vendor or Tor archives. Its logs contain no vendor
bootstrap and no Tor warning.
A third cold worktree, based on
`2a976d7ddcc3e24178218caff3276d1179b1e16c` and carrying the final
line-neutral Makefile, compiled the same 76 translation units in 13.894 s.
It likewise retained only the one preexisting archive and printed no
node-vendor or Tor bootstrap message. `make lint-fast` passed all 32 gates,
including the line-bound flag registry, after the Makefile edit.

| Exact artifact | SHA-256 |
| --- | --- |
| First cold game-check log | `7d2ad51c05c5cdfdd645eb96988f5bb9592a3db1da3aeca9bcfb1db1b6bab91f` |
| Final cold game-check log | `7c8ae2a6d75dbc2f6d9c9263352ab0bf1ab67a718f2c94680a280f4c23044df0` |
| Final cold game build log | `bbd80072f761d6291c17aa96af195c525909688926c5b29e51f6a8d254c367d2` |
| Line-neutral cold game-check log | `4789ba959e72c7bbd152b9c831e66fd07ba46996f81237bd1feae18a93144987` |

Repeat from a fresh worktree of the named base, with the two edited files
copied from this change:

```bash
make -j8 game-check
make -j8 game
sha256sum build/bin/z23-skycombat
```

The canonical SkyCombat aircraft Commons recipe still refuses a confined
factory build without declared libm. This game build improvement does not
publish or accept a Commons package, and the application owner has not
recorded a preview acceptance verdict.
