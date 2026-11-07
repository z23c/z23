<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

<p align="center">
  <img src="docs/assets/z23-hero.webp" alt="Z23: Share the software. Build the future. A hacker in a black Z23 hoodie and six plush mascots build a glowing gold cube on a terrace, while gold threads carry cubes to and from other teams across a sunlit bay.">
</p>

<p align="center">
  <b>Your own ZClassic full node and C23 software lab, in one program<br>
  you build from source and run on your own machine.</b>
</p>

<p align="center">
  <a href="#start-here">Start here</a> ·
  <a href="#your-first-lab">Your first lab</a> ·
  <a href="#join-in">Join in</a> ·
  <a href="docs/README.md">Docs</a> ·
  <a href="https://t.me/z23_chat">Chat</a>
</p>

<a id="north-star"></a>

## Why Z23

We're building Z23 toward a lab that helps improve itself: free software you
can inspect, change, and share. Every part answers to the person running it,
not to an AI vendor, a package registry, or a hosted service.

<table>
  <tr>
    <td width="33%"><img src="docs/assets/z23-node.webp" alt="Your own node: a robot inspects a chain of glowing blocks beside a node tower and a ZCL coin in a glass case."></td>
    <td width="33%"><img src="docs/assets/z23-lab.webp" alt="Your own lab: a penguin and a squirrel feed a page marked C into a glass test box; a green check lights and a sealed gold cube comes out."></td>
    <td width="33%"><img src="docs/assets/z23-share.webp" alt="Share it freely: a fox hands a gold cube to a bunny on another balcony, who checks it with a magnifying glass while a unicorn cheers."></td>
  </tr>
  <tr>
    <td>A full ZClassic node that checks every block itself, down to the
    zero-knowledge proofs, and keeps your private wallet. ZCL is money for
    paying and being paid, not an investment.</td>
    <td>Write one C file; Z23 runs it in a sandbox, tests it, and signs it
    as a plugin.</td>
    <td>Send source to other nodes. Whatever you fetch is rebuilt and
    re-tested on your machine and kept only if you accept it.</td>
  </tr>
</table>

You and any AI you choose use the same commands. An AI can propose, build
and test; it never holds your keys or decides what you accept. Z23 is
pre-v1: ready to build, run and inspect, not finished.
[MVP](docs/quality/MVP.md) tracks the eight v1 criteria with their evidence.

## Start here

```bash
git clone --recurse-submodules https://github.com/z23c/z23.git
cd z23
make doctor                                 # what this machine still needs
make -j"$(getconf _NPROCESSORS_ONLN)" z23   # builds build/bin/z23
build/bin/z23                               # start the node (leave it running)
build/bin/z23 status                        # in a second terminal: how it is doing, and what to do next
```

You need gcc 14+ (or clang with `-std=c23`) and GNU make. The first build
fetches pinned sources and checks each one's SHA-256; after that it builds
offline. macOS, Windows and the rest are in
[Getting Started](docs/node/GETTING_STARTED.md). For an experimental Android app, see
[Android ARM64](docs/dev/ANDROID.md).

## Try an app

The quickest thing to touch is Sky Combat, a single-player flight game that
ships in this repo. It needs no node and no network. Play it, make your own
copy, change it, and give it to a friend, one plain command per step. The
examples keep your copies in their own data directory, apart from a node's:

```bash
make z23 game          # build/bin/z23 and the game (needs X11 + GL headers)
build/bin/z23 -datadir="$HOME/.z23-apps" app open skycombat     # play it
build/bin/z23 -datadir="$HOME/.z23-apps" app copy skycombat     # skycombat-1
#   ...edit a file in the copy it names...
build/bin/z23 -datadir="$HOME/.z23-apps" app save skycombat-1   # keep the edit
build/bin/z23 -datadir="$HOME/.z23-apps" app build skycombat-1
build/bin/z23 -datadir="$HOME/.z23-apps" app open skycombat-1   # your version
build/bin/z23 -datadir="$HOME/.z23-apps" app share skycombat-1  # one file
```

Send the file `skycombat-1.z23share`. Share also prints the fingerprint and
version root your friend will be asked to confirm; tell them these another
way, over chat or voice, so they can check. Your copy keeps opening as before.

Your friend builds the game from the file's source, so they need z23 from a
clone and build (Start here above, about 3 minutes), a C compiler and, on
Linux, the X11 and GL headers (the ones `make game` needs). Then they run one
command:

```bash
z23 -datadir="$HOME/.z23-apps" app open skycombat-1.z23share
```

It checks the file, shows who signed it as a short fingerprint such as
`833d-7ae5-d858-315d` and the exact version root, asks y/N,
then keeps, builds and opens the game. Each step asks y/N before it changes
anything; `--yes` answers for scripts, and without a terminal or `--yes` a
step only shows its plan. `z23 app list` lists your copies.
[Sky Combat](docs/commons/GAME.md) covers controls, checks and packaging.

Bare `build/bin/z23` uses the default ports and data directory and starts
syncing mainnet. To run a node beside other work, or just to look around,
give it its own data directory and ports:

```bash
build/bin/z23 -datadir="$HOME/.zclassic-c23-dev" -port=8035 -rpcport=18234 \
    -fsport=18035 -httpsport=8445
build/bin/z23 -datadir="$HOME/.zclassic-c23-dev" -rpcport=18234 stop   # when done
```

To publish a package for everyone rather than one friend, see the
[Commons quickstart](docs/commons/C23_COMMONS_QUICKSTART.md).

## Connect your AI to a local app

Follow [Try, change and share an app](docs/commons/PLUGIN_APPS.md#try-change-and-share-an-app)
to connect your AI client to the installed local stdio MCP server, using the
same persistent app data directory as your CLI commands. Local apps need no
repository checkout, running node or blockchain sync. The
[shipped app guide](platform/packaging/release/AGENT_CARD.md#connect-your-ai-to-a-local-app)
lists the graphical desktop and compiler requirements for Linux and macOS.

Then ask your AI:

> Open the flight game. Help me make my own copy, change its appearance,
> preview the saved version, keep it if I approve, and share it with a friend.

Making a personal copy and sharing require your local native confirmation.

<!-- claim: symbol-present zcl_mcp_serve_main tools/mcp/mcp_serve.c # local stdio app adapter -->
<!-- claim: symbol-present SKYCOMBAT_GAME_MAIN apps/skycombat/skycombat.mk # maintained game entrypoint -->

## Run a node

```bash
build/bin/z23
```

The node joins the network over its built-in Tor and serves its own block
explorer on its own `.onion` address. If sync stalls,
`build/bin/z23 core sync diagnose` says why and `ops logs` shows recent
diagnostics. Faster first syncs: [Sync](docs/node/SYNC.md).

## Your first lab

```bash
cat > hello.c <<'EOF'
#include <stdio.h>
int main(void) { puts("hello, lab"); return 0; }
EOF
build/bin/z23 lab run hello.c
```

`lab run` builds the file as strict C23 (with sanitizers when your compiler
has them), runs it in a private sandbox with no network, and keeps a
receipt. `lab test` checks it against your cases, and `lab promote` signs it
as a plugin. `build/bin/z23 discover help lab` lists the rest.

<!-- claim: symbol-present lab.run engine/composition/commands/lab.def # live one-file lab leaf -->
<!-- claim: symbol-present lab.test engine/composition/commands/lab.def # live lab cases leaf -->
<!-- claim: symbol-present lab.promote engine/composition/commands/lab.def # live lab-to-plugin leaf -->

## Join in

<p align="center">
  <img src="docs/assets/z23-join.webp" alt="Join us. Build free software. The hacker and six mascots wave from a sunset terrace beside an empty seat and an open laptop.">
</p>

Z23 improves itself in the open: AI workers propose changes, a different
model reviews each one, and only changes with evidence land. Take the same
small tasks, with or without your own AI.

- **Pick a task:** `build/bin/z23 card` lists starter tasks, and
  [CONTRIBUTING](.github/CONTRIBUTING.md) shows how to submit one.
- **Change the code:** `make dev-bin` builds fast,
  `make t-list` lists every registered group, and
  `make t-fast ONLY=<group>` runs one.
  `build/bin/z23 discover help` walks the native command registry.
- **Go deeper:** [How the node works](docs/node/HOW_THE_NODE_WORKS.md) ·
  [The C23 Commons](docs/commons/C23_COMMONS_QUICKSTART.md) ·
  [Vision](docs/agent/VISION.md) · [Developing](docs/dev/DEVELOPING.md) ·
  [AGENTS.md](AGENTS.md)
- **Talk to us:** [Z23 Chat on Telegram](https://t.me/z23_chat)

<!-- claim: symbol-present work.list engine/composition/commands/work.def # card alias leaf -->

## License

100% permissive: [Apache-2.0](LICENSE), with upstream notices kept in
[NOTICE](NOTICE).
