<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

<p align="center">
  <img src="docs/assets/z23-banner.svg" alt="Z23 — software made for you, not imposed on you" width="100%">
</p>

<p align="center">
  <a href="LICENSE"><img src="docs/assets/badges/license.svg" alt="license: Apache-2.0"></a>
  <img src="docs/assets/badges/language.svg" alt="language: C23">
  <a href="docs/MVP.md"><img src="docs/assets/badges/status.svg" alt="status: pre-v1"></a>
  <a href="#try-the-magic"><img src="docs/assets/badges/start.svg" alt="start here"></a>
</p>

# Z23

**Software made for you, not imposed on you.**

Tell Z23 what you want software to do.

It can inspect the C23 that already exists, show an AI the small part that
matters, build and test an exact change, let you see the result, preserve the
version you chose, and let another machine reproduce it.

```text
YOU
 │
 │  "I want the plane to turn faster."
 ▼
Z23 finds the flight code
 │
 ├── what already exists?
 ├── what calls it?
 ├── what depends on it?
 ├── what should change?
 └── what tests prove the change?
         │
         ▼
AI changes a small amount of C23
         │
         ▼
you see the plane turn faster
         │
         ▼
you accept one exact version
         │
         ▼
another node reproduces it
```

And Z23 is also a real ZClassic proof-of-work full node.

The same project owns your software commons, exact source history, wallet,
peer-to-peer distribution, explorer, API, and optional Tor onion service.

AI workers are replaceable.

**Your software is not.**

---

# ✨ Try the magic

Public start here: [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md) is the
generic fresh-machine setup and first-run guide.

For a fast local development binary, run `make dev-bin`. When impact analysis
maps a change to tests, run the returned registered parallel group through the
canonical Make targets; do not invoke a test binary directly.

Build Z23:

```bash
git clone https://github.com/z23c/z23.git
cd z23

make doctor
make setup
make -j4 z23
```

Now ask the binary to explain itself:

```bash
build/bin/z23 discover help
```

This is not a hand-written CLI help page.

Z23 has a native command registry that describes the operations the running
software actually exposes.

Search it:

```bash
build/bin/z23 discover search "find C23 that already does something"
```

Inspect a command:

```bash
build/bin/z23 discover describe code.have
```

Ask for its exact machine-readable input schema:

```bash
build/bin/z23 discover schema code.have --side=input
```

An AI does not need a giant prompt containing hundreds of guessed tools.

It can ask Z23:

```text
What can you do?
        ↓
What command handles this?
        ↓
What exact input does it accept?
        ↓
What does it return?
        ↓
What should I do next?
```

That is the API.

---

# 🧠 Now ask Z23 about its own code

Before an AI writes another implementation, ask:

```bash
build/bin/z23 code have \
  --input='{"text":"bounded parser"}'
```

`code have` searches for the **concept**, not merely the spelling of a symbol.

Its job is to answer:

```text
DO WE ALREADY HAVE THIS?
```

with evidence from the checkout.

Then explore:

```bash
build/bin/z23 code map
```

```bash
build/bin/z23 code group lib/ontology
```

```bash
build/bin/z23 code room app/jobs/src/utxo_apply_stage.c
```

```bash
build/bin/z23 code sym codeindex_open
```

And this is where it gets interesting:

```bash
build/bin/z23 code capsule codeindex_open
```

A capsule can bring together the symbol's identity, declaration and
definition, callers, callees, include dependencies, command bindings,
evidence labels, likely change files, and explicit unknown sections.

Instead of:

```text
AI
 ↓
grep
 ↓
open file
 ↓
open another file
 ↓
grep again
 ↓
read 8,000 tokens
 ↓
guess
```

the goal is:

```text
AI
 ↓
z23 code capsule <thing>
 ↓
small bounded context
 ↓
understand
```

---

# 🔬 Ask what a change would affect

Suppose the AI wants to change:

```text
lib/util/include/util/safe_alloc.h
```

Ask Z23 for the blast radius:

```bash
build/bin/z23 code impact \
  lib/util/include/util/safe_alloc.h
```

Ask which focused tests own the change:

```bash
build/bin/z23 code tests \
  lib/util/include/util/safe_alloc.h
```

Or ask for a change plan around a symbol:

```bash
build/bin/z23 code change-plan codeindex_open
```

The desired loop is:

```text
WHAT DO I WANT?
       │
       ▼
DOES IT ALREADY EXIST?
       │
       ▼
WHAT EXACTLY SHOULD I READ?
       │
       ▼
WHAT SHOULD CHANGE?
       │
       ▼
WHAT DOES THAT AFFECT?
       │
       ▼
WHAT MUST BE PROVED?
```

Then run the exact focused proof:

```bash
make -j"$(getconf _NPROCESSORS_ONLN)" \
  t-fast-exact ONLY=<returned-group>

make lint-fast
```

This is what Z23 is trying to do for AI coding:

> **replace repository archaeology with a native, bounded, evidence-aware
> development API.**

---

# 📊 Ask Z23 whether the codebase is actually getting better

Z23 can inspect more than individual symbols.

For example:

```bash
build/bin/z23 code territory lib/net
```

asks questions like:

```text
What does this module own?

What tests reach its public API?

What dependencies enter it?

What depends on it?

What is weak or unproven?
```

And:

```bash
build/bin/z23 code corpus
```

is deliberately not just a line counter.

The long-term goal is a huge C23 corpus, but more lines are not automatically
better.

Z23 separates:

```text
HOW MUCH CODE EXISTS?
          ≠
HOW MUCH IS ACTUALLY PROVEN?
```

It can also record development metrics:

```bash
build/bin/z23 code kpi
```

The point is not to congratulate ourselves for producing code.

The point is to make useful software accumulate **without hiding duplicated,
unproven, or poorly understood complexity.**

---

# 🚀 Now make software

Ask Z23 for the current software-creation journey:

```bash
build/bin/z23 zcode guide
```

The product loop is:

```text
DESCRIBE
   ↓
REUSE
   ↓
CREATE
   ↓
SEE
   ↓
KEEP
   ↓
SHARE
```

### DESCRIBE

Say what behavior you want.

### REUSE

Find C23 that already provides part of it.

### CREATE

Write only what is missing.

### SEE

Run the real software and experience the consequence.

### KEEP

Accept one exact version.

### SHARE

Let another independent machine fetch and reproduce it.

![Describe, reuse, create, see, keep, share](docs/assets/z23-journey.svg)

**SEE is the center of the product.**

The user should not care that a manifest root is beautiful.

The user should care that:

> “I asked for the plane to turn faster, and now the plane turns faster.”

Everything else exists to make that result fast, reusable, explainable, and
durable.

---

# 🪄 See the whole Commons proof

Run:

```bash
make commons-demo
```

Z23 creates isolated nodes and proves the journey end to end.

```text
          NODE A
            │
            │ publishes useful C23
            ▼
          NODE B
            │
            │ discovers it
            │ fetches it
            │ verifies the source
            │ rebuilds it
            │ gets identical result
            ▼
      accepted software
            │
            │
       KILL NODE A
            │
            ▼
          NODE C
            │
            │ finds the surviving copy
            │ fetches it
            │ reproduces it
            ▼
       SOFTWARE LIVES
```

![make commons-demo — the whole loop, end to end](docs/assets/z23-term-commons-demo.svg)

The original publisher can disappear.

The original AI can disappear.

GitHub can disappear from the workflow.

The software remains identified by what it **is**, not by where it happened to
be hosted.

There is also a physical-host acceptance journey:

```bash
make commons-multihost-acceptance
```

![what the multihost proof measured](docs/assets/z23-term-commons-proof.svg)

That is the beginning of the C23 Commons.

---

# 🌐 Source without a central registry

Z23 can capture source into its own content-addressed source system:

```bash
z23 zcode workspace source capture \
  --input='{"workspace":"/src/project"}'
```

That produces an exact source identity.

A source bundle can be created:

```bash
z23 zcode workspace source bundle create \
  --input='{
    "workspace":"/src/project",
    "source_root":"<64hex>",
    "output":"/tmp/source.zvsb"
  }'
```

Verified:

```bash
z23 zcode workspace source bundle verify \
  --input='{
    "bundle":"/tmp/source.zvsb",
    "source_root":"<64hex>"
  }'
```

Reconstructed without Git:

```bash
z23 zcode workspace source bundle checkout \
  --input='{
    "bundle":"/tmp/source.zvsb",
    "source_root":"<64hex>",
    "workspace":"/tmp/zvcs",
    "destination":"/tmp/source"
  }'
```

Or fetched from peers by the root itself:

```bash
z23 zcode workspace source bundle fetch \
  --input='{
    "source_root":"<64hex>",
    "output":"/tmp/source.zvsb",
    "peers":"peer-a:18034,peer-b:18034"
  }'
```

The important part is what fetching **does not** mean.

```text
FETCHED
   ≠
ACCEPTED

SIGNED
   ≠
CORRECT

BUILT
   ≠
SAFE

AVAILABLE
   ≠
AUTHORIZED TO EXECUTE
```

Bytes arrive inert.

Every receiver verifies and decides locally.

---

# ⚡ Repeated work should become cheap

Two agents should not perform the same expensive action just because they are
different agents.

Z23 binds build and proof work to exact inputs such as:

```text
source
+ toolchain
+ flags
+ environment
+ build graph
+ requested proof
```

Conceptually:

```text
Machine A
   │
   │ executes exact Action X
   ▼
Receipt + output
   │
   │
Machine B asks for Action X
   │
   ▼
reconstruct exact identity
   │
   ├── DIFFERENT → do the work
   │
   └── IDENTICAL → verify and reuse
```

As the commons grows, the desired economics are:

```text
TOTAL WORK
   ≈
NEW WORK
```

not:

```text
TOTAL WORK
   ≈
EVERYTHING × EVERY AGENT
```

---

# 🤖 One API for humans and AI

The native API has a shallow command tree.

Examples include:

```text
z23
│
├── status
│
├── core
│   ├── chain
│   ├── sync
│   ├── consensus
│   ├── network
│   ├── wallet
│   └── storage
│
├── app
│
├── dev
│
├── ops
│
├── discover
│   ├── help
│   ├── search
│   ├── describe
│   └── schema
│
├── code
│   ├── guide
│   ├── have
│   ├── map
│   ├── room
│   ├── sym
│   ├── capsule
│   ├── change-plan
│   ├── impact
│   ├── tests
│   ├── territory
│   ├── corpus
│   └── ...
│
└── zcode
    ├── work
    ├── task
    ├── workspace
    ├── package
    └── ...
```

Do not memorize this tree.

Ask the binary:

```bash
z23 discover help
```

That is the point.

The same registry owns typed metadata such as:

```text
command identity
input schema
output schema
authority
side effects
risk
latency
cost
capabilities
availability
example invocation
```

An AI can load only the tiny branch needed for the current task.

That is radically different from handing a model hundreds of tool
descriptions on every turn.

---

# 🔌 The HTTP API describes itself too

Z23 is its own web server.

When the HTTPS surface is enabled, the same binary can serve the explorer and
REST API directly—no application server is required.

The API index is available at:

```text
GET /api/v1
```

Machine-readable OpenAPI:

```text
GET /api/v1/openapi
```

Public node/agent status:

```text
GET /api/v1/agent
```

Service catalog:

```text
GET /api/v1/service-catalog
```

Operations:

```text
GET /api/v1/service-operations
```

So a client or AI can discover:

```text
What services exist?
        ↓
What operations do they expose?
        ↓
Which are public reads?
        ↓
Which require operator authority?
        ↓
What schema does the operation accept?
        ↓
What native command corresponds to it?
```

The native command system and web API are not intended to become two
independent descriptions of reality.

They project the same C-owned contracts.

---

# ⛓️ And it is a real ZClassic full node

This is not only a developer tool.

Build and run:

```bash
make -j4 z23
build/bin/z23
```

Inspect it:

```bash
build/bin/z23 status
```

Ask about sync:

```bash
build/bin/z23 core sync diagnose
```

Inspect bounded logs through the native command registry:

```bash
build/bin/z23 ops logs --pattern='<regex>'
```

Inspect a block:

```bash
build/bin/z23 core chain block get --height=478544
```

Inspect networking:

```bash
build/bin/z23 core network status
```

Inspect the wallet:

```bash
build/bin/z23 core wallet status
```

The node validates the ZClassic proof-of-work chain, owns wallet custody behind
local keys, speaks the P2P protocol, exposes native and web APIs, and can serve
its explorer through its own HTTPS/onion surface.

No other node gets to tell your node what the valid chain is.

It verifies for itself.

---

# ⛏️ Why proof of work belongs here

The blockchain and the software commons solve different problems.

```text
C23 COMMONS
├── source
├── packages
├── builds
├── tests
├── evidence
└── reproduction

ZCLASSIC PoW
├── public ordering
├── durable history
├── payments
├── names
└── optional anchors
```

The blockchain is a terrible place to store a source tree.

It is useful when independent people need to agree:

```text
"This existed by here."

"This payment happened."

"This name changed hands."

"This root was anchored before that root."
```

But:

```text
ON CHAIN
   ≠
CORRECT SOFTWARE
```

A block cannot grant code permission to execute.

A miner cannot decide what software your computer accepts.

The node always keeps those authorities separate.

---

# 👤 Your machine is the sovereign self

Z23 is designed around a simple boundary:

```text
                 👤 YOU
        goals + final acceptance
                   │
                   ▼
              🖥️ YOUR NODE
        keys + policy + software
                   │
          ┌────────┴────────┐
          ▼                 ▼
     🌐 COMMONS         ⛓️ CHAIN
   shared knowledge     shared history
   shared evidence      ordering/payment
```

The commons can become extremely intelligent.

It does not become your ruler.

The chain can become extremely durable.

It does not become your software judge.

The AI can become extremely capable.

It does not own the result.

> **Shared intelligence without shared sovereignty.**

---

# 🎮 The game on the cover

Every good software box should show what the machine can do.

`zdogace` is a real-time 3D C23 dogfight over a neon grid city.

![the red ace turns, fires, and takes the match — a verified replay, 30 fps](docs/assets/z23-flyover-hero.gif)

Now imagine telling an AI:

> “Make the aircraft turn faster.”

The interesting problem is not whether an LLM can generate some C.

The interesting problem is whether the whole system can do this:

```text
understand request
       ↓
find flight behavior
       ↓
retrieve tiny relevant context
       ↓
reuse existing components
       ↓
change the smallest thing
       ↓
compile quickly
       ↓
show the consequence
       ↓
run affected proof
       ↓
keep exact version
       ↓
make improvement reusable
```

Then:

> “Add a blue engine trail.”

Then:

> “Make the enemies cooperate.”

Then:

> “Put a building there that I can enter.”

The shared software should get richer.

The amount of reinvention required for the next request should get smaller.

---

# 📈 The big bet

AI makes code cheap to create.

That creates a new problem:

```text
MORE AI
   ↓
MORE CODE
   ↓
MORE DUPLICATION
   ↓
MORE TECH DEBT
```

unless we build a better substrate.

Z23 is aiming for:

```text
MORE AI
   +
MORE C23
   +
MORE EVIDENCE
      ↓
BETTER SEARCH
      ↓
MORE REUSE
      ↓
LESS NEW CODE PER FEATURE
      ↓
LESS DUPLICATE BUILD/TEST WORK
      ↓
FASTER SOFTWARE CREATION
      ↓
BETTER COMMONS
```

Eventually a very large software commons should be easier for an AI to work
with than a normal medium-sized repository.

Because the agent should not read the commons.

It should ask the commons.

---

# 🧠 Where the intelligence is going

Today Z23 already has native source navigation, exact identities, contexts,
ontology objects, dependency relationships, evidence, retrieval benchmarking,
build actions, and receipts.

The next step is to make these pieces work together.

```text
LLM
 │
 │ proposes
 ▼
semantic retrieval
 │
 │ narrows
 ▼
code + dependency graph
 │
 │ structures
 ▼
ontology + contexts
 │
 │ explains
 ▼
exact C23
 │
 │ executes
 ▼
tests + observations
 │
 │ establish evidence
 ▼
reusable commons
```

The rule remains:

```text
VECTOR SIMILARITY
      =
LOOK HERE

not

THIS IS TRUE
```

and:

```text
LLM CONFIDENCE
      ≠
EVIDENCE
```

---

# 🖥️ Native C23 applications

You can also start with the smallest visible part of the project.

Build the reference GUI application:

```bash
make -f Makefile.gui zhello-selftest
make -f Makefile.gui zhello
```

Create your own:

```bash
make new-app NAME=myapp
make -f Makefile.gui myapp-selftest
make -f Makefile.gui myapp
```

On macOS:

```bash
make -f Makefile.gui myapp-app
```

The goal is deliberately simple:

```text
EDIT C23
   ↓
SEE NATIVE RESULT
```

For macOS:

[`docs/MACOS_GUI_QUICKSTART.md`](docs/MACOS_GUI_QUICKSTART.md)

For Windows:

[`docs/WINDOWS.md`](docs/WINDOWS.md)

---

# 🛡️ Pre-v1 means what it says

Z23 is under active development.

Do not infer completion from a large feature list.

The actual full-node product bar is:

> **someone we do not know can run Z23 and use it for a week without
> intervention.**

Ask the project:

```bash
make mvp
```

Run the local acceptance aggregate:

```bash
make mvp-verify
```

Anything unavailable should be named as unavailable or blocked—not silently
turned into green.

See:

[`docs/MVP.md`](docs/MVP.md)

Current live operator state belongs in:

[`docs/HANDOFF.md`](docs/HANDOFF.md)

---

# Principles

### Verify, don't trust.

Every receiver checks what it accepts.

### Reuse before create.

Do not generate another implementation until you know you need one.

### See the real consequence.

The user cares about behavior, not internal machinery.

### Exact identity beats names.

Names are labels. Content roots identify exact things.

### Missing evidence is not a pass.

`UNKNOWN` and `INCOMPLETE` are useful answers.

### Signatures prove authorship, not correctness.

### Proof of work proves accumulated public work, not software correctness.

### Fetching code never grants permission to execute it.

### No privileged coordinator.

Peers, AI workers, schedulers, registries, and signers are replaceable.

### Consensus and wallet custody always win resource conflicts.

Software indexing and AI work must not impair the full node.

### C23 source first.

Keep useful software small, native, inspectable, portable, and reusable.

### Free reuse first.

Copyable source should remain cheap to copy. Scarce compute, storage,
verification, hosting, and human work can be paid for separately.

---

# Where to go next

| I want to...                             | Start here                                                             |
| ---------------------------------------- | ---------------------------------------------------------------------- |
| **See what Z23 can do**                  | `z23 discover help`                                                    |
| **Ask whether code already exists**      | `z23 code have <concept>`                                              |
| **Understand one symbol**                | `z23 code capsule <symbol>`                                            |
| **Plan a change**                        | `z23 code change-plan <symbol>`                                        |
| **See blast radius**                     | `z23 code impact <path>`                                               |
| **Find the required tests**              | `z23 code tests <path>`                                                |
| **Inspect corpus health**                | `z23 code corpus`                                                      |
| **Start the software Commons journey**   | `z23 zcode guide`                                                      |
| **Prove the whole local Commons loop**   | `make commons-demo`                                                    |
| **Build the full node**                  | [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md)                   |
| **Develop on macOS**                     | [`docs/MACOS_GUI_QUICKSTART.md`](docs/MACOS_GUI_QUICKSTART.md)         |
| **Develop on Windows**                   | [`docs/WINDOWS.md`](docs/WINDOWS.md)                                   |
| **Use the package commons**              | [`docs/C23_COMMONS_QUICKSTART.md`](docs/C23_COMMONS_QUICKSTART.md)     |
| **Give an AI agent work**                | [`AGENTS.md`](AGENTS.md)                                               |
| **Understand the API**                   | [`docs/NATIVE_COMMAND_INTERFACE.md`](docs/NATIVE_COMMAND_INTERFACE.md) |
| **See every generated command contract** | [`docs/API_REFERENCE.md`](docs/API_REFERENCE.md)                       |
| **See current development priority**     | [`docs/work/FORWARD_PLAN.md`](docs/work/FORWARD_PLAN.md)               |
| **See the pre-v1 acceptance bar**        | [`docs/MVP.md`](docs/MVP.md)                                           |

---

# Z23

```text
ASK
 ↓
UNDERSTAND
 ↓
REUSE
 ↓
CREATE
 ↓
SEE
 ↓
VERIFY
 ↓
KEEP
 ↓
SHARE
 ↓
MAKE THE NEXT THING EASIER
```

**Software made for you, not imposed on you.**

Z23 is Apache-2.0.

**ZClassic + C23.**
