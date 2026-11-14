<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Installed app journey qualification

This guide records how to qualify an installed app journey end to end. It is
not a replacement for [development instructions](DEVELOPING.md) or the
repository's [agent instructions](../../AGENTS.md). Use their current host
admission, ownership, review, and native landing workflow. Preserve other
writers' work and do not push around receipt-gated landing.

## Scope and preparation

Qualify the exact source and installed release under review. Record the commit,
tree, installer and manifest hashes, runtime hash, platform, and test results.
A previously qualified local payload does not prove the public endpoint serves
those bytes: verify the HTTPS installer and manifest separately before claiming
public availability. Pins identify an individual release; they are not policy
constants and should be reverified for each qualification.

The 2026-11-14 Linux x86_64 qualification used two fresh HOME/XDG profiles, a
local graphical desktop, and host C compiler and build tools. Editing used an existing
local-MCP assistant. The friend needed the app installation, but no assistant,
account, or node service. This is not an all-platform or human usability study.
Use isolated fixtures, admitted jobs, and a bounded lifetime; do not start or
alter canonical nodes, services, wallets, or profiles.

For installed-source fixtures, choose an owner-private temporary root whose
ancestors meet the resolver's ownership and permissions checks. In the recorded
run, a world-writable temporary directory and a checkout with group-writable
ancestors both caused the installed-source check to refuse the copy. Set the
existing `ZCL_TEST_TMPROOT` to a suitable private root for the canonical fixture;
retain failed logs and do not weaken the resolver to make the test pass.
<!-- claim: symbol-present isr_directory tools/command/app_installed_source_resolve.c # installed-source ancestor trust -->
<!-- claim: symbol-present ZCL_TEST_TMPROOT tests/harness/include/test/test_core.h # private fixture root override -->
See `tools/command/app_installed_source_resolve.c` and
`tests/harness/src/test_app_seed_skycombat.c` at the source being qualified.

## Qualify build prerequisites

Sky Combat carries its Linux X11/GL compile-time headers in the source copy and
loads the window-system libraries at runtime. Do not tell recipients to install
X11/GL development packages for this app. A compiler and make are still needed;
a working graphical session and runtime libraries are separate launch inputs.
<!-- claim: symbol-present SKYCOMBAT_X11_INPUTS apps/skycombat/skycombat.mk # vendored window-system header closure -->
<!-- claim: symbol-present RGFW_USE_XDL apps/skycombat/skycombat.mk # runtime window-system loading -->

To qualify this boundary, hide the host X11/GL include directories inside an
isolated mount namespace, keep the received source read-only, and build into a
fresh output directory under host admission. Record mount evidence, compiler
identity, dependency files and the output hash. Check that no system X11/GL
header appears in the dependency files, then verify the host directories remain
unchanged after exit. This proves that build prerequisite boundary; it does not
qualify a bundled compiler kit, every app, or GUI launch without runtime libraries.

## Run the journey

1. Install the verified release into a fresh sender profile. Open the installed
   app and record the original visible state. In My Apps, use **Change with your
   AI** and copy its setup. If a draft is waiting, choose **Change**, then
   **Change with your AI**. Confirm the copied command and arguments refer to the
   installed runtime and this profile.
2. Use the assistant's actual MCP requests to adopt the app. Review native
   consent, build and preview, then explicitly Keep. Read the source through
   MCP; plan and confirm a small visible edit using the returned revision,
   source version, head and blob identities. Save the requests and responses.
3. In My Apps select the kept copy, choose **Change**, then
   **Review unkept changes**. Verify the displayed edited version, build and
   preview it, and explicitly Keep. Save the Keep and selection receipts.
4. Share that kept version as a signed `.z23share` file. Save the share receipt
   and file digest. Stop the sender before the recipient receives it.
5. Install the same verified release in a fresh recipient profile. Open the
   file through the generated desktop association. Review native Receive
   consent, build and preview, and explicitly Keep. Record the receipt and the
   running image's executable hash; check that the rendered change is visible.
6. After both sessions stop, reopen the recipient's kept copy in a private
   network namespace and graphical session. Record parent, session, and image
   namespace identities and route evidence, the `app.open` receipt, executable
   hash, bounded cleanup, and process exit. A stopped sender alone does not prove
   the recipient had no network access.

Compare sender and recipient release, package and publisher identities, the
confirmed MCP content bytes against recipient source, and the independently
hashed image against both Keep receipts. Import can assign a different local
version ID: compare each Keep with its own selection and compare shared content
and image across profiles. A screenshot supports the receipts and hashes; it
is not a substitute for them. Do not claim the original working directory was
modified unless separately demonstrated.

<!-- claim: symbol-present al_change_choice tools/command/native_app_library_command.c # saved draft uses Change; no draft uses Change with your AI -->

## Qualify catalog transport separately

Keep the same network identity throughout copy, save, sign, publish and fetch.
Do not import a default-network signed release into a regtest store or alter
its chain metadata to make it fit. For a regtest transport fixture, create a
fresh copy from the verified installed source with the active regtest network,
then apply the intended edit and compare the rebuilt source and image. Installed
seeding obtains the active chain identity. Reapplying a previously confirmed
edit qualifies transport; it does not prove another AI or GUI interaction.
<!-- claim: symbol-present vcs_package_accept_chain_id tools/command/native_app_seed_command.c # installed seeding uses the active chain -->

Prepare the personal signed copy before handing the store to a hosting node.
Record the publication's actual package root, publisher fingerprint and offer
ID; a new personal namespace can change the package root. Fetch with those
identities pinned, then compare source bytes and the running executable. A Tor
handshake alone does not prove package transfer, reproduction or execution.
<!-- claim: symbol-present app.get engine/composition/commands/apps.def # exact offer inputs for catalog fetch -->

Use bounded fixture nodes and display sessions under current host admission.
If the scheduler serializes a project's jobs, run the node and fetch within
one admitted test job; do not leave the fetch waiting for a slot held by its
own node or bypass admission. Verify fixture process cleanup after exit.
After stopping the publisher, check the recipient's running image and hosting
status. A fresh third-party fetch from that recipient is a separate check.
Distinguish two host environments from independent physical hardware, and
record network evidence before claiming strict peer or offline isolation.

## Evidence and failure disposition

Keep a compact result index alongside the immutable or retained artifacts:
source/release identity and checksums; installed desktop association; MCP edit
input and confirmation result; sender share and Keep receipts; recipient Receive
and Keep receipts; exact source comparison; running image hash and process
identity; screenshots; offline namespace and route evidence; and cleanup logs.
Record source and scope for each independent review and test receipt. Preserve
unique failed logs, including source-selection or display failures, instead of
relabeling them as passes. Do not put private host paths, keys, or profile data
in public documentation.

If a receipt, identity, process hash, preview, explicit Keep, or cleanup check
fails, stop and report which step is unproven. A local signed-file pass does not
prove Tor-link reliability, online deployment, another platform, or public
artifact availability. Re-run only checks affected by a change, failure, or
unresolved finding, and land source or documentation through the existing
native workflow after non-author review and applicable gates.
