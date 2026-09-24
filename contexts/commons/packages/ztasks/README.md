# ztasks

Reusable bounded C23 task state, extracted from the native task-app reference.
The same code is consumed by its resident workers and host. It validates task
titles and IDs, preserves revisions and write IDs, and encodes a canonical
schema for persistence and process-generation handoff. Failed decoding leaves
the previous value intact. No database, process, network or wallet authority
belongs to this package.

The package test proves byte-identical reload and refuses empty titles,
duplicate IDs, unknown schema and noncanonical state without losing edits.
The host supplies add/edit/complete/delete, undo, presentation and durable writes.

## Local task editor

Choose a private directory for your task data, then open a new task or the task
list with the native host:

```sh
task_datadir="$HOME/Tasks"
z23 app tasks new "$task_datadir"
z23 app tasks open "$task_datadir"
```

`open` shows the task list; `task_id` opens one saved task directly. The list
offers New task, Edit, Complete/Reopen, and More with Delete and durable Undo.
Arrows, Home/End and Page Up/Down move the selection and scroll it into view.
Tab/Shift-Tab move between the list and action buttons; Enter edits the selected
task, Space toggles completion, Delete removes it, and Cmd/Ctrl+Z undoes the last
durable change. Cmd/Ctrl+N opens a new task. Selected rows have a visible focus
border. The list displays eight rows at a time and retains selection while a
save completes.

Save keeps the editor open; Back to tasks saves the latest valid draft before
returning to the list. Closing the editor window saves before exiting the app.
Saving runs on an owned worker. Saving, Saved and Save failed describe the durable
save state; a failed save retains the draft. Tab and Shift-Tab move focus between
the title and actions. Titles currently use up to 95 Basic Latin characters and
the reused state codec bounds a document to 32 tasks.

Headless `app tasks` actions are `list`, `add`, `edit`, `complete`, `reopen`,
`delete` and `undo`. Changes require `expected_revision` from the last read;
stale edits refuse. Undo survives restarting the host. These operations remain
available for automation and headless use.

`tests/harness/src/test_task_document.c` exercises persistence, failed commits,
busy storage, newer typing during a save, native form/list pixels, keyboard focus,
list navigation during a save, deletion/undo, restart and conflicting writers.
Real macOS desktop interaction remains OPEN pending desktop access. The update
journey below adds confined execution and checked program selection. Package
reproduction alone does not establish GUI interaction or grant permission to
install or execute an application.

### Program changes and user data

The host stores task data independently of the current and previous program
identities. Returning to a previous program must preserve the current document,
including its durable undo history. It must never restore the data that existed
when that program was last used.

For host integration, `task_document_capture` observes the app name, canonical
current state and undo state. After a confined candidate has demonstrated that
it understands those exact bytes, use the checked resident activation or
rollback API with a trusted host guard. The guard binds the candidate's complete
identity and calls `task_document_check_current` inside the resident switch's
write transaction. An intervening edit refuses the switch and asks for a fresh
preview. The transaction contains no candidate execution or worker wait, so
slow preview work happens before it and does not hold the data lock.

These APIs supply atomic admission, not compatibility or execution permission.
A schema number, a checkpoint, or a matching digest does not prove a candidate
understands the data. The task update owner below supplies the bounded preview
and canonical round-trip checks. The existing unguarded resident APIs remain
for stateless consumers; data-bearing apps must use the checked path. Real Mac
desktop acceptance remains open.

## Try, Keep, and Go back

The native task list's **More / Undo → Updates** page owns the complete update
journey. An AI or local operator selects an exact installed package root,
receipt, and program through `app.tasks`'s `preview_root`, `preview_receipt`,
and `preview_program` inputs. Merely opening that page does not run the
candidate: **Try update → Allow preview** grants execution for that action.

The existing package verifier runs the candidate in a separate, confined
process with copies of the current canonical tasks and durable undo. It has
no filesystem grant for the working app's database, no network, and no child
creation. The task list and editor continue to run while the preview works.
**Keep** changes the accepted program only after a transaction checks that
both tasks and undo still match the preview's observation. A newer edit
refuses the stale preview and asks for a fresh one. Preview output never
replaces live data.

**Go back** runs the previous exact program against copies of *current* tasks
and undo, then checks the same observation before switching. It does not
restore an old data snapshot. Missing artifacts, incompatible codecs, failed
execution, and intervening edits leave the working program and data intact.
A completed Keep survives closing and reopening; reopening renders current
data with the previously accepted program.

The preview ABI is a bounded values-to-view computation. The verifier owns
process supervision and isolation; the resident record owns exact program
selection; the task adapter owns canonical data compatibility; and the native
host owns input, durable saves, and undo. Downloaded function pointers never
enter the GUI process. These lifecycle pieces can be reused by other apps.
ABI v1 accepts presentation changes that round-trip the existing canonical
state exactly. Data migrations require a separate compatibility contract and
are refused here.

### Qualification replay

The package manifest is [`zcode-package.json`](./zcode-package.json). From a
clean checkout of the exact source commit being qualified, replay the real
application journey through the registered test group:

```sh
git rev-parse HEAD
git hash-object contexts/commons/packages/ztasks/zcode-package.json
devbuild --wait make -j"$(getconf _NPROCESSORS_ONLN)" t-fast-exact \
  ONLY=test_resident_launch_contract T_FAST_EXACT_ARGS=--no-cache
```

The group edits the C23 application into distinct package roots, installs the
resulting programs, and runs their actual preview entry points through the
separate package verifier while the previously accepted version stays usable.
Its output names each root, receipt, artifact digest, edit-to-visible-preview
time, and the p50/p95 of 20 samples. It also checks that a compile-valid wrong
task row, a crashing program, and an incompatible preview interface leave the
accepted program, tasks, and undo unchanged. The preview child probes an
inherited descriptor and environment secret; seeing either fails the run.

This replay needs a host with qualified full package isolation. Linux uses
Landlock and seccomp; macOS uses native Seatbelt for the separate verifier.
Windows refuses preview execution. A headless pass does not establish real
macOS desktop interaction or grant publication, acceptance, or deployment.

Headless acceptance uses real installed package variants and the same update
owner and native actions. **Real Mac desktop interaction remains OPEN** until
an authorized desktop session is available.
