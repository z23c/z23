# Code Fearlessly

Fear is a fact about the environment, not about the coder.

An engineer who hesitates before a change is usually reading the environment
correctly: the change is hard to undo, or nothing will catch the mistake, or
the thing that claims to catch it cannot be trusted. Hesitation is a rational
response to missing rails. It is not a character flaw to be exhorted away.

So the instruction "code fearlessly" is not addressed to the coder. It is
addressed to whoever builds the environment. Build the rails, and fearlessness
follows for free. Skip them, and no amount of courage substitutes.

## Where the phrase comes from

Rhett Creighton coined it, published 2010-12-02 and reprinted in
*Hacker Monthly* issue 9 (2011). John Carmack later used the same phrase in his
note on parallel implementations — "code fearlessly on the copy, while the
original remains fully functional and unmolested" — which is the principle
applied to one specific rail: work on a copy, and the blast radius is zero.

Source: <https://news.ycombinator.com/item?id=1964060>

## The agent's version of it

An agent working in this repository is expected to act, not to ask. When the
gates are green, the change is proven, and a revert path exists, the
deliberation has already been done by the machinery — asking a human at that
point is pure friction and adds no safety.

But this cuts both ways, and the second half is the half that gets forgotten:

**An agent that has to think about safety is a design bug.** If an agent must
hold a rule in its head to avoid breaking something, the rule belongs in a gate
instead. Every "remember to..." in a document is an admission that a rail is
missing.

**So build the rails as part of the work.** An agent here does not merely
consume its environment; it is expected to improve it. Finding a defect and
fixing it is half the job. The other half is asking why nothing caught it, and
making something catch it next time.

## What an environment must supply to earn fearless coding

- **A revert path that is real.** Not "we could roll back in principle" — an
  actual, exercised path back to the previous state.
- **Isolation for experiments.** A copy, a worktree, a scratch datadir. Nothing
  a newcomer tries should be able to damage anything that matters.
- **Gates that fail closed.** An unmapped file, an unverified claim, or an
  unreplayed artifact must block rather than pass quietly. Fail-open is
  indistinguishable from having no gate at all, right up until it matters.
- **Determinism where determinism is possible.** A probabilistic failure that
  can be made deterministic should be. A build that could be reproducible
  should be — a result you can reproduce is a result you can act on alone,
  without asking anyone to vouch for it.
- **Verifiability over vouching.** Prefer a property anyone can check
  independently to a claim someone must be trusted for. This is the same
  principle that makes the network decentralized, applied to the workshop.

## What quietly destroys it

These are the failure modes that matter, because each one leaves the rail
*visible* while removing its protection. An engineer who trusts a rail that is
not there is worse off than one who knows there is no rail.

- **A gate that can pass without testing anything.** If a change maps to no
  test group and the gate still reports success, the gate is measuring its own
  existence. Read what actually ran, not the verdict.
- **A verdict that rests on a single clean run.** Some defects are
  probabilistic by nature — a stale-stack bug reads clean on a fresh stack and
  fires only later. "Did not reproduce" is an observation, never an
  exoneration, unless you also ran the thing that makes it deterministic.
- **A pinned checkout that nothing refreshes.** A judge running old code emits
  confident verdicts that can never be right, and does it silently.
- **A claim that was true when written.** Verified-once decays into
  verified-never. Evidence should carry its measurement and its expiry, and
  staleness should be a gate failure rather than a discovery.
- **A label applied without looking.** Classifying an artifact by its filename
  rather than by running it produces a tidy ledger describing nothing.

## The rule

Fearless *because of* the rails, never instead of them. The rails themselves —
the seals, the gates, the revert paths, the isolation — are the one thing not
to be brave with.
