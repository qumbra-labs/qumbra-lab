# lab #490: v5 work-value predicate — trailing-8-LE, keyed off the form (the xmrig-congruence fix)

Repo: `qumbra-lab`, branch `claude/i490-v5-pow-predicate`, **open a PR — NEVER merge**. Read `CLAUDE.md` (CI-lane acceptance, `verify-graviton` label; 🔴 never run the full workspace suite locally). Read lab #490 IN FULL — the finding, the source-verified xmrig quote, and the coordinator ruling are all there; this baton implements the ruling, it does not re-litigate it.

## The change

1. `qlab_devnet::pow`: the work value becomes form-keyed. V4: `u64::from_be_bytes(hash[0..8])` — **byte-identical to today, test-locked against today's exact behavior**. V5: `u64::from_le_bytes(hash[24..32])` (Monero-congruent). Shape suggestion (yours to refine): `hash_to_work_value_for(hash, form)` + `satisfies_target_for(hash, difficulty, form)`; the existing un-keyed fns stay as the v4 aliases so no call site silently changes meaning.
2. Every call site keys off `ChainRules.form` exactly like the other v5 rules (the stage-4a plumbing pattern, PR #472): validation, `mine.rs`, template checks. Sweep for every consumer of `satisfies_target`/`hash_to_work_value` — a missed site is a consensus fork between miner and validator.
3. Post-halt `pow_value()` revision-digest mixing composes unchanged (it post-processes outside the hashed bytes — assert this understanding in a test, don't just cite it).
4. Comparison strictness: consensus keeps `<=` on both forms (changing v4's would be a rule change nobody ordered; v5's `<=` vs xmrig's `<` only matters at the pool's share filter, which is stage-1 pool code, not consensus — state this in the PR body so nobody "fixes" it later).

## Tests

- v4 predicate: golden vector asserting today's exact accept/reject boundary (u64::MAX/d edge included) — the compat lock.
- v5 predicate: vector locked from an xmrig-congruent fixture (hand-built hash where tail-LE passes and head-BE fails, and the converse) — the property that IS the fix.
- Form-divergence test: one hash, one difficulty, the two forms disagree — proving the keying reaches the predicate.
- Miner/validator agreement on v5: a mined-accepted block validates under the same form (mine.rs path).

## Boundaries

- No header/genesis/golden bytes move (T2 genesis `0e55ccb316ea…` asserted unchanged — cite the existing pin test in the PR body). No LWMA change. No pool code (stage 1 consumes this).
- If any call site cannot see `ChainRules.form` without a signature change beyond additive plumbing — STOP and report the shape on #490 first.

## Acceptance

- CI `verify-graviton`, arithmetic reconciled out loud (baseline 1,918 + your new tests).
- PR body: call-site sweep table (every consumer, keyed or exempt-with-reason), the four test vectors, honest remainder.
