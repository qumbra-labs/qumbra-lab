# Intake fixtures — real wallet artifacts from rehearsal box runs

Real files a wallet wrote, not synthesised, so the intake's verify-on-arrival
is a CI gate that verifies a real proof without proving anything (an L2 prove
is 3–30 GiB and never runs on the lane).

| fixture | what it is |
|---|---|
| `w3c-deposit.claim` | The claim file `qumbra-wallet deposit claim` wrote in the W3c box run (lab #831, 2026-10-03, r7g.2xlarge). 327,202 B, SHA-256 `03ab5f8931734b1806eef058dda24b6adb5f93dc748483041229b6747500879a`. |

## The chain it belongs to

The V6 **rehearsal** genesis `4f725b2932b06154cdc069016ccf4435bbeaea89ddcfaccdc70ed6c6d367bfd4`
(the F5-6 rehearsal datadir the W3c run resumed from), L2 `1`, claim fee tier `4`.
The tests pin these as literals (`intake::tests::w3c_chain`) and pin the file by its
size and SHA-256 (`the_fixture_is_the_pinned_w3c_claim`) — a swapped file fails
there, it cannot re-pin itself.

## What it carries, by design

A claim file holds the deposit-sum opening `(v, r_v)` — the deposit amount and its
commitment blind — because the sequencer needs it. This one opens a **rehearsal
wallet's 0.5 QMB deposit on a rehearsal chain under rehearsal keys: nobody's money**.
That is the only reason it may sit in a public repository.

## The rule

**No claim or exit file from a non-rehearsal chain is ever committed** — here or
anywhere in this repository. A real chain's claim file reveals a real person's
deposit amount to everyone who can read the repo.

An exit fixture follows once one is minted on the box during S3's measurement run
(lab #847); until then the exit path is tested for its codec refusals only, and the
S6 box rehearsal is its first real proof check.
