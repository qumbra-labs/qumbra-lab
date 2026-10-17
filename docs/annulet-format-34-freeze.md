# Annulet format 34: the freeze record

*Chinese translation: [`annulet-format-34-freeze-zh.md`](annulet-format-34-freeze-zh.md). EN is authoritative.*

Lab #937, PR F. Format 34 is the Candidate A Annulet in which the prover is paid inside the transaction: S and P spends carry three outputs, and the third pays the prover its fee in asset 0. It was built by:

| PR | Content |
|---|---|
| lab PR #939 | AIR v3 |
| lab PR #940 | Consensus |
| lab PR #941 | Witness, bundle and planner |
| lab PR #943 | A′: the third output charged to the fee bank |
| lab PR #944 | Kernel |
| lab PR #946 | Service |
| lab PR #947 | Importer |

This record states what is frozen, where each value is pinned, and how each pin was produced.

The design-side account is in the design repository's L2 roadmap notes: the residual, and D4 and D5 as built.

## What "frozen" means

Every item in the table below is relied on by something already built: a format-34 node, wallet kernel, prover service or genesis. **A change to any of them is a new format version, with its own genesis. It is never an edit to 34.**

Each value is held in two places:
1. its production constant;
2. the literal in `format_34_is_frozen` (`crates/qlab-bench/src/freeze34.rs`).

A change has to edit both by hand, and the test names the item that moved. The test lives in `qlab-bench` because that crate already depends on every crate that owns one of the values, so it adds no dependency edge.

## What is frozen

The base is lab main `5a719644`. Lane run 38589728298 passed every pin below, with result 201/3671/0/17.

| Identity | Value | Pinned at | Produced by |
|---|---|---|---|
| Genesis format version | 34 ↔ `(Annulet, CandidateAV3)` | `qlab-devnet/src/forms.rs` (`ANNULET_AUTH_V3_GENESIS_FORMAT_VERSION`, `annulet_forms_of_genesis_format_version`) | lab PR #940 |
| S/P outputs | 3 (R stays 2) | `qlab-devnet/src/forms.rs` (`L2AuthForm::sp_outputs`) | lab PR #940 |
| Body and genesis-body domains | the v3 domains | `qlab-devnet/src/annulet.rs` (`BODY_PREIMAGE_DOMAIN_ANNULET_V3`, `GENESIS_BODY_DOMAIN_ANNULET_V3`); test `format_34_is_frozen` | lab PR #940 |
| Served wire form | byte 6 | `qlab-p2p/src/served.rs` (`wire_form_byte`), `qlab-p2p/src/compact.rs` (`WireForm::ANNULET_AUTH_V3`) | lab PR #940 |
| Proving-bundle version (three outputs) | 2 | `qlab-l2spend/src/bundle.rs` (`BUNDLE_VERSION_THREE_OUTPUTS`) | lab PR #941 |
| S v3 shape digest | `2b65c9d45b626dcbfc02bb49ae9574d5724d87a577a759b0a297ab1e0da015b8` | `qlab-l2/src/v3.rs` (`SHAPE_S_DIGEST_V3`); recomputed by `l2_v3_shape_digests_are_pinned` | `l2_goldens` at `3d987c9e` (A′, lab PR #943) |
| P v3 shape digest | `925d542ef83f4f2910394c21c30842bd64f5c17c32fba628fa6f16434b469b34` | `qlab-l2/src/v3.rs` (`SHAPE_P_DIGEST_V3`) | same |
| v3 constants and constraints digests, and the constraint counts | `v3::PINS_V3` | `qlab-l2/src/v3.rs`; test `l2_v3_shape_digests_are_pinned` | same |
| devnet_v3 genesis | `7673e01f2902344b902e40ad498e3bf4368e355dffa277669c947fbda700f65e`, 5,241 B | `qumbra-node/src/annulet_genesis.rs` (`DEVNET_V3_GENESIS_HASH`) | `qumbra-node genesis annulet-devnet --v3`, run twice at `d8ff3606`; re-checked at `5a719644` (below) |
| devnet_v3 rehearsal genesis | `439de6fca8be1efb78996c0a0906e33ae43d854f50d5e299d0dfe6049b541fb5`, 5,251 B | same (`DEVNET_V3_REHEARSAL_GENESIS_HASH`) | `--v3 --rehearsal`, same runs |
| detaudit v3 arms | `s3v3` and `p3v3`, each over the `house`, `exact` and `fee-bank` fixtures | `qlab-bench/src/detaudit.rs` | lab PR #939 and lab PR #943 |

**Unchanged by format 34, and re-checked at 5a719644:**
- The v2 devnet `2bd53cd1…` and its rehearsal `e21a7b08…`.
- The v1 devnet `00c70e55…`.
- The fixture `85dd805d…`.

**Nothing in `.github/` names a format-34 value.** The frozen digest and the rule domains there belong to L1, and so do the T1 and T2 genesis hashes.

## The genesis re-check at 5a719644

The genesis constructions were run twice each, each time in a fresh process, with `qumbra-node genesis annulet-devnet [--v2 | --v3] [--rehearsal]`. Both runs of every construction were byte-identical, and each equals its pin:

| Construction | Genesis hash | File sha256 | Size |
|---|---|---|---|
| v1 devnet | `00c70e55c95e8f6519e956884bf6ffc56476fe1b3cd196983a46e1f4221d7e03` | `85af2662e244b6e61f3dfc231b7b7e361eee9a82f290b56da26268c2f7f13be3` | 5,238 B |
| v2 devnet | `2bd53cd149cd5e8b43917b468c82249dd41c1602814b1f24ef39e61cafb3d13a` | `9a276e7debf5a7bda7d375c02d987ec594a53f7d2267db972b04e053c9fe2139` | 5,241 B |
| v2 rehearsal | `e21a7b089927dbede8171744675830bd60f8f3b854617421a9fcf8e4728fee97` | `cd49f691ba811de4d2c81fb5369800d0c2d28b1604c633b7147b7780d2b61e1e` | 5,251 B |
| v3 devnet | `7673e01f2902344b902e40ad498e3bf4368e355dffa277669c947fbda700f65e` | `2ada7f470727454dc9b03d243e8e0d696e0360a3672bb43fe3a1fe434c709d33` | 5,241 B |
| v3 rehearsal | `439de6fca8be1efb78996c0a0906e33ae43d854f50d5e299d0dfe6049b541fb5` | `0f9a32dac72e8205916aec09daa50bfa21da1845c48ffdb52571348b407b6b77` | 5,251 B |

The v1 devnet has no rehearsal construction. The fixture genesis (`85dd805d…`) is built only in tests, and its pin test is on the same lane.

## The AIR's measurements

The o3f box re-measure on prover-1 (r7g.2xlarge, 64 GiB, Ubuntu 24.04 arm64, rustc 1.99.0), at lab main `5a719644`, host idle, 2026-10-15 06:18–07:23 UTC. Script `run-o3f-box.sh`; tarball sha256 `1ab0b639a822c3be621fa8eebdf758d013b967247baff77891fdba3ffc0527bc`. All eight runs exited 0.

**Proving** (`l2shape`, b4/q45 lane, log height 20; peak RSS and wall time from `/usr/bin/time -v` on the process, prove time the bench's best of three):

| Shape | Instance | Width | Peak RSS (kB) | Wall | Prove (ms) | Verify (ms) | Proof (KB) |
|---|---|---|---|---|---|---|---|
| P | fee bank (o3f = 1), run 1 | 871 | 33,701,756 | 2:55.87 | 55,774 | 12.2 | 470.5 |
| P | fee bank (o3f = 1), run 2 | 871 | 33,701,756 | 2:58.08 | 56,852 | 12.0 | 470.2 |
| P | exact (o3f = 0) | 871 | 33,701,796 | 2:57.28 | 55,603 | 12.1 | 470.3 |
| S | fee bank (o3f = 1), run 1 | 788 | 30,981,600 | 2:42.40 | 51,552 | 11.5 | 449.3 |
| S | fee bank (o3f = 1), run 2 | 788 | 30,981,388 | 2:41.44 | 51,413 | 11.7 | 449.5 |
| S | exact (o3f = 0) | 788 | 30,981,400 | 2:41.11 | 51,190 | 11.8 | 449.3 |

The fee bank costs nothing measurable over exact on the same AIR: peak RSS within 0.001 %, wall time within 1.5 %. Against lab PR #939's pre-o3f box on the same instance type (2026-10-08, widths 780/863), o3f adds 0.8 % peak memory to S and to P, and no prove time.

**The determination census** (fee-bank fixture; aggregate only):

| AIR | Cells | Determined | Public values undetermined | Wall | Peak RSS (kB) |
|---|---|---|---|---|---|
| s3v3 | 826,277,888 | 728,755,477 | **0** | 32:06 | 23,476,344 |
| p3v3 (`--no-pv-inputs --cr-premise`) | 913,309,696 | 832,201,994 | 55, **all the `q = 1` accounting freedom** (below) | 45:55 | 27,539,712 |

**The p3v3 verdict.** The fee-bank fixture spends two inputs of the same asset (`q = 1`). Every public value its census leaves undetermined, the output commitments included, belongs to the accounting freedom that the i758 census found on the P3 merge (`docs/i758-determination-census.md`, P3): which balance row each output is charged to. It is closed the way i758 closed it, by follow-up runs on the same host, sha and premises (2026-10-15; tarball sha256 `2d9de314497e70d8e5ccddb2a9b11fcfdd438c727b51be840560e03cb16fe770` and `bdce8f9528b9a79dcaea9ae9c0fcee4943773eb5fcfd194a0310809972e462bb`):
- With the output-row selectors `o1a`/`o2a`/`o3a` declared sources (`--pin-sel2`, i758's diagnostic premise), 3 public values stay undetermined: the same 3 as i758's P3 merge under that premise. The output commitments are determined.
- Unpinned, the flip of `o1a` and the flip of `o2a` each confirm **SAT with no public value moved**, and the independent p3 check on the full repaired trace is SAT for both (1:14:46 and 1:13:32, peak 30,594,636 kB).
- `o3a` is not free here: the AIR forces `o3f · o3a = 0`, and the fee-bank fixture has `o3f = 1`.
- An earlier confirm aimed at the output commitments directly picked a dummy-role witness root and was UNSAT with the other roots held. That is not a refutation, so it is not counted.

The same follows from the constraints. The selectors only move how an amount splits between the two balance rows. Summed, rows 1 and 2 advance by `(AG_IN1 + AG_IN2 − AG_O1 − AG_O2 − AG_O3 + SF3) · pw · v`, so `SG₀`, `SG₁` and `SG₃` cancel. Under `q` the close reads only the summed chain. This is i758's `o1a` argument, extended by output 3's terms.

## Not frozen here

- **The production genesis and the prover pin.** The format-34 production genesis is minted at the cut-over, and the runbook adds its prover pin (`qumbra-wallet/src/prover_pins.rs`, `PINS`, empty until then) and releases the kernel. Done for **annulet-testnet-3**: genesis `024ed17b…8b70`, its payee, and a maximum of S 2 / P 4 (test `the_production_pin_is_annulet_testnet_3s`).
- **The price.** It is deploy configuration, at or below the pinned maximum.
- **The token retirement** (#937 D6). It happens after the cut-over.
- **The cut-over rehearsal.** It runs on prover-1 with the real ingress (Caddy adds `X-Qumbra-Client-IP`), driven by the kernel client: first against `devnet_v3_rehearsal`, then against the production genesis. It also yields the service path's S and P figures.
- **A CLI remote-prove client.** There is none: `qumbra-wallet` has no `--prover`. If one is wanted, it gets its own small PR.

The prover service's protocol version (`ANNULET_PROTOCOL_VERSION = 1`) does not move. A 33 and a 34 service already differ by the `genesis_hash` in `/v2/annulet/info`, and a two-output bundle on 34 is refused by name.

## See also

- [`prover-service-annulet.md`](prover-service-annulet.md): the service on format 34.
- [`prover-payee-wallet.md`](prover-payee-wallet.md): importing the paid ledger.
