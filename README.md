# qumbra-lab

Prototype lab for **Qumbra** — the post-quantum privacy-chain design exercise. Canonical spec: [`lai3d/qumbra-design`](https://github.com/lai3d/qumbra-design) (22 paired design docs + six EN-only appendices + ROADMAP). This repo answers the design thread's prototype-gated questions with measured code. Not a chain implementation; the lab that decides whether one is worth building. Private, personal.

**Orientation:** read `CLAUDE.md` — it carries the full milestone log (source of truth for lab state) and the bench discipline. One-page status: the design repo's [ROADMAP](https://github.com/lai3d/qumbra-design/blob/main/ROADMAP.md).

**State (2026-07-29):** M1–M10 complete. Consensus tx circuit **145,609 B / 142.2 KB** at ~100-bit conjectured under the corrected accounting (b16/q21/g22/fp16/a16 — FROZEN v1.0). M4 aggregation rung-1 two-level prototype end-to-end (leaf + interior + merge root + Σfee rider; **interior 20.5 GB @ b2/q86 default**, b4 fallback 31.21 GB); issue #24 closed 2026-07-27 (PR #82), so the ≥3-level per-level config re-derivation is unblocked and owed. `qumbra-node` binary, real RandomX + LWMA, P2P, mempool, committee over network, RPC. **M10 T0 net: the 48 h WAN soak is SEALED** (2026-07-28, PR #93) — four hosts, three continents, 48.01 h minimum uptime, zero restarts, zero finality reversions, two epoch boundaries crossed. **M11 open**: peer discovery merged (PR #86); [#87](https://github.com/lai3d/qumbra-lab/issues/87) committee diagnostics and [#91](https://github.com/lai3d/qumbra-lab/issues/91) peer hardening are dispatchable; the four T0 scenario drills are held until one redeploy carries #79 + #82 + #86 + #87.

## Layout

```
crates/         # 17 crates
  qlab-air/           # the fixed-shape AIR: Merkle path, PRF, commitment, balance
  qlab-bench/         # bench harness: hash matrix × hardware, criterion-based
  qlab-consensus/     # the frozen CONSENSUS_CFG + prove/verify wrappers (single source)
  qlab-pow/           # RandomX (light) + Zawy LWMA-1, exact integer form
  qlab-p2p/           # wire envelope, peer table, gossip, sync, discovery, transports
  qlab-node/          # node state, mempool, emission, finality recovery, RPC
  qlab-devnet/        # chain sim, committee/epoch machinery, vote tally
  qlab-wallet/        # key hierarchy, bech32m addresses, HD seed, diversifiers
  qlab-note/          # ML-KEM-768 + ChaCha20-Poly1305 note encryption
  qlab-cbserver/      # compact-block server (interop-spec §2 reference)
  qlab-disclosure/    # selective-disclosure STARK
  qlab-econ/          # emission simulator
  qlab-demo/          # whole-stack composition
  qlab-faucet/        # the M11 faucet: a proof-generating wallet + off-chain anti-abuse
  qumbra-node/        # the shipping binary: config, genesis, run
  qumbra-opview/      # the T0 operator view: cross-node checkpoint agreement + supply attestation (deliberately NOT an explorer)
  qumbra-faucet/      # the T1 faucet listener: HTTP over qlab-faucet's core, in-process with a KEYLESS node
docs/           # lab notes; polished results go to the design repo, not here
```

## Ground rules

- Rust, Plonky3-class stack; pin exact revs in `Cargo.lock` (bench numbers are meaningless against a moving prover).
- Every bench result records: git rev of this repo, prover crate revs, hardware, OS, power state.
- Numbers land in the design repo only after being reproduced twice on the same rig.
