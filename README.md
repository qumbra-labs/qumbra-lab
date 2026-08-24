# qumbra-lab

Prototype lab for **Qumbra** — the post-quantum privacy-chain design exercise. Canonical spec: [`lai3d/qumbra-design`](https://github.com/qumbra-labs/qumbra-design) (22 paired design docs + six EN-only appendices + ROADMAP). This repo answers the design thread's prototype-gated questions with measured code. Not a chain implementation; the lab that decides whether one is worth building. Private, personal.

**Orientation:** read `CLAUDE.md` — it carries the full milestone log (source of truth for lab state) and the bench discipline. One-page status: the design repo's [ROADMAP](https://github.com/qumbra-labs/qumbra-design/blob/main/ROADMAP.md).

**State (2026-07-31):** M1–M9 complete; **M10 software half complete, Phase B-WAN soak SEALED** (2026-07-28, PR #93) — four hosts, three continents, 48.01 h minimum uptime, zero restarts, zero finality reversions, two epoch boundaries crossed; **four T0 scenario drills still owed** (redeploy that used to gate them is DONE; the gate is now **#130 (a) ✅ landed → #106 → mint → drills**, with **#107 answered *by* the new net rather than before it** — re-sequenced 2026-07-30, `qumbra-deploy/OPERATOR.md` §4 is authoritative). Consensus tx circuit **145,609 B / 142.2 KB** at ~100-bit conjectured under the corrected accounting (b16/q21/g22/fp16/a16 — FROZEN v1.0). M4 aggregation rung-1 two-level prototype end-to-end (leaf + interior + merge root + Σfee rider; **interior 20.5 GB @ b2/q86 default**, b4 fallback 31.21 GB); issue #24 closed 2026-07-27 (PR #82). `qumbra-node` binary, real RandomX + LWMA, P2P, mempool, committee over network, RPC; **20 crates** including `qumbra-opview`, `qumbra-faucet`, `qumbra-explorer`, `qumbra-wallet` and `qumbra-ffi`. **M11 open and advanced**: peer discovery ✅ (#86), peer hardening ✅ (#99), committee diagnostics ✅ (#96), faucet ✅ (#103), faucet listener ✅ (#128), opview + supply attestation 🟡 (#119/#126). Coordinator-independent unfiltered spine through 2026-07-31: **887 → 890 → 902 → 911 → 913 → 915**. T1 still cannot transact — note discovery serving **DECIDED option 3** (body-bound; design brief §10).

## Layout

```
crates/         # 27 crates
  qlab-air/           # the fixed-shape AIR: Merkle path, PRF, commitment, balance
  qlab-bench/         # bench harness: hash matrix × hardware, criterion-based
  qlab-consensus/     # the frozen CONSENSUS_CFG + prove/verify wrappers (single source)
  qlab-pow/           # RandomX (light) + Zawy LWMA-1, exact integer form
  qlab-stratum/       # Monero-convention stratum codec (pool protocol lib; no I/O)
  qlab-http-framing/  # HTTP/1.1 response framing for the four hand-rolled clients (lab #631)
  qlab-remote-auth/   # research-only Candidate A authorization spike (not production-reachable)
  qlab-remote-auth-mobile-bench/ # isolated D12..D16 iOS/Android measurement ABI
  qumbra-pool/        # the T2 pool binary: TCP stratum + accounting + form-keyed template source (lab #482 stage 1)
  qlab-p2p/           # wire envelope, peer table, gossip, sync, discovery, transports
  qlab-node/          # node state, mempool, emission, finality recovery, RPC
  qlab-devnet/        # chain sim, committee/epoch machinery, vote tally
  qlab-wallet/        # key hierarchy, bech32m addresses, HD seed, diversifiers
  qlab-note/          # ML-KEM-768 + ChaCha20-Poly1305 note encryption
  qlab-cbserver/      # compact-block server (interop-spec §2 reference)
  qlab-disclosure/    # selective-disclosure STARK
  qlab-vask/          # exchange/VASP kit: envelope verifier lib + qvask C ABI — crates/qlab-vask/README.md is the kit's front door (lab #483)
  qlab-econ/          # emission simulator
  qlab-demo/          # whole-stack composition
  qlab-faucet/        # the M11 faucet: a proof-generating wallet + off-chain anti-abuse
  qumbra-node/        # the shipping binary: config, genesis, run
  qumbra-opview/      # the T0 operator view: cross-node checkpoint agreement + supply attestation (deliberately NOT an explorer)
  qumbra-faucet/      # the T1 faucet listener: HTTP over qlab-faucet's core, in-process with a KEYLESS node
  qumbra-explorer/    # the public chain-health JSON projection over its own keyless observer node (deliberately not an Etherscan; the page is qumbra-explorer-web, #281)
  qumbra-wallet/      # the end-user wallet CLI: keygen/restore/address/backup/scan/send (#276 wired send: tree sync + POST /v1/tx)
  qumbra-prover-service/ # valueless-only shared proving mechanics: bounded jobs, ephemeral workers, no submit
  qumbra-ffi/         # the wallet kernel over a hand C ABI, cross-compiled for iOS (rung A, #246)
  qumbra-credit-ref/  # the exchange crediting-flow reference: POST /v1/credit over qlab-vask + the light-client scan (lab #483)
docs/           # lab notes; polished results go to the design repo, not here
```

## Ground rules

- Rust, Plonky3-class stack; pin exact revs in `Cargo.lock` (bench numbers are meaningless against a moving prover).
- Every bench result records: git rev of this repo, prover crate revs, hardware, OS, power state.
- Numbers land in the design repo only after being reproduced twice on the same rig.
