# Exchange kit — standing-fvk custody audit (lab #483 stage 3)

> [中文版](kit-custody-audit-zh.md)

**Status: stage-3 deliverable of the exchange/VASP kit
([#483](https://github.com/qumbra-labs/qumbra-lab/issues/483); spec:
`qumbra-design/ecosystem-and-adoption.md` §4, `auditable-privacy.md` §4 —
the "Standing" layer).** Audience: an exchange, custodian, or institution
arranging ongoing audit visibility over a Qumbra wallet — and the auditor or
regulator on the receiving end. The precedent shape is Circle's institutional
**USDCx on Aleo**, where protocol-native view keys carry AML/audit visibility
([aleo.org](https://aleo.org/post/aleo-view-key-compliance/)) — the strongest
institutional validation to date that standing key-level disclosure is what
compliance actually accepts (`auditable-privacy.md` §3). EN is authoritative;
line numbers are against lab `main` at `cf15b11`.

**Scope boundary, first**: this doc is about the exchange's (or any
institution's) **own wallets** — deposit desk, treasury, cold custody — being
made auditable to a party of its choosing, on a standing basis. It is *not*
about depositors: an arriving deposit is screened per-transaction by the
disclosure envelope (the kit's edge layer — `crates/qlab-vask/README.md`),
which requires no standing key from anyone.

---

## 1. The key ladder — what exists to hand over

Qumbra's disclosure stack is key-level: the pool is uniform, nothing on-chain
marks an audited wallet, and every capability below is enforced **at the type
level** in the reference wallet (`qlab-wallet/src/viewing.rs:8-12`; the
"cannot" column is compile-error-locked by `compile_fail` doc-tests, not
policy):

| Key | Holds | Can | Cannot |
|---|---|---|---|
| spending key (`Wallet`/`SpendingKey`) | `sk` | everything, incl. spend | — |
| **full viewing key `Fvk`** | `nk`, `div_seed` | detect+decrypt all incoming; **view spends** (derive `nf`); derive `rkm(d)`; generate the wallet's addresses | spend |
| **incoming viewing key `Ivk`** | `div_seed` only | detect+decrypt incoming; enumerate the wallet's diversifier slots for scanning | view spends; generate addresses; spend |
| diversified decryption key `dk_d` | one diversifier's ML-KEM key | detect+decrypt incoming **at one address slot** | everything else |

`Fvk::to_ivk` is a one-way downgrade — `nk` is dropped and cannot be
recovered (`viewing.rs:94`). Since issue #32, address *generation* is an
`Fvk` capability, not an `Ivk` one (`viewing.rs:17-27`): an `Ivk` holder can
scan the addresses it is given but cannot mint new ones for the wallet.

## 2. What a standing fvk shows an auditor — and what it does not

Handing an auditor the `Fvk` of a custody account gives them, on an ongoing
basis and over the account's **entire history, past and future**:

- **Every incoming note**: detection plus full decryption of the 104-B note
  plaintext — value, and the opening material that recomputes the on-chain
  commitment, so amounts are verified against consensus data, not asserted.
- **Every spend event**: the `Fvk` derives each held note's nullifier
  (`viewing.rs:87`) and matches it against the served per-block nullifier
  sets (`GET /v1/nullifiers`, the #314 wire), so it sees *when* custody funds
  move and which notes moved.
- **Change and balance evolution**: change outputs return to the wallet and
  are visible as incoming, so spendable balance is reconstructible at every
  height — the treasury-audit and proof-of-holdings use.
- **Address linkage**: the `Fvk` derives `rkm(d)` for every diversifier, so
  all of the account's diversified addresses are linkable *to the auditor*
  (that is the point of the audit; to everyone else they stay unlinkable,
  PR #35).

What it does **not** show, stated as plainly as the capabilities above:

- **Outgoing recipients and per-recipient amounts.** Qumbra has no
  outgoing-viewing-key mechanism: an outbound payment's output notes are
  encrypted to the *recipient's* keys, and the chain never carries the
  recipient identity at all (the wallet's own history feature needs a local
  `sends.v1` record for exactly this reason — lab PR #324). A standing-fvk
  auditor sees that N notes totalling X left custody at height h and what
  came back as change — the outflow ledger — not who was paid. An audit
  regime that needs recipient-level answers uses the **selective** layer:
  the same disclosure-proof envelope this kit verifies, produced per
  transaction by the sender, who holds every witness.
- **Anything about any other wallet.** The fvk is scoped to one account's
  key tree; there is no path from it to the pool at large.
- **Spend authority.** An fvk cannot move funds under any compromise — the
  blast radius of a leaked fvk is the account's *privacy* (its whole history,
  retroactively), never its money. Treat the fvk accordingly: as regulated-
  records-class secret material, not as a casual API credential.

## 3. Scoping and rotation

- **Scope by HD account, never by seed.** Each account of a master seed is an
  independent sub-wallet with its own `nk`, `fvk`, `ivk` and diversifier tree
  (`qlab-wallet/src/viewing.rs:185-192`; format:
  `qumbra-design/wallet-interop-spec.md` §5). Disclose the fvk of the account
  under audit — handing anything derived above the account level (and above
  all the seed phrase itself) discloses every account, present and future.
- **Disclosure is irrevocable for the past.** An fvk decrypts the account's
  full history from genesis of the account, and nothing can later narrow
  that (`auditable-privacy.md` §5's retroactivity point cuts both ways).
  "Revoking" an auditor therefore means **rotation**: open a fresh account,
  move custody forward, and let the disclosed account's forward visibility
  decay to nothing. Price rotation into the custody design from day one —
  it is one HD index, not a migration.
- **Per-desk keys.** Deposit desk, hot treasury and cold custody should be
  separate accounts so each disclosure arrangement matches one operational
  surface, and a leak of one fvk prices at one desk's history.

## 4. The deposit desk needs less than an fvk

Crediting deposits requires detecting and decrypting **incoming** notes —
nothing else. That is the `Ivk` row of §1's ladder, or narrower still the
single-diversifier `dk_d`. The shipped crediting reference is the precedent:
`qumbra-credit-ref`'s `ExchangeKeys` holds exactly one diversified `dk` plus
the address commitment (`qumbra-credit-ref/src/lib.rs:77`), and its own docs
declare the devnet-grade shortcut — the key file derives from a seed
in-process (`src/main.rs:1-20`), which is acceptable on a devnet and is
**not** the production shape. Production:

| Surface | Key material on the host | Never on the host |
|---|---|---|
| crediting service / deposit desk | `Ivk` (or per-slot `dk_d`) | `nk`, `sk`, seed |
| audit feed to a third party | `Fvk` of the audited account | seed, other accounts' keys |
| funds movement | `sk`, in cold custody / signing ceremony | — |

An `Ivk` on a compromised edge host leaks incoming-deposit history — bad, but
strictly less than an fvk (no spend visibility, no address minting) and
categorically less than a spend key (no funds at risk). The ladder exists so
the exposed surface holds the least key that does the job; use it.

## 5. Operating the audit feed

- **The auditor scans like any wallet**: the compact-block wire
  (`wallet-interop-spec.md` §2) serves consensus data verbatim; a server
  learns the requester's IP and fetch pattern, never keys. An auditor who
  must not reveal *that* they audit a given account should run their own node
  or scan over Tor with decoy fetches — the §2 trust-posture mitigations
  apply to auditors exactly as to wallets.
- **Verification is native.** Everything the fvk decrypts recomputes against
  committed on-chain data (`cm` recomputation in scan, nullifiers from the
  served sets), so an audit finding is checkable against consensus, not a
  trust-me export from the audited party. This is the property that makes
  standing-key audit stronger than statement-based audit — the auditee
  cannot curate what the key sees.
- **Confirmations**: an audit ledger should count a movement at finality,
  same rule as crediting (`docs/kit-confirmation-policy.md`).
- **Paperwork**: the disclosure agreement should state the account scope
  (one fvk = one account), the retroactivity fact from §3, the rotation
  procedure, and the handling class of the key itself. None of this is
  protocol; all of it is what the USDCx precedent normalizes.

## 6. Honest limits

- **EU AMLR** (applies 2027-07-10) currently defines anonymity-enhancing
  coins broadly enough to catch optional-privacy designs regardless of
  viewing-key arrangements; whether standing disclosure earns a carve-out
  awaits AMLA technical standards (`auditable-privacy.md` §6). This doc's
  arrangement is what has worked with institutions (§3 evidence table there);
  it is not a legal opinion for any jurisdiction.
- **Granularity between `Ivk` and per-tx proofs is deliberately empty.**
  There is no "outgoing viewing key" and no time-boxed fvk; if a regime needs
  narrower-than-standing outbound visibility, the answer is selective
  disclosure proofs per transaction — which this kit already verifies — not
  a new key class. That gap is a design decision
  (`auditable-privacy.md` §8), recorded here so nobody sells an audit scope
  the keys cannot deliver.
