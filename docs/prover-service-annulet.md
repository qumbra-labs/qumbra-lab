# The Annulet proving service — operator guide

*Chinese translation: [`prover-service-annulet-zh.md`](prover-service-annulet-zh.md). EN is authoritative.*

Lab issue #924, 5A-D3/D4. Code: `crates/qumbra-prover-service` (`src/annulet.rs`, `src/token.rs`).

## What it is

`qumbra-prover-service` proves Candidate A **holder** spends (shapes S and P) for wallets that keep their own keys. A wallet uploads a `ProvingBundle`: its transaction with the proof empty, the authorization section already signed and attached, and the witness. The section's intent binds every public field except the proof. The service can therefore add a proof and nothing else, so it cannot spend, re-aim or re-sign anything. Issuer operations (a P row carrying an issuer secret, or a non-zero `vPublic`) are refused as `issuer-shape` and are never delegated.

The service submits the proved transaction itself, to the pinned node's `POST /v1/tx` (and to the relay, if one is configured), and returns the tx id.

The L1 `WitnessBundle` mode (`/v1/jobs`) is unchanged. It now runs only when its own valueless acknowledgement is set, and is **off on an Annulet prover**.

## API

| Route | Auth | What |
|---|---|---|
| `GET /v2/annulet/info` | none | `genesis_format`, `genesis_hash`, `shapes`, `d_auth`, `max_bundle_bytes`, `queue_capacity`, `prove_timeout_secs`, `slot_secs`, **`recommended_valid_for_blocks`** |
| `GET /v2/annulet/quota` | Bearer | `per_day`, `used_today`, `in_flight` |
| `POST /v2/annulet/jobs` | Bearer | body = the bundle bytes (`application/octet-stream`, ≤ 80 KiB); 202 with `job_url`, or 200 with the existing job for the same intent |
| `GET /v2/annulet/jobs/<cap>` | **the URL** | `state` (`queued` / `proving` / `submitting` / `submitted` / `failed` / `refused` / `cancelled`), `queue_position`, `tx_id`, `refusal`, `expires_in_secs` |
| `DELETE /v2/annulet/jobs/<cap>` | **the URL** | cancels a queued or proving job |

**The job URL is a capability.** It is 32 random bytes, and it is the only thing that authorizes reading or cancelling the job. The popup that uploaded the bundle holds it as a secret. It stops working once the result TTL (default 600 s) has passed after the job ends.

**Admission order.** Every refusal is by name, and nothing is spawned or queued before step 5 passes:

1. The token: signature, validity window, net, revocation → `401` with `unauthorized`, `token-malformed`, `token-key-unknown`, `token-signature-invalid`, `token-window-invalid`, `token-expired`, `token-wrong-net` or `token-revoked`.
2. The token's single in-flight job, its single upload being read, and its daily quota → `429` with `token-busy` or `quota-exhausted`. Only **admitted** jobs count against the quota. An admitted upload must arrive within 30 s. Past that the handler gives up (counted as `upload-deadline`), but the token's reading slot stays taken until the connection actually ends, so a slow upload holds up only its own token.
3. The byte ceiling, read bounded → `413` `bundle-too-large`.
4. Decode → `400` `bundle-malformed`, or `403` `issuer-shape`.
5. The bundle's lock, run on this net → `422` with `statement-mismatch`, `unauthorized-section`, `proof-present`, `auth-missing`, `outputs-not-the-nets` (lab #937: the bundle's output count is not this net's — a three-output bundle on format 33) or `third-output-asset` (lab #937: a three-output bundle whose third output carries neither input's asset — the v3 AIR has no proof for it).

After admission the request can still be refused with `409` `intent-in-flight` (another token holds this intent) or `503` `prover-busy` (the queue is full).

**Idempotency.** The idempotency key is the signed intent's digest, computed by the server. Re-sending the same signed transaction returns its existing job. A job that ended without a transaction (`failed`, `refused`, `cancelled`) may be retried.

**Validity.** The service does not judge `valid_until`, because it does not know the tip. A client signs with at least `recommended_valid_for_blocks` = ⌈((queue + 1) × prove timeout + 60 s) / slot⌉. If the transaction lands too late, the node refuses it and the job fails with `node-refused:<code>`.

## Tokens

The wire form is `qpt1.<base64url(payload ‖ ML-DSA-44 signature)>`. The payload is fixed width: key id, a 16-byte token id, the net's genesis hash, `not_before`, `not_after` (at most 30 days apart), `per_day` (0 means the operator default), and flags (zero). The prover holds **verifying keys only**; the minting key never touches the prover box.

```sh
# Once, on the operator's machine. The seed is 64 hex characters in a file,
# never on a command line.
qumbra-prover-service token-key  --seed-file issuer.seed --key-id 1   > token-keys.txt   # public: copy to the box
qumbra-prover-service mint-token --seed-file issuer.seed --key-id 1 \
    --genesis-hash <64 hex> --days 30 [--per-day 20]        # token on stdout, token id on stderr
```

To revoke a token, add its token id (32 hex) to `QUMBRA_PROVER_TOKEN_DENY_FILE`. The service re-reads that file every minute.

The gateway's portal will mint tokens later by calling `qumbra_prover_service::token::mint` with its own issuer key under its own `key_id`.

## Configuration

The Annulet mode is on exactly when `QUMBRA_PROVER_ANNULET_GENESIS_HASH` is set. Everything else then fails closed:

| Variable | Default | Notes |
|---|---|---|
| `QUMBRA_PROVER_ANNULET_GENESIS_HASH` | — | 64 lowercase hex; the net's genesis file hash |
| `QUMBRA_PROVER_ANNULET_SLOT_SECS` | — | the genesis `slot_secs` |
| `QUMBRA_PROVER_ANNULET_NODE_URL` | — | a node accepting `POST /v1/tx`; https, unless the plain-http acknowledgement below is set |
| `QUMBRA_PROVER_ANNULET_RELAY_URL` | unset | best-effort second submission; same rule |
| `QUMBRA_PROVER_ANNULET_ALLOW_PLAIN_HTTP_NODE` | unset | exactly `I_UNDERSTAND_THE_NODE_LINK_IS_PLAINTEXT_AND_FIREWALLED_TO_THIS_HOST` admits a plain `http://` node or relay URL. Use it only where a firewall admits this host alone to that port. What crosses the link is a signed, proved transaction that is public once submitted, and any change to it invalidates it, so the exposure is a dropped submission. The L1 experiment's `QUMBRA_PROVER_ALLOW_INSECURE_NODE_HTTP` does not apply to this mode |
| `QUMBRA_PROVER_ANNULET_QUEUE` | 3 | 1..=8, queued jobs, not counting the running one |
| `QUMBRA_PROVER_ANNULET_TIMEOUT_SECS` | 300 | 30..=1800, per prove |
| `QUMBRA_PROVER_ANNULET_RESULT_TTL_SECS` | 600 | 60..=3600 |
| `QUMBRA_PROVER_ANNULET_PER_DAY` | 20 | the default for tokens that state 0 |
| `QUMBRA_PROVER_TOKEN_KEYS_FILE` | — | `key_id verifying_key_hex` per line |
| `QUMBRA_PROVER_TOKEN_DENY_FILE` | unset | revoked token ids |
| `QUMBRA_PROVER_SCRATCH` | — | **must be a tmpfs mount** (checked at start; Linux only) |
| `QUMBRA_PROVER_LISTEN`, `QUMBRA_PROVER_ALLOW_NON_LOOPBACK_LISTEN` | as for L1 | TLS, rate limiting and a request-header size cap live at ingress |

## The worker child

Proofs run one at a time, each in a fresh `annulet-worker` child process:

- the environment is cleared except for the protocol tag and the genesis hash, so the child has no URL and no token;
- core dumps are off: `RLIMIT_CORE = 0` is set between fork and exec. On Linux the child also clears `PR_SET_DUMPABLE` itself, first thing after exec (the kernel resets that flag on `execve`). After that, a same-uid process cannot `ptrace` it or read `/proc/<pid>/mem`. The server does the same to itself at startup, because it holds bundles too;
- the working directory and `TMPDIR` are the tmpfs scratch;
- stderr is closed;
- the bundle is written to the child's stdin from its own thread, because 80 KiB can exceed a pipe's buffer. The prove timeout therefore also covers a child that stalls before reading.

Both processes wipe the decoded bundle's witness when they drop it.

The child re-runs the bundle's lock and proves. The server then checks that the answer is the bundle's transaction plus a non-empty proof and nothing else (otherwise the job fails with `proof-mismatch`), and only then submits it.

## Logs and what resets

- Per job: an 8-hex job prefix, the shape, bundle and tx sizes, queue wait, prove time, and an outcome code. Bundle bytes, transaction bytes, token ids and tx ids are never logged.
- Every minute: admission refusals counted per code, under a 4-byte hash of the token id (`-` before a token verified). This shows abuse without naming the user.
- **Per-day counts, in-flight state and jobs live in memory and reset on restart.**

## The pilot box (prover-1)

- **Host:** r7g.2xlarge (64 GiB, arm64). One P prove peaks at about 32 GiB.
- **Container:** `mem_limit` about 58g, no swap, `ulimits: core: 0`, a tmpfs mounted at `/scratch` (1g), read-only root filesystem.
- **Env:** the variables above. The net is format 33; take the genesis hash from the deploy repo. The node URL must point at a node that accepts `POST /v1/tx`.
- **Ingress:** TLS, rate limiting and a request-header size cap (Caddy), plus the non-loopback acknowledgement. Security group 443 is open, because the extension calls the service directly. **Keep `/v2/annulet/jobs/<cap>` out of the ingress access log**, or log only the path prefix: the capability in that URL is the job's secret.
- **Operator-held, not on the box:** the issuer seed.
- **Manual operator steps:** the Terraform apply for the host and its security group, DNS, keeping the issuer seed, and starting and stopping the host by hand.
